//! High availability (lane G): virtual IPs with VRRP failover (keepalived)
//! and connection-state sync (conntrackd), applied from the store.
//!
//! Store (`ha_vips` + `lan_settings` keys `ha.*`):
//! - a **carp** virtual IP is an address two (or more) firewalls share:
//!   keepalived runs one VRRP instance per (interface, VRID, family), all in
//!   one sync group so LAN and WAN move together; the node with the higher
//!   priority is MASTER and carries the address, the other holds BACKUP and
//!   takes over within a few seconds when the master stops advertising, loses
//!   a tracked link (every WAN/LAN interface), or enters maintenance mode;
//! - an **alias** virtual IP is just an extra address on an interface (no
//!   failover); the interfaces applier leaves both kinds alone;
//! - state sync (conntrackd, FTFW over UDP unicast) replicates the
//!   connection table to the peer so established connections survive a
//!   failover; the notify script drives conntrackd on every transition and
//!   records the HA state in `/run/patronus/ha-state`.
//!
//! Files (marker-owned, atomically replaced): `/etc/keepalived/keepalived.conf`,
//! `/etc/conntrackd/conntrackd.conf`, `/etc/patronus/ha-notify.sh`. Daemons
//! are started through the init system (OpenRC / systemd) like every other
//! service; a config change reloads keepalived with SIGHUP (no VIP flap),
//! conntrackd is restarted.

use crate::lan::{self, check_description, db_err, invalid, now, LanEnv, ManagedFile};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const KEEPALIVED_CONF: &str = "/etc/keepalived/keepalived.conf";
pub const KEEPALIVED_BIN: &str = "/usr/sbin/keepalived";
pub const CONNTRACKD_CONF: &str = "/etc/conntrackd/conntrackd.conf";
pub const CONNTRACKD_BIN: &str = "/usr/sbin/conntrackd";
pub const NOTIFY_SCRIPT: &str = "/etc/patronus/ha-notify.sh";
pub const STATE_FILE: &str = "/run/patronus/ha-state";
pub const SYNC_PORT: u16 = 3780;
pub const DEFAULT_PRIORITY: u8 = 100;
/// The priority a node in maintenance mode advertises (0 would release).
pub const MAINTENANCE_PRIORITY: u8 = 1;

// ---------------------------------------------------------------------------
// virtual IPs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vip {
    pub id: i64,
    pub name: String,
    /// device name or role (`@lan`)
    pub interface: String,
    /// address/prefix, e.g. `192.168.50.254/24`
    pub address: String,
    pub vrid: u8,
    /// `carp` (VRRP failover) or `alias` (extra address)
    pub mode: String,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VipInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub vrid: Option<u8>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn list_vips(store: &ConfigStore) -> Result<Vec<Vip>> {
    let rows = sqlx::query(
        "SELECT id, name, interface, address, vrid, mode, enabled, description
         FROM ha_vips ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ha_vips"))?;
    Ok(rows
        .iter()
        .map(|r| Vip {
            id: r.get(0),
            name: r.get(1),
            interface: r.get(2),
            address: r.get(3),
            vrid: r.get::<i64, _>(4) as u8,
            mode: r.get(5),
            enabled: r.get::<i64, _>(6) != 0,
            description: r.get(7),
        })
        .collect())
}

fn check_vip_name(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 32
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(invalid(format!(
            "virtual IP name {s:?}: 1-32 letters, digits, '-', '_' or '.'"
        )));
    }
    Ok(s.to_string())
}

/// `192.168.50.254/24`: a host address with its prefix length.
pub fn check_vip_address(s: &str) -> Result<String> {
    let s = s.trim();
    let n: IpNetwork = s
        .parse()
        .map_err(|_| invalid(format!("virtual IP address {s:?}: use address/prefix")))?;
    if !s.contains('/') {
        return Err(invalid(format!(
            "virtual IP address {s:?}: the prefix length is required (192.168.50.254/24)"
        )));
    }
    let a = n.ip();
    let bad = a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || match n {
            IpNetwork::V4(v) => v.prefix() == 0 || (a == v.network() && v.prefix() < 31),
            IpNetwork::V6(v) => v.prefix() == 0,
        }
        || match a {
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
            _ => false,
        };
    if bad {
        return Err(invalid(format!(
            "virtual IP address {s:?}: not a usable host address"
        )));
    }
    Ok(n.to_string())
}

pub async fn save_vip(store: &ConfigStore, id: Option<i64>, i: &VipInput) -> Result<i64> {
    let all = list_vips(store).await?;
    let cur = match id {
        Some(id) => Some(
            all.iter()
                .find(|v| v.id == id)
                .cloned()
                .ok_or_else(|| Error::Config(format!("no virtual IP {id}")))?,
        ),
        None => None,
    };
    let name = match (&i.name, &cur) {
        (Some(n), _) => check_vip_name(n)?,
        (None, Some(c)) => c.name.clone(),
        (None, None) => return Err(invalid("virtual IP: a name is required")),
    };
    if all.iter().any(|v| v.name == name && Some(v.id) != id) {
        return Err(invalid(format!("virtual IP: {name} already exists")));
    }
    let interface = match (&i.interface, &cur) {
        (Some(n), _) => lan::check_iface_spec(n)?,
        (None, Some(c)) => c.interface.clone(),
        (None, None) => return Err(invalid("virtual IP: an interface is required")),
    };
    let address = match (&i.address, &cur) {
        (Some(a), _) => check_vip_address(a)?,
        (None, Some(c)) => c.address.clone(),
        (None, None) => return Err(invalid("virtual IP: an address is required")),
    };
    let mode = match (i.mode.as_deref(), &cur) {
        (Some(m @ ("carp" | "alias")), _) => m.to_string(),
        (Some(m), _) => return Err(invalid(format!("mode {m:?}: carp or alias"))),
        (None, Some(c)) => c.mode.clone(),
        (None, None) => "carp".into(),
    };
    let vrid = match (i.vrid, &cur) {
        (Some(0), _) => return Err(invalid("VRID: 1-255")),
        (Some(v), _) => v,
        (None, Some(c)) => c.vrid,
        (None, None) => 51,
    };
    let description = match (&i.description, &cur) {
        (Some(d), _) => check_description(Some(d))?,
        (None, Some(c)) => c.description.clone(),
        (None, None) => None,
    };
    let enabled = i
        .enabled
        .or(cur.as_ref().map(|c| c.enabled))
        .unwrap_or(true);
    // the same address twice is a mistake whatever the mode
    if all.iter().any(|v| {
        Some(v.id) != id
            && v.address.split('/').next() == address.split('/').next()
            && v.interface == interface
    }) {
        return Err(invalid(format!(
            "virtual IP: {address} is already configured on {interface}"
        )));
    }
    let sql = if id.is_some() {
        "UPDATE ha_vips SET name=?, interface=?, address=?, vrid=?, mode=?, enabled=?,
            description=?, updated_at=? WHERE id=?"
    } else {
        "INSERT INTO ha_vips (name, interface, address, vrid, mode, enabled, description,
            updated_at) VALUES (?,?,?,?,?,?,?,?)"
    };
    let mut q = sqlx::query(sql)
        .bind(&name)
        .bind(&interface)
        .bind(&address)
        .bind(i64::from(vrid))
        .bind(&mode)
        .bind(enabled as i64)
        .bind(&description)
        .bind(now());
    if let Some(id) = id {
        q = q.bind(id);
    }
    let r = q
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("save virtual IP: {e}")))?;
    Ok(id.unwrap_or_else(|| r.last_insert_rowid()))
}

pub async fn delete_vip(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM ha_vips WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete virtual IP"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no virtual IP {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    /// VRRP priority 1-254 (higher = preferred master)
    pub priority: u8,
    /// a higher-priority node takes the addresses back when it returns
    pub preempt: bool,
    /// VRRP authentication string (up to 8 characters, same on both nodes)
    pub password: String,
    /// the other node's address on the VIP interface (unicast VRRP); none = multicast
    pub peer: Option<String>,
    /// replicate the connection table (conntrackd)
    pub sync: bool,
    /// interface the sync traffic uses (device or role)
    pub sync_interface: Option<String>,
    /// the peer's address on the sync interface
    pub sync_peer: Option<String>,
    /// advertise the lowest priority so the peer takes over (persistent maintenance mode)
    pub maintenance: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            priority: DEFAULT_PRIORITY,
            preempt: true,
            password: String::new(),
            peer: None,
            sync: false,
            sync_interface: None,
            sync_peer: None,
            maintenance: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SettingsInput {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub preempt: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub peer: Option<String>,
    #[serde(default)]
    pub sync: Option<bool>,
    #[serde(default)]
    pub sync_interface: Option<String>,
    #[serde(default)]
    pub sync_peer: Option<String>,
    #[serde(default)]
    pub maintenance: Option<bool>,
}

fn opt(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub async fn settings(store: &ConfigStore) -> Result<Settings> {
    let m = lan::settings_with_prefix(store, "ha.").await?;
    let g = |k: &str| m.get(&format!("ha.{k}")).cloned();
    let d = Settings::default();
    Ok(Settings {
        enabled: g("enabled").is_some_and(|v| lan::flag(&v)),
        priority: g("priority")
            .and_then(|v| v.parse().ok())
            .filter(|p| (1..=254).contains(p))
            .unwrap_or(d.priority),
        preempt: g("preempt").map(|v| lan::flag(&v)).unwrap_or(d.preempt),
        password: g("password").unwrap_or_default(),
        peer: opt(g("peer")),
        sync: g("sync").is_some_and(|v| lan::flag(&v)),
        sync_interface: opt(g("sync_interface")),
        sync_peer: opt(g("sync_peer")),
        maintenance: g("maintenance").is_some_and(|v| lan::flag(&v)),
    })
}

/// VRRP authentication strings: 1-8 letters, digits or `- _ . + =`.
pub fn check_password(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 8
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '='))
    {
        return Err(invalid(
            "HA password: 1-8 letters, digits or - _ . + = (VRRP limits it to 8 characters)",
        ));
    }
    Ok(s.to_string())
}

fn generate_password() -> String {
    use std::io::Read;
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        b = (now() as u64).to_le_bytes();
    }
    const CS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    b.iter()
        .map(|x| CS[*x as usize % CS.len()] as char)
        .collect()
}

fn check_ip(what: &str, s: &str) -> Result<String> {
    let ip: IpAddr = s
        .trim()
        .parse()
        .map_err(|_| invalid(format!("{what} {s:?}: an IP address")))?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return Err(invalid(format!(
            "{what} {s:?}: not a usable unicast address"
        )));
    }
    Ok(ip.to_string())
}

pub async fn save_settings(store: &ConfigStore, i: &SettingsInput) -> Result<Settings> {
    let mut s = settings(store).await?;
    if let Some(e) = i.enabled {
        s.enabled = e;
    }
    if let Some(p) = i.priority {
        if !(1..=254).contains(&p) {
            return Err(invalid("priority: 1-254"));
        }
        s.priority = p;
    }
    if let Some(p) = i.preempt {
        s.preempt = p;
    }
    if let Some(p) = &i.password {
        s.password = check_password(p)?;
    }
    if let Some(p) = &i.peer {
        s.peer = if p.trim().is_empty() {
            None
        } else {
            Some(check_ip("peer address", p)?)
        };
    }
    if let Some(v) = i.sync {
        s.sync = v;
    }
    if let Some(v) = &i.sync_interface {
        s.sync_interface = if v.trim().is_empty() {
            None
        } else {
            Some(lan::check_iface_spec(v)?)
        };
    }
    if let Some(p) = &i.sync_peer {
        s.sync_peer = if p.trim().is_empty() {
            None
        } else {
            Some(check_ip("sync peer address", p)?)
        };
    }
    if let Some(m) = i.maintenance {
        s.maintenance = m;
    }
    if s.sync && (s.sync_interface.is_none() || s.sync_peer.is_none()) {
        return Err(invalid(
            "state sync: needs the sync interface and the peer's address on it",
        ));
    }
    if s.enabled && s.password.is_empty() {
        s.password = generate_password();
    }
    for (k, v) in [
        ("ha.enabled", (s.enabled as u8).to_string()),
        ("ha.priority", s.priority.to_string()),
        ("ha.preempt", (s.preempt as u8).to_string()),
        ("ha.password", s.password.clone()),
        ("ha.peer", s.peer.clone().unwrap_or_default()),
        ("ha.sync", (s.sync as u8).to_string()),
        (
            "ha.sync_interface",
            s.sync_interface.clone().unwrap_or_default(),
        ),
        ("ha.sync_peer", s.sync_peer.clone().unwrap_or_default()),
        ("ha.maintenance", (s.maintenance as u8).to_string()),
    ] {
        lan::set_setting(store, k, &v).await?;
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

/// A virtual IP resolved onto a real device.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedVip {
    pub name: String,
    pub dev: String,
    pub net: IpNetwork,
    pub vrid: u8,
}

fn dev_ident(dev: &str) -> String {
    dev.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// keepalived.conf. `local_for(dev, v6)` = this node's own address on `dev`
/// (for unicast VRRP), `track` = the links whose loss demotes the node.
pub fn render_keepalived(
    s: &Settings,
    vips: &[ResolvedVip],
    router_id: &str,
    track: &[String],
    local_for: &dyn Fn(&str, bool) -> Option<IpAddr>,
) -> Result<String> {
    let prio = if s.maintenance {
        MAINTENANCE_PRIORITY
    } else {
        s.priority
    };
    type Key = (String, u8, bool);
    let mut groups: Vec<(Key, Vec<&ResolvedVip>)> = Vec::new();
    for v in vips {
        let key = (v.dev.clone(), v.vrid, v.net.is_ipv6());
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, g)) => g.push(v),
            None => groups.push((key, vec![v])),
        }
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    let mut o = lan::header("!", "high availability");
    o.push_str(&format!(
        "global_defs {{\n    router_id {}\n    enable_script_security\n    script_user root\n}}\n\n",
        dev_ident(router_id)
    ));
    let mut names = Vec::new();
    for ((dev, vrid, v6), g) in &groups {
        let name = format!(
            "PAT_{}_{}{}",
            dev_ident(dev),
            vrid,
            if *v6 { "_6" } else { "" }
        );
        names.push(name.clone());
        o.push_str(&format!("vrrp_instance {name} {{\n"));
        o.push_str("    state BACKUP\n");
        o.push_str(&format!("    interface {dev}\n"));
        o.push_str(&format!("    virtual_router_id {vrid}\n"));
        o.push_str(&format!("    priority {prio}\n"));
        o.push_str("    advert_int 1\n");
        if !s.preempt {
            o.push_str("    nopreempt\n");
        }
        if *v6 {
            o.push_str("    version 3\n    native_ipv6\n");
        } else {
            o.push_str(&format!(
                "    authentication {{\n        auth_type PASS\n        auth_pass {}\n    }}\n",
                s.password
            ));
            if let Some(peer) = &s.peer {
                let src = local_for(dev, false).ok_or_else(|| {
                    Error::Config(format!(
                        "HA: {dev} has no IPv4 address of its own to send unicast VRRP from"
                    ))
                })?;
                o.push_str(&format!(
                    "    unicast_src_ip {src}\n    unicast_peer {{\n        {peer}\n    }}\n"
                ));
            }
        }
        if !track.is_empty() {
            o.push_str("    track_interface {\n");
            for t in track {
                o.push_str(&format!("        {t}\n"));
            }
            o.push_str("    }\n");
        }
        o.push_str("    virtual_ipaddress {\n");
        for v in g {
            o.push_str(&format!("        {} dev {}\n", v.net, v.dev));
        }
        o.push_str("    }\n}\n\n");
    }
    o.push_str("vrrp_sync_group PATRONUS {\n    group {\n");
    for n in &names {
        o.push_str(&format!("        {n}\n"));
    }
    o.push_str(&format!("    }}\n    notify {NOTIFY_SCRIPT}\n}}\n"));
    Ok(o)
}

/// An empty keepalived.conf (HA off): nothing to start.
pub fn idle_keepalived() -> String {
    format!(
        "{}global_defs {{\n}}\n",
        lan::header("!", "high availability, off")
    )
}

pub fn idle_conntrackd() -> String {
    format!(
        "{}# state sync is off\n",
        lan::header("#", "state sync, off")
    )
}

/// conntrackd.conf for FTFW state sync over UDP unicast.
pub fn render_conntrackd(local: IpAddr, peer: &str, dev: &str) -> String {
    let mut o = lan::header("#", "connection state sync");
    o.push_str(&format!(
        "Sync {{
    Mode FTFW {{
        ResendQueueSize 131072
        CommitTimeout 1800
        PurgeTimeout 5
        ACKWindowSize 300
        DisableExternalCache Off
    }}
    UDP {{
        IPv4_address {local}
        IPv4_Destination_Address {peer}
        Port {SYNC_PORT}
        Interface {dev}
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }}
}}
General {{
    Nice -20
    HashSize 32768
    HashLimit 131072
    LogFile off
    Syslog on
    LockFile /var/lock/conntrack.lock
    UNIX {{
        Path /var/run/conntrackd.ctl
        Backlog 20
    }}
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {{
        Protocol Accept {{
            TCP
            UDP
            ICMP
        }}
        Address Ignore {{
            IPv4_address 127.0.0.1
            IPv4_address {local}
            IPv4_address {peer}
        }}
    }}
}}
"
    ));
    o
}

/// The script keepalived runs on every state change: record the state and
/// drive conntrackd (commit/flush/resync/bulk on MASTER; shorten timers and
/// ask the peer for a resync on BACKUP/FAULT).
pub fn render_notify() -> String {
    format!(
        "#!/bin/sh
# {marker} (HA). keepalived calls: ha-notify.sh GROUP|INSTANCE NAME STATE PRIORITY
STATE=\"$3\"
DIR=/run/patronus
mkdir -p \"$DIR\"
printf '%s %s\\n' \"$STATE\" \"$(date +%s)\" > \"$DIR/ha-state.tmp\" && mv \"$DIR/ha-state.tmp\" \"$DIR/ha-state\"
chmod 644 \"$DIR/ha-state\"
if [ -x {ct_bin} ] && grep -q '^Sync' {ct_conf} 2>/dev/null; then
    CT=\"{ct_bin} -C {ct_conf}\"
    case \"$STATE\" in
        MASTER) $CT -c; $CT -f; $CT -R; $CT -B ;;
        BACKUP|FAULT) $CT -t; $CT -n ;;
    esac
fi
logger -t patronus-ha \"HA state: $STATE\" 2>/dev/null
exit 0
",
        marker = lan::MARKER,
        ct_bin = CONNTRACKD_BIN,
        ct_conf = CONNTRACKD_CONF,
    )
}

// ---------------------------------------------------------------------------
// the applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HaApplier {
    env: LanEnv,
}

impl Default for HaApplier {
    fn default() -> Self {
        Self::new(LanEnv::system())
    }
}

type Resolved = (Vec<ResolvedVip>, Vec<ResolvedVip>, Vec<String>);

/// Enabled virtual IPs resolved onto devices: (carp, alias, warnings).
pub async fn resolve_vips(store: &ConfigStore) -> Result<Resolved> {
    let (mut carp, mut alias, mut warnings) = (Vec::new(), Vec::new(), Vec::new());
    for v in list_vips(store).await?.into_iter().filter(|v| v.enabled) {
        let devs = lan::resolve_iface(store, &v.interface).await?;
        if devs.is_empty() {
            warnings.push(format!(
                "virtual IP {} skipped: {} is not assigned to any interface",
                v.name, v.interface
            ));
            continue;
        }
        let net: IpNetwork = v.address.parse().map_err(|_| {
            Error::Config(format!("virtual IP {}: bad address {}", v.name, v.address))
        })?;
        for dev in devs {
            let r = ResolvedVip {
                name: v.name.clone(),
                dev,
                net,
                vrid: v.vrid,
            };
            if v.mode == "alias" {
                alias.push(r);
            } else {
                carp.push(r);
            }
        }
    }
    Ok((carp, alias, warnings))
}

impl HaApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    fn own_addr(&self, dev: &str, v6: bool, vips: &[ResolvedVip]) -> Option<IpAddr> {
        let addrs = self.env.addrs().ok()?;
        addrs
            .into_iter()
            .filter(|a| a.ifname == dev && a.addr.is_ipv6() == v6)
            .filter(|a| !a.addr.is_loopback())
            .find(|a| !vips.iter().any(|v| v.dev == dev && v.net.ip() == a.addr))
            .map(|a| a.addr)
    }

    /// Links whose loss triggers a failover (every WAN and LAN interface).
    async fn tracked(&self, store: &ConfigStore) -> Vec<String> {
        let mut t = BTreeSet::new();
        for role in ["wan", "lan"] {
            if let Ok(v) = store.interfaces_with_role(role).await {
                t.extend(v);
            }
        }
        t.into_iter().collect()
    }

    fn reload_keepalived(&self) -> bool {
        for p in [
            "/run/keepalived.pid",
            "/var/run/keepalived.pid",
            "/run/keepalived/keepalived.pid",
        ] {
            if let Some(pid) = std::fs::read_to_string(self.env.path(p))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                if nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGHUP,
                )
                .is_ok()
                {
                    return true;
                }
            }
        }
        false
    }

    /// Real kernel changes only on a real root (tests use a temp dir).
    fn live(&self) -> bool {
        self.env.root == std::path::Path::new("/")
    }

    fn ip(&self, args: &[&str]) -> std::result::Result<(), String> {
        let o = std::process::Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("ip {}: {e}", args.join(" ")))?;
        if o.status.success() {
            return Ok(());
        }
        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
        // already there / already gone: the goal state
        if err.contains("File exists") || err.contains("Address not found") {
            return Ok(());
        }
        Err(format!("ip {}: {err}", args.join(" ")))
    }

    /// Make the alias virtual IPs exist, and remove the ones this applier
    /// added earlier that are no longer configured (remembered in
    /// `/var/lib/patronus/ha-aliases`).
    async fn sync_aliases(&self, store: &ConfigStore, rep: &mut ApplyReport) -> Result<()> {
        let (_, alias, _) = resolve_vips(store).await?;
        let want: Vec<(String, String)> = alias
            .iter()
            .map(|v| (v.dev.clone(), v.net.to_string()))
            .collect();
        let file = "/var/lib/patronus/ha-aliases";
        let prev: Vec<(String, String)> = std::fs::read_to_string(self.env.path(file))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if want.is_empty() && prev.is_empty() {
            return Ok(());
        }
        let have = self.env.addrs().unwrap_or_default();
        let mut kept = Vec::new();
        for (dev, a) in &prev {
            if !want.contains(&(dev.clone(), a.clone())) && self.live() {
                match self.ip(&["addr", "del", a, "dev", dev]) {
                    Ok(()) => rep.applied(format!("removed alias address {a} from {dev}")),
                    Err(e) => {
                        rep.warn(e);
                        kept.push((dev.clone(), a.clone()));
                    }
                }
            }
        }
        for (dev, a) in &want {
            let ip = a.split('/').next().unwrap_or("");
            let present = have
                .iter()
                .any(|h| &h.ifname == dev && h.addr.to_string() == ip);
            if !present && self.live() {
                match self.ip(&["addr", "add", a, "dev", dev]) {
                    Ok(()) => rep.applied(format!("added alias address {a} on {dev}")),
                    Err(e) => {
                        rep.warn(e);
                        continue;
                    }
                }
            }
            kept.push((dev.clone(), a.clone()));
        }
        let path = self.env.path(file);
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(&path, serde_json::to_string(&kept).unwrap_or_default());
        Ok(())
    }

    fn file(path: &'static str, content: String, mode: u32) -> ManagedFile {
        ManagedFile {
            path,
            content,
            mode,
            group: None,
            check: None,
        }
    }

    /// (keepalived.conf, conntrackd.conf if state sync is on), or None when
    /// HA is off / has nothing to share.
    async fn build(
        &self,
        store: &ConfigStore,
        rep: &mut ApplyReport,
    ) -> Result<Option<(String, Option<String>)>> {
        let s = settings(store).await?;
        let (carp, _alias, warnings) = resolve_vips(store).await?;
        for w in warnings {
            rep.warn(w);
        }
        if !s.enabled || carp.is_empty() {
            return Ok(None);
        }
        let hostname = std::fs::read_to_string(self.env.path("/etc/hostname"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let track = self.tracked(store).await;
        let ka = render_keepalived(
            &s,
            &carp,
            if hostname.is_empty() {
                "patronus"
            } else {
                &hostname
            },
            &track,
            &|dev, v6| self.own_addr(dev, v6, &carp),
        )?;
        let ct = if s.sync {
            let spec = s.sync_interface.clone().unwrap_or_default();
            let devs = lan::resolve_iface(store, &spec).await?;
            let dev = devs.first().ok_or_else(|| {
                Error::Config(format!(
                    "HA state sync: {spec} is not assigned to any interface"
                ))
            })?;
            let local = self.own_addr(dev, false, &[]).ok_or_else(|| {
                Error::Config(format!("HA state sync: {dev} has no IPv4 address"))
            })?;
            Some(render_conntrackd(
                local,
                s.sync_peer.as_deref().unwrap_or(""),
                dev,
            ))
        } else {
            None
        };
        Ok(Some((ka, ct)))
    }
}

#[async_trait]
impl Applier for HaApplier {
    fn name(&self) -> &'static str {
        "ha"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        // alias addresses do not depend on the HA switch
        self.sync_aliases(store, &mut rep).await?;
        let Some((ka, ct)) = self.build(store, &mut rep).await? else {
            // HA off / nothing to share: stop what we started, leave the rest alone
            lan::retire(
                &self.env,
                "keepalived",
                Self::file(KEEPALIVED_CONF, idle_keepalived(), 0o644),
                &mut rep,
            )?;
            lan::retire(
                &self.env,
                "conntrackd",
                Self::file(CONNTRACKD_CONF, idle_conntrackd(), 0o644),
                &mut rep,
            )?;
            let _ = std::fs::remove_file(self.env.path(STATE_FILE));
            if rep.applied.is_empty() {
                rep.applied("high availability is off (keepalived/conntrackd untouched)");
            }
            return Ok(rep);
        };
        if !self.env.has_binary(KEEPALIVED_BIN) {
            return Err(Error::Service(
                "high availability needs keepalived but /usr/sbin/keepalived is not installed \
                 (emerge sys-cluster/keepalived, USE=ha keepalived)"
                    .into(),
            ));
        }
        if ct.is_some() && !self.env.has_binary(CONNTRACKD_BIN) {
            return Err(Error::Service(
                "state sync needs conntrackd but /usr/sbin/conntrackd is not installed \
                 (emerge net-firewall/conntrack-tools)"
                    .into(),
            ));
        }
        lan::ensure_dir(&self.env, "/etc/patronus", 0o750, None);
        lan::ensure_dir(&self.env, "/etc/keepalived", 0o755, None);
        lan::ensure_dir(&self.env, "/etc/conntrackd", 0o755, None);
        if lan::install(
            &self.env,
            &Self::file(NOTIFY_SCRIPT, render_notify(), 0o750),
        )? {
            rep.applied(format!("wrote {NOTIFY_SCRIPT}"));
        }
        // conntrackd first: the notify script talks to it on the first MASTER
        match &ct {
            Some(c) => {
                let changed =
                    lan::install(&self.env, &Self::file(CONNTRACKD_CONF, c.clone(), 0o644))?;
                if changed {
                    rep.applied(format!("wrote {CONNTRACKD_CONF}"));
                }
                lan::reconcile(
                    &self.env,
                    "conntrackd",
                    true,
                    changed,
                    CONNTRACKD_CONF,
                    &mut rep,
                )?;
            }
            None => lan::retire(
                &self.env,
                "conntrackd",
                Self::file(CONNTRACKD_CONF, idle_conntrackd(), 0o644),
                &mut rep,
            )?,
        }
        let changed = lan::install(&self.env, &Self::file(KEEPALIVED_CONF, ka, 0o644))?;
        if changed {
            rep.applied(format!("wrote {KEEPALIVED_CONF}"));
        }
        if changed && self.env.services.is_running("keepalived") {
            if self.reload_keepalived() {
                rep.applied("keepalived reloaded (SIGHUP, no address flap)");
            } else {
                self.env.services.restart("keepalived")?;
                rep.applied("keepalived restarted with the new config");
            }
        } else {
            lan::reconcile(
                &self.env,
                "keepalived",
                true,
                false,
                KEEPALIVED_CONF,
                &mut rep,
            )?;
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        Ok(match self.build(store, &mut rep).await? {
            None => "# high availability is off\n".to_string(),
            Some((ka, ct)) => {
                let mut o = format!(
                    "## {KEEPALIVED_CONF}\n{ka}\n## {NOTIFY_SCRIPT}\n{}",
                    render_notify()
                );
                if let Some(ct) = ct {
                    o.push_str(&format!("\n## {CONNTRACKD_CONF}\n{ct}"));
                }
                o
            }
        })
    }

    /// `{installed, enabled, state, since, keepalived, conntrackd, vips[{name,address,dev,mode,present}], peer, sync}`
    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        let (carp, alias, _) = resolve_vips(store).await?;
        let addrs = self.env.addrs().unwrap_or_default();
        let present = |v: &ResolvedVip| {
            addrs
                .iter()
                .any(|a| a.ifname == v.dev && a.addr == v.net.ip())
        };
        let (state, since) = read_state(&self.env);
        let vips: Vec<Value> = carp
            .iter()
            .map(|v| (v, "carp"))
            .chain(alias.iter().map(|v| (v, "alias")))
            .map(|(v, mode)| {
                json!({"name": v.name, "address": v.net.to_string(), "dev": v.dev,
                       "mode": mode, "present": present(v)})
            })
            .collect();
        Ok(json!({
            "installed": self.env.has_binary(KEEPALIVED_BIN),
            "conntrackd_installed": self.env.has_binary(CONNTRACKD_BIN),
            "enabled": s.enabled,
            "maintenance": s.maintenance,
            "state": if s.enabled && !carp.is_empty() { state } else { Value::Null },
            "since": since,
            "keepalived": self.env.services.is_running("keepalived"),
            "conntrackd": self.env.services.is_running("conntrackd"),
            "vips": vips,
            "peer": s.peer,
            "sync": s.sync,
        }))
    }
}

/// (`MASTER`|`BACKUP`|`FAULT`|..., unix time) from the notify script's file.
fn read_state(env: &LanEnv) -> (Value, Value) {
    match std::fs::read_to_string(env.path(STATE_FILE)) {
        Ok(t) => {
            let mut it = t.split_whitespace();
            (
                it.next().map(|s| json!(s)).unwrap_or(Value::Null),
                it.next()
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|v| json!(v))
                    .unwrap_or(Value::Null),
            )
        }
        Err(_) => (Value::Null, Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;

    fn rv(name: &str, dev: &str, addr: &str, vrid: u8) -> ResolvedVip {
        ResolvedVip {
            name: name.into(),
            dev: dev.into(),
            net: addr.parse().unwrap(),
            vrid,
        }
    }

    fn settings_on() -> Settings {
        Settings {
            enabled: true,
            priority: 150,
            password: "s3cr3tpw".into(),
            peer: Some("192.168.50.3".into()),
            ..Settings::default()
        }
    }

    fn local(dev: &str, _v6: bool) -> Option<IpAddr> {
        Some(if dev == "eth1" {
            "192.168.50.2".parse().unwrap()
        } else {
            "203.0.113.2".parse().unwrap()
        })
    }

    #[test]
    fn keepalived_conf_has_one_instance_per_interface_vrid_and_a_sync_group() {
        let vips = [
            rv("lan-gw", "eth1", "192.168.50.254/24", 51),
            rv("lan-gw2", "eth1", "192.168.50.253/24", 51),
            rv("wan-vip", "eth0", "203.0.113.5/24", 52),
            rv("lan-v6", "eth1", "fd00:50::fe/64", 51),
        ];
        let track = ["eth0".to_string(), "eth1".to_string()];
        let c = render_keepalived(&settings_on(), &vips, "fw-1.lan", &track, &local).unwrap();
        assert!(c.starts_with("! Managed by Patronus"), "{c}");
        assert!(c.contains("router_id fw_1_lan"), "{c}");
        assert_eq!(c.matches("vrrp_instance").count(), 3, "{c}");
        assert!(c.contains("vrrp_instance PAT_eth1_51 {"));
        assert!(c.contains("vrrp_instance PAT_eth0_52 {"));
        assert!(c.contains("vrrp_instance PAT_eth1_51_6 {"));
        let block_of = |name: &str| {
            let i = c.find(&format!("vrrp_instance {name} {{")).unwrap();
            c[i..i + c[i..].find("\n}\n").unwrap()].to_string()
        };
        let b = block_of("PAT_eth1_51");
        assert!(
            b.contains("192.168.50.254/24 dev eth1") && b.contains("192.168.50.253/24 dev eth1"),
            "{b}"
        );
        assert!(b.contains("priority 150") && b.contains("auth_pass s3cr3tpw"));
        assert!(
            b.contains("unicast_src_ip 192.168.50.2") && b.contains("192.168.50.3"),
            "{b}"
        );
        assert!(b.contains("track_interface {") && b.contains("eth0"));
        let v6 = block_of("PAT_eth1_51_6");
        assert!(
            v6.contains("version 3") && v6.contains("native_ipv6") && !v6.contains("auth_pass"),
            "{v6}"
        );
        assert!(c.contains("vrrp_sync_group PATRONUS"));
        assert!(c.contains(&format!("notify {NOTIFY_SCRIPT}")));
        assert!(!c.contains("nopreempt"));
        assert_eq!(
            c,
            render_keepalived(&settings_on(), &vips, "fw-1.lan", &track, &local).unwrap(),
            "same input, same file"
        );
    }

    #[test]
    fn maintenance_mode_and_nopreempt_change_the_advert() {
        let vips = [rv("gw", "eth1", "192.168.50.254/24", 51)];
        let mut s = settings_on();
        s.peer = None;
        s.maintenance = true;
        s.preempt = false;
        let c = render_keepalived(&s, &vips, "x", &[], &|_, _| None).unwrap();
        assert!(
            c.contains(&format!("priority {MAINTENANCE_PRIORITY}")),
            "{c}"
        );
        assert!(c.contains("nopreempt"));
        assert!(!c.contains("unicast_peer") && !c.contains("track_interface"));
        // unicast without a local address is an error, not a broken file
        let e = render_keepalived(&settings_on(), &vips, "x", &[], &|_, _| None).unwrap_err();
        assert!(e.to_string().contains("no IPv4 address"), "{e}");
    }

    #[test]
    fn conntrackd_and_notify_content() {
        let c = render_conntrackd("10.9.9.1".parse().unwrap(), "10.9.9.2", "eth2");
        for want in [
            "Mode FTFW",
            "IPv4_address 10.9.9.1",
            "IPv4_Destination_Address 10.9.9.2",
            "Port 3780",
            "Interface eth2",
            "Filter From Userspace",
            "Managed by Patronus",
        ] {
            assert!(c.contains(want), "{want}: {c}");
        }
        let n = render_notify();
        assert!(
            n.starts_with("#!/bin/sh")
                && n.contains(" -c; ")
                && n.contains("-B")
                && n.contains("-n"),
            "{n}"
        );
        assert!(n.contains("/run/patronus"));
    }

    #[test]
    fn addresses_names_passwords_and_settings_are_validated() {
        assert_eq!(
            check_vip_address("192.168.50.254/24").unwrap(),
            "192.168.50.254/24"
        );
        assert_eq!(check_vip_address(" fd00::1/64 ").unwrap(), "fd00::1/64");
        for bad in [
            "192.168.50.254",
            "0.0.0.0/24",
            "192.168.50.0/24",
            "127.0.0.1/8",
            "224.0.0.1/24",
            "fe80::1/64",
            "x/24",
            "10.0.0.1/0",
            "",
        ] {
            assert!(
                check_vip_address(bad)
                    .unwrap_err()
                    .to_string()
                    .contains("Invalid"),
                "{bad}"
            );
        }
        assert!(check_vip_name("lan-gw.1").is_ok());
        assert!(check_vip_name("a b").is_err() && check_vip_name("").is_err());
        assert!(check_password("abc12345").is_ok());
        assert!(
            check_password("123456789").is_err()
                && check_password("a b").is_err()
                && check_password("").is_err()
        );
    }

    fn vip_in(name: &str, addr: &str) -> VipInput {
        VipInput {
            name: Some(name.into()),
            interface: Some("@lan".into()),
            address: Some(addr.into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn vips_and_settings_round_trip_through_the_store() {
        let s = testutil::store().await;
        let id = save_vip(&s, None, &vip_in("lan-gw", "192.168.50.254/24"))
            .await
            .unwrap();
        let v = list_vips(&s).await.unwrap();
        assert_eq!(
            (v[0].vrid, v[0].mode.as_str(), v[0].enabled),
            (51, "carp", true)
        );
        for (inp, why) in [
            (vip_in("lan-gw", "192.168.50.2/24"), "already exists"),
            (vip_in("other", "192.168.50.254/24"), "already configured"),
            (
                VipInput {
                    mode: Some("weird".into()),
                    ..vip_in("o2", "192.168.50.9/24")
                },
                "carp or alias",
            ),
            (
                VipInput {
                    vrid: Some(0),
                    ..vip_in("o3", "192.168.50.9/24")
                },
                "VRID",
            ),
        ] {
            let e = save_vip(&s, None, &inp).await.unwrap_err().to_string();
            assert!(e.contains("Invalid") && e.contains(why), "{e}");
        }
        save_vip(
            &s,
            Some(id),
            &VipInput {
                vrid: Some(60),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(list_vips(&s).await.unwrap()[0].vrid, 60);

        assert_eq!(settings(&s).await.unwrap(), Settings::default());
        let e = save_settings(
            &s,
            &SettingsInput {
                sync: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("sync interface"), "{e}");
        let st = save_settings(
            &s,
            &SettingsInput {
                enabled: Some(true),
                priority: Some(200),
                peer: Some("192.168.50.3".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            st.enabled && st.priority == 200 && st.password.len() == 8,
            "{st:?}"
        );
        assert_eq!(settings(&s).await.unwrap(), st);
        for bad in [
            SettingsInput {
                priority: Some(255),
                ..Default::default()
            },
            SettingsInput {
                peer: Some("not-an-ip".into()),
                ..Default::default()
            },
        ] {
            assert!(save_settings(&s, &bad).await.is_err());
        }
        delete_vip(&s, id).await.unwrap();
        assert!(delete_vip(&s, id).await.is_err());
    }

    fn log(t: &testutil::TestEnv) -> Vec<String> {
        t.services.log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn apply_writes_the_files_starts_the_daemons_and_turns_off_cleanly() {
        let t = testutil::env(&["usr/sbin/keepalived", "usr/sbin/conntrackd"]);
        let a = HaApplier::new(t.env.clone());
        let s = testutil::store().await;
        // off: nothing happens
        let r = a.apply(&s).await.unwrap();
        assert!(r.applied[0].contains("off"), "{r:?}");
        assert!(!t.env.path(KEEPALIVED_CONF).exists());

        save_vip(&s, None, &vip_in("gw", "192.168.50.254/24"))
            .await
            .unwrap();
        save_settings(
            &s,
            &SettingsInput {
                enabled: Some(true),
                priority: Some(150),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let r = a.apply(&s).await.unwrap();
        let ka = testutil::read(&t, KEEPALIVED_CONF);
        assert!(
            ka.contains("192.168.50.254/24 dev rtr-lan") && ka.contains("priority 150"),
            "{ka}"
        );
        assert!(
            ka.contains("track_interface") && ka.contains("rtr-wan"),
            "{ka}"
        );
        assert!(testutil::read(&t, NOTIFY_SCRIPT).contains("conntrackd"));
        assert!(
            !t.env.path(CONNTRACKD_CONF).exists(),
            "no sync: no conntrackd file"
        );
        assert!(
            log(&t).iter().any(|l| l == "restart keepalived"),
            "{:?} {r:?}",
            log(&t)
        );
        assert!(!log(&t).iter().any(|l| l.contains("conntrackd")));

        // idempotent
        let before = log(&t).len();
        a.apply(&s).await.unwrap();
        assert_eq!(log(&t).len(), before, "second apply: {:?}", log(&t));

        // state sync on an interface without an address is refused, files stay
        save_settings(
            &s,
            &SettingsInput {
                sync: Some(true),
                sync_interface: Some("eth9".into()),
                sync_peer: Some("10.9.9.2".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("no IPv4 address"), "{e}");
        assert!(testutil::read(&t, KEEPALIVED_CONF).contains("priority 150"));
        // on a real one: conntrackd file + service, keepalived reloaded or restarted
        save_settings(
            &s,
            &SettingsInput {
                sync_interface: Some("rtr-opt1".into()),
                sync_peer: Some("192.168.60.2".into()),
                priority: Some(160),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let ct = testutil::read(&t, CONNTRACKD_CONF);
        assert!(
            ct.contains("IPv4_address 192.168.60.1")
                && ct.contains("IPv4_Destination_Address 192.168.60.2")
                && ct.contains("Interface rtr-opt1"),
            "{ct}"
        );
        assert!(
            log(&t).iter().any(|l| l == "restart conntrackd"),
            "{:?}",
            log(&t)
        );
        assert!(testutil::read(&t, KEEPALIVED_CONF).contains("priority 160"));
        assert!(
            log(&t)
                .iter()
                .filter(|l| *l == "restart keepalived")
                .count()
                == 2,
            "a running keepalived without a pidfile is restarted: {:?}",
            log(&t)
        );

        // off again: files rewritten idle, daemons stopped
        save_settings(
            &s,
            &SettingsInput {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!testutil::read(&t, KEEPALIVED_CONF).contains("192.168.50.254"));
        assert!(!testutil::read(&t, CONNTRACKD_CONF).contains("Mode FTFW"));
        assert!(
            log(&t).iter().any(|l| l == "stop keepalived"),
            "{:?}",
            log(&t)
        );
        assert!(
            log(&t).iter().any(|l| l == "stop conntrackd"),
            "{:?}",
            log(&t)
        );
    }

    #[tokio::test]
    async fn a_missing_keepalived_is_a_clear_error_and_a_foreign_config_is_left_alone() {
        let t = testutil::env(&[]);
        let a = HaApplier::new(t.env.clone());
        let s = testutil::store().await;
        save_vip(&s, None, &vip_in("gw", "192.168.50.254/24"))
            .await
            .unwrap();
        save_settings(
            &s,
            &SettingsInput {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("keepalived") && e.contains("emerge"), "{e}");
        // a hand-written keepalived.conf (no marker) survives HA being off
        let t2 = testutil::env(&["usr/sbin/keepalived"]);
        let p = t2.env.path(KEEPALIVED_CONF);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "! mine\n").unwrap();
        HaApplier::new(t2.env.clone())
            .apply(&testutil::store().await)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "! mine\n");
    }

    #[tokio::test]
    async fn status_reports_state_and_which_vips_are_on_this_node() {
        let t = testutil::env(&["usr/sbin/keepalived"]);
        let a = HaApplier::new(t.env.clone());
        let s = testutil::store().await;
        save_vip(&s, None, &vip_in("gw", "192.168.50.254/24"))
            .await
            .unwrap();
        save_vip(
            &s,
            None,
            &VipInput {
                mode: Some("alias".into()),
                ..vip_in("on-lan", "192.168.50.1/24")
            },
        )
        .await
        .unwrap();
        save_settings(
            &s,
            &SettingsInput {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let st = a.status(&s).await.unwrap();
        assert_eq!(st["enabled"], true);
        assert_eq!(
            st["state"],
            Value::Null,
            "no notify yet: state unknown, not invented"
        );
        let by = |n: &str| {
            st["vips"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == n)
                .unwrap()
                .clone()
        };
        assert_eq!(by("gw")["present"], false);
        assert_eq!(
            by("on-lan")["present"],
            true,
            "192.168.50.1 is on rtr-lan in the test env"
        );
        assert_eq!(by("on-lan")["mode"], "alias");
        std::fs::create_dir_all(t.env.path("/run/patronus")).unwrap();
        std::fs::write(t.env.path(STATE_FILE), "MASTER 1700000000\n").unwrap();
        let st = a.status(&s).await.unwrap();
        assert_eq!(st["state"], "MASTER");
        assert_eq!(st["since"], 1700000000);
    }
}
