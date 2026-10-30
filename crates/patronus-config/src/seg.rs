//! Device segmentation model (docs/design/device-segmentation.md, lane `s`):
//! device groups, enrolled devices, group links, one-way service rules and the
//! per-segment opt-in switch, plus the adoption step that makes turning
//! isolation on a no-op on day one.
//!
//! Pure store accessors: rendering lives in `patronus-firewall/src/seg_rules.rs`
//! (nft) and `patronus-network/src/seg.rs` (sysctls, bridge ports); the
//! web adapter (`patronus-web/src/state/segmentation.rs`) wraps every
//! mutation in snapshot -> write -> apply -> undo-on-failure.
//!
//! A *segment* is a role token (`@lan`, `@opt1`) or an interface name, like the
//! `interface` columns of the LAN-service tables; it is resolved to devices at
//! render time.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub const GROUP_HOME: &str = "home";
pub const GROUP_QUARANTINE: &str = "quarantine";

pub(crate) fn invalid(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {m}"))
}
pub(crate) fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}
pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub(crate) fn unique(e: sqlx::Error, what: &str) -> Error {
    if e.to_string().contains("UNIQUE") {
        invalid(format!("request: {what} already exists"))
    } else {
        Error::Config(format!("store: {e}"))
    }
}

// ---------------------------------------------------------------------------
// validation (shared with the nft renderer: nothing unvalidated reaches a script)
// ---------------------------------------------------------------------------

/// Group / device / service name: `[a-z0-9_-]{1,32}`.
pub fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Normalise a MAC address to lower-case `aa:bb:cc:dd:ee:ff`.
pub fn norm_mac(s: &str) -> Result<String> {
    let p: Vec<&str> = s.trim().split(':').collect();
    if p.len() != 6
        || p.iter()
            .any(|x| x.len() != 2 || !x.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(invalid(format!("MAC address {s:?}")));
    }
    let m = p.join(":").to_ascii_lowercase();
    if m == "00:00:00:00:00:00" || m == "ff:ff:ff:ff:ff:ff" {
        return Err(invalid(format!("MAC address {s:?}")));
    }
    // multicast bit set: never a station address
    if u8::from_str_radix(&m[0..2], 16).unwrap_or(1) & 1 == 1 {
        return Err(invalid(format!(
            "MAC address {s:?}: group/multicast address"
        )));
    }
    Ok(m)
}

/// Linux interface name as nft and `ip` accept it.
pub fn is_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A segment spec: `@role` or an interface name.
pub fn check_segment(s: &str) -> Result<String> {
    let t = s.trim();
    let body = t.strip_prefix('@').unwrap_or(t);
    if body.is_empty() || !is_ifname(body) || (t.starts_with('@') && body.contains('.')) {
        return Err(invalid(format!("segment {s:?}")));
    }
    Ok(if t.starts_with('@') {
        format!("@{}", body.to_ascii_lowercase())
    } else {
        t.to_string()
    })
}

pub(crate) fn check_v4(what: &str, s: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = s
        .trim()
        .parse()
        .map_err(|_| invalid(format!("{what} {s:?}")))?;
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        return Err(invalid(format!("{what} {s:?}")));
    }
    Ok(ip)
}

/// "80,443,8000-8010" -> normalised string; every port 1..=65535, at most 32 items.
pub fn check_ports(s: &str) -> Result<String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        let (a, b) = match p.split_once('-') {
            Some((a, b)) => (a, Some(b)),
            None => (p, None),
        };
        let lo: u16 = a.parse().map_err(|_| invalid(format!("ports {s:?}")))?;
        if lo == 0 {
            return Err(invalid(format!("ports {s:?}")));
        }
        match b {
            None => out.push(lo.to_string()),
            Some(b) => {
                let hi: u16 = b.parse().map_err(|_| invalid(format!("ports {s:?}")))?;
                if hi < lo {
                    return Err(invalid(format!("ports {s:?}")));
                }
                out.push(format!("{lo}-{hi}"));
            }
        }
    }
    if out.is_empty() || out.len() > 32 {
        return Err(invalid(format!("ports {s:?}")));
    }
    Ok(out.join(","))
}

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub intra: bool,
    /// `allow` | `deny`
    pub internet: String,
    pub quarantine: bool,
    pub builtin: bool,
    pub members: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "yes")]
    pub intra: bool,
    #[serde(default = "allow")]
    pub internet: String,
    #[serde(default)]
    pub quarantine: bool,
}
fn yes() -> bool {
    true
}
fn allow() -> String {
    "allow".into()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub mac: Option<String>,
    pub group_id: i64,
    pub group: String,
    /// wifi | wired | vpn
    pub kind: String,
    pub segment: String,
    pub ip4: Option<String>,
    /// pending | active | revoked
    pub state: String,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_seen: Option<i64>,
    pub last_ip: Option<String>,
    pub note: Option<String>,
    pub dhcp_mapping_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DeviceInput {
    pub name: String,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub segment: Option<String>,
    #[serde(default)]
    pub ip4: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Link {
    pub id: i64,
    pub group_a: i64,
    pub group_b: i64,
    pub a: String,
    pub b: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Service {
    pub id: i64,
    pub name: String,
    pub src_kind: String,
    pub src_id: i64,
    pub dst_kind: String,
    pub dst_id: i64,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub ports: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServiceInput {
    pub name: String,
    /// `device:<name>` or `group:<name>`
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub ports: String,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Segment {
    pub segment: String,
    pub enabled: bool,
    pub adopted_at: Option<i64>,
}

/// A host seen on the network (DHCP lease, ARP/neighbour table) that is not
/// necessarily a device yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Discovered {
    pub mac: String,
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AdoptReport {
    pub adopted: Vec<String>,
    pub skipped: Vec<String>,
}

// ---------------------------------------------------------------------------
// groups
// ---------------------------------------------------------------------------

fn group_row(r: &sqlx::sqlite::SqliteRow) -> Group {
    Group {
        id: r.get("id"),
        name: r.get("name"),
        description: r.get("description"),
        intra: r.get::<i64, _>("intra") != 0,
        internet: r.get("internet"),
        quarantine: r.get::<i64, _>("quarantine") != 0,
        builtin: r.get::<i64, _>("builtin") != 0,
        members: r.get("members"),
    }
}

const GROUP_SELECT: &str = "SELECT g.*, (SELECT COUNT(*) FROM seg_devices d WHERE d.group_id = g.id AND d.state != 'revoked') AS members FROM seg_groups g";

/// The built-in groups exist even after a factory reset emptied the tables.
pub async fn ensure_builtin(store: &ConfigStore) -> Result<()> {
    for (name, desc, intra, internet, q) in [
        (
            GROUP_HOME,
            "Devices that were on the network when segmentation was enabled",
            1,
            "allow",
            0,
        ),
        (
            GROUP_QUARANTINE,
            "Unknown devices: DHCP, DNS and ping only",
            0,
            "deny",
            1,
        ),
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO seg_groups (name, description, intra, internet, quarantine, builtin)
             VALUES (?,?,?,?,?,1)",
        )
        .bind(name)
        .bind(desc)
        .bind(intra)
        .bind(internet)
        .bind(q)
        .execute(store.pool()?)
        .await
        .map_err(db("seed built-in groups"))?;
    }
    Ok(())
}

pub async fn list_groups(store: &ConfigStore) -> Result<Vec<Group>> {
    ensure_builtin(store).await?;
    let rows = sqlx::query(&format!("{GROUP_SELECT} ORDER BY g.builtin DESC, g.name"))
        .fetch_all(store.pool()?)
        .await
        .map_err(db("list groups"))?;
    Ok(rows.iter().map(group_row).collect())
}

pub async fn get_group(store: &ConfigStore, id: i64) -> Result<Option<Group>> {
    let r = sqlx::query(&format!("{GROUP_SELECT} WHERE g.id = ?"))
        .bind(id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read group"))?;
    Ok(r.as_ref().map(group_row))
}

pub async fn group_by_name(store: &ConfigStore, name: &str) -> Result<Option<Group>> {
    let r = sqlx::query(&format!("{GROUP_SELECT} WHERE g.name = ?"))
        .bind(name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read group"))?;
    Ok(r.as_ref().map(group_row))
}

fn check_group(i: &GroupInput) -> Result<()> {
    if !is_name(&i.name) {
        return Err(invalid(format!(
            "group name {:?}: use a-z 0-9 _ - (max 32)",
            i.name
        )));
    }
    if i.internet != "allow" && i.internet != "deny" {
        return Err(invalid("group internet policy: allow or deny"));
    }
    if let Some(d) = &i.description {
        if d.len() > 200 || d.chars().any(|c| c.is_control()) {
            return Err(invalid("group description"));
        }
    }
    Ok(())
}

pub async fn create_group(store: &ConfigStore, i: &GroupInput) -> Result<i64> {
    check_group(i)?;
    let r = sqlx::query(
        "INSERT INTO seg_groups (name, description, intra, internet, quarantine, builtin)
         VALUES (?,?,?,?,?,0)",
    )
    .bind(&i.name)
    .bind(&i.description)
    .bind(i.intra as i64)
    .bind(&i.internet)
    .bind(i.quarantine as i64)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("group {}", i.name)))?;
    Ok(r.last_insert_rowid())
}

pub async fn update_group(store: &ConfigStore, id: i64, i: &GroupInput) -> Result<()> {
    check_group(i)?;
    let g = get_group(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no group {id}")))?;
    if g.builtin && (g.name != i.name || g.quarantine != i.quarantine) {
        return Err(invalid(format!(
            "change: the built-in group {} cannot be renamed or lose its quarantine flag",
            g.name
        )));
    }
    sqlx::query(
        "UPDATE seg_groups SET name=?, description=?, intra=?, internet=?, quarantine=? WHERE id=?",
    )
    .bind(&i.name)
    .bind(&i.description)
    .bind(i.intra as i64)
    .bind(&i.internet)
    .bind(i.quarantine as i64)
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("group {}", i.name)))?;
    Ok(())
}

pub async fn delete_group(store: &ConfigStore, id: i64) -> Result<()> {
    let g = get_group(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no group {id}")))?;
    if g.builtin {
        return Err(invalid(format!("delete: {} is a built-in group", g.name)));
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM seg_devices WHERE group_id = ?")
        .bind(id)
        .fetch_one(store.pool()?)
        .await
        .map_err(db("count members"))?;
    if n > 0 {
        return Err(invalid(format!(
            "delete: group {} still has {n} device(s); move them first",
            g.name
        )));
    }
    sqlx::query("DELETE FROM seg_services WHERE (src_kind='group' AND src_id=?) OR (dst_kind='group' AND dst_id=?)")
        .bind(id)
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete group services"))?;
    sqlx::query("DELETE FROM seg_groups WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete group"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// segments (the per-interface opt-in)
// ---------------------------------------------------------------------------

pub async fn list_segments(store: &ConfigStore) -> Result<Vec<Segment>> {
    let rows =
        sqlx::query("SELECT segment, enabled, adopted_at FROM seg_segments ORDER BY segment")
            .fetch_all(store.pool()?)
            .await
            .map_err(db("list segments"))?;
    Ok(rows
        .iter()
        .map(|r| Segment {
            segment: r.get(0),
            enabled: r.get::<i64, _>(1) != 0,
            adopted_at: r.get(2),
        })
        .collect())
}

pub async fn set_segment_enabled(store: &ConfigStore, segment: &str, on: bool) -> Result<()> {
    let seg = check_segment(segment)?;
    sqlx::query(
        "INSERT INTO seg_segments (segment, enabled, adopted_at, updated_at) VALUES (?,?,NULL,?)
         ON CONFLICT(segment) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
    )
    .bind(&seg)
    .bind(on as i64)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db("set segment"))?;
    Ok(())
}

async fn mark_adopted(store: &ConfigStore, segment: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO seg_segments (segment, enabled, adopted_at, updated_at) VALUES (?,0,?,?)
         ON CONFLICT(segment) DO UPDATE SET adopted_at = excluded.adopted_at",
    )
    .bind(segment)
    .bind(now())
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db("mark adopted"))?;
    Ok(())
}

/// Interfaces a segment spec stands for (`@lan` -> the interfaces with that role).
pub async fn resolve_segment(store: &ConfigStore, spec: &str) -> Result<Vec<String>> {
    Ok(match spec.strip_prefix('@') {
        Some(role) => store
            .interfaces_with_role(&role.to_ascii_lowercase())
            .await?
            .into_iter()
            .filter(|d| is_ifname(d))
            .collect(),
        None => vec![spec.to_string()],
    })
}

/// An IPv4 network of a segment: its prefix, and the router's own addresses on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    pub net: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Self {
            net: Ipv4Addr::from(u32::from(addr) & mask),
            prefix,
        }
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        u32::from(ip) & mask == u32::from(self.net)
    }
    pub fn broadcast(&self) -> Ipv4Addr {
        let host = if self.prefix >= 32 {
            0
        } else {
            u32::MAX >> self.prefix
        };
        Ipv4Addr::from(u32::from(self.net) | host)
    }
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.net, self.prefix)
    }
}

/// IPv4 subnets configured on the interfaces of a segment, plus the router's
/// own addresses there.
pub async fn segment_v4(store: &ConfigStore, spec: &str) -> Result<(Vec<Subnet>, Vec<Ipv4Addr>)> {
    let mut nets = Vec::new();
    let mut own = Vec::new();
    for dev in resolve_segment(store, spec).await? {
        let rows = sqlx::query(
            "SELECT address, prefix_len FROM interface_addresses WHERE interface_name = ? AND family = 'ipv4' ORDER BY address",
        )
        .bind(&dev)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("read interface addresses"))?;
        for r in rows {
            let a: String = r.get(0);
            let p: i64 = r.get(1);
            if let (Ok(ip), true) = (a.parse::<Ipv4Addr>(), (1..=30).contains(&p)) {
                let s = Subnet::new(ip, p as u8);
                if !nets.contains(&s) {
                    nets.push(s);
                }
                own.push(ip);
            }
        }
    }
    Ok((nets, own))
}

// ---------------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------------

const DEVICE_SELECT: &str = "SELECT d.id, d.name, d.mac, d.group_id, g.name AS gname, d.kind, d.segment, d.ip4, d.state, d.created_at, d.activated_at, d.revoked_at, d.last_seen, d.last_ip, d.note, d.dhcp_mapping_id FROM seg_devices d JOIN seg_groups g ON g.id = d.group_id";

fn device_row(r: &sqlx::sqlite::SqliteRow) -> Device {
    Device {
        id: r.get("id"),
        name: r.get("name"),
        mac: r.get("mac"),
        group_id: r.get("group_id"),
        group: r.get("gname"),
        kind: r.get("kind"),
        segment: r.get("segment"),
        ip4: r.get("ip4"),
        state: r.get("state"),
        created_at: r.get("created_at"),
        activated_at: r.get("activated_at"),
        revoked_at: r.get("revoked_at"),
        last_seen: r.get("last_seen"),
        last_ip: r.get("last_ip"),
        note: r.get("note"),
        dhcp_mapping_id: r.get("dhcp_mapping_id"),
    }
}

pub async fn list_devices(store: &ConfigStore) -> Result<Vec<Device>> {
    let rows = sqlx::query(&format!("{DEVICE_SELECT} ORDER BY d.name"))
        .fetch_all(store.pool()?)
        .await
        .map_err(db("list devices"))?;
    Ok(rows.iter().map(device_row).collect())
}

pub async fn get_device(store: &ConfigStore, id: i64) -> Result<Option<Device>> {
    let r = sqlx::query(&format!("{DEVICE_SELECT} WHERE d.id = ?"))
        .bind(id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read device"))?;
    Ok(r.as_ref().map(device_row))
}

pub async fn device_by_mac(store: &ConfigStore, mac: &str) -> Result<Option<Device>> {
    let r = sqlx::query(&format!("{DEVICE_SELECT} WHERE d.mac = ?"))
        .bind(mac.to_ascii_lowercase())
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read device"))?;
    Ok(r.as_ref().map(device_row))
}

/// The DHCP pool serving a segment, if any: (pool id, range start, range end).
async fn pool_for(store: &ConfigStore, segment: &str) -> Result<Option<(i64, Ipv4Addr, Ipv4Addr)>> {
    let want = resolve_segment(store, segment).await?;
    let rows =
        sqlx::query("SELECT id, interface, range_start, range_end FROM dhcp_pools ORDER BY id")
            .fetch_all(store.pool()?)
            .await
            .map_err(db("read dhcp pools"))?;
    for r in rows {
        let iface: String = r.get(1);
        let have = resolve_segment(store, &iface).await?;
        if have.iter().any(|h| want.contains(h)) {
            let (Ok(a), Ok(b)) = (
                r.get::<String, _>(2).parse::<Ipv4Addr>(),
                r.get::<String, _>(3).parse::<Ipv4Addr>(),
            ) else {
                continue;
            };
            return Ok(Some((r.get(0), a, b)));
        }
    }
    Ok(None)
}

async fn taken_ips(store: &ConfigStore) -> Result<BTreeSet<Ipv4Addr>> {
    let mut s = BTreeSet::new();
    for q in [
        "SELECT ip4 FROM seg_devices WHERE ip4 IS NOT NULL",
        "SELECT ip FROM dhcp_static_mappings",
    ] {
        for r in sqlx::query(q)
            .fetch_all(store.pool()?)
            .await
            .map_err(db("read addresses"))?
        {
            if let Ok(ip) = r.get::<String, _>(0).parse() {
                s.insert(ip);
            }
        }
    }
    Ok(s)
}

/// A free address for a new device on `segment`: inside the segment's
/// subnet, outside the dynamic DHCP range, not the router's, not another
/// device's or reservation's.
pub async fn allocate_ip(store: &ConfigStore, segment: &str) -> Result<Ipv4Addr> {
    let (nets, own) = segment_v4(store, segment).await?;
    let net = nets.first().ok_or_else(|| {
        invalid(format!(
            "segment {segment}: no IPv4 address configured on it"
        ))
    })?;
    let pool = pool_for(store, segment).await?;
    let taken = taken_ips(store).await?;
    let lo = u32::from(net.net) + 1;
    let hi = u32::from(net.broadcast()) - 1;
    for n in lo..=hi {
        let ip = Ipv4Addr::from(n);
        if own.contains(&ip) || taken.contains(&ip) {
            continue;
        }
        if let Some((_, a, b)) = pool {
            if (u32::from(a)..=u32::from(b)).contains(&n) {
                continue;
            }
        }
        return Ok(ip);
    }
    Err(invalid(format!(
        "segment {segment}: no free address left outside the DHCP range"
    )))
}

fn host_label(name: &str) -> Option<String> {
    let h: String = name.replace('_', "-");
    (!h.is_empty() && !h.starts_with('-') && !h.ends_with('-')).then_some(h)
}

/// Create (or replace) the DHCP reservation that keeps a device's address stable.
async fn reserve(
    store: &ConfigStore,
    segment: &str,
    name: &str,
    mac: &str,
    ip: Ipv4Addr,
) -> Result<Option<i64>> {
    let Some((pool, _, _)) = pool_for(store, segment).await? else {
        return Ok(None);
    };
    sqlx::query("DELETE FROM dhcp_static_mappings WHERE pool_id = ? AND (mac = ? OR ip = ?)")
        .bind(pool)
        .bind(mac)
        .bind(ip.to_string())
        .execute(store.pool()?)
        .await
        .map_err(db("replace reservation"))?;
    let r = sqlx::query(
        "INSERT INTO dhcp_static_mappings (pool_id, mac, ip, hostname, description, updated_at)
         VALUES (?,?,?,?,?,?)",
    )
    .bind(pool)
    .bind(mac)
    .bind(ip.to_string())
    .bind(host_label(name))
    .bind(format!("segmentation device {name}"))
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db("create reservation"))?;
    Ok(Some(r.last_insert_rowid()))
}

fn check_kind(k: &str) -> Result<()> {
    if matches!(k, "wifi" | "wired" | "vpn") {
        Ok(())
    } else {
        Err(invalid(format!("device kind {k:?}: wifi, wired or vpn")))
    }
}

/// Create a device. With a MAC it is `active` at once (address allocated and
/// reserved when none is given); without one (a Wi-Fi device that has not
/// joined yet) it is `pending` and not bound anywhere.
pub async fn create_device(store: &ConfigStore, i: &DeviceInput) -> Result<Device> {
    if !is_name(&i.name) {
        return Err(invalid(format!(
            "device name {:?}: use a-z 0-9 _ - (max 32)",
            i.name
        )));
    }
    let kind = i.kind.clone().unwrap_or_else(|| "wired".into());
    check_kind(&kind)?;
    let segment = check_segment(i.segment.as_deref().unwrap_or("@lan"))?;
    let gname = i.group.clone().unwrap_or_else(|| GROUP_HOME.into());
    ensure_builtin(store).await?;
    let g = group_by_name(store, &gname)
        .await?
        .ok_or_else(|| invalid(format!("group {gname:?}: no such group")))?;
    if let Some(n) = &i.note {
        if n.len() > 200 || n.chars().any(|c| c.is_control()) {
            return Err(invalid("note"));
        }
    }
    let mac = i
        .mac
        .as_deref()
        .filter(|m| !m.trim().is_empty())
        .map(norm_mac)
        .transpose()?;
    // re-enrolling a device whose old record was revoked: the MAC moves to the new record
    if let Some(m) = &mac {
        if let Some(old) = device_by_mac(store, m).await? {
            if old.state == "revoked" {
                sqlx::query("UPDATE seg_devices SET mac = NULL, ip4 = NULL WHERE id = ?")
                    .bind(old.id)
                    .execute(store.pool()?)
                    .await
                    .map_err(db("release the MAC of a revoked device"))?;
            }
        }
    }
    let (state, ip, mapping) = match &mac {
        None => {
            if kind != "wifi" {
                return Err(invalid(
                    "device: a MAC address is required (only Wi-Fi devices may be pending)",
                ));
            }
            ("pending", None, None)
        }
        Some(m) => {
            let ip = match i.ip4.as_deref().filter(|s| !s.trim().is_empty()) {
                Some(s) => check_v4("IPv4 address", s)?,
                None => allocate_ip(store, &segment).await?,
            };
            let (nets, own) = segment_v4(store, &segment).await?;
            if !nets.is_empty() && !nets.iter().any(|n| n.contains(ip)) {
                return Err(invalid(format!(
                    "IPv4 address {ip}: not inside the segment's subnet"
                )));
            }
            if own.contains(&ip) || nets.iter().any(|n| n.broadcast() == ip || n.net == ip) {
                return Err(invalid(format!(
                    "IPv4 address {ip}: reserved on this segment"
                )));
            }
            let mapping = reserve(store, &segment, &i.name, m, ip).await?;
            ("active", Some(ip), mapping)
        }
    };
    let t = now();
    let r = sqlx::query(
        "INSERT INTO seg_devices (name, mac, group_id, kind, segment, ip4, state, dhcp_mapping_id, created_at, activated_at, note)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&i.name)
    .bind(&mac)
    .bind(g.id)
    .bind(&kind)
    .bind(&segment)
    .bind(ip.map(|a| a.to_string()))
    .bind(state)
    .bind(mapping)
    .bind(t)
    .bind((state == "active").then_some(t))
    .bind(&i.note)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("device with that name, MAC or address ({})", i.name)))?;
    get_device(store, r.last_insert_rowid())
        .await?
        .ok_or_else(|| Error::Config("device vanished after insert".into()))
}

/// Change a device's name, group or note (address/MAC/segment are identity).
pub async fn update_device(
    store: &ConfigStore,
    id: i64,
    name: Option<&str>,
    group: Option<&str>,
    note: Option<&str>,
) -> Result<Device> {
    let d = get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no device {id}")))?;
    if d.state == "revoked" && group.is_some() {
        return Err(invalid(
            "change: a revoked device cannot be moved; delete or re-create it",
        ));
    }
    let name = name.unwrap_or(&d.name);
    if !is_name(name) {
        return Err(invalid(format!("device name {name:?}")));
    }
    let gid = match group {
        Some(g) => {
            group_by_name(store, g)
                .await?
                .ok_or_else(|| invalid(format!("group {g:?}: no such group")))?
                .id
        }
        None => d.group_id,
    };
    if let Some(n) = note {
        if n.len() > 200 || n.chars().any(|c| c.is_control()) {
            return Err(invalid("note"));
        }
    }
    sqlx::query("UPDATE seg_devices SET name=?, group_id=?, note=? WHERE id=?")
        .bind(name)
        .bind(gid)
        .bind(note.map(str::to_string).or(d.note.clone()))
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(|e| unique(e, &format!("device {name}")))?;
    get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config("device vanished".into()))
}

/// Revoke: the device keeps its row (history) but loses its binding and reservation.
pub async fn revoke_device(store: &ConfigStore, id: i64) -> Result<Device> {
    let d = get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no device {id}")))?;
    if let Some(m) = d.dhcp_mapping_id {
        sqlx::query("DELETE FROM dhcp_static_mappings WHERE id = ?")
            .bind(m)
            .execute(store.pool()?)
            .await
            .map_err(db("drop reservation"))?;
    }
    // its Wi-Fi passphrases go with it (WPA2 entries leave the PSK file at the next apply)
    sqlx::query(
        "UPDATE seg_wifi_creds SET state='revoked', revoked_at=? WHERE device_id=? AND state != 'revoked'",
    )
    .bind(now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(db("revoke Wi-Fi credentials"))?;
    sqlx::query(
        "UPDATE seg_devices SET state='revoked', revoked_at=?, dhcp_mapping_id=NULL, last_ip=COALESCE(ip4, last_ip), ip4=NULL WHERE id=?",
    )
    .bind(now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(db("revoke device"))?;
    get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config("device vanished".into()))
}

pub async fn delete_device(store: &ConfigStore, id: i64) -> Result<()> {
    let d = get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no device {id}")))?;
    if let Some(m) = d.dhcp_mapping_id {
        sqlx::query("DELETE FROM dhcp_static_mappings WHERE id = ?")
            .bind(m)
            .execute(store.pool()?)
            .await
            .map_err(db("drop reservation"))?;
    }
    sqlx::query("DELETE FROM seg_services WHERE (src_kind='device' AND src_id=?) OR (dst_kind='device' AND dst_id=?)")
        .bind(id)
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete device services"))?;
    sqlx::query("DELETE FROM seg_devices WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete device"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// links and one-way service rules
// ---------------------------------------------------------------------------

pub async fn list_links(store: &ConfigStore) -> Result<Vec<Link>> {
    let rows = sqlx::query(
        "SELECT l.id, l.group_a, l.group_b, a.name, b.name FROM seg_links l
         JOIN seg_groups a ON a.id = l.group_a JOIN seg_groups b ON b.id = l.group_b ORDER BY a.name, b.name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list links"))?;
    Ok(rows
        .iter()
        .map(|r| Link {
            id: r.get(0),
            group_a: r.get(1),
            group_b: r.get(2),
            a: r.get(3),
            b: r.get(4),
        })
        .collect())
}

pub async fn add_link(store: &ConfigStore, a: &str, b: &str) -> Result<i64> {
    let ga = group_by_name(store, a)
        .await?
        .ok_or_else(|| invalid(format!("group {a:?}: no such group")))?;
    let gb = group_by_name(store, b)
        .await?
        .ok_or_else(|| invalid(format!("group {b:?}: no such group")))?;
    if ga.id == gb.id {
        return Err(invalid(
            "link: a group is linked to itself through its 'intra' switch",
        ));
    }
    if ga.quarantine || gb.quarantine {
        return Err(invalid("link: a quarantine group cannot be linked"));
    }
    let (lo, hi) = (ga.id.min(gb.id), ga.id.max(gb.id));
    let r = sqlx::query("INSERT INTO seg_links (group_a, group_b) VALUES (?,?)")
        .bind(lo)
        .bind(hi)
        .execute(store.pool()?)
        .await
        .map_err(|e| unique(e, &format!("link {a} - {b}")))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_link(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM seg_links WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete link"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no link {id}")));
    }
    Ok(())
}

async fn endpoint(store: &ConfigStore, spec: &str) -> Result<(String, i64)> {
    let (kind, name) = spec.split_once(':').ok_or_else(|| {
        invalid(format!(
            "endpoint {spec:?}: use device:<name> or group:<name>"
        ))
    })?;
    match kind {
        "group" => {
            let g = group_by_name(store, name)
                .await?
                .ok_or_else(|| invalid(format!("endpoint {spec:?}: no such group")))?;
            Ok(("group".into(), g.id))
        }
        "device" => {
            let r = sqlx::query("SELECT id FROM seg_devices WHERE name = ?")
                .bind(name)
                .fetch_optional(store.pool()?)
                .await
                .map_err(db("read device"))?
                .ok_or_else(|| invalid(format!("endpoint {spec:?}: no such device")))?;
            Ok(("device".into(), r.get(0)))
        }
        _ => Err(invalid(format!(
            "endpoint {spec:?}: use device:<name> or group:<name>"
        ))),
    }
}

pub async fn list_services(store: &ConfigStore) -> Result<Vec<Service>> {
    let rows = sqlx::query(
        "SELECT id, name, src_kind, src_id, dst_kind, dst_id, proto, ports, enabled,
           CASE src_kind WHEN 'group' THEN (SELECT name FROM seg_groups WHERE id = src_id) ELSE (SELECT name FROM seg_devices WHERE id = src_id) END,
           CASE dst_kind WHEN 'group' THEN (SELECT name FROM seg_groups WHERE id = dst_id) ELSE (SELECT name FROM seg_devices WHERE id = dst_id) END
         FROM seg_services ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list services"))?;
    Ok(rows
        .iter()
        .map(|r| Service {
            id: r.get(0),
            name: r.get(1),
            src_kind: r.get(2),
            src_id: r.get(3),
            dst_kind: r.get(4),
            dst_id: r.get(5),
            proto: r.get(6),
            ports: r.get(7),
            enabled: r.get::<i64, _>(8) != 0,
            src: format!(
                "{}:{}",
                r.get::<String, _>(2),
                r.get::<Option<String>, _>(9).unwrap_or_default()
            ),
            dst: format!(
                "{}:{}",
                r.get::<String, _>(4),
                r.get::<Option<String>, _>(10).unwrap_or_default()
            ),
        })
        .collect())
}

pub async fn add_service(store: &ConfigStore, i: &ServiceInput) -> Result<i64> {
    if !is_name(&i.name) {
        return Err(invalid(format!("service name {:?}", i.name)));
    }
    if i.proto != "tcp" && i.proto != "udp" {
        return Err(invalid("service protocol: tcp or udp"));
    }
    if i.schedule.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return Err(invalid(
            "service: schedules are not enforced yet, leave it empty",
        ));
    }
    let ports = check_ports(&i.ports)?;
    let (sk, si) = endpoint(store, &i.src).await?;
    let (dk, di) = endpoint(store, &i.dst).await?;
    if sk == dk && si == di {
        return Err(invalid("service: source and destination are the same"));
    }
    let r = sqlx::query(
        "INSERT INTO seg_services (name, src_kind, src_id, dst_kind, dst_id, proto, ports, enabled)
         VALUES (?,?,?,?,?,?,?,?)",
    )
    .bind(&i.name)
    .bind(sk)
    .bind(si)
    .bind(dk)
    .bind(di)
    .bind(&i.proto)
    .bind(ports)
    .bind(i.enabled as i64)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("service {}", i.name)))?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_service(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM seg_services WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete service"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no service {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// adoption: turning isolation on keeps every current device reachable
// ---------------------------------------------------------------------------

fn name_for(found: &Discovered, taken: &mut BTreeSet<String>) -> String {
    let mut base: String = found
        .hostname
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    base.truncate(24);
    let base = base.trim_matches('-').to_string();
    let suffix: String = found.mac.replace(':', "");
    let base = if base.is_empty() {
        format!("dev-{}", &suffix[suffix.len().saturating_sub(6)..])
    } else {
        base
    };
    let mut n = base.clone();
    let mut k = 2;
    while taken.contains(&n) {
        n = format!("{base}-{k}");
        k += 1;
    }
    taken.insert(n.clone());
    n
}

/// What adopting a host on one segment needs to know.
struct AdoptCtx<'a> {
    segment: &'a str,
    group: &'a str,
    nets: &'a [Subnet],
    own: &'a [Ipv4Addr],
}

async fn adopt_one(
    store: &ConfigStore,
    cx: &AdoptCtx<'_>,
    found: &Discovered,
    taken_names: &mut BTreeSet<String>,
    rep: &mut AdoptReport,
) -> Result<()> {
    let AdoptCtx {
        segment,
        group,
        nets,
        own,
    } = *cx;
    let mac = match norm_mac(&found.mac) {
        Ok(m) => m,
        Err(_) => {
            rep.skipped
                .push(format!("{}: not a station MAC", found.mac));
            return Ok(());
        }
    };
    let Ok(ip) = found.ip.parse::<Ipv4Addr>() else {
        rep.skipped.push(format!("{mac}: bad address {}", found.ip));
        return Ok(());
    };
    if own.contains(&ip) {
        return Ok(()); // the router itself
    }
    if !nets
        .iter()
        .any(|n| n.contains(ip) && n.net != ip && n.broadcast() != ip)
    {
        rep.skipped
            .push(format!("{mac} {ip}: outside the segment's subnet"));
        return Ok(());
    }
    if device_by_mac(store, &mac).await?.is_some() {
        return Ok(());
    }
    if taken_ips(store)
        .await
        .map(|t| t.contains(&ip))
        .unwrap_or(false)
    {
        // an address held by another device or a reservation of another MAC
        let held_by_mac: Option<String> =
            sqlx::query_scalar("SELECT mac FROM dhcp_static_mappings WHERE ip = ?")
                .bind(ip.to_string())
                .fetch_optional(store.pool()?)
                .await
                .map_err(db("read reservation"))?;
        let own_reservation = held_by_mac
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case(&mac));
        let dev_has: Option<i64> = sqlx::query_scalar("SELECT id FROM seg_devices WHERE ip4 = ?")
            .bind(ip.to_string())
            .fetch_optional(store.pool()?)
            .await
            .map_err(db("read device"))?;
        if dev_has.is_some() || !own_reservation {
            rep.skipped.push(format!(
                "{mac} {ip}: address already assigned to another device"
            ));
            return Ok(());
        }
    }
    let name = name_for(found, taken_names);
    let d = create_device(
        store,
        &DeviceInput {
            name: name.clone(),
            mac: Some(mac.clone()),
            group: Some(group.to_string()),
            kind: Some("wired".into()),
            segment: Some(segment.to_string()),
            ip4: Some(ip.to_string()),
            note: Some("adopted".into()),
        },
    )
    .await;
    match d {
        Ok(_) => rep.adopted.push(format!("{name} {mac} {ip}")),
        Err(e) => rep.skipped.push(format!("{mac} {ip}: {e}")),
    }
    Ok(())
}

/// Turn what is on `segment` into devices of `group` (default `home`):
/// existing DHCP reservations first, then the hosts in `found` (leases, ARP).
/// Idempotent: known MACs are left alone.
pub async fn adopt(
    store: &ConfigStore,
    segment: &str,
    found: &[Discovered],
    group: Option<&str>,
) -> Result<AdoptReport> {
    let segment = check_segment(segment)?;
    ensure_builtin(store).await?;
    let group = group.unwrap_or(GROUP_HOME);
    group_by_name(store, group)
        .await?
        .ok_or_else(|| invalid(format!("group {group:?}: no such group")))?;
    let (nets, own) = segment_v4(store, &segment).await?;
    if nets.is_empty() {
        return Err(invalid(format!(
            "segment {segment}: no IPv4 address configured on it"
        )));
    }
    let mut taken: BTreeSet<String> = list_devices(store)
        .await?
        .into_iter()
        .map(|d| d.name)
        .collect();
    let mut rep = AdoptReport::default();
    // reservations of the segment's pool(s)
    let mut all: Vec<Discovered> = Vec::new();
    if let Some((pool, _, _)) = pool_for(store, &segment).await? {
        for r in sqlx::query("SELECT mac, ip, hostname FROM dhcp_static_mappings WHERE pool_id = ?")
            .bind(pool)
            .fetch_all(store.pool()?)
            .await
            .map_err(db("read reservations"))?
        {
            all.push(Discovered {
                mac: r.get(0),
                ip: r.get(1),
                hostname: r.get(2),
            });
        }
    }
    all.extend(found.iter().cloned());
    let mut seen = BTreeSet::new();
    for f in &all {
        if !seen.insert(f.mac.to_ascii_lowercase()) {
            continue;
        }
        let cx = AdoptCtx {
            segment: &segment,
            group,
            nets: &nets,
            own: &own,
        };
        adopt_one(store, &cx, f, &mut taken, &mut rep).await?;
    }
    mark_adopted(store, &segment).await?;
    Ok(rep)
}

/// Adopt exactly one discovered host into `group` (the "Discovered" tab).
pub async fn adopt_host(
    store: &ConfigStore,
    segment: &str,
    found: &Discovered,
    name: Option<&str>,
    group: &str,
) -> Result<Device> {
    let segment = check_segment(segment)?;
    let (nets, own) = segment_v4(store, &segment).await?;
    let mut taken: BTreeSet<String> = list_devices(store)
        .await?
        .into_iter()
        .map(|d| d.name)
        .collect();
    let mut f = found.clone();
    if let Some(n) = name {
        if !is_name(n) {
            return Err(invalid(format!("device name {n:?}")));
        }
        f.hostname = Some(n.to_string());
        taken.remove(n);
    }
    let mut rep = AdoptReport::default();
    let cx = AdoptCtx {
        segment: &segment,
        group,
        nets: &nets,
        own: &own,
    };
    adopt_one(store, &cx, &f, &mut taken, &mut rep).await?;
    match device_by_mac(store, &norm_mac(&found.mac)?).await? {
        Some(d) => Ok(d),
        None => Err(invalid(format!(
            "adopt: {}",
            rep.skipped
                .first()
                .cloned()
                .unwrap_or_else(|| "nothing adopted".into())
        ))),
    }
}

/// A pending (Wi-Fi) device joined: learn its MAC and bind it. The address is
/// `ip_hint` (its current DHCP lease) when that is free and inside the
/// segment, else a fresh one outside the DHCP range; a reservation keeps it.
/// Idempotent for the same MAC.
pub async fn activate_pending(
    store: &ConfigStore,
    id: i64,
    mac: &str,
    ip_hint: Option<Ipv4Addr>,
) -> Result<Device> {
    let mac = norm_mac(mac)?;
    let d = get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no device {id}")))?;
    if d.state == "active" && d.mac.as_deref() == Some(mac.as_str()) {
        return Ok(d);
    }
    if d.state != "pending" {
        return Err(invalid(format!(
            "device {}: it is {}, not pending",
            d.name, d.state
        )));
    }
    if let Some(o) = device_by_mac(store, &mac).await? {
        return Err(invalid(format!("MAC {mac}: already the device {}", o.name)));
    }
    let (nets, own) = segment_v4(store, &d.segment).await?;
    let taken = taken_ips(store).await?;
    let ip = match ip_hint {
        Some(h)
            if nets
                .iter()
                .any(|n| n.contains(h) && n.net != h && n.broadcast() != h)
                && !own.contains(&h)
                && !taken.contains(&h) =>
        {
            h
        }
        _ => allocate_ip(store, &d.segment).await?,
    };
    let mapping = reserve(store, &d.segment, &d.name, &mac, ip).await?;
    sqlx::query(
        "UPDATE seg_devices SET mac=?, ip4=?, state='active', dhcp_mapping_id=?, activated_at=? WHERE id=?",
    )
    .bind(&mac)
    .bind(ip.to_string())
    .bind(mapping)
    .bind(now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("MAC or address of {}", d.name)))?;
    get_device(store, id)
        .await?
        .ok_or_else(|| Error::Config("device vanished".into()))
}

/// Record that a device was seen (called by the discovery code).
pub async fn touch(store: &ConfigStore, mac: &str, ip: &str) -> Result<()> {
    sqlx::query("UPDATE seg_devices SET last_seen = ?, last_ip = ? WHERE mac = ?")
        .bind(now())
        .bind(ip)
        .bind(mac.to_ascii_lowercase())
        .execute(store.pool()?)
        .await
        .map_err(db("touch device"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lab() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO interfaces (name, enabled, role, updated_at) VALUES ('br0',1,'lan',0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        sqlx::query("INSERT INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO dhcp_pools (interface, enabled, range_start, range_end, lease_time, updated_at) VALUES ('@lan',1,'192.168.50.100','192.168.50.199',3600,0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        s
    }

    fn dev(name: &str, mac: &str) -> DeviceInput {
        DeviceInput {
            name: name.into(),
            mac: Some(mac.into()),
            segment: Some("@lan".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn builtin_groups_exist_and_are_protected() {
        let s = lab().await;
        let g = list_groups(&s).await.unwrap();
        assert!(g
            .iter()
            .any(|g| g.name == "home" && g.builtin && g.intra && g.internet == "allow"));
        assert!(g
            .iter()
            .any(|g| g.name == "quarantine" && g.quarantine && g.internet == "deny" && !g.intra));
        let home = g.iter().find(|g| g.name == "home").unwrap();
        assert!(delete_group(&s, home.id).await.is_err());
        let mut i = GroupInput {
            name: "renamed".into(),
            ..Default::default()
        };
        i.internet = "allow".into();
        assert!(update_group(&s, home.id, &i).await.is_err());
        // an emptied table (factory reset) is re-seeded
        sqlx::query("DELETE FROM seg_groups")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(list_groups(&s).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn device_gets_an_address_outside_the_dhcp_range_and_a_reservation() {
        let s = lab().await;
        let d = create_device(&s, &dev("laptop", "02:AA:00:00:00:11"))
            .await
            .unwrap();
        assert_eq!(d.mac.as_deref(), Some("02:aa:00:00:00:11"));
        assert_eq!(d.state, "active");
        assert_eq!(d.group, "home");
        assert_eq!(
            d.ip4.as_deref(),
            Some("192.168.50.2"),
            "first free address, not the router's .1"
        );
        let m: (String, String) = sqlx::query_as("SELECT mac, ip FROM dhcp_static_mappings")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(m, ("02:aa:00:00:00:11".into(), "192.168.50.2".into()));
        let d2 = create_device(&s, &dev("cam", "02:aa:00:00:00:12"))
            .await
            .unwrap();
        assert_eq!(d2.ip4.as_deref(), Some("192.168.50.3"));
        assert!(
            create_device(&s, &dev("cam", "02:aa:00:00:00:13"))
                .await
                .is_err(),
            "duplicate name"
        );
        assert!(
            create_device(&s, &dev("x", "02:aa:00:00:00:12"))
                .await
                .is_err(),
            "duplicate MAC"
        );
    }

    #[tokio::test]
    async fn hostile_and_bad_input_is_rejected() {
        let s = lab().await;
        for name in ["", "A", "a b", "x\"; flush ruleset; \"", &"a".repeat(33)] {
            assert!(
                create_device(&s, &dev(name, "02:aa:00:00:00:11"))
                    .await
                    .is_err(),
                "{name:?}"
            );
        }
        for mac in [
            "",
            "zz:aa:00:00:00:11",
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "02:aa:00:00:00",
        ] {
            let mut d = dev("a", mac);
            d.mac = Some(mac.into());
            let r = create_device(&s, &d).await;
            // an empty MAC for a wired device is refused as well
            assert!(r.is_err(), "{mac:?}");
        }
        let mut d = dev("a", "02:aa:00:00:00:11");
        d.ip4 = Some("192.168.50.1".into()); // the router
        assert!(create_device(&s, &d).await.is_err());
        d.ip4 = Some("10.9.9.9".into()); // outside the subnet
        assert!(create_device(&s, &d).await.is_err());
        d.ip4 = Some("192.168.50.255".into());
        assert!(create_device(&s, &d).await.is_err());
        d.ip4 = None;
        d.group = Some("nope".into());
        assert!(create_device(&s, &d).await.is_err());
        d.group = None;
        d.segment = Some("@lan; drop".into());
        assert!(create_device(&s, &d).await.is_err());
        assert!(
            check_ports("0").is_err()
                && check_ports("70000").is_err()
                && check_ports("90-80").is_err()
        );
        assert_eq!(check_ports(" 80, 8000-8010 ").unwrap(), "80,8000-8010");
    }

    #[tokio::test]
    async fn pending_wifi_device_has_no_mac_and_no_address() {
        let s = lab().await;
        let mut d = dev("phone", "");
        d.mac = None;
        d.kind = Some("wifi".into());
        let p = create_device(&s, &d).await.unwrap();
        assert_eq!((p.state.as_str(), p.mac, p.ip4), ("pending", None, None));
        let mut w = dev("w", "");
        w.mac = None;
        assert!(
            create_device(&s, &w).await.is_err(),
            "wired devices need a MAC"
        );
    }

    #[tokio::test]
    async fn revoke_drops_the_reservation_and_keeps_the_row() {
        let s = lab().await;
        let d = create_device(&s, &dev("cam", "02:aa:00:00:00:12"))
            .await
            .unwrap();
        let r = revoke_device(&s, d.id).await.unwrap();
        assert_eq!(r.state, "revoked");
        assert!(r.revoked_at.is_some());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_static_mappings")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(update_device(&s, d.id, None, Some("home"), None)
            .await
            .is_err());
        delete_device(&s, d.id).await.unwrap();
        assert!(list_devices(&s).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_revoked_device_frees_its_mac_and_address_for_a_new_enrolment() {
        let s = lab().await;
        let old = create_device(&s, &dev("old-phone", "02:aa:00:00:00:61"))
            .await
            .unwrap();
        let ip = old.ip4.clone().unwrap();
        let r = revoke_device(&s, old.id).await.unwrap();
        assert_eq!(
            (r.ip4.clone(), r.last_ip.clone()),
            (None, Some(ip.clone())),
            "the address is released, the last one remembered"
        );
        let again = create_device(&s, &dev("new-phone", "02:AA:00:00:00:61"))
            .await
            .unwrap();
        assert_eq!(again.state, "active");
        assert_eq!(
            again.ip4.as_deref(),
            Some(ip.as_str()),
            "the freed address is reusable"
        );
        let old = get_device(&s, old.id).await.unwrap().unwrap();
        assert_eq!(
            (old.state.as_str(), old.mac),
            ("revoked", None),
            "history kept, MAC moved"
        );
        // an ACTIVE device's MAC cannot be taken
        assert!(create_device(&s, &dev("thief", "02:aa:00:00:00:61"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn groups_links_and_services_validate() {
        let s = lab().await;
        let iot = create_group(
            &s,
            &GroupInput {
                name: "iot".into(),
                intra: true,
                internet: "allow".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(create_group(
            &s,
            &GroupInput {
                name: "iot".into(),
                internet: "allow".into(),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(create_group(
            &s,
            &GroupInput {
                name: "bad name".into(),
                internet: "allow".into(),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert!(create_group(
            &s,
            &GroupInput {
                name: "g2".into(),
                internet: "maybe".into(),
                ..Default::default()
            }
        )
        .await
        .is_err());
        add_link(&s, "iot", "home").await.unwrap();
        assert!(
            add_link(&s, "home", "iot").await.is_err(),
            "same pair either way round"
        );
        assert!(add_link(&s, "iot", "iot").await.is_err());
        assert!(add_link(&s, "iot", "quarantine").await.is_err());
        let _a = create_device(&s, &dev("laptop", "02:aa:00:00:00:11"))
            .await
            .unwrap();
        let svc = |src: &str, dst: &str, proto: &str, ports: &str| ServiceInput {
            name: "s1".into(),
            src: src.into(),
            dst: dst.into(),
            proto: proto.into(),
            ports: ports.into(),
            schedule: None,
            enabled: true,
        };
        assert!(
            add_service(&s, &svc("device:laptop", "group:iot", "tcp", "8080"))
                .await
                .is_ok()
        );
        assert!(
            add_service(&s, &svc("device:ghost", "group:iot", "tcp", "1"))
                .await
                .is_err()
        );
        assert!(
            add_service(&s, &svc("device:laptop", "group:iot", "icmp", "1"))
                .await
                .is_err()
        );
        assert!(add_service(&s, &svc("laptop", "group:iot", "tcp", "1"))
            .await
            .is_err());
        let mut sch = svc("device:laptop", "group:iot", "tcp", "1");
        sch.name = "s2".into();
        sch.schedule = Some("mon".into());
        assert!(add_service(&s, &sch).await.is_err());
        let l = list_services(&s).await.unwrap();
        assert_eq!(
            (l[0].src.as_str(), l[0].dst.as_str(), l[0].ports.as_str()),
            ("device:laptop", "group:iot", "8080")
        );
        delete_group(&s, iot).await.unwrap();
        assert!(
            list_services(&s).await.unwrap().is_empty(),
            "services naming a deleted group go with it"
        );
        assert!(
            list_links(&s).await.unwrap().is_empty(),
            "links go with the group (cascade)"
        );
    }

    #[tokio::test]
    async fn group_with_members_cannot_be_deleted() {
        let s = lab().await;
        let g = create_group(
            &s,
            &GroupInput {
                name: "kids".into(),
                internet: "allow".into(),
                intra: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut d = dev("tab", "02:aa:00:00:00:21");
        d.group = Some("kids".into());
        create_device(&s, &d).await.unwrap();
        assert!(delete_group(&s, g).await.is_err());
    }

    #[tokio::test]
    async fn adoption_puts_everything_on_the_segment_into_home_and_is_idempotent() {
        let s = lab().await;
        // one reservation already exists
        sqlx::query("INSERT INTO dhcp_static_mappings (pool_id, mac, ip, hostname, updated_at) VALUES (1,'02:aa:00:00:00:30','192.168.50.30','printer',0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let found = vec![
            Discovered {
                mac: "02:aa:00:00:00:31".into(),
                ip: "192.168.50.120".into(),
                hostname: Some("Living Room TV".into()),
            },
            Discovered {
                mac: "02:AA:00:00:00:32".into(),
                ip: "192.168.50.121".into(),
                hostname: None,
            },
            Discovered {
                mac: "02:aa:00:00:00:33".into(),
                ip: "10.1.1.1".into(),
                hostname: None,
            }, // other subnet
            Discovered {
                mac: "02:aa:00:00:00:34".into(),
                ip: "192.168.50.1".into(),
                hostname: None,
            }, // the router
            Discovered {
                mac: "02:aa:00:00:00:30".into(),
                ip: "192.168.50.30".into(),
                hostname: None,
            }, // duplicate of the reservation
        ];
        let r = adopt(&s, "@lan", &found, None).await.unwrap();
        assert_eq!(r.adopted.len(), 3, "{r:?}");
        assert_eq!(r.skipped.len(), 1, "{r:?}");
        let d = list_devices(&s).await.unwrap();
        assert!(d.iter().all(|d| d.group == "home" && d.state == "active"));
        assert!(d
            .iter()
            .any(|d| d.name == "printer" && d.ip4.as_deref() == Some("192.168.50.30")));
        assert!(d
            .iter()
            .any(|d| d.name == "living-room-tv" && d.ip4.as_deref() == Some("192.168.50.120")));
        assert!(d.iter().any(|d| d.name == "dev-000032"));
        // the adopted leases are now reservations: same address after a reboot
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dhcp_static_mappings")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 3);
        let again = adopt(&s, "@lan", &found, None).await.unwrap();
        assert!(again.adopted.is_empty(), "idempotent: {again:?}");
        assert!(list_segments(&s).await.unwrap()[0].adopted_at.is_some());
    }

    #[tokio::test]
    async fn segments_are_opt_in() {
        let s = lab().await;
        assert!(
            list_segments(&s).await.unwrap().is_empty(),
            "nothing enabled on a fresh or upgraded store"
        );
        set_segment_enabled(&s, "@lan", true).await.unwrap();
        assert!(list_segments(&s).await.unwrap()[0].enabled);
        set_segment_enabled(&s, "@lan", false).await.unwrap();
        assert!(!list_segments(&s).await.unwrap()[0].enabled);
        assert!(set_segment_enabled(&s, "lan\" ;", true).await.is_err());
    }

    #[test]
    fn subnet_math() {
        let n = Subnet::new("192.168.50.77".parse().unwrap(), 24);
        assert_eq!(n.cidr(), "192.168.50.0/24");
        assert_eq!(n.broadcast(), "192.168.50.255".parse::<Ipv4Addr>().unwrap());
        assert!(
            n.contains("192.168.50.9".parse().unwrap())
                && !n.contains("192.168.51.9".parse().unwrap())
        );
        let h = Subnet::new("10.0.0.5".parse().unwrap(), 30);
        assert_eq!(h.broadcast(), "10.0.0.7".parse::<Ipv4Addr>().unwrap());
    }
}
