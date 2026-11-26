//! Security overview + one-click hardening baseline (docs/SECURITY-OVERVIEW.md,
//! docs/design/security-suite.md items 3, 10 and 11).
//!
//! Every check reads LIVE state: the facts `patronus applyd` collects as root
//! (`patronus_network::posture`: listening sockets and their processes, the
//! running sshd's effective configuration, the kernel's WireGuard peers, what
//! strongSwan loaded, running OpenVPN configs, Suricata, Unbound, the main
//! nftables table) plus the accounts and settings in the store. Reachability
//! from the WAN is decided by walking the loaded `input` chain
//! (`patronus_firewall::exposure`), not by reading rules from the store.
//!
//! The baseline is computed on the server from the same evaluation: a dry run
//! (`GET /api/security/baseline`) lists each change with before/after and
//! each item it leaves alone with the reason (the management path the admin
//! is using right now, a WAN that legitimately has private sources, no SSH key
//! installed yet ...). `POST /api/security/baseline` repeats the computation,
//! refuses when the plan changed since the dry run (token), takes ONE
//! configuration revision, writes every change, applies the affected
//! subsystems and puts everything back if any of them fails. Undo = restore
//! that revision.
//!
//! Measured data (`sec_feed_hits`, `sec_feed_counter_pos`, `sec_wg_seen`) is
//! NON_CONFIG with retention (`security.feed_hits_days`).

use crate::state::AppState;
use patronus_config::ConfigStore;
use patronus_core::types::{ChainType, FirewallAction, PortSpec, Protocol};
use patronus_firewall::exposure::{self, Exposure};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// settings (system_config `security.*`)
// ---------------------------------------------------------------------------

pub const K_WG_SILENT_DAYS: &str = "security.wg_silent_days";
pub const K_IDS_MIN_RAM_MB: &str = "security.ids_min_ram_mb";
pub const K_HITS_DAYS: &str = "security.feed_hits_days";
pub const K_SAMPLE_SECS: &str = "security.sample_secs";
pub const K_BASELINE_FEEDS: &str = "security.baseline_feeds";
/// Revision taken right before the last baseline (the Undo button).
pub const K_BASELINE_REVISION: &str = "security.baseline_revision";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Settings {
    /// A WireGuard peer without a handshake for this many days is "silent".
    pub wg_silent_days: u32,
    /// Below this much RAM the IDS check is "not available" instead of failing.
    pub ids_min_ram_mb: u32,
    /// Hourly feed-hit history kept this many days.
    pub feed_hits_days: u32,
    /// How often the hit counters and WireGuard handshakes are sampled.
    pub sample_secs: u32,
    /// Catalog feeds the baseline turns on.
    pub baseline_feeds: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            wg_silent_days: 90,
            ids_min_ram_mb: 2048,
            feed_hits_days: 30,
            sample_secs: 60,
            baseline_feeds: vec![
                "spamhaus_drop".into(),
                "spamhaus_edrop".into(),
                "spamhaus_dropv6".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsIn {
    pub wg_silent_days: Option<u32>,
    pub ids_min_ram_mb: Option<u32>,
    pub feed_hits_days: Option<u32>,
    pub sample_secs: Option<u32>,
    pub baseline_feeds: Option<Vec<String>>,
}

fn bad(m: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("Invalid {m}")
}

impl Settings {
    pub fn merged(&self, i: &SettingsIn) -> anyhow::Result<Settings> {
        let mut s = self.clone();
        if let Some(v) = i.wg_silent_days {
            if !(1..=3650).contains(&v) {
                return Err(bad("wg_silent_days: 1 to 3650"));
            }
            s.wg_silent_days = v;
        }
        if let Some(v) = i.ids_min_ram_mb {
            if !(256..=1_048_576).contains(&v) {
                return Err(bad("ids_min_ram_mb: 256 to 1048576"));
            }
            s.ids_min_ram_mb = v;
        }
        if let Some(v) = i.feed_hits_days {
            if !(1..=366).contains(&v) {
                return Err(bad("feed_hits_days: 1 to 366"));
            }
            s.feed_hits_days = v;
        }
        if let Some(v) = i.sample_secs {
            if !(10..=3600).contains(&v) {
                return Err(bad("sample_secs: 10 to 3600"));
            }
            s.sample_secs = v;
        }
        if let Some(v) = &i.baseline_feeds {
            let mut out = Vec::new();
            for f in v {
                let f = f.trim();
                if patronus_firewall::feeds::catalog_feed(f).is_none() {
                    return Err(bad(format!("baseline_feeds: {f:?} is not a catalog feed")));
                }
                if !out.iter().any(|x| x == f) {
                    out.push(f.to_string());
                }
            }
            s.baseline_feeds = out;
        }
        Ok(s)
    }
}

pub async fn load_settings(store: &ConfigStore) -> anyhow::Result<Settings> {
    let d = Settings::default();
    let g = |k: &'static str| async move { store.load_system_config(k).await };
    let num =
        |v: Option<String>, def: u32| v.and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(def);
    let feeds = g(K_BASELINE_FEEDS).await?.map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let raw = SettingsIn {
        wg_silent_days: Some(num(g(K_WG_SILENT_DAYS).await?, d.wg_silent_days)),
        ids_min_ram_mb: Some(num(g(K_IDS_MIN_RAM_MB).await?, d.ids_min_ram_mb)),
        feed_hits_days: Some(num(g(K_HITS_DAYS).await?, d.feed_hits_days)),
        sample_secs: Some(num(g(K_SAMPLE_SECS).await?, d.sample_secs)),
        baseline_feeds: feeds,
    };
    // a hand-edited bad value falls back to the default instead of breaking the page
    Ok(d.merged(&raw).unwrap_or(d))
}

pub async fn save_settings(store: &ConfigStore, i: &SettingsIn) -> anyhow::Result<Settings> {
    let s = load_settings(store).await?.merged(i)?;
    for (k, v) in [
        (K_WG_SILENT_DAYS, s.wg_silent_days.to_string()),
        (K_IDS_MIN_RAM_MB, s.ids_min_ram_mb.to_string()),
        (K_HITS_DAYS, s.feed_hits_days.to_string()),
        (K_SAMPLE_SECS, s.sample_secs.to_string()),
        (K_BASELINE_FEEDS, s.baseline_feeds.join(",")),
    ] {
        store.save_system_config(k, &v).await?;
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// checks (pure: inputs -> results)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    /// Does not apply here (feature not built, not enough RAM, no VPN).
    Na,
    /// Live state could not be read.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub group: &'static str,
    pub title: &'static str,
    pub status: Status,
    /// What was measured (plain words, the live evidence).
    pub evidence: String,
    /// Page that fixes it.
    pub fix_href: &'static str,
    pub fix_label: &'static str,
    pub weight: u32,
    /// A failure caps the grade (the router is open to the internet).
    pub critical: bool,
    /// The recommended baseline changes this.
    pub in_baseline: bool,
    /// Extra per-check data for the page (peers to disable, ...).
    #[serde(skip_serializing_if = "Value::is_null")]
    pub detail: Value,
}

/// Everything the checks look at, gathered once.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Inputs {
    /// `posture_facts` from applyd (Null = could not be read).
    pub facts: Value,
    pub facts_error: Option<String>,
    pub wan_devs: Vec<String>,
    /// Local addresses on the WAN devices.
    pub wan_addrs: Vec<IpAddr>,
    pub guard_built: bool,
    pub guard_enabled: bool,
    pub threat_feeds: Vec<FeedState>,
    pub dnssec_setting: bool,
    pub wan_block_private: bool,
    pub wan_block_bogons: bool,
    pub synflood: bool,
    pub ssh_port: u16,
    pub web_ports: Vec<u16>,
    pub https_port: u16,
    pub redirect_port: u16,
    pub totp_built: bool,
    /// (username, two-factor on) of every enabled admin.
    pub admins: Vec<(String, bool)>,
    pub ids_built: bool,
    pub ids_enabled: bool,
    /// (id, interface, name, public key, enabled, updated_at) from the store.
    pub wg_store: Vec<WgStorePeer>,
    /// public key -> last handshake ever seen (sampler).
    pub wg_seen: HashMap<String, i64>,
    pub updates: Value,
    pub settings: Settings,
    pub now: i64,
    /// Store rules that open a port on a WAN interface (for the baseline).
    pub wan_rules: Vec<WanRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedState {
    pub id: String,
    pub enabled: bool,
    pub action: String,
    pub entries: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WgStorePeer {
    pub id: i64,
    pub interface: String,
    pub name: String,
    pub public_key: String,
    pub enabled: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WanRule {
    pub id: u64,
    pub name: String,
    /// The ports it opens (None = every port).
    pub ports: Option<Vec<(u16, u16)>>,
}

impl WanRule {
    fn covers(&self, port: u16) -> bool {
        match &self.ports {
            None => true,
            Some(v) => v.iter().any(|(a, b)| (*a..=*b).contains(&port)),
        }
    }
}

/// `ip` inside `cidr` (`10.0.0.0/8`, `fc00::/7`).
pub fn cidr_contains(cidr: &str, ip: &IpAddr) -> bool {
    let Some((net, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(len)) = (net.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) if len <= 32 => {
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(n) & m) == (u32::from(*a) & m)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) if len <= 128 => {
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(n) & m) == (u128::from(*a) & m)
        }
        _ => false,
    }
}

fn is_private(ip: &IpAddr) -> bool {
    use patronus_firewall::wanguard::{PRIVATE_V4, PRIVATE_V6};
    PRIVATE_V4
        .iter()
        .chain(PRIVATE_V6)
        .any(|n| cidr_contains(n, ip))
}

fn is_bogon(ip: &IpAddr) -> bool {
    use patronus_firewall::wanguard::{BOGONS_V4, BOGONS_V6};
    BOGONS_V4
        .iter()
        .chain(BOGONS_V6)
        .any(|n| cidr_contains(n, ip))
}

/// Listeners of `process`-names on `port` that are bound to a wildcard or a
/// WAN address (bound to the LAN address only = not reachable on the WAN).
fn listening_on_wan(i: &Inputs, proto: &str, port: u16) -> Vec<Value> {
    i.facts["listeners"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| l["proto"] == proto && l["port"].as_u64() == Some(port as u64))
        .filter(|l| {
            let a = l["addr"].as_str().unwrap_or("");
            a == "0.0.0.0"
                || a == "::"
                || a.parse::<IpAddr>()
                    .map(|ip| i.wan_addrs.contains(&ip))
                    .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// For every WAN device: what a new TCP connection to `port` gets.
fn wan_exposure(i: &Inputs, port: u16) -> Vec<(String, Exposure)> {
    let nft = &i.facts["nft"]["main"];
    i.wan_devs
        .iter()
        .map(|d| (d.clone(), exposure::evaluate(nft, d, "tcp", port)))
        .collect()
}

/// pass / warn / fail for "is `ports` reachable from the WAN" (one service).
fn reach_check(i: &Inputs, what: &str, ports: &[u16]) -> (Status, String, Value) {
    if i.facts.is_null() {
        return (
            Status::Unknown,
            format!(
                "live state not readable: {}",
                i.facts_error.clone().unwrap_or_default()
            ),
            Value::Null,
        );
    }
    if i.wan_devs.is_empty() {
        return (
            Status::Na,
            "no interface has the WAN role".into(),
            Value::Null,
        );
    }
    if i.facts["nft"]["main"].is_null() {
        return (
            Status::Fail,
            "the firewall table inet patronus is not loaded: nothing filters the WAN".into(),
            Value::Null,
        );
    }
    let mut open = Vec::new();
    let mut restricted = Vec::new();
    let mut listening_any = false;
    for &p in ports {
        let l = listening_on_wan(i, "tcp", p);
        if l.is_empty() {
            continue;
        }
        listening_any = true;
        for (dev, e) in wan_exposure(i, p) {
            match e {
                Exposure::Open { comment, .. } => open.push(format!(
                    "port {p} on {dev} is accepted{}",
                    if comment.is_empty() {
                        String::new()
                    } else {
                        format!(" by rule \"{comment}\"")
                    }
                )),
                Exposure::Restricted { comment, .. } => restricted.push(format!(
                    "port {p} on {dev} is accepted from some sources{}",
                    if comment.is_empty() {
                        String::new()
                    } else {
                        format!(" (rule \"{comment}\")")
                    }
                )),
                _ => {}
            }
        }
    }
    let rules: Vec<Value> = i
        .wan_rules
        .iter()
        .filter(|r| ports.iter().any(|p| r.covers(*p)))
        .map(|r| json!({"id": r.id, "name": r.name}))
        .collect();
    if !listening_any {
        return (
            Status::Pass,
            format!("no {what} listener is bound to a WAN address"),
            Value::Null,
        );
    }
    if !open.is_empty() {
        return (Status::Fail, open.join("; "), json!({ "rules": rules }));
    }
    if !restricted.is_empty() {
        return (
            Status::Warn,
            restricted.join("; "),
            json!({ "rules": rules }),
        );
    }
    (
        Status::Pass,
        format!(
            "{what} listens on port {}, the firewall drops new connections to it from the WAN",
            ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Null,
    )
}

fn has_rule_comment(nft: &Value, needle: &str) -> bool {
    nft["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.get("rule"))
        .any(|r| r["comment"].as_str().is_some_and(|c| c.contains(needle)))
}

fn has_chain(nft: &Value, name: &str) -> bool {
    nft["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.get("chain"))
        .any(|c| c["name"] == name)
}

/// Weak IKE/ESP algorithms (strongSwan proposal keywords and SA names).
pub fn weak_algorithms(s: &str) -> Vec<&'static str> {
    let l = s.to_ascii_lowercase();
    let mut v = Vec::new();
    for (needle, name) in [
        ("modp768", "MODP-768"),
        ("modp_768", "MODP-768"),
        ("modp1024", "MODP-1024"),
        ("modp_1024", "MODP-1024"),
        ("modp1536", "MODP-1536"),
        ("modp_1536", "MODP-1536"),
        ("3des", "3DES"),
        ("des_cbc", "DES"),
        ("blowfish", "Blowfish"),
        ("md5", "MD5"),
    ] {
        if l.contains(needle) && !v.contains(&name) {
            v.push(name);
        }
    }
    // sha1 as integrity/PRF (not sha1 inside sha128/sha256/...)
    let toks: Vec<&str> = l.split(['-', '/', ',', ' ']).collect();
    if toks.iter().any(|t| {
        matches!(
            *t,
            "sha1" | "sha" | "hmac_sha1_96" | "prf_hmac_sha1" | "prfsha1" | "aes128-sha1"
        ) || t.starts_with("hmac_sha1_")
    }) && !v.contains(&"SHA-1")
    {
        v.push("SHA-1");
    }
    v
}

const MANAGED_PROCESSES: &[&str] = &[
    "sshd",
    "sshd-session",
    "dropbear",
    "patronus-web",
    "patronus",
    "patronus-dashb",
    "unbound",
    "dnsmasq",
    "kea-dhcp4",
    "kea-dhcp6",
    "dhcpcd",
    "udhcpc",
    "chronyd",
    "ntpd",
    "charon",
    "charon-systemd",
    "openvpn",
    "miniupnpd",
    "avahi-daemon",
    "hostapd",
    "keepalived",
    "conntrackd",
    "bgpd",
    "ospfd",
    "ospf6d",
    "zebra",
    "bfdd",
    "ripd",
    "staticd",
    "watchfrr",
    "snmpd",
    "radvd",
    "suricata",
    "Suricata-Main",
    "softflowd",
    "igmpproxy",
    "xl2tpd",
    "tayga",
    "squid",
    "lldpd",
    "udp-broadcast-relay",
    "wg-crypt-wg",
];

/// Ports that are risky to have listening at all on a router.
const RISKY_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (23, "telnet"),
    (69, "TFTP"),
    (111, "rpcbind"),
    (135, "MS RPC"),
    (139, "NetBIOS"),
    (445, "SMB"),
    (512, "rexec"),
    (513, "rlogin"),
    (514, "rsh"),
    (2049, "NFS"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
];

pub fn run_checks(i: &Inputs) -> Vec<Check> {
    let mut out: Vec<Check> = Vec::new();
    let live = !i.facts.is_null();
    let unknown = || {
        (
            Status::Unknown,
            format!(
                "live state not readable: {}",
                i.facts_error.clone().unwrap_or_else(|| "no answer".into())
            ),
        )
    };
    let nft = &i.facts["nft"]["main"];
    macro_rules! push {
        ($id:literal, $group:literal, $title:literal, $st:expr, $ev:expr, $href:literal, $label:literal, $w:expr, $crit:expr, $bl:expr, $detail:expr) => {
            out.push(Check {
                id: $id,
                group: $group,
                title: $title,
                status: $st,
                evidence: $ev,
                fix_href: $href,
                fix_label: $label,
                weight: $w,
                critical: $crit,
                in_baseline: $bl,
                detail: $detail,
            })
        };
    }

    // --- access -------------------------------------------------------------------------------
    let (st, ev, detail) = reach_check(i, "the web UI", &i.web_ports);
    push!(
        "web_wan",
        "access",
        "Web UI not reachable from the WAN",
        st,
        ev,
        "/firewall#tab-rules",
        "Firewall rules",
        10,
        true,
        matches!(st, Status::Fail | Status::Warn)
            && !detail["rules"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        detail
    );

    let mut ssh_ports: Vec<u16> = i.facts["ssh"]["sshd"]["port"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str()?.parse().ok())
        .collect();
    for p in i.facts["ssh"]["dropbear"]["ports"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(p) = p.as_str().and_then(|p| p.rsplit(':').next()?.parse().ok()) {
            ssh_ports.push(p);
        }
    }
    if ssh_ports.is_empty() {
        ssh_ports.push(i.ssh_port);
    }
    ssh_ports.sort();
    ssh_ports.dedup();
    let (st, ev, detail) = reach_check(i, "SSH", &ssh_ports);
    push!(
        "ssh_wan",
        "access",
        "SSH not reachable from the WAN",
        st,
        ev,
        "/firewall#tab-rules",
        "Firewall rules",
        8,
        true,
        matches!(st, Status::Fail | Status::Warn)
            && !detail["rules"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true),
        detail
    );

    let (st, ev, bl) = if !live {
        let (s, e) = unknown();
        (s, e, false)
    } else {
        let sshd = &i.facts["ssh"]["sshd"];
        let db = &i.facts["ssh"]["dropbear"];
        let first = |k: &str| sshd[k][0].as_str().unwrap_or("").to_string();
        if sshd.is_null() && db.is_null() {
            if let Some(e) = i.facts["ssh"]["sshd_error"].as_str() {
                (
                    Status::Unknown,
                    format!("sshd runs but its effective configuration could not be read: {e}"),
                    false,
                )
            } else {
                (
                    Status::Pass,
                    "no SSH server (sshd or Dropbear) is running".into(),
                    false,
                )
            }
        } else {
            let mut bad = Vec::new();
            if !sshd.is_null() {
                if first("passwordauthentication") == "yes" {
                    bad.push("sshd accepts passwords".to_string());
                }
                if first("kbdinteractiveauthentication") == "yes" {
                    bad.push("sshd accepts keyboard-interactive logins".to_string());
                }
                if first("permitrootlogin") == "yes" {
                    bad.push("sshd lets root log in with a password".to_string());
                }
            }
            if db["password_auth"] == true {
                bad.push("Dropbear accepts passwords".into());
            }
            if bad.is_empty() {
                (
                    Status::Pass,
                    "the running SSH server accepts keys only".into(),
                    false,
                )
            } else {
                (Status::Fail, bad.join("; "), !sshd.is_null())
            }
        }
    };
    push!(
        "ssh_keys",
        "access",
        "SSH logins with keys only",
        st,
        ev,
        "/system#ssh-card",
        "SSH server",
        6,
        false,
        bl,
        Value::Null
    );

    let (st, ev) = if !i.totp_built {
        (
            Status::Na,
            "two-factor login is not built into this firmware (USE=totp)".into(),
        )
    } else if i.admins.is_empty() {
        (Status::Warn, "no enabled admin account".into())
    } else {
        let without: Vec<&str> = i
            .admins
            .iter()
            .filter(|(_, t)| !t)
            .map(|(n, _)| n.as_str())
            .collect();
        if without.is_empty() {
            (
                Status::Pass,
                format!("all {} admin accounts use two-factor login", i.admins.len()),
            )
        } else if without.len() == i.admins.len() {
            (
                Status::Fail,
                format!("no admin uses two-factor login ({})", without.join(", ")),
            )
        } else {
            (
                Status::Warn,
                format!("admins without two-factor login: {}", without.join(", ")),
            )
        }
    };
    push!(
        "admin_2fa",
        "access",
        "Two-factor login for admins",
        st,
        ev,
        "/system#my-account",
        "Your account",
        6,
        false,
        false,
        Value::Null
    );

    let (st, ev) = if !i.guard_built {
        (Status::Na, "brute-force protection is not built into this firmware (USE=bruteforce; router images: next phase)".into())
    } else if !i.guard_enabled {
        (
            Status::Fail,
            "off: password guessing on SSH and the web UI is never banned".into(),
        )
    } else if !live {
        unknown()
    } else if i.facts["nft"]["guard_table"] == true {
        (
            Status::Pass,
            "on: the ban table inet patronus_guard is loaded".into(),
        )
    } else {
        (
            Status::Warn,
            "switched on, but the table inet patronus_guard is not loaded".into(),
        )
    };
    push!(
        "guard",
        "access",
        "Brute-force protection",
        st,
        ev,
        "/security/brute-force",
        "Brute-force protection",
        6,
        false,
        i.guard_built && !i.guard_enabled,
        Value::Null
    );

    let std_ssh = ssh_ports.iter().all(|p| *p == 22);
    let std_web = i.https_port == 443 && (i.redirect_port == 80 || i.redirect_port == 0);
    let (st, ev) = if std_ssh && std_web {
        (
            Status::Pass,
            "web UI on 443 (80 only redirects), SSH on 22".to_string(),
        )
    } else {
        (
            Status::Warn,
            format!(
                "web UI on {} ({}), SSH on {}: a moved port hides nothing from a scanner and makes the router look down",
                i.https_port,
                if i.redirect_port == 0 {
                    "no HTTP redirect".to_string()
                } else {
                    format!("HTTP redirect on {}", i.redirect_port)
                },
                ssh_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
            ),
        )
    };
    push!(
        "std_ports",
        "access",
        "Standard ports",
        st,
        ev,
        "/system#web-card",
        "Web UI addresses and ports",
        1,
        false,
        false,
        Value::Null
    );

    // --- network ------------------------------------------------------------------------------
    let enabled: Vec<&FeedState> = i.threat_feeds.iter().filter(|f| f.enabled).collect();
    let (st, ev) = if enabled.is_empty() {
        (
            Status::Fail,
            "no threat feed is on: known-bad networks reach the router and the LAN".to_string(),
        )
    } else if !live {
        unknown()
    } else if !has_chain(nft, patronus_firewall::feeds::THREAT_CHAIN) {
        let fetched = enabled.iter().any(|f| f.entries > 0);
        if fetched {
            (
                Status::Warn,
                "feeds are on but the firewall has no ti_check chain loaded".into(),
            )
        } else {
            (
                Status::Warn,
                "feeds are on but none has been downloaded yet".into(),
            )
        }
    } else {
        let dropping: Vec<&&FeedState> = enabled
            .iter()
            .filter(|f| f.action == "drop" && f.entries > 0)
            .collect();
        let entries: i64 = enabled.iter().map(|f| f.entries).sum();
        if dropping.is_empty() {
            (Status::Warn, format!("{} feed(s) on in alert-only mode ({entries} entries): matches are counted, not blocked", enabled.len()))
        } else {
            (
                Status::Pass,
                format!(
                    "{} feed(s) loaded, {entries} entries, {} blocking",
                    enabled.len(),
                    dropping.len()
                ),
            )
        }
    };
    let feeds_bl = i
        .settings
        .baseline_feeds
        .iter()
        .any(|b| !i.threat_feeds.iter().any(|f| &f.id == b && f.enabled));
    push!(
        "threat_feeds",
        "network",
        "Threat feeds",
        st,
        ev,
        "#feeds",
        "Threat-feed catalog",
        6,
        false,
        feeds_bl,
        Value::Null
    );

    let (st, ev) = if !i.dnssec_setting {
        (
            Status::Fail,
            "DNSSEC validation is switched off: forged DNS answers are accepted".to_string(),
        )
    } else if !live {
        unknown()
    } else {
        let d = &i.facts["dns"];
        if d["unbound_running"] == true {
            if d["validator"] == true && d["trust_anchor"] == true && d["permissive"] != true {
                (
                    Status::Pass,
                    "Unbound validates (validator module and root trust anchor loaded)".into(),
                )
            } else {
                (Status::Fail, format!(
                    "Unbound runs without validating (validator: {}, trust anchor: {}, permissive: {})",
                    d["validator"], d["trust_anchor"], d["permissive"]
                ))
            }
        } else if d["dnsmasq_running"] == true {
            (
                Status::Warn,
                "dnsmasq forwards DNS: answers are not validated on the router".into(),
            )
        } else {
            (Status::Na, "no DNS resolver runs on the router".into())
        }
    };
    push!(
        "dnssec",
        "network",
        "DNSSEC validation",
        st,
        ev,
        "/dns",
        "DNS",
        4,
        false,
        !i.dnssec_setting,
        Value::Null
    );

    let (st, ev) = if !i.wan_block_bogons {
        (
            Status::Fail,
            "off: reserved and unallocated source addresses are accepted on the WAN".to_string(),
        )
    } else if !live {
        unknown()
    } else if has_rule_comment(nft, "WAN: block bogon sources") {
        (Status::Pass, "on: the WAN guard drops bogon sources".into())
    } else {
        (
            Status::Warn,
            "switched on, but no bogon rule is loaded (no WAN interface?)".into(),
        )
    };
    push!(
        "wan_bogons",
        "network",
        "Bogon sources dropped on the WAN",
        st,
        ev,
        "/firewall#tab-hardening",
        "Firewall hardening",
        3,
        false,
        !i.wan_block_bogons,
        Value::Null
    );

    let wan_private = i.wan_addrs.iter().filter(|a| a.is_ipv4()).any(is_private);
    let (st, ev) = if wan_private {
        (Status::Na, "the WAN address is private (this router sits behind another one): private sources are normal there".to_string())
    } else if !i.wan_block_private {
        (
            Status::Fail,
            "off: private (RFC 1918 / CGNAT / ULA) sources are accepted on the WAN".into(),
        )
    } else if !live {
        unknown()
    } else if has_rule_comment(nft, "WAN: block private sources") {
        (
            Status::Pass,
            "on: the WAN guard drops private sources".into(),
        )
    } else {
        (Status::Warn, "switched on, but no rule is loaded".into())
    };
    push!(
        "wan_private",
        "network",
        "Private sources dropped on the WAN",
        st,
        ev,
        "/firewall#tab-hardening",
        "Firewall hardening",
        3,
        false,
        !wan_private && !i.wan_block_private,
        Value::Null
    );

    let (st, ev) = if !i.synflood {
        (
            Status::Fail,
            format!(
            "off: new TCP connections from the WAN are not rate-limited (kernel SYN cookies: {})",
            i.facts["system"]["tcp_syncookies"].as_str().unwrap_or("?")
        ),
        )
    } else if !live {
        unknown()
    } else if has_rule_comment(nft, "SYN flood protection") {
        (
            Status::Pass,
            "on: new WAN SYNs above the limit are dropped".into(),
        )
    } else {
        (
            Status::Warn,
            "switched on, but no rule is loaded (no WAN interface?)".into(),
        )
    };
    push!(
        "synflood",
        "network",
        "SYN flood protection",
        st,
        ev,
        "/firewall#tab-hardening",
        "Firewall hardening",
        3,
        false,
        !i.synflood,
        Value::Null
    );

    // --- services -----------------------------------------------------------------------------
    let mem = i.facts["system"]["mem_total_mb"].as_u64().unwrap_or(0);
    let (st, ev) = if !i.ids_built {
        (
            Status::Na,
            "intrusion detection is not built into this firmware (router tier: not enough memory)"
                .to_string(),
        )
    } else if !live {
        unknown()
    } else if mem < i.settings.ids_min_ram_mb as u64 {
        (
            Status::Na,
            format!(
                "{} RAM: the community rule set needs about 520 MB, recommended from {} MB",
                human_mb(mem),
                i.settings.ids_min_ram_mb
            ),
        )
    } else if i.facts["ids"]["suricata_running"] == true {
        (Status::Pass, "Suricata runs".into())
    } else if i.ids_enabled {
        (
            Status::Fail,
            "switched on, but Suricata is not running".into(),
        )
    } else {
        (
            Status::Warn,
            format!("off ({} RAM is enough to run it)", human_mb(mem)),
        )
    };
    push!(
        "ids",
        "services",
        "Intrusion detection",
        st,
        ev,
        "/svc/ids",
        "Intrusion detection",
        4,
        false,
        false,
        Value::Null
    );

    let (st, ev) = {
        let pending = i.updates["pending"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        let when = i.updates["checked_at"].as_i64();
        let age = when.map(|t| (i.now - t) / 86_400);
        let last = match age {
            Some(d) => format!("last check {d} day(s) ago, {pending} update(s) pending"),
            None => "never checked".into(),
        };
        (
            Status::Warn,
            format!("this firmware has no automatic update schedule yet: {last}; check and install from System > Updates"),
        )
    };
    push!(
        "auto_updates",
        "services",
        "Automatic security updates",
        st,
        ev,
        "/system#updates-card",
        "Updates",
        4,
        false,
        false,
        Value::Null
    );

    let (st, ev, detail) = if !live {
        let (s, e) = unknown();
        (s, e, Value::Null)
    } else {
        let mut unexpected = Vec::new();
        let mut risky = Vec::new();
        for l in i.facts["listeners"].as_array().into_iter().flatten() {
            let addr = l["addr"].as_str().unwrap_or("");
            if addr.starts_with("127.") || addr == "::1" {
                continue;
            }
            let port = l["port"].as_u64().unwrap_or(0) as u16;
            let proc_ = l["process"].as_str().unwrap_or("");
            let proto = l["proto"].as_str().unwrap_or("");
            let name = format!(
                "{proto}/{port} {}",
                if proc_.is_empty() {
                    "(unknown process)"
                } else {
                    proc_
                }
            );
            if let Some((_, what)) = RISKY_PORTS.iter().find(|(p, _)| *p == port) {
                if proto == "tcp" {
                    let exposed = wan_exposure(i, port).iter().any(|(_, e)| e.is_open());
                    risky.push(format!(
                        "{name} ({what}){}",
                        if exposed {
                            ", reachable from the WAN"
                        } else {
                            ""
                        }
                    ));
                    continue;
                }
            }
            if !MANAGED_PROCESSES.contains(&proc_) {
                unexpected.push(name);
            }
        }
        unexpected.sort();
        unexpected.dedup();
        if !risky.is_empty() {
            (
                Status::Fail,
                format!("risky services listening: {}", risky.join(", ")),
                json!({ "unexpected": unexpected, "risky": risky }),
            )
        } else if !unexpected.is_empty() {
            (
                Status::Warn,
                format!(
                    "listening but not managed by Patronus: {}",
                    unexpected.join(", ")
                ),
                json!({ "unexpected": unexpected }),
            )
        } else {
            (
                Status::Pass,
                "every listening service is one Patronus manages".into(),
                Value::Null,
            )
        }
    };
    push!(
        "services",
        "services",
        "No unused services listening",
        st,
        ev,
        "/system#services-card",
        "Services",
        3,
        false,
        false,
        detail
    );

    // --- VPN ----------------------------------------------------------------------------------
    let kernel: Vec<&Value> = i.facts["wg"]["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let (st, ev, detail) = if !live {
        let (s, e) = unknown();
        (s, e, Value::Null)
    } else if kernel.is_empty() && i.wg_store.is_empty() {
        (Status::Na, "no WireGuard peers".into(), Value::Null)
    } else {
        let name_of = |k: &str| {
            i.wg_store
                .iter()
                .find(|p| p.public_key == k)
                .map(|p| format!("{} ({})", p.name, p.interface))
                .unwrap_or_else(|| format!("{}…", &k[..k.len().min(8)]))
        };
        let nopsk: Vec<String> = kernel
            .iter()
            .filter(|p| p["preshared_key"] == false)
            .map(|p| name_of(p["public_key"].as_str().unwrap_or("")))
            .collect();
        if nopsk.is_empty() {
            (
                Status::Pass,
                format!("all {} peers use a preshared key", kernel.len()),
                Value::Null,
            )
        } else {
            (Status::Warn, format!(
                "peers without a preshared key (no post-quantum layer, a leaked private key opens old captures): {}",
                nopsk.join(", ")
            ), json!({ "peers": nopsk }))
        }
    };
    push!(
        "wg_psk",
        "vpn",
        "WireGuard peers use preshared keys",
        st,
        ev,
        "/vpn",
        "VPN",
        2,
        false,
        false,
        detail
    );

    let (st, ev, detail) = if i.wg_store.is_empty() {
        (Status::Na, "no WireGuard peers".into(), Value::Null)
    } else {
        let limit = i.settings.wg_silent_days as i64 * 86_400;
        let mut silent = Vec::new();
        for p in i.wg_store.iter().filter(|p| p.enabled) {
            let k_hs = kernel
                .iter()
                .find(|k| k["public_key"] == p.public_key.as_str())
                .and_then(|k| k["latest_handshake"].as_i64())
                .unwrap_or(0);
            let seen = k_hs.max(i.wg_seen.get(&p.public_key).copied().unwrap_or(0));
            let since = if seen > 0 { seen } else { p.updated_at };
            if i.now - since > limit {
                silent.push(json!({
                    "id": p.id, "name": p.name, "interface": p.interface,
                    "last_seen": if seen > 0 { json!(seen) } else { Value::Null },
                    "days": (i.now - since) / 86_400,
                }));
            }
        }
        if silent.is_empty() {
            (
                Status::Pass,
                format!(
                    "every enabled peer connected within {} days",
                    i.settings.wg_silent_days
                ),
                Value::Null,
            )
        } else {
            let names: Vec<String> = silent
                .iter()
                .map(|s| format!("{} ({} days)", s["name"].as_str().unwrap_or(""), s["days"]))
                .collect();
            (
                Status::Warn,
                format!(
                    "peers silent for more than {} days (unused keys are standing access): {}",
                    i.settings.wg_silent_days,
                    names.join(", ")
                ),
                json!({ "silent": silent }),
            )
        }
    };
    push!(
        "wg_silent",
        "vpn",
        "No silent WireGuard peers",
        st,
        ev,
        "/vpn",
        "VPN",
        2,
        false,
        false,
        detail
    );

    let (st, ev) = if !live {
        unknown()
    } else {
        let ip = &i.facts["ipsec"];
        let props: Vec<&Value> = ip["proposals"].as_array().into_iter().flatten().collect();
        let sas: Vec<&str> = ip["sa_algorithms"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if props.is_empty() && sas.is_empty() {
            (Status::Na, "no IPsec connections loaded".into())
        } else {
            let mut bad = Vec::new();
            for p in &props {
                for prop in p["proposals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    let w = weak_algorithms(prop);
                    if !w.is_empty() {
                        bad.push(format!(
                            "{} offers {prop} ({})",
                            p["block"].as_str().unwrap_or("?"),
                            w.join(", ")
                        ));
                    }
                }
            }
            for s in &sas {
                let w = weak_algorithms(s);
                if !w.is_empty() {
                    bad.push(format!("an SA that is up uses {s} ({})", w.join(", ")));
                }
            }
            if bad.is_empty() {
                (
                    Status::Pass,
                    format!(
                        "{} proposal line(s) loaded, none below the current recommendation",
                        props.len()
                    ),
                )
            } else {
                (Status::Fail, bad.join("; "))
            }
        }
    };
    push!(
        "ipsec_weak",
        "vpn",
        "IPsec proposals are current",
        st,
        ev,
        "/vpn",
        "VPN",
        3,
        false,
        false,
        Value::Null
    );

    let (st, ev) = if !live {
        unknown()
    } else {
        let o: Vec<&Value> = i.facts["openvpn"]
            .as_array()
            .into_iter()
            .flatten()
            .collect();
        if o.is_empty() {
            (Status::Na, "no OpenVPN instance runs".into())
        } else {
            let mut fail = Vec::new();
            let mut warn = Vec::new();
            for x in &o {
                let name = x["config"].as_str().unwrap_or("(command line)").to_string();
                if x["weak_cipher"] == true {
                    fail.push(format!("{name} allows a weak data cipher"));
                }
                if x["tls_crypt"] != true {
                    if x["tls_auth"] == true {
                        warn.push(format!(
                            "{name} uses tls-auth (authenticates, does not encrypt the handshake)"
                        ));
                    } else {
                        fail.push(format!("{name} has neither tls-crypt nor tls-auth"));
                    }
                }
            }
            if !fail.is_empty() {
                (
                    Status::Fail,
                    fail.into_iter().chain(warn).collect::<Vec<_>>().join("; "),
                )
            } else if !warn.is_empty() {
                (Status::Warn, warn.join("; "))
            } else {
                (
                    Status::Pass,
                    format!("{} instance(s), all with tls-crypt", o.len()),
                )
            }
        }
    };
    push!(
        "openvpn_tls",
        "vpn",
        "OpenVPN uses tls-crypt",
        st,
        ev,
        "/vpn",
        "VPN",
        2,
        false,
        false,
        Value::Null
    );

    out
}

/// `31485` MB -> `30.7 GB`, `512` -> `512 MB`.
pub fn human_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

/// Score 0..100 and letter grade. Warn counts half; n/a is left out; an
/// unreadable check counts as a warning; a critical failure caps at D.
pub fn grade(checks: &[Check]) -> (u32, &'static str) {
    let mut total = 0u32;
    let mut got = 0u32;
    let mut crit = false;
    for c in checks {
        match c.status {
            Status::Na => continue,
            Status::Pass => got += 2 * c.weight,
            Status::Warn | Status::Unknown => got += c.weight,
            Status::Fail => crit |= c.critical,
        }
        total += 2 * c.weight;
    }
    let score = (got * 100 + total / 2).checked_div(total).unwrap_or(100);
    let mut g = match score {
        90.. => "A",
        80..=89 => "B",
        65..=79 => "C",
        50..=64 => "D",
        _ => "F",
    };
    if crit && matches!(g, "A" | "B" | "C") {
        g = "D";
    }
    (score, g)
}

// ---------------------------------------------------------------------------
// baseline plan (pure)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    System { key: String, value: String },
    Lan { key: String, value: String },
    Guard,
    SshPasswordOff,
    Feed { id: String },
    DisableRule { id: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub check: &'static str,
    pub title: String,
    pub before: String,
    pub after: String,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub check: &'static str,
    pub title: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub skipped: Vec<Skipped>,
    /// Changes the server will make for this token, nothing else.
    pub token: String,
    /// The admin's own connection, as the router sees it.
    pub session: Value,
}

/// The admin's management path: where their connection comes from.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionPath {
    pub addr: Option<IpAddr>,
    /// Interface the router reaches that address through.
    pub dev: Option<String>,
    pub over_wan: bool,
}

pub fn plan(i: &Inputs, checks: &[Check], s: &SessionPath) -> Plan {
    let mut changes = Vec::new();
    let mut skipped = Vec::new();
    let st = |id: &str| checks.iter().find(|c| c.id == id).map(|c| c.status);

    if i.guard_built && !i.guard_enabled {
        changes.push(Change {
            check: "guard",
            title: "Turn on brute-force protection".into(),
            before: "off".into(),
            after: "on (5 failures in 10 min = 15 min ban, LAN never banned)".into(),
            action: Action::Guard,
        });
    }
    for f in &i.settings.baseline_feeds {
        if i.threat_feeds.iter().any(|x| &x.id == f && x.enabled) {
            continue;
        }
        let name = patronus_firewall::feeds::catalog_feed(f)
            .map(|c| c.name)
            .unwrap_or(f.as_str());
        changes.push(Change {
            check: "threat_feeds",
            title: format!("Turn on threat feed {name}"),
            before: "off".into(),
            after: "on, drop, refreshed daily".into(),
            action: Action::Feed { id: f.clone() },
        });
    }
    if !i.dnssec_setting {
        changes.push(Change {
            check: "dnssec",
            title: "Validate DNS answers (DNSSEC)".into(),
            before: "off".into(),
            after: "on".into(),
            action: Action::Lan {
                key: "dns.dnssec".into(),
                value: "1".into(),
            },
        });
    }
    let bogon_session = s.over_wan && s.addr.as_ref().is_some_and(is_bogon);
    let private_session = s.over_wan && s.addr.as_ref().is_some_and(is_private);
    if !i.wan_block_bogons {
        if bogon_session {
            skipped.push(Skipped {
                check: "wan_bogons",
                title: "Drop bogon sources on the WAN".into(),
                reason: format!(
                    "you are connected over the WAN from {}, a reserved address: this would cut your session",
                    s.addr.map(|a| a.to_string()).unwrap_or_default()
                ),
            });
        } else {
            changes.push(Change {
                check: "wan_bogons",
                title: "Drop bogon sources on the WAN".into(),
                before: "off".into(),
                after: "on".into(),
                action: Action::System {
                    key: patronus_firewall::wanguard::CFG_BLOCK_BOGONS.into(),
                    value: "1".into(),
                },
            });
        }
    }
    if !i.wan_block_private {
        if st("wan_private") == Some(Status::Na) {
            skipped.push(Skipped {
                check: "wan_private",
                title: "Drop private sources on the WAN".into(),
                reason: "the WAN address is private: this router is behind another one, private sources are normal".into(),
            });
        } else if private_session {
            skipped.push(Skipped {
                check: "wan_private",
                title: "Drop private sources on the WAN".into(),
                reason: format!(
                    "you are connected over the WAN from the private address {}: this would cut your session",
                    s.addr.map(|a| a.to_string()).unwrap_or_default()
                ),
            });
        } else {
            changes.push(Change {
                check: "wan_private",
                title: "Drop private sources on the WAN".into(),
                before: "off".into(),
                after: "on".into(),
                action: Action::System {
                    key: patronus_firewall::wanguard::CFG_BLOCK_PRIVATE.into(),
                    value: "1".into(),
                },
            });
        }
    }
    if !i.synflood {
        changes.push(Change {
            check: "synflood",
            title: "Rate-limit new TCP connections from the WAN (SYN flood)".into(),
            before: "off".into(),
            after: format!(
                "on ({}, burst {})",
                patronus_firewall::hardening::DEFAULT_SYNFLOOD_RATE,
                patronus_firewall::hardening::DEFAULT_SYNFLOOD_BURST
            ),
            action: Action::System {
                key: patronus_firewall::hardening::SYNFLOOD_KEY.into(),
                value: "1".into(),
            },
        });
    }
    if let Some(c) = checks.iter().find(|c| c.id == "ssh_keys" && c.in_baseline) {
        let keys = i.facts["ssh"]["authorized_keys"].as_u64().unwrap_or(0);
        let ca = i.facts["ssh"]["sshd"]["trustedusercakeys"][0]
            .as_str()
            .is_some_and(|v| v != "none");
        if keys == 0 && !ca {
            skipped.push(Skipped {
                check: "ssh_keys",
                title: "SSH: keys only".into(),
                reason: "no SSH key (and no user CA) is installed: switching passwords off would leave no way in over SSH; add a key first".into(),
            });
        } else {
            changes.push(Change {
                check: "ssh_keys",
                title: "SSH: keys only, no password logins".into(),
                before: c.evidence.clone(),
                after: format!("password logins off ({keys} authorized key(s) installed)"),
                action: Action::SshPasswordOff,
            });
        }
    }
    for (check, ports, what) in [
        ("web_wan", &i.web_ports, "web UI"),
        ("ssh_wan", &vec![i.ssh_port], "SSH"),
    ] {
        if !matches!(st(check), Some(Status::Fail | Status::Warn)) {
            continue;
        }
        for r in i
            .wan_rules
            .iter()
            .filter(|r| ports.iter().any(|p| r.covers(*p)))
        {
            let carries_session = s.over_wan
                && (check == "web_wan"
                    || r.ports.is_none()
                    || i.web_ports.iter().any(|p| r.covers(*p)));
            if carries_session {
                skipped.push(Skipped {
                    check,
                    title: format!("Disable firewall rule \"{}\" ({what} from the WAN)", r.name),
                    reason: format!(
                        "your own session arrives over the WAN ({} on {}): this rule may be how you are connected",
                        s.addr.map(|a| a.to_string()).unwrap_or_default(),
                        s.dev.clone().unwrap_or_default()
                    ),
                });
                continue;
            }
            if changes
                .iter()
                .any(|c| c.action == Action::DisableRule { id: r.id })
            {
                continue;
            }
            changes.push(Change {
                check,
                title: format!("Disable firewall rule \"{}\"", r.name),
                before: format!("opens {what} on the WAN"),
                after: "disabled (kept, can be switched back on)".into(),
                action: Action::DisableRule { id: r.id },
            });
        }
    }
    for c in checks {
        if matches!(c.status, Status::Fail | Status::Warn)
            && !c.in_baseline
            && !skipped.iter().any(|s| s.check == c.id)
            && !changes.iter().any(|x| x.check == c.id)
        {
            skipped.push(Skipped {
                check: c.id,
                title: c.title.to_string(),
                reason: match c.id {
                    "dnssec" => "validation is already switched on; Unbound is not validating (see the DNS page: usually the root trust anchor could not be fetched)".into(),
                    "admin_2fa" => "needs each admin to enrol an authenticator app".into(),
                    "ids" => "Suricata costs about 520 MB and the interface to watch is your choice".into(),
                    "auto_updates" => "no automatic update schedule in this firmware yet".into(),
                    "wg_psk" | "ipsec_weak" | "openvpn_tls" => "the other end of the tunnel must change too".into(),
                    "wg_silent" => "disable or delete each silent peer yourself (it may be a rarely used client)".into(),
                    "services" => "stop or uninstall those services on the System page".into(),
                    "web_wan" | "ssh_wan" => "the rule that opens it is not one Patronus can safely switch off (any interface, or not in the store)".into(),
                    "std_ports" => "moving the ports back changes how you reach the router".into(),
                    _ => "not something the baseline changes".into(),
                },
            });
        }
    }
    let token = {
        use sha2::{Digest, Sha256};
        let acts: Vec<&Action> = changes.iter().map(|c| &c.action).collect();
        let h = Sha256::digest(serde_json::to_vec(&acts).unwrap_or_default());
        h.iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    Plan {
        changes,
        skipped,
        token,
        session: json!(s),
    }
}

// ---------------------------------------------------------------------------
// gathering (IO)
// ---------------------------------------------------------------------------

fn wan_addresses(ip_json: &str, devs: &[String]) -> Vec<IpAddr> {
    let v: Value = serde_json::from_str(ip_json).unwrap_or_default();
    let mut out = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        if !devs.iter().any(|d| link["ifname"] == d.as_str()) {
            continue;
        }
        for a in link["addr_info"].as_array().into_iter().flatten() {
            if let Some(ip) = a["local"].as_str().and_then(|s| s.parse().ok()) {
                out.push(ip);
            }
        }
    }
    out
}

fn ports_of(p: &Option<PortSpec>) -> Option<Option<Vec<(u16, u16)>>> {
    match p {
        None => Some(None),
        Some(PortSpec::Single(n)) => Some(Some(vec![(*n, *n)])),
        Some(PortSpec::Range(a, b)) => Some(Some(vec![(*a, *b)])),
        Some(PortSpec::Multiple(v)) => Some(Some(v.iter().map(|n| (*n, *n)).collect())),
        // a port alias: its contents can change, never switched off automatically
        Some(PortSpec::Alias(_)) => None,
    }
}

async fn wan_rules(store: &ConfigStore, wan_devs: &[String]) -> Vec<WanRule> {
    let Ok(rules) = store.load_firewall_rules_with_origin().await else {
        return Vec::new();
    };
    rules
        .into_iter()
        .filter(|(r, o)| {
            *o != patronus_config::RuleOrigin::System
                && r.enabled
                && r.chain == ChainType::Input
                && r.action == FirewallAction::Accept
                && r.schedule.is_none()
                && r.source
                    .as_deref()
                    .map(|s| s.is_empty() || s == "any")
                    .unwrap_or(true)
                && matches!(r.protocol, None | Some(Protocol::Tcp) | Some(Protocol::All))
                && r.interface_in
                    .as_deref()
                    .is_some_and(|i| i == "@wan" || wan_devs.iter().any(|d| d == i))
        })
        .filter_map(|(r, _)| {
            Some(WanRule {
                id: r.id?,
                name: r.name.clone(),
                ports: ports_of(&r.dport)?,
            })
        })
        .collect()
}

async fn lan_setting(store: &ConfigStore, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM lan_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(store.pool().ok()?)
        .await
        .ok()
        .flatten()
}

fn flag(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "yes" | "on")
}

pub async fn gather(state: &AppState) -> Inputs {
    let store = &*state.config_store;
    let settings = load_settings(store).await.unwrap_or_default();
    let (facts, facts_error) = match state.system.system_op("posture_facts", json!({})).await {
        Ok(v) => (v, None),
        Err(e) => (Value::Null, Some(e.to_string())),
    };
    let wan_devs = store.interfaces_with_role("wan").await.unwrap_or_default();
    let ip_json = tokio::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let wan_addrs = wan_addresses(&ip_json, &wan_devs);
    let guard = patronus_firewall::guard::load(store).await.ok();
    let aliases = patronus_firewall::aliases::load_aliases(store)
        .await
        .unwrap_or_default();
    let threat_feeds = aliases
        .iter()
        .filter_map(|a| {
            let s = a.source.as_ref()?;
            (s.kind == patronus_firewall::feeds::KIND_THREAT).then(|| FeedState {
                id: a
                    .name
                    .trim_start_matches(patronus_firewall::feeds::THREAT_PREFIX)
                    .to_string(),
                enabled: s.enabled,
                action: s.action.clone(),
                entries: a.entries.len() as i64,
            })
        })
        .collect();
    let wg = patronus_firewall::wanguard::load(store)
        .await
        .unwrap_or_default();
    let hard = patronus_firewall::hardening::load(store)
        .await
        .unwrap_or_default();
    let web = patronus_config::webui::resolve(Some(store)).await;
    let ssh_port = patronus_network::ssh::configured_port(store).await;
    let admins: Vec<(String, bool)> = match store.pool() {
        Ok(pool) => sqlx::query(
            "SELECT username, totp_secret IS NOT NULL FROM web_users WHERE enabled = 1 AND role = 'admin'",
        )
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.iter()
                .map(|r| (r.get::<String, _>(0), r.get::<bool, _>(1)))
                .collect()
        })
        .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let wg_store: Vec<WgStorePeer> = match store.pool() {
        Ok(pool) => sqlx::query(
            "SELECT id, interface, name, public_key, enabled, updated_at FROM wg_peers ORDER BY interface, name",
        )
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.iter()
                .map(|r| WgStorePeer {
                    id: r.get(0),
                    interface: r.get(1),
                    name: r.get(2),
                    public_key: r.get(3),
                    enabled: r.get::<i64, _>(4) != 0,
                    updated_at: r.get(5),
                })
                .collect()
        })
        .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let wg_seen = wg_seen(store).await;
    let updates = patronus_network::sysops::pending_from_last_check(std::path::Path::new(
        &std::env::var("PATRONUS_UPDATE_DIR").unwrap_or_else(|_| "/var/lib/patronus/update".into()),
    ));
    Inputs {
        facts,
        facts_error,
        wan_rules: wan_rules(store, &wan_devs).await,
        wan_devs,
        wan_addrs,
        guard_built: cfg!(feature = "bruteforce"),
        guard_enabled: guard.map(|g| g.enabled).unwrap_or(false),
        threat_feeds,
        dnssec_setting: flag(
            &lan_setting(store, "dns.dnssec")
                .await
                .unwrap_or_else(|| "1".into()),
        ),
        wan_block_private: wg.block_private,
        wan_block_bogons: wg.block_bogons,
        synflood: hard.synflood,
        ssh_port,
        web_ports: web.all_ports(),
        https_port: web.https_port,
        redirect_port: web.http_redirect_port,
        totp_built: cfg!(feature = "totp"),
        admins,
        ids_built: cfg!(feature = "intrusion-detection"),
        ids_enabled: flag(&lan_setting(store, "ids.enabled").await.unwrap_or_default()),
        wg_store,
        wg_seen,
        updates,
        settings,
        now: chrono::Utc::now().timestamp(),
    }
}

/// Where the admin's connection comes from (`ip route get`).
pub async fn session_path(state: &AppState, addr: Option<IpAddr>) -> SessionPath {
    let Some(a) = addr else {
        return SessionPath::default();
    };
    let a = match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
        x => x,
    };
    let dev = tokio::process::Command::new("ip")
        .args(["-j", "route", "get", &a.to_string()])
        .output()
        .await
        .ok()
        .and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok())
        .and_then(|v| v[0]["dev"].as_str().map(str::to_string));
    let wan = state
        .config_store
        .interfaces_with_role("wan")
        .await
        .unwrap_or_default();
    SessionPath {
        over_wan: dev.as_ref().is_some_and(|d| wan.contains(d)),
        addr: Some(a),
        dev,
    }
}

pub async fn overview(state: &AppState) -> Value {
    let i = gather(state).await;
    let checks = run_checks(&i);
    let (score, letter) = grade(&checks);
    let rev = state
        .config_store
        .load_system_config(K_BASELINE_REVISION)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok());
    json!({
        "score": score,
        "grade": letter,
        "checks": checks,
        "counts": {
            "pass": checks.iter().filter(|c| c.status == Status::Pass).count(),
            "warn": checks.iter().filter(|c| c.status == Status::Warn).count(),
            "fail": checks.iter().filter(|c| c.status == Status::Fail).count(),
            "na": checks.iter().filter(|c| c.status == Status::Na).count(),
            "unknown": checks.iter().filter(|c| c.status == Status::Unknown).count(),
        },
        "baseline_revision": rev,
        "settings": i.settings,
        "defaults": Settings::default(),
        "live": !i.facts.is_null(),
        "live_error": i.facts_error,
        "checked_at": i.now,
    })
}

// ---------------------------------------------------------------------------
// apply / undo
// ---------------------------------------------------------------------------

/// Write and apply the plan as ONE configuration revision. Returns the
/// revision taken before (Undo restores it).
pub async fn apply_plan(
    state: &AppState,
    p: &Plan,
    user: &str,
) -> anyhow::Result<(i64, Vec<String>)> {
    let store = &*state.config_store;
    if p.changes.is_empty() {
        anyhow::bail!(
            "Invalid request: nothing to change, the recommended baseline is already in place"
        );
    }
    let rev = store
        .snapshot(user, "before security baseline")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut lines = Vec::new();
    let mut need_dns = false;
    let mut need_ssh = false;
    let mut need_guard = false;
    let mut feeds = Vec::new();
    let write = async {
        for c in &p.changes {
            match &c.action {
                Action::System { key, value } => store.save_system_config(key, value).await?,
                Action::Lan { key, value } => {
                    sqlx::query(
                        "INSERT INTO lan_settings (key, value, updated_at) VALUES (?, ?, ?)
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    )
                    .bind(key)
                    .bind(value)
                    .bind(chrono::Utc::now().timestamp())
                    .execute(store.pool()?)
                    .await
                    .map_err(|e| patronus_core::Error::Config(format!("lan setting: {e}")))?;
                    need_dns |= key.starts_with("dns.");
                }
                Action::Guard => {
                    patronus_firewall::guard::save(
                        store,
                        &patronus_firewall::guard::SettingsIn {
                            enabled: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;
                    need_guard = true;
                }
                Action::SshPasswordOff => {
                    patronus_network::ssh::save_settings(
                        store,
                        &patronus_network::ssh::SshInput {
                            password_auth: Some(false),
                            ..Default::default()
                        },
                    )
                    .await?;
                    need_ssh = true;
                }
                Action::Feed { id } => {
                    let name = patronus_firewall::feeds::threat_alias_name(id);
                    let old = patronus_firewall::aliases::get_alias(store, &name).await?;
                    let cat = patronus_firewall::feeds::catalog_feed(id);
                    let mut src = old
                        .as_ref()
                        .and_then(|a| a.source.clone())
                        .unwrap_or_else(|| {
                            patronus_firewall::aliases::AliasSource::new(patronus_firewall::feeds::KIND_THREAT)
                        });
                    src.enabled = true;
                    src.action = "drop".into();
                    if src.url.is_none() {
                        src.url = cat.map(|c| c.url.to_string());
                    }
                    let a = patronus_firewall::aliases::Alias {
                        name: name.clone(),
                        kind: patronus_firewall::nftables::AliasKind::Host,
                        entries: old.as_ref().map(|a| a.entries.clone()).unwrap_or_default(),
                        description: old
                            .as_ref()
                            .and_then(|a| a.description.clone())
                            .or_else(|| cat.map(|c| c.name.to_string())),
                        source: Some(src),
                    };
                    patronus_firewall::aliases::save_alias(store, &a).await?;
                    feeds.push(name);
                }
                Action::DisableRule { id } => {
                    if let Some((mut r, _)) = store.get_firewall_rule(*id).await? {
                        r.enabled = false;
                        store.update_firewall_rule(*id, &r).await?;
                    }
                }
            }
            lines.push(c.title.clone());
        }
        Ok::<(), patronus_core::Error>(())
    }
    .await;
    let applied = match write {
        Err(e) => Err(format!("{e}")),
        Ok(()) => apply_affected(state, need_dns, need_ssh, need_guard).await,
    };
    if let Err(e) = applied {
        if let Err(re) = store.restore_revision(rev, user).await {
            tracing::error!("security baseline: could not restore revision {rev}: {re}");
        }
        let _ = apply_affected(state, need_dns, need_ssh, need_guard).await;
        anyhow::bail!("the baseline was undone because it could not be applied: {e}");
    }
    store
        .save_system_config(K_BASELINE_REVISION, &rev.to_string())
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = store
        .audit(
            user,
            "apply",
            "security",
            Some("baseline"),
            &json!({ "changes": lines, "revision_before": rev }),
        )
        .await;
    for f in feeds {
        crate::state::FirewallManager::spawn_refresh(state.firewall.clone(), f);
    }
    Ok((rev, lines))
}

async fn apply_affected(state: &AppState, dns: bool, ssh: bool, guard: bool) -> Result<(), String> {
    state
        .firewall
        .apply_rules()
        .await
        .map_err(|e| format!("firewall: {e}"))?;
    if guard {
        guard_applier()
            .apply(&state.config_store)
            .await
            .map_err(|e| format!("brute-force protection: {e}"))?;
    }
    if dns && cfg!(feature = "dns") {
        state
            .lan
            .reapply("dns")
            .await
            .map_err(|e| format!("DNS: {e}"))?;
    }
    if ssh {
        state
            .lan
            .reapply("ssh")
            .await
            .map_err(|e| format!("SSH: {e}"))?;
    }
    Ok(())
}

fn guard_applier() -> std::sync::Arc<dyn patronus_config::Applier> {
    static A: std::sync::OnceLock<std::sync::Arc<dyn patronus_config::Applier>> =
        std::sync::OnceLock::new();
    A.get_or_init(|| {
        patronus_network::applyd::RemoteApplier::wrap(std::sync::Arc::new(
            patronus_firewall::guard::GuardApplier,
        ))
    })
    .clone()
}

/// Undo: restore the revision taken before the baseline and apply everything.
pub async fn undo(state: &AppState, rev: i64, user: &str) -> anyhow::Result<Vec<String>> {
    let store = &*state.config_store;
    store
        .restore_revision(rev, user)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let lines = state
        .system
        .apply_everything(store)
        .await
        .map_err(|e| anyhow::anyhow!("restored revision {rev}, but applying it failed: {e}"))?;
    // the guard is not one of the system appliers
    let _ = guard_applier().apply(store).await;
    let _ = store
        .audit(
            user,
            "undo",
            "security",
            Some("baseline"),
            &json!({ "revision": rev }),
        )
        .await;
    Ok(lines)
}

// ---------------------------------------------------------------------------
// measured history: feed hits, WireGuard handshakes (NON_CONFIG)
// ---------------------------------------------------------------------------

/// Packets per feed since `since` (hourly buckets).
pub async fn feed_hits_since(
    store: &ConfigStore,
    since: i64,
) -> anyhow::Result<HashMap<String, u64>> {
    let rows =
        sqlx::query("SELECT feed, SUM(packets) FROM sec_feed_hits WHERE hour >= ? GROUP BY feed")
            .bind(since - since.rem_euclid(3600))
            .fetch_all(store.pool()?)
            .await?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<String, _>(0), r.get::<i64, _>(1).max(0) as u64))
        .collect())
}

/// Hourly series per feed since `since`: feed -> [(hour, packets)].
pub async fn feed_hit_series(
    store: &ConfigStore,
    since: i64,
) -> anyhow::Result<BTreeMap<String, Vec<(i64, u64)>>> {
    let rows = sqlx::query(
        "SELECT feed, hour, packets FROM sec_feed_hits WHERE hour >= ? ORDER BY feed, hour",
    )
    .bind(since - since.rem_euclid(3600))
    .fetch_all(store.pool()?)
    .await?;
    let mut m: BTreeMap<String, Vec<(i64, u64)>> = BTreeMap::new();
    for r in rows {
        m.entry(r.get(0))
            .or_default()
            .push((r.get(1), r.get::<i64, _>(2).max(0) as u64));
    }
    Ok(m)
}

async fn wg_seen(store: &ConfigStore) -> HashMap<String, i64> {
    let Ok(pool) = store.pool() else {
        return HashMap::new();
    };
    sqlx::query("SELECT public_key, last_handshake FROM sec_wg_seen")
        .fetch_all(pool)
        .await
        .map(|rows| rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        .unwrap_or_default()
}

/// Delta of a kernel counter that restarts at every ruleset load.
pub fn counter_delta(last: u64, cur: u64) -> u64 {
    if cur >= last {
        cur - last
    } else {
        cur
    }
}

/// One sampler round: kernel feed counters -> hourly history, WireGuard
/// handshakes -> last seen. `nft` is the JSON of the ti_check chain (or the
/// table), `wg` the posture `wg` facts.
pub async fn record_sample(
    store: &ConfigStore,
    nft: &Value,
    wg: Option<&Value>,
    now: i64,
    keep_days: u32,
) -> anyhow::Result<()> {
    let pool = store.pool()?;
    let hour = now - now.rem_euclid(3600);
    for (feed, (packets, bytes)) in patronus_firewall::feeds::live_hits(nft) {
        let last: Option<(i64, i64)> =
            sqlx::query_as("SELECT packets, bytes FROM sec_feed_counter_pos WHERE feed = ?")
                .bind(&feed)
                .fetch_optional(pool)
                .await?;
        let (dp, db) = match last {
            Some((lp, lb)) => (
                counter_delta(lp.max(0) as u64, packets),
                counter_delta(lb.max(0) as u64, bytes),
            ),
            None => (packets, bytes),
        };
        sqlx::query(
            "INSERT INTO sec_feed_counter_pos (feed, packets, bytes, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(feed) DO UPDATE SET packets = excluded.packets, bytes = excluded.bytes, updated_at = excluded.updated_at",
        )
        .bind(&feed)
        .bind(packets as i64)
        .bind(bytes as i64)
        .bind(now)
        .execute(pool)
        .await?;
        if dp > 0 || db > 0 {
            sqlx::query(
                "INSERT INTO sec_feed_hits (feed, hour, packets, bytes) VALUES (?, ?, ?, ?)
                 ON CONFLICT(feed, hour) DO UPDATE SET packets = packets + excluded.packets, bytes = bytes + excluded.bytes",
            )
            .bind(&feed)
            .bind(hour)
            .bind(dp as i64)
            .bind(db as i64)
            .execute(pool)
            .await?;
        }
    }
    if let Some(wg) = wg {
        for p in wg["peers"].as_array().into_iter().flatten() {
            let hs = p["latest_handshake"].as_i64().unwrap_or(0);
            if hs <= 0 {
                continue;
            }
            sqlx::query(
                "INSERT INTO sec_wg_seen (interface, public_key, last_handshake) VALUES (?, ?, ?)
                 ON CONFLICT(interface, public_key) DO UPDATE SET last_handshake = MAX(last_handshake, excluded.last_handshake)",
            )
            .bind(p["interface"].as_str().unwrap_or(""))
            .bind(p["public_key"].as_str().unwrap_or(""))
            .bind(hs)
            .execute(pool)
            .await?;
        }
    }
    sqlx::query("DELETE FROM sec_feed_hits WHERE hour < ?")
        .bind(now - keep_days as i64 * 86_400)
        .execute(pool)
        .await?;
    Ok(())
}

async fn read_ti_chain(state: &AppState) -> Option<Value> {
    // patronus-web has CAP_NET_ADMIN: read the chain directly, else through applyd
    if let Ok(o) = tokio::process::Command::new("nft")
        .args([
            "-j",
            "list",
            "chain",
            "inet",
            "patronus",
            patronus_firewall::feeds::THREAT_CHAIN,
        ])
        .output()
        .await
    {
        if o.status.success() {
            return serde_json::from_slice(&o.stdout).ok();
        }
        // no chain = no feed on: nothing to count
        if String::from_utf8_lossy(&o.stderr).contains("No such file") {
            return Some(json!({ "nftables": [] }));
        }
    }
    state
        .system
        .system_op("posture_facts", json!({ "parts": ["nft"] }))
        .await
        .ok()
        .map(|v| v["nft"]["main"].clone())
}

/// Background sampler (feed hit counters, WireGuard handshakes).
pub fn spawn_sampler(state: AppState) {
    tokio::spawn(async move {
        let mut wg_tick = 0u32;
        loop {
            let s = load_settings(&state.config_store).await.unwrap_or_default();
            let nft = read_ti_chain(&state).await.unwrap_or(Value::Null);
            wg_tick += s.sample_secs;
            let wg = if wg_tick >= 300 {
                wg_tick = 0;
                let any: bool = match state.config_store.pool() {
                    Ok(p) => sqlx::query_scalar::<_, i64>("SELECT count(*) FROM wg_peers")
                        .fetch_one(p)
                        .await
                        .map(|n| n > 0)
                        .unwrap_or(false),
                    Err(_) => false,
                };
                if any {
                    state
                        .system
                        .system_op("posture_facts", json!({ "parts": ["wg"] }))
                        .await
                        .ok()
                        .map(|v| v["wg"].clone())
                } else {
                    None
                }
            } else {
                None
            };
            if let Err(e) = record_sample(
                &state.config_store,
                &nft,
                wg.as_ref(),
                chrono::Utc::now().timestamp(),
                s.feed_hits_days,
            )
            .await
            {
                tracing::debug!("security sampler: {e}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(s.sample_secs as u64)).await;
        }
    });
}

#[cfg(test)]
mod tests;
