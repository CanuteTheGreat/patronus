//! Brute-force protection (lane B, docs/BRUTE-FORCE.md): the sshguard / fail2ban /
//! CrowdSec-bouncer role, built in and cheap enough for the router tier.
//!
//! Failed logins come from three places:
//!
//! - **SSH**: OpenSSH (`sshd`, `sshd-session`) and Dropbear messages, read from the
//!   system log files (`guard.log_files`, `auto` = the one auth log this system
//!   writes) and, on systemd, from the journal (`journalctl -f`);
//! - **web UI**: patronus-web reports every refused login (wrong password, wrong
//!   two-factor code) into `guard_reports`, because it runs unprivileged and cannot
//!   touch the firewall itself.
//!
//! An address (an IPv4 address, or the IPv6 prefix `guard.ipv6_prefix`, default /64,
//! since an attacker owns a whole /64) that fails `guard.max_failures` times within
//! `guard.find_secs` is banned for `guard.ban_secs`; with `guard.escalate` every
//! further ban inside `guard.escalate_window_secs` doubles, up to `guard.ban_max_secs`.
//! Addresses on the allow list, loopback and (`guard.exempt_lan`, default on) the
//! router's own LAN subnets are never banned, so a mistyped password can not lock the
//! administrator out of the box he sits next to.
//!
//! Enforcement is an own table `inet patronus_guard` (hook priority -20, ahead of
//! every other Patronus table), so it survives every firewall re-apply: the sets
//! `ban4` (`flags timeout`) and `ban6` (`flags interval, timeout`) drop everything
//! from a banned source, to the router (input) and through it (forward, port
//! forwards included). The kernel expires each element by itself; the store
//! (`guard_bans`) is the source of truth and every sync rewrites both sets in one
//! atomic `nft -f`, so bans survive a reboot and an unban from the web UI or the CLI
//! takes effect in any process.
//!
//! Log lines are attacker-influenced (a user name can contain `from 1.2.3.4`): the
//! address is taken from the END of the message, where sshd/dropbear put it, and a
//! syslog-style line counts only when its tag is one of the SSH daemons.

use async_trait::async_trait;
use ipnetwork::{IpNetwork, Ipv6Network};
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const TABLE_NAME: &str = "patronus_guard";
/// Hook priority of the guard chains: before segmentation (-10), time limits (-11),
/// DNS policy (-12), guest (-15) and the main table (0).
pub const PRIORITY: i32 = -20;
/// Login sources the engine knows.
pub const SOURCES: &[&str] = &["sshd", "dropbear", "web"];
/// Log files tried, in order, when `guard.log_files` is `auto` and the journal is not used.
pub const AUTO_LOG_FILES: &[&str] = &["/var/log/auth.log", "/var/log/secure", "/var/log/messages"];
/// Syslog tags whose messages may count.
const SSH_TAGS: &[&str] = &["sshd", "sshd-session", "sshd-auth", "dropbear"];
/// Bytes read from one log file per tick (a flood is read over several ticks).
const MAX_READ_PER_TICK: u64 = 1 << 20;

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

fn bad(msg: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {msg}"))
}

// ---------------------------------------------------------------------------
// settings (system_config `guard.*`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settings {
    pub enabled: bool,
    pub sources: Vec<String>,
    pub max_failures: u32,
    pub find_secs: u64,
    pub ban_secs: u64,
    pub ban_max_secs: u64,
    pub escalate: bool,
    pub escalate_window_secs: u64,
    pub exempt_lan: bool,
    /// Normalised CIDRs (`10.0.0.0/8`, `2001:db8::/32`, `192.0.2.7/32`).
    pub allowlist: Vec<String>,
    pub ipv6_prefix: u8,
    /// Empty = automatic.
    pub log_files: Vec<String>,
    /// `auto` (systemd hosts), `on`, `off`.
    pub journal: String,
    pub history_days: u32,
    pub history_max_rows: u32,
    pub tick_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            sources: SOURCES.iter().map(|s| s.to_string()).collect(),
            max_failures: 5,
            find_secs: 600,
            ban_secs: 900,
            ban_max_secs: 86_400,
            escalate: true,
            escalate_window_secs: 86_400,
            exempt_lan: true,
            allowlist: Vec::new(),
            ipv6_prefix: 64,
            log_files: Vec::new(),
            journal: "auto".into(),
            history_days: 30,
            history_max_rows: 5000,
            tick_secs: 2,
        }
    }
}

/// A partial update (the API's PUT body and `patronus guard set`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsIn {
    pub enabled: Option<bool>,
    pub sources: Option<Vec<String>>,
    pub max_failures: Option<u32>,
    pub find_secs: Option<u64>,
    pub ban_secs: Option<u64>,
    pub ban_max_secs: Option<u64>,
    pub escalate: Option<bool>,
    pub escalate_window_secs: Option<u64>,
    pub exempt_lan: Option<bool>,
    pub allowlist: Option<Vec<String>>,
    pub ipv6_prefix: Option<u8>,
    pub log_files: Option<Vec<String>>,
    pub journal: Option<String>,
    pub history_days: Option<u32>,
    pub history_max_rows: Option<u32>,
    pub tick_secs: Option<u64>,
}

fn flag(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "yes" | "on")
}

fn list(v: &str) -> Vec<String> {
    v.split([',', '\n', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Validate and normalise one allow-list entry (an address is a /32 or /128).
pub fn normalize_cidr(s: &str) -> Result<String> {
    let t = s.trim();
    let n: IpNetwork = if t.contains('/') {
        t.parse()
            .map_err(|_| bad(format!("allow-list entry {t:?}")))?
    } else {
        let ip: IpAddr = t
            .parse()
            .map_err(|_| bad(format!("allow-list entry {t:?}")))?;
        IpNetwork::from(ip)
    };
    // the network address, so 10.1.2.3/8 is stored as 10.0.0.0/8
    let net = IpNetwork::new(n.network(), n.prefix())
        .map_err(|_| bad(format!("allow-list entry {t:?}")))?;
    Ok(net.to_string())
}

fn valid_log_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() < 256
        && !p.contains("..")
        && p.bytes().all(|b| b.is_ascii_graphic() && b != b',')
}

impl Settings {
    /// Apply a partial update on top of `self`, validating the result.
    pub fn merged(&self, i: &SettingsIn) -> Result<Settings> {
        let mut s = self.clone();
        if let Some(v) = i.enabled {
            s.enabled = v;
        }
        if let Some(v) = &i.sources {
            let mut out = Vec::new();
            for x in v {
                let x = x.trim().to_ascii_lowercase();
                if !SOURCES.contains(&x.as_str()) {
                    return Err(bad(format!("source {x:?} (one of {})", SOURCES.join(", "))));
                }
                if !out.contains(&x) {
                    out.push(x);
                }
            }
            s.sources = out;
        }
        macro_rules! num {
            ($f:ident, $lo:expr, $hi:expr, $what:literal) => {
                if let Some(v) = i.$f {
                    if !($lo..=$hi).contains(&v) {
                        return Err(bad(format!(
                            concat!($what, " {} (allowed {}..={})"),
                            v, $lo, $hi
                        )));
                    }
                    s.$f = v;
                }
            };
        }
        num!(max_failures, 1, 1000, "failure count");
        num!(find_secs, 10, 7 * 86_400, "counting window");
        num!(ban_secs, 10, 365 * 86_400, "ban length");
        num!(ban_max_secs, 10, 365 * 86_400, "longest ban");
        num!(
            escalate_window_secs,
            60,
            365 * 86_400,
            "repeat-offender window"
        );
        num!(ipv6_prefix, 32, 128, "IPv6 prefix length");
        num!(history_days, 1, 3650, "history retention (days)");
        num!(history_max_rows, 100, 1_000_000, "history size");
        num!(tick_secs, 1, 300, "check interval");
        if let Some(v) = i.escalate {
            s.escalate = v;
        }
        if let Some(v) = i.exempt_lan {
            s.exempt_lan = v;
        }
        if let Some(v) = &i.allowlist {
            let mut out: Vec<String> = Vec::new();
            for x in v.iter().map(|x| x.trim()).filter(|x| !x.is_empty()) {
                let n = normalize_cidr(x)?;
                if !out.contains(&n) {
                    out.push(n);
                }
            }
            s.allowlist = out;
        }
        if let Some(v) = &i.log_files {
            let mut out = Vec::new();
            for x in v
                .iter()
                .map(|x| x.trim())
                .filter(|x| !x.is_empty() && *x != "auto")
            {
                if !valid_log_path(x) {
                    return Err(bad(format!("log file {x:?} (an absolute path)")));
                }
                out.push(x.to_string());
            }
            s.log_files = out;
        }
        if let Some(v) = &i.journal {
            let v = v.trim().to_ascii_lowercase();
            if !["auto", "on", "off"].contains(&v.as_str()) {
                return Err(bad(format!("journal mode {v:?} (auto, on or off)")));
            }
            s.journal = v;
        }
        if s.ban_max_secs < s.ban_secs {
            return Err(bad("longest ban: shorter than the first ban"));
        }
        Ok(s)
    }

    fn pairs(&self) -> Vec<(&'static str, String)> {
        let b = |v: bool| if v { "1" } else { "0" }.to_string();
        vec![
            ("guard.enabled", b(self.enabled)),
            ("guard.sources", self.sources.join(",")),
            ("guard.max_failures", self.max_failures.to_string()),
            ("guard.find_secs", self.find_secs.to_string()),
            ("guard.ban_secs", self.ban_secs.to_string()),
            ("guard.ban_max_secs", self.ban_max_secs.to_string()),
            ("guard.escalate", b(self.escalate)),
            (
                "guard.escalate_window_secs",
                self.escalate_window_secs.to_string(),
            ),
            ("guard.exempt_lan", b(self.exempt_lan)),
            ("guard.allowlist", self.allowlist.join(",")),
            ("guard.ipv6_prefix", self.ipv6_prefix.to_string()),
            (
                "guard.log_files",
                if self.log_files.is_empty() {
                    "auto".into()
                } else {
                    self.log_files.join(",")
                },
            ),
            ("guard.journal", self.journal.clone()),
            ("guard.history_days", self.history_days.to_string()),
            ("guard.history_max_rows", self.history_max_rows.to_string()),
            ("guard.tick_secs", self.tick_secs.to_string()),
        ]
    }

    pub fn source_on(&self, s: &str) -> bool {
        self.sources.iter().any(|x| x == s)
    }
}

/// Read the settings; a stored value that does not validate falls back to its default
/// (with a warning), so one bad key never switches the protection off.
pub async fn load(store: &ConfigStore) -> Result<Settings> {
    let d = Settings::default();
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    let rows = sqlx::query("SELECT key, value FROM system_config WHERE key LIKE 'guard.%'")
        .fetch_all(store.pool()?)
        .await
        .map_err(db("guard settings"))?;
    for r in rows {
        raw.insert(r.get(0), r.get(1));
    }
    let g = |k: &str| raw.get(k).map(|v| v.trim().to_string());
    let mut i = SettingsIn::default();
    macro_rules! parse {
        ($f:ident, $k:literal) => {
            if let Some(v) = g($k) {
                i.$f = v.parse().ok();
            }
        };
    }
    i.enabled = g("guard.enabled").map(|v| flag(&v));
    i.escalate = g("guard.escalate").map(|v| flag(&v));
    i.exempt_lan = g("guard.exempt_lan").map(|v| flag(&v));
    i.sources = g("guard.sources").map(|v| list(&v));
    i.allowlist = g("guard.allowlist").map(|v| list(&v));
    i.log_files = g("guard.log_files").map(|v| list(&v));
    i.journal = g("guard.journal");
    parse!(max_failures, "guard.max_failures");
    parse!(find_secs, "guard.find_secs");
    parse!(ban_secs, "guard.ban_secs");
    parse!(ban_max_secs, "guard.ban_max_secs");
    parse!(escalate_window_secs, "guard.escalate_window_secs");
    parse!(ipv6_prefix, "guard.ipv6_prefix");
    parse!(history_days, "guard.history_days");
    parse!(history_max_rows, "guard.history_max_rows");
    parse!(tick_secs, "guard.tick_secs");
    match d.merged(&i) {
        Ok(s) => Ok(s),
        Err(e) => {
            tracing::warn!(
                "brute-force protection settings: {e}; using the defaults for the bad keys"
            );
            // field by field, keeping every key that validates on its own
            let mut s = d.clone();
            let one = |s: &Settings, f: SettingsIn| s.merged(&f).ok();
            macro_rules! try1 {
                ($f:ident) => {
                    if let Some(n) = one(
                        &s,
                        SettingsIn {
                            $f: i.$f.clone(),
                            ..Default::default()
                        },
                    ) {
                        s = n;
                    }
                };
            }
            try1!(enabled);
            try1!(sources);
            try1!(max_failures);
            try1!(find_secs);
            try1!(ban_secs);
            try1!(ban_max_secs);
            try1!(escalate);
            try1!(escalate_window_secs);
            try1!(exempt_lan);
            try1!(allowlist);
            try1!(ipv6_prefix);
            try1!(log_files);
            try1!(journal);
            try1!(history_days);
            try1!(history_max_rows);
            try1!(tick_secs);
            Ok(s)
        }
    }
}

/// Validate and store a partial update; returns the new settings.
pub async fn save(store: &ConfigStore, i: &SettingsIn) -> Result<Settings> {
    let s = load(store).await?.merged(i)?;
    write(store, &s).await?;
    Ok(s)
}

/// Store complete settings (used to undo a failed apply).
pub async fn write(store: &ConfigStore, s: &Settings) -> Result<()> {
    for (k, v) in s.pairs() {
        store.save_system_config(k, &v).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// log parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub source: &'static str,
    pub addr: IpAddr,
    pub user: String,
}

/// The text before the message must be empty (a file sshd writes itself, `-E`) or a
/// syslog-style prefix whose tag (`host sshd[123]:`) is one of the SSH daemons.
fn tag_ok(prefix: &str) -> bool {
    let p = prefix.trim_end();
    if p.is_empty() {
        return true;
    }
    let Some(p) = p.strip_suffix(':') else {
        return false;
    };
    let tag = p.rsplit(' ').next().unwrap_or("");
    let tag = tag.split('[').next().unwrap_or("");
    SSH_TAGS.contains(&tag)
}

fn strip_suffixes(mut t: &str) -> &str {
    loop {
        let before = t;
        for suf in [" [preauth]", " ssh2"] {
            if let Some(x) = t.strip_suffix(suf) {
                t = x.trim_end();
            }
        }
        if t == before {
            return t;
        }
    }
}

/// `... from <ip> port <n>` at the very end (OpenSSH).
fn openssh_tail(t: &str) -> Option<(&str, IpAddr)> {
    let t = strip_suffixes(t.trim_end());
    let (head, port) = t.rsplit_once(" port ")?;
    port.parse::<u16>().ok()?;
    let (user, ip) = head.rsplit_once(" from ")?;
    Some((user, ip.parse().ok()?))
}

/// `<ip>:<port>` or `[<ip>]:<port>` at the very end (Dropbear).
fn dropbear_addr(t: &str) -> Option<IpAddr> {
    let t = t.trim_end();
    let a = t.rsplit_once(" from ")?.1;
    if let Some(rest) = a.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        port.parse::<u16>().ok()?;
        return ip.parse().ok();
    }
    let (ip, port) = a.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    ip.parse().ok()
}

/// One failed login in a log line, or None. Pure; see the tests for the exact
/// messages of OpenSSH 9.x and Dropbear 2022+/2024+. Only password guesses count
/// (`Failed password`, `Failed keyboard-interactive/pam`, too many attempts on one
/// connection; Dropbear's bad password / unknown user): the `Invalid user` line sshd
/// writes before the `Failed password for invalid user` of the same guess would count
/// it twice, and a failed public key is what every client with several keys produces.
pub fn parse_line(line: &str) -> Option<Attempt> {
    const OPENSSH: &[&str] = &[
        "Failed password for ",
        "Failed keyboard-interactive/pam for ",
        "error: maximum authentication attempts exceeded for ",
        "maximum authentication attempts exceeded for ",
    ];
    for k in OPENSSH {
        if let Some(i) = line.find(k) {
            if !tag_ok(&line[..i]) {
                return None;
            }
            let (user, addr) = openssh_tail(&line[i + k.len()..])?;
            let user = user.strip_prefix("invalid user ").unwrap_or(user);
            return Some(Attempt {
                source: "sshd",
                addr,
                user: clean_user(user),
            });
        }
    }
    const DROPBEAR: &[&str] = &[
        "Bad password attempt for ",
        "Login attempt for nonexistent user",
    ];
    for k in DROPBEAR {
        if let Some(i) = line.find(k) {
            if !tag_ok(&line[..i]) {
                return None;
            }
            let rest = &line[i + k.len()..];
            let addr = dropbear_addr(rest)?;
            let user = rest
                .rsplit_once(" from ")
                .map(|(u, _)| u.trim().trim_matches('\''))
                .unwrap_or("");
            return Some(Attempt {
                source: "dropbear",
                addr,
                user: clean_user(user),
            });
        }
    }
    None
}

fn clean_user(u: &str) -> String {
    u.chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// addresses
// ---------------------------------------------------------------------------

/// The ban key of an address: the address itself for IPv4 (and IPv4-mapped IPv6),
/// the /`prefix` network for IPv6.
pub fn ban_key(addr: IpAddr, ipv6_prefix: u8) -> String {
    match addr {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return v4.to_string();
            }
            if ipv6_prefix >= 128 {
                return a.to_string();
            }
            match Ipv6Network::new(a, ipv6_prefix) {
                Ok(n) => format!("{}/{}", n.network(), ipv6_prefix),
                Err(_) => a.to_string(),
            }
        }
    }
}

fn key_addr(key: &str) -> Option<IpAddr> {
    key.split('/').next()?.parse().ok()
}

fn in_any(addr: IpAddr, nets: &[IpNetwork]) -> bool {
    nets.iter().any(|n| n.contains(addr))
}

/// Never banned: loopback, unspecified, the allow list and (exempt_lan) `lan_nets`.
pub fn exempt(addr: IpAddr, s: &Settings, lan_nets: &[IpNetwork]) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return true;
    }
    let allow: Vec<IpNetwork> = s.allowlist.iter().filter_map(|n| n.parse().ok()).collect();
    if in_any(addr, &allow) {
        return true;
    }
    s.exempt_lan && in_any(addr, lan_nets)
}

/// Subnets of the router's non-WAN interfaces as the kernel has them now.
pub async fn lan_networks(store: &ConfigStore) -> Vec<IpNetwork> {
    let roles = store.interface_roles().await.unwrap_or_default();
    let devs: Vec<String> = roles
        .into_iter()
        .filter(|(_, r)| r != "wan")
        .map(|(d, _)| d)
        .collect();
    if devs.is_empty() {
        return Vec::new();
    }
    let out = tokio::task::spawn_blocking(|| {
        std::process::Command::new("ip")
            .args(["-j", "addr", "show"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    parse_ip_addr_json(&out, &devs)
}

/// Networks of `devs` in `ip -j addr show` output.
pub fn parse_ip_addr_json(json: &str, devs: &[String]) -> Vec<IpNetwork> {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    let mut nets = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        let name = link["ifname"].as_str().unwrap_or("");
        if !devs.iter().any(|d| d == name) {
            continue;
        }
        for a in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(len)) = (a["local"].as_str(), a["prefixlen"].as_u64()) else {
                continue;
            };
            if let (Ok(ip), Ok(len)) = (local.parse::<IpAddr>(), u8::try_from(len)) {
                if let Ok(n) = IpNetwork::new(ip, len) {
                    if let Ok(n) = IpNetwork::new(n.network(), len) {
                        if !nets.contains(&n) {
                            nets.push(n);
                        }
                    }
                }
            }
        }
    }
    nets
}

// ---------------------------------------------------------------------------
// ban decisions (pure)
// ---------------------------------------------------------------------------

/// Length of a ban for the `offence`-th ban (1-based) of an address.
pub fn ban_length(s: &Settings, offence: u32) -> u64 {
    if !s.escalate || offence <= 1 {
        return s.ban_secs;
    }
    let shift = (offence - 1).min(30);
    s.ban_secs.saturating_mul(1u64 << shift).min(s.ban_max_secs)
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ban {
    pub id: i64,
    pub address: String,
    pub source: String,
    pub reason: String,
    pub failures: i64,
    pub offence: i64,
    pub banned_at: i64,
    pub expires_at: Option<i64>,
    pub lifted_at: Option<i64>,
    pub lifted_by: Option<String>,
    /// active now
    pub active: bool,
}

fn ban_row(r: &sqlx::sqlite::SqliteRow, now: i64) -> Ban {
    let expires_at: Option<i64> = r.get("expires_at");
    let lifted_at: Option<i64> = r.get("lifted_at");
    Ban {
        id: r.get("id"),
        address: r.get("address"),
        source: r.get("source"),
        reason: r.get("reason"),
        failures: r.get("failures"),
        offence: r.get("offence"),
        banned_at: r.get("banned_at"),
        expires_at,
        lifted_at,
        lifted_by: r.get("lifted_by"),
        active: lifted_at.is_none() && expires_at.is_none_or(|e| e > now),
    }
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub async fn active_bans(store: &ConfigStore, now: i64) -> Result<Vec<Ban>> {
    let rows = sqlx::query(
        "SELECT * FROM guard_bans WHERE lifted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
         ORDER BY banned_at DESC, id DESC",
    )
    .bind(now)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("active bans"))?;
    Ok(rows.iter().map(|r| ban_row(r, now)).collect())
}

pub async fn history(store: &ConfigStore, limit: i64, now: i64) -> Result<Vec<Ban>> {
    let rows = sqlx::query("SELECT * FROM guard_bans ORDER BY banned_at DESC, id DESC LIMIT ?")
        .bind(limit.clamp(1, 5000))
        .fetch_all(store.pool()?)
        .await
        .map_err(db("ban history"))?;
    Ok(rows.iter().map(|r| ban_row(r, now)).collect())
}

/// Failed attempts per address inside the counting window (for the status page).
pub async fn recent_failures(store: &ConfigStore, since: i64) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query(
        "SELECT address, COUNT(*) AS n, MAX(at) AS last, GROUP_CONCAT(DISTINCT source) AS sources,
                GROUP_CONCAT(DISTINCT username) AS users
         FROM guard_failures WHERE at >= ? GROUP BY address ORDER BY n DESC, last DESC LIMIT 200",
    )
    .bind(since)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("recent failures"))?;
    Ok(rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "address": r.get::<String, _>("address"),
                "failures": r.get::<i64, _>("n"),
                "last": r.get::<i64, _>("last"),
                "sources": r.get::<Option<String>, _>("sources").unwrap_or_default(),
                "users": r.get::<Option<String>, _>("users").unwrap_or_default(),
            })
        })
        .collect())
}

/// Record a failed login from a process that cannot ban by itself (patronus-web).
/// Cheap no-op while the protection or that source is off.
pub async fn report(store: &ConfigStore, source: &str, addr: IpAddr, user: &str) -> Result<()> {
    let s = load(store).await?;
    if !s.enabled || !s.source_on(source) {
        return Ok(());
    }
    sqlx::query("INSERT INTO guard_reports (source, address, username, at) VALUES (?,?,?,?)")
        .bind(source)
        .bind(addr.to_string())
        .bind(clean_user(user))
        .bind(now())
        .execute(store.pool()?)
        .await
        .map_err(db("guard report"))?;
    Ok(())
}

/// Ban by hand. `addr` is an address or (IPv6) a prefix; `secs` None = until lifted.
pub async fn manual_ban(
    store: &ConfigStore,
    addr: &str,
    secs: Option<u64>,
    reason: &str,
) -> Result<String> {
    let s = load(store).await?;
    let key = parse_ban_target(addr, s.ipv6_prefix)?;
    let ip = key_addr(&key).ok_or_else(|| bad(format!("address {addr:?}")))?;
    if ip.is_loopback() || ip.is_unspecified() {
        return Err(bad(format!("address {addr:?} (loopback/unspecified)")));
    }
    if let Some(n) = secs {
        if !(10..=365 * 86_400).contains(&n) {
            return Err(bad(format!("ban length {n} s (10 s to one year)")));
        }
    }
    let now = now();
    lift(store, &key, "replaced", now).await?;
    sqlx::query(
        "INSERT INTO guard_bans (address, source, reason, failures, offence, banned_at, expires_at)
         VALUES (?, 'manual', ?, 0, 1, ?, ?)",
    )
    .bind(&key)
    .bind(clean_user(reason))
    .bind(now)
    .bind(secs.map(|n| now + n as i64))
    .execute(store.pool()?)
    .await
    .map_err(db("manual ban"))?;
    Ok(key)
}

fn parse_ban_target(addr: &str, ipv6_prefix: u8) -> Result<String> {
    let t = addr.trim();
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(ban_key(ip, ipv6_prefix));
    }
    match t.parse::<IpNetwork>() {
        Ok(IpNetwork::V6(n)) if n.prefix() >= 32 => Ok(format!("{}/{}", n.network(), n.prefix())),
        Ok(IpNetwork::V4(n)) if n.prefix() == 32 => Ok(n.ip().to_string()),
        _ => Err(bad(format!(
            "address {t:?} (an IPv4 address, an IPv6 address or an IPv6 prefix /32../128)"
        ))),
    }
}

async fn lift(store: &ConfigStore, key: &str, by: &str, now: i64) -> Result<u64> {
    let r = sqlx::query(
        "UPDATE guard_bans SET lifted_at = ?, lifted_by = ?
         WHERE address = ? AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(now)
    .bind(by)
    .bind(key)
    .bind(now)
    .execute(store.pool()?)
    .await
    .map_err(db("lift ban"))?;
    Ok(r.rows_affected())
}

/// Lift the active ban of `addr` (address, or the IPv6 prefix it falls in) and forget
/// its counted failures. Returns how many bans were lifted.
pub async fn unban(store: &ConfigStore, addr: &str, by: &str) -> Result<u64> {
    let s = load(store).await?;
    let key = parse_ban_target(addr, s.ipv6_prefix)?;
    let n = lift(store, &key, by, now()).await?;
    sqlx::query("DELETE FROM guard_failures WHERE address = ?")
        .bind(&key)
        .execute(store.pool()?)
        .await
        .map_err(db("forget failures"))?;
    if n == 0 {
        return Err(Error::Config(format!("ban for {key} not found")));
    }
    Ok(n)
}

/// Count one failed attempt and ban when the threshold is reached. Returns the new ban.
pub async fn record(
    store: &ConfigStore,
    s: &Settings,
    a: &Attempt,
    at: i64,
) -> Result<Option<Ban>> {
    let key = ban_key(a.addr, s.ipv6_prefix);
    let pool = store.pool()?;
    // an already banned address (e.g. a slow drip after the ban) adds nothing
    let banned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM guard_bans WHERE address = ? AND lifted_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(&key)
    .bind(at)
    .fetch_one(pool)
    .await
    .map_err(db("guard state"))?;
    if banned > 0 {
        return Ok(None);
    }
    sqlx::query("INSERT INTO guard_failures (address, source, username, at) VALUES (?,?,?,?)")
        .bind(&key)
        .bind(a.source)
        .bind(&a.user)
        .bind(at)
        .execute(pool)
        .await
        .map_err(db("guard failure"))?;
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM guard_failures WHERE address = ? AND at > ?")
            .bind(&key)
            .bind(at - s.find_secs as i64)
            .fetch_one(pool)
            .await
            .map_err(db("guard count"))?;
    if n < i64::from(s.max_failures) {
        return Ok(None);
    }
    let prior: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM guard_bans WHERE address = ? AND source != 'manual' AND banned_at > ?",
    )
    .bind(&key)
    .bind(at - s.escalate_window_secs as i64)
    .fetch_one(pool)
    .await
    .map_err(db("guard history"))?;
    let offence = u32::try_from(prior + 1).unwrap_or(u32::MAX);
    let secs = ban_length(s, offence);
    let users: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT username FROM guard_failures WHERE address = ? AND at > ? AND username != '' LIMIT 5",
    )
    .bind(&key)
    .bind(at - s.find_secs as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let reason = format!(
        "{n} failed {} logins in {}{}",
        label(a.source),
        human_secs(s.find_secs),
        if users.is_empty() {
            String::new()
        } else {
            format!(" (users: {})", users.join(", "))
        }
    );
    let id = sqlx::query(
        "INSERT INTO guard_bans (address, source, reason, failures, offence, banned_at, expires_at)
         VALUES (?,?,?,?,?,?,?)",
    )
    .bind(&key)
    .bind(a.source)
    .bind(&reason)
    .bind(n)
    .bind(i64::from(offence))
    .bind(at)
    .bind(at + secs as i64)
    .execute(pool)
    .await
    .map_err(db("guard ban"))?
    .last_insert_rowid();
    sqlx::query("DELETE FROM guard_failures WHERE address = ?")
        .bind(&key)
        .execute(pool)
        .await
        .map_err(db("guard failures"))?;
    tracing::warn!(
        "brute-force protection: banned {key} for {} ({reason}, offence {offence})",
        human_secs(secs)
    );
    Ok(Some(Ban {
        id,
        address: key,
        source: a.source.to_string(),
        reason,
        failures: n,
        offence: i64::from(offence),
        banned_at: at,
        expires_at: Some(at + secs as i64),
        lifted_at: None,
        lifted_by: None,
        active: true,
    }))
}

pub fn label(source: &str) -> &'static str {
    match source {
        "sshd" => "SSH",
        "dropbear" => "SSH (Dropbear)",
        "web" => "web UI",
        "manual" => "manual",
        _ => "other",
    }
}

pub fn human_secs(s: u64) -> String {
    if s >= 86_400 && s.is_multiple_of(86_400) {
        format!("{} d", s / 86_400)
    } else if s >= 3600 && s.is_multiple_of(3600) {
        format!("{} h", s / 3600)
    } else if s >= 60 && s.is_multiple_of(60) {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

/// Drop old failures and history beyond retention.
pub async fn prune(store: &ConfigStore, s: &Settings, now: i64) -> Result<()> {
    let pool = store.pool()?;
    sqlx::query("DELETE FROM guard_failures WHERE at <= ?")
        .bind(now - s.find_secs as i64)
        .execute(pool)
        .await
        .map_err(db("prune failures"))?;
    sqlx::query("DELETE FROM guard_reports WHERE at <= ?")
        .bind(now - 3600)
        .execute(pool)
        .await
        .map_err(db("prune reports"))?;
    // inactive history only: an active ban is never pruned
    sqlx::query(
        "DELETE FROM guard_bans WHERE banned_at < ?
         AND (lifted_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?))",
    )
    .bind(now - i64::from(s.history_days) * 86_400)
    .bind(now)
    .execute(pool)
    .await
    .map_err(db("prune history"))?;
    sqlx::query(
        "DELETE FROM guard_bans WHERE id IN (
           SELECT id FROM guard_bans
           WHERE lifted_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= ?)
           ORDER BY banned_at DESC, id DESC LIMIT -1 OFFSET ?)",
    )
    .bind(now)
    .bind(i64::from(s.history_max_rows))
    .execute(pool)
    .await
    .map_err(db("prune history size"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

fn elem(b: &Ban, now: i64) -> String {
    match b.expires_at {
        Some(e) => format!("{} timeout {}s", b.address, (e - now).max(1)),
        None => b.address.clone(),
    }
}

/// The whole table as one idempotent script: objects are created when missing,
/// chains and both sets are flushed and refilled from `bans` in the same transaction.
pub fn render_script(bans: &[Ban], now: i64) -> String {
    let t = format!("inet {TABLE_NAME}");
    let mut s = String::new();
    s.push_str(&format!("add table {t}\n"));
    s.push_str(&format!(
        "add set {t} ban4 {{ type ipv4_addr; flags timeout; }}\n"
    ));
    s.push_str(&format!(
        "add set {t} ban6 {{ type ipv6_addr; flags interval, timeout; }}\n"
    ));
    for c in ["input", "forward"] {
        s.push_str(&format!(
            "add chain {t} {c} {{ type filter hook {c} priority {PRIORITY}; policy accept; }}\n"
        ));
        s.push_str(&format!("flush chain {t} {c}\n"));
    }
    s.push_str(&format!("flush set {t} ban4\nflush set {t} ban6\n"));
    let (v6, v4): (Vec<&Ban>, Vec<&Ban>) = bans
        .iter()
        .filter(|b| b.active)
        .partition(|b| b.address.contains(':'));
    if !v4.is_empty() {
        let e: Vec<String> = v4.iter().map(|b| elem(b, now)).collect();
        s.push_str(&format!("add element {t} ban4 {{ {} }}\n", e.join(", ")));
    }
    if !v6.is_empty() {
        let e: Vec<String> = v6.iter().map(|b| elem(b, now)).collect();
        s.push_str(&format!("add element {t} ban6 {{ {} }}\n", e.join(", ")));
    }
    for c in ["input", "forward"] {
        s.push_str(&format!(
            "add rule {t} {c} ip saddr @ban4 counter drop comment \"brute-force ban\"\n"
        ));
        s.push_str(&format!(
            "add rule {t} {c} ip6 saddr @ban6 counter drop comment \"brute-force ban\"\n"
        ));
    }
    s
}

pub fn table_exists() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", TABLE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn delete_table() -> Result<()> {
    if table_exists() {
        crate::nftables::execute_nft_command(&["delete", "table", "inet", TABLE_NAME])?;
    }
    Ok(())
}

/// Make the kernel match the store (enabled) or remove the table (disabled).
pub async fn sync(store: &ConfigStore, s: &Settings) -> Result<usize> {
    if !s.enabled {
        tokio::task::spawn_blocking(delete_table)
            .await
            .map_err(|e| Error::Firewall(format!("guard: {e}")))??;
        return Ok(0);
    }
    let now = now();
    let bans = active_bans(store, now).await?;
    let script = render_script(&bans, now);
    tokio::task::spawn_blocking(move || crate::nftables::execute_nft_script(&script))
        .await
        .map_err(|e| Error::Firewall(format!("guard: {e}")))??;
    Ok(bans.len())
}

/// Elements and drop counters of the live table (status page, tests).
pub fn live_state() -> serde_json::Value {
    let Ok(out) =
        crate::nftables::execute_nft_command(&["-j", "list", "table", "inet", TABLE_NAME])
    else {
        return serde_json::json!({ "present": false });
    };
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
    let mut sets = serde_json::Map::new();
    let mut dropped_packets = 0u64;
    for item in v["nftables"].as_array().into_iter().flatten() {
        if let Some(set) = item.get("set") {
            let n = set["elem"].as_array().map(|a| a.len()).unwrap_or(0);
            sets.insert(set["name"].as_str().unwrap_or("").to_string(), n.into());
        }
        if let Some(rule) = item.get("rule") {
            for e in rule["expr"].as_array().into_iter().flatten() {
                if let Some(p) = e["counter"]["packets"].as_u64() {
                    dropped_packets += p;
                }
            }
        }
    }
    serde_json::json!({ "present": true, "elements": sets, "dropped_packets": dropped_packets })
}

// ---------------------------------------------------------------------------
// the engine: log readers + reports -> bans
// ---------------------------------------------------------------------------

struct Tail {
    ino: u64,
    pos: u64,
    partial: String,
}

/// Follows log files and the journal, turns failed logins into bans.
#[derive(Default)]
pub struct Engine {
    tails: HashMap<PathBuf, Tail>,
    journal: Option<Journal>,
    last_sync: i64,
    fingerprint: (i64, i64, i64),
    lan: (i64, Vec<IpNetwork>),
    was_enabled: bool,
    /// the "off" state was made true once (table removed) since the engine started
    off_checked: bool,
}

struct Journal {
    child: tokio::process::Child,
    rx: tokio::sync::mpsc::Receiver<String>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn systemd_running() -> bool {
    Path::new("/run/systemd/system").exists()
}

fn journal_wanted(s: &Settings) -> bool {
    let want_ssh = s.source_on("sshd") || s.source_on("dropbear");
    want_ssh
        && match s.journal.as_str() {
            "on" => true,
            "off" => false,
            _ => systemd_running() && s.log_files.is_empty(),
        }
}

/// The files to follow: explicit ones, or (automatic, journal not used) the first
/// auth log that exists.
pub fn log_files(s: &Settings, journal: bool) -> Vec<PathBuf> {
    if !(s.source_on("sshd") || s.source_on("dropbear")) {
        return Vec::new();
    }
    if !s.log_files.is_empty() {
        return s.log_files.iter().map(PathBuf::from).collect();
    }
    if journal {
        return Vec::new();
    }
    AUTO_LOG_FILES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .into_iter()
        .collect()
}

fn read_new(path: &Path, t: &mut Tail, first: bool) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(meta) = f.metadata() else {
        return Vec::new();
    };
    if first {
        // start at the end: what was logged before the engine started is history
        t.ino = meta.ino();
        t.pos = meta.len();
        return Vec::new();
    }
    if meta.ino() != t.ino || meta.len() < t.pos {
        // rotated or truncated: the new file is read from its start
        t.ino = meta.ino();
        t.pos = 0;
        t.partial.clear();
    }
    if meta.len() == t.pos || f.seek(SeekFrom::Start(t.pos)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let n = f.take(MAX_READ_PER_TICK).read_to_end(&mut buf).unwrap_or(0);
    t.pos += n as u64;
    let text = format!("{}{}", t.partial, String::from_utf8_lossy(&buf));
    let mut lines: Vec<String> = text.split('\n').map(String::from).collect();
    t.partial = lines.pop().unwrap_or_default();
    if t.partial.len() > 8192 {
        t.partial.clear();
    }
    lines
}

fn start_journal() -> Option<Journal> {
    let mut child = tokio::process::Command::new("journalctl")
        .args([
            "-f",
            "-n",
            "0",
            "-o",
            "short",
            "--no-pager",
            "-t",
            "sshd",
            "-t",
            "sshd-session",
            "-t",
            "sshd-auth",
            "-t",
            "dropbear",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| tracing::warn!("brute-force protection: journalctl: {e}"))
        .ok()?;
    let out = child.stdout.take()?;
    let (tx, rx) = tokio::sync::mpsc::channel(10_000);
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt;
        let mut lines = tokio::io::BufReader::new(out).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if parse_line(&l).is_some() {
                let _ = tx.try_send(l);
            }
        }
    });
    Some(Journal { child, rx })
}

#[derive(Debug, Default, Serialize)]
pub struct TickReport {
    pub attempts: usize,
    pub exempt: usize,
    pub new_bans: Vec<String>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    async fn lan_nets(&mut self, store: &ConfigStore, now: i64) -> Vec<IpNetwork> {
        if now - self.lan.0 >= 60 || self.lan.0 == 0 {
            self.lan = (now, lan_networks(store).await);
        }
        self.lan.1.clone()
    }

    async fn fingerprint(store: &ConfigStore) -> (i64, i64, i64) {
        let Ok(pool) = store.pool() else {
            return (0, 0, 0);
        };
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT COUNT(*), COALESCE(MAX(id),0), COALESCE(MAX(lifted_at),0) FROM guard_bans",
        )
        .fetch_one(pool)
        .await
        .unwrap_or((0, 0, 0))
    }

    /// One round: read new log lines and reports, count, ban, keep the kernel in sync.
    pub async fn tick(&mut self, store: &ConfigStore) -> Result<TickReport> {
        let s = load(store).await?;
        let mut rep = TickReport::default();
        if !s.enabled {
            if self.was_enabled || !self.off_checked {
                sync(store, &s).await?;
                self.off_checked = true;
            }
            self.was_enabled = false;
            self.journal = None;
            self.tails.clear();
            return Ok(rep);
        }
        let now = now();
        // inputs
        let use_journal = journal_wanted(&s);
        if use_journal && self.journal.is_none() {
            self.journal = start_journal();
        } else if !use_journal {
            self.journal = None;
        }
        let files = log_files(&s, use_journal);
        self.tails.retain(|p, _| files.contains(p));
        let mut lines: Vec<String> = Vec::new();
        for p in &files {
            let first = !self.tails.contains_key(p);
            let t = self.tails.entry(p.clone()).or_insert(Tail {
                ino: 0,
                pos: 0,
                partial: String::new(),
            });
            let p2 = p.clone();
            let mut t2 = std::mem::replace(
                t,
                Tail {
                    ino: 0,
                    pos: 0,
                    partial: String::new(),
                },
            );
            let (got, t3) = tokio::task::spawn_blocking(move || {
                let l = read_new(&p2, &mut t2, first);
                (l, t2)
            })
            .await
            .map_err(|e| Error::Firewall(format!("guard: {e}")))?;
            *self.tails.get_mut(p).expect("tail") = t3;
            lines.extend(got);
        }
        if let Some(j) = self.journal.as_mut() {
            while let Ok(l) = j.rx.try_recv() {
                lines.push(l);
            }
            if let Ok(Some(_)) = j.child.try_wait() {
                tracing::warn!("brute-force protection: journalctl ended, restarting it");
                self.journal = None;
            }
        }
        let mut attempts: Vec<Attempt> = lines
            .iter()
            .filter_map(|l| parse_line(l))
            .filter(|a| s.source_on(a.source))
            .collect();
        // reports from patronus-web
        let pool = store.pool()?;
        let reports = sqlx::query(
            "SELECT id, source, address, username FROM guard_reports ORDER BY id LIMIT 1000",
        )
        .fetch_all(pool)
        .await
        .map_err(db("guard reports"))?;
        let mut max_id = 0i64;
        for r in &reports {
            max_id = max_id.max(r.get::<i64, _>("id"));
            let src: String = r.get("source");
            let Some(source) = SOURCES.iter().find(|x| **x == src) else {
                continue;
            };
            if let Ok(addr) = r.get::<String, _>("address").parse::<IpAddr>() {
                if s.source_on(source) {
                    attempts.push(Attempt {
                        source,
                        addr,
                        user: r.get("username"),
                    });
                }
            }
        }
        if max_id > 0 {
            sqlx::query("DELETE FROM guard_reports WHERE id <= ?")
                .bind(max_id)
                .execute(pool)
                .await
                .map_err(db("guard reports"))?;
        }
        // decisions
        let lan = if attempts.is_empty() {
            Vec::new()
        } else {
            self.lan_nets(store, now).await
        };
        for a in &attempts {
            rep.attempts += 1;
            if exempt(a.addr, &s, &lan) {
                rep.exempt += 1;
                continue;
            }
            if let Some(b) = record(store, &s, a, now).await? {
                rep.new_bans.push(b.address);
            }
        }
        // kernel
        let fp = Self::fingerprint(store).await;
        if !rep.new_bans.is_empty()
            || fp != self.fingerprint
            || !self.was_enabled
            || now - self.last_sync >= 60
        {
            if now - self.last_sync >= 60 {
                prune(store, &s, now).await?;
            }
            sync(store, &s).await?;
            self.fingerprint = Self::fingerprint(store).await;
            self.last_sync = now;
        }
        self.was_enabled = true;
        Ok(rep)
    }
}

/// Run the engine forever. `only_without_applyd`: skip rounds while the root broker's
/// socket exists (patronus-web runs it only when there is no `patronus applyd`).
pub fn spawn_task(
    store: std::sync::Arc<ConfigStore>,
    only_without_applyd: bool,
    applyd_socket: PathBuf,
) {
    tokio::spawn(async move {
        let mut engine = Engine::new();
        let mut last_err = String::new();
        loop {
            let secs = std::env::var("PATRONUS_GUARD_TICK_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0);
            let secs = match secs {
                Some(v) => v,
                None => load(&store).await.map(|s| s.tick_secs).unwrap_or(2),
            };
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            if only_without_applyd && applyd_socket.exists() {
                continue;
            }
            match engine.tick(&store).await {
                Ok(_) => last_err.clear(),
                Err(e) => {
                    if last_err != e.to_string() {
                        tracing::error!("brute-force protection: {e}");
                        last_err = e.to_string();
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// applier (boot + every settings change)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
pub struct GuardApplier;

#[async_trait]
impl Applier for GuardApplier {
    fn name(&self) -> &'static str {
        "guard"
    }

    fn phase(&self) -> Phase {
        Phase::Firewall
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let s = load(store).await?;
        let mut rep = ApplyReport::default();
        let n = sync(store, &s).await?;
        if s.enabled {
            rep.applied(format!("brute-force protection on, {n} active ban(s)"));
        } else {
            rep.applied("brute-force protection is off");
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = load(store).await?;
        if !s.enabled {
            return Ok(format!(
                "# brute-force protection off: table inet {TABLE_NAME} removed\n"
            ));
        }
        let now = now();
        Ok(render_script(&active_bans(store, now).await?, now))
    }

    async fn status(&self, store: &ConfigStore) -> Result<serde_json::Value> {
        let s = load(store).await?;
        let live = tokio::task::spawn_blocking(live_state)
            .await
            .unwrap_or_default();
        let j = journal_wanted(&s);
        let files: Vec<String> = log_files(&s, j)
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        Ok(serde_json::json!({
            "enabled": s.enabled,
            "kernel": live,
            "inputs": { "journal": j, "log_files": files },
        }))
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn openssh_messages() {
        let cases = [
            ("Nov 25 10:00:01 rtr sshd[812]: Failed password for root from 203.0.113.9 port 50122 ssh2", "203.0.113.9", "root"),
            ("Nov 25 10:00:01 rtr sshd-session[812]: Failed password for invalid user admin from 198.51.100.4 port 4022 ssh2", "198.51.100.4", "admin"),
            ("Failed password for invalid user oracle from 192.0.2.7 port 3333 ssh2", "192.0.2.7", "oracle"),
            ("2026-11-25T10:00:01-08:00 rtr sshd[9]: Failed keyboard-interactive/pam for bob from 2001:db8::5 port 22 ssh2", "2001:db8::5", "bob"),
            ("Nov 25 10:00:01 rtr sshd[812]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 50122 ssh2 [preauth]", "203.0.113.9", "root"),
            ("sshd-session[1]: Failed password for invalid user  from 192.0.2.8 port 1 ", "192.0.2.8", ""),
        ];
        for (l, a, u) in cases {
            let got = parse_line(l).unwrap_or_else(|| panic!("no match: {l}"));
            assert_eq!(got.source, "sshd", "{l}");
            assert_eq!(got.addr, ip(a), "{l}");
            assert_eq!(got.user, u, "{l}");
        }
    }

    #[test]
    fn dropbear_messages() {
        let cases = [
            ("Nov 25 10:00:01 ap authpriv.warn dropbear[2201]: Bad password attempt for 'root' from 203.0.113.9:40100", "203.0.113.9", "root"),
            ("dropbear[2201]: Login attempt for nonexistent user from 198.51.100.4:4022", "198.51.100.4", ""),
            ("dropbear[2201]: Login attempt for nonexistent user 'pi' from 198.51.100.4:4022", "198.51.100.4", "pi"),
            ("dropbear[3]: Bad password attempt for 'root' from [2001:db8::9]:51515", "2001:db8::9", "root"),
            ("dropbear[3]: Bad password attempt for 'root' from 2001:db8::9:51515", "2001:db8::9", "root"),
        ];
        for (l, a, u) in cases {
            let got = parse_line(l).unwrap_or_else(|| panic!("no match: {l}"));
            assert_eq!(got.source, "dropbear", "{l}");
            assert_eq!(got.addr, ip(a), "{l}");
            assert_eq!(got.user, u, "{l}");
        }
    }

    #[test]
    fn harmless_lines_and_injection_attempts() {
        for l in [
            // one guess logs "Invalid user" AND "Failed password": only the second counts
            "Nov 25 10:00:01 rtr sshd[812]: Invalid user oracle from 192.0.2.7 port 3333",
            "Nov 25 10:00:01 rtr sshd[812]: Accepted publickey for admin from 192.168.1.5 port 50122 ssh2",
            "Nov 25 10:00:01 rtr sshd[812]: Connection closed by authenticating user root 203.0.113.9 port 1 [preauth]",
            "Nov 25 10:00:01 rtr sshd[812]: Failed publickey for admin from 192.168.1.5 port 50122 ssh2",
            // another program repeating attacker text must not count
            "Nov 25 10:00:01 rtr nginx[3]: GET /?q=Failed password for root from 192.168.1.5 port 22 ssh2",
            "Nov 25 10:00:01 rtr kernel: Failed password for x from 192.168.1.5 port 22 ssh2",
            "Failed password for root from not-an-ip port 22 ssh2",
            "",
        ] {
            assert_eq!(parse_line(l), None, "{l}");
        }
        // a user name that names another address: the address sshd appended wins
        let l = "rtr sshd[1]: Failed password for invalid user x from 192.168.1.5 port 22 from 203.0.113.66 port 4000 ssh2";
        assert_eq!(parse_line(l).unwrap().addr, ip("203.0.113.66"));
        let l = "rtr sshd[1]: Failed password for invalid user a from 10.0.0.1 port 1 ssh2 from 203.0.113.67 port 9 ssh2";
        assert_eq!(parse_line(l).unwrap().addr, ip("203.0.113.67"));
        let l =
            "dropbear[1]: Bad password attempt for 'x' from 10.0.0.1:22' from 203.0.113.68:4444";
        assert_eq!(parse_line(l).unwrap().addr, ip("203.0.113.68"));
    }

    #[test]
    fn keys_prefixes_and_exemptions() {
        assert_eq!(ban_key(ip("203.0.113.9"), 64), "203.0.113.9");
        assert_eq!(ban_key(ip("2001:db8:1:2:aaaa::5"), 64), "2001:db8:1:2::/64");
        assert_eq!(
            ban_key(ip("2001:db8:1:2:aaaa::5"), 128),
            "2001:db8:1:2:aaaa::5"
        );
        assert_eq!(ban_key(ip("::ffff:198.51.100.4"), 64), "198.51.100.4");
        let mut s = Settings::default();
        let lan: Vec<IpNetwork> = vec!["192.168.50.0/24".parse().unwrap()];
        assert!(exempt(ip("127.0.0.1"), &s, &lan));
        assert!(exempt(ip("::1"), &s, &lan));
        assert!(exempt(ip("192.168.50.10"), &s, &lan));
        assert!(!exempt(ip("203.0.113.9"), &s, &lan));
        s.exempt_lan = false;
        assert!(!exempt(ip("192.168.50.10"), &s, &lan));
        s.allowlist = vec!["203.0.113.0/24".into()];
        assert!(exempt(ip("203.0.113.9"), &s, &lan));
    }

    #[test]
    fn escalation_doubles_and_caps() {
        let s = Settings::default();
        assert_eq!(ban_length(&s, 1), 900);
        assert_eq!(ban_length(&s, 2), 1800);
        assert_eq!(ban_length(&s, 3), 3600);
        assert_eq!(ban_length(&s, 8), 86_400);
        assert_eq!(ban_length(&s, 400), 86_400);
        let s = Settings {
            escalate: false,
            ..Settings::default()
        };
        assert_eq!(ban_length(&s, 5), 900);
    }

    #[test]
    fn settings_validation() {
        let d = Settings::default();
        let s = d
            .merged(&SettingsIn {
                allowlist: Some(vec![
                    "10.1.2.3/8".into(),
                    "192.0.2.7".into(),
                    "2001:db8::1/32".into(),
                    " ".into(),
                ]),
                sources: Some(vec!["SSHD".into(), "web".into()]),
                log_files: Some(vec!["auto".into()]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            s.allowlist,
            vec!["10.0.0.0/8", "192.0.2.7/32", "2001:db8::/32"]
        );
        assert_eq!(s.sources, vec!["sshd", "web"]);
        assert!(s.log_files.is_empty());
        for bad_in in [
            SettingsIn {
                allowlist: Some(vec!["10.0.0.0/33".into()]),
                ..Default::default()
            },
            SettingsIn {
                sources: Some(vec!["telnet".into()]),
                ..Default::default()
            },
            SettingsIn {
                max_failures: Some(0),
                ..Default::default()
            },
            SettingsIn {
                ban_secs: Some(100),
                ban_max_secs: Some(50),
                ..Default::default()
            },
            SettingsIn {
                ipv6_prefix: Some(16),
                ..Default::default()
            },
            SettingsIn {
                log_files: Some(vec!["var/log/x".into()]),
                ..Default::default()
            },
            SettingsIn {
                log_files: Some(vec!["/var/../etc/shadow".into()]),
                ..Default::default()
            },
            SettingsIn {
                journal: Some("maybe".into()),
                ..Default::default()
            },
        ] {
            let e = d.merged(&bad_in).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{e}");
        }
    }

    #[test]
    fn script_shape() {
        let now = 1000;
        let b = |a: &str, e: Option<i64>, active: bool| Ban {
            id: 1,
            address: a.into(),
            source: "sshd".into(),
            reason: String::new(),
            failures: 5,
            offence: 1,
            banned_at: 900,
            expires_at: e,
            lifted_at: None,
            lifted_by: None,
            active,
        };
        let s = render_script(
            &[
                b("203.0.113.9", Some(1900), true),
                b("2001:db8:1:2::/64", None, true),
                b("198.51.100.1", Some(950), false),
            ],
            now,
        );
        assert!(s.contains(
            "add set inet patronus_guard ban6 { type ipv6_addr; flags interval, timeout; }"
        ));
        assert!(s.contains("add element inet patronus_guard ban4 { 203.0.113.9 timeout 900s }"));
        assert!(s.contains("add element inet patronus_guard ban6 { 2001:db8:1:2::/64 }"));
        assert!(!s.contains("198.51.100.1"));
        assert!(
            s.find("flush set inet patronus_guard ban4").unwrap() < s.find("add element").unwrap()
        );
        assert!(s.contains("type filter hook input priority -20; policy accept;"));
        assert!(s.contains("add rule inet patronus_guard forward ip saddr @ban4 counter drop"));
    }

    #[test]
    fn ip_addr_json() {
        let j = r#"[{"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
            {"ifname":"rtr-lan","addr_info":[{"local":"192.168.50.1","prefixlen":24},{"local":"fd00:1::1","prefixlen":64}]},
            {"ifname":"rtr-wan","addr_info":[{"local":"203.0.113.2","prefixlen":24}]}]"#;
        let n = parse_ip_addr_json(j, &["rtr-lan".to_string()]);
        assert_eq!(
            n,
            vec![
                "192.168.50.0/24".parse::<IpNetwork>().unwrap(),
                "fd00:1::/64".parse().unwrap()
            ]
        );
    }

    async fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::open(&d.path().join("c.db")).await.unwrap();
        (d, s)
    }

    #[tokio::test]
    async fn threshold_ban_escalation_and_unban() {
        let (_d, st) = store().await;
        let s = save(
            &st,
            &SettingsIn {
                enabled: Some(true),
                max_failures: Some(3),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = Attempt {
            source: "sshd",
            addr: ip("203.0.113.9"),
            user: "root".into(),
        };
        let t = now();
        assert!(record(&st, &s, &a, t).await.unwrap().is_none());
        assert!(record(&st, &s, &a, t + 1).await.unwrap().is_none());
        let b = record(&st, &s, &a, t + 2)
            .await
            .unwrap()
            .expect("ban on the 3rd failure");
        assert_eq!(b.expires_at, Some(t + 2 + 900));
        assert!(b.reason.contains("3 failed SSH logins"), "{}", b.reason);
        assert!(b.reason.contains("root"));
        // banned: more failures add nothing
        assert!(record(&st, &s, &a, t + 3).await.unwrap().is_none());
        assert_eq!(active_bans(&st, t + 3).await.unwrap().len(), 1);
        // unban and offend again: the second ban is twice as long
        assert_eq!(unban(&st, "203.0.113.9", "test").await.unwrap(), 1);
        assert!(active_bans(&st, t + 3).await.unwrap().is_empty());
        for i in 0..2 {
            assert!(record(&st, &s, &a, t + 10 + i).await.unwrap().is_none());
        }
        let b2 = record(&st, &s, &a, t + 12).await.unwrap().unwrap();
        assert_eq!(b2.offence, 2);
        assert_eq!(b2.expires_at, Some(t + 12 + 1800));
        // an expired ban is not active
        assert!(active_bans(&st, t + 12 + 1801).await.unwrap().is_empty());
        assert!(unban(&st, "198.51.100.200", "test")
            .await
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[tokio::test]
    async fn failures_outside_the_window_do_not_count() {
        let (_d, st) = store().await;
        let s = save(
            &st,
            &SettingsIn {
                enabled: Some(true),
                max_failures: Some(2),
                find_secs: Some(60),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = Attempt {
            source: "web",
            addr: ip("2001:db8:1:2::77"),
            user: String::new(),
        };
        let t = now();
        assert!(record(&st, &s, &a, t).await.unwrap().is_none());
        assert!(record(&st, &s, &a, t + 61).await.unwrap().is_none());
        // same /64, inside the window: banned as a prefix
        let a2 = Attempt {
            addr: ip("2001:db8:1:2::99"),
            ..a.clone()
        };
        let b = record(&st, &s, &a2, t + 62).await.unwrap().unwrap();
        assert_eq!(b.address, "2001:db8:1:2::/64");
    }

    #[tokio::test]
    async fn manual_bans_reports_and_prune() {
        let (_d, st) = store().await;
        let s = save(
            &st,
            &SettingsIn {
                enabled: Some(true),
                history_max_rows: Some(100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            manual_ban(&st, "198.51.100.7", None, "scanner")
                .await
                .unwrap(),
            "198.51.100.7"
        );
        assert_eq!(
            manual_ban(&st, "2001:db8:5::1", Some(60), "")
                .await
                .unwrap(),
            "2001:db8:5::/64"
        );
        assert!(manual_ban(&st, "127.0.0.1", None, "").await.is_err());
        assert!(manual_ban(&st, "10.0.0.0/8", None, "").await.is_err());
        assert!(manual_ban(&st, "198.51.100.8", Some(1), "").await.is_err());
        let act = active_bans(&st, now()).await.unwrap();
        assert_eq!(act.len(), 2);
        assert!(act.iter().any(|b| b.expires_at.is_none()));
        // reports are only taken while on
        report(&st, "web", ip("203.0.113.50"), "admin")
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM guard_reports")
            .fetch_one(st.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 1);
        save(
            &st,
            &SettingsIn {
                sources: Some(vec!["sshd".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        report(&st, "web", ip("203.0.113.50"), "admin")
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM guard_reports")
            .fetch_one(st.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(n, 1);
        // retention never drops an active ban
        prune(&st, &s, now() + 10 * 365 * 86_400).await.unwrap();
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM guard_bans WHERE expires_at IS NULL")
                .fetch_one(st.pool().unwrap())
                .await
                .unwrap();
        assert_eq!(left, 1);
    }

    #[tokio::test]
    async fn bad_stored_key_keeps_the_rest() {
        let (_d, st) = store().await;
        st.save_system_config("guard.enabled", "1").await.unwrap();
        st.save_system_config("guard.max_failures", "0")
            .await
            .unwrap();
        st.save_system_config("guard.ban_secs", "120")
            .await
            .unwrap();
        let s = load(&st).await.unwrap();
        assert!(s.enabled);
        assert_eq!(s.max_failures, 5);
        assert_eq!(s.ban_secs, 120);
    }

    #[test]
    fn tail_follows_rotation() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        std::fs::write(&p, "old line\n").unwrap();
        let mut t = Tail {
            ino: 0,
            pos: 0,
            partial: String::new(),
        };
        assert!(read_new(&p, &mut t, true).is_empty());
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        write!(f, "one\ntw").unwrap();
        assert_eq!(read_new(&p, &mut t, false), vec!["one"]);
        writeln!(f, "o").unwrap();
        assert_eq!(read_new(&p, &mut t, false), vec!["two"]);
        // rotation: a new file at the same path is read from its start
        std::fs::rename(&p, d.path().join("auth.log.1")).unwrap();
        std::fs::write(&p, "three\n").unwrap();
        assert_eq!(read_new(&p, &mut t, false), vec!["three"]);
    }
}
