//! Typed settings registry: operational values that used to be hard-coded.
//!
//! Product rule: nothing operational is baked into the code or the image.
//! Every such value is a key here with a type, bounds, a documented default
//! and a description. Values live in the `system_config` table, so
//! `export_json`/`import_json`, revisions, rollback and config generations
//! carry them without any extra code; a key that was never set reads as its
//! default. `docs/design/configurable-everything.md` lists every key and the
//! values still waiting for one.
//!
//! Interfaces: `GET/PUT/DELETE /api/settings[/{key}]` (web, System >
//! Advanced settings), `patronus settings list|get|set|reset|env` (CLI).
//! `patronus settings env` prints every value as shell variables
//! (`PATRONUS_SET_<KEY>`), which the embedded images' boot scripts source.
//!
//! Synchronous code (session checks, login throttle) reads [`current`],
//! a process cache filled by [`load_cache`]; async code reads the store with
//! [`get`] so it always sees the latest value.

use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Value type and bounds of a setting.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kind {
    Bool,
    /// Whole number in `min..=max` (unit in [`Setting::unit`]).
    Int {
        min: i64,
        max: i64,
    },
    /// TCP/UDP port 1-65535.
    Port,
    /// Free text up to `max_len` bytes, no control characters.
    Text {
        max_len: usize,
    },
    /// An http(s) URL; empty allowed only when `optional`.
    Url {
        optional: bool,
    },
    /// Comma-separated IPv4/IPv6 addresses (a resolver list); empty allowed only when `optional`.
    Addrs {
        optional: bool,
    },
    /// One of a fixed set of words.
    Choice {
        options: &'static [&'static str],
    },
}

/// Which key/value table holds a setting: `system_config` (system-wide) or
/// `lan_settings` (next to the subsystem's other keys, e.g. `ha.*`). Both are
/// configuration tables, so either way the value is exported, versioned and
/// restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    System,
    Lan,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Table::System => "system_config",
            Table::Lan => "lan_settings",
        }
    }
}

/// One registry entry.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Setting {
    /// Store key, `<section>.<name>`.
    pub key: &'static str,
    /// UI group.
    pub section: &'static str,
    pub label: &'static str,
    /// What it does, for the UI and the docs.
    pub doc: &'static str,
    pub kind: Kind,
    pub default: &'static str,
    /// Unit shown next to numbers ("seconds", "characters", ...).
    pub unit: &'static str,
    /// When a change takes effect.
    pub effect: &'static str,
    /// Where the value is stored.
    pub table: Table,
}

/// Every setting. Keep keys stable: they are part of exported configs.
pub static REGISTRY: &[Setting] = &[
    Setting {
        key: "web.session_lifetime_secs",
        section: "Web interface",
        label: "Session lifetime",
        doc: "How long a web login lasts before the user must sign in again (the cookie's Max-Age is the same).",
        kind: Kind::Int { min: 300, max: 30 * 86_400 },
        default: "86400",
        unit: "seconds",
        effect: "new logins at once; existing sessions are checked against the new value",
        table: Table::System,
    },
    Setting {
        key: "web.login_max_failures",
        section: "Web interface",
        label: "Failed logins before lockout",
        doc: "Wrong passwords (or two-factor codes) one client may send within the lockout window before its logins are refused with 429.",
        kind: Kind::Int { min: 1, max: 100 },
        default: "5",
        unit: "attempts",
        effect: "at once",
        table: Table::System,
    },
    Setting {
        key: "web.login_lockout_secs",
        section: "Web interface",
        label: "Login lockout window",
        doc: "Window in which failed logins are counted, and how long a client stays locked out after reaching the limit.",
        kind: Kind::Int { min: 60, max: 86_400 },
        default: "900",
        unit: "seconds",
        effect: "at once",
        table: Table::System,
    },
    Setting {
        key: "web.min_password_length",
        section: "Web interface",
        label: "Minimum password length",
        doc: "Shortest password accepted for any web account (existing passwords are not affected until changed).",
        kind: Kind::Int { min: 8, max: 128 },
        default: "12",
        unit: "characters",
        effect: "next password change",
        table: Table::System,
    },
    Setting {
        key: "web.housekeeping_interval_secs",
        section: "Web interface",
        label: "Housekeeping interval",
        doc: "How often expired sessions and login-throttle records are purged and secret rotation is enforced.",
        kind: Kind::Int { min: 60, max: 86_400 },
        default: "3600",
        unit: "seconds",
        effect: "next web service start",
        table: Table::System,
    },
    Setting {
        key: "network.ddns_refresh_secs",
        section: "Network",
        label: "Dynamic DNS forced refresh",
        doc: "Re-send a dynamic DNS update after this long even when the address did not change (providers expire idle records).",
        kind: Kind::Int { min: 3_600, max: 365 * 86_400 },
        default: "2160000",
        unit: "seconds",
        effect: "next DDNS check",
        table: Table::System,
    },
    Setting {
        key: "wifi.enrolment_ttl_secs",
        section: "Wi-Fi",
        label: "Pending device credential lifetime",
        doc: "How long a per-device Wi-Fi credential that no device has used yet stays valid before it expires.",
        kind: Kind::Int { min: 300, max: 30 * 86_400 },
        default: "86400",
        unit: "seconds",
        effect: "credentials created after the change",
        table: Table::System,
    },
    Setting {
        key: "wifi.guard_crash_max",
        section: "Wi-Fi crash protection",
        label: "Crashes before safe mode",
        doc: "Wi-Fi firmware crashes within the window that switch the access points to safe mode (first network per radio only).",
        kind: Kind::Int { min: 1, max: 50 },
        default: "3",
        unit: "crashes",
        effect: "next boot (router-tier access points)",
        table: Table::System,
    },
    Setting {
        key: "wifi.guard_crash_window_secs",
        section: "Wi-Fi crash protection",
        label: "Crash window",
        doc: "Time window in which the crashes are counted.",
        kind: Kind::Int { min: 60, max: 86400 },
        default: "600",
        unit: "s",
        effect: "next boot (router-tier access points)",
        table: Table::System,
    },
    Setting {
        key: "wifi.guard_safe_hold_secs",
        section: "Wi-Fi crash protection",
        label: "Safe-mode hold",
        doc: "How long safe mode stays on after the last crash at first; each new entry within a day doubles it, up to 24 h.",
        kind: Kind::Int { min: 300, max: 86400 },
        default: "3600",
        unit: "s",
        effect: "next boot (router-tier access points)",
        table: Table::System,
    },
    Setting {
        key: "wifi.guard_loop_boots",
        section: "Wi-Fi crash protection",
        label: "Restart-loop boots",
        doc: "A firmware crash in each of this many boots in a row counts as a restart loop and starts the next boot in safe mode.",
        kind: Kind::Int { min: 1, max: 10 },
        default: "2",
        unit: "boots",
        effect: "next boot (router-tier access points)",
        table: Table::System,
    },
    Setting {
        key: "ha.sync_port",
        section: "High availability",
        label: "State sync port",
        doc: "UDP port conntrackd uses to copy connection state to the HA peer (both routers must use the same port; the firewall opens it on the sync interface for the peer only).",
        kind: Kind::Port,
        default: "3780",
        unit: "UDP port",
        effect: "next HA apply",
        table: Table::Lan,
    },
    Setting {
        key: "proxy.intercept_port",
        section: "Web proxy",
        label: "Intercept port",
        doc: "Port Squid listens on for plain HTTP that the firewall redirects from the LAN when interception is on (the proxy port itself is on the Web proxy page).",
        kind: Kind::Int { min: 1025, max: 65_535 },
        default: "3129",
        unit: "TCP port",
        effect: "next web proxy apply",
        table: Table::Lan,
    },
    Setting {
        key: "guard.confirm_secs",
        section: "Router firmware safety",
        label: "Boot confirmation window",
        doc: "How long a freshly flashed Patronus boot has to be confirmed (by an operator or the unattended gateway check) before the unit reverts to the previous firmware.",
        kind: Kind::Int { min: 60, max: 86_400 },
        default: "600",
        unit: "seconds",
        effect: "next boot (router-tier units)",
        table: Table::System,
    },
    Setting {
        key: "guard.max_unconfirmed_boots",
        section: "Router firmware safety",
        label: "Unconfirmed boots before rollback",
        doc: "After this many boots in a row that were never confirmed, early boot puts the previous root back instead of starting init again (stops a boot loop).",
        kind: Kind::Int { min: 1, max: 20 },
        default: "3",
        unit: "boots",
        effect: "next boot (router-tier units)",
        table: Table::System,
    },
    Setting {
        key: "guard.wan_lease_fallback_secs",
        section: "Router firmware safety",
        label: "WAN lease fallback delay",
        doc: "Seconds the boot script waits for Patronus' own DHCP client to get a WAN lease before it starts the fallback client.",
        kind: Kind::Int { min: 5, max: 600 },
        default: "45",
        unit: "seconds",
        effect: "next boot (router-tier units)",
        table: Table::System,
    },
    Setting {
        key: "wifi.radio_wait_secs",
        section: "Wi-Fi access point",
        label: "Radio detection wait",
        doc: "How long the access-point start waits for both Wi-Fi radios to appear after boot (the firmware loads them late) before it gives up.",
        kind: Kind::Int { min: 10, max: 600 },
        default: "90",
        unit: "seconds",
        effect: "next access-point start",
        table: Table::System,
    },
    Setting {
        key: "wifi.recover_wait_secs",
        section: "Wi-Fi access point",
        label: "Firmware crash recovery wait",
        doc: "How long wifi-guard waits after a Wi-Fi firmware crash for every network to come back by itself before it restarts the access points.",
        kind: Kind::Int { min: 5, max: 300 },
        default: "20",
        unit: "seconds",
        effect: "next firmware crash",
        table: Table::System,
    },
    Setting {
        key: "upgrade.ubiblock_wait_secs",
        section: "Firmware upgrade",
        label: "Root volume release wait",
        doc: "How long the firmware installer waits for the old root volume to be released before it gives up.",
        kind: Kind::Int { min: 1, max: 120 },
        default: "10",
        unit: "seconds",
        effect: "next firmware upgrade",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_spamhaus_drop",
        section: "Blocklist feeds",
        label: "Spamhaus DROP URL",
        doc: "Where the Spamhaus DROP list (IPv4 netblocks of spammers and cyber-criminals) is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://www.spamhaus.org/drop/drop.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_spamhaus_edrop",
        section: "Blocklist feeds",
        label: "Spamhaus EDROP URL",
        doc: "Where the Spamhaus EDROP list is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://www.spamhaus.org/drop/edrop.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_spamhaus_dropv6",
        section: "Blocklist feeds",
        label: "Spamhaus DROPv6 URL",
        doc: "Where the Spamhaus DROP list for IPv6 is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://www.spamhaus.org/drop/dropv6.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_firehol_level1",
        section: "Blocklist feeds",
        label: "FireHOL level 1 URL",
        doc: "Where the FireHOL level 1 netset is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_abusech_feodo",
        section: "Blocklist feeds",
        label: "abuse.ch Feodo Tracker URL",
        doc: "Where the abuse.ch Feodo Tracker botnet list is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_abusech_sslbl",
        section: "Blocklist feeds",
        label: "abuse.ch SSLBL URL",
        doc: "Where the abuse.ch SSL blacklist of botnet C&C addresses is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.url_et_compromised",
        section: "Blocklist feeds",
        label: "Emerging Threats compromised IPs URL",
        doc: "Where the Emerging Threats list of compromised hosts is downloaded from when you enable that feed.",
        kind: Kind::Url { optional: false },
        default: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        unit: "URL",
        effect: "when the feed is next enabled",
        table: Table::System,
    },
    Setting {
        key: "feeds.geoip_db_template",
        section: "Blocklist feeds",
        label: "GeoIP database download template",
        doc: "Address of the monthly country database; {year} and {month} (two digits) are replaced, the current month is tried first and last month's file is the fallback. A custom address on the Firewall page's GeoIP box wins over this.",
        kind: Kind::Text { max_len: 512 },
        default: "https://download.db-ip.com/free/dbip-country-lite-{year}-{month}.csv.gz",
        unit: "URL template",
        effect: "next GeoIP database refresh",
        table: Table::System,
    },
    Setting {
        key: "feeds.asn_db_template",
        section: "Blocklist feeds",
        label: "ASN database download template",
        doc: "Address of the monthly ASN database used by traffic insight; {year} and {month} (two digits) are replaced, last month's file is the fallback. A custom address on the Insight page wins over this.",
        kind: Kind::Text { max_len: 512 },
        default: "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month}.csv.gz",
        unit: "URL template",
        effect: "next ASN database refresh",
        table: Table::System,
    },
    Setting {
        key: "dns.family_lists",
        section: "DNS filtering",
        label: "Family filter blocklists",
        doc: "Hosts-format blocklists that the 'family' DNS policy preset downloads and enforces.",
        kind: Kind::Text { max_len: 2000 },
        default: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts,https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
        unit: "URLs, comma separated",
        effect: "next DNS policy apply",
        table: Table::Lan,
    },
    Setting {
        key: "dns.fallback_servers",
        section: "DNS",
        label: "Fallback resolvers",
        doc: "Upstream resolvers a fresh configuration forwards to until the administrator picks their own (an existing configuration keeps its servers).",
        kind: Kind::Addrs { optional: false },
        default: "8.8.8.8,8.8.4.4",
        unit: "IP addresses, comma separated",
        effect: "new configurations (first boot, reset)",
        table: Table::System,
    },
    Setting {
        key: "portal.default_redirect_url",
        section: "Captive portal",
        label: "Default landing page",
        doc: "Where a guest is sent after signing in when the original page they asked for is unknown.",
        kind: Kind::Url { optional: false },
        default: "http://www.google.com",
        unit: "URL",
        effect: "at once",
        table: Table::System,
    },
    Setting {
        key: "portal.pre_auth_dns",
        section: "Captive portal",
        label: "Resolvers reachable before sign-in",
        doc: "DNS servers that guests can reach before they have signed in (so the portal page can be found).",
        kind: Kind::Addrs { optional: false },
        default: "8.8.8.8,8.8.4.4,1.1.1.1",
        unit: "IP addresses, comma separated",
        effect: "next captive-portal start",
        table: Table::System,
    },
    Setting {
        key: "speedtest.down_url",
        section: "Speed test",
        label: "Download test URL",
        doc: "Address the download speed test fetches; {bytes} is replaced by the test size.",
        kind: Kind::Url { optional: false },
        default: "https://speed.cloudflare.com/__down?bytes={bytes}",
        unit: "URL",
        effect: "next speed test",
        table: Table::System,
    },
    Setting {
        key: "speedtest.up_url",
        section: "Speed test",
        label: "Upload test URL",
        doc: "Address the upload speed test posts to. Empty turns the upload test off.",
        kind: Kind::Url { optional: true },
        default: "https://speed.cloudflare.com/__up",
        unit: "URL (empty = no upload test)",
        effect: "next speed test",
        table: Table::System,
    },
    Setting {
        key: "speedtest.bytes_down",
        section: "Speed test",
        label: "Download test size",
        doc: "How much data the download speed test fetches.",
        kind: Kind::Int { min: 100_000, max: 1_000_000_000 },
        default: "25000000",
        unit: "bytes",
        effect: "next speed test",
        table: Table::System,
    },
    Setting {
        key: "speedtest.bytes_up",
        section: "Speed test",
        label: "Upload test size",
        doc: "How much data the upload speed test sends.",
        kind: Kind::Int { min: 100_000, max: 1_000_000_000 },
        default: "10000000",
        unit: "bytes",
        effect: "next speed test",
        table: Table::System,
    },
    Setting {
        key: "speedtest.interval_hours",
        section: "Speed test",
        label: "Scheduled test interval",
        doc: "How often a speed test runs by itself; 0 runs tests only on demand.",
        kind: Kind::Int { min: 0, max: 168 },
        default: "0",
        unit: "hours (0 = off)",
        effect: "next scheduler tick",
        table: Table::System,
    },
    Setting {
        key: "feeds.ipdeny_aggregated_template",
        section: "Blocklist feeds",
        label: "Country block list (aggregated) template",
        doc: "Where the country IP list generator downloads aggregated per-country zones from; {cc} is the lower-case country code.",
        kind: Kind::Text { max_len: 512 },
        default: "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone",
        unit: "URL template",
        effect: "next country list download",
        table: Table::System,
    },
    Setting {
        key: "feeds.ipdeny_country_template",
        section: "Blocklist feeds",
        label: "Country block list template",
        doc: "Where the legacy country IP list generator downloads per-country zones from; {cc} is the lower-case country code.",
        kind: Kind::Text { max_len: 512 },
        default: "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone",
        unit: "URL template",
        effect: "next country list download",
        table: Table::System,
    },
    Setting {
        key: "seg.time_portal_port",
        section: "Device segmentation",
        label: "Time's-up page port",
        doc: "Plain-HTTP port of the page a device sees when its daily time limit is used up (the firewall redirects HTTP to it).",
        kind: Kind::Int { min: 1024, max: 65_535 },
        default: "8081",
        unit: "TCP port",
        effect: "next time-limit apply",
        table: Table::Lan,
    },
    Setting {
        key: "upnp.control_port",
        section: "UPnP / NAT-PMP",
        label: "UPnP control port",
        doc: "TCP port of miniupnpd's control URL on the LAN side (opened on the served interface only).",
        kind: Kind::Int { min: 1024, max: 65_535 },
        default: "5000",
        unit: "TCP port",
        effect: "next UPnP apply",
        table: Table::Lan,
    },
    Setting {
        key: "proxy.port",
        section: "Web proxy",
        label: "Proxy port",
        doc: "Port Squid listens on for proxy clients (the Web proxy page edits the same value).",
        kind: Kind::Int { min: 1025, max: 65_535 },
        default: "3128",
        unit: "TCP port",
        effect: "next web proxy apply",
        table: Table::Lan,
    },
    Setting {
        key: "network.vxlan_port",
        section: "VPN and overlay",
        label: "Default VXLAN port",
        doc: "UDP destination port of a VXLAN overlay that does not set its own.",
        kind: Kind::Port,
        default: "4789",
        unit: "UDP port",
        effect: "next overlay apply",
        table: Table::System,
    },
    Setting {
        key: "vpn.wireguard_port",
        section: "VPN and overlay",
        label: "Default WireGuard port",
        doc: "First listen port offered to a new WireGuard tunnel (the next free port from here is used).",
        kind: Kind::Port,
        default: "51820",
        unit: "UDP port",
        effect: "new WireGuard tunnels",
        table: Table::System,
    },
    Setting {
        key: "vpn.openvpn_port",
        section: "VPN and overlay",
        label: "Default OpenVPN port",
        doc: "Listen port a new OpenVPN server starts with.",
        kind: Kind::Port,
        default: "1194",
        unit: "port",
        effect: "new OpenVPN servers",
        table: Table::System,
    },
    Setting {
        key: "gitops.webhook_port",
        section: "GitOps",
        label: "Webhook listen port",
        doc: "Port the GitOps webhook receiver listens on (bound to the webhook's listen address).",
        kind: Kind::Port,
        default: "9999",
        unit: "TCP port",
        effect: "next GitOps watch start",
        table: Table::System,
    },
];

/// Registered default of `key` (for code that has no store at hand, such as a form's pre-filled
/// value or a CLI fallback). Panics in debug builds on an unregistered key.
pub fn default_of(key: &str) -> &'static str {
    match find(key) {
        Some(s) => s.default,
        None => {
            debug_assert!(false, "unregistered setting {key}");
            ""
        }
    }
}

/// Registry entry for `key`.
pub fn find(key: &str) -> Option<&'static Setting> {
    REGISTRY.iter().find(|s| s.key == key)
}

fn invalid(msg: String) -> Error {
    Error::Config(format!("Invalid setting: {msg}"))
}

/// Validate and normalise `value` for `s`.
pub fn validate(s: &Setting, value: &str) -> Result<String> {
    let v = value.trim();
    match s.kind {
        Kind::Bool => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok("true".into()),
            "0" | "false" | "no" | "off" => Ok("false".into()),
            _ => Err(invalid(format!("{}: {value:?} is not true/false", s.key))),
        },
        Kind::Int { min, max } => {
            let n: i64 = v
                .parse()
                .map_err(|_| invalid(format!("{}: {value:?} is not a whole number", s.key)))?;
            if n < min || n > max {
                return Err(invalid(format!(
                    "{}: {n} is outside {min}..{max} {}",
                    s.key, s.unit
                )));
            }
            Ok(n.to_string())
        }
        Kind::Port => match v.parse::<u16>() {
            Ok(p) if p > 0 => Ok(p.to_string()),
            _ => Err(invalid(format!(
                "{}: {value:?} is not a port (1-65535)",
                s.key
            ))),
        },
        Kind::Text { max_len } => {
            if v.len() > max_len || v.chars().any(char::is_control) {
                return Err(invalid(format!(
                    "{}: at most {max_len} bytes, no control characters",
                    s.key
                )));
            }
            Ok(v.to_string())
        }
        Kind::Url { optional } => {
            if v.is_empty() && optional {
                return Ok(String::new());
            }
            let ok = (v.starts_with("http://") || v.starts_with("https://"))
                && v.len() <= 2048
                && !v.chars().any(|c| c.is_control() || c.is_whitespace());
            if ok {
                Ok(v.to_string())
            } else {
                Err(invalid(format!(
                    "{}: {value:?} is not an http(s) URL",
                    s.key
                )))
            }
        }
        Kind::Addrs { optional } => {
            let parts: Vec<&str> = v
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .collect();
            if parts.is_empty() && optional {
                return Ok(String::new());
            }
            if parts.is_empty()
                || parts.len() > 16
                || parts.iter().any(|p| p.parse::<std::net::IpAddr>().is_err())
            {
                return Err(invalid(format!(
                    "{}: {value:?} is not a comma-separated list of IP addresses (1-16)",
                    s.key
                )));
            }
            Ok(parts.join(","))
        }
        Kind::Choice { options } => {
            if options.contains(&v) {
                Ok(v.to_string())
            } else {
                Err(invalid(format!(
                    "{}: {value:?} is not one of {}",
                    s.key,
                    options.join(", ")
                )))
            }
        }
    }
}

fn entry(key: &str) -> Result<&'static Setting> {
    find(key).ok_or_else(|| invalid(format!("unknown key {key:?}")))
}

fn db_err(e: sqlx::Error) -> Error {
    Error::Config(format!("settings store: {e}"))
}

async fn load_raw(store: &ConfigStore, s: &Setting) -> Result<Option<String>> {
    if s.table == Table::System {
        return store.load_system_config(s.key).await;
    }
    let row: Option<String> = sqlx::query_scalar(&format!(
        "SELECT value FROM {} WHERE key = ?",
        s.table.name()
    ))
    .bind(s.key)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db_err)?;
    Ok(row)
}

async fn save_raw(store: &ConfigStore, s: &Setting, v: &str) -> Result<()> {
    if s.table == Table::System {
        return store.save_system_config(s.key, v).await;
    }
    sqlx::query(&format!(
        "INSERT INTO {} (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        s.table.name()
    ))
    .bind(s.key)
    .bind(v)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn delete_raw(store: &ConfigStore, s: &Setting) -> Result<()> {
    if s.table == Table::System {
        return store.delete_system_config(s.key).await;
    }
    sqlx::query(&format!("DELETE FROM {} WHERE key = ?", s.table.name()))
        .bind(s.key)
        .execute(store.pool()?)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Stored value of `key`, or its default. A stored value that no longer
/// validates (bounds tightened in a newer release) falls back to the default.
pub async fn get(store: &ConfigStore, key: &str) -> Result<String> {
    let s = entry(key)?;
    Ok(match load_raw(store, s).await? {
        Some(v) => validate(s, &v).unwrap_or_else(|e| {
            tracing::warn!("{e}; using the default {}", s.default);
            s.default.to_string()
        }),
        None => s.default.to_string(),
    })
}

/// [`get`] as a number (Int/Port settings).
pub async fn get_i64(store: &ConfigStore, key: &str) -> Result<i64> {
    let v = get(store, key).await?;
    v.parse()
        .map_err(|_| invalid(format!("{key}: {v:?} is not a number")))
}

/// Validate and store `value`; returns the normalised value. Processes
/// holding a cache refresh it with [`load_cache`].
pub async fn set(store: &ConfigStore, key: &str, value: &str) -> Result<String> {
    let s = entry(key)?;
    let v = validate(s, value)?;
    save_raw(store, s, &v).await?;
    notify_changed();
    Ok(v)
}

/// Where the router-tier images keep their `settings-env` helper (the boot scripts read the file
/// it renders). `PATRONUS_SETTINGS_HOOK` points elsewhere (tests, other layouts); a path that
/// does not exist means this box has no such scripts and nothing runs.
pub const DEFAULT_CHANGE_HOOK: &str = "/usr/libexec/patronus/settings-env";

/// After a stored change: let the boot/helper scripts see it without waiting for the next boot
/// (`settings-env refresh`). Fire and forget: a failing hook never fails the change.
pub fn notify_changed() {
    let hook =
        std::env::var("PATRONUS_SETTINGS_HOOK").unwrap_or_else(|_| DEFAULT_CHANGE_HOOK.into());
    if hook.is_empty() || !std::path::Path::new(&hook).exists() {
        return;
    }
    if let Ok(mut child) = std::process::Command::new(&hook)
        .arg("refresh")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

/// Back to the default (removes the stored value).
pub async fn reset(store: &ConfigStore, key: &str) -> Result<()> {
    delete_raw(store, entry(key)?).await?;
    notify_changed();
    Ok(())
}

/// A setting with its current value, for the API/UI.
#[derive(Debug, Clone, Serialize)]
pub struct SettingView {
    #[serde(flatten)]
    pub setting: Setting,
    pub value: String,
    pub is_default: bool,
}

/// Every setting with its value.
pub async fn list(store: &ConfigStore) -> Result<Vec<SettingView>> {
    let mut out = Vec::with_capacity(REGISTRY.len());
    for s in REGISTRY {
        let stored = load_raw(store, s).await?;
        let value = get(store, s.key).await?;
        out.push(SettingView {
            setting: *s,
            is_default: stored.is_none(),
            value,
        });
    }
    Ok(out)
}

/// Shell variable name of a key: `web.session_lifetime_secs` ->
/// `PATRONUS_SET_WEB_SESSION_LIFETIME_SECS`.
pub fn env_name(key: &str) -> String {
    let mut n = String::from("PATRONUS_SET_");
    for c in key.chars() {
        n.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    n
}

/// Every value as `NAME='value'` lines, safe to `.` from a POSIX shell.
pub fn render_env(values: &[SettingView]) -> String {
    let mut out = String::from("# Generated by `patronus settings env` -- edit through the web UI or `patronus settings set`.\n");
    for v in values {
        out.push_str(&env_name(v.setting.key));
        out.push_str("='");
        out.push_str(&v.value.replace('\'', "'\\''"));
        out.push_str("'\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Process cache for synchronous readers.

fn cache() -> &'static RwLock<HashMap<String, String>> {
    static C: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    C.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Refill the process cache from the store (web start, after changes, and
/// periodically so `patronus settings set` from a shell reaches the web).
pub async fn load_cache(store: &ConfigStore) -> Result<()> {
    let mut fresh = HashMap::new();
    for s in REGISTRY {
        if load_raw(store, s).await?.is_some() {
            fresh.insert(s.key.to_string(), get(store, s.key).await?);
        }
    }
    *cache().write().unwrap_or_else(|e| e.into_inner()) = fresh;
    Ok(())
}

/// Cached value of `key` (default when not set or not loaded yet).
/// Panics in debug builds on an unregistered key: that is a code bug.
pub fn current(key: &str) -> String {
    if let Some(v) = cache().read().unwrap_or_else(|e| e.into_inner()).get(key) {
        return v.clone();
    }
    match find(key) {
        Some(s) => s.default.to_string(),
        None => {
            debug_assert!(false, "unregistered setting {key}");
            String::new()
        }
    }
}

/// [`current`] as a number; falls back to the registered default.
pub fn current_i64(key: &str) -> i64 {
    current(key)
        .parse()
        .ok()
        .or_else(|| find(key).and_then(|s| s.default.parse().ok()))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::open(d.path().join("c.db")).await.unwrap();
        (d, s)
    }

    #[test]
    fn registry_is_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for s in REGISTRY {
            assert!(seen.insert(s.key), "duplicate key {}", s.key);
            assert!(
                s.key.contains('.') && s.key == s.key.to_ascii_lowercase(),
                "{}",
                s.key
            );
            assert!(
                !s.doc.is_empty() && !s.label.is_empty() && !s.effect.is_empty(),
                "{}",
                s.key
            );
            // every default must pass its own validation
            assert_eq!(validate(s, s.default).unwrap(), s.default, "{}", s.key);
        }
    }

    #[test]
    fn validation_rejects_out_of_range_and_junk() {
        let s = find("web.min_password_length").unwrap();
        assert!(validate(s, "7").is_err());
        assert!(validate(s, "x").is_err());
        assert_eq!(validate(s, " 16 ").unwrap(), "16");
        let b = Setting {
            kind: Kind::Bool,
            ..*s
        };
        assert_eq!(validate(&b, "on").unwrap(), "true");
        assert!(validate(&b, "maybe").is_err());
        let p = Setting {
            kind: Kind::Port,
            ..*s
        };
        assert!(validate(&p, "0").is_err() && validate(&p, "70000").is_err());
        let u = Setting {
            kind: Kind::Url { optional: true },
            ..*s
        };
        assert_eq!(validate(&u, "").unwrap(), "");
        assert!(validate(&u, "ftp://x").is_err());
        let c = Setting {
            kind: Kind::Choice {
                options: &["a", "b"],
            },
            ..*s
        };
        assert!(validate(&c, "c").is_err());
        let t = Setting {
            kind: Kind::Text { max_len: 3 },
            ..*s
        };
        assert!(validate(&t, "abcd").is_err() && validate(&t, "a\nb").is_err());
    }

    #[tokio::test]
    async fn set_get_reset_and_unknown_keys() {
        let (_d, s) = store().await;
        assert_eq!(get(&s, "web.login_max_failures").await.unwrap(), "5");
        assert_eq!(set(&s, "web.login_max_failures", "7").await.unwrap(), "7");
        assert_eq!(get_i64(&s, "web.login_max_failures").await.unwrap(), 7);
        assert!(set(&s, "web.login_max_failures", "0").await.is_err());
        assert!(set(&s, "no.such_key", "1").await.is_err());
        let l = list(&s).await.unwrap();
        let v = l
            .iter()
            .find(|v| v.setting.key == "web.login_max_failures")
            .unwrap();
        assert!(!v.is_default && v.value == "7");
        reset(&s, "web.login_max_failures").await.unwrap();
        assert_eq!(get(&s, "web.login_max_failures").await.unwrap(), "5");
        // a stored value that no longer validates reads as the default
        s.save_system_config("web.login_max_failures", "100000")
            .await
            .unwrap();
        assert_eq!(get(&s, "web.login_max_failures").await.unwrap(), "5");
    }

    /// The schema contract: every registered key survives export -> import
    /// into a fresh box, and so does "never set" (stays the default).
    #[tokio::test]
    async fn every_key_round_trips_export_import() {
        let (_d, a) = store().await;
        let mut want = HashMap::new();
        for (i, k) in REGISTRY.iter().enumerate() {
            // a non-default valid value per type
            let v = match k.kind {
                Kind::Bool => if k.default == "true" { "false" } else { "true" }.to_string(),
                Kind::Int { min, max } => {
                    let d: i64 = k.default.parse().unwrap();
                    if d < max {
                        (d + 1).to_string()
                    } else {
                        min.to_string()
                    }
                }
                Kind::Port => if k.default == "1024" { "1025" } else { "1024" }.to_string(),
                Kind::Text { .. } => format!("v{i}"),
                Kind::Url { .. } => format!("https://example.test/{i}"),
                Kind::Addrs { .. } => format!("192.0.2.{}", i % 250 + 1),
                Kind::Choice { options } => options
                    .iter()
                    .find(|o| **o != k.default)
                    .unwrap_or(&options[0])
                    .to_string(),
            };
            assert_ne!(v, k.default, "{}", k.key);
            set(&a, k.key, &v).await.unwrap();
            want.insert(k.key, v);
        }
        let doc = a.export_json().await.unwrap();
        let (_d2, b) = store().await;
        b.import_json(&doc).await.unwrap();
        for k in REGISTRY {
            assert_eq!(
                get(&b, k.key).await.unwrap(),
                want[k.key],
                "{} lost in export/import",
                k.key
            );
        }
        // and an export of an untouched box imports as all-defaults
        let (_d3, c) = store().await;
        let doc = c.export_json().await.unwrap();
        b.import_json(&doc).await.unwrap();
        for k in REGISTRY {
            assert_eq!(
                get(&b, k.key).await.unwrap(),
                k.default,
                "{} not reset by import",
                k.key
            );
        }
    }

    #[tokio::test]
    async fn a_change_runs_the_refresh_hook() {
        let d = tempfile::tempdir().unwrap();
        let hook = d.path().join("hook.sh");
        let out = d.path().join("out");
        std::fs::write(
            &hook,
            format!("#!/bin/sh\necho \"$1\" >> {}\n", out.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("PATRONUS_SETTINGS_HOOK", &hook);
        let (_d, s) = store().await;
        set(&s, "web.login_max_failures", "6").await.unwrap();
        reset(&s, "web.login_max_failures").await.unwrap();
        std::env::remove_var("PATRONUS_SETTINGS_HOOK");
        for _ in 0..50 {
            if std::fs::read_to_string(&out)
                .map(|t| t.lines().count() >= 2)
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        // other tests set values at the same time and may trigger it too: at least our two
        let t = std::fs::read_to_string(&out).unwrap();
        assert!(
            t.lines().count() >= 2 && t.lines().all(|l| l == "refresh"),
            "{t:?}"
        );
    }

    #[tokio::test]
    async fn env_rendering_is_shell_safe() {
        let (_d, s) = store().await;
        let v = list(&s).await.unwrap();
        let mut odd = v[0].clone();
        odd.value = "it's $(x)".into();
        let out = render_env(&[odd]);
        assert!(
            out.contains("PATRONUS_SET_WEB_SESSION_LIFETIME_SECS='it'\\''s $(x)'"),
            "{out}"
        );
        assert_eq!(env_name("a.b-c"), "PATRONUS_SET_A_B_C");
    }
}
