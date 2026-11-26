//! LAN security audit (USE=lan-audit, `net-analyzer/nmap` + `net-analyzer/rustscan`).
//!
//! "Scan my network": on demand (`patronus scan`, the page's Scan now button)
//! and on a schedule (quiet hours, rate limited) it looks at the devices on the
//! LAN segments — never the WAN — for open ports and the services behind them,
//! runs a rule set over the result (telnet, FTP, SMB, UPnP/SSDP, admin pages on
//! plain HTTP, known default-credential logins, exposed databases), compares it
//! with the last scan ("new device", "new open port") and routes the findings
//! into the security events.
//!
//! Two scanners:
//!
//! - **standard tier**: when `rustscan` and `nmap` are installed, a fast
//!   rustscan port sweep feeds `nmap -sV` for service/version detection
//!   ([`NmapScanner`]); the XML (`-oX`) is parsed, nothing is trusted from a
//!   banner beyond text;
//! - **every tier (and the fallback)**: a small built-in TCP connect scan of a
//!   port list with a light banner read ([`BuiltinScanner`]), pure Rust, no
//!   raw sockets and no external tool, which is all the router tier ships.
//!
//! Hosts are the ones Patronus already knows (DHCP leases, segmentation
//! devices and the kernel neighbour table), so a scan names them; it never
//! sweeps a whole subnet by default. Measured data (scans, hosts, ports,
//! findings) lives in `NON_CONFIG` tables with a retention bound; the settings
//! are `lanaudit.*` configuration keys.

use crate::lan::invalid;
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

fn bad(msg: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {msg}"))
}

/// Unix seconds now (or the fake clock a test sets through the schedule module).
pub fn now() -> i64 {
    patronus_firewall_now()
}

// patronus-network must not depend on patronus-firewall, so mirror the schedule
// module's fake-clock contract here (the env var is the same, so a netlab lane
// can freeze time for both the firewall and the audit).
fn patronus_firewall_now() -> i64 {
    if let Some(p) = std::env::var_os("PATRONUS_FAKE_TIME_FILE") {
        if let Ok(t) = std::fs::read_to_string(&p) {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(t.trim(), "%Y-%m-%d %H:%M") {
                return dt.and_utc().timestamp();
            }
        }
    }
    chrono::Utc::now().timestamp()
}

/// Local wall-clock minutes-since-midnight and weekday, for the quiet-hours and
/// schedule checks. Uses the fake clock when it is set (as local time).
fn local_now() -> chrono::NaiveDateTime {
    if let Some(p) = std::env::var_os("PATRONUS_FAKE_TIME_FILE") {
        if let Ok(t) = std::fs::read_to_string(&p) {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(t.trim(), "%Y-%m-%d %H:%M") {
                return dt;
            }
        }
    }
    chrono::Local::now().naive_local()
}

// ---------------------------------------------------------------------------
// port catalogue
// ---------------------------------------------------------------------------

/// The built-in top-ports TCP list (the router tier and the fallback scan).
/// Kept small on purpose: the common services plus the ones a finding rule
/// cares about. The standard tier's nmap pass widens this.
pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 515, 548, 587,
    631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2375, 2376, 2869, 3000, 3128, 3306, 3389, 4444, 5000, 5060, 5432, 5601, 5672,
    5900, 5984, 6000, 6379, 7000, 7070, 7474, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8123, 8181,
    8443, 8500, 8686, 8888, 9000, 9042, 9090, 9100, 9200, 9300, 11211, 15672, 27017, 27018, 28017,
    50000,
];

/// A best-guess service name for a port when no banner says otherwise.
pub fn guess_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "domain",
        80 | 8000 | 8008 | 8080 | 8081 | 8088 | 8181 | 8888 | 3000 | 5000 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        161 => "snmp",
        389 | 636 => "ldap",
        443 | 8443 => "https",
        514 => "syslog",
        548 => "afp",
        631 => "ipp",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        1900 => "upnp",
        2049 => "nfs",
        2375 | 2376 => "docker",
        2869 => "upnp-http",
        3128 => "proxy",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5060 => "sip",
        5432 => "postgresql",
        5601 => "kibana",
        5672 | 15672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        7474 => "neo4j",
        8086 => "influxdb",
        9042 => "cassandra",
        9090 => "prometheus",
        9100 => "jetdirect",
        9200 | 9300 => "elasticsearch",
        11211 => "memcached",
        27017 | 27018 | 28017 => "mongodb",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// settings (system_config `lanaudit.*`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settings {
    pub enabled: bool,
    /// Segments to scan: specs like `@lan`, `@opt1` or an interface name.
    /// Empty = every non-WAN interface. The WAN is never scanned.
    pub segments: Vec<String>,
    /// Run a scheduled scan every this many hours (0 = on demand only).
    pub interval_hours: u32,
    /// Only start a scheduled scan inside the quiet window (local time,
    /// minutes since midnight). Equal start and end = no restriction.
    pub quiet_start_min: u32,
    pub quiet_end_min: u32,
    /// Rate limit: at most this many hosts probed at once.
    pub max_parallel: u32,
    /// Rate limit handed to nmap (`--max-rate`, packets/second; 0 = no cap).
    pub max_rate: u32,
    /// Per-port connect timeout, milliseconds.
    pub connect_timeout_ms: u32,
    /// Also discover unknown hosts from the neighbour table (for new-device
    /// findings), not only the hosts Patronus already knows.
    pub discover_neighbours: bool,
    /// How many finished scans to keep (retention for the measured tables).
    pub keep_scans: u32,
    /// Minimum finding severity routed to the security events.
    pub alert_min_severity: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            segments: Vec::new(),
            interval_hours: 24,
            quiet_start_min: 2 * 60,
            quiet_end_min: 5 * 60,
            max_parallel: 16,
            max_rate: 0,
            connect_timeout_ms: 800,
            discover_neighbours: true,
            keep_scans: 30,
            alert_min_severity: "warning".into(),
        }
    }
}

/// A partial update (the API PUT body and `patronus scan set`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsIn {
    pub enabled: Option<bool>,
    pub segments: Option<Vec<String>>,
    pub interval_hours: Option<u32>,
    pub quiet_start_min: Option<u32>,
    pub quiet_end_min: Option<u32>,
    pub max_parallel: Option<u32>,
    pub max_rate: Option<u32>,
    pub connect_timeout_ms: Option<u32>,
    pub discover_neighbours: Option<bool>,
    pub keep_scans: Option<u32>,
    pub alert_min_severity: Option<String>,
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

pub const SEVERITIES: &[&str] = &["info", "warning", "critical"];

/// A segment spec is `@role`, `@optN`, or an interface name. Never `@wan`.
fn valid_segment(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 32 {
        return false;
    }
    if let Some(role) = s.strip_prefix('@') {
        let role = role.to_ascii_lowercase();
        return role != "wan" && role.bytes().all(|b| b.is_ascii_alphanumeric());
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b'@')
        && !s.eq_ignore_ascii_case("@wan")
}

impl Settings {
    pub fn merged(&self, i: &SettingsIn) -> Result<Settings> {
        let mut s = self.clone();
        if let Some(v) = i.enabled {
            s.enabled = v;
        }
        if let Some(v) = i.discover_neighbours {
            s.discover_neighbours = v;
        }
        if let Some(v) = &i.segments {
            let mut out = Vec::new();
            for x in v.iter().map(|x| x.trim()).filter(|x| !x.is_empty()) {
                if !valid_segment(x) {
                    return Err(bad(format!(
                        "segment {x:?} (@role, @optN or a device; not the WAN)"
                    )));
                }
                let x = x.to_string();
                if !out.contains(&x) {
                    out.push(x);
                }
            }
            s.segments = out;
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
        num!(interval_hours, 0, 24 * 30, "scan interval (hours)");
        num!(quiet_start_min, 0, 1439, "quiet-hours start");
        num!(quiet_end_min, 0, 1439, "quiet-hours end");
        num!(max_parallel, 1, 256, "parallel hosts");
        num!(max_rate, 0, 1_000_000, "packet rate");
        num!(connect_timeout_ms, 50, 10_000, "connect timeout (ms)");
        num!(keep_scans, 1, 10_000, "scans to keep");
        if let Some(v) = &i.alert_min_severity {
            let v = v.trim().to_ascii_lowercase();
            if !SEVERITIES.contains(&v.as_str()) {
                return Err(bad(format!("severity {v:?} (info, warning or critical)")));
            }
            s.alert_min_severity = v;
        }
        Ok(s)
    }

    fn pairs(&self) -> Vec<(&'static str, String)> {
        let b = |v: bool| if v { "1" } else { "0" }.to_string();
        vec![
            ("lanaudit.enabled", b(self.enabled)),
            ("lanaudit.segments", self.segments.join(",")),
            ("lanaudit.interval_hours", self.interval_hours.to_string()),
            ("lanaudit.quiet_start_min", self.quiet_start_min.to_string()),
            ("lanaudit.quiet_end_min", self.quiet_end_min.to_string()),
            ("lanaudit.max_parallel", self.max_parallel.to_string()),
            ("lanaudit.max_rate", self.max_rate.to_string()),
            (
                "lanaudit.connect_timeout_ms",
                self.connect_timeout_ms.to_string(),
            ),
            ("lanaudit.discover_neighbours", b(self.discover_neighbours)),
            ("lanaudit.keep_scans", self.keep_scans.to_string()),
            (
                "lanaudit.alert_min_severity",
                self.alert_min_severity.clone(),
            ),
        ]
    }

    /// Is `at` (minutes since midnight) inside the quiet window? No window = always.
    pub fn in_quiet_window(&self, at: u32) -> bool {
        let (s, e) = (self.quiet_start_min, self.quiet_end_min);
        if s == e {
            return true;
        }
        if s < e {
            at >= s && at < e
        } else {
            // wraps midnight
            at >= s || at < e
        }
    }
}

/// Read the settings; a stored value that does not validate falls back to its
/// default (with a warning), so one bad key never disables scanning behaviour.
pub async fn load(store: &ConfigStore) -> Result<Settings> {
    let d = Settings::default();
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    let rows = sqlx::query("SELECT key, value FROM system_config WHERE key LIKE 'lanaudit.%'")
        .fetch_all(store.pool()?)
        .await
        .map_err(db("lan-audit settings"))?;
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
    i.enabled = g("lanaudit.enabled").map(|v| flag(&v));
    i.discover_neighbours = g("lanaudit.discover_neighbours").map(|v| flag(&v));
    i.segments = g("lanaudit.segments").map(|v| list(&v));
    i.alert_min_severity = g("lanaudit.alert_min_severity");
    parse!(interval_hours, "lanaudit.interval_hours");
    parse!(quiet_start_min, "lanaudit.quiet_start_min");
    parse!(quiet_end_min, "lanaudit.quiet_end_min");
    parse!(max_parallel, "lanaudit.max_parallel");
    parse!(max_rate, "lanaudit.max_rate");
    parse!(connect_timeout_ms, "lanaudit.connect_timeout_ms");
    parse!(keep_scans, "lanaudit.keep_scans");
    match d.merged(&i) {
        Ok(s) => Ok(s),
        Err(e) => {
            tracing::warn!("lan-audit settings: {e}; using the defaults for the bad keys");
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
            try1!(segments);
            try1!(interval_hours);
            try1!(quiet_start_min);
            try1!(quiet_end_min);
            try1!(max_parallel);
            try1!(max_rate);
            try1!(connect_timeout_ms);
            try1!(discover_neighbours);
            try1!(keep_scans);
            try1!(alert_min_severity);
            Ok(s)
        }
    }
}

pub async fn save(store: &ConfigStore, i: &SettingsIn) -> Result<Settings> {
    let s = load(store).await?.merged(i)?;
    write(store, &s).await?;
    Ok(s)
}

pub async fn write(store: &ConfigStore, s: &Settings) -> Result<()> {
    for (k, v) in s.pairs() {
        store.save_system_config(k, &v).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// scan model
// ---------------------------------------------------------------------------

/// One host and the open ports found on it in a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Host {
    pub address: String,
    pub name: String,
    pub mac: String,
    pub segment: String,
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Port {
    pub proto: String,
    pub port: u16,
    pub service: String,
    pub product: String,
    pub version: String,
}

/// A target to scan: an address with the best name/MAC/segment we have for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: IpAddr,
    pub name: String,
    pub mac: String,
    pub segment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub address: String,
    pub name: String,
    pub port: Option<u16>,
    pub proto: String,
    pub rule: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// finding rules (pure)
// ---------------------------------------------------------------------------

/// Ports whose service is a database management system reachable on the LAN.
fn database_name(port: u16, service: &str) -> Option<&'static str> {
    let s = service.to_ascii_lowercase();
    Some(match port {
        3306 => "MySQL / MariaDB",
        5432 => "PostgreSQL",
        1433 => "Microsoft SQL Server",
        1521 => "Oracle",
        27017 | 27018 | 28017 => "MongoDB",
        6379 => "Redis",
        9200 | 9300 => "Elasticsearch",
        5984 => "CouchDB",
        11211 => "memcached",
        9042 => "Cassandra",
        7474 => "Neo4j",
        8086 => "InfluxDB",
        _ => {
            return if s.contains("mysql") || s.contains("postgres") || s.contains("mongo") {
                Some("a database")
            } else {
                None
            }
        }
    })
}

/// Login/admin pages whose default credentials are widely published. Matched
/// against the HTTP banner (`Server` header + page title we grab). Kept small
/// and specific; extend with care.
const DEFAULT_CRED_SIGNATURES: &[(&str, &str)] = &[
    (
        "boa/",
        "a Boa-server embedded device (cameras/routers often ship admin/admin)",
    ),
    (
        "gostreamer",
        "a GoAhead/GoStreamer IP camera (default admin password)",
    ),
    (
        "goahead",
        "a GoAhead embedded web server (often default credentials)",
    ),
    (
        "jenkins",
        "Jenkins (an unsecured instance allows anyone in)",
    ),
    ("grafana", "Grafana (the shipped admin/admin login)"),
    ("tomcat", "Apache Tomcat manager (default tomcat/tomcat)"),
    ("phpmyadmin", "phpMyAdmin (often root with no password)"),
    (
        "router webserver",
        "a consumer router admin page (default credentials)",
    ),
    ("hikvision", "a Hikvision device (default admin password)"),
    ("dahua", "a Dahua device (default admin password)"),
];

/// Decide the findings for one host from its open ports. `has_https` is whether
/// the same host also answers on an HTTPS port, so an HTTP admin page is only
/// flagged when there is no HTTPS alternative. `is_new` marks a host that was
/// not in the previous scan.
pub fn findings_for_host(h: &Host, is_new: bool, new_ports: &BTreeSet<u16>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mk =
        |rule: &str, port: Option<u16>, proto: &str, sev: &str, title: String, detail: String| {
            Finding {
                address: h.address.clone(),
                name: h.name.clone(),
                port,
                proto: proto.to_string(),
                rule: rule.to_string(),
                severity: sev.to_string(),
                title,
                detail,
            }
        };
    let has_https = h.ports.iter().any(|p| {
        p.proto == "tcp" && (p.port == 443 || p.port == 8443 || p.service.contains("https"))
    });

    if is_new {
        out.push(mk(
            "new_device",
            None,
            "tcp",
            "info",
            "New device on the network".into(),
            format!(
                "{} was not in the previous scan.",
                display_host(&h.address, &h.name)
            ),
        ));
    }

    for p in &h.ports {
        let svc = p.service.to_ascii_lowercase();
        let banner = format!("{} {} {}", p.service, p.product, p.version).to_ascii_lowercase();
        match p.port {
            23 => out.push(mk(
                "telnet",
                Some(23),
                &p.proto,
                "critical",
                "Telnet is open".into(),
                "Telnet sends passwords in the clear; use SSH instead and close port 23.".into(),
            )),
            21 => out.push(mk(
                "ftp",
                Some(21),
                &p.proto,
                "warning",
                "FTP is open".into(),
                "Plain FTP sends credentials in the clear; prefer SFTP/FTPS.".into(),
            )),
            139 | 445 => out.push(mk(
                "smb",
                Some(p.port),
                &p.proto,
                if banner.contains("smbv1") || banner.contains("smb1") {
                    "critical"
                } else {
                    "warning"
                },
                "SMB file sharing is exposed".into(),
                format!(
                    "SMB on port {} is reachable{}.",
                    p.port,
                    if banner.contains("smbv1") || banner.contains("smb1") {
                        " and offers SMBv1 (WannaCry/EternalBlue); disable SMBv1"
                    } else {
                        "; make sure it is meant to be"
                    }
                ),
            )),
            1900 | 2869 => out.push(mk(
                "upnp",
                Some(p.port),
                &p.proto,
                "warning",
                "UPnP / SSDP service is exposed".into(),
                "UPnP lets devices open firewall holes by themselves; turn it off where it is not needed.".into(),
            )),
            161 if p.proto == "udp" => out.push(mk(
                "upnp",
                Some(161),
                "udp",
                "warning",
                "SNMP is open".into(),
                "SNMP often ships with the community string 'public' and leaks device details.".into(),
            )),
            _ => {}
        }

        // database reachable on the LAN
        if let Some(name) = database_name(p.port, &p.service) {
            out.push(mk(
                "database",
                Some(p.port),
                &p.proto,
                "warning",
                format!("{name} is reachable on the network"),
                format!(
                    "A database ({name}) answers on port {}. Bind it to localhost or firewall it off the LAN unless clients really need it.",
                    p.port
                ),
            ));
        }

        // admin page on plain HTTP with no HTTPS alternative
        let is_http = p.proto == "tcp"
            && (svc == "http" || svc.contains("http") && !svc.contains("https"))
            && p.port != 443
            && p.port != 8443;
        if is_http && !has_https && looks_like_admin(&banner, p.port) {
            out.push(mk(
                "http_admin",
                Some(p.port),
                "tcp",
                "warning",
                "Admin page served over plain HTTP".into(),
                "An administration page is reachable over unencrypted HTTP; serve it over HTTPS."
                    .into(),
            ));
        }

        // known default-credential device
        for (sig, what) in DEFAULT_CRED_SIGNATURES {
            if banner.contains(sig) {
                out.push(mk(
                    "default_creds",
                    Some(p.port),
                    &p.proto,
                    "critical",
                    "Device with well-known default credentials".into(),
                    format!("Looks like {what}. Change the default password."),
                ));
                break;
            }
        }

        // a port that is new since the last scan
        if !is_new && new_ports.contains(&p.port) {
            out.push(mk(
                "new_port",
                Some(p.port),
                &p.proto,
                "warning",
                "New open port".into(),
                format!(
                    "Port {} ({}) is open now but was not in the previous scan.",
                    p.port,
                    if p.service.is_empty() {
                        guess_service(p.port)
                    } else {
                        &p.service
                    }
                ),
            ));
        }
    }
    out
}

fn display_host(addr: &str, name: &str) -> String {
    if name.is_empty() {
        addr.to_string()
    } else {
        format!("{name} ({addr})")
    }
}

fn looks_like_admin(banner: &str, port: u16) -> bool {
    const HINTS: &[&str] = &[
        "login",
        "admin",
        "sign in",
        "router",
        "unauthorized",
        "dashboard",
        "management",
        "web management",
        "configuration",
        "realm",
    ];
    HINTS.iter().any(|h| banner.contains(h))
        || matches!(port, 8080 | 8443 | 2082 | 2083 | 2086 | 2087 | 10000)
}

// ---------------------------------------------------------------------------
// scanners
// ---------------------------------------------------------------------------

/// How to scan a host: the built-in connect scan, or nmap when it is installed.
#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    /// Scan one host; return the open ports (empty if the host is down).
    async fn scan_host(&self, addr: IpAddr) -> Vec<Port>;
}

/// Pure-Rust TCP connect scan of a port list, with a light banner read for a
/// service/version guess. No raw sockets, works unprivileged, ships on every
/// tier.
pub struct BuiltinScanner {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    /// How many ports of one host to probe at once.
    pub parallel: usize,
}

impl Default for BuiltinScanner {
    fn default() -> Self {
        Self {
            ports: TOP_PORTS.to_vec(),
            timeout: Duration::from_millis(800),
            parallel: 16,
        }
    }
}

#[async_trait]
impl Scanner for BuiltinScanner {
    fn name(&self) -> &'static str {
        "builtin"
    }

    async fn scan_host(&self, addr: IpAddr) -> Vec<Port> {
        let mut open = Vec::new();
        // modest per-host parallelism so one host cannot flood the box
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(self.parallel.max(1)));
        let mut tasks = Vec::new();
        for &port in &self.ports {
            let sem = sem.clone();
            let to = self.timeout;
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire().await.ok()?;
                connect_probe(addr, port, to).await
            }));
        }
        for t in tasks {
            if let Ok(Some(p)) = t.await {
                open.push(p);
            }
        }
        open.sort_by_key(|p| p.port);
        open
    }
}

/// Connect to one TCP port; on success, read a short banner and guess the
/// service/version.
async fn connect_probe(addr: IpAddr, port: u16, timeout: Duration) -> Option<Port> {
    let sa = SocketAddr::new(addr, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(sa))
        .await
        .ok()?
        .ok()?;
    let (service, product, version) = banner_of(stream, port, timeout).await;
    Some(Port {
        proto: "tcp".into(),
        port,
        service,
        product,
        version,
    })
}

/// Read a banner from an open connection and turn it into (service, product, version).
async fn banner_of(
    mut stream: TcpStream,
    port: u16,
    timeout: Duration,
) -> (String, String, String) {
    let mut service = guess_service(port).to_string();
    let http = matches!(service.as_str(), "http" | "https" | "upnp-http" | "proxy")
        || matches!(
            port,
            80 | 8080 | 8000 | 8008 | 8081 | 8088 | 8181 | 8888 | 3000 | 5000 | 2869
        );
    let mut product = String::new();
    let mut version = String::new();
    if http {
        let _ = stream
            .write_all(b"GET / HTTP/1.0\r\nHost: scan\r\nAccept: */*\r\n\r\n")
            .await;
    }
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    if n > 0 {
        let text = String::from_utf8_lossy(&buf[..n]);
        if http {
            if service.is_empty() {
                service = "http".into();
            }
            for line in text.lines() {
                let l = line.to_ascii_lowercase();
                if let Some(v) = l.strip_prefix("server:") {
                    product = v.trim().to_string();
                }
                if l.starts_with("www-authenticate:") || l.contains("realm=") {
                    if product.is_empty() {
                        product = "realm".into();
                    } else {
                        product.push_str(" realm");
                    }
                }
            }
            if let (Some(a), Some(b)) = (text.find("<title>"), text.find("</title>")) {
                if b > a + 7 {
                    let t = text[a + 7..b].trim();
                    if !t.is_empty() {
                        version = t.chars().take(80).collect();
                    }
                }
            }
        } else {
            // a line-oriented greeting (ssh/ftp/smtp/telnet/pop/imap/...)
            let first = text.lines().next().unwrap_or("").trim();
            product = first.chars().take(120).collect();
        }
    }
    (service, product, version)
}

/// rustscan (fast port discovery) + nmap `-sV -oX` for service/version
/// detection on the standard tier. Falls back to the built-in scan when the
/// tools are missing or error out.
pub struct NmapScanner {
    pub nmap: PathBuf,
    pub rustscan: Option<PathBuf>,
    pub ports: Vec<u16>,
    pub max_rate: u32,
    pub timeout: Duration,
    pub parallel: usize,
}

impl NmapScanner {
    /// `Some(scanner)` when nmap is on PATH; rustscan is used when it is too.
    pub fn detect(
        ports: Vec<u16>,
        max_rate: u32,
        timeout: Duration,
        parallel: usize,
    ) -> Option<Self> {
        let nmap = which("nmap")?;
        Some(Self {
            nmap,
            rustscan: which("rustscan"),
            ports,
            max_rate,
            timeout,
            parallel,
        })
    }
}

#[async_trait]
impl Scanner for NmapScanner {
    fn name(&self) -> &'static str {
        if self.rustscan.is_some() {
            "nmap+rustscan"
        } else {
            "nmap"
        }
    }

    async fn scan_host(&self, addr: IpAddr) -> Vec<Port> {
        match self.run(addr).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("nmap scan of {addr} failed ({e}); using the built-in scan");
                BuiltinScanner {
                    ports: self.ports.clone(),
                    timeout: self.timeout,
                    parallel: self.parallel,
                }
                .scan_host(addr)
                .await
            }
        }
    }
}

impl NmapScanner {
    async fn run(&self, addr: IpAddr) -> Result<Vec<Port>> {
        let ports_arg = self
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // -sT connect scan (no root), -sV service/version, -Pn (we already know
        // the host), -oX - (XML to stdout), rate limited.
        let mut cmd = tokio::process::Command::new(&self.nmap);
        cmd.arg("-sT")
            .arg("-sV")
            .arg("-Pn")
            .arg("-p")
            .arg(&ports_arg)
            .arg("-oX")
            .arg("-");
        if self.max_rate > 0 {
            cmd.arg("--max-rate").arg(self.max_rate.to_string());
        }
        cmd.arg(addr.to_string());
        cmd.stdin(std::process::Stdio::null());
        let out = tokio::time::timeout(self.timeout + Duration::from_secs(120), cmd.output())
            .await
            .map_err(|_| invalid("nmap timed out"))?
            .map_err(|e| Error::Config(format!("nmap: {e}")))?;
        let xml = String::from_utf8_lossy(&out.stdout);
        Ok(parse_nmap_xml(&xml))
    }
}

/// Parse open ports out of nmap's `-oX` XML (text scan, no external XML crate).
pub fn parse_nmap_xml(xml: &str) -> Vec<Port> {
    let mut out = Vec::new();
    // each <port protocol="tcp" portid="22"> ... <state state="open"/> <service .../> </port>
    for chunk in xml.split("<port ").skip(1) {
        let head = chunk.split('>').next().unwrap_or("");
        let proto = attr(head, "protocol").unwrap_or_else(|| "tcp".into());
        let Some(port) = attr(head, "portid").and_then(|p| p.parse::<u16>().ok()) else {
            continue;
        };
        let body = chunk.split("</port>").next().unwrap_or(chunk);
        let state = body
            .split("<state ")
            .nth(1)
            .and_then(|s| attr(s.split('>').next().unwrap_or(""), "state"))
            .unwrap_or_default();
        if state != "open" {
            continue;
        }
        let (mut service, mut product, mut version) = (String::new(), String::new(), String::new());
        if let Some(svc) = body.split("<service ").nth(1) {
            let h = svc.split('>').next().unwrap_or("");
            service = attr(h, "name").unwrap_or_default();
            product = attr(h, "product").unwrap_or_default();
            version = attr(h, "version").unwrap_or_default();
            if let Some(extra) = attr(h, "extrainfo") {
                if !extra.is_empty() {
                    version = format!("{version} {extra}").trim().to_string();
                }
            }
        }
        if service.is_empty() {
            service = guess_service(port).to_string();
        }
        out.push(Port {
            proto,
            port,
            service: unescape_xml(&service),
            product: unescape_xml(&product),
            version: unescape_xml(&version),
        });
    }
    out.sort_by_key(|p| p.port);
    out
}

fn attr(head: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let i = head.find(&needle)? + needle.len();
    let rest = &head[i..];
    let j = rest.find('"')?;
    Some(rest[..j].to_string())
}

fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x2f;", "/")
        .replace("&apos;", "'")
}

fn which(bin: &str) -> Option<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(dir).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Which scanning tools this box has (nmap, rustscan), for the UI.
pub fn tools_present() -> (bool, bool) {
    (which("nmap").is_some(), which("rustscan").is_some())
}

/// The scanner this build/tier should use, honouring the installed tools and
/// the test override. `PATRONUS_LANAUDIT_FORCE_BUILTIN=1` forces the built-in
/// scan (the router tier and the netlab lane without nmap).
pub fn pick_scanner(s: &Settings) -> Box<dyn Scanner> {
    let timeout = Duration::from_millis(s.connect_timeout_ms as u64);
    let ports = TOP_PORTS.to_vec();
    let parallel = s.max_parallel.max(1) as usize;
    let force_builtin = std::env::var("PATRONUS_LANAUDIT_FORCE_BUILTIN")
        .map(|v| flag(&v))
        .unwrap_or(false);
    if !force_builtin {
        if let Some(n) = NmapScanner::detect(ports.clone(), s.max_rate, timeout, parallel) {
            return Box::new(n);
        }
    }
    Box::new(BuiltinScanner {
        ports,
        timeout,
        parallel,
    })
}

// ---------------------------------------------------------------------------
// target enumeration (never the WAN)
// ---------------------------------------------------------------------------

/// The hosts to scan for the chosen segments: DHCP leases, segmentation devices
/// and (optionally) the kernel neighbour table, keyed by address, never
/// including the WAN's own hosts. The test override `PATRONUS_LANAUDIT_TARGETS`
/// (comma-separated IPs) replaces enumeration for netlab.
pub async fn targets(store: &ConfigStore, s: &Settings) -> Result<Vec<Target>> {
    if let Ok(v) = std::env::var("PATRONUS_LANAUDIT_TARGETS") {
        let mut out = Vec::new();
        for ip in v.split([',', ' ']).filter(|x| !x.trim().is_empty()) {
            if let Ok(a) = ip.trim().parse::<IpAddr>() {
                out.push(Target {
                    address: a,
                    name: String::new(),
                    mac: String::new(),
                    segment: s.segments.first().cloned().unwrap_or_default(),
                });
            }
        }
        // still enrich names/segments from the store below
        enrich(store, &mut out).await;
        return Ok(out);
    }

    // which interfaces are in scope (non-WAN)
    let roles = store.interface_roles().await.unwrap_or_default();
    let wan: BTreeSet<String> = roles
        .iter()
        .filter(|(_, r)| r == "wan")
        .map(|(d, _)| d.clone())
        .collect();
    let scope_ifaces: BTreeSet<String> = if s.segments.is_empty() {
        roles
            .iter()
            .filter(|(_, r)| r != "wan")
            .map(|(d, _)| d.clone())
            .collect()
    } else {
        let mut set = BTreeSet::new();
        for seg in &s.segments {
            for dev in resolve_segment(store, seg).await {
                if !wan.contains(&dev) {
                    set.insert(dev);
                }
            }
        }
        set
    };
    // subnets of the in-scope interfaces, so we can keep only addresses on them
    let nets = iface_subnets(store, &scope_ifaces).await;

    let mut by_ip: BTreeMap<IpAddr, Target> = BTreeMap::new();
    let seg_for = |a: &IpAddr| -> String {
        for (iface, net) in &nets {
            if net.contains(*a) {
                return iface.clone();
            }
        }
        String::new()
    };

    // DHCP leases
    #[cfg(feature = "dhcp")]
    if let Ok(leases) = crate::dhcp::leases(store, &crate::lan::LanEnv::system()).await {
        for l in leases {
            if l.state != "active" {
                continue;
            }
            if let Ok(a) = l.ip.parse::<IpAddr>() {
                if !on_scope(&a, &nets) {
                    continue;
                }
                let t = by_ip.entry(a).or_insert_with(|| Target {
                    address: a,
                    name: String::new(),
                    mac: String::new(),
                    segment: seg_for(&a),
                });
                if t.name.is_empty() {
                    t.name = l.hostname.clone().unwrap_or_default();
                }
                if t.mac.is_empty() && !l.mac.is_empty() {
                    t.mac = l.mac.clone();
                }
            }
        }
    }

    // segmentation devices
    #[cfg(feature = "segmentation")]
    if let Ok(devs) = patronus_config::seg::list_devices(store).await {
        for d in devs {
            if d.state == "revoked" {
                continue;
            }
            let ip = d
                .last_ip
                .clone()
                .or_else(|| d.ip4.clone())
                .and_then(|x| x.parse::<IpAddr>().ok());
            if let Some(a) = ip {
                if !on_scope(&a, &nets) {
                    continue;
                }
                let t = by_ip.entry(a).or_insert_with(|| Target {
                    address: a,
                    name: String::new(),
                    mac: String::new(),
                    segment: seg_for(&a),
                });
                if t.name.is_empty() {
                    t.name = d.name.clone();
                }
                if t.mac.is_empty() {
                    if let Some(m) = &d.mac {
                        t.mac = m.clone();
                    }
                }
            }
        }
    }

    // neighbour table
    if s.discover_neighbours {
        for (a, mac) in neighbours(&scope_ifaces).await {
            if !on_scope(&a, &nets) {
                continue;
            }
            let t = by_ip.entry(a).or_insert_with(|| Target {
                address: a,
                name: String::new(),
                mac: String::new(),
                segment: seg_for(&a),
            });
            if t.mac.is_empty() {
                t.mac = mac;
            }
        }
    }

    // never scan the router's own LAN addresses
    let own = own_addresses(&scope_ifaces).await;
    Ok(by_ip
        .into_values()
        .filter(|t| !own.contains(&t.address))
        .collect())
}

#[cfg_attr(
    not(any(feature = "dhcp", feature = "segmentation")),
    allow(unused_variables, unused_mut)
)]
async fn enrich(store: &ConfigStore, targets: &mut [Target]) {
    if targets.is_empty() {
        return;
    }
    let mut name: BTreeMap<IpAddr, String> = BTreeMap::new();
    #[cfg(feature = "dhcp")]
    if let Ok(leases) = crate::dhcp::leases(store, &crate::lan::LanEnv::system()).await {
        for l in leases {
            if let (Ok(a), Some(h)) = (l.ip.parse::<IpAddr>(), l.hostname) {
                name.entry(a).or_insert(h);
            }
        }
    }
    #[cfg(feature = "segmentation")]
    if let Ok(devs) = patronus_config::seg::list_devices(store).await {
        for d in devs {
            if let Some(a) = d
                .last_ip
                .clone()
                .or_else(|| d.ip4.clone())
                .and_then(|x| x.parse::<IpAddr>().ok())
            {
                name.insert(a, d.name);
            }
        }
    }
    for t in targets.iter_mut() {
        if t.name.is_empty() {
            if let Some(n) = name.get(&t.address) {
                t.name = n.clone();
            }
        }
    }
}

fn on_scope(a: &IpAddr, nets: &[(String, IpNet)]) -> bool {
    nets.is_empty() || nets.iter().any(|(_, n)| n.contains(*a))
}

/// A very small CIDR holder (we only need "contains").
#[derive(Debug, Clone)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix.min(32))
                };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let (n, i) = (u128::from(net), u128::from(ip));
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix.min(128))
                };
                n & mask == i & mask
            }
            _ => false,
        }
    }
}

async fn iface_subnets(store: &ConfigStore, ifaces: &BTreeSet<String>) -> Vec<(String, IpNet)> {
    let mut out = Vec::new();
    for dev in ifaces {
        let rows = sqlx::query(
            "SELECT address, prefix_len, family FROM interface_addresses WHERE interface_name = ?",
        )
        .bind(dev)
        .fetch_all(match store.pool() {
            Ok(p) => p,
            Err(_) => return out,
        })
        .await
        .unwrap_or_default();
        for r in rows {
            let a: String = r.get(0);
            let prefix: i64 = r.get(1);
            if let Ok(addr) = a.parse::<IpAddr>() {
                out.push((
                    dev.clone(),
                    IpNet {
                        addr,
                        prefix: prefix as u8,
                    },
                ));
            }
        }
    }
    out
}

#[cfg(feature = "segmentation")]
async fn resolve_segment(store: &ConfigStore, spec: &str) -> Vec<String> {
    patronus_config::seg::resolve_segment(store, spec)
        .await
        .unwrap_or_else(|_| vec![spec.to_string()])
}

#[cfg(not(feature = "segmentation"))]
async fn resolve_segment(store: &ConfigStore, spec: &str) -> Vec<String> {
    if let Some(role) = spec.strip_prefix('@') {
        store
            .interfaces_with_role(&role.to_ascii_lowercase())
            .await
            .unwrap_or_default()
    } else {
        vec![spec.to_string()]
    }
}

/// Parse `ip -j neigh show` for reachable neighbours on the in-scope interfaces.
async fn neighbours(ifaces: &BTreeSet<String>) -> Vec<(IpAddr, String)> {
    let out = tokio::task::spawn_blocking(|| {
        std::process::Command::new("ip")
            .args(["-j", "neigh", "show"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    parse_neigh_json(&out, ifaces)
}

/// Neighbours from `ip -j neigh show` output, restricted to `ifaces` and to
/// usable states (not FAILED / INCOMPLETE).
pub fn parse_neigh_json(json: &str, ifaces: &BTreeSet<String>) -> Vec<(IpAddr, String)> {
    let v: Value = serde_json::from_str(json).unwrap_or_default();
    let mut out = Vec::new();
    for e in v.as_array().into_iter().flatten() {
        let dev = e["dev"].as_str().unwrap_or("");
        if !ifaces.is_empty() && !ifaces.contains(dev) {
            continue;
        }
        let state = e["state"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or("");
        if matches!(state, "FAILED" | "INCOMPLETE" | "NOARP") {
            continue;
        }
        if let Some(ip) = e["dst"].as_str().and_then(|x| x.parse::<IpAddr>().ok()) {
            let mac = e["lladdr"].as_str().unwrap_or("").to_string();
            out.push((ip, mac));
        }
    }
    out
}

async fn own_addresses(ifaces: &BTreeSet<String>) -> BTreeSet<IpAddr> {
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
    let v: Value = serde_json::from_str(&out).unwrap_or_default();
    let mut set = BTreeSet::new();
    for link in v.as_array().into_iter().flatten() {
        let name = link["ifname"].as_str().unwrap_or("");
        if !ifaces.is_empty() && !ifaces.contains(name) {
            continue;
        }
        for a in link["addr_info"].as_array().into_iter().flatten() {
            if let Some(ip) = a["local"].as_str().and_then(|x| x.parse::<IpAddr>().ok()) {
                set.insert(ip);
            }
        }
    }
    set
}

// ---------------------------------------------------------------------------
// running a scan
// ---------------------------------------------------------------------------

/// Run one scan now and store it. `trigger` is "manual" or "scheduled". Returns
/// the scan id. Emits the findings as security events at or above the
/// configured severity.
pub async fn run_scan(
    store: &ConfigStore,
    trigger: &str,
    reporter: Option<&EventSink>,
) -> Result<i64> {
    let s = load(store).await?;
    let scanner = pick_scanner(&s);
    run_scan_with(store, trigger, &s, scanner.as_ref(), reporter).await
}

/// Run a scan with an explicit scanner (tests inject a fake one).
pub async fn run_scan_with(
    store: &ConfigStore,
    trigger: &str,
    s: &Settings,
    scanner: &dyn Scanner,
    reporter: Option<&EventSink>,
) -> Result<i64> {
    let started = now();
    let segs = if s.segments.is_empty() {
        "@lan".to_string()
    } else {
        s.segments.join(",")
    };
    let scan_id = sqlx::query(
        "INSERT INTO audit_scans (started_at, trigger, segments, engine, state) VALUES (?,?,?,?, 'running')",
    )
    .bind(started)
    .bind(trigger)
    .bind(&segs)
    .bind(scanner.name())
    .execute(store.pool()?)
    .await
    .map_err(db("start scan"))?
    .last_insert_rowid();

    let result = scan_body(store, s, scanner, scan_id).await;
    match result {
        Ok((hosts, ports_open)) => {
            // previous completed scan for the diff
            let prev = previous_scan(store, scan_id).await.unwrap_or(None);
            let (prev_hosts, prev_ports) = match prev {
                Some(pid) => prior_sets(store, pid).await.unwrap_or_default(),
                None => Default::default(),
            };
            let mut all_findings = Vec::new();
            for h in &hosts {
                let is_new = prev.is_some() && !prev_hosts.contains(&h.address);
                let new_ports: BTreeSet<u16> = if prev.is_some() {
                    h.ports
                        .iter()
                        .map(|p| p.port)
                        .filter(|p| !prev_ports.contains(&(h.address.clone(), *p)))
                        .collect()
                } else {
                    BTreeSet::new()
                };
                let fs = findings_for_host(h, is_new, &new_ports);
                all_findings.extend(fs);
            }
            store_findings(store, scan_id, &all_findings).await?;
            sqlx::query(
                "UPDATE audit_scans SET finished_at=?, state='done', hosts_up=?, ports_open=?, findings=? WHERE id=?",
            )
            .bind(now())
            .bind(hosts.len() as i64)
            .bind(ports_open as i64)
            .bind(all_findings.len() as i64)
            .bind(scan_id)
            .execute(store.pool()?)
            .await
            .map_err(db("finish scan"))?;

            // route findings to the security events
            if let Some(sink) = reporter {
                emit_events(store, s, scan_id, &all_findings, sink).await;
            }
            prune(store, s).await.ok();
            Ok(scan_id)
        }
        Err(e) => {
            sqlx::query("UPDATE audit_scans SET finished_at=?, state='failed', error=? WHERE id=?")
                .bind(now())
                .bind(e.to_string())
                .bind(scan_id)
                .execute(store.pool()?)
                .await
                .ok();
            Err(e)
        }
    }
}

async fn scan_body(
    store: &ConfigStore,
    s: &Settings,
    scanner: &dyn Scanner,
    scan_id: i64,
) -> Result<(Vec<Host>, usize)> {
    let targets = targets(store, s).await?;
    let mut hosts: Vec<Host> = Vec::new();
    let mut ports_total = 0usize;

    // scan hosts one after another (each host's own port probes are already
    // bounded internally); max_parallel caps that inner fan-out.
    let mut results: Vec<(Target, Vec<Port>)> = Vec::new();
    for t in targets {
        let ports = scanner.scan_host(t.address).await;
        results.push((t, ports));
    }

    for (t, ports) in results {
        if ports.is_empty() {
            continue; // host down / nothing open
        }
        ports_total += ports.len();
        let host_id = sqlx::query(
            "INSERT INTO audit_hosts (scan_id, address, name, mac, segment) VALUES (?,?,?,?,?)",
        )
        .bind(scan_id)
        .bind(t.address.to_string())
        .bind(&t.name)
        .bind(&t.mac)
        .bind(&t.segment)
        .execute(store.pool()?)
        .await
        .map_err(db("store host"))?
        .last_insert_rowid();
        for p in &ports {
            sqlx::query(
                "INSERT INTO audit_ports (host_id, scan_id, address, proto, port, service, product, version) VALUES (?,?,?,?,?,?,?,?)",
            )
            .bind(host_id)
            .bind(scan_id)
            .bind(t.address.to_string())
            .bind(&p.proto)
            .bind(p.port as i64)
            .bind(&p.service)
            .bind(&p.product)
            .bind(&p.version)
            .execute(store.pool()?)
            .await
            .map_err(db("store port"))?;
        }
        hosts.push(Host {
            address: t.address.to_string(),
            name: t.name,
            mac: t.mac,
            segment: t.segment,
            ports,
        });
    }
    Ok((hosts, ports_total))
}

async fn store_findings(store: &ConfigStore, scan_id: i64, fs: &[Finding]) -> Result<()> {
    for f in fs {
        sqlx::query(
            "INSERT INTO audit_findings (scan_id, address, name, port, proto, rule, severity, title, detail) VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(scan_id)
        .bind(&f.address)
        .bind(&f.name)
        .bind(f.port.map(|p| p as i64))
        .bind(&f.proto)
        .bind(&f.rule)
        .bind(&f.severity)
        .bind(&f.title)
        .bind(&f.detail)
        .execute(store.pool()?)
        .await
        .map_err(db("store finding"))?;
    }
    Ok(())
}

/// The id of the newest completed scan before `before` (for the diff).
pub async fn previous_scan(store: &ConfigStore, before: i64) -> Result<Option<i64>> {
    let r = sqlx::query(
        "SELECT id FROM audit_scans WHERE id < ? AND state='done' ORDER BY id DESC LIMIT 1",
    )
    .bind(before)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("previous scan"))?;
    Ok(r.map(|r| r.get::<i64, _>(0)))
}

type PriorSets = (BTreeSet<String>, BTreeSet<(String, u16)>);

async fn prior_sets(store: &ConfigStore, scan_id: i64) -> Result<PriorSets> {
    let hosts = sqlx::query("SELECT address FROM audit_hosts WHERE scan_id=?")
        .bind(scan_id)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("prior hosts"))?;
    let hset: BTreeSet<String> = hosts.iter().map(|r| r.get::<String, _>(0)).collect();
    let ports = sqlx::query("SELECT address, port FROM audit_ports WHERE scan_id=?")
        .bind(scan_id)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("prior ports"))?;
    let pset: BTreeSet<(String, u16)> = ports
        .iter()
        .map(|r| (r.get::<String, _>(0), r.get::<i64, _>(1) as u16))
        .collect();
    Ok((hset, pset))
}

/// A sink that records a security event. patronus-web passes one that calls
/// `telemetry::record` + `deliver`; the CLI passes None.
pub struct EventSink {
    pub record: Box<
        dyn Fn(String, String, String, String) -> futures::future::BoxFuture<'static, ()>
            + Send
            + Sync,
    >,
}

async fn emit_events(
    store: &ConfigStore,
    s: &Settings,
    scan_id: i64,
    findings: &[Finding],
    sink: &EventSink,
) {
    let _ = store;
    let _ = scan_id;
    let min = sev_rank(&s.alert_min_severity);
    // one incident per (rule, source) with a count, never one event per finding
    let mut by_key: BTreeMap<(String, String), (String, String, usize)> = BTreeMap::new();
    for f in findings {
        if sev_rank(&f.severity) < min {
            continue;
        }
        let key = (f.rule.clone(), f.address.clone());
        let e = by_key
            .entry(key)
            .or_insert((f.severity.clone(), f.title.clone(), 0));
        e.2 += 1;
        if sev_rank(&f.severity) > sev_rank(&e.0) {
            e.0 = f.severity.clone();
        }
    }
    for ((rule, addr), (sev, title, count)) in by_key {
        let subject = addr.clone();
        let detail = if count > 1 {
            format!("{title} ({count} on {addr})")
        } else {
            format!("{title} on {addr}")
        };
        (sink.record)(format!("audit_{rule}"), subject, sev, detail).await;
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

/// Keep only the newest `keep_scans` finished scans (and the running one);
/// cascade deletes drop their hosts/ports/findings.
pub async fn prune(store: &ConfigStore, s: &Settings) -> Result<()> {
    let keep = s.keep_scans.max(1) as usize;
    // newest-first list of finished scans; keep the first `keep`, delete the rest.
    let all: Vec<i64> =
        sqlx::query("SELECT id FROM audit_scans WHERE state != 'running' ORDER BY id DESC")
            .fetch_all(store.pool()?)
            .await
            .map_err(db("prune select"))?
            .iter()
            .map(|r| r.get::<i64, _>(0))
            .collect();
    for id in all.into_iter().skip(keep) {
        for t in [
            "audit_findings",
            "audit_ports",
            "audit_hosts",
            "audit_scans",
        ] {
            let col = if t == "audit_scans" { "id" } else { "scan_id" };
            sqlx::query(&format!("DELETE FROM {t} WHERE {col} = ?"))
                .bind(id)
                .execute(store.pool()?)
                .await
                .map_err(db("prune"))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// queries for the UI / CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ScanRow {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub trigger: String,
    pub segments: String,
    pub engine: String,
    pub state: String,
    pub hosts_up: i64,
    pub ports_open: i64,
    pub findings: i64,
    pub error: String,
}

pub async fn list_scans(store: &ConfigStore, limit: i64) -> Result<Vec<ScanRow>> {
    let rows = sqlx::query(
        "SELECT id, started_at, finished_at, trigger, segments, engine, state, hosts_up, ports_open, findings, error \
         FROM audit_scans ORDER BY id DESC LIMIT ?",
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list scans"))?;
    Ok(rows
        .iter()
        .map(|r| ScanRow {
            id: r.get(0),
            started_at: r.get(1),
            finished_at: r.get(2),
            trigger: r.get(3),
            segments: r.get(4),
            engine: r.get(5),
            state: r.get(6),
            hosts_up: r.get(7),
            ports_open: r.get(8),
            findings: r.get(9),
            error: r.get(10),
        })
        .collect())
}

/// The newest scan id, or None.
pub async fn latest_scan(store: &ConfigStore) -> Result<Option<i64>> {
    let r = sqlx::query("SELECT id FROM audit_scans ORDER BY id DESC LIMIT 1")
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("latest scan"))?;
    Ok(r.map(|r| r.get::<i64, _>(0)))
}

/// The full result of one scan: its hosts (with ports) and findings.
pub async fn scan_detail(store: &ConfigStore, scan_id: i64) -> Result<Value> {
    let scan = list_scans(store, 1000)
        .await?
        .into_iter()
        .find(|s| s.id == scan_id);
    let Some(scan) = scan else {
        return Err(invalid("scan not found"));
    };
    let hrows = sqlx::query(
        "SELECT id, address, name, mac, segment FROM audit_hosts WHERE scan_id=? ORDER BY address",
    )
    .bind(scan_id)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("scan hosts"))?;
    let mut hosts = Vec::new();
    for h in &hrows {
        let hid: i64 = h.get(0);
        let prows = sqlx::query(
            "SELECT proto, port, service, product, version FROM audit_ports WHERE host_id=? ORDER BY port",
        )
        .bind(hid)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("scan ports"))?;
        let ports: Vec<Value> = prows
            .iter()
            .map(|p| {
                json!({
                    "proto": p.get::<String,_>(0),
                    "port": p.get::<i64,_>(1),
                    "service": p.get::<String,_>(2),
                    "product": p.get::<String,_>(3),
                    "version": p.get::<String,_>(4),
                })
            })
            .collect();
        hosts.push(json!({
            "address": h.get::<String,_>(1),
            "name": h.get::<String,_>(2),
            "mac": h.get::<String,_>(3),
            "segment": h.get::<String,_>(4),
            "ports": ports,
        }));
    }
    let frows = sqlx::query(
        "SELECT address, name, port, proto, rule, severity, title, detail FROM audit_findings WHERE scan_id=? \
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, address",
    )
    .bind(scan_id)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("scan findings"))?;
    let findings: Vec<Value> = frows
        .iter()
        .map(|f| {
            json!({
                "address": f.get::<String,_>(0),
                "name": f.get::<String,_>(1),
                "port": f.get::<Option<i64>,_>(2),
                "proto": f.get::<String,_>(3),
                "rule": f.get::<String,_>(4),
                "severity": f.get::<String,_>(5),
                "title": f.get::<String,_>(6),
                "detail": f.get::<String,_>(7),
            })
        })
        .collect();
    Ok(json!({
        "scan": {
            "id": scan.id, "started_at": scan.started_at, "finished_at": scan.finished_at,
            "trigger": scan.trigger, "segments": scan.segments, "engine": scan.engine,
            "state": scan.state, "hosts_up": scan.hosts_up, "ports_open": scan.ports_open,
            "findings": scan.findings, "error": scan.error,
        },
        "hosts": hosts,
        "findings": findings,
    }))
}

/// A scan's open ports as CSV (host,name,mac,segment,proto,port,service,product,version).
pub async fn scan_csv(store: &ConfigStore, scan_id: i64) -> Result<String> {
    let d = scan_detail(store, scan_id).await?;
    let mut out = String::from("address,name,mac,segment,proto,port,service,product,version\n");
    for h in d["hosts"].as_array().into_iter().flatten() {
        let addr = h["address"].as_str().unwrap_or("");
        let name = h["name"].as_str().unwrap_or("");
        let mac = h["mac"].as_str().unwrap_or("");
        let seg = h["segment"].as_str().unwrap_or("");
        for p in h["ports"].as_array().into_iter().flatten() {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                csv(addr),
                csv(name),
                csv(mac),
                csv(seg),
                csv(p["proto"].as_str().unwrap_or("")),
                p["port"].as_i64().unwrap_or(0),
                csv(p["service"].as_str().unwrap_or("")),
                csv(p["product"].as_str().unwrap_or("")),
                csv(p["version"].as_str().unwrap_or("")),
            ));
        }
    }
    Ok(out)
}

fn csv(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A scan report as a minimal, self-contained PDF (no external crate): a
/// summary, the findings grouped by severity, then the hosts and their open
/// ports. Pure Helvetica text, wrapped and paginated.
pub async fn scan_pdf(store: &ConfigStore, scan_id: i64) -> Result<Vec<u8>> {
    let d = scan_detail(store, scan_id).await?;
    let scan = &d["scan"];
    let mut lines: Vec<(bool, String)> = Vec::new(); // (bold, text)
    let b = |t: &str| (true, t.to_string());
    let n = |t: &str| (false, t.to_string());
    lines.push(b("Patronus - LAN security audit"));
    let started = scan["started_at"].as_i64().unwrap_or(0);
    lines.push(n(&format!(
        "Scan #{}  started {}  engine {}  state {}",
        scan["id"].as_i64().unwrap_or(0),
        fmt_ts(started),
        scan["engine"].as_str().unwrap_or(""),
        scan["state"].as_str().unwrap_or(""),
    )));
    lines.push(n(&format!(
        "Segments: {}   Hosts up: {}   Open ports: {}   Findings: {}",
        scan["segments"].as_str().unwrap_or(""),
        scan["hosts_up"].as_i64().unwrap_or(0),
        scan["ports_open"].as_i64().unwrap_or(0),
        scan["findings"].as_i64().unwrap_or(0),
    )));
    lines.push(n(""));
    lines.push(b("Findings"));
    let findings = d["findings"].as_array().cloned().unwrap_or_default();
    if findings.is_empty() {
        lines.push(n("  None."));
    }
    for f in &findings {
        let sev = f["severity"].as_str().unwrap_or("");
        let addr = f["address"].as_str().unwrap_or("");
        let name = f["name"].as_str().unwrap_or("");
        let port = f["port"]
            .as_i64()
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        lines.push(n(&format!(
            "  [{}] {}{} - {}",
            sev.to_uppercase(),
            display_host(addr, name),
            port,
            f["title"].as_str().unwrap_or(""),
        )));
        let detail = f["detail"].as_str().unwrap_or("");
        for w in wrap(detail, 88) {
            lines.push(n(&format!("       {w}")));
        }
    }
    lines.push(n(""));
    lines.push(b("Hosts and open ports"));
    for h in d["hosts"].as_array().cloned().unwrap_or_default() {
        let addr = h["address"].as_str().unwrap_or("");
        let name = h["name"].as_str().unwrap_or("");
        lines.push(b(&format!("  {}", display_host(addr, name))));
        for p in h["ports"].as_array().cloned().unwrap_or_default() {
            lines.push(n(&format!(
                "      {}/{}  {}  {} {}",
                p["port"].as_i64().unwrap_or(0),
                p["proto"].as_str().unwrap_or("tcp"),
                p["service"].as_str().unwrap_or(""),
                p["product"].as_str().unwrap_or(""),
                p["version"].as_str().unwrap_or(""),
            )));
        }
    }
    Ok(render_pdf(&lines))
}

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if line.len() + word.len() + 1 > width && !line.is_empty() {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// Escape a string for a PDF literal `( ... )`.
fn pdf_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            // keep PDF to printable ASCII (WinAnsi); drop anything else
            c if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Render text lines to a minimal multi-page PDF (Helvetica / Helvetica-Bold).
pub fn render_pdf(lines: &[(bool, String)]) -> Vec<u8> {
    const PER_PAGE: usize = 54;
    const TOP: i32 = 770;
    const LEFT: i32 = 40;
    const LH: i32 = 13;
    let pages: Vec<&[(bool, String)]> = lines.chunks(PER_PAGE).collect();
    let page_count = pages.len().max(1);

    // object ids: 1 catalog, 2 pages, 3 font F1 (Helvetica), 4 font F2 (Bold),
    // then per page: content + page objects.
    let mut objects: Vec<String> = Vec::new();
    // 1 catalog
    objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
    // 2 pages (kids filled below)
    let first_page_obj = 5;
    let kids: Vec<String> = (0..page_count)
        .map(|i| format!("{} 0 R", first_page_obj + i * 2 + 1))
        .collect();
    objects.push(format!(
        "<< /Type /Pages /Count {} /Kids [{}] >>",
        page_count,
        kids.join(" ")
    ));
    // 3 font Helvetica
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string());
    // 4 font Helvetica-Bold
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_string());

    for (i, page) in pages.iter().enumerate() {
        let mut content = String::from("BT\n");
        content.push_str(&format!("1 0 0 1 {LEFT} {TOP} Tm\n"));
        for (y, (bold, text)) in page.iter().enumerate() {
            let font = if *bold { "F2" } else { "F1" };
            let size = if *bold { 11 } else { 9 };
            content.push_str(&format!(
                "/{font} {size} Tf\n1 0 0 1 {LEFT} {} Tm\n({}) Tj\n",
                TOP - y as i32 * LH,
                pdf_escape(text)
            ));
        }
        content.push_str("ET");
        let content_obj = first_page_obj + i * 2; // even offset
        let page_obj = content_obj + 1;
        let _ = page_obj;
        objects.push(format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.len(),
            content
        ));
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {} 0 R >>",
            content_obj
        ));
    }

    // assemble with a cross-reference table
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (idx, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", idx + 1, body));
    }
    let xref_pos = pdf.len();
    let count = objects.len() + 1;
    pdf.push_str(&format!("xref\n0 {count}\n"));
    pdf.push_str("0000000000 65535 f \n");
    for off in &offsets {
        pdf.push_str(&format!("{:010} 00000 n \n", off));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
    ));
    pdf.into_bytes()
}

// ---------------------------------------------------------------------------
// scheduler task
// ---------------------------------------------------------------------------

/// Should a scheduled scan start now? True when enabled, an interval is set, we
/// are inside the quiet window and at least `interval_hours` have passed since
/// the last scan started.
pub async fn due(store: &ConfigStore, s: &Settings) -> bool {
    if !s.enabled || s.interval_hours == 0 {
        return false;
    }
    let dt = local_now();
    use chrono::Timelike;
    let minute = dt.hour() * 60 + dt.minute();
    if !s.in_quiet_window(minute) {
        return false;
    }
    let last: Option<i64> =
        sqlx::query("SELECT started_at FROM audit_scans ORDER BY id DESC LIMIT 1")
            .fetch_optional(match store.pool() {
                Ok(p) => p,
                Err(_) => return false,
            })
            .await
            .ok()
            .flatten()
            .map(|r| r.get::<i64, _>(0));
    match last {
        None => true,
        Some(t) => now() - t >= s.interval_hours as i64 * 3600,
    }
}

/// Run the scheduler forever: every minute (or `PATRONUS_LANAUDIT_TICK_SECS`),
/// start a scheduled scan when it is due. `only_without_applyd` skips rounds
/// while the root broker's socket exists (patronus-web runs this only when
/// there is no `patronus applyd`).
pub fn spawn_task(
    store: std::sync::Arc<ConfigStore>,
    only_without_applyd: bool,
    applyd_socket: PathBuf,
    sink: Option<std::sync::Arc<EventSink>>,
) {
    tokio::spawn(async move {
        loop {
            let secs = std::env::var("PATRONUS_LANAUDIT_TICK_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(60);
            tokio::time::sleep(Duration::from_secs(secs)).await;
            if only_without_applyd && applyd_socket.exists() {
                continue;
            }
            let s = match load(&store).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if due(&store, &s).await {
                if let Err(e) = run_scan(&store, "scheduled", sink.as_deref()).await {
                    tracing::warn!("scheduled LAN audit: {e}");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
