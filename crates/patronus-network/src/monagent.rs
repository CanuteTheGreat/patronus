//! Optional monitoring agents (USE=zabbix-agent, USE=telegraf) next to the
//! built-in Prometheus `/metrics` endpoint.
//!
//! - `metrics`: the typed settings of the web UI's own `/metrics` endpoint
//!   (switch, allowed source network, scrape token). The web crate enforces
//!   them in its authentication gate; there is no daemon behind this page.
//! - `zabbix`: Zabbix agent 2 (7.x), a passive/active agent that answers on
//!   the LAN interface only. Remote commands are fixed OFF (`DenyKey=system.run[*]`,
//!   not configurable). Patronus' own items come from `patronus zabbix-item`,
//!   which only reads the metrics snapshot (see below).
//! - `telegraf`: Telegraf with one output (Prometheus client on the LAN,
//!   InfluxDB v2 or v1) and a typed set of inputs.
//!
//! Both daemons run through the supervisor (`patronus-daemon@<instance>`,
//! OpenRC and systemd) under their package's unprivileged account (through
//! `setpriv`) when it exists. Their generated files live in
//! `/var/lib/patronus-monagent/<agent>/` (not under `/var/lib/patronus`, whose
//! mode keeps every other account out), owned `root:<agent group>` mode 0750;
//! secrets (Zabbix PSK, Telegraf token) are only ever written there and never
//! returned by the API.
//!
//! The web UI refreshes `<base>/metrics.prom` (the same text as `/metrics`)
//! every 30 s while an agent is enabled, so neither agent needs a login: the
//! Zabbix helper and Telegraf's `inputs.file` read that file.

use crate::supervise::{NetPaths, DEFAULT_STATE_DIR};
use crate::svc::{Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
use crate::lan::{self, invalid, LanEnv};
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
use crate::supervise::{which, write_atomic, Supervisor};
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
use crate::svc::{self, Coll, SECRET_MASK};
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
use patronus_config::applier::{Applier, ApplyReport, Phase};

pub const DEFAULT_BASE: &str = "/var/lib/patronus-monagent";
/// File name of the metrics snapshot inside the base directory.
pub const SNAPSHOT: &str = "metrics.prom";
/// A snapshot older than this is not trusted by the Zabbix helper.
pub const SNAPSHOT_MAX_AGE_SECS: u64 = 180;
#[cfg(feature = "zabbix-agent")]
pub const ZABBIX_INSTANCE: &str = "zabbix-agent2";
#[cfg(feature = "telegraf")]
pub const TELEGRAF_INSTANCE: &str = "telegraf";
#[cfg(feature = "zabbix-agent")]
pub const ZABBIX_USER: &str = "zabbix";
#[cfg(feature = "telegraf")]
pub const TELEGRAF_USER: &str = "telegraf";

/// Directory of the generated agent files and the metrics snapshot.
/// `PATRONUS_MONAGENT_DIR` overrides it; with a non-default net dir (tests,
/// netlab) it lives beside it.
pub fn base_dir(paths: &NetPaths) -> PathBuf {
    if let Some(d) = std::env::var_os("PATRONUS_MONAGENT_DIR") {
        return PathBuf::from(d);
    }
    if paths.state_dir == Path::new(DEFAULT_STATE_DIR) {
        PathBuf::from(DEFAULT_BASE)
    } else {
        paths.state_dir.join("monagent")
    }
}

// ---------------------------------------------------------------------------
// the web UI's /metrics endpoint
// ---------------------------------------------------------------------------

static METRICS_FIELDS: [Field; 3] = [
    Field::new("enabled", "Metrics endpoint", Kind::Bool)
        .def("1")
        .help("serve /metrics (Prometheus text format); off answers 404"),
    Field::new("allowed_source", "Allowed source network", Kind::Cidr).help(
        "only this network may read /metrics, for example 192.168.1.0/24; empty = any source",
    ),
    Field::new("token", "Scrape token", Kind::Secret).help(
        "a scraper sends it as 'Authorization: Bearer <token>' instead of logging in; empty = \
         sign-in or API key required",
    ),
];

static METRICS_SPEC: Spec = Spec {
    slug: "metrics",
    title: "Prometheus metrics",
    blurb: "The /metrics endpoint of this web UI (Prometheus text format: gateways, firewall, \
            connections, services). Choose who may read it; without a scrape token a scraper \
            needs a Patronus API key.",
    applier: "",
    fields: &METRICS_FIELDS,
    colls: &[],
    actions: &[],
};

pub struct MetricsSvc;

#[async_trait]
impl Svc for MetricsSvc {
    fn spec(&self) -> &'static Spec {
        &METRICS_SPEC
    }
}

/// What the web gate needs to know about `/metrics`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsPolicy {
    pub enabled: bool,
    pub allowed: Option<ipnetwork::IpNetwork>,
    pub token: Option<String>,
}

pub async fn metrics_policy(store: &ConfigStore) -> Result<MetricsPolicy> {
    let s = Settings::load(store, &METRICS_SPEC).await?;
    Ok(MetricsPolicy {
        enabled: s.b("enabled"),
        allowed: s.s("allowed_source").parse().ok(),
        token: Some(s.s("token")).filter(|t| !t.is_empty()),
    })
}

impl MetricsPolicy {
    /// May `peer` read `/metrics` at all (switch + source network)?
    pub fn allows_source(&self, peer: Option<IpAddr>) -> bool {
        match (&self.allowed, peer) {
            (None, _) => true,
            (Some(net), Some(ip)) => net.contains(unmap(ip)),
            (Some(_), None) => false,
        }
    }

    /// Is `header` (an `Authorization` value) the scrape token?
    pub fn token_matches(&self, header: Option<&str>) -> bool {
        let (Some(t), Some(h)) = (&self.token, header) else {
            return false;
        };
        let Some(got) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) else {
            return false;
        };
        let (a, b) = (t.as_bytes(), got.trim().as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// A TOML basic string for `s`: quotes, backslashes and every control
/// character are escaped, so no value can end the string or start a new key.
pub fn toml_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                o.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A value for a `Key=Value` line config (Zabbix): control characters
/// (so, line breaks) are dropped, the value stays on its one line.
pub fn conf_val(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn user_exists(name: &str) -> bool {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .is_some()
}

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn group_gid(name: &str) -> Option<u32> {
    nix::unistd::Group::from_name(name)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

/// The system host name as a `Token` (what Zabbix and a monitoring server
/// should call this box), `patronus` when it cannot be read.
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
pub fn system_hostname() -> String {
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    token_or(&h, "patronus")
}

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn token_or(s: &str, fallback: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect();
    if t.is_empty() {
        fallback.to_string()
    } else {
        t
    }
}

/// Create `dir` with `mode`; owner root, group `group` when it exists
/// (best effort: an unprivileged test run keeps its own owner).
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn ensure_dir(dir: &Path, mode: u32, owner: Option<&str>, group: Option<&str>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Network(format!("create {}: {e}", dir.display())))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::Network(format!("chmod {}: {e}", dir.display())))?;
    chown_names(dir, owner, group);
    Ok(())
}

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn chown_names(p: &Path, owner: Option<&str>, group: Option<&str>) {
    let uid = owner.and_then(|o| {
        nix::unistd::User::from_name(o)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    });
    let gid = group.and_then(group_gid);
    if uid.is_some() || gid.is_some() {
        let _ = std::os::unix::fs::chown(p, uid, gid);
    }
}

/// Write a generated file group-readable by the agent's account.
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn put_file(path: &Path, content: &str, mode: u32, group: Option<&str>) -> Result<()> {
    write_atomic(path, content, mode)?;
    chown_names(path, Some("root"), group);
    Ok(())
}

/// Command line that runs `argv` as `user` (no extra capabilities unless
/// `caps` names some, for example `net_admin`); `argv` unchanged when the
/// account or `setpriv` does not exist.
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn privileged_argv(user: &str, caps: &[&str], argv: Vec<String>) -> (Vec<String>, bool) {
    let Some(sp) = which("setpriv") else {
        return (argv, false);
    };
    if !user_exists(user) {
        return (argv, false);
    }
    let mut v = vec![
        sp.to_string_lossy().into_owned(),
        format!("--reuid={user}"),
        format!("--regid={user}"),
        "--init-groups".into(),
    ];
    if !caps.is_empty() {
        let c = caps
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(",");
        v.push(format!("--inh-caps={c}"));
        v.push(format!("--ambient-caps={c}"));
    }
    v.push("--".into());
    v.extend(argv);
    (v, true)
}

/// First IPv4 (else non-link-local IPv6) address on the devices `spec`
/// resolves to: what an agent listens on.
#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
async fn listen_addr(store: &ConfigStore, env: &LanEnv, spec: &str) -> Result<(String, IpAddr)> {
    let devs = lan::resolve_iface(store, spec).await?;
    if devs.is_empty() {
        return Err(invalid(format!(
            "listen interface {spec} is not assigned to any device"
        )));
    }
    let addrs = env.addrs()?;
    for want_v4 in [true, false] {
        for d in &devs {
            for a in addrs.iter().filter(|a| &a.ifname == d) {
                let ok = match a.addr {
                    IpAddr::V4(_) => want_v4,
                    IpAddr::V6(v6) => {
                        !want_v4 && (v6.segments()[0] & 0xffc0) != 0xfe80 && !v6.is_loopback()
                    }
                };
                if ok {
                    return Ok((d.clone(), a.addr));
                }
            }
        }
    }
    Err(invalid(format!(
        "listen interface {spec} ({}) has no address yet",
        devs.join(", ")
    )))
}

#[cfg(any(feature = "zabbix-agent", feature = "telegraf"))]
fn fmt_listen(ip: IpAddr, port: i64) -> String {
    match ip {
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    }
}

// ---------------------------------------------------------------------------
// metrics snapshot: Prometheus text -> items (Zabbix helper, tests)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// Parse Prometheus text exposition (`name{l="v"} 1.5`); comments, blank and
/// malformed lines are skipped.
pub fn parse_prom(text: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (head, rest) = match line.find('{') {
            Some(b) => {
                let Some(e) = find_label_end(line, b) else {
                    continue;
                };
                (&line[..=e], line[e + 1..].trim())
            }
            None => match line.split_once(char::is_whitespace) {
                Some((h, r)) => (h, r.trim()),
                None => continue,
            },
        };
        let Some(v) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
        else {
            continue;
        };
        let (name, labels) = match head.split_once('{') {
            Some((n, l)) => (n, parse_labels(l.trim_end_matches('}'))),
            None => (head, BTreeMap::new()),
        };
        out.push(Sample {
            name: name.to_string(),
            labels,
            value: v,
        });
    }
    out
}

/// Index of the `}` closing the label set that opens at `open`.
fn find_label_end(s: &str, open: usize) -> Option<usize> {
    let mut in_q = false;
    let mut esc = false;
    for (i, c) in s.char_indices().skip_while(|(i, _)| *i < open) {
        if esc {
            esc = false;
        } else if c == '\\' && in_q {
            esc = true;
        } else if c == '"' {
            in_q = !in_q;
        } else if c == '}' && !in_q {
            return Some(i);
        }
    }
    None
}

fn parse_labels(s: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut chars = s.chars().peekable();
    loop {
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            chars.next();
            if c != ',' && !c.is_whitespace() {
                key.push(c);
            }
        }
        if chars.next() != Some('=') || chars.next() != Some('"') {
            break;
        }
        let mut val = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('n') => val.push('\n'),
                    Some(o) => val.push(o),
                    None => break,
                },
                '"' => break,
                c => val.push(c),
            }
        }
        if !key.is_empty() {
            m.insert(key, val);
        }
    }
    m
}

/// Keys `patronus zabbix-item` answers (also the list shown in the docs).
pub const ZABBIX_ITEMS: &[&str] = &[
    "host.uptime",
    "host.load1",
    "host.load5",
    "host.load15",
    "host.mem.used_pct",
    "host.disk.used_pct",
    "firewall.rules",
    "conntrack.entries",
    "conntrack.max",
    "dhcp.leases",
    "config.revision",
    "ha.master",
    "gateway.discovery",
    "gateway.up",
    "gateway.rtt_ms",
    "gateway.loss_pct",
    "service.up",
];

/// Answer one Zabbix item from the metrics snapshot `prom` (and
/// `/proc/loadavg` content `loadavg` for the CPU load keys). `arg` is the
/// gateway or service name. Errors name what is missing.
pub fn zabbix_item(key: &str, arg: &str, prom: &str, loadavg: &str) -> Result<String> {
    let samples = parse_prom(prom);
    let one = |name: &str| {
        samples
            .iter()
            .find(|s| s.name == name && s.labels.is_empty())
            .map(|s| s.value)
            .ok_or_else(|| Error::Config(format!("{name} is not in the metrics snapshot")))
    };
    let by = |name: &str, label: &str| {
        if arg.is_empty() {
            return Err(Error::Config(format!("{key} needs the {label} name")));
        }
        samples
            .iter()
            .find(|s| s.name == name && s.labels.get(label).map(String::as_str) == Some(arg))
            .map(|s| s.value)
            .ok_or_else(|| Error::Config(format!("no {label} {arg:?} in {name}")))
    };
    let num = |v: f64| {
        if v.fract() == 0.0 && v.abs() < 1e15 {
            format!("{}", v as i64)
        } else {
            format!("{v}")
        }
    };
    let load = |i: usize| {
        loadavg
            .split_whitespace()
            .nth(i)
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| format!("{v}"))
            .ok_or_else(|| Error::Config("cannot read the load average".into()))
    };
    Ok(match key {
        "host.uptime" => num(one("patronus_uptime_seconds")?),
        "host.load1" => load(0)?,
        "host.load5" => load(1)?,
        "host.load15" => load(2)?,
        "host.mem.used_pct" => num(one("patronus_memory_used_percent")?),
        "host.disk.used_pct" => num(one("patronus_disk_used_percent")?),
        "firewall.rules" => num(one("patronus_firewall_active_rules")?),
        "conntrack.entries" => num(one("patronus_conntrack_entries")?),
        "conntrack.max" => num(one("patronus_conntrack_max")?),
        "dhcp.leases" => num(one("patronus_dhcp_leases")?),
        "config.revision" => num(one("patronus_config_revision")?),
        "ha.master" => num(one("patronus_ha_master")?),
        "gateway.up" => num(by("patronus_gateway_up", "gateway")?),
        "gateway.rtt_ms" => num(by("patronus_gateway_rtt_ms", "gateway")?),
        "gateway.loss_pct" => num(by("patronus_gateway_loss_percent", "gateway")?),
        "service.up" => num(by("patronus_service_up", "service")?),
        "gateway.discovery" => {
            let data: Vec<Value> = samples
                .iter()
                .filter(|s| s.name == "patronus_gateway_up")
                .filter_map(|s| s.labels.get("gateway"))
                .map(|g| json!({"{#GATEWAY}": g}))
                .collect();
            json!({ "data": data }).to_string()
        }
        _ => return Err(Error::Config(format!("unknown item {key:?}"))),
    })
}

// ---------------------------------------------------------------------------
// Zabbix agent 2
// ---------------------------------------------------------------------------

#[cfg(feature = "zabbix-agent")]
pub use zabbix::{check_psk, ZabbixApplier, ZabbixConf, ZabbixSvc, ZABBIX_SPEC};

#[cfg(feature = "zabbix-agent")]
pub mod zabbix {
    use super::*;

    static FIELDS: [Field; 8] = [
        Field::new("enabled", "Zabbix agent", Kind::Bool).def("0"),
        Field::new("hostname", "Host name", Kind::Token).help(
            "how the Zabbix server knows this router (must match the host entry there); \
             empty = the system host name",
        ),
        Field::new("active_server", "Active-check server", Kind::Host)
            .help("optional: the server this agent reports to by itself (active checks)"),
        Field::new("listen_iface", "Listen interface", Kind::Iface)
            .def("@lan")
            .help("the agent answers on the first address of this interface only"),
        Field::new("listen_port", "Listen port", Kind::Int(1, 65535)).def("10050"),
        Field::new("psk_identity", "TLS PSK identity", Kind::Token)
            .help("with a key: the identity the server must present"),
        Field::new("psk", "TLS PSK", Kind::Secret).help(
            "pre-shared key as hex, 32 to 128 digits (`openssl rand -hex 32`); with it the \
             agent refuses unencrypted queries",
        ),
        Field::new("remote_commands", "Remote commands", Kind::Select(&["off"]))
            .def("off")
            .help("fixed: this agent never runs commands the server sends"),
    ];

    static SERVER_FIELDS: [Field; 1] = [Field::new("host", "Server", Kind::Host)
        .req()
        .help("a Zabbix server or proxy that may query this agent (address or name)")];

    pub static ZABBIX_SPEC: Spec = Spec {
        slug: "zabbix",
        title: "Zabbix agent",
        blurb: "Zabbix agent 2 (7.x) so a Zabbix server can monitor this router: host items \
                plus gateways, firewall, connections and services through UserParameters. \
                It listens on the LAN only, runs as its own unprivileged account and never \
                runs remote commands.",
        applier: "zabbix",
        fields: &FIELDS,
        colls: &[Coll {
            key: "servers",
            title: "Allowed Zabbix servers",
            table: "zabbix_servers",
            fields: &SERVER_FIELDS,
            unique: Some("host"),
        }],
        actions: &[],
    };

    pub struct ZabbixSvc;

    /// A PSK is hex, at least 128 bits (Zabbix' minimum).
    pub fn check_psk(psk: &str) -> Result<()> {
        if psk == SECRET_MASK || psk.is_empty() {
            return Ok(());
        }
        if psk.len() >= 32 && psk.len().is_multiple_of(2) && psk.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(invalid(
                "tls psk (hexadecimal digits only, an even number, at least 32)",
            ))
        }
    }

    #[async_trait]
    impl Svc for ZabbixSvc {
        fn spec(&self) -> &'static Spec {
            &ZABBIX_SPEC
        }

        async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
            if let Some(p) = body.get("psk").and_then(Value::as_str) {
                check_psk(p.trim())?;
            }
            svc::put_settings(store, &ZABBIX_SPEC, body).await
        }
    }

    /// Everything the agent configuration is made from.
    pub struct ZabbixConf<'a> {
        pub servers: &'a [String],
        pub active: &'a str,
        pub hostname: &'a str,
        pub listen_ip: IpAddr,
        pub port: i64,
        pub psk_identity: &'a str,
        /// path of the PSK file when a key is configured
        pub psk_file: Option<&'a Path>,
        /// the program UserParameters call (`patronus`)
        pub item_bin: &'a str,
        pub control_socket: &'a str,
    }

    /// zabbix_agent2.conf. Every value passes [`conf_val`] (one line).
    pub fn render(c: &ZabbixConf) -> String {
        let mut o = lan::header("#", "zabbix_agent2");
        let mut kv = |k: &str, v: &str| o.push_str(&format!("{k}={}\n", conf_val(v)));
        kv("Server", &c.servers.join(","));
        if !c.active.is_empty() {
            kv("ServerActive", c.active);
        }
        kv("Hostname", c.hostname);
        kv("ListenIP", &c.listen_ip.to_string());
        kv("ListenPort", &c.port.to_string());
        kv("LogType", "console");
        kv("ControlSocket", c.control_socket);
        kv("Timeout", "10");
        if let (Some(f), false) = (c.psk_file, c.psk_identity.is_empty()) {
            kv("TLSConnect", "psk");
            kv("TLSAccept", "psk");
            kv("TLSPSKIdentity", c.psk_identity);
            kv("TLSPSKFile", &f.to_string_lossy());
        }
        // remote commands are fixed off, whatever the server says
        kv("DenyKey", "system.run[*]");
        kv("Plugins.SystemRun.LogRemoteCommands", "0");
        kv("UnsafeUserParameters", "0");
        kv(
            "UserParameter",
            &format!("patronus.item[*],{} zabbix-item $1 $2", c.item_bin),
        );
        o
    }

    pub struct ZabbixApplier {
        sup: Supervisor,
        env: LanEnv,
        bin: Option<PathBuf>,
    }

    impl Default for ZabbixApplier {
        fn default() -> Self {
            Self::new(LanEnv::system())
        }
    }

    impl ZabbixApplier {
        pub fn new(env: LanEnv) -> Self {
            Self {
                sup: Supervisor::detect(),
                env,
                bin: None,
            }
        }
        pub fn with_parts(sup: Supervisor, env: LanEnv, bin: Option<PathBuf>) -> Self {
            Self { sup, env, bin }
        }
        fn dir(&self) -> PathBuf {
            base_dir(&self.sup.paths).join("zabbix")
        }
        fn program(&self) -> Option<PathBuf> {
            self.bin
                .clone()
                .or_else(|| which("zabbix_agent2"))
                .or_else(|| which("zabbix-agent2"))
        }

        async fn conf(&self, store: &ConfigStore) -> Result<(String, String, String)> {
            let s = Settings::load(store, &ZABBIX_SPEC).await?;
            let servers: Vec<String> = svc::raw_rows(store, &ZABBIX_SPEC.colls[0])
                .await?
                .iter()
                .filter_map(|r| r["host"].as_str().map(str::to_string))
                .filter(|h| !h.is_empty())
                .collect();
            if servers.is_empty() {
                return Err(invalid(
                    "Zabbix agent: add at least one allowed Zabbix server",
                ));
            }
            let psk = s.s("psk");
            let ident = s.s("psk_identity");
            if psk.is_empty() != ident.is_empty() {
                return Err(invalid(
                    "Zabbix agent: the TLS PSK needs both an identity and a key (or neither)",
                ));
            }
            check_psk(&psk)?;
            let (_dev, ip) = listen_addr(store, &self.env, &s.s("listen_iface")).await?;
            let hostname = match s.s("hostname") {
                h if h.is_empty() => system_hostname(),
                h => h,
            };
            let dir = self.dir();
            let psk_path = dir.join("psk.key");
            let item_bin = which("patronus")
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/usr/bin/patronus".into());
            let sock = format!("/tmp/patronus-{ZABBIX_INSTANCE}.sock");
            let conf = render(&ZabbixConf {
                servers: &servers,
                active: &s.s("active_server"),
                hostname: &hostname,
                listen_ip: ip,
                port: s.n("listen_port"),
                psk_identity: &ident,
                psk_file: (!psk.is_empty()).then_some(psk_path.as_path()),
                item_bin: &item_bin,
                control_socket: &sock,
            });
            Ok((conf, psk, fmt_listen(ip, s.n("listen_port"))))
        }
    }

    #[async_trait]
    impl Applier for ZabbixApplier {
        fn name(&self) -> &'static str {
            "zabbix"
        }

        fn phase(&self) -> Phase {
            Phase::Services
        }

        async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
            let mut rep = ApplyReport::default();
            let s = Settings::load(store, &ZABBIX_SPEC).await?;
            let dir = self.dir();
            if !s.b("enabled") {
                let was = self.sup.stop(svc::DAEMON_SERVICE, ZABBIX_INSTANCE).await?;
                // the key must not outlive the feature
                let _ = std::fs::remove_file(dir.join("psk.key"));
                let _ = std::fs::remove_file(dir.join("zabbix_agent2.conf"));
                rep.applied(if was {
                    "Zabbix agent stopped"
                } else {
                    "Zabbix agent is off"
                });
                return Ok(rep);
            }
            let (conf, psk, listen) = self.conf(store).await?;
            let bin = self.program().ok_or_else(|| {
                Error::Service(
                    "the Zabbix agent needs zabbix_agent2, which is not installed (emerge \
                     net-analyzer/zabbix[agent2], USE=zabbix-agent)"
                        .into(),
                )
            })?;
            let grp = group_gid(ZABBIX_USER).map(|_| ZABBIX_USER);
            let base = base_dir(&self.sup.paths);
            ensure_dir(&base, 0o755, Some("patronus"), Some("patronus"))?;
            ensure_dir(&dir, 0o750, Some("root"), grp)?;
            let conf_path = dir.join("zabbix_agent2.conf");
            put_file(&conf_path, &conf, 0o640, grp)?;
            if psk.is_empty() {
                let _ = std::fs::remove_file(dir.join("psk.key"));
            } else {
                put_file(&dir.join("psk.key"), &format!("{psk}\n"), 0o640, grp)?;
            }
            let (argv, dropped) = privileged_argv(
                ZABBIX_USER,
                &[],
                vec![
                    bin.to_string_lossy().into_owned(),
                    "-f".into(),
                    "-c".into(),
                    conf_path.to_string_lossy().into_owned(),
                ],
            );
            // the files are already in place (owned by the agent's group); listing them makes
            // the supervisor's fingerprint cover their content, so a changed config restarts it
            let mut files = vec![(conf_path.clone(), conf.clone(), 0o640)];
            if !psk.is_empty() {
                files.push((dir.join("psk.key"), format!("{psk}\n"), 0o640));
            }
            let started = svc::ensure_daemon(&self.sup, ZABBIX_INSTANCE, argv, files).await?;
            rep.applied(format!(
                "Zabbix agent {} on {listen}{}",
                if started {
                    "(re)started"
                } else {
                    "running, unchanged"
                },
                if dropped {
                    ""
                } else {
                    " (as root: no zabbix account or setpriv)"
                }
            ));
            Ok(rep)
        }

        async fn render(&self, store: &ConfigStore) -> Result<String> {
            let s = Settings::load(store, &ZABBIX_SPEC).await?;
            if !s.b("enabled") {
                return Ok("# Zabbix agent off\n".into());
            }
            Ok(match self.conf(store).await {
                Ok((c, psk, _)) => format!(
                    "## zabbix_agent2.conf\n{c}{}",
                    if psk.is_empty() {
                        ""
                    } else {
                        "## psk.key: (set, not shown)\n"
                    }
                ),
                Err(e) => format!("# Zabbix agent: {e}\n"),
            })
        }

        async fn status(&self, store: &ConfigStore) -> Result<Value> {
            let s = Settings::load(store, &ZABBIX_SPEC).await?;
            Ok(json!({
                "enabled": s.b("enabled"),
                "installed": self.program().is_some(),
                "running": self.sup.is_running(svc::DAEMON_SERVICE, ZABBIX_INSTANCE),
                "listen_port": s.n("listen_port"),
                "tls_psk": !s.s("psk").is_empty(),
                "remote_commands": "off",
                "items": ZABBIX_ITEMS,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Telegraf
// ---------------------------------------------------------------------------

#[cfg(feature = "telegraf")]
pub use telegraf::{
    check_tables, check_url, Inputs, TelegrafApplier, TelegrafConf, TelegrafSvc, OUTPUTS, TELEGRAF_SPEC,
};

#[cfg(feature = "telegraf")]
pub mod telegraf {
    use super::*;

    pub const OUTPUTS: &[&str] = &["prometheus_client", "influxdb_v2", "influxdb_v1"];

    static FIELDS: [Field; 20] = [
        Field::new("enabled", "Telegraf", Kind::Bool).def("0"),
        Field::new("output", "Output", Kind::Select(OUTPUTS))
            .def("prometheus_client")
            .help("prometheus_client: scrape port on the LAN; influxdb_v2 / influxdb_v1: push to a server"),
        Field::new("url", "Server URL", Kind::Text)
            .help("InfluxDB: http(s)://host:8086"),
        Field::new("token", "Token or password", Kind::Secret)
            .help("InfluxDB v2 API token, or the v1 user's password"),
        Field::new("organization", "Organization", Kind::Token).help("InfluxDB v2"),
        Field::new("bucket", "Bucket or database", Kind::Token)
            .help("InfluxDB v2 bucket, or the v1 database"),
        Field::new("username", "User name", Kind::Token).help("InfluxDB v1"),
        Field::new("interval", "Collection interval (s)", Kind::Int(5, 3600)).def("30"),
        Field::new("listen_iface", "Scrape interface", Kind::Iface)
            .def("@lan")
            .help("prometheus_client only: it answers on the first address of this interface"),
        Field::new("listen_port", "Scrape port", Kind::Int(1, 65535)).def("9273"),
        Field::new("in_cpu", "CPU", Kind::Bool).def("1"),
        Field::new("in_mem", "Memory", Kind::Bool).def("1"),
        Field::new("in_disk", "Disk space", Kind::Bool).def("1"),
        Field::new("in_net", "Network interfaces", Kind::Bool).def("1"),
        Field::new("in_diskio", "Disk I/O", Kind::Bool).def("0"),
        Field::new("in_system", "Load and uptime", Kind::Bool).def("1"),
        Field::new("in_conntrack", "Connection tracking", Kind::Bool).def("1"),
        Field::new("in_nft", "Firewall counters (nftables)", Kind::Bool)
            .def("0")
            .help("named counters of the firewall tables; runs Telegraf with CAP_NET_ADMIN"),
        Field::new("nft_tables", "nftables tables", Kind::Text)
            .def("inet patronus")
            .help("comma separated, family and name, for example inet patronus"),
        Field::new("in_patronus", "Patronus gateway/service metrics", Kind::Bool)
            .def("1")
            .help("gateways, firewall rules, services and DHCP from the metrics snapshot"),
    ];

    pub static TELEGRAF_SPEC: Spec = Spec {
        slug: "telegraf",
        title: "Telegraf",
        blurb: "Telegraf collects host, network, connection and firewall metrics and either \
                serves them to a Prometheus scraper on the LAN or pushes them to an InfluxDB. \
                It runs as its own unprivileged account.",
        applier: "telegraf",
        fields: &FIELDS,
        colls: &[],
        actions: &[],
    };

    pub struct TelegrafSvc;

    /// `http(s)://host[:port][/path]` with a valid host and nothing that could
    /// break out of a quoted config value.
    pub fn check_url(u: &str) -> Result<String> {
        let bad = || invalid("server url (http:// or https:// and a host name or address)");
        let u = u.trim();
        if u.len() > 200
            || !u
                .bytes()
                .all(|b| (0x21..0x7f).contains(&b) && !matches!(b, b'"' | b'\\' | b'\'' | b'`'))
        {
            return Err(bad());
        }
        let rest = u
            .strip_prefix("https://")
            .or_else(|| u.strip_prefix("http://"))
            .ok_or_else(bad)?;
        let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
        if auth.is_empty() || auth.contains('@') {
            return Err(bad());
        }
        let host = if let Some(v6) = auth.strip_prefix('[') {
            v6.split(']').next().unwrap_or("")
        } else {
            auth.rsplit_once(':').map(|(h, _)| h).unwrap_or(auth)
        };
        let port_ok = match auth.rsplit_once(':') {
            Some((_, p)) if !auth.ends_with(']') => p.parse::<u16>().is_ok(),
            _ => true,
        };
        if port_ok && (host.parse::<IpAddr>().is_ok() || lan::valid_dns_name(host, false)) {
            Ok(u.to_string())
        } else {
            Err(bad())
        }
    }

    /// `inet patronus, ip nat`: family + name pairs only.
    pub fn check_tables(t: &str) -> Result<Vec<String>> {
        let mut v = Vec::new();
        for part in t.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let w: Vec<&str> = part.split_whitespace().collect();
            let ok = w.len() == 2
                && ["ip", "ip6", "inet", "bridge", "arp", "netdev"].contains(&w[0])
                && w[1].len() <= 32
                && w[1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
            if !ok {
                return Err(invalid(
                    "nftables tables (family and name, for example inet patronus)",
                ));
            }
            v.push(format!("{} {}", w[0], w[1]));
        }
        Ok(v)
    }

    #[async_trait]
    impl Svc for TelegrafSvc {
        fn spec(&self) -> &'static Spec {
            &TELEGRAF_SPEC
        }

        async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
            if let Some(u) = body.get("url").and_then(Value::as_str) {
                if !u.trim().is_empty() {
                    check_url(u)?;
                }
            }
            if let Some(t) = body.get("nft_tables").and_then(Value::as_str) {
                check_tables(t)?;
            }
            svc::put_settings(store, &TELEGRAF_SPEC, body).await
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct Inputs {
        pub cpu: bool,
        pub mem: bool,
        pub disk: bool,
        pub net: bool,
        pub diskio: bool,
        pub system: bool,
        pub conntrack: bool,
        pub nft: bool,
        pub patronus: bool,
    }

    pub struct TelegrafConf<'a> {
        pub interval_secs: i64,
        pub output: &'a str,
        pub url: &'a str,
        pub token: &'a str,
        pub org: &'a str,
        pub bucket: &'a str,
        pub username: &'a str,
        /// `ip:port` the Prometheus client listens on
        pub listen: &'a str,
        pub inputs: Inputs,
        pub nft_tables: &'a [String],
        pub snapshot: &'a Path,
    }

    /// telegraf.conf. Every string value goes through [`toml_str`].
    pub fn render(c: &TelegrafConf) -> String {
        let mut o = lan::header("#", "telegraf");
        o.push_str(&format!(
            "\n[agent]\n  interval = {}\n  round_interval = true\n  flush_interval = {}\n  \
             omit_hostname = false\n",
            toml_str(&format!("{}s", c.interval_secs)),
            toml_str(&format!("{}s", c.interval_secs)),
        ));
        match c.output {
            "influxdb_v2" => o.push_str(&format!(
                "\n[[outputs.influxdb_v2]]\n  urls = [{}]\n  token = {}\n  organization = {}\n  \
                 bucket = {}\n",
                toml_str(c.url),
                toml_str(c.token),
                toml_str(c.org),
                toml_str(c.bucket)
            )),
            "influxdb_v1" => o.push_str(&format!(
                "\n[[outputs.influxdb]]\n  urls = [{}]\n  database = {}\n  username = {}\n  \
                 password = {}\n",
                toml_str(c.url),
                toml_str(c.bucket),
                toml_str(c.username),
                toml_str(c.token)
            )),
            _ => o.push_str(&format!(
                "\n[[outputs.prometheus_client]]\n  listen = {}\n  metric_version = 2\n  \
                 expiration_interval = \"{}s\"\n",
                toml_str(c.listen),
                c.interval_secs * 3
            )),
        }
        let i = &c.inputs;
        if i.cpu {
            o.push_str("\n[[inputs.cpu]]\n  percpu = false\n  totalcpu = true\n");
        }
        if i.mem {
            o.push_str("\n[[inputs.mem]]\n");
        }
        if i.disk {
            o.push_str(
                "\n[[inputs.disk]]\n  ignore_fs = [\"tmpfs\", \"devtmpfs\", \"devfs\", \
                 \"overlay\", \"squashfs\", \"iso9660\"]\n",
            );
        }
        if i.net {
            o.push_str("\n[[inputs.net]]\n");
        }
        if i.diskio {
            o.push_str("\n[[inputs.diskio]]\n");
        }
        if i.system {
            o.push_str("\n[[inputs.system]]\n");
        }
        if i.conntrack {
            o.push_str(
                "\n[[inputs.conntrack]]\n  files = [\"ip_conntrack_count\", \"ip_conntrack_max\", \
                 \"nf_conntrack_count\", \"nf_conntrack_max\"]\n  dirs = [\"/proc/sys/net/\", \
                 \"/proc/sys/net/netfilter/\"]\n",
            );
        }
        if i.nft {
            o.push_str(&format!(
                "\n[[inputs.nftables]]\n  tables = [{}]\n  include = [\"counters\", \
                 \"anonymous-counters\"]\n",
                c.nft_tables
                    .iter()
                    .map(|t| toml_str(t))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if i.patronus {
            o.push_str(&format!(
                "\n[[inputs.file]]\n  files = [{}]\n  data_format = \"prometheus\"\n  \
                 name_override = \"patronus\"\n",
                toml_str(&c.snapshot.to_string_lossy())
            ));
        }
        o
    }

    pub struct TelegrafApplier {
        sup: Supervisor,
        env: LanEnv,
        bin: Option<PathBuf>,
    }

    impl Default for TelegrafApplier {
        fn default() -> Self {
            Self::new(LanEnv::system())
        }
    }

    impl TelegrafApplier {
        pub fn new(env: LanEnv) -> Self {
            Self {
                sup: Supervisor::detect(),
                env,
                bin: None,
            }
        }
        pub fn with_parts(sup: Supervisor, env: LanEnv, bin: Option<PathBuf>) -> Self {
            Self { sup, env, bin }
        }
        fn dir(&self) -> PathBuf {
            base_dir(&self.sup.paths).join("telegraf")
        }
        fn program(&self) -> Option<PathBuf> {
            self.bin.clone().or_else(|| which("telegraf"))
        }

        /// (telegraf.conf, listen address, needs CAP_NET_ADMIN)
        async fn conf(&self, store: &ConfigStore) -> Result<(String, String, bool)> {
            let s = Settings::load(store, &TELEGRAF_SPEC).await?;
            let output = s.s("output");
            let url = s.s("url");
            if output != "prometheus_client" {
                if url.is_empty() {
                    return Err(invalid("Telegraf: the server URL is required for InfluxDB"));
                }
                check_url(&url)?;
                if s.s("bucket").is_empty() {
                    return Err(invalid("Telegraf: the bucket or database is required"));
                }
                if output == "influxdb_v2" && (s.s("organization").is_empty() || s.s("token").is_empty())
                {
                    return Err(invalid(
                        "Telegraf: InfluxDB v2 needs an organization and a token",
                    ));
                }
            }
            let tables = check_tables(&s.s("nft_tables"))?;
            let listen = if output == "prometheus_client" {
                let (_, ip) = listen_addr(store, &self.env, &s.s("listen_iface")).await?;
                fmt_listen(ip, s.n("listen_port"))
            } else {
                String::new()
            };
            let snap = base_dir(&self.sup.paths).join(SNAPSHOT);
            let inputs = Inputs {
                cpu: s.b("in_cpu"),
                mem: s.b("in_mem"),
                disk: s.b("in_disk"),
                net: s.b("in_net"),
                diskio: s.b("in_diskio"),
                system: s.b("in_system"),
                conntrack: s.b("in_conntrack"),
                nft: s.b("in_nft"),
                patronus: s.b("in_patronus"),
            };
            let nft = inputs.nft;
            let conf = render(&TelegrafConf {
                interval_secs: s.n("interval"),
                output: &output,
                url: &url,
                token: &s.s("token"),
                org: &s.s("organization"),
                bucket: &s.s("bucket"),
                username: &s.s("username"),
                listen: &listen,
                inputs,
                nft_tables: &tables,
                snapshot: &snap,
            });
            Ok((conf, listen, nft))
        }
    }

    #[async_trait]
    impl Applier for TelegrafApplier {
        fn name(&self) -> &'static str {
            "telegraf"
        }

        fn phase(&self) -> Phase {
            Phase::Services
        }

        async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
            let mut rep = ApplyReport::default();
            let s = Settings::load(store, &TELEGRAF_SPEC).await?;
            let dir = self.dir();
            if !s.b("enabled") {
                let was = self
                    .sup
                    .stop(svc::DAEMON_SERVICE, TELEGRAF_INSTANCE)
                    .await?;
                // the file carries the token
                let _ = std::fs::remove_file(dir.join("telegraf.conf"));
                rep.applied(if was {
                    "Telegraf stopped"
                } else {
                    "Telegraf is off"
                });
                return Ok(rep);
            }
            let (conf, listen, nft) = self.conf(store).await?;
            let bin = self.program().ok_or_else(|| {
                Error::Service(
                    "Telegraf is not installed (emerge app-metrics/telegraf-bin, \
                     USE=telegraf)"
                        .into(),
                )
            })?;
            let grp = group_gid(TELEGRAF_USER).map(|_| TELEGRAF_USER);
            let base = base_dir(&self.sup.paths);
            ensure_dir(&base, 0o755, Some("patronus"), Some("patronus"))?;
            ensure_dir(&dir, 0o750, Some("root"), grp)?;
            let conf_path = dir.join("telegraf.conf");
            put_file(&conf_path, &conf, 0o640, grp)?;
            let caps: &[&str] = if nft { &["net_admin"] } else { &[] };
            let (argv, dropped) = privileged_argv(
                TELEGRAF_USER,
                caps,
                vec![
                    bin.to_string_lossy().into_owned(),
                    "--config".into(),
                    conf_path.to_string_lossy().into_owned(),
                ],
            );
            let files = vec![(conf_path.clone(), conf.clone(), 0o640)];
            let started = svc::ensure_daemon(&self.sup, TELEGRAF_INSTANCE, argv, files).await?;
            rep.applied(format!(
                "Telegraf {}{}{}",
                if started {
                    "(re)started"
                } else {
                    "running, unchanged"
                },
                if listen.is_empty() {
                    String::new()
                } else {
                    format!(", scrape on {listen}")
                },
                if dropped {
                    ""
                } else {
                    " (as root: no telegraf account or setpriv)"
                }
            ));
            Ok(rep)
        }

        async fn render(&self, store: &ConfigStore) -> Result<String> {
            let s = Settings::load(store, &TELEGRAF_SPEC).await?;
            if !s.b("enabled") {
                return Ok("# Telegraf off\n".into());
            }
            Ok(match self.conf(store).await {
                // the token is not part of what the UI may show
                Ok((c, _, _)) => {
                    let t = s.s("token");
                    let shown = if t.is_empty() {
                        c
                    } else {
                        c.replace(&toml_str(&t), "\"********\"")
                    };
                    format!("## telegraf.conf\n{shown}")
                }
                Err(e) => format!("# Telegraf: {e}\n"),
            })
        }

        async fn status(&self, store: &ConfigStore) -> Result<Value> {
            let s = Settings::load(store, &TELEGRAF_SPEC).await?;
            Ok(json!({
                "enabled": s.b("enabled"),
                "installed": self.program().is_some(),
                "running": self.sup.is_running(svc::DAEMON_SERVICE, TELEGRAF_INSTANCE),
                "output": s.s("output"),
                "interval": s.n("interval"),
                "scrape_port": s.n("listen_port"),
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan;
    use crate::svc::{self, SECRET_MASK};

    const PROM: &str = "# HELP patronus_gateway_up x\n# TYPE patronus_gateway_up gauge\n\
        patronus_gateway_up{gateway=\"WAN\"} 1\npatronus_gateway_up{gateway=\"LTE \\\"b\\\"\"} 0\n\
        patronus_gateway_rtt_ms{gateway=\"WAN\"} 12.5\npatronus_gateway_loss_percent{gateway=\"WAN\"} 0\n\
        patronus_uptime_seconds 86400\npatronus_memory_used_percent 41.5\n\
        patronus_firewall_active_rules 37\npatronus_conntrack_entries 120\n\
        patronus_service_up{service=\"dnsmasq\"} 1\n";

    #[test]
    fn toml_strings_cannot_escape() {
        assert_eq!(toml_str("plain"), "\"plain\"");
        let hostile = "a\"b\\c\nd\re\u{0}f\u{7f}g\th";
        let t = toml_str(hostile);
        assert!(!t.contains('\n') && !t.contains('\r') && !t.contains('\u{0}'));
        let doc = format!("k = {t}\n");
        let v: toml::Value = toml::from_str(&doc).unwrap();
        assert_eq!(v["k"].as_str().unwrap(), hostile);
    }

    #[test]
    fn conf_values_stay_on_one_line() {
        assert_eq!(conf_val("a\nServer=evil\r\n"), "aServer=evil");
        assert_eq!(conf_val("  ok  "), "ok");
    }

    #[test]
    fn prometheus_text_is_parsed_with_labels() {
        let s = parse_prom(PROM);
        assert_eq!(s.len(), 9);
        let g = s.iter().find(|x| x.value == 0.0 && x.name == "patronus_gateway_up");
        assert_eq!(g.unwrap().labels["gateway"], "LTE \"b\"");
    }

    #[test]
    fn zabbix_items_come_from_the_snapshot() {
        let q = |k: &str, a: &str| zabbix_item(k, a, PROM, "0.52 0.40 0.30 1/200 99");
        assert_eq!(q("gateway.up", "WAN").unwrap(), "1");
        assert_eq!(q("gateway.rtt_ms", "WAN").unwrap(), "12.5");
        assert_eq!(q("host.uptime", "").unwrap(), "86400");
        assert_eq!(q("host.load5", "").unwrap(), "0.4");
        assert_eq!(q("firewall.rules", "").unwrap(), "37");
        assert_eq!(q("service.up", "dnsmasq").unwrap(), "1");
        assert!(q("gateway.up", "").is_err());
        assert!(q("gateway.up", "nope").is_err());
        assert!(q("dhcp.leases", "").is_err(), "absent metric is an error, not 0");
        assert!(q("system.run", "id").is_err());
        let d: Value = serde_json::from_str(&q("gateway.discovery", "").unwrap()).unwrap();
        assert_eq!(d["data"].as_array().unwrap().len(), 2);
        assert_eq!(d["data"][0]["{#GATEWAY}"], "WAN");
        for k in ZABBIX_ITEMS {
            // every advertised key is understood (an error here may only be a missing metric)
            if let Err(e) = q(k, "WAN") {
                assert!(!e.to_string().contains("unknown item"), "{k}: {e}");
            }
        }
    }

    #[test]
    fn metrics_policy_checks_source_and_token() {
        let p = MetricsPolicy {
            enabled: true,
            allowed: Some("192.168.50.0/24".parse().unwrap()),
            token: Some("s3cret-token".into()),
        };
        assert!(p.allows_source(Some("192.168.50.7".parse().unwrap())));
        assert!(p.allows_source(Some("::ffff:192.168.50.7".parse().unwrap())));
        assert!(!p.allows_source(Some("203.0.113.9".parse().unwrap())));
        assert!(!p.allows_source(None));
        assert!(p.token_matches(Some("Bearer s3cret-token")));
        assert!(!p.token_matches(Some("Bearer s3cret-tokeN")));
        assert!(!p.token_matches(Some("Bearer s3cret")));
        assert!(!p.token_matches(Some("s3cret-token")));
        assert!(!p.token_matches(None));
        let open = MetricsPolicy {
            enabled: true,
            allowed: None,
            token: None,
        };
        assert!(open.allows_source(None) && !open.token_matches(Some("Bearer x")));
    }

    #[tokio::test]
    async fn metrics_page_defaults_keep_today_s_behaviour() {
        let s = lan::testutil::store().await;
        let p = metrics_policy(&s).await.unwrap();
        assert!(p.enabled && p.allowed.is_none() && p.token.is_none());
        svc::put_settings(
            &s,
            &METRICS_SPEC,
            &json!({"allowed_source": "10.0.0.0/8", "token": "abcdefgh-1234"}),
        )
        .await
        .unwrap();
        let p = metrics_policy(&s).await.unwrap();
        assert_eq!(p.allowed.unwrap().to_string(), "10.0.0.0/8");
        let shown = svc::get_settings(&s, &METRICS_SPEC).await.unwrap();
        assert_eq!(shown["token"], SECRET_MASK, "the token is never returned");
        assert!(
            svc::put_settings(&s, &METRICS_SPEC, &json!({"allowed_source": "not a net"}))
                .await
                .is_err()
        );
    }

    #[cfg(feature = "zabbix-agent")]
    mod zbx {
        use super::*;
        use crate::supervise::InitMode;

        fn conf<'a>(servers: &'a [String], hostname: &'a str) -> zabbix::ZabbixConf<'a> {
            zabbix::ZabbixConf {
                servers,
                active: "",
                hostname,
                listen_ip: "192.168.50.1".parse().unwrap(),
                port: 10050,
                psk_identity: "",
                psk_file: None,
                item_bin: "/usr/bin/patronus",
                control_socket: "/tmp/x.sock",
            }
        }

        #[test]
        fn config_has_fixed_remote_command_denial_and_one_line_values() {
            let servers = vec!["zbx.example.net".to_string(), "10.0.0.5".to_string()];
            let c = zabbix::render(&conf(&servers, "rtr"));
            for want in [
                "Server=zbx.example.net,10.0.0.5\n",
                "Hostname=rtr\n",
                "ListenIP=192.168.50.1\n",
                "ListenPort=10050\n",
                "DenyKey=system.run[*]\n",
                "UnsafeUserParameters=0\n",
                "UserParameter=patronus.item[*],/usr/bin/patronus zabbix-item $1 $2\n",
            ] {
                assert!(c.contains(want), "missing {want:?} in\n{c}");
            }
            assert!(!c.contains("TLSPSKFile"), "no key, no TLS lines");
            assert!(!c.contains("AllowKey"));
        }

        #[test]
        fn hostile_values_cannot_add_keys() {
            let servers = vec!["a.example\nAllowKey=system.run[*]\nServer=evil".to_string()];
            let mut c = conf(&servers, "h\nUnsafeUserParameters=1");
            c.psk_identity = "id\nTLSAccept=unencrypted";
            let psk = PathBuf::from("/x/psk.key\nTLSPSKFile=/etc/shadow");
            c.psk_file = Some(&psk);
            let out = zabbix::render(&c);
            let keys: Vec<&str> = out
                .lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .filter_map(|l| l.split('=').next())
                .collect();
            for k in &keys {
                assert!(
                    [
                        "Server", "Hostname", "ListenIP", "ListenPort", "LogType",
                        "ControlSocket", "Timeout", "TLSConnect", "TLSAccept",
                        "TLSPSKIdentity", "TLSPSKFile", "DenyKey",
                        "Plugins.SystemRun.LogRemoteCommands", "UnsafeUserParameters",
                        "UserParameter"
                    ]
                    .contains(k),
                    "unexpected key {k}\n{out}"
                );
            }
            assert_eq!(keys.iter().filter(|k| **k == "UnsafeUserParameters").count(), 1);
            assert!(out.contains("UnsafeUserParameters=0\n"));
            assert_eq!(keys.iter().filter(|k| **k == "TLSAccept").count(), 1);
            assert!(out.contains("TLSAccept=psk\n"));
        }

        #[test]
        fn psk_must_be_hex() {
            assert!(zabbix::check_psk(&"ab".repeat(16)).is_ok());
            assert!(zabbix::check_psk("short").is_err());
            assert!(zabbix::check_psk(&"zz".repeat(16)).is_err());
            assert!(zabbix::check_psk(&format!("{}a", "ab".repeat(16))).is_err());
            assert!(zabbix::check_psk(SECRET_MASK).is_ok());
        }

        #[tokio::test]
        async fn applier_needs_a_server_and_never_returns_the_key() {
            let t = lan::testutil::env(&[]);
            let st = lan::testutil::store().await;
            let d = tempfile::tempdir().unwrap();
            let sup = Supervisor::new(InitMode::Direct, NetPaths::under(d.path()));
            let fake = d.path().join("zabbix_agent2");
            std::fs::write(&fake, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let a = zabbix::ZabbixApplier::with_parts(sup.clone(), t.env.clone(), Some(fake));
            a.apply(&st).await.unwrap(); // off: nothing to do
            svc::put_settings(&st, &zabbix::ZABBIX_SPEC, &json!({"enabled": true}))
                .await
                .unwrap();
            let e = a.apply(&st).await.unwrap_err();
            assert!(e.to_string().contains("server"), "{e}");
            svc::save_row(&st, &zabbix::ZABBIX_SPEC.colls[0], None, &json!({"host": "zbx.example.net"}))
                .await
                .unwrap();
            assert!(
                svc::save_row(&st, &zabbix::ZABBIX_SPEC.colls[0], None, &json!({"host": "a;b"}))
                    .await
                    .is_err()
            );
            let psk = "0123456789abcdef".repeat(2);
            svc::put_settings(
                &st,
                &zabbix::ZABBIX_SPEC,
                &json!({"psk": psk, "psk_identity": "patronus-router", "hostname": "rtr1"}),
            )
            .await
            .unwrap();
            let rep = a.apply(&st).await.unwrap();
            assert!(rep.applied.iter().any(|l| l.contains("10050") || l.contains("Zabbix")));
            let dir = base_dir(&sup.paths).join("zabbix");
            let conf = std::fs::read_to_string(dir.join("zabbix_agent2.conf")).unwrap();
            assert!(conf.contains("Server=zbx.example.net\n") && conf.contains("Hostname=rtr1\n"));
            assert!(conf.contains("ListenIP=192.168.50.1\n"), "{conf}");
            assert!(conf.contains("TLSPSKIdentity=patronus-router\n"));
            assert!(!conf.contains(&psk), "the key is in its own file");
            let key = std::fs::read_to_string(dir.join("psk.key")).unwrap();
            assert_eq!(key.trim(), psk);
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join("psk.key")).unwrap().permissions().mode() & 0o777,
                0o640
            );
            // the page and the dry-run render never show the key
            let shown = svc::get_settings(&st, &zabbix::ZABBIX_SPEC).await.unwrap();
            assert_eq!(shown["psk"], SECRET_MASK);
            assert!(!a.render(&st).await.unwrap().contains(&psk));
            // unchanged config: no restart
            let rep2 = a.apply(&st).await.unwrap();
            assert!(rep2.applied.iter().any(|l| l.contains("unchanged")), "{:?}", rep2.applied);
            // disabling stops it and removes the key
            svc::put_settings(&st, &zabbix::ZABBIX_SPEC, &json!({"enabled": false}))
                .await
                .unwrap();
            a.apply(&st).await.unwrap();
            assert!(!dir.join("psk.key").exists());
            assert!(!sup.is_running(svc::DAEMON_SERVICE, ZABBIX_INSTANCE));
        }

        #[tokio::test]
        async fn page_refuses_a_bad_key_and_remote_commands_stay_off() {
            let st = lan::testutil::store().await;
            let page = zabbix::ZabbixSvc;
            assert!(page.put(&st, &json!({"psk": "nothex-nothex-nothex-nothex-nothex"})).await.is_err());
            assert!(page.put(&st, &json!({"remote_commands": "on"})).await.is_err());
            page.put(&st, &json!({"psk": "ab".repeat(20)})).await.unwrap();
            let g = page.get(&st).await.unwrap();
            assert_eq!(g["settings"]["psk"], SECRET_MASK);
            assert_eq!(g["settings"]["remote_commands"], "off");
        }
    }

    #[cfg(feature = "telegraf")]
    mod tg {
        use super::*;
        use crate::supervise::InitMode;

        fn base<'a>(tables: &'a [String], snap: &'a Path) -> telegraf::TelegrafConf<'a> {
            telegraf::TelegrafConf {
                interval_secs: 30,
                output: "prometheus_client",
                url: "",
                token: "",
                org: "",
                bucket: "",
                username: "",
                listen: "192.168.50.1:9273",
                inputs: telegraf::Inputs {
                    cpu: true,
                    mem: true,
                    conntrack: true,
                    patronus: true,
                    nft: true,
                    ..Default::default()
                },
                nft_tables: tables,
                snapshot: snap,
            }
        }

        #[test]
        fn prometheus_client_golden() {
            let t = vec!["inet patronus".to_string()];
            let snap = PathBuf::from("/var/lib/patronus-monagent/metrics.prom");
            let c = telegraf::render(&base(&t, &snap));
            let v: toml::Value = toml::from_str(&c).unwrap();
            assert_eq!(v["agent"]["interval"].as_str(), Some("30s"));
            let out = &v["outputs"]["prometheus_client"][0];
            assert_eq!(out["listen"].as_str(), Some("192.168.50.1:9273"));
            assert_eq!(out["metric_version"].as_integer(), Some(2));
            assert!(v["inputs"]["cpu"].is_array() && v["inputs"]["mem"].is_array());
            assert!(v["inputs"]["conntrack"].is_array());
            assert_eq!(v["inputs"]["nftables"][0]["tables"][0].as_str(), Some("inet patronus"));
            assert_eq!(
                v["inputs"]["file"][0]["files"][0].as_str(),
                Some("/var/lib/patronus-monagent/metrics.prom")
            );
            assert!(v["inputs"].get("disk").is_none(), "off inputs are not rendered");
        }

        #[test]
        fn hostile_values_round_trip_through_toml() {
            let hostile = "t\"k\n[[outputs.exec]]\ncommand = \"id\"\\\r\u{0}";
            let t = vec!["inet \"x\"\nevil".to_string()];
            let snap = PathBuf::from("/s\"nap\n.prom");
            for out in ["influxdb_v2", "influxdb_v1"] {
                let mut c = base(&t, &snap);
                c.output = out;
                c.url = "http://h\"\n[x]";
                c.token = hostile;
                c.org = hostile;
                c.bucket = hostile;
                c.username = hostile;
                let doc = telegraf::render(&c);
                let v: toml::Value = toml::from_str(&doc).unwrap_or_else(|e| panic!("{e}\n{doc}"));
                assert!(v["outputs"].get("exec").is_none(), "no injected output\n{doc}");
                let o = match out {
                    "influxdb_v2" => &v["outputs"]["influxdb_v2"][0],
                    _ => &v["outputs"]["influxdb"][0],
                };
                let token_key = if out == "influxdb_v2" { "token" } else { "password" };
                assert_eq!(o[token_key].as_str(), Some(hostile));
                assert_eq!(v["outputs"].as_table().unwrap().len(), 1);
            }
        }

        #[test]
        fn url_and_table_validation() {
            for ok in ["http://influx.example:8086", "https://10.0.0.2:8086/", "https://[fd00::1]:8086/x", "http://a.b"] {
                assert!(telegraf::check_url(ok).is_ok(), "{ok}");
            }
            for bad in [
                "ftp://x", "http://", "http://a b", "http://a\"b", "http://u:p@h", "http://h:99999",
                "http://h/a\nb", "http://h\\x", "javascript:1",
            ] {
                assert!(telegraf::check_url(bad).is_err(), "{bad}");
            }
            assert_eq!(telegraf::check_tables("inet patronus, ip nat").unwrap().len(), 2);
            assert!(telegraf::check_tables("inet patronus; rm").is_err());
            assert!(telegraf::check_tables("evil x").is_err());
            assert!(telegraf::check_tables("inet").is_err());
        }

        #[tokio::test]
        async fn applier_runs_only_on_change_and_hides_the_token() {
            let t = lan::testutil::env(&[]);
            let st = lan::testutil::store().await;
            let d = tempfile::tempdir().unwrap();
            let sup = Supervisor::new(InitMode::Direct, NetPaths::under(d.path()));
            let fake = d.path().join("telegraf");
            std::fs::write(&fake, "#!/bin/sh\nwhile :; do sleep 1; done\n").unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let a = telegraf::TelegrafApplier::with_parts(sup.clone(), t.env.clone(), Some(fake));
            let page = telegraf::TelegrafSvc;
            page.put(&st, &json!({"enabled": true, "output": "influxdb_v2"})).await.unwrap();
            assert!(a.apply(&st).await.unwrap_err().to_string().contains("URL"));
            assert!(page.put(&st, &json!({"url": "http://h\"x"})).await.is_err());
            page.put(
                &st,
                &json!({"url": "https://influx.example:8086", "token": "tok-0123456789",
                        "organization": "home", "bucket": "router"}),
            )
            .await
            .unwrap();
            let rep = a.apply(&st).await.unwrap();
            assert!(rep.applied[0].contains("(re)started"), "{:?}", rep.applied);
            let cfg = base_dir(&sup.paths).join("telegraf/telegraf.conf");
            let txt = std::fs::read_to_string(&cfg).unwrap();
            assert!(txt.contains("tok-0123456789"), "the daemon's file has the token");
            assert!(!a.render(&st).await.unwrap().contains("tok-0123456789"));
            let g = page.get(&st).await.unwrap();
            assert_eq!(g["settings"]["token"], SECRET_MASK);
            let rep = a.apply(&st).await.unwrap();
            assert!(rep.applied[0].contains("unchanged"), "{:?}", rep.applied);
            // a changed interval restarts it
            page.put(&st, &json!({"interval": 60})).await.unwrap();
            let rep = a.apply(&st).await.unwrap();
            assert!(rep.applied[0].contains("(re)started"), "{:?}", rep.applied);
            // prometheus_client binds the LAN address
            page.put(&st, &json!({"output": "prometheus_client"})).await.unwrap();
            let rep = a.apply(&st).await.unwrap();
            assert!(rep.applied[0].contains("192.168.50.1:9273"), "{:?}", rep.applied);
            page.put(&st, &json!({"enabled": false})).await.unwrap();
            a.apply(&st).await.unwrap();
            assert!(!cfg.exists());
            assert!(!sup.is_running(svc::DAEMON_SERVICE, TELEGRAF_INSTANCE));
        }
    }
}
