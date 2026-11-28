//! RFC 2136 dynamic DNS client (USE=rfc2136): keep A/AAAA records in your own
//! authoritative DNS server (BIND, Knot, PowerDNS, NSD with a TSIG key) pointing
//! at an interface's current address, like pfSense's "RFC 2136" dynamic DNS
//! client type and OPNsense's os-ddclient/RFC 2136 backend.
//!
//! One *client* (a table row) says: "keep `host.example.net` in zone
//! `example.net` on server S equal to the address of interface X, signed with
//! this TSIG key". Several clients may share an interface and a server.
//!
//! The engine is `patronus rfc2136 run`, started by the supervisor
//! (`patronus-daemon@rfc2136`, OpenRC and systemd) from a generated JSON file
//! (mode 0600: it carries the TSIG secrets). It wakes every `interval`
//! seconds, reads the device addresses (no network access needed for that),
//! and runs `nsupdate -k <keyfile>` (net-dns/bind-tools) only when an address
//! changed, the periodic `refresh` is due, or the last attempt failed (then
//! with a back-off up to 15 minutes). The secret is passed in a 0600 key file
//! in the run directory, never on a command line. Status goes to a JSON file
//! the page reads. The exchange is a plain RFC 2136 UPDATE signed with TSIG
//! (HMAC-SHA256/384/512), over UDP or TCP.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const INSTANCE: &str = "rfc2136";

pub const ALGOS: &[&str] = &["hmac-sha256", "hmac-sha384", "hmac-sha512"];
pub const FAMILIES: &[&str] = &["ipv4", "ipv6", "both"];

static FIELDS: [Field; 4] = [
    Field::new("enabled", "RFC 2136 dynamic DNS", Kind::Bool).def("0"),
    Field::new("interval", "Check interval (seconds)", Kind::Int(5, 86_400))
        .def("60")
        .help("how often the interface addresses are compared with what was last sent"),
    Field::new("refresh", "Re-send every (seconds)", Kind::Int(0, 2_592_000))
        .def("86400")
        .help("send the record again even when nothing changed (keeps a server that lost the zone in step); 0 = only on change"),
    Field::new("timeout", "Server timeout (seconds)", Kind::Int(2, 120))
        .def("15")
        .help("how long one update may take before it counts as failed"),
];

static CLIENT_FIELDS: [Field; 13] = [
    Field::new("hostname", "Host name", Kind::Host)
        .req()
        .help("the full name to keep up to date, e.g. router.example.net (must be inside the zone)"),
    Field::new("zone", "Zone", Kind::Host)
        .req()
        .help("the DNS zone the server is authoritative for, e.g. example.net"),
    Field::new("server", "DNS server", Kind::Host)
        .req()
        .help("address or name of the authoritative server that takes the update"),
    Field::new("port", "Server port", Kind::Int(1, 65535)).def("53"),
    Field::new("tcp", "Use TCP", Kind::Bool)
        .def("0")
        .help("send the update over TCP instead of UDP"),
    Field::new("key_name", "TSIG key name", Kind::Token)
        .req()
        .help("the key name as configured on the server, e.g. ddns-key"),
    Field::new("key_algo", "TSIG algorithm", Kind::Select(ALGOS)).def("hmac-sha256"),
    Field::new("key_secret", "TSIG secret", Kind::Secret)
        .req()
        .help("the base64 secret of the key (write-only)"),
    Field::new("iface", "Address of", Kind::Iface)
        .req()
        .help("device or @wan / @lan / @optN whose address is published"),
    Field::new("family", "Records", Kind::Select(FAMILIES))
        .def("ipv4")
        .help("A, AAAA or both"),
    Field::new("ttl", "TTL (seconds)", Kind::Int(1, 86_400)).def("300"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "rfc2136",
    title: "Dynamic DNS (RFC 2136)",
    blurb: "Keep A and AAAA records on your own DNS server (BIND, Knot, PowerDNS, NSD) equal to \
            an interface's address. Each client names the host, the zone, the server and the \
            TSIG key; an update is sent when the address changes, periodically, and again after \
            a failure. Runs nsupdate.",
    applier: "rfc2136",
    fields: &FIELDS,
    colls: &[Coll {
        key: "clients",
        title: "Clients",
        table: "rfc2136_clients",
        fields: &CLIENT_FIELDS,
        unique: Some("hostname"),
    }],
    actions: &[],
};

pub struct Rfc2136Svc;

#[async_trait]
impl Svc for Rfc2136Svc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// One client as the engine sees it (devices, not roles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConf {
    pub id: i64,
    pub hostname: String,
    pub zone: String,
    pub server: String,
    pub port: u16,
    pub tcp: bool,
    pub key_name: String,
    pub key_algo: String,
    pub key_secret: String,
    pub devices: Vec<String>,
    pub v4: bool,
    pub v6: bool,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EngineConf {
    pub interval: u64,
    pub refresh: u64,
    pub timeout: u64,
    pub nsupdate: String,
    pub clients: Vec<ClientConf>,
}

/// The engine's JSON file (carries the secrets: write it 0600).
pub fn render(c: &EngineConf) -> String {
    let mut s = serde_json::to_string_pretty(c).unwrap_or_default();
    s.push('\n');
    s
}

/// The same without the secrets, for the UI/export "rendered" view.
pub fn render_public(c: &EngineConf) -> String {
    let mut c = c.clone();
    for x in &mut c.clients {
        x.key_secret = svc::SECRET_MASK.into();
    }
    render(&c)
}

/// A base64 TSIG secret: standard alphabet, padded, at least 8 bytes decoded
/// (`nsupdate` would reject anything else with a parse error that names no field).
pub fn valid_base64_secret(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 12 || b.len() % 4 != 0 {
        return false;
    }
    let pad = b.iter().rev().take_while(|c| **c == b'=').count();
    if pad > 2 {
        return false;
    }
    b[..b.len() - pad]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
}

fn in_zone(host: &str, zone: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let z = zone.trim_end_matches('.').to_ascii_lowercase();
    h == z || h.ends_with(&format!(".{z}"))
}

/// Enabled clients resolved to devices; nothing is sent from here.
pub async fn load(store: &ConfigStore, nsupdate: &str) -> Result<EngineConf> {
    let s = Settings::load(store, &SPEC).await?;
    let mut conf = EngineConf {
        interval: s.n("interval").max(1) as u64,
        refresh: s.n("refresh").max(0) as u64,
        timeout: s.n("timeout").max(1) as u64,
        nsupdate: nsupdate.into(),
        clients: Vec::new(),
    };
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        let f = |k: &str| r[k].as_str().unwrap_or("").to_string();
        let id = r["id"].as_i64().unwrap_or(0);
        let name = f("hostname");
        if !in_zone(&name, &f("zone")) {
            return Err(invalid(format!(
                "dynamic DNS {name}: the host name is not inside zone {}",
                f("zone")
            )));
        }
        if !valid_base64_secret(&f("key_secret")) {
            return Err(invalid(format!(
                "dynamic DNS {name}: the TSIG secret must be base64 (as in the server's key file)"
            )));
        }
        let family = f("family");
        let devices = lan::resolve_iface(store, &f("iface")).await?;
        conf.clients.push(ClientConf {
            id,
            hostname: name,
            zone: f("zone"),
            server: f("server"),
            port: f("port").parse().unwrap_or(53),
            tcp: lan::flag(&f("tcp")),
            key_name: f("key_name"),
            key_algo: f("key_algo"),
            key_secret: f("key_secret"),
            devices,
            v4: family != "ipv6",
            v6: family != "ipv4",
            ttl: f("ttl").parse().unwrap_or(300),
        });
    }
    Ok(conf)
}

#[derive(Clone)]
pub struct Rfc2136Applier {
    sup: Supervisor,
    bin: Option<std::path::PathBuf>,
    nsupdate: Option<std::path::PathBuf>,
}

impl Default for Rfc2136Applier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            bin: None,
            nsupdate: None,
        }
    }
}

impl Rfc2136Applier {
    pub fn with(
        sup: Supervisor,
        bin: Option<std::path::PathBuf>,
        nsupdate: Option<std::path::PathBuf>,
    ) -> Self {
        Self { sup, bin, nsupdate }
    }
    fn patronus(&self) -> Option<std::path::PathBuf> {
        self.bin.clone().or_else(|| which("patronus"))
    }
    fn nsupdate(&self) -> Option<std::path::PathBuf> {
        self.nsupdate.clone().or_else(|| which("nsupdate"))
    }
    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("rfc2136.json")
    }
    pub fn stats_path(&self) -> std::path::PathBuf {
        self.sup.paths.run_dir.join("rfc2136.stats")
    }
}

#[async_trait]
impl Applier for Rfc2136Applier {
    fn name(&self) -> &'static str {
        "rfc2136"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("dynamic DNS (RFC 2136) stopped");
            } else {
                rep.applied("dynamic DNS (RFC 2136) is off");
            }
            return Ok(rep);
        }
        let ns = self.nsupdate().ok_or_else(|| {
            Error::Service(
                "RFC 2136 dynamic DNS needs nsupdate, which is not installed (emerge \
                 net-dns/bind-tools, USE=rfc2136)"
                    .into(),
            )
        })?;
        let conf = load(store, &ns.to_string_lossy()).await?;
        if conf.clients.is_empty() {
            return Err(invalid(
                "dynamic DNS (RFC 2136): add at least one enabled client (host, zone, server, key)",
            ));
        }
        let bin = self.patronus().ok_or_else(|| {
            Error::Service("RFC 2136 dynamic DNS needs the `patronus` binary on the PATH".into())
        })?;
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        let cp = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "rfc2136".into(),
                "run".into(),
                "--conf".into(),
                cp.to_string_lossy().into(),
                "--stats".into(),
                self.stats_path().to_string_lossy().into(),
            ],
            vec![(cp, render(&conf), 0o600)],
        )
        .await?;
        rep.applied(format!(
            "dynamic DNS (RFC 2136) {} ({} client(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            conf.clients.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# dynamic DNS (RFC 2136) off\n".into());
        }
        let ns = self
            .nsupdate()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "nsupdate".into());
        Ok(format!(
            "## rfc2136.json\n{}",
            render_public(&load(store, &ns).await?)
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let stats: Value = std::fs::read_to_string(self.stats_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null);
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": self.nsupdate().is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "clients": svc::raw_rows(store, &SPEC.colls[0]).await.map(|r| r.len()).unwrap_or(0),
            "summary": summary(&stats),
            "stats": stats,
        }))
    }
}

/// One readable line per client from the engine's status file (what the page shows).
pub fn summary(stats: &Value) -> Vec<String> {
    let Some(c) = stats.get("clients").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut rows: Vec<String> = c
        .values()
        .map(|v| {
            let host = v["hostname"].as_str().unwrap_or("?");
            let addrs = [v["ipv4"].as_str(), v["ipv6"].as_str()]
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(e) = v["last_error"].as_str() {
                format!(
                    "{host}: FAILED ({} attempt(s)): {e}",
                    v["failures"].as_u64().unwrap_or(0)
                )
            } else if let Some(n) = v["note"].as_str() {
                format!("{host}: waiting: {n}")
            } else if v["last_ok"].is_null() {
                format!("{host}: not sent yet ({addrs})")
            } else {
                format!(
                    "{host}: ok, {addrs}, {} update(s) sent",
                    v["updates"].as_u64().unwrap_or(0)
                )
            }
        })
        .collect();
    rows.sort();
    rows
}

/// What nsupdate is told, kept pure so it is unit-tested.
pub mod script {
    use super::ClientConf;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The TSIG key file (BIND syntax) for `nsupdate -k`.
    pub fn key_file(c: &ClientConf) -> String {
        format!(
            "key \"{}\" {{\n\talgorithm {};\n\tsecret \"{}\";\n}};\n",
            c.key_name, c.key_algo, c.key_secret
        )
    }

    fn fqdn(h: &str) -> String {
        if h.ends_with('.') {
            h.to_string()
        } else {
            format!("{h}.")
        }
    }

    /// The update: replace the RRset of each wanted family with the current address.
    pub fn update(c: &ClientConf, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> String {
        let h = fqdn(&c.hostname);
        let mut s = format!(
            "server {} {}\nzone {}\n",
            c.server,
            c.port,
            fqdn(&c.zone)
        );
        if let Some(a) = v4 {
            s.push_str(&format!(
                "update delete {h} A\nupdate add {h} {} A {a}\n",
                c.ttl
            ));
        }
        if let Some(a) = v6 {
            s.push_str(&format!(
                "update delete {h} AAAA\nupdate add {h} {} AAAA {a}\n",
                c.ttl
            ));
        }
        s.push_str("send\n");
        s
    }

    pub fn args(c: &ClientConf, key_path: &str, timeout: u64) -> Vec<String> {
        let mut a = vec![
            "-k".to_string(),
            key_path.to_string(),
            "-t".to_string(),
            timeout.to_string(),
            "-u".to_string(),
            "2".to_string(),
            "-r".to_string(),
            "1".to_string(),
        ];
        if c.tcp {
            a.push("-v".into());
        }
        a
    }
}

/// Address choice, shared by the engine and its tests.
pub fn pick_v4(addrs: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    let private = |a: &Ipv4Addr| {
        a.is_private()
            || a.is_loopback()
            || a.is_link_local()
            || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
    };
    addrs
        .iter()
        .copied()
        .find(|a| !private(a) && !a.is_unspecified())
        .or_else(|| {
            addrs
                .iter()
                .copied()
                .find(|a| !a.is_loopback() && !a.is_link_local() && !a.is_unspecified())
        })
}

/// The address to publish as AAAA: global unicast, not ULA/link-local; a `/128`
/// (what DHCPv6 IA_NA hands a WAN) wins, otherwise the first one.
pub fn pick_v6(addrs: &[(Ipv6Addr, u8)]) -> Option<Ipv6Addr> {
    let global = |a: &Ipv6Addr| {
        let s0 = a.segments()[0];
        !a.is_loopback()
            && !a.is_unspecified()
            && !a.is_multicast()
            && (s0 & 0xffc0) != 0xfe80
            && (s0 & 0xfe00) != 0xfc00
    };
    addrs
        .iter()
        .filter(|(a, _)| global(a))
        .find(|(_, p)| *p == 128)
        .or_else(|| addrs.iter().find(|(a, _)| global(a)))
        .map(|(a, _)| *a)
}

pub mod engine {
    use super::{pick_v4, script, ClientConf, EngineConf};
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Backs off to at most this many seconds after repeated failures.
    pub const MAX_BACKOFF: u64 = 900;

    /// Where addresses and the DNS server come from: a seam for tests.
    pub trait Host {
        fn addrs(&self, devices: &[String]) -> (Vec<Ipv4Addr>, Vec<(Ipv6Addr, u8)>);
        /// Run nsupdate with `script` on stdin; Err = why it failed.
        fn send(&self, conf: &EngineConf, c: &ClientConf, script: &str) -> Result<(), String>;
    }

    pub struct Real {
        pub key_dir: std::path::PathBuf,
    }

    impl Host for Real {
        fn addrs(&self, devices: &[String]) -> (Vec<Ipv4Addr>, Vec<(Ipv6Addr, u8)>) {
            let (mut v4, mut v6) = (Vec::new(), Vec::new());
            if let Ok(it) = nix::ifaddrs::getifaddrs() {
                for a in it {
                    if !devices.contains(&a.interface_name) {
                        continue;
                    }
                    if let Some(ad) = a.address.as_ref().and_then(|x| x.as_sockaddr_in()) {
                        v4.push(ad.ip());
                    } else if let Some(ad) = a.address.as_ref().and_then(|x| x.as_sockaddr_in6())
                    {
                        let plen = a
                            .netmask
                            .as_ref()
                            .and_then(|m| m.as_sockaddr_in6())
                            .map(|m| m.ip().octets().iter().map(|b| b.count_ones()).sum::<u32>())
                            .unwrap_or(128) as u8;
                        v6.push((ad.ip(), plen));
                    }
                }
            }
            (v4, v6)
        }

        fn send(&self, conf: &EngineConf, c: &ClientConf, script: &str) -> Result<(), String> {
            // the key file lives only as long as the call, mode 0600
            let path = self.key_dir.join(format!("rfc2136-key-{}", c.id));
            let _ = std::fs::remove_file(&path);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("key file: {e}"))?;
            f.write_all(script::key_file(c).as_bytes())
                .map_err(|e| format!("key file: {e}"))?;
            drop(f);
            let res = (|| {
                let mut child = Command::new(&conf.nsupdate)
                    .args(script::args(c, &path.to_string_lossy(), conf.timeout))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("cannot run {}: {e}", conf.nsupdate))?;
                child
                    .stdin
                    .take()
                    .ok_or("no stdin")?
                    .write_all(script.as_bytes())
                    .map_err(|e| format!("nsupdate stdin: {e}"))?;
                let deadline = Instant::now() + Duration::from_secs(conf.timeout * 3 + 5);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(50))
                        }
                        Ok(None) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err("nsupdate did not finish in time".to_string());
                        }
                        Err(e) => return Err(format!("nsupdate: {e}")),
                    }
                }
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                if out.status.success() {
                    Ok(())
                } else {
                    let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    if msg.is_empty() {
                        msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    }
                    let msg: String = msg.lines().last().unwrap_or("").chars().take(200).collect();
                    Err(if msg.is_empty() {
                        format!("nsupdate failed ({})", out.status)
                    } else {
                        msg
                    })
                }
            })();
            let _ = std::fs::remove_file(&path);
            res
        }
    }

    #[derive(Debug, Default, Clone)]
    pub struct State {
        pub sent: Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)>,
        pub last_ok: Option<u64>,
        pub next_try: Option<Instant>,
        pub fails: u32,
        pub updates: u64,
        pub last_error: Option<String>,
        pub note: Option<String>,
    }

    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// One pass over every client at monotonic time `now`.
    pub fn tick(
        host: &dyn Host,
        conf: &EngineConf,
        st: &mut BTreeMap<i64, State>,
        now: Instant,
        unix: u64,
    ) {
        for c in &conf.clients {
            let s = st.entry(c.id).or_default();
            let (a4, a6) = host.addrs(&c.devices);
            let want4 = if c.v4 { pick_v4(&a4) } else { None };
            let want6 = if c.v6 { super::pick_v6(&a6) } else { None };
            if want4.is_none() && want6.is_none() {
                s.note = Some("no address on the interface yet".into());
                continue;
            }
            s.note = None;
            let cur = (want4, want6);
            let changed = s.sent != Some(cur);
            let refresh_due = conf.refresh > 0
                && s.last_ok
                    .map(|t| unix.saturating_sub(t) >= conf.refresh)
                    .unwrap_or(true);
            let held = s.next_try.map(|t| now < t).unwrap_or(false);
            if (!changed && !refresh_due && s.fails == 0) || held {
                continue;
            }
            let body = script::update(c, want4, want6);
            match host.send(conf, c, &body) {
                Ok(()) => {
                    s.sent = Some(cur);
                    s.last_ok = Some(unix);
                    s.fails = 0;
                    s.next_try = None;
                    s.updates += 1;
                    s.last_error = None;
                }
                Err(e) => {
                    s.fails += 1;
                    let back = (conf.interval << s.fails.min(10)).min(MAX_BACKOFF);
                    s.next_try = Some(now + Duration::from_secs(back));
                    s.last_error = Some(e);
                    // an address that failed to publish must be retried even
                    // when it later equals the last one that worked
                    s.sent = None;
                }
            }
        }
    }

    pub fn status_json(conf: &EngineConf, st: &BTreeMap<i64, State>, host: &dyn Host) -> Value {
        let mut m = Map::new();
        for c in &conf.clients {
            let s = st.get(&c.id).cloned().unwrap_or_default();
            let (a4, a6) = host.addrs(&c.devices);
            m.insert(
                c.id.to_string(),
                json!({
                    "hostname": c.hostname,
                    "server": c.server,
                    "ok": s.last_error.is_none() && s.last_ok.is_some(),
                    "last_ok": s.last_ok,
                    "last_error": s.last_error,
                    "note": s.note,
                    "updates": s.updates,
                    "failures": s.fails,
                    "ipv4": pick_v4(&a4).map(|a| a.to_string()),
                    "ipv6": super::pick_v6(&a6).map(|a| a.to_string()),
                }),
            );
        }
        json!({"updated": now_unix(), "clients": Value::Object(m)})
    }

    fn write_status(path: &std::path::Path, v: &Value) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// `patronus rfc2136 run`: never returns unless the configuration is unreadable.
    pub fn run(conf_path: &std::path::Path, stats: Option<&std::path::Path>) -> anyhow::Result<()> {
        let conf: EngineConf = serde_json::from_str(&std::fs::read_to_string(conf_path)?)?;
        let key_dir = stats
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("/run"));
        std::fs::create_dir_all(&key_dir).ok();
        let host = Real { key_dir };
        let mut st: BTreeMap<i64, State> = BTreeMap::new();
        loop {
            tick(&host, &conf, &mut st, Instant::now(), now_unix());
            if let Some(p) = stats {
                write_status(p, &status_json(&conf, &st, &host));
            }
            std::thread::sleep(Duration::from_secs(conf.interval.clamp(1, 86_400)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    fn client() -> ClientConf {
        ClientConf {
            id: 1,
            hostname: "router.example.net".into(),
            zone: "example.net".into(),
            server: "192.0.2.53".into(),
            port: 53,
            tcp: false,
            key_name: "ddns-key".into(),
            key_algo: "hmac-sha256".into(),
            key_secret: "c2VjcmV0c2VjcmV0c2VjcmV0".into(),
            devices: vec!["wan0".into()],
            v4: true,
            v6: true,
            ttl: 300,
        }
    }

    #[test]
    fn nsupdate_script_and_key_file() {
        let c = client();
        let s = script::update(
            &c,
            Some("198.51.100.7".parse().unwrap()),
            Some("2001:db8::7".parse().unwrap()),
        );
        assert_eq!(
            s,
            "server 192.0.2.53 53\nzone example.net.\n\
             update delete router.example.net. A\n\
             update add router.example.net. 300 A 198.51.100.7\n\
             update delete router.example.net. AAAA\n\
             update add router.example.net. 300 AAAA 2001:db8::7\nsend\n"
        );
        let only6 = script::update(&c, None, Some("2001:db8::7".parse().unwrap()));
        assert!(!only6.contains(" A "), "{only6}");
        let k = script::key_file(&c);
        assert!(k.contains("key \"ddns-key\"") && k.contains("algorithm hmac-sha256;"));
        assert!(k.contains("secret \"c2VjcmV0c2VjcmV0c2VjcmV0\";"));
        let mut t = c.clone();
        t.tcp = true;
        assert!(script::args(&t, "/k", 9).contains(&"-v".to_string()));
        assert!(!script::args(&c, "/k", 9).contains(&"-v".to_string()));
        // the secret is never on the command line
        assert!(!script::args(&c, "/k", 9).iter().any(|a| a.contains("c2Vj")));
    }

    #[test]
    fn secrets_and_zones() {
        assert!(valid_base64_secret("c2VjcmV0c2VjcmV0c2VjcmV0"));
        assert!(valid_base64_secret("YWJjZGVmZ2hpamtsbQ=="));
        assert!(!valid_base64_secret("short"));
        assert!(!valid_base64_secret("not base64 at all!"));
        assert!(!valid_base64_secret("YWJjZGVmZ2hpamtsbQ==="));
        assert!(in_zone("a.b.example.net", "example.net"));
        assert!(in_zone("example.net.", "example.net"));
        assert!(!in_zone("badexample.net", "example.net"));
        assert!(!in_zone("example.org", "example.net"));
    }

    #[test]
    fn address_choice_prefers_public() {
        let p = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            pick_v4(&[p("192.168.1.1"), p("203.0.113.9")]),
            Some(p("203.0.113.9"))
        );
        assert_eq!(pick_v4(&[p("192.168.1.1")]), Some(p("192.168.1.1")));
        assert_eq!(pick_v4(&[p("169.254.1.1")]), None);
        assert_eq!(pick_v4(&[]), None);
    }

    struct Fake {
        v4: RefCell<Vec<Ipv4Addr>>,
        fail: RefCell<bool>,
        sent: RefCell<Vec<String>>,
    }
    impl engine::Host for Fake {
        fn addrs(&self, _d: &[String]) -> (Vec<Ipv4Addr>, Vec<(Ipv6Addr, u8)>) {
            (self.v4.borrow().clone(), vec![])
        }
        fn send(
            &self,
            _c: &EngineConf,
            _c2: &ClientConf,
            s: &str,
        ) -> std::result::Result<(), String> {
            self.sent.borrow_mut().push(s.to_string());
            if *self.fail.borrow() {
                Err("NOTAUTH".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn sends_on_change_refresh_and_after_failure_with_backoff() {
        let mut c = client();
        c.v6 = false;
        let conf = EngineConf {
            interval: 60,
            refresh: 3600,
            timeout: 15,
            nsupdate: "nsupdate".into(),
            clients: vec![c],
        };
        let h = Fake {
            v4: RefCell::new(vec![]),
            fail: RefCell::new(false),
            sent: RefCell::new(vec![]),
        };
        let mut st = BTreeMap::new();
        let t0 = Instant::now();
        // no address yet: nothing sent, a note says why
        engine::tick(&h, &conf, &mut st, t0, 1000);
        assert!(h.sent.borrow().is_empty());
        assert!(st[&1].note.is_some());
        // address appears: one update
        *h.v4.borrow_mut() = vec!["203.0.113.5".parse().unwrap()];
        engine::tick(&h, &conf, &mut st, t0, 1000);
        assert_eq!(h.sent.borrow().len(), 1);
        // nothing changed: quiet
        engine::tick(&h, &conf, &mut st, t0, 1100);
        assert_eq!(h.sent.borrow().len(), 1);
        // refresh due
        engine::tick(&h, &conf, &mut st, t0, 1000 + 3600);
        assert_eq!(h.sent.borrow().len(), 2);
        // address change, server refuses: failure recorded, held back
        *h.v4.borrow_mut() = vec!["203.0.113.6".parse().unwrap()];
        *h.fail.borrow_mut() = true;
        engine::tick(&h, &conf, &mut st, t0, 5000);
        assert_eq!(h.sent.borrow().len(), 3);
        assert_eq!(st[&1].last_error.as_deref(), Some("NOTAUTH"));
        engine::tick(&h, &conf, &mut st, t0 + Duration::from_secs(10), 5010);
        assert_eq!(h.sent.borrow().len(), 3, "held during back-off");
        // back-off over and the server is fine again: sent, error cleared
        *h.fail.borrow_mut() = false;
        engine::tick(&h, &conf, &mut st, t0 + Duration::from_secs(500), 5500);
        assert_eq!(h.sent.borrow().len(), 4);
        assert!(st[&1].last_error.is_none());
        assert!(h.sent.borrow()[3].contains("203.0.113.6"));
        let j = engine::status_json(&conf, &st, &h);
        assert_eq!(
            summary(&j),
            vec!["router.example.net: ok, 203.0.113.6, 3 update(s) sent".to_string()]
        );
        assert_eq!(j["clients"]["1"]["ok"], true);
        assert_eq!(j["clients"]["1"]["ipv4"], "203.0.113.6");
    }

    #[tokio::test]
    async fn validation_load_and_render_hide_the_secret() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = Rfc2136Applier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            Some("/bin/true".into()),
            Some("/bin/true".into()),
        );
        assert!(a.apply(&s).await.is_ok(), "off: nothing to do");
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least one"), "{e}");
        let ok = json!({"hostname": "r.example.net", "zone": "example.net",
            "server": "192.0.2.53", "key_name": "k1",
            "key_secret": "c2VjcmV0c2VjcmV0c2VjcmV0", "iface": "eth9"});
        // newline / quote injection is refused by the field kinds
        for (k, v) in [
            ("hostname", "a b.example.net"),
            ("server", "x\nupdate delete z A"),
            ("key_name", "k\"1"),
            ("zone", "example.net;"),
        ] {
            let mut bad = ok.clone();
            bad[k] = json!(v);
            assert!(
                svc::save_row(&s, &SPEC.colls[0], None, &bad).await.is_err(),
                "{k}"
            );
        }
        let mut bad = ok.clone();
        bad["key_algo"] = json!("hmac-md5");
        assert!(svc::save_row(&s, &SPEC.colls[0], None, &bad).await.is_err());
        let id = svc::save_row(&s, &SPEC.colls[0], None, &ok).await.unwrap();
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &ok).await.is_err(),
            "a host name twice is refused"
        );
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("r.example.net") && r.contains("eth9"), "{r}");
        assert!(!r.contains("c2VjcmV0"), "the secret never shows: {r}");
        // the page never returns the secret either
        let page = svc::find("rfc2136").map(|_| ()).is_some();
        assert!(page);
        // a host outside the zone and a non-base64 secret fail at apply
        let mut other = ok.clone();
        other["hostname"] = json!("r.example.org");
        svc::save_row(&s, &SPEC.colls[0], Some(id), &other)
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("not inside zone"), "{e}");
        let mut other = ok.clone();
        other["key_secret"] = json!("not-base64-secret!");
        svc::save_row(&s, &SPEC.colls[0], Some(id), &other)
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("base64"), "{e}");
    }
}
