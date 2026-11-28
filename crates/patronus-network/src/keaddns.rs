//! Kea DDNS (USE=kea-ddns): DHCP clients get DNS names. Kea's DHCP servers
//! hand every lease to `kea-dhcp-ddns` (the D2 daemon) as a name change
//! request, and D2 sends RFC 2136 dynamic updates (signed with a TSIG key) to
//! the DNS server that is authoritative for the zone. pfSense and OPNsense
//! do the same with their Kea plugins.
//!
//! Two destinations, one typed setting (`kea-ddns.mode`):
//!
//! * `local`: the router's own Unbound. Unbound is a resolver and cannot take
//!   RFC 2136 updates, so Patronus runs a small built-in receiver
//!   (`patronus kea-ddns run`, supervised as `patronus-daemon@kea-ddns-sink`)
//!   on a loopback port. It checks the TSIG signature, applies the update
//!   rules of RFC 2136 (zone, prerequisites, add/delete, only A, AAAA, PTR and
//!   DHCID records, only inside the configured zones, a record limit), keeps
//!   its records in a state file and publishes them into the running Unbound
//!   with `unbound-control local_data` (re-pushed every few seconds, so an
//!   Unbound restart or a DNS re-apply does not lose them).
//! * `external`: any RFC 2136 server (BIND, Knot, PowerDNS, Windows DNS...).
//!   D2 talks to it directly; no receiver runs here.
//!
//! The reverse zones are derived from the DHCP pools. Kea itself is told to
//! send requests by the DHCP applier (`dhcp.rs` renders the `dhcp-ddns` block
//! from [`dhcp_side`]); this module owns D2's config and daemon and the
//! receiver. The TSIG secret is a [`Kind::Secret`]: never returned by the
//! API, and written only to root-only (0600) files.

use crate::lan::{self, invalid, LanEnv};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use base64::Engine as _;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const SINK_INSTANCE: &str = "kea-ddns-sink";
pub const D2_INSTANCE: &str = "kea-ddns-d2";
pub const D2_BIN: &str = "/usr/sbin/kea-dhcp-ddns";

static FIELDS: [Field; 17] = [
    Field::new("enabled", "Register DHCP clients in DNS", Kind::Bool).def("0"),
    Field::new("mode", "Update", Kind::Select(&["local", "external"]))
        .def("local")
        .help("local = the router's own DNS resolver (Unbound); external = an RFC 2136 server you run"),
    Field::new("forward_zone", "Zone for client names", Kind::Host).help(
        "e.g. lan.example; empty = the DNS page's local domain. Should match the domain the DHCP pools hand out",
    ),
    Field::new("reverse", "Also register reverse (PTR) names", Kind::Bool)
        .def("1")
        .help("the reverse zones come from the DHCP pools' subnets"),
    Field::new("server", "External DNS server", Kind::Ip)
        .def("127.0.0.1")
        .help("external mode: the server that accepts RFC 2136 updates for the zones (an address, not a name)"),
    Field::new("server_port", "External DNS server port", Kind::Int(1, 65535)).def("53"),
    Field::new("key_name", "TSIG key name", Kind::Token)
        .def("patronus-ddns")
        .help("the key's name as the DNS server knows it"),
    Field::new(
        "algorithm",
        "TSIG algorithm",
        Kind::Select(&["hmac-sha256", "hmac-sha384", "hmac-sha512"]),
    )
    .def("hmac-sha256"),
    Field::new("secret", "TSIG secret (base64)", Kind::Secret).help(
        "local mode: leave empty and a random key is generated; external mode: the key the server holds",
    ),
    Field::new("local_port", "Local receiver port (loopback)", Kind::Int(1024, 65535)).def("5335"),
    Field::new("d2_port", "Kea DDNS daemon port (loopback)", Kind::Int(1024, 65535)).def("53001"),
    Field::new(
        "override_client_update",
        "Update even if the client asks to do it itself",
        Kind::Bool,
    )
    .def("0"),
    Field::new(
        "replace_client_name",
        "Replace the client's own host name",
        Kind::Select(&["never", "always", "when-present", "when-not-present"]),
    )
    .def("when-not-present")
    .help("when-not-present = a client that sends no name gets a generated one"),
    Field::new("generated_prefix", "Prefix of generated names", Kind::Token).def("host"),
    Field::new("update_on_renew", "Refresh the records at every renewal", Kind::Bool).def("0"),
    Field::new("unbound_socket", "Resolver control socket", Kind::Token)
        .def("/run/unbound.ctl")
        .help("local mode: the unbound-control socket the receiver publishes the names through (the DNS page's default)"),
    Field::new("max_records", "Most records the local receiver keeps", Kind::Int(16, 200_000))
        .def("4096")
        .help("a guard against a flood of updates; the oldest leases fall out when they expire"),
];

static SPEC: Spec = Spec {
    slug: "kea-ddns",
    title: "Dynamic DNS for DHCP clients (Kea DDNS)",
    blurb: "Give every DHCP client a DNS name (and a reverse name) when it gets a lease, and remove \
            it when the lease ends. Kea's DHCP server hands each lease to the Kea DDNS daemon, which \
            sends signed RFC 2136 updates either to the router's own resolver (a built-in receiver \
            feeds Unbound) or to a DNS server you run. Needs the Kea DHCP backend.",
    applier: "kea-ddns",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct KeaDdnsSvc;

#[async_trait]
impl Svc for KeaDdnsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        if let Some(z) = body.get("forward_zone").and_then(Value::as_str) {
            if !z.trim().is_empty() {
                check_zone(z)?;
            }
        }
        if let Some(s) = body.get("secret").and_then(Value::as_str) {
            if s != svc::SECRET_MASK && !s.is_empty() {
                check_secret(s)?;
            }
        }
        svc::put_settings(store, &SPEC, body).await
    }

    /// `records`: the names the local receiver holds right now.
    async fn action(&self, _store: &ConfigStore, name: &str, _body: &Value) -> Result<Value> {
        match name {
            "records" => {
                let sup = Supervisor::detect();
                let stats: Value = std::fs::read_to_string(stats_path(&sup))
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(Value::Null);
                Ok(json!({
                    "names": stats.get("names").cloned().unwrap_or(json!([])),
                    "total": stats.get("records").cloned().unwrap_or(json!(0)),
                    "truncated": stats.get("truncated").cloned().unwrap_or(json!(false)),
                }))
            }
            _ => Err(Error::Config(format!(
                "Invalid request: no action {name:?}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// validation helpers
// ---------------------------------------------------------------------------

/// A zone name: dot separated labels of letters, digits and hyphens.
pub fn check_zone(z: &str) -> Result<String> {
    let t = z.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !t.is_empty()
        && t.len() <= 253
        && t.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok {
        Ok(t)
    } else {
        Err(invalid(format!(
            "zone {z:?}: letters, digits, hyphens and dots"
        )))
    }
}

/// A TSIG secret is base64 of at least 16 bytes.
pub fn check_secret(s: &str) -> Result<Vec<u8>> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| {
            invalid(
                "TSIG secret: not base64 (the key as `dnssec-keygen` / `tsig-keygen` prints it)",
            )
        })?;
    if raw.len() < 16 {
        return Err(invalid(
            "TSIG secret: at least 16 bytes (22 base64 characters)",
        ));
    }
    Ok(raw)
}

fn random_secret() -> Result<String> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| Error::Service(format!("kea-ddns: no random bytes for the TSIG key: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(b))
}

/// Reverse zone that holds the PTR names of `cidr` (the zone boundary is an
/// octet for IPv4 and a nibble for IPv6; a /25 sits in its /24's zone).
pub fn reverse_zone(cidr: &str) -> Option<String> {
    let (addr, len) = cidr.split_once('/')?;
    let len: u32 = len.parse().ok()?;
    if let Ok(a) = addr.parse::<Ipv4Addr>() {
        if len > 32 {
            return None;
        }
        let n = ((len / 8).clamp(1, 3)) as usize;
        let o = a.octets();
        let mut parts: Vec<String> = o[..n].iter().map(|x| x.to_string()).collect();
        parts.reverse();
        return Some(format!("{}.in-addr.arpa", parts.join(".")));
    }
    let a = addr.parse::<Ipv6Addr>().ok()?;
    if len > 128 {
        return None;
    }
    let n = ((len / 4).clamp(1, 31)) as usize;
    let hex: String = a
        .octets()
        .iter()
        .flat_map(|b| [b >> 4, b & 15])
        .map(|d| char::from_digit(d as u32, 16).unwrap_or('0'))
        .collect();
    let nib: Vec<String> = hex[..n].chars().rev().map(|c| c.to_string()).collect();
    Some(format!("{}.ip6.arpa", nib.join(".")))
}

// ---------------------------------------------------------------------------
// resolved configuration
// ---------------------------------------------------------------------------

/// Everything the three consumers (Kea DHCP, D2, the receiver) need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub local: bool,
    pub forward_zone: String,
    pub reverse_zones: Vec<String>,
    pub key_name: String,
    pub algorithm: String,
    pub secret: String,
    pub server: String,
    pub server_port: u16,
    pub d2_port: u16,
    pub local_port: u16,
    pub override_client_update: bool,
    pub replace_client_name: String,
    pub generated_prefix: String,
    pub update_on_renew: bool,
    pub max_records: u64,
}

impl Plan {
    /// All zones D2 may update and the receiver is authoritative for.
    pub fn zones(&self) -> Vec<String> {
        let mut z = vec![self.forward_zone.clone()];
        z.extend(self.reverse_zones.iter().cloned());
        z
    }
}

/// The part of the settings Kea's DHCP servers need (the `dhcp-ddns` block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpSide {
    pub d2_port: u16,
    pub suffix: String,
    pub override_client_update: bool,
    pub replace_client_name: String,
    pub generated_prefix: String,
    pub update_on_renew: bool,
}

/// Kea DDNS switched on? Then what the DHCP servers must be told. `None`
/// when it is off or when no zone can be worked out yet.
pub async fn dhcp_side(store: &ConfigStore) -> Result<Option<DhcpSide>> {
    let s = Settings::load(store, &SPEC).await?;
    if !s.b("enabled") {
        return Ok(None);
    }
    let zone = forward_zone(store, &s).await?;
    if zone.is_empty() {
        return Ok(None);
    }
    Ok(Some(DhcpSide {
        d2_port: s.n("d2_port") as u16,
        suffix: zone,
        override_client_update: s.b("override_client_update"),
        replace_client_name: s.s("replace_client_name"),
        generated_prefix: s.s("generated_prefix"),
        update_on_renew: s.b("update_on_renew"),
    }))
}

async fn forward_zone(store: &ConfigStore, s: &Settings) -> Result<String> {
    let z = s.s("forward_zone");
    let z = if z.trim().is_empty() {
        lan::setting_or(store, "dns.local_domain", "").await?
    } else {
        z
    };
    if z.trim().is_empty() {
        return Ok(String::new());
    }
    check_zone(&z)
}

/// The Kea part of a DHCP config: `dhcp-ddns` plus the global `ddns-*`
/// parameters (valid at the top of Dhcp4 and Dhcp6 in Kea 2.4 and 3.x).
pub fn kea_block(d: &DhcpSide) -> Vec<(&'static str, Value)> {
    vec![
        (
            "dhcp-ddns",
            json!({
                "enable-updates": true,
                "server-ip": "127.0.0.1",
                "server-port": d.d2_port,
                "sender-ip": "127.0.0.1",
                "sender-port": 0,
                "max-queue-size": 1024,
                "ncr-protocol": "UDP",
                "ncr-format": "JSON",
            }),
        ),
        ("ddns-send-updates", json!(true)),
        (
            "ddns-override-client-update",
            json!(d.override_client_update),
        ),
        ("ddns-replace-client-name", json!(d.replace_client_name)),
        ("ddns-generated-prefix", json!(d.generated_prefix)),
        ("ddns-qualifying-suffix", json!(format!("{}.", d.suffix))),
        ("ddns-update-on-renew", json!(d.update_on_renew)),
    ]
}

fn algo_d2(a: &str) -> &'static str {
    match a {
        "hmac-sha384" => "HMAC-SHA384",
        "hmac-sha512" => "HMAC-SHA512",
        _ => "HMAC-SHA256",
    }
}

/// `/etc/kea/kea-dhcp-ddns.conf`-style document for D2 (contains the secret).
pub fn render_d2(p: &Plan) -> String {
    let (ip, port) = if p.local {
        ("127.0.0.1".to_string(), p.local_port)
    } else {
        (p.server.clone(), p.server_port)
    };
    let dom = |z: &str| {
        json!({
            "name": format!("{z}."),
            "key-name": p.key_name,
            "dns-servers": [{"ip-address": ip, "port": port}],
        })
    };
    let mut doc = json!({
        "DhcpDdns": {
            "ip-address": "127.0.0.1",
            "port": p.d2_port,
            "dns-server-timeout": 2000,
            "ncr-protocol": "UDP",
            "ncr-format": "JSON",
            "tsig-keys": [{
                "name": p.key_name,
                "algorithm": algo_d2(&p.algorithm),
                "secret": p.secret,
            }],
            "forward-ddns": {"ddns-domains": [dom(&p.forward_zone)]},
            "loggers": [{"name": "kea-dhcp-ddns", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
        }
    });
    if !p.reverse_zones.is_empty() {
        doc["DhcpDdns"]["reverse-ddns"] = json!({
            "ddns-domains": p.reverse_zones.iter().map(|z| dom(z)).collect::<Vec<_>>()
        });
    }
    format!(
        "{}{}\n",
        lan::header(
            "//",
            "Kea DDNS (D2) daemon; holds the TSIG secret, keep it 0600"
        ),
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    )
}

/// The receiver's JSON file (contains the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkConf {
    pub listen: String,
    pub port: u16,
    pub key_name: String,
    pub algorithm: String,
    pub secret: String,
    pub zones: Vec<String>,
    pub max_records: u64,
    pub state_file: String,
    pub unbound_socket: String,
    /// seconds between re-pushes of every record into Unbound
    pub push_interval: u64,
    /// TSIG time tolerance in seconds
    pub fudge: u64,
}

pub fn sink_conf(p: &Plan, sup: &Supervisor, unbound_socket: &str) -> SinkConf {
    SinkConf {
        listen: "127.0.0.1".into(),
        port: p.local_port,
        key_name: p.key_name.clone(),
        algorithm: p.algorithm.clone(),
        secret: p.secret.clone(),
        zones: p.zones(),
        max_records: p.max_records,
        state_file: state_path(sup).to_string_lossy().into(),
        unbound_socket: unbound_socket.into(),
        push_interval: 5,
        fudge: 300,
    }
}

fn state_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.state_dir.join("kea-ddns-records.json")
}

pub fn stats_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.run_dir.join("kea-ddns.stats")
}

fn sink_conf_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.state_dir.join("kea-ddns-sink.json")
}

fn d2_conf_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.state_dir.join("kea-dhcp-ddns.conf")
}

/// Resolve the stored settings and the DHCP pools into a [`Plan`]. A local
/// key that does not exist yet is created (and stored) here.
pub async fn load(store: &ConfigStore, env: &LanEnv, create_key: bool) -> Result<Plan> {
    let s = Settings::load(store, &SPEC).await?;
    let local = s.s("mode") != "external";
    let zone = forward_zone(store, &s).await?;
    if zone.is_empty() {
        return Err(invalid(
            "Kea DDNS: no zone for client names (set one here or the local domain on the DNS page)",
        ));
    }
    let key_name = s.s("key_name");
    let mut secret = s.s("secret");
    if secret.trim().is_empty() {
        if local {
            if !create_key {
                return Err(invalid(
                    "Kea DDNS: no TSIG key yet (it is created when this is applied)",
                ));
            }
            secret = random_secret()?;
            lan::set_setting(store, "kea-ddns.secret", &secret).await?;
        } else {
            return Err(invalid(
                "Kea DDNS: external mode needs the TSIG secret of the DNS server's key",
            ));
        }
    }
    check_secret(&secret)?;
    let (backend_kea, subnets) = crate::dhcp::ddns_subnets(store, env).await?;
    if !backend_kea {
        return Err(invalid(
            "Kea DDNS: it needs the Kea DHCP backend (USE=kea, DHCP backend kea or auto with Kea installed)",
        ));
    }
    let mut reverse_zones: Vec<String> = Vec::new();
    if s.b("reverse") {
        for c in &subnets {
            if let Some(z) = reverse_zone(c) {
                if !reverse_zones.contains(&z) {
                    reverse_zones.push(z);
                }
            }
        }
    }
    reverse_zones.sort();
    let (d2, local_port) = (s.n("d2_port") as u16, s.n("local_port") as u16);
    if d2 == local_port {
        return Err(invalid(
            "Kea DDNS: the daemon port and the local receiver port must differ",
        ));
    }
    Ok(Plan {
        local,
        forward_zone: zone,
        reverse_zones,
        key_name,
        algorithm: s.s("algorithm"),
        secret,
        server: s.s("server"),
        server_port: s.n("server_port") as u16,
        d2_port: d2,
        local_port,
        override_client_update: s.b("override_client_update"),
        replace_client_name: s.s("replace_client_name"),
        generated_prefix: s.s("generated_prefix"),
        update_on_renew: s.b("update_on_renew"),
        max_records: s.n("max_records").max(16) as u64,
    })
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct KeaDdnsApplier {
    env: LanEnv,
    sup: Supervisor,
    bin: Option<std::path::PathBuf>,
}

impl Default for KeaDdnsApplier {
    fn default() -> Self {
        Self {
            env: LanEnv::system(),
            sup: Supervisor::detect(),
            bin: None,
        }
    }
}

impl KeaDdnsApplier {
    pub fn with(env: LanEnv, sup: Supervisor, bin: Option<std::path::PathBuf>) -> Self {
        Self { env, sup, bin }
    }
    fn patronus(&self) -> Option<std::path::PathBuf> {
        self.bin.clone().or_else(|| which("patronus"))
    }
    fn d2_bin(&self) -> Option<std::path::PathBuf> {
        let p = self.env.path(D2_BIN);
        if p.exists() {
            Some(std::path::PathBuf::from(D2_BIN))
        } else {
            which("kea-dhcp-ddns")
        }
    }
    async fn stop_all(&self, store: &ConfigStore, rep: &mut ApplyReport) -> Result<()> {
        let stopped = svc::stop_daemons(&self.sup, "kea-ddns", &[]).await?;
        for s in stopped {
            rep.applied(format!("{s} stopped"));
        }
        // the names it registered go with it: out of the running Unbound and out of the state file
        let sock = lan::setting_or(store, "kea-ddns.unbound_socket", "/run/unbound.ctl").await?;
        let n = engine::withdraw(&state_path(&self.sup), &sock);
        if n > 0 {
            rep.applied(format!("{n} registered name(s) removed from the resolver"));
        }
        for p in [d2_conf_path(&self.sup), sink_conf_path(&self.sup)] {
            // the files hold the TSIG secret: nothing keeps them once it is off
            let _ = std::fs::remove_file(p);
        }
        Ok(())
    }

    /// `kea-dhcp-ddns -t` on the candidate before it replaces a good config.
    fn check_d2(&self, bin: &std::path::Path, content: &str) -> Result<()> {
        if !self.env.check_configs {
            return Ok(());
        }
        let tmp = self.sup.paths.state_dir.join("kea-dhcp-ddns.conf.check");
        crate::supervise::write_atomic(&tmp, content, 0o600)?;
        let out = std::process::Command::new(bin).arg("-t").arg(&tmp).output();
        let _ = std::fs::remove_file(&tmp);
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(Error::Service(format!(
                "kea-dhcp-ddns refused the generated configuration: {}",
                String::from_utf8_lossy(&o.stderr)
                    .lines()
                    .chain(String::from_utf8_lossy(&o.stdout).lines())
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("no message")
            ))),
            Err(e) => Err(Error::Service(format!(
                "could not run {}: {e}",
                bin.display()
            ))),
        }
    }
}

#[async_trait]
impl Applier for KeaDdnsApplier {
    fn name(&self) -> &'static str {
        "kea-ddns"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            self.stop_all(store, &mut rep).await?;
            rep.applied("Kea DDNS is off");
            return Ok(rep);
        }
        let p = load(store, &self.env, true).await?;
        let d2 = self.d2_bin().ok_or_else(|| {
            Error::Service(
                "Kea DDNS needs kea-dhcp-ddns (emerge net-misc/kea; it is part of it)".into(),
            )
        })?;
        std::fs::create_dir_all(&self.sup.paths.state_dir).ok();
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        // D2 keeps its pid file in /run/kea
        lan::ensure_dir(&self.env, "/run/kea", 0o750, Some(("dhcp", "dhcp")));

        let d2conf = render_d2(&p);
        self.check_d2(&d2, &d2conf)?;
        let d2path = d2_conf_path(&self.sup);

        if p.local {
            #[cfg(feature = "dns")]
            let dns_ok = crate::dns::settings(store).await?.effective_mode(&self.env) == "resolver";
            #[cfg(not(feature = "dns"))]
            let dns_ok = false;
            if !dns_ok {
                return Err(invalid(
                    "Kea DDNS (local): the DNS resolver (Unbound) must be on: switch the DNS page to resolver mode, or use an external RFC 2136 server",
                ));
            }
            let bin = self.patronus().ok_or_else(|| {
                Error::Service("Kea DDNS (local) needs the `patronus` binary on the PATH".into())
            })?;
            let sock = s.s("unbound_socket");
            let sc = sink_conf(&p, &self.sup, &sock);
            let scp = sink_conf_path(&self.sup);
            let mut j = serde_json::to_string_pretty(&sc).unwrap_or_default();
            j.push('\n');
            let started = svc::ensure_daemon(
                &self.sup,
                SINK_INSTANCE,
                vec![
                    bin.to_string_lossy().into(),
                    "kea-ddns".into(),
                    "run".into(),
                    "--conf".into(),
                    scp.to_string_lossy().into(),
                    "--stats".into(),
                    stats_path(&self.sup).to_string_lossy().into(),
                ],
                vec![(scp, j, 0o600)],
            )
            .await?;
            rep.applied(format!(
                "Kea DDNS receiver {} on 127.0.0.1:{} for {} zone(s)",
                if started {
                    "(re)started"
                } else {
                    "running, unchanged,"
                },
                p.local_port,
                sc.zones.len()
            ));
        } else if self.sup.stop(svc::DAEMON_SERVICE, SINK_INSTANCE).await? {
            rep.applied("Kea DDNS receiver stopped (external server in use)");
        }
        let started = svc::ensure_daemon(
            &self.sup,
            D2_INSTANCE,
            vec![
                d2.to_string_lossy().into(),
                "-c".into(),
                d2path.to_string_lossy().into(),
            ],
            vec![(d2path, d2conf, 0o600)],
        )
        .await?;
        rep.applied(format!(
            "Kea DDNS daemon (D2) {} ({} zone(s), {})",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            p.zones().len(),
            if p.local {
                "local receiver"
            } else {
                "external server"
            }
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# Kea DDNS off\n".into());
        }
        let mut p = load(store, &self.env, false).await?;
        // never show the secret in an export or a plan
        p.secret = svc::SECRET_MASK.into();
        Ok(format!("## kea-dhcp-ddns.conf\n{}", render_d2(&p)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let stats: Value = std::fs::read_to_string(stats_path(&self.sup))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .map(|mut v: Value| {
                if let Some(o) = v.as_object_mut() {
                    o.remove("names");
                }
                v
            })
            .unwrap_or(Value::Null);
        Ok(json!({
            "enabled": s.b("enabled"),
            "mode": s.s("mode"),
            "installed": self.d2_bin().is_some(),
            "daemon_running": self.sup.is_running(svc::DAEMON_SERVICE, D2_INSTANCE),
            "receiver_running": self.sup.is_running(svc::DAEMON_SERVICE, SINK_INSTANCE),
            "receiver": stats,
        }))
    }
}

// ===========================================================================
// DNS wire format, TSIG and the update rules (RFC 1035, 2136, 8945)
// ===========================================================================

pub mod wire {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    pub const T_A: u16 = 1;
    pub const T_SOA: u16 = 6;
    pub const T_PTR: u16 = 12;
    pub const T_AAAA: u16 = 28;
    pub const T_DHCID: u16 = 49;
    pub const T_TSIG: u16 = 250;
    pub const T_ANY: u16 = 255;
    pub const C_IN: u16 = 1;
    pub const C_NONE: u16 = 254;
    pub const C_ANY: u16 = 255;
    pub const OP_UPDATE: u8 = 5;

    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
    pub const YXDOMAIN: u8 = 6;
    pub const YXRRSET: u8 = 7;
    pub const NXRRSET: u8 = 8;
    pub const NOTAUTH: u8 = 9;
    pub const NOTZONE: u8 = 10;

    pub type Labels = Vec<Vec<u8>>;

    /// Read a (possibly compressed) name at `*pos`; `*pos` ends after it.
    pub fn read_name(msg: &[u8], pos: &mut usize) -> Option<Labels> {
        let mut labels: Labels = Vec::new();
        let mut p = *pos;
        let mut end: Option<usize> = None;
        let mut jumps = 0;
        let mut total = 0usize;
        loop {
            let len = *msg.get(p)? as usize;
            if len & 0xc0 == 0xc0 {
                let lo = *msg.get(p + 1)? as usize;
                if end.is_none() {
                    end = Some(p + 2);
                }
                jumps += 1;
                if jumps > 32 {
                    return None;
                }
                p = ((len & 0x3f) << 8) | lo;
                continue;
            }
            if len & 0xc0 != 0 {
                return None;
            }
            p += 1;
            if len == 0 {
                break;
            }
            total += len + 1;
            if total > 255 {
                return None;
            }
            labels.push(msg.get(p..p + len)?.to_ascii_lowercase());
            p += len;
        }
        *pos = end.unwrap_or(p);
        Some(labels)
    }

    pub fn name_wire(l: &Labels) -> Vec<u8> {
        let mut v = Vec::new();
        for x in l {
            v.push(x.len() as u8);
            v.extend_from_slice(x);
        }
        v.push(0);
        v
    }

    /// `www.lan.example.` (absolute, lower case).
    pub fn name_text(l: &Labels) -> String {
        if l.is_empty() {
            return ".".into();
        }
        let mut s = String::new();
        for x in l {
            s.push_str(&String::from_utf8_lossy(x));
            s.push('.');
        }
        s
    }

    pub fn parse_text_name(t: &str) -> Labels {
        t.trim_end_matches('.')
            .split('.')
            .filter(|x| !x.is_empty())
            .map(|x| x.as_bytes().to_ascii_lowercase())
            .collect()
    }

    pub fn is_under(name: &Labels, zone: &Labels) -> bool {
        name.len() >= zone.len() && name[name.len() - zone.len()..] == zone[..]
    }

    #[derive(Debug, Clone)]
    pub struct Rr {
        pub name: Labels,
        pub rtype: u16,
        pub class: u16,
        pub ttl: u32,
        /// RDATA with names decompressed (PTR) so it compares byte for byte
        pub rdata: Vec<u8>,
        /// offset of this record in the message (for the TSIG digest)
        pub start: usize,
    }

    #[derive(Debug, Clone)]
    pub struct Msg {
        pub id: u16,
        pub flags: u16,
        pub zone: Vec<(Labels, u16, u16)>,
        pub prereq: Vec<Rr>,
        pub update: Vec<Rr>,
        pub additional: Vec<Rr>,
    }

    impl Msg {
        pub fn opcode(&self) -> u8 {
            ((self.flags >> 11) & 0xf) as u8
        }
        pub fn is_response(&self) -> bool {
            self.flags & 0x8000 != 0
        }
    }

    fn u16at(m: &[u8], p: usize) -> Option<u16> {
        Some(u16::from_be_bytes([*m.get(p)?, *m.get(p + 1)?]))
    }

    fn read_rr(m: &[u8], pos: &mut usize) -> Option<Rr> {
        let start = *pos;
        let name = read_name(m, pos)?;
        let rtype = u16at(m, *pos)?;
        let class = u16at(m, *pos + 2)?;
        let ttl = u32::from_be_bytes(m.get(*pos + 4..*pos + 8)?.try_into().ok()?);
        let rdlen = u16at(m, *pos + 8)? as usize;
        let rd_start = *pos + 10;
        let raw = m.get(rd_start..rd_start + rdlen)?;
        let rdata = if rtype == T_PTR && rdlen > 0 {
            let mut p = rd_start;
            let n = read_name(m, &mut p)?;
            if p > rd_start + rdlen {
                return None;
            }
            name_wire(&n)
        } else {
            raw.to_vec()
        };
        *pos = rd_start + rdlen;
        Some(Rr {
            name,
            rtype,
            class,
            ttl,
            rdata,
            start,
        })
    }

    /// Parse an UPDATE message (opcode 5). Sections are named as in RFC 2136.
    pub fn parse(m: &[u8]) -> Option<Msg> {
        if m.len() < 12 {
            return None;
        }
        let id = u16at(m, 0)?;
        let flags = u16at(m, 2)?;
        let (zo, pr, up, ad) = (
            u16at(m, 4)? as usize,
            u16at(m, 6)? as usize,
            u16at(m, 8)? as usize,
            u16at(m, 10)? as usize,
        );
        if zo > 8 || pr > 256 || up > 1024 || ad > 8 {
            return None;
        }
        let mut pos = 12;
        let mut zone = Vec::new();
        for _ in 0..zo {
            let n = read_name(m, &mut pos)?;
            let t = u16at(m, pos)?;
            let c = u16at(m, pos + 2)?;
            pos += 4;
            zone.push((n, t, c));
        }
        let mut sect = |n: usize| -> Option<Vec<Rr>> {
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(read_rr(m, &mut pos)?);
            }
            Some(v)
        };
        let prereq = sect(pr)?;
        let update = sect(up)?;
        let additional = sect(ad)?;
        Some(Msg {
            id,
            flags,
            zone,
            prereq,
            update,
            additional,
        })
    }

    // ----- HMAC ----------------------------------------------------------

    fn hash(alg: &str, data: &[u8]) -> Vec<u8> {
        match alg {
            "hmac-sha384" => Sha384::digest(data).to_vec(),
            "hmac-sha512" => Sha512::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }

    pub fn hmac(alg: &str, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let block = if alg == "hmac-sha256" { 64 } else { 128 };
        let mut k = if key.len() > block {
            hash(alg, key)
        } else {
            key.to_vec()
        };
        k.resize(block, 0);
        let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        inner.extend_from_slice(msg);
        let ih = hash(alg, &inner);
        let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        outer.extend_from_slice(&ih);
        hash(alg, &outer)
    }

    /// Constant-time comparison.
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
    }

    // ----- TSIG ----------------------------------------------------------

    #[derive(Debug, Clone)]
    pub struct Tsig {
        pub key: Labels,
        pub alg: Labels,
        pub time: u64,
        pub fudge: u16,
        pub mac: Vec<u8>,
        pub orig_id: u16,
        pub error: u16,
        pub start: usize,
    }

    pub fn alg_labels(alg: &str) -> Labels {
        parse_text_name(alg)
    }

    /// The TSIG record of a message (the last additional record), if any.
    pub fn tsig_of(m: &[u8], msg: &Msg) -> Option<Tsig> {
        let r = msg.additional.last()?;
        if r.rtype != T_TSIG {
            return None;
        }
        let d = &r.rdata;
        let mut p = 0usize;
        // the algorithm name is not compressed in practice; read it from the raw bytes
        let mut labels: Labels = Vec::new();
        loop {
            let l = *d.get(p)? as usize;
            p += 1;
            if l == 0 {
                break;
            }
            if l & 0xc0 != 0 {
                return None;
            }
            labels.push(d.get(p..p + l)?.to_ascii_lowercase());
            p += l;
        }
        let time = {
            let b = d.get(p..p + 6)?;
            b.iter().fold(0u64, |a, x| (a << 8) | *x as u64)
        };
        let fudge = u16at(d, p + 6)?;
        let ml = u16at(d, p + 8)? as usize;
        let mac = d.get(p + 10..p + 10 + ml)?.to_vec();
        let q = p + 10 + ml;
        let orig_id = u16at(d, q)?;
        let error = u16at(d, q + 2)?;
        let _ = m;
        Some(Tsig {
            key: r.name.clone(),
            alg: labels,
            time,
            fudge,
            mac,
            orig_id,
            error,
            start: r.start,
        })
    }

    fn tsig_vars(key: &Labels, alg: &Labels, time: u64, fudge: u16, error: u16) -> Vec<u8> {
        let mut v = name_wire(key);
        v.extend_from_slice(&C_ANY.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&name_wire(alg));
        v.extend_from_slice(&time.to_be_bytes()[2..]);
        v.extend_from_slice(&fudge.to_be_bytes());
        v.extend_from_slice(&error.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    }

    /// The bytes a request's MAC covers: the message without its TSIG record
    /// (ARCOUNT - 1, original id) plus the TSIG variables.
    pub fn request_digest_input(m: &[u8], t: &Tsig) -> Vec<u8> {
        let mut body = m[..t.start].to_vec();
        body[0..2].copy_from_slice(&t.orig_id.to_be_bytes());
        let ar = u16::from_be_bytes([body[10], body[11]]).saturating_sub(1);
        body[10..12].copy_from_slice(&ar.to_be_bytes());
        body.extend_from_slice(&tsig_vars(&t.key, &t.alg, t.time, t.fudge, 0));
        body
    }

    /// Append a TSIG record signing `msg` (a response to a request that carried
    /// `req_mac`).
    pub fn sign_response(
        mut msg: Vec<u8>,
        alg: &str,
        key_name: &Labels,
        secret: &[u8],
        req_mac: &[u8],
        now: u64,
        fudge: u16,
    ) -> Vec<u8> {
        let alg_l = alg_labels(alg);
        let mut input = Vec::new();
        input.extend_from_slice(&(req_mac.len() as u16).to_be_bytes());
        input.extend_from_slice(req_mac);
        input.extend_from_slice(&msg);
        input.extend_from_slice(&tsig_vars(key_name, &alg_l, now, fudge, 0));
        let mac = hmac(alg, secret, &input);
        let id = u16::from_be_bytes([msg[0], msg[1]]);
        let mut rd = name_wire(&alg_l);
        rd.extend_from_slice(&now.to_be_bytes()[2..]);
        rd.extend_from_slice(&fudge.to_be_bytes());
        rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        rd.extend_from_slice(&mac);
        rd.extend_from_slice(&id.to_be_bytes());
        rd.extend_from_slice(&0u16.to_be_bytes());
        rd.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&name_wire(key_name));
        msg.extend_from_slice(&T_TSIG.to_be_bytes());
        msg.extend_from_slice(&C_ANY.to_be_bytes());
        msg.extend_from_slice(&0u32.to_be_bytes());
        msg.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rd);
        let ar = u16::from_be_bytes([msg[10], msg[11]]) + 1;
        msg[10..12].copy_from_slice(&ar.to_be_bytes());
        msg
    }

    /// Verify a signed request's MAC (and time). Returns the request MAC.
    pub fn verify_request(
        m: &[u8],
        t: &Tsig,
        alg: &str,
        key_name: &Labels,
        secret: &[u8],
        now: u64,
        fudge: u64,
    ) -> Result<Vec<u8>, &'static str> {
        if t.key != *key_name {
            return Err("unknown key");
        }
        if t.alg != alg_labels(alg) {
            return Err("wrong algorithm");
        }
        if now.abs_diff(t.time) > fudge.min(t.fudge as u64).max(1) {
            return Err("time out of range");
        }
        let input = request_digest_input(m, t);
        let want = hmac(alg, secret, &input);
        if !ct_eq(&want, &t.mac) {
            return Err("bad signature");
        }
        Ok(t.mac.clone())
    }

    /// The response header + echoed zone section (no records).
    pub fn response(req: &Msg, rcode: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&req.id.to_be_bytes());
        let flags: u16 = 0x8000 | ((OP_UPDATE as u16) << 11) | rcode as u16;
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&(req.zone.len() as u16).to_be_bytes());
        v.extend_from_slice(&[0u8; 6]);
        for (n, t, c) in &req.zone {
            v.extend_from_slice(&name_wire(n));
            v.extend_from_slice(&t.to_be_bytes());
            v.extend_from_slice(&c.to_be_bytes());
        }
        v
    }

    // ----- test / client helpers (also used by the unit tests) -------------

    /// Builds a TSIG-signed UPDATE request (what D2 sends).
    pub struct UpdateBuilder {
        pub id: u16,
        pub zone: Labels,
        pub prereq: Vec<Vec<u8>>,
        pub update: Vec<Vec<u8>>,
    }

    pub fn rr_bytes(name: &Labels, rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut v = name_wire(name);
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&class.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    impl UpdateBuilder {
        pub fn new(id: u16, zone: &str) -> Self {
            Self {
                id,
                zone: parse_text_name(zone),
                prereq: vec![],
                update: vec![],
            }
        }
        pub fn build(&self) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&self.id.to_be_bytes());
            v.extend_from_slice(&((OP_UPDATE as u16) << 11).to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&(self.prereq.len() as u16).to_be_bytes());
            v.extend_from_slice(&(self.update.len() as u16).to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&name_wire(&self.zone));
            v.extend_from_slice(&T_SOA.to_be_bytes());
            v.extend_from_slice(&C_IN.to_be_bytes());
            for r in self.prereq.iter().chain(&self.update) {
                v.extend_from_slice(r);
            }
            v
        }
        /// Signed like D2 does it.
        pub fn signed(&self, alg: &str, key: &str, secret: &[u8], now: u64) -> (Vec<u8>, Vec<u8>) {
            let mut msg = self.build();
            let key_l = parse_text_name(key);
            let alg_l = alg_labels(alg);
            let mut input = msg.clone();
            input.extend_from_slice(&tsig_vars(&key_l, &alg_l, now, 300, 0));
            let mac = hmac(alg, secret, &input);
            let mut rd = name_wire(&alg_l);
            rd.extend_from_slice(&now.to_be_bytes()[2..]);
            rd.extend_from_slice(&300u16.to_be_bytes());
            rd.extend_from_slice(&(mac.len() as u16).to_be_bytes());
            rd.extend_from_slice(&mac);
            rd.extend_from_slice(&self.id.to_be_bytes());
            rd.extend_from_slice(&[0, 0, 0, 0]);
            msg.extend_from_slice(&rr_bytes(&key_l, T_TSIG, C_ANY, 0, &rd));
            msg[10..12].copy_from_slice(&1u16.to_be_bytes());
            (msg, mac)
        }
    }
}

// ===========================================================================
// the record store and the RFC 2136 rules
// ===========================================================================

pub mod store {
    use super::wire::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    /// type -> [(ttl, rdata)]
    pub type RrSets = BTreeMap<u16, Vec<(u32, Vec<u8>)>>;

    /// name (absolute text) -> type -> [(ttl, rdata)]
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Records(pub BTreeMap<String, RrSets>);

    pub fn allowed_type(t: u16) -> bool {
        matches!(t, T_A | T_AAAA | T_PTR | T_DHCID)
    }

    impl Records {
        pub fn count(&self) -> usize {
            self.0
                .values()
                .map(|m| m.values().map(Vec::len).sum::<usize>())
                .sum()
        }

        fn set(&self, n: &str, t: u16) -> Option<&Vec<(u32, Vec<u8>)>> {
            self.0.get(n).and_then(|m| m.get(&t))
        }

        /// RFC 2136 section 3.2: prerequisite checks. `Err(rcode)` on failure.
        fn prereqs(&self, msg: &Msg, zone: &Labels) -> Result<(), u8> {
            // value dependent sets are compared as a whole
            let mut want: BTreeMap<(String, u16), Vec<Vec<u8>>> = BTreeMap::new();
            for r in &msg.prereq {
                if r.ttl != 0 {
                    return Err(FORMERR);
                }
                if !is_under(&r.name, zone) {
                    return Err(NOTZONE);
                }
                let n = name_text(&r.name);
                match (r.class, r.rtype) {
                    (C_ANY, T_ANY) => {
                        if !r.rdata.is_empty() {
                            return Err(FORMERR);
                        }
                        if !self.0.get(&n).is_some_and(|m| !m.is_empty()) {
                            return Err(NXDOMAIN);
                        }
                    }
                    (C_ANY, t) => {
                        if !r.rdata.is_empty() {
                            return Err(FORMERR);
                        }
                        if self.set(&n, t).is_none_or(|s| s.is_empty()) {
                            return Err(NXRRSET);
                        }
                    }
                    (C_NONE, T_ANY) => {
                        if !r.rdata.is_empty() {
                            return Err(FORMERR);
                        }
                        if self.0.get(&n).is_some_and(|m| !m.is_empty()) {
                            return Err(YXDOMAIN);
                        }
                    }
                    (C_NONE, t) => {
                        if !r.rdata.is_empty() {
                            return Err(FORMERR);
                        }
                        if self.set(&n, t).is_some_and(|s| !s.is_empty()) {
                            return Err(YXRRSET);
                        }
                    }
                    (C_IN, t) => want.entry((n, t)).or_default().push(r.rdata.clone()),
                    _ => return Err(FORMERR),
                }
            }
            for ((n, t), mut w) in want {
                w.sort();
                w.dedup();
                let mut have: Vec<Vec<u8>> = self
                    .set(&n, t)
                    .map(|s| s.iter().map(|x| x.1.clone()).collect())
                    .unwrap_or_default();
                have.sort();
                if have != w {
                    return Err(NXRRSET);
                }
            }
            Ok(())
        }

        /// Apply an UPDATE (zone already matched and signature checked). The
        /// store is only changed when every rule passes.
        pub fn update(&mut self, msg: &Msg, zone: &Labels, max_records: usize) -> Result<(), u8> {
            self.prereqs(msg, zone)?;
            // prescan (3.4.1)
            for r in &msg.update {
                if !is_under(&r.name, zone) {
                    return Err(NOTZONE);
                }
                match r.class {
                    C_IN => {
                        if !allowed_type(r.rtype) {
                            return Err(REFUSED);
                        }
                        let ok = match r.rtype {
                            T_A => r.rdata.len() == 4,
                            T_AAAA => r.rdata.len() == 16,
                            T_DHCID => !r.rdata.is_empty() && r.rdata.len() <= 64,
                            _ => !r.rdata.is_empty(),
                        };
                        if !ok {
                            return Err(FORMERR);
                        }
                    }
                    C_ANY => {
                        if r.ttl != 0 || !r.rdata.is_empty() {
                            return Err(FORMERR);
                        }
                        if r.rtype != T_ANY && !allowed_type(r.rtype) {
                            return Err(REFUSED);
                        }
                    }
                    C_NONE => {
                        if r.ttl != 0 {
                            return Err(FORMERR);
                        }
                        if !allowed_type(r.rtype) {
                            return Err(REFUSED);
                        }
                    }
                    _ => return Err(FORMERR),
                }
            }
            let mut next = self.clone();
            for r in &msg.update {
                let n = name_text(&r.name);
                match r.class {
                    C_IN => {
                        let set = next.0.entry(n).or_default().entry(r.rtype).or_default();
                        if let Some(e) = set.iter_mut().find(|e| e.1 == r.rdata) {
                            e.0 = r.ttl;
                        } else {
                            set.push((r.ttl, r.rdata.clone()));
                        }
                    }
                    C_ANY if r.rtype == T_ANY => {
                        next.0.remove(&n);
                    }
                    C_ANY => {
                        if let Some(m) = next.0.get_mut(&n) {
                            m.remove(&r.rtype);
                        }
                    }
                    _ => {
                        if let Some(m) = next.0.get_mut(&n) {
                            if let Some(s) = m.get_mut(&r.rtype) {
                                s.retain(|e| e.1 != r.rdata);
                            }
                        }
                    }
                }
                if let Some(m) = next.0.get_mut(&name_text(&r.name)) {
                    m.retain(|_, s| !s.is_empty());
                }
            }
            next.0.retain(|_, m| !m.is_empty());
            if next.count() > max_records {
                return Err(REFUSED);
            }
            *self = next;
            Ok(())
        }

        /// Records as Unbound `local-data` lines (A, AAAA, PTR; DHCID is bookkeeping).
        pub fn unbound_lines(&self) -> Vec<String> {
            let mut v = Vec::new();
            for (n, m) in &self.0 {
                for (t, set) in m {
                    for (ttl, rd) in set {
                        let val = match *t {
                            T_A if rd.len() == 4 => {
                                format!("A {}", std::net::Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))
                            }
                            T_AAAA if rd.len() == 16 => {
                                let mut o = [0u8; 16];
                                o.copy_from_slice(rd);
                                format!("AAAA {}", std::net::Ipv6Addr::from(o))
                            }
                            T_PTR => {
                                let mut p = 0;
                                match read_name(rd, &mut p) {
                                    Some(l) => format!("PTR {}", name_text(&l)),
                                    None => continue,
                                }
                            }
                            _ => continue,
                        };
                        v.push(format!("{n} {ttl} IN {val}"));
                    }
                }
            }
            v
        }

        /// Presentation form for the page: (name, type, value, ttl).
        pub fn listing(&self, limit: usize) -> (Vec<serde_json::Value>, bool) {
            let mut out = Vec::new();
            let mut cut = false;
            'o: for (n, m) in &self.0 {
                for (t, set) in m {
                    if *t == T_DHCID {
                        continue;
                    }
                    for line in self.unbound_lines_of(n, *t, set) {
                        if out.len() >= limit {
                            cut = true;
                            break 'o;
                        }
                        out.push(line);
                    }
                }
            }
            (out, cut)
        }

        fn unbound_lines_of(
            &self,
            n: &str,
            t: u16,
            set: &[(u32, Vec<u8>)],
        ) -> Vec<serde_json::Value> {
            let mut one = Records::default();
            one.0
                .entry(n.to_string())
                .or_default()
                .insert(t, set.to_vec());
            one.unbound_lines()
                .into_iter()
                .map(|l| {
                    let p: Vec<&str> = l.splitn(5, ' ').collect();
                    serde_json::json!({"name": p[0], "ttl": p[1].parse::<u32>().unwrap_or(0), "type": p[3], "value": p.get(4).unwrap_or(&"")})
                })
                .collect()
        }
    }

    /// Which zone (of the configured ones) the message's zone section names.
    pub fn match_zone(msg: &Msg, zones: &[Labels]) -> Result<Labels, u8> {
        if msg.zone.len() != 1 {
            return Err(FORMERR);
        }
        let (n, t, c) = &msg.zone[0];
        if *t != T_SOA || *c != C_IN {
            return Err(FORMERR);
        }
        zones.iter().find(|z| *z == n).cloned().ok_or(NOTAUTH)
    }
}

// ===========================================================================
// the receiver process
// ===========================================================================

pub mod engine {
    use super::store::{match_zone, Records};
    use super::wire::*;
    use super::SinkConf;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub struct Core {
        pub conf: SinkConf,
        secret: Vec<u8>,
        zones: Vec<Labels>,
        key: Labels,
        pub recs: Mutex<Records>,
        pub ok: AtomicU64,
        pub refused: AtomicU64,
        pub bad_sig: AtomicU64,
        pub push_errors: AtomicU64,
        pub last_error: Mutex<String>,
        pub last_update: AtomicU64,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    impl Core {
        pub fn new(conf: SinkConf, recs: Records) -> Result<Self, String> {
            use base64::Engine as _;
            let secret = base64::engine::general_purpose::STANDARD
                .decode(conf.secret.trim())
                .map_err(|e| format!("TSIG secret is not base64: {e}"))?;
            let zones = conf.zones.iter().map(|z| parse_text_name(z)).collect();
            let key = parse_text_name(&conf.key_name);
            Ok(Self {
                conf,
                secret,
                zones,
                key,
                recs: Mutex::new(recs),
                ok: 0.into(),
                refused: 0.into(),
                bad_sig: 0.into(),
                push_errors: 0.into(),
                last_error: Mutex::new(String::new()),
                last_update: 0.into(),
            })
        }

        /// One datagram (or TCP message) in, the answer out (None = no answer).
        pub fn handle(&self, m: &[u8], at: u64) -> Option<Vec<u8>> {
            let msg = parse(m)?;
            if msg.is_response() {
                return None;
            }
            if msg.opcode() != OP_UPDATE {
                return Some(error_reply(&msg, NOTIMP));
            }
            // signature first: an unsigned or wrongly signed update changes nothing
            let t = match tsig_of(m, &msg) {
                Some(t) => t,
                None => {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return Some(error_reply(&msg, REFUSED));
                }
            };
            let req_mac = match verify_request(
                m,
                &t,
                &self.conf.algorithm,
                &self.key,
                &self.secret,
                at,
                self.conf.fudge,
            ) {
                Ok(mac) => mac,
                Err(_) => {
                    self.bad_sig.fetch_add(1, Ordering::Relaxed);
                    return Some(error_reply(&msg, NOTAUTH));
                }
            };
            let rcode = self.apply(&msg);
            if rcode == NOERROR {
                self.ok.fetch_add(1, Ordering::Relaxed);
                self.last_update.store(at, Ordering::Relaxed);
            } else {
                self.refused.fetch_add(1, Ordering::Relaxed);
            }
            let body = response(&msg, rcode);
            Some(sign_response(
                body,
                &self.conf.algorithm,
                &self.key,
                &self.secret,
                &req_mac,
                at,
                self.conf.fudge as u16,
            ))
        }

        fn apply(&self, msg: &Msg) -> u8 {
            let zone = match match_zone(msg, &self.zones) {
                Ok(z) => z,
                Err(e) => return e,
            };
            let mut recs = self.recs.lock().unwrap_or_else(|e| e.into_inner());
            match recs.update(msg, &zone, self.conf.max_records as usize) {
                Ok(()) => {
                    if let Err(e) = save(Path::new(&self.conf.state_file), &recs) {
                        eprintln!("kea-ddns: cannot save {}: {e}", self.conf.state_file);
                    }
                    NOERROR
                }
                Err(c) => c,
            }
        }
    }

    fn error_reply(msg: &Msg, rcode: u8) -> Vec<u8> {
        response(msg, rcode)
    }

    pub fn save(p: &Path, r: &Records) -> std::io::Result<()> {
        let tmp = p.with_extension("tmp");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(serde_json::to_string(r).unwrap_or_default().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, p)
    }

    pub fn load_state(p: &Path, zones: &[Labels]) -> Records {
        let mut r: Records = std::fs::read_to_string(p)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        // a zone that was removed from the configuration takes its records along
        r.0.retain(|n, _| zones.iter().any(|z| is_under(&parse_text_name(n), z)));
        r
    }

    // ----- Unbound -------------------------------------------------------

    fn unbound_control(sock: &str, args: &[&str], stdin: Option<&str>) -> Result<(), String> {
        let bin = crate::supervise::which("unbound-control")
            .ok_or_else(|| "unbound-control is not installed".to_string())?;
        let mut c = Command::new(bin);
        c.arg("-s").arg(sock).args(args);
        c.stdout(Stdio::null()).stderr(Stdio::piped());
        if stdin.is_some() {
            c.stdin(Stdio::piped());
        }
        let mut ch = c.spawn().map_err(|e| e.to_string())?;
        if let (Some(s), Some(mut i)) = (stdin, ch.stdin.take()) {
            i.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
        }
        let o = ch.wait_with_output().map_err(|e| e.to_string())?;
        if o.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
        }
    }

    /// Make the running Unbound hold exactly these records: reverse zones
    /// transparent, names we hold re-added. Names that vanished since the last
    /// push are removed.
    pub fn push(core: &Core, last: &mut Vec<String>) -> Result<(), String> {
        let sock = &core.conf.unbound_socket;
        if sock.is_empty() {
            return Ok(());
        }
        let recs = core.recs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let lines = recs.unbound_lines();
        let names: Vec<String> = recs.0.keys().cloned().collect();
        for z in &core.conf.zones {
            unbound_control(sock, &["local_zone", &format!("{z}."), "transparent"], None)?;
        }
        for gone in last.iter().filter(|n| !names.contains(n)) {
            unbound_control(sock, &["local_data_remove", gone], None)?;
        }
        // a name's data is replaced as a whole, so a deleted address disappears
        for n in &names {
            unbound_control(sock, &["local_data_remove", n], None)?;
        }
        let mut input = lines.join("\n");
        input.push('\n');
        if !lines.is_empty() {
            unbound_control(sock, &["local_datas"], Some(&input))?;
        }
        *last = names;
        Ok(())
    }

    // ----- sockets --------------------------------------------------------

    fn serve_udp(core: Arc<Core>, s: UdpSocket) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = match s.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if let Some(r) = core.handle(&buf[..n], now()) {
                let _ = s.send_to(&r, from);
            }
        }
    }

    fn serve_tcp(core: Arc<Core>, l: TcpListener) {
        let live = Arc::new(AtomicU64::new(0));
        for st in l.incoming().flatten() {
            if live.load(Ordering::Relaxed) >= 16 {
                continue;
            }
            live.fetch_add(1, Ordering::Relaxed);
            let (core, live) = (core.clone(), live.clone());
            std::thread::spawn(move || {
                let mut st = st;
                let _ = st.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = st.set_write_timeout(Some(Duration::from_secs(5)));
                let mut lenb = [0u8; 2];
                while st.read_exact(&mut lenb).is_ok() {
                    let n = u16::from_be_bytes(lenb) as usize;
                    if n == 0 || n > 16384 {
                        break;
                    }
                    let mut m = vec![0u8; n];
                    if st.read_exact(&mut m).is_err() {
                        break;
                    }
                    match core.handle(&m, now()) {
                        Some(r) => {
                            let mut o = (r.len() as u16).to_be_bytes().to_vec();
                            o.extend_from_slice(&r);
                            if st.write_all(&o).is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                live.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    fn write_stats(core: &Core, p: &Path, pushed: bool) {
        let (names, cut) = core
            .recs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .listing(500);
        let total = core.recs.lock().unwrap_or_else(|e| e.into_inner()).count();
        let v = serde_json::json!({
            "updates_ok": core.ok.load(Ordering::Relaxed),
            "updates_refused": core.refused.load(Ordering::Relaxed),
            "bad_signature": core.bad_sig.load(Ordering::Relaxed),
            "records": total,
            "zones": core.conf.zones,
            "last_update": core.last_update.load(Ordering::Relaxed),
            "unbound_ok": pushed,
            "push_errors": core.push_errors.load(Ordering::Relaxed),
            "last_error": *core.last_error.lock().unwrap_or_else(|e| e.into_inner()),
            "names": names,
            "truncated": cut,
            "at": now(),
        });
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, v.to_string()).is_ok() {
            let _ = std::fs::rename(tmp, p);
        }
    }

    /// Remove every record the receiver registered from the running Unbound and
    /// forget them (Kea DDNS was switched off). Returns how many names went.
    pub fn withdraw(state_file: &Path, unbound_socket: &str) -> usize {
        let recs = load_state(state_file, &[Vec::new()]);
        let names: Vec<String> = recs.0.keys().cloned().collect();
        if !unbound_socket.is_empty() {
            for n in &names {
                let _ = unbound_control(unbound_socket, &["local_data_remove", n], None);
            }
        }
        let _ = std::fs::remove_file(state_file);
        names.len()
    }

    /// Run until killed.
    pub fn run(conf_path: &Path, stats: Option<&Path>) -> Result<(), String> {
        let conf: SinkConf = serde_json::from_str(
            &std::fs::read_to_string(conf_path)
                .map_err(|e| format!("{}: {e}", conf_path.display()))?,
        )
        .map_err(|e| format!("{}: {e}", conf_path.display()))?;
        let zones: Vec<Labels> = conf.zones.iter().map(|z| parse_text_name(z)).collect();
        let recs = load_state(Path::new(&conf.state_file), &zones);
        let addr: SocketAddr = format!("{}:{}", conf.listen, conf.port)
            .parse()
            .map_err(|e| format!("listen address: {e}"))?;
        let core = Arc::new(Core::new(conf, recs)?);
        let udp = UdpSocket::bind(addr).map_err(|e| format!("udp {addr}: {e}"))?;
        let tcp = TcpListener::bind(addr).map_err(|e| format!("tcp {addr}: {e}"))?;
        {
            let c = core.clone();
            std::thread::spawn(move || serve_udp(c, udp));
            let c = core.clone();
            std::thread::spawn(move || serve_tcp(c, tcp));
        }
        let mut last: Vec<String> = Vec::new();
        let every = Duration::from_secs(core.conf.push_interval.max(1));
        loop {
            let pushed = match push(&core, &mut last) {
                Ok(()) => true,
                Err(e) => {
                    core.push_errors.fetch_add(1, Ordering::Relaxed);
                    *core.last_error.lock().unwrap_or_else(|x| x.into_inner()) = e;
                    false
                }
            };
            if let Some(p) = stats {
                write_stats(&core, p, pushed);
            }
            std::thread::sleep(every);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::engine::Core;
    use super::store::Records;
    use super::wire::*;
    use super::*;

    const SECRET_B64: &str = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ=";

    fn secret() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(SECRET_B64)
            .unwrap()
    }

    fn core(zones: &[&str], max: u64) -> Core {
        let conf = SinkConf {
            listen: "127.0.0.1".into(),
            port: 0,
            key_name: "k1".into(),
            algorithm: "hmac-sha256".into(),
            secret: SECRET_B64.into(),
            zones: zones.iter().map(|s| s.to_string()).collect(),
            max_records: max,
            state_file: std::env::temp_dir()
                .join(format!(
                    "kd-{}-{}.json",
                    std::process::id(),
                    zones.join("_")
                ))
                .to_string_lossy()
                .into(),
            unbound_socket: String::new(),
            push_interval: 5,
            fudge: 300,
        };
        Core::new(conf, Records::default()).unwrap()
    }

    fn n(s: &str) -> Labels {
        parse_text_name(s)
    }

    fn a_rr(name: &str, ip: [u8; 4]) -> Vec<u8> {
        rr_bytes(&n(name), T_A, C_IN, 300, &ip)
    }
    fn dhcid(name: &str, d: &[u8]) -> Vec<u8> {
        rr_bytes(&n(name), T_DHCID, C_IN, 300, d)
    }
    /// the same record as a prerequisite (RFC 2136: TTL 0)
    fn dhcid_pre(name: &str, d: &[u8]) -> Vec<u8> {
        rr_bytes(&n(name), T_DHCID, C_IN, 0, d)
    }

    fn rcode(r: &[u8]) -> u8 {
        r[3] & 0xf
    }

    fn send(c: &Core, b: &UpdateBuilder, at: u64) -> Vec<u8> {
        let (m, _) = b.signed("hmac-sha256", "k1", &secret(), at);
        c.handle(&m, at).expect("answer")
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // test case 2 of RFC 4231
        let mac = hmac("hmac-sha256", b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let mac = hmac("hmac-sha512", b"Jefe", b"what do ya want for nothing?");
        assert!(hex(&mac).starts_with("164b7a7bfcf819e2e395fbe73b56e0a3"));
        // a key longer than the block is hashed first
        assert_eq!(hmac("hmac-sha256", &[0xaa; 131], b"x").len(), 32);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_signed_add_registers_the_name_and_the_answer_is_signed() {
        let c = core(&["lan.example"], 100);
        let mut b = UpdateBuilder::new(7, "lan.example");
        // D2's first try: the name must not be in use, then add A and DHCID
        b.prereq
            .push(rr_bytes(&n("pc1.lan.example"), T_ANY, C_NONE, 0, &[]));
        b.update.push(a_rr("pc1.lan.example", [192, 168, 50, 100]));
        b.update.push(dhcid("pc1.lan.example", &[0, 1, 1, 9, 9, 9]));
        let (m, req_mac) = b.signed("hmac-sha256", "k1", &secret(), 1000);
        let r = c.handle(&m, 1000).unwrap();
        assert_eq!(rcode(&r), NOERROR);
        // the response carries a TSIG that verifies against the request's MAC
        let p = parse(&r).unwrap();
        let t = tsig_of(&r, &p).expect("signed answer");
        let mut input = Vec::new();
        input.extend_from_slice(&(req_mac.len() as u16).to_be_bytes());
        input.extend_from_slice(&req_mac);
        input.extend_from_slice(&r[..t.start]);
        input[2 + req_mac.len() + 10..2 + req_mac.len() + 12].copy_from_slice(&0u16.to_be_bytes());
        let key = n("k1");
        let mut vars = name_wire(&key);
        vars.extend_from_slice(&C_ANY.to_be_bytes());
        vars.extend_from_slice(&0u32.to_be_bytes());
        vars.extend_from_slice(&name_wire(&alg_labels("hmac-sha256")));
        vars.extend_from_slice(&t.time.to_be_bytes()[2..]);
        vars.extend_from_slice(&t.fudge.to_be_bytes());
        vars.extend_from_slice(&[0, 0, 0, 0]);
        input.extend_from_slice(&vars);
        assert!(ct_eq(&hmac("hmac-sha256", &secret(), &input), &t.mac));
        let lines = c.recs.lock().unwrap().unbound_lines();
        assert_eq!(
            lines,
            vec!["pc1.lan.example. 300 IN A 192.168.50.100".to_string()]
        );
        // the same name again: "name not in use" now fails with YXDOMAIN, D2 then replaces
        let r = send(&c, &b, 1001);
        assert_eq!(rcode(&r), YXDOMAIN);
        let mut b2 = UpdateBuilder::new(8, "lan.example");
        b2.prereq
            .push(dhcid_pre("pc1.lan.example", &[0, 1, 1, 9, 9, 9]));
        b2.update
            .push(rr_bytes(&n("pc1.lan.example"), T_A, C_ANY, 0, &[]));
        b2.update.push(a_rr("pc1.lan.example", [192, 168, 50, 101]));
        assert_eq!(rcode(&send(&c, &b2, 1002)), NOERROR);
        assert_eq!(
            c.recs.lock().unwrap().unbound_lines(),
            vec!["pc1.lan.example. 300 IN A 192.168.50.101".to_string()]
        );
        // a different client's DHCID must not take the name over
        let mut b3 = UpdateBuilder::new(9, "lan.example");
        b3.prereq
            .push(dhcid_pre("pc1.lan.example", &[0, 1, 1, 1, 1, 1]));
        b3.update
            .push(rr_bytes(&n("pc1.lan.example"), T_A, C_ANY, 0, &[]));
        b3.update.push(a_rr("pc1.lan.example", [10, 9, 9, 9]));
        assert_eq!(rcode(&send(&c, &b3, 1003)), NXRRSET);
        assert!(c.recs.lock().unwrap().unbound_lines()[0].ends_with("192.168.50.101"));
    }

    #[test]
    fn delete_removes_the_records_and_ptr_works() {
        let c = core(&["lan.example", "50.168.192.in-addr.arpa"], 100);
        let mut b = UpdateBuilder::new(1, "lan.example");
        b.update.push(a_rr("pc1.lan.example", [192, 168, 50, 100]));
        b.update.push(dhcid("pc1.lan.example", &[1, 2, 3]));
        assert_eq!(rcode(&send(&c, &b, 5)), NOERROR);
        let mut r = UpdateBuilder::new(2, "50.168.192.in-addr.arpa");
        let ptr = name_wire(&n("pc1.lan.example"));
        r.update.push(rr_bytes(
            &n("100.50.168.192.in-addr.arpa"),
            T_PTR,
            C_ANY,
            0,
            &[],
        ));
        r.update.push(rr_bytes(
            &n("100.50.168.192.in-addr.arpa"),
            T_PTR,
            C_IN,
            300,
            &ptr,
        ));
        assert_eq!(rcode(&send(&c, &r, 6)), NOERROR);
        let l = c.recs.lock().unwrap().unbound_lines();
        assert!(
            l.contains(&"100.50.168.192.in-addr.arpa. 300 IN PTR pc1.lan.example.".to_string()),
            "{l:?}"
        );
        // delete forward: DHCID must match, then drop A and DHCID
        let mut d = UpdateBuilder::new(3, "lan.example");
        d.prereq.push(dhcid_pre("pc1.lan.example", &[1, 2, 3]));
        d.update
            .push(rr_bytes(&n("pc1.lan.example"), T_A, C_ANY, 0, &[]));
        d.update.push(rr_bytes(
            &n("pc1.lan.example"),
            T_DHCID,
            C_NONE,
            0,
            &[1, 2, 3],
        ));
        assert_eq!(rcode(&send(&c, &d, 7)), NOERROR);
        let mut dr = UpdateBuilder::new(4, "50.168.192.in-addr.arpa");
        dr.update.push(rr_bytes(
            &n("100.50.168.192.in-addr.arpa"),
            T_PTR,
            C_ANY,
            0,
            &[],
        ));
        assert_eq!(rcode(&send(&c, &dr, 8)), NOERROR);
        assert_eq!(c.recs.lock().unwrap().count(), 0);
    }

    #[test]
    fn unsigned_badly_signed_and_stale_updates_change_nothing() {
        let c = core(&["lan.example"], 100);
        let mut b = UpdateBuilder::new(1, "lan.example");
        b.update.push(a_rr("x.lan.example", [1, 2, 3, 4]));
        // no TSIG at all
        assert_eq!(rcode(&c.handle(&b.build(), 10).unwrap()), REFUSED);
        // wrong secret
        let (m, _) = b.signed("hmac-sha256", "k1", b"another secret entirely", 10);
        assert_eq!(rcode(&c.handle(&m, 10).unwrap()), NOTAUTH);
        // wrong key name
        let (m, _) = b.signed("hmac-sha256", "k2", &secret(), 10);
        assert_eq!(rcode(&c.handle(&m, 10).unwrap()), NOTAUTH);
        // wrong algorithm name for the key
        let (m, _) = b.signed("hmac-sha512", "k1", &secret(), 10);
        assert_eq!(rcode(&c.handle(&m, 10).unwrap()), NOTAUTH);
        // replayed an hour later
        let (m, _) = b.signed("hmac-sha256", "k1", &secret(), 10);
        assert_eq!(rcode(&c.handle(&m, 10 + 3600).unwrap()), NOTAUTH);
        // a flipped byte in the body
        let (mut m, _) = b.signed("hmac-sha256", "k1", &secret(), 10);
        m[20] ^= 1;
        assert_ne!(rcode(&c.handle(&m, 10).unwrap()), NOERROR);
        assert_eq!(c.recs.lock().unwrap().count(), 0);
        assert!(c.bad_sig.load(std::sync::atomic::Ordering::Relaxed) >= 4);
    }

    #[test]
    fn zone_limits_types_and_the_record_cap_are_enforced() {
        let c = core(&["lan.example"], 3);
        // not a zone we serve
        let mut b = UpdateBuilder::new(1, "evil.example");
        b.update.push(a_rr("a.evil.example", [1, 1, 1, 1]));
        assert_eq!(rcode(&send(&c, &b, 1)), NOTAUTH);
        // a name outside the zone inside a lan.example update
        let mut b = UpdateBuilder::new(2, "lan.example");
        b.update.push(a_rr("a.evil.example", [1, 1, 1, 1]));
        assert_eq!(rcode(&send(&c, &b, 1)), NOTZONE);
        // a type we do not keep (TXT, MX, NS)
        for t in [16u16, 15, 2] {
            let mut b = UpdateBuilder::new(3, "lan.example");
            b.update
                .push(rr_bytes(&n("a.lan.example"), t, C_IN, 300, &[1, 2, 3, 4]));
            assert_eq!(rcode(&send(&c, &b, 1)), REFUSED, "type {t}");
        }
        // an A record that is not 4 bytes
        let mut b = UpdateBuilder::new(4, "lan.example");
        b.update
            .push(rr_bytes(&n("a.lan.example"), T_A, C_IN, 300, &[1, 2, 3]));
        assert_eq!(rcode(&send(&c, &b, 1)), FORMERR);
        // the cap: three records fit, the fourth is refused and nothing of that update stays
        for i in 0..3u8 {
            let mut b = UpdateBuilder::new(10 + i as u16, "lan.example");
            b.update
                .push(a_rr(&format!("h{i}.lan.example"), [10, 0, 0, i]));
            assert_eq!(rcode(&send(&c, &b, 1)), NOERROR);
        }
        let mut b = UpdateBuilder::new(20, "lan.example");
        b.update.push(a_rr("h9.lan.example", [10, 0, 0, 9]));
        assert_eq!(rcode(&send(&c, &b, 1)), REFUSED);
        assert_eq!(c.recs.lock().unwrap().count(), 3);
        // a query is not served here
        let mut q = UpdateBuilder::new(30, "lan.example").build();
        q[2] = 0; // opcode QUERY
        assert_eq!(rcode(&c.handle(&q, 1).unwrap()), NOTIMP);
    }

    #[test]
    fn compressed_names_and_ptr_rdata_parse() {
        // zone name compressed into the update name, PTR rdata pointing into the zone
        let mut m = Vec::new();
        m.extend_from_slice(&[0, 9, 0x28, 0, 0, 1, 0, 0, 0, 1, 0, 0]);
        let zone_off = m.len();
        m.extend_from_slice(&name_wire(&n("lan.example")));
        m.extend_from_slice(&[0, 6, 0, 1]);
        // "pc." + pointer to zone
        m.extend_from_slice(&[2, b'p', b'c', 0xc0, zone_off as u8]);
        m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 1, 44]);
        let rd = [2u8, b'h', b'q', 0xc0, zone_off as u8];
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        let p = parse(&m).unwrap();
        assert_eq!(name_text(&p.update[0].name), "pc.lan.example.");
        assert_eq!(p.update[0].rdata, name_wire(&n("hq.lan.example")));
        // a compression loop is refused, not followed forever
        let mut bad = m.clone();
        bad[zone_off] = 0xc0;
        bad[zone_off + 1] = zone_off as u8;
        assert!(parse(&bad).is_none());
        // truncated
        assert!(parse(&m[..m.len() - 3]).is_none());
    }

    #[test]
    fn reverse_zones_follow_the_subnet() {
        assert_eq!(
            reverse_zone("192.168.50.0/24").unwrap(),
            "50.168.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_zone("192.168.50.128/25").unwrap(),
            "50.168.192.in-addr.arpa"
        );
        assert_eq!(reverse_zone("10.1.0.0/16").unwrap(), "1.10.in-addr.arpa");
        assert_eq!(reverse_zone("10.0.0.0/8").unwrap(), "10.in-addr.arpa");
        assert_eq!(
            reverse_zone("fd00:50::/64").unwrap(),
            "0.0.0.0.0.0.0.0.0.5.0.0.0.0.d.f.ip6.arpa"
        );
        assert!(reverse_zone("nonsense").is_none());
    }

    #[test]
    fn config_files_carry_the_zones_and_never_leak_through_render() {
        let p = Plan {
            local: true,
            forward_zone: "lan.example".into(),
            reverse_zones: vec!["50.168.192.in-addr.arpa".into()],
            key_name: "patronus-ddns".into(),
            algorithm: "hmac-sha256".into(),
            secret: SECRET_B64.into(),
            server: "127.0.0.1".into(),
            server_port: 53,
            d2_port: 53001,
            local_port: 5335,
            override_client_update: false,
            replace_client_name: "when-not-present".into(),
            generated_prefix: "host".into(),
            update_on_renew: false,
            max_records: 100,
        };
        let d2 = render_d2(&p);
        let body: String = d2
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let j: Value = serde_json::from_str(&body).unwrap();
        let d = &j["DhcpDdns"];
        assert_eq!(d["port"], 53001);
        assert_eq!(d["tsig-keys"][0]["algorithm"], "HMAC-SHA256");
        assert_eq!(d["forward-ddns"]["ddns-domains"][0]["name"], "lan.example.");
        assert_eq!(
            d["forward-ddns"]["ddns-domains"][0]["dns-servers"][0]["port"],
            5335
        );
        assert_eq!(
            d["reverse-ddns"]["ddns-domains"][0]["name"],
            "50.168.192.in-addr.arpa."
        );
        // external mode points D2 at the configured server
        let ext = Plan {
            local: false,
            server: "203.0.113.53".into(),
            server_port: 5300,
            ..p.clone()
        };
        let body: String = render_d2(&ext)
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let j: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            j["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]["dns-servers"][0]["ip-address"],
            "203.0.113.53"
        );
        let side = DhcpSide {
            d2_port: 53001,
            suffix: "lan.example".into(),
            override_client_update: true,
            replace_client_name: "always".into(),
            generated_prefix: "host".into(),
            update_on_renew: false,
        };
        let k: std::collections::BTreeMap<_, _> = kea_block(&side).into_iter().collect();
        assert_eq!(k["dhcp-ddns"]["server-port"], 53001);
        assert_eq!(k["ddns-qualifying-suffix"], "lan.example.");
        assert_eq!(k["ddns-override-client-update"], true);
        assert!(check_secret("not base64 !!").is_err());
        assert!(check_secret("AAAA").is_err(), "too short");
        assert!(check_secret(SECRET_B64).is_ok());
        assert!(check_zone("lan.example").is_ok());
        assert!(check_zone("bad zone;x").is_err());
    }
}
