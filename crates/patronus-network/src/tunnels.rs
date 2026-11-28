//! IP-in-IP, 6in4 and GIF-style tunnels (USE=tunnels): the plain kernel
//! encapsulations pfSense calls GIF and OPNsense calls GIF / 6in4 tunnels,
//! plus the Linux IPIP link, as a svc-framework page.
//!
//! * `ipip` - IPv4 inside IPv4 (IP protocol 4).
//! * `sit`  - IPv6 inside IPv4, "6in4" (IP protocol 41): tunnel-broker
//!   service tunnels (Hurricane Electric style), a routed /64 or /48 behind
//!   the router and a default IPv6 route over the tunnel.
//! * `gif`  - the BSD-style generic tunnel: IPv4 *and* IPv6 inside IPv4 on
//!   one link (Linux `sit` in `mode any`, accepting protocols 4 and 41).
//!
//! The outer header is IPv4 for all three. Every tunnel is a kernel link
//! named `tn-<name>` (the prefix is how the applier recognises its own links:
//! anything else is never touched). The applier (interfaces phase, so it runs
//! at boot on both init systems and in `patronus apply`) reconciles the
//! kernel with the store: creates, re-creates when the tunnel's kind or
//! endpoints changed, sets MTU, inner addresses and routes (route protocol
//! [`ROUTE_PROTO`]), removes stale `tn-*` links, and keeps one own nft table
//! (`inet patronus_tunnel`) that clamps TCP MSS to the path MTU for traffic
//! forwarded into or out of a tunnel. The firewall applier adds the accept
//! rules for the encapsulated protocols from each remote endpoint and for
//! ICMP/ICMPv6 on the tunnel links (`patronus-firewall` `svc_rules.rs`);
//! forwarding between a tunnel and the LAN is decided by the ordinary
//! firewall rules, which can name the link (`tn-<name>`) as an interface.
//!
//! An empty local address means "any local address" (the kernel picks the
//! source from the route to the remote), which is what a tunnel over a WAN
//! with a dynamic address needs.

use crate::lan::{self, invalid};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

/// Prefix of every link this module owns.
pub const PREFIX: &str = "tn-";
/// Route protocol of the routes this module installs (249 wireguard, 251-253 routes).
pub const ROUTE_PROTO: u8 = 248;
/// The module's own nft table (MSS clamp).
pub const NFT_TABLE: &str = "patronus_tunnel";
/// `ifalias` set on every owned link (a second guard beside the prefix).
pub const ALIAS: &str = "patronus-tunnel";

pub const KINDS: &[&str] = &["ipip", "sit", "gif"];

static FIELDS: [Field; 1] = [Field::new("clamp_mss", "Clamp TCP MSS to the tunnel MTU", Kind::Bool)
    .def("1")
    .help("TCP connections forwarded through a tunnel get an MSS that fits it, so a path that drops ICMP \"too big\" still works")];

static TUNNEL_FIELDS: [Field; 12] = [
    Field::new("name", "Name", Kind::Token)
        .req()
        .help("1-11 lowercase letters, digits, - or _; the link is tn-<name>"),
    Field::new("kind", "Type", Kind::Select(KINDS))
        .req()
        .def("sit")
        .help("ipip = IPv4 in IPv4, sit = IPv6 in IPv4 (6in4, tunnel brokers), gif = IPv4 and IPv6 in IPv4"),
    Field::new("remote", "Remote endpoint", Kind::Ipv4)
        .req()
        .help("the far end's public IPv4 address (the broker's server address)"),
    Field::new("local", "Local endpoint", Kind::Ipv4)
        .help("this router's IPv4 address on the tunnel; empty = any (use that behind a dynamic WAN address)"),
    Field::new("address", "Inner address", Kind::Cidr)
        .help("this end's address inside the tunnel with prefix length: IPv4 for ipip, IPv6 for sit (the broker's client address), either for gif"),
    Field::new("address2", "Second inner address", Kind::Cidr)
        .help("gif only: this end's address of the other family, so one GIF link carries IPv4 and IPv6"),
    Field::new("mtu", "MTU", Kind::Int(576, 9000))
        .def("1480")
        .help("1480 fits a 1500-byte uplink (20 bytes of outer header); lower it for PPPoE (1472) or other encapsulations"),
    Field::new("ttl", "TTL", Kind::Int(0, 255))
        .def("64")
        .help("outer packet TTL; 0 = copy the inner packet's"),
    Field::new("default_route", "Default route over the tunnel", Kind::Bool)
        .def("0")
        .help("install a default route (IPv6 for sit, IPv4 for ipip, the inner address's family for gif) with the metric below; a gateway set on the Routing page takes precedence"),
    Field::new("metric", "Route metric", Kind::Int(1, 9999)).def("1024"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static ROUTE_FIELDS: [Field; 3] = [
    Field::new("tunnel", "Tunnel", Kind::Token)
        .req()
        .help("the name of a tunnel above"),
    Field::new("destination", "Destination", Kind::Cidr)
        .req()
        .help("a network reached through the tunnel (a routed /48 or /64 from the broker is not listed here: it is on your LAN, not behind the tunnel)"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "tunnels",
    title: "IP tunnels (IPIP, 6in4, GIF)",
    blurb: "Point-to-point IP-in-IP tunnels over IPv4: IPIP, 6in4 (SIT: IPv6 over IPv4 for tunnel \
            brokers such as Hurricane Electric) and GIF-style generic tunnels carrying both \
            families. Each tunnel is a link named tn-<name>; use that name in firewall rules. \
            The firewall accepts the tunnel protocol only from the remote endpoint you enter.",
    applier: "tunnels",
    fields: &FIELDS,
    colls: &[
        Coll {
            key: "tunnels",
            title: "Tunnels",
            table: "ip_tunnels",
            fields: &TUNNEL_FIELDS,
            unique: Some("name"),
        },
        Coll {
            key: "routes",
            title: "Routes over a tunnel",
            table: "ip_tunnel_routes",
            fields: &ROUTE_FIELDS,
            unique: None,
        },
    ],
    actions: &[],
};

pub struct TunnelsSvc;

#[async_trait]
impl Svc for TunnelsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    /// Cross-field checks (inner address family vs tunnel type, endpoints)
    /// at save time, so the form refuses what the applier would refuse.
    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let c = svc::find_coll(&SPEC, coll)?;
        if coll == "tunnels" {
            let mut merged = match id {
                Some(id) => svc::raw_rows(store, c)
                    .await?
                    .into_iter()
                    .find(|r| r["id"].as_i64() == Some(id))
                    .ok_or_else(|| Error::Config(format!("no tunnels {id}")))?,
                None => serde_json::Map::new(),
            };
            if let Some(o) = body.as_object() {
                for (k, v) in o {
                    // a bad value is reported by the field check below
                    if let Some(s) = match v {
                        Value::String(s) => Some(s.trim().to_string()),
                        Value::Number(n) => Some(n.to_string()),
                        Value::Bool(b) => Some(if *b { "1" } else { "0" }.into()),
                        _ => None,
                    } {
                        merged.insert(k.clone(), Value::String(s));
                    }
                }
            }
            for f in TUNNEL_FIELDS.iter() {
                if !merged.contains_key(f.key) && !f.default.is_empty() {
                    merged.insert(f.key.into(), Value::String(f.default.into()));
                }
            }
            // field-level problems come first, in the framework's words
            for f in TUNNEL_FIELDS.iter() {
                if let Some(v) = body.get(f.key) {
                    svc::check(f, v)?;
                }
            }
            // `name` / `remote` missing on a partial body is the framework's
            // required-field error, reported by save_row below
            if merged.contains_key("name") && merged.contains_key("remote") {
                parse_tunnel(&merged)?;
            }
        }
        svc::save_row(store, c, id, body).await
    }
}

/// One tunnel as the applier sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub id: i64,
    pub name: String,
    /// `tn-<name>`
    pub dev: String,
    pub kind: String,
    pub local: Option<Ipv4Addr>,
    pub remote: Ipv4Addr,
    pub address: Option<String>,
    /// gif only: an address of the other family
    pub address2: Option<String>,
    pub mtu: u32,
    pub ttl: u32,
    pub default_route: bool,
    pub metric: u32,
    pub enabled: bool,
}

impl Tunnel {
    /// `ip link add ... type` arguments.
    pub fn create_args(&self) -> Vec<String> {
        let mut a: Vec<String> = ["link", "add", "name", &self.dev, "type"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (typ, mode) = match self.kind.as_str() {
            "ipip" => ("ipip", "ipip"),
            "sit" => ("sit", "ip6ip"),
            _ => ("sit", "any"),
        };
        a.push(typ.into());
        a.push("mode".into());
        a.push(mode.into());
        a.push("remote".into());
        a.push(self.remote.to_string());
        if let Some(l) = self.local {
            a.push("local".into());
            a.push(l.to_string());
        }
        a.push("ttl".into());
        a.push(self.ttl.to_string());
        a
    }

    /// The kernel's name for this tunnel's link type and (sit) mode.
    fn kernel(&self) -> (&'static str, &'static str) {
        match self.kind.as_str() {
            "ipip" => ("ipip", "ipip"),
            "sit" => ("sit", "ip6ip"),
            _ => ("sit", "any"),
        }
    }

    /// Every inner address this tunnel should carry.
    pub fn addrs(&self) -> Vec<String> {
        self.address
            .iter()
            .chain(self.address2.iter())
            .cloned()
            .collect()
    }

    fn addr_v6(&self) -> bool {
        self.address.as_deref().is_some_and(|a| a.contains(':'))
    }
}

/// `name` must be a short lowercase token: it becomes part of a kernel link
/// name (15 characters at most) and of nft rules.
pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 11
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// An endpoint address that can carry a tunnel at all.
fn usable_endpoint(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast())
}

fn text(r: &serde_json::Map<String, Value>, k: &str) -> String {
    r.get(k)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn num(r: &serde_json::Map<String, Value>, k: &str, d: u32) -> u32 {
    text(r, k).parse().unwrap_or(d)
}

/// Parse and cross-check one stored tunnel row.
pub fn parse_tunnel(r: &serde_json::Map<String, Value>) -> Result<Tunnel> {
    let name = text(r, "name");
    if !valid_name(&name) {
        return Err(invalid(format!(
            "tunnel name {name:?}: 1-11 lowercase letters, digits, - or _"
        )));
    }
    let kind = text(r, "kind");
    if !KINDS.contains(&kind.as_str()) {
        return Err(invalid(format!(
            "tunnel {name}: type must be one of {}",
            KINDS.join(", ")
        )));
    }
    let remote: Ipv4Addr = text(r, "remote")
        .parse()
        .map_err(|_| invalid(format!("tunnel {name}: remote endpoint must be an IPv4 address")))?;
    if !usable_endpoint(remote) {
        return Err(invalid(format!(
            "tunnel {name}: {remote} cannot be a remote endpoint"
        )));
    }
    let local = match text(r, "local").as_str() {
        "" => None,
        s => {
            let l: Ipv4Addr = s.parse().map_err(|_| {
                invalid(format!("tunnel {name}: local endpoint must be an IPv4 address"))
            })?;
            if !usable_endpoint(l) {
                return Err(invalid(format!(
                    "tunnel {name}: {l} cannot be a local endpoint"
                )));
            }
            if l == remote {
                return Err(invalid(format!(
                    "tunnel {name}: local and remote endpoint are the same address"
                )));
            }
            Some(l)
        }
    };
    let address = parse_inner(r, "address", &name, &kind)?;
    let address2 = parse_inner(r, "address2", &name, &kind)?;
    if let Some(a2) = &address2 {
        if kind != "gif" {
            return Err(invalid(format!(
                "tunnel {name}: a second inner address is for gif tunnels only"
            )));
        }
        let Some(a1) = &address else {
            return Err(invalid(format!(
                "tunnel {name}: the second inner address needs the first one"
            )));
        };
        if a1.contains(':') == a2.contains(':') {
            return Err(invalid(format!(
                "tunnel {name}: the two inner addresses must be one IPv4 and one IPv6"
            )));
        }
    }
    let mtu = num(r, "mtu", 1480);
    if !(576..=9000).contains(&mtu) {
        return Err(invalid(format!("tunnel {name}: MTU 576-9000")));
    }
    if [&address, &address2].iter().any(|a| matches!(a, Some(a) if a.contains(':'))) && mtu < 1280 {
        return Err(invalid(format!(
            "tunnel {name}: IPv6 needs an MTU of at least 1280"
        )));
    }
    let ttl = num(r, "ttl", 64);
    if ttl > 255 {
        return Err(invalid(format!("tunnel {name}: TTL 0-255")));
    }
    let default_route = lan::flag(&text(r, "default_route"));
    if default_route && address.is_none() {
        return Err(invalid(format!(
            "tunnel {name}: a default route over the tunnel needs an inner address"
        )));
    }
    Ok(Tunnel {
        id: r.get("id").and_then(Value::as_i64).unwrap_or(0),
        dev: format!("{PREFIX}{name}"),
        name,
        kind,
        local,
        remote,
        address,
        address2,
        mtu,
        ttl,
        default_route,
        metric: num(r, "metric", 1024).clamp(1, 9999),
        enabled: !matches!(text(r, "enabled").as_str(), "0" | "false" | "no" | "off"),
    })
}

/// One inner address field: valid for the tunnel type, normalised.
fn parse_inner(
    r: &serde_json::Map<String, Value>,
    key: &str,
    name: &str,
    kind: &str,
) -> Result<Option<String>> {
    let s = text(r, key);
    if s.is_empty() {
        return Ok(None);
    }
    let n: ipnetwork::IpNetwork = s
        .parse()
        .map_err(|_| invalid(format!("tunnel {name}: inner address {s:?}")))?;
    match (kind, &n) {
        ("ipip", ipnetwork::IpNetwork::V6(_)) => {
            return Err(invalid(format!(
                "tunnel {name}: an IPIP tunnel carries IPv4 only (use type sit or gif for IPv6)"
            )))
        }
        ("sit", ipnetwork::IpNetwork::V4(_)) => {
            return Err(invalid(format!(
                "tunnel {name}: a 6in4 (sit) tunnel carries IPv6 only (use type ipip or gif for IPv4)"
            )))
        }
        _ => {}
    }
    if n.ip().is_unspecified() || n.ip().is_multicast() || n.ip().is_loopback() {
        return Err(invalid(format!(
            "tunnel {name}: {} is not a usable inner address",
            n.ip()
        )));
    }
    if let ipnetwork::IpNetwork::V6(v6) = &n {
        if (v6.ip().segments()[0] & 0xffc0) == 0xfe80 {
            return Err(invalid(format!(
                "tunnel {name}: link-local inner addresses are assigned by the kernel"
            )));
        }
    }
    Ok(Some(format!("{}/{}", n.ip(), n.prefix())))
}

/// What the store asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub tunnels: Vec<Tunnel>,
    /// (device, destination CIDR)
    pub routes: Vec<(String, String)>,
    pub clamp_mss: bool,
}

/// Cross-check the rows: unique names, no two tunnels that would collide in
/// the kernel, route destinations of the tunnel's own families.
pub fn plan(
    tunnels: &[serde_json::Map<String, Value>],
    routes: &[serde_json::Map<String, Value>],
    clamp_mss: bool,
) -> Result<Plan> {
    let mut out = Plan {
        clamp_mss,
        ..Plan::default()
    };
    let mut names = BTreeSet::new();
    for r in tunnels {
        let t = parse_tunnel(r)?;
        if !names.insert(t.name.clone()) {
            return Err(invalid(format!("tunnel name {} is used twice", t.name)));
        }
        out.tunnels.push(t);
    }
    let live: Vec<&Tunnel> = out.tunnels.iter().filter(|t| t.enabled).collect();
    for (i, a) in live.iter().enumerate() {
        for b in &live[i + 1..] {
            // the kernel keys a tunnel by (protocol family, local, remote);
            // gif (mode any) overlaps both of the others
            let overlap = a.kernel().0 == b.kernel().0 && a.local == b.local && a.remote == b.remote
                && (a.kind == b.kind || a.kind == "gif" || b.kind == "gif");
            let any_overlap = a.remote == b.remote
                && a.local == b.local
                && (a.kind == "gif" || b.kind == "gif");
            if overlap || any_overlap {
                return Err(invalid(format!(
                    "tunnels {} and {} have the same endpoints and overlapping types; the kernel cannot tell their packets apart",
                    a.name, b.name
                )));
            }
        }
    }
    for r in routes {
        let t = text(r, "tunnel");
        let d = text(r, "destination");
        let Some(tun) = out.tunnels.iter().find(|x| x.name == t) else {
            return Err(invalid(format!("route {d} refers to the unknown tunnel {t:?}")));
        };
        let n: ipnetwork::IpNetwork = d
            .parse()
            .map_err(|_| invalid(format!("route destination {d:?}")))?;
        match (tun.kind.as_str(), &n) {
            ("ipip", ipnetwork::IpNetwork::V6(_)) | ("sit", ipnetwork::IpNetwork::V4(_)) => {
                return Err(invalid(format!(
                    "route {d} over tunnel {t}: the tunnel type does not carry that address family"
                )))
            }
            _ => {}
        }
        if tun.enabled {
            out.routes
                .push((tun.dev.clone(), format!("{}/{}", n.network(), n.prefix())));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// kernel
// ---------------------------------------------------------------------------

fn ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| Error::Network(format!("ip {}: {e}", args.join(" "))))?;
    if !out.status.success() {
        return Err(Error::Network(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A kernel link as `ip -j -d link` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KTun {
    pub dev: String,
    pub info_kind: String,
    pub proto: Option<String>,
    pub local: Option<String>,
    pub remote: Option<String>,
    pub ttl: Option<u32>,
    pub mtu: Option<u32>,
    pub alias: String,
    pub up: bool,
}

fn addr_opt(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    if s.is_empty() || s == "any" || s == "0.0.0.0" || s == "::" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse `ip -j -d link show` output (only ipip / sit links are returned).
pub fn parse_links(json: &str) -> Vec<KTun> {
    let Ok(Value::Array(v)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    v.iter()
        .filter_map(|l| {
            let li = l.get("linkinfo")?;
            let kind = li.get("info_kind")?.as_str()?;
            if kind != "ipip" && kind != "sit" {
                return None;
            }
            let d = li.get("info_data");
            Some(KTun {
                dev: l.get("ifname")?.as_str()?.to_string(),
                info_kind: kind.to_string(),
                proto: d
                    .and_then(|d| d.get("proto"))
                    .and_then(Value::as_str)
                    .map(String::from),
                local: addr_opt(d.and_then(|d| d.get("local"))),
                remote: addr_opt(d.and_then(|d| d.get("remote"))),
                ttl: d
                    .and_then(|d| d.get("ttl"))
                    .and_then(Value::as_u64)
                    .map(|t| t as u32),
                mtu: l.get("mtu").and_then(Value::as_u64).map(|m| m as u32),
                alias: l
                    .get("ifalias")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                up: l
                    .get("flags")
                    .and_then(Value::as_array)
                    .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("UP"))),
            })
        })
        .collect()
}

/// Is the existing link already this tunnel (no re-creation needed)?
pub fn matches_kernel(t: &Tunnel, k: &KTun) -> bool {
    let (typ, mode) = t.kernel();
    if k.info_kind != typ {
        return false;
    }
    if k.remote.as_deref() != Some(&t.remote.to_string()) {
        return false;
    }
    if k.local != t.local.map(|l| l.to_string()) {
        return false;
    }
    if let Some(ttl) = k.ttl {
        if ttl != t.ttl {
            return false;
        }
    }
    // the sit mode is only reported by newer iproute2: compare when present
    if typ == "sit" {
        if let Some(p) = &k.proto {
            if p != mode {
                return false;
            }
        }
    }
    true
}

fn links() -> Vec<KTun> {
    parse_links(&ip(&["-j", "-d", "link", "show"]).unwrap_or_default())
}

fn addrs_of(dev: &str) -> Vec<String> {
    let out = ip(&["-j", "addr", "show", "dev", dev]).unwrap_or_default();
    let Ok(Value::Array(v)) = serde_json::from_str::<Value>(&out) else {
        return Vec::new();
    };
    v.iter()
        .flat_map(|l| {
            l.get("addr_info")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter(|a| a.get("scope").and_then(Value::as_str) == Some("global"))
        .filter_map(|a| {
            Some(format!(
                "{}/{}",
                a.get("local")?.as_str()?,
                a.get("prefixlen")?.as_u64()?
            ))
        })
        .collect()
}

/// Routes of protocol [`ROUTE_PROTO`] (family flag `-4` / `-6`): (dst, dev).
fn own_routes(fam: &str) -> Vec<(String, String)> {
    let out = ip(&[fam, "-j", "route", "show", "proto", &ROUTE_PROTO.to_string()])
        .unwrap_or_default();
    let Ok(Value::Array(v)) = serde_json::from_str::<Value>(&out) else {
        return Vec::new();
    };
    v.iter()
        .filter_map(|r| {
            Some((
                r.get("dst")?.as_str()?.to_string(),
                r.get("dev")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn canonical(dst: &str) -> String {
    if dst == "default" {
        return dst.into();
    }
    match dst.parse::<ipnetwork::IpNetwork>() {
        Ok(n) => format!("{}/{}", n.network(), n.prefix()),
        Err(_) => match dst.parse::<IpAddr>() {
            // the kernel prints a host route without a prefix
            Ok(IpAddr::V4(a)) => format!("{a}/32"),
            Ok(IpAddr::V6(a)) => format!("{a}/128"),
            Err(_) => dst.into(),
        },
    }
}

/// (family flag, destination) for every route the plan wants, with `default`
/// spelled out.
pub fn wanted_routes(p: &Plan) -> BTreeMap<(String, String), (String, u32)> {
    let mut m = BTreeMap::new();
    for t in p.tunnels.iter().filter(|t| t.enabled) {
        if t.default_route && t.address.is_some() {
            let v6 = t.addr_v6();
            m.insert(
                (
                    if v6 { "-6" } else { "-4" }.to_string(),
                    "default".to_string(),
                ),
                (t.dev.clone(), t.metric),
            );
        }
    }
    for (dev, dst) in &p.routes {
        let fam = if dst.contains(':') { "-6" } else { "-4" };
        let metric = p
            .tunnels
            .iter()
            .find(|t| &t.dev == dev)
            .map(|t| t.metric)
            .unwrap_or(1024);
        m.insert((fam.to_string(), canonical(dst)), (dev.clone(), metric));
    }
    m
}

/// The MSS clamp table (one atomic `nft -f` script). Empty plan or clamping
/// off = the table is deleted.
pub fn nft_script(p: &Plan) -> String {
    let devs: Vec<String> = p
        .tunnels
        .iter()
        .filter(|t| t.enabled)
        .map(|t| format!("\"{}\"", t.dev))
        .collect();
    let mut s = format!("add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n");
    if p.clamp_mss && !devs.is_empty() {
        let set = devs.join(", ");
        s.push_str(&format!(
            "add table inet {NFT_TABLE}\n\
             add chain inet {NFT_TABLE} forward {{ type filter hook forward priority mangle; policy accept; }}\n\
             add rule inet {NFT_TABLE} forward oifname {{ {set} }} tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n\
             add rule inet {NFT_TABLE} forward iifname {{ {set} }} tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n"
        ));
    }
    s
}

fn apply_nft(p: &Plan, rep: &mut ApplyReport) {
    use std::io::Write;
    let want = p.clamp_mss && p.tunnels.iter().any(|t| t.enabled);
    let have = Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !want && !have {
        return;
    }
    let child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    match child {
        Ok(mut c) => {
            if let Some(mut si) = c.stdin.take() {
                let _ = si.write_all(nft_script(p).as_bytes());
            }
            match c.wait_with_output() {
                Ok(o) if o.status.success() => {
                    rep.applied(if want {
                        "TCP MSS clamp for tunnels".to_string()
                    } else {
                        "TCP MSS clamp removed".to_string()
                    });
                }
                Ok(o) => rep.warn(format!(
                    "tunnel MSS clamp: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => rep.warn(format!("tunnel MSS clamp: {e}")),
            }
        }
        Err(e) => rep.warn(format!("tunnel MSS clamp: nft: {e}")),
    }
}

/// Reconcile the kernel with `want`. One tunnel failing does not stop the
/// others; the first error is returned at the end.
pub fn reconcile(want: &Plan, rep: &mut ApplyReport) -> Result<()> {
    let mut first_err: Option<Error> = None;
    let mut note = |e: Error, rep: &mut ApplyReport| {
        rep.warn(e.to_string());
        if first_err.is_none() {
            first_err = Some(e);
        }
    };
    let have = links();
    let live: BTreeMap<&str, &Tunnel> = want
        .tunnels
        .iter()
        .filter(|t| t.enabled)
        .map(|t| (t.dev.as_str(), t))
        .collect();
    // stale links: ours (prefix) and not wanted
    for k in &have {
        if k.dev.starts_with(PREFIX) && !live.contains_key(k.dev.as_str()) {
            match ip(&["link", "del", &k.dev]) {
                Ok(_) => rep.applied(format!("removed {}", k.dev)),
                Err(e) => note(e, rep),
            }
        }
    }
    for (dev, t) in &live {
        let existing = have.iter().find(|k| k.dev == *dev);
        let mut create = existing.is_none();
        if let Some(k) = existing {
            if !matches_kernel(t, k) {
                if let Err(e) = ip(&["link", "del", dev]) {
                    note(e, rep);
                    continue;
                }
                create = true;
            }
        }
        if create {
            let args = t.create_args();
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(e) = ip(&a) {
                note(e, rep);
                continue;
            }
            rep.applied(format!(
                "created {dev} ({} {} -> {})",
                t.kind, t.local.map(|l| l.to_string()).unwrap_or("any".into()), t.remote
            ));
        }
        let mtu = t.mtu.to_string();
        let steps: Vec<Vec<&str>> = vec![
            vec!["link", "set", "dev", dev, "mtu", &mtu],
            vec!["link", "set", "dev", dev, "alias", ALIAS],
            vec!["link", "set", "dev", dev, "up"],
        ];
        for s in steps {
            if let Err(e) = ip(&s) {
                note(e, rep);
            }
        }
        // inner addresses: exactly the configured ones (plus the kernel's link-local)
        let cur = addrs_of(dev);
        let wanted = t.addrs();
        for a in &cur {
            if !wanted.contains(a) {
                match ip(&["addr", "del", a, "dev", dev]) {
                    Ok(_) => rep.applied(format!("{dev}: removed address {a}")),
                    Err(e) => note(e, rep),
                }
            }
        }
        for a in &wanted {
            if !cur.contains(a) {
                match ip(&["addr", "replace", a, "dev", dev]) {
                    Ok(_) => rep.applied(format!("{dev}: address {a}")),
                    Err(e) => note(e, rep),
                }
            }
        }
    }
    // routes
    let wr = wanted_routes(want);
    for fam in ["-4", "-6"] {
        for (dst, dev) in own_routes(fam) {
            let key = (fam.to_string(), canonical(&dst));
            if !dev.starts_with(PREFIX) {
                continue;
            }
            if wr.get(&key).map(|(d, _)| d.as_str()) != Some(dev.as_str()) {
                let _ = ip(&[fam, "route", "del", &dst, "dev", &dev, "proto", &ROUTE_PROTO.to_string()]);
                rep.applied(format!("removed route {dst} dev {dev}"));
            }
        }
    }
    for ((fam, dst), (dev, metric)) in &wr {
        if !live.contains_key(dev.as_str()) {
            continue;
        }
        let m = metric.to_string();
        let proto = ROUTE_PROTO.to_string();
        match ip(&[
            fam, "route", "replace", dst, "dev", dev, "proto", &proto, "metric", &m,
        ]) {
            Ok(_) => {}
            Err(e) => note(e, rep),
        }
    }
    apply_nft(want, rep);
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

pub async fn load(store: &ConfigStore) -> Result<Plan> {
    let s = Settings::load(store, &SPEC).await?;
    let tunnels = svc::raw_rows(store, &SPEC.colls[0]).await?;
    let routes = svc::raw_rows(store, &SPEC.colls[1]).await?;
    plan(&tunnels, &routes, s.b("clamp_mss"))
}

/// The commands `apply` would run (dry run).
pub fn render(p: &Plan) -> String {
    let mut s = String::new();
    for t in p.tunnels.iter().filter(|t| t.enabled) {
        s.push_str(&format!("ip {}\n", t.create_args().join(" ")));
        s.push_str(&format!("ip link set dev {} mtu {} alias {ALIAS} up\n", t.dev, t.mtu));
        for a in t.addrs() {
            s.push_str(&format!("ip addr replace {a} dev {}\n", t.dev));
        }
    }
    for ((fam, dst), (dev, m)) in wanted_routes(p) {
        s.push_str(&format!(
            "ip {fam} route replace {dst} dev {dev} proto {ROUTE_PROTO} metric {m}\n"
        ));
    }
    s.push_str(&nft_script(p));
    s
}

#[derive(Default, Clone)]
pub struct TunnelsApplier;

#[async_trait]
impl Applier for TunnelsApplier {
    fn name(&self) -> &'static str {
        "tunnels"
    }

    fn phase(&self) -> Phase {
        // the links must exist before routes and the firewall use them
        Phase::Interfaces
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let want = load(store).await?;
        reconcile(&want, &mut rep)?;
        if rep.applied.is_empty() {
            rep.applied(format!(
                "{} tunnel(s), unchanged",
                want.tunnels.iter().filter(|t| t.enabled).count()
            ));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(render(&load(store).await?))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let want = load(store).await.unwrap_or_default();
        let have = links();
        let rows: Vec<Value> = want
            .tunnels
            .iter()
            .map(|t| {
                let k = have.iter().find(|k| k.dev == t.dev);
                let (rx, tx) = counters(&t.dev);
                json!({
                    "name": t.name,
                    "link": t.dev,
                    "type": t.kind,
                    "remote": t.remote.to_string(),
                    "local": t.local.map(|l| l.to_string()).unwrap_or_else(|| "any".into()),
                    "enabled": t.enabled,
                    "present": k.is_some(),
                    "up": k.is_some_and(|k| k.up),
                    "in_sync": k.is_some_and(|k| matches_kernel(t, k)),
                    "addresses": if k.is_some() { addrs_of(&t.dev) } else { Vec::new() },
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                })
            })
            .collect();
        Ok(json!({
            "configured": want.tunnels.len(),
            "present": have.iter().filter(|k| k.dev.starts_with(PREFIX)).count(),
            "tunnels": rows,
        }))
    }
}

fn counters(dev: &str) -> (u64, u64) {
    let rd = |f: &str| {
        std::fs::read_to_string(format!("/sys/class/net/{dev}/statistics/{f}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    (rd("rx_bytes"), rd("tx_bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        for (k, v) in pairs {
            m.insert((*k).into(), Value::String((*v).into()));
        }
        m
    }

    fn sit() -> serde_json::Map<String, Value> {
        row(&[
            ("name", "he"),
            ("kind", "sit"),
            ("remote", "203.0.113.9"),
            ("local", "198.51.100.2"),
            ("address", "2001:db8:1::2/64"),
            ("mtu", "1480"),
            ("ttl", "64"),
            ("default_route", "1"),
            ("metric", "1024"),
            ("enabled", "1"),
        ])
    }

    #[test]
    fn create_args_per_kind() {
        let t = parse_tunnel(&sit()).unwrap();
        assert_eq!(t.dev, "tn-he");
        assert_eq!(
            t.create_args().join(" "),
            "link add name tn-he type sit mode ip6ip remote 203.0.113.9 local 198.51.100.2 ttl 64"
        );
        let mut r = sit();
        r.insert("kind".into(), "ipip".into());
        r.insert("address".into(), "10.99.0.1/30".into());
        r.insert("local".into(), "".into());
        let t = parse_tunnel(&r).unwrap();
        assert_eq!(
            t.create_args().join(" "),
            "link add name tn-he type ipip mode ipip remote 203.0.113.9 ttl 64"
        );
        r.insert("kind".into(), "gif".into());
        let t = parse_tunnel(&r).unwrap();
        assert!(t.create_args().join(" ").contains("type sit mode any"));
    }

    #[test]
    fn rows_are_checked() {
        let bad = |k: &str, v: &str| {
            let mut r = sit();
            r.insert(k.into(), v.into());
            parse_tunnel(&r).unwrap_err().to_string()
        };
        assert!(bad("name", "Upper").contains("lowercase"));
        assert!(bad("name", "twelve-chars").contains("1-11"));
        assert!(bad("name", "a b").contains("lowercase"));
        assert!(bad("kind", "gre").contains("type must be"));
        assert!(bad("remote", "0.0.0.0").contains("cannot be a remote"));
        assert!(bad("remote", "127.0.0.1").contains("cannot be a remote"));
        assert!(bad("remote", "224.0.0.1").contains("cannot be a remote"));
        assert!(bad("remote", "2001:db8::1").contains("IPv4"));
        assert!(bad("local", "203.0.113.9").contains("same address"));
        assert!(bad("address", "10.0.0.1/30").contains("IPv6 only"));
        assert!(bad("address", "fe80::1/64").contains("link-local"));
        assert!(bad("mtu", "1000").contains("1280"));
        let mut r = sit();
        r.insert("kind".into(), "ipip".into());
        assert!(parse_tunnel(&r).unwrap_err().to_string().contains("IPv4 only"));
        let mut r = sit();
        r.insert("address".into(), "".into());
        assert!(parse_tunnel(&r)
            .unwrap_err()
            .to_string()
            .contains("needs an inner address"));
    }

    #[test]
    fn plan_rejects_collisions_and_bad_routes() {
        let a = sit();
        let mut b = sit();
        b.insert("name".into(), "other".into());
        assert!(plan(&[a.clone(), b.clone()], &[], true)
            .unwrap_err()
            .to_string()
            .contains("same endpoints"));
        // same name twice
        let mut c = sit();
        c.insert("remote".into(), "203.0.113.10".into());
        assert!(plan(&[a.clone(), c.clone()], &[], true)
            .unwrap_err()
            .to_string()
            .contains("used twice"));
        // a different remote is fine; a disabled twin is fine
        c.insert("name".into(), "c".into());
        assert!(plan(&[a.clone(), c], &[], true).is_ok());
        b.insert("enabled".into(), "0".into());
        assert!(plan(&[a.clone(), b], &[], true).is_ok());
        // ipip and sit on the same endpoints do not collide in the kernel
        let mut i = sit();
        i.insert("name".into(), "ip".into());
        i.insert("kind".into(), "ipip".into());
        i.insert("address".into(), "10.1.1.1/30".into());
        i.insert("default_route".into(), "0".into());
        assert!(plan(&[a.clone(), i.clone()], &[], true).is_ok());
        // but gif overlaps both
        i.insert("kind".into(), "gif".into());
        assert!(plan(&[a.clone(), i], &[], true).is_err());
        // routes
        let ok = row(&[("tunnel", "he"), ("destination", "2001:db8:ffff::/48")]);
        let p = plan(&[a.clone()], &[ok], true).unwrap();
        assert_eq!(
            p.routes,
            vec![("tn-he".to_string(), "2001:db8:ffff::/48".to_string())]
        );
        let v4 = row(&[("tunnel", "he"), ("destination", "10.5.0.0/16")]);
        assert!(plan(&[a.clone()], &[v4], true).is_err());
        let ghost = row(&[("tunnel", "nope"), ("destination", "2001:db8::/32")]);
        assert!(plan(&[a], &[ghost], true).is_err());
    }

    #[test]
    fn wanted_routes_include_default_and_networks() {
        let mut a = sit();
        a.insert("name".into(), "he".into());
        let routes = [row(&[("tunnel", "he"), ("destination", "2001:db8:ffff::5/48")])];
        let p = plan(&[a], &routes, true).unwrap();
        let w = wanted_routes(&p);
        assert_eq!(
            w[&("-6".to_string(), "default".to_string())],
            ("tn-he".to_string(), 1024)
        );
        // the destination is normalised to its network address
        assert!(w.contains_key(&("-6".to_string(), "2001:db8:ffff::/48".to_string())));
    }

    #[test]
    fn nft_script_clamps_only_tunnel_links() {
        let p = plan(&[sit()], &[], true).unwrap();
        let s = nft_script(&p);
        assert!(s.contains("oifname { \"tn-he\" } tcp flags syn / syn,rst tcp option maxseg size set rt mtu"));
        assert!(s.contains("iifname { \"tn-he\" }"));
        assert!(s.starts_with("add table inet patronus_tunnel\ndelete table"));
        let off = plan(&[sit()], &[], false).unwrap();
        assert!(!nft_script(&off).contains("maxseg"));
        let mut dis = sit();
        dis.insert("enabled".into(), "0".into());
        assert!(!nft_script(&plan(&[dis], &[], true).unwrap()).contains("maxseg"));
    }

    #[test]
    fn kernel_links_are_parsed_and_compared() {
        let j = r#"[
          {"ifindex":2,"ifname":"eth0","flags":["UP"],"mtu":1500,"linkinfo":{"info_kind":"veth"}},
          {"ifindex":5,"ifname":"tn-he","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1480,"ifalias":"patronus-tunnel",
           "linkinfo":{"info_kind":"sit","info_data":{"proto":"ip6ip","remote":"203.0.113.9","local":"198.51.100.2","ttl":64}}},
          {"ifindex":6,"ifname":"sit0","flags":["NOARP"],"mtu":1480,
           "linkinfo":{"info_kind":"sit","info_data":{"proto":"ip6ip","remote":"any","local":"any","ttl":0}}},
          {"ifindex":7,"ifname":"tn-x","flags":[],"mtu":1480,"linkinfo":{"info_kind":"ipip","info_data":{"remote":"10.0.0.2","local":"any","ttl":0}}}
        ]"#;
        let k = parse_links(j);
        assert_eq!(k.len(), 3, "veth is not a tunnel");
        let he = &k[0];
        assert!(he.up && he.alias == ALIAS);
        let t = parse_tunnel(&sit()).unwrap();
        assert!(matches_kernel(&t, he));
        // a changed endpoint, ttl, kind or mode means re-creation
        for (key, val) in [
            ("remote", "203.0.113.10"),
            ("local", "198.51.100.3"),
            ("ttl", "32"),
            ("kind", "gif"),
            ("kind", "ipip"),
        ] {
            let mut r = sit();
            r.insert(key.into(), val.into());
            if key == "kind" && val == "ipip" {
                r.insert("address".into(), "10.0.0.1/30".into());
            }
            let t2 = parse_tunnel(&r).unwrap();
            assert!(!matches_kernel(&t2, he), "{key}={val}");
        }
        assert_eq!(k[1].remote, None, "the fallback sit0 has no endpoints");
        assert_eq!(parse_links("not json"), vec![]);
    }

    #[test]
    fn canonical_spells_routes_like_the_kernel() {
        assert_eq!(canonical("default"), "default");
        assert_eq!(canonical("10.1.2.3"), "10.1.2.3/32");
        assert_eq!(canonical("2001:db8::"), "2001:db8::/128");
        assert_eq!(canonical("10.1.2.0/24"), "10.1.2.0/24");
    }

    #[tokio::test]
    async fn store_round_trip_and_cross_field_check() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let svc = TunnelsSvc;
        let body = json!({"name": "he", "kind": "sit", "remote": "203.0.113.9",
                          "address": "2001:db8:1::2/64"});
        let id = svc.save_row(&s, "tunnels", None, &body).await.unwrap();
        // an IPv4 address on a 6in4 tunnel is refused
        let e = svc
            .save_row(&s, "tunnels", Some(id), &json!({"address": "10.0.0.1/30"}))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("IPv6 only"), "{e}");
        // the type cannot be flipped under a mismatching address either
        let e = svc
            .save_row(&s, "tunnels", Some(id), &json!({"kind": "ipip"}))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("IPv4 only"), "{e}");
        let e = svc
            .save_row(&s, "tunnels", None, &json!({"name": "Bad", "remote": "203.0.113.9"}))
            .await
            .unwrap_err();
        assert!(e.to_string().to_lowercase().contains("lowercase"), "{e}");
        svc.save_row(
            &s,
            "routes",
            None,
            &json!({"tunnel": "he", "destination": "2001:db8:ffff::/48"}),
        )
        .await
        .unwrap();
        let p = load(&s).await.unwrap();
        assert_eq!(p.tunnels.len(), 1);
        assert_eq!(p.tunnels[0].mtu, 1480);
        assert_eq!(p.tunnels[0].ttl, 64);
        assert!(p.clamp_mss, "MSS clamping is on by default");
        assert_eq!(p.routes.len(), 1);
        let r = TunnelsApplier.render(&s).await.unwrap();
        assert!(r.contains("ip link add name tn-he type sit mode ip6ip remote 203.0.113.9"));
        assert!(r.contains("ip addr replace 2001:db8:1::2/64 dev tn-he"));
        assert!(r.contains("ip -6 route replace 2001:db8:ffff::/48 dev tn-he proto 248"));
        // a duplicate name is refused by the unique key
        let dup = svc
            .save_row(&s, "tunnels", None, &json!({"name": "he", "remote": "203.0.113.10"}))
            .await;
        assert!(dup.is_err());
    }
}
