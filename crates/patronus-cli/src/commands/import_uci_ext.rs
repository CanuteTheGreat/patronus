//! Full-router part of `patronus import-uci`: everything an x86 OpenWrt
//! router carries beyond interfaces, the DHCP pool and plain firewall rules.
//!
//! | UCI / file | Patronus |
//! |---|---|
//! | `network.globals` `ula_prefix` + `ip6assign` | a static ULA `::1/64` per interface (OpenWrt's slot order: larger assignments first) |
//! | `network.globals` `dhcp_default_duid`, `wan6` `clientid` | `interfaces.dhcp6_duid` of the DHCPv6 WAN |
//! | `wan6` `reqprefix` | WAN `pd_downstream` = the non-tunnel interfaces with `ip6assign` |
//! | `network.globals` `packet_steering` | `system.packet_steering` |
//! | `proto wireguard` + `wireguard_<iface>` peers | `wg_interfaces` / `wg_peers` with the SAME private key, port, addresses and peer keys |
//! | `network` `route` | static routes |
//! | `dhcp` `dnsmasq` | `dns.mode forwarder`, `dns.local_domain`, `dns.rebind_*`, `dns.cache_size`, `dns.log_queries`, `dns.interfaces`, upstreams, domain overrides |
//! | `dhcp` `domain` | DNS host overrides |
//! | `dhcp` `dhcp_option 6`, `ra`/`dhcpv6`/`ra_flags` | pool DNS servers, RA mode + a prefix-relative DHCPv6 pool |
//! | `dhcp` `host` `leasetime` / `dns` | static lease `lease_time` (0 = infinite) / `dns_record` |
//! | `firewall` `defaults` REJECT, `synflood_protect`; zone `mtu_fix`; non-WAN zone `masq`; `include` | `firewall.inbound_action`, `firewall.synflood_protect`, `firewall.mss_clamp`, masquerade NAT rules, `firewall.drop_ipv4_options` |
//! | `mwan3` | gateways (monitor IPs, reliability, interval, down/up) + a failover gateway group as the IPv4 default |
//! | `wireless` `mode sta` | `wifi_clients` (Wi-Fi uplink) |
//! | `ddns` | DDNS clients (an IPv4 + IPv6 pair for one name becomes one client with family `both`) |
//! | `system` hostname/zonename, `system.ntp` | general settings, NTP server |
//! | `etc/ssh/sshd_config` (+ CA key / principals files) | `ssh.*` settings |
//!
//! Secrets (WireGuard keys, PSKs, DDNS passwords, Wi-Fi keys) go into the
//! store only; the report prints `(set)`.

use super::*;
use std::net::Ipv6Addr;

/// Extra files of the input tree besides `etc/config/*`, by relative path
/// (`etc/ssh/sshd_config`, `etc/ssh/*.pub`, `etc/ssh/auth_principals/*`,
/// `etc/*.nft`). Private keys are never read.
#[derive(Debug, Default, Clone)]
pub struct Extras(pub BTreeMap<String, String>);

impl Extras {
    pub fn get(&self, path: &str) -> Option<&str> {
        self.0.get(path.trim_start_matches('/')).map(String::as_str)
    }
}

/// The tree root holding `etc/` for a directory input (`root`, `root/etc/config` or `root/config`).
fn tree_base(root: &Path) -> PathBuf {
    if root.join("etc/config/network").is_file() {
        root.to_path_buf()
    } else if root.join("config/network").is_file() {
        root.parent().map(Path::to_path_buf).unwrap_or_default()
    } else {
        root.parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }
}

/// Is this relative path one of the extra files the importer may read?
pub fn wanted_extra(rel: &str) -> bool {
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    if rel == "etc/ssh/sshd_config" {
        return true;
    }
    if let Some(f) = rel.strip_prefix("etc/ssh/") {
        if let Some(u) = f.strip_prefix("auth_principals/") {
            return !u.is_empty() && !u.contains('/');
        }
        return !f.contains('/') && f.ends_with(".pub");
    }
    rel.strip_prefix("etc/")
        .is_some_and(|f| !f.contains('/') && f.ends_with(".nft"))
}

pub fn load_extras(root: &Path) -> Extras {
    let base = tree_base(root);
    let mut out = Extras::default();
    let mut dirs = vec![
        base.join("etc"),
        base.join("etc/ssh"),
        base.join("etc/ssh/auth_principals"),
    ];
    while let Some(d) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(rel) = p.strip_prefix(&base) else {
                continue;
            };
            let rel = rel.to_string_lossy().into_owned();
            if !p.is_file() || !wanted_extra(&rel) {
                continue;
            }
            if std::fs::metadata(&p).map(|m| m.len()).unwrap_or(u64::MAX) > 65536 {
                continue;
            }
            if let Ok(t) = std::fs::read_to_string(&p) {
                out.0.insert(rel, t);
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Iface6 {
    pub addrs: Vec<IpNetwork>,
    pub pd_downstream: Vec<String>,
    pub duid: Option<String>,
    /// UCI `metric` of the interface: the order of several DHCP uplinks (`interfaces.metric`)
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoutePlan {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct WgPeerPlan {
    pub name: String,
    pub description: Option<String>,
    pub public_key: String,
    /// Legacy LuCI peers keep their private key in UCI: carried into the store only.
    pub private_key: Option<String>,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub keepalive: Option<u16>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct WgPlan {
    pub uci: String,
    pub device: String,
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub addresses: Vec<String>,
    pub mtu: Option<u32>,
    pub peers: Vec<WgPeerPlan>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DdnsPlan {
    pub provider: String,
    pub hostname: String,
    pub server: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub family: String,
    pub interface: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GwPlan {
    pub name: String,
    pub interface: String,
    pub family: String,
    pub monitor_ips: Vec<String>,
    pub reliability: u32,
    pub interval: u32,
    pub down: u32,
    pub up: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupPlan {
    pub name: String,
    /// gateway:tier:weight
    pub members: Vec<(String, u32, u32)>,
    pub default4: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WifiClientPlan {
    pub section: String,
    pub device: Option<String>,
    pub ssid: String,
    pub security: String,
    pub psk: Option<String>,
    pub bssid: Option<String>,
    pub enabled: bool,
}

/// A store setting: `(key, value, secret)`.
pub type Setting = (String, String, bool);

#[derive(Debug, Default, Clone)]
pub struct ExtPlan {
    /// `lan_settings` (dns.*, general.*, ntp via its own input)
    pub lan_settings: Vec<Setting>,
    /// `system_config` (firewall.*, ssh.*, system.*)
    pub sys_settings: Vec<Setting>,
    pub iface6: BTreeMap<String, Iface6>,
    pub pool_dns: BTreeMap<String, String>,
    /// IPv6 DNS servers announced on an interface (RA RDNSS + DHCPv6), `dhcp.<if>.dns`
    pub pool_dns6: BTreeMap<String, String>,
    pub static_opts: BTreeMap<Ipv4Addr, (Option<u32>, bool)>,
    pub hosts: Vec<(String, String, IpAddr)>,
    pub domains: Vec<(String, String)>,
    pub routes: Vec<RoutePlan>,
    pub wg: Vec<WgPlan>,
    pub ddns: Vec<DdnsPlan>,
    pub gateways: Vec<GwPlan>,
    pub groups: Vec<GroupPlan>,
    /// (device, RA mode, stateful DHCPv6 pool)
    pub ra: Vec<(String, String, bool)>,
    pub wifi_clients: Vec<WifiClientPlan>,
    pub ntp: Option<(bool, Vec<String>, Vec<String>)>,
    pub general: Option<(Option<String>, Option<String>)>,
}

impl ExtPlan {
    fn lan(&mut self, k: &str, v: impl Into<String>) {
        self.lan_settings.push((k.into(), v.into(), false));
    }
    fn sys(&mut self, k: &str, v: impl Into<String>) {
        self.sys_settings.push((k.into(), v.into(), false));
    }
}

/// Zone name -> interface specs of the Patronus side (`@lan`, a tunnel device, ...).
pub type ZoneMap = BTreeMap<String, Vec<String>>;

/// The UCI interface names whose device is a WireGuard tunnel -> Patronus tunnel device.
pub fn wg_devices(files: &Files, maps: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    sections(files, "network", "interface")
        .filter(|s| s.get("proto") == Some("wireguard"))
        .map(|s| {
            let n = s.label();
            let dev = maps.get(&n).cloned().unwrap_or_else(|| n.clone());
            (n, dev)
        })
        .collect()
}

pub fn zone_map(plan: &Plan, files: &Files, wg: &BTreeMap<String, String>) -> ZoneMap {
    let mut m = ZoneMap::new();
    for z in sections(files, "firewall", "zone") {
        let name = z.get("name").unwrap_or("").to_string();
        let mut specs: Vec<String> = Vec::new();
        for n in z.words("network") {
            let spec = if let Some(i) = plan.ifaces.iter().find(|i| i.uci == n) {
                match &i.role {
                    Some(r) => format!("@{r}"),
                    None => i.device.clone(),
                }
            } else if let Some(d) = wg.get(&n) {
                d.clone()
            } else {
                continue;
            };
            if !specs.contains(&spec) {
                specs.push(spec);
            }
        }
        m.insert(name, specs);
    }
    m
}

/// `fda7:...::/48` + OpenWrt slot assignment: interfaces asking for the
/// largest share (smallest `ip6assign`) are placed first, each at the
/// lowest free slot aligned to its size; the interface gets `<slot>::1/64`.
pub fn ula_assign(prefix: &str, wants: &[(String, u8)]) -> Vec<(String, IpNetwork)> {
    let Some((addr, len)) = prefix.split_once('/') else {
        return vec![];
    };
    let (Ok(base), Ok(len)) = (addr.parse::<Ipv6Addr>(), len.parse::<u8>()) else {
        return vec![];
    };
    if !(8..=64).contains(&len) {
        return vec![];
    }
    let base = u128::from(base) & (u128::MAX << (128 - len as u32));
    let total: u128 = 1u128 << (64 - len as u32);
    let mut order: Vec<(usize, &(String, u8))> = wants.iter().enumerate().collect();
    order.sort_by_key(|(i, (_, a))| (*a, *i));
    let mut used: Vec<(u128, u128)> = Vec::new();
    let mut out = Vec::new();
    for (_, (name, assign)) in order {
        if *assign < len || *assign > 64 {
            continue;
        }
        let size: u128 = 1u128 << (64 - *assign as u32);
        let mut slot = 0u128;
        while slot + size <= total {
            if used.iter().all(|(s, e)| slot + size <= *s || slot >= *e) {
                break;
            }
            slot += size;
        }
        if slot + size > total {
            continue;
        }
        used.push((slot, slot + size));
        let a = Ipv6Addr::from(base | (slot << 64) | 1);
        if let Ok(n) = IpNetwork::new(IpAddr::V6(a), 64) {
            out.push((name.clone(), n));
        }
    }
    out
}

fn duid_colons(s: &str) -> Option<String> {
    let h: String = s.chars().filter(|c| *c != ':').collect();
    if h.len() < 4
        || !h.len().is_multiple_of(2)
        || h.len() > 260
        || !h.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some(
        h.as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn slug(s: &str, n: usize) -> String {
    let mut o: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while o.contains("--") {
        o = o.replace("--", "-");
    }
    let o = o.trim_matches('-').chars().take(40).collect::<String>();
    let o = o.trim_matches('-').to_string();
    if o.is_empty() || !o.starts_with(|c: char| c.is_ascii_alphabetic()) {
        format!("peer{n}")
    } else {
        o
    }
}

/// Remove report lines the base importer wrote for things handled here.
fn drop_lines(v: &mut Vec<String>, pred: impl Fn(&str) -> bool) {
    v.retain(|l| !pred(l));
}

pub fn plan_ext(plan: &mut Plan, files: &Files, extras: &Extras, maps: &BTreeMap<String, String>) {
    let wg = wg_devices(files, maps);
    let zones = zone_map(plan, files, &wg);
    let mut x = ExtPlan::default();
    network_ext(plan, &mut x, files, maps, &wg);
    dhcp_ext(plan, &mut x, files, &zones, &wg);
    firewall_ext(plan, &mut x, files, extras, &zones);
    mwan3_ext(plan, &mut x, files, maps);
    ddns_ext(plan, &mut x, files);
    system_ext(plan, &mut x, files);
    sshd_ext(plan, &mut x, files, extras);
    wireless_ext(plan, &mut x, maps);
    other_files(plan);
    plan.ext = x;
}

fn network_ext(
    plan: &mut Plan,
    x: &mut ExtPlan,
    files: &Files,
    maps: &BTreeMap<String, String>,
    wg: &BTreeMap<String, String>,
) {
    let globals = sections(files, "network", "globals").next();
    let ula = globals
        .and_then(|g| g.get("ula_prefix"))
        .map(str::to_string);
    let default_duid = globals.and_then(|g| g.get("dhcp_default_duid"));
    if let Some(g) = globals {
        if g.flag("packet_steering") == Some(true) {
            x.sys("system.packet_steering", "1");
        }
        if let Some(u) = &ula {
            plan.notes.push(format!(
                "network: globals ula_prefix '{u}' -> static ULA addresses (see ipv6)"
            ));
        }
        let left = g.leftover(&["ula_prefix", "packet_steering", "dhcp_default_duid"]);
        if !left.is_empty() {
            plan.unmapped.push(format!(
                "network: globals: option(s) not imported: {}",
                left.join(", ")
            ));
        }
    }
    // ip6assign: device of each interface asking for a share
    let mut wants: Vec<(String, u8)> = Vec::new();
    let mut downstream: Vec<String> = Vec::new();
    for s in sections(files, "network", "interface") {
        let Some(a) = s.get("ip6assign").and_then(|v| v.parse::<u8>().ok()) else {
            continue;
        };
        let name = s.label();
        let dev = if let Some(d) = wg.get(&name) {
            d.clone()
        } else if let Some(i) = plan.ifaces.iter().find(|i| i.uci == name) {
            downstream.push(i.device.clone());
            i.device.clone()
        } else {
            continue;
        };
        wants.push((dev, a));
    }
    if let Some(u) = &ula {
        for (dev, net) in ula_assign(u, &wants) {
            if wg.values().any(|d| *d == dev) {
                if let Some(w) = x.wg.iter_mut().find(|w| w.device == dev) {
                    w.addresses.push(net.to_string());
                } else {
                    x.iface6
                        .entry(format!("wg:{dev}"))
                        .or_default()
                        .addrs
                        .push(net);
                }
            } else {
                x.iface6.entry(dev).or_default().addrs.push(net);
            }
        }
    }
    // the DHCPv6 WAN: delegated prefix downstream + DUID
    for s in sections(files, "network", "interface") {
        if s.get("proto") != Some("dhcpv6") {
            continue;
        }
        let uci_dev = s.get("device").or(s.get("ifname")).unwrap_or("");
        let Some(i) = plan.ifaces.iter().find(|i| {
            i.v6 == V6Mode::Dhcp6
                && (maps.get(&s.label()) == Some(&i.device)
                    || plan_dev_matches(files, &i.uci, uci_dev))
        }) else {
            continue;
        };
        let dev = i.device.clone();
        let e = x.iface6.entry(dev.clone()).or_default();
        if s.get("reqprefix").is_some_and(|p| p != "no") && !downstream.is_empty() {
            e.pd_downstream = downstream.clone();
        }
        if let Some(d) = s.get("clientid").or(default_duid).and_then(duid_colons) {
            e.duid = Some(d);
        }
    }
    // route metrics: several DHCP uplinks (wan + a Wi-Fi backup) must not install their default routes with the same
    // metric (the second one is refused and the primary WAN can end up without its default route)
    for s in sections(files, "network", "interface") {
        let Some(m) = s.get("metric").and_then(|m| m.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(i) = plan.ifaces.iter().find(|i| i.uci == s.label()) {
            x.iface6.entry(i.device.clone()).or_default().metric = Some(m.clamp(1, 9999));
        }
    }
    // WireGuard tunnels + peers
    for s in sections(files, "network", "interface") {
        if s.get("proto") != Some("wireguard") {
            continue;
        }
        let name = s.label();
        let device = wg.get(&name).cloned().unwrap_or(name.clone());
        let mut w = WgPlan {
            uci: name.clone(),
            device: device.clone(),
            private_key: s.get("private_key").map(str::to_string),
            listen_port: s.get("listen_port").and_then(|p| p.parse().ok()),
            addresses: s.words("addresses"),
            mtu: s.get("mtu").and_then(|m| m.parse().ok()),
            peers: vec![],
        };
        if let Some(e) = x.iface6.remove(&format!("wg:{device}")) {
            w.addresses.extend(e.addrs.iter().map(|a| a.to_string()));
        }
        let kind = format!("wireguard_{name}");
        for (n, p) in files
            .get("network")
            .into_iter()
            .flatten()
            .filter(|p| p.kind == kind)
            .enumerate()
        {
            let desc = p.get("description").map(str::to_string);
            let mut name = slug(desc.as_deref().unwrap_or(""), n + 1);
            if w.peers.iter().any(|q| q.name == name) {
                name = format!("{name}-{}", n + 1);
            }
            let endpoint = p
                .get("endpoint_host")
                .map(|h| match p.get("endpoint_port") {
                    Some(port) if h.contains(':') => format!("[{h}]:{port}"),
                    Some(port) => format!("{h}:{port}"),
                    None => format!("{h}:51820"),
                });
            w.peers.push(WgPeerPlan {
                name,
                description: desc,
                public_key: p.get("public_key").unwrap_or("").to_string(),
                private_key: p.get("private_key").map(str::to_string),
                preshared_key: p.get("preshared_key").map(str::to_string),
                allowed_ips: p.words("allowed_ips"),
                endpoint,
                keepalive: p.get("persistent_keepalive").and_then(|k| k.parse().ok()),
                enabled: p.flag("disabled") != Some(true),
            });
            let left = p.leftover(&[
                "description",
                "public_key",
                "private_key",
                "preshared_key",
                "allowed_ips",
                "endpoint_host",
                "endpoint_port",
                "persistent_keepalive",
                "route_allowed_ips",
                "disabled",
            ]);
            if !left.is_empty() {
                plan.unmapped.push(format!(
                    "network: {kind} '{}': option(s) not imported: {}",
                    p.label(),
                    left.join(", ")
                ));
            }
        }
        let left = s.leftover(&[
            "proto",
            "private_key",
            "listen_port",
            "addresses",
            "mtu",
            "ip6assign",
            "force_link",
            "multipath",
        ]);
        if !left.is_empty() {
            plan.unmapped.push(format!(
                "network: interface '{name}' (wireguard): option(s) not imported: {}",
                left.join(", ")
            ));
        }
        x.wg.push(w);
    }
    // static routes
    for s in sections(files, "network", "route") {
        let Some(t) = s.get("target") else {
            plan.unmapped
                .push(format!("network: route '{}' (no target)", s.label()));
            continue;
        };
        let dest = if t.contains('/') {
            t.to_string()
        } else {
            match s.get("netmask").and_then(v4_netmask_prefix) {
                Some(p) => format!("{t}/{p}"),
                None => format!("{t}/32"),
            }
        };
        let interface = s.get("interface").map(|i| {
            wg.get(i)
                .cloned()
                .or_else(|| {
                    plan.ifaces.iter().find(|p| p.uci == i).map(|p| {
                        p.role
                            .as_ref()
                            .map(|r| format!("@{r}"))
                            .unwrap_or(p.device.clone())
                    })
                })
                .unwrap_or_else(|| i.to_string())
        });
        if x.routes.iter().any(|r| r.destination == dest) {
            plan.notes.push(format!(
                "network: route '{}' to {dest}: a second route to the same destination, the first one is kept",
                s.label()
            ));
            continue;
        }
        x.routes.push(RoutePlan {
            destination: dest,
            gateway: s.get("gateway").map(str::to_string),
            interface,
            metric: s.get("metric").and_then(|m| m.parse().ok()),
        });
    }
    // the base importer reported these as unmapped
    let wgs: Vec<String> = wg.keys().cloned().collect();
    drop_lines(&mut plan.unmapped, |l| {
        l.starts_with("network: globals")
            && l.contains("(bridges, switch, routes and globals are not imported)")
            || l.starts_with("network: route ")
                && l.contains("(bridges, switch, routes and globals are not imported)")
            || l.starts_with("network: wireguard_")
            || wgs
                .iter()
                .any(|w| l.starts_with(&format!("network: interface '{w}' proto 'wireguard'")))
            || (l.starts_with("network: interface '") && l.contains("option(s) not imported") && {
                // ip6assign / reqaddress / reqprefix / clientid are handled here
                let opts = l.rsplit(": ").next().unwrap_or("");
                opts.split(", ").all(|o| {
                    [
                        "ip6assign",
                        "reqaddress",
                        "reqprefix",
                        "clientid",
                        "metric",
                        "force_link",
                        "multipath",
                    ]
                    .contains(&o)
                })
            })
    });
}

fn plan_dev_matches(files: &Files, uci: &str, uci_dev: &str) -> bool {
    sections(files, "network", "interface")
        .find(|s| s.label() == uci)
        .and_then(|s| s.get("device").or(s.get("ifname")))
        == Some(uci_dev)
}

fn dhcp_ext(
    plan: &mut Plan,
    x: &mut ExtPlan,
    files: &Files,
    zones: &ZoneMap,
    wg: &BTreeMap<String, String>,
) {
    let mut local_domain: Option<String> = None;
    if let Some(d) = sections(files, "dhcp", "dnsmasq").next() {
        x.lan("dns.mode", "forwarder");
        let domain = d.get("domain").map(|s| s.trim_matches('.').to_string());
        let local = d.get("local").map(|s| s.trim_matches('/').to_string());
        if let Some(dom) = domain.clone().or(local.clone()) {
            x.lan("dns.local_domain", dom.clone());
            local_domain = Some(dom);
        }
        if let Some(r) = d.flag("rebind_protection") {
            x.lan("dns.rebind_protection", if r { "1" } else { "0" });
        }
        let ex = d.words("rebind_domain");
        if !ex.is_empty() {
            x.lan(
                "dns.rebind_exceptions",
                ex.iter()
                    .map(|e| e.trim_matches('/').to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(c) = d.get("cachesize") {
            x.lan("dns.cache_size", c);
        }
        if let Some(q) = d.flag("logqueries") {
            x.lan("dns.log_queries", if q { "1" } else { "0" });
        }
        if d.flag("localservice") == Some(false) {
            // answer every subnet routed in through the LAN zone's interfaces
            let specs = zones
                .get("lan")
                .cloned()
                .unwrap_or_else(|| vec!["@lan".into()]);
            x.lan("dns.interfaces", specs.join(","));
        }
        let mut upstreams = Vec::new();
        for sv in d.words("server") {
            let parts: Vec<&str> = sv.trim_start_matches('/').split('/').collect();
            if sv.starts_with('/') && parts.len() == 2 {
                x.domains.push((parts[0].to_string(), parts[1].to_string()));
            } else if sv.parse::<IpAddr>().is_ok() {
                upstreams.push(sv);
            } else {
                plan.unmapped
                    .push(format!("dhcp: dnsmasq server '{sv}' (syntax not imported)"));
            }
        }
        if !upstreams.is_empty() {
            x.lan("dns.upstreams", upstreams.join(","));
        }
        let left = d.leftover(&[
            "domain",
            "local",
            "expandhosts",
            "rebind_protection",
            "rebind_domain",
            "rebind_localhost",
            "cachesize",
            "logqueries",
            "localservice",
            "server",
            "domainneeded",
            "localise_queries",
            "authoritative",
            "readethers",
            "leasefile",
            "resolvfile",
            "ednspacket_max",
            "nonwildcard",
            "boguspriv",
            "filterwin2k",
            "nonegcache",
        ]);
        plan.notes.push(
            "dhcp: dnsmasq -> DNS forwarder (dnsmasq) with local domain, lease names, rebind protection, \
             per-domain forwarding (domainneeded, authoritative, localise_queries, rebind_localhost and the \
             lease/resolv files are Patronus defaults)"
                .into(),
        );
        if !left.is_empty() {
            plan.unmapped.push(format!(
                "dhcp: dnsmasq: option(s) not imported: {}",
                left.join(", ")
            ));
        }
    }
    for s in sections(files, "dhcp", "domain") {
        let (Some(name), Some(ip)) = (
            s.get("name"),
            s.get("ip").and_then(|i| i.parse::<IpAddr>().ok()),
        ) else {
            plan.unmapped
                .push(format!("dhcp: domain '{}' (needs name and ip)", s.label()));
            continue;
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let (host, dom) = match name.split_once('.') {
            Some((h, d)) => (h.to_string(), d.to_string()),
            None => match &local_domain {
                Some(d) => (name.clone(), d.clone()),
                None => {
                    plan.unmapped.push(format!(
                        "dhcp: domain '{name}' (a bare name needs the dnsmasq local domain)"
                    ));
                    continue;
                }
            },
        };
        if name.contains('.') && local_domain.as_deref() == Some(name.as_str()) {
            // the domain apex itself (`home.example` -> router): host override needs a label
            if !x
                .hosts
                .iter()
                .any(|(h, d, a)| h == "router" && *d == name && *a == ip)
            {
                x.hosts.push(("router".into(), name.clone(), ip));
            }
            plan.notes.push(format!(
                "dhcp: domain '{name}' (the local domain apex) -> router.{name}; the apex itself answers with the router (dnsmasq local domain)"
            ));
            continue;
        }
        if !x.hosts.iter().any(|(h, d, _)| *h == host && *d == dom) {
            x.hosts.push((host, dom, ip));
        }
    }
    for s in sections(files, "dhcp", "ipset") {
        plan.unmapped.push(format!(
            "dhcp: ipset '{}' ({} -> nft set '{}'): dnsmasq-filled sets are not imported (use a firewall alias with a hostname)",
            s.label(),
            s.words("domain").join(" "),
            s.words("name").join(" ")
        ));
    }
    for s in sections(files, "dhcp", "odhcpd") {
        plan.covered.push(format!(
            "dhcp: odhcpd '{}' (lease files / log level: the DHCPv6 + RA daemon is dnsmasq on Patronus)",
            s.label()
        ));
    }
    // pool options, IPv6
    for s in sections(files, "dhcp", "dhcp") {
        if s.flag("ignore") == Some(true) {
            continue;
        }
        let uci_if = s.get("interface").map(str::to_string).unwrap_or(s.label());
        let Some(i) = plan.ifaces.iter().find(|i| i.uci == uci_if) else {
            continue;
        };
        let dev = i.device.clone();
        for o in s.words("dhcp_option") {
            let (code, val) = o.split_once(',').unwrap_or((&o, ""));
            if code == "6" || code == "option:dns-server" {
                x.pool_dns.insert(dev.clone(), val.to_string());
            } else {
                plan.unmapped.push(format!(
                    "dhcp: '{uci_if}' dhcp_option '{o}' (only option 6 is imported)"
                ));
            }
        }
        let dns6: Vec<String> = s
            .words("dns")
            .into_iter()
            .filter(|a| a.parse::<std::net::Ipv6Addr>().is_ok())
            .collect();
        if !dns6.is_empty() {
            x.pool_dns6.insert(dev.clone(), dns6.join(","));
        }
        let ra = s.get("ra").unwrap_or("disabled");
        let v6 = s.get("dhcpv6").unwrap_or("disabled");
        if ra != "disabled" {
            let flags = s.words("ra_flags");
            let managed = flags.iter().any(|f| f == "managed-config");
            let other = flags.iter().any(|f| f == "other-config");
            let slaac = s.flag("ra_slaac") != Some(false);
            let stateful = v6 == "server" || v6 == "hybrid";
            let mode = match (managed && stateful, slaac, other || stateful) {
                (true, true, _) => "assisted",
                (true, false, _) => "managed",
                (false, _, true) => "stateless",
                _ => "slaac",
            };
            x.ra.push((dev.clone(), mode.into(), stateful && managed));
            if ra == "relay" || v6 == "relay" {
                plan.unmapped.push(format!(
                    "dhcp: '{uci_if}' ra/dhcpv6 relay mode (Patronus serves RA/DHCPv6 itself)"
                ));
            }
        }
        if s.get("ndp").is_some_and(|n| n != "disabled") {
            plan.notes.push(format!(
                "dhcp: '{uci_if}' ndp '{}': no NDP proxy master interface configured, nothing to proxy",
                s.get("ndp").unwrap_or("")
            ));
        }
    }
    drop_lines(&mut plan.unmapped, |l| {
        l.starts_with("dhcp: dnsmasq '")
            || l.starts_with("dhcp: domain '")
            || l.starts_with("dhcp: ipset '") && l.contains("(not imported)")
            || l.starts_with("dhcp: odhcpd '")
            || l.starts_with("dhcp: dhcp '") && l.contains("IPv6 RA/DHCPv6 option(s) not imported")
            || l.starts_with("dhcp: dhcp '")
                && l.contains("option(s) not imported")
                && l.rsplit(": ").next().unwrap_or("").split(", ").all(|o| {
                    [
                        "dhcp_option",
                        "force",
                        "ra_useleasetime",
                        "ndp",
                        "ra_slaac",
                        "dynamicdhcp",
                    ]
                    .contains(&o)
                })
            || l.starts_with("dhcp: host '")
                && l.contains("option(s) not imported")
                && l.rsplit(": ")
                    .next()
                    .unwrap_or("")
                    .split(", ")
                    .all(|o| ["leasetime", "dns"].contains(&o))
    });
    // static lease options
    for s in sections(files, "dhcp", "host") {
        let Some(ip) = s.get("ip").and_then(|i| i.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let lt = match s.get("leasetime") {
            Some("infinite") => Some(0),
            Some(l) => parse_duration(l),
            None => None,
        };
        let dns = s.flag("dns") == Some(true);
        if lt.is_some() || dns {
            x.static_opts.insert(ip, (lt, dns));
        }
    }
    let _ = wg;
}

/// Zone policies for interfaces with no role (a WireGuard tunnel in the lan
/// zone): Patronus' default rules cover `@lan`/`@wan` only, so the zone's
/// input/forward ACCEPT and its `forwarding` sections become explicit rules
/// for those members, as fw4 does.
fn zone_member_rules(plan: &mut Plan, files: &Files, zones: &ZoneMap) {
    let accept = |v: Option<&str>| v.is_some_and(|v| v.eq_ignore_ascii_case("ACCEPT"));
    let mut seen: Vec<(ChainType, Option<String>, Option<String>)> = Vec::new();
    let mut add =
        |plan: &mut Plan, chain: ChainType, i: Option<&String>, o: Option<&String>, why: String| {
            let key = (chain.clone(), i.cloned(), o.cloned());
            if seen.contains(&key) {
                return;
            }
            seen.push(key);
            let mut r = FirewallRule::new(why, chain, FirewallAction::Accept);
            r.interface_in = i.cloned();
            r.interface_out = o.cloned();
            r.comment = Some("imported from OpenWrt UCI (zone policy)".into());
            plan.fw_rules.push(r);
        };
    let tunnels = |z: &str| -> Vec<String> {
        zones
            .get(z)
            .map(|v| v.iter().filter(|s| !s.starts_with('@')).cloned().collect())
            .unwrap_or_default()
    };
    for z in sections(files, "firewall", "zone") {
        let name = z.get("name").unwrap_or("");
        let members = zones.get(name).cloned().unwrap_or_default();
        for t in tunnels(name) {
            if accept(z.get("input")) {
                add(
                    plan,
                    ChainType::Input,
                    Some(&t),
                    None,
                    format!("{t} may reach the router (zone {name})"),
                );
            }
            if accept(z.get("forward")) {
                for m in members.iter().filter(|m| **m != t) {
                    add(
                        plan,
                        ChainType::Forward,
                        Some(&t),
                        Some(m),
                        format!("{t} -> {m} (zone {name})"),
                    );
                    add(
                        plan,
                        ChainType::Forward,
                        Some(m),
                        Some(&t),
                        format!("{m} -> {t} (zone {name})"),
                    );
                }
            }
        }
    }
    for f in sections(files, "firewall", "forwarding") {
        let (Some(src), Some(dst)) = (f.get("src"), f.get("dest")) else {
            continue;
        };
        let (srcs, dsts) = (
            zones.get(src).cloned().unwrap_or_default(),
            zones.get(dst).cloned().unwrap_or_default(),
        );
        for t in tunnels(src) {
            for d in &dsts {
                add(
                    plan,
                    ChainType::Forward,
                    Some(&t),
                    Some(d),
                    format!("{t} -> {d} (forwarding {src} -> {dst})"),
                );
            }
        }
        for t in tunnels(dst) {
            for s0 in &srcs {
                add(
                    plan,
                    ChainType::Forward,
                    Some(s0),
                    Some(&t),
                    format!("{s0} -> {t} (forwarding {src} -> {dst})"),
                );
            }
        }
    }
}

fn firewall_ext(plan: &mut Plan, x: &mut ExtPlan, files: &Files, extras: &Extras, zones: &ZoneMap) {
    zone_member_rules(plan, files, zones);
    for s in files.get("firewall").into_iter().flatten() {
        match s.kind.as_str() {
            "defaults" => {
                let rej = |k: &str| s.get(k).is_some_and(|v| v.eq_ignore_ascii_case("REJECT"));
                x.sys(
                    "firewall.inbound_action",
                    if rej("input") || rej("forward") {
                        "reject"
                    } else {
                        "drop"
                    },
                );
                if s.flag("synflood_protect").or(s.flag("syn_flood")) == Some(true) {
                    x.sys("firewall.synflood_protect", "1");
                    if let Some(r) = s.get("synflood_rate") {
                        x.sys("firewall.synflood_rate", r);
                    }
                    if let Some(b) = s.get("synflood_burst") {
                        x.sys("firewall.synflood_burst", b);
                    }
                }
            }
            "zone" => {
                let name = s.get("name").unwrap_or("");
                let specs = zones.get(name).cloned().unwrap_or_default();
                if s.flag("mtu_fix") == Some(true) {
                    let mut cur: Vec<String> = x
                        .sys_settings
                        .iter()
                        .find(|(k, _, _)| k == "firewall.mss_clamp")
                        .map(|(_, v, _)| v.split(',').map(str::to_string).collect())
                        .unwrap_or_default();
                    for sp in &specs {
                        if !cur.contains(sp) {
                            cur.push(sp.clone());
                        }
                    }
                    x.sys_settings.retain(|(k, _, _)| k != "firewall.mss_clamp");
                    x.sys("firewall.mss_clamp", cur.join(","));
                }
                if s.flag("masq") == Some(true) && name != "wan" {
                    for sp in &specs {
                        let mut r = NatRule::new(
                            format!("Masquerade out {sp} (zone {name})"),
                            NatType::Masquerade,
                        );
                        r.interface_out = Some(sp.clone());
                        r.comment = Some("imported from OpenWrt UCI (zone masq)".into());
                        plan.nat_rules.push(r);
                    }
                }
            }
            "include" => {
                let path = s.get("path").unwrap_or("");
                match extras.get(path) {
                    Some(t) if is_ipv4_options_drop(t) => {
                        x.sys("firewall.drop_ipv4_options", "1");
                        plan.notes.push(format!(
                            "firewall: include '{}' ({path}): drop IPv4 TCP with IP options -> firewall.drop_ipv4_options",
                            s.label()
                        ));
                    }
                    Some(_) => plan.unmapped.push(format!(
                        "firewall: include '{}' ({path}): custom nftables, review and recreate as rules",
                        s.label()
                    )),
                    None => plan.unmapped.push(format!(
                        "firewall: include '{}' ({path}): file not in the input",
                        s.label()
                    )),
                }
            }
            _ => {}
        }
    }
    drop_lines(&mut plan.unmapped, |l| {
        l.starts_with("firewall: defaults: option(s) not imported")
            && l.rsplit(": ").next().unwrap_or("").split(", ").all(|o| {
                [
                    "synflood_protect",
                    "syn_flood",
                    "synflood_rate",
                    "synflood_burst",
                    "drop_invalid",
                ]
                .contains(&o)
            })
            || l.starts_with("firewall: zone '")
                && l.contains("masq '1' (only the wan zone is NATed)")
            || l.starts_with("firewall: zone '")
                && l.contains("option(s) not imported")
                && l.rsplit(": ")
                    .next()
                    .unwrap_or("")
                    .split(", ")
                    .all(|o| o == "mtu_fix")
            || l.starts_with("firewall: include '") && l.ends_with("(not imported)")
    });
    drop_lines(&mut plan.notes, |l| {
        l.starts_with("firewall: defaults input/output/forward")
    });
    plan.notes.push(
        "firewall: defaults -> firewall.inbound_action (REJECT -> reject), synflood_protect".into(),
    );
}

/// The fw4 include that drops IPv4 TCP packets carrying IP options: every
/// verdict line in it is that one drop (nothing else to translate).
pub fn is_ipv4_options_drop(t: &str) -> bool {
    let mut seen = false;
    for l in t.lines().map(str::trim) {
        if l.starts_with('#') || l.contains("policy accept") {
            continue;
        }
        let verdict = [
            "drop",
            "accept",
            "reject",
            "dnat",
            "snat",
            "masquerade",
            "jump",
            "goto",
            "redirect",
        ]
        .iter()
        .any(|v| {
            l.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == *v)
        });
        if !verdict {
            continue;
        }
        if l.contains("ip hdrlength > 5") && l.contains(" drop") {
            seen = true;
        } else if !l.starts_with("delete table") && !l.starts_with("table ") {
            return false;
        }
    }
    seen
}

fn mwan3_ext(plan: &mut Plan, x: &mut ExtPlan, files: &Files, maps: &BTreeMap<String, String>) {
    let Some(secs) = files.get("mwan3") else {
        return;
    };
    let dev_of = |iface: &str| -> Option<String> {
        maps.get(iface).cloned().or_else(|| {
            plan.ifaces
                .iter()
                .find(|i| i.uci == iface)
                .map(|i| i.device.clone())
        })
    };
    let mut gws: BTreeMap<String, GwPlan> = BTreeMap::new();
    for s in secs.iter().filter(|s| s.kind == "interface") {
        let name = s.label();
        if s.flag("enabled") != Some(true) {
            plan.notes
                .push(format!("mwan3: interface '{name}' disabled, not imported"));
            continue;
        }
        let Some(dev) = dev_of(&name) else {
            plan.unmapped.push(format!(
                "mwan3: interface '{name}' (no mapped network interface; --map {name}=DEVICE)"
            ));
            continue;
        };
        let num = |k: &str, d: u32| s.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        gws.insert(
            name.clone(),
            GwPlan {
                name: name.clone(),
                interface: dev,
                family: if s.get("family") == Some("ipv6") {
                    "inet6".into()
                } else {
                    "inet".into()
                },
                monitor_ips: s.words("track_ip"),
                reliability: num("reliability", 1),
                interval: num("interval", 5),
                down: num("down", 5),
                up: num("up", 5),
            },
        );
    }
    let members: BTreeMap<String, (String, u32, u32)> = secs
        .iter()
        .filter(|s| s.kind == "member")
        .filter_map(|s| {
            Some((
                s.label(),
                (
                    s.get("interface")?.to_string(),
                    s.get("metric").and_then(|v| v.parse().ok()).unwrap_or(1),
                    s.get("weight").and_then(|v| v.parse().ok()).unwrap_or(1),
                ),
            ))
        })
        .collect();
    let default_policy = secs
        .iter()
        .filter(|s| s.kind == "rule")
        .find(|s| {
            s.get("dest_ip").is_none_or(|d| d == "0.0.0.0/0") && s.get("family") != Some("ipv6")
        })
        .and_then(|s| s.get("use_policy"))
        .map(str::to_string);
    for p in secs.iter().filter(|s| s.kind == "policy") {
        let mut m = Vec::new();
        for mem in p.words("use_member") {
            match members.get(&mem) {
                Some((iface, metric, weight)) if gws.contains_key(iface) => {
                    m.push((iface.clone(), *metric, *weight))
                }
                _ => plan.notes.push(format!(
                    "mwan3: policy '{}' member '{mem}' skipped (its interface is disabled or unmapped)",
                    p.label()
                )),
            }
        }
        if m.is_empty() {
            continue;
        }
        x.groups.push(GroupPlan {
            name: p.label(),
            members: m,
            default4: default_policy.as_deref() == Some(p.label().as_str()),
        });
    }
    for r in secs.iter().filter(|s| s.kind == "rule") {
        if r.get("use_policy") != default_policy.as_deref() {
            plan.unmapped.push(format!(
                "mwan3: rule '{}' (only the default rule is imported: per-traffic policies become firewall rules with a gateway)",
                r.label()
            ));
        }
    }
    for g in secs.iter().filter(|s| s.kind == "globals") {
        plan.covered.push(format!(
            "mwan3: globals '{}' (mark mask: Patronus owns its own fwmark range)",
            g.label()
        ));
    }
    x.gateways = gws.into_values().collect();
}

fn ddns_ext(plan: &mut Plan, x: &mut ExtPlan, files: &Files) {
    let Some(secs) = files.get("ddns") else {
        return;
    };
    for s in secs {
        if s.kind == "ddns" {
            plan.covered
                .push("ddns: global settings (log/run dirs, date format)".into());
            continue;
        }
        if s.kind != "service" {
            continue;
        }
        let svc = s.get("service_name").unwrap_or("");
        let (provider, server) = match svc {
            "no-ip.com" | "noip.com" => ("dyndns2", Some("dynupdate.no-ip.com".to_string())),
            "dyndns.org" | "dyn.com" => ("dyndns2", Some("members.dyndns.org".to_string())),
            "duckdns.org" => ("duckdns", None),
            "cloudflare.com-v4" => ("cloudflare", None),
            other => {
                plan.unmapped.push(format!(
                    "ddns: service '{}' provider '{other}' (not imported: add it as a custom DDNS client)",
                    s.label()
                ));
                continue;
            }
        };
        let host = s
            .get("lookup_host")
            .or(s.get("domain"))
            .unwrap_or("")
            .to_string();
        let v6 = s.flag("use_ipv6") == Some(true)
            || s.get("ip_network").is_some_and(|n| n.ends_with('6'))
            || s.get("interface").is_some_and(|n| n.ends_with('6'));
        let fam = if v6 { "ipv6" } else { "ipv4" };
        let enabled = s.flag("enabled") == Some(true);
        let (user, pass) = (
            s.get("username").map(str::to_string),
            s.get("password").map(str::to_string),
        );
        if let Some(e) = x
            .ddns
            .iter_mut()
            .find(|d| d.provider == provider && d.hostname == host && d.username == user)
        {
            if e.family != fam {
                e.family = "both".into();
            }
            e.enabled |= enabled;
            continue;
        }
        x.ddns.push(DdnsPlan {
            provider: provider.into(),
            hostname: host,
            server,
            username: user,
            password: pass,
            family: fam.into(),
            interface: "@wan".into(),
            enabled,
        });
    }
}

fn system_ext(plan: &mut Plan, x: &mut ExtPlan, files: &Files) {
    let Some(secs) = files.get("system") else {
        return;
    };
    for s in secs {
        match s.kind.as_str() {
            "system" => {
                // "OpenWrt" is the firmware's stock default, not a name anybody chose:
                // keep the name the new box was installed with instead
                let host = s
                    .get("hostname")
                    .map(|h| h.to_ascii_lowercase())
                    .filter(|h| h != "openwrt");
                if s.get("hostname").is_some() && host.is_none() {
                    plan.notes.push(
                        "system: hostname 'OpenWrt' is the stock default, the installed host name is kept"
                            .into(),
                    );
                }
                let tz = s.get("zonename").map(|z| z.replace(' ', "_")).or_else(|| {
                    match s.get("timezone") {
                        Some("UTC") | Some("GMT0") | Some("UTC0") => Some("UTC".to_string()),
                        Some(t) => {
                            plan.unmapped.push(format!(
                                "system: timezone '{t}' without zonename (set the time zone on the General page)"
                            ));
                            None
                        }
                        None => None,
                    }
                });
                x.general = Some((host, tz));
                let left = s.leftover(&[
                    "hostname",
                    "timezone",
                    "zonename",
                    "ttylogin",
                    "log_size",
                    "urandom_seed",
                    "log_proto",
                    "conloglevel",
                    "cronloglevel",
                ]);
                if s.get("log_ip").is_some() {
                    plan.unmapped.push(
                        "system: remote syslog (log_ip): configure it on the Logging page (lane J syslog)"
                            .into(),
                    );
                }
                if !left.is_empty() {
                    plan.unmapped.push(format!(
                        "system: system: option(s) not imported: {}",
                        left.join(", ")
                    ));
                }
                plan.covered.push(
                    "system: log_size / log levels / ttylogin / urandom_seed (Patronus logging and console defaults)"
                        .into(),
                );
            }
            "timeserver" => {
                let ifs: Vec<String> = s
                    .words("interface")
                    .iter()
                    .map(|i| format!("@{i}"))
                    .collect();
                x.ntp = Some((
                    s.flag("enable_server") == Some(true),
                    s.words("server"),
                    if ifs.is_empty() {
                        vec!["@lan".into()]
                    } else {
                        ifs
                    },
                ));
            }
            _ => plan
                .unmapped
                .push(format!("system: {} '{}' (not imported)", s.kind, s.label())),
        }
    }
    drop_lines(&mut plan.unmapped, |l| {
        l.starts_with("system: system '") || l.starts_with("system: timeserver '")
    });
}

fn sshd_ext(plan: &mut Plan, x: &mut ExtPlan, files: &Files, extras: &Extras) {
    for d in sections(files, "dropbear", "dropbear") {
        plan.unmapped.push(format!(
            "dropbear: '{}' port {} (Patronus runs one OpenSSH server; a second fallback daemon is not imported)",
            d.label(),
            d.get("Port").unwrap_or("22")
        ));
    }
    let Some(cfg) = extras.get("etc/ssh/sshd_config") else {
        return;
    };
    let mut listen = Vec::new();
    let mut principals_path: Option<String> = None;
    for line in cfg.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
        match k.to_ascii_lowercase().as_str() {
            "port" => x.sys("ssh.port", v),
            "listenaddress" => listen.push(v.trim_matches(['[', ']']).to_string()),
            "passwordauthentication" => x.sys("ssh.password_auth", if v == "yes" { "1" } else { "0" }),
            "permitrootlogin" => x.sys(
                "ssh.root_login",
                match v {
                    "without-password" => "prohibit-password",
                    o => o,
                },
            ),
            "trustedusercakeys" => match extras.get(v) {
                Some(t) => x.sys("ssh.trusted_user_ca_keys", t.trim()),
                None => plan.unmapped.push(format!(
                    "sshd: TrustedUserCAKeys {v}: file not in the input (copy the CA public key into ssh.trusted_user_ca_keys)"
                )),
            },
            "authorizedprincipalsfile" => principals_path = Some(v.to_string()),
            "hostcertificate" => plan.notes.push(format!(
                "sshd: HostCertificate {v}: not imported (it certifies the old router's host key; sign this unit's key and set ssh.host_certificate)"
            )),
            "authorizedkeysfile" => plan.unmapped.push(format!(
                "sshd: AuthorizedKeysFile {v}: per-user authorized keys are not imported (add the admin keys on the Users page)"
            )),
            "hostkey" | "subsystem" | "x11forwarding" | "allowagentforwarding" | "pubkeyauthentication"
            | "kbdinteractiveauthentication" | "challengeresponseauthentication" | "usepam" => {}
            other => plan
                .unmapped
                .push(format!("sshd: {other} (not imported)")),
        }
    }
    if !listen.is_empty() {
        x.sys("ssh.listen", listen.join(","));
    }
    if let Some(p) = principals_path {
        // `/etc/ssh/auth_principals/%u` -> every file of that directory
        let dir = p.trim_start_matches('/').trim_end_matches("%u").to_string();
        let mut map = serde_json::Map::new();
        for (path, text) in &extras.0 {
            if let Some(user) = path.strip_prefix(&dir) {
                if !user.is_empty() && !user.contains('/') {
                    let v: Vec<serde_json::Value> = text
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(|l| serde_json::Value::String(l.to_string()))
                        .collect();
                    map.insert(user.to_string(), serde_json::Value::Array(v));
                }
            }
        }
        if map.is_empty() || !p.contains("%u") {
            plan.unmapped.push(format!(
                "sshd: AuthorizedPrincipalsFile {p}: no principals files in the input"
            ));
        } else {
            x.sys(
                "ssh.authorized_principals",
                serde_json::Value::Object(map).to_string(),
            );
        }
    }
}

fn wireless_ext(plan: &mut Plan, x: &mut ExtPlan, maps: &BTreeMap<String, String>) {
    // one uplink per radio device: the first enabled network (the rest stay parked in the report)
    for w in plan.wifi.iter().filter(|w| w.mode == "sta" && !w.disabled) {
        let dev = maps
            .get(&w.section)
            .or_else(|| maps.get(&w.network))
            .cloned();
        if x.wifi_clients.iter().any(|c| c.device == dev) {
            continue;
        }
        let security = match w.encryption.as_str() {
            "none" | "" => "open",
            "sae" => "wpa3",
            "sae-mixed" => "wpa2-wpa3",
            _ => "wpa2",
        };
        x.wifi_clients.push(WifiClientPlan {
            section: w.section.clone(),
            device: dev,
            ssid: w.ssid.clone(),
            security: security.into(),
            psk: w.key.clone(),
            bssid: None,
            enabled: !w.disabled,
        });
    }
}

fn other_files(plan: &mut Plan) {
    const WHY: &[(&str, &str)] = &[
        ("acme", "certificates: use the TLS page (ACME) of Patronus"),
        ("luci", "LuCI web UI settings (Patronus has its own web UI)"),
        ("rpcd", "LuCI/ubus RPC accounts (Patronus web accounts are separate)"),
        ("uhttpd", "LuCI web server (Patronus web UI: TLS on 443)"),
        ("ucitrack", "OpenWrt internal service dependency table"),
        ("attendedsysupgrade", "OpenWrt firmware upgrade client (Patronus updates through its stable channel)"),
        ("wgserver", "wg-installer server (automatic mesh tunnels), not imported"),
        ("socat", "socat forwarders: recreate as port forwards"),
        ("vnstat", "vnstat traffic accounting: Patronus records interface and per-device traffic history itself"),
        ("patronus_lab", "a lab steering helper, not router configuration"),
        ("openssl", "OpenSSL engine settings"),
        ("dropbear", "see the dropbear lines above"),
        ("mwan3", "imported (see routing)"),
        ("ddns", "imported (see DDNS)"),
    ];
    let mut out = Vec::new();
    for l in plan.unmapped.drain(..) {
        let file = l
            .strip_suffix(" section(s))")
            .and_then(|_| l.split_once(": file not imported"))
            .map(|(f, _)| f.to_string());
        match file.and_then(|f| WHY.iter().find(|(n, _)| *n == f)) {
            Some((n, why)) if why.starts_with("imported") || why.starts_with("see") => {
                let _ = n;
            }
            Some((n, why)) => out.push(format!("{n}: not imported: {why}")),
            None => out.push(l),
        }
    }
    plan.unmapped = out;
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

pub fn render_ext(x: &ExtPlan, o: &mut String, verb: &str) {
    use std::fmt::Write;
    let shown = |(k, v, s): &Setting| -> String {
        let secretish = *s || k.contains("key") || k.contains("password") || k.contains("psk");
        let v = if secretish && !k.starts_with("ssh.") {
            "(set)".to_string()
        } else if v.len() > 120 {
            format!(
                "{}... ({} chars)",
                &v[..v.char_indices().nth(100).map(|c| c.0).unwrap_or(v.len())],
                v.len()
            )
        } else {
            v.clone()
        };
        format!("{k} = {v}")
    };
    let _ = writeln!(o, "\nsettings ({verb}):");
    for s in x.lan_settings.iter().chain(&x.sys_settings) {
        let _ = writeln!(o, "  {}", shown(s));
    }
    if let Some((h, tz)) = &x.general {
        let _ = writeln!(
            o,
            "  general: hostname {} timezone {}",
            h.as_deref().unwrap_or("-"),
            tz.as_deref().unwrap_or("-")
        );
    }
    if let Some((on, servers, ifs)) = &x.ntp {
        let _ = writeln!(
            o,
            "  ntp: server {} upstreams {} on {}",
            if *on { "on" } else { "off" },
            servers.join(","),
            ifs.join(",")
        );
    }
    let _ = writeln!(o, "\nipv6 ({verb}):");
    for (d, e) in &x.iface6 {
        let _ = writeln!(
            o,
            "  {d}: static {}{}{}",
            if e.addrs.is_empty() {
                "-".to_string()
            } else {
                e.addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            },
            if e.pd_downstream.is_empty() {
                String::new()
            } else {
                format!(", prefix delegation to {}", e.pd_downstream.join(","))
            },
            if e.duid.is_some() {
                ", DHCPv6 DUID kept"
            } else {
                ""
            }
        );
    }
    for (d, m, st) in &x.ra {
        let _ = writeln!(
            o,
            "  RA on {d}: {m}{}",
            if *st {
                ", stateful DHCPv6 pool ::1000-::ffff following the interface prefixes"
            } else {
                ""
            }
        );
    }
    let _ = writeln!(o, "\ndns ({verb}):");
    for (h, d, a) in &x.hosts {
        let _ = writeln!(o, "  host {h}.{d} -> {a}");
    }
    for (d, s) in &x.domains {
        let _ = writeln!(o, "  forward {d} -> {s}");
    }
    for (dev, v) in &x.pool_dns {
        let _ = writeln!(o, "  DHCP clients on {dev} get DNS {v}");
    }
    for (dev, v) in &x.pool_dns6 {
        let _ = writeln!(o, "  IPv6 clients on {dev} get DNS {v} (RA + DHCPv6)");
    }
    for (ip, (lt, dns)) in &x.static_opts {
        let _ = writeln!(
            o,
            "  static lease {ip}: lease {}{}",
            match lt {
                Some(0) => "infinite".into(),
                Some(s) => format!("{s}s"),
                None => "pool".into(),
            },
            if *dns { ", DNS record" } else { "" }
        );
    }
    let _ = writeln!(o, "\nrouting ({verb}):");
    for r in &x.routes {
        let _ = writeln!(
            o,
            "  route {} via {} dev {}",
            r.destination,
            r.gateway.as_deref().unwrap_or("-"),
            r.interface.as_deref().unwrap_or("-")
        );
    }
    for g in &x.gateways {
        let _ = writeln!(
            o,
            "  gateway {} on {} ({}): monitor {} need {} every {}s down {} up {}",
            g.name,
            g.interface,
            g.family,
            g.monitor_ips.join(","),
            g.reliability,
            g.interval,
            g.down,
            g.up
        );
    }
    for g in &x.groups {
        let _ = writeln!(
            o,
            "  group {}: {}{}",
            g.name,
            g.members
                .iter()
                .map(|(n, t, w)| format!("{n} tier {t} weight {w}"))
                .collect::<Vec<_>>()
                .join(", "),
            if g.default4 {
                " (IPv4 default gateway)"
            } else {
                ""
            }
        );
    }
    let _ = writeln!(o, "\nwireguard ({verb}, keys stay in the store):");
    for w in &x.wg {
        let _ = writeln!(
            o,
            "  tunnel {} (UCI {}): port {} addresses {} mtu {} private key: {}",
            w.device,
            w.uci,
            w.listen_port.map(|p| p.to_string()).unwrap_or("-".into()),
            w.addresses.join(","),
            w.mtu.map(|m| m.to_string()).unwrap_or("-".into()),
            if w.private_key.is_some() {
                "(kept)"
            } else {
                "(none: a new one is generated)"
            }
        );
        for p in &w.peers {
            let _ = writeln!(
                o,
                "    peer {} \"{}\": allowed {}{}{}, preshared key {}{}",
                p.name,
                p.description.as_deref().unwrap_or(""),
                p.allowed_ips.join(","),
                p.endpoint
                    .as_ref()
                    .map(|e| format!(" endpoint {e}"))
                    .unwrap_or_default(),
                p.keepalive
                    .map(|k| format!(" keepalive {k}"))
                    .unwrap_or_default(),
                if p.preshared_key.is_some() {
                    "kept"
                } else {
                    "none"
                },
                if p.enabled { "" } else { " disabled" }
            );
        }
    }
    let _ = writeln!(o, "\nddns ({verb}):");
    for d in &x.ddns {
        let _ = writeln!(
            o,
            "  {} {} family {} on {}, login {}{}",
            d.provider,
            d.hostname,
            d.family,
            d.interface,
            if d.password.is_some() { "kept" } else { "none" },
            if d.enabled { "" } else { " disabled" }
        );
    }
    let _ = writeln!(o, "\nwifi uplink ({verb}):");
    for w in &x.wifi_clients {
        let _ = writeln!(
            o,
            "  {} on {}: ssid '{}' {}, passphrase {}{}",
            w.section,
            w.device.as_deref().unwrap_or("(no --map: not written)"),
            w.ssid,
            w.security,
            if w.psk.is_some() { "kept" } else { "none" },
            if w.enabled { "" } else { " disabled" }
        );
    }
}

// ---------------------------------------------------------------------------
// store writes
// ---------------------------------------------------------------------------

pub async fn apply_ext(
    store: &patronus_config::store::ConfigStore,
    plan: &Plan,
    out: &mut Vec<String>,
) -> Result<()> {
    let x = &plan.ext;
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    for (k, v, _) in &x.lan_settings {
        patronus_network::lan::set_setting(store, k, v)
            .await
            .map_err(e)?;
    }
    for (k, v, _) in &x.sys_settings {
        store.save_system_config(k, v).await.map_err(e)?;
    }
    if !x.lan_settings.is_empty() || !x.sys_settings.is_empty() {
        out.push(format!(
            "settings: {} written",
            x.lan_settings.len() + x.sys_settings.len()
        ));
    }
    if let Some((h, tz)) = &x.general {
        let r = patronus_network::general::save_settings(
            store,
            &patronus_network::general::GeneralInput {
                hostname: h.clone(),
                domain: None,
                timezone: tz.clone(),
            },
        )
        .await;
        out.push(match r {
            Ok(()) => "general: hostname/timezone written".into(),
            Err(x) => format!("general: skipped ({x})"),
        });
    }
    // IPv6 extras on the interfaces written by the base importer
    if !x.iface6.is_empty() {
        let mut cfg = NetConfig::load(store).await.map_err(e)?;
        for (dev, i6) in &x.iface6 {
            let i = cfg.iface_mut(dev);
            if !i6.addrs.is_empty() {
                for a in &i6.addrs {
                    if !i.ipv6.contains(a) {
                        i.ipv6.push(*a);
                    }
                }
                if matches!(i.ipv6_mode, V6Mode::Unmanaged | V6Mode::None) {
                    i.ipv6_mode = V6Mode::Static;
                }
            }
            if !i6.pd_downstream.is_empty() {
                i.pd_downstream = i6.pd_downstream.clone();
            }
            if let Some(d) = &i6.duid {
                i.dhcp6_duid = Some(d.clone());
            }
            if let Some(m) = i6.metric {
                i.metric = Some(m);
            }
        }
        cfg.save(store).await.map_err(e)?;
        out.push(format!("ipv6: {} interface(s) updated", x.iface6.len()));
    }
    #[cfg(feature = "dhcp-server")]
    {
        use patronus_network::{dhcp, dhcp6, ra};
        let pools = dhcp::list_pools(store).await.map_err(e)?;
        for (dev, servers) in &x.pool_dns {
            if let Some(p) = pools.iter().find(|p| p.interface == *dev) {
                let mut q = p.clone();
                q.dns_servers = servers
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                dhcp::upsert_pool(store, Some(p.id), &q).await.map_err(e)?;
                out.push(format!("dhcp pool on {dev}: DNS servers {servers}"));
            }
        }
        let have_ra = ra::list(store).await.map_err(e)?;
        let have6 = dhcp6::list(store).await.map_err(e)?;
        for (dev, mode, stateful) in &x.ra {
            if !have_ra.iter().any(|r| r.interface == *dev) {
                let c = ra::RaInput {
                    interface: dev.clone(),
                    enabled: true,
                    mode: Some(mode.clone()),
                    dns_servers: x.pool_dns6.get(dev).cloned(),
                    description: Some("imported from OpenWrt UCI".into()),
                    ..Default::default()
                }
                .validate()
                .map_err(e)?;
                ra::upsert(store, None, &c).await.map_err(e)?;
                out.push(format!("router advertisements on {dev}: {mode}"));
            }
            if *stateful && !have6.iter().any(|p| p.interface == *dev) {
                let p = dhcp6::Dhcp6Input {
                    interface: dev.clone(),
                    enabled: true,
                    range_start: "::1000".into(),
                    range_end: "::ffff".into(),
                    dns_servers: x.pool_dns6.get(dev).cloned(),
                    description: Some(
                        "imported from OpenWrt UCI (follows the interface prefixes)".into(),
                    ),
                    ..Default::default()
                }
                .validate()
                .map_err(e)?;
                dhcp6::upsert(store, None, &p).await.map_err(e)?;
                out.push(format!("DHCPv6 pool on {dev}: ::1000-::ffff"));
            }
        }
    }
    #[cfg(feature = "dns-server")]
    {
        use patronus_network::dns;
        let hosts = dns::list_hosts(store).await.map_err(e)?;
        for (h, d, a) in &x.hosts {
            if hosts
                .iter()
                .any(|x| x.hostname == *h && x.domain == *d && x.address == *a)
            {
                continue;
            }
            match (dns::HostInput {
                hostname: h.clone(),
                domain: d.clone(),
                address: a.to_string(),
                description: Some("imported from OpenWrt UCI".into()),
            })
            .validate()
            {
                Ok(v) => {
                    dns::add_host(store, &v).await.map_err(e)?;
                }
                Err(err) => out.push(format!("dns host {h}.{d}: skipped ({err})")),
            }
        }
        let doms = dns::list_domains(store).await.map_err(e)?;
        for (d, s) in &x.domains {
            match (dns::DomainInput {
                domain: d.clone(),
                server: s.clone(),
                description: Some("imported from OpenWrt UCI".into()),
            })
            .validate()
            {
                Ok(v)
                    if doms
                        .iter()
                        .any(|x| x.domain == v.domain && x.server == v.server) => {}
                Ok(v) => {
                    dns::add_domain(store, &v).await.map_err(e)?;
                }
                Err(err) => out.push(format!("dns forward {d}: skipped ({err})")),
            }
        }
        if !x.hosts.is_empty() || !x.domains.is_empty() {
            out.push(format!(
                "dns: {} host record(s), {} forwarding rule(s)",
                x.hosts.len(),
                x.domains.len()
            ));
        }
        let have = dns_ddns_list(store).await?;
        for d in &x.ddns {
            if have
                .iter()
                .any(|(p, h)| *p == d.provider && *h == d.hostname)
            {
                out.push(format!("ddns {}: already present", d.hostname));
                continue;
            }
            let c = patronus_network::ddns::DdnsInput {
                enabled: d.enabled,
                provider: d.provider.clone(),
                hostname: d.hostname.clone(),
                interface: Some(d.interface.clone()),
                username: d.username.clone(),
                password: d.password.clone(),
                server: d.server.clone(),
                description: Some("imported from OpenWrt UCI".into()),
                family: Some(d.family.clone()),
            }
            .validate(None);
            match c {
                Ok(c) => {
                    patronus_network::ddns::upsert(store, None, &c)
                        .await
                        .map_err(e)?;
                    out.push(format!(
                        "ddns {} ({}): created, credentials: (set)",
                        d.hostname, d.family
                    ));
                }
                Err(err) => out.push(format!("ddns {}: skipped ({err})", d.hostname)),
            }
        }
    }
    #[cfg(feature = "ntp-server")]
    if let Some((on, servers, ifs)) = &x.ntp {
        patronus_network::ntp::save_settings(
            store,
            &patronus_network::ntp::NtpInput {
                enabled: Some(*on),
                servers: Some(servers.join(",")),
                interfaces: Some(ifs.join(",")),
            },
        )
        .await
        .map_err(e)?;
        out.push(format!("ntp: server {}", if *on { "on" } else { "off" }));
    }
    #[cfg(feature = "vpn-wireguard")]
    for w in &x.wg {
        use patronus_network::wireguard as wgm;
        let existing = wgm::list_interfaces(store).await.map_err(e)?;
        if existing.iter().any(|i| i.name == w.device) {
            out.push(format!("wireguard {}: already present", w.device));
            continue;
        }
        wgm::save_interface(
            store,
            None,
            &wgm::InterfaceInput {
                name: Some(w.device.clone()),
                enabled: Some(true),
                listen_port: w.listen_port,
                addresses: Some(w.addresses.join(", ")),
                mtu: w.mtu,
                description: Some(format!("imported from OpenWrt UCI interface {}", w.uci)),
                ..Default::default()
            },
        )
        .await
        .map_err(e)?;
        if let Some(k) = &w.private_key {
            let k = wgm::check_key("tunnel private key", k).map_err(e)?;
            sqlx::query("UPDATE wg_interfaces SET private_key = ? WHERE name = ?")
                .bind(k)
                .bind(&w.device)
                .execute(store.pool().map_err(e)?)
                .await
                .map_err(|x| anyhow::anyhow!("wg_interfaces: {x}"))?;
        }
        let mut n = 0;
        for p in &w.peers {
            let id = match wgm::save_peer(
                store,
                None,
                &wgm::PeerInput {
                    interface: Some(w.device.clone()),
                    name: Some(p.name.clone()),
                    enabled: Some(p.enabled),
                    public_key: Some(p.public_key.clone()),
                    allowed_ips: Some(p.allowed_ips.join(", ")),
                    endpoint: p.endpoint.clone(),
                    persistent_keepalive: p.keepalive,
                    preshared_key: None,
                    description: p.description.clone(),
                },
            )
            .await
            {
                Ok(id) => id,
                Err(err) => {
                    out.push(format!("wireguard peer {}: skipped ({err})", p.name));
                    continue;
                }
            };
            for (col, v) in [
                ("private_key", &p.private_key),
                ("preshared_key", &p.preshared_key),
            ] {
                if let Some(v) = v {
                    let v = wgm::check_key("peer key", v).map_err(e)?;
                    sqlx::query(&format!("UPDATE wg_peers SET {col} = ? WHERE id = ?"))
                        .bind(v)
                        .bind(id)
                        .execute(store.pool().map_err(e)?)
                        .await
                        .map_err(|x| anyhow::anyhow!("wg_peers: {x}"))?;
                }
            }
            n += 1;
        }
        out.push(format!(
            "wireguard {}: tunnel with the same key/port/addresses, {n} peer(s), keys: (kept)",
            w.device
        ));
    }
    if !x.routes.is_empty() {
        let cfg = patronus_network::routes::load(store).await.map_err(e)?;
        for r in &x.routes {
            if cfg
                .routes
                .iter()
                .any(|s| s.destination.to_string() == r.destination)
            {
                out.push(format!("route {}: already present", r.destination));
                continue;
            }
            let v = patronus_network::routes::RouteInput {
                destination: r.destination.clone(),
                gateway: r.gateway.clone(),
                interface: r.interface.clone(),
                metric: r.metric,
                description: Some("imported from OpenWrt UCI".into()),
                enabled: Some(true),
            }
            .validated(&cfg, 0);
            match v {
                Ok(v) => {
                    patronus_network::routes::save_route(store, None, &v)
                        .await
                        .map_err(e)?;
                    out.push(format!("route {}: created", r.destination));
                }
                Err(err) => out.push(format!("route {}: skipped ({err})", r.destination)),
            }
        }
    }
    if !x.gateways.is_empty() {
        use patronus_network::routes as rt;
        let cfg = rt::load(store).await.map_err(e)?;
        for g in &x.gateways {
            if cfg.gateways.iter().any(|c| c.name == g.name) {
                out.push(format!("gateway {}: already present", g.name));
                continue;
            }
            let v = rt::GatewayInput {
                name: g.name.clone(),
                interface: g.interface.clone(),
                family: Some(g.family.clone()),
                monitor_ips: Some(g.monitor_ips.join(",")),
                monitor_reliability: Some(g.reliability),
                monitor_interval: Some(g.interval),
                monitor_down: Some(g.down),
                monitor_up: Some(g.up),
                monitor_enabled: Some(true),
                description: Some("imported from OpenWrt mwan3".into()),
                ..Default::default()
            }
            .validated()
            .map_err(e)?;
            rt::save_gateway(store, None, &v).await.map_err(e)?;
            out.push(format!("gateway {}: created", g.name));
        }
        for gr in &x.groups {
            let spec = gr
                .members
                .iter()
                .map(|(n, t, w)| format!("{n}:{t}:{w}"))
                .collect::<Vec<_>>()
                .join(",");
            let v = rt::GroupInput {
                name: gr.name.clone(),
                trigger: Some("down".into()),
                members: rt::MembersInput::Spec(spec),
                description: Some("imported from OpenWrt mwan3".into()),
            }
            .validated();
            match v {
                Ok(v) => match rt::save_group(store, None, &v).await {
                    Ok(()) => {
                        out.push(format!("gateway group {}: created", gr.name));
                        if gr.default4 {
                            rt::set_default(store, rt::Family::Inet, Some(&gr.name))
                                .await
                                .map_err(e)?;
                            out.push(format!("IPv4 default gateway: group {}", gr.name));
                        }
                    }
                    Err(err) => out.push(format!("gateway group {}: skipped ({err})", gr.name)),
                },
                Err(err) => out.push(format!("gateway group {}: skipped ({err})", gr.name)),
            }
        }
    }
    #[cfg(feature = "wifi-client")]
    for w in &x.wifi_clients {
        let Some(dev) = &w.device else {
            out.push(format!(
                "wifi uplink {}: not written (pass --map {}=DEVICE)",
                w.section, w.section
            ));
            continue;
        };
        let r = patronus_network::wifi_client::save(
            store,
            &patronus_network::wifi_client::WifiClientInput {
                device: dev.clone(),
                enabled: Some(w.enabled),
                ssid: w.ssid.clone(),
                security: Some(w.security.clone()),
                psk: w.psk.clone(),
                bssid: w.bssid.clone(),
                description: Some(format!("imported from OpenWrt UCI {}", w.section)),
            },
        )
        .await;
        out.push(match r {
            Ok(_) => format!("wifi uplink on {dev}: ssid '{}', key: (set)", w.ssid),
            Err(err) => format!("wifi uplink on {dev}: skipped ({err})"),
        });
    }
    Ok(())
}

#[cfg(feature = "dns-server")]
async fn dns_ddns_list(
    store: &patronus_config::store::ConfigStore,
) -> Result<Vec<(String, String)>> {
    Ok(patronus_network::ddns::list(store)
        .await
        .map_err(|x| anyhow::anyhow!("{x}"))?
        .into_iter()
        .map(|c| (c.provider, c.hostname))
        .collect())
}

/// `patronus import-uci --ssh root@router[:port]`: stream the needed files
/// over ssh into a 0700 scratch tarball (keys never touch stdout or a log).
pub fn fetch_over_ssh(target: &str, dir: &Path) -> Result<PathBuf> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.contains(':') => {
            (h.to_string(), Some(p.to_string()))
        }
        _ => (target.to_string(), None),
    };
    let out = dir.join("router-config.tar.gz");
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_0600()
        .open(&out)
        .with_context(|| format!("create {}", out.display()))?;
    let mut cmd = std::process::Command::new("ssh");
    if let Some(p) = port {
        cmd.arg("-p").arg(p);
    }
    let remote = "cd / && tar czf - etc/config $(ls etc/ssh/sshd_config etc/ssh/*.pub etc/*.nft 2>/dev/null) \
                  $( [ -d etc/ssh/auth_principals ] && echo etc/ssh/auth_principals )";
    let st = cmd
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(&host)
        .arg(remote)
        .stdout(f)
        .status()
        .context("run ssh")?;
    if !st.success() {
        bail!("ssh {target}: reading the router configuration failed ({st})");
    }
    Ok(out)
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}

impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::store::ConfigStore;

    fn dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/uci-x86-router")
    }

    fn maps() -> BTreeMap<String, String> {
        parse_maps(&[
            "lan=eth0".into(),
            "wan=eth1".into(),
            "wwan=wlan0".into(),
            "wwan_sta=wlan0".into(),
            "vpn=wg0".into(),
        ])
        .unwrap()
    }

    fn plan() -> Plan {
        let (f, x) = load_input_full(&dir()).unwrap();
        build_plan_with(&f, &x, &maps())
    }

    fn setting<'a>(v: &'a [Setting], k: &str) -> Option<&'a str> {
        v.iter()
            .find(|(a, _, _)| a == k)
            .map(|(_, b, _)| b.as_str())
    }

    #[test]
    fn ula_slots_follow_openwrt_order() {
        let a = ula_assign(
            "fd12:3456:789a::/48",
            &[("eth0".into(), 60), ("wg0".into(), 64)],
        );
        assert_eq!(
            a[0],
            ("eth0".into(), "fd12:3456:789a::1/64".parse().unwrap())
        );
        assert_eq!(
            a[1],
            ("wg0".into(), "fd12:3456:789a:10::1/64".parse().unwrap())
        );
        assert!(ula_assign("garbage", &[("x".into(), 64)]).is_empty());
    }

    #[test]
    fn extras_are_limited_to_safe_files() {
        assert!(wanted_extra("etc/ssh/sshd_config"));
        assert!(wanted_extra("./etc/ssh/user_ca.pub"));
        assert!(wanted_extra("etc/ssh/auth_principals/root"));
        assert!(wanted_extra("etc/drop-ipopts.nft"));
        assert!(!wanted_extra("etc/ssh/ssh_host_ed25519_key"));
        assert!(!wanted_extra("etc/shadow"));
        assert!(!wanted_extra("etc/ssh/auth_principals/a/b"));
    }

    #[test]
    fn full_router_plan() {
        let p = plan();
        let x = &p.ext;
        // dns
        assert_eq!(
            setting(&x.lan_settings, "dns.local_domain"),
            Some("home.example")
        );
        assert_eq!(setting(&x.lan_settings, "dns.cache_size"), Some("1000"));
        assert_eq!(setting(&x.lan_settings, "dns.log_queries"), Some("1"));
        assert_eq!(setting(&x.lan_settings, "dns.interfaces"), Some("@lan,wg0"));
        assert_eq!(
            setting(&x.lan_settings, "dns.rebind_exceptions"),
            Some("home.example,corp.example,internal-lb-1.elb.example.net")
        );
        assert_eq!(x.domains.len(), 4);
        assert!(x
            .domains
            .contains(&("10.in-addr.arpa".into(), "203.0.113.53".into())));
        assert!(x.hosts.contains(&(
            "dns-a".into(),
            "home.example".into(),
            "192.168.50.3".parse().unwrap()
        )));
        assert!(x.hosts.contains(&(
            "router".into(),
            "home.example".into(),
            "192.168.50.1".parse().unwrap()
        )));
        assert_eq!(
            x.pool_dns.get("eth0").map(String::as_str),
            Some("192.168.50.3,192.168.50.4")
        );
        assert_eq!(
            x.static_opts.get(&"192.168.50.21".parse().unwrap()),
            Some(&(Some(0), true))
        );
        // ipv6
        let lan = &x.iface6["eth0"];
        assert_eq!(
            lan.addrs,
            vec!["fd12:3456:789a::1/64".parse::<IpNetwork>().unwrap()]
        );
        let wan = &x.iface6["eth1"];
        assert_eq!(wan.pd_downstream, vec!["eth0".to_string()]);
        assert_eq!(
            wan.duid.as_deref(),
            Some("00:04:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
        );
        assert_eq!(x.ra, vec![("eth0".into(), "assisted".into(), true)]);
        assert_eq!(
            x.pool_dns6.get("eth0").map(String::as_str),
            Some("fd12:3456:789a::3")
        );
        // an IPv6 port forward (family ipv6) is imported, disabled like its source
        assert!(p
            .nat_rules
            .iter()
            .any(|r| r.name.starts_with("web_ipv6") && !r.enabled));
        // wireguard
        assert_eq!(x.wg.len(), 1);
        let w = &x.wg[0];
        assert_eq!(
            (w.device.as_str(), w.listen_port, w.mtu),
            ("wg0", Some(51820), Some(1400))
        );
        assert_eq!(
            w.addresses,
            vec!["10.99.0.1/24".to_string(), "fd12:3456:789a:10::1/64".into()]
        );
        assert_eq!(w.peers.len(), 3);
        assert_eq!(w.peers[0].name, "site-b");
        assert!(w.peers[0].private_key.is_some());
        assert_eq!(w.peers[2].name, "ci-runner-restricted");
        // routes
        assert!(x.routes.iter().any(|r| r.destination == "203.0.113.53/32"
            && r.gateway.as_deref() == Some("192.168.50.60")
            && r.interface.as_deref() == Some("@lan")));
        assert!(x.routes.iter().any(|r| r.destination == "10.200.0.0/24"));
        // firewall + system
        assert_eq!(
            setting(&x.sys_settings, "firewall.inbound_action"),
            Some("reject")
        );
        assert_eq!(
            setting(&x.sys_settings, "firewall.synflood_protect"),
            Some("1")
        );
        assert_eq!(setting(&x.sys_settings, "firewall.mss_clamp"), Some("@wan"));
        assert_eq!(
            setting(&x.sys_settings, "firewall.drop_ipv4_options"),
            Some("1")
        );
        assert_eq!(
            setting(&x.sys_settings, "system.packet_steering"),
            Some("1")
        );
        assert!(p
            .nat_rules
            .iter()
            .any(|r| r.interface_out.as_deref() == Some("wg0")));
        // the "redirect to the router itself" became an input allow, not a DNAT
        assert!(p
            .fw_rules
            .iter()
            .any(|r| r.name == "WireGuard" && r.chain == ChainType::Input));
        assert!(!p.nat_rules.iter().any(|f| f.name == "WireGuard"));
        // DROP rule for the restricted peer, accept to one host:port
        assert!(p
            .fw_rules
            .iter()
            .any(|r| r.name.starts_with("ci-deny-router") && r.action == FirewallAction::Drop));
        assert!(p
            .fw_rules
            .iter()
            .any(|r| r.name.starts_with("ci-allow-one-port")));
        // the tunnel in the lan zone gets the zone's policies (fw4 semantics)
        let fwd = |i: &str, o: &str| {
            p.fw_rules.iter().any(|r| {
                r.chain == ChainType::Forward
                    && r.interface_in.as_deref() == Some(i)
                    && r.interface_out.as_deref() == Some(o)
            })
        };
        assert!(fwd("wg0", "@lan") && fwd("@lan", "wg0") && fwd("wg0", "@wan"));
        assert!(p
            .fw_rules
            .iter()
            .any(|r| r.chain == ChainType::Input && r.interface_in.as_deref() == Some("wg0")));
        // mwan3
        assert_eq!(x.gateways.len(), 2);
        let g = x.gateways.iter().find(|g| g.name == "wan").unwrap();
        assert_eq!((g.reliability, g.monitor_ips.len()), (2, 3));
        assert_eq!(x.groups.len(), 1);
        assert!(x.groups[0].default4);
        assert_eq!(
            x.groups[0].members,
            vec![("wan".into(), 1, 3), ("wwan".into(), 2, 3)]
        );
        // ddns pair -> one client, both families
        assert_eq!(x.ddns.len(), 1);
        assert_eq!(x.ddns[0].family, "both");
        assert_eq!(x.ddns[0].provider, "dyndns2");
        // system: the stock default name "OpenWrt" is not carried (the installed name stays)
        assert_eq!(x.general, Some((None, Some("America/Los_Angeles".into()))));
        assert!(p
            .notes
            .iter()
            .any(|n| n.contains("hostname 'OpenWrt' is the stock default")));
        assert!(x.ntp.as_ref().unwrap().0);
        // sshd
        assert_eq!(setting(&x.sys_settings, "ssh.port"), Some("2222"));
        assert_eq!(
            setting(&x.sys_settings, "ssh.listen"),
            Some("192.168.50.1,fd12:3456:789a::1")
        );
        assert_eq!(setting(&x.sys_settings, "ssh.password_auth"), Some("0"));
        assert!(setting(&x.sys_settings, "ssh.trusted_user_ca_keys")
            .unwrap()
            .starts_with("ssh-ed25519 "));
        assert_eq!(
            setting(&x.sys_settings, "ssh.authorized_principals"),
            Some(r#"{"root":["admin","ops"]}"#)
        );
        // wifi uplink
        assert_eq!(x.wifi_clients.len(), 1);
        assert_eq!(x.wifi_clients[0].device.as_deref(), Some("wlan0"));
        // nothing secret in the report
        let r = render(&p, true);
        for s in [
            "test-uplink-passphrase",
            "test-password",
            "yAnz5TF",
            "cEhzR3x",
            "FpCyhws",
        ] {
            assert!(!r.contains(s), "report leaks {s}");
        }
        // what is still reported as not imported
        let un = p.unmapped.join("\n");
        assert!(un.contains("dhcp: ipset"), "{un}");
        assert!(un.contains("dropbear"), "{un}");
        assert!(!un.contains("network: globals"), "{un}");
        assert!(!un.contains("wireguard_vpn"), "{un}");
        assert!(!un.contains("mwan3: file"), "{un}");
        assert!(!un.contains("dhcp: dnsmasq"), "{un}");
    }

    /// A sanitized copy of a router with 7 WireGuard peers (test keys only):
    /// every attribute that matters must reach the store unchanged.
    #[cfg(feature = "vpn-wireguard")]
    #[tokio::test]
    async fn wireguard_seven_peers_all_attributes() {
        const IFACE_KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let pk = |n: usize| {
            [
                "4NFQRhy5Bp+A5o95B17GRNkR2hKHCUUmpVtWqZy4XHs=",
                "IN6hfoxQn9m0Kkm57QwX1qQzdgExI3iOWGhgR8pBImI=",
                "QBohFPseMT7MDdYLFQ/ioW30REO6G9dLyKTTOM+SvlQ=",
                "CNaf/ZYQoPq7Q0NWGBJz9Hu4Ikl610bFdPLyO4KBmmk=",
                "cHdOrPa0QWiXE9S0XHdjccJjdaQlNf+qRNr6l9sCm0M=",
                "4B95uXKAy2nbfgIjLKjiMlsd0LxieTZuIkDOkxd9GEA=",
                "OKrUBrhUmuviIACTujtN/SLb4CDQRhQhucPcfSHhHlI=",
            ][n]
        };
        let psk = "qDjIBwVu2E5iGiCOotzH38urWFSwC2xRmq+xkEWdtnA=";
        let tmp = tempfile::tempdir().unwrap();
        let st = std::process::Command::new("cp")
            .arg("-r")
            .arg(dir())
            .arg(tmp.path().join("r"))
            .status()
            .unwrap();
        assert!(st.success());
        let net = tmp.path().join("r/etc/config/network");
        let old = std::fs::read_to_string(&net).unwrap();
        let head = &old[..old.find("config wireguard_vpn").unwrap()];
        let tail = &old[old.find("config interface 'wwan'").unwrap()..];
        let peers = [
            (
                "laptop",
                pk(0),
                Some(psk),
                "'10.99.0.2/32'\n\tlist allowed_ips 'fd12:3456:789a:10::2/128'",
                "",
                "\toption persistent_keepalive '25'\n",
            ),
            (
                "phone",
                pk(1),
                Some(psk),
                "'10.99.0.3/32'",
                "",
                "\toption route_allowed_ips '1'\n",
            ),
            (
                "site-b",
                pk(2),
                None,
                "'10.99.0.9/32'\n\tlist allowed_ips '10.200.0.0/24'",
                "\toption endpoint_host '198.51.100.7'\n\toption endpoint_port '51821'\n",
                "\toption persistent_keepalive '25'\n",
            ),
            (
                "v6 site",
                pk(3),
                None,
                "'10.99.0.11/32'",
                "\toption endpoint_host '2001:db8::7'\n\toption endpoint_port '51820'\n",
                "",
            ),
            (
                "named",
                pk(4),
                None,
                "'10.99.0.12/32'",
                "\toption endpoint_host 'vpn.example.net'\n",
                "",
            ),
            (
                "off",
                pk(5),
                None,
                "'10.99.0.13/32'",
                "",
                "\toption disabled '1'\n",
            ),
            ("laptop", pk(6), None, "'10.99.0.14/32'", "", ""),
        ];
        let mut mid = String::new();
        for (d, k, ps, al, ep, extra) in peers {
            mid += &format!(
                "config wireguard_vpn\n\toption description '{d}'\n\toption public_key '{k}'\n"
            );
            if let Some(ps) = ps {
                mid += &format!("\toption preshared_key '{ps}'\n");
            }
            mid += &format!("\tlist allowed_ips {al}\n{ep}{extra}\n");
        }
        std::fs::write(&net, format!("{head}{mid}{tail}")).unwrap();
        let (f, x) = load_input_full(&tmp.path().join("r")).unwrap();
        let p = build_plan_with(&f, &x, &maps());
        let store = ConfigStore::open_in_memory().await.unwrap();
        let out = apply(&store, &p).await.unwrap().join("\n");
        assert!(!out.contains("skipped"), "{out}");
        assert!(
            !out.contains(psk) && !out.contains(IFACE_KEY),
            "keys leaked"
        );
        let w = patronus_network::wireguard::list_peers(&store)
            .await
            .unwrap();
        assert_eq!(w.len(), 7, "{w:?}");
        let k: (String,) =
            sqlx::query_as("SELECT private_key FROM wg_interfaces WHERE name = 'wg0'")
                .fetch_one(store.pool().unwrap())
                .await
                .unwrap();
        assert_eq!(k.0, IFACE_KEY);
        let by = |k: &str| w.iter().find(|p| p.public_key == k).unwrap();
        let a = by(pk(0));
        assert_eq!(a.allowed_ips, "10.99.0.2/32, fd12:3456:789a:10::2/128");
        assert_eq!((a.persistent_keepalive, a.has_psk), (Some(25), true));
        assert_eq!(a.description.as_deref(), Some("laptop"));
        assert_eq!(a.preshared_key.as_deref(), Some(psk));
        assert!(by(pk(1)).has_psk);
        let b = by(pk(2));
        assert_eq!(b.endpoint.as_deref(), Some("198.51.100.7:51821"));
        assert_eq!(b.allowed_ips, "10.99.0.9/32, 10.200.0.0/24");
        assert_eq!(by(pk(3)).endpoint.as_deref(), Some("[2001:db8::7]:51820"));
        assert_eq!(by(pk(4)).endpoint.as_deref(), Some("vpn.example.net:51820"));
        assert!(!by(pk(5)).enabled);
        assert!(by(pk(0)).enabled && by(pk(6)).enabled);
        let names: std::collections::BTreeSet<_> = w.iter().map(|p| p.name.clone()).collect();
        assert_eq!(names.len(), 7, "peer names must stay unique: {names:?}");
    }

    #[tokio::test]
    async fn full_router_store_writes() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let p = plan();
        let out = apply(&store, &p).await.unwrap();
        let j = out.join("\n");
        // the gateway group needs USE=multiwan; a build without it says so and skips just that
        let unexpected: Vec<&str> = j
            .lines()
            .filter(|l| {
                l.contains("skipped")
                    && !(cfg!(not(feature = "multiwan")) && l.contains("USE=multiwan"))
            })
            .collect();
        assert!(unexpected.is_empty(), "{j}");
        for s in ["test-uplink-passphrase", "test-password", "yAnz5TF"] {
            assert!(!j.contains(s));
        }
        let cfg = NetConfig::load(&store).await.unwrap();
        let wan = cfg.iface("eth1").unwrap();
        assert_eq!(wan.pd_downstream, vec!["eth0".to_string()]);
        assert!(wan.dhcp6_duid.is_some());
        // the uplinks' UCI metrics order their DHCP default routes (equal metrics: the second route is refused)
        assert_eq!(wan.metric, Some(10));
        assert_eq!(cfg.iface("wlan0").unwrap().metric, Some(20));
        assert!(cfg
            .iface("eth0")
            .unwrap()
            .ipv6
            .iter()
            .any(|a| a.to_string() == "fd12:3456:789a::1/64"));
        assert_eq!(
            store
                .load_system_config("firewall.inbound_action")
                .await
                .unwrap()
                .as_deref(),
            Some("reject")
        );
        let rt = patronus_network::routes::load(&store).await.unwrap();
        #[cfg(feature = "multiwan")]
        assert_eq!(rt.default4.as_deref(), Some("failover"));
        assert_eq!(rt.routes.len(), 2);
        #[cfg(feature = "vpn-wireguard")]
        {
            let w = patronus_network::wireguard::list_interfaces(&store)
                .await
                .unwrap();
            assert_eq!(w.len(), 1);
            let k: (String,) =
                sqlx::query_as("SELECT private_key FROM wg_interfaces WHERE name = 'wg0'")
                    .fetch_one(store.pool().unwrap())
                    .await
                    .unwrap();
            assert_eq!(k.0, "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=");
        }
        #[cfg(feature = "dhcp-server")]
        {
            let m: Vec<_> = patronus_network::dhcp::list_pools(&store)
                .await
                .unwrap()
                .into_iter()
                .flat_map(|p| p.static_mappings)
                .collect();
            let nas = m
                .iter()
                .find(|m| m.hostname.as_deref() == Some("nas"))
                .unwrap();
            assert_eq!((nas.lease_time, nas.dns_record), (Some(0), true));
        }
        // a second run adds nothing
        let again = apply(&store, &p).await.unwrap().join("\n");
        assert!(again.contains("already present"), "{again}");
        assert_eq!(
            patronus_network::routes::load(&store)
                .await
                .unwrap()
                .routes
                .len(),
            2
        );
    }
}
