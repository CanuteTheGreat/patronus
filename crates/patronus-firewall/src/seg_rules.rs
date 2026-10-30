//! Device segmentation rules (docs/design/device-segmentation.md, section 4):
//! default-deny isolation between enrolled devices, rendered into its OWN nft
//! table `inet patronus_seg` that is appended to the same atomic `nft -f`
//! script as the main table.
//!
//! Why a separate table at priority -10: the main table starts with
//! `ct state established,related accept` and seeds `LAN -> any accept`, so
//! rules placed after them could neither isolate devices nor cut a revoked
//! device's live connections. The seg table runs first, only ever *drops*
//! (or lets the packet through to the main table: an `accept` here does not
//! skip the main table's chains), and `return`s everything that is not
//! device-to-device traffic or an unbound source.
//!
//! Semantics (per enabled segment, see `patronus_config::seg`):
//! - a frame from an `(iface, MAC, IPv4)` that is not an active, un-revoked,
//!   non-quarantine device forwards nothing (unknown / spoofed / revoked /
//!   quarantine) and may reach the router only for DHCP, DNS and ICMP, never
//!   the admin UI or SSH;
//! - an address of the segment that is not a live device receives nothing, not
//!   even on an established flow (revocation cuts live connections);
//! - two devices exchange NEW flows only inside one group (`intra`), across
//!   linked groups, or through a one-way service rule; everything else is
//!   dropped and logged (NFLOG group 7, rate limited);
//! - group `internet=deny` drops its devices' traffic leaving the segments;
//! - IPv6: device-to-device inside the segment prefixes is denied, and an
//!   unknown MAC forwards no IPv6 either (MAC-level binding; per-address
//!   IPv6 binding is the next item).
//!
//! Nothing is emitted for a segment whose switch is off, and with no enabled
//! segment the script only deletes a table left over from before.

use crate::feeds::NFLOG_GROUP;
use patronus_config::seg::{self, is_ifname, is_name, norm_mac};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// nft table the segmentation rules live in.
pub const SEG_TABLE: &str = "inet patronus_seg";

#[derive(Debug, Clone, PartialEq)]
pub struct SegGroup {
    pub id: i64,
    pub intra: bool,
    pub internet_deny: bool,
    pub quarantine: bool,
}

/// A device as the renderer needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct SegDevice {
    pub id: i64,
    pub name: String,
    pub mac: String,
    pub ip: Ipv4Addr,
    /// interfaces the device's segment resolves to
    pub ifaces: Vec<String>,
    pub group_id: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SegService {
    pub name: String,
    /// ("device"|"group", id)
    pub src: (String, i64),
    pub dst: (String, i64),
    pub proto: String,
    pub ports: String,
}

/// Everything the renderer reads; built from the store by [`load`], or by a
/// test directly.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SegConfig {
    pub ifaces: Vec<String>,
    pub v4_subnets: Vec<String>,
    pub v6_prefixes: Vec<String>,
    pub groups: Vec<SegGroup>,
    /// active devices only (pending and revoked ones have no identity)
    pub devices: Vec<SegDevice>,
    pub links: Vec<(i64, i64)>,
    pub services: Vec<SegService>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SegRules {
    /// nft script fragment: always starts with the add+delete of the table
    pub script: String,
    pub warnings: Vec<String>,
    /// at least one segment is enforced
    pub active: bool,
    pub devices: usize,
}

fn err(m: impl std::fmt::Display) -> Error {
    Error::Firewall(format!("segmentation: {m}"))
}

/// nft port list for an already validated `80,8000-8010` string.
fn port_set(ports: &str) -> Result<String> {
    let p = seg::check_ports(ports).map_err(err)?;
    Ok(format!("{{ {} }}", p.replace(',', ", ")))
}

fn check_prefix(p: &str, v6: bool) -> Result<()> {
    let n: ipnetwork::IpNetwork = p.parse().map_err(|_| err(format!("bad prefix {p:?}")))?;
    match (n, v6) {
        (ipnetwork::IpNetwork::V4(_), false) | (ipnetwork::IpNetwork::V6(_), true) => Ok(()),
        _ => Err(err(format!("bad prefix {p:?}"))),
    }
}

fn join(v: impl IntoIterator<Item = String>) -> String {
    v.into_iter().collect::<Vec<_>>().join(", ")
}

/// Render the segmentation table (a pure function: validates everything it
/// writes). With no interface or subnet it renders only the teardown.
pub fn render_nft(c: &SegConfig) -> Result<String> {
    let t = SEG_TABLE;
    let mut o = format!("add table {t}\ndelete table {t}\n");
    if c.ifaces.is_empty() {
        return Ok(o);
    }
    for i in &c.ifaces {
        if !is_ifname(i) {
            return Err(err(format!("bad interface {i:?}")));
        }
    }
    if c.v4_subnets.is_empty() {
        return Err(err("no IPv4 subnet for the enabled segments"));
    }
    for p in &c.v4_subnets {
        check_prefix(p, false)?;
    }
    for p in &c.v6_prefixes {
        check_prefix(p, true)?;
    }
    let gids: BTreeSet<i64> = c.groups.iter().map(|g| g.id).collect();
    let quarantine: BTreeSet<i64> = c
        .groups
        .iter()
        .filter(|g| g.quarantine)
        .map(|g| g.id)
        .collect();
    // quarantine members are unbound: no sets, no forwarding, DHCP/DNS/ICMP only
    let mut macs = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut live: Vec<&SegDevice> = Vec::new();
    for d in &c.devices {
        if !is_name(&d.name) {
            return Err(err(format!("bad device name {:?}", d.name)));
        }
        let mac = norm_mac(&d.mac).map_err(err)?;
        if mac != d.mac {
            return Err(err(format!("device {}: MAC not normalised", d.name)));
        }
        if !gids.contains(&d.group_id) {
            return Err(err(format!("device {}: unknown group", d.name)));
        }
        if d.ifaces.is_empty() || d.ifaces.iter().any(|i| !c.ifaces.contains(i)) {
            return Err(err(format!("device {}: not on an enabled segment", d.name)));
        }
        if !macs.insert(mac.clone()) {
            return Err(err(format!("duplicate MAC {mac}")));
        }
        if !ips.insert(d.ip) {
            return Err(err(format!("duplicate address {}", d.ip)));
        }
        if !quarantine.contains(&d.group_id) {
            live.push(d);
        }
    }

    let ifs = join(c.ifaces.iter().map(|i| format!("\"{i}\"")));
    o.push_str(&format!("table {t} {{\n"));
    o.push_str(&format!(
        "  set seg_ifaces {{ type ifname; elements = {{ {ifs} }} }}\n"
    ));
    let bound: Vec<String> = live
        .iter()
        .flat_map(|d| {
            d.ifaces
                .iter()
                .map(move |i| format!("\"{i}\" . {} . {} comment \"{}\"", d.mac, d.ip, d.name))
        })
        .collect();
    if bound.is_empty() {
        o.push_str("  set bound_v4 { type ifname . ether_addr . ipv4_addr; }\n");
    } else {
        o.push_str(&format!(
            "  set bound_v4 {{ type ifname . ether_addr . ipv4_addr; elements = {{\n    {}\n  }} }}\n",
            bound.join(",\n    ")
        ));
    }
    let bmac: BTreeSet<String> = live
        .iter()
        .flat_map(|d| d.ifaces.iter().map(move |i| format!("\"{i}\" . {}", d.mac)))
        .collect();
    if bmac.is_empty() {
        o.push_str("  set bound_mac { type ifname . ether_addr; }\n");
    } else {
        o.push_str(&format!(
            "  set bound_mac {{ type ifname . ether_addr; elements = {{ {} }} }}\n",
            join(bmac)
        ));
    }
    let set4 = |name: &str, v: Vec<String>| {
        if v.is_empty() {
            format!("  set {name} {{ type ipv4_addr; }}\n")
        } else {
            format!(
                "  set {name} {{ type ipv4_addr; elements = {{ {} }} }}\n",
                join(v)
            )
        }
    };
    o.push_str(&set4(
        "seg_v4",
        live.iter().map(|d| d.ip.to_string()).collect(),
    ));
    o.push_str(&set4(
        "noinet_v4",
        live.iter()
            .filter(|d| {
                c.groups
                    .iter()
                    .any(|g| g.id == d.group_id && g.internet_deny)
            })
            .map(|d| d.ip.to_string())
            .collect(),
    ));
    for g in c.groups.iter().filter(|g| !g.quarantine) {
        o.push_str(&set4(
            &format!("grp_{}_v4", g.id),
            live.iter()
                .filter(|d| d.group_id == g.id)
                .map(|d| d.ip.to_string())
                .collect(),
        ));
    }
    o.push_str(&format!(
        "  set seg_net_v4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}\n",
        join(c.v4_subnets.iter().cloned())
    ));
    if !c.v6_prefixes.is_empty() {
        o.push_str(&format!(
            "  set seg_v6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}\n",
            join(c.v6_prefixes.iter().cloned())
        ));
    }

    // one-way service rules: src set x dst set, tcp|udp, ports
    let members = |kind: &str, id: i64| -> Vec<Ipv4Addr> {
        live.iter()
            .filter(|d| match kind {
                "device" => d.id == id,
                _ => d.group_id == id,
            })
            .map(|d| d.ip)
            .collect()
    };
    let mut svc_rules = String::new();
    for (n, s) in c.services.iter().enumerate() {
        if s.proto != "tcp" && s.proto != "udp" {
            return Err(err(format!("service {}: proto must be tcp or udp", s.name)));
        }
        if !matches!(s.src.0.as_str(), "device" | "group")
            || !matches!(s.dst.0.as_str(), "device" | "group")
        {
            return Err(err(format!("service {}: bad endpoint", s.name)));
        }
        let ports = port_set(&s.ports)?;
        let (a, b) = (members(&s.src.0, s.src.1), members(&s.dst.0, s.dst.1));
        if a.is_empty() || b.is_empty() {
            continue; // an endpoint that is revoked, pending or quarantined: nothing to allow
        }
        o.push_str(&set4(
            &format!("svc{n}_src"),
            a.iter().map(|i| i.to_string()).collect(),
        ));
        o.push_str(&set4(
            &format!("svc{n}_dst"),
            b.iter().map(|i| i.to_string()).collect(),
        ));
        svc_rules.push_str(&format!(
            "    ip saddr @svc{n}_src ip daddr @svc{n}_dst meta l4proto {} th dport {ports} counter accept comment \"service {}\"\n",
            s.proto, s.name
        ));
    }

    let nflog = NFLOG_GROUP;
    o.push_str("  chain seg_forward {\n");
    o.push_str("    # an address of the segment that is not a live device receives nothing, not even established\n");
    o.push_str("    # flows: revocation cuts live connections without a conntrack flush\n");
    o.push_str("    ip daddr @seg_net_v4 ip daddr != @seg_v4 counter drop comment \"unbound or revoked destination\"\n");
    o.push_str("    ip daddr @noinet_v4 iifname != @seg_ifaces counter drop comment \"group without internet\"\n");
    o.push_str("    iifname != @seg_ifaces return\n");
    if !c.v6_prefixes.is_empty() {
        o.push_str("    ip6 saddr @seg_v6 ip6 daddr @seg_v6 counter drop comment \"IPv6 between devices: denied\"\n");
    }
    o.push_str("    meta nfproto ipv6 iifname . ether saddr != @bound_mac counter drop comment \"IPv6 from an unbound MAC\"\n");
    o.push_str("    meta nfproto ipv6 return\n");
    o.push_str("    # unknown / spoofed / revoked / quarantine: an unbound (iface, MAC, IP) forwards nothing\n");
    o.push_str(&format!(
        "    iifname . ether saddr . ip saddr != @bound_v4 limit rate 10/second log prefix \"seg-unbound \" group {nflog}\n"
    ));
    o.push_str("    iifname . ether saddr . ip saddr != @bound_v4 counter drop comment \"unbound source\"\n");
    o.push_str("    ip saddr @noinet_v4 oifname != @seg_ifaces counter drop comment \"group without internet\"\n");
    o.push_str("    ct state established,related accept\n");
    o.push_str("    ct state invalid drop\n");
    o.push_str("    # not device-to-device: the ordinary firewall decides\n");
    o.push_str("    ip daddr != @seg_v4 return\n");
    o.push_str(&svc_rules);
    for g in c.groups.iter().filter(|g| g.intra && !g.quarantine) {
        o.push_str(&format!(
            "    ip saddr @grp_{0}_v4 ip daddr @grp_{0}_v4 counter accept comment \"group {0}\"\n",
            g.id
        ));
    }
    let mut seen = BTreeSet::new();
    for (a, b) in &c.links {
        if !gids.contains(a)
            || !gids.contains(b)
            || quarantine.contains(a)
            || quarantine.contains(b)
            || a == b
        {
            return Err(err(format!(
                "link {a}-{b}: unknown, quarantine or identical group"
            )));
        }
        let key = (*a.min(b), *a.max(b));
        if !seen.insert(key) {
            continue;
        }
        for (x, y) in [(a, b), (b, a)] {
            o.push_str(&format!(
                "    ip saddr @grp_{x}_v4 ip daddr @grp_{y}_v4 counter accept comment \"link {x}->{y}\"\n"
            ));
        }
    }
    o.push_str(&format!(
        "    limit rate 10/second log prefix \"seg-deny \" group {nflog}\n"
    ));
    o.push_str("    counter drop comment \"default deny between devices\"\n");
    o.push_str("  }\n");
    o.push_str(
        "  # unbound sources and quarantine may reach the router for DHCP, DNS and ping only:\n",
    );
    o.push_str("  # the LAN anti-lockout rule of the main table would otherwise open SSH and the web UI to them\n");
    o.push_str("  chain seg_input {\n");
    o.push_str("    iifname != @seg_ifaces return\n");
    o.push_str("    iifname . ether saddr . ip saddr @bound_v4 return\n");
    o.push_str("    meta nfproto ipv6 iifname . ether saddr @bound_mac return\n");
    o.push_str("    meta l4proto { icmp, ipv6-icmp } accept\n");
    o.push_str("    udp dport { 53, 67, 68, 547 } accept\n");
    o.push_str("    tcp dport 53 accept\n");
    o.push_str(&format!(
        "    limit rate 10/second log prefix \"seg-input \" group {nflog}\n"
    ));
    o.push_str("    counter drop comment \"unbound or quarantined: no management access\"\n");
    o.push_str("  }\n");
    // priority -10: runs before the main table's chains (see the module docs)
    o.push_str("  chain forward {\n    type filter hook forward priority -10; policy accept;\n    jump seg_forward\n  }\n");
    o.push_str("  chain input {\n    type filter hook input priority -10; policy accept;\n    jump seg_input\n  }\n");
    o.push_str("}\n");
    Ok(o)
}

/// IPv6 prefixes (global /64s etc.) configured on a segment's interfaces.
async fn segment_v6(store: &ConfigStore, ifaces: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(pool) = store.pool() else {
        return out;
    };
    for i in ifaces {
        let Ok(rows) = sqlx::query(
            "SELECT address, prefix_len FROM interface_addresses WHERE interface_name = ? AND family = 'ipv6'",
        )
        .bind(i)
        .fetch_all(pool)
        .await
        else {
            continue;
        };
        for r in rows {
            let a: String = r.get(0);
            let p: i64 = r.get(1);
            if let Ok(ip) = a.parse::<std::net::Ipv6Addr>() {
                let seg0 = ip.segments()[0];
                if seg0 & 0xffc0 == 0xfe80 || ip.is_loopback() || !(16..=128).contains(&p) {
                    continue;
                }
                if let Ok(n) = ipnetwork::Ipv6Network::new(ip, p as u8) {
                    let s = format!("{}/{}", n.network(), n.prefix());
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
    }
    out
}

/// Read the store and render. Segments that cannot be enforced (role without
/// an interface, no IPv4 address) are skipped with a warning.
pub async fn load(store: &ConfigStore) -> Result<(SegConfig, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut cfg = SegConfig::default();
    let enabled: Vec<seg::Segment> = seg::list_segments(store)
        .await?
        .into_iter()
        .filter(|s| s.enabled)
        .collect();
    if enabled.is_empty() {
        return Ok((cfg, warnings));
    }
    let mut seg_ifaces: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &enabled {
        let ifs = seg::resolve_segment(store, &s.segment).await?;
        if ifs.is_empty() {
            warnings.push(format!(
                "segmentation: {} is not assigned to any interface, not enforced",
                s.segment
            ));
            continue;
        }
        let (nets, _) = seg::segment_v4(store, &s.segment).await?;
        if nets.is_empty() {
            warnings.push(format!(
                "segmentation: {} has no IPv4 address, not enforced",
                s.segment
            ));
            continue;
        }
        for n in nets {
            let c = n.cidr();
            if !cfg.v4_subnets.contains(&c) {
                cfg.v4_subnets.push(c);
            }
        }
        for i in &ifs {
            if !cfg.ifaces.contains(i) {
                cfg.ifaces.push(i.clone());
            }
        }
        for p in segment_v6(store, &ifs).await {
            if !cfg.v6_prefixes.contains(&p) {
                cfg.v6_prefixes.push(p);
            }
        }
        seg_ifaces.insert(s.segment.clone(), ifs);
    }
    if cfg.ifaces.is_empty() {
        return Ok((SegConfig::default(), warnings));
    }
    for g in seg::list_groups(store).await? {
        cfg.groups.push(SegGroup {
            id: g.id,
            intra: g.intra,
            internet_deny: g.internet == "deny",
            quarantine: g.quarantine,
        });
    }
    for d in seg::list_devices(store).await? {
        if d.state != "active" {
            continue;
        }
        let (Some(mac), Some(ip)) = (d.mac.as_deref(), d.ip4.as_deref()) else {
            continue;
        };
        let Some(ifaces) = seg_ifaces.get(&d.segment) else {
            continue; // its segment's switch is off
        };
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            warnings.push(format!(
                "segmentation: device {} has a bad address, skipped",
                d.name
            ));
            continue;
        };
        cfg.devices.push(SegDevice {
            id: d.id,
            name: d.name,
            mac: mac.to_string(),
            ip,
            ifaces: ifaces.clone(),
            group_id: d.group_id,
        });
    }
    for l in seg::list_links(store).await? {
        cfg.links.push((l.group_a, l.group_b));
    }
    for s in seg::list_services(store).await? {
        if s.enabled {
            cfg.services.push(SegService {
                name: s.name,
                src: (s.src_kind, s.src_id),
                dst: (s.dst_kind, s.dst_id),
                proto: s.proto,
                ports: s.ports,
            });
        }
    }
    Ok((cfg, warnings))
}

/// The nft fragment for the store's current segmentation state.
pub async fn seg_rules(store: &ConfigStore) -> Result<SegRules> {
    let (cfg, warnings) = load(store).await?;
    let script = render_nft(&cfg)?;
    Ok(SegRules {
        active: !cfg.ifaces.is_empty(),
        devices: cfg.devices.len(),
        script,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SegConfig {
        SegConfig {
            ifaces: vec!["br0".into()],
            v4_subnets: vec!["172.31.77.0/24".into()],
            v6_prefixes: vec!["fd77:31::/64".into()],
            groups: vec![
                SegGroup {
                    id: 1,
                    intra: true,
                    internet_deny: false,
                    quarantine: false,
                },
                SegGroup {
                    id: 2,
                    intra: true,
                    internet_deny: true,
                    quarantine: false,
                },
                SegGroup {
                    id: 3,
                    intra: false,
                    internet_deny: true,
                    quarantine: true,
                },
            ],
            devices: vec![
                dev(1, "laptop", "02:aa:00:00:00:11", "172.31.77.11", 1),
                dev(2, "cam", "02:aa:00:00:00:12", "172.31.77.12", 2),
                dev(3, "tv", "02:aa:00:00:00:13", "172.31.77.13", 2),
                dev(4, "guest", "02:aa:00:00:00:14", "172.31.77.14", 3),
            ],
            links: vec![],
            services: vec![SegService {
                name: "laptop-cam".into(),
                src: ("device".into(), 1),
                dst: ("device".into(), 2),
                proto: "tcp".into(),
                ports: "8080,9000-9010".into(),
            }],
        }
    }
    fn dev(id: i64, name: &str, mac: &str, ip: &str, g: i64) -> SegDevice {
        SegDevice {
            id,
            name: name.into(),
            mac: mac.into(),
            ip: ip.parse().unwrap(),
            ifaces: vec!["br0".into()],
            group_id: g,
        }
    }

    #[test]
    fn nothing_enabled_only_deletes_the_table() {
        let s = render_nft(&SegConfig::default()).unwrap();
        assert_eq!(
            s,
            "add table inet patronus_seg\ndelete table inet patronus_seg\n"
        );
    }

    #[test]
    fn default_deny_binding_and_priority() {
        let n = render_nft(&cfg()).unwrap();
        assert!(
            n.contains("counter drop comment \"default deny between devices\""),
            "{n}"
        );
        assert!(
            n.contains("\"br0\" . 02:aa:00:00:00:11 . 172.31.77.11 comment \"laptop\""),
            "{n}"
        );
        assert!(n.contains("hook forward priority -10") && n.contains("hook input priority -10"));
        assert!(n.contains("ip saddr @grp_1_v4 ip daddr @grp_1_v4 counter accept"));
        assert!(n.contains("ip saddr @grp_2_v4 ip daddr @grp_2_v4 counter accept"));
    }

    #[test]
    fn service_rule_is_one_way_with_port_ranges() {
        let n = render_nft(&cfg()).unwrap();
        assert!(
            n.contains("set svc0_src { type ipv4_addr; elements = { 172.31.77.11 } }"),
            "{n}"
        );
        assert!(n.contains("set svc0_dst { type ipv4_addr; elements = { 172.31.77.12 } }"));
        assert!(n.contains("ip saddr @svc0_src ip daddr @svc0_dst meta l4proto tcp th dport { 8080, 9000-9010 } counter accept"));
        assert_eq!(
            n.matches("@svc0_").count(),
            2,
            "used once each way: no reverse rule"
        );
        assert!(!n.contains("ip saddr @svc0_dst"));
    }

    #[test]
    fn quarantine_members_are_unbound_and_cannot_reach_the_admin_ui() {
        let n = render_nft(&cfg()).unwrap();
        assert!(
            !n.contains("172.31.77.14"),
            "quarantine device has no binding and no set entry: {n}"
        );
        assert!(!n.contains("02:aa:00:00:00:14"));
        let input = &n[n.find("chain seg_input").unwrap()..n.find("chain forward").unwrap()];
        assert!(
            input.contains("udp dport { 53, 67, 68, 547 } accept")
                && input.contains("tcp dport 53 accept")
        );
        assert!(
            !input.contains("22") && !input.contains("8443"),
            "management ports are never opened: {input}"
        );
        let last = input.lines().rev().find(|l| l.contains("drop")).unwrap();
        assert!(last.contains("no management access"), "{input}");
        // the final verdict for unbound sources is a drop, after the narrow accepts
        let a = input.find("tcp dport 53 accept").unwrap();
        let d = input.find("no management access").unwrap();
        assert!(a < d);
    }

    #[test]
    fn revoked_destination_drop_precedes_conntrack_accept() {
        let n = render_nft(&cfg()).unwrap();
        let a = n.find("unbound or revoked destination").unwrap();
        let b = n.find("ct state established,related accept").unwrap();
        assert!(a < b, "revocation must beat conntrack");
        let c = n.find("unbound source").unwrap();
        assert!(c < b, "an unbound source must beat conntrack too");
        let d = n.find("ip saddr @noinet_v4 oifname").unwrap();
        assert!(d < b, "internet=deny must cut established flows");
    }

    #[test]
    fn group_without_internet_is_dropped_both_ways() {
        let n = render_nft(&cfg()).unwrap();
        assert!(
            n.contains(
                "set noinet_v4 { type ipv4_addr; elements = { 172.31.77.12, 172.31.77.13 } }"
            ),
            "{n}"
        );
        assert!(n.contains("ip daddr @noinet_v4 iifname != @seg_ifaces counter drop"));
        assert!(n.contains("ip saddr @noinet_v4 oifname != @seg_ifaces counter drop"));
    }

    #[test]
    fn ipv6_is_not_swallowed_by_the_ipv4_default_deny() {
        let n = render_nft(&cfg()).unwrap();
        let v6 = n.find("meta nfproto ipv6 return").unwrap();
        let deny = n.find("default deny between devices").unwrap();
        assert!(
            v6 < deny,
            "v6 must return to the main table before the v4 default deny"
        );
        assert!(n.contains("ip6 saddr @seg_v6 ip6 daddr @seg_v6 counter drop"));
        assert!(n.contains("iifname . ether saddr != @bound_mac"));
    }

    #[test]
    fn links_are_bidirectional_once() {
        let mut c = cfg();
        c.links = vec![(1, 2), (2, 1)];
        let n = render_nft(&c).unwrap();
        assert!(n.contains("link 1->2") && n.contains("link 2->1"));
        assert_eq!(n.matches("link 1->2").count(), 1);
        c.links = vec![(1, 3)];
        assert!(
            render_nft(&c).is_err(),
            "a quarantine group cannot be linked"
        );
    }

    #[test]
    fn hostile_input_is_rejected() {
        let mut c = cfg();
        c.devices[0].name = "a\"; flush ruleset; \"".into();
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.ifaces = vec!["br0\" }; flush ruleset".into()];
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.devices[1].mac = c.devices[0].mac.clone();
        assert!(render_nft(&c)
            .unwrap_err()
            .to_string()
            .contains("duplicate MAC"));
        let mut c = cfg();
        c.devices[1].ip = c.devices[0].ip;
        assert!(render_nft(&c)
            .unwrap_err()
            .to_string()
            .contains("duplicate address"));
        let mut c = cfg();
        c.devices[1].group_id = 99;
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.services[0].ports = "80; drop".into();
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.services[0].proto = "icmp".into();
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.v4_subnets.clear();
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.v4_subnets = vec!["1.2.3.4/33".into()];
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.devices[0].mac = "02:AA:00:00:00:11".into();
        assert!(
            render_nft(&c).is_err(),
            "MACs reach the renderer normalised"
        );
    }

    #[test]
    fn service_to_a_revoked_or_quarantined_endpoint_renders_nothing() {
        let mut c = cfg();
        c.devices.retain(|d| d.id != 2); // cam revoked: not in the active list
        let n = render_nft(&c).unwrap();
        assert!(!n.contains("svc0_"), "{n}");
        let mut c = cfg();
        c.services[0].dst = ("group".into(), 3);
        assert!(!render_nft(&c).unwrap().contains("svc0_"));
    }

    #[test]
    fn empty_groups_still_render_valid_sets() {
        let mut c = cfg();
        c.devices.clear();
        let n = render_nft(&c).unwrap();
        assert!(n.contains("set grp_1_v4 { type ipv4_addr; }"), "{n}");
        assert!(n.contains("set bound_v4 { type ifname . ether_addr . ipv4_addr; }"));
    }

    /// The real `nft` parses what we render (skipped where nft cannot run,
    /// e.g. no CAP_NET_ADMIN; the netlab scenario loads it for real).
    #[test]
    fn nft_check_accepts_the_rendered_table() {
        use std::io::Write;
        let probe = std::process::Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let Ok(mut probe) = probe else {
            eprintln!("skip: no nft binary");
            return;
        };
        probe
            .stdin
            .take()
            .unwrap()
            .write_all(b"add table inet seg_probe\n")
            .unwrap();
        let o = probe.wait_with_output().unwrap();
        if !o.status.success() {
            eprintln!(
                "skip: nft cannot run here: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return;
        }
        for c in [cfg(), SegConfig::default(), {
            let mut c = cfg();
            c.v6_prefixes.clear();
            c.services.clear();
            c.devices.clear();
            c
        }] {
            let script = render_nft(&c).unwrap();
            let mut ch = std::process::Command::new("nft")
                .args(["-c", "-f", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            ch.stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .unwrap();
            let o = ch.wait_with_output().unwrap();
            assert!(
                o.status.success(),
                "nft -c rejected the table: {}\n{script}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }

    // --- against the store ---------------------------------------------------

    async fn lab_store() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO interfaces (name, enabled, role, updated_at) VALUES ('br0',1,'lan',0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        sqlx::query("INSERT INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','172.31.77.1',24,'ipv4'), ('br0','fd77:31::1',64,'ipv6'), ('br0','fe80::1',64,'ipv6')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        s
    }

    fn input(name: &str, mac: &str, group: Option<&str>) -> seg::DeviceInput {
        seg::DeviceInput {
            name: name.into(),
            mac: Some(mac.into()),
            group: group.map(str::to_string),
            segment: Some("@lan".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn upgrade_state_renders_only_a_teardown() {
        let s = lab_store().await;
        seg::create_device(&s, &input("laptop", "02:aa:00:00:00:11", None))
            .await
            .unwrap();
        let r = seg_rules(&s).await.unwrap();
        assert!(
            !r.active,
            "devices exist but the segment's switch is off: nothing changes"
        );
        assert_eq!(
            r.script,
            "add table inet patronus_seg\ndelete table inet patronus_seg\n"
        );
    }

    #[tokio::test]
    async fn enabled_segment_renders_the_store() {
        let s = lab_store().await;
        seg::create_group(
            &s,
            &seg::GroupInput {
                name: "iot".into(),
                internet: "deny".into(),
                intra: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        seg::create_device(&s, &input("laptop", "02:aa:00:00:00:11", None))
            .await
            .unwrap();
        let cam = seg::create_device(&s, &input("cam", "02:aa:00:00:00:12", Some("iot")))
            .await
            .unwrap();
        let mut guest = input("guest", "02:aa:00:00:00:14", Some("quarantine"));
        guest.ip4 = Some("172.31.77.50".into());
        seg::create_device(&s, &guest).await.unwrap();
        seg::add_service(
            &s,
            &seg::ServiceInput {
                name: "lc".into(),
                src: "device:laptop".into(),
                dst: "device:cam".into(),
                proto: "tcp".into(),
                ports: "8080".into(),
                schedule: None,
                enabled: true,
            },
        )
        .await
        .unwrap();
        seg::set_segment_enabled(&s, "@lan", true).await.unwrap();
        let r = seg_rules(&s).await.unwrap();
        assert!(r.active && r.devices == 3, "{r:?}");
        assert!(
            r.script.contains("172.31.77.2") && r.script.contains("02:aa:00:00:00:12"),
            "{}",
            r.script
        );
        assert!(
            !r.script.contains("02:aa:00:00:00:14"),
            "quarantine device unbound"
        );
        assert!(
            r.script.contains("fd77:31::/64") && !r.script.contains("fe80"),
            "global prefix only"
        );
        assert!(r.script.contains("ip saddr @svc0_src ip daddr @svc0_dst"));
        // revoke the camera: gone from every set, service rule vanishes
        seg::revoke_device(&s, cam.id).await.unwrap();
        let r = seg_rules(&s).await.unwrap();
        assert!(
            !r.script.contains("02:aa:00:00:00:12") && !r.script.contains("svc0_"),
            "{}",
            r.script
        );
        // switch off again: back to a bare teardown
        seg::set_segment_enabled(&s, "@lan", false).await.unwrap();
        assert!(!seg_rules(&s).await.unwrap().active);
    }

    #[tokio::test]
    async fn a_segment_without_an_address_or_interface_is_skipped_with_a_warning() {
        let s = lab_store().await;
        seg::set_segment_enabled(&s, "@opt9", true).await.unwrap();
        let r = seg_rules(&s).await.unwrap();
        assert!(!r.active);
        assert!(r.warnings.iter().any(|w| w.contains("@opt9")), "{r:?}");
        sqlx::query("DELETE FROM interface_addresses")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        seg::set_segment_enabled(&s, "@lan", true).await.unwrap();
        let r = seg_rules(&s).await.unwrap();
        assert!(
            !r.active && r.warnings.iter().any(|w| w.contains("no IPv4 address")),
            "{r:?}"
        );
    }
}
