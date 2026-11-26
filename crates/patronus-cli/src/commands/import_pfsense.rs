//! `patronus import pfsense FILE [--plan] [--map OLD=NEW]... [--yes]`: read a pfSense CE or
//! OPNsense `config.xml` and build the same [`Plan`] the OpenWrt importer builds, so the
//! report ([`import_uci::render`]) and the store writes ([`import_uci::apply`]) are shared.
//!
//! The XML is parsed with `roxmltree`; the root element (`pfsense` or `opnsense`) says which
//! of the two it is. Both keep the classic sections (`system`, `interfaces`, `filter`, `nat`,
//! `dhcpd`, `aliases`, ...) in the same shape; OPNsense keeps aliases, Unbound overrides and
//! WireGuard under `<OPNsense>` (MVC models), pfSense keeps WireGuard under
//! `<installedpackages>`. Anything the importer cannot translate lands in `plan.unmapped` in
//! plain words, nothing is dropped silently, and secrets print as `(set)`.
//!
//! Interface device names (`em0`, `igb1`, `vtnet0`) differ on this box: `--map OLD=NEW`
//! renames them (the VLAN devices on top follow their parent: `em0.10` becomes `NEW.10`).
//!
//! VLANs, PPPoE links, aliases and IPsec tunnels have no slot in the OpenWrt plan, so
//! [`PfPlan`] carries them next to it and [`apply`] writes them before it calls
//! [`import_uci::apply`] (which loads the network configuration again and keeps them).

use super::import_uci::{self, IfacePlan, Plan, PoolPlan, StaticPlan};
use super::import_uci::{GroupPlan, GwPlan, RoutePlan, WgPeerPlan, WgPlan};
use anyhow::{bail, Context, Result};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule, IpVersion, NatRule, NatType, PortSpec, Protocol,
};
use patronus_firewall::aliases::Alias;
use patronus_firewall::nftables::{is_valid_alias_name, AliasKind};
use patronus_network::ipnetwork::IpNetwork;
use patronus_network::netconf::{
    is_valid_ifname, NetConfig, PppoeConfig, V4Mode, V6Mode, VlanConfig,
};
use roxmltree::{Document, Node};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

const COMMENT: &str = "imported from a pfSense/OPNsense config.xml";

// ---------------------------------------------------------------------------
// the plan
// ---------------------------------------------------------------------------

/// An IPsec site-to-site tunnel (IKEv2, pre-shared key) for `ipsec_tunnels`.
#[derive(Clone, PartialEq)]
pub struct IpsecPlan {
    pub name: String,
    pub remote: String,
    pub local_ts: Vec<String>,
    pub remote_ts: Vec<String>,
    /// Never printed.
    pub psk: String,
    pub enabled: bool,
    pub description: Option<String>,
}

/// The OpenWrt-style [`Plan`] plus what only this importer produces.
pub struct PfPlan {
    /// `pfsense` or `opnsense` (the root element of the file).
    pub flavor: &'static str,
    pub plan: Plan,
    pub vlans: Vec<VlanConfig>,
    pub pppoe: Vec<PppoeConfig>,
    pub aliases: Vec<Alias>,
    pub ipsec: Vec<IpsecPlan>,
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

fn kid<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn kids<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    n.children()
        .filter(|c| c.is_element() && c.tag_name().name() == name)
        .collect()
}

fn elems<'a, 'i>(n: Node<'a, 'i>) -> Vec<Node<'a, 'i>> {
    n.children().filter(|c| c.is_element()).collect()
}

fn at<'a, 'i>(n: Node<'a, 'i>, path: &[&str]) -> Option<Node<'a, 'i>> {
    path.iter().try_fold(n, |n, p| kid(n, p))
}

fn text_of(n: Node) -> Option<String> {
    let t = n.text()?.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn txt(n: Node, name: &str) -> Option<String> {
    kid(n, name).and_then(text_of)
}

/// `<disabled/>`, `<enable/>`, `<not/>`: the element is there (`<x>0</x>` counts as off).
fn flag(n: Node, name: &str) -> bool {
    kid(n, name).is_some_and(|c| c.text().map(str::trim) != Some("0"))
}

fn off(n: Node, name: &str) -> bool {
    txt(n, name).is_some_and(|x| x == "0" || x == "no")
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn looks_like_wg_key(k: &str) -> bool {
    k.len() == 44
        && k.ends_with('=')
        && k[..43]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

fn net_string(n: &IpNetwork) -> String {
    format!("{}/{}", n.network(), n.prefix())
}

fn parse_ports(s: &str) -> Option<PortSpec> {
    let one = |p: &str| p.trim().parse::<u16>().ok().filter(|n| *n != 0);
    match s.split_once(['-', ':']) {
        Some((a, b)) => {
            let (a, b) = (one(a)?, one(b)?);
            (a <= b).then_some(PortSpec::Range(a, b))
        }
        None => one(s).map(PortSpec::Single),
    }
}

fn names_of(n: Node, known: &[&str]) -> Vec<String> {
    elems(n)
        .into_iter()
        .map(|e| e.tag_name().name().to_string())
        .filter(|t| !known.contains(&t.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// How rules name an interface: its role (`@wan`) when it has one, else the device.
fn spec_of(i: &IfacePlan) -> String {
    match &i.role {
        Some(r) => format!("@{r}"),
        None => i.device.clone(),
    }
}

// ---------------------------------------------------------------------------
// builder state
// ---------------------------------------------------------------------------

struct Gw {
    name: String,
    /// logical pfSense interface (`wan`)
    iface: String,
    addr: Option<IpAddr>,
    family: &'static str,
    monitor: Option<String>,
}

#[derive(Default)]
struct B {
    flavor: &'static str,
    maps: BTreeMap<String, String>,
    plan: Plan,
    vlans: Vec<VlanConfig>,
    pppoe: Vec<PppoeConfig>,
    aliases: Vec<Alias>,
    ipsec: Vec<IpsecPlan>,
    /// pfSense VLAN device name -> (parent device, tag)
    vlanif: BTreeMap<String, (String, u16)>,
    gws: Vec<Gw>,
    gw_names: BTreeSet<String>,
    alias_kind: BTreeMap<String, AliasKind>,
    alias_all: BTreeSet<String>,
    used_names: BTreeSet<String>,
    /// WireGuard tunnel address assigned through an interface (`tun_wg0` -> addresses)
    wg_addrs: BTreeMap<String, Vec<String>>,
}

impl B {
    /// The device name on this box for a pfSense device name.
    fn dev(&self, old: &str) -> String {
        self.dev_depth(old, 0)
    }

    fn dev_depth(&self, old: &str, depth: u8) -> String {
        if let Some(m) = self.maps.get(old) {
            return m.clone();
        }
        match self.vlanif.get(old) {
            Some((parent, tag)) if depth < 4 => {
                format!("{}.{tag}", self.dev_depth(parent, depth + 1))
            }
            _ => old.to_string(),
        }
    }

    fn iface(&self, logical: &str) -> Option<&IfacePlan> {
        self.plan.ifaces.iter().find(|i| i.uci == logical)
    }

    fn unmapped(&mut self, s: impl Into<String>) {
        self.plan.unmapped.push(s.into());
    }

    fn note(&mut self, s: impl Into<String>) {
        self.plan.notes.push(s.into());
    }

    fn unique_name(&mut self, base: &str) -> String {
        let mut name = base.to_string();
        let mut n = 1;
        while !self.used_names.insert(name.clone()) {
            n += 1;
            name = format!("{base} #{n}");
        }
        name
    }

    /// Network of an imported interface (`lan` in a rule means its subnet).
    fn subnet_of(&self, logical: &str, v6: bool) -> Result<String, String> {
        let i = self
            .iface(logical)
            .ok_or_else(|| format!("interface '{logical}' is not imported"))?;
        if v6 {
            return self
                .plan
                .ext
                .iface6
                .get(&i.device)
                .and_then(|e| e.addrs.first())
                .map(net_string)
                .ok_or_else(|| {
                    format!(
                        "the IPv6 network of '{logical}' is not a fixed prefix (it is delegated or automatic)"
                    )
                });
        }
        if i.v4 != V4Mode::Static {
            return Err(format!(
                "the IPv4 network of '{logical}' is not known here (its address comes from DHCP or the provider)"
            ));
        }
        i.addrs
            .iter()
            .find(|a| a.is_ipv4())
            .map(net_string)
            .ok_or_else(|| format!("'{logical}' has no IPv4 address"))
    }
}

// ---------------------------------------------------------------------------
// entry: parse + build
// ---------------------------------------------------------------------------

/// Parse `xml` and build the plan. `maps` is `--map OLD=NEW` (see [`import_uci::parse_maps`]).
pub fn build_plan(xml: &str, maps: &BTreeMap<String, String>) -> Result<PfPlan> {
    let doc = Document::parse(xml).context("config.xml is not well-formed XML")?;
    let root = doc.root_element();
    let flavor = match root.tag_name().name() {
        "pfsense" => "pfsense",
        "opnsense" => "opnsense",
        other => bail!(
            "not a pfSense or OPNsense config.xml (the root element is <{other}>, expected <pfsense> or <opnsense>)"
        ),
    };
    let mut b = B {
        flavor,
        maps: maps.clone(),
        ..Default::default()
    };
    system(&mut b, root);
    vlans(&mut b, root);
    ppps(&mut b, root);
    gateways_raw(&mut b, root);
    aliases(&mut b, root);
    interfaces(&mut b, root);
    gateways_plan(&mut b, root);
    routes(&mut b, root);
    filter_rules(&mut b, root);
    nat(&mut b, root);
    dhcp(&mut b, root);
    dns(&mut b, root);
    wireguard(&mut b, root);
    openvpn(&mut b, root);
    ipsec(&mut b, root);
    other_sections(&mut b, root);
    Ok(PfPlan {
        flavor,
        plan: b.plan,
        vlans: b.vlans,
        pppoe: b.pppoe,
        aliases: b.aliases,
        ipsec: b.ipsec,
    })
}

// ---------------------------------------------------------------------------
// system
// ---------------------------------------------------------------------------

fn system(b: &mut B, root: Node) {
    let Some(s) = kid(root, "system") else { return };
    let host = txt(s, "hostname").map(|h| h.to_ascii_lowercase());
    let tz = txt(s, "timezone");
    if host.is_some() || tz.is_some() {
        b.plan.ext.general = Some((host, tz));
    }
    if let Some(d) = txt(s, "domain") {
        b.note(format!(
            "system: domain '{d}': set it on the General page (the importer writes the host name and time zone only)"
        ));
    }
    let servers = txt(s, "timeservers").map(|t| words(&t)).unwrap_or_default();
    if !servers.is_empty() {
        // the old box was an NTP client of these servers; serving time to clients stays off
        b.plan.ext.ntp = Some((false, servers, vec!["@lan".into()]));
        b.note("system: time servers imported; the NTP server for clients is left off, turn it on under NTP if you served time to the LAN");
    }
    let dns: Vec<String> = kids(s, "dnsserver")
        .into_iter()
        .filter_map(text_of)
        .collect();
    if !dns.is_empty() {
        b.unmapped(format!(
            "system: DNS servers {}: set them on the DNS page (they are the upstream resolvers)",
            dns.join(", ")
        ));
    }
    let users = kids(s, "user").len();
    if users > 0 {
        b.unmapped(format!(
            "system: {users} local user account(s) and their passwords: not imported, create them under Users and set a new admin password"
        ));
    }
    if !kids(s, "group").is_empty() {
        b.unmapped("system: local user groups and privileges: not imported");
    }
    if let Some(w) = kid(s, "webgui") {
        let port = txt(w, "port").unwrap_or_else(|| "443".into());
        b.unmapped(format!(
            "system: web interface settings (protocol {}, port {port}): not imported, Patronus serves its UI on the standard ports",
            txt(w, "protocol").unwrap_or_else(|| "https".into())
        ));
    }
    if let Some(sh) = kid(s, "ssh") {
        if flag(sh, "enable") {
            b.unmapped("system: SSH access was enabled: not imported, enable the OpenSSH server in Patronus setup");
        }
    }
}

// ---------------------------------------------------------------------------
// VLANs and PPPoE
// ---------------------------------------------------------------------------

fn vlans(b: &mut B, root: Node) {
    let Some(v) = kid(root, "vlans") else { return };
    let entries = kids(v, "vlan");
    // register every VLAN device first (a VLAN may sit on another VLAN)
    for e in &entries {
        let (Some(parent), Some(tag)) = (
            txt(*e, "if"),
            txt(*e, "tag").and_then(|t| t.parse::<u16>().ok()),
        ) else {
            continue;
        };
        let old = txt(*e, "vlanif").unwrap_or_else(|| format!("{parent}.{tag}"));
        b.vlanif.insert(old, (parent, tag));
    }
    for e in entries {
        let (Some(parent), Some(tag)) = (
            txt(e, "if"),
            txt(e, "tag").and_then(|t| t.parse::<u16>().ok()),
        ) else {
            b.unmapped("vlans: a VLAN entry without a parent device or a tag: not imported");
            continue;
        };
        let old = txt(e, "vlanif").unwrap_or_else(|| format!("{parent}.{tag}"));
        let name = b.dev(&old);
        if !is_valid_ifname(&name) || !(1..=4094).contains(&tag) {
            b.unmapped(format!(
                "vlans: VLAN {tag} on {parent}: '{name}' is not a usable device name or tag (use --map {old}=<name>)"
            ));
            continue;
        }
        let proto = if txt(e, "proto").as_deref() == Some("802.1ad") {
            "802.1ad"
        } else {
            "802.1q"
        };
        if txt(e, "pcp").is_some_and(|p| p != "0") {
            b.unmapped(format!(
                "vlans: VLAN {tag} on {parent}: the priority code point is not imported"
            ));
        }
        let parent_dev = b.dev(&parent);
        b.vlans.push(VlanConfig {
            name,
            parent: parent_dev,
            vlan_id: tag,
            protocol: proto.into(),
            enabled: true,
            description: txt(e, "descr"),
        });
    }
}

fn ppps(b: &mut B, root: Node) {
    let Some(p) = kid(root, "ppps") else { return };
    for e in kids(p, "ppp") {
        let ty = txt(e, "type").unwrap_or_default();
        let ptp = txt(e, "ptpid").unwrap_or_else(|| "0".into());
        let old = txt(e, "if").unwrap_or_else(|| format!("{ty}{ptp}"));
        if ty != "pppoe" {
            b.unmapped(format!(
                "ppps: {} link '{old}': not imported, only PPPoE is supported, recreate it under Interfaces",
                if ty.is_empty() { "a PPP" } else { ty.as_str() }
            ));
            continue;
        }
        let ports = txt(e, "ports").map(|s| words(&s)).unwrap_or_default();
        let Some(port) = ports.first() else {
            b.unmapped(format!(
                "ppps: PPPoE link '{old}' has no parent port: not imported"
            ));
            continue;
        };
        if ports.len() > 1 {
            b.unmapped(format!(
                "ppps: PPPoE link '{old}' uses several ports (multilink): only {port} is imported"
            ));
        }
        let name = b.dev(&old);
        if !is_valid_ifname(&name) {
            b.unmapped(format!(
                "ppps: PPPoE link '{old}': '{name}' is not a usable device name"
            ));
            continue;
        }
        let Some(user) = txt(e, "username") else {
            b.unmapped(format!(
                "ppps: PPPoE link '{old}' has no user name: not imported"
            ));
            continue;
        };
        // config.xml keeps the password base64-encoded; fall back to the text as written
        let secret = txt(e, "password")
            .map(|s| {
                base64_decode(&s)
                    .and_then(|v| String::from_utf8(v).ok())
                    .filter(|d| !d.is_empty() && !d.chars().any(|c| c.is_control()))
                    .unwrap_or(s)
            })
            .unwrap_or_default();
        if secret.is_empty() || secret.chars().any(|c| c.is_control()) {
            b.unmapped(format!(
                "ppps: PPPoE link '{old}': the password is missing or unusable, enter it under Interfaces"
            ));
            continue;
        }
        let parent = b.dev(port);
        b.pppoe.push(PppoeConfig {
            name,
            parent,
            username: user,
            password: secret,
            service_name: txt(e, "provider"),
            mtu: txt(e, "mtu").and_then(|m| m.parse().ok()).unwrap_or(1492),
            default_route: true,
            use_peer_dns: true,
            ipv6: false,
            enabled: !flag(e, "disabled"),
            description: txt(e, "descr"),
        });
    }
}

// ---------------------------------------------------------------------------
// gateways
// ---------------------------------------------------------------------------

fn gateways_raw(b: &mut B, root: Node) {
    let Some(g) = kid(root, "gateways") else {
        return;
    };
    for e in kids(g, "gateway_item") {
        let Some(name) = txt(e, "name") else { continue };
        if flag(e, "disabled") {
            b.note(format!(
                "gateways: gateway '{name}' is disabled, not imported"
            ));
            continue;
        }
        let addr = txt(e, "gateway").and_then(|a| a.parse::<IpAddr>().ok());
        let family = if txt(e, "ipprotocol").as_deref() == Some("inet6") {
            "inet6"
        } else {
            "inet"
        };
        let monitor = if flag(e, "monitor_disable") {
            None
        } else {
            txt(e, "monitor").or_else(|| addr.map(|a| a.to_string()))
        };
        b.gws.push(Gw {
            name,
            iface: txt(e, "interface").unwrap_or_default(),
            addr,
            family,
            monitor,
        });
    }
}

fn gateways_plan(b: &mut B, root: Node) {
    let mut done = Vec::new();
    for gw in &b.gws {
        let Some(i) = b.iface(&gw.iface) else {
            done.push(Err(format!(
                "gateways: gateway '{}' on interface '{}' (not an imported interface): not imported",
                gw.name, gw.iface
            )));
            continue;
        };
        let note = (i.v4 != V4Mode::Static && gw.addr.is_some_and(|a| a.is_ipv4())).then(|| {
            format!(
                "gateways: gateway '{}' on {} has a fixed address in the file but the interface is dynamic; check it on Routing > Gateways",
                gw.name, i.device
            )
        });
        done.push(Ok((
            GwPlan {
                name: gw.name.clone(),
                interface: i.device.clone(),
                family: gw.family.into(),
                monitor_ips: gw.monitor.iter().cloned().collect(),
                reliability: 1,
                interval: 5,
                down: 5,
                up: 5,
            },
            note,
        )));
    }
    for r in done {
        match r {
            Ok((g, note)) => {
                if let Some(n) = note {
                    b.note(n);
                }
                b.plan.ext.gateways.push(g);
            }
            Err(e) => b.unmapped(e),
        }
    }
    b.gw_names = b.plan.ext.gateways.iter().map(|g| g.name.clone()).collect();
    let Some(g) = kid(root, "gateways") else {
        return;
    };
    let default4 = txt(g, "defaultgw4");
    for grp in kids(g, "gateway_group") {
        let Some(name) = txt(grp, "name") else {
            continue;
        };
        let mut members = Vec::new();
        for it in kids(grp, "item").into_iter().filter_map(text_of) {
            let mut p = it.split('|');
            let (gw, tier) = (p.next().unwrap_or(""), p.next().unwrap_or("1"));
            if b.gw_names.contains(gw) {
                members.push((gw.to_string(), tier.parse().unwrap_or(1), 1));
            } else {
                b.note(format!(
                    "gateways: group '{name}' member '{gw}' skipped (not an imported gateway)"
                ));
            }
        }
        if members.is_empty() {
            b.unmapped(format!(
                "gateways: gateway group '{name}': no usable member, not imported"
            ));
            continue;
        }
        let d4 = default4.as_deref() == Some(name.as_str());
        b.gw_names.insert(name.clone());
        b.plan.ext.groups.push(GroupPlan {
            name,
            members,
            default4: d4,
        });
    }
    if let Some(d) = default4 {
        if !b.plan.ext.groups.iter().any(|g| g.name == d) {
            b.note(format!(
                "gateways: default IPv4 gateway '{d}': Patronus uses the default route of the WAN interface; set it on Routing > Gateways if you need a specific one"
            ));
        }
    }
}

fn routes(b: &mut B, root: Node) {
    let Some(s) = kid(root, "staticroutes") else {
        return;
    };
    for r in kids(s, "route") {
        let net = txt(r, "network").unwrap_or_default();
        let label = txt(r, "descr")
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        if flag(r, "disabled") {
            b.note(format!(
                "routes: route to {net}{label} is disabled, not imported"
            ));
            continue;
        }
        let Ok(dest) = net.parse::<IpNetwork>() else {
            b.unmapped(format!(
                "routes: route to '{net}'{label}: not a network address (an alias?), recreate it under Routing"
            ));
            continue;
        };
        let gwname = txt(r, "gateway").unwrap_or_default();
        match b
            .gws
            .iter()
            .find(|g| g.name == gwname)
            .and_then(|g| g.addr)
        {
            Some(a) => b.plan.ext.routes.push(RoutePlan {
                destination: net_string(&dest),
                gateway: Some(a.to_string()),
                interface: None,
                metric: None,
            }),
            None => b.unmapped(format!(
                "routes: route to {net}{label} via gateway '{gwname}': the gateway has no fixed address (or is not imported), recreate the route under Routing"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// interfaces
// ---------------------------------------------------------------------------

fn interfaces(b: &mut B, root: Node) {
    let Some(ifs) = kid(root, "interfaces") else {
        return;
    };
    let mut track6: Vec<(String, String, String)> = Vec::new();
    for n in elems(ifs) {
        let logical = n.tag_name().name().to_string();
        let Some(old_if) = txt(n, "if") else {
            continue;
        };
        let label = txt(n, "descr").unwrap_or_else(|| logical.to_ascii_uppercase());
        if old_if.starts_with("ovpn") {
            b.unmapped(format!(
                "interfaces: '{logical}' ({label}, {old_if}) is an OpenVPN tunnel interface: not imported, it comes back when you recreate the tunnel"
            ));
            continue;
        }
        if old_if.starts_with("tun_wg") || old_if.starts_with("wg") {
            let mut v = Vec::new();
            if let Some(a) = txt(n, "ipaddr").filter(|a| a.parse::<Ipv4Addr>().is_ok()) {
                v.push(format!(
                    "{a}/{}",
                    txt(n, "subnet").unwrap_or_else(|| "24".into())
                ));
            }
            b.wg_addrs.insert(old_if.clone(), v);
            b.plan.covered.push(format!(
                "interfaces: '{logical}' ({label}) is the WireGuard tunnel {old_if}: its address goes with the tunnel below"
            ));
            continue;
        }
        let device = b.dev(&old_if);
        if !is_valid_ifname(&device) {
            b.unmapped(format!(
                "interfaces: '{logical}' ({label}): '{device}' is not a usable device name (use --map {old_if}=<device>)"
            ));
            continue;
        }
        let is_virtual = b.vlanif.contains_key(&old_if) || b.pppoe.iter().any(|p| p.name == device);
        if device == old_if && !is_virtual {
            b.note(format!(
                "interfaces: '{logical}' ({label}) keeps the pfSense device name {old_if}; pass --map {old_if}=<device on this box> if it is named differently"
            ));
        }
        let role = patronus_config::store::is_valid_role(&logical).then(|| logical.clone());
        if role.is_none() {
            b.note(format!(
                "interfaces: '{logical}' is not named wan, lan or optN: no role set"
            ));
        }
        let mut ip = IfacePlan {
            uci: logical.clone(),
            device: device.clone(),
            role,
            enabled: flag(n, "enable"),
            v4: V4Mode::Unmanaged,
            addrs: vec![],
            gateway4: None,
            v6: V6Mode::Unmanaged,
            mtu: txt(n, "mtu").and_then(|m| m.parse().ok()),
        };
        match txt(n, "ipaddr").as_deref() {
            None => {}
            Some("dhcp") => ip.v4 = V4Mode::Dhcp,
            Some("none") => ip.v4 = V4Mode::None,
            Some("pppoe") => {
                if let Some(p) = b.pppoe.iter_mut().find(|p| p.name == device) {
                    p.ipv6 = txt(n, "ipaddrv6").as_deref() == Some("dhcp6");
                } else {
                    b.unmapped(format!(
                        "interfaces: '{logical}' ({label}) uses PPPoE but no usable PPPoE link '{old_if}' was imported: set it up under Interfaces"
                    ));
                }
            }
            Some(a @ ("ppp" | "pptp" | "l2tp")) => {
                b.unmapped(format!(
                    "interfaces: '{logical}' ({label}) uses {}: not imported, only PPPoE is supported",
                    a.to_ascii_uppercase()
                ));
                continue;
            }
            Some(a) => match a.parse::<Ipv4Addr>() {
                Ok(v4) => {
                    let prefix = txt(n, "subnet")
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(24);
                    match IpNetwork::new(IpAddr::V4(v4), prefix) {
                        Ok(net) => {
                            ip.v4 = V4Mode::Static;
                            ip.addrs.push(net);
                        }
                        Err(_) => b.unmapped(format!(
                            "interfaces: '{logical}' ({label}) address {a}/{prefix} is not valid"
                        )),
                    }
                }
                Err(_) => b.unmapped(format!(
                    "interfaces: '{logical}' ({label}) ipaddr '{a}' (not an IPv4 address, DHCP or PPPoE)"
                )),
            },
        }
        if let Some(gwn) = txt(n, "gateway") {
            if let Some(a) = b.gws.iter().find(|g| g.name == gwn).and_then(|g| g.addr) {
                if a.is_ipv4() && ip.v4 == V4Mode::Static {
                    ip.gateway4 = Some(a);
                }
            }
        }
        match txt(n, "ipaddrv6").as_deref() {
            None | Some("none") => {}
            Some("dhcp6") => ip.v6 = V6Mode::Dhcp6,
            Some("slaac") => ip.v6 = V6Mode::Slaac,
            Some("track6") => {
                let from = txt(n, "track6-interface").unwrap_or_else(|| "wan".into());
                track6.push((logical.clone(), device.clone(), from));
            }
            Some(a @ ("6rd" | "6to4")) => b.unmapped(format!(
                "interfaces: '{logical}' ({label}) uses IPv6 {a}: not imported"
            )),
            Some(a) => match a.parse::<std::net::Ipv6Addr>() {
                Ok(v6) => {
                    let prefix = txt(n, "subnetv6")
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(64);
                    if let Ok(net) = IpNetwork::new(IpAddr::V6(v6), prefix) {
                        ip.v6 = V6Mode::Static;
                        b.plan
                            .ext
                            .iface6
                            .entry(device.clone())
                            .or_default()
                            .addrs
                            .push(net);
                    }
                }
                Err(_) => b.unmapped(format!(
                    "interfaces: '{logical}' ({label}) ipaddrv6 '{a}' is not supported"
                )),
            },
        }
        if flag(n, "blockpriv") || flag(n, "blockbogons") {
            b.unmapped(format!(
                "interfaces: '{logical}' ({label}): 'block private networks' / 'block bogon networks' are not imported, add a drop rule for those sources on the WAN if you want it"
            ));
        }
        if txt(n, "spoofmac").is_some() {
            b.unmapped(format!(
                "interfaces: '{logical}' ({label}): the spoofed MAC address is not imported, set it on the interface page"
            ));
        }
        b.plan.ifaces.push(ip);
    }
    // track6: the WAN's DHCPv6 prefix delegation hands a prefix to this interface
    for (logical, dev, from) in track6 {
        let wan = b.iface(&from).map(|w| (w.device.clone(), w.v6));
        match wan {
            Some((wdev, V6Mode::Dhcp6)) => {
                let e = b.plan.ext.iface6.entry(wdev.clone()).or_default();
                if !e.pd_downstream.contains(&dev) {
                    e.pd_downstream.push(dev.clone());
                }
                b.note(format!(
                    "interfaces: '{logical}' tracks '{from}' for IPv6: prefix delegation from {wdev} to {dev}"
                ));
            }
            _ => b.unmapped(format!(
                "interfaces: '{logical}' tracks the IPv6 prefix of '{from}', which does not use DHCPv6: set up prefix delegation on the WAN by hand"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// aliases
// ---------------------------------------------------------------------------

struct RawAlias {
    name: String,
    ty: String,
    entries: Vec<String>,
    descr: Option<String>,
    enabled: bool,
}

fn raw_aliases(root: Node) -> Vec<RawAlias> {
    let mut v = Vec::new();
    if let Some(a) = kid(root, "aliases") {
        for e in kids(a, "alias") {
            v.push(RawAlias {
                name: txt(e, "name").unwrap_or_default(),
                ty: txt(e, "type").unwrap_or_default(),
                entries: txt(e, "address").map(|s| words(&s)).unwrap_or_default(),
                descr: txt(e, "descr"),
                enabled: true,
            });
        }
    }
    if let Some(a) = at(root, &["OPNsense", "Firewall", "Alias", "aliases"]) {
        for e in kids(a, "alias") {
            v.push(RawAlias {
                name: txt(e, "name").unwrap_or_default(),
                ty: txt(e, "type").unwrap_or_default(),
                entries: txt(e, "content")
                    .map(|s| {
                        s.lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                descr: txt(e, "description"),
                enabled: !off(e, "enabled"),
            });
        }
    }
    v
}

fn kind_of(ty: &str) -> Option<AliasKind> {
    match ty {
        "host" | "network" => Some(AliasKind::Host),
        "port" => Some(AliasKind::Port),
        _ => None,
    }
}

/// Flatten nested aliases of the same kind (depth-limited; a loop ends in an error).
fn flatten(
    a: &RawAlias,
    by_name: &BTreeMap<&str, &RawAlias>,
    depth: u8,
    kind: AliasKind,
    out: &mut Vec<String>,
) -> Result<(), String> {
    if depth > 5 {
        return Err("aliases are nested too deeply (or loop)".into());
    }
    for e in &a.entries {
        if let Some(inner) = by_name.get(e.as_str()) {
            let Some(ik) = kind_of(&inner.ty) else {
                return Err(format!(
                    "it contains the alias '{e}' of type '{}', which is not imported",
                    inner.ty
                ));
            };
            if ik != kind {
                return Err(format!("it contains the alias '{e}' of another kind"));
            }
            flatten(inner, by_name, depth + 1, kind, out)?;
        } else if kind == AliasKind::Port {
            out.push(e.replace(':', "-"));
        } else {
            out.push(e.clone());
        }
    }
    Ok(())
}

fn aliases(b: &mut B, root: Node) {
    let raw = raw_aliases(root);
    for a in &raw {
        b.alias_all.insert(a.name.clone());
    }
    let by_name: BTreeMap<&str, &RawAlias> = raw.iter().map(|a| (a.name.as_str(), a)).collect();
    for a in &raw {
        let why = |b: &mut B, w: String| {
            b.unmapped(format!("aliases: alias '{}' ({}): {w}", a.name, a.ty));
        };
        if !a.enabled {
            b.note(format!(
                "aliases: alias '{}' is disabled, not imported",
                a.name
            ));
            continue;
        }
        if !is_valid_alias_name(&a.name) {
            why(
                b,
                "not imported, Patronus alias names start with a letter and hold letters, digits and _ (31 at most); rename it and recreate it under Firewall > Aliases".into(),
            );
            continue;
        }
        let kind = match a.ty.as_str() {
            "url" | "url_ports" | "urltable" | "urltable_ports" => {
                why(
                    b,
                    "not imported, it is filled from a URL; recreate it as a URL table alias under Firewall > Aliases".into(),
                );
                continue;
            }
            "geoip" => {
                why(
                    b,
                    "not imported, it lists countries; recreate it as a GeoIP alias under Firewall > Aliases".into(),
                );
                continue;
            }
            t => match kind_of(t) {
                Some(k) => k,
                None => {
                    why(
                        b,
                        format!("not imported, alias type '{t}' has no Patronus equivalent; recreate it by hand"),
                    );
                    continue;
                }
            },
        };
        let mut entries = Vec::new();
        if let Err(w) = flatten(a, &by_name, 0, kind, &mut entries) {
            why(b, format!("not imported, {w}"));
            continue;
        }
        let alias = Alias {
            name: a.name.clone(),
            kind,
            entries,
            description: a.descr.clone(),
            source: None,
        };
        match alias.validated() {
            Ok(al) => {
                b.alias_kind.insert(al.name.clone(), kind);
                b.aliases.push(al);
            }
            Err(e) => why(
                b,
                format!(
                    "not imported, an entry is not usable ({e}); Patronus aliases hold addresses, networks and ranges (host names are not resolved), ports and port ranges"
                ),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// firewall rules
// ---------------------------------------------------------------------------

enum Addr {
    Any,
    /// the firewall itself (`(self)`, `lanip`)
    Fw,
    Net(String),
    Alias(String),
}

struct Ep {
    addr: Addr,
    port: Option<PortSpec>,
}

fn endpoint(b: &B, n: Option<Node>, v6: bool, what: &str) -> Result<Ep, String> {
    let Some(n) = n else {
        return Ok(Ep {
            addr: Addr::Any,
            port: None,
        });
    };
    if flag(n, "not") {
        return Err(format!(
            "the {what} is negated (\"not\"): Patronus rules cannot invert an address"
        ));
    }
    let port = match txt(n, "port").as_deref() {
        None | Some("any") => None,
        Some(p) => {
            if b.alias_kind.get(p) == Some(&AliasKind::Port) {
                Some(PortSpec::Alias(p.to_string()))
            } else if b.alias_all.contains(p) {
                return Err(format!(
                    "the {what} port uses the alias '{p}', which was not imported as a port alias"
                ));
            } else {
                match parse_ports(p) {
                    Some(ps) => Some(ps),
                    None => return Err(format!("the {what} port '{p}' is not a port or a range")),
                }
            }
        }
    };
    let addr = if kid(n, "any").is_some() {
        Addr::Any
    } else if let Some(net) = txt(n, "network") {
        if net == "(self)" || net.strip_suffix("ip").is_some_and(|i| b.iface(i).is_some()) {
            Addr::Fw
        } else if b.iface(&net).is_some() {
            Addr::Net(
                b.subnet_of(&net, v6)
                    .map_err(|e| format!("the {what}: {e}"))?,
            )
        } else {
            return Err(format!(
                "the {what} is the network '{net}' (not an imported interface)"
            ));
        }
    } else if let Some(a) = txt(n, "address") {
        if b.alias_kind.get(&a) == Some(&AliasKind::Host) {
            Addr::Alias(a)
        } else if b.alias_all.contains(&a) {
            return Err(format!(
                "the {what} uses the alias '{a}', which was not imported"
            ));
        } else if let Ok(ip) = a.parse::<IpAddr>() {
            match txt(n, "subnet").and_then(|s| s.parse::<u8>().ok()) {
                Some(p) => Addr::Net(
                    IpNetwork::new(ip, p)
                        .map(|n| net_string(&n))
                        .map_err(|_| format!("the {what} address {a}/{p} is not valid"))?,
                ),
                None => Addr::Net(ip.to_string()),
            }
        } else if let Ok(net) = a.parse::<IpNetwork>() {
            Addr::Net(net_string(&net))
        } else {
            return Err(format!(
                "the {what} is '{a}' (a host name or an alias that does not exist; Patronus rules take addresses, networks and aliases)"
            ));
        }
    } else {
        Addr::Any
    };
    Ok(Ep { addr, port })
}

/// Children of a rule that are understood (handled or harmless).
const RULE_KNOWN: &[&str] = &[
    "id",
    "tracker",
    "type",
    "interface",
    "ipprotocol",
    "protocol",
    "source",
    "destination",
    "descr",
    "disabled",
    "log",
    "created",
    "updated",
    "statetype",
    "gateway",
    "sequence",
    "category",
    "quick",
    "direction",
    "associated-rule-id",
    "floating",
];

fn filter_rules(b: &mut B, root: Node) {
    let Some(f) = kid(root, "filter") else { return };
    for (i, r) in kids(f, "rule").into_iter().enumerate() {
        filter_rule(b, r, i + 1);
    }
    if b.flavor == "opnsense" {
        if let Some(x) = at(root, &["OPNsense", "Firewall", "Filter", "rules"]) {
            let n = kids(x, "rule").len();
            if n > 0 {
                b.unmapped(format!(
                    "firewall: {n} rule(s) made in OPNsense's newer rule editor (Firewall > Automation): not imported, recreate them under Firewall > Rules"
                ));
            }
        }
    }
}

fn filter_rule(b: &mut B, r: Node, idx: usize) {
    let descr = txt(r, "descr");
    let label = descr.clone().unwrap_or_else(|| format!("rule {idx}"));
    let skip = |b: &mut B, why: String| {
        b.unmapped(format!("firewall: rule '{label}': {why}"));
    };
    if txt(r, "associated-rule-id").is_some() {
        b.plan.covered.push(format!(
            "firewall: rule '{label}' is the allow rule pfSense generated for a port forward (the Patronus port forward needs none)"
        ));
        return;
    }
    if txt(r, "floating").is_some_and(|f| f == "yes" || f == "1") {
        return skip(b, "not imported, it is a floating rule (it applies to several interfaces and directions at once); recreate it under Firewall > Rules".into());
    }
    let left = names_of(r, RULE_KNOWN);
    if !left.is_empty() {
        return skip(
            b,
            format!(
                "not imported, option(s) Patronus rules do not have: {}",
                left.join(", ")
            ),
        );
    }
    let action = match txt(r, "type").as_deref().unwrap_or("pass") {
        "pass" => FirewallAction::Accept,
        "block" => FirewallAction::Drop,
        "reject" => FirewallAction::Reject,
        other => {
            return skip(
                b,
                format!("not imported, rule type '{other}' (pass, block and reject are imported)"),
            )
        }
    };
    let ifaces_old = txt(r, "interface").map(|s| words(&s)).unwrap_or_default();
    if ifaces_old.is_empty() {
        return skip(b, "not imported, it names no interface".into());
    }
    let mut ifaces = Vec::new();
    for o in &ifaces_old {
        match b.iface(o) {
            Some(i) => ifaces.push((o.clone(), spec_of(i))),
            None => {
                return skip(
                    b,
                    format!("not imported, interface '{o}' is not an imported interface (VPN, group or unmapped); recreate the rule where it applies"),
                )
            }
        }
    }
    let version = match txt(r, "ipprotocol").as_deref().unwrap_or("inet") {
        "inet" => Some(IpVersion::V4),
        "inet6" => Some(IpVersion::V6),
        _ => None,
    };
    let v6 = version == Some(IpVersion::V6);
    let protos: Vec<Option<Protocol>> = match txt(r, "protocol").as_deref() {
        None | Some("any") => vec![None],
        Some("tcp") => vec![Some(Protocol::Tcp)],
        Some("udp") => vec![Some(Protocol::Udp)],
        Some("tcp/udp") => vec![Some(Protocol::Tcp), Some(Protocol::Udp)],
        Some("icmp") | Some("icmp6") | Some("ipv6-icmp") => vec![Some(Protocol::Icmp)],
        Some(p) => {
            return skip(
                b,
                format!(
                    "not imported, protocol '{p}' (any, tcp, udp, tcp/udp and icmp are imported)"
                ),
            )
        }
    };
    let src = match endpoint(b, kid(r, "source"), v6, "source") {
        Ok(e) => e,
        Err(e) => return skip(b, format!("not imported, {e}")),
    };
    let dst = match endpoint(b, kid(r, "destination"), v6, "destination") {
        Ok(e) => e,
        Err(e) => return skip(b, format!("not imported, {e}")),
    };
    if matches!(src.addr, Addr::Fw) {
        return skip(b, "not imported, the source is the firewall itself".into());
    }
    if (src.port.is_some() || dst.port.is_some())
        && !protos
            .iter()
            .all(|p| matches!(p, Some(Protocol::Tcp | Protocol::Udp)))
    {
        return skip(
            b,
            "not imported, a port needs protocol tcp, udp or tcp/udp".into(),
        );
    }
    let gateway = match txt(r, "gateway") {
        None => None,
        Some(g) if b.gw_names.contains(&g) => Some(g),
        Some(g) => {
            return skip(
                b,
                format!("not imported, it routes through the gateway '{g}', which is not imported (policy routing)"),
            )
        }
    };
    // the default LAN allow rules pfSense creates itself
    if matches!(action, FirewallAction::Accept)
        && descr
            .as_deref()
            .is_some_and(|d| d.starts_with("Default allow LAN"))
        && matches!(src.addr, Addr::Net(_))
        && matches!(dst.addr, Addr::Any)
    {
        b.plan.covered.push(format!(
            "firewall: rule '{label}' (the default LAN allow rule, covered by default)"
        ));
        return;
    }
    let chain = if matches!(dst.addr, Addr::Fw) {
        ChainType::Input
    } else {
        ChainType::Forward
    };
    let spec = |a: &Addr| match a {
        Addr::Net(n) => Some(n.clone()),
        Addr::Alias(n) => Some(format!("${n}")),
        _ => None,
    };
    let many = ifaces.len() * protos.len() > 1;
    for (old, dev) in &ifaces {
        for p in &protos {
            let base = if many {
                format!(
                    "{label} ({old}{})",
                    p.as_ref().map(|p| format!("/{p}")).unwrap_or_default()
                )
            } else {
                label.clone()
            };
            let name = b.unique_name(&base);
            let mut fr = FirewallRule::new(name, chain.clone(), action.clone());
            fr.enabled = !flag(r, "disabled");
            fr.protocol = p.clone();
            fr.source = spec(&src.addr);
            fr.destination = spec(&dst.addr);
            fr.sport = src.port.clone();
            fr.dport = dst.port.clone();
            fr.interface_in = Some(dev.clone());
            fr.ip_version = version;
            fr.log = flag(r, "log");
            fr.gateway = gateway.clone();
            fr.comment = Some(COMMENT.into());
            b.plan.fw_rules.push(fr);
        }
    }
}

// ---------------------------------------------------------------------------
// NAT
// ---------------------------------------------------------------------------

const NAT_KNOWN: &[&str] = &[
    "source",
    "destination",
    "protocol",
    "target",
    "local-port",
    "interface",
    "descr",
    "disabled",
    "natreflection",
    "associated-rule-id",
    "created",
    "updated",
    "nosync",
    "filter-rule-association",
    "ipprotocol",
    "tag",
    "tagged",
];

fn nat(b: &mut B, root: Node) {
    let Some(nat) = kid(root, "nat") else { return };
    for (i, r) in kids(nat, "rule").into_iter().enumerate() {
        port_forward(b, r, i + 1);
    }
    for (i, r) in kids(nat, "onetoone").into_iter().enumerate() {
        one_to_one(b, r, i + 1);
    }
    for r in kids(nat, "npt") {
        b.unmapped(format!(
            "nat: IPv6 prefix translation (NPt) rule '{}': not imported, recreate it under Firewall > NAT",
            txt(r, "descr").unwrap_or_default()
        ));
    }
    if let Some(o) = kid(nat, "outbound") {
        let mode = txt(o, "mode").unwrap_or_else(|| "automatic".into());
        match mode.as_str() {
            "automatic" | "hybrid" => b.plan.covered.push(format!(
                "nat: outbound NAT mode '{mode}' (Patronus masquerades the LAN networks out of the WAN automatically, like hybrid mode)"
            )),
            other => b.note(format!(
                "nat: outbound NAT mode '{other}': Patronus keeps its automatic outbound NAT; check the rules below"
            )),
        }
        for r in kids(o, "rule") {
            b.unmapped(format!(
                "nat: outbound NAT rule '{}' (interface {}): not imported, Patronus masquerades automatically; recreate it under Firewall > NAT if you need a manual one",
                txt(r, "descr").unwrap_or_default(),
                txt(r, "interface").unwrap_or_else(|| "wan".into())
            ));
        }
    }
}

fn port_forward(b: &mut B, r: Node, idx: usize) {
    let label = txt(r, "descr").unwrap_or_else(|| format!("port forward {idx}"));
    let skip = |b: &mut B, why: String| {
        b.unmapped(format!("nat: port forward '{label}': {why}"));
    };
    let left = names_of(r, NAT_KNOWN);
    if !left.is_empty() {
        return skip(
            b,
            format!("not imported, option(s) not supported: {}", left.join(", ")),
        );
    }
    let logical = txt(r, "interface").unwrap_or_else(|| "wan".into());
    let Some(dev) = b.iface(&logical).map(spec_of) else {
        return skip(
            b,
            format!("not imported, interface '{logical}' is not an imported interface"),
        );
    };
    let src = match endpoint(b, kid(r, "source"), false, "source") {
        Ok(e) => e,
        Err(e) => return skip(b, format!("not imported, {e}")),
    };
    let dst = match endpoint(b, kid(r, "destination"), false, "destination") {
        Ok(e) => e,
        Err(e) => return skip(b, format!("not imported, {e}")),
    };
    let source = match &src.addr {
        Addr::Any => None,
        Addr::Net(n) => Some(n.clone()),
        _ => {
            return skip(
                b,
                "not imported, the source is an alias or the firewall (not supported for port forwards)".into(),
            )
        }
    };
    if src.port.is_some() {
        return skip(b, "not imported, it matches a source port".into());
    }
    let destination = match &dst.addr {
        Addr::Any | Addr::Fw => None,
        Addr::Net(n) if n.parse::<IpAddr>().is_ok() => Some(n.clone()),
        _ => {
            return skip(
                b,
                "not imported, the destination is a network or an alias, only the firewall's own address or one address is supported".into(),
            )
        }
    };
    let dport = match &dst.port {
        Some(PortSpec::Alias(_)) => {
            return skip(
                b,
                "not imported, the port is a port alias (not supported for port forwards)".into(),
            )
        }
        p => p.clone(),
    };
    let Some(target) = txt(r, "target") else {
        return skip(b, "not imported, it has no target address".into());
    };
    let Ok(to) = target.parse::<IpAddr>() else {
        return skip(
            b,
            format!("not imported, the target '{target}' is not an address (an alias?)"),
        );
    };
    let to_port =
        match txt(r, "local-port") {
            None => None,
            Some(p) => match (p.parse::<u16>(), &dport) {
                (Ok(n), Some(PortSpec::Range(a, _))) if n == *a => None,
                (Ok(_), Some(PortSpec::Range(..))) => return skip(
                    b,
                    "not imported, a port range that moves to another start port is not supported"
                        .into(),
                ),
                (Ok(n), _) => Some(n),
                (Err(_), _) => {
                    return skip(
                        b,
                        format!("not imported, the local port '{p}' is not a single port"),
                    )
                }
            },
        };
    let protos: Vec<Option<Protocol>> = match txt(r, "protocol").as_deref() {
        None | Some("tcp/udp") => vec![Some(Protocol::Tcp), Some(Protocol::Udp)],
        Some("tcp") => vec![Some(Protocol::Tcp)],
        Some("udp") => vec![Some(Protocol::Udp)],
        Some(p) => {
            return skip(
                b,
                format!("not imported, protocol '{p}' (tcp, udp and tcp/udp are imported)"),
            )
        }
    };
    let reflection = matches!(
        txt(r, "natreflection").as_deref(),
        Some("enable" | "purenat")
    );
    let many = protos.len() > 1;
    for p in protos {
        let tag = p.as_ref().map(|p| p.to_string()).unwrap_or_default();
        let name = b.unique_name(&if many {
            format!("{label} ({tag})")
        } else {
            label.clone()
        });
        let mut n = NatRule::new(
            name,
            NatType::Dnat {
                to_address: to,
                to_port,
            },
        );
        n.enabled = !flag(r, "disabled");
        n.protocol = p;
        n.dport = dport.clone();
        n.interface_in = Some(dev.clone());
        n.source = source.clone();
        n.destination = destination.clone();
        n.reflection = reflection;
        n.comment = Some(COMMENT.into());
        b.plan.nat_rules.push(n);
    }
}

fn one_to_one(b: &mut B, r: Node, idx: usize) {
    let label = txt(r, "descr").unwrap_or_else(|| format!("1:1 NAT {idx}"));
    let skip = |b: &mut B, why: String| {
        b.unmapped(format!("nat: 1:1 NAT '{label}': {why}"));
    };
    let logical = txt(r, "interface").unwrap_or_else(|| "wan".into());
    let Some(dev) = b.iface(&logical).map(spec_of) else {
        return skip(
            b,
            format!("not imported, interface '{logical}' is not an imported interface"),
        );
    };
    let ext = txt(r, "external").and_then(|e| e.parse::<IpAddr>().ok());
    let single = |s: &str, mask: Option<String>| -> Option<IpAddr> {
        match s.split_once('/') {
            Some((a, "32" | "128")) => a.parse().ok(),
            Some(_) => None,
            None => match mask.as_deref() {
                None | Some("32") | Some("128") => s.parse().ok(),
                _ => None,
            },
        }
    };
    let internal = kid(r, "source")
        .and_then(|s| txt(s, "address"))
        .and_then(|i| single(&i, kid(r, "source").and_then(|s| txt(s, "subnet"))));
    let (Some(ext), Some(int)) = (ext, internal) else {
        return skip(b, "not imported, only a single external address mapped to a single internal address is supported (a whole subnet is not)".into());
    };
    let name = b.unique_name(&label);
    let mut n = NatRule::new(
        name,
        NatType::OneToOne {
            external: ext,
            internal: int,
        },
    );
    n.enabled = !flag(r, "disabled");
    n.interface_in = Some(dev.clone());
    n.interface_out = Some(dev);
    n.comment = Some(COMMENT.into());
    b.plan.nat_rules.push(n);
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

fn dhcp(b: &mut B, root: Node) {
    if let Some(d) = kid(root, "dhcpd") {
        for e in elems(d) {
            dhcp_pool(b, e);
        }
    }
    if let Some(d) = kid(root, "dhcpdv6") {
        for e in elems(d) {
            if flag(e, "enable") {
                b.unmapped(format!(
                    "dhcp: DHCPv6 server on '{}': not imported, set up DHCPv6 / router advertisements on the interface page",
                    e.tag_name().name()
                ));
            }
        }
    }
}

fn dhcp_pool(b: &mut B, e: Node) {
    let logical = e.tag_name().name().to_string();
    let Some(i) = b.iface(&logical) else {
        if flag(e, "enable") {
            b.unmapped(format!(
                "dhcp: server on '{logical}' (not an imported interface): not imported"
            ));
        }
        return;
    };
    let dev = i.device.clone();
    let iface_v4 = i.addrs.iter().find_map(|a| match a.ip() {
        IpAddr::V4(v) => Some(v),
        _ => None,
    });
    if !flag(e, "enable") {
        let n = kids(e, "staticmap").len();
        if n > 0 {
            b.note(format!(
                "dhcp: server on '{logical}' is switched off: its {n} static mapping(s) are not imported"
            ));
        }
        return;
    }
    let left = names_of(
        e,
        &[
            "enable",
            "range",
            "defaultleasetime",
            "domain",
            "dnsserver",
            "gateway",
            "staticmap",
        ],
    );
    if !left.is_empty() {
        b.unmapped(format!(
            "dhcp: server on '{logical}': option(s) not imported: {}",
            left.join(", ")
        ));
    }
    let range = kid(e, "range");
    let parse = |k: &str| {
        range
            .and_then(|r| txt(r, k))
            .and_then(|v| v.parse::<Ipv4Addr>().ok())
    };
    let router = txt(e, "gateway")
        .and_then(|g| g.parse::<Ipv4Addr>().ok())
        .or(iface_v4);
    let (Some(start), Some(end), Some(router)) = (parse("from"), parse("to"), router) else {
        b.unmapped(format!(
            "dhcp: server on '{logical}': no usable address range or router address, not imported"
        ));
        return;
    };
    b.plan.pools.push(PoolPlan {
        uci: logical.clone(),
        device: dev.clone(),
        start,
        end,
        lease_time: txt(e, "defaultleasetime").and_then(|t| t.parse().ok()),
        router,
        domain: txt(e, "domain"),
    });
    let dns: Vec<String> = kids(e, "dnsserver")
        .into_iter()
        .filter_map(text_of)
        .filter(|s| s.parse::<Ipv4Addr>().is_ok())
        .collect();
    if !dns.is_empty() {
        b.plan.ext.pool_dns.insert(dev.clone(), dns.join(","));
    }
    for m in kids(e, "staticmap") {
        let mac = txt(m, "mac");
        let ip = txt(m, "ipaddr").and_then(|i| i.parse::<Ipv4Addr>().ok());
        let (Some(mac), Some(ip)) = (mac, ip) else {
            b.unmapped(format!(
                "dhcp: static mapping '{}' on '{logical}' has no MAC address or IPv4 address: not imported",
                txt(m, "hostname").unwrap_or_default()
            ));
            continue;
        };
        let extra = names_of(m, &["mac", "ipaddr", "hostname", "descr", "cid"]);
        if !extra.is_empty() {
            b.unmapped(format!(
                "dhcp: static mapping {ip} on '{logical}': option(s) not imported: {}",
                extra.join(", ")
            ));
        }
        b.plan.statics.push(StaticPlan {
            device: dev.clone(),
            name: txt(m, "hostname"),
            mac,
            ip,
        });
    }
}

// ---------------------------------------------------------------------------
// DNS overrides
// ---------------------------------------------------------------------------

fn dns(b: &mut B, root: Node) {
    for sec in ["unbound", "dnsmasq"] {
        let Some(u) = kid(root, sec) else { continue };
        // pfSense repeats <hosts> once per override
        for h in kids(u, "hosts") {
            let host = txt(h, "host");
            let (dom, ip) = (txt(h, "domain"), txt(h, "ip"));
            let (Some(dom), Some(ip)) = (dom, ip.and_then(|i| i.parse::<IpAddr>().ok())) else {
                b.unmapped(format!(
                    "dns: host override '{}' has no valid domain or address: not imported",
                    host.unwrap_or_default()
                ));
                continue;
            };
            let Some(host) = host else {
                b.unmapped(format!(
                    "dns: host override for the domain '{dom}' without a host name: not imported"
                ));
                continue;
            };
            b.plan.ext.hosts.push((host, dom, ip));
            for a in kids(h, "aliases").into_iter().flat_map(|a| kids(a, "item")) {
                if let (Some(ah), Some(ad)) = (txt(a, "host"), txt(a, "domain")) {
                    b.plan.ext.hosts.push((ah, ad, ip));
                }
            }
        }
        for d in kids(u, "domainoverrides") {
            match (txt(d, "domain"), txt(d, "ip")) {
                (Some(dom), Some(ip)) if ip.parse::<IpAddr>().is_ok() => {
                    b.plan.ext.domains.push((dom, ip));
                }
                (dom, ip) => b.unmapped(format!(
                    "dns: domain override '{}' to '{}': only a plain server address is imported, recreate it under DNS",
                    dom.unwrap_or_default(),
                    ip.unwrap_or_default()
                )),
            }
        }
    }
    let Some(u) = at(root, &["OPNsense", "unboundplus"]) else {
        return;
    };
    if let Some(h) = kid(u, "hosts") {
        for e in kids(h, "host") {
            if off(e, "enabled") {
                continue;
            }
            let name = txt(e, "hostname").unwrap_or_default();
            let rr = txt(e, "rr").unwrap_or_else(|| "A".into());
            let dom = txt(e, "domain");
            let ip = txt(e, "server").and_then(|s| s.parse::<IpAddr>().ok());
            match (dom, ip) {
                (Some(dom), Some(ip)) if matches!(rr.as_str(), "A" | "AAAA") && !name.is_empty() => {
                    b.plan.ext.hosts.push((name, dom, ip));
                }
                _ => b.unmapped(format!(
                    "dns: host override '{name}' (record type {rr}): only A/AAAA records with a host name are imported, recreate it under DNS"
                )),
            }
        }
    }
    if let Some(d) = kid(u, "domains") {
        for e in kids(d, "domain") {
            if off(e, "enabled") {
                continue;
            }
            let (dom, srv) = (txt(e, "domain"), txt(e, "server"));
            let port_ok = matches!(txt(e, "port").as_deref(), None | Some("53"));
            match (dom, srv) {
                (Some(dom), Some(s)) if port_ok && s.parse::<IpAddr>().is_ok() => {
                    b.plan.ext.domains.push((dom, s));
                }
                (dom, _) => b.unmapped(format!(
                    "dns: domain override '{}': only a plain server address on port 53 is imported, recreate it under DNS",
                    dom.unwrap_or_default()
                )),
            }
        }
    }
    let n = kid(u, "aliases")
        .map(|a| kids(a, "alias").len())
        .unwrap_or(0);
    if n > 0 {
        b.unmapped(format!(
            "dns: {n} Unbound host alias(es): not imported, add them as extra host overrides"
        ));
    }
}

// ---------------------------------------------------------------------------
// WireGuard
// ---------------------------------------------------------------------------

fn cidr_rows(n: Node) -> Vec<String> {
    let mut v = Vec::new();
    for row in n.descendants().filter(|d| d.is_element()) {
        if let Some(a) = txt(row, "address") {
            v.push(match txt(row, "mask") {
                Some(m) if !a.contains('/') => format!("{a}/{m}"),
                _ => a,
            });
        }
    }
    v
}

fn endpoint_of(host: Option<String>, port: Option<String>) -> Option<String> {
    host.map(|h| match port {
        Some(p) if h.contains(':') => format!("[{h}]:{p}"),
        Some(p) => format!("{h}:{p}"),
        None => h,
    })
}

fn wireguard(b: &mut B, root: Node) {
    // pfSense: <installedpackages><wireguard><tunnels><item> + <peers><item>
    if let Some(w) = at(root, &["installedpackages", "wireguard"]) {
        let tunnels: Vec<Node> = kid(w, "tunnels")
            .map(|t| kids(t, "item"))
            .unwrap_or_default();
        let peers: Vec<Node> = kid(w, "peers").map(|t| kids(t, "item")).unwrap_or_default();
        for t in tunnels {
            let Some(old) = txt(t, "name") else { continue };
            if off(t, "enabled") {
                b.note(format!(
                    "wireguard: tunnel '{old}' is disabled, not imported"
                ));
                continue;
            }
            let dev = b.dev(&old);
            let mut addrs = kid(t, "addresses").map(cidr_rows).unwrap_or_default();
            if addrs.is_empty() {
                addrs = b.wg_addrs.get(&old).cloned().unwrap_or_default();
            }
            let mut plan = WgPlan {
                uci: old.clone(),
                device: dev,
                private_key: txt(t, "privatekey"),
                listen_port: txt(t, "listenport").and_then(|p| p.parse().ok()),
                addresses: addrs,
                mtu: txt(t, "mtu").and_then(|m| m.parse().ok()),
                peers: vec![],
            };
            for p in peers
                .iter()
                .filter(|p| txt(**p, "tun").as_deref() == Some(old.as_str()))
            {
                let peer = WgPeerPlan {
                    name: txt(*p, "descr").unwrap_or_else(|| "peer".into()),
                    description: Some(COMMENT.into()),
                    public_key: txt(*p, "publickey").unwrap_or_default(),
                    private_key: None,
                    preshared_key: txt(*p, "presharedkey"),
                    allowed_ips: kid(*p, "allowedips").map(cidr_rows).unwrap_or_default(),
                    endpoint: endpoint_of(txt(*p, "endpoint"), txt(*p, "port")),
                    keepalive: txt(*p, "persistentkeepalive").and_then(|k| k.parse().ok()),
                    enabled: !off(*p, "enabled"),
                };
                wg_peer(b, &mut plan, peer);
            }
            wg_finish(b, plan);
        }
    }
    // OPNsense: <OPNsense><wireguard><server><servers><server> + <client><clients><client>
    if let Some(w) = at(root, &["OPNsense", "wireguard"]) {
        let clients: BTreeMap<String, Node> = at(w, &["client", "clients"])
            .map(|c| kids(c, "client"))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| Some((c.attribute("uuid")?.to_string(), c)))
            .collect();
        let servers = at(w, &["server", "servers"])
            .map(|s| kids(s, "server"))
            .unwrap_or_default();
        for (idx, s) in servers.into_iter().enumerate() {
            let name = txt(s, "name").unwrap_or_else(|| format!("server{idx}"));
            if off(s, "enabled") {
                b.note(format!(
                    "wireguard: instance '{name}' is disabled, not imported"
                ));
                continue;
            }
            let dev = b.dev(&format!(
                "wg{}",
                txt(s, "instance").unwrap_or_else(|| idx.to_string())
            ));
            let mut plan = WgPlan {
                uci: name.clone(),
                device: dev,
                private_key: txt(s, "privkey"),
                listen_port: txt(s, "port").and_then(|p| p.parse().ok()),
                addresses: txt(s, "tunneladdress")
                    .map(|t| words(&t))
                    .unwrap_or_default(),
                mtu: txt(s, "mtu").and_then(|m| m.parse().ok()),
                peers: vec![],
            };
            for id in txt(s, "peers").map(|p| words(&p)).unwrap_or_default() {
                let Some(c) = clients.get(&id) else {
                    b.note(format!(
                        "wireguard: instance '{name}' lists an unknown peer {id}"
                    ));
                    continue;
                };
                let peer = WgPeerPlan {
                    name: txt(*c, "name").unwrap_or_else(|| "peer".into()),
                    description: Some(COMMENT.into()),
                    public_key: txt(*c, "pubkey").unwrap_or_default(),
                    private_key: None,
                    preshared_key: txt(*c, "psk"),
                    allowed_ips: txt(*c, "tunneladdress")
                        .map(|t| words(&t))
                        .unwrap_or_default(),
                    endpoint: endpoint_of(txt(*c, "serveraddress"), txt(*c, "serverport")),
                    keepalive: txt(*c, "keepalive").and_then(|k| k.parse().ok()),
                    enabled: !off(*c, "enabled"),
                };
                wg_peer(b, &mut plan, peer);
            }
            wg_finish(b, plan);
        }
    }
}

fn wg_peer(b: &mut B, plan: &mut WgPlan, p: WgPeerPlan) {
    if !looks_like_wg_key(&p.public_key) {
        b.unmapped(format!(
            "wireguard: peer '{}' of tunnel '{}': no valid public key, recreate it under VPN > WireGuard",
            p.name, plan.uci
        ));
        return;
    }
    if p.preshared_key
        .as_deref()
        .is_some_and(|k| !looks_like_wg_key(k))
    {
        b.unmapped(format!(
            "wireguard: peer '{}' of tunnel '{}': the pre-shared key is not a valid key, recreate the peer under VPN > WireGuard",
            p.name, plan.uci
        ));
        return;
    }
    plan.peers.push(p);
}

fn wg_finish(b: &mut B, plan: WgPlan) {
    if !is_valid_ifname(&plan.device) {
        b.unmapped(format!(
            "wireguard: tunnel '{}': '{}' is not a usable device name, recreate it under VPN > WireGuard",
            plan.uci, plan.device
        ));
        return;
    }
    if !plan.private_key.as_deref().is_some_and(looks_like_wg_key) {
        b.unmapped(format!(
            "wireguard: tunnel '{}': no valid private key, recreate it under VPN > WireGuard",
            plan.uci
        ));
        return;
    }
    if plan.addresses.is_empty() {
        b.note(format!(
            "wireguard: tunnel '{}' has no address in the file, set it on VPN > WireGuard",
            plan.uci
        ));
    }
    b.plan.ext.wg.push(plan);
}

// ---------------------------------------------------------------------------
// OpenVPN and IPsec
// ---------------------------------------------------------------------------

fn openvpn(b: &mut B, root: Node) {
    if let Some(o) = kid(root, "openvpn") {
        for s in kids(o, "openvpn-server") {
            let name = txt(s, "description")
                .unwrap_or_else(|| format!("server {}", txt(s, "vpnid").unwrap_or_default()));
            let proto = txt(s, "protocol")
                .unwrap_or_else(|| "UDP".into())
                .to_ascii_uppercase();
            let port = txt(s, "local_port").unwrap_or_else(|| "1194".into());
            b.unmapped(format!(
                "OpenVPN server '{name}' ({proto} {port}, mode {}, tunnel network {}{}): not imported, recreate it under VPN > OpenVPN",
                txt(s, "mode").unwrap_or_else(|| "-".into()),
                txt(s, "tunnel_network").unwrap_or_else(|| "-".into()),
                if flag(s, "disable") { ", disabled" } else { "" },
            ));
        }
        for c in kids(o, "openvpn-client") {
            let name = txt(c, "description")
                .unwrap_or_else(|| format!("client {}", txt(c, "vpnid").unwrap_or_default()));
            b.unmapped(format!(
                "OpenVPN client '{name}' (to {}:{}, {}): not imported, recreate it under VPN > OpenVPN",
                txt(c, "server_addr").unwrap_or_else(|| "-".into()),
                txt(c, "server_port").unwrap_or_else(|| "1194".into()),
                txt(c, "protocol")
                    .unwrap_or_else(|| "UDP".into())
                    .to_ascii_uppercase(),
            ));
        }
        let n = kids(o, "openvpn-csc").len();
        if n > 0 {
            b.unmapped(format!(
                "OpenVPN: {n} client-specific override(s): not imported, recreate them with the server"
            ));
        }
    }
    if let Some(i) = at(root, &["OPNsense", "OpenVPN", "Instances"]) {
        for e in kids(i, "Instance") {
            b.unmapped(format!(
                "OpenVPN instance '{}' ({}, {} port {}): not imported, recreate it under VPN > OpenVPN",
                txt(e, "description").unwrap_or_default(),
                txt(e, "role").unwrap_or_else(|| "server".into()),
                txt(e, "proto").unwrap_or_else(|| "udp".into()),
                txt(e, "port").unwrap_or_else(|| "1194".into()),
            ));
        }
    }
}

fn ts_of(b: &B, n: Option<Node>) -> Result<String, String> {
    let Some(n) = n else {
        return Err("a phase 2 entry has no local/remote network".into());
    };
    let ty = txt(n, "type").unwrap_or_default();
    match ty.as_str() {
        "network" | "address" => {
            let a = txt(n, "address").unwrap_or_default();
            let ip = a
                .parse::<IpAddr>()
                .map_err(|_| format!("network '{a}' is not an address"))?;
            let bits = txt(n, "netbits")
                .and_then(|x| x.parse::<u8>().ok())
                .unwrap_or(if ty == "address" {
                    if ip.is_ipv4() {
                        32
                    } else {
                        128
                    }
                } else {
                    24
                });
            IpNetwork::new(ip, bits)
                .map(|n| net_string(&n))
                .map_err(|_| format!("network {a}/{bits} is not valid"))
        }
        i if b.iface(i).is_some() => b.subnet_of(i, false),
        other => Err(format!(
            "a phase 2 network of type '{other}' (not a plain network)"
        )),
    }
}

fn ipsec(b: &mut B, root: Node) {
    if let Some(x) = kid(root, "ipsec") {
        let p2s = kids(x, "phase2");
        for p1 in kids(x, "phase1") {
            ipsec_tunnel(b, x, p1, &p2s);
        }
        if x.children()
            .any(|c| c.is_element() && c.tag_name().name() == "client")
            && kid(x, "client").is_some_and(|c| flag(c, "enable"))
        {
            b.unmapped(
                "IPsec mobile clients (remote access): not imported, recreate it under VPN > IPsec",
            );
        }
    }
    if let Some(c) = at(root, &["OPNsense", "Swanctl", "Connections"]) {
        for e in kids(c, "Connection") {
            b.unmapped(format!(
                "IPsec connection '{}' (to {}): not imported, recreate it under VPN > IPsec",
                txt(e, "description").unwrap_or_default(),
                txt(e, "remote_addrs").unwrap_or_else(|| "-".into())
            ));
        }
    }
}

fn ipsec_tunnel(b: &mut B, x: Node, p1: Node, p2s: &[Node]) {
    let ikeid = txt(p1, "ikeid").unwrap_or_default();
    let descr = txt(p1, "descr").unwrap_or_else(|| format!("ipsec{ikeid}"));
    let remote = txt(p1, "remote-gateway").unwrap_or_default();
    let ike = txt(p1, "iketype").unwrap_or_else(|| "ikev1".into());
    let unfit = |b: &mut B, why: String| {
        b.unmapped(format!(
            "IPsec tunnel '{descr}' to {} ({}): not imported, recreate it under VPN > IPsec ({why})",
            if remote.is_empty() { "-" } else { remote.as_str() },
            ike.to_ascii_uppercase()
        ));
    };
    if flag(p1, "disabled") {
        b.note(format!("ipsec: tunnel '{descr}' is disabled, not imported"));
        return;
    }
    if ike != "ikev2" {
        return unfit(b, "only IKEv2 tunnels are imported".into());
    }
    if txt(p1, "authentication_method").is_some_and(|m| m != "pre_shared_key") {
        return unfit(
            b,
            "only pre-shared key authentication is imported, certificates are not".into(),
        );
    }
    if remote.is_empty() {
        return unfit(b, "no remote gateway".into());
    }
    let psk = txt(p1, "pre-shared-key").or_else(|| {
        kids(x, "mobilekey")
            .into_iter()
            .find(|k| {
                txt(*k, "ident").is_some_and(|i| {
                    i == remote
                        || Some(&i) == txt(p1, "peerid_data").as_ref()
                        || Some(&i) == txt(p1, "myid_data").as_ref()
                })
            })
            .and_then(|k| txt(k, "pre-shared-key"))
    });
    let Some(psk) = psk else {
        return unfit(b, "its pre-shared key was not found in the file".into());
    };
    if !(16..=128).contains(&psk.len())
        || !psk
            .chars()
            .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
    {
        return unfit(b, "its pre-shared key is shorter than 16 or longer than 128 characters, or has quotes or backslashes; set a new key on both ends".into());
    }
    let (mut lts, mut rts) = (Vec::new(), Vec::new());
    for p2 in p2s
        .iter()
        .filter(|p| txt(**p, "ikeid") == txt(p1, "ikeid") && !flag(**p, "disabled"))
    {
        if txt(*p2, "mode").is_some_and(|m| m != "tunnel") {
            return unfit(b, "a phase 2 entry is not in tunnel mode".into());
        }
        match (
            ts_of(b, kid(*p2, "localid")),
            ts_of(b, kid(*p2, "remoteid")),
        ) {
            (Ok(l), Ok(r)) => {
                if !lts.contains(&l) {
                    lts.push(l);
                }
                if !rts.contains(&r) {
                    rts.push(r);
                }
            }
            (Err(e), _) | (_, Err(e)) => return unfit(b, e),
        }
    }
    if lts.is_empty() {
        return unfit(b, "no enabled phase 2 entry".into());
    }
    let name: String = descr
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    let name = if name.is_empty() {
        format!("ipsec{ikeid}")
    } else {
        name
    };
    if b.ipsec.iter().any(|t| t.name == name) {
        return unfit(b, format!("another tunnel already uses the name '{name}'"));
    }
    b.note(format!(
        "ipsec: tunnel '{name}' to {remote} uses the Patronus default IKE/ESP proposals, not the algorithms of the old phase 1/2: check the peer accepts them"
    ));
    b.ipsec.push(IpsecPlan {
        name,
        remote,
        local_ts: lts,
        remote_ts: rts,
        psk,
        enabled: true,
        description: Some(COMMENT.into()),
    });
}

// ---------------------------------------------------------------------------
// everything else
// ---------------------------------------------------------------------------

fn other_sections(b: &mut B, root: Node) {
    const HANDLED: &[&str] = &[
        "system",
        "interfaces",
        "vlans",
        "ppps",
        "gateways",
        "staticroutes",
        "aliases",
        "filter",
        "nat",
        "dhcpd",
        "dhcpdv6",
        "unbound",
        "dnsmasq",
        "openvpn",
        "ipsec",
        "version",
        "lastchange",
        "revision",
        "theme",
        "widgets",
        "sysctl",
        "rrd",
        "diag",
        "notifications",
        "cron",
        "trigger_initial_wizard",
    ];
    let plain = |name: &str| -> Option<&'static str> {
        Some(match name {
            "virtualip" => "virtual IPs (CARP / IP aliases): not imported, add the addresses on the interface by hand",
            "cert" | "ca" | "crl" => "certificates and certificate authorities: not imported, import them again under Certificates",
            "schedules" => "firewall schedules: not imported",
            "dnshaper" | "shaper" | "ezshaper" => "traffic shaper / limiters: not imported, recreate them under QoS",
            "captiveportal" => "captive portal: not imported, recreate it under Guest",
            "bridges" => "bridge devices: not imported, recreate them under Interfaces",
            "laggs" => "link aggregation (LAGG): not imported, recreate it under Interfaces",
            "gres" | "gifs" | "qinqs" => "GRE/GIF/QinQ tunnels: not imported, recreate them by hand",
            "dhcrelay" | "dhcrelay6" => "DHCP relay: not imported",
            "snmpd" => "SNMP settings: not imported",
            "syslog" => "remote logging settings: not imported, set them on the Logging page",
            "load_balancer" => "load balancer pools: not imported",
            "ntpd" => "NTP server settings (listening interfaces, pool): not imported, set them under NTP",
            "hasync" => "high availability sync settings: not imported, set up HA under High Availability",
            "wol" => "Wake-on-LAN entries: not imported",
            "proxyarp" => "proxy ARP entries: not imported",
            "wireless" => "wireless clones: not imported",
            "dyndnses" | "dnsupdates" => "dynamic DNS clients: not imported, recreate them under DNS > Dynamic DNS",
            _ => return None,
        })
    };
    for n in elems(root) {
        let name = n.tag_name().name();
        if HANDLED.contains(&name) || n.children().all(|c| !c.is_element()) {
            continue;
        }
        match name {
            "installedpackages" => {
                for p in elems(n) {
                    let pn = p.tag_name().name();
                    if pn != "wireguard" && p.children().any(|c| c.is_element()) {
                        b.unmapped(format!("package '{pn}': its settings are not imported"));
                    }
                }
            }
            "OPNsense" => {
                for p in elems(n) {
                    let pn = p.tag_name().name();
                    if !p.children().any(|c| c.is_element()) {
                        continue;
                    }
                    match pn {
                        "wireguard" | "unboundplus" | "OpenVPN" | "Swanctl" => {}
                        "Firewall" => {
                            for f in elems(p) {
                                let fname = f.tag_name().name();
                                if fname != "Alias"
                                    && fname != "Filter"
                                    && f.children().any(|c| c.is_element())
                                {
                                    b.unmapped(format!(
                                        "OPNsense firewall settings '{fname}': not imported"
                                    ));
                                }
                            }
                        }
                        _ => b.unmapped(format!("OPNsense plugin settings '{pn}': not imported")),
                    }
                }
            }
            _ => match plain(name) {
                Some(w) => b.unmapped(format!("{name}: {w}")),
                None => b.unmapped(format!(
                    "config.xml section '{name}': not imported (no Patronus equivalent known to the importer)"
                )),
            },
        }
    }
    b.plan.covered.push(
        "config.xml bookkeeping (version, revision, theme, widgets, sysctl tuning): nothing to import"
            .into(),
    );
    b.plan.covered.push(
        "firewall: the automatic anti-lockout rule has no config.xml entry (Patronus applies its own default policy)"
            .into(),
    );
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

/// The report: the shared OpenWrt-plan report plus the VLAN/PPPoE/alias/IPsec sections.
/// Contains no secret.
pub fn render(p: &PfPlan, dry_run: bool) -> String {
    use std::fmt::Write;
    let base = import_uci::render(&p.plan, dry_run);
    let rest: String = base.lines().skip(1).map(|l| format!("{l}\n")).collect();
    let verb = if dry_run { "would write" } else { "write" };
    let mut o = String::new();
    let _ = writeln!(
        o,
        "patronus import pfsense: {} config.xml{}",
        p.flavor,
        if dry_run {
            " (plan only, nothing is written)"
        } else {
            ""
        }
    );
    let mut extra = String::new();
    let _ = writeln!(extra, "\nvlans and PPPoE ({verb}):");
    for v in &p.vlans {
        let _ = writeln!(
            extra,
            "  vlan {} on {} tag {} ({})",
            v.name, v.parent, v.vlan_id, v.protocol
        );
    }
    for l in &p.pppoe {
        let _ = writeln!(
            extra,
            "  pppoe {} on {}: user {}{} mtu {} password: (set){}",
            l.name,
            l.parent,
            l.username,
            l.service_name
                .as_ref()
                .map(|s| format!(" service '{s}'"))
                .unwrap_or_default(),
            l.mtu,
            if l.enabled { "" } else { " disabled" }
        );
    }
    let _ = writeln!(extra, "\naliases ({verb}):");
    for a in &p.aliases {
        let _ = writeln!(
            extra,
            "  alias {} ({}): {}",
            a.name,
            patronus_firewall::aliases::kind_str(a.kind),
            a.entries.join(", ")
        );
    }
    let _ = writeln!(extra, "\nipsec site-to-site ({verb}):");
    for t in &p.ipsec {
        let _ = writeln!(
            extra,
            "  tunnel {} to {}: {} <-> {} IKEv2 psk: (set)",
            t.name,
            t.remote,
            t.local_ts.join(","),
            t.remote_ts.join(",")
        );
    }
    match rest.find("\ncovered by default:") {
        Some(at) => {
            o.push_str(&rest[..at]);
            o.push_str(&extra);
            o.push_str(&rest[at..]);
        }
        None => {
            o.push_str(&rest);
            o.push_str(&extra);
        }
    }
    o
}

// ---------------------------------------------------------------------------
// store writes
// ---------------------------------------------------------------------------

/// Write the plan into the store: VLANs/PPPoE, aliases and IPsec first, then the shared
/// [`import_uci::apply`] (interfaces, DHCP, rules, port forwards, DNS, WireGuard, routes ...).
pub async fn apply(store: &patronus_config::store::ConfigStore, p: &PfPlan) -> Result<Vec<String>> {
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    let mut out = Vec::new();
    if !p.vlans.is_empty() || !p.pppoe.is_empty() {
        let mut cfg = NetConfig::load(store).await.map_err(e)?;
        for v in &p.vlans {
            cfg.vlans.retain(|x| x.name != v.name);
            cfg.vlans.push(v.clone());
            out.push(format!("vlan {} on {}: written", v.name, v.parent));
        }
        for l in &p.pppoe {
            cfg.pppoe.retain(|x| x.name != l.name);
            cfg.pppoe.push(l.clone());
            out.push(format!(
                "pppoe {} on {}: written, password: (set)",
                l.name, l.parent
            ));
        }
        cfg.save(store).await.map_err(e)?;
    }
    for a in &p.aliases {
        if patronus_firewall::aliases::get_alias(store, &a.name)
            .await
            .map_err(e)?
            .is_some()
        {
            out.push(format!("alias {}: already present, left as it is", a.name));
            continue;
        }
        patronus_firewall::aliases::save_alias(store, a)
            .await
            .map_err(e)?;
        out.push(format!("alias {}: created", a.name));
    }
    #[cfg(feature = "vpn-ipsec")]
    for t in &p.ipsec {
        use patronus_network::ipsec;
        let have = ipsec::list_tunnels(store).await.map_err(e)?;
        if have.iter().any(|x| x.name == t.name) {
            out.push(format!(
                "ipsec tunnel {}: already present, left as it is",
                t.name
            ));
            continue;
        }
        let r = ipsec::save_tunnel(
            store,
            None,
            &ipsec::TunnelInput {
                name: Some(t.name.clone()),
                enabled: Some(t.enabled),
                remote_address: Some(t.remote.clone()),
                psk: Some(t.psk.clone()),
                local_ts: Some(t.local_ts.join(",")),
                remote_ts: Some(t.remote_ts.join(",")),
                description: t.description.clone(),
                ..Default::default()
            },
        )
        .await;
        out.push(match r {
            Ok(_) => format!("ipsec tunnel {}: created, psk: (set)", t.name),
            Err(x) => format!("ipsec tunnel {}: skipped ({x})", t.name),
        });
    }
    #[cfg(not(feature = "vpn-ipsec"))]
    if !p.ipsec.is_empty() {
        out.push("ipsec: skipped (built without the vpn-ipsec feature)".into());
    }
    out.extend(import_uci::apply(store, &p.plan).await?);
    Ok(out)
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// `patronus import pfsense FILE [--plan] [--map OLD=NEW]... [--yes]`.
pub async fn run(db: Option<PathBuf>, file: PathBuf, maps: Vec<String>, yes: bool) -> Result<()> {
    let maps = import_uci::parse_maps(&maps)?;
    let xml = std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
    let plan = build_plan(&xml, &maps)?;
    print!("{}", render(&plan, !yes));
    if !yes {
        println!("\nplan only, nothing written; add --yes to write it into the config store");
        return Ok(());
    }
    let store = super::apply::open_store(db.as_deref()).await?;
    println!("\nstore:");
    for l in apply(&store, &plan).await? {
        println!("  {l}");
    }
    println!("\nreview with `patronus apply --dry-run`, then `patronus apply`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::store::ConfigStore;

    // Documentation addresses only (RFC 5737 / RFC 3849), example.org names.
    const WG_PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const WG_PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const WG_PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";
    const IPSEC_PSK: &str = "correct-horse-battery-staple";

    fn pfsense_xml() -> String {
        format!(
            r#"<?xml version="1.0"?>
<pfsense>
  <version>22.2</version>
  <system>
    <hostname>Edge1</hostname>
    <domain>example.org</domain>
    <timezone>Europe/Berlin</timezone>
    <timeservers>0.pool.example.org 1.pool.example.org</timeservers>
    <dnsserver>192.0.2.53</dnsserver>
    <user><name>admin</name><password>$2y$10$notarealhash</password></user>
  </system>
  <interfaces>
    <wan>
      <enable></enable>
      <if>pppoe0</if>
      <descr>Uplink</descr>
      <ipaddr>pppoe</ipaddr>
      <ipaddrv6>dhcp6</ipaddrv6>
      <mtu>1492</mtu>
    </wan>
    <lan>
      <enable></enable>
      <if>em1</if>
      <descr>LAN</descr>
      <ipaddr>192.0.2.1</ipaddr>
      <subnet>24</subnet>
      <ipaddrv6>track6</ipaddrv6>
      <track6-interface>wan</track6-interface>
      <track6-prefix-id>0</track6-prefix-id>
    </lan>
    <opt1>
      <enable></enable>
      <if>em1.20</if>
      <descr>Servers</descr>
      <ipaddr>198.51.100.1</ipaddr>
      <subnet>24</subnet>
    </opt1>
  </interfaces>
  <vlans>
    <vlan><if>em1</if><tag>20</tag><vlanif>em1.20</vlanif><descr>Servers VLAN</descr></vlan>
  </vlans>
  <ppps>
    <ppp>
      <ptpid>0</ptpid><type>pppoe</type><if>pppoe0</if><ports>em0</ports>
      <username>user@example.org</username>
      <password>aHVudGVyMnBhc3M=</password>
      <provider>ExampleISP</provider>
    </ppp>
  </ppps>
  <gateways>
    <gateway_item><name>WAN_PPPOE</name><interface>wan</interface><gateway>dynamic</gateway><ipprotocol>inet</ipprotocol></gateway_item>
    <gateway_item><name>LAB_GW</name><interface>opt1</interface><gateway>198.51.100.254</gateway><ipprotocol>inet</ipprotocol></gateway_item>
  </gateways>
  <staticroutes>
    <route><network>203.0.113.0/24</network><gateway>LAB_GW</gateway><descr>Lab</descr></route>
  </staticroutes>
  <aliases>
    <alias><name>web_hosts</name><type>host</type><address>198.51.100.10 198.51.100.11</address><descr>Web servers</descr></alias>
    <alias><name>web_ports</name><type>port</type><address>80 443 8000:8080</address></alias>
    <alias><name>blocklist</name><type>urltable</type><url>https://lists.example.org/bad.txt</url><address>https://lists.example.org/bad.txt</address></alias>
    <alias><name>nordics</name><type>geoip</type><address>SE NO</address></alias>
  </aliases>
  <filter>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
      <source><network>lan</network></source><destination><any></any></destination>
      <descr>Default allow LAN to any rule</descr>
    </rule>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any></any></source>
      <destination><address>web_hosts</address><port>web_ports</port></destination>
      <descr>Web in</descr><log></log>
    </rule>
    <rule>
      <type>block</type><interface>opt1</interface><ipprotocol>inet</ipprotocol><protocol>tcp/udp</protocol>
      <source><network>opt1</network></source>
      <destination><address>192.0.2.0</address><subnet>24</subnet><port>53</port></destination>
      <descr>No DNS to LAN</descr><disabled></disabled>
    </rule>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any></any></source>
      <destination><not></not><address>198.51.100.0</address><subnet>24</subnet></destination>
      <descr>Everything but servers</descr>
    </rule>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol>
      <source><network>lan</network></source><destination><network>(self)</network></destination>
      <descr>Ping the firewall</descr>
    </rule>
  </filter>
  <nat>
    <outbound><mode>automatic</mode></outbound>
    <rule>
      <interface>wan</interface><protocol>tcp</protocol>
      <source><any></any></source>
      <destination><network>wanip</network><port>8443</port></destination>
      <target>198.51.100.10</target><local-port>443</local-port>
      <descr>HTTPS to web</descr><natreflection>enable</natreflection>
    </rule>
    <onetoone>
      <interface>wan</interface><external>203.0.113.7</external>
      <source><address>198.51.100.12</address></source><descr>Mail 1:1</descr>
    </onetoone>
  </nat>
  <dhcpd>
    <lan>
      <enable></enable>
      <range><from>192.0.2.100</from><to>192.0.2.199</to></range>
      <defaultleasetime>7200</defaultleasetime>
      <domain>lan.example.org</domain>
      <dnsserver>192.0.2.1</dnsserver>
      <staticmap><mac>02:00:00:00:00:10</mac><ipaddr>192.0.2.10</ipaddr><hostname>printer</hostname></staticmap>
      <staticmap><mac>02:00:00:00:00:11</mac><ipaddr>192.0.2.11</ipaddr><hostname>nas</hostname></staticmap>
    </lan>
  </dhcpd>
  <unbound>
    <enable></enable>
    <hosts><host>files</host><domain>example.org</domain><ip>192.0.2.20</ip></hosts>
    <domainoverrides><domain>corp.example.org</domain><ip>192.0.2.53</ip></domainoverrides>
  </unbound>
  <installedpackages>
    <wireguard>
      <tunnels>
        <item><name>tun_wg0</name><enabled>yes</enabled><listenport>51820</listenport>
          <privatekey>{WG_PRIV}</privatekey>
          <addresses><item><address>10.200.0.1</address><mask>24</mask></item></addresses></item>
      </tunnels>
      <peers>
        <item><tun>tun_wg0</tun><descr>laptop</descr><publickey>{WG_PUB}</publickey><presharedkey>{WG_PSK}</presharedkey>
          <allowedips><item><address>10.200.0.2</address><mask>32</mask></item></allowedips>
          <endpoint>vpn.example.org</endpoint><port>51821</port><persistentkeepalive>25</persistentkeepalive></item>
      </peers>
    </wireguard>
  </installedpackages>
  <openvpn>
    <openvpn-server>
      <vpnid>1</vpnid><mode>server_tls_user</mode><protocol>UDP4</protocol><local_port>1194</local_port>
      <tunnel_network>10.8.0.0/24</tunnel_network><description>Remote access</description>
    </openvpn-server>
  </openvpn>
  <ipsec>
    <phase1>
      <ikeid>1</ikeid><iketype>ikev2</iketype><remote-gateway>203.0.113.99</remote-gateway>
      <authentication_method>pre_shared_key</authentication_method>
      <pre-shared-key>{IPSEC_PSK}</pre-shared-key><descr>Branch office</descr>
    </phase1>
    <phase2>
      <ikeid>1</ikeid><mode>tunnel</mode>
      <localid><type>lan</type></localid>
      <remoteid><type>network</type><address>10.99.0.0</address><netbits>24</netbits></remoteid>
    </phase2>
    <phase1>
      <ikeid>2</ikeid><iketype>ikev1</iketype><remote-gateway>203.0.113.100</remote-gateway>
      <pre-shared-key>old-ikev1-secret-value</pre-shared-key><descr>Old site</descr>
    </phase1>
  </ipsec>
  <virtualip><vip><mode>ipalias</mode><interface>wan</interface><subnet>203.0.113.8</subnet></vip></virtualip>
</pfsense>"#
        )
    }

    fn maps() -> BTreeMap<String, String> {
        import_uci::parse_maps(&["em0=eth0".into(), "em1=eth1".into()]).unwrap()
    }

    fn plan() -> PfPlan {
        build_plan(&pfsense_xml(), &maps()).unwrap()
    }

    fn unmapped_has(p: &PfPlan, what: &str) -> bool {
        p.plan.unmapped.iter().any(|u| u.contains(what))
    }

    #[test]
    fn pfsense_interfaces_vlan_and_pppoe() {
        let p = plan();
        assert_eq!(p.flavor, "pfsense");
        let by = |n: &str| p.plan.ifaces.iter().find(|i| i.uci == n).unwrap();
        let (wan, lan, dmz) = (by("wan"), by("lan"), by("opt1"));
        assert_eq!(
            (wan.device.as_str(), wan.role.as_deref()),
            ("pppoe0", Some("wan"))
        );
        assert_eq!(wan.v6, V6Mode::Dhcp6);
        assert_eq!(wan.mtu, Some(1492));
        assert_eq!((lan.device.as_str(), lan.v4), ("eth1", V4Mode::Static));
        assert_eq!(lan.addrs[0].to_string(), "192.0.2.1/24");
        // the VLAN device follows its mapped parent
        assert_eq!(dmz.device, "eth1.20");
        assert_eq!(dmz.role.as_deref(), Some("opt1"));
        assert_eq!(p.vlans.len(), 1);
        assert_eq!(
            (
                p.vlans[0].name.as_str(),
                p.vlans[0].parent.as_str(),
                p.vlans[0].vlan_id
            ),
            ("eth1.20", "eth1", 20)
        );
        // PPPoE: base64 password decoded, service name kept
        assert_eq!(p.pppoe.len(), 1);
        let l = &p.pppoe[0];
        assert_eq!((l.name.as_str(), l.parent.as_str()), ("pppoe0", "eth0"));
        assert_eq!(l.username, "user@example.org");
        assert_eq!(l.password, "hunter2pass");
        assert_eq!(l.service_name.as_deref(), Some("ExampleISP"));
        assert!(l.ipv6);
        // track6 -> prefix delegation from the WAN to the LAN
        let pd = &p.plan.ext.iface6["pppoe0"].pd_downstream;
        assert_eq!(pd, &vec!["eth1".to_string()]);
        // system
        assert_eq!(
            p.plan.ext.general,
            Some((Some("edge1".into()), Some("Europe/Berlin".into())))
        );
        let ntp = p.plan.ext.ntp.as_ref().unwrap();
        assert_eq!(ntp.1, vec!["0.pool.example.org", "1.pool.example.org"]);
    }

    #[test]
    fn pfsense_aliases() {
        let p = plan();
        let names: Vec<&str> = p.aliases.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["web_hosts", "web_ports"]);
        assert_eq!(p.aliases[0].entries, vec!["198.51.100.10", "198.51.100.11"]);
        assert_eq!(p.aliases[1].kind, AliasKind::Port);
        assert_eq!(p.aliases[1].entries, vec!["80", "443", "8000-8080"]);
        assert!(unmapped_has(&p, "alias 'blocklist'") && unmapped_has(&p, "filled from a URL"));
        assert!(unmapped_has(&p, "alias 'nordics'") && unmapped_has(&p, "lists countries"));
    }

    #[test]
    fn pfsense_rules_disabled_not_alias_and_defaults() {
        let p = plan();
        let r = &p.plan.fw_rules;
        let by = |n: &str| r.iter().find(|x| x.name == n).unwrap();
        // the default LAN allow rule is covered by default, not imported
        assert!(!r.iter().any(|x| x.name.starts_with("Default allow LAN")));
        assert!(p
            .plan
            .covered
            .iter()
            .any(|c| c.contains("default LAN allow rule")));
        let web = by("Web in");
        assert_eq!(web.destination.as_deref(), Some("$web_hosts"));
        assert_eq!(web.dport, Some(PortSpec::Alias("web_ports".into())));
        assert_eq!(web.protocol, Some(Protocol::Tcp));
        assert_eq!(web.interface_in.as_deref(), Some("@wan"));
        assert!(web.log && web.enabled);
        // tcp/udp becomes two rules, disabled stays disabled, the interface name is the subnet
        let dns: Vec<_> = r
            .iter()
            .filter(|x| x.name.starts_with("No DNS to LAN"))
            .collect();
        assert_eq!(dns.len(), 2);
        assert!(dns.iter().all(|x| !x.enabled));
        assert_eq!(dns[0].source.as_deref(), Some("198.51.100.0/24"));
        assert_eq!(dns[0].destination.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(dns[0].action, FirewallAction::Drop);
        // "not" cannot be expressed: reported, not imported
        assert!(!r.iter().any(|x| x.name == "Everything but servers"));
        assert!(unmapped_has(&p, "rule 'Everything but servers'") && unmapped_has(&p, "negated"));
        // to the firewall itself: input chain
        assert_eq!(by("Ping the firewall").chain, ChainType::Input);
    }

    #[test]
    fn pfsense_port_forward_one_to_one_and_outbound() {
        let p = plan();
        let nat = &p.plan.nat_rules;
        let fwd: Vec<_> = nat
            .iter()
            .filter(|n| n.name.starts_with("HTTPS to web"))
            .collect();
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].dport, Some(PortSpec::Single(8443)));
        assert_eq!(fwd[0].interface_in.as_deref(), Some("@wan"));
        assert!(fwd[0].reflection);
        match &fwd[0].nat_type {
            NatType::Dnat {
                to_address,
                to_port,
            } => {
                assert_eq!(to_address.to_string(), "198.51.100.10");
                assert_eq!(*to_port, Some(443));
            }
            t => panic!("not a port forward: {t:?}"),
        }
        assert!(nat.iter().any(|n| matches!(
            &n.nat_type,
            NatType::OneToOne { external, internal }
                if external.to_string() == "203.0.113.7" && internal.to_string() == "198.51.100.12"
        )));
        assert!(p
            .plan
            .covered
            .iter()
            .any(|c| c.contains("outbound NAT mode 'automatic'")));
    }

    #[test]
    fn pfsense_dhcp_static_maps_dns_gateways_routes() {
        let p = plan();
        assert_eq!(p.plan.pools.len(), 1);
        let pool = &p.plan.pools[0];
        assert_eq!(pool.device, "eth1");
        assert_eq!(
            (pool.start.to_string(), pool.end.to_string()),
            ("192.0.2.100".into(), "192.0.2.199".into())
        );
        assert_eq!(pool.lease_time, Some(7200));
        assert_eq!(pool.router.to_string(), "192.0.2.1");
        assert_eq!(pool.domain.as_deref(), Some("lan.example.org"));
        assert_eq!(p.plan.statics.len(), 2);
        assert_eq!(p.plan.statics[0].mac, "02:00:00:00:00:10");
        assert_eq!(p.plan.statics[0].name.as_deref(), Some("printer"));
        assert_eq!(p.plan.statics[1].ip.to_string(), "192.0.2.11");
        assert_eq!(p.plan.ext.pool_dns["eth1"], "192.0.2.1");
        assert_eq!(p.plan.ext.hosts.len(), 1);
        assert_eq!(p.plan.ext.hosts[0].0, "files");
        assert_eq!(p.plan.ext.hosts[0].2.to_string(), "192.0.2.20");
        assert_eq!(
            p.plan.ext.domains,
            vec![("corp.example.org".to_string(), "192.0.2.53".to_string())]
        );
        let gw: Vec<&str> = p
            .plan
            .ext
            .gateways
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(gw, vec!["WAN_PPPOE", "LAB_GW"]);
        assert_eq!(p.plan.ext.routes.len(), 1);
        assert_eq!(p.plan.ext.routes[0].destination, "203.0.113.0/24");
        assert_eq!(
            p.plan.ext.routes[0].gateway.as_deref(),
            Some("198.51.100.254")
        );
    }

    #[test]
    fn pfsense_wireguard_openvpn_ipsec() {
        let p = plan();
        assert_eq!(p.plan.ext.wg.len(), 1);
        let wg = &p.plan.ext.wg[0];
        assert_eq!(wg.listen_port, Some(51820));
        assert_eq!(wg.addresses, vec!["10.200.0.1/24"]);
        assert_eq!(wg.private_key.as_deref(), Some(WG_PRIV));
        assert_eq!(wg.peers.len(), 1);
        assert_eq!(wg.peers[0].public_key, WG_PUB);
        assert_eq!(wg.peers[0].allowed_ips, vec!["10.200.0.2/32"]);
        assert_eq!(
            wg.peers[0].endpoint.as_deref(),
            Some("vpn.example.org:51821")
        );
        assert_eq!(wg.peers[0].keepalive, Some(25));
        // OpenVPN: plain-words entry in unmapped
        assert!(p
            .plan
            .unmapped
            .iter()
            .any(|u| u.contains("OpenVPN server 'Remote access' (UDP4 1194")
                && u.contains("recreate it under VPN > OpenVPN")));
        // IKEv2 + PSK site-to-site maps, IKEv1 is listed
        assert_eq!(p.ipsec.len(), 1);
        let t = &p.ipsec[0];
        assert_eq!(
            (t.name.as_str(), t.remote.as_str()),
            ("Branch_office", "203.0.113.99")
        );
        assert_eq!(t.local_ts, vec!["192.0.2.0/24"]);
        assert_eq!(t.remote_ts, vec!["10.99.0.0/24"]);
        assert!(unmapped_has(
            &p,
            "IPsec tunnel 'Old site' to 203.0.113.100 (IKEV1)"
        ));
        assert!(unmapped_has(&p, "virtual IPs"));
        assert!(unmapped_has(&p, "local user account"));
    }

    #[test]
    fn report_never_prints_secrets() {
        let p = plan();
        let out = render(&p, true);
        for secret in [
            WG_PRIV,
            WG_PSK,
            IPSEC_PSK,
            "hunter2pass",
            "aHVudGVyMnBhc3M=",
            "old-ikev1-secret-value",
        ] {
            assert!(!out.contains(secret), "leaked {secret}");
        }
        assert!(out.contains("password: (set)"));
        assert!(out.contains("psk: (set)"));
        assert!(out.contains("pfsense config.xml (plan only"));
        assert!(out.contains("vlan eth1.20 on eth1 tag 20"));
        assert!(out.contains("alias web_hosts (host)"));
        assert!(out.contains("unmapped ("));
    }

    const OPNSENSE_XML: &str = r#"<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw2</hostname><domain>example.org</domain><timezone>UTC</timezone></system>
  <interfaces>
    <wan><if>vtnet0</if><enable>1</enable><ipaddr>dhcp</ipaddr><ipaddrv6>slaac</ipaddrv6></wan>
    <lan><if>vtnet1</if><enable>1</enable><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
    <opt2><if>wg0</if><descr>WG</descr><enable>1</enable></opt2>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type><interface>lan</interface><ipprotocol>inet46</ipprotocol>
      <source><network>lan</network></source><destination><any/></destination>
      <descr>LAN out</descr>
    </rule>
    <rule>
      <type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>udp</protocol>
      <source><any/></source><destination><network>wanip</network><port>51820</port></destination>
      <descr>WireGuard in</descr>
    </rule>
  </filter>
  <OPNsense>
    <Firewall>
      <Alias>
        <aliases>
          <alias uuid="a1"><name>admins</name><type>host</type><content>192.0.2.50
192.0.2.51</content><enabled>1</enabled><description>Admin hosts</description></alias>
          <alias uuid="a2"><name>mgmt_ports</name><type>port</type><content>22
8443</content><enabled>1</enabled></alias>
          <alias uuid="a3"><name>feed</name><type>urltable</type><content>https://lists.example.org/x.txt</content><enabled>1</enabled></alias>
        </aliases>
      </Alias>
    </Firewall>
    <unboundplus>
      <hosts>
        <host uuid="h1"><enabled>1</enabled><hostname>nas</hostname><domain>example.org</domain><rr>A</rr><server>192.0.2.30</server></host>
        <host uuid="h2"><enabled>1</enabled><hostname>mail</hostname><domain>example.org</domain><rr>MX</rr><server>mx.example.org</server></host>
      </hosts>
      <domains>
        <domain uuid="d1"><enabled>1</enabled><domain>corp.example.org</domain><server>192.0.2.53</server></domain>
      </domains>
    </unboundplus>
    <wireguard>
      <server>
        <servers>
          <server uuid="s1"><enabled>1</enabled><name>road</name><instance>0</instance>
            <privkey>yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=</privkey>
            <port>51820</port><tunneladdress>10.201.0.1/24</tunneladdress>
            <peers>c1</peers></server>
        </servers>
      </server>
      <client>
        <clients>
          <client uuid="c1"><enabled>1</enabled><name>phone</name>
            <pubkey>xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=</pubkey>
            <tunneladdress>10.201.0.2/32</tunneladdress></client>
        </clients>
      </client>
    </wireguard>
  </OPNsense>
</opnsense>"#;

    #[test]
    fn opnsense_aliases_dns_wireguard() {
        let m = import_uci::parse_maps(&["vtnet0=eth0".into(), "vtnet1=eth1".into()]).unwrap();
        let p = build_plan(OPNSENSE_XML, &m).unwrap();
        assert_eq!(p.flavor, "opnsense");
        assert_eq!(p.aliases.len(), 2);
        assert_eq!(p.aliases[0].entries, vec!["192.0.2.50", "192.0.2.51"]);
        assert_eq!(p.aliases[1].entries, vec!["22", "8443"]);
        assert!(unmapped_has(&p, "alias 'feed'"));
        assert_eq!(p.plan.ext.hosts.len(), 1);
        assert_eq!(p.plan.ext.hosts[0].0, "nas");
        assert!(unmapped_has(&p, "host override 'mail' (record type MX)"));
        assert_eq!(p.plan.ext.domains.len(), 1);
        assert_eq!(p.plan.ext.wg.len(), 1);
        assert_eq!(p.plan.ext.wg[0].addresses, vec!["10.201.0.1/24"]);
        assert_eq!(p.plan.ext.wg[0].peers[0].allowed_ips, vec!["10.201.0.2/32"]);
        // the WireGuard interface assignment is not a device
        assert!(p.plan.ifaces.iter().all(|i| i.uci != "opt2"));
        // slaac WAN, inet46 rule keeps both families (no ip_version)
        let wan = p.plan.ifaces.iter().find(|i| i.uci == "wan").unwrap();
        assert_eq!((wan.v4, wan.v6), (V4Mode::Dhcp, V6Mode::Slaac));
        let r = p
            .plan
            .fw_rules
            .iter()
            .find(|r| r.name == "LAN out")
            .unwrap();
        assert_eq!(r.ip_version, None);
        assert_eq!(r.source.as_deref(), Some("192.0.2.0/24"));
        // wanip destination = the firewall itself
        let w = p
            .plan
            .fw_rules
            .iter()
            .find(|r| r.name == "WireGuard in")
            .unwrap();
        assert_eq!(w.chain, ChainType::Input);
        assert_eq!(w.dport, Some(PortSpec::Single(51820)));
    }

    #[test]
    fn rejects_other_files() {
        assert!(build_plan("<?xml version=\"1.0\"?><config/>", &BTreeMap::new()).is_err());
        assert!(build_plan("not xml", &BTreeMap::new()).is_err());
    }

    #[tokio::test]
    async fn apply_writes_the_store() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let p = plan();
        let out = apply(&store, &p).await.unwrap().join("\n");
        for s in [WG_PRIV, "hunter2pass", IPSEC_PSK] {
            assert!(!out.contains(s), "leaked {s}");
        }
        // VLAN and PPPoE survive the shared apply (it reloads the NetConfig)
        let cfg = NetConfig::load(&store).await.unwrap();
        assert!(cfg
            .vlans
            .iter()
            .any(|v| v.name == "eth1.20" && v.vlan_id == 20));
        let pp = cfg.pppoe.iter().find(|l| l.name == "pppoe0").unwrap();
        assert_eq!(pp.username, "user@example.org");
        assert_eq!(pp.password, "hunter2pass");
        assert_eq!(cfg.iface("eth1").unwrap().role.as_deref(), Some("lan"));
        assert_eq!(
            cfg.iface("eth1").unwrap().ipv4[0].to_string(),
            "192.0.2.1/24"
        );
        // aliases
        let al = patronus_firewall::aliases::load_aliases(&store)
            .await
            .unwrap();
        assert!(al.iter().any(|a| a.name == "web_hosts"));
        assert!(al.iter().any(|a| a.name == "web_ports"));
        // rules, port forward, static leases
        let rules = store.load_firewall_rules().await.unwrap();
        assert!(rules
            .iter()
            .any(|r| r.name == "Web in" && r.destination.as_deref() == Some("$web_hosts")));
        let nats = store.load_nat_rules().await.unwrap();
        assert!(nats.iter().any(|n| n.name.starts_with("HTTPS to web")));
        #[cfg(feature = "dhcp-server")]
        {
            let pools = patronus_network::dhcp::list_pools(&store).await.unwrap();
            assert_eq!(pools[0].static_mappings.len(), 2);
            assert!(pools[0]
                .static_mappings
                .iter()
                .any(|l| l.mac.eq_ignore_ascii_case("02:00:00:00:00:10")));
        }
        #[cfg(feature = "vpn-ipsec")]
        {
            let t = patronus_network::ipsec::list_tunnels(&store).await.unwrap();
            assert!(t
                .iter()
                .any(|t| t.name == "Branch_office" && t.remote_address == "203.0.113.99"));
        }
        // a second run changes nothing it should not
        let again = apply(&store, &p).await.unwrap().join("\n");
        assert!(again.contains("alias web_hosts: already present"));
    }
}
