//! Spike for docs/design/device-segmentation.md (patronus, branch
//! spike/device-segmentation).  Pure functions: config in, nftables script and
//! hostapd files out.  Nothing here touches the system.
//!
//! Original code: the nft layout and the hostapd file formats follow
//! the nftables and hostapd documentation. No code was copied from SPR
//! (BSD-3-Clause, github.com/spr-networks/super); only its ideas (per-device
//! passwords, default isolation, one-way service rules) are reused.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Layer-2 domains whose members are managed devices (bridge / VLAN
    /// interface names). Traffic entering from any other interface is
    /// not touched by the segmentation chain.
    pub segment_ifaces: Vec<String>,
    /// IPv4 subnets of the segment. An address inside them that is not an
    /// enrolled, un-revoked device is unreachable (a revoked or unknown host
    /// that still sits on the wire gets nothing forwarded to it either).
    pub segment_v4_subnets: Vec<String>,
    /// IPv6 prefixes of the segment: device-to-device IPv6 inside them is
    /// denied (IPv6 identity binding is a later phase; see the design doc)
    #[serde(default)]
    pub segment_v6_prefixes: Vec<String>,
    pub groups: Vec<Group>,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub group_links: Vec<GroupLink>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub wifi: Option<Wifi>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    pub name: String,
    /// members of the group may talk to each other (default true)
    #[serde(default = "yes")]
    pub intra: bool,
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub name: String,
    pub mac: String,
    pub ip: String,
    pub iface: String,
    pub group: String,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub wifi: Option<DeviceWifi>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceWifi {
    /// WPA2-PSK passphrase bound to this device's MAC
    pub psk: Option<String>,
    /// WPA3-SAE password bound to this device's MAC
    pub sae_password: Option<String>,
    /// optional SAE password identifier (`id=`)
    pub sae_id: Option<String>,
}

/// bidirectional link between two groups
#[derive(Debug, Clone, Deserialize)]
pub struct GroupLink {
    pub a: String,
    pub b: String,
}

/// one-way service rule: `from` may open NEW connections to `to`:ports.
/// `from`/`to` = device name or `group:NAME`. Replies ride conntrack.
#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    pub name: String,
    pub from: String,
    pub to: String,
    pub proto: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Wifi {
    pub interface: String,
    pub ssid: String,
    #[serde(default = "default_channel")]
    pub channel: u32,
    #[serde(default = "default_country")]
    pub country: String,
    /// shared enrolment password: unknown stations may join with it and
    /// are held in quarantine by the nft layer (no entry = no forwarding)
    pub enrol_password: Option<String>,
}
fn default_channel() -> u32 {
    6
}
fn default_country() -> String {
    "US".into()
}

pub fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

pub fn norm_mac(s: &str) -> Result<String, String> {
    let p: Vec<&str> = s.split(':').collect();
    if p.len() != 6 || p.iter().any(|x| x.len() != 2 || !x.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(format!("bad MAC {s:?}"));
    }
    Ok(s.to_ascii_lowercase())
}

fn check_v4_prefix(p: &str) -> Result<(), String> {
    let (a, l) = p.split_once('/').ok_or_else(|| format!("bad IPv4 subnet {p:?}"))?;
    a.parse::<Ipv4Addr>().map_err(|_| format!("bad IPv4 subnet {p:?}"))?;
    match l.parse::<u8>() {
        Ok(n) if n <= 32 => Ok(()),
        _ => Err(format!("bad IPv4 subnet {p:?}")),
    }
}

fn check_v6_prefix(p: &str) -> Result<(), String> {
    let (a, l) = p.split_once('/').ok_or_else(|| format!("bad IPv6 prefix {p:?}"))?;
    a.parse::<std::net::Ipv6Addr>().map_err(|_| format!("bad IPv6 prefix {p:?}"))?;
    match l.parse::<u8>() {
        Ok(n) if n <= 128 => Ok(()),
        _ => Err(format!("bad IPv6 prefix {p:?}")),
    }
}

fn is_ifname(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// WPA2 passphrase: 8..63 printable ASCII without space; or 64 hex digits.
pub fn check_psk(p: &str) -> Result<(), String> {
    let ok_chars = p.bytes().all(|b| b.is_ascii_graphic());
    let hex64 = p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit());
    if (8..=63).contains(&p.len()) && ok_chars || hex64 {
        Ok(())
    } else {
        Err("WPA2 passphrase must be 8-63 printable ASCII characters without spaces (or 64 hex digits)".into())
    }
}

/// SAE password: 8..80 printable ASCII; `|` is the option separator of hostapd's
/// `sae_password=pw|mac=..|id=..` and would corrupt the line, so it is rejected.
pub fn check_sae(p: &str) -> Result<(), String> {
    if (8..=80).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_graphic() && b != b'|') {
        Ok(())
    } else {
        Err("SAE password must be 8-80 printable ASCII characters without '|' or spaces".into())
    }
}

fn check_id(p: &str) -> Result<(), String> {
    if !p.is_empty() && p.len() <= 32 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
        Ok(())
    } else {
        Err(format!("bad SAE identifier {p:?}"))
    }
}

struct Resolved<'a> {
    dev: &'a Device,
    mac: String,
    ip: Ipv4Addr,
}

fn resolve(c: &Config) -> Result<Vec<Resolved<'_>>, String> {
    let groups: BTreeSet<&str> = c.groups.iter().map(|g| g.name.as_str()).collect();
    for g in &c.groups {
        if !is_name(&g.name) {
            return Err(format!("bad group name {:?}", g.name));
        }
    }
    for i in &c.segment_ifaces {
        if !is_ifname(i) {
            return Err(format!("bad interface {i:?}"));
        }
    }
    let (mut macs, mut ips, mut names) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let mut out = Vec::new();
    for d in &c.devices {
        if !is_name(&d.name) || !names.insert(d.name.clone()) {
            return Err(format!("bad or duplicate device name {:?}", d.name));
        }
        if !groups.contains(d.group.as_str()) {
            return Err(format!("device {}: unknown group {:?}", d.name, d.group));
        }
        if !c.segment_ifaces.contains(&d.iface) {
            return Err(format!("device {}: iface {:?} is not a segment interface", d.name, d.iface));
        }
        let mac = norm_mac(&d.mac)?;
        let ip: Ipv4Addr = d.ip.parse().map_err(|_| format!("device {}: bad IPv4 {:?}", d.name, d.ip))?;
        if !macs.insert(mac.clone()) {
            return Err(format!("duplicate MAC {mac}"));
        }
        if !ips.insert(ip) {
            return Err(format!("duplicate IP {ip}"));
        }
        out.push(Resolved { dev: d, mac, ip });
    }
    Ok(out)
}

/// device names matched by `name` or `group:NAME` (revoked devices excluded:
/// a revoked device has no identity, so it can be neither source nor target)
fn endpoint<'a>(spec: &str, devs: &'a [Resolved<'a>]) -> Result<Vec<&'a Resolved<'a>>, String> {
    let v: Vec<&Resolved> = if let Some(g) = spec.strip_prefix("group:") {
        devs.iter().filter(|d| d.dev.group == g).collect()
    } else {
        devs.iter().filter(|d| d.dev.name == spec).collect()
    };
    if v.is_empty() && !devs.iter().any(|d| d.dev.name == spec || spec.strip_prefix("group:") == Some(&d.dev.group)) {
        return Err(format!("service endpoint {spec:?} matches no device"));
    }
    Ok(v.into_iter().filter(|d| !d.dev.revoked).collect())
}

/// Render the segmentation table. Loaded atomically (`add`+`delete`+`table`
/// in one `nft -f`), like the main Patronus ruleset.
pub fn render_nft(c: &Config) -> Result<String, String> {
    let devs = resolve(c)?;
    let live: Vec<&Resolved> = devs.iter().filter(|d| !d.dev.revoked).collect();
    let mut o = String::new();
    o.push_str("add table inet pseg\ndelete table inet pseg\ntable inet pseg {\n");

    let ifs: Vec<String> = c.segment_ifaces.iter().map(|i| format!("\"{i}\"")).collect();
    o.push_str(&format!("  set seg_ifaces {{ type ifname; elements = {{ {} }} }}\n", ifs.join(", ")));

    // identity binding: (ingress interface, MAC, IPv4) must match an enrolled, un-revoked device
    o.push_str("  set bound_v4 { type ifname . ether_addr . ipv4_addr; elements = {\n");
    let b: Vec<String> = live
        .iter()
        .map(|d| format!("    \"{}\" . {} . {} comment \"{}\"", d.dev.iface, d.mac, d.ip, d.dev.name))
        .collect();
    o.push_str(&b.join(",\n"));
    o.push_str("\n  } }\n");

    let all: Vec<String> = live.iter().map(|d| d.ip.to_string()).collect();
    o.push_str(&format!("  set seg_v4 {{ type ipv4_addr; elements = {{ {} }} }}\n", all.join(", ")));

    // per-group member sets
    let mut by_group: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for g in &c.groups {
        by_group.entry(g.name.as_str()).or_default();
    }
    for d in &live {
        by_group.get_mut(d.dev.group.as_str()).unwrap().push(d.ip.to_string());
    }
    for (g, m) in &by_group {
        if m.is_empty() {
            o.push_str(&format!("  set grp_{g}_v4 {{ type ipv4_addr; }}\n"));
        } else {
            o.push_str(&format!("  set grp_{g}_v4 {{ type ipv4_addr; elements = {{ {} }} }}\n", m.join(", ")));
        }
    }

    // one-way service rules, expanded to a single concatenated set
    let mut svc: BTreeSet<String> = BTreeSet::new();
    for s in &c.services {
        if s.proto != "tcp" && s.proto != "udp" {
            return Err(format!("service {}: proto must be tcp or udp", s.name));
        }
        if s.ports.is_empty() || s.ports.contains(&0) {
            return Err(format!("service {}: bad ports", s.name));
        }
        for f in endpoint(&s.from, &devs)? {
            for t in endpoint(&s.to, &devs)? {
                for p in &s.ports {
                    svc.insert(format!("{} . {} . {} . {}", f.ip, t.ip, s.proto, p));
                }
            }
        }
    }
    o.push_str("  set svc_v4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service;");
    if !svc.is_empty() {
        let v: Vec<String> = svc.into_iter().collect();
        o.push_str(&format!(" elements = {{ {} }};", v.join(", ")));
    }
    o.push_str(" }\n");

    for p in &c.segment_v6_prefixes {
        check_v6_prefix(p)?;
    }
    if c.segment_v4_subnets.is_empty() {
        return Err("segment_v4_subnets must not be empty".into());
    }
    for p in &c.segment_v4_subnets {
        check_v4_prefix(p)?;
    }
    o.push_str(&format!(
        "  set seg_net_v4 {{ type ipv4_addr; flags interval; elements = {{ {} }} }}\n",
        c.segment_v4_subnets.join(", ")
    ));
    if !c.segment_v6_prefixes.is_empty() {
        o.push_str(&format!(
            "  set seg_v6 {{ type ipv6_addr; flags interval; elements = {{ {} }} }}\n",
            c.segment_v6_prefixes.join(", ")
        ));
    }
    o.push_str("  chain seg_forward {\n");
    o.push_str("    # an address of the segment that is not an enrolled device (revoked, unknown) receives nothing,\n");
    o.push_str("    # not even established flows: revocation cuts live connections without a conntrack flush\n");
    o.push_str("    ip daddr @seg_net_v4 ip daddr != @seg_v4 counter drop comment \"unbound or revoked destination\"\n");
    o.push_str("    iifname != @seg_ifaces return\n");
    if !c.segment_v6_prefixes.is_empty() {
        o.push_str("    ip6 saddr @seg_v6 ip6 daddr @seg_v6 counter drop comment \"IPv6 between devices: denied\"\n");
    }
    o.push_str("    # quarantine / spoof / revoked: unknown (iface, MAC, IP) forwards nothing\n");
    o.push_str("    iifname . ether saddr . ip saddr != @bound_v4 limit rate 10/second log prefix \"seg-unbound \" group 7 counter drop\n");
    o.push_str("    iifname . ether saddr . ip saddr != @bound_v4 drop\n");
    o.push_str("    ct state established,related accept\n");
    o.push_str("    ct state invalid drop\n");
    o.push_str("    # traffic that is not device-to-device is the ordinary firewall's business\n");
    o.push_str("    ip daddr != @seg_v4 return\n");
    o.push_str("    ip saddr . ip daddr . meta l4proto . th dport @svc_v4 counter accept comment \"service rule\"\n");
    for g in &c.groups {
        if g.intra {
            o.push_str(&format!("    ip saddr @grp_{0}_v4 ip daddr @grp_{0}_v4 counter accept comment \"group {0}\"\n", g.name));
        }
    }
    let gnames: BTreeSet<&str> = c.groups.iter().map(|g| g.name.as_str()).collect();
    for l in &c.group_links {
        for g in [&l.a, &l.b] {
            if !gnames.contains(g.as_str()) {
                return Err(format!("group link: unknown group {g:?}"));
            }
        }
        o.push_str(&format!("    ip saddr @grp_{0}_v4 ip daddr @grp_{1}_v4 counter accept comment \"link {0}->{1}\"\n", l.a, l.b));
        o.push_str(&format!("    ip saddr @grp_{1}_v4 ip daddr @grp_{0}_v4 counter accept comment \"link {1}->{0}\"\n", l.a, l.b));
    }
    o.push_str("    limit rate 10/second log prefix \"seg-deny \" group 7\n");
    o.push_str("    counter drop comment \"default deny between devices\"\n");
    o.push_str("  }\n");
    // priority -10: runs before the main `inet patronus` forward chain, so a
    // permissive LAN->any rule there cannot re-open device-to-device paths.
    o.push_str("  chain forward { type filter hook forward priority -10; policy accept;\n    jump seg_forward\n  }\n");
    o.push_str("}\n");
    Ok(o)
}

pub struct Hostapd {
    pub conf: String,
    pub psk_file: String,
}

/// hostapd.conf + wpa_psk_file for the per-device credentials.
/// Revoked devices get no entry: that IS the revocation.
pub fn render_hostapd(c: &Config) -> Result<Hostapd, String> {
    let w = c.wifi.as_ref().ok_or("no [wifi] section")?;
    if !is_ifname(&w.interface) {
        return Err("bad wifi interface".into());
    }
    if w.ssid.is_empty() || w.ssid.len() > 32 || !w.ssid.bytes().all(|b| b.is_ascii_graphic() || b == b' ') || w.ssid.contains('\n') {
        return Err("bad SSID".into());
    }
    let devs = resolve(c)?;
    let mut psk = String::from("# generated by Patronus - do not edit\n");
    let mut sae = String::new();
    for d in devs.iter().filter(|d| !d.dev.revoked) {
        let Some(wf) = &d.dev.wifi else { continue };
        if let Some(p) = &wf.psk {
            check_psk(p).map_err(|e| format!("device {}: {e}", d.dev.name))?;
            psk.push_str(&format!("keyid={} {} {}\n", d.dev.name, d.mac, p));
        }
        if let Some(p) = &wf.sae_password {
            check_sae(p).map_err(|e| format!("device {}: {e}", d.dev.name))?;
            let id = match &wf.sae_id {
                Some(i) => {
                    check_id(i)?;
                    format!("|id={i}")
                }
                None => String::new(),
            };
            sae.push_str(&format!("sae_password={p}|mac={}{id}\n", d.mac));
        }
    }
    if let Some(e) = &w.enrol_password {
        check_psk(e)?;
        check_sae(e)?;
        psk.push_str(&format!("keyid=enrol 00:00:00:00:00:00 {e}\n"));
        sae.push_str(&format!("sae_password={e}|mac=ff:ff:ff:ff:ff:ff\n"));
    }
    let has_sae = !sae.is_empty();
    let has_psk = psk.lines().any(|l| !l.starts_with('#'));
    let mut km = Vec::new();
    if has_psk {
        km.push("WPA-PSK");
    }
    if has_sae {
        km.push("SAE");
    }
    if km.is_empty() {
        return Err("no device has a Wi-Fi credential".into());
    }
    let mut o = String::new();
    o.push_str("# generated by Patronus - do not edit\n");
    o.push_str(&format!("interface={}\ndriver=nl80211\nssid={}\nhw_mode=g\nchannel={}\ncountry_code={}\n", w.interface, w.ssid, w.channel, w.country));
    o.push_str("ctrl_interface=/run/hostapd\nctrl_interface_group=0\n");
    o.push_str("wpa=2\nrsn_pairwise=CCMP\n");
    o.push_str(&format!("wpa_key_mgmt={}\n", km.join(" ")));
    o.push_str(if has_sae && !has_psk { "ieee80211w=2\n" } else { "ieee80211w=1\n" });
    if has_sae {
        o.push_str("sae_pwe=2\n");
    }
    o.push_str("# stations may only talk through the router\nap_isolate=1\nmulticast_to_unicast=1\ntdls_prohibit=1\nwpa_disable_eapol_key_retries=1\n");
    if has_psk {
        o.push_str("wpa_psk_file=WPA_PSK_FILE_PATH\n");
    }
    o.push_str(&sae);
    Ok(Hostapd { conf: o, psk_file: psk })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        serde_json::from_str(include_str!("../examples/lab.json")).unwrap()
    }

    #[test]
    fn nft_has_default_deny_and_one_service_and_binding() {
        let n = render_nft(&cfg()).unwrap();
        assert!(n.contains("counter drop comment \"default deny between devices\""));
        assert!(n.contains("172.31.77.11 . 172.31.77.12 . tcp . 8080"), "{n}");
        assert!(!n.contains("172.31.77.12 . 172.31.77.11 . tcp"), "service rules are one-way");
        assert!(n.contains("\"br0\" . 02:aa:00:00:00:11 . 172.31.77.11"));
        assert!(n.contains("priority -10"));
    }

    #[test]
    fn revoked_device_leaves_every_set() {
        let mut c = cfg();
        c.devices.iter_mut().find(|d| d.name == "cam").unwrap().revoked = true;
        let n = render_nft(&c).unwrap();
        assert!(!n.contains("172.31.77.12"), "{n}");
        let h = render_hostapd(&c).unwrap();
        assert!(!h.psk_file.contains("02:aa:00:00:00:12"));
        assert!(!h.conf.contains("02:aa:00:00:00:12"));
    }

    #[test]
    fn hostapd_files_have_per_mac_entries_and_ids() {
        let h = render_hostapd(&cfg()).unwrap();
        assert!(h.psk_file.contains("keyid=laptop 02:aa:00:00:00:11 "));
        assert!(h.conf.contains("|mac=02:aa:00:00:00:11|id=laptop"));
        assert!(h.conf.contains("wpa_key_mgmt=WPA-PSK SAE"));
        assert!(h.conf.contains("ap_isolate=1"));
    }

    #[test]
    fn hostile_input_is_rejected() {
        let mut c = cfg();
        c.devices[0].wifi.as_mut().unwrap().sae_password = Some("abc|mac=00:00:00:00:00:00".into());
        assert!(render_hostapd(&c).is_err());
        let mut c = cfg();
        c.devices[0].wifi.as_mut().unwrap().psk = Some("short".into());
        assert!(render_hostapd(&c).is_err());
        let mut c = cfg();
        c.devices[0].mac = "02:aa:00:00:00:12".into();
        assert!(render_nft(&c).unwrap_err().contains("duplicate MAC"));
        let mut c = cfg();
        c.devices[0].group = "nope\"; flush ruleset; \"".into();
        assert!(render_nft(&c).is_err());
        let mut c = cfg();
        c.services[0].to = "ghost".into();
        assert!(render_nft(&c).is_err());
    }

    #[test]
    fn unbound_destination_in_segment_is_dropped_before_established() {
        let n = render_nft(&cfg()).unwrap();
        let a = n.find("unbound or revoked destination").unwrap();
        let b = n.find("ct state established,related accept").unwrap();
        assert!(a < b, "revocation must beat conntrack");
        let mut c = cfg();
        c.segment_v4_subnets.clear();
        assert!(render_nft(&c).is_err());
    }

    #[test]
    fn group_link_is_bidirectional() {
        let mut c = cfg();
        c.group_links.push(GroupLink { a: "trusted".into(), b: "iot".into() });
        let n = render_nft(&c).unwrap();
        assert!(n.contains("link trusted->iot") && n.contains("link iot->trusted"));
    }
}
