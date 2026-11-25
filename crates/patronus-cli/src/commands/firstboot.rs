//! First-boot network seeding (`[firstboot]` + the bonds / VLANs of
//! `[network]` in patronus.toml), shared by the router images and the
//! standard-tier installer.
//!
//! ```toml
//! [network]
//! lan_interface  = "br-lan"
//! wan_interface  = "eth1"            # or a VLAN / bond declared below
//! mgmt_interface = "bond0.20"        # optional dedicated management network
//! [[network.bond]]                   # see patronus_config::Bootstrap
//! name = "bond0"
//! members = ["eth2", "eth3"]
//! mode = "802.3ad"
//! [[network.vlan]]
//! parent = "bond0"
//! tag = 20
//! [firstboot]
//! lan_address  = "192.168.1.1/24"    # OpenWrt-style default LAN IP
//! wan_dhcp     = true                # the WAN port is a DHCP client (= wan_mode "dhcp")
//! wan_mode     = "dhcp"              # dhcp | static | pppoe
//! wan_address  = "198.51.100.2/24"   # wan_mode static
//! wan_gateway  = "198.51.100.1"
//! wan_dns      = ["9.9.9.9"]         # static: upstream DNS servers
//! pppoe_username = "user@isp"        # wan_mode pppoe (the WAN role moves to the ppp device)
//! pppoe_password = "..."
//! pppoe_service  = ""                # optional
//! pppoe_device   = "pppoe0"          # optional, the ppp device name
//! mgmt_address = "10.20.0.1/24"      # management network address (none = DHCP)
//! mgmt_gateway = "10.20.0.254"       # optional
//! mgmt_only    = true                # SSH + web UI answer only on the management network (default)
//! dhcp_start   = "192.168.1.100"     # optional pool (needs the dhcp feature)
//! dhcp_end     = "192.168.1.249"
//! dns_mode     = "forwarder"         # optional: dnsmasq answers DNS (no Unbound on the image)
//! ```
//!
//! Applied once: the `firstboot.lan_seeded` setting records it, after which the
//! store (Interfaces / DHCP pages, the setup wizard) is the single source of truth.
//! Everything is validated before the first write: a bad file seeds nothing.

use patronus_config::store::ConfigStore;
use patronus_config::Bootstrap;
use patronus_network::lan::{get_setting, set_setting};
use patronus_network::netconf::{BondConfig, NetConfig, PppoeConfig, V4Mode, VlanConfig};
use std::path::Path;

const SEEDED: &str = "firstboot.lan_seeded";

/// Link monitor interval of a first-boot bond without `miimon` (ms).
pub const DEFAULT_BOND_MIIMON: u32 = 100;
/// ppp device of a PPPoE WAN without `pppoe_device`.
pub const DEFAULT_PPPOE_DEVICE: &str = "pppoe0";
/// MTU of a first-boot PPPoE link (RFC 2516: 1500 - 8).
pub const DEFAULT_PPPOE_MTU: u32 = 1492;

#[derive(serde::Deserialize, Default)]
struct File {
    #[serde(default)]
    firstboot: Section,
}

#[derive(serde::Deserialize, Default)]
struct Section {
    lan_address: Option<String>,
    /// WAN port gets its address by DHCP (the usual ISP/modem case).
    wan_dhcp: Option<bool>,
    /// `dhcp`, `static` or `pppoe` (`wan_dhcp = true` is `dhcp`).
    wan_mode: Option<String>,
    wan_address: Option<String>,
    wan_gateway: Option<String>,
    #[serde(default)]
    wan_dns: Vec<String>,
    pppoe_username: Option<String>,
    pppoe_password: Option<String>,
    pppoe_service: Option<String>,
    pppoe_device: Option<String>,
    mgmt_address: Option<String>,
    mgmt_gateway: Option<String>,
    mgmt_only: Option<bool>,
    dhcp_start: Option<String>,
    dhcp_end: Option<String>,
    /// `dns.mode` to start with (auto, resolver, forwarder, disabled). Router
    /// images without Unbound set `forwarder`: `auto` would resolve to
    /// `disabled` there, while the first-boot DHCP pool hands out the
    /// router's own address as the clients' DNS server.
    dns_mode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WanMode {
    Dhcp,
    Static,
    Pppoe,
}

fn wan_mode(s: &Section) -> anyhow::Result<Option<WanMode>> {
    match s.wan_mode.as_deref().map(|m| m.trim().to_ascii_lowercase()) {
        None => Ok((s.wan_dhcp == Some(true)).then_some(WanMode::Dhcp)),
        Some(m) => match m.as_str() {
            "dhcp" => Ok(Some(WanMode::Dhcp)),
            "static" => Ok(Some(WanMode::Static)),
            "pppoe" => Ok(Some(WanMode::Pppoe)),
            _ => anyhow::bail!("[firstboot] wan_mode {m:?} (dhcp, static or pppoe)"),
        },
    }
}

/// Route metric of the `rank`-th (0 = first) `wan_interfaces` entry: the first keeps the role's default
/// (100), each later one is 50 worse, so the list order is the failover order.
fn wan_metric(rank: usize) -> Option<u32> {
    (rank > 0).then(|| 100 + 50 * rank.min(100) as u32)
}

const DNS_MODES: &[&str] = &["auto", "resolver", "forwarder", "disabled"];

/// The validated `[firstboot] dns_mode`, if any.
fn dns_mode(s: &Section) -> anyhow::Result<Option<String>> {
    match s.dns_mode.as_deref().map(|m| m.trim().to_ascii_lowercase()) {
        None => Ok(None),
        Some(m) if DNS_MODES.contains(&m.as_str()) => Ok(Some(m)),
        Some(m) => {
            anyhow::bail!("[firstboot] dns_mode {m:?} (auto, resolver, forwarder or disabled)")
        }
    }
}

fn net(key: &str, v: &str) -> anyhow::Result<patronus_network::ipnetwork::IpNetwork> {
    if !v.contains('/') {
        anyhow::bail!("[firstboot] {key} {v:?}: give the prefix length too (e.g. {v}/24)");
    }
    v.parse()
        .map_err(|e| anyhow::anyhow!("[firstboot] {key} {v:?}: {e} (address/prefix)"))
}

fn ip(key: &str, v: &str) -> anyhow::Result<std::net::IpAddr> {
    v.trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("[firstboot] {key} {v:?} is not an IP address"))
}

fn opt_ip(key: &str, v: Option<&str>) -> anyhow::Result<Option<std::net::IpAddr>> {
    v.filter(|g| !g.trim().is_empty())
        .map(|g| ip(key, g))
        .transpose()
}

/// Build the seeded network configuration on top of `cfg` (pure, so it is
/// unit-tested without a store). Returns the report parts.
fn plan(
    cfg: &mut NetConfig,
    b: &Bootstrap,
    s: &Section,
    lan_seed: bool,
) -> anyhow::Result<Vec<String>> {
    let mut msg = Vec::new();
    b.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let made = Some("created by the installer (first boot)".to_string());
    for bd in &b.bonds {
        cfg.bonds.retain(|x| x.name != bd.name);
        cfg.bonds.push(BondConfig {
            name: bd.name.clone(),
            mode: bd.mode.clone(),
            miimon: bd.miimon.unwrap_or(DEFAULT_BOND_MIIMON),
            lacp_rate: bd.lacp_rate.clone(),
            xmit_hash_policy: bd.xmit_hash_policy.clone(),
            primary: bd.primary.clone(),
            members: bd.members.clone(),
            enabled: true,
            description: made.clone(),
        });
        msg.push(format!(
            "bond {} ({}: {})",
            bd.name,
            bd.mode,
            bd.members.join("+")
        ));
    }
    for v in &b.vlans {
        let name = v.device();
        cfg.vlans.retain(|x| x.name != name);
        cfg.vlans.push(VlanConfig {
            name: name.clone(),
            parent: v.parent.clone(),
            vlan_id: v.tag,
            protocol: "802.1q".into(),
            enabled: true,
            description: made.clone(),
        });
        msg.push(format!("VLAN {name} (tag {} on {})", v.tag, v.parent));
    }
    if lan_seed {
        if let (Some(addr), Some(lan)) = (s.lan_address.as_deref(), b.lan.first()) {
            let n = net("lan_address", addr)?;
            let i = cfg.iface_mut(lan);
            i.role = Some("lan".into());
            i.ipv4_mode = V4Mode::Static;
            i.ipv4 = vec![n];
            msg.push(format!("LAN {lan} -> {addr}"));
        }
    }
    match wan_mode(s)? {
        None => {}
        Some(WanMode::Dhcp) => {
            // every `wan_interfaces` entry is a DHCP uplink; the list is in preference order
            // (a Wi-Fi router lists its 5 GHz client first and the 2.4 GHz one as the fallback)
            for (rank, wan) in b.wan.iter().enumerate() {
                let i = cfg.iface_mut(wan);
                i.role = Some("wan".into());
                i.ipv4_mode = V4Mode::Dhcp;
                i.metric = wan_metric(rank);
            }
            if !b.wan.is_empty() {
                msg.push(format!("WAN {} DHCP", b.wan.join(", ")));
            }
        }
        Some(WanMode::Static) => {
            let wan = b.wan.first().ok_or_else(|| {
                anyhow::anyhow!("[firstboot] wan_mode static needs wan_interface")
            })?;
            let addr = s
                .wan_address
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("[firstboot] wan_mode static needs wan_address"))?;
            let n = net("wan_address", addr)?;
            let gw = opt_ip("wan_gateway", s.wan_gateway.as_deref())?;
            if let Some(g) = gw {
                if !n.contains(g) {
                    anyhow::bail!("[firstboot] wan_gateway {g} is not inside {addr}");
                }
            }
            let i = cfg.iface_mut(wan);
            i.role = Some("wan".into());
            i.ipv4_mode = V4Mode::Static;
            i.ipv4 = vec![n];
            i.gateway4 = gw;
            msg.push(format!("WAN {wan} -> {addr}"));
        }
        Some(WanMode::Pppoe) => {
            let parent = b
                .wan
                .first()
                .ok_or_else(|| anyhow::anyhow!("[firstboot] wan_mode pppoe needs wan_interface"))?
                .clone();
            let user = s
                .pppoe_username
                .clone()
                .filter(|u| !u.trim().is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("[firstboot] wan_mode pppoe needs pppoe_username")
                })?;
            let dev = s
                .pppoe_device
                .clone()
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_PPPOE_DEVICE.into());
            if !patronus_network::netconf::is_valid_ifname(&dev) {
                anyhow::bail!("[firstboot] pppoe_device {dev:?} is not a valid interface name");
            }
            cfg.pppoe.retain(|p| p.name != dev);
            cfg.pppoe.push(PppoeConfig {
                name: dev.clone(),
                parent: parent.clone(),
                username: user,
                password: s.pppoe_password.clone().unwrap_or_default(),
                service_name: s.pppoe_service.clone().filter(|x| !x.is_empty()),
                mtu: DEFAULT_PPPOE_MTU,
                default_route: true,
                use_peer_dns: true,
                ipv6: false,
                enabled: true,
                description: made.clone(),
            });
            // the role belongs to the ppp device; the parent only carries the session
            cfg.iface_mut(&parent).role = None;
            cfg.iface_mut(&dev).role = Some("wan".into());
            msg.push(format!("WAN PPPoE {dev} over {parent}"));
        }
    }
    if let Some(mg) = b.mgmt.first() {
        let addr = s.mgmt_address.as_deref().filter(|a| !a.trim().is_empty());
        let n = addr.map(|a| net("mgmt_address", a)).transpose()?;
        let gw = opt_ip("mgmt_gateway", s.mgmt_gateway.as_deref())?;
        let i = cfg.iface_mut(mg);
        i.role = Some("mgmt".into());
        match n {
            Some(n) => {
                i.ipv4_mode = V4Mode::Static;
                i.ipv4 = vec![n];
                i.gateway4 = gw;
                msg.push(format!("management {mg} -> {n}"));
            }
            None => {
                i.ipv4_mode = V4Mode::Dhcp;
                msg.push(format!("management {mg} DHCP"));
            }
        }
    }
    Ok(msg)
}

/// Returns a one-line report when something was seeded.
pub async fn seed_lan(
    store: &ConfigStore,
    bootstrap_path: &Path,
    b: Option<&Bootstrap>,
) -> anyhow::Result<Option<String>> {
    let (Some(b), Ok(text)) = (b, std::fs::read_to_string(bootstrap_path)) else {
        return Ok(None);
    };
    let f: File = toml::from_str(&text).unwrap_or_default();
    let s = &f.firstboot;
    let lan_seed = s.lan_address.is_some() && !b.lan.is_empty();
    let net_seed =
        !b.bonds.is_empty() || !b.vlans.is_empty() || !b.mgmt.is_empty() || s.wan_mode.is_some();
    if !lan_seed && !net_seed {
        return Ok(None);
    }
    if get_setting(store, SEEDED).await.ok().flatten().is_some() {
        return Ok(None);
    }
    // validate everything before the first write
    let dns = dns_mode(s)?;
    let wan_dns = if wan_mode(s)? == Some(WanMode::Static) && !s.wan_dns.is_empty() {
        let v = s
            .wan_dns
            .iter()
            .map(|d| ip("wan_dns", d).map(|x| x.to_string()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Some(v.join(","))
    } else {
        None
    };
    let mut cfg = NetConfig::load(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut msg = plan(&mut cfg, b, s, lan_seed)?.join(", ");
    cfg.save(store).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(on) = s.mgmt_only {
        store
            .save_system_config(
                patronus_config::defaults::MGMT_ONLY_KEY,
                if on { "1" } else { "0" },
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    if let Some(u) = wan_dns {
        set_setting(store, "dns.upstreams", &u)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        msg.push_str(&format!(", upstream DNS {u}"));
    }
    #[cfg(feature = "dhcp-server")]
    if let (Some(st), Some(en), Some(lan), Some(addr)) = (
        s.dhcp_start.as_deref(),
        s.dhcp_end.as_deref(),
        b.lan.first(),
        s.lan_address.as_deref(),
    ) {
        let ip = addr.split('/').next().unwrap_or("").to_string();
        let pool = patronus_network::dhcp::PoolInput {
            interface: lan.clone(),
            enabled: true,
            range_start: st.into(),
            range_end: en.into(),
            gateway: Some(ip.clone()),
            dns_servers: Some(ip),
            description: Some("first-boot default".into()),
            ..Default::default()
        }
        .validate()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        patronus_network::dhcp::upsert_pool(store, None, &pool)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        msg.push_str(&format!(", DHCP {st}-{en}"));
    }
    #[cfg(not(feature = "dhcp-server"))]
    let _ = (&s.dhcp_start, &s.dhcp_end);
    if let Some(m) = dns {
        set_setting(store, "dns.mode", &m)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        msg.push_str(&format!(", DNS {m}"));
    }
    set_setting(store, SEEDED, "1")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> Section {
        toml::from_str::<File>(t).unwrap().firstboot
    }

    #[test]
    fn wan_list_order_is_the_failover_order() {
        assert_eq!(wan_metric(0), None);
        assert_eq!(wan_metric(1), Some(150));
        assert_eq!(wan_metric(2), Some(200));
    }

    #[test]
    fn dns_mode_is_validated() {
        assert_eq!(dns_mode(&parse("")).unwrap(), None);
        assert_eq!(
            dns_mode(&parse("[firstboot]\ndns_mode = \" Forwarder \"\n")).unwrap(),
            Some("forwarder".into())
        );
        let e = dns_mode(&parse("[firstboot]\ndns_mode = \"unbound\"\n")).unwrap_err();
        assert!(e.to_string().contains("dns_mode"), "{e}");
    }

    #[test]
    fn wan_mode_reads_the_old_wan_dhcp_flag() {
        assert_eq!(wan_mode(&parse("")).unwrap(), None);
        assert_eq!(
            wan_mode(&parse("[firstboot]\nwan_dhcp = true\n")).unwrap(),
            Some(WanMode::Dhcp)
        );
        assert_eq!(
            wan_mode(&parse("[firstboot]\nwan_mode = \"PPPoE\"\n")).unwrap(),
            Some(WanMode::Pppoe)
        );
        assert!(wan_mode(&parse("[firstboot]\nwan_mode = \"lte\"\n")).is_err());
    }

    const LAGG: &str = "[network]\nwan_interface='bond0.100'\nlan_interface='bond0.30'\nmgmt_interface='bond0.20'\n\
        [[network.bond]]\nname='bond0'\nmembers=['eth0','eth1']\nmode='802.3ad'\nlacp_rate='fast'\nxmit_hash_policy='layer2+3'\n\
        [[network.vlan]]\nparent='bond0'\ntag=100\n[[network.vlan]]\nparent='bond0'\ntag=30\n[[network.vlan]]\nparent='bond0'\ntag=20\n";

    #[test]
    fn bonds_vlans_wan_dhcp_and_the_management_network() {
        let text = format!(
            "{LAGG}[firstboot]\nlan_address='192.168.30.1/24'\nwan_mode='dhcp'\nmgmt_address='10.20.0.1/24'\n"
        );
        let b = Bootstrap::parse(&text).unwrap();
        let s = parse(&text);
        let mut cfg = NetConfig::default();
        let msg = plan(&mut cfg, &b, &s, true).unwrap();
        assert_eq!(cfg.bonds.len(), 1);
        assert_eq!(cfg.bonds[0].mode, "802.3ad");
        assert_eq!(cfg.bonds[0].lacp_rate.as_deref(), Some("fast"));
        assert_eq!(cfg.bonds[0].miimon, DEFAULT_BOND_MIIMON);
        assert_eq!(
            cfg.vlans
                .iter()
                .map(|v| (v.name.as_str(), v.vlan_id))
                .collect::<Vec<_>>(),
            vec![("bond0.100", 100), ("bond0.30", 30), ("bond0.20", 20)]
        );
        let w = cfg.iface("bond0.100").unwrap();
        assert_eq!(
            (w.role.as_deref(), w.ipv4_mode),
            (Some("wan"), V4Mode::Dhcp)
        );
        let m = cfg.iface("bond0.20").unwrap();
        assert_eq!(
            (m.role.as_deref(), m.ipv4_mode),
            (Some("mgmt"), V4Mode::Static)
        );
        assert_eq!(m.ipv4[0].to_string(), "10.20.0.1/24");
        assert_eq!(cfg.iface("bond0.30").unwrap().role.as_deref(), Some("lan"));
        // the members themselves carry nothing (NetConfig::validate refuses addressed members)
        assert!(cfg.iface("eth0").is_none());
        cfg.validate(&["eth0".into(), "eth1".into()]).unwrap();
        assert!(
            msg.join(", ").contains("bond bond0 (802.3ad: eth0+eth1)"),
            "{msg:?}"
        );
    }

    #[test]
    fn pppoe_over_a_vlan_moves_the_wan_role_to_the_ppp_device() {
        let text = "[network]\nwan_interface='eth0.7'\n[[network.vlan]]\nparent='eth0'\ntag=7\n\
                    [firstboot]\nwan_mode='pppoe'\npppoe_username='u@isp'\npppoe_password='p'\n";
        let b = Bootstrap::parse(text).unwrap();
        let mut cfg = NetConfig::default();
        plan(&mut cfg, &b, &parse(text), false).unwrap();
        assert_eq!(cfg.pppoe[0].parent, "eth0.7");
        assert_eq!(cfg.pppoe[0].name, DEFAULT_PPPOE_DEVICE);
        assert_eq!(
            cfg.iface(DEFAULT_PPPOE_DEVICE).unwrap().role.as_deref(),
            Some("wan")
        );
        assert_eq!(cfg.iface("eth0.7").and_then(|i| i.role.clone()), None);
        cfg.validate(&["eth0".into()]).unwrap();
    }

    #[test]
    fn static_wan_and_bad_values_are_plain_words() {
        let text = "[network]\nwan_interface='eth0'\n[firstboot]\nwan_mode='static'\nwan_address='198.51.100.2/24'\nwan_gateway='198.51.100.1'\n";
        let b = Bootstrap::parse(text).unwrap();
        let mut cfg = NetConfig::default();
        plan(&mut cfg, &b, &parse(text), false).unwrap();
        let w = cfg.iface("eth0").unwrap();
        assert_eq!(w.gateway4.unwrap().to_string(), "198.51.100.1");
        let bad = |t: &str| {
            let b = Bootstrap::parse(t).unwrap();
            plan(&mut NetConfig::default(), &b, &parse(t), true)
                .unwrap_err()
                .to_string()
        };
        assert!(bad("[network]\nwan_interface='eth0'\n[firstboot]\nwan_mode='static'\nwan_address='198.51.100.2/24'\nwan_gateway='10.0.0.1'\n").contains("not inside"));
        assert!(bad("[network]\nwan_interface='eth0'\n[firstboot]\nwan_mode='static'\nwan_address='198.51.100.2'\n").contains("prefix"));
        assert!(
            bad("[network]\nwan_interface='eth0'\n[firstboot]\nwan_mode='pppoe'\n")
                .contains("pppoe_username")
        );
        assert!(bad("[[network.vlan]]\nparent='eth0'\ntag=5000\n").contains("1-4094"));
    }
}
