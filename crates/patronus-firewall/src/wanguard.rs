//! WAN source-address guard: "block private networks" and "block bogon
//! networks" on the WAN interfaces (the pfSense / OPNsense per-WAN switches).
//!
//! New connections arriving on a WAN-role interface whose source address is
//! private (RFC 1918, CGNAT, loopback, ULA) or a bogon (reserved,
//! documentation, multicast and future-use ranges) are dropped, with a
//! rate-limited NFLOG entry so they show in the firewall log. Answers to the
//! router's own connections are unaffected (established/related is accepted
//! first), and DHCP server replies are always let through: many ISPs and
//! modems hand out leases from a private server address.
//!
//! Off by default, also for new installs: a router behind another NAT (a
//! modem in router mode, a carrier-grade NAT, a lab) sees private sources on
//! its WAN legitimately. Settings live in `system_config`.

use crate::nftables::TABLE;

/// `1` = drop private source addresses arriving on the WAN.
pub const CFG_BLOCK_PRIVATE: &str = "firewall.wan_block_private";
/// `1` = drop bogon source addresses arriving on the WAN.
pub const CFG_BLOCK_BOGONS: &str = "firewall.wan_block_bogons";

pub const PRIVATE_V4: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];
pub const PRIVATE_V6: &[&str] = &["fc00::/7"];

/// Reserved / unallocatable IPv4 space that never appears as a public source.
pub const BOGONS_V4: &[&str] = &[
    "0.0.0.0/8",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
/// IPv6 bogons. Link-local (fe80::/10) is NOT listed: neighbour discovery,
/// router advertisements and DHCPv6 replies on the WAN use it.
pub const BOGONS_V6: &[&str] = &[
    "::ffff:0:0/96",
    "100::/64",
    "2001:db8::/32",
    "3ffe::/16",
    "fec0::/10",
    "ff00::/8",
];

/// What the guard should do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WanGuard {
    pub block_private: bool,
    pub block_bogons: bool,
}

impl WanGuard {
    pub fn any(&self) -> bool {
        self.block_private || self.block_bogons
    }
}

pub async fn load(store: &patronus_config::store::ConfigStore) -> patronus_core::Result<WanGuard> {
    let on = |v: Option<String>| v.as_deref() == Some("1");
    Ok(WanGuard {
        block_private: on(store.load_system_config(CFG_BLOCK_PRIVATE).await?),
        block_bogons: on(store.load_system_config(CFG_BLOCK_BOGONS).await?),
    })
}

pub async fn save(
    store: &patronus_config::store::ConfigStore,
    g: WanGuard,
) -> patronus_core::Result<()> {
    let b = |x: bool| if x { "1" } else { "0" };
    store
        .save_system_config(CFG_BLOCK_PRIVATE, b(g.block_private))
        .await?;
    store
        .save_system_config(CFG_BLOCK_BOGONS, b(g.block_bogons))
        .await?;
    Ok(())
}

fn set(name: &str, ty: &str, elems: &[&str]) -> String {
    format!(
        "add set {TABLE} {name} {{ type {ty}; flags interval; auto-merge; elements = {{ {} }} }}\n",
        elems.join(", ")
    )
}

/// nft script lines (sets, the `wan_guard` chain and the jumps from input
/// and forward) for the WAN devices `devs`. Empty when off or no WAN.
pub fn script(g: WanGuard, devs: &[String], log_group: u16) -> String {
    let devs: Vec<&String> = devs
        .iter()
        .filter(|d| crate::nftables::is_valid_interface_name(d))
        .collect();
    if !g.any() || devs.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    s.push_str(&format!("add chain {TABLE} wan_guard\n"));
    // DHCP server replies (often from a private or 0/8-adjacent server)
    s.push_str(&format!(
        "add rule {TABLE} wan_guard udp sport 67 udp dport 68 return comment \"DHCP replies\"\n"
    ));
    s.push_str(&format!(
        "add rule {TABLE} wan_guard ip6 saddr fe80::/10 return comment \"link-local\"\n"
    ));
    let mut lists: Vec<(&str, &str, &str, &[&str])> = Vec::new();
    if g.block_private {
        lists.push(("wan_private4", "ipv4_addr", "ip", PRIVATE_V4));
        lists.push(("wan_private6", "ipv6_addr", "ip6", PRIVATE_V6));
    }
    if g.block_bogons {
        lists.push(("wan_bogon4", "ipv4_addr", "ip", BOGONS_V4));
        lists.push(("wan_bogon6", "ipv6_addr", "ip6", BOGONS_V6));
    }
    for (name, ty, fam, elems) in lists {
        s.push_str(&set(name, ty, elems));
        let what = if name.contains("private") {
            "private"
        } else {
            "bogon"
        };
        s.push_str(&format!(
            "add rule {TABLE} wan_guard {fam} saddr @{name} limit rate 5/second burst 20 packets \
             log prefix \"patronus[wan-{what}] drop: \" group {log_group}\n"
        ));
        s.push_str(&format!(
            "add rule {TABLE} wan_guard {fam} saddr @{name} counter drop comment \"WAN: block {what} sources\"\n"
        ));
    }
    let set_of = devs
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    for chain in ["input", "forward"] {
        s.push_str(&format!(
            "add rule {TABLE} {chain} iifname {{ {set_of} }} ct state new jump wan_guard\n"
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_or_no_wan_renders_nothing() {
        assert_eq!(script(WanGuard::default(), &["eth0".into()], 7), "");
        let on = WanGuard {
            block_private: true,
            block_bogons: true,
        };
        assert_eq!(script(on, &[], 7), "");
        // a hostile interface name never reaches the script
        assert_eq!(script(on, &["eth0\"; flush ruleset".into()], 7), "");
    }

    #[test]
    fn private_and_bogon_sets_and_jumps() {
        let s = script(
            WanGuard {
                block_private: true,
                block_bogons: false,
            },
            &["wan0".into(), "ppp0".into()],
            7,
        );
        assert!(s.contains("add set inet patronus wan_private4 { type ipv4_addr; flags interval; auto-merge; elements = { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } }"), "{s}");
        assert!(s.contains("ip6 saddr @wan_private6"), "{s}");
        assert!(!s.contains("bogon"), "{s}");
        assert!(s.contains("udp sport 67 udp dport 68 return"));
        assert!(s.contains("group 7"));
        assert!(s.contains(
            "add rule inet patronus input iifname { \"wan0\", \"ppp0\" } ct state new jump wan_guard"
        ));
        assert!(s.contains("add rule inet patronus forward iifname { \"wan0\", \"ppp0\" } ct state new jump wan_guard"));
        let b = script(
            WanGuard {
                block_private: false,
                block_bogons: true,
            },
            &["wan0".into()],
            7,
        );
        assert!(b.contains("ip saddr @wan_bogon4") && b.contains("ip6 saddr @wan_bogon6"));
        assert!(b.contains("203.0.113.0/24") && !b.contains("fe80::/10 }"));
        assert!(!b.contains("wan_private"));
    }

    #[test]
    fn link_local_and_rfc1918_are_not_bogons() {
        for x in BOGONS_V6 {
            assert!(!x.starts_with("fe80"), "{x}");
        }
        for x in BOGONS_V4 {
            assert!(!PRIVATE_V4.contains(x), "{x}");
        }
    }
}
