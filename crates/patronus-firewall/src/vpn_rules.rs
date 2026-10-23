//! Automatic firewall rules for the VPNs of lane F (`wg_interfaces`,
//! `ipsec_tunnels`), rendered after the user's rules so a user block still
//! wins:
//!
//! - input: each enabled WireGuard tunnel's UDP listen port; IKE (UDP
//!   500/4500) and ESP when an IPsec tunnel is enabled;
//! - input/forward: traffic that arrived through an IPsec SA (`meta ipsec
//!   exists`) from the tunnel's remote subnets to its local subnets -- the
//!   site-to-site equivalent of "LAN -> any"; plain packets spoofing those
//!   subnets on the WAN do not match;
//! - postrouting: local -> remote subnet traffic is exempt from outbound
//!   NAT (masquerading it would make it miss the IPsec policy and leave
//!   unencrypted).
//!
//! What WireGuard peers may reach stays with the user's rules on the tunnel
//! interface (e.g. interface `wg0`).

use crate::nftables::TABLE;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::net::IpAddr;

/// Rules to splice into the ruleset.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VpnRules {
    /// input/forward rules (full `add rule ...` lines)
    pub filter: Vec<String>,
    /// postrouting NAT exemptions, before any masquerade
    pub nat_exempt: Vec<String>,
    /// prerouting NAT rules (the web proxy's HTTP interception)
    pub nat_pre: Vec<String>,
}

/// `a.b.c.d/n` or `v6/n` (a bare address = host) -> (family keyword, text).
fn net(s: &str) -> Option<(&'static str, String)> {
    let s = s.trim();
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len: u8 = match len {
        Some(l) => l.parse().ok().filter(|l| *l <= max)?,
        None => max,
    };
    Some((
        if ip.is_ipv4() { "ip" } else { "ip6" },
        format!("{ip}/{len}"),
    ))
}

fn nets(list: &str) -> Vec<(&'static str, String)> {
    list.split([',', ' ', '\n'])
        .filter(|t| !t.trim().is_empty())
        .filter_map(net)
        .collect()
}

fn safe(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        .collect()
}

/// Render the VPN rules for the store.
pub async fn vpn_rules(store: &ConfigStore) -> Result<VpnRules> {
    let mut out = VpnRules::default();
    let db = |e: sqlx::Error| Error::Config(format!("read VPN tables: {e}"));
    let wg =
        sqlx::query("SELECT name, listen_port FROM wg_interfaces WHERE enabled = 1 ORDER BY name")
            .fetch_all(store.pool()?)
            .await
            .map_err(db)?;
    for r in wg {
        let name: String = r.get(0);
        let port: i64 = r.get(1);
        if (1..=65535).contains(&port) {
            out.filter.push(format!(
                "add rule {TABLE} input udp dport {port} accept comment \"WireGuard {}\"",
                safe(&name)
            ));
        }
    }
    let ipsec = sqlx::query(
        "SELECT name, local_ts, remote_ts FROM ipsec_tunnels WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db)?;
    if !ipsec.is_empty() {
        out.filter.push(format!(
            "add rule {TABLE} input udp dport {{ 500, 4500 }} accept comment \"IPsec IKE\""
        ));
        out.filter.push(format!(
            "add rule {TABLE} input meta l4proto esp accept comment \"IPsec ESP\""
        ));
    }
    for r in ipsec {
        let name = safe(&r.get::<String, _>(0));
        let local = nets(&r.get::<String, _>(1));
        let remote = nets(&r.get::<String, _>(2));
        for (lf, l) in &local {
            for (rf, rn) in &remote {
                if lf != rf {
                    continue;
                }
                for chain in ["input", "forward"] {
                    out.filter.push(format!(
                        "add rule {TABLE} {chain} meta ipsec exists {lf} saddr {rn} {lf} daddr {l} \
                         accept comment \"IPsec {name}\""
                    ));
                }
                out.nat_exempt.push(format!(
                    "add rule {TABLE} postrouting {lf} saddr {l} {lf} daddr {rn} accept \
                     comment \"IPsec {name}: no NAT\""
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tunnels_open_their_ports_and_ipsec_traffic_skips_nat() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        assert_eq!(vpn_rules(&s).await.unwrap(), VpnRules::default());
        let pool = s.pool().unwrap();
        sqlx::query(
            "INSERT INTO wg_interfaces (name, private_key, listen_port, updated_at)
             VALUES ('wg0','k',51820,0), ('wg1','k',51821,0)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE wg_interfaces SET enabled = 0 WHERE name = 'wg1'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ipsec_tunnels (name, remote_address, psk, local_ts, remote_ts, updated_at)
             VALUES ('siteb','198.51.100.2','x','192.168.50.0/24, fd00:50::/64','10.2.0.0/16,fd00:2::/64',0)",
        )
        .execute(pool)
        .await
        .unwrap();
        let r = vpn_rules(&s).await.unwrap();
        let f = r.filter.join("\n");
        assert!(
            f.contains("input udp dport 51820 accept comment \"WireGuard wg0\""),
            "{f}"
        );
        assert!(!f.contains("51821"), "a disabled tunnel opens nothing: {f}");
        assert!(f.contains("udp dport { 500, 4500 } accept"), "{f}");
        assert!(f.contains("meta l4proto esp accept"), "{f}");
        assert!(
            f.contains(
                "forward meta ipsec exists ip saddr 10.2.0.0/16 ip daddr 192.168.50.0/24 accept"
            ),
            "{f}"
        );
        assert!(
            f.contains(
                "input meta ipsec exists ip6 saddr fd00:2::/64 ip6 daddr fd00:50::/64 accept"
            ),
            "{f}"
        );
        assert!(!f.contains("ip saddr fd00"), "no mixed families: {f}");
        assert_eq!(r.nat_exempt.len(), 2, "{:?}", r.nat_exempt);
        assert!(r.nat_exempt[0]
            .contains("postrouting ip saddr 192.168.50.0/24 ip daddr 10.2.0.0/16 accept"));
        assert_eq!(net("10.0.0.1"), Some(("ip", "10.0.0.1/32".into())));
        assert_eq!(net("10.0.0.0/40"), None);
        assert_eq!(net("x;drop"), None);
    }
}
