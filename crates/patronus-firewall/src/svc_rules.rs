//! Automatic firewall rules for the daemon-backed feature pages (IGMP proxy,
//! NAT64, L2TP, IDS in inline mode), rendered after the user's rules like the
//! VPN and HA rules. Everything is read from `lan_settings` / the feature
//! tables, and nothing is emitted for a feature that is switched off.
//!
//! - IGMP proxy: IGMP on the proxied interfaces (input) and multicast
//!   (224.0.0.0/4) upstream -> downstream (forward);
//! - NAT64: the clients' IPv6 traffic to the NAT64 prefix into `nat64`,
//!   translated IPv4 out of the WAN, and masquerade of the translation pool;
//! - L2TP: UDP 1701 on the listening interface;
//! - IDS inline mode: forwarded traffic of the watched interface goes through
//!   an NFQUEUE (own base chain ahead of the filter chain, `bypass` so the
//!   firewall keeps forwarding if the IDS is not running).

use crate::nftables::TABLE;
use crate::vpn_rules::VpnRules;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::collections::BTreeMap;

pub const NAT64_DEV: &str = "nat64";
pub const IDS_QUEUE: u16 = 3;

async fn settings(store: &ConfigStore, prefix: &str) -> Result<BTreeMap<String, String>> {
    let rows = sqlx::query("SELECT key, value FROM lan_settings WHERE key LIKE ?")
        .bind(format!("{prefix}.%"))
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read {prefix} settings: {e}")))?;
    Ok(rows
        .iter()
        .map(|r| {
            let k: String = r.get(0);
            (
                k.trim_start_matches(&format!("{prefix}.")).to_string(),
                r.get::<String, _>(1),
            )
        })
        .collect())
}

fn on(m: &BTreeMap<String, String>, k: &str) -> bool {
    m.get(k)
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

fn safe_dev(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 15
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

async fn devices(store: &ConfigStore, spec: &str) -> Vec<String> {
    let v = match spec.strip_prefix('@') {
        Some(role) => store.interfaces_with_role(role).await.unwrap_or_default(),
        None => vec![spec.to_string()],
    };
    v.into_iter().filter(|d| safe_dev(d)).collect()
}

fn safe_net(s: &str, v6: bool) -> Option<String> {
    let n: ipnetwork::IpNetwork = s.trim().parse().ok()?;
    match (n, v6) {
        (ipnetwork::IpNetwork::V4(_), false) | (ipnetwork::IpNetwork::V6(_), true) => {
            Some(format!("{}/{}", n.ip(), n.prefix()))
        }
        _ => None,
    }
}

pub async fn svc_rules(store: &ConfigStore) -> Result<VpnRules> {
    let mut out = VpnRules::default();
    let t = TABLE;

    // --- IGMP proxy
    let igmp = settings(store, "igmp").await?;
    if on(&igmp, "enabled") {
        let up = devices(
            store,
            igmp.get("upstream").map(String::as_str).unwrap_or("@wan"),
        )
        .await;
        let rows = sqlx::query("SELECT iface FROM igmp_interfaces WHERE enabled = 1")
            .fetch_all(store.pool()?)
            .await
            .map_err(|e| Error::Config(format!("read igmp_interfaces: {e}")))?;
        let mut down = Vec::new();
        for r in rows {
            for d in devices(store, &r.get::<String, _>(0)).await {
                if !up.contains(&d) && !down.contains(&d) {
                    down.push(d);
                }
            }
        }
        if let Some(u) = up.first() {
            for d in std::iter::once(u).chain(down.iter()) {
                out.filter.push(format!(
                    "add rule {t} input iifname \"{d}\" ip protocol igmp accept comment \"IGMP proxy\""
                ));
            }
            for d in &down {
                out.filter.push(format!(
                    "add rule {t} forward iifname \"{u}\" oifname \"{d}\" ip daddr 224.0.0.0/4 accept comment \"IGMP proxy multicast\""
                ));
            }
        }
    }

    // --- NAT64
    let n = settings(store, "nat64").await?;
    if on(&n, "enabled") {
        let prefix = n
            .get("prefix")
            .and_then(|p| safe_net(p, true))
            .unwrap_or_else(|| "64:ff9b::/96".into());
        let pool = n.get("pool").and_then(|p| safe_net(p, false));
        let clients = devices(
            store,
            n.get("clients").map(String::as_str).unwrap_or("@lan"),
        )
        .await;
        let wan = devices(store, "@wan").await;
        for c in &clients {
            out.filter.push(format!(
                "add rule {t} forward iifname \"{c}\" oifname \"{NAT64_DEV}\" ip6 daddr {prefix} accept comment \"NAT64 clients\""
            ));
        }
        for w in &wan {
            out.filter.push(format!(
                "add rule {t} forward iifname \"{NAT64_DEV}\" oifname \"{w}\" accept comment \"NAT64 translated\""
            ));
            if let Some(p) = &pool {
                out.nat_exempt.push(format!(
                    "add rule {t} postrouting ip saddr {p} oifname \"{w}\" masquerade comment \"NAT64 pool\""
                ));
            }
        }
        for c in &clients {
            out.filter.push(format!(
                "add rule {t} forward iifname \"{NAT64_DEV}\" oifname \"{c}\" ct state established,related accept comment \"NAT64 replies\""
            ));
        }
    }

    // --- UPnP / NAT-PMP (off by default): discovery + control on the LAN
    // side only; connections miniupnpd mapped (DNAT) may reach the LAN
    let u = settings(store, "upnp").await?;
    if on(&u, "enabled") {
        let lan_devs = devices(store, u.get("interface").map(String::as_str).unwrap_or("@lan")).await;
        let wan_devs = devices(store, u.get("ext_interface").map(String::as_str).unwrap_or("@wan")).await;
        for d in &lan_devs {
            out.filter.push(format!(
                "add rule {t} input iifname \"{d}\" udp dport {{ 1900, 5351 }} accept comment \"UPnP/NAT-PMP\""
            ));
            out.filter.push(format!(
                "add rule {t} input iifname \"{d}\" tcp dport 5000 accept comment \"UPnP control\""
            ));
            for w in &wan_devs {
                out.filter.push(format!(
                    "add rule {t} forward iifname \"{w}\" oifname \"{d}\" ct status dnat accept comment \"UPnP mapped ports\""
                ));
            }
        }
    }

    // --- OpenVPN server: the listen port, and the tunnel may reach the LAN
    let ov = settings(store, "openvpn").await?;
    if on(&ov, "enabled") {
        let proto = if ov.get("proto").map(String::as_str) == Some("tcp") { "tcp" } else { "udp" };
        let port: u16 = ov.get("port").and_then(|p| p.parse().ok()).unwrap_or(1194);
        for d in devices(store, ov.get("interface").map(String::as_str).unwrap_or("@wan")).await {
            out.filter.push(format!(
                "add rule {t} input iifname \"{d}\" {proto} dport {port} accept comment \"OpenVPN server\""
            ));
        }
        if ov.get("lan_route").is_some_and(|r| !r.is_empty()) {
            for d in devices(store, "@lan").await {
                out.filter.push(format!(
                    "add rule {t} forward iifname \"pat-ovpn\" oifname \"{d}\" accept comment \"OpenVPN clients to the LAN\""
                ));
            }
        }
    }

    // --- web proxy: the proxy ports on the LAN side; optional interception
    let px = settings(store, "proxy").await?;
    if on(&px, "enabled") {
        let port: u16 = px.get("port").and_then(|p| p.parse().ok()).unwrap_or(3128);
        let icpt = on(&px, "transparent");
        for d in devices(store, px.get("interface").map(String::as_str).unwrap_or("@lan")).await {
            out.filter.push(format!(
                "add rule {t} input iifname \"{d}\" tcp dport {port} accept comment \"web proxy\""
            ));
            if icpt {
                out.filter.push(format!(
                    "add rule {t} input iifname \"{d}\" tcp dport 3129 accept comment \"web proxy (intercepted HTTP)\""
                ));
                // the router's own web server must stay reachable: only
                // traffic to other hosts is redirected
                out.nat_pre.push(format!(
                    "add rule {t} prerouting iifname \"{d}\" fib daddr type != local tcp dport 80 redirect to :3129 comment \"web proxy intercept\""
                ));
            }
        }
    }

    // --- L2TP
    let l = settings(store, "l2tp").await?;
    if on(&l, "enabled") {
        for d in devices(
            store,
            l.get("interface").map(String::as_str).unwrap_or("@wan"),
        )
        .await
        {
            out.filter.push(format!(
                "add rule {t} input iifname \"{d}\" udp dport 1701 accept comment \"L2TP\""
            ));
        }
    }

    // --- dynamic routing (FRR): BGP sessions from the configured neighbours, OSPF on its interfaces
    let f = settings(store, "frr").await?;
    if on(&f, "bgp_enabled") {
        let rows = sqlx::query("SELECT address FROM frr_bgp_neighbors WHERE enabled = 1")
            .fetch_all(store.pool()?)
            .await
            .map_err(|e| Error::Config(format!("read frr_bgp_neighbors: {e}")))?;
        for r in rows {
            let a: String = r.get(0);
            match a.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => out.filter.push(format!(
                    "add rule {t} input ip saddr {v4} tcp dport 179 accept comment \"BGP neighbour\""
                )),
                Ok(std::net::IpAddr::V6(v6)) => out.filter.push(format!(
                    "add rule {t} input ip6 saddr {v6} tcp dport 179 accept comment \"BGP neighbour\""
                )),
                Err(_) => {}
            }
        }
    }
    if on(&f, "ospf_enabled") {
        let rows = sqlx::query("SELECT iface FROM frr_ospf_interfaces WHERE enabled = 1")
            .fetch_all(store.pool()?)
            .await
            .map_err(|e| Error::Config(format!("read frr_ospf_interfaces: {e}")))?;
        let mut done = Vec::new();
        for r in rows {
            for d in devices(store, &r.get::<String, _>(0)).await {
                if !done.contains(&d) {
                    out.filter.push(format!(
                        "add rule {t} input iifname \"{d}\" meta l4proto 89 accept comment \"OSPF\""
                    ));
                    done.push(d);
                }
            }
        }
    }

    // --- SD-WAN edge: the overlay tunnel may reach the LAN and answer pings
    // (the agent measures peers with ICMP over the tunnel); user rules come first
    let ed = settings(store, "edge").await?;
    if on(&ed, "enabled") {
        for c in devices(store, "@lan").await {
            out.filter.push(format!(
                "add rule {t} forward iifname \"sdwan0\" oifname \"{c}\" accept comment \"SD-WAN overlay to LAN\""
            ));
        }
        out.filter.push(format!(
            "add rule {t} input iifname \"sdwan0\" icmp type echo-request accept comment \"SD-WAN overlay ping\""
        ));
    }

    // --- IDS inline mode
    let i = settings(store, "ids").await?;
    if on(&i, "enabled") && i.get("mode").map(String::as_str) == Some("ips") {
        let devs = devices(
            store,
            i.get("interface").map(String::as_str).unwrap_or("@wan"),
        )
        .await;
        if !devs.is_empty() {
            out.filter.push(format!(
                "add chain {t} ids_ips {{ type filter hook forward priority -10 ; policy accept ; }}"
            ));
            for d in devs {
                out.filter.push(format!(
                    "add rule {t} ids_ips iifname \"{d}\" queue num {IDS_QUEUE} bypass comment \"IDS inline in\""
                ));
                out.filter.push(format!(
                    "add rule {t} ids_ips oifname \"{d}\" queue num {IDS_QUEUE} bypass comment \"IDS inline out\""
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn put(s: &ConfigStore, k: &str, v: &str) {
        sqlx::query(
            "INSERT OR REPLACE INTO lan_settings (key, value, updated_at) VALUES (?, ?, 0)",
        )
        .bind(k)
        .bind(v)
        .execute(s.pool().unwrap())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn nothing_for_features_that_are_off() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_interface_role("eth0", Some("wan")).await.unwrap();
        s.set_interface_role("eth1", Some("lan")).await.unwrap();
        assert_eq!(svc_rules(&s).await.unwrap(), VpnRules::default());
        put(&s, "igmp.enabled", "0").await;
        put(&s, "nat64.enabled", "0").await;
        assert_eq!(svc_rules(&s).await.unwrap(), VpnRules::default());
    }

    #[tokio::test]
    async fn each_enabled_feature_opens_exactly_what_it_needs() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_interface_role("eth0", Some("wan")).await.unwrap();
        s.set_interface_role("eth1", Some("lan")).await.unwrap();
        put(&s, "igmp.enabled", "1").await;
        sqlx::query(
            "INSERT INTO igmp_interfaces (iface, enabled, updated_at) VALUES ('@lan', 1, 0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        put(&s, "nat64.enabled", "1").await;
        put(&s, "nat64.pool", "192.168.255.0/24").await;
        put(&s, "l2tp.enabled", "1").await;
        put(&s, "ids.enabled", "1").await;
        put(&s, "ids.mode", "ips").await;
        put(&s, "edge.enabled", "1").await;
        put(&s, "frr.bgp_enabled", "1").await;
        put(&s, "frr.ospf_enabled", "1").await;
        sqlx::query("INSERT INTO frr_bgp_neighbors (address, remote_as, enabled, updated_at) VALUES ('203.0.113.1', 65000, 1, 0), ('2001:db8::1', 65000, 1, 0), ('not-an-ip', 1, 1, 0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO frr_ospf_interfaces (iface, enabled, updated_at) VALUES ('@lan', 1, 0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        let r = svc_rules(&s).await.unwrap();
        let f = r.filter.join("\n");
        assert!(
            f.contains("input iifname \"eth1\" ip protocol igmp accept"),
            "{f}"
        );
        assert!(
            f.contains("forward iifname \"eth0\" oifname \"eth1\" ip daddr 224.0.0.0/4 accept"),
            "{f}"
        );
        assert!(
            f.contains("forward iifname \"eth1\" oifname \"nat64\" ip6 daddr 64:ff9b::/96 accept"),
            "{f}"
        );
        assert!(
            f.contains("input iifname \"eth0\" udp dport 1701 accept"),
            "{f}"
        );
        assert!(
            f.contains("ids_ips iifname \"eth0\" queue num 3 bypass"),
            "{f}"
        );
        assert!(
            f.contains("input ip saddr 203.0.113.1 tcp dport 179 accept"),
            "{f}"
        );
        assert!(
            f.contains("input ip6 saddr 2001:db8::1 tcp dport 179 accept"),
            "{f}"
        );
        assert!(!f.contains("not-an-ip"), "{f}");
        assert!(
            f.contains("input iifname \"eth1\" meta l4proto 89 accept"),
            "{f}"
        );
        assert_eq!(r.nat_exempt.len(), 1);
        assert!(r.nat_exempt[0].contains("ip saddr 192.168.255.0/24 oifname \"eth0\" masquerade"));
    }

    #[test]
    fn only_clean_networks_and_devices_pass() {
        assert_eq!(safe_net("10.0.0.0/8", false).as_deref(), Some("10.0.0.0/8"));
        assert_eq!(safe_net("10.0.0.0/8", true), None);
        assert_eq!(safe_net("x; drop", false), None);
        assert!(!safe_dev("eth0\" accept #"));
    }
}
