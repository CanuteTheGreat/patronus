//! Automatic firewall rules for high availability (lane G, `ha_vips` +
//! the `ha.*` keys of `lan_settings`), rendered after the user's rules:
//!
//! - input: VRRP (IP protocol 112, IPv4 multicast 224.0.0.18 or unicast
//!   from the peer, and IPv6) on the interfaces that carry a virtual IP;
//! - input: connection-state sync (conntrackd, UDP 3780) from the sync
//!   peer on the sync interface only;
//! - input: the DHCP failover channel (Kea HA lease updates and heartbeats,
//!   TCP, default 8000 for DHCPv4 and 8001 for DHCPv6) from the peer only,
//!   on the sync interface (or the virtual IP interfaces without a sync
//!   network).

use crate::nftables::TABLE;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use sqlx::Row;
use std::collections::BTreeSet;
use std::net::IpAddr;

pub const SYNC_PORT: u16 = 3780;

async fn setting(store: &ConfigStore, key: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT value FROM lan_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read HA settings: {e}")))?;
    Ok(row
        .map(|r| r.get::<String, _>(0))
        .filter(|v| !v.trim().is_empty()))
}

async fn devices(store: &ConfigStore, spec: &str) -> Vec<String> {
    match spec.strip_prefix('@') {
        Some(role) => store.interfaces_with_role(role).await.unwrap_or_default(),
        None => vec![spec.to_string()],
    }
}

fn safe_dev(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 15
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// `add rule ...` lines for the input chain.
pub async fn ha_rules(store: &ConfigStore) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if !setting(store, "ha.enabled")
        .await?
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
    {
        return Ok(out);
    }
    let vips = sqlx::query("SELECT interface FROM ha_vips WHERE enabled = 1 AND mode = 'carp'")
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read ha_vips: {e}")))?;
    let mut devs = BTreeSet::new();
    for r in vips {
        devs.extend(devices(store, &r.get::<String, _>(0)).await);
    }
    if devs.is_empty() {
        return Ok(out);
    }
    for d in devs.iter().filter(|d| safe_dev(d)) {
        out.push(format!(
            "add rule {TABLE} input iifname \"{d}\" meta l4proto 112 accept comment \"HA VRRP\""
        ));
    }
    let sync = setting(store, "ha.sync")
        .await?
        .is_some_and(|v| v.trim() == "1");
    if let (true, Some(spec), Some(peer)) = (
        sync,
        setting(store, "ha.sync_interface").await?,
        setting(store, "ha.sync_peer").await?,
    ) {
        if let Ok(IpAddr::V4(p)) = peer.trim().parse::<IpAddr>() {
            for d in devices(store, &spec).await.iter().filter(|d| safe_dev(d)) {
                out.push(format!(
                    "add rule {TABLE} input iifname \"{d}\" ip saddr {p} udp dport {SYNC_PORT} accept comment \"HA state sync\""
                ));
            }
        }
    }
    // DHCP failover channel (the same defaults and key names as
    // patronus_network::ha::Settings)
    let dhcp_on = setting(store, "ha.dhcp_failover")
        .await?
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(true);
    let dhcp_peer = setting(store, "ha.dhcp_peer").await?;
    let sync_peer = setting(store, "ha.sync_peer").await?;
    let vrrp_peer = setting(store, "ha.peer").await?;
    let from_sync = dhcp_peer.is_none() && sync_peer.is_some();
    let peer = dhcp_peer.or(sync_peer).or(vrrp_peer);
    if let (true, Some(peer)) = (dhcp_on, peer) {
        let mut ports = Vec::new();
        for (key, default) in [("ha.dhcp_port4", 8000u16), ("ha.dhcp_port6", 8001u16)] {
            let p = setting(store, key)
                .await?
                .and_then(|v| v.trim().parse::<u16>().ok())
                .filter(|p| *p >= 1024)
                .unwrap_or(default);
            if !ports.contains(&p) {
                ports.push(p);
            }
        }
        let list = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let on_devs: BTreeSet<String> =
            match (from_sync, setting(store, "ha.sync_interface").await?) {
                (true, Some(spec)) => devices(store, &spec).await.into_iter().collect(),
                _ => devs.clone(),
            };
        if let Ok(ip) = peer.trim().parse::<IpAddr>() {
            let fam = if ip.is_ipv6() { "ip6" } else { "ip" };
            for d in on_devs.iter().filter(|d| safe_dev(d)) {
                out.push(format!(
                    "add rule {TABLE} input iifname \"{d}\" {fam} saddr {ip} tcp dport {{ {list} }} accept comment \"HA DHCP failover\""
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
        sqlx::query("INSERT INTO lan_settings (key, value, updated_at) VALUES (?, ?, 0)")
            .bind(k)
            .bind(v)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn vrrp_and_sync_are_opened_only_where_they_are_needed() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_interface_role("eth1", Some("lan")).await.unwrap();
        assert!(ha_rules(&s).await.unwrap().is_empty(), "HA off: nothing");
        sqlx::query("INSERT INTO ha_vips (name, interface, address, updated_at) VALUES ('gw','@lan','192.168.50.254/24',0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert!(ha_rules(&s).await.unwrap().is_empty(), "no switch: nothing");
        put(&s, "ha.enabled", "1").await;
        let r = ha_rules(&s).await.unwrap();
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].contains("iifname \"eth1\" meta l4proto 112 accept"),
            "{r:?}"
        );
        put(&s, "ha.sync", "1").await;
        put(&s, "ha.sync_interface", "eth2").await;
        put(&s, "ha.sync_peer", "10.9.9.2").await;
        let r = ha_rules(&s).await.unwrap();
        assert!(
            r.iter()
                .any(|l| l.contains("iifname \"eth2\" ip saddr 10.9.9.2 udp dport 3780 accept")),
            "{r:?}"
        );
        // DHCP failover: the peer's address on the sync interface, the two Kea HA ports
        put(&s, "ha.dhcp_port4", "8100").await;
        let r = ha_rules(&s).await.unwrap();
        assert!(
            r.iter().any(|l| l.contains(
                "iifname \"eth2\" ip saddr 10.9.9.2 tcp dport { 8100, 8001 } accept comment \"HA DHCP failover\""
            )),
            "{r:?}"
        );
        put(&s, "ha.dhcp_failover", "0").await;
        assert!(!ha_rules(&s)
            .await
            .unwrap()
            .iter()
            .any(|l| l.contains("HA DHCP failover")));
        // a hostile device name never reaches nft
        sqlx::query(
            "UPDATE lan_settings SET value='eth2\" accept #' WHERE key='ha.sync_interface'",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        assert!(!ha_rules(&s)
            .await
            .unwrap()
            .iter()
            .any(|l| l.contains("accept #")));
    }
}
