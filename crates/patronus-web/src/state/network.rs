//! Network state (DHCP, DNS, routes). Lanes D/E replace the in-memory
//! fixtures below with store-backed adapters + appliers. Interfaces moved
//! to the store-backed `state/interfaces.rs` (lane C).

use std::sync::Arc;
use tokio::sync::RwLock;

/// Network management operations
pub struct NetworkManager {
    dhcp_pools: Arc<RwLock<Vec<crate::templates::DhcpPool>>>,
    dhcp_leases: Arc<RwLock<Vec<crate::templates::DhcpLease>>>,
    dns_records: Arc<RwLock<Vec<crate::templates::DnsRecord>>>,
    routes: Arc<RwLock<Vec<crate::templates::Route>>>,
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkManager {
    pub fn new() -> Self {
        let default_dhcp_pools = vec![crate::templates::DhcpPool {
            id: 1,
            interface: "eth1".to_string(),
            range_start: "10.0.0.100".to_string(),
            range_end: "10.0.0.200".to_string(),
            subnet: "10.0.0.0/24".to_string(),
            gateway: "10.0.0.1".to_string(),
            lease_time: 86400,
            enabled: true,
        }];

        let default_dhcp_leases = vec![
            crate::templates::DhcpLease {
                ip_address: "10.0.0.101".to_string(),
                mac_address: "aa:bb:cc:dd:ee:01".to_string(),
                hostname: Some("workstation-1".to_string()),
                lease_start: "2024-01-15 10:00:00".to_string(),
                lease_end: "2024-01-16 10:00:00".to_string(),
                is_active: true,
                hostname_display: "workstation-1".to_string(),
            },
            crate::templates::DhcpLease {
                ip_address: "10.0.0.102".to_string(),
                mac_address: "aa:bb:cc:dd:ee:02".to_string(),
                hostname: Some("laptop-user".to_string()),
                lease_start: "2024-01-15 11:30:00".to_string(),
                lease_end: "2024-01-16 11:30:00".to_string(),
                is_active: true,
                hostname_display: "laptop-user".to_string(),
            },
        ];

        let default_dns_records = vec![
            crate::templates::DnsRecord {
                id: 1,
                hostname: "gateway.local".to_string(),
                ip_address: "10.0.0.1".to_string(),
                record_type: "A".to_string(),
                value: "10.0.0.1".to_string(),
                ttl: 3600,
            },
            crate::templates::DnsRecord {
                id: 2,
                hostname: "vpn.local".to_string(),
                ip_address: "10.99.0.1".to_string(),
                record_type: "A".to_string(),
                value: "10.99.0.1".to_string(),
                ttl: 3600,
            },
        ];

        let default_routes = vec![
            crate::templates::Route {
                destination: "0.0.0.0/0".to_string(),
                gateway: "192.168.1.254".to_string(),
                interface: "eth0".to_string(),
                metric: 100,
                is_static: true,
                is_active: true,
            },
            crate::templates::Route {
                destination: "10.1.0.0/24".to_string(),
                gateway: "10.99.0.2".to_string(),
                interface: "wg0".to_string(),
                metric: 50,
                is_static: true,
                is_active: true,
            },
        ];

        Self {
            dhcp_pools: Arc::new(RwLock::new(default_dhcp_pools)),
            dhcp_leases: Arc::new(RwLock::new(default_dhcp_leases)),
            dns_records: Arc::new(RwLock::new(default_dns_records)),
            routes: Arc::new(RwLock::new(default_routes)),
        }
    }

    pub async fn list_dhcp_pools(&self) -> anyhow::Result<Vec<crate::templates::DhcpPool>> {
        let pools = self.dhcp_pools.read().await;
        Ok(pools.clone())
    }

    pub async fn list_dhcp_leases(&self) -> anyhow::Result<Vec<crate::templates::DhcpLease>> {
        let leases = self.dhcp_leases.read().await;
        Ok(leases.clone())
    }

    pub async fn list_dns_records(&self) -> anyhow::Result<Vec<crate::templates::DnsRecord>> {
        let records = self.dns_records.read().await;
        Ok(records.clone())
    }

    pub async fn list_routes(&self) -> anyhow::Result<Vec<crate::templates::Route>> {
        let routes = self.routes.read().await;
        Ok(routes.clone())
    }
}
