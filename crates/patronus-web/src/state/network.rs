//! Network state (interfaces, DHCP, DNS, routes). Lanes C/D/E replace
//! the in-memory fixtures below with store-backed adapters + appliers.

use std::sync::Arc;
use tokio::sync::RwLock;

/// Network management operations
pub struct NetworkManager {
    interfaces: Arc<RwLock<Vec<crate::templates::InterfaceInfo>>>,
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
        let default_interfaces = vec![
            crate::templates::InterfaceInfo {
                name: "eth0".to_string(),
                state: "UP".to_string(),
                ip_address: Some("192.168.1.1".to_string()),
                ip_addresses: vec!["192.168.1.1/24".to_string()],
                mac_address: "00:11:22:33:44:55".to_string(),
                rx_bytes: 1_234_567_890,
                tx_bytes: 987_654_321,
                mtu: 1500,
                enabled: true,
                interface_type: "Ethernet".to_string(),
                ip_display: "192.168.1.1/24".to_string(),
                mac_display: "00:11:22:33:44:55".to_string(),
                speed_display: "1 Gbps".to_string(),
            },
            crate::templates::InterfaceInfo {
                name: "eth1".to_string(),
                state: "UP".to_string(),
                ip_address: Some("10.0.0.1".to_string()),
                ip_addresses: vec!["10.0.0.1/24".to_string()],
                mac_address: "00:11:22:33:44:56".to_string(),
                rx_bytes: 567_890_123,
                tx_bytes: 234_567_890,
                mtu: 1500,
                enabled: true,
                interface_type: "Ethernet".to_string(),
                ip_display: "10.0.0.1/24".to_string(),
                mac_display: "00:11:22:33:44:56".to_string(),
                speed_display: "1 Gbps".to_string(),
            },
            crate::templates::InterfaceInfo {
                name: "wg0".to_string(),
                state: "UP".to_string(),
                ip_address: Some("10.99.0.1".to_string()),
                ip_addresses: vec!["10.99.0.1/24".to_string()],
                mac_address: "N/A".to_string(),
                rx_bytes: 123_456_789,
                tx_bytes: 98_765_432,
                mtu: 1420,
                enabled: true,
                interface_type: "WireGuard".to_string(),
                ip_display: "10.99.0.1/24".to_string(),
                mac_display: "N/A".to_string(),
                speed_display: "Virtual".to_string(),
            },
        ];

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
            interfaces: Arc::new(RwLock::new(default_interfaces)),
            dhcp_pools: Arc::new(RwLock::new(default_dhcp_pools)),
            dhcp_leases: Arc::new(RwLock::new(default_dhcp_leases)),
            dns_records: Arc::new(RwLock::new(default_dns_records)),
            routes: Arc::new(RwLock::new(default_routes)),
        }
    }

    pub async fn list_interfaces(&self) -> anyhow::Result<Vec<crate::templates::InterfaceInfo>> {
        if let Ok(ifaces) = patronus_network::list_interfaces().await {
            let template_ifaces: Vec<crate::templates::InterfaceInfo> = ifaces
                .into_iter()
                .map(|iface| crate::templates::InterfaceInfo {
                    name: iface.name.clone(),
                    state: if iface.enabled {
                        "UP".to_string()
                    } else {
                        "DOWN".to_string()
                    },
                    ip_address: iface.ip_addresses.first().map(|ip| ip.to_string()),
                    ip_addresses: iface.ip_addresses.iter().map(|ip| ip.to_string()).collect(),
                    mac_address: iface
                        .mac_address
                        .clone()
                        .unwrap_or_else(|| "N/A".to_string()),
                    rx_bytes: 0,
                    tx_bytes: 0,
                    mtu: iface.mtu,
                    enabled: iface.enabled,
                    interface_type: "Ethernet".to_string(),
                    ip_display: iface
                        .ip_addresses
                        .first()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "N/A".to_string()),
                    mac_display: iface.mac_address.unwrap_or_else(|| "N/A".to_string()),
                    speed_display: "1 Gbps".to_string(),
                })
                .collect();
            if !template_ifaces.is_empty() {
                return Ok(template_ifaces);
            }
        }

        let interfaces = self.interfaces.read().await;
        Ok(interfaces.clone())
    }

    pub async fn update_interface(
        &self,
        name: String,
        interface: crate::routes::api::network::NetworkInterface,
    ) -> anyhow::Result<()> {
        let mut interfaces = self.interfaces.write().await;
        if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
            iface.state = interface.state.clone();
            iface.enabled = interface.state == "UP";
            if let Some(ip) = interface.ip_address {
                iface.ip_address = Some(ip.clone());
                iface.ip_display = ip;
            }
            iface.mtu = interface.mtu;
        }
        Ok(())
    }

    pub async fn bring_interface_up(&self, name: &str) -> anyhow::Result<()> {
        let mut interfaces = self.interfaces.write().await;
        if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
            iface.enabled = true;
            iface.state = "UP".to_string();
        }
        Ok(())
    }

    pub async fn bring_interface_down(&self, name: &str) -> anyhow::Result<()> {
        let mut interfaces = self.interfaces.write().await;
        if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
            iface.enabled = false;
            iface.state = "DOWN".to_string();
        }
        Ok(())
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
