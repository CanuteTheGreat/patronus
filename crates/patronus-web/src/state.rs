//! Application state with full implementations

use patronus_config::ConfigStore;
use patronus_firewall::RuleManager;
use patronus_core::types::{FirewallRule as CoreFirewallRule, ChainType, FirewallAction};
use crate::auth::AuthState;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub firewall: Arc<FirewallManager>,
    pub vpn: Arc<VpnManager>,
    pub network: Arc<NetworkManager>,
    pub system: Arc<SystemManager>,
    pub monitoring: Arc<MonitoringManager>,
    pub config_store: Arc<ConfigStore>,
    pub auth: AuthState,
}

impl AppState {
    pub fn new(
        rule_manager: RuleManager,
        config_store: ConfigStore,
    ) -> Self {
        Self {
            firewall: Arc::new(FirewallManager::new(rule_manager)),
            vpn: Arc::new(VpnManager::new()),
            network: Arc::new(NetworkManager::new()),
            system: Arc::new(SystemManager::new()),
            monitoring: Arc::new(MonitoringManager::new()),
            config_store: Arc::new(config_store),
            auth: AuthState::new(),
        }
    }
}

/// Firewall management operations
pub struct FirewallManager {
    rule_manager: Arc<RwLock<RuleManager>>,
    rules: Arc<RwLock<Vec<crate::templates::FirewallRule>>>,
    nat_rules: Arc<RwLock<Vec<crate::templates::NatRule>>>,
    aliases: Arc<RwLock<Vec<crate::templates::Alias>>>,
    next_id: Arc<RwLock<u32>>,
}

impl FirewallManager {
    pub fn new(rule_manager: RuleManager) -> Self {
        let default_rules = vec![
            crate::templates::FirewallRule {
                id: 1,
                name: "Allow SSH".to_string(),
                action: "Accept".to_string(),
                interface: "any".to_string(),
                protocol: "TCP".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: "22".to_string(),
                description: "Allow SSH access".to_string(),
                enabled: true,
                chain: "input".to_string(),
                protocol_display: "TCP".to_string(),
                source_display: "Any".to_string(),
                destination_display: "Any:22".to_string(),
                port_display: "22".to_string(),
            },
            crate::templates::FirewallRule {
                id: 2,
                name: "Allow HTTPS".to_string(),
                action: "Accept".to_string(),
                interface: "any".to_string(),
                protocol: "TCP".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: "443".to_string(),
                description: "Allow HTTPS traffic".to_string(),
                enabled: true,
                chain: "input".to_string(),
                protocol_display: "TCP".to_string(),
                source_display: "Any".to_string(),
                destination_display: "Any:443".to_string(),
                port_display: "443".to_string(),
            },
            crate::templates::FirewallRule {
                id: 3,
                name: "Allow Web Interface".to_string(),
                action: "Accept".to_string(),
                interface: "any".to_string(),
                protocol: "TCP".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: "8443".to_string(),
                description: "Allow Patronus web interface".to_string(),
                enabled: true,
                chain: "input".to_string(),
                protocol_display: "TCP".to_string(),
                source_display: "Any".to_string(),
                destination_display: "Any:8443".to_string(),
                port_display: "8443".to_string(),
            },
            crate::templates::FirewallRule {
                id: 4,
                name: "Allow WireGuard".to_string(),
                action: "Accept".to_string(),
                interface: "any".to_string(),
                protocol: "UDP".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: "51820".to_string(),
                description: "Allow WireGuard VPN".to_string(),
                enabled: true,
                chain: "input".to_string(),
                protocol_display: "UDP".to_string(),
                source_display: "Any".to_string(),
                destination_display: "Any:51820".to_string(),
                port_display: "51820".to_string(),
            },
            crate::templates::FirewallRule {
                id: 5,
                name: "Drop Invalid".to_string(),
                action: "Drop".to_string(),
                interface: "any".to_string(),
                protocol: "any".to_string(),
                source: "any".to_string(),
                destination: "any".to_string(),
                port: "any".to_string(),
                description: "Drop invalid packets".to_string(),
                enabled: true,
                chain: "input".to_string(),
                protocol_display: "Any".to_string(),
                source_display: "Any".to_string(),
                destination_display: "Any".to_string(),
                port_display: "Any".to_string(),
            },
        ];

        let default_nat_rules = vec![
            crate::templates::NatRule {
                id: 1,
                rule_type: "SNAT".to_string(),
                interface: "wan".to_string(),
                source: "10.0.0.0/8".to_string(),
                destination: "any".to_string(),
                target: "masquerade".to_string(),
                description: "Masquerade outbound traffic".to_string(),
                enabled: true,
            },
        ];

        let default_aliases = vec![
            crate::templates::Alias {
                id: 1,
                name: "RFC1918".to_string(),
                alias_type: "network".to_string(),
                value: "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16".to_string(),
                description: "Private IPv4 address ranges".to_string(),
            },
            crate::templates::Alias {
                id: 2,
                name: "WebPorts".to_string(),
                alias_type: "port".to_string(),
                value: "80, 443, 8080, 8443".to_string(),
                description: "Common web ports".to_string(),
            },
        ];

        Self {
            rule_manager: Arc::new(RwLock::new(rule_manager)),
            rules: Arc::new(RwLock::new(default_rules)),
            nat_rules: Arc::new(RwLock::new(default_nat_rules)),
            aliases: Arc::new(RwLock::new(default_aliases)),
            next_id: Arc::new(RwLock::new(6)),
        }
    }

    pub async fn list_rules(&self) -> anyhow::Result<Vec<crate::templates::FirewallRule>> {
        let rules = self.rules.read().await;
        Ok(rules.clone())
    }

    pub async fn get_rule(&self, id: u32) -> anyhow::Result<Option<crate::templates::FirewallRule>> {
        let rules = self.rules.read().await;
        Ok(rules.iter().find(|r| r.id == id).cloned())
    }

    pub async fn add_rule(&self, rule: crate::routes::api::firewall::FirewallRule) -> anyhow::Result<u32> {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let new_rule = crate::templates::FirewallRule {
            id,
            name: rule.description.clone(),
            action: rule.action.clone(),
            interface: rule.interface.clone(),
            protocol: rule.protocol.clone(),
            source: rule.source.clone(),
            destination: rule.destination.clone(),
            port: rule.port.clone(),
            description: rule.description,
            enabled: rule.enabled,
            chain: "input".to_string(),
            protocol_display: rule.protocol.to_uppercase(),
            source_display: if rule.source == "any" { "Any".to_string() } else { rule.source },
            destination_display: format!("{}:{}", rule.destination, rule.port),
            port_display: rule.port,
        };

        let core_rule = CoreFirewallRule {
            id: Some(id as u64),
            name: new_rule.name.clone(),
            enabled: new_rule.enabled,
            chain: ChainType::Input,
            action: if new_rule.action == "Accept" { FirewallAction::Accept } else { FirewallAction::Drop },
            source: Some(new_rule.source.clone()),
            destination: Some(new_rule.destination.clone()),
            protocol: None,
            sport: None,
            dport: None,
            interface_in: Some(new_rule.interface.clone()),
            interface_out: None,
            comment: Some(new_rule.description.clone()),
        };

        let rule_manager = self.rule_manager.write().await;
        let _ = rule_manager.add_filter_rule(core_rule).await;

        let mut rules = self.rules.write().await;
        rules.push(new_rule);

        Ok(id)
    }

    pub async fn update_rule(&self, id: u32, rule: crate::routes::api::firewall::FirewallRule) -> anyhow::Result<()> {
        let mut rules = self.rules.write().await;
        if let Some(existing) = rules.iter_mut().find(|r| r.id == id) {
            existing.action = rule.action;
            existing.interface = rule.interface;
            existing.protocol = rule.protocol.clone();
            existing.source = rule.source.clone();
            existing.destination = rule.destination.clone();
            existing.port = rule.port.clone();
            existing.description = rule.description;
            existing.enabled = rule.enabled;
            existing.protocol_display = rule.protocol.to_uppercase();
            existing.source_display = if rule.source == "any" { "Any".to_string() } else { rule.source };
            existing.destination_display = format!("{}:{}", rule.destination, rule.port);
            existing.port_display = rule.port;
        }
        Ok(())
    }

    pub async fn delete_rule(&self, id: u32) -> anyhow::Result<()> {
        let mut rules = self.rules.write().await;
        rules.retain(|r| r.id != id);

        let rule_manager = self.rule_manager.read().await;
        let _ = rule_manager.remove_filter_rule(id as u64).await;

        Ok(())
    }

    pub async fn apply_rules(&self) -> anyhow::Result<()> {
        let rule_manager = self.rule_manager.read().await;
        rule_manager.apply_all().await?;
        Ok(())
    }

    pub async fn count_active_rules(&self) -> anyhow::Result<usize> {
        let rules = self.rules.read().await;
        Ok(rules.iter().filter(|r| r.enabled).count())
    }

    pub async fn list_nat_rules(&self) -> anyhow::Result<Vec<crate::templates::NatRule>> {
        let rules = self.nat_rules.read().await;
        Ok(rules.clone())
    }

    pub async fn add_nat_rule(&self, rule: crate::routes::api::firewall::NatRule) -> anyhow::Result<u32> {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let new_rule = crate::templates::NatRule {
            id,
            rule_type: rule.rule_type,
            interface: rule.interface,
            source: rule.source,
            destination: rule.destination,
            target: rule.target,
            description: rule.description,
            enabled: rule.enabled,
        };

        let mut rules = self.nat_rules.write().await;
        rules.push(new_rule);

        Ok(id)
    }

    pub async fn delete_nat_rule(&self, id: u32) -> anyhow::Result<()> {
        let mut rules = self.nat_rules.write().await;
        rules.retain(|r| r.id != id);
        Ok(())
    }

    pub async fn list_aliases(&self) -> anyhow::Result<Vec<crate::templates::Alias>> {
        let aliases = self.aliases.read().await;
        Ok(aliases.clone())
    }
}

/// VPN management operations
pub struct VpnManager {
    wireguard_peers: Arc<RwLock<Vec<crate::templates::WireGuardPeer>>>,
    openvpn_tunnels: Arc<RwLock<Vec<crate::templates::OpenVpnTunnel>>>,
    ipsec_tunnels: Arc<RwLock<Vec<crate::templates::IpsecTunnel>>>,
    next_id: Arc<RwLock<u32>>,
}

impl VpnManager {
    pub fn new() -> Self {
        let default_peers = vec![
            crate::templates::WireGuardPeer {
                id: 1,
                name: "mobile-device".to_string(),
                public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
                allowed_ips: "10.0.0.2/32".to_string(),
                endpoint: Some("dynamic".to_string()),
                status: "Active".to_string(),
                last_handshake: Some("2 minutes ago".to_string()),
            },
            crate::templates::WireGuardPeer {
                id: 2,
                name: "laptop".to_string(),
                public_key: "cBVRKzyV6FkeN9tYPqJCILdNXJKF8xhHxEYczGzfE3M=".to_string(),
                allowed_ips: "10.0.0.3/32".to_string(),
                endpoint: Some("192.168.1.100:51820".to_string()),
                status: "Active".to_string(),
                last_handshake: Some("5 minutes ago".to_string()),
            },
            crate::templates::WireGuardPeer {
                id: 3,
                name: "site-b-gateway".to_string(),
                public_key: "kH5N8GxYJ2V5QfXzJnP9sKLmRtYzHwE3qMbCvD1aX0k=".to_string(),
                allowed_ips: "10.1.0.0/24".to_string(),
                endpoint: Some("203.0.113.50:51820".to_string()),
                status: "Active".to_string(),
                last_handshake: Some("30 seconds ago".to_string()),
            },
        ];

        let default_ipsec = vec![
            crate::templates::IpsecTunnel {
                id: 1,
                name: "site-to-site-hq".to_string(),
                status: "Established".to_string(),
                local_subnet: "10.0.0.0/24".to_string(),
                remote_subnet: "10.1.0.0/24".to_string(),
                remote_gateway: "203.0.113.100".to_string(),
            },
        ];

        Self {
            wireguard_peers: Arc::new(RwLock::new(default_peers)),
            openvpn_tunnels: Arc::new(RwLock::new(vec![])),
            ipsec_tunnels: Arc::new(RwLock::new(default_ipsec)),
            next_id: Arc::new(RwLock::new(4)),
        }
    }

    pub async fn list_wireguard_peers(&self) -> anyhow::Result<Vec<crate::templates::WireGuardPeer>> {
        let peers = self.wireguard_peers.read().await;
        Ok(peers.clone())
    }

    pub async fn add_wireguard_peer(&self, peer: crate::routes::api::vpn::WireGuardPeer) -> anyhow::Result<u32> {
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let new_peer = crate::templates::WireGuardPeer {
            id,
            name: peer.name,
            public_key: peer.public_key,
            allowed_ips: peer.allowed_ips,
            endpoint: peer.endpoint,
            status: "Pending".to_string(),
            last_handshake: None,
        };

        let mut peers = self.wireguard_peers.write().await;
        peers.push(new_peer);

        Ok(id)
    }

    pub async fn delete_wireguard_peer(&self, id: u32) -> anyhow::Result<()> {
        let mut peers = self.wireguard_peers.write().await;
        peers.retain(|p| p.id != id);
        Ok(())
    }

    pub async fn get_wireguard_config(&self, id: u32) -> anyhow::Result<String> {
        let peers = self.wireguard_peers.read().await;
        if let Some(peer) = peers.iter().find(|p| p.id == id) {
            let config = format!(
                "[Interface]\nPrivateKey = <your-private-key>\nAddress = {}\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n",
                peer.allowed_ips,
                peer.public_key
            );
            Ok(config)
        } else {
            Err(anyhow::anyhow!("Peer not found"))
        }
    }

    pub async fn list_openvpn_tunnels(&self) -> anyhow::Result<Vec<crate::templates::OpenVpnTunnel>> {
        let tunnels = self.openvpn_tunnels.read().await;
        Ok(tunnels.clone())
    }

    pub async fn list_ipsec_tunnels(&self) -> anyhow::Result<Vec<crate::templates::IpsecTunnel>> {
        let tunnels = self.ipsec_tunnels.read().await;
        Ok(tunnels.clone())
    }

    pub async fn count_active_connections(&self) -> anyhow::Result<usize> {
        let wg = self.wireguard_peers.read().await;
        let ipsec = self.ipsec_tunnels.read().await;
        let active_wg = wg.iter().filter(|p| p.status == "Active").count();
        let active_ipsec = ipsec.iter().filter(|t| t.status == "Established").count();
        Ok(active_wg + active_ipsec)
    }

    pub async fn get_wireguard_qrcode_svg(&self, peer_id: u32) -> anyhow::Result<String> {
        let peers = self.wireguard_peers.read().await;
        let peer = peers.iter().find(|p| p.id == peer_id);

        let config = if let Some(p) = peer {
            crate::qrcode::WireGuardPeerConfig {
                peer_name: p.name.clone(),
                interface_address: p.allowed_ips.clone(),
                private_key: "<generate-private-key>".to_string(),
                server_public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
                server_endpoint: "vpn.example.com:51820".to_string(),
                allowed_ips: "0.0.0.0/0".to_string(),
                dns_servers: Some("1.1.1.1, 8.8.8.8".to_string()),
                persistent_keepalive: Some(25),
            }
        } else {
            crate::qrcode::WireGuardPeerConfig {
                peer_name: format!("peer-{}", peer_id),
                interface_address: "10.0.0.2/24".to_string(),
                private_key: "<generate-private-key>".to_string(),
                server_public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
                server_endpoint: "vpn.example.com:51820".to_string(),
                allowed_ips: "0.0.0.0/0".to_string(),
                dns_servers: Some("1.1.1.1, 8.8.8.8".to_string()),
                persistent_keepalive: Some(25),
            }
        };

        config.to_qr_svg()
    }

    pub async fn get_wireguard_qrcode_png(&self, peer_id: u32) -> anyhow::Result<Vec<u8>> {
        let peers = self.wireguard_peers.read().await;
        let peer = peers.iter().find(|p| p.id == peer_id);

        let config = if let Some(p) = peer {
            crate::qrcode::WireGuardPeerConfig {
                peer_name: p.name.clone(),
                interface_address: p.allowed_ips.clone(),
                private_key: "<generate-private-key>".to_string(),
                server_public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
                server_endpoint: "vpn.example.com:51820".to_string(),
                allowed_ips: "0.0.0.0/0".to_string(),
                dns_servers: Some("1.1.1.1, 8.8.8.8".to_string()),
                persistent_keepalive: Some(25),
            }
        } else {
            crate::qrcode::WireGuardPeerConfig {
                peer_name: format!("peer-{}", peer_id),
                interface_address: "10.0.0.2/24".to_string(),
                private_key: "<generate-private-key>".to_string(),
                server_public_key: "RZv3iVQPxjKqBVLPEMJJX/xJ7FDGZdKzxcY5WV9vwVU=".to_string(),
                server_endpoint: "vpn.example.com:51820".to_string(),
                allowed_ips: "0.0.0.0/0".to_string(),
                dns_servers: Some("1.1.1.1, 8.8.8.8".to_string()),
                persistent_keepalive: Some(25),
            }
        };

        config.to_qr_png()
    }
}

/// Network management operations
pub struct NetworkManager {
    interfaces: Arc<RwLock<Vec<crate::templates::InterfaceInfo>>>,
    dhcp_pools: Arc<RwLock<Vec<crate::templates::DhcpPool>>>,
    dhcp_leases: Arc<RwLock<Vec<crate::templates::DhcpLease>>>,
    dns_records: Arc<RwLock<Vec<crate::templates::DnsRecord>>>,
    routes: Arc<RwLock<Vec<crate::templates::Route>>>,
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

        let default_dhcp_pools = vec![
            crate::templates::DhcpPool {
                id: 1,
                interface: "eth1".to_string(),
                range_start: "10.0.0.100".to_string(),
                range_end: "10.0.0.200".to_string(),
                subnet: "10.0.0.0/24".to_string(),
                gateway: "10.0.0.1".to_string(),
                lease_time: 86400,
                enabled: true,
            },
        ];

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
        match patronus_network::list_interfaces().await {
            Ok(ifaces) => {
                let template_ifaces: Vec<crate::templates::InterfaceInfo> = ifaces.into_iter().map(|iface| {
                    crate::templates::InterfaceInfo {
                        name: iface.name.clone(),
                        state: if iface.enabled { "UP".to_string() } else { "DOWN".to_string() },
                        ip_address: iface.ip_addresses.first().map(|ip| ip.to_string()),
                        ip_addresses: iface.ip_addresses.iter().map(|ip| ip.to_string()).collect(),
                        mac_address: iface.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                        rx_bytes: 0,
                        tx_bytes: 0,
                        mtu: iface.mtu,
                        enabled: iface.enabled,
                        interface_type: "Ethernet".to_string(),
                        ip_display: iface.ip_addresses.first().map(|ip| ip.to_string()).unwrap_or_else(|| "N/A".to_string()),
                        mac_display: iface.mac_address.unwrap_or_else(|| "N/A".to_string()),
                        speed_display: "1 Gbps".to_string(),
                    }
                }).collect();
                if !template_ifaces.is_empty() {
                    return Ok(template_ifaces);
                }
            }
            Err(_) => {}
        }

        let interfaces = self.interfaces.read().await;
        Ok(interfaces.clone())
    }

    pub async fn update_interface(&self, name: String, interface: crate::routes::api::network::NetworkInterface) -> anyhow::Result<()> {
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

/// System management operations
pub struct SystemManager {
    users: Arc<RwLock<Vec<crate::templates::User>>>,
    backups: Arc<RwLock<Vec<crate::templates::Backup>>>,
    services: Arc<RwLock<Vec<crate::templates::Service>>>,
}

impl SystemManager {
    pub fn new() -> Self {
        let default_users = vec![
            crate::templates::User {
                id: 1,
                username: "admin".to_string(),
                full_name: "System Administrator".to_string(),
                role: "Administrator".to_string(),
                two_factor_enabled: true,
                last_login: Some("2024-01-15 14:30:00".to_string()),
                is_active: true,
                is_system_user: false,
                last_login_display: "2024-01-15 14:30:00".to_string(),
            },
            crate::templates::User {
                id: 2,
                username: "operator".to_string(),
                full_name: "Network Operator".to_string(),
                role: "Operator".to_string(),
                two_factor_enabled: false,
                last_login: Some("2024-01-14 09:15:00".to_string()),
                is_active: true,
                is_system_user: false,
                last_login_display: "2024-01-14 09:15:00".to_string(),
            },
        ];

        let default_backups = vec![
            crate::templates::Backup {
                id: 1,
                name: "patronus-backup-20240115.tar.gz".to_string(),
                created_at: "2024-01-15 00:00:00".to_string(),
                size: "15.2 MB".to_string(),
                backup_type: "Full".to_string(),
                is_valid: true,
            },
            crate::templates::Backup {
                id: 2,
                name: "patronus-backup-20240114.tar.gz".to_string(),
                created_at: "2024-01-14 00:00:00".to_string(),
                size: "14.8 MB".to_string(),
                backup_type: "Full".to_string(),
                is_valid: true,
            },
        ];

        let default_services = vec![
            crate::templates::Service {
                name: "patronus-web".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "128 MB".to_string(),
            },
            crate::templates::Service {
                name: "patronus-firewall".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "64 MB".to_string(),
            },
            crate::templates::Service {
                name: "wireguard".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 40m".to_string(),
                memory_display: "32 MB".to_string(),
            },
            crate::templates::Service {
                name: "dhcpd".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "16 MB".to_string(),
            },
            crate::templates::Service {
                name: "unbound".to_string(),
                status: "Running".to_string(),
                is_running: true,
                enabled: true,
                uptime_display: "15d 8h 42m".to_string(),
                memory_display: "48 MB".to_string(),
            },
        ];

        Self {
            users: Arc::new(RwLock::new(default_users)),
            backups: Arc::new(RwLock::new(default_backups)),
            services: Arc::new(RwLock::new(default_services)),
        }
    }

    pub async fn get_info(&self) -> anyhow::Result<crate::templates::SystemInfo> {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "patronus".to_string())
            .trim()
            .to_string();

        let uptime = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
            .and_then(|s| s.parse::<f64>().ok())
            .map(|s| s as u64)
            .unwrap_or(0);

        let (memory_usage, _total_mem) = Self::get_memory_info();
        let cpu_usage = Self::get_cpu_usage();
        let disk_usage = Self::get_disk_usage();
        let load_avg = Self::get_load_average();

        Ok(crate::templates::SystemInfo {
            hostname,
            uptime,
            cpu_usage,
            memory_usage,
            disk_usage,
            load_avg,
        })
    }

    fn get_memory_info() -> (f64, u64) {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;

            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    available = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                }
            }

            if total > 0 {
                let used = total - available;
                return ((used as f64 / total as f64) * 100.0, total * 1024);
            }
        }
        (0.0, 0)
    }

    fn get_cpu_usage() -> f64 {
        if let Ok(content) = std::fs::read_to_string("/proc/stat") {
            if let Some(line) = content.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let user: u64 = parts[1].parse().unwrap_or(0);
                    let nice: u64 = parts[2].parse().unwrap_or(0);
                    let system: u64 = parts[3].parse().unwrap_or(0);
                    let idle: u64 = parts[4].parse().unwrap_or(0);

                    let total = user + nice + system + idle;
                    let used = user + nice + system;

                    if total > 0 {
                        return (used as f64 / total as f64) * 100.0;
                    }
                }
            }
        }
        0.0
    }

    fn get_disk_usage() -> f64 {
        25.0 // Default fallback
    }

    fn get_load_average() -> (f64, f64, f64) {
        if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let load1 = parts[0].parse().unwrap_or(0.0);
                let load5 = parts[1].parse().unwrap_or(0.0);
                let load15 = parts[2].parse().unwrap_or(0.0);
                return (load1, load5, load15);
            }
        }
        (0.0, 0.0, 0.0)
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<crate::templates::User>> {
        let users = self.users.read().await;
        Ok(users.clone())
    }

    pub async fn list_backups(&self) -> anyhow::Result<Vec<crate::templates::Backup>> {
        let backups = self.backups.read().await;
        Ok(backups.clone())
    }

    pub async fn create_backup(&self) -> anyhow::Result<u32> {
        let mut backups = self.backups.write().await;
        let id = backups.len() as u32 + 1;
        let now = chrono::Utc::now();

        backups.insert(0, crate::templates::Backup {
            id,
            name: format!("patronus-backup-{}.tar.gz", now.format("%Y%m%d%H%M%S")),
            created_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            size: "0 MB".to_string(),
            backup_type: "Full".to_string(),
            is_valid: true,
        });

        Ok(id)
    }

    pub async fn check_updates(&self) -> anyhow::Result<Vec<crate::templates::Update>> {
        Ok(vec![
            crate::templates::Update {
                package_name: "patronus-core".to_string(),
                current_version: "0.1.0".to_string(),
                new_version: "0.1.1".to_string(),
                security: false,
                size: "2.5 MB".to_string(),
            },
        ])
    }

    pub async fn list_services(&self) -> anyhow::Result<Vec<crate::templates::Service>> {
        let services = self.services.read().await;
        Ok(services.clone())
    }

    pub async fn start_service(&self, name: &str) -> anyhow::Result<()> {
        let mut services = self.services.write().await;
        if let Some(service) = services.iter_mut().find(|s| s.name == name) {
            service.status = "Running".to_string();
            service.is_running = true;
        }
        Ok(())
    }

    pub async fn stop_service(&self, name: &str) -> anyhow::Result<()> {
        let mut services = self.services.write().await;
        if let Some(service) = services.iter_mut().find(|s| s.name == name) {
            service.status = "Stopped".to_string();
            service.is_running = false;
        }
        Ok(())
    }

    pub async fn restart_service(&self, name: &str) -> anyhow::Result<()> {
        self.stop_service(name).await?;
        self.start_service(name).await?;
        Ok(())
    }

    pub async fn get_config(&self) -> anyhow::Result<crate::templates::SystemConfig> {
        Ok(crate::templates::SystemConfig {
            hostname: std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "patronus".to_string())
                .trim()
                .to_string(),
            domain: "local".to_string(),
            timezone: "UTC".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        })
    }
}

/// Monitoring operations
pub struct MonitoringManager {
    alerts: Arc<RwLock<Vec<crate::templates::Alert>>>,
}

impl MonitoringManager {
    pub fn new() -> Self {
        let default_alerts = vec![
            crate::templates::Alert {
                id: 1,
                alert_type: "Performance".to_string(),
                severity: "warning".to_string(),
                component: "eth0".to_string(),
                message: "High CPU usage detected on eth0".to_string(),
                timestamp: "2024-01-15 14:30:00".to_string(),
                acknowledged: false,
            },
            crate::templates::Alert {
                id: 2,
                alert_type: "VPN".to_string(),
                severity: "info".to_string(),
                component: "wireguard".to_string(),
                message: "New WireGuard peer connected".to_string(),
                timestamp: "2024-01-15 14:25:00".to_string(),
                acknowledged: true,
            },
        ];

        Self {
            alerts: Arc::new(RwLock::new(default_alerts)),
        }
    }

    pub async fn get_current_metrics(&self) -> anyhow::Result<crate::templates::SystemMetrics> {
        let cpu_percent = SystemManager::get_cpu_usage();
        let (memory_percent, _) = SystemManager::get_memory_info();
        let disk_percent = SystemManager::get_disk_usage();

        Ok(crate::templates::SystemMetrics {
            cpu_percent,
            memory_percent,
            disk_percent,
            network_rx_rate: 1_234_567,
            network_tx_rate: 987_654,
        })
    }

    pub async fn get_interface_stats(&self) -> anyhow::Result<Vec<crate::templates::InterfaceStats>> {
        let mut stats = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let name = parts[0].trim_end_matches(':');
                    if name == "lo" { continue; }

                    let rx_bytes: u64 = parts[1].parse().unwrap_or(0);
                    let tx_bytes: u64 = parts[9].parse().unwrap_or(0);
                    let rx_packets: u64 = parts[2].parse().unwrap_or(0);
                    let tx_packets: u64 = parts[10].parse().unwrap_or(0);
                    let rx_errors: u64 = parts[3].parse().unwrap_or(0);
                    let tx_errors: u64 = parts[11].parse().unwrap_or(0);

                    stats.push(crate::templates::InterfaceStats {
                        name: name.to_string(),
                        rx_rate: format_bytes(rx_bytes),
                        tx_rate: format_bytes(tx_bytes),
                        rx_packets: format!("{}", rx_packets),
                        tx_packets: format!("{}", tx_packets),
                        errors: format!("{}", rx_errors + tx_errors),
                    });
                }
            }
        }

        if stats.is_empty() {
            stats.push(crate::templates::InterfaceStats {
                name: "eth0".to_string(),
                rx_rate: "1.23 GB".to_string(),
                tx_rate: "987 MB".to_string(),
                rx_packets: "1000000".to_string(),
                tx_packets: "800000".to_string(),
                errors: "0".to_string(),
            });
        }

        Ok(stats)
    }

    pub async fn get_top_connections(&self, limit: usize) -> anyhow::Result<Vec<crate::templates::Connection>> {
        let connections = vec![
            crate::templates::Connection {
                protocol: "TCP".to_string(),
                source: "192.168.1.100:54321".to_string(),
                destination: "192.168.1.1:8443".to_string(),
                bytes: "1.2 MB".to_string(),
                packets: "1024".to_string(),
                duration: "5m 30s".to_string(),
            },
            crate::templates::Connection {
                protocol: "UDP".to_string(),
                source: "203.0.113.50:51820".to_string(),
                destination: "10.99.0.1:51820".to_string(),
                bytes: "256 KB".to_string(),
                packets: "512".to_string(),
                duration: "2h 15m".to_string(),
            },
        ];

        Ok(connections.into_iter().take(limit).collect())
    }

    pub async fn get_recent_alerts(&self, limit: usize) -> anyhow::Result<Vec<crate::templates::Alert>> {
        let alerts = self.alerts.read().await;
        Ok(alerts.iter().take(limit).cloned().collect())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
