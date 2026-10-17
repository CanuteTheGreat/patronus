//! VPN state (WireGuard / OpenVPN / IPsec). Lane F replaces the
//! in-memory fixtures below with a store-backed adapter + applier.

use std::sync::Arc;
use tokio::sync::RwLock;

/// VPN management operations
pub struct VpnManager {
    wireguard_peers: Arc<RwLock<Vec<crate::templates::WireGuardPeer>>>,
    openvpn_tunnels: Arc<RwLock<Vec<crate::templates::OpenVpnTunnel>>>,
    ipsec_tunnels: Arc<RwLock<Vec<crate::templates::IpsecTunnel>>>,
    next_id: Arc<RwLock<u32>>,
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
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

        let default_ipsec = vec![crate::templates::IpsecTunnel {
            id: 1,
            name: "site-to-site-hq".to_string(),
            status: "Established".to_string(),
            local_subnet: "10.0.0.0/24".to_string(),
            remote_subnet: "10.1.0.0/24".to_string(),
            remote_gateway: "203.0.113.100".to_string(),
        }];

        Self {
            wireguard_peers: Arc::new(RwLock::new(default_peers)),
            openvpn_tunnels: Arc::new(RwLock::new(vec![])),
            ipsec_tunnels: Arc::new(RwLock::new(default_ipsec)),
            next_id: Arc::new(RwLock::new(4)),
        }
    }

    pub async fn list_wireguard_peers(
        &self,
    ) -> anyhow::Result<Vec<crate::templates::WireGuardPeer>> {
        let peers = self.wireguard_peers.read().await;
        Ok(peers.clone())
    }

    pub async fn add_wireguard_peer(
        &self,
        peer: crate::routes::api::vpn::WireGuardPeer,
    ) -> anyhow::Result<u32> {
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

    pub async fn list_openvpn_tunnels(
        &self,
    ) -> anyhow::Result<Vec<crate::templates::OpenVpnTunnel>> {
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
