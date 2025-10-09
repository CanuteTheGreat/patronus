//! WireGuard automatic peering
//!
//! Automatically establishes WireGuard VPN tunnels between discovered sites.

use crate::{database::Database, types::*, Error, Result};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard peering manager
pub struct PeeringManager {
    db: Arc<Database>,
    own_site_id: SiteId,
    own_private_key: StaticSecret,
    own_public_key: PublicKey,
    peers: Arc<RwLock<Vec<PeerConfig>>>,
    interface_name: String,
    listen_port: u16,
    network_prefix: String, // e.g., "10.99.0.0/16"
}

/// WireGuard peer configuration
#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub site_id: SiteId,
    pub public_key: PublicKey,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// WireGuard interface configuration
#[derive(Debug)]
pub struct InterfaceConfig {
    pub name: String,
    pub private_key: StaticSecret,
    pub listen_port: u16,
    pub address: String,
}

impl PeeringManager {
    /// Create a new peering manager
    pub fn new(
        db: Arc<Database>,
        own_site_id: SiteId,
        interface_name: String,
        listen_port: u16,
    ) -> Self {
        // Generate WireGuard keypair
        let private_key = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            db,
            own_site_id,
            own_private_key: private_key,
            own_public_key: public_key,
            peers: Arc::new(RwLock::new(Vec::new())),
            interface_name,
            listen_port,
            network_prefix: "10.99.0.0/16".to_string(),
        }
    }

    /// Get public key for announcements
    pub fn public_key(&self) -> &PublicKey {
        &self.own_public_key
    }

    /// Initialize WireGuard interface
    pub async fn initialize_interface(&self) -> Result<()> {
        info!(
            interface = %self.interface_name,
            port = self.listen_port,
            "Initializing WireGuard interface"
        );

        // Assign IP address based on site ID
        let ip_addr = self.generate_site_ip();

        // Create WireGuard interface
        self.create_interface(&ip_addr).await?;

        // Configure interface
        self.configure_interface().await?;

        // Bring interface up
        self.bring_interface_up().await?;

        info!(
            interface = %self.interface_name,
            address = %ip_addr,
            "WireGuard interface initialized"
        );

        Ok(())
    }

    /// Generate IP address for this site
    fn generate_site_ip(&self) -> String {
        // Use last 4 bytes of site ID UUID for IP
        let uuid_bytes = self.own_site_id.as_uuid().as_bytes();
        let octets = &uuid_bytes[12..16];

        format!("10.99.{}.{}/16", octets[0], octets[1])
    }

    /// Create WireGuard interface
    async fn create_interface(&self, address: &str) -> Result<()> {
        debug!("Creating WireGuard interface {}", self.interface_name);

        // ip link add dev wg-sdwan type wireguard
        let output = Command::new("ip")
            .args(["link", "add", "dev", &self.interface_name, "type", "wireguard"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to create interface: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if interface already exists
            if !stderr.contains("File exists") {
                return Err(Error::Network(format!(
                    "Failed to create interface: {}",
                    stderr
                )));
            }
        }

        // ip addr add {address} dev wg-sdwan
        let output = Command::new("ip")
            .args(["addr", "add", address, "dev", &self.interface_name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to add address: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if address already exists
            if !stderr.contains("File exists") {
                return Err(Error::Network(format!(
                    "Failed to add address: {}",
                    stderr
                )));
            }
        }

        Ok(())
    }

    /// Configure WireGuard interface (private key, port)
    async fn configure_interface(&self) -> Result<()> {
        debug!("Configuring WireGuard interface");

        // Convert private key to base64
        let private_key_b64 = base64::encode(self.own_private_key.to_bytes());

        // wg set wg-sdwan private-key <(echo {private_key})
        let output = Command::new("wg")
            .args([
                "set",
                &self.interface_name,
                "listen-port",
                &self.listen_port.to_string(),
                "private-key",
                "/dev/stdin",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Network(format!("Failed to spawn wg command: {}", e)))?;

        // Write private key to stdin
        use std::io::Write;
        if let Some(mut stdin) = output.stdin {
            stdin
                .write_all(private_key_b64.as_bytes())
                .map_err(|e| Error::Network(format!("Failed to write private key: {}", e)))?;
        }

        let result = output
            .wait_with_output()
            .map_err(|e| Error::Network(format!("Failed to wait for wg command: {}", e)))?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(Error::Network(format!(
                "Failed to configure interface: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Bring interface up
    async fn bring_interface_up(&self) -> Result<()> {
        debug!("Bringing up WireGuard interface");

        // ip link set wg-sdwan up
        let output = Command::new("ip")
            .args(["link", "set", &self.interface_name, "up"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to bring interface up: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!(
                "Failed to bring interface up: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Add peer to WireGuard interface
    pub async fn add_peer(&self, site: &Site) -> Result<()> {
        info!(
            site_id = %site.id,
            site_name = %site.name,
            "Adding WireGuard peer"
        );

        // Extract WireGuard public key from site announcement
        if site.public_key.len() != 32 {
            return Err(Error::InvalidConfig(format!(
                "Invalid public key length: {}",
                site.public_key.len()
            )));
        }

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(&site.public_key[..32]);
        let public_key = PublicKey::from(public_key_bytes);

        // Generate allowed IPs for this peer
        let allowed_ips = self.generate_peer_allowed_ips(&site.id);

        // Get endpoint from site
        let endpoint = site
            .endpoints
            .first()
            .ok_or_else(|| Error::Network("No endpoints available for site".to_string()))?
            .address
            .to_string();

        // Create peer config
        let peer_config = PeerConfig {
            site_id: site.id,
            public_key,
            endpoint,
            allowed_ips: allowed_ips.clone(),
            persistent_keepalive: Some(25),
        };

        // Add to WireGuard
        self.add_wg_peer(&peer_config).await?;

        // Store in memory
        let mut peers = self.peers.write().await;
        peers.push(peer_config);

        // Store path in database
        let path = Path {
            id: PathId::new(0), // Will be assigned by database
            src_site: self.own_site_id,
            dst_site: site.id,
            src_endpoint: format!("0.0.0.0:{}", self.listen_port)
                .parse()
                .unwrap(),
            dst_endpoint: endpoint.parse().unwrap(),
            wg_interface: Some(self.interface_name.clone()),
            metrics: PathMetrics::default(),
            status: PathStatus::Up,
        };

        let path_id = self.db.insert_path(&path).await?;

        info!(
            site_id = %site.id,
            path_id = %path_id,
            "WireGuard peer added successfully"
        );

        Ok(())
    }

    /// Generate allowed IPs for a peer
    fn generate_peer_allowed_ips(&self, site_id: &SiteId) -> Vec<String> {
        // Assign /32 based on site ID
        let uuid_bytes = site_id.as_uuid().as_bytes();
        let octets = &uuid_bytes[12..16];

        vec![format!("10.99.{}.{}/32", octets[0], octets[1])]
    }

    /// Add peer using wg command
    async fn add_wg_peer(&self, peer: &PeerConfig) -> Result<()> {
        debug!(
            site_id = %peer.site_id,
            endpoint = %peer.endpoint,
            "Configuring WireGuard peer"
        );

        let public_key_b64 = base64::encode(peer.public_key.as_bytes());

        // Build wg command
        let mut args = vec![
            "set".to_string(),
            self.interface_name.clone(),
            "peer".to_string(),
            public_key_b64,
            "endpoint".to_string(),
            peer.endpoint.clone(),
            "allowed-ips".to_string(),
            peer.allowed_ips.join(","),
        ];

        if let Some(keepalive) = peer.persistent_keepalive {
            args.push("persistent-keepalive".to_string());
            args.push(keepalive.to_string());
        }

        let output = Command::new("wg")
            .args(&args)
            .output()
            .map_err(|e| Error::Network(format!("Failed to execute wg command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to add peer: {}", stderr)));
        }

        Ok(())
    }

    /// Remove peer from WireGuard interface
    pub async fn remove_peer(&self, site_id: &SiteId) -> Result<()> {
        info!(site_id = %site_id, "Removing WireGuard peer");

        // Find peer config
        let mut peers = self.peers.write().await;
        let peer_idx = peers
            .iter()
            .position(|p| &p.site_id == site_id)
            .ok_or_else(|| Error::SiteNotFound(site_id.to_string()))?;

        let peer = peers.remove(peer_idx);

        // Remove from WireGuard
        let public_key_b64 = base64::encode(peer.public_key.as_bytes());

        let output = Command::new("wg")
            .args(["set", &self.interface_name, "peer", &public_key_b64, "remove"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to remove peer: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to remove peer from WireGuard: {}", stderr);
        }

        Ok(())
    }

    /// Get current peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// List all peers
    pub async fn list_peers(&self) -> Vec<PeerConfig> {
        self.peers.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_generation() {
        let site_id = SiteId::generate();
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let manager = PeeringManager::new(
            db,
            site_id,
            "wg-test".to_string(),
            51820,
        );

        let ip = manager.generate_site_ip();
        assert!(ip.starts_with("10.99."));
        assert!(ip.ends_with("/16"));
    }

    #[test]
    fn test_allowed_ips_generation() {
        let site_id = SiteId::generate();
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let manager = PeeringManager::new(
            db,
            SiteId::generate(),
            "wg-test".to_string(),
            51820,
        );

        let allowed_ips = manager.generate_peer_allowed_ips(&site_id);
        assert_eq!(allowed_ips.len(), 1);
        assert!(allowed_ips[0].starts_with("10.99."));
        assert!(allowed_ips[0].ends_with("/32"));
    }
}
