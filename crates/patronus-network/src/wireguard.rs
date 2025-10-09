//! WireGuard VPN management
//!
//! Provides WireGuard tunnel and peer configuration

use patronus_core::{Error, Result};
use std::process::Command;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// WireGuard interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardInterface {
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u16,
    pub address: Vec<String>, // CIDR notation
}

/// WireGuard peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>, // IP:port
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// WireGuard tunnel status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardStatus {
    pub interface: String,
    pub public_key: String,
    pub listen_port: u16,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<i64>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

/// WireGuard manager
pub struct WireGuardManager {}

impl WireGuardManager {
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a new WireGuard private key
    pub fn generate_private_key() -> Result<String> {
        let output = Command::new("wg")
            .arg("genkey")
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate private key: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Network("Failed to generate private key".to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Derive public key from private key
    pub fn derive_public_key(private_key: &str) -> Result<String> {
        let output = Command::new("wg")
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(private_key.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| Error::Network(format!("Failed to derive public key: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Network("Failed to derive public key".to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Generate a preshared key
    pub fn generate_preshared_key() -> Result<String> {
        let output = Command::new("wg")
            .arg("genpsk")
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate preshared key: {}", e)))?;

        if !output.status.success() {
            return Err(Error::Network("Failed to generate preshared key".to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Create a WireGuard interface
    pub async fn create_interface(&self, config: &WireGuardInterface) -> Result<()> {
        // Create the interface using ip link
        let output = Command::new("ip")
            .args(&["link", "add", &config.name, "type", "wireguard"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to create WireGuard interface: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to create interface: {}", stderr)));
        }

        // Configure the interface
        self.configure_interface(config).await?;

        // Assign IP addresses
        for addr in &config.address {
            let output = Command::new("ip")
                .args(&["address", "add", addr, "dev", &config.name])
                .output()
                .map_err(|e| Error::Network(format!("Failed to add address: {}", e)))?;

            if !output.status.success() {
                tracing::warn!("Failed to add address {} to {}", addr, config.name);
            }
        }

        // Bring interface up
        Command::new("ip")
            .args(&["link", "set", &config.name, "up"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to bring interface up: {}", e)))?;

        tracing::info!("Created WireGuard interface: {}", config.name);
        Ok(())
    }

    /// Configure a WireGuard interface
    async fn configure_interface(&self, config: &WireGuardInterface) -> Result<()> {
        // Set private key
        Command::new("wg")
            .args(&["set", &config.name, "private-key", "/dev/stdin"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    stdin.write_all(config.private_key.as_bytes())?;
                }
                child.wait()
            })
            .map_err(|e| Error::Network(format!("Failed to set private key: {}", e)))?;

        // Set listen port
        Command::new("wg")
            .args(&[
                "set",
                &config.name,
                "listen-port",
                &config.listen_port.to_string(),
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to set listen port: {}", e)))?;

        Ok(())
    }

    /// Add a peer to a WireGuard interface
    pub async fn add_peer(&self, interface: &str, peer: &WireGuardPeer) -> Result<()> {
        let mut args = vec!["set", interface, "peer", &peer.public_key];

        // Allowed IPs
        if !peer.allowed_ips.is_empty() {
            args.push("allowed-ips");
            let allowed_ips = peer.allowed_ips.join(",");
            args.push(&allowed_ips);
        }

        // Endpoint
        if let Some(ref endpoint) = peer.endpoint {
            args.push("endpoint");
            args.push(endpoint);
        }

        // Persistent keepalive
        if let Some(keepalive) = peer.persistent_keepalive {
            args.push("persistent-keepalive");
            let keepalive_str = keepalive.to_string();
            args.push(&keepalive_str);
        }

        let output = Command::new("wg")
            .args(&args)
            .output()
            .map_err(|e| Error::Network(format!("Failed to add peer: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to add peer: {}", stderr)));
        }

        // Set preshared key if provided
        if let Some(ref psk) = peer.preshared_key {
            Command::new("wg")
                .args(&["set", interface, "peer", &peer.public_key, "preshared-key", "/dev/stdin"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(stdin) = child.stdin.as_mut() {
                        stdin.write_all(psk.as_bytes())?;
                    }
                    child.wait()
                })
                .map_err(|e| Error::Network(format!("Failed to set preshared key: {}", e)))?;
        }

        tracing::info!("Added peer {} to {}", peer.public_key, interface);
        Ok(())
    }

    /// Remove a peer from a WireGuard interface
    pub async fn remove_peer(&self, interface: &str, public_key: &str) -> Result<()> {
        let output = Command::new("wg")
            .args(&["set", interface, "peer", public_key, "remove"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to remove peer: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to remove peer: {}", stderr)));
        }

        tracing::info!("Removed peer {} from {}", public_key, interface);
        Ok(())
    }

    /// Delete a WireGuard interface
    pub async fn delete_interface(&self, name: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(&["link", "delete", name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to delete interface: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to delete interface: {}", stderr)));
        }

        tracing::info!("Deleted WireGuard interface: {}", name);
        Ok(())
    }

    /// Get WireGuard interface status
    pub async fn get_status(&self, interface: &str) -> Result<WireGuardStatus> {
        let output = Command::new("wg")
            .args(&["show", interface, "dump"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to get WireGuard status: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to get status: {}", stderr)));
        }

        let dump = String::from_utf8_lossy(&output.stdout);
        self.parse_wg_dump(&dump, interface)
    }

    /// Parse WireGuard dump output
    fn parse_wg_dump(&self, dump: &str, interface: &str) -> Result<WireGuardStatus> {
        let lines: Vec<&str> = dump.lines().collect();
        if lines.is_empty() {
            return Err(Error::Network("Empty WireGuard dump".to_string()));
        }

        // First line is interface info
        let interface_parts: Vec<&str> = lines[0].split('\t').collect();
        if interface_parts.len() < 3 {
            return Err(Error::Network("Invalid WireGuard dump format".to_string()));
        }

        let public_key = interface_parts[1].to_string();
        let listen_port = interface_parts[2].parse::<u16>().unwrap_or(0);

        // Remaining lines are peers
        let mut peers = Vec::new();
        for line in &lines[1..] {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 5 {
                let peer_public_key = parts[0].to_string();
                let endpoint = if !parts[2].is_empty() {
                    Some(parts[2].to_string())
                } else {
                    None
                };
                let allowed_ips: Vec<String> = parts[3]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                let latest_handshake = parts[4].parse::<i64>().ok();
                let transfer_rx = parts[5].parse::<u64>().unwrap_or(0);
                let transfer_tx = parts[6].parse::<u64>().unwrap_or(0);

                peers.push(PeerStatus {
                    public_key: peer_public_key,
                    endpoint,
                    allowed_ips,
                    latest_handshake,
                    transfer_rx,
                    transfer_tx,
                });
            }
        }

        Ok(WireGuardStatus {
            interface: interface.to_string(),
            public_key,
            listen_port,
            peers,
        })
    }

    /// Save WireGuard configuration to file
    pub async fn save_config(&self, interface: &str, path: &str) -> Result<()> {
        let output = Command::new("wg")
            .args(&["showconf", interface])
            .output()
            .map_err(|e| Error::Network(format!("Failed to get config: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to get config: {}", stderr)));
        }

        std::fs::write(path, &output.stdout)
            .map_err(|e| Error::Network(format!("Failed to write config: {}", e)))?;

        tracing::info!("Saved WireGuard config for {} to {}", interface, path);
        Ok(())
    }

    /// Load WireGuard configuration from file
    pub async fn load_config(&self, interface: &str, path: &str) -> Result<()> {
        Command::new("wg")
            .args(&["setconf", interface, path])
            .output()
            .map_err(|e| Error::Network(format!("Failed to load config: {}", e)))?;

        tracing::info!("Loaded WireGuard config for {} from {}", interface, path);
        Ok(())
    }
}

impl Default for WireGuardManager {
    fn default() -> Self {
        Self::new()
    }
}
