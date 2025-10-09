//! DHCP server management
//!
//! Provides DHCP server configuration and lease management

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

/// DHCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub interface: String,
    pub subnet: String,
    pub netmask: String,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time: u32, // seconds
    pub domain_name: Option<String>,
}

/// DHCP lease entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: Ipv4Addr,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_start: i64,
    pub lease_end: i64,
    pub state: LeaseState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LeaseState {
    Active,
    Expired,
    Reserved,
}

/// Static DHCP reservation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLease {
    pub mac_address: String,
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
}

/// DHCP server manager
pub struct DhcpManager {
    config_path: PathBuf,
    leases_path: PathBuf,
}

impl DhcpManager {
    pub fn new() -> Self {
        Self {
            config_path: PathBuf::from("/etc/patronus/dhcp.conf"),
            leases_path: PathBuf::from("/var/lib/patronus/dhcp.leases"),
        }
    }

    /// Generate ISC DHCP server configuration
    pub fn generate_config(&self, config: &DhcpConfig) -> Result<String> {
        let mut conf = String::new();

        conf.push_str(&format!(
            r#"# Patronus DHCP Server Configuration
# Generated automatically - do not edit manually

ddns-update-style none;
authoritative;

default-lease-time {};
max-lease-time {};

"#,
            config.lease_time,
            config.lease_time * 2
        ));

        // Domain name
        if let Some(ref domain) = config.domain_name {
            conf.push_str(&format!("option domain-name \"{}\";\n", domain));
        }

        // DNS servers
        if !config.dns_servers.is_empty() {
            let dns_list: Vec<String> = config.dns_servers.iter().map(|ip| ip.to_string()).collect();
            conf.push_str(&format!("option domain-name-servers {};\n", dns_list.join(", ")));
        }

        // Subnet declaration
        conf.push_str(&format!(
            r#"
subnet {} netmask {} {{
    range {} {};
"#,
            config.subnet, config.netmask, config.range_start, config.range_end
        ));

        // Gateway
        if let Some(gateway) = config.gateway {
            conf.push_str(&format!("    option routers {};\n", gateway));
        }

        conf.push_str("}\n");

        Ok(conf)
    }

    /// Save DHCP configuration to file
    pub async fn save_config(&self, config: &DhcpConfig) -> Result<()> {
        let conf_content = self.generate_config(config)?;

        // Create config directory if it doesn't exist
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Network(format!("Failed to create config dir: {}", e)))?;
        }

        std::fs::write(&self.config_path, conf_content)
            .map_err(|e| Error::Network(format!("Failed to write DHCP config: {}", e)))?;

        tracing::info!("Saved DHCP configuration to {:?}", self.config_path);
        Ok(())
    }

    /// Add static DHCP reservation
    pub async fn add_static_lease(&self, reservation: &StaticLease) -> Result<()> {
        let mut config_content = std::fs::read_to_string(&self.config_path)
            .unwrap_or_else(|_| String::new());

        let static_entry = format!(
            r#"
# Static reservation: {}
host {} {{
    hardware ethernet {};
    fixed-address {};
}}
"#,
            reservation.hostname.as_ref().unwrap_or(&"unknown".to_string()),
            reservation.hostname.as_ref().unwrap_or(&reservation.mac_address),
            reservation.mac_address,
            reservation.ip_address
        );

        config_content.push_str(&static_entry);

        std::fs::write(&self.config_path, config_content)
            .map_err(|e| Error::Network(format!("Failed to add static lease: {}", e)))?;

        tracing::info!("Added static DHCP reservation: {} -> {}",
            reservation.mac_address, reservation.ip_address);
        Ok(())
    }

    /// Parse DHCP leases file
    pub async fn get_leases(&self) -> Result<Vec<DhcpLease>> {
        let leases_content = std::fs::read_to_string(&self.leases_path)
            .unwrap_or_else(|_| String::new());

        let mut leases = Vec::new();
        let mut current_lease: Option<DhcpLease> = None;

        for line in leases_content.lines() {
            let line = line.trim();

            if line.starts_with("lease ") {
                if let Some(ip_str) = line.strip_prefix("lease ").and_then(|s| s.split_whitespace().next()) {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        current_lease = Some(DhcpLease {
                            ip_address: ip,
                            mac_address: String::new(),
                            hostname: None,
                            lease_start: 0,
                            lease_end: 0,
                            state: LeaseState::Active,
                        });
                    }
                }
            } else if let Some(ref mut lease) = current_lease {
                if line.starts_with("hardware ethernet ") {
                    if let Some(mac) = line.strip_prefix("hardware ethernet ").and_then(|s| s.trim_end_matches(';').split_whitespace().next()) {
                        lease.mac_address = mac.to_string();
                    }
                } else if line.starts_with("client-hostname ") {
                    if let Some(hostname) = line.strip_prefix("client-hostname ").and_then(|s| s.trim_matches(|c| c == '"' || c == ';').split_whitespace().next()) {
                        lease.hostname = Some(hostname.to_string());
                    }
                } else if line.starts_with("binding state ") {
                    if let Some(state) = line.strip_prefix("binding state ").and_then(|s| s.trim_end_matches(';').split_whitespace().next()) {
                        lease.state = match state {
                            "active" => LeaseState::Active,
                            "expired" => LeaseState::Expired,
                            "reserved" => LeaseState::Reserved,
                            _ => LeaseState::Active,
                        };
                    }
                }
            }

            if line == "}" {
                if let Some(lease) = current_lease.take() {
                    if !lease.mac_address.is_empty() {
                        leases.push(lease);
                    }
                }
            }
        }

        Ok(leases)
    }

    /// Start DHCP server
    pub async fn start(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(&["start", "dhcpd"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to start DHCP server: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to start DHCP server: {}", stderr)));
        }

        tracing::info!("Started DHCP server");
        Ok(())
    }

    /// Stop DHCP server
    pub async fn stop(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(&["stop", "dhcpd"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to stop DHCP server: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to stop DHCP server: {}", stderr)));
        }

        tracing::info!("Stopped DHCP server");
        Ok(())
    }

    /// Restart DHCP server (apply configuration changes)
    pub async fn restart(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(&["restart", "dhcpd"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to restart DHCP server: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Network(format!("Failed to restart DHCP server: {}", stderr)));
        }

        tracing::info!("Restarted DHCP server");
        Ok(())
    }

    /// Get DHCP server status
    pub async fn status(&self) -> Result<bool> {
        let output = Command::new("systemctl")
            .args(&["is-active", "dhcpd"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to check DHCP status: {}", e)))?;

        Ok(output.status.success())
    }

    /// Clear all leases
    pub async fn clear_leases(&self) -> Result<()> {
        std::fs::write(&self.leases_path, "")
            .map_err(|e| Error::Network(format!("Failed to clear leases: {}", e)))?;

        // Restart to pick up changes
        self.restart().await?;

        tracing::info!("Cleared all DHCP leases");
        Ok(())
    }
}

impl Default for DhcpManager {
    fn default() -> Self {
        Self::new()
    }
}
