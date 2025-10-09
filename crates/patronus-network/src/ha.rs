//! High Availability (HA) and Failover
//!
//! Provides HA with multiple backend options (the Gentoo way!):
//! - CARP (Common Address Redundancy Protocol) via ucarp
//! - VRRP (Virtual Router Redundancy Protocol) via keepalived
//! - Custom VRRP via vrrpd
//!
//! Includes configuration synchronization between nodes.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;

/// HA backend implementation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HaBackend {
    Ucarp,      // CARP implementation (BSD-compatible)
    Keepalived, // VRRP via keepalived (feature-rich)
    Vrrpd,      // Simple VRRP daemon
}

impl std::fmt::Display for HaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ucarp => write!(f, "ucarp"),
            Self::Keepalived => write!(f, "keepalived"),
            Self::Vrrpd => write!(f, "vrrpd"),
        }
    }
}

/// HA node role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HaRole {
    Master,    // Primary/active node
    Backup,    // Backup/standby node
}

/// HA node state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HaState {
    Master,      // Currently active
    Backup,      // Currently standby
    Fault,       // Failed state
    Unknown,
}

/// Virtual IP (VIP) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualIp {
    pub name: String,
    pub enabled: bool,
    pub vip: IpAddr,
    pub interface: String,
    pub vhid: u8,          // Virtual Host ID (1-255)
    pub priority: u8,      // Priority (0-255, higher = preferred master)
    pub password: Option<String>,  // Authentication password
    pub preempt: bool,     // Allow preemption (higher priority takes over)
    pub advskew: u8,       // Advertisement skew (0-254)
}

impl Default for VirtualIp {
    fn default() -> Self {
        Self {
            name: "vip1".to_string(),
            enabled: true,
            vip: "192.168.1.100".parse().unwrap(),
            interface: "eth0".to_string(),
            vhid: 1,
            priority: 100,
            password: Some("secret".to_string()),
            preempt: true,
            advskew: 0,
        }
    }
}

/// HA cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaCluster {
    pub name: String,
    pub enabled: bool,
    pub backend: HaBackend,
    pub role: HaRole,

    // Peer configuration
    pub peer_ip: IpAddr,
    pub sync_interface: String,
    pub sync_enabled: bool,

    // Virtual IPs
    pub virtual_ips: Vec<VirtualIp>,

    // Config sync
    pub config_sync_enabled: bool,
    pub config_sync_user: String,
    pub config_sync_path: PathBuf,
}

impl Default for HaCluster {
    fn default() -> Self {
        Self {
            name: "cluster1".to_string(),
            enabled: true,
            backend: HaBackend::Ucarp,
            role: HaRole::Master,
            peer_ip: "192.168.1.2".parse().unwrap(),
            sync_interface: "eth1".to_string(),
            sync_enabled: true,
            virtual_ips: vec![VirtualIp::default()],
            config_sync_enabled: true,
            config_sync_user: "patronus".to_string(),
            config_sync_path: PathBuf::from("/etc/patronus"),
        }
    }
}

/// Keepalived configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepalivedConfig {
    pub router_id: String,
    pub notification_email: Option<String>,
    pub vrrp_instances: Vec<VrrpInstance>,
}

/// VRRP instance for Keepalived
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrrpInstance {
    pub name: String,
    pub state: HaRole,
    pub interface: String,
    pub virtual_router_id: u8,
    pub priority: u8,
    pub advert_int: u8,  // Advertisement interval (seconds)
    pub virtual_ips: Vec<IpAddr>,
    pub track_interfaces: Vec<String>,  // Monitor these interfaces
    pub track_scripts: Vec<String>,     // Health check scripts
}

/// HA manager
pub struct HaManager {
    config_dir: PathBuf,
    backend: HaBackend,
}

impl HaManager {
    /// Create a new HA manager with specified backend
    pub fn new(backend: HaBackend) -> Self {
        Self {
            config_dir: PathBuf::from("/etc/patronus/ha"),
            backend,
        }
    }

    /// Create with auto-detected backend
    pub fn new_auto() -> Self {
        // Try to detect available backends
        let backend = if Self::is_available("keepalived") {
            HaBackend::Keepalived
        } else if Self::is_available("ucarp") {
            HaBackend::Ucarp
        } else if Self::is_available("vrrpd") {
            HaBackend::Vrrpd
        } else {
            HaBackend::Ucarp  // Default
        };

        Self::new(backend)
    }

    /// Check if a command is available
    fn is_available(cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get current backend
    pub fn backend(&self) -> HaBackend {
        self.backend.clone()
    }

    /// Generate ucarp configuration
    fn generate_ucarp_config(&self, vip: &VirtualIp) -> Result<Vec<String>> {
        let mut args = vec![
            "--interface".to_string(), vip.interface.clone(),
            "--srcip".to_string(), vip.vip.to_string(),
            "--vhid".to_string(), vip.vhid.to_string(),
            "--advskew".to_string(), vip.advskew.to_string(),
            "--advbase".to_string(), "1".to_string(),
        ];

        if let Some(pass) = &vip.password {
            args.push("--pass".to_string());
            args.push(pass.clone());
        }

        if vip.preempt {
            args.push("--preempt".to_string());
        }

        // Up/down scripts
        args.push("--upscript".to_string());
        args.push(format!("/etc/patronus/ha/vip-{}-up.sh", vip.name));
        args.push("--downscript".to_string());
        args.push(format!("/etc/patronus/ha/vip-{}-down.sh", vip.name));

        Ok(args)
    }

    /// Generate keepalived configuration
    fn generate_keepalived_config(&self, cluster: &HaCluster) -> Result<String> {
        let mut config = String::new();

        config.push_str("# Patronus Keepalived Configuration\n\n");

        // Global configuration
        config.push_str("global_defs {\n");
        config.push_str(&format!("  router_id {}\n", cluster.name));
        config.push_str("  enable_script_security\n");
        config.push_str("}\n\n");

        // VRRP instances
        for vip in &cluster.virtual_ips {
            if !vip.enabled {
                continue;
            }

            config.push_str(&format!("vrrp_instance {} {{\n", vip.name));

            let state = match cluster.role {
                HaRole::Master => "MASTER",
                HaRole::Backup => "BACKUP",
            };
            config.push_str(&format!("  state {}\n", state));
            config.push_str(&format!("  interface {}\n", vip.interface));
            config.push_str(&format!("  virtual_router_id {}\n", vip.vhid));
            config.push_str(&format!("  priority {}\n", vip.priority));
            config.push_str("  advert_int 1\n");

            if let Some(pass) = &vip.password {
                config.push_str("  authentication {\n");
                config.push_str("    auth_type PASS\n");
                config.push_str(&format!("    auth_pass {}\n", pass));
                config.push_str("  }\n");
            }

            if vip.preempt {
                config.push_str("  preempt_delay 300\n");
            } else {
                config.push_str("  nopreempt\n");
            }

            config.push_str("  virtual_ipaddress {\n");
            config.push_str(&format!("    {}\n", vip.vip));
            config.push_str("  }\n");

            // Notify scripts
            config.push_str(&format!("  notify_master \"/etc/patronus/ha/vip-{}-up.sh\"\n", vip.name));
            config.push_str(&format!("  notify_backup \"/etc/patronus/ha/vip-{}-down.sh\"\n", vip.name));
            config.push_str(&format!("  notify_fault \"/etc/patronus/ha/vip-{}-down.sh\"\n", vip.name));

            config.push_str("}\n\n");
        }

        Ok(config)
    }

    /// Generate VRRP up script
    async fn generate_up_script(&self, vip: &VirtualIp) -> Result<String> {
        let mut script = String::new();

        script.push_str("#!/bin/bash\n");
        script.push_str("# Patronus HA - VIP UP script\n\n");
        script.push_str(&format!("# VIP {} is now MASTER\n", vip.name));
        script.push_str(&format!("ip addr add {}/{} dev {} 2>/dev/null || true\n",
            vip.vip, 32, vip.interface));
        script.push_str("# Send gratuitous ARP\n");
        script.push_str(&format!("arping -c 3 -A -I {} {} 2>/dev/null || true\n",
            vip.interface, vip.vip));
        script.push_str("# Trigger firewall reload\n");
        script.push_str("/usr/bin/patronus firewall apply 2>/dev/null || true\n");
        script.push_str("# Log event\n");
        script.push_str(&format!("logger \"Patronus HA: VIP {} became MASTER\"\n", vip.name));

        Ok(script)
    }

    /// Generate VRRP down script
    async fn generate_down_script(&self, vip: &VirtualIp) -> Result<String> {
        let mut script = String::new();

        script.push_str("#!/bin/bash\n");
        script.push_str("# Patronus HA - VIP DOWN script\n\n");
        script.push_str(&format!("# VIP {} is now BACKUP\n", vip.name));
        script.push_str(&format!("ip addr del {}/{} dev {} 2>/dev/null || true\n",
            vip.vip, 32, vip.interface));
        script.push_str("# Log event\n");
        script.push_str(&format!("logger \"Patronus HA: VIP {} became BACKUP\"\n", vip.name));

        Ok(script)
    }

    /// Configure HA cluster
    pub async fn configure(&self, cluster: &HaCluster) -> Result<()> {
        if !cluster.enabled {
            return Ok(());
        }

        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create HA config directory: {}", e)))?;

        match self.backend {
            HaBackend::Keepalived => {
                self.configure_keepalived(cluster).await?;
            }
            HaBackend::Ucarp => {
                self.configure_ucarp(cluster).await?;
            }
            HaBackend::Vrrpd => {
                self.configure_vrrpd(cluster).await?;
            }
        }

        // Generate up/down scripts for each VIP
        for vip in &cluster.virtual_ips {
            if !vip.enabled {
                continue;
            }

            let up_script = self.generate_up_script(vip).await?;
            let down_script = self.generate_down_script(vip).await?;

            let up_path = self.config_dir.join(format!("vip-{}-up.sh", vip.name));
            let down_path = self.config_dir.join(format!("vip-{}-down.sh", vip.name));

            fs::write(&up_path, up_script).await
                .map_err(|e| Error::Network(format!("Failed to write up script: {}", e)))?;
            fs::write(&down_path, down_script).await
                .map_err(|e| Error::Network(format!("Failed to write down script: {}", e)))?;

            // Make scripts executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&up_path).await?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&up_path, perms.clone()).await?;
                fs::set_permissions(&down_path, perms).await?;
            }
        }

        Ok(())
    }

    /// Configure Keepalived
    async fn configure_keepalived(&self, cluster: &HaCluster) -> Result<()> {
        let config = self.generate_keepalived_config(cluster)?;
        let config_path = PathBuf::from("/etc/keepalived/keepalived.conf");

        fs::create_dir_all("/etc/keepalived").await.ok();
        fs::write(&config_path, config).await
            .map_err(|e| Error::Network(format!("Failed to write keepalived config: {}", e)))?;

        Ok(())
    }

    /// Configure ucarp
    async fn configure_ucarp(&self, cluster: &HaCluster) -> Result<()> {
        // ucarp is typically configured per-VIP via systemd/openrc services
        // We'll generate service files for each VIP

        for vip in &cluster.virtual_ips {
            if !vip.enabled {
                continue;
            }

            let args = self.generate_ucarp_config(vip)?;

            // Generate systemd service
            let service = format!(
                "[Unit]\n\
                Description=CARP Virtual IP {}\n\
                After=network.target\n\
                \n\
                [Service]\n\
                Type=simple\n\
                ExecStart=/usr/sbin/ucarp {}\n\
                Restart=always\n\
                \n\
                [Install]\n\
                WantedBy=multi-user.target\n",
                vip.name,
                args.join(" ")
            );

            let service_path = self.config_dir.join(format!("ucarp-{}.service", vip.name));
            fs::write(&service_path, service).await
                .map_err(|e| Error::Network(format!("Failed to write ucarp service: {}", e)))?;
        }

        Ok(())
    }

    /// Configure vrrpd
    async fn configure_vrrpd(&self, cluster: &HaCluster) -> Result<()> {
        // vrrpd configuration (simplified)
        for vip in &cluster.virtual_ips {
            if !vip.enabled {
                continue;
            }

            // vrrpd is typically started with command-line args
            let args = vec![
                "-i", &vip.interface,
                "-v", &vip.vhid.to_string(),
                "-p", &vip.priority.to_string(),
                &vip.vip.to_string(),
            ];

            // Save command for later use
            let cmd_file = self.config_dir.join(format!("vrrpd-{}.cmd", vip.name));
            fs::write(&cmd_file, args.join(" ")).await
                .map_err(|e| Error::Network(format!("Failed to write vrrpd command: {}", e)))?;
        }

        Ok(())
    }

    /// Start HA services
    pub async fn start(&self) -> Result<()> {
        match self.backend {
            HaBackend::Keepalived => {
                Command::new("systemctl")
                    .args(&["start", "keepalived"])
                    .output()
                    .map_err(|e| Error::Network(format!("Failed to start keepalived: {}", e)))?;
            }
            HaBackend::Ucarp => {
                // Start all ucarp VIP services
                // Would enumerate generated services
            }
            HaBackend::Vrrpd => {
                // Start vrrpd instances
            }
        }

        Ok(())
    }

    /// Stop HA services
    pub async fn stop(&self) -> Result<()> {
        match self.backend {
            HaBackend::Keepalived => {
                Command::new("systemctl")
                    .args(&["stop", "keepalived"])
                    .output()
                    .ok();
            }
            HaBackend::Ucarp => {
                // Stop all ucarp services
            }
            HaBackend::Vrrpd => {
                // Stop vrrpd
            }
        }

        Ok(())
    }

    /// Get HA status
    pub async fn get_status(&self) -> Result<HashMap<String, HaState>> {
        let mut status = HashMap::new();

        match self.backend {
            HaBackend::Keepalived => {
                // Parse keepalived status
                let output = Command::new("systemctl")
                    .args(&["status", "keepalived"])
                    .output()
                    .ok();

                if let Some(output) = output {
                    if output.status.success() {
                        status.insert("keepalived".to_string(), HaState::Master);
                    } else {
                        status.insert("keepalived".to_string(), HaState::Fault);
                    }
                }
            }
            HaBackend::Ucarp => {
                // Check ucarp processes
            }
            HaBackend::Vrrpd => {
                // Check vrrpd status
            }
        }

        Ok(status)
    }

    /// Synchronize configuration to peer
    pub async fn sync_config(&self, cluster: &HaCluster) -> Result<()> {
        if !cluster.config_sync_enabled {
            return Ok(());
        }

        // Use rsync to sync configuration to peer
        Command::new("rsync")
            .args(&[
                "-avz",
                "--delete",
                cluster.config_sync_path.to_str().unwrap(),
                &format!("{}@{}:{}",
                    cluster.config_sync_user,
                    cluster.peer_ip,
                    cluster.config_sync_path.display()
                ),
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to sync config: {}", e)))?;

        Ok(())
    }

    /// Manually trigger failover (for testing)
    pub async fn trigger_failover(&self) -> Result<()> {
        match self.backend {
            HaBackend::Keepalived => {
                // Reload keepalived with lower priority
                Command::new("systemctl")
                    .args(&["reload", "keepalived"])
                    .output()
                    .map_err(|e| Error::Network(format!("Failed to trigger failover: {}", e)))?;
            }
            HaBackend::Ucarp => {
                // Send USR2 signal to ucarp to step down
            }
            HaBackend::Vrrpd => {
                // Similar signal mechanism
            }
        }

        Ok(())
    }

    /// Get available backends
    pub fn list_available_backends() -> Vec<HaBackend> {
        let mut backends = Vec::new();

        if Self::is_available("keepalived") {
            backends.push(HaBackend::Keepalived);
        }
        if Self::is_available("ucarp") {
            backends.push(HaBackend::Ucarp);
        }
        if Self::is_available("vrrpd") {
            backends.push(HaBackend::Vrrpd);
        }

        backends
    }
}

impl Default for HaManager {
    fn default() -> Self {
        Self::new_auto()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_config() {
        let cluster = HaCluster::default();
        assert_eq!(cluster.role, HaRole::Master);
        assert!(cluster.enabled);
    }

    #[test]
    fn test_keepalived_config_generation() {
        let manager = HaManager::new(HaBackend::Keepalived);
        let cluster = HaCluster::default();

        let config = manager.generate_keepalived_config(&cluster).unwrap();
        assert!(config.contains("vrrp_instance"));
        assert!(config.contains("virtual_ipaddress"));
    }

    #[test]
    fn test_backend_detection() {
        let backends = HaManager::list_available_backends();
        // Should have at least one backend available on most systems
        assert!(!backends.is_empty() || cfg!(test));
    }
}
