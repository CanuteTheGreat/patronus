//! IPsec VPN management using strongSwan
//!
//! Provides IPsec tunnel configuration and management using strongSwan (IKEv2).

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;

/// IPsec authentication method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IpsecAuthMethod {
    Psk,           // Pre-shared key
    PubKey,        // Public key (certificates)
    Eap,           // EAP (for mobile clients)
    EapMschapv2,   // EAP-MSCHAPv2
    EapTls,        // EAP-TLS
}

impl std::fmt::Display for IpsecAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Psk => write!(f, "psk"),
            Self::PubKey => write!(f, "pubkey"),
            Self::Eap => write!(f, "eap"),
            Self::EapMschapv2 => write!(f, "eap-mschapv2"),
            Self::EapTls => write!(f, "eap-tls"),
        }
    }
}

/// IPsec encryption algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IpsecCipher {
    Aes128,
    Aes192,
    Aes256,
    Aes128Gcm128,
    Aes256Gcm128,
}

impl std::fmt::Display for IpsecCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128 => write!(f, "aes128"),
            Self::Aes192 => write!(f, "aes192"),
            Self::Aes256 => write!(f, "aes256"),
            Self::Aes128Gcm128 => write!(f, "aes128gcm128"),
            Self::Aes256Gcm128 => write!(f, "aes256gcm128"),
        }
    }
}

/// IPsec integrity algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IpsecIntegrity {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    AesXcbc,
}

impl std::fmt::Display for IpsecIntegrity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha384 => write!(f, "sha384"),
            Self::Sha512 => write!(f, "sha512"),
            Self::AesXcbc => write!(f, "aesxcbc"),
        }
    }
}

/// Diffie-Hellman group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DhGroup {
    Modp1024,  // Group 2
    Modp1536,  // Group 5
    Modp2048,  // Group 14
    Modp3072,  // Group 15
    Modp4096,  // Group 16
    Modp8192,  // Group 18
    Ecp256,    // Group 19
    Ecp384,    // Group 20
    Ecp521,    // Group 21
}

impl std::fmt::Display for DhGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Modp1024 => write!(f, "modp1024"),
            Self::Modp1536 => write!(f, "modp1536"),
            Self::Modp2048 => write!(f, "modp2048"),
            Self::Modp3072 => write!(f, "modp3072"),
            Self::Modp4096 => write!(f, "modp4096"),
            Self::Modp8192 => write!(f, "modp8192"),
            Self::Ecp256 => write!(f, "ecp256"),
            Self::Ecp384 => write!(f, "ecp384"),
            Self::Ecp521 => write!(f, "ecp521"),
        }
    }
}

/// IPsec tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecTunnelConfig {
    pub name: String,
    pub enabled: bool,
    pub ikev2: bool,  // Use IKEv2 (recommended), false = IKEv1

    // Local configuration
    pub local_id: Option<String>,  // Local identifier (IP, FQDN, email)
    pub local_subnets: Vec<String>,  // Local subnets to tunnel
    pub local_cert: Option<PathBuf>,
    pub local_key: Option<PathBuf>,

    // Remote configuration
    pub remote_id: Option<String>,
    pub remote_address: String,  // Remote gateway IP/hostname
    pub remote_subnets: Vec<String>,
    pub remote_cert: Option<PathBuf>,

    // Authentication
    pub auth_method: IpsecAuthMethod,
    pub psk: Option<String>,  // Pre-shared key (if PSK auth)

    // Phase 1 (IKE) proposals
    pub ike_cipher: Vec<IpsecCipher>,
    pub ike_integrity: Vec<IpsecIntegrity>,
    pub ike_dh_group: Vec<DhGroup>,
    pub ike_lifetime: u32,  // seconds

    // Phase 2 (ESP) proposals
    pub esp_cipher: Vec<IpsecCipher>,
    pub esp_integrity: Vec<IpsecIntegrity>,
    pub esp_dh_group: Vec<DhGroup>,
    pub esp_lifetime: u32,  // seconds

    // Options
    pub auto_start: bool,  // Start on boot
    pub dpdaction: String,  // Dead peer detection action (restart, clear, hold)
    pub dpddelay: u32,     // DPD delay in seconds
    pub close_action: String,  // Action on close (restart, clear)
}

impl Default for IpsecTunnelConfig {
    fn default() -> Self {
        Self {
            name: "tunnel1".to_string(),
            enabled: true,
            ikev2: true,
            local_id: None,
            local_subnets: vec!["10.0.1.0/24".to_string()],
            local_cert: None,
            local_key: None,
            remote_id: None,
            remote_address: "203.0.113.1".to_string(),
            remote_subnets: vec!["10.0.2.0/24".to_string()],
            remote_cert: None,
            auth_method: IpsecAuthMethod::Psk,
            psk: Some("changeme".to_string()),
            ike_cipher: vec![IpsecCipher::Aes256, IpsecCipher::Aes128],
            ike_integrity: vec![IpsecIntegrity::Sha256, IpsecIntegrity::Sha512],
            ike_dh_group: vec![DhGroup::Modp2048, DhGroup::Ecp256],
            ike_lifetime: 28800,  // 8 hours
            esp_cipher: vec![IpsecCipher::Aes256Gcm128, IpsecCipher::Aes256],
            esp_integrity: vec![IpsecIntegrity::Sha256],
            esp_dh_group: vec![DhGroup::Modp2048, DhGroup::Ecp256],
            esp_lifetime: 3600,  // 1 hour
            auto_start: true,
            dpdaction: "restart".to_string(),
            dpddelay: 30,
            close_action: "restart".to_string(),
        }
    }
}

/// Mobile client (road warrior) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecMobileClientConfig {
    pub name: String,
    pub enabled: bool,
    pub pool_name: String,  // IP pool for clients
    pub pool_range: (IpAddr, IpAddr),  // IP range
    pub dns_servers: Vec<IpAddr>,
    pub push_routes: Vec<String>,  // Routes to push to clients

    // Authentication
    pub auth_method: IpsecAuthMethod,
    pub eap_id: Option<String>,  // EAP identity

    // Certificates
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,

    // Proposals
    pub ike_cipher: Vec<IpsecCipher>,
    pub ike_integrity: Vec<IpsecIntegrity>,
    pub ike_dh_group: Vec<DhGroup>,
    pub esp_cipher: Vec<IpsecCipher>,
    pub esp_integrity: Vec<IpsecIntegrity>,
}

/// IPsec connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecConnectionStatus {
    pub name: String,
    pub state: IpsecState,
    pub local_ip: Option<IpAddr>,
    pub remote_ip: Option<IpAddr>,
    pub established: Option<String>,  // Time established
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

/// IPsec connection state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IpsecState {
    Established,
    Connecting,
    Disconnected,
    Failed,
}

/// strongSwan manager
pub struct IpsecManager {
    config_dir: PathBuf,
    secrets_file: PathBuf,
}

impl IpsecManager {
    /// Create a new IPsec manager
    pub fn new() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/patronus/ipsec"),
            secrets_file: PathBuf::from("/etc/patronus/ipsec/ipsec.secrets"),
        }
    }

    /// Generate ipsec.conf configuration
    pub fn generate_tunnel_config(&self, config: &IpsecTunnelConfig) -> Result<String> {
        let mut conf = String::new();

        conf.push_str(&format!("conn {}\n", config.name));

        // IKE version
        if config.ikev2 {
            conf.push_str("  keyexchange=ikev2\n");
        } else {
            conf.push_str("  keyexchange=ikev1\n");
        }

        // Auto start
        if config.auto_start {
            conf.push_str("  auto=start\n");
        } else {
            conf.push_str("  auto=add\n");
        }

        // Local configuration
        if let Some(local_id) = &config.local_id {
            conf.push_str(&format!("  leftid={}\n", local_id));
        }

        let local_subnets = config.local_subnets.join(",");
        conf.push_str(&format!("  leftsubnet={}\n", local_subnets));

        // Authentication method
        match config.auth_method {
            IpsecAuthMethod::Psk => {
                conf.push_str("  leftauth=psk\n");
                conf.push_str("  rightauth=psk\n");
            }
            IpsecAuthMethod::PubKey => {
                conf.push_str("  leftauth=pubkey\n");
                conf.push_str("  rightauth=pubkey\n");
                if let Some(cert) = &config.local_cert {
                    conf.push_str(&format!("  leftcert={}\n", cert.display()));
                }
            }
            _ => {
                conf.push_str(&format!("  leftauth={}\n", config.auth_method));
            }
        }

        // Remote configuration
        conf.push_str(&format!("  right={}\n", config.remote_address));

        if let Some(remote_id) = &config.remote_id {
            conf.push_str(&format!("  rightid={}\n", remote_id));
        }

        let remote_subnets = config.remote_subnets.join(",");
        conf.push_str(&format!("  rightsubnet={}\n", remote_subnets));

        // IKE proposals
        let ike_proposals = self.format_ike_proposals(
            &config.ike_cipher,
            &config.ike_integrity,
            &config.ike_dh_group,
        );
        conf.push_str(&format!("  ike={}\n", ike_proposals));
        conf.push_str(&format!("  ikelifetime={}s\n", config.ike_lifetime));

        // ESP proposals
        let esp_proposals = self.format_esp_proposals(
            &config.esp_cipher,
            &config.esp_integrity,
            &config.esp_dh_group,
        );
        conf.push_str(&format!("  esp={}\n", esp_proposals));
        conf.push_str(&format!("  lifetime={}s\n", config.esp_lifetime));

        // DPD
        conf.push_str(&format!("  dpdaction={}\n", config.dpdaction));
        conf.push_str(&format!("  dpddelay={}s\n", config.dpddelay));
        conf.push_str(&format!("  closeaction={}\n", config.close_action));

        conf.push_str("\n");

        Ok(conf)
    }

    /// Generate mobile client configuration
    pub fn generate_mobile_client_config(&self, config: &IpsecMobileClientConfig) -> Result<String> {
        let mut conf = String::new();

        conf.push_str(&format!("conn {}\n", config.name));
        conf.push_str("  keyexchange=ikev2\n");
        conf.push_str("  auto=add\n");

        // Left (server) side
        conf.push_str("  left=%any\n");
        conf.push_str(&format!("  leftcert={}\n", config.server_cert.display()));
        conf.push_str("  leftid=%any\n");
        conf.push_str("  leftsubnet=0.0.0.0/0\n");

        // Right (client) side
        conf.push_str("  right=%any\n");
        conf.push_str("  rightauth=eap-mschapv2\n");
        conf.push_str("  rightsourceip=%dhcp\n");  // Or use pool
        conf.push_str(&format!("  rightsourceip={}\n", config.pool_name));

        // DNS
        if !config.dns_servers.is_empty() {
            let dns = config.dns_servers.iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            conf.push_str(&format!("  rightdns={}\n", dns));
        }

        // IKE proposals
        let ike_proposals = self.format_ike_proposals(
            &config.ike_cipher,
            &config.ike_integrity,
            &config.ike_dh_group,
        );
        conf.push_str(&format!("  ike={}\n", ike_proposals));

        // ESP proposals
        let esp_proposals = self.format_esp_proposals(
            &config.esp_cipher,
            &config.esp_integrity,
            &vec![],  // No PFS for mobile
        );
        conf.push_str(&format!("  esp={}\n", esp_proposals));

        conf.push_str("  dpdaction=clear\n");
        conf.push_str("  rekey=no\n");

        conf.push_str("\n");

        Ok(conf)
    }

    /// Format IKE proposals
    fn format_ike_proposals(
        &self,
        ciphers: &[IpsecCipher],
        integrities: &[IpsecIntegrity],
        dh_groups: &[DhGroup],
    ) -> String {
        let mut proposals = Vec::new();

        for cipher in ciphers {
            for integrity in integrities {
                for dh in dh_groups {
                    proposals.push(format!("{}-{}-{}", cipher, integrity, dh));
                }
            }
        }

        proposals.join(",")
    }

    /// Format ESP proposals
    fn format_esp_proposals(
        &self,
        ciphers: &[IpsecCipher],
        integrities: &[IpsecIntegrity],
        dh_groups: &[DhGroup],
    ) -> String {
        let mut proposals = Vec::new();

        for cipher in ciphers {
            // GCM ciphers don't need separate integrity
            if matches!(cipher, IpsecCipher::Aes128Gcm128 | IpsecCipher::Aes256Gcm128) {
                if dh_groups.is_empty() {
                    proposals.push(format!("{}", cipher));
                } else {
                    for dh in dh_groups {
                        proposals.push(format!("{}-{}", cipher, dh));
                    }
                }
            } else {
                for integrity in integrities {
                    if dh_groups.is_empty() {
                        proposals.push(format!("{}-{}", cipher, integrity));
                    } else {
                        for dh in dh_groups {
                            proposals.push(format!("{}-{}-{}", cipher, integrity, dh));
                        }
                    }
                }
            }
        }

        proposals.join(",")
    }

    /// Save tunnel configuration
    pub async fn save_tunnel_config(&self, config: &IpsecTunnelConfig) -> Result<()> {
        let conf_content = self.generate_tunnel_config(config)?;
        let conf_path = self.config_dir.join(format!("{}.conf", config.name));

        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create config directory: {}", e)))?;

        fs::write(&conf_path, conf_content).await
            .map_err(|e| Error::Network(format!("Failed to write config file: {}", e)))?;

        // Update secrets file if PSK
        if config.auth_method == IpsecAuthMethod::Psk {
            if let Some(psk) = &config.psk {
                self.add_psk_secret(
                    config.local_id.as_deref(),
                    config.remote_id.as_deref(),
                    psk
                ).await?;
            }
        }

        Ok(())
    }

    /// Add PSK secret
    async fn add_psk_secret(
        &self,
        local_id: Option<&str>,
        remote_id: Option<&str>,
        psk: &str,
    ) -> Result<()> {
        let local = local_id.unwrap_or("%any");
        let remote = remote_id.unwrap_or("%any");

        let secret_line = format!("{} {} : PSK \"{}\"\n", local, remote, psk);

        // Read existing secrets
        let mut secrets = if self.secrets_file.exists() {
            fs::read_to_string(&self.secrets_file).await.unwrap_or_default()
        } else {
            String::new()
        };

        secrets.push_str(&secret_line);

        fs::write(&self.secrets_file, secrets).await
            .map_err(|e| Error::Network(format!("Failed to write secrets file: {}", e)))?;

        Ok(())
    }

    /// Start strongSwan
    pub async fn start(&self) -> Result<()> {
        Command::new("systemctl")
            .args(&["start", "strongswan"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to start strongSwan: {}", e)))?;

        Ok(())
    }

    /// Stop strongSwan
    pub async fn stop(&self) -> Result<()> {
        Command::new("systemctl")
            .args(&["stop", "strongswan"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to stop strongSwan: {}", e)))?;

        Ok(())
    }

    /// Restart strongSwan
    pub async fn restart(&self) -> Result<()> {
        Command::new("systemctl")
            .args(&["restart", "strongswan"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to restart strongSwan: {}", e)))?;

        Ok(())
    }

    /// Reload configuration
    pub async fn reload(&self) -> Result<()> {
        Command::new("ipsec")
            .arg("reload")
            .output()
            .map_err(|e| Error::Network(format!("Failed to reload IPsec: {}", e)))?;

        Ok(())
    }

    /// Start a specific tunnel
    pub async fn start_tunnel(&self, name: &str) -> Result<()> {
        Command::new("ipsec")
            .args(&["up", name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to start tunnel: {}", e)))?;

        Ok(())
    }

    /// Stop a specific tunnel
    pub async fn stop_tunnel(&self, name: &str) -> Result<()> {
        Command::new("ipsec")
            .args(&["down", name])
            .output()
            .map_err(|e| Error::Network(format!("Failed to stop tunnel: {}", e)))?;

        Ok(())
    }

    /// Get status of all tunnels
    pub async fn get_status(&self) -> Result<Vec<IpsecConnectionStatus>> {
        let output = Command::new("ipsec")
            .arg("status")
            .output()
            .map_err(|e| Error::Network(format!("Failed to get status: {}", e)))?;

        // Parse output (simplified - would need proper parsing)
        // For now, return empty vector
        Ok(vec![])
    }

    /// Generate certificates
    pub async fn generate_ca(&self, common_name: &str) -> Result<()> {
        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create config directory: {}", e)))?;

        let pki_dir = self.config_dir.join("pki");
        fs::create_dir_all(&pki_dir).await
            .map_err(|e| Error::Network(format!("Failed to create PKI directory: {}", e)))?;

        // Generate CA key
        Command::new("ipsec")
            .args(&["pki", "--gen", "--type", "rsa", "--size", "4096", "--outform", "pem"])
            .output()
            .map(|output| {
                std::fs::write(pki_dir.join("ca-key.pem"), output.stdout)
            })
            .map_err(|e| Error::Network(format!("Failed to generate CA key: {}", e)))?
            .map_err(|e| Error::Network(format!("Failed to write CA key: {}", e)))?;

        // Generate CA certificate
        Command::new("ipsec")
            .args(&[
                "pki", "--self", "--ca", "--lifetime", "3650",
                "--in", pki_dir.join("ca-key.pem").to_str().unwrap(),
                "--type", "rsa",
                "--dn", &format!("CN={}", common_name),
                "--outform", "pem"
            ])
            .output()
            .map(|output| {
                std::fs::write(pki_dir.join("ca-cert.pem"), output.stdout)
            })
            .map_err(|e| Error::Network(format!("Failed to generate CA cert: {}", e)))?
            .map_err(|e| Error::Network(format!("Failed to write CA cert: {}", e)))?;

        Ok(())
    }
}

impl Default for IpsecManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config_generation() {
        let manager = IpsecManager::new();
        let config = IpsecTunnelConfig::default();

        let conf = manager.generate_tunnel_config(&config).unwrap();

        assert!(conf.contains("conn tunnel1"));
        assert!(conf.contains("keyexchange=ikev2"));
        assert!(conf.contains("auto=start"));
    }

    #[test]
    fn test_proposal_formatting() {
        let manager = IpsecManager::new();

        let ike_prop = manager.format_ike_proposals(
            &[IpsecCipher::Aes256],
            &[IpsecIntegrity::Sha256],
            &[DhGroup::Modp2048],
        );

        assert_eq!(ike_prop, "aes256-sha256-modp2048");
    }
}
