//! OpenVPN management
//!
//! Provides OpenVPN server and client configuration and management.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;

/// OpenVPN protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OpenVpnProtocol {
    Udp,
    Tcp,
}

impl std::fmt::Display for OpenVpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

/// OpenVPN cipher
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OpenVpnCipher {
    Aes256Gcm,
    Aes128Gcm,
    Aes256Cbc,
    Aes128Cbc,
}

impl std::fmt::Display for OpenVpnCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
            Self::Aes128Gcm => write!(f, "AES-128-GCM"),
            Self::Aes256Cbc => write!(f, "AES-256-CBC"),
            Self::Aes128Cbc => write!(f, "AES-128-CBC"),
        }
    }
}

/// OpenVPN authentication method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OpenVpnAuth {
    Sha256,
    Sha512,
    Sha1,
}

impl std::fmt::Display for OpenVpnAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha512 => write!(f, "SHA512"),
            Self::Sha1 => write!(f, "SHA1"),
        }
    }
}

/// OpenVPN server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnServerConfig {
    pub name: String,
    pub enabled: bool,
    pub protocol: OpenVpnProtocol,
    pub port: u16,
    pub device: String,  // tun or tap
    pub local_ip: Option<IpAddr>,
    pub tunnel_network: String,  // e.g., "10.8.0.0/24"
    pub tunnel_netmask: String,  // e.g., "255.255.255.0"
    pub cipher: OpenVpnCipher,
    pub auth: OpenVpnAuth,
    pub compression: bool,
    pub max_clients: u32,
    pub push_routes: Vec<String>,  // Routes to push to clients
    pub push_dns: Vec<IpAddr>,     // DNS servers to push
    pub client_to_client: bool,
    pub duplicate_cn: bool,
    pub keepalive_interval: u32,
    pub keepalive_timeout: u32,
    pub tls_auth: bool,
    pub tls_crypt: bool,
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub dh_params_path: PathBuf,
    pub tls_key_path: Option<PathBuf>,
}

impl Default for OpenVpnServerConfig {
    fn default() -> Self {
        Self {
            name: "server1".to_string(),
            enabled: true,
            protocol: OpenVpnProtocol::Udp,
            port: 1194,
            device: "tun".to_string(),
            local_ip: None,
            tunnel_network: "10.8.0.0".to_string(),
            tunnel_netmask: "255.255.255.0".to_string(),
            cipher: OpenVpnCipher::Aes256Gcm,
            auth: OpenVpnAuth::Sha256,
            compression: false,
            max_clients: 100,
            push_routes: vec![],
            push_dns: vec![],
            client_to_client: false,
            duplicate_cn: false,
            keepalive_interval: 10,
            keepalive_timeout: 120,
            tls_auth: false,
            tls_crypt: true,
            ca_cert_path: PathBuf::from("/etc/patronus/openvpn/ca.crt"),
            server_cert_path: PathBuf::from("/etc/patronus/openvpn/server.crt"),
            server_key_path: PathBuf::from("/etc/patronus/openvpn/server.key"),
            dh_params_path: PathBuf::from("/etc/patronus/openvpn/dh2048.pem"),
            tls_key_path: Some(PathBuf::from("/etc/patronus/openvpn/ta.key")),
        }
    }
}

/// OpenVPN client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnClientConfig {
    pub name: String,
    pub enabled: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub protocol: OpenVpnProtocol,
    pub device: String,
    pub cipher: OpenVpnCipher,
    pub auth: OpenVpnAuth,
    pub compression: bool,
    pub verify_x509_name: Option<String>,
    pub ca_cert_path: PathBuf,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    pub tls_auth: bool,
    pub tls_crypt: bool,
    pub tls_key_path: Option<PathBuf>,
}

/// OpenVPN connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnConnectionStatus {
    pub name: String,
    pub state: OpenVpnState,
    pub local_ip: Option<IpAddr>,
    pub remote_ip: Option<IpAddr>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_since: Option<String>,
    pub uptime: Option<String>,
}

/// OpenVPN connection state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OpenVpnState {
    Connected,
    Connecting,
    Disconnected,
    Error,
}

/// OpenVPN client info (connected clients on server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnClient {
    pub common_name: String,
    pub real_address: String,
    pub virtual_address: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_since: String,
}

/// OpenVPN manager
pub struct OpenVpnManager {
    config_dir: PathBuf,
}

impl OpenVpnManager {
    /// Create a new OpenVPN manager
    pub fn new() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/patronus/openvpn"),
        }
    }

    /// Create a new OpenVPN manager with custom config directory
    pub fn with_config_dir<P: AsRef<Path>>(path: P) -> Self {
        Self {
            config_dir: path.as_ref().to_path_buf(),
        }
    }

    /// Generate server configuration file
    pub fn generate_server_config(&self, config: &OpenVpnServerConfig) -> Result<String> {
        let mut conf = String::new();

        // Mode and protocol
        conf.push_str(&format!("mode server\n"));
        conf.push_str(&format!("proto {}\n", config.protocol));
        conf.push_str(&format!("port {}\n", config.port));
        conf.push_str(&format!("dev {}\n", config.device));

        // Local IP if specified
        if let Some(local_ip) = config.local_ip {
            conf.push_str(&format!("local {}\n", local_ip));
        }

        // Server network
        conf.push_str(&format!("server {} {}\n", config.tunnel_network, config.tunnel_netmask));

        // Topology
        conf.push_str("topology subnet\n");

        // Certificates and keys
        conf.push_str(&format!("ca {}\n", config.ca_cert_path.display()));
        conf.push_str(&format!("cert {}\n", config.server_cert_path.display()));
        conf.push_str(&format!("key {}\n", config.server_key_path.display()));
        conf.push_str(&format!("dh {}\n", config.dh_params_path.display()));

        // TLS authentication/encryption
        if config.tls_crypt {
            if let Some(tls_key) = &config.tls_key_path {
                conf.push_str(&format!("tls-crypt {}\n", tls_key.display()));
            }
        } else if config.tls_auth {
            if let Some(tls_key) = &config.tls_key_path {
                conf.push_str(&format!("tls-auth {} 0\n", tls_key.display()));
            }
        }

        // Cipher and auth
        conf.push_str(&format!("cipher {}\n", config.cipher));
        conf.push_str(&format!("auth {}\n", config.auth));

        // Compression
        if config.compression {
            conf.push_str("compress lz4-v2\n");
            conf.push_str("push \"compress lz4-v2\"\n");
        }

        // Max clients
        conf.push_str(&format!("max-clients {}\n", config.max_clients));

        // Client-to-client
        if config.client_to_client {
            conf.push_str("client-to-client\n");
        }

        // Duplicate CN
        if config.duplicate_cn {
            conf.push_str("duplicate-cn\n");
        }

        // Keepalive
        conf.push_str(&format!("keepalive {} {}\n", config.keepalive_interval, config.keepalive_timeout));

        // Push routes
        for route in &config.push_routes {
            conf.push_str(&format!("push \"route {}\"\n", route));
        }

        // Push DNS
        for dns in &config.push_dns {
            conf.push_str(&format!("push \"dhcp-option DNS {}\"\n", dns));
        }

        // Persist
        conf.push_str("persist-key\n");
        conf.push_str("persist-tun\n");

        // Status and log
        conf.push_str(&format!("status /var/log/patronus/openvpn-{}-status.log\n", config.name));
        conf.push_str(&format!("log-append /var/log/patronus/openvpn-{}.log\n", config.name));
        conf.push_str("verb 3\n");

        // User and group for security
        conf.push_str("user nobody\n");
        conf.push_str("group nobody\n");

        Ok(conf)
    }

    /// Generate client configuration file
    pub fn generate_client_config(&self, config: &OpenVpnClientConfig) -> Result<String> {
        let mut conf = String::new();

        conf.push_str("client\n");
        conf.push_str(&format!("dev {}\n", config.device));
        conf.push_str(&format!("proto {}\n", config.protocol));
        conf.push_str(&format!("remote {} {}\n", config.remote_host, config.remote_port));

        conf.push_str("resolv-retry infinite\n");
        conf.push_str("nobind\n");

        // Persist
        conf.push_str("persist-key\n");
        conf.push_str("persist-tun\n");

        // Certificates
        conf.push_str(&format!("ca {}\n", config.ca_cert_path.display()));
        conf.push_str(&format!("cert {}\n", config.client_cert_path.display()));
        conf.push_str(&format!("key {}\n", config.client_key_path.display()));

        // TLS
        if config.tls_crypt {
            if let Some(tls_key) = &config.tls_key_path {
                conf.push_str(&format!("tls-crypt {}\n", tls_key.display()));
            }
        } else if config.tls_auth {
            if let Some(tls_key) = &config.tls_key_path {
                conf.push_str(&format!("tls-auth {} 1\n", tls_key.display()));
            }
        }

        // Cipher and auth
        conf.push_str(&format!("cipher {}\n", config.cipher));
        conf.push_str(&format!("auth {}\n", config.auth));

        // Compression
        if config.compression {
            conf.push_str("compress lz4-v2\n");
        }

        // Verify server name
        if let Some(name) = &config.verify_x509_name {
            conf.push_str(&format!("verify-x509-name {} name\n", name));
        }

        conf.push_str("verb 3\n");

        Ok(conf)
    }

    /// Save server configuration
    pub async fn save_server_config(&self, config: &OpenVpnServerConfig) -> Result<()> {
        let conf_content = self.generate_server_config(config)?;
        let conf_path = self.config_dir.join(format!("{}.conf", config.name));

        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create config directory: {}", e)))?;

        fs::write(&conf_path, conf_content).await
            .map_err(|e| Error::Network(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Save client configuration
    pub async fn save_client_config(&self, config: &OpenVpnClientConfig) -> Result<()> {
        let conf_content = self.generate_client_config(config)?;
        let conf_path = self.config_dir.join(format!("{}.conf", config.name));

        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create config directory: {}", e)))?;

        fs::write(&conf_path, conf_content).await
            .map_err(|e| Error::Network(format!("Failed to write config file: {}", e)))?;

        Ok(())
    }

    /// Start OpenVPN server
    pub async fn start_server(&self, name: &str) -> Result<()> {
        let conf_path = self.config_dir.join(format!("{}.conf", name));

        Command::new("openvpn")
            .arg("--config")
            .arg(&conf_path)
            .arg("--daemon")
            .output()
            .map_err(|e| Error::Network(format!("Failed to start OpenVPN server: {}", e)))?;

        Ok(())
    }

    /// Start OpenVPN client
    pub async fn start_client(&self, name: &str) -> Result<()> {
        let conf_path = self.config_dir.join(format!("{}.conf", name));

        Command::new("openvpn")
            .arg("--config")
            .arg(&conf_path)
            .arg("--daemon")
            .output()
            .map_err(|e| Error::Network(format!("Failed to start OpenVPN client: {}", e)))?;

        Ok(())
    }

    /// Stop OpenVPN instance
    pub async fn stop(&self, name: &str) -> Result<()> {
        Command::new("pkill")
            .arg("-f")
            .arg(format!("openvpn.*{}.conf", name))
            .output()
            .map_err(|e| Error::Network(format!("Failed to stop OpenVPN: {}", e)))?;

        Ok(())
    }

    /// Get OpenVPN status
    pub async fn get_status(&self, name: &str) -> Result<OpenVpnConnectionStatus> {
        let status_path = PathBuf::from(format!("/var/log/patronus/openvpn-{}-status.log", name));

        let is_running = Command::new("pgrep")
            .arg("-f")
            .arg(format!("openvpn.*{}.conf", name))
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        let state = if is_running {
            OpenVpnState::Connected
        } else {
            OpenVpnState::Disconnected
        };

        Ok(OpenVpnConnectionStatus {
            name: name.to_string(),
            state,
            local_ip: None,
            remote_ip: None,
            bytes_sent: 0,
            bytes_received: 0,
            connected_since: None,
            uptime: None,
        })
    }

    /// Generate CA certificate and key
    pub async fn generate_ca(&self, common_name: &str) -> Result<()> {
        fs::create_dir_all(&self.config_dir).await
            .map_err(|e| Error::Network(format!("Failed to create config directory: {}", e)))?;

        // Generate CA key
        Command::new("openssl")
            .args(&["genrsa", "-out"])
            .arg(self.config_dir.join("ca.key"))
            .arg("4096")
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate CA key: {}", e)))?;

        // Generate CA certificate
        Command::new("openssl")
            .args(&["req", "-new", "-x509", "-days", "3650", "-key"])
            .arg(self.config_dir.join("ca.key"))
            .args(&["-out"])
            .arg(self.config_dir.join("ca.crt"))
            .args(&["-subj", &format!("/CN={}", common_name)])
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate CA certificate: {}", e)))?;

        Ok(())
    }

    /// Generate server certificate and key
    pub async fn generate_server_cert(&self, common_name: &str) -> Result<()> {
        // Generate server key
        Command::new("openssl")
            .args(&["genrsa", "-out"])
            .arg(self.config_dir.join("server.key"))
            .arg("4096")
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate server key: {}", e)))?;

        // Generate server certificate request
        Command::new("openssl")
            .args(&["req", "-new", "-key"])
            .arg(self.config_dir.join("server.key"))
            .args(&["-out"])
            .arg(self.config_dir.join("server.csr"))
            .args(&["-subj", &format!("/CN={}", common_name)])
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate server CSR: {}", e)))?;

        // Sign server certificate
        Command::new("openssl")
            .args(&["x509", "-req", "-in"])
            .arg(self.config_dir.join("server.csr"))
            .args(&["-CA"])
            .arg(self.config_dir.join("ca.crt"))
            .args(&["-CAkey"])
            .arg(self.config_dir.join("ca.key"))
            .args(&["-CAcreateserial", "-out"])
            .arg(self.config_dir.join("server.crt"))
            .args(&["-days", "3650"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to sign server certificate: {}", e)))?;

        Ok(())
    }

    /// Generate Diffie-Hellman parameters
    pub async fn generate_dh_params(&self, bits: u32) -> Result<()> {
        Command::new("openssl")
            .args(&["dhparam", "-out"])
            .arg(self.config_dir.join(format!("dh{}.pem", bits)))
            .arg(bits.to_string())
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate DH params: {}", e)))?;

        Ok(())
    }

    /// Generate TLS authentication key
    pub async fn generate_tls_key(&self) -> Result<()> {
        Command::new("openvpn")
            .args(&["--genkey", "--secret"])
            .arg(self.config_dir.join("ta.key"))
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate TLS key: {}", e)))?;

        Ok(())
    }

    /// Generate client certificate and key
    pub async fn generate_client_cert(&self, client_name: &str) -> Result<()> {
        let client_dir = self.config_dir.join("clients").join(client_name);
        fs::create_dir_all(&client_dir).await
            .map_err(|e| Error::Network(format!("Failed to create client directory: {}", e)))?;

        // Generate client key
        Command::new("openssl")
            .args(&["genrsa", "-out"])
            .arg(client_dir.join("client.key"))
            .arg("4096")
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate client key: {}", e)))?;

        // Generate client certificate request
        Command::new("openssl")
            .args(&["req", "-new", "-key"])
            .arg(client_dir.join("client.key"))
            .args(&["-out"])
            .arg(client_dir.join("client.csr"))
            .args(&["-subj", &format!("/CN={}", client_name)])
            .output()
            .map_err(|e| Error::Network(format!("Failed to generate client CSR: {}", e)))?;

        // Sign client certificate
        Command::new("openssl")
            .args(&["x509", "-req", "-in"])
            .arg(client_dir.join("client.csr"))
            .args(&["-CA"])
            .arg(self.config_dir.join("ca.crt"))
            .args(&["-CAkey"])
            .arg(self.config_dir.join("ca.key"))
            .args(&["-CAcreateserial", "-out"])
            .arg(client_dir.join("client.crt"))
            .args(&["-days", "3650"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to sign client certificate: {}", e)))?;

        Ok(())
    }

    /// Export client configuration as a single .ovpn file
    pub async fn export_client_config(&self, config: &OpenVpnClientConfig) -> Result<String> {
        let mut ovpn = self.generate_client_config(config)?;

        // Read and embed certificates
        let ca_cert = fs::read_to_string(&config.ca_cert_path).await
            .map_err(|e| Error::Network(format!("Failed to read CA cert: {}", e)))?;
        let client_cert = fs::read_to_string(&config.client_cert_path).await
            .map_err(|e| Error::Network(format!("Failed to read client cert: {}", e)))?;
        let client_key = fs::read_to_string(&config.client_key_path).await
            .map_err(|e| Error::Network(format!("Failed to read client key: {}", e)))?;

        ovpn.push_str("\n<ca>\n");
        ovpn.push_str(&ca_cert);
        ovpn.push_str("</ca>\n");

        ovpn.push_str("\n<cert>\n");
        ovpn.push_str(&client_cert);
        ovpn.push_str("</cert>\n");

        ovpn.push_str("\n<key>\n");
        ovpn.push_str(&client_key);
        ovpn.push_str("</key>\n");

        // Embed TLS key if present
        if config.tls_crypt || config.tls_auth {
            if let Some(tls_key_path) = &config.tls_key_path {
                let tls_key = fs::read_to_string(tls_key_path).await
                    .map_err(|e| Error::Network(format!("Failed to read TLS key: {}", e)))?;

                if config.tls_crypt {
                    ovpn.push_str("\n<tls-crypt>\n");
                    ovpn.push_str(&tls_key);
                    ovpn.push_str("</tls-crypt>\n");
                } else {
                    ovpn.push_str("\n<tls-auth>\n");
                    ovpn.push_str(&tls_key);
                    ovpn.push_str("</tls-auth>\n");
                    ovpn.push_str("key-direction 1\n");
                }
            }
        }

        Ok(ovpn)
    }

    /// List connected clients (server only)
    pub async fn list_connected_clients(&self, server_name: &str) -> Result<Vec<OpenVpnClient>> {
        // This would parse the status log file
        // For now, return empty vector
        Ok(vec![])
    }
}

impl Default for OpenVpnManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_generation() {
        let manager = OpenVpnManager::new();
        let config = OpenVpnServerConfig::default();

        let conf = manager.generate_server_config(&config).unwrap();

        assert!(conf.contains("mode server"));
        assert!(conf.contains("proto udp"));
        assert!(conf.contains("port 1194"));
    }

    #[test]
    fn test_client_config_generation() {
        let manager = OpenVpnManager::new();
        let config = OpenVpnClientConfig {
            name: "client1".to_string(),
            enabled: true,
            remote_host: "vpn.example.com".to_string(),
            remote_port: 1194,
            protocol: OpenVpnProtocol::Udp,
            device: "tun".to_string(),
            cipher: OpenVpnCipher::Aes256Gcm,
            auth: OpenVpnAuth::Sha256,
            compression: false,
            verify_x509_name: Some("vpn.example.com".to_string()),
            ca_cert_path: PathBuf::from("/etc/patronus/openvpn/ca.crt"),
            client_cert_path: PathBuf::from("/etc/patronus/openvpn/client.crt"),
            client_key_path: PathBuf::from("/etc/patronus/openvpn/client.key"),
            tls_auth: false,
            tls_crypt: true,
            tls_key_path: Some(PathBuf::from("/etc/patronus/openvpn/ta.key")),
        };

        let conf = manager.generate_client_config(&config).unwrap();

        assert!(conf.contains("client"));
        assert!(conf.contains("remote vpn.example.com 1194"));
    }
}
