//! OpenVPN Client Export Utility
//!
//! Automatically generates client configuration files and certificates
//! for easy distribution to VPN users. Huge usability improvement!

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::process::Command;

/// Client export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientExportConfig {
    pub server_address: String,  // Public hostname or IP
    pub server_port: u16,
    pub protocol: ExportProtocol,

    // Certificate Authority
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,

    // Server certificate
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,

    // TLS auth
    pub tls_auth_key_path: Option<PathBuf>,
    pub tls_crypt_key_path: Option<PathBuf>,

    // Client defaults
    pub use_compression: bool,
    pub redirect_gateway: bool,
    pub use_server_dns: bool,
    pub dns_servers: Vec<String>,

    // Advanced
    pub cipher: String,
    pub auth_digest: String,
    pub tls_version_min: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportProtocol {
    UDP,
    TCP,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Ovpn,          // Single .ovpn file with embedded certs (best)
    Separate,      // Multiple files (ovpn + certs)
    Archive,       // ZIP archive with all files
}

/// Client export package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPackage {
    pub username: String,
    pub config_file: String,      // .ovpn content
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub tls_auth_key: Option<String>,
}

pub struct OpenVpnExporter {
    config: ClientExportConfig,
}

impl OpenVpnExporter {
    pub fn new(config: ClientExportConfig) -> Self {
        Self { config }
    }

    /// Generate client configuration and certificates
    pub async fn export_client(&self, username: &str, format: ExportFormat) -> Result<ClientPackage> {
        tracing::info!("Exporting OpenVPN client config for {}", username);

        // Generate client certificate if needed
        let (client_cert_path, client_key_path) = self.generate_client_cert(username).await?;

        // Read certificates
        let ca_cert = tokio::fs::read_to_string(&self.config.ca_cert_path).await?;
        let client_cert = tokio::fs::read_to_string(&client_cert_path).await?;
        let client_key = tokio::fs::read_to_string(&client_key_path).await?;

        let tls_auth_key = if let Some(path) = &self.config.tls_auth_key_path {
            Some(tokio::fs::read_to_string(path).await?)
        } else if let Some(path) = &self.config.tls_crypt_key_path {
            Some(tokio::fs::read_to_string(path).await?)
        } else {
            None
        };

        // Generate config file
        let config_content = match format {
            ExportFormat::Ovpn => {
                // Embed everything in single .ovpn file
                self.generate_inline_config(&ca_cert, &client_cert, &client_key, tls_auth_key.as_ref())
            }
            ExportFormat::Separate | ExportFormat::Archive => {
                // Reference external cert files
                self.generate_reference_config(username)
            }
        };

        Ok(ClientPackage {
            username: username.to_string(),
            config_file: config_content,
            ca_cert: if format != ExportFormat::Ovpn { Some(ca_cert) } else { None },
            client_cert: if format != ExportFormat::Ovpn { Some(client_cert) } else { None },
            client_key: if format != ExportFormat::Ovpn { Some(client_key) } else { None },
            tls_auth_key: if format != ExportFormat::Ovpn { tls_auth_key } else { None },
        })
    }

    async fn generate_client_cert(&self, username: &str) -> Result<(PathBuf, PathBuf)> {
        let cert_dir = PathBuf::from("/etc/openvpn/clients");
        tokio::fs::create_dir_all(&cert_dir).await?;

        let cert_path = cert_dir.join(format!("{}.crt", username));
        let key_path = cert_dir.join(format!("{}.key", username));

        // Check if certificate already exists
        if cert_path.exists() && key_path.exists() {
            tracing::info!("Using existing certificate for {}", username);
            return Ok((cert_path, key_path));
        }

        tracing::info!("Generating new certificate for {}", username);

        // Generate client key
        Command::new("openssl")
            .args(&[
                "genrsa",
                "-out", key_path.to_str().unwrap(),
                "2048"
            ])
            .status()
            .await?;

        // Generate certificate signing request
        let csr_path = cert_dir.join(format!("{}.csr", username));
        Command::new("openssl")
            .args(&[
                "req",
                "-new",
                "-key", key_path.to_str().unwrap(),
                "-out", csr_path.to_str().unwrap(),
                "-subj", &format!("/CN={}", username)
            ])
            .status()
            .await?;

        // Sign certificate with CA
        Command::new("openssl")
            .args(&[
                "x509",
                "-req",
                "-in", csr_path.to_str().unwrap(),
                "-CA", self.config.ca_cert_path.to_str().unwrap(),
                "-CAkey", self.config.ca_key_path.to_str().unwrap(),
                "-CAcreateserial",
                "-out", cert_path.to_str().unwrap(),
                "-days", "365",
                "-sha256"
            ])
            .status()
            .await?;

        // Clean up CSR
        tokio::fs::remove_file(csr_path).await?;

        // Set secure permissions on private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = tokio::fs::metadata(&key_path).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            tokio::fs::set_permissions(&key_path, perms).await?;
        }

        Ok((cert_path, key_path))
    }

    fn generate_inline_config(&self, ca_cert: &str, client_cert: &str, client_key: &str, tls_auth_key: Option<&String>) -> String {
        let mut config = self.generate_base_config();

        // Embed CA certificate
        config.push_str("\n<ca>\n");
        config.push_str(ca_cert);
        config.push_str("</ca>\n");

        // Embed client certificate
        config.push_str("\n<cert>\n");
        config.push_str(client_cert);
        config.push_str("</cert>\n");

        // Embed client key
        config.push_str("\n<key>\n");
        config.push_str(client_key);
        config.push_str("</key>\n");

        // Embed TLS auth/crypt key
        if let Some(key) = tls_auth_key {
            if self.config.tls_crypt_key_path.is_some() {
                config.push_str("\n<tls-crypt>\n");
                config.push_str(key);
                config.push_str("</tls-crypt>\n");
            } else {
                config.push_str("\nkey-direction 1\n");
                config.push_str("<tls-auth>\n");
                config.push_str(key);
                config.push_str("</tls-auth>\n");
            }
        }

        config
    }

    fn generate_reference_config(&self, username: &str) -> String {
        let mut config = self.generate_base_config();

        // Reference external certificate files
        config.push_str("\n# Certificate files\n");
        config.push_str("ca ca.crt\n");
        config.push_str(&format!("cert {}.crt\n", username));
        config.push_str(&format!("key {}.key\n", username));

        if self.config.tls_auth_key_path.is_some() {
            config.push_str("tls-auth ta.key 1\n");
        } else if self.config.tls_crypt_key_path.is_some() {
            config.push_str("tls-crypt tc.key\n");
        }

        config
    }

    fn generate_base_config(&self) -> String {
        let mut config = String::from("# OpenVPN Client Configuration\n");
        config.push_str("# Generated by Patronus\n\n");

        config.push_str("client\n");
        config.push_str("dev tun\n");

        // Protocol
        match self.config.protocol {
            ExportProtocol::UDP => config.push_str("proto udp\n"),
            ExportProtocol::TCP => config.push_str("proto tcp-client\n"),
        }

        // Server
        config.push_str(&format!("remote {} {}\n",
            self.config.server_address, self.config.server_port));

        // Resolution
        config.push_str("resolv-retry infinite\n");
        config.push_str("nobind\n");

        // User/group (drop privileges)
        #[cfg(target_os = "linux")]
        {
            config.push_str("user nobody\n");
            config.push_str("group nogroup\n");
        }

        // Persistence
        config.push_str("persist-key\n");
        config.push_str("persist-tun\n");

        // Routing
        if self.config.redirect_gateway {
            config.push_str("redirect-gateway def1\n");
        }

        // DNS
        if self.config.use_server_dns {
            config.push_str("dhcp-option DNS-push\n");
        }

        for dns in &self.config.dns_servers {
            config.push_str(&format!("dhcp-option DNS {}\n", dns));
        }

        // Compression
        if self.config.use_compression {
            config.push_str("compress lz4-v2\n");
            config.push_str("push \"compress lz4-v2\"\n");
        }

        // Security
        config.push_str(&format!("cipher {}\n", self.config.cipher));
        config.push_str(&format!("auth {}\n", self.config.auth_digest));
        config.push_str(&format!("tls-version-min {}\n", self.config.tls_version_min));

        // Remote certificate verification
        config.push_str("remote-cert-tls server\n");

        // Logging
        config.push_str("verb 3\n");
        config.push_str("mute 20\n");

        config
    }

    /// Revoke a client certificate
    pub async fn revoke_client(&self, username: &str) -> Result<()> {
        tracing::info!("Revoking certificate for {}", username);

        let cert_path = PathBuf::from(format!("/etc/openvpn/clients/{}.crt", username));

        if !cert_path.exists() {
            return Err(Error::Config(format!("Certificate for {} not found", username)));
        }

        // Revoke with OpenSSL
        Command::new("openssl")
            .args(&[
                "ca",
                "-revoke", cert_path.to_str().unwrap(),
                "-config", "/etc/openvpn/ca/openssl.cnf"
            ])
            .status()
            .await?;

        // Update CRL
        self.update_crl().await?;

        Ok(())
    }

    async fn update_crl(&self) -> Result<()> {
        // Generate Certificate Revocation List
        Command::new("openssl")
            .args(&[
                "ca",
                "-gencrl",
                "-out", "/etc/openvpn/crl.pem",
                "-config", "/etc/openvpn/ca/openssl.cnf"
            ])
            .status()
            .await?;

        Ok(())
    }

    /// List all exported clients
    pub async fn list_clients(&self) -> Result<Vec<String>> {
        let cert_dir = PathBuf::from("/etc/openvpn/clients");

        if !cert_dir.exists() {
            return Ok(vec![]);
        }

        let mut clients = Vec::new();
        let mut entries = tokio::fs::read_dir(&cert_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "crt" {
                    if let Some(name) = path.file_stem() {
                        clients.push(name.to_string_lossy().to_string());
                    }
                }
            }
        }

        Ok(clients)
    }

    /// Export client package as ZIP archive
    pub async fn export_as_archive(&self, username: &str) -> Result<Vec<u8>> {
        let package = self.export_client(username, ExportFormat::Archive).await?;

        // Create ZIP archive (simplified - would use zip crate in production)
        let mut archive_data = Vec::new();

        // In production, use zip crate to create proper archive
        // with config file, certificates, README, etc.

        Ok(archive_data)
    }

    /// Generate installation instructions
    pub fn generate_instructions(&self, username: &str, platform: ClientPlatform) -> String {
        match platform {
            ClientPlatform::Windows => {
                format!(r#"# OpenVPN Installation - Windows

1. Download and install OpenVPN GUI from:
   https://openvpn.net/community-downloads/

2. Extract the contents of this ZIP file to:
   C:\Program Files\OpenVPN\config\

3. Right-click the OpenVPN GUI icon in system tray
   and select "Connect"

Your VPN username: {}
"#, username)
            }
            ClientPlatform::MacOS => {
                format!(r#"# OpenVPN Installation - macOS

1. Download and install Tunnelblick from:
   https://tunnelblick.net/

2. Double-click the {}.ovpn file to import

3. Click "Connect" in Tunnelblick menu

Your VPN username: {}
"#, username, username)
            }
            ClientPlatform::Linux => {
                format!(r#"# OpenVPN Installation - Linux

1. Install OpenVPN:
   sudo apt-get install openvpn
   # or
   sudo yum install openvpn

2. Copy configuration:
   sudo cp {}.ovpn /etc/openvpn/client/

3. Start VPN:
   sudo systemctl start openvpn-client@{}

Your VPN username: {}
"#, username, username, username)
            }
            ClientPlatform::Android => {
                format!(r#"# OpenVPN Installation - Android

1. Install "OpenVPN for Android" from Google Play Store

2. Import the {}.ovpn file

3. Tap to connect

Your VPN username: {}
"#, username, username)
            }
            ClientPlatform::iOS => {
                format!(r#"# OpenVPN Installation - iOS

1. Install "OpenVPN Connect" from App Store

2. Import the {}.ovpn file via:
   - iTunes file sharing, or
   - Email attachment, or
   - AirDrop

3. Tap to connect

Your VPN username: {}
"#, username, username)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Windows,
    MacOS,
    Linux,
    Android,
    iOS,
}

impl Default for ClientExportConfig {
    fn default() -> Self {
        Self {
            server_address: "vpn.example.com".to_string(),
            server_port: 1194,
            protocol: ExportProtocol::UDP,
            ca_cert_path: PathBuf::from("/etc/openvpn/ca.crt"),
            ca_key_path: PathBuf::from("/etc/openvpn/ca.key"),
            server_cert_path: PathBuf::from("/etc/openvpn/server.crt"),
            server_key_path: PathBuf::from("/etc/openvpn/server.key"),
            tls_auth_key_path: Some(PathBuf::from("/etc/openvpn/ta.key")),
            tls_crypt_key_path: None,
            use_compression: true,
            redirect_gateway: true,
            use_server_dns: true,
            dns_servers: vec![],
            cipher: "AES-256-GCM".to_string(),
            auth_digest: "SHA256".to_string(),
            tls_version_min: "1.2".to_string(),
        }
    }
}
