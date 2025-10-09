//! Certificate Management
//!
//! Provides automated certificate management with support for:
//! - **ACME (acme.sh)**: Lightweight, pure shell script
//! - **Certbot**: Official Let's Encrypt client
//!
//! The Gentoo Way: Choice of backends!

use crate::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

/// Certificate backend
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertBackend {
    /// acme.sh - Lightweight shell script
    AcmeSh,
    /// Certbot - Official Let's Encrypt client
    Certbot,
}

impl std::fmt::Display for CertBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertBackend::AcmeSh => write!(f, "acme.sh"),
            CertBackend::Certbot => write!(f, "certbot"),
        }
    }
}

/// ACME challenge method
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcmeChallenge {
    /// HTTP-01: Serves challenge via HTTP (port 80)
    Http01,
    /// DNS-01: Creates TXT record (works with wildcard)
    Dns01 { provider: String },
    /// TLS-ALPN-01: Uses TLS with ALPN extension
    TlsAlpn01,
}

/// Certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    pub name: String,
    pub enabled: bool,
    pub domains: Vec<String>,  // First is primary, rest are SANs
    pub email: String,
    pub challenge: AcmeChallenge,
    pub key_type: KeyType,
    pub key_length: u32,
    pub auto_renew: bool,
    pub renew_days_before: u32,  // Renew when this many days before expiry
    pub post_renew_hook: Option<String>,  // Command to run after renewal
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    RSA,
    ECDSA,
}

/// Certificate status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertStatus {
    pub name: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub days_remaining: i64,
    pub key_type: String,
    pub needs_renewal: bool,
}

pub struct CertManager {
    backend: CertBackend,
    config_dir: PathBuf,
    certs_dir: PathBuf,
}

impl CertManager {
    pub fn new(backend: CertBackend) -> Self {
        let (config_dir, certs_dir) = match backend {
            CertBackend::AcmeSh => (
                PathBuf::from("/etc/patronus/certs/acme"),
                PathBuf::from("/etc/patronus/certs/acme/certs"),
            ),
            CertBackend::Certbot => (
                PathBuf::from("/etc/letsencrypt"),
                PathBuf::from("/etc/letsencrypt/live"),
            ),
        };

        Self {
            backend,
            config_dir,
            certs_dir,
        }
    }

    /// Auto-detect available certificate backend
    pub fn new_auto() -> Self {
        let backend = Self::detect_backend();
        Self::new(backend)
    }

    /// Detect which backend is available
    pub fn detect_backend() -> CertBackend {
        if Self::is_command_available("acme.sh") {
            CertBackend::AcmeSh
        } else if Self::is_command_available("certbot") {
            CertBackend::Certbot
        } else {
            CertBackend::AcmeSh  // Default preference
        }
    }

    /// List all available backends
    pub fn list_available_backends() -> Vec<CertBackend> {
        let mut backends = Vec::new();

        if Self::is_command_available("acme.sh") {
            backends.push(CertBackend::AcmeSh);
        }

        if Self::is_command_available("certbot") {
            backends.push(CertBackend::Certbot);
        }

        backends
    }

    fn is_command_available(cmd: &str) -> bool {
        std::process::Command::new("which")
            .arg(cmd)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Issue a new certificate
    pub async fn issue_certificate(&self, config: &CertConfig) -> Result<()> {
        fs::create_dir_all(&self.config_dir).await?;
        fs::create_dir_all(&self.certs_dir).await?;

        match self.backend {
            CertBackend::AcmeSh => self.issue_acmesh(config).await,
            CertBackend::Certbot => self.issue_certbot(config).await,
        }
    }

    async fn issue_acmesh(&self, config: &CertConfig) -> Result<()> {
        let mut cmd = Command::new("acme.sh");

        cmd.arg("--issue");

        // Domains
        cmd.arg("-d").arg(&config.domains[0]);
        for san in &config.domains[1..] {
            cmd.arg("-d").arg(san);
        }

        // Challenge type
        match &config.challenge {
            AcmeChallenge::Http01 => {
                cmd.arg("-w").arg("/var/www/acme");
            }
            AcmeChallenge::Dns01 { provider } => {
                cmd.arg("--dns").arg(provider);
            }
            AcmeChallenge::TlsAlpn01 => {
                cmd.arg("--alpn");
            }
        }

        // Key type
        match config.key_type {
            KeyType::RSA => {
                cmd.arg("--keylength").arg(config.key_length.to_string());
            }
            KeyType::ECDSA => {
                cmd.arg("--keylength")
                    .arg(format!("ec-{}", config.key_length));
            }
        }

        // Email
        cmd.arg("--accountemail").arg(&config.email);

        // Execute
        cmd.spawn()
            .map_err(|e| Error::Service(format!("Failed to run acme.sh: {}", e)))?
            .wait()
            .await
            .map_err(|e| Error::Service(format!("acme.sh failed: {}", e)))?;

        Ok(())
    }

    async fn issue_certbot(&self, config: &CertConfig) -> Result<()> {
        let mut cmd = Command::new("certbot");

        cmd.arg("certonly");
        cmd.arg("--non-interactive");
        cmd.arg("--agree-tos");

        // Email
        cmd.arg("--email").arg(&config.email);

        // Domains
        for domain in &config.domains {
            cmd.arg("-d").arg(domain);
        }

        // Challenge type
        match &config.challenge {
            AcmeChallenge::Http01 => {
                cmd.arg("--standalone");
                cmd.arg("--http-01-port").arg("80");
            }
            AcmeChallenge::Dns01 { provider } => {
                cmd.arg("--dns-").arg(provider);
            }
            AcmeChallenge::TlsAlpn01 => {
                cmd.arg("--standalone");
                cmd.arg("--preferred-challenges").arg("tls-alpn-01");
            }
        }

        // Key type
        match config.key_type {
            KeyType::RSA => {
                cmd.arg("--rsa-key-size").arg(config.key_length.to_string());
            }
            KeyType::ECDSA => {
                cmd.arg("--key-type").arg("ecdsa");
                cmd.arg("--elliptic-curve").arg(match config.key_length {
                    256 => "secp256r1",
                    384 => "secp384r1",
                    _ => "secp256r1",
                });
            }
        }

        // Execute
        cmd.spawn()
            .map_err(|e| Error::Service(format!("Failed to run certbot: {}", e)))?
            .wait()
            .await
            .map_err(|e| Error::Service(format!("certbot failed: {}", e)))?;

        Ok(())
    }

    /// Renew a certificate
    pub async fn renew_certificate(&self, domain: &str) -> Result<()> {
        match self.backend {
            CertBackend::AcmeSh => {
                Command::new("acme.sh")
                    .arg("--renew")
                    .arg("-d")
                    .arg(domain)
                    .arg("--force")
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to renew cert: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Renewal failed: {}", e)))?;
            }
            CertBackend::Certbot => {
                Command::new("certbot")
                    .arg("renew")
                    .arg("--cert-name")
                    .arg(domain)
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to renew cert: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Renewal failed: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Renew all certificates that are close to expiry
    pub async fn renew_all(&self) -> Result<()> {
        match self.backend {
            CertBackend::AcmeSh => {
                Command::new("acme.sh")
                    .arg("--cron")
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to run renewal: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Renewal failed: {}", e)))?;
            }
            CertBackend::Certbot => {
                Command::new("certbot")
                    .arg("renew")
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to run renewal: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Renewal failed: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, domain: &str) -> Result<()> {
        match self.backend {
            CertBackend::AcmeSh => {
                Command::new("acme.sh")
                    .arg("--revoke")
                    .arg("-d")
                    .arg(domain)
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to revoke cert: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Revocation failed: {}", e)))?;
            }
            CertBackend::Certbot => {
                Command::new("certbot")
                    .arg("revoke")
                    .arg("--cert-name")
                    .arg(domain)
                    .spawn()
                    .map_err(|e| Error::Service(format!("Failed to revoke cert: {}", e)))?
                    .wait()
                    .await
                    .map_err(|e| Error::Service(format!("Revocation failed: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Get certificate paths
    pub fn get_cert_paths(&self, domain: &str) -> CertPaths {
        match self.backend {
            CertBackend::AcmeSh => CertPaths {
                cert: self.certs_dir.join(domain).join(format!("{}.cer", domain)),
                key: self.certs_dir.join(domain).join(format!("{}.key", domain)),
                chain: self.certs_dir.join(domain).join("ca.cer"),
                fullchain: self.certs_dir.join(domain).join("fullchain.cer"),
            },
            CertBackend::Certbot => CertPaths {
                cert: self.certs_dir.join(domain).join("cert.pem"),
                key: self.certs_dir.join(domain).join("privkey.pem"),
                chain: self.certs_dir.join(domain).join("chain.pem"),
                fullchain: self.certs_dir.join(domain).join("fullchain.pem"),
            },
        }
    }

    /// List all certificates
    pub async fn list_certificates(&self) -> Result<Vec<CertStatus>> {
        match self.backend {
            CertBackend::AcmeSh => {
                let output = Command::new("acme.sh")
                    .arg("--list")
                    .output()
                    .await
                    .map_err(|e| Error::Service(format!("Failed to list certs: {}", e)))?;

                // Parse output (simplified)
                Ok(Vec::new())
            }
            CertBackend::Certbot => {
                let output = Command::new("certbot")
                    .arg("certificates")
                    .output()
                    .await
                    .map_err(|e| Error::Service(format!("Failed to list certs: {}", e)))?;

                // Parse output (simplified)
                Ok(Vec::new())
            }
        }
    }

    /// Install auto-renewal cron job
    pub async fn setup_auto_renewal(&self) -> Result<()> {
        let cron_entry = match self.backend {
            CertBackend::AcmeSh => {
                "0 0 * * * /usr/bin/acme.sh --cron --home /etc/patronus/certs/acme > /dev/null\n"
            }
            CertBackend::Certbot => {
                "0 0,12 * * * /usr/bin/certbot renew --quiet\n"
            }
        };

        let cron_file = PathBuf::from("/etc/cron.d/patronus-certs");
        fs::write(&cron_file, cron_entry).await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub chain: PathBuf,
    pub fullchain: PathBuf,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            enabled: false,
            domains: vec!["example.com".to_string()],
            email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Http01,
            key_type: KeyType::ECDSA,
            key_length: 256,
            auto_renew: true,
            renew_days_before: 30,
            post_renew_hook: None,
        }
    }
}

/// Common DNS providers for DNS-01 challenge
pub struct DnsProviders;

impl DnsProviders {
    pub const CLOUDFLARE: &'static str = "dns_cf";
    pub const ROUTE53: &'static str = "dns_aws";
    pub const DIGITALOCEAN: &'static str = "dns_dgon";
    pub const NAMECHEAP: &'static str = "dns_namecheap";
    pub const GANDI: &'static str = "dns_gandi";
    pub const LINODE: &'static str = "dns_linode";
    pub const HETZNER: &'static str = "dns_hetzner";
    pub const OVH: &'static str = "dns_ovh";
}
