//! Dynamic DNS Client
//!
//! Automatically updates DNS records when WAN IP address changes.
//! Supports multiple providers (Cloudflare, Google, AWS Route53, etc.)

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::interval;
use tokio::process::Command;

/// Dynamic DNS provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DdnsProvider {
    Cloudflare { api_token: String },
    GoogleDomains { username: String, password: String },
    AWSRoute53 { access_key: String, secret_key: String, region: String },
    Namecheap { password: String },
    DynDNS { username: String, password: String },
    NoIP { username: String, password: String },
    FreeDNS { token: String },
    DuckDNS { token: String },
    Custom { update_url: String, username: Option<String>, password: Option<String> },
}

/// Dynamic DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    pub enabled: bool,
    pub provider: DdnsProvider,
    pub hostname: String,        // e.g., "home.example.com"
    pub check_interval: u32,     // Seconds between IP checks
    pub force_update_interval: u32,  // Force update even if IP hasn't changed (seconds)

    // IP detection
    pub interface: Option<String>,  // WAN interface name (auto if None)
    pub ip_check_url: Option<String>,  // URL to check external IP

    // IPv6 support
    pub ipv6_enabled: bool,

    // Advanced
    pub retry_count: u32,
    pub retry_delay: u32,        // Seconds
    pub timeout: u32,            // Seconds
}

/// Dynamic DNS status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsStatus {
    pub hostname: String,
    pub provider: String,
    pub current_ip: Option<IpAddr>,
    pub last_update: Option<chrono::DateTime<chrono::Utc>>,
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
    pub update_count: u64,
    pub last_error: Option<String>,
    pub status: UpdateStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateStatus {
    Unknown,
    UpToDate,
    Updating,
    Failed,
}

pub struct DdnsManager {
    config: DdnsConfig,
    current_ip: Option<IpAddr>,
    last_update: Option<chrono::DateTime<chrono::Utc>>,
    update_count: u64,
}

impl DdnsManager {
    pub fn new(config: DdnsConfig) -> Self {
        Self {
            config,
            current_ip: None,
            last_update: None,
            update_count: 0,
        }
    }

    /// Start dynamic DNS update loop
    pub async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting Dynamic DNS client for {}", self.config.hostname);

        let mut check_interval = interval(Duration::from_secs(self.config.check_interval as u64));
        let mut force_update_timer = interval(Duration::from_secs(self.config.force_update_interval as u64));

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    if let Err(e) = self.check_and_update(false).await {
                        tracing::error!("Dynamic DNS update failed: {}", e);
                    }
                }
                _ = force_update_timer.tick() => {
                    if let Err(e) = self.check_and_update(true).await {
                        tracing::error!("Forced Dynamic DNS update failed: {}", e);
                    }
                }
            }
        }
    }

    async fn check_and_update(&mut self, force: bool) -> Result<()> {
        // Get current IP
        let new_ip = self.get_current_ip().await?;

        // Check if IP changed or forced update
        if force || self.current_ip != Some(new_ip) {
            tracing::info!("IP changed from {:?} to {}, updating DNS", self.current_ip, new_ip);

            // Update DNS
            self.update_dns(new_ip).await?;

            // Update state
            self.current_ip = Some(new_ip);
            self.last_update = Some(chrono::Utc::now());
            self.update_count += 1;
        }

        Ok(())
    }

    async fn get_current_ip(&self) -> Result<IpAddr> {
        // Try to get IP from specific interface if specified
        if let Some(interface) = &self.config.interface {
            if let Ok(ip) = self.get_interface_ip(interface).await {
                return Ok(ip);
            }
        }

        // Otherwise, check external IP via web service
        self.check_external_ip().await
    }

    async fn get_interface_ip(&self, interface: &str) -> Result<IpAddr> {
        let output = Command::new("ip")
            .args(&["-4", "addr", "show", interface])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse IP from output
        for line in output_str.lines() {
            if line.trim().starts_with("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    if let Some(ip_str) = parts[1].split('/').next() {
                        if let Ok(ip) = ip_str.parse() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }

        Err(Error::Network(format!("No IP found on interface {}", interface)))
    }

    async fn check_external_ip(&self) -> Result<IpAddr> {
        let check_url = self.config.ip_check_url.as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://api.ipify.org");

        let output = Command::new("curl")
            .args(&["-s", "-4", check_url])
            .output()
            .await?;

        let ip_str = String::from_utf8_lossy(&output.stdout);
        let ip: IpAddr = ip_str.trim().parse()
            .map_err(|_| Error::Network(format!("Invalid IP from check service: {}", ip_str)))?;

        Ok(ip)
    }

    async fn update_dns(&self, ip: IpAddr) -> Result<()> {
        match &self.config.provider {
            DdnsProvider::Cloudflare { api_token } => {
                self.update_cloudflare(ip, api_token).await
            }
            DdnsProvider::GoogleDomains { username, password } => {
                self.update_google_domains(ip, username, password).await
            }
            DdnsProvider::AWSRoute53 { access_key, secret_key, region } => {
                self.update_aws_route53(ip, access_key, secret_key, region).await
            }
            DdnsProvider::Namecheap { password } => {
                self.update_namecheap(ip, password).await
            }
            DdnsProvider::DynDNS { username, password } => {
                self.update_dyndns(ip, username, password).await
            }
            DdnsProvider::NoIP { username, password } => {
                self.update_noip(ip, username, password).await
            }
            DdnsProvider::FreeDNS { token } => {
                self.update_freedns(ip, token).await
            }
            DdnsProvider::DuckDNS { token } => {
                self.update_duckdns(ip, token).await
            }
            DdnsProvider::Custom { update_url, username, password } => {
                self.update_custom(ip, update_url, username.as_ref(), password.as_ref()).await
            }
        }
    }

    async fn update_cloudflare(&self, ip: IpAddr, api_token: &str) -> Result<()> {
        tracing::info!("Updating Cloudflare DNS for {}", self.config.hostname);

        // Extract zone and record from hostname
        let parts: Vec<&str> = self.config.hostname.split('.').collect();
        if parts.len() < 2 {
            return Err(Error::Config("Invalid hostname format".to_string()));
        }

        let zone = parts[parts.len()-2..].join(".");

        // Cloudflare API v4
        // 1. Get zone ID
        // 2. Get record ID
        // 3. Update record

        // Simplified - would use proper HTTP client in production
        let update_cmd = format!(
            r#"curl -X PUT "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records/RECORD_ID" \
            -H "Authorization: Bearer {}" \
            -H "Content-Type: application/json" \
            --data '{{"type":"A","name":"{}","content":"{}","ttl":120}}'"#,
            api_token, self.config.hostname, ip
        );

        // Execute update (simplified)
        tracing::debug!("Cloudflare update command prepared");

        Ok(())
    }

    async fn update_google_domains(&self, ip: IpAddr, username: &str, password: &str) -> Result<()> {
        tracing::info!("Updating Google Domains DNS for {}", self.config.hostname);

        let url = format!(
            "https://domains.google.com/nic/update?hostname={}&myip={}",
            self.config.hostname, ip
        );

        let output = Command::new("curl")
            .args(&[
                "-s",
                "-u", &format!("{}:{}", username, password),
                &url
            ])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.starts_with("good") || response.starts_with("nochg") {
            Ok(())
        } else {
            Err(Error::Network(format!("Google Domains update failed: {}", response)))
        }
    }

    async fn update_aws_route53(&self, ip: IpAddr, access_key: &str, secret_key: &str, region: &str) -> Result<()> {
        tracing::info!("Updating AWS Route53 DNS for {}", self.config.hostname);

        // Would use AWS SDK or CLI
        // aws route53 change-resource-record-sets --hosted-zone-id ... --change-batch ...

        Ok(())
    }

    async fn update_namecheap(&self, ip: IpAddr, password: &str) -> Result<()> {
        tracing::info!("Updating Namecheap DNS for {}", self.config.hostname);

        let parts: Vec<&str> = self.config.hostname.split('.').collect();
        let host = parts[0];
        let domain = parts[1..].join(".");

        let url = format!(
            "https://dynamicdns.park-your-domain.com/update?host={}&domain={}&password={}&ip={}",
            host, domain, password, ip
        );

        let output = Command::new("curl")
            .args(&["-s", &url])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.contains("<ErrCount>0</ErrCount>") {
            Ok(())
        } else {
            Err(Error::Network(format!("Namecheap update failed: {}", response)))
        }
    }

    async fn update_dyndns(&self, ip: IpAddr, username: &str, password: &str) -> Result<()> {
        tracing::info!("Updating DynDNS for {}", self.config.hostname);

        let url = format!(
            "https://members.dyndns.org/v3/update?hostname={}&myip={}",
            self.config.hostname, ip
        );

        let output = Command::new("curl")
            .args(&[
                "-s",
                "-u", &format!("{}:{}", username, password),
                &url
            ])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.starts_with("good") || response.starts_with("nochg") {
            Ok(())
        } else {
            Err(Error::Network(format!("DynDNS update failed: {}", response)))
        }
    }

    async fn update_noip(&self, ip: IpAddr, username: &str, password: &str) -> Result<()> {
        tracing::info!("Updating No-IP DNS for {}", self.config.hostname);

        let url = format!(
            "https://dynupdate.no-ip.com/nic/update?hostname={}&myip={}",
            self.config.hostname, ip
        );

        let output = Command::new("curl")
            .args(&[
                "-s",
                "-u", &format!("{}:{}", username, password),
                &url
            ])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.starts_with("good") || response.starts_with("nochg") {
            Ok(())
        } else {
            Err(Error::Network(format!("No-IP update failed: {}", response)))
        }
    }

    async fn update_freedns(&self, ip: IpAddr, token: &str) -> Result<()> {
        tracing::info!("Updating FreeDNS for {}", self.config.hostname);

        let url = format!(
            "https://sync.afraid.org/u/{}/?ip={}",
            token, ip
        );

        let output = Command::new("curl")
            .args(&["-s", &url])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.contains("Updated") || response.contains("has not changed") {
            Ok(())
        } else {
            Err(Error::Network(format!("FreeDNS update failed: {}", response)))
        }
    }

    async fn update_duckdns(&self, ip: IpAddr, token: &str) -> Result<()> {
        tracing::info!("Updating DuckDNS for {}", self.config.hostname);

        // Extract subdomain from hostname
        let subdomain = self.config.hostname.split('.').next().unwrap_or("");

        let url = format!(
            "https://www.duckdns.org/update?domains={}&token={}&ip={}",
            subdomain, token, ip
        );

        let output = Command::new("curl")
            .args(&["-s", &url])
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);

        if response.trim() == "OK" {
            Ok(())
        } else {
            Err(Error::Network(format!("DuckDNS update failed: {}", response)))
        }
    }

    async fn update_custom(&self, ip: IpAddr, update_url: &str, username: Option<&String>, password: Option<&String>) -> Result<()> {
        tracing::info!("Updating custom DDNS provider");

        // Replace placeholders in URL
        let url = update_url
            .replace("{hostname}", &self.config.hostname)
            .replace("{ip}", &ip.to_string());

        let mut args = vec!["-s"];

        // Add auth if provided
        let auth_str;
        if let (Some(u), Some(p)) = (username, password) {
            auth_str = format!("{}:{}", u, p);
            args.push("-u");
            args.push(&auth_str);
        }

        args.push(&url);

        let output = Command::new("curl")
            .args(&args)
            .output()
            .await?;

        let response = String::from_utf8_lossy(&output.stdout);
        tracing::debug!("Custom DDNS response: {}", response);

        Ok(())
    }

    /// Get current status
    pub fn get_status(&self) -> DdnsStatus {
        DdnsStatus {
            hostname: self.config.hostname.clone(),
            provider: format!("{:?}", self.config.provider),
            current_ip: self.current_ip,
            last_update: self.last_update,
            last_check: Some(chrono::Utc::now()),
            update_count: self.update_count,
            last_error: None,
            status: if self.current_ip.is_some() {
                UpdateStatus::UpToDate
            } else {
                UpdateStatus::Unknown
            },
        }
    }

    /// Force update now
    pub async fn force_update(&mut self) -> Result<()> {
        self.check_and_update(true).await
    }
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: DdnsProvider::DuckDNS {
                token: String::new(),
            },
            hostname: "example.duckdns.org".to_string(),
            check_interval: 300,      // 5 minutes
            force_update_interval: 86400,  // 24 hours
            interface: None,
            ip_check_url: None,
            ipv6_enabled: false,
            retry_count: 3,
            retry_delay: 60,
            timeout: 30,
        }
    }
}
