//! GeoIP Blocking
//!
//! Country-based filtering using geolocation databases.
//!
//! # The Gentoo Way: Choice of Backends
//!
//! - **GeoIP2 (MaxMind)**: Modern, accurate, actively maintained
//! - **Legacy GeoIP**: Older format, deprecated but still available
//!
//! Both integrate seamlessly with nftables for high-performance filtering.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use tokio::fs;
use tokio::process::Command;

/// GeoIP backend
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoIpBackend {
    /// Modern MaxMind GeoIP2 (mmdb format)
    GeoIp2,
    /// Legacy GeoIP (dat format)
    GeoIpLegacy,
}

impl std::fmt::Display for GeoIpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpBackend::GeoIp2 => write!(f, "geoip2"),
            GeoIpBackend::GeoIpLegacy => write!(f, "geoip"),
        }
    }
}

/// GeoIP rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoIpAction {
    /// Allow traffic from these countries
    Allow,
    /// Block traffic from these countries
    Block,
}

/// GeoIP filtering rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpRule {
    pub name: String,
    pub enabled: bool,
    pub action: GeoIpAction,
    pub countries: Vec<String>,  // ISO 3166-1 alpha-2 codes (US, CN, RU, etc.)
    pub interfaces: Vec<String>,  // Apply to these interfaces ("wan", "eth1")
    pub direction: TrafficDirection,
    pub log: bool,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Both,
}

/// GeoIP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    pub enabled: bool,
    pub backend: GeoIpBackend,
    pub database_path: PathBuf,
    pub auto_update: bool,
    pub update_interval_days: u32,
    pub rules: Vec<GeoIpRule>,
}

/// Statistics for GeoIP blocking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpStats {
    pub total_blocked: u64,
    pub blocked_by_country: HashMap<String, u64>,
}

pub struct GeoIpManager {
    backend: GeoIpBackend,
    db_path: PathBuf,
    ipsets_dir: PathBuf,
}

impl GeoIpManager {
    pub fn new(backend: GeoIpBackend) -> Self {
        let db_path = match backend {
            GeoIpBackend::GeoIp2 => PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
            GeoIpBackend::GeoIpLegacy => PathBuf::from("/usr/share/GeoIP/GeoIP.dat"),
        };

        Self {
            backend,
            db_path,
            ipsets_dir: PathBuf::from("/etc/patronus/geoip/ipsets"),
        }
    }

    /// Auto-detect available backend
    pub fn new_auto() -> Self {
        let backend = Self::detect_backend();
        Self::new(backend)
    }

    /// Detect which GeoIP backend is available
    pub fn detect_backend() -> GeoIpBackend {
        if PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb").exists() {
            GeoIpBackend::GeoIp2
        } else if PathBuf::from("/usr/share/GeoIP/GeoIP.dat").exists() {
            GeoIpBackend::GeoIpLegacy
        } else {
            GeoIpBackend::GeoIp2  // Default preference
        }
    }

    /// List available backends
    pub fn list_available_backends() -> Vec<GeoIpBackend> {
        let mut backends = Vec::new();

        if PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb").exists() {
            backends.push(GeoIpBackend::GeoIp2);
        }

        if PathBuf::from("/usr/share/GeoIP/GeoIP.dat").exists() {
            backends.push(GeoIpBackend::GeoIpLegacy);
        }

        backends
    }

    /// Download/update GeoIP database
    pub async fn update_database(&self) -> Result<()> {
        match self.backend {
            GeoIpBackend::GeoIp2 => self.update_geoip2().await,
            GeoIpBackend::GeoIpLegacy => self.update_geoip_legacy().await,
        }
    }

    async fn update_geoip2(&self) -> Result<()> {
        // GeoIP2 requires MaxMind account
        // In production, use geoipupdate tool
        println!("Updating GeoIP2 database...");
        println!("Note: Requires MaxMind account and license key");
        println!("Install geoipupdate: emerge net-misc/geoipupdate");
        println!("Configure: /etc/GeoIP.conf");

        Command::new("geoipupdate")
            .spawn()
            .map_err(|e| Error::Firewall(format!("Failed to update GeoIP2: {}", e)))?
            .wait()
            .await
            .map_err(|e| Error::Firewall(format!("GeoIP2 update failed: {}", e)))?;

        Ok(())
    }

    async fn update_geoip_legacy(&self) -> Result<()> {
        // Legacy GeoIP is deprecated, but databases still available
        println!("Updating legacy GeoIP database...");
        println!("Note: Legacy GeoIP is deprecated, consider upgrading to GeoIP2");

        // Would download from legacy sources
        Ok(())
    }

    /// Generate IP sets for countries
    pub async fn generate_ipsets(&self, config: &GeoIpConfig) -> Result<()> {
        fs::create_dir_all(&self.ipsets_dir).await?;

        // Collect all countries we need
        let mut countries = HashSet::new();
        for rule in &config.rules {
            if rule.enabled {
                for country in &rule.countries {
                    countries.insert(country.to_uppercase());
                }
            }
        }

        // Generate IP sets for each country
        for country in countries {
            self.generate_country_ipset(&country).await?;
        }

        Ok(())
    }

    async fn generate_country_ipset(&self, country: &str) -> Result<()> {
        println!("Generating IP set for country: {}", country);

        match self.backend {
            GeoIpBackend::GeoIp2 => {
                // Use mmdb to extract IPs for country
                // This requires a tool like geoip2-csv-converter or custom extraction

                // For now, we'll download pre-built IP lists
                let ipset_file = self.ipsets_dir.join(format!("{}.txt", country));

                // In production, download from:
                // https://www.ipdeny.com/ipblocks/data/aggregated/
                // or extract from GeoIP2 database

                let url = format!("https://www.ipdeny.com/ipblocks/data/aggregated/{}-aggregated.zone", country.to_lowercase());

                println!("  Downloading IP blocks from ipdeny.com...");
                let output = Command::new("curl")
                    .arg("-s")
                    .arg("-o")
                    .arg(&ipset_file)
                    .arg(&url)
                    .output()
                    .await
                    .map_err(|e| Error::Firewall(format!("Failed to download IP blocks: {}", e)))?;

                if !output.status.success() {
                    return Err(Error::Firewall(format!("Failed to download IP blocks for {}", country)));
                }
            }
            GeoIpBackend::GeoIpLegacy => {
                // Similar approach for legacy GeoIP
                let ipset_file = self.ipsets_dir.join(format!("{}.txt", country));

                // Download IP blocks
                let url = format!("https://www.ipdeny.com/ipblocks/data/countries/{}.zone", country.to_lowercase());

                let output = Command::new("curl")
                    .arg("-s")
                    .arg("-o")
                    .arg(&ipset_file)
                    .arg(&url)
                    .output()
                    .await
                    .map_err(|e| Error::Firewall(format!("Failed to download IP blocks: {}", e)))?;

                if !output.status.success() {
                    return Err(Error::Firewall(format!("Failed to download IP blocks for {}", country)));
                }
            }
        }

        Ok(())
    }

    /// Apply GeoIP rules to nftables
    pub async fn apply_rules(&self, config: &GeoIpConfig) -> Result<String> {
        let mut nft_rules = String::from("# GeoIP Rules - Managed by Patronus\n\n");

        nft_rules.push_str("# Create table for GeoIP filtering\n");
        nft_rules.push_str("table inet geoip {\n");

        // Create sets for each country
        let mut countries = HashSet::new();
        for rule in &config.rules {
            if rule.enabled {
                for country in &rule.countries {
                    countries.insert(country.to_uppercase());
                }
            }
        }

        for country in &countries {
            let ipset_file = self.ipsets_dir.join(format!("{}.txt", country));

            if ipset_file.exists() {
                nft_rules.push_str(&format!("\n  # IP set for {}\n", country));
                nft_rules.push_str(&format!("  set {}_ipv4 {{\n", country.to_lowercase()));
                nft_rules.push_str("    type ipv4_addr\n");
                nft_rules.push_str("    flags interval\n");
                nft_rules.push_str(&format!("    # Load from {}\n", ipset_file.display()));
                nft_rules.push_str("    elements = {\n");

                // Read IP addresses from file
                if let Ok(content) = fs::read_to_string(&ipset_file).await {
                    for line in content.lines().take(100) {  // Limit for example
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            nft_rules.push_str(&format!("      {},\n", line));
                        }
                    }
                }

                nft_rules.push_str("    }\n");
                nft_rules.push_str("  }\n");
            }
        }

        // Create chains
        nft_rules.push_str("\n  chain input {\n");
        nft_rules.push_str("    type filter hook input priority filter - 10\n");
        nft_rules.push_str("    policy accept\n\n");

        // Apply rules
        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }

            if rule.direction == TrafficDirection::Outbound {
                continue;  // Skip outbound in input chain
            }

            let action = match rule.action {
                GeoIpAction::Allow => "accept",
                GeoIpAction::Block => "drop",
            };

            if let Some(ref comment) = rule.comment {
                nft_rules.push_str(&format!("    # {}\n", comment));
            } else {
                nft_rules.push_str(&format!("    # Rule: {}\n", rule.name));
            }

            for country in &rule.countries {
                let country_lower = country.to_lowercase();
                nft_rules.push_str(&format!(
                    "    ip saddr @{}_ipv4 {} comment \"{}\"\n",
                    country_lower,
                    action,
                    rule.name
                ));

                if rule.log {
                    nft_rules.push_str(&format!(
                        "    ip saddr @{}_ipv4 log prefix \"[GeoIP-{}] \"\n",
                        country_lower, country
                    ));
                }
            }

            nft_rules.push_str("\n");
        }

        nft_rules.push_str("  }\n");

        // Output chain for outbound filtering
        nft_rules.push_str("\n  chain output {\n");
        nft_rules.push_str("    type filter hook output priority filter - 10\n");
        nft_rules.push_str("    policy accept\n\n");

        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }

            if rule.direction == TrafficDirection::Inbound {
                continue;  // Skip inbound in output chain
            }

            let action = match rule.action {
                GeoIpAction::Allow => "accept",
                GeoIpAction::Block => "drop",
            };

            for country in &rule.countries {
                let country_lower = country.to_lowercase();
                nft_rules.push_str(&format!(
                    "    ip daddr @{}_ipv4 {} comment \"{} outbound\"\n",
                    country_lower,
                    action,
                    rule.name
                ));
            }
        }

        nft_rules.push_str("  }\n");
        nft_rules.push_str("}\n");

        Ok(nft_rules)
    }

    /// Lookup country for an IP address
    pub async fn lookup_country(&self, ip: IpAddr) -> Result<String> {
        match self.backend {
            GeoIpBackend::GeoIp2 => self.lookup_geoip2(ip).await,
            GeoIpBackend::GeoIpLegacy => self.lookup_geoip_legacy(ip).await,
        }
    }

    async fn lookup_geoip2(&self, ip: IpAddr) -> Result<String> {
        // Use mmdblookup command-line tool
        let output = Command::new("mmdblookup")
            .arg("--file")
            .arg(&self.db_path)
            .arg("--ip")
            .arg(ip.to_string())
            .arg("country")
            .arg("iso_code")
            .output()
            .await
            .map_err(|e| Error::Firewall(format!("GeoIP lookup failed: {}", e)))?;

        let result = String::from_utf8_lossy(&output.stdout);

        // Parse output like:  "US" <utf8_string>
        if let Some(country) = result.split('"').nth(1) {
            Ok(country.to_string())
        } else {
            Ok("Unknown".to_string())
        }
    }

    async fn lookup_geoip_legacy(&self, ip: IpAddr) -> Result<String> {
        // Use geoiplookup command
        let output = Command::new("geoiplookup")
            .arg(ip.to_string())
            .output()
            .await
            .map_err(|e| Error::Firewall(format!("GeoIP lookup failed: {}", e)))?;

        let result = String::from_utf8_lossy(&output.stdout);

        // Parse output like: GeoIP Country Edition: US, United States
        if let Some(country) = result.split(": ").nth(1) {
            if let Some(code) = country.split(',').next() {
                return Ok(code.trim().to_string());
            }
        }

        Ok("Unknown".to_string())
    }

    /// Common blocking presets
    pub fn create_block_abusive_countries() -> GeoIpRule {
        GeoIpRule {
            name: "Block High-Risk Countries".to_string(),
            enabled: true,
            action: GeoIpAction::Block,
            countries: vec![
                // Common sources of attacks (adjust based on your needs)
                "CN".to_string(),  // China
                "RU".to_string(),  // Russia
                "KP".to_string(),  // North Korea
                "IR".to_string(),  // Iran
            ],
            interfaces: vec!["wan".to_string()],
            direction: TrafficDirection::Inbound,
            log: true,
            comment: Some("Block traffic from high-risk countries".to_string()),
        }
    }

    pub fn create_allow_local_only() -> GeoIpRule {
        GeoIpRule {
            name: "Allow Local Country Only".to_string(),
            enabled: true,
            action: GeoIpAction::Allow,
            countries: vec![
                "US".to_string(),  // Change to your country
            ],
            interfaces: vec!["wan".to_string()],
            direction: TrafficDirection::Inbound,
            log: false,
            comment: Some("Only allow traffic from local country".to_string()),
        }
    }
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: GeoIpBackend::GeoIp2,
            database_path: PathBuf::from("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
            auto_update: true,
            update_interval_days: 7,
            rules: Vec::new(),
        }
    }
}

/// Common country codes (ISO 3166-1 alpha-2)
pub struct CountryCodes;

impl CountryCodes {
    pub const US: &'static str = "US";  // United States
    pub const CN: &'static str = "CN";  // China
    pub const RU: &'static str = "RU";  // Russia
    pub const DE: &'static str = "DE";  // Germany
    pub const GB: &'static str = "GB";  // United Kingdom
    pub const FR: &'static str = "FR";  // France
    pub const JP: &'static str = "JP";  // Japan
    pub const KR: &'static str = "KR";  // South Korea
    pub const BR: &'static str = "BR";  // Brazil
    pub const IN: &'static str = "IN";  // India
    pub const AU: &'static str = "AU";  // Australia
    pub const CA: &'static str = "CA";  // Canada
    pub const MX: &'static str = "MX";  // Mexico
    pub const IT: &'static str = "IT";  // Italy
    pub const ES: &'static str = "ES";  // Spain
    pub const NL: &'static str = "NL";  // Netherlands
    pub const SE: &'static str = "SE";  // Sweden
    pub const CH: &'static str = "CH";  // Switzerland
    pub const PL: &'static str = "PL";  // Poland
    pub const TR: &'static str = "TR";  // Turkey
    pub const IR: &'static str = "IR";  // Iran
    pub const KP: &'static str = "KP";  // North Korea
}
