//! Firewall Aliases
//!
//! Aliases allow grouping of IP addresses, networks, ports, and URLs
//! for easier firewall rule management. Like pfSense/OPNsense aliases,
//! but implemented with nftables sets for high performance.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Alias type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AliasType {
    /// Host addresses and networks
    Network,
    /// Port numbers
    Port,
    /// URLs and domains
    Url,
    /// MAC addresses
    Mac,
}

/// Network/Host alias
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAlias {
    pub name: String,
    pub description: Option<String>,
    pub entries: Vec<NetworkEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEntry {
    /// Single IP address
    Host(IpAddr),
    /// Network in CIDR notation
    Network { addr: IpAddr, prefix: u8 },
    /// IP range
    Range { start: IpAddr, end: IpAddr },
    /// Reference to another alias
    Alias(String),
}

/// Port alias
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAlias {
    pub name: String,
    pub description: Option<String>,
    pub entries: Vec<PortEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortEntry {
    /// Single port
    Port(u16),
    /// Port range
    Range { start: u16, end: u16 },
    /// Reference to another port alias
    Alias(String),
}

/// URL/Domain alias
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAlias {
    pub name: String,
    pub description: Option<String>,
    pub entries: Vec<UrlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UrlEntry {
    /// Domain name (will be resolved to IPs)
    Domain(String),
    /// URL pattern
    Url(String),
    /// Reference to another URL alias
    Alias(String),
}

/// MAC address alias
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAlias {
    pub name: String,
    pub description: Option<String>,
    pub mac_addresses: Vec<String>,
}

pub struct AliasManager {
    network_aliases: Vec<NetworkAlias>,
    port_aliases: Vec<PortAlias>,
    url_aliases: Vec<UrlAlias>,
    mac_aliases: Vec<MacAlias>,
}

impl AliasManager {
    pub fn new() -> Self {
        Self {
            network_aliases: Vec::new(),
            port_aliases: Vec::new(),
            url_aliases: Vec::new(),
            mac_aliases: Vec::new(),
        }
    }

    /// Add a network alias
    pub fn add_network_alias(&mut self, alias: NetworkAlias) -> Result<()> {
        // Validate name is unique
        if self.network_aliases.iter().any(|a| a.name == alias.name) {
            return Err(Error::Firewall(format!("Alias '{}' already exists", alias.name)));
        }

        self.network_aliases.push(alias);
        Ok(())
    }

    /// Add a port alias
    pub fn add_port_alias(&mut self, alias: PortAlias) -> Result<()> {
        if self.port_aliases.iter().any(|a| a.name == alias.name) {
            return Err(Error::Firewall(format!("Alias '{}' already exists", alias.name)));
        }

        self.port_aliases.push(alias);
        Ok(())
    }

    /// Add a URL alias
    pub fn add_url_alias(&mut self, alias: UrlAlias) -> Result<()> {
        if self.url_aliases.iter().any(|a| a.name == alias.name) {
            return Err(Error::Firewall(format!("Alias '{}' already exists", alias.name)));
        }

        self.url_aliases.push(alias);
        Ok(())
    }

    /// Add a MAC alias
    pub fn add_mac_alias(&mut self, alias: MacAlias) -> Result<()> {
        if self.mac_aliases.iter().any(|a| a.name == alias.name) {
            return Err(Error::Firewall(format!("Alias '{}' already exists", alias.name)));
        }

        self.mac_aliases.push(alias);
        Ok(())
    }

    /// Generate nftables sets from aliases
    pub fn generate_nftables(&self) -> Result<String> {
        let mut nft = String::from("# Patronus Aliases\n\n");

        nft.push_str("table inet aliases {\n");

        // Network aliases
        if !self.network_aliases.is_empty() {
            nft.push_str("\n  # Network Aliases\n");

            for alias in &self.network_aliases {
                if let Some(ref desc) = alias.description {
                    nft.push_str(&format!("  # {}\n", desc));
                }

                nft.push_str(&format!("  set {} {{\n", alias.name));
                nft.push_str("    type ipv4_addr\n");
                nft.push_str("    flags interval\n");
                nft.push_str("    elements = {\n");

                for entry in &alias.entries {
                    match entry {
                        NetworkEntry::Host(ip) => {
                            nft.push_str(&format!("      {},\n", ip));
                        }
                        NetworkEntry::Network { addr, prefix } => {
                            nft.push_str(&format!("      {}/{},\n", addr, prefix));
                        }
                        NetworkEntry::Range { start, end } => {
                            nft.push_str(&format!("      {}-{},\n", start, end));
                        }
                        NetworkEntry::Alias(alias_name) => {
                            nft.push_str(&format!("      # Reference: {}\n", alias_name));
                        }
                    }
                }

                nft.push_str("    }\n");
                nft.push_str("  }\n\n");
            }
        }

        // Port aliases
        if !self.port_aliases.is_empty() {
            nft.push_str("\n  # Port Aliases\n");

            for alias in &self.port_aliases {
                if let Some(ref desc) = alias.description {
                    nft.push_str(&format!("  # {}\n", desc));
                }

                nft.push_str(&format!("  set {} {{\n", alias.name));
                nft.push_str("    type inet_service\n");
                nft.push_str("    flags interval\n");
                nft.push_str("    elements = {\n");

                for entry in &alias.entries {
                    match entry {
                        PortEntry::Port(port) => {
                            nft.push_str(&format!("      {},\n", port));
                        }
                        PortEntry::Range { start, end } => {
                            nft.push_str(&format!("      {}-{},\n", start, end));
                        }
                        PortEntry::Alias(alias_name) => {
                            nft.push_str(&format!("      # Reference: {}\n", alias_name));
                        }
                    }
                }

                nft.push_str("    }\n");
                nft.push_str("  }\n\n");
            }
        }

        // MAC aliases
        if !self.mac_aliases.is_empty() {
            nft.push_str("\n  # MAC Address Aliases\n");

            for alias in &self.mac_aliases {
                if let Some(ref desc) = alias.description {
                    nft.push_str(&format!("  # {}\n", desc));
                }

                nft.push_str(&format!("  set {} {{\n", alias.name));
                nft.push_str("    type ether_addr\n");
                nft.push_str("    elements = {\n");

                for mac in &alias.mac_addresses {
                    nft.push_str(&format!("      {},\n", mac));
                }

                nft.push_str("    }\n");
                nft.push_str("  }\n\n");
            }
        }

        nft.push_str("}\n");

        Ok(nft)
    }

    /// Get network alias by name
    pub fn get_network_alias(&self, name: &str) -> Option<&NetworkAlias> {
        self.network_aliases.iter().find(|a| a.name == name)
    }

    /// Get port alias by name
    pub fn get_port_alias(&self, name: &str) -> Option<&PortAlias> {
        self.port_aliases.iter().find(|a| a.name == name)
    }

    /// List all aliases
    pub fn list_all(&self) -> Vec<(String, AliasType, usize)> {
        let mut aliases = Vec::new();

        for alias in &self.network_aliases {
            aliases.push((alias.name.clone(), AliasType::Network, alias.entries.len()));
        }

        for alias in &self.port_aliases {
            aliases.push((alias.name.clone(), AliasType::Port, alias.entries.len()));
        }

        for alias in &self.url_aliases {
            aliases.push((alias.name.clone(), AliasType::Url, alias.entries.len()));
        }

        for alias in &self.mac_aliases {
            aliases.push((alias.name.clone(), AliasType::Mac, alias.mac_addresses.len()));
        }

        aliases
    }

    /// Create common presets
    pub fn load_common_aliases(&mut self) -> Result<()> {
        // RFC1918 private networks
        self.add_network_alias(NetworkAlias {
            name: "RFC1918".to_string(),
            description: Some("Private IP address ranges".to_string()),
            entries: vec![
                NetworkEntry::Network {
                    addr: "10.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
                NetworkEntry::Network {
                    addr: "172.16.0.0".parse().unwrap(),
                    prefix: 12,
                },
                NetworkEntry::Network {
                    addr: "192.168.0.0".parse().unwrap(),
                    prefix: 16,
                },
            ],
        })?;

        // Bogon networks (should not appear on internet)
        self.add_network_alias(NetworkAlias {
            name: "Bogons".to_string(),
            description: Some("Reserved/bogon IP ranges".to_string()),
            entries: vec![
                NetworkEntry::Network {
                    addr: "0.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
                NetworkEntry::Network {
                    addr: "127.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
                NetworkEntry::Network {
                    addr: "169.254.0.0".parse().unwrap(),
                    prefix: 16,
                },
                NetworkEntry::Network {
                    addr: "224.0.0.0".parse().unwrap(),
                    prefix: 4,
                },
                NetworkEntry::Network {
                    addr: "240.0.0.0".parse().unwrap(),
                    prefix: 4,
                },
            ],
        })?;

        // Common web ports
        self.add_port_alias(PortAlias {
            name: "WebPorts".to_string(),
            description: Some("HTTP and HTTPS ports".to_string()),
            entries: vec![
                PortEntry::Port(80),
                PortEntry::Port(443),
                PortEntry::Port(8080),
                PortEntry::Port(8443),
            ],
        })?;

        // Email ports
        self.add_port_alias(PortAlias {
            name: "EmailPorts".to_string(),
            description: Some("SMTP, IMAP, POP3 ports".to_string()),
            entries: vec![
                PortEntry::Port(25),   // SMTP
                PortEntry::Port(587),  // SMTP Submission
                PortEntry::Port(465),  // SMTPS
                PortEntry::Port(143),  // IMAP
                PortEntry::Port(993),  // IMAPS
                PortEntry::Port(110),  // POP3
                PortEntry::Port(995),  // POP3S
            ],
        })?;

        // Database ports
        self.add_port_alias(PortAlias {
            name: "DatabasePorts".to_string(),
            description: Some("Common database ports".to_string()),
            entries: vec![
                PortEntry::Port(3306),  // MySQL
                PortEntry::Port(5432),  // PostgreSQL
                PortEntry::Port(6379),  // Redis
                PortEntry::Port(27017), // MongoDB
                PortEntry::Port(1433),  // MSSQL
                PortEntry::Port(1521),  // Oracle
            ],
        })?;

        // High ports (ephemeral)
        self.add_port_alias(PortAlias {
            name: "HighPorts".to_string(),
            description: Some("Ephemeral port range".to_string()),
            entries: vec![
                PortEntry::Range {
                    start: 49152,
                    end: 65535,
                },
            ],
        })?;

        Ok(())
    }
}

impl Default for AliasManager {
    fn default() -> Self {
        let mut manager = Self::new();
        let _ = manager.load_common_aliases();
        manager
    }
}

/// Helper to build network aliases
pub struct NetworkAliasBuilder {
    name: String,
    description: Option<String>,
    entries: Vec<NetworkEntry>,
}

impl NetworkAliasBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            entries: Vec::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn add_host(mut self, ip: IpAddr) -> Self {
        self.entries.push(NetworkEntry::Host(ip));
        self
    }

    pub fn add_network(mut self, addr: IpAddr, prefix: u8) -> Self {
        self.entries.push(NetworkEntry::Network { addr, prefix });
        self
    }

    pub fn add_range(mut self, start: IpAddr, end: IpAddr) -> Self {
        self.entries.push(NetworkEntry::Range { start, end });
        self
    }

    pub fn add_alias(mut self, alias: impl Into<String>) -> Self {
        self.entries.push(NetworkEntry::Alias(alias.into()));
        self
    }

    pub fn build(self) -> NetworkAlias {
        NetworkAlias {
            name: self.name,
            description: self.description,
            entries: self.entries,
        }
    }
}

/// Helper to build port aliases
pub struct PortAliasBuilder {
    name: String,
    description: Option<String>,
    entries: Vec<PortEntry>,
}

impl PortAliasBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            entries: Vec::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn add_port(mut self, port: u16) -> Self {
        self.entries.push(PortEntry::Port(port));
        self
    }

    pub fn add_range(mut self, start: u16, end: u16) -> Self {
        self.entries.push(PortEntry::Range { start, end });
        self
    }

    pub fn add_alias(mut self, alias: impl Into<String>) -> Self {
        self.entries.push(PortEntry::Alias(alias.into()));
        self
    }

    pub fn build(self) -> PortAlias {
        PortAlias {
            name: self.name,
            description: self.description,
            entries: self.entries,
        }
    }
}
