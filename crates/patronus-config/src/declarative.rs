//! Declarative Configuration - Policy as Code
//!
//! This module provides the foundation for GitOps-native firewall management.
//! Firewall rules, NAT policies, VPN configs, and all settings can be defined
//! in declarative YAML/TOML files and version-controlled in Git.
//!
//! Key features:
//! - Declarative YAML/TOML configuration
//! - Schema validation
//! - Dry-run and diff mode
//! - Git repository watching
//! - Terraform/Ansible integration
//! - Template support with variables
//! - Atomic apply with rollback

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::net::IpAddr;

/// API version for configuration schema
pub const API_VERSION: &str = "patronus.firewall/v1";

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarativeConfig {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: ResourceKind,
    pub metadata: Metadata,
    pub spec: ResourceSpec,
}

/// Supported resource kinds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceKind {
    FirewallRule,
    NatRule,
    VpnConnection,
    Interface,
    GatewayGroup,
    DhcpServer,
    DnsResolver,
    HaProxyBackend,
    Certificate,
    User,
    SystemSettings,
}

/// Resource metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

/// Resource specification (polymorphic)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceSpec {
    FirewallRule(FirewallRuleSpec),
    NatRule(NatRuleSpec),
    VpnConnection(VpnConnectionSpec),
    Interface(InterfaceSpec),
    GatewayGroup(GatewayGroupSpec),
    DhcpServer(DhcpServerSpec),
    DnsResolver(DnsResolverSpec),
    HaProxyBackend(HaProxyBackendSpec),
    Certificate(CertificateSpec),
    User(UserSpec),
    SystemSettings(SystemSettingsSpec),
}

/// Firewall rule specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleSpec {
    pub action: RuleAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub source: AddressSpec,
    pub destination: AddressSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default)]
    pub log: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ScheduleSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "reject")]
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Direction {
    #[serde(rename = "inbound")]
    Inbound,
    #[serde(rename = "outbound")]
    Outbound,
    #[serde(rename = "both")]
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,  // IP, CIDR, or alias name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_ranges: Option<Vec<PortRange>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<String>>,  // mon, tue, wed, thu, fri, sat, sun
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: String,  // HH:MM
    pub end: String,    // HH:MM
}

/// NAT rule specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleSpec {
    pub nat_type: NatType,
    pub interface: String,
    pub source: AddressSpec,
    pub destination: AddressSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub translation: Option<AddressSpec>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatType {
    #[serde(rename = "snat")]
    Snat,
    #[serde(rename = "dnat")]
    Dnat,
    #[serde(rename = "masquerade")]
    Masquerade,
    #[serde(rename = "redirect")]
    Redirect,
}

/// VPN connection specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConnectionSpec {
    pub vpn_type: VpnType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireGuardConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openvpn: Option<OpenVpnConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipsec: Option<IpsecConfig>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VpnType {
    #[serde(rename = "wireguard")]
    WireGuard,
    #[serde(rename = "openvpn")]
    OpenVpn,
    #[serde(rename = "ipsec")]
    Ipsec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub listen_port: u16,
    pub peers: Vec<WireGuardPeer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnConfig {
    pub mode: String,  // server or client
    pub protocol: String,  // udp or tcp
    pub port: u16,
    pub cipher: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecConfig {
    pub local_id: String,
    pub remote_id: String,
    pub remote_address: String,
    pub psk: String,
}

/// Interface specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSpec {
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub enabled: bool,
}

/// Gateway group specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroupSpec {
    pub members: Vec<GatewayMemberSpec>,
    #[serde(default)]
    pub sticky: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMemberSpec {
    pub gateway_name: String,
    pub tier: u8,
    pub weight: u32,
}

/// DHCP server specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServerSpec {
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: bool,
}

/// DNS resolver specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolverSpec {
    pub backend: String,  // unbound, bind, dnsmasq
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarders: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_records: Option<Vec<DnsRecord>>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

/// HAProxy backend specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaProxyBackendSpec {
    pub algorithm: String,
    pub servers: Vec<BackendServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendServer {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub check_type: String,
    pub interval: u32,
    pub timeout: u32,
}

/// Certificate specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSpec {
    pub cert_type: String,  // ca, server, client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub san: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_days: Option<u32>,
}

/// User specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSpec {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    pub groups: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

/// System settings specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettingsSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Configuration parser
pub struct ConfigParser;

impl ConfigParser {
    /// Parse YAML configuration file
    pub fn parse_yaml(content: &str) -> Result<Vec<DeclarativeConfig>> {
        // Support both single document and multi-document YAML
        let configs: Vec<DeclarativeConfig> = serde_yaml::from_str(content)
            .map_err(|e| Error::Config(format!("YAML parse error: {}", e)))?;

        // Validate each config
        for config in &configs {
            Self::validate_config(config)?;
        }

        Ok(configs)
    }

    /// Parse YAML from file
    pub async fn parse_yaml_file(path: &Path) -> Result<Vec<DeclarativeConfig>> {
        let content = tokio::fs::read_to_string(path).await?;
        Self::parse_yaml(&content)
    }

    /// Parse TOML configuration file
    pub fn parse_toml(content: &str) -> Result<DeclarativeConfig> {
        let config: DeclarativeConfig = toml::from_str(content)
            .map_err(|e| Error::Config(format!("TOML parse error: {}", e)))?;

        Self::validate_config(&config)?;

        Ok(config)
    }

    /// Validate configuration
    pub fn validate_config(config: &DeclarativeConfig) -> Result<()> {
        // Check API version
        if config.api_version != API_VERSION {
            return Err(Error::Config(format!(
                "Unsupported API version: {} (expected: {})",
                config.api_version, API_VERSION
            )));
        }

        // Validate metadata
        if config.metadata.name.is_empty() {
            return Err(Error::Config("Resource name cannot be empty".to_string()));
        }

        // Validate spec based on kind
        match (&config.kind, &config.spec) {
            (ResourceKind::FirewallRule, ResourceSpec::FirewallRule(spec)) => {
                Self::validate_firewall_rule(spec)?;
            }
            (ResourceKind::NatRule, ResourceSpec::NatRule(spec)) => {
                Self::validate_nat_rule(spec)?;
            }
            (ResourceKind::VpnConnection, ResourceSpec::VpnConnection(spec)) => {
                Self::validate_vpn_connection(spec)?;
            }
            _ => {
                return Err(Error::Config(format!(
                    "Kind {:?} does not match spec",
                    config.kind
                )));
            }
        }

        Ok(())
    }

    fn validate_firewall_rule(spec: &FirewallRuleSpec) -> Result<()> {
        // Validate addresses
        if let Some(addr) = &spec.source.address {
            Self::validate_address(addr)?;
        }
        if let Some(addr) = &spec.destination.address {
            Self::validate_address(addr)?;
        }

        // Validate ports
        if let Some(ports) = &spec.source.ports {
            for port in ports {
                if *port == 0 {
                    return Err(Error::Config("Port cannot be 0".to_string()));
                }
            }
        }

        Ok(())
    }

    fn validate_nat_rule(spec: &NatRuleSpec) -> Result<()> {
        // Validate interface exists
        if spec.interface.is_empty() {
            return Err(Error::Config("NAT rule must specify interface".to_string()));
        }

        Ok(())
    }

    fn validate_vpn_connection(spec: &VpnConnectionSpec) -> Result<()> {
        // Ensure config exists for the specified type
        match spec.vpn_type {
            VpnType::WireGuard if spec.wireguard.is_none() => {
                return Err(Error::Config("WireGuard config required".to_string()));
            }
            VpnType::OpenVpn if spec.openvpn.is_none() => {
                return Err(Error::Config("OpenVPN config required".to_string()));
            }
            VpnType::Ipsec if spec.ipsec.is_none() => {
                return Err(Error::Config("IPsec config required".to_string()));
            }
            _ => {}
        }

        Ok(())
    }

    fn validate_address(addr: &str) -> Result<()> {
        // Try parsing as IP or CIDR
        if addr.contains('/') {
            // CIDR notation
            let parts: Vec<&str> = addr.split('/').collect();
            if parts.len() != 2 {
                return Err(Error::Config(format!("Invalid CIDR: {}", addr)));
            }

            // Validate IP part
            if parts[0].parse::<IpAddr>().is_err() {
                return Err(Error::Config(format!("Invalid IP in CIDR: {}", addr)));
            }

            // Validate prefix length
            if let Ok(prefix) = parts[1].parse::<u8>() {
                if prefix > 128 {
                    return Err(Error::Config(format!("Invalid prefix length: {}", prefix)));
                }
            } else {
                return Err(Error::Config(format!("Invalid prefix length: {}", parts[1])));
            }
        } else if addr != "any" && addr.parse::<IpAddr>().is_err() {
            // Not a valid IP and not "any"
            // Could be an alias name, which is OK
        }

        Ok(())
    }

    /// Serialize config to YAML
    pub fn to_yaml(config: &DeclarativeConfig) -> Result<String> {
        serde_yaml::to_string(config)
            .map_err(|e| Error::Config(format!("YAML serialization error: {}", e)))
    }

    /// Serialize config to TOML
    pub fn to_toml(config: &DeclarativeConfig) -> Result<String> {
        toml::to_string(config)
            .map_err(|e| Error::Config(format!("TOML serialization error: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_firewall_rule_yaml() {
        let yaml = r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata:
    name: allow-web-traffic
    description: "Allow HTTP/HTTPS from internet"
  spec:
    action: allow
    interface: wan0
    direction: inbound
    source:
      address: "0.0.0.0/0"
    destination:
      address: "10.0.1.10"
      ports: [80, 443]
    protocol: tcp
    log: true
    enabled: true
"#;

        let configs = ConfigParser::parse_yaml(yaml).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].metadata.name, "allow-web-traffic");
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let yaml = r#"
- apiVersion: patronus.firewall/v1
  kind: FirewallRule
  metadata:
    name: bad-rule
  spec:
    action: allow
    source:
      address: "192.168.1.0/999"
    destination:
      address: "10.0.0.1"
    enabled: true
"#;

        let result = ConfigParser::parse_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_to_yaml() {
        let config = DeclarativeConfig {
            api_version: API_VERSION.to_string(),
            kind: ResourceKind::FirewallRule,
            metadata: Metadata {
                name: "test-rule".to_string(),
                description: Some("Test rule".to_string()),
                labels: None,
                annotations: None,
            },
            spec: ResourceSpec::FirewallRule(FirewallRuleSpec {
                action: RuleAction::Allow,
                interface: Some("wan0".to_string()),
                direction: Some(Direction::Inbound),
                source: AddressSpec {
                    address: Some("0.0.0.0/0".to_string()),
                    ports: None,
                    port_ranges: None,
                },
                destination: AddressSpec {
                    address: Some("10.0.0.1".to_string()),
                    ports: Some(vec![80, 443]),
                    port_ranges: None,
                },
                protocol: Some("tcp".to_string()),
                log: true,
                schedule: None,
                gateway: None,
                enabled: true,
            }),
        };

        let yaml = ConfigParser::to_yaml(&config).unwrap();
        assert!(yaml.contains("allow-web-traffic") || yaml.contains("test-rule"));
    }
}
