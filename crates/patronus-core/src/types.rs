//! Core type definitions

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents a network interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub mtu: u32,
    pub enabled: bool,
    pub index: u32,
}

/// IP address with CIDR prefix
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpNetwork {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpNetwork {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Represents a firewall rule action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
}

impl std::fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallAction::Accept => write!(f, "accept"),
            FirewallAction::Drop => write!(f, "drop"),
            FirewallAction::Reject => write!(f, "reject"),
        }
    }
}

/// Protocol type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    All,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::All => write!(f, "all"),
        }
    }
}

/// Port specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
    Multiple(Vec<u16>),
    /// A port alias (an nftables set of ports maintained by the firewall
    /// crate); the name is validated there before it reaches nft.
    Alias(String),
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortSpec::Single(port) => write!(f, "{}", port),
            PortSpec::Range(start, end) => write!(f, "{}-{}", start, end),
            PortSpec::Multiple(ports) => {
                let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{{{}}}", ports_str.join(","))
            }
            PortSpec::Alias(name) => write!(f, "${}", name),
        }
    }
}

/// Firewall chain type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainType {
    Input,
    Output,
    Forward,
}

impl std::fmt::Display for ChainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainType::Input => write!(f, "input"),
            ChainType::Output => write!(f, "output"),
            ChainType::Forward => write!(f, "forward"),
        }
    }
}

/// Address family a rule is restricted to (`None` = both).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    V4,
    V6,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::V4 => write!(f, "ipv4"),
            IpVersion::V6 => write!(f, "ipv6"),
        }
    }
}

/// Represents a firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Option<u64>,
    pub name: String,
    pub enabled: bool,
    pub chain: ChainType,
    pub action: FirewallAction,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<Protocol>,
    pub sport: Option<PortSpec>,
    pub dport: Option<PortSpec>,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub comment: Option<String>,
    /// Log matching packets (nft `log prefix "patronus[<id>] "`).
    #[serde(default)]
    pub log: bool,
    /// Name of a firewall schedule: the rule is only enforced while the
    /// schedule is active.
    #[serde(default)]
    pub schedule: Option<String>,
    /// Restrict the rule to IPv4 or IPv6 (`None` = whatever the addresses
    /// imply, or both).
    #[serde(default)]
    pub ip_version: Option<IpVersion>,
    /// Policy routing: send traffic this (accept) rule matches through this
    /// gateway or gateway group (routing lane E) instead of the default
    /// route.
    #[serde(default)]
    pub gateway: Option<String>,
}

impl FirewallRule {
    pub fn new(name: String, chain: ChainType, action: FirewallAction) -> Self {
        Self {
            id: None,
            name,
            enabled: true,
            chain,
            action,
            source: None,
            destination: None,
            protocol: None,
            sport: None,
            dport: None,
            interface_in: None,
            interface_out: None,
            comment: None,
            log: false,
            schedule: None,
            ip_version: None,
            gateway: None,
        }
    }
}

/// NAT rule types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    Masquerade,
    Snat {
        to_address: IpAddr,
    },
    /// Port forward / destination NAT. Matches traffic arriving on
    /// `NatRule::interface_in` (with `protocol`/`dport`) and rewrites the
    /// destination to `to_address[:to_port]`.
    Dnat {
        to_address: IpAddr,
        to_port: Option<u16>,
    },
    /// 1:1 NAT: `external` (an address on the WAN side) maps to `internal`
    /// in both directions (DNAT inbound, SNAT outbound).
    OneToOne {
        external: IpAddr,
        internal: IpAddr,
    },
    /// IPv6 network prefix translation (NPTv6): the `internal` /N prefix
    /// (matched on the way out of `interface_out`) is rewritten to the
    /// `external` /N prefix, and back for traffic to `external`
    /// arriving on `interface_in`. Host bits are kept. Both are `addr/len`
    /// strings of the same length, validated where the rule is built.
    Npt {
        external: String,
        internal: String,
    },
}

/// NAT rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Option<u64>,
    pub name: String,
    pub enabled: bool,
    pub nat_type: NatType,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<Protocol>,
    pub dport: Option<PortSpec>,
    /// Outbound interface (masquerade/SNAT/1:1 outbound half).
    pub interface_out: Option<String>,
    /// Inbound interface (port forward / 1:1 inbound half), e.g. `@wan`.
    #[serde(default)]
    pub interface_in: Option<String>,
    /// NAT reflection (hairpin): LAN clients reaching the WAN address of a
    /// port forward are forwarded to the internal host too.
    #[serde(default)]
    pub reflection: bool,
    pub comment: Option<String>,
}

impl NatRule {
    pub fn new(name: String, nat_type: NatType) -> Self {
        Self {
            id: None,
            name,
            enabled: true,
            nat_type,
            source: None,
            destination: None,
            protocol: None,
            dport: None,
            interface_out: None,
            interface_in: None,
            reflection: false,
            comment: None,
        }
    }
}
