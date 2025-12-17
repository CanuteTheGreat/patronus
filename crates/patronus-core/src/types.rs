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

    pub fn to_string(&self) -> String {
        format!("{}/{}", self.addr, self.prefix_len)
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
        }
    }
}

/// NAT rule types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    Masquerade,
    Snat { to_address: IpAddr },
    Dnat { to_address: IpAddr, to_port: Option<u16> },
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
    pub interface_out: Option<String>,
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
            comment: None,
        }
    }
}
