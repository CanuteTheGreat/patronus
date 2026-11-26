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
    /// Floating-rule, state-limit, limiter and category options.
    #[serde(default)]
    pub ext: RuleExt,
}

/// Direction a floating rule matches its interfaces in.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    /// Traffic arriving on the interfaces (`iifname`).
    #[default]
    In,
    /// Traffic leaving through the interfaces (`oifname`).
    Out,
    /// Either (rendered once per direction).
    Any,
}

impl std::fmt::Display for RuleDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RuleDirection::In => "in",
            RuleDirection::Out => "out",
            RuleDirection::Any => "any",
        })
    }
}

fn default_true() -> bool {
    true
}

/// Options beyond the plain single-interface rule (pfSense/OPNsense parity:
/// floating rules, state limits, limiters, categories). Stored as one JSON
/// column; every field is optional so old rules load unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleExt {
    /// Floating rule: not tied to one interface; `interfaces` + `direction`
    /// select what it matches.
    #[serde(default)]
    pub floating: bool,
    /// Floating only. Quick = evaluated before the interface rules (first
    /// match wins). Not quick = evaluated after them, so an interface rule
    /// that matches takes precedence.
    #[serde(default = "default_true")]
    pub quick: bool,
    #[serde(default)]
    pub direction: RuleDirection,
    /// Floating only: device names, `@role` tokens or `group:NAME`
    /// references; empty = every interface.
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Most connections this rule may have open (all sources together).
    #[serde(default)]
    pub max_states: Option<u32>,
    /// Most simultaneous connections per source address.
    #[serde(default)]
    pub max_src_conn: Option<u32>,
    /// New connections per source: `max_src_rate` per `max_src_rate_secs`.
    #[serde(default)]
    pub max_src_rate: Option<u32>,
    #[serde(default)]
    pub max_src_rate_secs: Option<u32>,
    /// Sources exceeding `max_src_rate` land in this overload table and are
    /// dropped for `overload_secs`.
    #[serde(default)]
    pub overload: Option<String>,
    #[serde(default)]
    pub overload_secs: Option<u32>,
    /// Name of a limiter (rate cap) from the shaping/limiter list.
    #[serde(default)]
    pub limiter: Option<String>,
    /// Free-form grouping label.
    #[serde(default)]
    pub category: Option<String>,
}

impl Default for RuleExt {
    fn default() -> Self {
        Self {
            floating: false,
            quick: true,
            direction: RuleDirection::In,
            interfaces: Vec::new(),
            max_states: None,
            max_src_conn: None,
            max_src_rate: None,
            max_src_rate_secs: None,
            overload: None,
            overload_secs: None,
            limiter: None,
            category: None,
        }
    }
}

impl RuleExt {
    /// Whether any per-source state option is set (needs per-family sets).
    pub fn per_source(&self) -> bool {
        self.max_src_conn.is_some() || self.max_src_rate.is_some() || self.limiter.is_some()
    }

    /// Nothing set: the rule is a plain one.
    pub fn is_plain(&self) -> bool {
        *self == RuleExt::default()
    }
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
            ext: RuleExt::default(),
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
