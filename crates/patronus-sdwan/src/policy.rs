//! Routing policy engine

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Routing policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    /// Policy ID
    pub id: u64,

    /// Policy name
    pub name: String,

    /// Priority (higher = more important)
    pub priority: u32,

    /// Match rules
    pub match_rules: MatchRules,

    /// Path preference
    pub path_preference: PathPreference,

    /// Whether policy is enabled
    pub enabled: bool,
}

/// Match rules for policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchRules {
    /// Match source IP (supports CIDR notation)
    pub src_ip: Option<String>,

    /// Match destination IP (supports CIDR notation)
    pub dst_ip: Option<String>,

    /// Match source port
    pub src_port: Option<u16>,

    /// Match destination port range
    pub dst_port_range: Option<(u16, u16)>,

    /// Match protocol (6=TCP, 17=UDP, etc.)
    pub protocol: Option<u8>,

    /// Match application class
    pub application_class: Option<ApplicationClass>,
}

/// Path selection preference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathPreference {
    /// Prefer lowest latency
    LowestLatency,

    /// Prefer highest bandwidth
    HighestBandwidth,

    /// Prefer lowest packet loss
    LowestPacketLoss,

    /// Prefer lowest cost
    LowestCost,

    /// Custom scoring weights
    Custom(PathScoringWeights),
}

/// Path scoring weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathScoringWeights {
    /// Latency weight (0.0-1.0)
    pub latency_weight: f64,

    /// Jitter weight (0.0-1.0)
    pub jitter_weight: f64,

    /// Packet loss weight (0.0-1.0)
    pub loss_weight: f64,

    /// Bandwidth weight (0.0-1.0)
    pub bandwidth_weight: f64,

    /// Cost weight (0.0-1.0)
    pub cost_weight: f64,
}

impl PathScoringWeights {
    /// Latency-sensitive preset (VoIP, video conferencing)
    pub fn latency_sensitive() -> Self {
        Self {
            latency_weight: 0.5,
            jitter_weight: 0.3,
            loss_weight: 0.2,
            bandwidth_weight: 0.0,
            cost_weight: 0.0,
        }
    }

    /// Throughput-focused preset (file transfers, backups)
    pub fn throughput_focused() -> Self {
        Self {
            latency_weight: 0.1,
            jitter_weight: 0.0,
            loss_weight: 0.2,
            bandwidth_weight: 0.7,
            cost_weight: 0.0,
        }
    }

    /// Cost-optimized preset (non-critical traffic)
    pub fn cost_optimized() -> Self {
        Self {
            latency_weight: 0.2,
            jitter_weight: 0.1,
            loss_weight: 0.2,
            bandwidth_weight: 0.0,
            cost_weight: 0.5,
        }
    }

    /// Balanced preset (general traffic)
    pub fn balanced() -> Self {
        Self {
            latency_weight: 0.3,
            jitter_weight: 0.2,
            loss_weight: 0.3,
            bandwidth_weight: 0.2,
            cost_weight: 0.0,
        }
    }
}

/// Application classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicationClass {
    /// Voice over IP
    VoIP,

    /// Video conferencing
    VideoConference,

    /// File transfer
    FileTransfer,

    /// Backup/sync
    Backup,

    /// Web browsing
    Web,

    /// Email
    Email,

    /// Database
    Database,

    /// Other
    Other,
}

impl ApplicationClass {
    /// Classify traffic based on port and protocol
    pub fn from_flow(protocol: u8, dst_port: u16) -> Self {
        match (protocol, dst_port) {
            // VoIP ports (SIP, RTP)
            (17, 5060) | (17, 5061) | (6, 5060) | (6, 5061) => Self::VoIP,
            (17, 16384..=32767) => Self::VoIP, // RTP range

            // Video conferencing
            (17, 3478..=3481) | (6, 3478..=3481) => Self::VideoConference, // TURN/STUN
            (6, 8801..=8810) | (17, 8801..=8810) => Self::VideoConference, // Zoom
            (6, 19302..=19310) | (17, 19302..=19310) => Self::VideoConference, // Google Meet

            // Web browsing
            (6, 80) | (6, 443) | (6, 8080) | (6, 8443) => Self::Web,

            // Email
            (6, 25) | (6, 465) | (6, 587) => Self::Email, // SMTP
            (6, 110) | (6, 995) => Self::Email, // POP3
            (6, 143) | (6, 993) => Self::Email, // IMAP

            // File transfer
            (6, 20) | (6, 21) => Self::FileTransfer, // FTP
            (6, 22) => Self::FileTransfer, // SFTP/SSH
            (6, 445) | (6, 139) => Self::FileTransfer, // SMB

            // Database
            (6, 3306) => Self::Database, // MySQL
            (6, 5432) => Self::Database, // PostgreSQL
            (6, 27017) => Self::Database, // MongoDB
            (6, 6379) => Self::Database, // Redis
            (6, 1433) => Self::Database, // MS SQL

            // Backup
            (6, 873) => Self::Backup, // rsync
            (6, 10000..=10999) => Self::Backup, // Common backup ports

            _ => Self::Other,
        }
    }

    /// Get recommended path preference for this application class
    pub fn recommended_preference(&self) -> PathPreference {
        match self {
            Self::VoIP | Self::VideoConference => {
                PathPreference::Custom(PathScoringWeights::latency_sensitive())
            }
            Self::FileTransfer | Self::Backup => {
                PathPreference::Custom(PathScoringWeights::throughput_focused())
            }
            Self::Web | Self::Email => {
                PathPreference::Custom(PathScoringWeights::balanced())
            }
            Self::Database => {
                PathPreference::LowestLatency
            }
            Self::Other => {
                PathPreference::Custom(PathScoringWeights::balanced())
            }
        }
    }
}

/// CIDR network for IP matching
#[derive(Debug, Clone)]
pub struct CidrNetwork {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl CidrNetwork {
    /// Parse a CIDR notation string (e.g., "192.168.1.0/24")
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 2 {
            let addr: IpAddr = parts[0].parse().ok()?;
            let prefix_len: u8 = parts[1].parse().ok()?;
            Some(Self { addr, prefix_len })
        } else {
            // Single IP address - /32 for IPv4, /128 for IPv6
            let addr: IpAddr = s.parse().ok()?;
            let prefix_len = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { addr, prefix_len })
        }
    }

    /// Check if an IP address is contained in this network
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from(net);
                let addr_bits = u32::from(*addr);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !((1u32 << (32 - self.prefix_len)) - 1)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from(net);
                let addr_bits = u128::from(*addr);
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !((1u128 << (128 - self.prefix_len)) - 1)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

/// Policy matcher
pub struct PolicyMatcher;

impl PolicyMatcher {
    /// Check if a flow matches the policy rules
    pub fn matches(flow: &FlowKey, rules: &MatchRules) -> bool {
        // Match protocol
        if let Some(protocol) = rules.protocol {
            if flow.protocol != protocol {
                return false;
            }
        }

        // Match source IP (with CIDR support)
        if let Some(ref src_ip_str) = rules.src_ip {
            if let Some(network) = CidrNetwork::parse(src_ip_str) {
                if !network.contains(&flow.src_ip) {
                    return false;
                }
            }
        }

        // Match destination IP (with CIDR support)
        if let Some(ref dst_ip_str) = rules.dst_ip {
            if let Some(network) = CidrNetwork::parse(dst_ip_str) {
                if !network.contains(&flow.dst_ip) {
                    return false;
                }
            }
        }

        // Match source port
        if let Some(src_port) = rules.src_port {
            if flow.src_port != src_port {
                return false;
            }
        }

        // Match destination port range
        if let Some((min, max)) = rules.dst_port_range {
            if flow.dst_port < min || flow.dst_port > max {
                return false;
            }
        }

        // Match application class
        if let Some(app_class) = rules.application_class {
            let flow_class = ApplicationClass::from_flow(flow.protocol, flow.dst_port);
            if flow_class != app_class {
                return false;
            }
        }

        true
    }

    /// Score a path based on preferences (0-100, higher is better)
    pub fn score_path(metrics: &PathMetrics, preference: &PathPreference, cost_per_gb: Option<f64>) -> f64 {
        match preference {
            PathPreference::LowestLatency => {
                // Lower latency = higher score
                // Score is 100 at 0ms, 50 at 100ms, 0 at 200ms+
                (200.0 - metrics.latency_ms.min(200.0)) / 2.0
            }
            PathPreference::HighestBandwidth => {
                // Higher bandwidth = higher score
                // Score based on bandwidth, scaled to 100 at 1Gbps
                (metrics.bandwidth_mbps / 1000.0 * 100.0).min(100.0)
            }
            PathPreference::LowestPacketLoss => {
                // Lower loss = higher score
                // Score is 100 at 0% loss, 0 at 100% loss
                100.0 - metrics.packet_loss_pct
            }
            PathPreference::LowestCost => {
                // Lower cost = higher score
                Self::score_by_cost(cost_per_gb)
            }
            PathPreference::Custom(weights) => {
                Self::score_with_weights(metrics, weights, cost_per_gb)
            }
        }
    }

    /// Score path based on cost (0-100, higher is better)
    fn score_by_cost(cost_per_gb: Option<f64>) -> f64 {
        match cost_per_gb {
            Some(cost) => {
                // Inverse scoring: lower cost = higher score
                // Score is 100 at $0/GB, 50 at $0.10/GB, 0 at $0.20/GB+
                let score = 100.0 - (cost * 500.0);
                score.max(0.0).min(100.0)
            }
            None => 50.0, // Default score when cost unknown
        }
    }

    fn score_with_weights(metrics: &PathMetrics, weights: &PathScoringWeights, cost_per_gb: Option<f64>) -> f64 {
        // Individual component scores (0-100)
        let latency_score = (200.0 - metrics.latency_ms.min(200.0)) / 2.0;
        let jitter_score = (50.0 - metrics.jitter_ms.min(50.0)) * 2.0;
        let loss_score = 100.0 - metrics.packet_loss_pct;
        let bandwidth_score = (metrics.bandwidth_mbps / 1000.0 * 100.0).min(100.0);
        let cost_score = Self::score_by_cost(cost_per_gb);

        // Weighted sum (weights should sum to 1.0)
        weights.latency_weight * latency_score +
        weights.jitter_weight * jitter_score +
        weights.loss_weight * loss_score +
        weights.bandwidth_weight * bandwidth_score +
        weights.cost_weight * cost_score
    }

    /// Select the best path from a list based on policy
    pub fn select_best_path<'a>(
        paths: &'a [(PathMetrics, Option<f64>)], // (metrics, cost_per_gb)
        preference: &PathPreference,
    ) -> Option<(usize, f64)> {
        if paths.is_empty() {
            return None;
        }

        let mut best_index = 0;
        let mut best_score = f64::MIN;

        for (index, (metrics, cost)) in paths.iter().enumerate() {
            let score = Self::score_path(metrics, preference, *cost);
            if score > best_score {
                best_score = score;
                best_index = index;
            }
        }

        Some((best_index, best_score))
    }
}

/// Policy engine for managing multiple policies
pub struct PolicyEngine {
    policies: Vec<RoutingPolicy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: RoutingPolicy) {
        self.policies.push(policy);
        // Sort by priority (highest first)
        self.policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn remove_policy(&mut self, id: u64) -> Option<RoutingPolicy> {
        if let Some(pos) = self.policies.iter().position(|p| p.id == id) {
            Some(self.policies.remove(pos))
        } else {
            None
        }
    }

    pub fn get_policy(&self, id: u64) -> Option<&RoutingPolicy> {
        self.policies.iter().find(|p| p.id == id)
    }

    pub fn list_policies(&self) -> &[RoutingPolicy] {
        &self.policies
    }

    /// Find the best matching policy for a flow
    pub fn find_matching_policy(&self, flow: &FlowKey) -> Option<&RoutingPolicy> {
        for policy in &self.policies {
            if policy.enabled && PolicyMatcher::matches(flow, &policy.match_rules) {
                return Some(policy);
            }
        }
        None
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_cidr_parsing() {
        let cidr = CidrNetwork::parse("192.168.1.0/24").unwrap();
        assert_eq!(cidr.prefix_len, 24);

        let ip1: IpAddr = "192.168.1.100".parse().unwrap();
        let ip2: IpAddr = "192.168.2.100".parse().unwrap();

        assert!(cidr.contains(&ip1));
        assert!(!cidr.contains(&ip2));
    }

    #[test]
    fn test_single_ip_match() {
        let cidr = CidrNetwork::parse("10.0.0.1").unwrap();
        assert_eq!(cidr.prefix_len, 32);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        assert!(cidr.contains(&ip1));
        assert!(!cidr.contains(&ip2));
    }

    #[test]
    fn test_policy_matching() {
        let flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6, // TCP
        };

        let rules = MatchRules {
            dst_port_range: Some((80, 443)),
            protocol: Some(6),
            src_ip: Some("192.168.1.0/24".to_string()),
            ..Default::default()
        };

        assert!(PolicyMatcher::matches(&flow, &rules));
    }

    #[test]
    fn test_policy_no_match_wrong_subnet() {
        let flow = FlowKey {
            src_ip: "192.168.2.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        let rules = MatchRules {
            src_ip: Some("192.168.1.0/24".to_string()),
            ..Default::default()
        };

        assert!(!PolicyMatcher::matches(&flow, &rules));
    }

    #[test]
    fn test_application_class() {
        assert_eq!(ApplicationClass::from_flow(6, 80), ApplicationClass::Web);
        assert_eq!(ApplicationClass::from_flow(6, 443), ApplicationClass::Web);
        assert_eq!(ApplicationClass::from_flow(17, 5060), ApplicationClass::VoIP);
        assert_eq!(ApplicationClass::from_flow(6, 3306), ApplicationClass::Database);
        assert_eq!(ApplicationClass::from_flow(6, 12345), ApplicationClass::Other);
    }

    #[test]
    fn test_path_scoring() {
        let metrics = PathMetrics {
            latency_ms: 25.0,
            jitter_ms: 5.0,
            packet_loss_pct: 0.1,
            bandwidth_mbps: 1000.0,
            ..Default::default()
        };

        let score = PolicyMatcher::score_path(&metrics, &PathPreference::LowestLatency, None);
        assert!(score > 80.0); // Good latency should score high

        let score = PolicyMatcher::score_path(&metrics, &PathPreference::HighestBandwidth, None);
        assert!(score > 90.0); // 1Gbps should score very high

        let score = PolicyMatcher::score_path(&metrics, &PathPreference::LowestPacketLoss, None);
        assert!(score > 99.0); // 0.1% loss should score very high
    }

    #[test]
    fn test_cost_scoring() {
        // Low cost = high score
        assert!(PolicyMatcher::score_by_cost(Some(0.0)) > 95.0);
        // Medium cost = medium score
        let mid_score = PolicyMatcher::score_by_cost(Some(0.10));
        assert!(mid_score > 40.0 && mid_score < 60.0);
        // High cost = low score
        assert!(PolicyMatcher::score_by_cost(Some(0.25)) < 10.0);
    }

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(RoutingPolicy {
            id: 1,
            name: "VoIP Traffic".to_string(),
            priority: 100,
            match_rules: MatchRules {
                dst_port_range: Some((5060, 5061)),
                protocol: Some(17),
                ..Default::default()
            },
            path_preference: PathPreference::LowestLatency,
            enabled: true,
        });

        engine.add_policy(RoutingPolicy {
            id: 2,
            name: "Web Traffic".to_string(),
            priority: 50,
            match_rules: MatchRules {
                dst_port_range: Some((80, 443)),
                protocol: Some(6),
                ..Default::default()
            },
            path_preference: PathPreference::Custom(PathScoringWeights::balanced()),
            enabled: true,
        });

        // VoIP flow should match VoIP policy
        let voip_flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 5060,
            protocol: 17,
        };

        let policy = engine.find_matching_policy(&voip_flow);
        assert!(policy.is_some());
        assert_eq!(policy.unwrap().name, "VoIP Traffic");
    }
}
