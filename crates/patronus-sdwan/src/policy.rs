//! Routing policy engine

use crate::{types::*, Error, Result};
use serde::{Deserialize, Serialize};

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
    /// Match source IP
    pub src_ip: Option<String>,

    /// Match destination IP
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

/// Policy matcher
pub struct PolicyMatcher;

impl PolicyMatcher {
    /// Check if a flow matches the policy rules
    pub fn matches(flow: &FlowKey, rules: &MatchRules) -> bool {
        // TODO: Implement full matching logic

        if let Some(protocol) = rules.protocol {
            if flow.protocol != protocol {
                return false;
            }
        }

        if let Some((min, max)) = rules.dst_port_range {
            if flow.dst_port < min || flow.dst_port > max {
                return false;
            }
        }

        true
    }

    /// Score a path based on preferences
    pub fn score_path(metrics: &PathMetrics, preference: &PathPreference) -> f64 {
        match preference {
            PathPreference::LowestLatency => {
                // Lower latency = higher score
                (200.0 - metrics.latency_ms.min(200.0)) / 2.0
            }
            PathPreference::HighestBandwidth => {
                // Higher bandwidth = higher score
                (metrics.bandwidth_mbps / 1000.0 * 100.0).min(100.0)
            }
            PathPreference::LowestPacketLoss => {
                // Lower loss = higher score
                100.0 - metrics.packet_loss_pct
            }
            PathPreference::LowestCost => {
                // TODO: Implement cost-based scoring
                50.0
            }
            PathPreference::Custom(weights) => {
                Self::score_with_weights(metrics, weights)
            }
        }
    }

    fn score_with_weights(metrics: &PathMetrics, weights: &PathScoringWeights) -> f64 {
        let latency_score = (200.0 - metrics.latency_ms.min(200.0)) / 2.0;
        let jitter_score = (50.0 - metrics.jitter_ms.min(50.0)) / 0.5;
        let loss_score = 100.0 - metrics.packet_loss_pct;
        let bandwidth_score = (metrics.bandwidth_mbps / 1000.0 * 100.0).min(100.0);
        let cost_score = 50.0; // TODO: Implement cost scoring

        weights.latency_weight * latency_score +
        weights.jitter_weight * jitter_score +
        weights.loss_weight * loss_score +
        weights.bandwidth_weight * bandwidth_score +
        weights.cost_weight * cost_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

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
            ..Default::default()
        };

        assert!(PolicyMatcher::matches(&flow, &rules));
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

        let score = PolicyMatcher::score_path(&metrics, &PathPreference::LowestLatency);
        assert!(score > 80.0); // Good latency should score high
    }
}
