//! Anomaly and Issue Detection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IssueType {
    TunnelDown,
    HighLatency,
    PacketLoss,
    BgpPeerDown,
    RoutingLoop,
    CapacityExhausted,
    SecurityThreat,
    ConfigurationError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub id: Uuid,
    pub issue_type: IssueType,
    pub severity: IssueSeverity,
    pub description: String,
    pub affected_resource_id: String,
    pub detected_at: DateTime<Utc>,
    pub metrics: HashMap<String, f64>,
    pub auto_remediable: bool,
}

impl Issue {
    pub fn new(
        issue_type: IssueType,
        severity: IssueSeverity,
        description: impl Into<String>,
        affected_resource_id: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            issue_type,
            severity,
            description: description.into(),
            affected_resource_id: affected_resource_id.into(),
            detected_at: Utc::now(),
            metrics: HashMap::new(),
            auto_remediable: true,
        }
    }

    pub fn with_metric(mut self, key: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(key.into(), value);
        self
    }

    pub fn non_remediable(mut self) -> Self {
        self.auto_remediable = false;
        self
    }
}

pub struct IssueDetector {
    thresholds: HashMap<String, f64>,
}

impl IssueDetector {
    pub fn new() -> Self {
        let mut thresholds = HashMap::new();

        // Default thresholds
        thresholds.insert("latency_ms".to_string(), 100.0);
        thresholds.insert("packet_loss_percent".to_string(), 5.0);
        thresholds.insert("cpu_percent".to_string(), 90.0);
        thresholds.insert("memory_percent".to_string(), 85.0);
        thresholds.insert("bandwidth_utilization_percent".to_string(), 80.0);

        Self { thresholds }
    }

    pub fn set_threshold(&mut self, metric: impl Into<String>, value: f64) {
        self.thresholds.insert(metric.into(), value);
    }

    pub fn detect_tunnel_issues(&self, tunnel_id: &str, metrics: &HashMap<String, f64>) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Check if tunnel is down
        if let Some(&state) = metrics.get("state") {
            if state == 0.0 {
                issues.push(
                    Issue::new(
                        IssueType::TunnelDown,
                        IssueSeverity::Critical,
                        format!("Tunnel {} is down", tunnel_id),
                        tunnel_id,
                    )
                );
            }
        }

        // Check latency
        if let Some(&latency) = metrics.get("latency_ms") {
            let threshold = self.thresholds.get("latency_ms").unwrap_or(&100.0);
            if latency > *threshold {
                issues.push(
                    Issue::new(
                        IssueType::HighLatency,
                        if latency > threshold * 2.0 { IssueSeverity::High } else { IssueSeverity::Medium },
                        format!("High latency detected: {:.2}ms (threshold: {:.2}ms)", latency, threshold),
                        tunnel_id,
                    )
                    .with_metric("latency_ms", latency)
                );
            }
        }

        // Check packet loss
        if let Some(&packet_loss) = metrics.get("packet_loss_percent") {
            let threshold = self.thresholds.get("packet_loss_percent").unwrap_or(&5.0);
            if packet_loss > *threshold {
                issues.push(
                    Issue::new(
                        IssueType::PacketLoss,
                        if packet_loss > threshold * 2.0 { IssueSeverity::High } else { IssueSeverity::Medium },
                        format!("Packet loss detected: {:.2}% (threshold: {:.2}%)", packet_loss, threshold),
                        tunnel_id,
                    )
                    .with_metric("packet_loss_percent", packet_loss)
                );
            }
        }

        issues
    }

    pub fn detect_bgp_issues(&self, peer_id: &str, peer_state: &str) -> Option<Issue> {
        if peer_state != "established" {
            Some(
                Issue::new(
                    IssueType::BgpPeerDown,
                    IssueSeverity::High,
                    format!("BGP peer {} is not established (state: {})", peer_id, peer_state),
                    peer_id,
                )
            )
        } else {
            None
        }
    }

    pub fn detect_capacity_issues(&self, resource_id: &str, utilization: f64) -> Option<Issue> {
        let threshold = self.thresholds.get("bandwidth_utilization_percent").unwrap_or(&80.0);

        if utilization > *threshold {
            Some(
                Issue::new(
                    IssueType::CapacityExhausted,
                    if utilization > 95.0 { IssueSeverity::Critical } else { IssueSeverity::High },
                    format!("Capacity exhausted: {:.2}% utilization (threshold: {:.2}%)", utilization, threshold),
                    resource_id,
                )
                .with_metric("utilization_percent", utilization)
            )
        } else {
            None
        }
    }
}

impl Default for IssueDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_creation() {
        let issue = Issue::new(
            IssueType::TunnelDown,
            IssueSeverity::Critical,
            "Tunnel is down",
            "tunnel-123",
        );

        assert_eq!(issue.issue_type, IssueType::TunnelDown);
        assert_eq!(issue.severity, IssueSeverity::Critical);
        assert_eq!(issue.affected_resource_id, "tunnel-123");
        assert!(issue.auto_remediable);
    }

    #[test]
    fn test_issue_with_metrics() {
        let issue = Issue::new(
            IssueType::HighLatency,
            IssueSeverity::Medium,
            "High latency",
            "tunnel-123",
        )
        .with_metric("latency_ms", 150.0);

        assert_eq!(issue.metrics.get("latency_ms"), Some(&150.0));
    }

    #[test]
    fn test_detect_tunnel_down() {
        let detector = IssueDetector::new();
        let mut metrics = HashMap::new();
        metrics.insert("state".to_string(), 0.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_type, IssueType::TunnelDown);
        assert_eq!(issues[0].severity, IssueSeverity::Critical);
    }

    #[test]
    fn test_detect_high_latency() {
        let detector = IssueDetector::new();
        let mut metrics = HashMap::new();
        metrics.insert("latency_ms".to_string(), 150.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_type, IssueType::HighLatency);
    }

    #[test]
    fn test_detect_packet_loss() {
        let detector = IssueDetector::new();
        let mut metrics = HashMap::new();
        metrics.insert("packet_loss_percent".to_string(), 10.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue_type, IssueType::PacketLoss);
    }

    #[test]
    fn test_detect_multiple_issues() {
        let detector = IssueDetector::new();
        let mut metrics = HashMap::new();
        metrics.insert("latency_ms".to_string(), 150.0);
        metrics.insert("packet_loss_percent".to_string(), 10.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn test_detect_bgp_peer_down() {
        let detector = IssueDetector::new();
        let issue = detector.detect_bgp_issues("peer-123", "idle");

        assert!(issue.is_some());
        let issue = issue.unwrap();
        assert_eq!(issue.issue_type, IssueType::BgpPeerDown);
        assert_eq!(issue.severity, IssueSeverity::High);
    }

    #[test]
    fn test_detect_capacity_exhausted() {
        let detector = IssueDetector::new();
        let issue = detector.detect_capacity_issues("link-123", 95.0);

        assert!(issue.is_some());
        let issue = issue.unwrap();
        assert_eq!(issue.issue_type, IssueType::CapacityExhausted);
    }

    #[test]
    fn test_custom_threshold() {
        let mut detector = IssueDetector::new();
        detector.set_threshold("latency_ms", 50.0);

        let mut metrics = HashMap::new();
        metrics.insert("latency_ms".to_string(), 60.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_no_issues() {
        let detector = IssueDetector::new();
        let mut metrics = HashMap::new();
        metrics.insert("latency_ms".to_string(), 50.0);
        metrics.insert("packet_loss_percent".to_string(), 1.0);

        let issues = detector.detect_tunnel_issues("tunnel-123", &metrics);

        assert_eq!(issues.len(), 0);
    }
}
