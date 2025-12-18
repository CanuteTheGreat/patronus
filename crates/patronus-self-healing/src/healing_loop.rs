//! Self-Healing Control Loop

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use anyhow::Result;
use crate::detector::IssueDetector;
use crate::remediation::{RemediationEngine, RemediationExecutor, RemediationAttempt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingStats {
    pub issues_detected: u64,
    pub remediations_attempted: u64,
    pub remediations_succeeded: u64,
    pub remediations_failed: u64,
    pub last_run: Option<String>,
}

impl Default for HealingStats {
    fn default() -> Self {
        Self {
            issues_detected: 0,
            remediations_attempted: 0,
            remediations_succeeded: 0,
            remediations_failed: 0,
            last_run: None,
        }
    }
}

pub struct HealingLoop<E: RemediationExecutor> {
    detector: Arc<RwLock<IssueDetector>>,
    engine: Arc<RwLock<RemediationEngine<E>>>,
    stats: Arc<RwLock<HealingStats>>,
    interval_secs: u64,
    enabled: Arc<RwLock<bool>>,
}

impl<E: RemediationExecutor + 'static> HealingLoop<E> {
    pub fn new(
        detector: IssueDetector,
        engine: RemediationEngine<E>,
        interval_secs: u64,
    ) -> Self {
        Self {
            detector: Arc::new(RwLock::new(detector)),
            engine: Arc::new(RwLock::new(engine)),
            stats: Arc::new(RwLock::new(HealingStats::default())),
            interval_secs,
            enabled: Arc::new(RwLock::new(true)),
        }
    }

    pub async fn enable(&self) {
        let mut enabled = self.enabled.write().await;
        *enabled = true;
        tracing::info!("Self-healing loop enabled");
    }

    pub async fn disable(&self) {
        let mut enabled = self.enabled.write().await;
        *enabled = false;
        tracing::info!("Self-healing loop disabled");
    }

    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }

    pub async fn get_stats(&self) -> HealingStats {
        self.stats.read().await.clone()
    }

    pub async fn detect_and_remediate(&self, resource_metrics: &HashMap<String, HashMap<String, f64>>) -> Result<Vec<RemediationAttempt>> {
        let mut all_attempts = Vec::new();

        // Check if enabled
        if !self.is_enabled().await {
            return Ok(all_attempts);
        }

        let detector = self.detector.read().await;
        let mut engine = self.engine.write().await;
        let mut stats = self.stats.write().await;

        // Detect issues across all resources
        for (resource_id, metrics) in resource_metrics {
            let issues = detector.detect_tunnel_issues(resource_id, metrics);

            for issue in issues {
                stats.issues_detected += 1;
                tracing::warn!("Issue detected: {:?} on {}", issue.issue_type, resource_id);

                // Attempt remediation
                if issue.auto_remediable {
                    stats.remediations_attempted += 1;

                    match engine.remediate(&issue).await {
                        Ok(attempt) => {
                            if attempt.status == crate::remediation::RemediationStatus::Succeeded {
                                stats.remediations_succeeded += 1;
                            } else {
                                stats.remediations_failed += 1;
                            }
                            all_attempts.push(attempt);
                        }
                        Err(e) => {
                            stats.remediations_failed += 1;
                            tracing::error!("Remediation error: {}", e);
                        }
                    }
                }
            }
        }

        stats.last_run = Some(chrono::Utc::now().to_rfc3339());

        Ok(all_attempts)
    }

    pub async fn run_once(&self, resource_metrics: &HashMap<String, HashMap<String, f64>>) -> Result<Vec<RemediationAttempt>> {
        self.detect_and_remediate(resource_metrics).await
    }

    pub async fn run_loop(self: Arc<Self>) {
        let mut tick = interval(Duration::from_secs(self.interval_secs));

        loop {
            tick.tick().await;

            if !self.is_enabled().await {
                continue;
            }

            tracing::debug!("Running self-healing loop");

            // In production, this would fetch real metrics from monitoring system
            let resource_metrics = HashMap::new();

            match self.detect_and_remediate(&resource_metrics).await {
                Ok(attempts) => {
                    if !attempts.is_empty() {
                        tracing::info!("Completed {} remediation attempts", attempts.len());
                    }
                }
                Err(e) => {
                    tracing::error!("Healing loop error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::IssueDetector;
    use crate::remediation::{RemediationEngine, RemediationExecutor};
    use async_trait::async_trait;

    struct MockExecutor;

    #[async_trait]
    impl RemediationExecutor for MockExecutor {
        async fn restart_tunnel(&self, _: &str) -> Result<()> { Ok(()) }
        async fn switch_path(&self, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn restart_bgp_session(&self, _: &str) -> Result<()> { Ok(()) }
        async fn scale_bandwidth(&self, _: &str, _: u64) -> Result<()> { Ok(()) }
        async fn reroute_traffic(&self, _: &str, _: &str) -> Result<()> { Ok(()) }
        async fn rollback_config(&self, _: &str) -> Result<()> { Ok(()) }
        async fn block_traffic(&self, _: &str) -> Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_healing_loop_creation() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        assert_eq!(loop_instance.interval_secs, 60);
        assert!(loop_instance.is_enabled().await);
    }

    #[tokio::test]
    async fn test_enable_disable() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        loop_instance.disable().await;
        assert!(!loop_instance.is_enabled().await);

        loop_instance.enable().await;
        assert!(loop_instance.is_enabled().await);
    }

    #[tokio::test]
    async fn test_detect_and_remediate() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        let mut resource_metrics = HashMap::new();
        let mut tunnel_metrics = HashMap::new();
        tunnel_metrics.insert("state".to_string(), 0.0); // Tunnel down
        resource_metrics.insert("tunnel-123".to_string(), tunnel_metrics);

        let attempts = loop_instance.detect_and_remediate(&resource_metrics).await.unwrap();

        assert_eq!(attempts.len(), 1);
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        let mut resource_metrics = HashMap::new();
        let mut tunnel_metrics = HashMap::new();
        tunnel_metrics.insert("latency_ms".to_string(), 150.0);
        resource_metrics.insert("tunnel-123".to_string(), tunnel_metrics);

        loop_instance.detect_and_remediate(&resource_metrics).await.unwrap();

        let stats = loop_instance.get_stats().await;

        assert_eq!(stats.issues_detected, 1);
        assert_eq!(stats.remediations_attempted, 1);
        assert_eq!(stats.remediations_succeeded, 1);
        assert!(stats.last_run.is_some());
    }

    #[tokio::test]
    async fn test_disabled_loop_does_nothing() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        loop_instance.disable().await;

        let mut resource_metrics = HashMap::new();
        let mut tunnel_metrics = HashMap::new();
        tunnel_metrics.insert("state".to_string(), 0.0);
        resource_metrics.insert("tunnel-123".to_string(), tunnel_metrics);

        let attempts = loop_instance.detect_and_remediate(&resource_metrics).await.unwrap();

        assert_eq!(attempts.len(), 0);

        let stats = loop_instance.get_stats().await;
        assert_eq!(stats.issues_detected, 0);
    }

    #[tokio::test]
    async fn test_multiple_issues() {
        let detector = IssueDetector::new();
        let engine = RemediationEngine::new(MockExecutor);
        let loop_instance = HealingLoop::new(detector, engine, 60);

        let mut resource_metrics = HashMap::new();

        // Tunnel 1: High latency
        let mut tunnel1_metrics = HashMap::new();
        tunnel1_metrics.insert("latency_ms".to_string(), 150.0);
        resource_metrics.insert("tunnel-1".to_string(), tunnel1_metrics);

        // Tunnel 2: Packet loss
        let mut tunnel2_metrics = HashMap::new();
        tunnel2_metrics.insert("packet_loss_percent".to_string(), 10.0);
        resource_metrics.insert("tunnel-2".to_string(), tunnel2_metrics);

        let attempts = loop_instance.detect_and_remediate(&resource_metrics).await.unwrap();

        assert_eq!(attempts.len(), 2);

        let stats = loop_instance.get_stats().await;
        assert_eq!(stats.issues_detected, 2);
        assert_eq!(stats.remediations_attempted, 2);
    }
}
