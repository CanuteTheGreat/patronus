//! Automatic Remediation Actions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use anyhow::Result;
use async_trait::async_trait;
use crate::detector::{Issue, IssueType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationAction {
    RestartTunnel,
    SwitchToBackupPath,
    RestartBgpSession,
    ScaleUpBandwidth,
    RerouteTraffic,
    RollbackConfiguration,
    BlockTraffic,
    NotifyOperator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationStatus {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAttempt {
    pub id: Uuid,
    pub issue_id: Uuid,
    pub action: RemediationAction,
    pub status: RemediationStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub rollback_performed: bool,
}

impl RemediationAttempt {
    pub fn new(issue_id: Uuid, action: RemediationAction) -> Self {
        Self {
            id: Uuid::new_v4(),
            issue_id,
            action,
            status: RemediationStatus::Pending,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
            rollback_performed: false,
        }
    }

    pub fn start(&mut self) {
        self.status = RemediationStatus::InProgress;
    }

    pub fn succeed(&mut self) {
        self.status = RemediationStatus::Succeeded;
        self.completed_at = Some(Utc::now());
    }

    pub fn fail(&mut self, error: String) {
        self.status = RemediationStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
    }

    pub fn rollback(&mut self) {
        self.status = RemediationStatus::RolledBack;
        self.rollback_performed = true;
    }
}

#[async_trait]
pub trait RemediationExecutor: Send + Sync {
    async fn restart_tunnel(&self, tunnel_id: &str) -> Result<()>;
    async fn switch_path(&self, tunnel_id: &str, backup_path_id: &str) -> Result<()>;
    async fn restart_bgp_session(&self, peer_id: &str) -> Result<()>;
    async fn scale_bandwidth(&self, link_id: &str, new_capacity: u64) -> Result<()>;
    async fn reroute_traffic(&self, from: &str, to: &str) -> Result<()>;
    async fn rollback_config(&self, checkpoint_id: &str) -> Result<()>;
    async fn block_traffic(&self, source: &str) -> Result<()>;
}

pub struct RemediationEngine<E: RemediationExecutor> {
    executor: E,
    attempts: HashMap<Uuid, RemediationAttempt>,
    action_map: HashMap<IssueType, Vec<RemediationAction>>,
}

impl<E: RemediationExecutor> RemediationEngine<E> {
    pub fn new(executor: E) -> Self {
        let mut action_map = HashMap::new();

        // Map issue types to remediation actions
        action_map.insert(
            IssueType::TunnelDown,
            vec![RemediationAction::RestartTunnel, RemediationAction::SwitchToBackupPath],
        );

        action_map.insert(
            IssueType::HighLatency,
            vec![RemediationAction::SwitchToBackupPath, RemediationAction::RerouteTraffic],
        );

        action_map.insert(
            IssueType::PacketLoss,
            vec![RemediationAction::SwitchToBackupPath, RemediationAction::RestartTunnel],
        );

        action_map.insert(
            IssueType::BgpPeerDown,
            vec![RemediationAction::RestartBgpSession],
        );

        action_map.insert(
            IssueType::CapacityExhausted,
            vec![RemediationAction::ScaleUpBandwidth, RemediationAction::RerouteTraffic],
        );

        action_map.insert(
            IssueType::ConfigurationError,
            vec![RemediationAction::RollbackConfiguration],
        );

        action_map.insert(
            IssueType::SecurityThreat,
            vec![RemediationAction::BlockTraffic, RemediationAction::NotifyOperator],
        );

        Self {
            executor,
            attempts: HashMap::new(),
            action_map,
        }
    }

    pub fn get_remediation_actions(&self, issue: &Issue) -> Vec<RemediationAction> {
        self.action_map
            .get(&issue.issue_type)
            .cloned()
            .unwrap_or_else(|| vec![RemediationAction::NotifyOperator])
    }

    pub async fn remediate(&mut self, issue: &Issue) -> Result<RemediationAttempt> {
        if !issue.auto_remediable {
            anyhow::bail!("Issue is not auto-remediable");
        }

        let actions = self.get_remediation_actions(issue);

        if actions.is_empty() {
            anyhow::bail!("No remediation actions available for issue type");
        }

        // Try first action
        let action = actions[0].clone();
        let mut attempt = RemediationAttempt::new(issue.id, action.clone());

        attempt.start();
        tracing::info!("Starting remediation: {:?} for issue {}", action, issue.id);

        let result = self.execute_action(&action, &issue.affected_resource_id).await;

        match result {
            Ok(_) => {
                attempt.succeed();
                tracing::info!("Remediation succeeded: {:?}", action);
            }
            Err(e) => {
                attempt.fail(e.to_string());
                tracing::error!("Remediation failed: {:?} - {}", action, e);
            }
        }

        self.attempts.insert(attempt.id, attempt.clone());

        Ok(attempt)
    }

    async fn execute_action(&self, action: &RemediationAction, resource_id: &str) -> Result<()> {
        match action {
            RemediationAction::RestartTunnel => {
                self.executor.restart_tunnel(resource_id).await
            }
            RemediationAction::SwitchToBackupPath => {
                // Assuming backup path ID is derived
                let backup_path = format!("{}-backup", resource_id);
                self.executor.switch_path(resource_id, &backup_path).await
            }
            RemediationAction::RestartBgpSession => {
                self.executor.restart_bgp_session(resource_id).await
            }
            RemediationAction::ScaleUpBandwidth => {
                self.executor.scale_bandwidth(resource_id, 1000).await
            }
            RemediationAction::RerouteTraffic => {
                let backup = format!("{}-alt", resource_id);
                self.executor.reroute_traffic(resource_id, &backup).await
            }
            RemediationAction::RollbackConfiguration => {
                self.executor.rollback_config("last-good").await
            }
            RemediationAction::BlockTraffic => {
                self.executor.block_traffic(resource_id).await
            }
            RemediationAction::NotifyOperator => {
                tracing::warn!("Manual intervention required for {}", resource_id);
                Ok(())
            }
        }
    }

    pub fn get_attempt(&self, attempt_id: &Uuid) -> Option<&RemediationAttempt> {
        self.attempts.get(attempt_id)
    }

    pub fn get_attempts_for_issue(&self, issue_id: &Uuid) -> Vec<&RemediationAttempt> {
        self.attempts
            .values()
            .filter(|a| &a.issue_id == issue_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Issue, IssueSeverity};

    struct MockExecutor;

    #[async_trait]
    impl RemediationExecutor for MockExecutor {
        async fn restart_tunnel(&self, _tunnel_id: &str) -> Result<()> {
            Ok(())
        }

        async fn switch_path(&self, _tunnel_id: &str, _backup_path_id: &str) -> Result<()> {
            Ok(())
        }

        async fn restart_bgp_session(&self, _peer_id: &str) -> Result<()> {
            Ok(())
        }

        async fn scale_bandwidth(&self, _link_id: &str, _new_capacity: u64) -> Result<()> {
            Ok(())
        }

        async fn reroute_traffic(&self, _from: &str, _to: &str) -> Result<()> {
            Ok(())
        }

        async fn rollback_config(&self, _checkpoint_id: &str) -> Result<()> {
            Ok(())
        }

        async fn block_traffic(&self, _source: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_remediation_attempt_creation() {
        let issue_id = Uuid::new_v4();
        let attempt = RemediationAttempt::new(issue_id, RemediationAction::RestartTunnel);

        assert_eq!(attempt.issue_id, issue_id);
        assert_eq!(attempt.action, RemediationAction::RestartTunnel);
        assert_eq!(attempt.status, RemediationStatus::Pending);
    }

    #[test]
    fn test_remediation_attempt_lifecycle() {
        let issue_id = Uuid::new_v4();
        let mut attempt = RemediationAttempt::new(issue_id, RemediationAction::RestartTunnel);

        attempt.start();
        assert_eq!(attempt.status, RemediationStatus::InProgress);

        attempt.succeed();
        assert_eq!(attempt.status, RemediationStatus::Succeeded);
        assert!(attempt.completed_at.is_some());
    }

    #[test]
    fn test_remediation_attempt_failure() {
        let issue_id = Uuid::new_v4();
        let mut attempt = RemediationAttempt::new(issue_id, RemediationAction::RestartTunnel);

        attempt.start();
        attempt.fail("Connection timeout".to_string());

        assert_eq!(attempt.status, RemediationStatus::Failed);
        assert_eq!(attempt.error, Some("Connection timeout".to_string()));
    }

    #[test]
    fn test_get_remediation_actions() {
        let executor = MockExecutor;
        let engine = RemediationEngine::new(executor);

        let issue = Issue::new(
            IssueType::TunnelDown,
            IssueSeverity::Critical,
            "Tunnel is down",
            "tunnel-123",
        );

        let actions = engine.get_remediation_actions(&issue);

        assert!(actions.contains(&RemediationAction::RestartTunnel));
        assert!(actions.contains(&RemediationAction::SwitchToBackupPath));
    }

    #[tokio::test]
    async fn test_remediate_tunnel_down() {
        let executor = MockExecutor;
        let mut engine = RemediationEngine::new(executor);

        let issue = Issue::new(
            IssueType::TunnelDown,
            IssueSeverity::Critical,
            "Tunnel is down",
            "tunnel-123",
        );

        let attempt = engine.remediate(&issue).await.unwrap();

        assert_eq!(attempt.action, RemediationAction::RestartTunnel);
        assert_eq!(attempt.status, RemediationStatus::Succeeded);
    }

    #[tokio::test]
    async fn test_remediate_bgp_peer_down() {
        let executor = MockExecutor;
        let mut engine = RemediationEngine::new(executor);

        let issue = Issue::new(
            IssueType::BgpPeerDown,
            IssueSeverity::High,
            "BGP peer is down",
            "peer-123",
        );

        let attempt = engine.remediate(&issue).await.unwrap();

        assert_eq!(attempt.action, RemediationAction::RestartBgpSession);
        assert_eq!(attempt.status, RemediationStatus::Succeeded);
    }

    #[tokio::test]
    async fn test_non_remediable_issue() {
        let executor = MockExecutor;
        let mut engine = RemediationEngine::new(executor);

        let issue = Issue::new(
            IssueType::TunnelDown,
            IssueSeverity::Critical,
            "Tunnel is down",
            "tunnel-123",
        )
        .non_remediable();

        let result = engine.remediate(&issue).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_attempts_for_issue() {
        let executor = MockExecutor;
        let mut engine = RemediationEngine::new(executor);

        let issue = Issue::new(
            IssueType::TunnelDown,
            IssueSeverity::Critical,
            "Tunnel is down",
            "tunnel-123",
        );

        let issue_id = issue.id;
        engine.remediate(&issue).await.unwrap();

        let attempts = engine.get_attempts_for_issue(&issue_id);

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].issue_id, issue_id);
    }
}
