//! Failover event logging and tracking

use crate::types::PathId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Type of failover event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverEventType {
    /// Failover was triggered (switched to backup)
    Triggered,

    /// Failback was completed (returned to primary)
    Completed,

    /// Failover failed (no healthy backup available)
    Failed,

    /// Policy was enabled
    PolicyEnabled,

    /// Policy was disabled
    PolicyDisabled,
}

impl FailoverEventType {
    /// Convert to string for database storage
    pub fn as_str(&self) -> &'static str {
        match self {
            FailoverEventType::Triggered => "triggered",
            FailoverEventType::Completed => "completed",
            FailoverEventType::Failed => "failed",
            FailoverEventType::PolicyEnabled => "policy_enabled",
            FailoverEventType::PolicyDisabled => "policy_disabled",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "triggered" => Some(FailoverEventType::Triggered),
            "completed" => Some(FailoverEventType::Completed),
            "failed" => Some(FailoverEventType::Failed),
            "policy_enabled" => Some(FailoverEventType::PolicyEnabled),
            "policy_disabled" => Some(FailoverEventType::PolicyDisabled),
            _ => None,
        }
    }
}

/// Failover event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEvent {
    /// Event identifier (database ID)
    pub event_id: Option<u64>,

    /// Policy that triggered the event
    pub policy_id: u64,

    /// Type of event
    pub event_type: FailoverEventType,

    /// Source path (path we're failing over from)
    pub from_path_id: Option<PathId>,

    /// Destination path (path we're failing over to)
    pub to_path_id: Option<PathId>,

    /// Reason for the failover
    pub reason: String,

    /// Health score of primary at time of event
    pub primary_health_score: Option<f64>,

    /// Health score of backup at time of event
    pub backup_health_score: Option<f64>,

    /// When the event occurred
    pub timestamp: SystemTime,
}

impl FailoverEvent {
    /// Create a new failover triggered event
    pub fn triggered(
        policy_id: u64,
        from_path: PathId,
        to_path: PathId,
        primary_health: f64,
        backup_health: f64,
        reason: String,
    ) -> Self {
        Self {
            event_id: None,
            policy_id,
            event_type: FailoverEventType::Triggered,
            from_path_id: Some(from_path),
            to_path_id: Some(to_path),
            reason,
            primary_health_score: Some(primary_health),
            backup_health_score: Some(backup_health),
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new failback completed event
    pub fn completed(
        policy_id: u64,
        to_path: PathId,
        primary_health: f64,
        reason: String,
    ) -> Self {
        Self {
            event_id: None,
            policy_id,
            event_type: FailoverEventType::Completed,
            from_path_id: None,
            to_path_id: Some(to_path),
            reason,
            primary_health_score: Some(primary_health),
            backup_health_score: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new failover failed event
    pub fn failed(policy_id: u64, reason: String) -> Self {
        Self {
            event_id: None,
            policy_id,
            event_type: FailoverEventType::Failed,
            from_path_id: None,
            to_path_id: None,
            reason,
            primary_health_score: None,
            backup_health_score: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a policy enabled event
    pub fn policy_enabled(policy_id: u64) -> Self {
        Self {
            event_id: None,
            policy_id,
            event_type: FailoverEventType::PolicyEnabled,
            from_path_id: None,
            to_path_id: None,
            reason: "Policy enabled".to_string(),
            primary_health_score: None,
            backup_health_score: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a policy disabled event
    pub fn policy_disabled(policy_id: u64) -> Self {
        Self {
            event_id: None,
            policy_id,
            event_type: FailoverEventType::PolicyDisabled,
            from_path_id: None,
            to_path_id: None,
            reason: "Policy disabled".to_string(),
            primary_health_score: None,
            backup_health_score: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Check if this is a state-changing event (triggered or completed)
    pub fn is_state_change(&self) -> bool {
        matches!(
            self.event_type,
            FailoverEventType::Triggered | FailoverEventType::Completed
        )
    }

    /// Get a human-readable description of the event
    pub fn description(&self) -> String {
        match self.event_type {
            FailoverEventType::Triggered => {
                format!(
                    "Failover triggered from {} to {} (health: {:.1} → {:.1}): {}",
                    self.from_path_id.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    self.to_path_id.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    self.primary_health_score.unwrap_or(0.0),
                    self.backup_health_score.unwrap_or(0.0),
                    self.reason
                )
            }
            FailoverEventType::Completed => {
                format!(
                    "Failback completed to {} (health: {:.1}): {}",
                    self.to_path_id.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    self.primary_health_score.unwrap_or(0.0),
                    self.reason
                )
            }
            FailoverEventType::Failed => {
                format!("Failover failed: {}", self.reason)
            }
            FailoverEventType::PolicyEnabled => {
                "Policy enabled".to_string()
            }
            FailoverEventType::PolicyDisabled => {
                "Policy disabled".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        assert_eq!(FailoverEventType::Triggered.as_str(), "triggered");
        assert_eq!(FailoverEventType::Completed.as_str(), "completed");
        assert_eq!(FailoverEventType::Failed.as_str(), "failed");

        assert_eq!(
            FailoverEventType::from_str("triggered"),
            Some(FailoverEventType::Triggered)
        );
        assert_eq!(
            FailoverEventType::from_str("completed"),
            Some(FailoverEventType::Completed)
        );
        assert_eq!(
            FailoverEventType::from_str("invalid"),
            None
        );
    }

    #[test]
    fn test_triggered_event() {
        let event = FailoverEvent::triggered(
            1,
            PathId::new(10),
            PathId::new(20),
            45.0,
            85.0,
            "Primary health below threshold".to_string(),
        );

        assert_eq!(event.policy_id, 1);
        assert_eq!(event.event_type, FailoverEventType::Triggered);
        assert_eq!(event.from_path_id, Some(PathId::new(10)));
        assert_eq!(event.to_path_id, Some(PathId::new(20)));
        assert_eq!(event.primary_health_score, Some(45.0));
        assert_eq!(event.backup_health_score, Some(85.0));
        assert!(event.is_state_change());
    }

    #[test]
    fn test_completed_event() {
        let event = FailoverEvent::completed(
            1,
            PathId::new(10),
            90.0,
            "Primary recovered".to_string(),
        );

        assert_eq!(event.policy_id, 1);
        assert_eq!(event.event_type, FailoverEventType::Completed);
        assert_eq!(event.to_path_id, Some(PathId::new(10)));
        assert_eq!(event.primary_health_score, Some(90.0));
        assert!(event.is_state_change());
    }

    #[test]
    fn test_failed_event() {
        let event = FailoverEvent::failed(
            1,
            "No healthy backup available".to_string(),
        );

        assert_eq!(event.policy_id, 1);
        assert_eq!(event.event_type, FailoverEventType::Failed);
        assert!(!event.is_state_change());
    }

    #[test]
    fn test_policy_events() {
        let enabled = FailoverEvent::policy_enabled(1);
        assert_eq!(enabled.event_type, FailoverEventType::PolicyEnabled);
        assert!(!enabled.is_state_change());

        let disabled = FailoverEvent::policy_disabled(1);
        assert_eq!(disabled.event_type, FailoverEventType::PolicyDisabled);
        assert!(!disabled.is_state_change());
    }

    #[test]
    fn test_event_description() {
        let event = FailoverEvent::triggered(
            1,
            PathId::new(10),
            PathId::new(20),
            45.0,
            85.0,
            "Test".to_string(),
        );

        let desc = event.description();
        assert!(desc.contains("Failover triggered"));
        assert!(desc.contains("45.0"));
        assert!(desc.contains("85.0"));
    }
}
