//! Failover policy definitions and management

use crate::types::PathId;
use serde::{Deserialize, Serialize};

/// Failover policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverPolicy {
    /// Unique policy identifier
    pub policy_id: u64,

    /// Human-readable policy name
    pub name: String,

    /// Primary path (preferred)
    pub primary_path_id: PathId,

    /// Backup paths (in priority order)
    pub backup_path_ids: Vec<PathId>,

    /// Health score threshold for triggering failover
    /// When primary drops below this, failover to backup
    pub failover_threshold: f64,

    /// Health score threshold for triggering failback
    /// Primary must exceed this to failback from backup
    pub failback_threshold: f64,

    /// Delay in seconds before failing back to primary
    /// Prevents flapping by requiring sustained health
    pub failback_delay_secs: u64,

    /// Whether this policy is active
    pub enabled: bool,
}

impl FailoverPolicy {
    /// Create a new failover policy
    pub fn new(
        policy_id: u64,
        name: String,
        primary_path_id: PathId,
        backup_path_ids: Vec<PathId>,
    ) -> Self {
        Self {
            policy_id,
            name,
            primary_path_id,
            backup_path_ids,
            failover_threshold: 50.0,  // Default: failover when degraded
            failback_threshold: 80.0,  // Default: failback when healthy
            failback_delay_secs: 60,   // Default: 1 minute stabilization
            enabled: true,
        }
    }

    /// Check if a health score should trigger failover
    pub fn should_failover(&self, primary_health_score: f64) -> bool {
        self.enabled && primary_health_score < self.failover_threshold
    }

    /// Check if a health score allows failback
    pub fn should_failback(&self, primary_health_score: f64) -> bool {
        self.enabled && primary_health_score >= self.failback_threshold
    }

    /// Get the best available backup path
    ///
    /// Returns the first backup path, or None if no backups configured
    pub fn get_best_backup(&self, backup_health: &[(PathId, f64)]) -> Option<PathId> {
        // Try backups in priority order
        for backup_id in &self.backup_path_ids {
            // Check if this backup is healthy
            if let Some((_, health)) = backup_health.iter().find(|(id, _)| id == backup_id) {
                if *health >= 50.0 {
                    // At least degraded status
                    return Some(*backup_id);
                }
            }
        }

        // If no healthy backup found, return first backup anyway
        // (better to try than to stay on failed primary)
        self.backup_path_ids.first().copied()
    }

    /// Validate policy configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Policy name cannot be empty".to_string());
        }

        if self.backup_path_ids.is_empty() {
            return Err("At least one backup path required".to_string());
        }

        if self.backup_path_ids.contains(&self.primary_path_id) {
            return Err("Primary path cannot be in backup list".to_string());
        }

        if self.failover_threshold >= self.failback_threshold {
            return Err("Failover threshold must be less than failback threshold".to_string());
        }

        if self.failover_threshold < 0.0 || self.failover_threshold > 100.0 {
            return Err("Failover threshold must be between 0 and 100".to_string());
        }

        if self.failback_threshold < 0.0 || self.failback_threshold > 100.0 {
            return Err("Failback threshold must be between 0 and 100".to_string());
        }

        Ok(())
    }
}

impl Default for FailoverPolicy {
    fn default() -> Self {
        Self {
            policy_id: 0,
            name: "default".to_string(),
            primary_path_id: PathId::new(0),
            backup_path_ids: Vec::new(),
            failover_threshold: 50.0,
            failback_threshold: 80.0,
            failback_delay_secs: 60,
            enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = FailoverPolicy::new(
            1,
            "test-policy".to_string(),
            PathId::new(10),
            vec![PathId::new(20), PathId::new(30)],
        );

        assert_eq!(policy.policy_id, 1);
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.primary_path_id, PathId::new(10));
        assert_eq!(policy.backup_path_ids.len(), 2);
        assert!(policy.enabled);
    }

    #[test]
    fn test_should_failover() {
        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );

        // Below threshold - should failover
        assert!(policy.should_failover(40.0));

        // At threshold - should NOT failover
        assert!(!policy.should_failover(50.0));

        // Above threshold - should NOT failover
        assert!(!policy.should_failover(60.0));
    }

    #[test]
    fn test_should_failback() {
        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );

        // Below threshold - should NOT failback
        assert!(!policy.should_failback(70.0));

        // At threshold - should failback
        assert!(policy.should_failback(80.0));

        // Above threshold - should failback
        assert!(!policy.should_failback(90.0));
    }

    #[test]
    fn test_disabled_policy() {
        let mut policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );
        policy.enabled = false;

        // Disabled policy should never trigger
        assert!(!policy.should_failover(0.0));
        assert!(!policy.should_failback(100.0));
    }

    #[test]
    fn test_get_best_backup() {
        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20), PathId::new(30), PathId::new(40)],
        );

        // First backup is healthy
        let backup_health = vec![
            (PathId::new(20), 90.0),
            (PathId::new(30), 60.0),
            (PathId::new(40), 70.0),
        ];
        assert_eq!(policy.get_best_backup(&backup_health), Some(PathId::new(20)));

        // First backup is down, second is healthy
        let backup_health = vec![
            (PathId::new(20), 30.0),
            (PathId::new(30), 60.0),
            (PathId::new(40), 70.0),
        ];
        assert_eq!(policy.get_best_backup(&backup_health), Some(PathId::new(30)));

        // All backups down, return first anyway
        let backup_health = vec![
            (PathId::new(20), 30.0),
            (PathId::new(30), 20.0),
            (PathId::new(40), 10.0),
        ];
        assert_eq!(policy.get_best_backup(&backup_health), Some(PathId::new(20)));
    }

    #[test]
    fn test_validate_empty_name() {
        let mut policy = FailoverPolicy::default();
        policy.name = "".to_string();
        policy.backup_path_ids = vec![PathId::new(1)];

        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_no_backups() {
        let mut policy = FailoverPolicy::default();
        policy.name = "test".to_string();
        policy.backup_path_ids = Vec::new();

        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_primary_in_backups() {
        let mut policy = FailoverPolicy::default();
        policy.name = "test".to_string();
        policy.primary_path_id = PathId::new(10);
        policy.backup_path_ids = vec![PathId::new(10), PathId::new(20)];

        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_thresholds() {
        let mut policy = FailoverPolicy::default();
        policy.name = "test".to_string();
        policy.primary_path_id = PathId::new(10);
        policy.backup_path_ids = vec![PathId::new(20)];

        // Invalid: failover >= failback
        policy.failover_threshold = 80.0;
        policy.failback_threshold = 80.0;
        assert!(policy.validate().is_err());

        // Invalid: failover > failback
        policy.failover_threshold = 90.0;
        policy.failback_threshold = 80.0;
        assert!(policy.validate().is_err());

        // Valid
        policy.failover_threshold = 50.0;
        policy.failback_threshold = 80.0;
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_threshold_ranges() {
        let mut policy = FailoverPolicy::default();
        policy.name = "test".to_string();
        policy.primary_path_id = PathId::new(10);
        policy.backup_path_ids = vec![PathId::new(20)];

        // Invalid: failover < 0
        policy.failover_threshold = -10.0;
        assert!(policy.validate().is_err());

        // Invalid: failover > 100
        policy.failover_threshold = 110.0;
        assert!(policy.validate().is_err());

        // Invalid: failback < 0
        policy.failover_threshold = 50.0;
        policy.failback_threshold = -10.0;
        assert!(policy.validate().is_err());

        // Invalid: failback > 100
        policy.failback_threshold = 110.0;
        assert!(policy.validate().is_err());
    }
}
