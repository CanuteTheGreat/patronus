//! Automatic routing failover for SD-WAN
//!
//! This module provides automatic path failover based on health monitoring,
//! with configurable policies and intelligent failback logic.
//!
//! # Features
//!
//! - **Policy-Based Failover**: Configure primary and backup paths
//! - **Health-Based Triggers**: Automatic failover on path degradation
//! - **Smart Failback**: Hysteresis prevents flapping
//! - **Event Logging**: Complete audit trail of failover events
//!
//! # Example
//!
//! ```rust,no_run
//! use patronus_sdwan::failover::{FailoverEngine, FailoverPolicy};
//! use patronus_sdwan::types::PathId;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = FailoverPolicy {
//!     policy_id: 1,
//!     name: "primary-backup".to_string(),
//!     primary_path_id: PathId::new(1),
//!     backup_path_ids: vec![PathId::new(2), PathId::new(3)],
//!     failover_threshold: 50.0,
//!     failback_threshold: 80.0,
//!     failback_delay_secs: 60,
//!     enabled: true,
//! };
//!
//! // Engine will monitor health and trigger failover automatically
//! # Ok(())
//! # }
//! ```

mod engine;
mod events;
mod policy;

pub use engine::FailoverEngine;
pub use events::{FailoverEvent, FailoverEventType};
pub use policy::FailoverPolicy;

use crate::types::PathId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Current state of a failover policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverState {
    /// Policy identifier
    pub policy_id: u64,

    /// Currently active path
    pub active_path_id: PathId,

    /// Whether we're using primary or backup
    pub using_primary: bool,

    /// When last failover occurred
    pub last_failover: Option<SystemTime>,

    /// When primary became healthy again (for failback timing)
    pub primary_healthy_since: Option<SystemTime>,

    /// Number of failovers in current session
    pub failover_count: u64,
}

impl FailoverState {
    /// Create a new failover state
    pub fn new(policy_id: u64, primary_path_id: PathId) -> Self {
        Self {
            policy_id,
            active_path_id: primary_path_id,
            using_primary: true,
            last_failover: None,
            primary_healthy_since: Some(SystemTime::now()),
            failover_count: 0,
        }
    }

    /// Check if enough time has passed for failback
    pub fn can_failback(&self, failback_delay_secs: u64) -> bool {
        if let Some(healthy_since) = self.primary_healthy_since {
            if let Ok(elapsed) = SystemTime::now().duration_since(healthy_since) {
                return elapsed.as_secs() >= failback_delay_secs;
            }
        }
        false
    }

    /// Record a failover event
    pub fn record_failover(&mut self, new_path_id: PathId) {
        self.active_path_id = new_path_id;
        self.last_failover = Some(SystemTime::now());
        self.failover_count += 1;
        self.primary_healthy_since = None;
    }

    /// Record failback to primary
    pub fn record_failback(&mut self, primary_path_id: PathId) {
        self.active_path_id = primary_path_id;
        self.using_primary = true;
        self.last_failover = Some(SystemTime::now());
        self.failover_count += 1;
    }

    /// Mark primary as healthy
    pub fn mark_primary_healthy(&mut self) {
        if self.primary_healthy_since.is_none() {
            self.primary_healthy_since = Some(SystemTime::now());
        }
    }

    /// Mark primary as unhealthy
    pub fn mark_primary_unhealthy(&mut self) {
        self.primary_healthy_since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failover_state_creation() {
        let state = FailoverState::new(1, PathId::new(10));

        assert_eq!(state.policy_id, 1);
        assert_eq!(state.active_path_id, PathId::new(10));
        assert!(state.using_primary);
        assert_eq!(state.failover_count, 0);
        assert!(state.last_failover.is_none());
        assert!(state.primary_healthy_since.is_some());
    }

    #[test]
    fn test_record_failover() {
        let mut state = FailoverState::new(1, PathId::new(10));

        state.record_failover(PathId::new(20));

        assert_eq!(state.active_path_id, PathId::new(20));
        assert_eq!(state.failover_count, 1);
        assert!(state.last_failover.is_some());
        assert!(state.primary_healthy_since.is_none());
    }

    #[test]
    fn test_record_failback() {
        let mut state = FailoverState::new(1, PathId::new(10));

        // Failover to backup
        state.record_failover(PathId::new(20));
        state.using_primary = false;

        // Failback to primary
        state.record_failback(PathId::new(10));

        assert_eq!(state.active_path_id, PathId::new(10));
        assert!(state.using_primary);
        assert_eq!(state.failover_count, 2);
    }

    #[test]
    fn test_can_failback_timing() {
        let mut state = FailoverState::new(1, PathId::new(10));

        // Mark primary unhealthy
        state.mark_primary_unhealthy();
        assert!(!state.can_failback(60));

        // Mark primary healthy (sets timestamp to now)
        state.mark_primary_healthy();

        // Should not be able to failback immediately
        assert!(!state.can_failback(60));

        // Note: In real usage, time would pass. For this test, we just verify
        // the logic works with the current timestamp
    }

    #[test]
    fn test_primary_health_tracking() {
        let mut state = FailoverState::new(1, PathId::new(10));

        // Initially healthy
        assert!(state.primary_healthy_since.is_some());

        // Mark unhealthy
        state.mark_primary_unhealthy();
        assert!(state.primary_healthy_since.is_none());

        // Mark healthy again
        state.mark_primary_healthy();
        assert!(state.primary_healthy_since.is_some());

        // Marking healthy again shouldn't reset timestamp
        let first_timestamp = state.primary_healthy_since.unwrap();
        state.mark_primary_healthy();
        assert_eq!(state.primary_healthy_since.unwrap(), first_timestamp);
    }
}
