//! Failover execution engine
//!
//! This module implements the core failover logic that monitors path health
//! and automatically switches between primary and backup paths.

use super::{FailoverEvent, FailoverEventType, FailoverPolicy, FailoverState};
use crate::database::Database;
use crate::health::HealthMonitor;
use crate::types::PathId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

/// Failover engine that monitors health and executes failovers
pub struct FailoverEngine {
    /// Database for persistence
    db: Arc<Database>,

    /// Health monitor for path health
    health_monitor: Arc<HealthMonitor>,

    /// Active policies
    policies: Arc<RwLock<HashMap<u64, FailoverPolicy>>>,

    /// Current failover states
    states: Arc<RwLock<HashMap<u64, FailoverState>>>,

    /// Evaluation interval in seconds
    eval_interval_secs: u64,
}

impl FailoverEngine {
    /// Create a new failover engine
    pub fn new(
        db: Arc<Database>,
        health_monitor: Arc<HealthMonitor>,
    ) -> Self {
        Self {
            db,
            health_monitor,
            policies: Arc::new(RwLock::new(HashMap::new())),
            states: Arc::new(RwLock::new(HashMap::new())),
            eval_interval_secs: 5, // Evaluate every 5 seconds
        }
    }

    /// Add a failover policy
    pub async fn add_policy(&self, policy: FailoverPolicy) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Validate policy
        policy.validate()?;

        let policy_id = policy.policy_id;
        let primary_path = policy.primary_path_id;

        // Store policy
        {
            let mut policies = self.policies.write().await;
            policies.insert(policy_id, policy.clone());
        }

        // Initialize state
        {
            let mut states = self.states.write().await;
            states.insert(policy_id, FailoverState::new(policy_id, primary_path));
        }

        // Persist to database
        self.persist_policy(&policy).await?;

        // Log event
        let event = FailoverEvent::policy_enabled(policy_id);
        self.log_event(&event).await?;

        tracing::info!(
            policy_id = policy_id,
            policy_name = %policy.name,
            "Failover policy added"
        );

        Ok(())
    }

    /// Remove a failover policy
    pub async fn remove_policy(&self, policy_id: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        {
            let mut policies = self.policies.write().await;
            policies.remove(&policy_id);
        }

        {
            let mut states = self.states.write().await;
            states.remove(&policy_id);
        }

        // Delete from database
        self.delete_policy(policy_id).await?;

        // Log event
        let event = FailoverEvent::policy_disabled(policy_id);
        self.log_event(&event).await?;

        tracing::info!(policy_id = policy_id, "Failover policy removed");

        Ok(())
    }

    /// Get current failover state for a policy
    pub async fn get_state(&self, policy_id: u64) -> Option<FailoverState> {
        let states = self.states.read().await;
        states.get(&policy_id).cloned()
    }

    /// Get all active policies
    pub async fn get_policies(&self) -> Vec<FailoverPolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Start the failover monitoring loop
    pub fn start_monitoring(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut eval_interval = interval(Duration::from_secs(self.eval_interval_secs));

            loop {
                eval_interval.tick().await;

                if let Err(e) = self.evaluate_all_policies().await {
                    tracing::error!(error = %e, "Failed to evaluate failover policies");
                }
            }
        })
    }

    /// Evaluate all policies and trigger failovers as needed
    async fn evaluate_all_policies(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let policies: Vec<FailoverPolicy> = {
            let policies_guard = self.policies.read().await;
            policies_guard.values().cloned().collect()
        };

        for policy in policies {
            if !policy.enabled {
                continue;
            }

            if let Err(e) = self.evaluate_policy(&policy).await {
                tracing::error!(
                    policy_id = policy.policy_id,
                    error = %e,
                    "Failed to evaluate policy"
                );
            }
        }

        Ok(())
    }

    /// Evaluate a single policy
    async fn evaluate_policy(&self, policy: &FailoverPolicy) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get current state
        let mut state = {
            let states = self.states.read().await;
            states.get(&policy.policy_id).cloned()
        };

        let mut state = match state {
            Some(s) => s,
            None => {
                // Initialize state if missing
                let new_state = FailoverState::new(policy.policy_id, policy.primary_path_id);
                let mut states = self.states.write().await;
                states.insert(policy.policy_id, new_state.clone());
                new_state
            }
        };

        // Get path health
        let primary_health = self.health_monitor.get_path_health(&policy.primary_path_id).await;
        let primary_score = primary_health.as_ref().map(|h| h.health_score).unwrap_or(0.0);

        // Check if we're currently using primary
        if state.using_primary {
            // On primary - check if we should failover
            if policy.should_failover(primary_score) {
                self.execute_failover(policy, &mut state, primary_score).await?;
            } else {
                // Primary is healthy, update state
                state.mark_primary_healthy();
            }
        } else {
            // On backup - check if we should failback
            if policy.should_failback(primary_score) {
                state.mark_primary_healthy();

                // Check if enough time has passed
                if state.can_failback(policy.failback_delay_secs) {
                    self.execute_failback(policy, &mut state, primary_score).await?;
                } else {
                    tracing::debug!(
                        policy_id = policy.policy_id,
                        "Primary healthy but waiting for stabilization period"
                    );
                }
            } else {
                // Primary still unhealthy
                state.mark_primary_unhealthy();
            }
        }

        // Update state
        {
            let mut states = self.states.write().await;
            states.insert(policy.policy_id, state);
        }

        Ok(())
    }

    /// Execute failover to backup path
    async fn execute_failover(
        &self,
        policy: &FailoverPolicy,
        state: &mut FailoverState,
        primary_score: f64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get health for all backup paths
        let mut backup_health = Vec::new();
        for backup_id in &policy.backup_path_ids {
            if let Some(health) = self.health_monitor.get_path_health(backup_id).await {
                backup_health.push((*backup_id, health.health_score));
            }
        }

        // Select best backup
        let backup_path = policy.get_best_backup(&backup_health);

        match backup_path {
            Some(backup_id) => {
                let backup_score = backup_health
                    .iter()
                    .find(|(id, _)| *id == backup_id)
                    .map(|(_, score)| *score)
                    .unwrap_or(0.0);

                // Execute failover
                let from_path = state.active_path_id;
                state.record_failover(backup_id);
                state.using_primary = false;

                // Log event
                let event = FailoverEvent::triggered(
                    policy.policy_id,
                    from_path,
                    backup_id,
                    primary_score,
                    backup_score,
                    format!(
                        "Primary health ({:.1}) below threshold ({:.1})",
                        primary_score, policy.failover_threshold
                    ),
                );

                self.log_event(&event).await?;

                tracing::warn!(
                    policy_id = policy.policy_id,
                    from_path = %from_path,
                    to_path = %backup_id,
                    primary_health = primary_score,
                    backup_health = backup_score,
                    "Failover triggered"
                );

                Ok(())
            }
            None => {
                // No backup available
                let event = FailoverEvent::failed(
                    policy.policy_id,
                    "No healthy backup paths available".to_string(),
                );

                self.log_event(&event).await?;

                tracing::error!(
                    policy_id = policy.policy_id,
                    "Failover failed: no healthy backup available"
                );

                Err("No healthy backup available".into())
            }
        }
    }

    /// Execute failback to primary path
    async fn execute_failback(
        &self,
        policy: &FailoverPolicy,
        state: &mut FailoverState,
        primary_score: f64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let from_path = state.active_path_id;

        state.record_failback(policy.primary_path_id);

        // Log event
        let event = FailoverEvent::completed(
            policy.policy_id,
            policy.primary_path_id,
            primary_score,
            format!(
                "Primary health ({:.1}) above threshold ({:.1}) for {} seconds",
                primary_score, policy.failback_threshold, policy.failback_delay_secs
            ),
        );

        self.log_event(&event).await?;

        tracing::info!(
            policy_id = policy.policy_id,
            from_path = %from_path,
            to_path = %policy.primary_path_id,
            primary_health = primary_score,
            "Failback completed"
        );

        Ok(())
    }

    /// Persist policy to database
    async fn persist_policy(&self, policy: &FailoverPolicy) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        let backup_ids_json = serde_json::to_string(&policy.backup_path_ids)?;

        sqlx::query(
            r#"
            INSERT INTO sdwan_failover_policies (
                policy_id, name, primary_path_id, backup_path_ids,
                failover_threshold, failback_threshold, failback_delay_secs, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(policy_id) DO UPDATE SET
                name = excluded.name,
                primary_path_id = excluded.primary_path_id,
                backup_path_ids = excluded.backup_path_ids,
                failover_threshold = excluded.failover_threshold,
                failback_threshold = excluded.failback_threshold,
                failback_delay_secs = excluded.failback_delay_secs,
                enabled = excluded.enabled
            "#,
        )
        .bind(policy.policy_id as i64)
        .bind(&policy.name)
        .bind(policy.primary_path_id.to_string())
        .bind(backup_ids_json)
        .bind(policy.failover_threshold)
        .bind(policy.failback_threshold)
        .bind(policy.failback_delay_secs as i64)
        .bind(policy.enabled as i64)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Delete policy from database
    async fn delete_policy(&self, policy_id: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query(
            r#"
            DELETE FROM sdwan_failover_policies
            WHERE policy_id = ?
            "#,
        )
        .bind(policy_id as i64)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Log a failover event
    async fn log_event(&self, event: &FailoverEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_failover_events (
                policy_id, event_type, from_path_id, to_path_id, reason, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.policy_id as i64)
        .bind(event.event_type.as_str())
        .bind(event.from_path_id.map(|id| id.to_string()))
        .bind(event.to_path_id.map(|id| id.to_string()))
        .bind(&event.reason)
        .bind(timestamp)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthConfig;

    async fn create_test_engine() -> (Arc<FailoverEngine>, Arc<HealthMonitor>) {
        let db = Arc::new(Database::new_in_memory().await.unwrap());

        let health_config = HealthConfig::default();
        let health_monitor = Arc::new(HealthMonitor::new(db.clone(), health_config).await.unwrap());

        let engine = Arc::new(FailoverEngine::new(db, health_monitor.clone()));

        (engine, health_monitor)
    }

    #[tokio::test]
    async fn test_add_policy() {
        let (engine, _) = create_test_engine().await;

        let policy = FailoverPolicy::new(
            1,
            "test-policy".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );

        let result = engine.add_policy(policy).await;
        assert!(result.is_ok());

        // Verify policy was added
        let policies = engine.get_policies().await;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_id, 1);

        // Verify state was initialized
        let state = engine.get_state(1).await;
        assert!(state.is_some());
        assert!(state.unwrap().using_primary);
    }

    #[tokio::test]
    async fn test_remove_policy() {
        let (engine, _) = create_test_engine().await;

        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );

        engine.add_policy(policy).await.unwrap();
        assert_eq!(engine.get_policies().await.len(), 1);

        engine.remove_policy(1).await.unwrap();
        assert_eq!(engine.get_policies().await.len(), 0);
    }

    #[tokio::test]
    async fn test_invalid_policy() {
        let (engine, _) = create_test_engine().await;

        let mut policy = FailoverPolicy::new(
            1,
            "".to_string(), // Invalid: empty name
            PathId::new(10),
            vec![PathId::new(20)],
        );

        let result = engine.add_policy(policy).await;
        assert!(result.is_err());
    }
}
