//! JSON export for REST API consumption

use crate::database::Database;
use crate::health::{HealthMonitor, PathHealth};
use crate::failover::{FailoverEngine, FailoverPolicy, FailoverEvent};
use crate::types::PathId;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::sync::Arc;
use std::time::SystemTime;

/// Serialize f64, converting NaN to 0.0
fn serialize_f64_nan_as_zero<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if value.is_nan() {
        serializer.serialize_f64(0.0)
    } else {
        serializer.serialize_f64(*value)
    }
}

/// Deserialize f64, defaulting to 0.0 for null
fn deserialize_f64_or_zero<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<f64>::deserialize(deserializer).map(|opt| opt.unwrap_or(0.0))
}

/// JSON exporter for REST APIs
pub struct JsonExporter {
    db: Arc<Database>,
    health_monitor: Arc<HealthMonitor>,
    failover_engine: Arc<FailoverEngine>,
}

/// Complete system health snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub timestamp: u64,
    pub paths: Vec<PathHealthJson>,
}

/// Path health data in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealthJson {
    pub path_id: String,
    #[serde(default, serialize_with = "serialize_f64_nan_as_zero", deserialize_with = "deserialize_f64_or_zero")]
    pub latency_ms: f64,
    #[serde(default, serialize_with = "serialize_f64_nan_as_zero", deserialize_with = "deserialize_f64_or_zero")]
    pub packet_loss_pct: f64,
    #[serde(default, serialize_with = "serialize_f64_nan_as_zero", deserialize_with = "deserialize_f64_or_zero")]
    pub jitter_ms: f64,
    #[serde(default, serialize_with = "serialize_f64_nan_as_zero", deserialize_with = "deserialize_f64_or_zero")]
    pub health_score: f64,
    pub status: String,
    pub last_checked: u64,
}

impl From<PathHealth> for PathHealthJson {
    fn from(health: PathHealth) -> Self {
        Self {
            path_id: health.path_id.to_string(),
            latency_ms: health.latency_ms,
            packet_loss_pct: health.packet_loss_pct,
            jitter_ms: health.jitter_ms,
            health_score: health.health_score,
            status: health.status.as_str().to_string(),
            last_checked: health.last_checked
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Failover status snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverSnapshot {
    pub timestamp: u64,
    pub policies: Vec<FailoverPolicyJson>,
}

/// Failover policy in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverPolicyJson {
    pub policy_id: u64,
    pub name: String,
    pub primary_path_id: String,
    pub backup_path_ids: Vec<String>,
    pub failover_threshold: f64,
    pub failback_threshold: f64,
    pub failback_delay_secs: u64,
    pub enabled: bool,
    pub active_path_id: Option<String>,
    pub using_primary: Option<bool>,
    pub failover_count: Option<u64>,
}

impl From<FailoverPolicy> for FailoverPolicyJson {
    fn from(policy: FailoverPolicy) -> Self {
        Self {
            policy_id: policy.policy_id,
            name: policy.name,
            primary_path_id: policy.primary_path_id.to_string(),
            backup_path_ids: policy.backup_path_ids.iter().map(|id| id.to_string()).collect(),
            failover_threshold: policy.failover_threshold,
            failback_threshold: policy.failback_threshold,
            failback_delay_secs: policy.failback_delay_secs,
            enabled: policy.enabled,
            active_path_id: None,
            using_primary: None,
            failover_count: None,
        }
    }
}

/// Failover event history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEventHistory {
    pub events: Vec<FailoverEventJson>,
    pub count: usize,
}

/// Failover event in JSON format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverEventJson {
    pub event_id: Option<u64>,
    pub policy_id: u64,
    pub event_type: String,
    pub from_path_id: Option<String>,
    pub to_path_id: Option<String>,
    pub reason: String,
    pub primary_health_score: Option<f64>,
    pub backup_health_score: Option<f64>,
    pub timestamp: u64,
}

impl From<FailoverEvent> for FailoverEventJson {
    fn from(event: FailoverEvent) -> Self {
        Self {
            event_id: event.event_id,
            policy_id: event.policy_id,
            event_type: event.event_type.as_str().to_string(),
            from_path_id: event.from_path_id.map(|id| id.to_string()),
            to_path_id: event.to_path_id.map(|id| id.to_string()),
            reason: event.reason,
            primary_health_score: event.primary_health_score,
            backup_health_score: event.backup_health_score,
            timestamp: event.timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl JsonExporter {
    /// Create a new JSON exporter
    pub fn new(
        db: Arc<Database>,
        health_monitor: Arc<HealthMonitor>,
        failover_engine: Arc<FailoverEngine>,
    ) -> Self {
        Self {
            db,
            health_monitor,
            failover_engine,
        }
    }

    /// Get current health snapshot
    pub async fn get_health_snapshot(&self) -> HealthSnapshot {
        let health_map = self.health_monitor.get_all_health().await;
        let paths: Vec<PathHealthJson> = health_map
            .into_iter()
            .map(|(_, health)| health.into())
            .collect();

        HealthSnapshot {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            paths,
        }
    }

    /// Get health history for a specific path
    pub async fn get_path_health_history(
        &self,
        path_id: &PathId,
        since: SystemTime,
        until: Option<SystemTime>,
    ) -> Result<Vec<PathHealthJson>, Box<dyn std::error::Error + Send + Sync>> {
        let history = self.health_monitor.get_health_history(path_id, since, until).await?;
        Ok(history.into_iter().map(|h| h.into()).collect())
    }

    /// Get current failover snapshot
    pub async fn get_failover_snapshot(&self) -> FailoverSnapshot {
        let policies = self.failover_engine.get_policies().await;
        let mut policies_json: Vec<FailoverPolicyJson> = Vec::new();

        for policy in policies {
            let mut policy_json: FailoverPolicyJson = policy.clone().into();

            // Add current state
            if let Some(state) = self.failover_engine.get_state(policy.policy_id).await {
                policy_json.active_path_id = Some(state.active_path_id.to_string());
                policy_json.using_primary = Some(state.using_primary);
                policy_json.failover_count = Some(state.failover_count);
            }

            policies_json.push(policy_json);
        }

        FailoverSnapshot {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            policies: policies_json,
        }
    }

    /// Get failover event history
    pub async fn get_failover_events(
        &self,
        policy_id: Option<u64>,
        limit: usize,
    ) -> Result<FailoverEventHistory, Box<dyn std::error::Error + Send + Sync>> {
        let events = self.query_failover_events(policy_id, limit).await?;
        let count = events.len();

        Ok(FailoverEventHistory {
            events: events.into_iter().map(|e| e.into()).collect(),
            count,
        })
    }

    /// Query failover events from database
    async fn query_failover_events(
        &self,
        policy_id: Option<u64>,
        limit: usize,
    ) -> Result<Vec<FailoverEvent>, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        let query = if let Some(pid) = policy_id {
            sqlx::query(
                r#"
                SELECT policy_id, event_type, from_path_id, to_path_id, reason, timestamp
                FROM sdwan_failover_events
                WHERE policy_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                "#
            )
            .bind(pid as i64)
            .bind(limit as i64)
        } else {
            sqlx::query(
                r#"
                SELECT policy_id, event_type, from_path_id, to_path_id, reason, timestamp
                FROM sdwan_failover_events
                ORDER BY timestamp DESC
                LIMIT ?
                "#
            )
            .bind(limit as i64)
        };

        let rows = query.fetch_all(self.db.pool()).await?;

        let mut events = Vec::new();
        for row in rows {
            let policy_id: i64 = row.try_get("policy_id")?;
            let event_type: String = row.try_get("event_type")?;
            let from_path_id: Option<String> = row.try_get("from_path_id").ok();
            let to_path_id: Option<String> = row.try_get("to_path_id").ok();
            let reason: String = row.try_get("reason")?;
            let timestamp: i64 = row.try_get("timestamp")?;

            use crate::failover::FailoverEventType;

            if let Some(event_type_enum) = FailoverEventType::from_str(&event_type) {
                events.push(FailoverEvent {
                    event_id: None,
                    policy_id: policy_id as u64,
                    event_type: event_type_enum,
                    from_path_id: from_path_id.and_then(|s| PathId::from_string(&s).ok()),
                    to_path_id: to_path_id.and_then(|s| PathId::from_string(&s).ok()),
                    reason,
                    primary_health_score: None,
                    backup_health_score: None,
                    timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64),
                });
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthConfig;
    use std::net::IpAddr;

    async fn create_test_exporter() -> (Arc<JsonExporter>, Arc<HealthMonitor>, Arc<FailoverEngine>) {
        let db = Arc::new(Database::new_in_memory().await.unwrap());
        let health_config = HealthConfig::default();
        let health_monitor = Arc::new(HealthMonitor::new(db.clone(), health_config).await.unwrap());
        let failover_engine = Arc::new(FailoverEngine::new(db.clone(), health_monitor.clone()));

        let exporter = Arc::new(JsonExporter::new(db, health_monitor.clone(), failover_engine.clone()));

        (exporter, health_monitor, failover_engine)
    }

    #[tokio::test]
    async fn test_empty_health_snapshot() {
        let (exporter, _, _) = create_test_exporter().await;

        let snapshot = exporter.get_health_snapshot().await;

        assert_eq!(snapshot.paths.len(), 0);
        assert!(snapshot.timestamp > 0);
    }

    #[tokio::test]
    async fn test_health_snapshot_with_paths() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        // Add health data
        let path1 = PathId::new(1);
        let path2 = PathId::new(2);
        let target: IpAddr = "192.168.1.1".parse().unwrap();

        health_monitor.check_path_health(&path1, target).await.unwrap();
        health_monitor.check_path_health(&path2, target).await.unwrap();

        let snapshot = exporter.get_health_snapshot().await;

        assert_eq!(snapshot.paths.len(), 2);
        assert!(snapshot.paths.iter().any(|p| p.path_id == path1.to_string()));
        assert!(snapshot.paths.iter().any(|p| p.path_id == path2.to_string()));

        // Verify JSON structure
        for path in &snapshot.paths {
            assert!(path.latency_ms >= 0.0);
            assert!(path.packet_loss_pct >= 0.0);
            assert!(path.jitter_ms >= 0.0);
            assert!(path.health_score >= 0.0 && path.health_score <= 100.0);
            assert!(!path.status.is_empty());
        }
    }

    #[tokio::test]
    async fn test_health_snapshot_serialization() {
        let (exporter, health_monitor, _) = create_test_exporter().await;

        let path1 = PathId::new(1);
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        health_monitor.check_path_health(&path1, target).await.unwrap();

        let snapshot = exporter.get_health_snapshot().await;

        // Should serialize to JSON
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("paths"));
        assert!(json.contains("latency_ms"));

        // Should deserialize back
        let deserialized: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.paths.len(), snapshot.paths.len());
    }

    #[tokio::test]
    async fn test_empty_failover_snapshot() {
        let (exporter, _, _) = create_test_exporter().await;

        let snapshot = exporter.get_failover_snapshot().await;

        assert_eq!(snapshot.policies.len(), 0);
        assert!(snapshot.timestamp > 0);
    }

    #[tokio::test]
    async fn test_failover_snapshot_with_policies() {
        let (exporter, _, failover_engine) = create_test_exporter().await;

        // Add policies
        let policy1 = FailoverPolicy::new(
            1,
            "policy-1".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );
        let policy2 = FailoverPolicy::new(
            2,
            "policy-2".to_string(),
            PathId::new(30),
            vec![PathId::new(40)],
        );

        failover_engine.add_policy(policy1).await.unwrap();
        failover_engine.add_policy(policy2).await.unwrap();

        let snapshot = exporter.get_failover_snapshot().await;

        assert_eq!(snapshot.policies.len(), 2);

        // Verify policy structure
        for policy in &snapshot.policies {
            assert!(!policy.name.is_empty());
            assert!(!policy.primary_path_id.is_empty());
            assert!(!policy.backup_path_ids.is_empty());
            assert!(policy.active_path_id.is_some());
            assert!(policy.using_primary.is_some());
            assert!(policy.failover_count.is_some());
        }
    }

    #[tokio::test]
    async fn test_failover_snapshot_serialization() {
        let (exporter, _, failover_engine) = create_test_exporter().await;

        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );
        failover_engine.add_policy(policy).await.unwrap();

        let snapshot = exporter.get_failover_snapshot().await;

        // Should serialize to JSON
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("policies"));
        assert!(json.contains("policy_id"));

        // Should deserialize back
        let deserialized: FailoverSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.policies.len(), snapshot.policies.len());
    }

    #[tokio::test]
    async fn test_failover_events_query() {
        let (exporter, _, failover_engine) = create_test_exporter().await;

        // Add a policy (this creates policy_enabled event)
        let policy = FailoverPolicy::new(
            1,
            "test".to_string(),
            PathId::new(10),
            vec![PathId::new(20)],
        );
        failover_engine.add_policy(policy).await.unwrap();

        // Query events
        let history = exporter.get_failover_events(None, 100).await.unwrap();

        assert!(history.count >= 1);
        assert_eq!(history.events.len(), history.count);

        // Should have policy_enabled event
        assert!(history.events.iter().any(|e| e.event_type == "policy_enabled"));
    }

    #[tokio::test]
    async fn test_failover_events_filter_by_policy() {
        let (exporter, _, failover_engine) = create_test_exporter().await;

        // Add two policies
        let policy1 = FailoverPolicy::new(1, "p1".to_string(), PathId::new(10), vec![PathId::new(20)]);
        let policy2 = FailoverPolicy::new(2, "p2".to_string(), PathId::new(30), vec![PathId::new(40)]);

        failover_engine.add_policy(policy1).await.unwrap();
        failover_engine.add_policy(policy2).await.unwrap();

        // Query events for policy 1 only
        let history = exporter.get_failover_events(Some(1), 100).await.unwrap();

        // All events should be for policy 1
        for event in &history.events {
            assert_eq!(event.policy_id, 1);
        }
    }
}
