//! Metrics aggregation for historical analysis

use crate::database::Database;
use crate::types::PathId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Metrics aggregator for time-series data
pub struct MetricsAggregator {
    db: Arc<Database>,
}

/// Time period for aggregation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationPeriod {
    /// Last 1 hour
    Hour,
    /// Last 24 hours
    Day,
    /// Last 7 days
    Week,
    /// Last 30 days
    Month,
    /// Custom duration in seconds
    Custom(u64),
}

impl AggregationPeriod {
    /// Get the duration for this period
    pub fn duration(&self) -> Duration {
        match self {
            AggregationPeriod::Hour => Duration::from_secs(3600),
            AggregationPeriod::Day => Duration::from_secs(86400),
            AggregationPeriod::Week => Duration::from_secs(604800),
            AggregationPeriod::Month => Duration::from_secs(2592000),
            AggregationPeriod::Custom(secs) => Duration::from_secs(*secs),
        }
    }

    /// Get human-readable name
    pub fn as_str(&self) -> &'static str {
        match self {
            AggregationPeriod::Hour => "hour",
            AggregationPeriod::Day => "day",
            AggregationPeriod::Week => "week",
            AggregationPeriod::Month => "month",
            AggregationPeriod::Custom(_) => "custom",
        }
    }
}

/// Aggregated metrics for a path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub path_id: String,
    pub period: String,
    pub start_time: u64,
    pub end_time: u64,
    pub sample_count: u64,
    pub latency_avg: f64,
    pub latency_min: f64,
    pub latency_max: f64,
    pub latency_p95: f64,
    pub packet_loss_avg: f64,
    pub packet_loss_max: f64,
    pub jitter_avg: f64,
    pub jitter_max: f64,
    pub health_score_avg: f64,
    pub health_score_min: f64,
    pub uptime_pct: f64,
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Aggregate metrics for a path over a time period
    pub async fn aggregate_path_metrics(
        &self,
        path_id: &PathId,
        period: AggregationPeriod,
    ) -> Result<AggregatedMetrics, Box<dyn std::error::Error + Send + Sync>> {
        let end_time = SystemTime::now();
        let start_time = end_time - period.duration();

        self.aggregate_path_metrics_range(path_id, start_time, end_time, period).await
    }

    /// Aggregate metrics for a path over a specific time range
    pub async fn aggregate_path_metrics_range(
        &self,
        path_id: &PathId,
        start_time: SystemTime,
        end_time: SystemTime,
        period: AggregationPeriod,
    ) -> Result<AggregatedMetrics, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        let start_secs = start_time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64;
        let end_secs = end_time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64;

        // Query aggregated statistics
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as sample_count,
                AVG(latency_ms) as latency_avg,
                MIN(latency_ms) as latency_min,
                MAX(latency_ms) as latency_max,
                AVG(packet_loss_pct) as packet_loss_avg,
                MAX(packet_loss_pct) as packet_loss_max,
                AVG(jitter_ms) as jitter_avg,
                MAX(jitter_ms) as jitter_max,
                AVG(health_score) as health_score_avg,
                MIN(health_score) as health_score_min
            FROM sdwan_path_health
            WHERE path_id = ? AND timestamp >= ? AND timestamp <= ?
            "#,
        )
        .bind(path_id.to_string())
        .bind(start_secs)
        .bind(end_secs)
        .fetch_one(self.db.pool())
        .await?;

        let sample_count: i64 = row.try_get("sample_count")?;
        let latency_avg: f64 = row.try_get("latency_avg").unwrap_or(0.0);
        let latency_min: f64 = row.try_get("latency_min").unwrap_or(0.0);
        let latency_max: f64 = row.try_get("latency_max").unwrap_or(0.0);
        let packet_loss_avg: f64 = row.try_get("packet_loss_avg").unwrap_or(0.0);
        let packet_loss_max: f64 = row.try_get("packet_loss_max").unwrap_or(0.0);
        let jitter_avg: f64 = row.try_get("jitter_avg").unwrap_or(0.0);
        let jitter_max: f64 = row.try_get("jitter_max").unwrap_or(0.0);
        let health_score_avg: f64 = row.try_get("health_score_avg").unwrap_or(0.0);
        let health_score_min: f64 = row.try_get("health_score_min").unwrap_or(0.0);

        // Calculate P95 latency (95th percentile)
        let latency_p95 = self.calculate_percentile(path_id, start_secs, end_secs, 95).await?;

        // Calculate uptime percentage (health_score >= 80 = up)
        let uptime_pct = self.calculate_uptime(path_id, start_secs, end_secs).await?;

        Ok(AggregatedMetrics {
            path_id: path_id.to_string(),
            period: period.as_str().to_string(),
            start_time: start_secs as u64,
            end_time: end_secs as u64,
            sample_count: sample_count as u64,
            latency_avg,
            latency_min,
            latency_max,
            latency_p95,
            packet_loss_avg,
            packet_loss_max,
            jitter_avg,
            jitter_max,
            health_score_avg,
            health_score_min,
            uptime_pct,
        })
    }

    /// Calculate percentile for latency
    async fn calculate_percentile(
        &self,
        path_id: &PathId,
        start_secs: i64,
        end_secs: i64,
        percentile: u8,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        // Get total count
        let count_row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM sdwan_path_health
            WHERE path_id = ? AND timestamp >= ? AND timestamp <= ?
            "#,
        )
        .bind(path_id.to_string())
        .bind(start_secs)
        .bind(end_secs)
        .fetch_one(self.db.pool())
        .await?;

        let total_count: i64 = count_row.try_get("count")?;

        if total_count == 0 {
            return Ok(0.0);
        }

        // Calculate offset for percentile
        let offset = ((total_count as f64) * (percentile as f64 / 100.0)) as i64;

        // Get the value at that percentile
        let row = sqlx::query(
            r#"
            SELECT latency_ms
            FROM sdwan_path_health
            WHERE path_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY latency_ms
            LIMIT 1 OFFSET ?
            "#,
        )
        .bind(path_id.to_string())
        .bind(start_secs)
        .bind(end_secs)
        .bind(offset)
        .fetch_one(self.db.pool())
        .await?;

        let latency: f64 = row.try_get("latency_ms")?;
        Ok(latency)
    }

    /// Calculate uptime percentage (health_score >= 80)
    async fn calculate_uptime(
        &self,
        path_id: &PathId,
        start_secs: i64,
        end_secs: i64,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_samples,
                SUM(CASE WHEN health_score >= 80.0 THEN 1 ELSE 0 END) as up_samples
            FROM sdwan_path_health
            WHERE path_id = ? AND timestamp >= ? AND timestamp <= ?
            "#,
        )
        .bind(path_id.to_string())
        .bind(start_secs)
        .bind(end_secs)
        .fetch_one(self.db.pool())
        .await?;

        let total_samples: i64 = row.try_get("total_samples")?;
        let up_samples: i64 = row.try_get("up_samples").unwrap_or(0);

        if total_samples == 0 {
            return Ok(0.0);
        }

        Ok((up_samples as f64 / total_samples as f64) * 100.0)
    }

    /// Get aggregated metrics for all paths
    pub async fn aggregate_all_paths(
        &self,
        period: AggregationPeriod,
    ) -> Result<Vec<AggregatedMetrics>, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::Row;

        let end_time = SystemTime::now();
        let start_time = end_time - period.duration();
        let start_secs = start_time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64;
        let end_secs = end_time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as i64;

        // Get all unique path IDs in the time range
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT path_id
            FROM sdwan_path_health
            WHERE timestamp >= ? AND timestamp <= ?
            "#,
        )
        .bind(start_secs)
        .bind(end_secs)
        .fetch_all(self.db.pool())
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let path_id_str: String = row.try_get("path_id")?;
            if let Ok(path_id) = PathId::from_string(&path_id_str) {
                let metrics = self.aggregate_path_metrics_range(&path_id, start_time, end_time, period).await?;
                results.push(metrics);
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{HealthMonitor, HealthConfig};

    async fn create_test_aggregator() -> (Arc<MetricsAggregator>, Arc<HealthMonitor>) {
        let db = Arc::new(Database::new_in_memory().await.unwrap());
        let health_config = HealthConfig {
            check_interval_secs: 10,
            probes_per_check: 3,
            probe_timeout_ms: 500,
            persist_to_db: true,
            db_persist_interval: 1, // Persist every check
        };
        let health_monitor = Arc::new(HealthMonitor::new(db.clone(), health_config).await.unwrap());
        let aggregator = Arc::new(MetricsAggregator::new(db));

        (aggregator, health_monitor)
    }

    #[tokio::test]
    async fn test_aggregation_period_duration() {
        assert_eq!(AggregationPeriod::Hour.duration(), Duration::from_secs(3600));
        assert_eq!(AggregationPeriod::Day.duration(), Duration::from_secs(86400));
        assert_eq!(AggregationPeriod::Week.duration(), Duration::from_secs(604800));
        assert_eq!(AggregationPeriod::Month.duration(), Duration::from_secs(2592000));
        assert_eq!(AggregationPeriod::Custom(100).duration(), Duration::from_secs(100));
    }

    #[tokio::test]
    async fn test_aggregate_empty_metrics() {
        let (aggregator, _) = create_test_aggregator().await;

        let path_id = PathId::new(1);
        let metrics = aggregator.aggregate_path_metrics(&path_id, AggregationPeriod::Hour).await.unwrap();

        assert_eq!(metrics.sample_count, 0);
        assert_eq!(metrics.latency_avg, 0.0);
    }

    #[tokio::test]
    async fn test_aggregate_with_data() {
        let (aggregator, health_monitor) = create_test_aggregator().await;

        let path_id = PathId::new(1);
        let target = "192.168.1.1".parse().unwrap();

        // Generate some health data
        // Note: db_persist_interval is 1, so each check should persist
        for _ in 0..5 {
            health_monitor.check_path_health(&path_id, target).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // Wait a bit for async persistence
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let metrics = aggregator.aggregate_path_metrics(&path_id, AggregationPeriod::Hour).await.unwrap();

        // Should have persisted records (at least some of them)
        assert!(metrics.sample_count > 0, "Expected some samples but got 0");
        assert!(metrics.latency_avg >= 0.0);
        assert!(metrics.health_score_avg > 0.0);
    }

    #[tokio::test]
    async fn test_aggregate_all_paths() {
        let (aggregator, health_monitor) = create_test_aggregator().await;

        let path1 = PathId::new(1);
        let path2 = PathId::new(2);
        let target = "192.168.1.1".parse().unwrap();

        // Generate data for multiple paths
        health_monitor.check_path_health(&path1, target).await.unwrap();
        health_monitor.check_path_health(&path2, target).await.unwrap();

        // Wait for persistence
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let all_metrics = aggregator.aggregate_all_paths(AggregationPeriod::Hour).await.unwrap();

        // Should have at least the paths we checked
        assert!(all_metrics.len() >= 2, "Expected at least 2 paths but got {}", all_metrics.len());
        assert!(all_metrics.iter().any(|m| m.path_id == path1.to_string()));
        assert!(all_metrics.iter().any(|m| m.path_id == path2.to_string()));
    }

    #[tokio::test]
    async fn test_aggregated_metrics_serialization() {
        let (aggregator, health_monitor) = create_test_aggregator().await;

        let path_id = PathId::new(1);
        let target = "192.168.1.1".parse().unwrap();

        health_monitor.check_path_health(&path_id, target).await.unwrap();

        let metrics = aggregator.aggregate_path_metrics(&path_id, AggregationPeriod::Day).await.unwrap();

        // Should serialize to JSON
        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("path_id"));
        assert!(json.contains("latency_avg"));
        assert!(json.contains("sample_count"));

        // Should deserialize back
        let deserialized: AggregatedMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.path_id, metrics.path_id);
    }
}
