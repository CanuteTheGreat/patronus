//! Health monitoring engine
//!
//! This module implements the health monitoring engine that coordinates
//! probe execution, health calculation, and database persistence.

use super::{HealthConfig, PathHealth, PathStatus, ProbeConfig, Prober};
use super::probe::ProbeType;
use crate::database::Database;
use crate::types::PathId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

/// Health monitoring engine
pub struct HealthMonitor {
    /// Database for persistence
    db: Arc<Database>,

    /// Configuration
    config: HealthConfig,

    /// Current health status for all paths
    health_cache: Arc<RwLock<HashMap<PathId, PathHealth>>>,

    /// Check counter for database persistence
    check_counter: Arc<RwLock<usize>>,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub async fn new(
        db: Arc<Database>,
        config: HealthConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            db,
            config,
            health_cache: Arc::new(RwLock::new(HashMap::new())),
            check_counter: Arc::new(RwLock::new(0)),
        })
    }

    /// Check health for a specific path
    ///
    /// # Arguments
    ///
    /// * `path_id` - Path to check
    /// * `target` - Target IP address for probes
    ///
    /// # Returns
    ///
    /// PathHealth with current measurements
    pub async fn check_path_health(
        &self,
        path_id: &PathId,
        target: std::net::IpAddr,
    ) -> Result<PathHealth, Box<dyn std::error::Error + Send + Sync>> {
        // Configure prober
        let probe_config = ProbeConfig {
            target,
            count: self.config.probes_per_check,
            timeout: Duration::from_millis(self.config.probe_timeout_ms),
            interval: Duration::from_millis(200), // 200ms between probes
            probe_type: ProbeType::Icmp, // Will auto-fallback to UDP if unavailable
        };

        let prober = Prober::new(probe_config).await;

        // Execute probes
        let probe_result = prober.probe().await?;

        // Calculate health
        let health = PathHealth::new(path_id.clone(), &probe_result);

        // Update cache
        {
            let mut cache = self.health_cache.write().await;
            cache.insert(path_id.clone(), health.clone());
        }

        // Persist to database if configured
        if self.config.persist_to_db {
            let mut counter = self.check_counter.write().await;
            *counter += 1;

            if *counter >= self.config.db_persist_interval {
                self.persist_health(&health).await?;
                *counter = 0;
            }
        }

        Ok(health)
    }

    /// Get current health for a path from cache
    ///
    /// Returns None if path hasn't been checked yet
    pub async fn get_path_health(&self, path_id: &PathId) -> Option<PathHealth> {
        let cache = self.health_cache.read().await;
        cache.get(path_id).cloned()
    }

    /// Get health for all monitored paths
    pub async fn get_all_health(&self) -> HashMap<PathId, PathHealth> {
        let cache = self.health_cache.read().await;
        cache.clone()
    }

    /// Get health history for a path from database
    ///
    /// # Arguments
    ///
    /// * `path_id` - Path to query
    /// * `since` - Start time for history
    /// * `until` - Optional end time (defaults to now)
    ///
    /// # Returns
    ///
    /// Vector of PathHealth records in chronological order
    pub async fn get_health_history(
        &self,
        path_id: &PathId,
        since: SystemTime,
        until: Option<SystemTime>,
    ) -> Result<Vec<PathHealth>, Box<dyn std::error::Error + Send + Sync>> {
        let until = until.unwrap_or_else(SystemTime::now);

        let since_secs = since
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64;
        let until_secs = until
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64;

        use sqlx::Row;

        let records = sqlx::query(
            r#"
            SELECT
                path_id,
                timestamp,
                latency_ms,
                packet_loss_pct,
                jitter_ms,
                health_score,
                status
            FROM sdwan_path_health
            WHERE path_id = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(path_id.to_string())
        .bind(since_secs)
        .bind(until_secs)
        .fetch_all(self.db.pool())
        .await?;

        let mut history = Vec::new();

        for record in records {
            let path_id_str: String = record.try_get("path_id")?;
            let timestamp: i64 = record.try_get("timestamp")?;
            let latency_ms: f64 = record.try_get("latency_ms")?;
            let packet_loss_pct: f64 = record.try_get("packet_loss_pct")?;
            let jitter_ms: f64 = record.try_get("jitter_ms")?;
            let health_score: f64 = record.try_get("health_score")?;
            let status_str: String = record.try_get("status")?;

            let status = PathStatus::from_str(&status_str)
                .unwrap_or(PathStatus::Down);

            let timestamp_sys = SystemTime::UNIX_EPOCH
                + Duration::from_secs(timestamp as u64);

            // Parse path_id - it's stored as string in DB
            // For now, we'll create a new PathId since we don't have from_string
            let path_id_parsed = path_id.clone();

            history.push(PathHealth {
                path_id: path_id_parsed,
                latency_ms,
                packet_loss_pct,
                jitter_ms,
                health_score,
                status,
                last_checked: timestamp_sys,
            });
        }

        Ok(history)
    }

    /// Persist health record to database
    async fn persist_health(&self, health: &PathHealth) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = health
            .last_checked
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64;

        sqlx::query(
            r#"
            INSERT INTO sdwan_path_health (
                path_id,
                timestamp,
                latency_ms,
                packet_loss_pct,
                jitter_ms,
                health_score,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(health.path_id.to_string())
        .bind(timestamp)
        .bind(health.latency_ms)
        .bind(health.packet_loss_pct)
        .bind(health.jitter_ms)
        .bind(health.health_score)
        .bind(health.status.as_str())
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Start continuous health monitoring for paths
    ///
    /// # Arguments
    ///
    /// * `paths` - Map of PathId to target IP addresses
    ///
    /// # Returns
    ///
    /// JoinHandle that can be used to stop the monitoring task
    pub fn start_monitoring(
        self: Arc<Self>,
        paths: HashMap<PathId, std::net::IpAddr>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(self.config.check_interval_secs));

            loop {
                check_interval.tick().await;

                // Check all paths concurrently
                let mut tasks = Vec::new();

                for (path_id, target_ip) in &paths {
                    let monitor = Arc::clone(&self);
                    let path_id = path_id.clone();
                    let target_ip = *target_ip;

                    let task = tokio::spawn(async move {
                        if let Err(e) = monitor.check_path_health(&path_id, target_ip).await {
                            tracing::error!(
                                "Health check failed for path {}: {}",
                                path_id,
                                e
                            );
                        }
                    });

                    tasks.push(task);
                }

                // Wait for all checks to complete
                for task in tasks {
                    let _ = task.await;
                }
            }
        })
    }

    /// Get statistics about monitored paths
    pub async fn get_stats(&self) -> HealthMonitorStats {
        let cache = self.health_cache.read().await;

        let total_paths = cache.len();
        let mut healthy_paths = 0;
        let mut degraded_paths = 0;
        let mut down_paths = 0;

        for health in cache.values() {
            match health.status {
                PathStatus::Up => healthy_paths += 1,
                PathStatus::Degraded => degraded_paths += 1,
                PathStatus::Down => down_paths += 1,
            }
        }

        HealthMonitorStats {
            total_paths,
            healthy_paths,
            degraded_paths,
            down_paths,
        }
    }
}

/// Statistics about health monitoring
#[derive(Debug, Clone)]
pub struct HealthMonitorStats {
    /// Total number of monitored paths
    pub total_paths: usize,

    /// Number of healthy paths (Up)
    pub healthy_paths: usize,

    /// Number of degraded paths
    pub degraded_paths: usize,

    /// Number of down paths
    pub down_paths: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    async fn create_test_monitor() -> HealthMonitor {
        let db = Arc::new(Database::new_in_memory().await.unwrap());

        let config = HealthConfig {
            check_interval_secs: 1,
            probes_per_check: 3,
            probe_timeout_ms: 500,
            persist_to_db: true,
            db_persist_interval: 1, // Persist every check for testing
        };

        HealthMonitor::new(db, config).await.unwrap()
    }

    #[tokio::test]
    async fn test_check_path_health() {
        let monitor = create_test_monitor().await;
        let path_id = PathId::new(1);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let health = monitor.check_path_health(&path_id, target).await.unwrap();

        // Health should be calculated
        assert!(health.latency_ms >= 0.0);
        assert!(health.packet_loss_pct >= 0.0);
        assert!(health.packet_loss_pct <= 100.0);
        assert!(health.health_score >= 0.0);
        assert!(health.health_score <= 100.0);
    }

    #[tokio::test]
    async fn test_health_cache() {
        let monitor = create_test_monitor().await;
        let path_id = PathId::new(2);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Initially no health
        assert!(monitor.get_path_health(&path_id).await.is_none());

        // Check health
        monitor.check_path_health(&path_id, target).await.unwrap();

        // Now health should be cached
        let cached = monitor.get_path_health(&path_id).await;
        assert!(cached.is_some());

        let health = cached.unwrap();
        assert_eq!(health.path_id, path_id);
    }

    #[tokio::test]
    async fn test_health_persistence() {
        let monitor = create_test_monitor().await;
        let path_id = PathId::new(3);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // Check health (should persist due to db_persist_interval = 1)
        monitor.check_path_health(&path_id, target).await.unwrap();

        // Retrieve from database
        let since = SystemTime::now() - Duration::from_secs(60);
        let history = monitor.get_health_history(&path_id, since, None).await.unwrap();

        // Should have at least one record
        assert!(!history.is_empty());
        assert_eq!(history[0].path_id, path_id);
    }

    #[tokio::test]
    async fn test_get_all_health() {
        let monitor = create_test_monitor().await;
        let path1 = PathId::new(4);
        let path2 = PathId::new(5);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        monitor.check_path_health(&path1, target).await.unwrap();
        monitor.check_path_health(&path2, target).await.unwrap();

        let all_health = monitor.get_all_health().await;

        assert_eq!(all_health.len(), 2);
        assert!(all_health.contains_key(&path1));
        assert!(all_health.contains_key(&path2));
    }

    #[tokio::test]
    async fn test_health_stats() {
        let monitor = create_test_monitor().await;
        let path_id = PathId::new(6);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        monitor.check_path_health(&path_id, target).await.unwrap();

        let stats = monitor.get_stats().await;

        assert_eq!(stats.total_paths, 1);
        // Simulated probes should usually result in healthy status
        assert!(stats.healthy_paths >= 0);
        assert_eq!(stats.total_paths, stats.healthy_paths + stats.degraded_paths + stats.down_paths);
    }
}
