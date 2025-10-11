//! System-wide Metrics Collection
//!
//! This module provides comprehensive metrics collection for the entire SD-WAN system,
//! aggregating path metrics, system resources, and traffic statistics.

use crate::{database::Database, types::*, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use sysinfo::System;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Metrics collection interval - collect every 10 seconds
const METRICS_INTERVAL: Duration = Duration::from_secs(10);

/// Number of historical metrics snapshots to keep in memory
const METRICS_HISTORY_SIZE: usize = 360; // 1 hour at 10-second intervals

/// Metrics retention period - keep 30 days of historical data
const METRICS_RETENTION_DAYS: u64 = 30;

/// Cleanup interval - run retention policy every 24 hours
const CLEANUP_INTERVAL: Duration = Duration::from_secs(86400);

/// System-wide metrics snapshot
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    /// Timestamp of metrics collection
    pub timestamp: SystemTime,

    /// Total throughput across all paths (Mbps)
    pub throughput_mbps: f64,

    /// Total packets per second
    pub packets_per_second: u64,

    /// Number of active flows
    pub active_flows: u64,

    /// Average latency across all paths (ms)
    pub avg_latency_ms: f64,

    /// Average packet loss across all paths (%)
    pub avg_packet_loss: f64,

    /// CPU utilization (0-100)
    pub cpu_usage: f64,

    /// Memory utilization (0-100)
    pub memory_usage: f64,

    /// Per-path metrics
    pub path_metrics: HashMap<PathId, PathMetrics>,
}

impl SystemMetrics {
    /// Create a new empty metrics snapshot
    pub fn new() -> Self {
        Self {
            timestamp: SystemTime::now(),
            throughput_mbps: 0.0,
            packets_per_second: 0,
            active_flows: 0,
            avg_latency_ms: 0.0,
            avg_packet_loss: 0.0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            path_metrics: HashMap::new(),
        }
    }
}

/// Metrics collector service
pub struct MetricsCollector {
    db: Arc<Database>,
    system: Arc<RwLock<System>>,
    running: Arc<RwLock<bool>>,
    current_metrics: Arc<RwLock<SystemMetrics>>,
    metrics_history: Arc<RwLock<Vec<SystemMetrics>>>,
    traffic_stats: Arc<RwLock<TrafficStats>>,
}

/// Traffic statistics tracked by eBPF
#[derive(Debug, Clone, Default)]
struct TrafficStats {
    /// Total bytes transmitted
    bytes_tx: u64,

    /// Total bytes received
    bytes_rx: u64,

    /// Total packets transmitted
    packets_tx: u64,

    /// Total packets received
    packets_rx: u64,

    /// Active flow count
    active_flows: u64,

    /// Last update time
    last_update: Option<SystemTime>,
}

impl TrafficStats {
    /// Calculate throughput in Mbps since last update
    fn calculate_throughput(&mut self) -> f64 {
        let now = SystemTime::now();

        if let Some(last) = self.last_update {
            let elapsed = now.duration_since(last).unwrap_or(Duration::from_secs(1));
            let elapsed_secs = elapsed.as_secs_f64();

            if elapsed_secs > 0.0 {
                let total_bytes = self.bytes_tx + self.bytes_rx;
                let bits = total_bytes as f64 * 8.0;
                let mbps = bits / (elapsed_secs * 1_000_000.0);

                // Reset counters for next interval
                self.bytes_tx = 0;
                self.bytes_rx = 0;
                self.last_update = Some(now);

                return mbps;
            }
        }

        self.last_update = Some(now);
        0.0
    }

    /// Calculate packets per second since last update
    fn calculate_pps(&mut self) -> u64 {
        let now = SystemTime::now();

        if let Some(last) = self.last_update {
            let elapsed = now.duration_since(last).unwrap_or(Duration::from_secs(1));
            let elapsed_secs = elapsed.as_secs_f64();

            if elapsed_secs > 0.0 {
                let total_packets = self.packets_tx + self.packets_rx;
                let pps = (total_packets as f64 / elapsed_secs) as u64;

                // Reset counters
                self.packets_tx = 0;
                self.packets_rx = 0;

                return pps;
            }
        }

        0
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(db: Arc<Database>) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        Self {
            db,
            system: Arc::new(RwLock::new(sys)),
            running: Arc::new(RwLock::new(false)),
            current_metrics: Arc::new(RwLock::new(SystemMetrics::new())),
            metrics_history: Arc::new(RwLock::new(Vec::with_capacity(METRICS_HISTORY_SIZE))),
            traffic_stats: Arc::new(RwLock::new(TrafficStats::default())),
        }
    }

    /// Start the metrics collector
    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let mut running = self.running.write().await;
        if *running {
            return Err(crate::Error::Other("Metrics collector already running".to_string()));
        }

        info!("Starting metrics collector");
        *running = true;

        // Start metrics collection task
        let collection_task = self.start_collection_task().await;

        // Start retention cleanup task
        let cleanup_task = self.start_cleanup_task().await;

        // Spawn a supervisor task to monitor both
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = collection_task => {
                    info!("Metrics collection task ended");
                }
                _ = cleanup_task => {
                    info!("Metrics cleanup task ended");
                }
            }
        });

        Ok(task)
    }

    /// Start the metrics collection task
    async fn start_collection_task(&self) -> tokio::task::JoinHandle<()> {
        let db = self.db.clone();
        let system = self.system.clone();
        let running_flag = self.running.clone();
        let current_metrics = self.current_metrics.clone();
        let metrics_history = self.metrics_history.clone();
        let traffic_stats = self.traffic_stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(METRICS_INTERVAL);

            while *running_flag.read().await {
                interval.tick().await;

                // Collect system metrics
                let mut metrics = SystemMetrics::new();

                // 1. Collect path metrics from database
                match db.list_paths().await {
                    Ok(paths) => {
                        let mut total_latency = 0.0;
                        let mut total_loss = 0.0;
                        let mut path_count = 0;

                        for path in paths {
                            // Get latest metrics for each path
                            if let Ok(path_metrics) = db.get_latest_metrics(path.id).await {
                                total_latency += path_metrics.latency_ms;
                                total_loss += path_metrics.packet_loss_pct;
                                path_count += 1;

                                metrics.path_metrics.insert(path.id, path_metrics);
                            }
                        }

                        // Calculate averages
                        if path_count > 0 {
                            metrics.avg_latency_ms = total_latency / path_count as f64;
                            metrics.avg_packet_loss = total_loss / path_count as f64;
                        }
                    }
                    Err(e) => {
                        error!("Failed to get paths for metrics: {}", e);
                    }
                }

                // 2. Collect system resource metrics
                {
                    let mut sys = system.write().await;
                    sys.refresh_cpu_all();
                    sys.refresh_memory();

                    // CPU usage (average across all cores)
                    let cpus = sys.cpus();
                    if !cpus.is_empty() {
                        metrics.cpu_usage = cpus.iter()
                            .map(|cpu| cpu.cpu_usage() as f64)
                            .sum::<f64>() / cpus.len() as f64;
                    }

                    // Memory usage percentage
                    let total_memory = sys.total_memory();
                    let used_memory = sys.used_memory();
                    if total_memory > 0 {
                        metrics.memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;
                    }
                }

                // 3. Collect traffic statistics
                {
                    let mut stats = traffic_stats.write().await;
                    metrics.throughput_mbps = stats.calculate_throughput();
                    metrics.packets_per_second = stats.calculate_pps();
                    metrics.active_flows = stats.active_flows;
                }

                // 4. Store metrics in database
                if let Err(e) = db.store_system_metrics(&metrics).await {
                    error!("Failed to store system metrics: {}", e);
                }

                // 5. Update current metrics
                *current_metrics.write().await = metrics.clone();

                // 6. Add to history (with size limit)
                {
                    let mut history = metrics_history.write().await;
                    history.push(metrics.clone());
                    if history.len() > METRICS_HISTORY_SIZE {
                        history.remove(0);
                    }
                }

                debug!(
                    throughput_mbps = %metrics.throughput_mbps,
                    pps = %metrics.packets_per_second,
                    flows = %metrics.active_flows,
                    cpu = %metrics.cpu_usage,
                    memory = %metrics.memory_usage,
                    "Metrics collected"
                );
            }

            info!("Metrics collector stopped");
        })
    }

    /// Start the cleanup task for metrics retention
    async fn start_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let db = self.db.clone();
        let running_flag = self.running.clone();

        tokio::spawn(async move {
            info!("Starting metrics cleanup task");

            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);

            while *running_flag.read().await {
                interval.tick().await;

                // Calculate cutoff time (30 days ago)
                let retention_duration = Duration::from_secs(METRICS_RETENTION_DAYS * 86400);
                let now = SystemTime::now();
                let cutoff_time = now.checked_sub(retention_duration)
                    .unwrap_or(SystemTime::UNIX_EPOCH);

                // Run cleanup
                match db.cleanup_old_metrics(cutoff_time).await {
                    Ok(deleted_count) => {
                        info!(
                            deleted_count = %deleted_count,
                            "Cleaned up old metrics"
                        );
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            "Failed to clean up old metrics"
                        );
                    }
                }
            }

            info!("Metrics cleanup task stopped");
        })
    }

    /// Stop the metrics collector
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Stopping metrics collector");
    }

    /// Get current system metrics
    pub async fn get_current_metrics(&self) -> SystemMetrics {
        self.current_metrics.read().await.clone()
    }

    /// Get metrics history over a time range
    pub async fn get_metrics_history(
        &self,
        from: SystemTime,
        to: SystemTime,
    ) -> Vec<SystemMetrics> {
        let history = self.metrics_history.read().await;

        history.iter()
            .filter(|m| m.timestamp >= from && m.timestamp <= to)
            .cloned()
            .collect()
    }

    /// Update traffic statistics (called by eBPF or packet processing layer)
    pub async fn update_traffic_stats(
        &self,
        bytes_tx: u64,
        bytes_rx: u64,
        packets_tx: u64,
        packets_rx: u64,
        active_flows: u64,
    ) {
        let mut stats = self.traffic_stats.write().await;
        stats.bytes_tx += bytes_tx;
        stats.bytes_rx += bytes_rx;
        stats.packets_tx += packets_tx;
        stats.packets_rx += packets_rx;
        stats.active_flows = active_flows;
    }

    /// Get traffic statistics snapshot
    pub async fn get_traffic_stats(&self) -> TrafficStats {
        self.traffic_stats.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let collector = MetricsCollector::new(db);

        // Should start successfully
        let task = collector.start().await;
        assert!(task.is_ok());

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Get current metrics
        let metrics = collector.get_current_metrics().await;
        assert!(metrics.cpu_usage >= 0.0);
        assert!(metrics.memory_usage >= 0.0);

        // Stop
        collector.stop().await;
        task.unwrap().abort();
    }

    #[tokio::test]
    async fn test_traffic_stats_calculation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let collector = MetricsCollector::new(db);

        // Update stats
        collector.update_traffic_stats(
            1_000_000, // 1 MB tx
            2_000_000, // 2 MB rx
            1000,      // 1000 packets tx
            2000,      // 2000 packets rx
            5,         // 5 active flows
        ).await;

        let stats = collector.get_traffic_stats().await;
        assert_eq!(stats.active_flows, 5);
    }

    #[test]
    fn test_throughput_calculation() {
        let mut stats = TrafficStats::default();

        // Simulate 1MB over 1 second = 8 Mbps
        stats.bytes_tx = 500_000;
        stats.bytes_rx = 500_000;
        stats.last_update = Some(SystemTime::now() - Duration::from_secs(1));

        let throughput = stats.calculate_throughput();
        assert!(throughput > 0.0);
        assert!(throughput < 100.0); // Sanity check
    }
}
