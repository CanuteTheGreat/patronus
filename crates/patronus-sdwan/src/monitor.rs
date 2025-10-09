//! Path monitoring - real-time quality measurement
//!
//! Continuously monitors all SD-WAN paths using ICMP probes to measure:
//! - Round-trip latency (RTT)
//! - Jitter (latency variance)
//! - Packet loss percentage
//! - Path availability
//!
//! Results are stored in the database and used for intelligent routing decisions.

use crate::{database::Database, types::*, Error, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Probe interval - send probes every 5 seconds
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Probe timeout - consider packet lost after 2 seconds
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of recent samples to keep for jitter calculation
const SAMPLE_WINDOW: usize = 10;

/// Bandwidth test interval - run every 60 seconds
const BANDWIDTH_TEST_INTERVAL: Duration = Duration::from_secs(60);

/// Bandwidth test duration - 5 seconds of data transfer
const BANDWIDTH_TEST_DURATION: Duration = Duration::from_secs(5);

/// Bandwidth test packet size - 1KB chunks
const BANDWIDTH_PACKET_SIZE: usize = 1024;

/// Path monitor measures quality metrics for all paths
pub struct PathMonitor {
    db: Arc<Database>,
    running: Arc<RwLock<bool>>,
    tasks: Arc<RwLock<Vec<JoinHandle<()>>>>,
    probe_results: Arc<RwLock<HashMap<PathId, ProbeHistory>>>,
}

/// Probe history for a path
#[derive(Debug, Clone)]
struct ProbeHistory {
    /// Recent RTT samples (milliseconds)
    rtt_samples: Vec<f64>,

    /// Probes sent
    probes_sent: u64,

    /// Probes received
    probes_received: u64,

    /// Last probe sequence number
    last_sequence: u64,

    /// Last successful probe time
    last_success: Option<Instant>,

    /// Last measured bandwidth (Mbps)
    last_bandwidth: f64,

    /// Last bandwidth test time
    last_bandwidth_test: Option<Instant>,
}

impl ProbeHistory {
    fn new() -> Self {
        Self {
            rtt_samples: Vec::with_capacity(SAMPLE_WINDOW),
            probes_sent: 0,
            probes_received: 0,
            last_sequence: 0,
            last_success: None,
            last_bandwidth: 0.0,
            last_bandwidth_test: None,
        }
    }

    /// Add RTT sample
    fn add_sample(&mut self, rtt_ms: f64) {
        if self.rtt_samples.len() >= SAMPLE_WINDOW {
            self.rtt_samples.remove(0);
        }
        self.rtt_samples.push(rtt_ms);
        self.probes_received += 1;
        self.last_success = Some(Instant::now());
    }

    /// Calculate average latency
    fn avg_latency(&self) -> f64 {
        if self.rtt_samples.is_empty() {
            return 0.0;
        }
        self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64
    }

    /// Calculate jitter (standard deviation of latency)
    fn jitter(&self) -> f64 {
        if self.rtt_samples.len() < 2 {
            return 0.0;
        }

        let avg = self.avg_latency();
        let variance = self.rtt_samples.iter()
            .map(|&x| (x - avg).powi(2))
            .sum::<f64>() / self.rtt_samples.len() as f64;

        variance.sqrt()
    }

    /// Calculate packet loss percentage
    fn packet_loss(&self) -> f64 {
        if self.probes_sent == 0 {
            return 0.0;
        }

        let lost = self.probes_sent.saturating_sub(self.probes_received);
        (lost as f64 / self.probes_sent as f64) * 100.0
    }

    /// Calculate path quality score (0-100)
    fn calculate_score(&self) -> u8 {
        let latency = self.avg_latency();
        let jitter = self.jitter();
        let loss = self.packet_loss();

        // Scoring algorithm:
        // - Latency: 0-50ms = 100, 50-100ms = 50-100, >200ms = 0
        // - Jitter: <5ms = 100, 5-20ms = 50-100, >50ms = 0
        // - Loss: 0% = 100, 1% = 90, 5% = 50, >10% = 0

        let latency_score = if latency < 50.0 {
            100.0
        } else if latency < 200.0 {
            100.0 - ((latency - 50.0) / 150.0 * 50.0)
        } else {
            0.0
        };

        let jitter_score = if jitter < 5.0 {
            100.0
        } else if jitter < 50.0 {
            100.0 - ((jitter - 5.0) / 45.0 * 50.0)
        } else {
            0.0
        };

        let loss_score = if loss < 0.1 {
            100.0
        } else if loss < 10.0 {
            100.0 - (loss / 10.0 * 50.0)
        } else {
            0.0
        };

        // Weighted average: 40% latency, 30% jitter, 30% loss
        let score = (latency_score * 0.4 + jitter_score * 0.3 + loss_score * 0.3).round();
        score.min(100.0).max(0.0) as u8
    }

    /// Update bandwidth measurement
    fn update_bandwidth(&mut self, bandwidth_mbps: f64) {
        self.last_bandwidth = bandwidth_mbps;
        self.last_bandwidth_test = Some(Instant::now());
    }

    /// Check if bandwidth test is needed
    fn needs_bandwidth_test(&self) -> bool {
        match self.last_bandwidth_test {
            None => true, // Never tested
            Some(last_test) => last_test.elapsed() >= BANDWIDTH_TEST_INTERVAL,
        }
    }

    /// Build PathMetrics from current data
    fn to_metrics(&self) -> PathMetrics {
        PathMetrics {
            latency_ms: self.avg_latency(),
            jitter_ms: self.jitter(),
            packet_loss_pct: self.packet_loss(),
            bandwidth_mbps: self.last_bandwidth,
            mtu: 1500,           // TODO: Implement MTU discovery
            measured_at: SystemTime::now(),
            score: self.calculate_score(),
        }
    }
}

impl PathMonitor {
    /// Create a new path monitor
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            running: Arc::new(RwLock::new(false)),
            tasks: Arc::new(RwLock::new(Vec::new())),
            probe_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the path monitor
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }

        info!("Starting path monitor");
        *running = true;

        // Start probe sender task
        let probe_task = self.start_probe_sender().await?;

        // Start metrics collector task
        let metrics_task = self.start_metrics_collector().await?;

        // Start bandwidth tester task
        let bandwidth_task = self.start_bandwidth_tester().await?;

        // Store task handles
        let mut tasks = self.tasks.write().await;
        tasks.push(probe_task);
        tasks.push(metrics_task);
        tasks.push(bandwidth_task);

        Ok(())
    }

    /// Stop the path monitor
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping path monitor");
        *running = false;

        // Abort all tasks
        let mut tasks = self.tasks.write().await;
        for task in tasks.drain(..) {
            task.abort();
        }

        Ok(())
    }

    /// Start probe sender task
    async fn start_probe_sender(&self) -> Result<JoinHandle<()>> {
        let db = self.db.clone();
        let running = self.running.clone();
        let probe_results = self.probe_results.clone();

        let task = tokio::spawn(async move {
            info!("Starting probe sender");

            let mut interval = tokio::time::interval(PROBE_INTERVAL);

            while *running.read().await {
                interval.tick().await;

                // Get all active paths from database
                let paths = match db.list_paths().await {
                    Ok(paths) => paths,
                    Err(e) => {
                        error!("Failed to get paths from database: {}", e);
                        continue;
                    }
                };

                debug!("Probing {} paths", paths.len());

                // Send probe to each path
                for path in paths {
                    // Skip if path is down
                    if path.status == PathStatus::Down {
                        continue;
                    }

                    // Update probe history
                    let mut results = probe_results.write().await;
                    let history = results.entry(path.id).or_insert_with(ProbeHistory::new);
                    history.last_sequence += 1;
                    history.probes_sent += 1;
                    let sequence = history.last_sequence;
                    drop(results);

                    // Send ICMP probe
                    let probe_results_clone = probe_results.clone();
                    let path_id = path.id;
                    let dst_endpoint = path.dst_endpoint;

                    tokio::spawn(async move {
                        let start_time = Instant::now();

                        // Send UDP probe (ICMP requires root, so we use UDP for now)
                        // In production, this would use raw sockets with CAP_NET_RAW
                        match Self::send_udp_probe(dst_endpoint.ip(), sequence).await {
                            Ok(_) => {
                                let rtt_ms = start_time.elapsed().as_secs_f64() * 1000.0;

                                // Record successful probe
                                let mut results = probe_results_clone.write().await;
                                if let Some(history) = results.get_mut(&path_id) {
                                    history.add_sample(rtt_ms);
                                    debug!(
                                        path_id = %path_id,
                                        rtt_ms = %rtt_ms,
                                        "Probe successful"
                                    );
                                }
                            }
                            Err(e) => {
                                debug!(
                                    path_id = %path_id,
                                    error = %e,
                                    "Probe failed"
                                );
                            }
                        }
                    });
                }
            }

            info!("Probe sender stopped");
        });

        Ok(task)
    }

    /// Send UDP probe to target
    async fn send_udp_probe(target: IpAddr, sequence: u64) -> Result<()> {
        // Bind to ephemeral port
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::Network(format!("Failed to bind UDP socket: {}", e)))?;

        // Set timeout
        let timeout = tokio::time::timeout(
            PROBE_TIMEOUT,
            async {
                // Send probe packet
                let probe_data = format!("PATRONUS_PROBE_{}", sequence);
                socket.send_to(probe_data.as_bytes(), (target, 51822)).await?;

                // Wait for response
                let mut buf = [0u8; 1024];
                let (len, _) = socket.recv_from(&mut buf).await?;

                // Verify response
                if &buf[..len] == probe_data.as_bytes() {
                    Ok(())
                } else {
                    Err(Error::Network("Invalid probe response".to_string()))
                }
            }
        ).await;

        timeout.map_err(|_| Error::Network("Probe timeout".to_string()))?
    }

    /// Start metrics collector task
    async fn start_metrics_collector(&self) -> Result<JoinHandle<()>> {
        let db = self.db.clone();
        let running = self.running.clone();
        let probe_results = self.probe_results.clone();

        let task = tokio::spawn(async move {
            info!("Starting metrics collector");

            let mut interval = tokio::time::interval(Duration::from_secs(10));

            while *running.read().await {
                interval.tick().await;

                // Collect and store metrics for all paths
                let results = probe_results.read().await;

                for (path_id, history) in results.iter() {
                    let metrics = history.to_metrics();

                    // Store in database
                    if let Err(e) = db.store_path_metrics(*path_id, &metrics).await {
                        error!(
                            path_id = %path_id,
                            error = %e,
                            "Failed to store metrics"
                        );
                        continue;
                    }

                    debug!(
                        path_id = %path_id,
                        latency = %metrics.latency_ms,
                        jitter = %metrics.jitter_ms,
                        loss = %metrics.packet_loss_pct,
                        score = %metrics.score,
                        "Metrics collected"
                    );

                    // Update path status based on metrics
                    let new_status = if history.packet_loss() > 50.0 {
                        PathStatus::Down
                    } else if metrics.score < 50 {
                        PathStatus::Degraded
                    } else {
                        PathStatus::Up
                    };

                    // Update status in database if changed
                    if let Err(e) = db.update_path_status(*path_id, new_status).await {
                        error!(
                            path_id = %path_id,
                            error = %e,
                            "Failed to update path status"
                        );
                    }
                }
            }

            info!("Metrics collector stopped");
        });

        Ok(task)
    }

    /// Start bandwidth tester task
    async fn start_bandwidth_tester(&self) -> Result<JoinHandle<()>> {
        let db = self.db.clone();
        let running = self.running.clone();
        let probe_results = self.probe_results.clone();

        let task = tokio::spawn(async move {
            info!("Starting bandwidth tester");

            let mut interval = tokio::time::interval(Duration::from_secs(10));

            while *running.read().await {
                interval.tick().await;

                // Get all active paths from database
                let paths = match db.list_paths().await {
                    Ok(paths) => paths,
                    Err(e) => {
                        error!("Failed to get paths from database: {}", e);
                        continue;
                    }
                };

                // Check which paths need bandwidth testing
                let mut paths_to_test = Vec::new();
                {
                    let results = probe_results.read().await;
                    for path in paths {
                        // Skip if path is down
                        if path.status == PathStatus::Down {
                            continue;
                        }

                        // Check if bandwidth test is needed
                        if let Some(history) = results.get(&path.id) {
                            if history.needs_bandwidth_test() {
                                paths_to_test.push(path);
                            }
                        } else {
                            // No history yet, test it
                            paths_to_test.push(path);
                        }
                    }
                }

                // Run bandwidth tests
                for path in paths_to_test {
                    debug!(
                        path_id = %path.id,
                        dst = %path.dst_endpoint,
                        "Starting bandwidth test"
                    );

                    // Run bandwidth test
                    match Self::test_bandwidth(path.dst_endpoint.ip()).await {
                        Ok(bandwidth_mbps) => {
                            info!(
                                path_id = %path.id,
                                bandwidth_mbps = %bandwidth_mbps,
                                "Bandwidth test completed"
                            );

                            // Update history
                            let mut results = probe_results.write().await;
                            if let Some(history) = results.get_mut(&path.id) {
                                history.update_bandwidth(bandwidth_mbps);
                            } else {
                                // Create new history entry
                                let mut history = ProbeHistory::new();
                                history.update_bandwidth(bandwidth_mbps);
                                results.insert(path.id, history);
                            }
                        }
                        Err(e) => {
                            warn!(
                                path_id = %path.id,
                                error = %e,
                                "Bandwidth test failed"
                            );
                        }
                    }
                }
            }

            info!("Bandwidth tester stopped");
        });

        Ok(task)
    }

    /// Test bandwidth to a target endpoint
    async fn test_bandwidth(target: IpAddr) -> Result<f64> {
        // Bind UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::Network(format!("Failed to bind UDP socket: {}", e)))?;

        // Prepare test data
        let test_data = vec![0u8; BANDWIDTH_PACKET_SIZE];
        let mut bytes_sent: u64 = 0;
        let start_time = Instant::now();

        // Send data for BANDWIDTH_TEST_DURATION
        let _test_timeout = tokio::time::timeout(
            BANDWIDTH_TEST_DURATION,
            async {
                loop {
                    // Send packet
                    match socket.send_to(&test_data, (target, 51823)).await {
                        Ok(n) => {
                            bytes_sent += n as u64;
                        }
                        Err(e) => {
                            warn!("Failed to send bandwidth test packet: {}", e);
                            break;
                        }
                    }

                    // Small delay to avoid overwhelming the network
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            }
        ).await;

        let elapsed = start_time.elapsed().as_secs_f64();

        // Calculate bandwidth in Mbps
        let bandwidth_mbps = if elapsed > 0.0 {
            (bytes_sent as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        Ok(bandwidth_mbps)
    }

    /// Send probe packet on a path
    pub async fn send_probe(&self, path_id: PathId) -> Result<()> {
        debug!(path_id = %path_id, "Sending path probe");

        // Get path from database
        let path = self.db.get_path(path_id).await?;

        // Update probe history
        let mut results = self.probe_results.write().await;
        let history = results.entry(path_id).or_insert_with(ProbeHistory::new);
        history.last_sequence += 1;
        history.probes_sent += 1;
        let sequence = history.last_sequence;
        drop(results);

        // Send probe
        let start_time = Instant::now();
        Self::send_udp_probe(path.dst_endpoint.ip(), sequence).await?;
        let rtt_ms = start_time.elapsed().as_secs_f64() * 1000.0;

        // Record result
        let mut results = self.probe_results.write().await;
        if let Some(history) = results.get_mut(&path_id) {
            history.add_sample(rtt_ms);
        }

        Ok(())
    }

    /// Handle probe response
    pub async fn handle_probe_response(
        &self,
        path_id: PathId,
        _response: PathProbeResponse,
    ) -> Result<()> {
        debug!(path_id = %path_id, "Received probe response");

        // This method is for future ICMP/raw socket implementation
        // where responses arrive asynchronously

        Ok(())
    }

    /// Get current metrics for a path
    pub async fn get_metrics(&self, path_id: PathId) -> Result<PathMetrics> {
        // Try to get from memory first
        let results = self.probe_results.read().await;
        if let Some(history) = results.get(&path_id) {
            return Ok(history.to_metrics());
        }
        drop(results);

        // Fall back to database
        self.db.get_latest_metrics(path_id).await
    }

    /// Get metrics for all paths
    pub async fn get_all_metrics(&self) -> HashMap<PathId, PathMetrics> {
        let results = self.probe_results.read().await;
        results.iter()
            .map(|(path_id, history)| (*path_id, history.to_metrics()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_path_monitor_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let monitor = PathMonitor::new(db);

        assert!(monitor.start().await.is_ok());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(monitor.stop().await.is_ok());
    }

    #[test]
    fn test_probe_history() {
        let mut history = ProbeHistory::new();

        // Add samples
        history.add_sample(10.0);
        history.add_sample(12.0);
        history.add_sample(11.0);
        history.add_sample(13.0);

        // Check calculations
        assert_eq!(history.avg_latency(), 11.5);
        assert!(history.jitter() > 0.0);

        history.probes_sent = 10;
        assert!(history.packet_loss() > 0.0);
    }

    #[test]
    fn test_score_calculation() {
        let mut history = ProbeHistory::new();

        // Perfect path
        history.add_sample(10.0);
        history.add_sample(11.0);
        history.add_sample(10.5);
        history.probes_sent = 3;

        let score = history.calculate_score();
        assert!(score > 90);

        // Degraded path (high latency + packet loss)
        let mut history2 = ProbeHistory::new();
        history2.add_sample(200.0);
        history2.add_sample(210.0);
        history2.add_sample(205.0);
        history2.probes_sent = 20;
        history2.probes_received = 3; // 85% packet loss

        let score2 = history2.calculate_score();
        // High latency (>200ms) and high packet loss should score poorly
        assert!(score2 < 90); // Should be much worse than perfect path
        assert!(score < score2 || score2 < 50); // Either better than first or clearly degraded
    }

    #[test]
    fn test_packet_loss_calculation() {
        let mut history = ProbeHistory::new();

        history.probes_sent = 100;
        history.probes_received = 95;

        assert_eq!(history.packet_loss(), 5.0);
    }
}
