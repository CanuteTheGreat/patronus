//! Service Level Agreement (SLA) Monitoring
//!
//! Tracks network path performance against configured SLA targets and
//! enables dynamic path selection based on application requirements.

use crate::types::PathId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// SLA configuration for a path
#[derive(Debug, Clone)]
pub struct SlaConfig {
    /// Target maximum latency (milliseconds)
    pub target_latency_ms: u32,

    /// Target maximum packet loss (percentage)
    pub target_packet_loss_pct: f32,

    /// Target maximum jitter (milliseconds)
    pub target_jitter_ms: u32,

    /// Measurement window duration
    pub window: Duration,

    /// Minimum samples required for valid measurement
    pub min_samples: usize,
}

impl Default for SlaConfig {
    fn default() -> Self {
        Self {
            target_latency_ms: 100,
            target_packet_loss_pct: 1.0,
            target_jitter_ms: 20,
            window: Duration::from_secs(60),
            min_samples: 10,
        }
    }
}

/// SLA measurement for a specific time window
#[derive(Debug, Clone)]
pub struct SlaMeasurement {
    /// Path identifier
    pub path_id: PathId,

    /// Measured latency (p50, p95, p99)
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,

    /// Measured packet loss percentage
    pub packet_loss_pct: f32,

    /// Measured jitter (milliseconds)
    pub jitter_ms: f64,

    /// Number of samples in measurement
    pub sample_count: usize,

    /// Timestamp of measurement
    pub timestamp: Instant,

    /// SLA compliance status
    pub latency_met: bool,
    pub packet_loss_met: bool,
    pub jitter_met: bool,
}

impl SlaMeasurement {
    /// Check if all SLA targets are met
    pub fn is_compliant(&self) -> bool {
        self.latency_met && self.packet_loss_met && self.jitter_met
    }

    /// Get overall SLA score (0-100)
    pub fn get_score(&self) -> f32 {
        let latency_score = if self.latency_met { 100.0 } else { 50.0 };
        let loss_score = if self.packet_loss_met { 100.0 } else { 50.0 };
        let jitter_score = if self.jitter_met { 100.0 } else { 50.0 };

        (latency_score + loss_score + jitter_score) / 3.0
    }
}

/// Latency sample
#[derive(Debug, Clone)]
struct LatencySample {
    latency_ms: f64,
    timestamp: Instant,
}

/// Path measurements
struct PathMeasurements {
    latency_samples: Vec<LatencySample>,
    packets_sent: u64,
    packets_lost: u64,
    jitter_samples: Vec<f64>,
    last_cleanup: Instant,
}

impl PathMeasurements {
    fn new() -> Self {
        Self {
            latency_samples: Vec::new(),
            packets_sent: 0,
            packets_lost: 0,
            jitter_samples: Vec::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Remove samples outside the window
    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;

        self.latency_samples.retain(|s| s.timestamp > cutoff);
        // Note: jitter is calculated from consecutive latency samples
        // so we don't need to clean it separately

        self.last_cleanup = Instant::now();
    }
}

/// SLA Monitor tracks path performance against SLA targets
pub struct SlaMonitor {
    /// SLA configuration per path
    configs: Arc<RwLock<HashMap<PathId, SlaConfig>>>,

    /// Current measurements per path
    measurements: Arc<RwLock<HashMap<PathId, PathMeasurements>>>,

    /// Latest SLA results per path
    results: Arc<RwLock<HashMap<PathId, SlaMeasurement>>>,
}

impl SlaMonitor {
    /// Create a new SLA monitor
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            measurements: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Configure SLA for a path
    pub fn configure_path(&self, path_id: PathId, config: SlaConfig) {
        debug!("Configuring SLA for path {}: {:?}", path_id, config);
        self.configs.write().unwrap().insert(path_id, config);
        self.measurements.write().unwrap().entry(path_id)
            .or_insert_with(PathMeasurements::new);
    }

    /// Record a latency measurement
    pub fn record_latency(&self, path_id: &PathId, latency_ms: f64) {
        let mut measurements = self.measurements.write().unwrap();
        if let Some(path_meas) = measurements.get_mut(path_id) {
            path_meas.latency_samples.push(LatencySample {
                latency_ms,
                timestamp: Instant::now(),
            });

            // Calculate jitter if we have a previous sample
            if path_meas.latency_samples.len() >= 2 {
                let len = path_meas.latency_samples.len();
                let jitter = (path_meas.latency_samples[len - 1].latency_ms -
                             path_meas.latency_samples[len - 2].latency_ms).abs();
                path_meas.jitter_samples.push(jitter);
            }
        }
    }

    /// Record packet statistics
    pub fn record_packets(&self, path_id: &PathId, sent: u64, lost: u64) {
        let mut measurements = self.measurements.write().unwrap();
        if let Some(path_meas) = measurements.get_mut(path_id) {
            path_meas.packets_sent += sent;
            path_meas.packets_lost += lost;
        }
    }

    /// Calculate percentile from sorted samples
    fn percentile(samples: &[f64], p: f64) -> f64 {
        if samples.is_empty() {
            return 0.0;
        }

        let index = (p / 100.0 * (samples.len() - 1) as f64).ceil() as usize;
        samples[index.min(samples.len() - 1)]
    }

    /// Compute SLA measurement for a path
    pub fn compute_sla(&self, path_id: &PathId) -> Option<SlaMeasurement> {
        let configs = self.configs.read().unwrap();
        let config = configs.get(path_id)?;

        let mut measurements = self.measurements.write().unwrap();
        let path_meas = measurements.get_mut(path_id)?;

        // Cleanup old samples
        if path_meas.last_cleanup.elapsed() > Duration::from_secs(10) {
            path_meas.cleanup(config.window);
        }

        // Check if we have enough samples
        if path_meas.latency_samples.len() < config.min_samples {
            return None;
        }

        // Calculate latency percentiles
        let mut latencies: Vec<f64> = path_meas.latency_samples
            .iter()
            .map(|s| s.latency_ms)
            .collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let p50 = Self::percentile(&latencies, 50.0);
        let p95 = Self::percentile(&latencies, 95.0);
        let p99 = Self::percentile(&latencies, 99.0);

        // Calculate packet loss percentage
        let packet_loss_pct = if path_meas.packets_sent > 0 {
            (path_meas.packets_lost as f32 / path_meas.packets_sent as f32) * 100.0
        } else {
            0.0
        };

        // Calculate average jitter
        let jitter_ms = if !path_meas.jitter_samples.is_empty() {
            path_meas.jitter_samples.iter().sum::<f64>() /
                path_meas.jitter_samples.len() as f64
        } else {
            0.0
        };

        // Check SLA compliance
        let latency_met = p95 <= config.target_latency_ms as f64;
        let packet_loss_met = packet_loss_pct <= config.target_packet_loss_pct;
        let jitter_met = jitter_ms <= config.target_jitter_ms as f64;

        let measurement = SlaMeasurement {
            path_id: *path_id,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            packet_loss_pct,
            jitter_ms,
            sample_count: latencies.len(),
            timestamp: Instant::now(),
            latency_met,
            packet_loss_met,
            jitter_met,
        };

        // Log SLA violations
        if !measurement.is_compliant() {
            warn!(
                "SLA violation on path {}: latency={:.1}ms (target={}ms), loss={:.2}% (target={:.1}%), jitter={:.1}ms (target={}ms)",
                path_id,
                p95,
                config.target_latency_ms,
                packet_loss_pct,
                config.target_packet_loss_pct,
                jitter_ms,
                config.target_jitter_ms
            );
        }

        // Store result
        self.results.write().unwrap().insert(*path_id, measurement.clone());

        Some(measurement)
    }

    /// Get latest SLA measurement for a path
    pub fn get_measurement(&self, path_id: &PathId) -> Option<SlaMeasurement> {
        self.results.read().unwrap().get(path_id).cloned()
    }

    /// Get all SLA measurements
    pub fn get_all_measurements(&self) -> HashMap<PathId, SlaMeasurement> {
        self.results.read().unwrap().clone()
    }

    /// Select best path based on SLA requirements
    pub fn select_best_path(
        &self,
        candidates: &[PathId],
        required_latency_ms: Option<u32>,
        required_loss_pct: Option<f32>,
    ) -> Option<PathId> {
        let results = self.results.read().unwrap();

        let mut best_path: Option<PathId> = None;
        let mut best_score: f32 = 0.0;

        for path_id in candidates {
            if let Some(measurement) = results.get(path_id) {
                // Check hard requirements
                if let Some(max_latency) = required_latency_ms {
                    if measurement.latency_p95_ms > max_latency as f64 {
                        continue;
                    }
                }

                if let Some(max_loss) = required_loss_pct {
                    if measurement.packet_loss_pct > max_loss {
                        continue;
                    }
                }

                // Calculate score
                let score = measurement.get_score();
                if score > best_score {
                    best_score = score;
                    best_path = Some(*path_id);
                }
            }
        }

        best_path
    }
}

impl Default for SlaMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_config_default() {
        let config = SlaConfig::default();
        assert_eq!(config.target_latency_ms, 100);
        assert_eq!(config.target_packet_loss_pct, 1.0);
        assert_eq!(config.target_jitter_ms, 20);
    }

    #[test]
    fn test_sla_monitor_configuration() {
        let monitor = SlaMonitor::new();
        let path_id = PathId::new(1);
        let config = SlaConfig::default();

        monitor.configure_path(path_id, config);

        // Verify configuration was stored
        assert!(monitor.configs.read().unwrap().contains_key(&path_id));
    }

    #[test]
    fn test_sla_measurement_compliance() {
        let measurement = SlaMeasurement {
            path_id: PathId::new(1),
            latency_p50_ms: 20.0,
            latency_p95_ms: 50.0,
            latency_p99_ms: 80.0,
            packet_loss_pct: 0.5,
            jitter_ms: 10.0,
            sample_count: 100,
            timestamp: Instant::now(),
            latency_met: true,
            packet_loss_met: true,
            jitter_met: true,
        };

        assert!(measurement.is_compliant());
        assert_eq!(measurement.get_score(), 100.0);
    }

    #[test]
    fn test_sla_measurement_violation() {
        let measurement = SlaMeasurement {
            path_id: PathId::new(1),
            latency_p50_ms: 20.0,
            latency_p95_ms: 150.0, // Violates 100ms target
            latency_p99_ms: 200.0,
            packet_loss_pct: 0.5,
            jitter_ms: 10.0,
            sample_count: 100,
            timestamp: Instant::now(),
            latency_met: false,
            packet_loss_met: true,
            jitter_met: true,
        };

        assert!(!measurement.is_compliant());
        assert!(measurement.get_score() < 100.0);
    }

    #[test]
    fn test_record_and_compute_sla() {
        let monitor = SlaMonitor::new();
        let path_id = PathId::new(1);

        // Configure SLA
        monitor.configure_path(path_id, SlaConfig {
            target_latency_ms: 100,
            target_packet_loss_pct: 1.0,
            target_jitter_ms: 20,
            window: Duration::from_secs(60),
            min_samples: 3,
        });

        // Record some latency measurements
        monitor.record_latency(&path_id, 30.0);
        monitor.record_latency(&path_id, 35.0);
        monitor.record_latency(&path_id, 40.0);
        monitor.record_latency(&path_id, 45.0);

        // Record packet statistics
        monitor.record_packets(&path_id, 1000, 5);

        // Compute SLA
        let measurement = monitor.compute_sla(&path_id);
        assert!(measurement.is_some());

        let m = measurement.unwrap();
        assert!(m.latency_met);
        assert!(m.packet_loss_met);
        assert_eq!(m.sample_count, 4);
    }

    #[test]
    fn test_percentile_calculation() {
        let samples = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0];

        // For 10 samples, 50th percentile is at index 4.5 -> rounds up to 5 -> value 60
        assert_eq!(SlaMonitor::percentile(&samples, 50.0), 60.0);
        // 95th percentile: index 8.55 -> rounds up to 9 -> value 100
        assert_eq!(SlaMonitor::percentile(&samples, 95.0), 100.0);
        // 99th percentile: index 8.91 -> rounds up to 9 -> value 100
        assert_eq!(SlaMonitor::percentile(&samples, 99.0), 100.0);
    }

    #[test]
    fn test_best_path_selection() {
        let monitor = SlaMonitor::new();

        let path1 = PathId::new(1);
        let path2 = PathId::new(2);

        // Path 1: Low latency, good quality
        monitor.results.write().unwrap().insert(path1, SlaMeasurement {
            path_id: path1,
            latency_p50_ms: 20.0,
            latency_p95_ms: 30.0,
            latency_p99_ms: 40.0,
            packet_loss_pct: 0.1,
            jitter_ms: 5.0,
            sample_count: 100,
            timestamp: Instant::now(),
            latency_met: true,
            packet_loss_met: true,
            jitter_met: true,
        });

        // Path 2: Higher latency
        monitor.results.write().unwrap().insert(path2, SlaMeasurement {
            path_id: path2,
            latency_p50_ms: 50.0,
            latency_p95_ms: 80.0,
            latency_p99_ms: 100.0,
            packet_loss_pct: 0.5,
            jitter_ms: 15.0,
            sample_count: 100,
            timestamp: Instant::now(),
            latency_met: true,
            packet_loss_met: true,
            jitter_met: true,
        });

        let best = monitor.select_best_path(&[path1, path2], Some(50), None);
        assert_eq!(best, Some(path1));
    }
}
