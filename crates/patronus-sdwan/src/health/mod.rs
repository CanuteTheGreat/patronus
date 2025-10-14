//! Path health monitoring for SD-WAN
//!
//! This module provides real-time health monitoring for network paths,
//! including latency tracking, packet loss detection, and health scoring.
//!
//! # Features
//!
//! - **Real-time Monitoring**: Continuous health checks via ICMP/UDP probes
//! - **Health Scoring**: Composite score (0-100) based on latency, loss, and jitter
//! - **Status Detection**: Automatic classification (Up, Degraded, Down)
//! - **Historical Data**: Database persistence for trend analysis
//!
//! # Example
//!
//! ```rust,no_run
//! use patronus_sdwan::health::HealthMonitor;
//! use patronus_sdwan::types::PathId;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let monitor = HealthMonitor::new(db).await?;
//!
//! // Check path health
//! let path_id = PathId::new();
//! let health = monitor.check_path_health(&path_id).await?;
//!
//! println!("Path health score: {}", health.health_score);
//! println!("Status: {:?}", health.status);
//! # Ok(())
//! # }
//! ```

mod bfd;
mod checker;
mod icmp_probe;
mod probe;
mod scoring;
mod udp_probe;

pub use bfd::{BfdConfig, BfdDiagnostic, BfdPacket, BfdSession, BfdState};
pub use checker::HealthMonitor;
pub use icmp_probe::{IcmpError, IcmpProbeResult, IcmpProber};
pub use probe::{ProbeConfig, ProbeResult, Prober};
pub use scoring::{HealthScore, HealthScorer};
pub use udp_probe::{UdpError, UdpProbeResult, UdpProber};

use crate::types::PathId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Path health status classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathStatus {
    /// Path is healthy and meeting all thresholds
    Up,
    /// Path has performance issues but is still usable
    Degraded,
    /// Path has failed health checks
    Down,
}

impl PathStatus {
    /// Convert status to string for database storage
    pub fn as_str(&self) -> &'static str {
        match self {
            PathStatus::Up => "up",
            PathStatus::Degraded => "degraded",
            PathStatus::Down => "down",
        }
    }

    /// Parse status from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "up" => Some(PathStatus::Up),
            "degraded" => Some(PathStatus::Degraded),
            "down" => Some(PathStatus::Down),
            _ => None,
        }
    }
}

/// Complete health metrics for a network path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealth {
    /// Path identifier
    pub path_id: PathId,

    /// Round-trip latency in milliseconds
    pub latency_ms: f64,

    /// Packet loss percentage (0.0-100.0)
    pub packet_loss_pct: f64,

    /// Jitter (variance in latency) in milliseconds
    pub jitter_ms: f64,

    /// Composite health score (0.0-100.0)
    /// - 100.0: Perfect health
    /// - 80.0+: Up
    /// - 50.0-79.9: Degraded
    /// - <50.0: Down
    pub health_score: f64,

    /// Current path status
    pub status: PathStatus,

    /// Timestamp of last health check
    pub last_checked: SystemTime,
}

impl PathHealth {
    /// Create a new PathHealth instance
    pub fn new(path_id: PathId, probe_result: &ProbeResult) -> Self {
        let scorer = HealthScorer::default();
        let score = scorer.calculate_score(
            probe_result.latency_ms,
            probe_result.packet_loss_pct,
            probe_result.jitter_ms,
        );

        let status = Self::determine_status(score.score);

        Self {
            path_id,
            latency_ms: probe_result.latency_ms,
            packet_loss_pct: probe_result.packet_loss_pct,
            jitter_ms: probe_result.jitter_ms,
            health_score: score.score,
            status,
            last_checked: SystemTime::now(),
        }
    }

    /// Determine path status from health score
    fn determine_status(score: f64) -> PathStatus {
        if score >= 80.0 {
            PathStatus::Up
        } else if score >= 50.0 {
            PathStatus::Degraded
        } else {
            PathStatus::Down
        }
    }

    /// Check if path is healthy (Up status)
    pub fn is_healthy(&self) -> bool {
        self.status == PathStatus::Up
    }

    /// Check if path is usable (Up or Degraded)
    pub fn is_usable(&self) -> bool {
        matches!(self.status, PathStatus::Up | PathStatus::Degraded)
    }

    /// Check if path is down
    pub fn is_down(&self) -> bool {
        self.status == PathStatus::Down
    }
}

/// Configuration for health monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Interval between health checks in seconds
    pub check_interval_secs: u64,

    /// Number of probes to send per check
    pub probes_per_check: usize,

    /// Timeout for probe responses in milliseconds
    pub probe_timeout_ms: u64,

    /// Whether to persist health data to database
    pub persist_to_db: bool,

    /// How often to persist to database (in checks)
    pub db_persist_interval: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 10,
            probes_per_check: 5,
            probe_timeout_ms: 1000,
            persist_to_db: true,
            db_persist_interval: 6, // Every 6 checks = 1 minute with default interval
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_status_conversion() {
        assert_eq!(PathStatus::Up.as_str(), "up");
        assert_eq!(PathStatus::Degraded.as_str(), "degraded");
        assert_eq!(PathStatus::Down.as_str(), "down");

        assert_eq!(PathStatus::from_str("up"), Some(PathStatus::Up));
        assert_eq!(PathStatus::from_str("degraded"), Some(PathStatus::Degraded));
        assert_eq!(PathStatus::from_str("down"), Some(PathStatus::Down));
        assert_eq!(PathStatus::from_str("invalid"), None);
    }

    #[test]
    fn test_determine_status() {
        assert_eq!(PathHealth::determine_status(100.0), PathStatus::Up);
        assert_eq!(PathHealth::determine_status(80.0), PathStatus::Up);
        assert_eq!(PathHealth::determine_status(79.9), PathStatus::Degraded);
        assert_eq!(PathHealth::determine_status(50.0), PathStatus::Degraded);
        assert_eq!(PathHealth::determine_status(49.9), PathStatus::Down);
        assert_eq!(PathHealth::determine_status(0.0), PathStatus::Down);
    }

    #[test]
    fn test_health_checks() {
        let probe_result = ProbeResult {
            latency_ms: 50.0,
            packet_loss_pct: 0.0,
            jitter_ms: 2.0,
            probes_sent: 5,
            probes_received: 5,
        };

        let health = PathHealth::new(PathId::new(1), &probe_result);

        // With good metrics, should be Up
        assert!(health.is_healthy());
        assert!(health.is_usable());
        assert!(!health.is_down());
    }
}
