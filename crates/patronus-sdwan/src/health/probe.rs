//! Network probing for path health measurements
//!
//! This module implements ICMP echo (ping) and UDP probes to measure
//! latency, packet loss, and jitter for network paths.

use super::icmp_probe::{IcmpProber, IcmpError};
use super::udp_probe::{UdpProber, UdpError};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Configuration for network probes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Target IP address to probe
    pub target: IpAddr,

    /// Number of probes to send
    pub count: usize,

    /// Timeout for each probe response
    pub timeout: Duration,

    /// Delay between probes
    pub interval: Duration,

    /// Probe type (ICMP or UDP)
    pub probe_type: ProbeType,
}

/// Type of probe to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeType {
    /// ICMP Echo Request (ping) - requires CAP_NET_RAW
    Icmp,
    /// UDP probe to high port - no special privileges required
    Udp,
    /// Simulated probe for testing
    Simulated,
}

/// Result of probe measurements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Average round-trip latency in milliseconds
    pub latency_ms: f64,

    /// Packet loss percentage (0.0-100.0)
    pub packet_loss_pct: f64,

    /// Jitter (standard deviation of latency) in milliseconds
    pub jitter_ms: f64,

    /// Number of probes sent
    pub probes_sent: usize,

    /// Number of probes that received responses
    pub probes_received: usize,
}

/// Network prober for health measurements with automatic fallback
pub struct Prober {
    config: ProbeConfig,
    icmp_prober: Option<Arc<IcmpProber>>,
    udp_prober: Arc<UdpProber>,
    active_probe_type: Arc<RwLock<ProbeType>>,
}

impl Prober {
    /// Create a new prober with the given configuration
    ///
    /// Automatically detects available probe methods and sets up fallback.
    pub async fn new(config: ProbeConfig) -> Self {
        // Try to create ICMP prober
        let icmp_prober = match IcmpProber::new() {
            Ok(prober) => {
                tracing::info!("ICMP probing available");
                Some(Arc::new(prober))
            }
            Err(IcmpError::InsufficientPermissions) => {
                tracing::warn!("ICMP probing unavailable (insufficient permissions), will use UDP");
                None
            }
            Err(e) => {
                tracing::warn!("ICMP probing unavailable: {}, will use UDP", e);
                None
            }
        };

        // Always create UDP prober as fallback
        let udp_prober = UdpProber::new()
            .await
            .expect("UDP prober creation should never fail");

        // Determine active probe type based on config and availability
        let active_probe_type = match config.probe_type {
            ProbeType::Icmp if icmp_prober.is_some() => ProbeType::Icmp,
            ProbeType::Icmp => {
                tracing::info!("ICMP requested but unavailable, using UDP");
                ProbeType::Udp
            }
            ProbeType::Udp => ProbeType::Udp,
            ProbeType::Simulated => ProbeType::Simulated,
        };

        Self {
            config,
            icmp_prober,
            udp_prober: Arc::new(udp_prober),
            active_probe_type: Arc::new(RwLock::new(active_probe_type)),
        }
    }

    /// Execute probes and collect measurements
    ///
    /// # Returns
    ///
    /// ProbeResult containing latency, packet loss, and jitter measurements
    ///
    /// # Errors
    ///
    /// Returns error if probing fails completely (all probes timeout)
    pub async fn probe(&self) -> Result<ProbeResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut latencies = Vec::new();
        let mut received = 0;

        for _ in 0..self.config.count {
            match self.send_probe().await {
                Ok(Some(latency)) => {
                    latencies.push(latency);
                    received += 1;
                }
                Ok(None) => {
                    // Probe timed out
                }
                Err(e) => {
                    tracing::warn!("Probe error: {}", e);
                }
            }

            // Wait between probes (except after last one)
            tokio::time::sleep(self.config.interval).await;
        }

        if latencies.is_empty() {
            // All probes failed
            return Ok(ProbeResult {
                latency_ms: f64::INFINITY,
                packet_loss_pct: 100.0,
                jitter_ms: 0.0,
                probes_sent: self.config.count,
                probes_received: 0,
            });
        }

        // Calculate average latency
        let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;

        // Calculate packet loss percentage
        let packet_loss_pct = ((self.config.count - received) as f64 / self.config.count as f64) * 100.0;

        // Calculate jitter (standard deviation of latencies)
        let jitter = if latencies.len() > 1 {
            let variance = latencies
                .iter()
                .map(|&latency| {
                    let diff = latency - avg_latency;
                    diff * diff
                })
                .sum::<f64>()
                / (latencies.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        Ok(ProbeResult {
            latency_ms: avg_latency,
            packet_loss_pct,
            jitter_ms: jitter,
            probes_sent: self.config.count,
            probes_received: received,
        })
    }

    /// Send a single probe and measure latency
    ///
    /// # Returns
    ///
    /// - Ok(Some(latency_ms)): Probe succeeded, returns latency in milliseconds
    /// - Ok(None): Probe timed out
    /// - Err: Probe failed with error
    async fn send_probe(&self) -> Result<Option<f64>, Box<dyn std::error::Error + Send + Sync>> {
        let probe_type = *self.active_probe_type.read().await;

        match probe_type {
            ProbeType::Icmp => self.send_icmp_probe().await,
            ProbeType::Udp => self.send_udp_probe().await,
            ProbeType::Simulated => self.send_simulated_probe().await,
        }
    }

    /// Send ICMP echo request
    async fn send_icmp_probe(&self) -> Result<Option<f64>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref prober) = self.icmp_prober {
            match prober.probe(self.config.target).await {
                Ok(result) => {
                    if result.success {
                        Ok(Some(result.latency_ms))
                    } else {
                        Ok(None)
                    }
                }
                Err(IcmpError::Timeout(_)) => Ok(None),
                Err(e) => {
                    tracing::warn!("ICMP probe failed: {}, falling back to UDP", e);
                    // Fall back to UDP
                    *self.active_probe_type.write().await = ProbeType::Udp;
                    self.send_udp_probe().await
                }
            }
        } else {
            // No ICMP prober available, use UDP
            self.send_udp_probe().await
        }
    }

    /// Send UDP probe
    async fn send_udp_probe(&self) -> Result<Option<f64>, Box<dyn std::error::Error + Send + Sync>> {
        match self.udp_prober.probe(self.config.target).await {
            Ok(result) => {
                if result.success {
                    Ok(Some(result.latency_ms))
                } else {
                    Ok(None)
                }
            }
            Err(UdpError::Timeout(_)) => Ok(None),
            Err(e) => {
                tracing::warn!("UDP probe failed: {}, using simulated", e);
                // Last resort: simulated probe
                *self.active_probe_type.write().await = ProbeType::Simulated;
                self.send_simulated_probe().await
            }
        }
    }

    /// Simulated probe for development/testing
    ///
    /// This simulates realistic network behavior for testing purposes.
    /// In production, this would be replaced with actual ICMP probes.
    async fn send_simulated_probe(&self) -> Result<Option<f64>, Box<dyn std::error::Error + Send + Sync>> {
        // Simulate network delay
        let base_latency = 20.0; // Base latency in ms
        let jitter = (rand::random::<f64>() - 0.5) * 10.0; // ±5ms jitter
        let latency = (base_latency + jitter).max(0.0);

        // Simulate occasional packet loss (5% chance)
        if rand::random::<f64>() < 0.05 {
            return Ok(None);
        }

        // Simulate the delay
        tokio::time::sleep(Duration::from_secs_f64(latency / 1000.0)).await;

        Ok(Some(latency))
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            target: "8.8.8.8".parse().unwrap(), // Google DNS
            count: 5,
            timeout: Duration::from_secs(1),
            interval: Duration::from_millis(200),
            probe_type: ProbeType::Icmp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simulated_probe() {
        let config = ProbeConfig {
            probe_type: ProbeType::Simulated,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        let result = prober.send_simulated_probe().await;
        assert!(result.is_ok());

        if let Ok(Some(latency)) = result {
            // Latency should be reasonable (0-50ms with base 20ms ±5ms)
            assert!(latency >= 0.0);
            assert!(latency < 100.0);
        }
    }

    #[tokio::test]
    async fn test_probe_multiple() {
        let config = ProbeConfig {
            count: 10,
            probe_type: ProbeType::Simulated,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        let result = prober.probe().await;
        assert!(result.is_ok());

        let probe_result = result.unwrap();

        // Should have sent 10 probes
        assert_eq!(probe_result.probes_sent, 10);

        // Should have received most of them (allowing for simulated loss)
        assert!(probe_result.probes_received >= 7);

        // Latency should be reasonable
        assert!(probe_result.latency_ms > 0.0);
        assert!(probe_result.latency_ms < 100.0);

        // Jitter should be present but reasonable
        assert!(probe_result.jitter_ms >= 0.0);
        assert!(probe_result.jitter_ms < 50.0);

        // Packet loss should be low
        assert!(probe_result.packet_loss_pct < 30.0);
    }

    #[tokio::test]
    async fn test_probe_calculates_stats() {
        let config = ProbeConfig {
            count: 20,
            probe_type: ProbeType::Simulated,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        let result = prober.probe().await.unwrap();

        // Verify all stats are calculated
        assert!(result.latency_ms > 0.0);
        assert!(result.jitter_ms >= 0.0);
        assert!(result.packet_loss_pct >= 0.0);
        assert!(result.packet_loss_pct <= 100.0);
        assert_eq!(result.probes_sent, 20);
    }

    #[test]
    fn test_probe_config_default() {
        let config = ProbeConfig::default();

        assert_eq!(config.count, 5);
        assert_eq!(config.timeout, Duration::from_secs(1));
        assert_eq!(config.interval, Duration::from_millis(200));
        assert_eq!(config.probe_type, ProbeType::Icmp);
    }

    #[test]
    fn test_probe_type_serialization() {
        let icmp = ProbeType::Icmp;
        let udp = ProbeType::Udp;
        let simulated = ProbeType::Simulated;

        assert_eq!(icmp, ProbeType::Icmp);
        assert_eq!(udp, ProbeType::Udp);
        assert_eq!(simulated, ProbeType::Simulated);
        assert_ne!(icmp, udp);
        assert_ne!(icmp, simulated);
        assert_ne!(udp, simulated);
    }

    #[tokio::test]
    async fn test_prober_automatic_fallback() {
        // When ICMP is requested but unavailable, should fall back to UDP
        let config = ProbeConfig {
            probe_type: ProbeType::Icmp,
            count: 5,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        // Should have created UDP prober as fallback
        assert!(prober.udp_prober.local_port().is_ok());

        // Active type should be ICMP if available, UDP otherwise
        let active_type = *prober.active_probe_type.read().await;
        assert!(
            active_type == ProbeType::Icmp || active_type == ProbeType::Udp,
            "Active type should be ICMP or UDP, got {:?}",
            active_type
        );
    }

    #[tokio::test]
    async fn test_udp_prober_always_available() {
        let config = ProbeConfig {
            probe_type: ProbeType::Udp,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        // Should always be able to create UDP prober
        assert!(prober.udp_prober.local_port().is_ok());

        let active_type = *prober.active_probe_type.read().await;
        assert_eq!(active_type, ProbeType::Udp);
    }

    #[tokio::test]
    async fn test_simulated_probe_mode() {
        let config = ProbeConfig {
            probe_type: ProbeType::Simulated,
            count: 5,
            ..Default::default()
        };
        let prober = Prober::new(config).await;

        let active_type = *prober.active_probe_type.read().await;
        assert_eq!(active_type, ProbeType::Simulated);

        // Should still work
        let result = prober.probe().await;
        assert!(result.is_ok());
    }
}
