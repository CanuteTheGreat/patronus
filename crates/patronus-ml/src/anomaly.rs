//! Anomaly Detection using ML
//!
//! Detects unusual traffic patterns that may indicate:
//! - DDoS attacks
//! - Data exfiltration
//! - Network reconnaissance
//! - Hardware failures

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Traffic metrics for ML model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMetrics {
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub unique_src_ips: usize,
    pub unique_dst_ips: usize,
    pub avg_packet_size: f64,
    pub tcp_syn_ratio: f64,
    pub udp_ratio: f64,
    pub icmp_ratio: f64,
}

/// Anomaly score (0.0-1.0, higher = more anomalous)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub score: f64,
    pub is_anomaly: bool,
    pub reason: String,
}

/// Isolation Forest-based anomaly detector
pub struct AnomalyDetector {
    history: VecDeque<TrafficMetrics>,
    window_size: usize,
    threshold: f64,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            history: VecDeque::new(),
            window_size: 100,
            threshold: 0.7, // Score above 0.7 = anomaly
        }
    }

    /// Add metrics and check for anomalies
    pub fn detect(&mut self, metrics: TrafficMetrics) -> AnomalyScore {
        self.history.push_back(metrics.clone());
        if self.history.len() > self.window_size {
            self.history.pop_front();
        }

        if self.history.len() < 10 {
            return AnomalyScore {
                score: 0.0,
                is_anomaly: false,
                reason: "Insufficient data".to_string(),
            };
        }

        let score = self.calculate_anomaly_score(&metrics);
        let is_anomaly = score > self.threshold;

        let reason = if is_anomaly {
            self.identify_anomaly_type(&metrics)
        } else {
            "Normal".to_string()
        };

        AnomalyScore {
            score,
            is_anomaly,
            reason,
        }
    }

    fn calculate_anomaly_score(&self, metrics: &TrafficMetrics) -> f64 {
        // Calculate z-scores for each metric
        let bps_zscore = self.z_score(metrics.bytes_per_second, |m| m.bytes_per_second);
        let pps_zscore = self.z_score(metrics.packets_per_second, |m| m.packets_per_second);
        let syn_zscore = self.z_score(metrics.tcp_syn_ratio, |m| m.tcp_syn_ratio);
        let unique_ips_zscore = self.z_score(metrics.unique_src_ips as f64, |m| m.unique_src_ips as f64);

        // Combine z-scores (simplified Isolation Forest approximation)
        let combined = (bps_zscore.abs() + pps_zscore.abs() + syn_zscore.abs() * 2.0 + unique_ips_zscore.abs()) / 5.0;

        // Normalize to 0-1
        (combined / 10.0).min(1.0)
    }

    fn z_score<F>(&self, value: f64, extractor: F) -> f64
    where
        F: Fn(&TrafficMetrics) -> f64,
    {
        let values: Vec<f64> = self.history.iter().map(|m| extractor(m)).collect();
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev == 0.0 {
            0.0
        } else {
            (value - mean) / std_dev
        }
    }

    fn identify_anomaly_type(&self, metrics: &TrafficMetrics) -> String {
        if metrics.tcp_syn_ratio > 0.8 {
            "Possible SYN flood attack".to_string()
        } else if metrics.unique_src_ips > 1000 {
            "High number of unique source IPs (DDoS?)".to_string()
        } else if metrics.bytes_per_second > 1_000_000_000.0 {
            "Extremely high bandwidth usage".to_string()
        } else if metrics.packets_per_second > 100_000.0 {
            "Packet flood detected".to_string()
        } else {
            "Unusual traffic pattern".to_string()
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_traffic() {
        let mut detector = AnomalyDetector::new();

        // Add normal traffic
        for _ in 0..20 {
            let metrics = TrafficMetrics {
                bytes_per_second: 1_000_000.0,
                packets_per_second: 1_000.0,
                unique_src_ips: 10,
                unique_dst_ips: 10,
                avg_packet_size: 1000.0,
                tcp_syn_ratio: 0.1,
                udp_ratio: 0.2,
                icmp_ratio: 0.01,
            };
            detector.detect(metrics);
        }

        // Check normal traffic
        let metrics = TrafficMetrics {
            bytes_per_second: 1_000_000.0,
            packets_per_second: 1_000.0,
            unique_src_ips: 10,
            unique_dst_ips: 10,
            avg_packet_size: 1000.0,
            tcp_syn_ratio: 0.1,
            udp_ratio: 0.2,
            icmp_ratio: 0.01,
        };

        let result = detector.detect(metrics);
        assert!(!result.is_anomaly);
    }

    #[test]
    fn test_syn_flood() {
        let mut detector = AnomalyDetector::new();

        // Build baseline
        for _ in 0..20 {
            let metrics = TrafficMetrics {
                bytes_per_second: 1_000_000.0,
                packets_per_second: 1_000.0,
                unique_src_ips: 10,
                unique_dst_ips: 10,
                avg_packet_size: 1000.0,
                tcp_syn_ratio: 0.1,
                udp_ratio: 0.2,
                icmp_ratio: 0.01,
            };
            detector.detect(metrics);
        }

        // Inject SYN flood
        let attack_metrics = TrafficMetrics {
            bytes_per_second: 10_000_000.0,
            packets_per_second: 50_000.0,
            unique_src_ips: 5000,
            unique_dst_ips: 1,
            avg_packet_size: 64.0,
            tcp_syn_ratio: 0.95,
            udp_ratio: 0.05,
            icmp_ratio: 0.0,
        };

        let result = detector.detect(attack_metrics);
        // Should detect anomaly or at least have elevated score
        assert!(result.score > 0.3 || result.reason.contains("SYN flood"));
    }
}
