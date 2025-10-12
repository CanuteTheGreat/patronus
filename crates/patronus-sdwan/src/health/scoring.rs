//! Health scoring algorithm for path quality assessment
//!
//! This module implements a composite scoring algorithm that combines
//! latency, packet loss, and jitter into a single health score (0-100).

use serde::{Deserialize, Serialize};

/// Thresholds for health score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthThresholds {
    /// Maximum acceptable latency in milliseconds
    pub max_latency_ms: f64,

    /// Maximum acceptable packet loss percentage
    pub max_packet_loss_pct: f64,

    /// Maximum acceptable jitter in milliseconds
    pub max_jitter_ms: f64,

    /// Weight for latency in overall score (0.0-1.0)
    pub latency_weight: f64,

    /// Weight for packet loss in overall score (0.0-1.0)
    pub loss_weight: f64,

    /// Weight for jitter in overall score (0.0-1.0)
    pub jitter_weight: f64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            max_latency_ms: 100.0,      // 100ms threshold
            max_packet_loss_pct: 2.0,   // 2% loss threshold
            max_jitter_ms: 10.0,        // 10ms jitter threshold
            latency_weight: 0.40,       // 40% weight
            loss_weight: 0.40,          // 40% weight
            jitter_weight: 0.20,        // 20% weight
        }
    }
}

/// Result of health score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    /// Overall composite score (0.0-100.0)
    pub score: f64,

    /// Individual score for latency (0.0-100.0)
    pub latency_score: f64,

    /// Individual score for packet loss (0.0-100.0)
    pub loss_score: f64,

    /// Individual score for jitter (0.0-100.0)
    pub jitter_score: f64,
}

/// Health scoring calculator
pub struct HealthScorer {
    thresholds: HealthThresholds,
}

impl Default for HealthScorer {
    fn default() -> Self {
        Self {
            thresholds: HealthThresholds::default(),
        }
    }
}

impl HealthScorer {
    /// Create a new health scorer with custom thresholds
    pub fn new(thresholds: HealthThresholds) -> Self {
        Self { thresholds }
    }

    /// Calculate composite health score from metrics
    ///
    /// # Algorithm
    ///
    /// 1. Calculate individual scores for latency, loss, and jitter
    /// 2. Apply exponential penalty for metrics exceeding thresholds
    /// 3. Combine scores using weighted average
    /// 4. Clamp result to 0.0-100.0 range
    ///
    /// # Arguments
    ///
    /// * `latency_ms` - Round-trip latency in milliseconds
    /// * `packet_loss_pct` - Packet loss percentage (0.0-100.0)
    /// * `jitter_ms` - Jitter in milliseconds
    ///
    /// # Returns
    ///
    /// HealthScore with overall and individual component scores
    pub fn calculate_score(
        &self,
        latency_ms: f64,
        packet_loss_pct: f64,
        jitter_ms: f64,
    ) -> HealthScore {
        let latency_score = self.score_latency(latency_ms);
        let loss_score = self.score_packet_loss(packet_loss_pct);
        let jitter_score = self.score_jitter(jitter_ms);

        // Weighted average
        let score = (latency_score * self.thresholds.latency_weight)
            + (loss_score * self.thresholds.loss_weight)
            + (jitter_score * self.thresholds.jitter_weight);

        // Clamp to valid range
        let score = score.max(0.0).min(100.0);

        HealthScore {
            score,
            latency_score,
            loss_score,
            jitter_score,
        }
    }

    /// Score latency component
    ///
    /// Uses exponential decay for latency above threshold:
    /// - latency <= threshold: 100.0
    /// - latency > threshold: exponential decay
    fn score_latency(&self, latency_ms: f64) -> f64 {
        if latency_ms <= self.thresholds.max_latency_ms {
            100.0
        } else {
            let ratio = latency_ms / self.thresholds.max_latency_ms;
            // Exponential penalty: 100 * e^(-ratio)
            100.0 * (-ratio).exp()
        }
    }

    /// Score packet loss component
    ///
    /// Uses exponential decay for loss above threshold:
    /// - loss <= threshold: 100.0
    /// - loss > threshold: exponential decay
    fn score_packet_loss(&self, packet_loss_pct: f64) -> f64 {
        if packet_loss_pct <= self.thresholds.max_packet_loss_pct {
            100.0
        } else {
            let ratio = packet_loss_pct / self.thresholds.max_packet_loss_pct;
            // Exponential penalty: 100 * e^(-2*ratio)
            // More aggressive penalty for packet loss
            100.0 * (-2.0 * ratio).exp()
        }
    }

    /// Score jitter component
    ///
    /// Uses exponential decay for jitter above threshold:
    /// - jitter <= threshold: 100.0
    /// - jitter > threshold: exponential decay
    fn score_jitter(&self, jitter_ms: f64) -> f64 {
        if jitter_ms <= self.thresholds.max_jitter_ms {
            100.0
        } else {
            let ratio = jitter_ms / self.thresholds.max_jitter_ms;
            // Exponential penalty: 100 * e^(-ratio)
            100.0 * (-ratio).exp()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_health() {
        let scorer = HealthScorer::default();
        let score = scorer.calculate_score(10.0, 0.0, 1.0);

        assert_eq!(score.latency_score, 100.0);
        assert_eq!(score.loss_score, 100.0);
        assert_eq!(score.jitter_score, 100.0);
        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn test_high_latency() {
        let scorer = HealthScorer::default();
        // 200ms latency (2x threshold)
        let score = scorer.calculate_score(200.0, 0.0, 1.0);

        // Latency score should be penalized
        assert!(score.latency_score < 50.0);
        // Loss and jitter should be perfect
        assert_eq!(score.loss_score, 100.0);
        assert_eq!(score.jitter_score, 100.0);
        // Overall should be degraded due to latency weight (40%)
        assert!(score.score < 100.0);
        assert!(score.score > 50.0);
    }

    #[test]
    fn test_high_packet_loss() {
        let scorer = HealthScorer::default();
        // 10% packet loss (5x threshold)
        let score = scorer.calculate_score(10.0, 10.0, 1.0);

        // Loss score should be heavily penalized
        assert!(score.loss_score < 10.0);
        // Latency and jitter should be perfect
        assert_eq!(score.latency_score, 100.0);
        assert_eq!(score.jitter_score, 100.0);
        // Overall should be down due to loss weight (40%)
        assert!(score.score < 70.0);
    }

    #[test]
    fn test_high_jitter() {
        let scorer = HealthScorer::default();
        // 20ms jitter (2x threshold)
        let score = scorer.calculate_score(10.0, 0.0, 20.0);

        // Jitter score should be penalized
        assert!(score.jitter_score < 50.0);
        // Latency and loss should be perfect
        assert_eq!(score.latency_score, 100.0);
        assert_eq!(score.loss_score, 100.0);
        // Overall should be slightly degraded due to jitter weight (20%)
        assert!(score.score > 80.0);
        assert!(score.score < 100.0);
    }

    #[test]
    fn test_all_bad() {
        let scorer = HealthScorer::default();
        // All metrics above threshold
        let score = scorer.calculate_score(300.0, 20.0, 50.0);

        // All component scores should be low
        assert!(score.latency_score < 30.0);
        assert!(score.loss_score < 1.0);
        assert!(score.jitter_score < 10.0);
        // Overall score should be very low
        assert!(score.score < 20.0);
    }

    #[test]
    fn test_at_threshold() {
        let scorer = HealthScorer::default();
        // Exactly at thresholds
        let score = scorer.calculate_score(100.0, 2.0, 10.0);

        assert_eq!(score.latency_score, 100.0);
        assert_eq!(score.loss_score, 100.0);
        assert_eq!(score.jitter_score, 100.0);
        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn test_custom_thresholds() {
        let thresholds = HealthThresholds {
            max_latency_ms: 50.0,
            max_packet_loss_pct: 1.0,
            max_jitter_ms: 5.0,
            latency_weight: 0.5,
            loss_weight: 0.3,
            jitter_weight: 0.2,
        };

        let scorer = HealthScorer::new(thresholds);
        let score = scorer.calculate_score(50.0, 1.0, 5.0);

        assert_eq!(score.score, 100.0);
    }

    #[test]
    fn test_weighted_average() {
        let scorer = HealthScorer::default();

        // Perfect latency and jitter, but 5% packet loss
        let score = scorer.calculate_score(10.0, 5.0, 1.0);

        // Latency: 100.0 * 0.40 = 40.0
        // Loss: very low * 0.40 ≈ small
        // Jitter: 100.0 * 0.20 = 20.0
        // Total should be around 60-70
        assert!(score.score > 50.0);
        assert!(score.score < 70.0);
    }

    #[test]
    fn test_score_clamping() {
        let scorer = HealthScorer::default();

        // Extreme values
        let score = scorer.calculate_score(10000.0, 100.0, 1000.0);

        // Score should be clamped to 0.0
        assert!(score.score >= 0.0);
        assert!(score.score <= 100.0);
    }
}
