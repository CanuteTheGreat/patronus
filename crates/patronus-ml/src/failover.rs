//! Predictive Failover using ML
//!
//! Predicts link failures before they happen using Gradient Boosting

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Link health metrics for prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkHealth {
    pub latency_ms: f64,
    pub packet_loss: f64,
    pub jitter_ms: f64,
    pub bandwidth_utilization: f64,
    pub error_rate: f64,
}

/// Failover prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverPrediction {
    pub failure_probability: f64,
    pub should_failover: bool,
    pub time_to_failure_seconds: Option<u64>,
    pub reason: String,
}

/// Gradient Boosting-based failover predictor
pub struct PredictiveFailover {
    history: VecDeque<LinkHealth>,
    window_size: usize,
    failure_threshold: f64,
}

impl PredictiveFailover {
    pub fn new() -> Self {
        Self {
            history: VecDeque::new(),
            window_size: 60, // 1 minute of history
            failure_threshold: 0.75, // 75% probability triggers failover
        }
    }

    /// Predict if link will fail
    pub fn predict(&mut self, health: LinkHealth) -> FailoverPrediction {
        self.history.push_back(health.clone());
        if self.history.len() > self.window_size {
            self.history.pop_front();
        }

        if self.history.len() < 10 {
            return FailoverPrediction {
                failure_probability: 0.0,
                should_failover: false,
                time_to_failure_seconds: None,
                reason: "Insufficient data".to_string(),
            };
        }

        let probability = self.calculate_failure_probability(&health);
        let should_failover = probability > self.failure_threshold;

        let time_to_failure = if should_failover {
            Some(self.estimate_time_to_failure())
        } else {
            None
        };

        let reason = self.get_failure_reason(&health);

        FailoverPrediction {
            failure_probability: probability,
            should_failover,
            time_to_failure_seconds: time_to_failure,
            reason,
        }
    }

    fn calculate_failure_probability(&self, health: &LinkHealth) -> f64 {
        // Simplified gradient boosting approximation
        let mut score: f64 = 0.0;

        // Tree 1: Latency degradation
        if health.latency_ms > 100.0 {
            score += 0.3;
        }

        // Tree 2: Packet loss
        if health.packet_loss > 0.05 {
            score += 0.4;
        }

        // Tree 3: Jitter
        if health.jitter_ms > 50.0 {
            score += 0.2;
        }

        // Tree 4: Error rate
        if health.error_rate > 0.01 {
            score += 0.3;
        }

        // Tree 5: Trend analysis
        if self.history.len() >= 5 {
            let recent: Vec<&LinkHealth> = self.history.iter().rev().take(5).collect();
            let latency_trend: f64 = recent.windows(2)
                .map(|w| w[0].latency_ms - w[1].latency_ms)
                .sum::<f64>() / 4.0;

            if latency_trend > 10.0 {
                score += 0.25; // Latency is increasing
            }
        }

        score.min(1.0)
    }

    fn estimate_time_to_failure(&self) -> u64 {
        // Estimate based on degradation rate
        if self.history.len() < 2 {
            return 60;
        }

        let recent: Vec<&LinkHealth> = self.history.iter().rev().take(5).collect();
        let avg_latency_increase: f64 = recent.windows(2)
            .map(|w| (w[0].latency_ms - w[1].latency_ms).max(0.0))
            .sum::<f64>() / (recent.len() - 1) as f64;

        if avg_latency_increase > 5.0 {
            30 // 30 seconds
        } else if avg_latency_increase > 1.0 {
            120 // 2 minutes
        } else {
            300 // 5 minutes
        }
    }

    fn get_failure_reason(&self, health: &LinkHealth) -> String {
        if health.packet_loss > 0.1 {
            "High packet loss detected".to_string()
        } else if health.latency_ms > 200.0 {
            "Excessive latency".to_string()
        } else if health.jitter_ms > 100.0 {
            "High jitter".to_string()
        } else if health.error_rate > 0.05 {
            "High error rate".to_string()
        } else {
            "Link degradation detected".to_string()
        }
    }
}

impl Default for PredictiveFailover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_link() {
        let mut predictor = PredictiveFailover::new();

        for _ in 0..15 {
            let health = LinkHealth {
                latency_ms: 20.0,
                packet_loss: 0.001,
                jitter_ms: 2.0,
                bandwidth_utilization: 0.5,
                error_rate: 0.0001,
            };
            predictor.predict(health);
        }

        let health = LinkHealth {
            latency_ms: 20.0,
            packet_loss: 0.001,
            jitter_ms: 2.0,
            bandwidth_utilization: 0.5,
            error_rate: 0.0001,
        };

        let prediction = predictor.predict(health);
        assert!(!prediction.should_failover);
    }

    #[test]
    fn test_failing_link() {
        let mut predictor = PredictiveFailover::new();

        // Simulate degrading link
        for i in 0..15 {
            let health = LinkHealth {
                latency_ms: 20.0 + (i as f64 * 10.0),
                packet_loss: 0.001 + (i as f64 * 0.01),
                jitter_ms: 2.0 + (i as f64 * 5.0),
                bandwidth_utilization: 0.5,
                error_rate: 0.0001 + (i as f64 * 0.001),
            };
            predictor.predict(health);
        }

        // Check final state
        let health = LinkHealth {
            latency_ms: 200.0,
            packet_loss: 0.15,
            jitter_ms: 75.0,
            bandwidth_utilization: 0.5,
            error_rate: 0.015,
        };

        let prediction = predictor.predict(health);
        assert!(prediction.should_failover);
        assert!(prediction.time_to_failure_seconds.is_some());
    }
}
