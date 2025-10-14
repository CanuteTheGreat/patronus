//! Traffic Demand Matrix and Prediction

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDemand {
    pub source: String,
    pub destination: String,
    pub bandwidth_mbps: f64,
    pub timestamp: DateTime<Utc>,
    pub priority: u8, // 0-7, higher is more important
}

impl TrafficDemand {
    pub fn new(source: String, destination: String, bandwidth_mbps: f64, priority: u8) -> Self {
        Self {
            source,
            destination,
            bandwidth_mbps,
            timestamp: Utc::now(),
            priority: priority.min(7),
        }
    }

    pub fn is_high_priority(&self) -> bool {
        self.priority >= 5
    }
}

/// Demand Matrix: Traffic demands between all source-destination pairs
pub struct DemandMatrix {
    demands: HashMap<(String, String), Vec<TrafficDemand>>,
    max_history: usize,
}

impl DemandMatrix {
    pub fn new(max_history: usize) -> Self {
        Self {
            demands: HashMap::new(),
            max_history,
        }
    }

    pub fn add_demand(&mut self, demand: TrafficDemand) {
        let key = (demand.source.clone(), demand.destination.clone());
        let history = self.demands.entry(key).or_insert_with(Vec::new);

        history.push(demand);

        // Keep only recent history
        if history.len() > self.max_history {
            history.remove(0);
        }
    }

    pub fn get_current_demand(&self, source: &str, destination: &str) -> Option<&TrafficDemand> {
        let key = (source.to_string(), destination.to_string());
        self.demands.get(&key).and_then(|v| v.last())
    }

    pub fn get_average_demand(&self, source: &str, destination: &str) -> Option<f64> {
        let key = (source.to_string(), destination.to_string());
        self.demands.get(&key).map(|demands| {
            if demands.is_empty() {
                return 0.0;
            }
            let sum: f64 = demands.iter().map(|d| d.bandwidth_mbps).sum();
            sum / demands.len() as f64
        })
    }

    pub fn get_peak_demand(&self, source: &str, destination: &str) -> Option<f64> {
        let key = (source.to_string(), destination.to_string());
        self.demands.get(&key).map(|demands| {
            demands.iter()
                .map(|d| d.bandwidth_mbps)
                .fold(0.0, f64::max)
        })
    }

    pub fn get_all_pairs(&self) -> Vec<(String, String)> {
        self.demands.keys().cloned().collect()
    }

    pub fn total_demand(&self) -> f64 {
        self.demands.values()
            .filter_map(|demands| demands.last())
            .map(|d| d.bandwidth_mbps)
            .sum()
    }

    pub fn high_priority_demand(&self) -> f64 {
        self.demands.values()
            .filter_map(|demands| demands.last())
            .filter(|d| d.is_high_priority())
            .map(|d| d.bandwidth_mbps)
            .sum()
    }
}

/// Predict future traffic demands using simple time-series models
pub struct DemandPredictor {
    matrix: DemandMatrix,
}

impl DemandPredictor {
    pub fn new(max_history: usize) -> Self {
        Self {
            matrix: DemandMatrix::new(max_history),
        }
    }

    pub fn add_observation(&mut self, demand: TrafficDemand) {
        self.matrix.add_demand(demand);
    }

    pub fn get_matrix(&self) -> &DemandMatrix {
        &self.matrix
    }

    /// Predict future demand using exponential moving average
    pub fn predict_demand(&self, source: &str, destination: &str, alpha: f64) -> Option<f64> {
        let key = (source.to_string(), destination.to_string());
        let demands = self.matrix.demands.get(&key)?;

        if demands.is_empty() {
            return None;
        }

        if demands.len() == 1 {
            return Some(demands[0].bandwidth_mbps);
        }

        // Exponential moving average
        let mut ema = demands[0].bandwidth_mbps;
        for demand in demands.iter().skip(1) {
            ema = alpha * demand.bandwidth_mbps + (1.0 - alpha) * ema;
        }

        Some(ema)
    }

    /// Predict growth rate (percentage per observation)
    pub fn predict_growth_rate(&self, source: &str, destination: &str) -> Option<f64> {
        let key = (source.to_string(), destination.to_string());
        let demands = self.matrix.demands.get(&key)?;

        if demands.len() < 2 {
            return None;
        }

        let first = demands.first()?.bandwidth_mbps;
        let last = demands.last()?.bandwidth_mbps;

        if first == 0.0 {
            return None;
        }

        Some(((last - first) / first) * 100.0)
    }

    /// Check if demand is increasing
    pub fn is_demand_increasing(&self, source: &str, destination: &str) -> bool {
        self.predict_growth_rate(source, destination)
            .map(|rate| rate > 5.0)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_demand_creation() {
        let demand = TrafficDemand::new(
            "site-a".to_string(),
            "site-b".to_string(),
            100.0,
            3
        );

        assert_eq!(demand.source, "site-a");
        assert_eq!(demand.destination, "site-b");
        assert_eq!(demand.bandwidth_mbps, 100.0);
        assert_eq!(demand.priority, 3);
        assert!(!demand.is_high_priority());
    }

    #[test]
    fn test_high_priority() {
        let high = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 6);
        let low = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 2);

        assert!(high.is_high_priority());
        assert!(!low.is_high_priority());
    }

    #[test]
    fn test_priority_clamping() {
        let demand = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 10);
        assert_eq!(demand.priority, 7);
    }

    #[test]
    fn test_demand_matrix_add() {
        let mut matrix = DemandMatrix::new(100);
        let demand = TrafficDemand::new("site-a".to_string(), "site-b".to_string(), 100.0, 3);

        matrix.add_demand(demand);

        let current = matrix.get_current_demand("site-a", "site-b");
        assert!(current.is_some());
        assert_eq!(current.unwrap().bandwidth_mbps, 100.0);
    }

    #[test]
    fn test_demand_matrix_history_limit() {
        let mut matrix = DemandMatrix::new(3);

        for i in 1..=5 {
            let demand = TrafficDemand::new(
                "a".to_string(),
                "b".to_string(),
                i as f64 * 10.0,
                1
            );
            matrix.add_demand(demand);
        }

        let key = ("a".to_string(), "b".to_string());
        let history = matrix.demands.get(&key).unwrap();

        // Should only keep last 3
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].bandwidth_mbps, 30.0);
        assert_eq!(history[2].bandwidth_mbps, 50.0);
    }

    #[test]
    fn test_average_demand() {
        let mut matrix = DemandMatrix::new(100);

        for bandwidth in [100.0, 200.0, 300.0] {
            let demand = TrafficDemand::new("a".to_string(), "b".to_string(), bandwidth, 1);
            matrix.add_demand(demand);
        }

        let avg = matrix.get_average_demand("a", "b");
        assert_eq!(avg, Some(200.0));
    }

    #[test]
    fn test_peak_demand() {
        let mut matrix = DemandMatrix::new(100);

        for bandwidth in [100.0, 500.0, 200.0] {
            let demand = TrafficDemand::new("a".to_string(), "b".to_string(), bandwidth, 1);
            matrix.add_demand(demand);
        }

        let peak = matrix.get_peak_demand("a", "b");
        assert_eq!(peak, Some(500.0));
    }

    #[test]
    fn test_total_demand() {
        let mut matrix = DemandMatrix::new(100);

        let d1 = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 1);
        let d2 = TrafficDemand::new("b".to_string(), "c".to_string(), 200.0, 1);
        let d3 = TrafficDemand::new("c".to_string(), "a".to_string(), 50.0, 1);

        matrix.add_demand(d1);
        matrix.add_demand(d2);
        matrix.add_demand(d3);

        assert_eq!(matrix.total_demand(), 350.0);
    }

    #[test]
    fn test_high_priority_demand() {
        let mut matrix = DemandMatrix::new(100);

        let high1 = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 6);
        let low = TrafficDemand::new("b".to_string(), "c".to_string(), 200.0, 2);
        let high2 = TrafficDemand::new("c".to_string(), "a".to_string(), 50.0, 7);

        matrix.add_demand(high1);
        matrix.add_demand(low);
        matrix.add_demand(high2);

        assert_eq!(matrix.high_priority_demand(), 150.0);
    }

    #[test]
    fn test_demand_predictor() {
        let mut predictor = DemandPredictor::new(100);

        for bandwidth in [100.0, 110.0, 120.0, 130.0] {
            let demand = TrafficDemand::new("a".to_string(), "b".to_string(), bandwidth, 1);
            predictor.add_observation(demand);
        }

        let predicted = predictor.predict_demand("a", "b", 0.3);
        assert!(predicted.is_some());
        assert!(predicted.unwrap() > 100.0);
    }

    #[test]
    fn test_growth_rate() {
        let mut predictor = DemandPredictor::new(100);

        let d1 = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 1);
        let d2 = TrafficDemand::new("a".to_string(), "b".to_string(), 150.0, 1);

        predictor.add_observation(d1);
        predictor.add_observation(d2);

        let rate = predictor.predict_growth_rate("a", "b");
        assert_eq!(rate, Some(50.0)); // 50% growth
    }

    #[test]
    fn test_is_demand_increasing() {
        let mut predictor = DemandPredictor::new(100);

        let d1 = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 1);
        let d2 = TrafficDemand::new("a".to_string(), "b".to_string(), 120.0, 1);

        predictor.add_observation(d1);
        predictor.add_observation(d2);

        assert!(predictor.is_demand_increasing("a", "b"));
    }

    #[test]
    fn test_get_all_pairs() {
        let mut matrix = DemandMatrix::new(100);

        let d1 = TrafficDemand::new("a".to_string(), "b".to_string(), 100.0, 1);
        let d2 = TrafficDemand::new("b".to_string(), "c".to_string(), 200.0, 1);

        matrix.add_demand(d1);
        matrix.add_demand(d2);

        let pairs = matrix.get_all_pairs();
        assert_eq!(pairs.len(), 2);
    }
}
