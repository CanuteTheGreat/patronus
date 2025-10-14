//! Capacity Metrics and History

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Bandwidth,
    CpuUsage,
    MemoryUsage,
    Storage,
    Connections,
    Tunnels,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityMetrics {
    pub timestamp: DateTime<Utc>,
    pub resource_type: ResourceType,
    pub current_value: f64,
    pub capacity: f64,
    pub utilization_percent: f64,
}

impl CapacityMetrics {
    pub fn new(resource_type: ResourceType, current_value: f64, capacity: f64) -> Self {
        let utilization_percent = if capacity > 0.0 {
            (current_value / capacity) * 100.0
        } else {
            0.0
        };

        Self {
            timestamp: Utc::now(),
            resource_type,
            current_value,
            capacity,
            utilization_percent,
        }
    }

    pub fn is_critical(&self, threshold: f64) -> bool {
        self.utilization_percent >= threshold
    }

    pub fn is_warning(&self, threshold: f64) -> bool {
        self.utilization_percent >= threshold && self.utilization_percent < threshold + 20.0
    }

    pub fn available_capacity(&self) -> f64 {
        (self.capacity - self.current_value).max(0.0)
    }
}

pub struct UtilizationHistory {
    resource_type: ResourceType,
    max_history: usize,
    history: VecDeque<CapacityMetrics>,
}

impl UtilizationHistory {
    pub fn new(resource_type: ResourceType, max_history: usize) -> Self {
        Self {
            resource_type,
            max_history,
            history: VecDeque::with_capacity(max_history),
        }
    }

    pub fn add_measurement(&mut self, metrics: CapacityMetrics) {
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(metrics);
    }

    pub fn get_history(&self) -> Vec<CapacityMetrics> {
        self.history.iter().cloned().collect()
    }

    pub fn get_values(&self) -> Vec<f64> {
        self.history.iter().map(|m| m.current_value).collect()
    }

    pub fn get_timestamps(&self) -> Vec<DateTime<Utc>> {
        self.history.iter().map(|m| m.timestamp).collect()
    }

    pub fn get_utilization_values(&self) -> Vec<f64> {
        self.history.iter().map(|m| m.utilization_percent).collect()
    }

    pub fn average_utilization(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }

        let sum: f64 = self.history.iter().map(|m| m.utilization_percent).sum();
        sum / self.history.len() as f64
    }

    pub fn peak_utilization(&self) -> f64 {
        self.history.iter()
            .map(|m| m.utilization_percent)
            .fold(0.0, f64::max)
    }

    pub fn min_utilization(&self) -> f64 {
        self.history.iter()
            .map(|m| m.utilization_percent)
            .fold(100.0, f64::min)
    }

    pub fn current_utilization(&self) -> Option<f64> {
        self.history.back().map(|m| m.utilization_percent)
    }

    pub fn growth_rate(&self) -> f64 {
        if self.history.len() < 2 {
            return 0.0;
        }

        let first = self.history.front().unwrap().current_value;
        let last = self.history.back().unwrap().current_value;

        if first == 0.0 {
            return 0.0;
        }

        ((last - first) / first) * 100.0
    }

    pub fn is_trending_up(&self) -> bool {
        self.growth_rate() > 5.0 // More than 5% growth
    }

    pub fn len(&self) -> usize {
        self.history.len()
    }

    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_metrics_creation() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 800.0, 1000.0);

        assert_eq!(metrics.resource_type, ResourceType::Bandwidth);
        assert_eq!(metrics.current_value, 800.0);
        assert_eq!(metrics.capacity, 1000.0);
        assert_eq!(metrics.utilization_percent, 80.0);
    }

    #[test]
    fn test_capacity_metrics_zero_capacity() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 100.0, 0.0);
        assert_eq!(metrics.utilization_percent, 0.0);
    }

    #[test]
    fn test_is_critical() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 950.0, 1000.0);
        assert!(metrics.is_critical(90.0));
        assert!(!metrics.is_critical(99.0));
    }

    #[test]
    fn test_is_warning() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 850.0, 1000.0);
        assert!(metrics.is_warning(80.0));
        assert!(!metrics.is_warning(90.0));
    }

    #[test]
    fn test_available_capacity() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 750.0, 1000.0);
        assert_eq!(metrics.available_capacity(), 250.0);
    }

    #[test]
    fn test_available_capacity_oversubscribed() {
        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 1200.0, 1000.0);
        assert_eq!(metrics.available_capacity(), 0.0);
    }

    #[test]
    fn test_utilization_history() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        assert_eq!(history.len(), 0);
        assert!(history.is_empty());

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 500.0, 1000.0);
        history.add_measurement(metrics1);

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
    }

    #[test]
    fn test_history_max_size() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 3);

        for i in 1..=5 {
            let metrics = CapacityMetrics::new(ResourceType::Bandwidth, i as f64 * 100.0, 1000.0);
            history.add_measurement(metrics);
        }

        // Should only keep last 3
        assert_eq!(history.len(), 3);

        let values = history.get_values();
        assert_eq!(values, vec![300.0, 400.0, 500.0]);
    }

    #[test]
    fn test_average_utilization() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0); // 60%
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 800.0, 1000.0); // 80%
        let metrics3 = CapacityMetrics::new(ResourceType::Bandwidth, 700.0, 1000.0); // 70%

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);
        history.add_measurement(metrics3);

        // Average should be (60+80+70)/3 = 70
        assert_eq!(history.average_utilization(), 70.0);
    }

    #[test]
    fn test_peak_utilization() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0); // 60%
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 950.0, 1000.0); // 95%
        let metrics3 = CapacityMetrics::new(ResourceType::Bandwidth, 700.0, 1000.0); // 70%

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);
        history.add_measurement(metrics3);

        assert_eq!(history.peak_utilization(), 95.0);
    }

    #[test]
    fn test_min_utilization() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0); // 60%
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 950.0, 1000.0); // 95%
        let metrics3 = CapacityMetrics::new(ResourceType::Bandwidth, 300.0, 1000.0); // 30%

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);
        history.add_measurement(metrics3);

        assert_eq!(history.min_utilization(), 30.0);
    }

    #[test]
    fn test_current_utilization() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        assert_eq!(history.current_utilization(), None);

        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 850.0, 1000.0); // 85%
        history.add_measurement(metrics);

        assert_eq!(history.current_utilization(), Some(85.0));
    }

    #[test]
    fn test_growth_rate() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        // Start at 500, grow to 750
        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 500.0, 1000.0);
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 750.0, 1000.0);

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);

        // Growth: (750-500)/500 * 100 = 50%
        assert_eq!(history.growth_rate(), 50.0);
    }

    #[test]
    fn test_is_trending_up() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 500.0, 1000.0);
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0);

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);

        // 20% growth should be trending up
        assert!(history.is_trending_up());
    }

    #[test]
    fn test_get_utilization_values() {
        let mut history = UtilizationHistory::new(ResourceType::Bandwidth, 10);

        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0); // 60%
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 800.0, 1000.0); // 80%

        history.add_measurement(metrics1);
        history.add_measurement(metrics2);

        let values = history.get_utilization_values();
        assert_eq!(values, vec![60.0, 80.0]);
    }
}
