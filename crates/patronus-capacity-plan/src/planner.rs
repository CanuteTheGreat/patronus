//! Capacity Planning and Recommendations

use crate::forecast::{TimeSeriesForecaster, ForecastModel, ForecastResult};
use crate::metrics::{CapacityMetrics, ResourceType, UtilizationHistory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrowthScenario {
    Conservative,  // 10% growth
    Moderate,      // 25% growth
    Aggressive,    // 50% growth
}

impl GrowthScenario {
    pub fn growth_factor(&self) -> f64 {
        match self {
            GrowthScenario::Conservative => 1.10,
            GrowthScenario::Moderate => 1.25,
            GrowthScenario::Aggressive => 1.50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityRecommendation {
    pub resource_type: ResourceType,
    pub current_capacity: f64,
    pub recommended_capacity: f64,
    pub increase_percent: f64,
    pub time_to_exhaustion_days: Option<f64>,
    pub urgency: UrgencyLevel,
    pub forecast: ForecastResult,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UrgencyLevel {
    Critical,  // < 7 days
    High,      // 7-30 days
    Medium,    // 30-90 days
    Low,       // > 90 days
}

pub struct CapacityPlanner {
    forecaster: TimeSeriesForecaster,
    history: HashMap<ResourceType, UtilizationHistory>,
    warning_threshold: f64,
    critical_threshold: f64,
}

impl CapacityPlanner {
    pub fn new(model: ForecastModel) -> Self {
        Self {
            forecaster: TimeSeriesForecaster::new(model),
            history: HashMap::new(),
            warning_threshold: 75.0,
            critical_threshold: 85.0,
        }
    }

    pub fn with_thresholds(mut self, warning: f64, critical: f64) -> Self {
        self.warning_threshold = warning;
        self.critical_threshold = critical;
        self
    }

    pub fn add_measurement(&mut self, metrics: CapacityMetrics) {
        let resource_type = metrics.resource_type.clone();

        self.history
            .entry(resource_type.clone())
            .or_insert_with(|| UtilizationHistory::new(resource_type, 1000))
            .add_measurement(metrics);
    }

    pub fn get_recommendations(&self, scenario: GrowthScenario, days_ahead: usize) -> Vec<CapacityRecommendation> {
        let mut recommendations = Vec::new();

        for (resource_type, history) in &self.history {
            if let Some(rec) = self.analyze_resource(resource_type, history, &scenario, days_ahead) {
                recommendations.push(rec);
            }
        }

        // Sort by urgency (Critical first)
        recommendations.sort_by(|a, b| {
            let urgency_order = |u: &UrgencyLevel| match u {
                UrgencyLevel::Critical => 0,
                UrgencyLevel::High => 1,
                UrgencyLevel::Medium => 2,
                UrgencyLevel::Low => 3,
            };
            urgency_order(&a.urgency).cmp(&urgency_order(&b.urgency))
        });

        recommendations
    }

    fn analyze_resource(
        &self,
        resource_type: &ResourceType,
        history: &UtilizationHistory,
        scenario: &GrowthScenario,
        days_ahead: usize,
    ) -> Option<CapacityRecommendation> {
        if history.len() < 3 {
            return None; // Need at least 3 data points
        }

        let values = history.get_values();
        let timestamps = history.get_timestamps();

        // Forecast future utilization
        let forecast = self.forecaster.forecast(&values, &timestamps, days_ahead);

        // Get current capacity
        let history_vec = history.get_history();
        let current_metrics = history_vec.last()?;
        let current_capacity = current_metrics.capacity;
        let current_utilization = current_metrics.utilization_percent;

        // Calculate time to exhaustion
        let time_to_exhaustion = self.calculate_time_to_exhaustion(&forecast, current_capacity);

        // Determine urgency
        let urgency = if current_utilization >= self.critical_threshold {
            UrgencyLevel::Critical
        } else if let Some(days) = time_to_exhaustion {
            if days < 7.0 {
                UrgencyLevel::Critical
            } else if days < 30.0 {
                UrgencyLevel::High
            } else if days < 90.0 {
                UrgencyLevel::Medium
            } else {
                UrgencyLevel::Low
            }
        } else {
            UrgencyLevel::Low
        };

        // Calculate recommended capacity
        let peak_forecast = forecast.predictions.iter()
            .copied()
            .fold(0.0, f64::max);

        let recommended_capacity = peak_forecast * scenario.growth_factor();
        let increase_percent = ((recommended_capacity - current_capacity) / current_capacity) * 100.0;

        // Generate reasoning
        let reasoning = self.generate_reasoning(
            current_utilization,
            history.growth_rate(),
            time_to_exhaustion,
            scenario,
        );

        Some(CapacityRecommendation {
            resource_type: resource_type.clone(),
            current_capacity,
            recommended_capacity,
            increase_percent,
            time_to_exhaustion_days: time_to_exhaustion,
            urgency,
            forecast,
            reasoning,
        })
    }

    fn calculate_time_to_exhaustion(&self, forecast: &ForecastResult, capacity: f64) -> Option<f64> {
        // Find when forecast exceeds capacity
        for (i, &prediction) in forecast.predictions.iter().enumerate() {
            if prediction >= capacity {
                // Interpolate the exact day
                if i > 0 {
                    let prev = forecast.predictions[i - 1];
                    let days_between = 1.0;
                    let excess = (capacity - prev) / (prediction - prev);
                    return Some((i - 1) as f64 + excess * days_between);
                } else {
                    return Some(0.0);
                }
            }
        }

        None // Capacity not exceeded in forecast period
    }

    fn generate_reasoning(
        &self,
        current_util: f64,
        growth_rate: f64,
        time_to_exhaustion: Option<f64>,
        scenario: &GrowthScenario,
    ) -> String {
        let mut reasons = Vec::new();

        if current_util >= self.critical_threshold {
            reasons.push(format!("Current utilization ({:.1}%) exceeds critical threshold ({:.1}%)",
                current_util, self.critical_threshold));
        } else if current_util >= self.warning_threshold {
            reasons.push(format!("Current utilization ({:.1}%) exceeds warning threshold ({:.1}%)",
                current_util, self.warning_threshold));
        }

        if growth_rate > 20.0 {
            reasons.push(format!("High growth rate ({:.1}%) indicates rapid capacity consumption", growth_rate));
        } else if growth_rate > 10.0 {
            reasons.push(format!("Moderate growth rate ({:.1}%) requires planning", growth_rate));
        }

        if let Some(days) = time_to_exhaustion {
            if days < 30.0 {
                reasons.push(format!("Capacity exhaustion predicted in {:.0} days", days));
            } else {
                reasons.push(format!("Capacity exhaustion predicted in {:.0} days", days));
            }
        }

        reasons.push(format!("Recommendation includes {:?} growth scenario buffer", scenario));

        reasons.join(". ")
    }

    pub fn get_resource_history(&self, resource_type: &ResourceType) -> Option<&UtilizationHistory> {
        self.history.get(resource_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_growth_scenario_factors() {
        assert_eq!(GrowthScenario::Conservative.growth_factor(), 1.10);
        assert_eq!(GrowthScenario::Moderate.growth_factor(), 1.25);
        assert_eq!(GrowthScenario::Aggressive.growth_factor(), 1.50);
    }

    #[test]
    fn test_capacity_planner_creation() {
        let planner = CapacityPlanner::new(ForecastModel::LinearRegression);
        assert_eq!(planner.warning_threshold, 75.0);
        assert_eq!(planner.critical_threshold, 85.0);
    }

    #[test]
    fn test_planner_with_thresholds() {
        let planner = CapacityPlanner::new(ForecastModel::LinearRegression)
            .with_thresholds(80.0, 90.0);

        assert_eq!(planner.warning_threshold, 80.0);
        assert_eq!(planner.critical_threshold, 90.0);
    }

    #[test]
    fn test_add_measurement() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression);

        let metrics = CapacityMetrics::new(ResourceType::Bandwidth, 500.0, 1000.0);
        planner.add_measurement(metrics);

        assert!(planner.get_resource_history(&ResourceType::Bandwidth).is_some());
    }

    #[test]
    fn test_recommendations_with_insufficient_data() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression);

        // Add only 2 measurements (need at least 3)
        let metrics1 = CapacityMetrics::new(ResourceType::Bandwidth, 500.0, 1000.0);
        let metrics2 = CapacityMetrics::new(ResourceType::Bandwidth, 600.0, 1000.0);

        planner.add_measurement(metrics1);
        planner.add_measurement(metrics2);

        let recommendations = planner.get_recommendations(GrowthScenario::Moderate, 30);
        assert_eq!(recommendations.len(), 0);
    }

    #[test]
    fn test_recommendations_with_sufficient_data() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression);

        // Add upward trending data
        for i in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::Bandwidth,
                i as f64 * 150.0,
                1000.0
            );
            planner.add_measurement(metrics);
        }

        let recommendations = planner.get_recommendations(GrowthScenario::Moderate, 30);
        assert_eq!(recommendations.len(), 1);

        let rec = &recommendations[0];
        assert_eq!(rec.resource_type, ResourceType::Bandwidth);
        assert!(rec.recommended_capacity > rec.current_capacity);
    }

    #[test]
    fn test_critical_urgency() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression)
            .with_thresholds(75.0, 85.0);

        // Add data at critical utilization
        for i in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::Bandwidth,
                850.0 + i as f64 * 10.0,
                1000.0
            );
            planner.add_measurement(metrics);
        }

        let recommendations = planner.get_recommendations(GrowthScenario::Conservative, 30);
        assert_eq!(recommendations[0].urgency, UrgencyLevel::Critical);
    }

    #[test]
    fn test_multiple_resource_types() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression);

        // Add bandwidth measurements
        for i in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::Bandwidth,
                i as f64 * 150.0,
                1000.0
            );
            planner.add_measurement(metrics);
        }

        // Add CPU measurements
        for i in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::CpuUsage,
                i as f64 * 15.0,
                100.0
            );
            planner.add_measurement(metrics);
        }

        let recommendations = planner.get_recommendations(GrowthScenario::Moderate, 30);
        assert_eq!(recommendations.len(), 2);
    }

    #[test]
    fn test_recommendation_sorting_by_urgency() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression)
            .with_thresholds(75.0, 85.0);

        // Add critical bandwidth data
        for _ in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::Bandwidth,
                900.0,
                1000.0
            );
            planner.add_measurement(metrics);
        }

        // Add low CPU data
        for _ in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::CpuUsage,
                30.0,
                100.0
            );
            planner.add_measurement(metrics);
        }

        let recommendations = planner.get_recommendations(GrowthScenario::Moderate, 90);

        // Critical should come first
        assert_eq!(recommendations[0].urgency, UrgencyLevel::Critical);
        assert_eq!(recommendations[0].resource_type, ResourceType::Bandwidth);
    }

    #[test]
    fn test_increase_percent_calculation() {
        let mut planner = CapacityPlanner::new(ForecastModel::LinearRegression);

        for i in 1..=5 {
            let metrics = CapacityMetrics::new(
                ResourceType::Bandwidth,
                i as f64 * 100.0,
                1000.0
            );
            planner.add_measurement(metrics);
        }

        let recommendations = planner.get_recommendations(GrowthScenario::Moderate, 30);
        let rec = &recommendations[0];

        // Should have positive increase
        assert!(rec.increase_percent > 0.0);
    }
}
