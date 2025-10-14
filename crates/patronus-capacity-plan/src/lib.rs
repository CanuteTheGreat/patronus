//! Predictive Capacity Planning
//!
//! Time-series forecasting and capacity planning for SD-WAN

pub mod forecast;
pub mod metrics;
pub mod planner;

pub use forecast::{TimeSeriesForecaster, ForecastModel, ForecastResult};
pub use metrics::{CapacityMetrics, ResourceType, UtilizationHistory};
pub use planner::{CapacityPlanner, CapacityRecommendation, GrowthScenario};
