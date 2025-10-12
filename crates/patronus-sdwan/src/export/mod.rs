//! Export module for traffic statistics and metrics
//!
//! Provides multiple export formats:
//! - Prometheus metrics for time-series monitoring
//! - JSON for REST API consumption
//! - Historical data aggregation

pub mod prometheus;
pub mod json;
mod aggregator;

pub use prometheus::PrometheusExporter;
pub use json::JsonExporter;
pub use aggregator::{MetricsAggregator, AggregationPeriod, AggregatedMetrics};

use crate::database::Database;
use crate::health::HealthMonitor;
use crate::failover::FailoverEngine;
use std::sync::Arc;

/// Export manager coordinating all export formats
pub struct ExportManager {
    prometheus: Arc<PrometheusExporter>,
    json: Arc<JsonExporter>,
    aggregator: Arc<MetricsAggregator>,
}

impl ExportManager {
    /// Create a new export manager
    pub fn new(
        db: Arc<Database>,
        health_monitor: Arc<HealthMonitor>,
        failover_engine: Arc<FailoverEngine>,
    ) -> Self {
        let prometheus = Arc::new(PrometheusExporter::new(
            health_monitor.clone(),
            failover_engine.clone(),
        ));

        let json = Arc::new(JsonExporter::new(
            db.clone(),
            health_monitor.clone(),
            failover_engine.clone(),
        ));

        let aggregator = Arc::new(MetricsAggregator::new(db));

        Self {
            prometheus,
            json,
            aggregator,
        }
    }

    /// Get Prometheus exporter
    pub fn prometheus(&self) -> &Arc<PrometheusExporter> {
        &self.prometheus
    }

    /// Get JSON exporter
    pub fn json(&self) -> &Arc<JsonExporter> {
        &self.json
    }

    /// Get metrics aggregator
    pub fn aggregator(&self) -> &Arc<MetricsAggregator> {
        &self.aggregator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthConfig;

    #[tokio::test]
    async fn test_export_manager_creation() {
        let db = Arc::new(Database::new_in_memory().await.unwrap());
        let health_config = HealthConfig::default();
        let health_monitor = Arc::new(HealthMonitor::new(db.clone(), health_config).await.unwrap());
        let failover_engine = Arc::new(FailoverEngine::new(db.clone(), health_monitor.clone()));

        let manager = ExportManager::new(db, health_monitor, failover_engine);

        // Verify all components are initialized
        assert!(Arc::strong_count(manager.prometheus()) >= 1);
        assert!(Arc::strong_count(manager.json()) >= 1);
        assert!(Arc::strong_count(manager.aggregator()) >= 1);
    }
}
