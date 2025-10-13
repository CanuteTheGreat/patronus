//! Prometheus metrics for the operator

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};
use std::sync::OnceLock;

/// Metrics registry
pub struct Metrics {
    /// Total reconciliations counter
    pub reconcile_total: IntCounterVec,

    /// Reconciliation errors counter
    pub reconcile_errors: IntCounterVec,

    /// Reconciliation duration histogram
    pub reconcile_duration: HistogramVec,

    /// Active resources gauge
    pub active_resources: IntGaugeVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

impl Metrics {
    /// Initialize metrics
    pub fn new() -> Self {
        Self {
            reconcile_total: register_int_counter_vec!(
                "patronus_operator_reconcile_total",
                "Total number of reconciliations",
                &["controller", "result"]
            )
            .unwrap(),

            reconcile_errors: register_int_counter_vec!(
                "patronus_operator_reconcile_errors_total",
                "Total number of reconciliation errors",
                &["controller", "error_type"]
            )
            .unwrap(),

            reconcile_duration: register_histogram_vec!(
                "patronus_operator_reconcile_duration_seconds",
                "Duration of reconciliation operations",
                &["controller"],
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )
            .unwrap(),

            active_resources: register_int_gauge_vec!(
                "patronus_operator_active_resources",
                "Number of active resources",
                &["kind", "phase"]
            )
            .unwrap(),
        }
    }

    /// Get global metrics instance
    pub fn global() -> &'static Metrics {
        METRICS.get_or_init(Metrics::new)
    }

    /// Record successful reconciliation
    pub fn record_reconcile_success(&self, controller: &str, duration_secs: f64) {
        self.reconcile_total
            .with_label_values(&[controller, "success"])
            .inc();
        self.reconcile_duration
            .with_label_values(&[controller])
            .observe(duration_secs);
    }

    /// Record failed reconciliation
    pub fn record_reconcile_error(&self, controller: &str, error_type: &str, duration_secs: f64) {
        self.reconcile_total
            .with_label_values(&[controller, "error"])
            .inc();
        self.reconcile_errors
            .with_label_values(&[controller, error_type])
            .inc();
        self.reconcile_duration
            .with_label_values(&[controller])
            .observe(duration_secs);
    }

    /// Update resource count
    pub fn set_resource_count(&self, kind: &str, phase: &str, count: i64) {
        self.active_resources
            .with_label_values(&[kind, phase])
            .set(count);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
