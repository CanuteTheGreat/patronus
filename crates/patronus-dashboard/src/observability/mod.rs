//! Observability module for metrics, logging, and health checks

pub mod health;
pub mod metrics;
// TODO: Re-enable after resolving axum version conflicts
// pub mod tracing;

pub use metrics::DashboardMetrics;
