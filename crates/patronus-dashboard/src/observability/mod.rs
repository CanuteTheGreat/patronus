//! Observability module for metrics, logging, and health checks

pub mod health;
pub mod metrics;
pub mod tracing;

pub use metrics::DashboardMetrics;
