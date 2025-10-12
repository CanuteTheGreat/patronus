//! Observability module for metrics, logging, and health checks

pub mod health;
pub mod metrics;

pub use health::{HealthCheck, HealthStatus, ComponentHealth};
pub use metrics::DashboardMetrics;
