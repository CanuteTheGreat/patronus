//! Observability Stack
//!
//! Prometheus metrics, Jaeger tracing, and monitoring

pub mod metrics;
pub mod tracing;
pub mod dashboards;

pub use metrics::{MetricsCollector, MetricType};
pub use self::tracing::{TracingConfig, DistributedTracer};
pub use dashboards::GrafanaDashboard;
