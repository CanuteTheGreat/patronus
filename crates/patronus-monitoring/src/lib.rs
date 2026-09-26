//! Patronus Monitoring & Observability
//!
//! Enterprise-grade monitoring with Prometheus metrics, alerting,
//! and comprehensive system telemetry.

pub mod alerts;
pub mod metrics;
pub mod prometheus;
pub mod status;

pub use alerts::AlertManager;
pub use metrics::MetricsCollector;
pub use prometheus::PrometheusExporter;
pub use status::{
    DashboardConfig, DashboardWidget, DhcpLease, GatewayHealth, InterfaceStatus, IpsecTunnelStatus,
    LogEntry, OpenVpnClientStatus, ServiceStatus, StatusPageManager, TrafficDataPoint, WidgetType,
    WireGuardPeerStatus,
};
