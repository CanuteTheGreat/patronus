//! Patronus Monitoring & Observability
//!
//! Enterprise-grade monitoring with Prometheus metrics, alerting,
//! and comprehensive system telemetry.

pub mod prometheus;
pub mod metrics;
pub mod alerts;
pub mod status;

pub use prometheus::PrometheusExporter;
pub use metrics::MetricsCollector;
pub use alerts::AlertManager;
pub use status::{
    StatusPageManager, DashboardConfig, DashboardWidget, WidgetType,
    InterfaceStatus, DhcpLease, ServiceStatus, IpsecTunnelStatus,
    OpenVpnClientStatus, WireGuardPeerStatus, GatewayHealth,
    TrafficDataPoint, LogEntry,
};
