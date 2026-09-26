//! Proxy and Load Balancing Services
//!
//! Provides HAProxy integration for load balancing and reverse proxy functionality.

pub mod haproxy;

pub use haproxy::{
    AccessControlList, AclCondition, Backend, BackendRule, BackendServer, BackendStats,
    BalanceAlgorithm, Frontend, HAProxyConfig, HAProxyManager, HAProxyStats, HealthCheck,
    HealthCheckMethod, ProxyMode, ServerStats, StatsConfig,
};
