//! Proxy and Load Balancing Services
//!
//! Provides HAProxy integration for load balancing and reverse proxy functionality.

pub mod haproxy;

pub use haproxy::{
    HAProxyManager, HAProxyConfig, Frontend, Backend, BackendServer,
    ProxyMode, BalanceAlgorithm, HealthCheck, HealthCheckMethod,
    AccessControlList, AclCondition, BackendRule, StatsConfig,
    HAProxyStats, BackendStats, ServerStats,
};
