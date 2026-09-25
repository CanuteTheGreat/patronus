//! Patronus Configuration Management
//!
//! Handles configuration storage, loading, and persistence.

use patronus_core::Result;
use serde::{Deserialize, Serialize};

pub mod apply;
pub mod declarative;
pub mod store;

pub use apply::{
    ApplyEngine, ApplyResult, ChangeOp, ConfigChange, ConfigSnapshot, DiffResult, StateManager,
};
pub use declarative::{
    AddressSpec, ConfigParser, DeclarativeConfig, Direction, FirewallRuleSpec, Metadata,
    NatRuleSpec, ResourceKind, ResourceSpec, RuleAction,
};
pub use store::ConfigStore;

/// Main system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
    pub dns_servers: Vec<String>,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "patronus".to_string(),
            domain: "local".to_string(),
            timezone: "UTC".to_string(),
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        }
    }
}
