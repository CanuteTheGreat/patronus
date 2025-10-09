//! Patronus Configuration Management
//!
//! Handles configuration storage, loading, and persistence.

use patronus_core::Result;
use serde::{Deserialize, Serialize};

pub mod store;
pub mod declarative;
pub mod apply;

pub use store::ConfigStore;
pub use declarative::{
    DeclarativeConfig, ResourceKind, ResourceSpec, Metadata, ConfigParser,
    FirewallRuleSpec, NatRuleSpec, AddressSpec, RuleAction, Direction,
};
pub use apply::{
    ApplyEngine, StateManager, ConfigChange, ChangeOp, DiffResult,
    ApplyResult, ConfigSnapshot,
};

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
