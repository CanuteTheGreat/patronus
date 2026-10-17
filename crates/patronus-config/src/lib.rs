//! Patronus Configuration Management
//!
//! Handles configuration storage, loading, and persistence.

use serde::{Deserialize, Serialize};

pub mod applier;
pub mod apply;
pub mod declarative;
pub mod defaults;
pub mod migrate;
pub mod store;

pub use applier::{Applier, ApplierOutcome, ApplierRegistry, ApplyReport, ApplyRunReport, Phase};
pub use apply::{
    ApplyEngine, ApplyResult, ChangeOp, ConfigChange, ConfigSnapshot, DiffResult, StateManager,
};
pub use declarative::{
    AddressSpec, ConfigParser, DeclarativeConfig, Direction, FirewallRuleSpec, Metadata,
    NatRuleSpec, ResourceKind, ResourceSpec, RuleAction,
};
pub use defaults::{ensure_defaults, Bootstrap};
pub use store::{ConfigStore, RuleOrigin};

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
