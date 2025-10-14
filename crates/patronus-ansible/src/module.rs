//! Ansible Module Interface

use crate::{ModuleResult, ModuleState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleArgs {
    pub name: String,
    pub state: ModuleState,
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

pub trait AnsibleModule {
    fn run(&self, args: ModuleArgs) -> ModuleResult;
    fn module_name(&self) -> &str;
}

#[derive(Debug, Clone)]
pub struct SiteModule;

impl AnsibleModule for SiteModule {
    fn run(&self, args: ModuleArgs) -> ModuleResult {
        match args.state {
            ModuleState::Present => {
                ModuleResult::success(true, format!("Site {} created", args.name))
                    .with_meta("site_id".to_string(), serde_json::json!("site-123"))
            }
            ModuleState::Absent => {
                ModuleResult::success(true, format!("Site {} removed", args.name))
            }
            _ => ModuleResult::failure("Invalid state for site module".to_string()),
        }
    }

    fn module_name(&self) -> &str {
        "patronus_site"
    }
}

#[derive(Debug, Clone)]
pub struct TunnelModule;

impl AnsibleModule for TunnelModule {
    fn run(&self, args: ModuleArgs) -> ModuleResult {
        match args.state {
            ModuleState::Started => {
                ModuleResult::success(true, format!("Tunnel {} started", args.name))
                    .with_meta("tunnel_id".to_string(), serde_json::json!("tunnel-456"))
            }
            ModuleState::Stopped => {
                ModuleResult::success(true, format!("Tunnel {} stopped", args.name))
            }
            _ => ModuleResult::failure("Invalid state for tunnel module".to_string()),
        }
    }

    fn module_name(&self) -> &str {
        "patronus_tunnel"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_module_present() {
        let module = SiteModule;
        let args = ModuleArgs {
            name: "site1".to_string(),
            state: ModuleState::Present,
            params: HashMap::new(),
        };

        let result = module.run(args);
        assert!(result.changed);
        assert!(!result.failed);
        assert!(result.msg.contains("created"));
    }

    #[test]
    fn test_site_module_absent() {
        let module = SiteModule;
        let args = ModuleArgs {
            name: "site1".to_string(),
            state: ModuleState::Absent,
            params: HashMap::new(),
        };

        let result = module.run(args);
        assert!(result.changed);
        assert!(!result.failed);
        assert!(result.msg.contains("removed"));
    }

    #[test]
    fn test_tunnel_module_started() {
        let module = TunnelModule;
        let args = ModuleArgs {
            name: "tunnel1".to_string(),
            state: ModuleState::Started,
            params: HashMap::new(),
        };

        let result = module.run(args);
        assert!(result.changed);
        assert!(!result.failed);
        assert!(result.msg.contains("started"));
    }

    #[test]
    fn test_tunnel_module_stopped() {
        let module = TunnelModule;
        let args = ModuleArgs {
            name: "tunnel1".to_string(),
            state: ModuleState::Stopped,
            params: HashMap::new(),
        };

        let result = module.run(args);
        assert!(result.changed);
        assert!(!result.failed);
        assert!(result.msg.contains("stopped"));
    }

    #[test]
    fn test_module_names() {
        assert_eq!(SiteModule.module_name(), "patronus_site");
        assert_eq!(TunnelModule.module_name(), "patronus_tunnel");
    }
}
