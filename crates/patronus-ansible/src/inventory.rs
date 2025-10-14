//! Ansible Inventory Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryHost {
    pub ansible_host: String,
    pub ansible_port: Option<u16>,
    pub ansible_user: Option<String>,
    #[serde(flatten)]
    pub vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryGroup {
    pub hosts: Vec<String>,
    pub children: Vec<String>,
    pub vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    #[serde(flatten)]
    pub groups: HashMap<String, InventoryGroup>,
    #[serde(rename = "_meta")]
    pub meta: InventoryMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryMeta {
    pub hostvars: HashMap<String, HashMap<String, String>>,
}

impl Inventory {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            meta: InventoryMeta {
                hostvars: HashMap::new(),
            },
        }
    }

    pub fn add_group(&mut self, name: String, group: InventoryGroup) {
        self.groups.insert(name, group);
    }

    pub fn add_host_vars(&mut self, hostname: String, vars: HashMap<String, String>) {
        self.meta.hostvars.insert(hostname, vars);
    }
}

impl Default for Inventory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inventory_creation() {
        let inv = Inventory::new();
        assert_eq!(inv.groups.len(), 0);
    }

    #[test]
    fn test_add_group() {
        let mut inv = Inventory::new();
        let group = InventoryGroup {
            hosts: vec!["host1".to_string()],
            children: vec![],
            vars: HashMap::new(),
        };

        inv.add_group("webservers".to_string(), group);
        assert_eq!(inv.groups.len(), 1);
    }

    #[test]
    fn test_add_host_vars() {
        let mut inv = Inventory::new();
        let mut vars = HashMap::new();
        vars.insert("env".to_string(), "prod".to_string());

        inv.add_host_vars("host1".to_string(), vars);
        assert_eq!(inv.meta.hostvars.len(), 1);
    }
}
