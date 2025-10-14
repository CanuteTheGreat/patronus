//! Ansible Modules for Patronus SD-WAN
//!
//! Automation integration for Ansible-based deployments

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod inventory;
pub mod module;
pub mod playbook;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModuleState {
    Present,
    Absent,
    Started,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    pub changed: bool,
    pub failed: bool,
    pub msg: String,
    pub meta: HashMap<String, serde_json::Value>,
}

impl ModuleResult {
    pub fn success(changed: bool, msg: String) -> Self {
        Self {
            changed,
            failed: false,
            msg,
            meta: HashMap::new(),
        }
    }

    pub fn failure(msg: String) -> Self {
        Self {
            changed: false,
            failed: true,
            msg,
            meta: HashMap::new(),
        }
    }

    pub fn with_meta(mut self, key: String, value: serde_json::Value) -> Self {
        self.meta.insert(key, value);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleHost {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub groups: Vec<String>,
    pub vars: HashMap<String, String>,
}

impl AnsibleHost {
    pub fn new(name: String, address: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            address,
            port: 22,
            groups: Vec::new(),
            vars: HashMap::new(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_group(mut self, group: String) -> Self {
        self.groups.push(group);
        self
    }

    pub fn with_var(mut self, key: String, value: String) -> Self {
        self.vars.insert(key, value);
        self
    }
}

pub struct AnsibleManager {
    hosts: Arc<RwLock<HashMap<Uuid, AnsibleHost>>>,
    groups: Arc<RwLock<HashMap<String, Vec<Uuid>>>>,
}

impl AnsibleManager {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_host(&self, host: AnsibleHost) -> Uuid {
        let id = host.id;
        let groups = host.groups.clone();

        let mut hosts = self.hosts.write().await;
        hosts.insert(id, host);
        drop(hosts);

        // Add to groups
        let mut group_map = self.groups.write().await;
        for group in groups {
            group_map.entry(group).or_insert_with(Vec::new).push(id);
        }

        id
    }

    pub async fn get_host(&self, id: &Uuid) -> Option<AnsibleHost> {
        let hosts = self.hosts.read().await;
        hosts.get(id).cloned()
    }

    pub async fn remove_host(&self, id: &Uuid) -> bool {
        let mut hosts = self.hosts.write().await;
        if let Some(host) = hosts.remove(id) {
            drop(hosts);

            let mut groups = self.groups.write().await;
            for group in &host.groups {
                if let Some(host_list) = groups.get_mut(group) {
                    host_list.retain(|h| h != id);
                }
            }
            true
        } else {
            false
        }
    }

    pub async fn get_hosts_in_group(&self, group: &str) -> Vec<AnsibleHost> {
        let groups = self.groups.read().await;
        let host_ids = match groups.get(group) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };
        drop(groups);

        let hosts = self.hosts.read().await;
        host_ids
            .iter()
            .filter_map(|id| hosts.get(id).cloned())
            .collect()
    }

    pub async fn list_groups(&self) -> Vec<String> {
        let groups = self.groups.read().await;
        groups.keys().cloned().collect()
    }

    pub async fn list_all_hosts(&self) -> Vec<AnsibleHost> {
        let hosts = self.hosts.read().await;
        hosts.values().cloned().collect()
    }

    pub async fn update_host_var(&self, id: &Uuid, key: String, value: String) -> bool {
        let mut hosts = self.hosts.write().await;
        if let Some(host) = hosts.get_mut(id) {
            host.vars.insert(key, value);
            true
        } else {
            false
        }
    }

    pub async fn generate_inventory(&self) -> String {
        let hosts = self.hosts.read().await;
        let groups = self.groups.read().await;

        let mut inventory = String::new();

        // Generate group sections
        for (group_name, host_ids) in groups.iter() {
            inventory.push_str(&format!("[{}]\n", group_name));
            for host_id in host_ids {
                if let Some(host) = hosts.get(host_id) {
                    inventory.push_str(&format!(
                        "{} ansible_host={} ansible_port={}\n",
                        host.name, host.address, host.port
                    ));
                }
            }
            inventory.push('\n');
        }

        // Add ungrouped hosts
        let grouped_hosts: std::collections::HashSet<_> = groups
            .values()
            .flatten()
            .collect();

        let ungrouped: Vec<_> = hosts
            .values()
            .filter(|h| !grouped_hosts.contains(&h.id))
            .collect();

        if !ungrouped.is_empty() {
            inventory.push_str("[ungrouped]\n");
            for host in ungrouped {
                inventory.push_str(&format!(
                    "{} ansible_host={} ansible_port={}\n",
                    host.name, host.address, host.port
                ));
            }
        }

        inventory
    }
}

impl Default for AnsibleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_result_success() {
        let result = ModuleResult::success(true, "Task completed".to_string());
        assert!(result.changed);
        assert!(!result.failed);
        assert_eq!(result.msg, "Task completed");
    }

    #[test]
    fn test_module_result_failure() {
        let result = ModuleResult::failure("Task failed".to_string());
        assert!(!result.changed);
        assert!(result.failed);
        assert_eq!(result.msg, "Task failed");
    }

    #[test]
    fn test_module_result_with_meta() {
        let result = ModuleResult::success(true, "Done".to_string())
            .with_meta("id".to_string(), serde_json::json!("abc123"));

        assert_eq!(result.meta.get("id"), Some(&serde_json::json!("abc123")));
    }

    #[test]
    fn test_ansible_host_creation() {
        let host = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string());

        assert_eq!(host.name, "server1");
        assert_eq!(host.address, "192.168.1.10");
        assert_eq!(host.port, 22);
    }

    #[test]
    fn test_ansible_host_builder() {
        let host = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string())
            .with_port(2222)
            .with_group("webservers".to_string())
            .with_var("env".to_string(), "production".to_string());

        assert_eq!(host.port, 2222);
        assert_eq!(host.groups.len(), 1);
        assert_eq!(host.vars.get("env"), Some(&"production".to_string()));
    }

    #[tokio::test]
    async fn test_ansible_manager_add_host() {
        let manager = AnsibleManager::new();

        let host = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string());
        let id = host.id;

        manager.add_host(host).await;

        let retrieved = manager.get_host(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "server1");
    }

    #[tokio::test]
    async fn test_ansible_manager_remove_host() {
        let manager = AnsibleManager::new();

        let host = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string());
        let id = host.id;

        manager.add_host(host).await;
        assert!(manager.remove_host(&id).await);
        assert!(manager.get_host(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_ansible_manager_groups() {
        let manager = AnsibleManager::new();

        let host1 = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string())
            .with_group("webservers".to_string());

        let host2 = AnsibleHost::new("server2".to_string(), "192.168.1.11".to_string())
            .with_group("webservers".to_string());

        manager.add_host(host1).await;
        manager.add_host(host2).await;

        let hosts = manager.get_hosts_in_group("webservers").await;
        assert_eq!(hosts.len(), 2);
    }

    #[tokio::test]
    async fn test_list_groups() {
        let manager = AnsibleManager::new();

        let host1 = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string())
            .with_group("webservers".to_string());

        let host2 = AnsibleHost::new("db1".to_string(), "192.168.1.20".to_string())
            .with_group("databases".to_string());

        manager.add_host(host1).await;
        manager.add_host(host2).await;

        let groups = manager.list_groups().await;
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"webservers".to_string()));
        assert!(groups.contains(&"databases".to_string()));
    }

    #[tokio::test]
    async fn test_list_all_hosts() {
        let manager = AnsibleManager::new();

        let host1 = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string());
        let host2 = AnsibleHost::new("server2".to_string(), "192.168.1.11".to_string());

        manager.add_host(host1).await;
        manager.add_host(host2).await;

        let hosts = manager.list_all_hosts().await;
        assert_eq!(hosts.len(), 2);
    }

    #[tokio::test]
    async fn test_update_host_var() {
        let manager = AnsibleManager::new();

        let host = AnsibleHost::new("server1".to_string(), "192.168.1.10".to_string());
        let id = host.id;

        manager.add_host(host).await;
        assert!(manager.update_host_var(&id, "env".to_string(), "staging".to_string()).await);

        let updated = manager.get_host(&id).await.unwrap();
        assert_eq!(updated.vars.get("env"), Some(&"staging".to_string()));
    }

    #[tokio::test]
    async fn test_generate_inventory() {
        let manager = AnsibleManager::new();

        let host1 = AnsibleHost::new("web1".to_string(), "192.168.1.10".to_string())
            .with_group("webservers".to_string());

        let host2 = AnsibleHost::new("web2".to_string(), "192.168.1.11".to_string())
            .with_group("webservers".to_string());

        let host3 = AnsibleHost::new("db1".to_string(), "192.168.1.20".to_string())
            .with_group("databases".to_string());

        manager.add_host(host1).await;
        manager.add_host(host2).await;
        manager.add_host(host3).await;

        let inventory = manager.generate_inventory().await;

        assert!(inventory.contains("[webservers]"));
        assert!(inventory.contains("[databases]"));
        assert!(inventory.contains("web1 ansible_host=192.168.1.10"));
        assert!(inventory.contains("db1 ansible_host=192.168.1.20"));
    }
}
