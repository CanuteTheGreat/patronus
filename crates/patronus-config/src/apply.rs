//! Configuration Apply Engine
//!
//! This module handles applying declarative configurations to the running system.
//! It provides diff generation, dry-run simulation, atomic application, and rollback.
//!
//! Key features:
//! - Generate diff between current and desired state
//! - Dry-run mode (show changes without applying)
//! - Atomic apply (all-or-nothing)
//! - Automatic rollback on failure
//! - State history for manual rollback
//! - Dependency resolution and ordering

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};

use crate::declarative::{DeclarativeConfig, ResourceKind, ConfigParser};

/// Change operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeOp {
    Create,
    Update,
    Delete,
    NoChange,
}

/// A single configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub operation: ChangeOp,
    pub resource_kind: ResourceKind,
    pub resource_name: String,
    pub old_config: Option<DeclarativeConfig>,
    pub new_config: Option<DeclarativeConfig>,
    pub dependencies: Vec<String>,  // Resources this depends on
}

/// Result of a diff operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub changes: Vec<ConfigChange>,
    pub creates: usize,
    pub updates: usize,
    pub deletes: usize,
    pub no_changes: usize,
}

impl DiffResult {
    pub fn has_changes(&self) -> bool {
        self.creates > 0 || self.updates > 0 || self.deletes > 0
    }

    pub fn total_changes(&self) -> usize {
        self.creates + self.updates + self.deletes
    }
}

/// Apply result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub success: bool,
    pub changes_applied: usize,
    pub changes_failed: usize,
    pub errors: Vec<String>,
    pub rollback_performed: bool,
}

/// Configuration snapshot for rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub configs: Vec<DeclarativeConfig>,
}

/// Configuration state manager
pub struct StateManager {
    state_dir: PathBuf,
    current_state: HashMap<String, DeclarativeConfig>,  // name -> config
    snapshots: Vec<ConfigSnapshot>,
}

impl StateManager {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            current_state: HashMap::new(),
            snapshots: Vec::new(),
        }
    }

    /// Initialize state manager and load current state
    pub async fn init(&mut self) -> Result<()> {
        // Create state directory if needed
        tokio::fs::create_dir_all(&self.state_dir).await?;

        // Load current state from disk
        self.load_current_state().await?;

        // Load snapshots
        self.load_snapshots().await?;

        Ok(())
    }

    async fn load_current_state(&mut self) -> Result<()> {
        let state_file = self.state_dir.join("current.yaml");

        if state_file.exists() {
            let content = tokio::fs::read_to_string(&state_file).await?;
            let configs = ConfigParser::parse_yaml(&content)?;

            for config in configs {
                self.current_state.insert(config.metadata.name.clone(), config);
            }

            tracing::info!("Loaded {} resources from current state", self.current_state.len());
        }

        Ok(())
    }

    async fn save_current_state(&self) -> Result<()> {
        let state_file = self.state_dir.join("current.yaml");

        let configs: Vec<&DeclarativeConfig> = self.current_state.values().collect();

        // Serialize all configs to YAML (multi-document)
        let mut yaml = String::new();
        for config in configs {
            yaml.push_str(&ConfigParser::to_yaml(config)?);
            yaml.push_str("\n---\n");
        }

        tokio::fs::write(&state_file, yaml).await?;

        Ok(())
    }

    async fn load_snapshots(&mut self) -> Result<()> {
        let snapshots_dir = self.state_dir.join("snapshots");

        if !snapshots_dir.exists() {
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(&snapshots_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                let content = tokio::fs::read_to_string(&path).await?;
                if let Ok(snapshot) = serde_yaml::from_str::<ConfigSnapshot>(&content) {
                    self.snapshots.push(snapshot);
                }
            }
        }

        // Sort by timestamp (newest first)
        self.snapshots.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        tracing::info!("Loaded {} snapshots", self.snapshots.len());

        Ok(())
    }

    /// Get current resource by name
    pub fn get(&self, name: &str) -> Option<&DeclarativeConfig> {
        self.current_state.get(name)
    }

    /// List all current resources
    pub fn list(&self) -> Vec<&DeclarativeConfig> {
        self.current_state.values().collect()
    }

    /// List resources of specific kind
    pub fn list_by_kind(&self, kind: &ResourceKind) -> Vec<&DeclarativeConfig> {
        self.current_state.values()
            .filter(|c| &c.kind == kind)
            .collect()
    }

    /// Update a resource
    fn update(&mut self, config: DeclarativeConfig) {
        self.current_state.insert(config.metadata.name.clone(), config);
    }

    /// Delete a resource
    fn delete(&mut self, name: &str) -> Option<DeclarativeConfig> {
        self.current_state.remove(name)
    }

    /// Create a snapshot of current state
    pub async fn create_snapshot(&mut self, description: String) -> Result<ConfigSnapshot> {
        let snapshot = ConfigSnapshot {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            description,
            configs: self.current_state.values().cloned().collect(),
        };

        // Save to disk
        let snapshots_dir = self.state_dir.join("snapshots");
        tokio::fs::create_dir_all(&snapshots_dir).await?;

        let snapshot_file = snapshots_dir.join(format!("{}.yaml", snapshot.id));
        let yaml = serde_yaml::to_string(&snapshot)
            .map_err(|e| Error::Config(format!("Failed to serialize snapshot: {}", e)))?;

        tokio::fs::write(&snapshot_file, yaml).await?;

        self.snapshots.insert(0, snapshot.clone());

        // Keep only last 100 snapshots
        if self.snapshots.len() > 100 {
            if let Some(old) = self.snapshots.pop() {
                let old_file = snapshots_dir.join(format!("{}.yaml", old.id));
                tokio::fs::remove_file(&old_file).await.ok();
            }
        }

        tracing::info!("Created snapshot: {}", snapshot.id);

        Ok(snapshot)
    }

    /// Get list of snapshots
    pub fn list_snapshots(&self) -> &[ConfigSnapshot] {
        &self.snapshots
    }

    /// Get specific snapshot
    pub fn get_snapshot(&self, id: &str) -> Option<&ConfigSnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }
}

/// Configuration apply engine
pub struct ApplyEngine {
    state_manager: StateManager,
    dry_run: bool,
}

impl ApplyEngine {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_manager: StateManager::new(state_dir),
            dry_run: false,
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        self.state_manager.init().await
    }

    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Generate diff between current and desired state
    pub fn diff(&self, desired_configs: &[DeclarativeConfig]) -> Result<DiffResult> {
        let mut changes = Vec::new();

        // Build map of desired configs
        let desired_map: HashMap<String, &DeclarativeConfig> = desired_configs.iter()
            .map(|c| (c.metadata.name.clone(), c))
            .collect();

        // Find creates and updates
        for (name, new_config) in &desired_map {
            if let Some(old_config) = self.state_manager.get(name) {
                // Resource exists - check if changed
                if self.has_changed(old_config, new_config) {
                    changes.push(ConfigChange {
                        operation: ChangeOp::Update,
                        resource_kind: new_config.kind.clone(),
                        resource_name: name.clone(),
                        old_config: Some(old_config.clone()),
                        new_config: Some((*new_config).clone()),
                        dependencies: self.get_dependencies(new_config),
                    });
                } else {
                    changes.push(ConfigChange {
                        operation: ChangeOp::NoChange,
                        resource_kind: new_config.kind.clone(),
                        resource_name: name.clone(),
                        old_config: Some(old_config.clone()),
                        new_config: Some((*new_config).clone()),
                        dependencies: Vec::new(),
                    });
                }
            } else {
                // New resource
                changes.push(ConfigChange {
                    operation: ChangeOp::Create,
                    resource_kind: new_config.kind.clone(),
                    resource_name: name.clone(),
                    old_config: None,
                    new_config: Some((*new_config).clone()),
                    dependencies: self.get_dependencies(new_config),
                });
            }
        }

        // Find deletes (resources in current but not in desired)
        for name in self.state_manager.current_state.keys() {
            if !desired_map.contains_key(name) {
                let old_config = self.state_manager.get(name).unwrap();
                changes.push(ConfigChange {
                    operation: ChangeOp::Delete,
                    resource_kind: old_config.kind.clone(),
                    resource_name: name.clone(),
                    old_config: Some(old_config.clone()),
                    new_config: None,
                    dependencies: Vec::new(),
                });
            }
        }

        // Sort changes by dependency order
        changes = self.sort_by_dependencies(changes)?;

        // Count operations
        let creates = changes.iter().filter(|c| c.operation == ChangeOp::Create).count();
        let updates = changes.iter().filter(|c| c.operation == ChangeOp::Update).count();
        let deletes = changes.iter().filter(|c| c.operation == ChangeOp::Delete).count();
        let no_changes = changes.iter().filter(|c| c.operation == ChangeOp::NoChange).count();

        Ok(DiffResult {
            changes,
            creates,
            updates,
            deletes,
            no_changes,
        })
    }

    fn has_changed(&self, old: &DeclarativeConfig, new: &DeclarativeConfig) -> bool {
        // Simple comparison - serialize and compare
        // In production, would do smarter comparison
        let old_yaml = ConfigParser::to_yaml(old).unwrap_or_default();
        let new_yaml = ConfigParser::to_yaml(new).unwrap_or_default();
        old_yaml != new_yaml
    }

    fn get_dependencies(&self, config: &DeclarativeConfig) -> Vec<String> {
        // Extract dependency names from config
        // For example, firewall rules might depend on aliases or interfaces
        // This is simplified - real implementation would parse spec
        Vec::new()
    }

    fn sort_by_dependencies(&self, mut changes: Vec<ConfigChange>) -> Result<Vec<ConfigChange>> {
        // Topological sort based on dependencies
        // For now, simple ordering: Create before Update before Delete
        changes.sort_by(|a, b| {
            match (&a.operation, &b.operation) {
                (ChangeOp::Create, ChangeOp::Create) => std::cmp::Ordering::Equal,
                (ChangeOp::Create, _) => std::cmp::Ordering::Less,
                (_, ChangeOp::Create) => std::cmp::Ordering::Greater,
                (ChangeOp::Update, ChangeOp::Update) => std::cmp::Ordering::Equal,
                (ChangeOp::Update, ChangeOp::Delete) => std::cmp::Ordering::Less,
                (ChangeOp::Delete, ChangeOp::Update) => std::cmp::Ordering::Greater,
                (ChangeOp::Delete, ChangeOp::Delete) => std::cmp::Ordering::Equal,
                _ => std::cmp::Ordering::Equal,
            }
        });

        Ok(changes)
    }

    /// Apply configuration changes
    pub async fn apply(&mut self, desired_configs: Vec<DeclarativeConfig>) -> Result<ApplyResult> {
        // Generate diff
        let diff = self.diff(&desired_configs)?;

        if !diff.has_changes() {
            tracing::info!("No changes to apply");
            return Ok(ApplyResult {
                success: true,
                changes_applied: 0,
                changes_failed: 0,
                errors: Vec::new(),
                rollback_performed: false,
            });
        }

        if self.dry_run {
            tracing::info!("Dry-run mode: would apply {} changes", diff.total_changes());
            return Ok(ApplyResult {
                success: true,
                changes_applied: 0,
                changes_failed: 0,
                errors: vec!["Dry-run mode - no changes applied".to_string()],
                rollback_performed: false,
            });
        }

        // Create snapshot before applying
        let snapshot = self.state_manager.create_snapshot("Pre-apply snapshot".to_string()).await?;

        tracing::info!("Applying {} changes (snapshot: {})", diff.total_changes(), snapshot.id);

        let mut changes_applied = 0;
        let mut changes_failed = 0;
        let mut errors = Vec::new();

        // Apply changes in order
        for change in &diff.changes {
            if change.operation == ChangeOp::NoChange {
                continue;
            }

            match self.apply_change(change).await {
                Ok(_) => {
                    changes_applied += 1;
                    tracing::info!("Applied {:?} {}", change.operation, change.resource_name);
                }
                Err(e) => {
                    changes_failed += 1;
                    let error_msg = format!("Failed to apply {:?} {}: {}",
                        change.operation, change.resource_name, e);
                    tracing::error!("{}", error_msg);
                    errors.push(error_msg);

                    // Rollback on first error
                    tracing::warn!("Rolling back to snapshot {}", snapshot.id);
                    if let Err(rollback_err) = self.rollback_to_snapshot(&snapshot.id).await {
                        errors.push(format!("Rollback failed: {}", rollback_err));
                        return Ok(ApplyResult {
                            success: false,
                            changes_applied,
                            changes_failed,
                            errors,
                            rollback_performed: false,
                        });
                    }

                    return Ok(ApplyResult {
                        success: false,
                        changes_applied,
                        changes_failed,
                        errors,
                        rollback_performed: true,
                    });
                }
            }
        }

        // Save new state
        self.state_manager.save_current_state().await?;

        tracing::info!("Successfully applied {} changes", changes_applied);

        Ok(ApplyResult {
            success: true,
            changes_applied,
            changes_failed,
            errors,
            rollback_performed: false,
        })
    }

    async fn apply_change(&mut self, change: &ConfigChange) -> Result<()> {
        match change.operation {
            ChangeOp::Create => {
                let config = change.new_config.as_ref()
                    .ok_or_else(|| Error::Config("No new config for create".to_string()))?;

                // Apply the resource creation based on kind
                self.create_resource(config).await?;

                // Update state
                self.state_manager.update(config.clone());

                Ok(())
            }
            ChangeOp::Update => {
                let config = change.new_config.as_ref()
                    .ok_or_else(|| Error::Config("No new config for update".to_string()))?;

                // Apply the resource update
                self.update_resource(config).await?;

                // Update state
                self.state_manager.update(config.clone());

                Ok(())
            }
            ChangeOp::Delete => {
                // Apply the resource deletion
                self.delete_resource(&change.resource_name, &change.resource_kind).await?;

                // Update state
                self.state_manager.delete(&change.resource_name);

                Ok(())
            }
            ChangeOp::NoChange => Ok(()),
        }
    }

    async fn create_resource(&self, config: &DeclarativeConfig) -> Result<()> {
        // Dispatch to appropriate handler based on resource kind
        // This would integrate with actual firewall/network management code

        tracing::debug!("Creating {:?}: {}", config.kind, config.metadata.name);

        match config.kind {
            ResourceKind::FirewallRule => {
                // Would call patronus-firewall crate to create rule
                // For now, just log
                Ok(())
            }
            ResourceKind::NatRule => {
                // Would call NAT management
                Ok(())
            }
            ResourceKind::VpnConnection => {
                // Would call VPN management
                Ok(())
            }
            _ => {
                Ok(())
            }
        }
    }

    async fn update_resource(&self, config: &DeclarativeConfig) -> Result<()> {
        tracing::debug!("Updating {:?}: {}", config.kind, config.metadata.name);

        // Similar to create, but update existing resource
        Ok(())
    }

    async fn delete_resource(&self, name: &str, kind: &ResourceKind) -> Result<()> {
        tracing::debug!("Deleting {:?}: {}", kind, name);

        // Delete the resource
        Ok(())
    }

    /// Rollback to a specific snapshot
    pub async fn rollback_to_snapshot(&mut self, snapshot_id: &str) -> Result<()> {
        let snapshot = self.state_manager.get_snapshot(snapshot_id)
            .ok_or_else(|| Error::Config(format!("Snapshot not found: {}", snapshot_id)))?;

        tracing::info!("Rolling back to snapshot: {} ({})",
            snapshot.id, snapshot.description);

        // Apply the snapshot configs
        let result = self.apply(snapshot.configs.clone()).await?;

        if !result.success {
            return Err(Error::Config(format!(
                "Rollback failed: {} errors", result.errors.len()
            )));
        }

        Ok(())
    }

    /// Get state manager reference
    pub fn state_manager(&self) -> &StateManager {
        &self.state_manager
    }
}

/// Pretty-print diff result
pub fn format_diff(diff: &DiffResult) -> String {
    let mut output = String::new();

    output.push_str(&format!("Changes: {} create, {} update, {} delete\n\n",
        diff.creates, diff.updates, diff.deletes));

    for change in &diff.changes {
        let symbol = match change.operation {
            ChangeOp::Create => "+",
            ChangeOp::Update => "~",
            ChangeOp::Delete => "-",
            ChangeOp::NoChange => " ",
        };

        output.push_str(&format!("{} {:?}: {}\n",
            symbol, change.resource_kind, change.resource_name));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declarative::*;

    #[tokio::test]
    async fn test_diff_create() {
        let temp_dir = tempfile::tempdir().unwrap();
        let engine = ApplyEngine::new(temp_dir.path().to_path_buf());

        let config = DeclarativeConfig {
            api_version: API_VERSION.to_string(),
            kind: ResourceKind::FirewallRule,
            metadata: Metadata {
                name: "test-rule".to_string(),
                description: None,
                labels: None,
                annotations: None,
            },
            spec: ResourceSpec::FirewallRule(FirewallRuleSpec {
                action: RuleAction::Allow,
                interface: None,
                direction: None,
                source: AddressSpec {
                    address: Some("0.0.0.0/0".to_string()),
                    ports: None,
                    port_ranges: None,
                },
                destination: AddressSpec {
                    address: Some("10.0.0.1".to_string()),
                    ports: Some(vec![80]),
                    port_ranges: None,
                },
                protocol: Some("tcp".to_string()),
                log: false,
                schedule: None,
                gateway: None,
                enabled: true,
            }),
        };

        let diff = engine.diff(&[config]).unwrap();

        assert_eq!(diff.creates, 1);
        assert_eq!(diff.updates, 0);
        assert_eq!(diff.deletes, 0);
    }

    #[test]
    fn test_format_diff() {
        let diff = DiffResult {
            changes: vec![
                ConfigChange {
                    operation: ChangeOp::Create,
                    resource_kind: ResourceKind::FirewallRule,
                    resource_name: "allow-web".to_string(),
                    old_config: None,
                    new_config: None,
                    dependencies: Vec::new(),
                },
            ],
            creates: 1,
            updates: 0,
            deletes: 0,
            no_changes: 0,
        };

        let formatted = format_diff(&diff);
        assert!(formatted.contains("+ FirewallRule: allow-web"));
    }
}
