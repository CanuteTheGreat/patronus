//! Plugin System for Patronus SD-WAN
//!
//! Extensibility framework for adding custom functionality

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub settings: HashMap<String, String>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            settings: HashMap::new(),
        }
    }
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    async fn initialize(&mut self, config: PluginConfig) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    async fn execute(&self, input: serde_json::Value) -> Result<serde_json::Value>;
}

pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn Plugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn register(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        let name = plugin.metadata().name.clone();
        self.plugins.insert(name, plugin);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Box<dyn Plugin>> {
        self.plugins.get(name)
    }

    pub fn list(&self) -> Vec<PluginMetadata> {
        self.plugins.values()
            .map(|p| p.metadata())
            .collect()
    }

    pub async fn initialize_all(&mut self, configs: HashMap<String, PluginConfig>) -> Result<()> {
        for (name, plugin) in self.plugins.iter_mut() {
            let config = configs.get(name)
                .cloned()
                .unwrap_or_default();
            plugin.initialize(config).await?;
        }
        Ok(())
    }

    pub async fn shutdown_all(&mut self) -> Result<()> {
        for plugin in self.plugins.values_mut() {
            plugin.shutdown().await?;
        }
        Ok(())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        metadata: PluginMetadata,
        initialized: bool,
    }

    impl TestPlugin {
        fn new() -> Self {
            Self {
                metadata: PluginMetadata {
                    name: "test-plugin".to_string(),
                    version: "1.0.0".to_string(),
                    author: "Test Author".to_string(),
                    description: "A test plugin".to_string(),
                },
                initialized: false,
            }
        }
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn metadata(&self) -> PluginMetadata {
            self.metadata.clone()
        }

        async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
            self.initialized = true;
            Ok(())
        }

        async fn shutdown(&mut self) -> Result<()> {
            self.initialized = false;
            Ok(())
        }

        async fn execute(&self, input: serde_json::Value) -> Result<serde_json::Value> {
            Ok(input)
        }
    }

    #[test]
    fn test_plugin_metadata() {
        let plugin = TestPlugin::new();
        let metadata = plugin.metadata();
        assert_eq!(metadata.name, "test-plugin");
        assert_eq!(metadata.version, "1.0.0");
    }

    #[tokio::test]
    async fn test_plugin_initialization() {
        let mut plugin = TestPlugin::new();
        assert!(!plugin.initialized);

        let config = PluginConfig::default();
        plugin.initialize(config).await.unwrap();
        assert!(plugin.initialized);
    }

    #[tokio::test]
    async fn test_plugin_execute() {
        let plugin = TestPlugin::new();
        let input = serde_json::json!({"test": "data"});
        let output = plugin.execute(input.clone()).await.unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.list().len(), 0);
    }

    #[test]
    fn test_registry_register() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin::new());

        registry.register(plugin).unwrap();
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn test_registry_get() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin::new());

        registry.register(plugin).unwrap();

        let retrieved = registry.get("test-plugin");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().metadata().name, "test-plugin");
    }

    #[tokio::test]
    async fn test_registry_initialize_all() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin::new());
        registry.register(plugin).unwrap();

        let mut configs = HashMap::new();
        configs.insert("test-plugin".to_string(), PluginConfig::default());

        registry.initialize_all(configs).await.unwrap();
    }

    #[tokio::test]
    async fn test_registry_shutdown_all() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin::new());
        registry.register(plugin).unwrap();

        let mut configs = HashMap::new();
        configs.insert("test-plugin".to_string(), PluginConfig::default());

        registry.initialize_all(configs).await.unwrap();
        registry.shutdown_all().await.unwrap();
    }
}
