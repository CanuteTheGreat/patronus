//! Edge Node Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub storage_gb: u32,
    pub gpu_available: bool,
    pub supports_5g: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNode {
    pub id: Uuid,
    pub name: String,
    pub location: (f64, f64),
    pub capabilities: NodeCapabilities,
    pub status: NodeStatus,
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub connected_devices: usize,
}

impl EdgeNode {
    pub fn new(name: String, location: (f64, f64), capabilities: NodeCapabilities) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            location,
            capabilities,
            status: NodeStatus::Online,
            cpu_usage_percent: 0.0,
            memory_usage_percent: 0.0,
            connected_devices: 0,
        }
    }

    pub fn is_overloaded(&self) -> bool {
        self.cpu_usage_percent > 80.0 || self.memory_usage_percent > 80.0
    }

    pub fn available_cpu(&self) -> f64 {
        100.0 - self.cpu_usage_percent
    }

    pub fn available_memory(&self) -> f64 {
        100.0 - self.memory_usage_percent
    }
}

pub struct EdgeNodeManager {
    nodes: Arc<RwLock<HashMap<Uuid, EdgeNode>>>,
}

impl EdgeNodeManager {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_node(&self, node: EdgeNode) -> Uuid {
        let id = node.id;
        let mut nodes = self.nodes.write().await;
        nodes.insert(id, node);
        id
    }

    pub async fn get_node(&self, id: &Uuid) -> Option<EdgeNode> {
        let nodes = self.nodes.read().await;
        nodes.get(id).cloned()
    }

    pub async fn list_nodes(&self) -> Vec<EdgeNode> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    pub async fn get_online_nodes(&self) -> Vec<EdgeNode> {
        let nodes = self.nodes.read().await;
        nodes.values()
            .filter(|n| n.status == NodeStatus::Online)
            .cloned()
            .collect()
    }

    pub async fn find_least_loaded_node(&self) -> Option<EdgeNode> {
        let nodes = self.nodes.read().await;
        nodes.values()
            .filter(|n| n.status == NodeStatus::Online && !n.is_overloaded())
            .min_by(|a, b| {
                let load_a = a.cpu_usage_percent + a.memory_usage_percent;
                let load_b = b.cpu_usage_percent + b.memory_usage_percent;
                load_a.partial_cmp(&load_b).unwrap()
            })
            .cloned()
    }
}

impl Default for EdgeNodeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_node_creation() {
        let caps = NodeCapabilities {
            cpu_cores: 16,
            memory_gb: 64,
            storage_gb: 1000,
            gpu_available: true,
            supports_5g: true,
        };

        let node = EdgeNode::new("edge-1".to_string(), (37.7749, -122.4194), caps);
        assert_eq!(node.name, "edge-1");
        assert_eq!(node.status, NodeStatus::Online);
    }

    #[test]
    fn test_overload_detection() {
        let caps = NodeCapabilities {
            cpu_cores: 8,
            memory_gb: 32,
            storage_gb: 500,
            gpu_available: false,
            supports_5g: true,
        };

        let mut node = EdgeNode::new("edge-1".to_string(), (0.0, 0.0), caps);
        assert!(!node.is_overloaded());

        node.cpu_usage_percent = 85.0;
        assert!(node.is_overloaded());
    }

    #[tokio::test]
    async fn test_find_least_loaded_node() {
        let manager = EdgeNodeManager::new();

        let caps = NodeCapabilities {
            cpu_cores: 8,
            memory_gb: 32,
            storage_gb: 500,
            gpu_available: false,
            supports_5g: true,
        };

        let mut node1 = EdgeNode::new("node1".to_string(), (0.0, 0.0), caps.clone());
        node1.cpu_usage_percent = 50.0;

        let mut node2 = EdgeNode::new("node2".to_string(), (0.0, 0.0), caps);
        node2.cpu_usage_percent = 20.0;

        manager.register_node(node1).await;
        manager.register_node(node2).await;

        let least_loaded = manager.find_least_loaded_node().await;
        assert!(least_loaded.is_some());
        assert_eq!(least_loaded.unwrap().name, "node2");
    }
}
