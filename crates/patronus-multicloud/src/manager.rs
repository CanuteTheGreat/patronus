//! Multi-Cloud Manager
//!
//! Manages connections to multiple cloud providers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

/// Cloud provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    AWS,
    Azure,
    GCP,
}

/// Cloud connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConnection {
    pub provider: CloudProvider,
    pub region: String,
    pub vpc_id: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub tunnel_id: u32,
    pub connected: bool,
    pub latency_ms: f64,
}

/// Multi-cloud connectivity manager
pub struct MultiCloudManager {
    connections: Arc<RwLock<HashMap<String, CloudConnection>>>,
}

impl MultiCloudManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add cloud connection
    pub async fn add_connection(&self, conn: CloudConnection) -> Result<()> {
        let mut connections = self.connections.write().await;
        let key = format!("{:?}_{}", conn.provider, conn.region);
        connections.insert(key, conn);
        Ok(())
    }

    /// Remove cloud connection
    pub async fn remove_connection(&self, provider: CloudProvider, region: &str) -> Result<()> {
        let mut connections = self.connections.write().await;
        let key = format!("{:?}_{}", provider, region);
        connections.remove(&key);
        Ok(())
    }

    /// Get all connections
    pub async fn get_connections(&self) -> Vec<CloudConnection> {
        let connections = self.connections.read().await;
        connections.values().cloned().collect()
    }

    /// Get connections for specific provider
    pub async fn get_provider_connections(&self, provider: CloudProvider) -> Vec<CloudConnection> {
        let connections = self.connections.read().await;
        connections.values()
            .filter(|c| c.provider == provider)
            .cloned()
            .collect()
    }

    /// Update connection status
    pub async fn update_status(&self, provider: CloudProvider, region: &str, connected: bool, latency: f64) -> Result<()> {
        let mut connections = self.connections.write().await;
        let key = format!("{:?}_{}", provider, region);
        if let Some(conn) = connections.get_mut(&key) {
            conn.connected = connected;
            conn.latency_ms = latency;
        }
        Ok(())
    }
}

impl Default for MultiCloudManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_connection() {
        let manager = MultiCloudManager::new();

        let conn = CloudConnection {
            provider: CloudProvider::AWS,
            region: "us-east-1".to_string(),
            vpc_id: "vpc-12345".to_string(),
            local_ip: "10.0.0.1".to_string(),
            remote_ip: "172.31.0.1".to_string(),
            tunnel_id: 1,
            connected: true,
            latency_ms: 5.0,
        };

        manager.add_connection(conn).await.unwrap();

        let connections = manager.get_connections().await;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].provider, CloudProvider::AWS);
    }

    #[tokio::test]
    async fn test_get_provider_connections() {
        let manager = MultiCloudManager::new();

        let aws_conn = CloudConnection {
            provider: CloudProvider::AWS,
            region: "us-east-1".to_string(),
            vpc_id: "vpc-12345".to_string(),
            local_ip: "10.0.0.1".to_string(),
            remote_ip: "172.31.0.1".to_string(),
            tunnel_id: 1,
            connected: true,
            latency_ms: 5.0,
        };

        let azure_conn = CloudConnection {
            provider: CloudProvider::Azure,
            region: "eastus".to_string(),
            vpc_id: "vnet-12345".to_string(),
            local_ip: "10.1.0.1".to_string(),
            remote_ip: "10.2.0.1".to_string(),
            tunnel_id: 2,
            connected: true,
            latency_ms: 8.0,
        };

        manager.add_connection(aws_conn).await.unwrap();
        manager.add_connection(azure_conn).await.unwrap();

        let aws_connections = manager.get_provider_connections(CloudProvider::AWS).await;
        assert_eq!(aws_connections.len(), 1);
        assert_eq!(aws_connections[0].region, "us-east-1");
    }
}
