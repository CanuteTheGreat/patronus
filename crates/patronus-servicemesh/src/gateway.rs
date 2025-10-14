//! Mesh Gateway for multi-cluster communication

use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use anyhow::Result;

pub struct MeshGateway {
    clusters: Arc<RwLock<HashMap<String, ClusterEndpoint>>>,
}

#[derive(Debug, Clone)]
pub struct ClusterEndpoint {
    pub name: String,
    pub endpoint: String,
    pub tls_enabled: bool,
    pub ca_cert: Option<String>,
}

impl MeshGateway {
    pub fn new() -> Self {
        Self {
            clusters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_cluster(&self, cluster: ClusterEndpoint) -> Result<()> {
        let mut clusters = self.clusters.write().await;
        tracing::info!("Registering cluster {} at {}", cluster.name, cluster.endpoint);
        clusters.insert(cluster.name.clone(), cluster);
        Ok(())
    }

    pub async fn route_to_cluster(&self, cluster_name: &str, service: &str) -> Result<String> {
        let clusters = self.clusters.read().await;
        let cluster = clusters.get(cluster_name)
            .ok_or_else(|| anyhow::anyhow!("Cluster not found"))?;
        Ok(format!("{}:{}", cluster.endpoint, service))
    }
}

impl Default for MeshGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mesh_gateway() {
        let gateway = MeshGateway::new();

        let cluster = ClusterEndpoint {
            name: "us-west".to_string(),
            endpoint: "gateway.us-west.example.com".to_string(),
            tls_enabled: true,
            ca_cert: None,
        };

        gateway.register_cluster(cluster).await.unwrap();
        let route = gateway.route_to_cluster("us-west", "my-service").await.unwrap();
        assert!(route.contains("us-west"));
    }
}
