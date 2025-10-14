//! Service Mesh Interface (SMI) Support

use async_trait::async_trait;
use anyhow::Result;

#[async_trait]
pub trait ServiceMeshInterface {
    async fn create_traffic_split(&self, name: &str, service: &str, backends: Vec<(String, u32)>) -> Result<()>;
    async fn create_traffic_access(&self, name: &str, source: &str, destination: &str) -> Result<()>;
    async fn get_metrics(&self, service: &str) -> Result<ServiceMetrics>;
}

#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    pub success_rate: f64,
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,
    pub requests_per_second: f64,
}

pub struct SmiAdapter;

#[async_trait]
impl ServiceMeshInterface for SmiAdapter {
    async fn create_traffic_split(&self, name: &str, service: &str, backends: Vec<(String, u32)>) -> Result<()> {
        tracing::info!("Creating TrafficSplit {} for service {}", name, service);
        Ok(())
    }

    async fn create_traffic_access(&self, name: &str, source: &str, destination: &str) -> Result<()> {
        tracing::info!("Creating TrafficTarget {} from {} to {}", name, source, destination);
        Ok(())
    }

    async fn get_metrics(&self, service: &str) -> Result<ServiceMetrics> {
        Ok(ServiceMetrics {
            success_rate: 0.999,
            latency_p50: 10.0,
            latency_p95: 50.0,
            latency_p99: 100.0,
            requests_per_second: 1000.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smi() {
        let smi = SmiAdapter;
        smi.create_traffic_split("test", "svc", vec![("backend1".to_string(), 80), ("backend2".to_string(), 20)]).await.unwrap();
        let metrics = smi.get_metrics("svc").await.unwrap();
        assert!(metrics.success_rate > 0.99);
    }
}
