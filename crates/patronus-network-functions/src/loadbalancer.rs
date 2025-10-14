//! Load Balancing
//!
//! Layer 4 and Layer 7 load balancing with health checking

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin,
    IpHash,
    Random,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackendStatus {
    Healthy,
    Unhealthy,
    Draining,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: Uuid,
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub weight: u32,
    pub status: BackendStatus,
    pub active_connections: u32,
    pub total_connections: u64,
    pub last_health_check: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
}

impl Backend {
    pub fn new(name: impl Into<String>, address: IpAddr, port: u16) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            address,
            port,
            weight: 100,
            status: BackendStatus::Healthy,
            active_connections: 0,
            total_connections: 0,
            last_health_check: None,
            consecutive_failures: 0,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    pub fn is_available(&self) -> bool {
        matches!(self.status, BackendStatus::Healthy)
    }

    pub fn mark_healthy(&mut self) {
        self.status = BackendStatus::Healthy;
        self.consecutive_failures = 0;
        self.last_health_check = Some(Utc::now());
    }

    pub fn mark_unhealthy(&mut self) {
        self.consecutive_failures += 1;
        self.status = BackendStatus::Unhealthy;
        self.last_health_check = Some(Utc::now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub path: Option<String>, // For HTTP health checks
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 10,
            timeout_seconds: 5,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            path: Some("/health".to_string()),
        }
    }
}

pub struct LoadBalancer {
    id: Uuid,
    name: String,
    algorithm: LoadBalancingAlgorithm,
    backends: Arc<RwLock<HashMap<Uuid, Backend>>>,
    health_check: HealthCheck,
    round_robin_index: Arc<RwLock<usize>>,
}

impl LoadBalancer {
    pub fn new(name: impl Into<String>, algorithm: LoadBalancingAlgorithm) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            algorithm,
            backends: Arc::new(RwLock::new(HashMap::new())),
            health_check: HealthCheck::default(),
            round_robin_index: Arc::new(RwLock::new(0)),
        }
    }

    pub fn with_health_check(mut self, health_check: HealthCheck) -> Self {
        self.health_check = health_check;
        self
    }

    pub async fn add_backend(&self, backend: Backend) -> Uuid {
        let id = backend.id;
        let mut backends = self.backends.write().await;
        backends.insert(id, backend);
        tracing::info!("Added backend to load balancer: {}", id);
        id
    }

    pub async fn remove_backend(&self, id: &Uuid) -> Result<()> {
        let mut backends = self.backends.write().await;
        backends.remove(id)
            .ok_or_else(|| anyhow::anyhow!("Backend not found"))?;
        tracing::info!("Removed backend from load balancer: {}", id);
        Ok(())
    }

    pub async fn get_backend(&self, id: &Uuid) -> Option<Backend> {
        let backends = self.backends.read().await;
        backends.get(id).cloned()
    }

    pub async fn list_backends(&self) -> Vec<Backend> {
        let backends = self.backends.read().await;
        backends.values().cloned().collect()
    }

    pub async fn select_backend(&self, client_ip: Option<IpAddr>) -> Option<Backend> {
        let backends = self.backends.read().await;
        let available: Vec<_> = backends.values()
            .filter(|b| b.is_available())
            .cloned()
            .collect();

        if available.is_empty() {
            return None;
        }

        drop(backends);

        match self.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                self.select_round_robin(&available).await
            }
            LoadBalancingAlgorithm::LeastConnections => {
                self.select_least_connections(&available)
            }
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                self.select_weighted_round_robin(&available).await
            }
            LoadBalancingAlgorithm::IpHash => {
                self.select_ip_hash(&available, client_ip)
            }
            LoadBalancingAlgorithm::Random => {
                self.select_random(&available)
            }
        }
    }

    async fn select_round_robin(&self, backends: &[Backend]) -> Option<Backend> {
        let mut index = self.round_robin_index.write().await;
        let selected = backends.get(*index % backends.len()).cloned();
        *index = (*index + 1) % backends.len();
        selected
    }

    fn select_least_connections(&self, backends: &[Backend]) -> Option<Backend> {
        backends.iter()
            .min_by_key(|b| b.active_connections)
            .cloned()
    }

    async fn select_weighted_round_robin(&self, backends: &[Backend]) -> Option<Backend> {
        // Simplified weighted selection
        let total_weight: u32 = backends.iter().map(|b| b.weight).sum();
        if total_weight == 0 {
            return self.select_round_robin(backends).await;
        }

        let mut index = self.round_robin_index.write().await;
        *index = (*index + 1) % total_weight as usize;

        let mut cumulative = 0u32;
        for backend in backends {
            cumulative += backend.weight;
            if (*index as u32) < cumulative {
                return Some(backend.clone());
            }
        }

        backends.first().cloned()
    }

    fn select_ip_hash(&self, backends: &[Backend], client_ip: Option<IpAddr>) -> Option<Backend> {
        if let Some(ip) = client_ip {
            let hash = match ip {
                IpAddr::V4(addr) => {
                    let octets = addr.octets();
                    u32::from_be_bytes(octets) as usize
                }
                IpAddr::V6(addr) => {
                    let segments = addr.segments();
                    segments[0] as usize ^ segments[1] as usize
                }
            };

            backends.get(hash % backends.len()).cloned()
        } else {
            backends.first().cloned()
        }
    }

    fn select_random(&self, backends: &[Backend]) -> Option<Backend> {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        let random_state = RandomState::new();
        let mut hasher = random_state.build_hasher();
        Utc::now().timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
        let index = hasher.finish() as usize % backends.len();

        backends.get(index).cloned()
    }

    pub async fn increment_connection(&self, backend_id: &Uuid) {
        let mut backends = self.backends.write().await;
        if let Some(backend) = backends.get_mut(backend_id) {
            backend.active_connections += 1;
            backend.total_connections += 1;
        }
    }

    pub async fn decrement_connection(&self, backend_id: &Uuid) {
        let mut backends = self.backends.write().await;
        if let Some(backend) = backends.get_mut(backend_id) {
            if backend.active_connections > 0 {
                backend.active_connections -= 1;
            }
        }
    }

    pub async fn perform_health_checks(&self) -> Result<HealthCheckResults> {
        if !self.health_check.enabled {
            return Ok(HealthCheckResults {
                total: 0,
                healthy: 0,
                unhealthy: 0,
                checked: vec![],
            });
        }

        let mut backends = self.backends.write().await;
        let mut results = HealthCheckResults {
            total: backends.len(),
            healthy: 0,
            unhealthy: 0,
            checked: vec![],
        };

        for backend in backends.values_mut() {
            // Simulate health check (in production, would make actual TCP/HTTP request)
            let is_healthy = self.simulate_health_check(backend).await;

            if is_healthy {
                backend.mark_healthy();
                results.healthy += 1;
            } else {
                if backend.consecutive_failures >= self.health_check.unhealthy_threshold {
                    backend.mark_unhealthy();
                }
                results.unhealthy += 1;
            }

            results.checked.push(BackendHealthStatus {
                backend_id: backend.id,
                backend_name: backend.name.clone(),
                status: backend.status.clone(),
                consecutive_failures: backend.consecutive_failures,
            });
        }

        tracing::debug!("Health check results: {} healthy, {} unhealthy",
            results.healthy, results.unhealthy);

        Ok(results)
    }

    async fn simulate_health_check(&self, backend: &Backend) -> bool {
        // In production, this would:
        // 1. For TCP: attempt to connect to backend.address:backend.port
        // 2. For HTTP: make GET request to http://backend.address:backend.port/health_check.path
        // 3. Return true if connection succeeds and response is valid

        // For testing, we simulate based on current status
        matches!(backend.status, BackendStatus::Healthy | BackendStatus::Draining)
    }

    pub async fn get_stats(&self) -> LoadBalancerStats {
        let backends = self.backends.read().await;

        let total_backends = backends.len();
        let healthy_backends = backends.values()
            .filter(|b| matches!(b.status, BackendStatus::Healthy))
            .count();
        let active_connections: u32 = backends.values()
            .map(|b| b.active_connections)
            .sum();
        let total_connections: u64 = backends.values()
            .map(|b| b.total_connections)
            .sum();

        LoadBalancerStats {
            total_backends,
            healthy_backends,
            active_connections,
            total_connections,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResults {
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: usize,
    pub checked: Vec<BackendHealthStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealthStatus {
    pub backend_id: Uuid,
    pub backend_name: String,
    pub status: BackendStatus,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerStats {
    pub total_backends: usize,
    pub healthy_backends: usize,
    pub active_connections: u32,
    pub total_connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_backend_creation() {
        let backend = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );

        assert_eq!(backend.name, "web-1");
        assert_eq!(backend.port, 8080);
        assert_eq!(backend.weight, 100);
        assert!(backend.is_available());
    }

    #[test]
    fn test_backend_health_status() {
        let mut backend = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );

        assert_eq!(backend.status, BackendStatus::Healthy);
        assert_eq!(backend.consecutive_failures, 0);

        backend.mark_unhealthy();
        assert_eq!(backend.status, BackendStatus::Unhealthy);
        assert_eq!(backend.consecutive_failures, 1);

        backend.mark_healthy();
        assert_eq!(backend.status, BackendStatus::Healthy);
        assert_eq!(backend.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn test_load_balancer_creation() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::RoundRobin);

        let backend = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );

        let id = lb.add_backend(backend).await;
        assert!(lb.get_backend(&id).await.is_some());
    }

    #[tokio::test]
    async fn test_round_robin_selection() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::RoundRobin);

        let backend1 = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );
        let backend2 = Backend::new(
            "web-2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            8080,
        );

        lb.add_backend(backend1).await;
        lb.add_backend(backend2).await;

        let selected1 = lb.select_backend(None).await;
        let selected2 = lb.select_backend(None).await;
        let selected3 = lb.select_backend(None).await;

        assert!(selected1.is_some());
        assert!(selected2.is_some());
        assert!(selected3.is_some());

        // Should cycle through backends
        assert_ne!(selected1.as_ref().unwrap().id, selected2.as_ref().unwrap().id);
        assert_eq!(selected1.as_ref().unwrap().id, selected3.as_ref().unwrap().id);
    }

    #[tokio::test]
    async fn test_least_connections_selection() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::LeastConnections);

        let mut backend1 = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );
        backend1.active_connections = 5;

        let backend2 = Backend::new(
            "web-2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            8080,
        );
        // backend2 has 0 active connections

        lb.add_backend(backend1).await;
        lb.add_backend(backend2.clone()).await;

        let selected = lb.select_backend(None).await;
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().id, backend2.id);
    }

    #[tokio::test]
    async fn test_weighted_round_robin() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::WeightedRoundRobin);

        let backend1 = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        ).with_weight(200); // 2x weight

        let backend2 = Backend::new(
            "web-2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            8080,
        ).with_weight(100);

        lb.add_backend(backend1).await;
        lb.add_backend(backend2).await;

        // With 2:1 weight ratio, backend1 should be selected more often
        let mut selections = HashMap::new();
        for _ in 0..300 {
            if let Some(backend) = lb.select_backend(None).await {
                *selections.entry(backend.name).or_insert(0) += 1;
            }
        }

        // backend1 should be selected roughly twice as often
        let web1_count = selections.get("web-1").unwrap_or(&0);
        let web2_count = selections.get("web-2").unwrap_or(&0);
        assert!(*web1_count > *web2_count);
    }

    #[tokio::test]
    async fn test_ip_hash_selection() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::IpHash);

        let backend1 = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );
        let backend2 = Backend::new(
            "web-2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            8080,
        );

        lb.add_backend(backend1).await;
        lb.add_backend(backend2).await;

        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));

        // Same client IP should always get same backend
        let selected1 = lb.select_backend(Some(client_ip)).await;
        let selected2 = lb.select_backend(Some(client_ip)).await;
        let selected3 = lb.select_backend(Some(client_ip)).await;

        assert!(selected1.is_some());
        assert_eq!(selected1.as_ref().unwrap().id, selected2.as_ref().unwrap().id);
        assert_eq!(selected1.as_ref().unwrap().id, selected3.as_ref().unwrap().id);
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::RoundRobin);

        let backend = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );

        let id = lb.add_backend(backend).await;

        lb.increment_connection(&id).await;
        lb.increment_connection(&id).await;

        let backend = lb.get_backend(&id).await.unwrap();
        assert_eq!(backend.active_connections, 2);
        assert_eq!(backend.total_connections, 2);

        lb.decrement_connection(&id).await;
        let backend = lb.get_backend(&id).await.unwrap();
        assert_eq!(backend.active_connections, 1);
    }

    #[tokio::test]
    async fn test_health_checks() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::RoundRobin);

        let backend1 = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );
        let backend2 = Backend::new(
            "web-2",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)),
            8080,
        );

        lb.add_backend(backend1).await;
        lb.add_backend(backend2).await;

        let results = lb.perform_health_checks().await.unwrap();
        assert_eq!(results.total, 2);
        assert_eq!(results.checked.len(), 2);
    }

    #[tokio::test]
    async fn test_stats() {
        let lb = LoadBalancer::new("web-lb", LoadBalancingAlgorithm::RoundRobin);

        let backend = Backend::new(
            "web-1",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            8080,
        );

        let id = lb.add_backend(backend).await;
        lb.increment_connection(&id).await;

        let stats = lb.get_stats().await;
        assert_eq!(stats.total_backends, 1);
        assert_eq!(stats.healthy_backends, 1);
        assert_eq!(stats.active_connections, 1);
    }
}
