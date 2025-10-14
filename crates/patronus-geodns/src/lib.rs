//! Global Traffic Manager with GeoDNS
//!
//! Geographic load balancing and DNS-based traffic steering

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub region: String,
    pub country: String,
}

impl GeoLocation {
    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        // Haversine formula for distance in km
        let r = 6371.0; // Earth radius in km
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        r * c
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub location: GeoLocation,
    pub health: HealthStatus,
    pub weight: u32,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoutingPolicy {
    Geoproximity,
    Latency,
    Weighted,
    Failover,
}

pub struct GeoDNSManager {
    endpoints: Arc<RwLock<HashMap<Uuid, Endpoint>>>,
    policy: RoutingPolicy,
}

impl GeoDNSManager {
    pub fn new(policy: RoutingPolicy) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            policy,
        }
    }

    pub async fn register_endpoint(&self, endpoint: Endpoint) -> Uuid {
        let id = endpoint.id;
        let mut endpoints = self.endpoints.write().await;
        endpoints.insert(id, endpoint);
        id
    }

    pub async fn get_endpoint(&self, id: &Uuid) -> Option<Endpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.get(id).cloned()
    }

    pub async fn update_health(&self, id: &Uuid, health: HealthStatus) -> bool {
        let mut endpoints = self.endpoints.write().await;
        if let Some(endpoint) = endpoints.get_mut(id) {
            endpoint.health = health;
            true
        } else {
            false
        }
    }

    pub async fn list_healthy_endpoints(&self) -> Vec<Endpoint> {
        let endpoints = self.endpoints.read().await;
        endpoints.values()
            .filter(|e| e.health == HealthStatus::Healthy)
            .cloned()
            .collect()
    }

    pub async fn resolve(&self, client_location: &GeoLocation) -> Option<Endpoint> {
        let endpoints = self.endpoints.read().await;
        let healthy: Vec<_> = endpoints.values()
            .filter(|e| e.health == HealthStatus::Healthy)
            .cloned()
            .collect();

        if healthy.is_empty() {
            return None;
        }

        match self.policy {
            RoutingPolicy::Geoproximity => {
                self.resolve_geoproximity(&healthy, client_location)
            }
            RoutingPolicy::Latency => {
                self.resolve_latency(&healthy)
            }
            RoutingPolicy::Weighted => {
                self.resolve_weighted(&healthy)
            }
            RoutingPolicy::Failover => {
                self.resolve_failover(&healthy)
            }
        }
    }

    fn resolve_geoproximity(&self, endpoints: &[Endpoint], client_loc: &GeoLocation) -> Option<Endpoint> {
        endpoints.iter()
            .min_by(|a, b| {
                let dist_a = client_loc.distance_to(&a.location);
                let dist_b = client_loc.distance_to(&b.location);
                dist_a.partial_cmp(&dist_b).unwrap()
            })
            .cloned()
    }

    fn resolve_latency(&self, endpoints: &[Endpoint]) -> Option<Endpoint> {
        endpoints.iter()
            .min_by(|a, b| a.latency_ms.partial_cmp(&b.latency_ms).unwrap())
            .cloned()
    }

    fn resolve_weighted(&self, endpoints: &[Endpoint]) -> Option<Endpoint> {
        let total_weight: u32 = endpoints.iter().map(|e| e.weight).sum();
        if total_weight == 0 {
            return endpoints.first().cloned();
        }

        // Simple weighted selection (in production, use proper random selection)
        let target = (total_weight / 2) as u32;
        let mut cumulative = 0;

        for endpoint in endpoints {
            cumulative += endpoint.weight;
            if cumulative >= target {
                return Some(endpoint.clone());
            }
        }

        endpoints.last().cloned()
    }

    fn resolve_failover(&self, endpoints: &[Endpoint]) -> Option<Endpoint> {
        // Return primary (first healthy endpoint)
        endpoints.first().cloned()
    }

    pub async fn get_region_stats(&self) -> HashMap<String, usize> {
        let endpoints = self.endpoints.read().await;
        let mut stats = HashMap::new();

        for endpoint in endpoints.values() {
            *stats.entry(endpoint.location.region.clone()).or_insert(0) += 1;
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_location(lat: f64, lon: f64) -> GeoLocation {
        GeoLocation {
            latitude: lat,
            longitude: lon,
            region: "us-west".to_string(),
            country: "US".to_string(),
        }
    }

    fn create_test_endpoint(name: &str, lat: f64, lon: f64) -> Endpoint {
        Endpoint {
            id: Uuid::new_v4(),
            name: name.to_string(),
            address: format!("10.0.0.{}", name.len()),
            location: create_test_location(lat, lon),
            health: HealthStatus::Healthy,
            weight: 100,
            latency_ms: 10.0,
        }
    }

    #[test]
    fn test_geolocation_distance() {
        let loc1 = create_test_location(37.7749, -122.4194); // San Francisco
        let loc2 = create_test_location(40.7128, -74.0060);  // New York

        let distance = loc1.distance_to(&loc2);
        assert!(distance > 4000.0 && distance < 5000.0); // ~4130 km
    }

    #[test]
    fn test_endpoint_creation() {
        let endpoint = create_test_endpoint("test", 37.0, -122.0);
        assert_eq!(endpoint.name, "test");
        assert_eq!(endpoint.health, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_geodns_manager_creation() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);
        let healthy = manager.list_healthy_endpoints().await;
        assert_eq!(healthy.len(), 0);
    }

    #[tokio::test]
    async fn test_register_endpoint() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);
        let endpoint = create_test_endpoint("ep1", 37.0, -122.0);
        let id = endpoint.id;

        manager.register_endpoint(endpoint).await;

        let retrieved = manager.get_endpoint(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "ep1");
    }

    #[tokio::test]
    async fn test_update_health() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);
        let endpoint = create_test_endpoint("ep1", 37.0, -122.0);
        let id = endpoint.id;

        manager.register_endpoint(endpoint).await;
        assert!(manager.update_health(&id, HealthStatus::Unhealthy).await);

        let updated = manager.get_endpoint(&id).await.unwrap();
        assert_eq!(updated.health, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_list_healthy_endpoints() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);

        let ep1 = create_test_endpoint("ep1", 37.0, -122.0);
        let mut ep2 = create_test_endpoint("ep2", 40.0, -74.0);
        ep2.health = HealthStatus::Unhealthy;

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;

        let healthy = manager.list_healthy_endpoints().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].name, "ep1");
    }

    #[tokio::test]
    async fn test_resolve_geoproximity() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);

        let ep1 = create_test_endpoint("west", 37.7749, -122.4194); // SF
        let ep2 = create_test_endpoint("east", 40.7128, -74.0060);  // NY

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;

        // Client in SF area
        let client_loc = create_test_location(37.5, -122.0);
        let resolved = manager.resolve(&client_loc).await;

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name, "west");
    }

    #[tokio::test]
    async fn test_resolve_latency() {
        let manager = GeoDNSManager::new(RoutingPolicy::Latency);

        let mut ep1 = create_test_endpoint("slow", 37.0, -122.0);
        ep1.latency_ms = 50.0;

        let mut ep2 = create_test_endpoint("fast", 40.0, -74.0);
        ep2.latency_ms = 10.0;

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;

        let client_loc = create_test_location(35.0, -100.0);
        let resolved = manager.resolve(&client_loc).await;

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name, "fast");
    }

    #[tokio::test]
    async fn test_resolve_weighted() {
        let manager = GeoDNSManager::new(RoutingPolicy::Weighted);

        let mut ep1 = create_test_endpoint("high", 37.0, -122.0);
        ep1.weight = 80;

        let mut ep2 = create_test_endpoint("low", 40.0, -74.0);
        ep2.weight = 20;

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;

        let client_loc = create_test_location(35.0, -100.0);
        let resolved = manager.resolve(&client_loc).await;

        assert!(resolved.is_some());
    }

    #[tokio::test]
    async fn test_resolve_failover() {
        let manager = GeoDNSManager::new(RoutingPolicy::Failover);

        let ep1 = create_test_endpoint("primary", 37.0, -122.0);
        let ep2 = create_test_endpoint("backup", 40.0, -74.0);

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;

        let client_loc = create_test_location(35.0, -100.0);
        let resolved = manager.resolve(&client_loc).await;

        assert!(resolved.is_some());
    }

    #[tokio::test]
    async fn test_resolve_no_healthy_endpoints() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);

        let mut ep1 = create_test_endpoint("unhealthy", 37.0, -122.0);
        ep1.health = HealthStatus::Unhealthy;

        manager.register_endpoint(ep1).await;

        let client_loc = create_test_location(35.0, -100.0);
        let resolved = manager.resolve(&client_loc).await;

        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn test_get_region_stats() {
        let manager = GeoDNSManager::new(RoutingPolicy::Geoproximity);

        let mut ep1 = create_test_endpoint("ep1", 37.0, -122.0);
        ep1.location.region = "us-west".to_string();

        let mut ep2 = create_test_endpoint("ep2", 40.0, -74.0);
        ep2.location.region = "us-east".to_string();

        let mut ep3 = create_test_endpoint("ep3", 37.5, -122.5);
        ep3.location.region = "us-west".to_string();

        manager.register_endpoint(ep1).await;
        manager.register_endpoint(ep2).await;
        manager.register_endpoint(ep3).await;

        let stats = manager.get_region_stats().await;
        assert_eq!(stats.get("us-west"), Some(&2));
        assert_eq!(stats.get("us-east"), Some(&1));
    }
}
