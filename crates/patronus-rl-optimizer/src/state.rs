//! Network State Representation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetrics {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub bandwidth_mbps: f64,
    pub utilization_percent: f64,
    pub cost: f64,
    pub last_updated: DateTime<Utc>,
}

impl LinkMetrics {
    pub fn new() -> Self {
        Self {
            latency_ms: 0.0,
            jitter_ms: 0.0,
            packet_loss_percent: 0.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 0.0,
            cost: 1.0,
            last_updated: Utc::now(),
        }
    }

    pub fn with_latency(mut self, latency_ms: f64) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_jitter(mut self, jitter_ms: f64) -> Self {
        self.jitter_ms = jitter_ms;
        self
    }

    pub fn with_packet_loss(mut self, packet_loss_percent: f64) -> Self {
        self.packet_loss_percent = packet_loss_percent;
        self
    }

    pub fn with_bandwidth(mut self, bandwidth_mbps: f64) -> Self {
        self.bandwidth_mbps = bandwidth_mbps;
        self
    }

    pub fn with_utilization(mut self, utilization_percent: f64) -> Self {
        self.utilization_percent = utilization_percent;
        self
    }

    pub fn with_cost(mut self, cost: f64) -> Self {
        self.cost = cost;
        self
    }

    /// Calculate overall quality score (0-100, higher is better)
    pub fn quality_score(&self) -> f64 {
        let latency_score = (100.0 - self.latency_ms.min(100.0)).max(0.0);
        let jitter_score = (100.0 - self.jitter_ms.min(100.0)).max(0.0);
        let loss_score = (100.0 - self.packet_loss_percent).max(0.0);
        let util_score = (100.0 - self.utilization_percent).max(0.0);

        latency_score * 0.3 + jitter_score * 0.2 + loss_score * 0.3 + util_score * 0.2
    }

    /// Check if link meets SLA requirements
    pub fn meets_sla(&self, max_latency: f64, max_loss: f64) -> bool {
        self.latency_ms <= max_latency && self.packet_loss_percent <= max_loss
    }
}

impl Default for LinkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub links: HashMap<String, LinkMetrics>,
    pub routes: HashMap<String, Vec<String>>, // destination -> path (list of link IDs)
    pub active_flows: HashMap<Uuid, FlowInfo>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            routes: HashMap::new(),
            active_flows: HashMap::new(),
        }
    }

    pub fn add_link(&mut self, link_id: String, metrics: LinkMetrics) {
        self.links.insert(link_id, metrics);
    }

    pub fn update_link_metrics(&mut self, link_id: &str, metrics: LinkMetrics) {
        if let Some(link) = self.links.get_mut(link_id) {
            *link = metrics;
        }
    }

    pub fn get_link_metrics(&self, link_id: &str) -> Option<&LinkMetrics> {
        self.links.get(link_id)
    }

    pub fn set_route(&mut self, destination: String, path: Vec<String>) {
        self.routes.insert(destination, path);
    }

    pub fn get_route(&self, destination: &str) -> Option<&Vec<String>> {
        self.routes.get(destination)
    }

    pub fn add_flow(&mut self, flow: FlowInfo) {
        self.active_flows.insert(flow.id, flow);
    }

    pub fn remove_flow(&mut self, flow_id: &Uuid) {
        self.active_flows.remove(flow_id);
    }

    /// Calculate path metrics for a given route
    pub fn calculate_path_metrics(&self, path: &[String]) -> PathMetrics {
        let mut total_latency: f64 = 0.0;
        let mut max_jitter: f64 = 0.0;
        let mut max_loss: f64 = 0.0;
        let mut min_bandwidth: f64 = f64::MAX;
        let mut max_utilization: f64 = 0.0;
        let mut total_cost: f64 = 0.0;

        for link_id in path {
            if let Some(metrics) = self.links.get(link_id) {
                total_latency += metrics.latency_ms;
                max_jitter = max_jitter.max(metrics.jitter_ms);
                max_loss = max_loss.max(metrics.packet_loss_percent);
                min_bandwidth = min_bandwidth.min(metrics.bandwidth_mbps);
                max_utilization = max_utilization.max(metrics.utilization_percent);
                total_cost += metrics.cost;
            }
        }

        PathMetrics {
            total_latency_ms: total_latency,
            max_jitter_ms: max_jitter,
            max_packet_loss_percent: max_loss,
            min_bandwidth_mbps: min_bandwidth,
            max_utilization_percent: max_utilization,
            total_cost,
            hop_count: path.len(),
        }
    }

    /// Get congested links (utilization > threshold)
    pub fn get_congested_links(&self, threshold: f64) -> Vec<String> {
        self.links
            .iter()
            .filter(|(_, metrics)| metrics.utilization_percent > threshold)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowInfo {
    pub id: Uuid,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub bandwidth_requirement_mbps: f64,
    pub latency_requirement_ms: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    pub total_latency_ms: f64,
    pub max_jitter_ms: f64,
    pub max_packet_loss_percent: f64,
    pub min_bandwidth_mbps: f64,
    pub max_utilization_percent: f64,
    pub total_cost: f64,
    pub hop_count: usize,
}

impl PathMetrics {
    /// Calculate overall path quality score
    pub fn quality_score(&self) -> f64 {
        let latency_score = (100.0 - self.total_latency_ms.min(100.0)).max(0.0);
        let jitter_score = (100.0 - self.max_jitter_ms.min(100.0)).max(0.0);
        let loss_score = (100.0 - self.max_packet_loss_percent).max(0.0);
        let util_score = (100.0 - self.max_utilization_percent).max(0.0);

        latency_score * 0.3 + jitter_score * 0.2 + loss_score * 0.3 + util_score * 0.2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_metrics_creation() {
        let metrics = LinkMetrics::new()
            .with_latency(10.0)
            .with_jitter(2.0)
            .with_packet_loss(0.1)
            .with_bandwidth(1000.0)
            .with_utilization(50.0);

        assert_eq!(metrics.latency_ms, 10.0);
        assert_eq!(metrics.jitter_ms, 2.0);
        assert_eq!(metrics.packet_loss_percent, 0.1);
        assert_eq!(metrics.utilization_percent, 50.0);
    }

    #[test]
    fn test_link_quality_score() {
        let good_link = LinkMetrics::new()
            .with_latency(5.0)
            .with_jitter(1.0)
            .with_packet_loss(0.1)
            .with_utilization(20.0);

        let bad_link = LinkMetrics::new()
            .with_latency(100.0)
            .with_jitter(50.0)
            .with_packet_loss(5.0)
            .with_utilization(95.0);

        // Good link should have much higher score than bad link
        assert!(good_link.quality_score() > bad_link.quality_score());
        assert!(good_link.quality_score() > 80.0);
        // Bad link should have low score (but not necessarily < 20)
        assert!(bad_link.quality_score() < 50.0);
    }

    #[test]
    fn test_sla_compliance() {
        let metrics = LinkMetrics::new()
            .with_latency(10.0)
            .with_packet_loss(0.5);

        assert!(metrics.meets_sla(20.0, 1.0));
        assert!(!metrics.meets_sla(5.0, 1.0));
        assert!(!metrics.meets_sla(20.0, 0.1));
    }

    #[test]
    fn test_network_state_creation() {
        let state = NetworkState::new();
        assert_eq!(state.links.len(), 0);
        assert_eq!(state.routes.len(), 0);
    }

    #[test]
    fn test_add_link() {
        let mut state = NetworkState::new();
        let metrics = LinkMetrics::new().with_latency(10.0);

        state.add_link("link1".to_string(), metrics);
        assert_eq!(state.links.len(), 1);
        assert!(state.get_link_metrics("link1").is_some());
    }

    #[test]
    fn test_update_link_metrics() {
        let mut state = NetworkState::new();
        let metrics1 = LinkMetrics::new().with_latency(10.0);
        state.add_link("link1".to_string(), metrics1);

        let metrics2 = LinkMetrics::new().with_latency(20.0);
        state.update_link_metrics("link1", metrics2);

        let updated = state.get_link_metrics("link1").unwrap();
        assert_eq!(updated.latency_ms, 20.0);
    }

    #[test]
    fn test_routes() {
        let mut state = NetworkState::new();
        let path = vec!["link1".to_string(), "link2".to_string()];

        state.set_route("destination1".to_string(), path.clone());
        assert_eq!(state.get_route("destination1"), Some(&path));
    }

    #[test]
    fn test_calculate_path_metrics() {
        let mut state = NetworkState::new();

        let link1 = LinkMetrics::new()
            .with_latency(10.0)
            .with_jitter(1.0)
            .with_packet_loss(0.1)
            .with_bandwidth(1000.0)
            .with_cost(1.0);

        let link2 = LinkMetrics::new()
            .with_latency(15.0)
            .with_jitter(2.0)
            .with_packet_loss(0.2)
            .with_bandwidth(500.0)
            .with_cost(2.0);

        state.add_link("link1".to_string(), link1);
        state.add_link("link2".to_string(), link2);

        let path = vec!["link1".to_string(), "link2".to_string()];
        let metrics = state.calculate_path_metrics(&path);

        assert_eq!(metrics.total_latency_ms, 25.0);
        assert_eq!(metrics.max_jitter_ms, 2.0);
        assert_eq!(metrics.max_packet_loss_percent, 0.2);
        assert_eq!(metrics.min_bandwidth_mbps, 500.0);
        assert_eq!(metrics.total_cost, 3.0);
        assert_eq!(metrics.hop_count, 2);
    }

    #[test]
    fn test_congested_links() {
        let mut state = NetworkState::new();

        state.add_link(
            "link1".to_string(),
            LinkMetrics::new().with_utilization(50.0),
        );
        state.add_link(
            "link2".to_string(),
            LinkMetrics::new().with_utilization(85.0),
        );
        state.add_link(
            "link3".to_string(),
            LinkMetrics::new().with_utilization(95.0),
        );

        let congested = state.get_congested_links(80.0);
        assert_eq!(congested.len(), 2);
        assert!(congested.contains(&"link2".to_string()));
        assert!(congested.contains(&"link3".to_string()));
    }

    #[test]
    fn test_flow_management() {
        let mut state = NetworkState::new();

        let flow = FlowInfo {
            id: Uuid::new_v4(),
            source: "site1".to_string(),
            destination: "site2".to_string(),
            protocol: "tcp".to_string(),
            bandwidth_requirement_mbps: 100.0,
            latency_requirement_ms: 50.0,
            created_at: Utc::now(),
        };

        let flow_id = flow.id;
        state.add_flow(flow);
        assert_eq!(state.active_flows.len(), 1);

        state.remove_flow(&flow_id);
        assert_eq!(state.active_flows.len(), 0);
    }

    #[test]
    fn test_path_quality_score() {
        let good_path = PathMetrics {
            total_latency_ms: 10.0,
            max_jitter_ms: 1.0,
            max_packet_loss_percent: 0.1,
            min_bandwidth_mbps: 1000.0,
            max_utilization_percent: 20.0,
            total_cost: 1.0,
            hop_count: 2,
        };

        let bad_path = PathMetrics {
            total_latency_ms: 100.0,
            max_jitter_ms: 50.0,
            max_packet_loss_percent: 5.0,
            min_bandwidth_mbps: 10.0,
            max_utilization_percent: 95.0,
            total_cost: 10.0,
            hop_count: 5,
        };

        assert!(good_path.quality_score() > bad_path.quality_score());
    }
}
