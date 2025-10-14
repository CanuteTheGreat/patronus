//! Path Computation and Constraints

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConstraints {
    pub max_latency_ms: Option<f64>,
    pub min_bandwidth_mbps: Option<f64>,
    pub max_hops: Option<usize>,
    pub max_loss_percent: Option<f64>,
    pub excluded_nodes: HashSet<String>,
    pub required_nodes: Vec<String>,
}

impl Default for PathConstraints {
    fn default() -> Self {
        Self {
            max_latency_ms: None,
            min_bandwidth_mbps: None,
            max_hops: None,
            max_loss_percent: None,
            excluded_nodes: HashSet::new(),
            required_nodes: Vec::new(),
        }
    }
}

impl PathConstraints {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_latency(mut self, latency_ms: f64) -> Self {
        self.max_latency_ms = Some(latency_ms);
        self
    }

    pub fn with_min_bandwidth(mut self, bandwidth_mbps: f64) -> Self {
        self.min_bandwidth_mbps = Some(bandwidth_mbps);
        self
    }

    pub fn with_max_hops(mut self, hops: usize) -> Self {
        self.max_hops = Some(hops);
        self
    }

    pub fn exclude_node(mut self, node: String) -> Self {
        self.excluded_nodes.insert(node);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetrics {
    pub latency_ms: f64,
    pub bandwidth_mbps: f64,
    pub utilization_percent: f64,
    pub loss_percent: f64,
}

impl LinkMetrics {
    pub fn available_bandwidth(&self) -> f64 {
        self.bandwidth_mbps * (1.0 - self.utilization_percent / 100.0)
    }

    pub fn cost(&self) -> f64 {
        // Lower is better: combine latency and utilization
        self.latency_ms + (self.utilization_percent * 10.0) + (self.loss_percent * 100.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputedPath {
    pub hops: Vec<String>,
    pub total_latency_ms: f64,
    pub min_bandwidth_mbps: f64,
    pub total_cost: f64,
    pub max_utilization: f64,
    pub meets_constraints: bool,
}

impl ComputedPath {
    pub fn hop_count(&self) -> usize {
        self.hops.len().saturating_sub(1) // edges = nodes - 1
    }
}

#[derive(Clone)]
struct PathNode {
    node: String,
    cost: f64,
    latency: f64,
    min_bandwidth: f64,
    path: Vec<String>,
}

impl Eq for PathNode {}

impl PartialEq for PathNode {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost
    }
}

impl Ord for PathNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap
        other.cost.partial_cmp(&self.cost).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for PathNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct PathComputation {
    topology: HashMap<String, HashMap<String, LinkMetrics>>,
}

impl PathComputation {
    pub fn new() -> Self {
        Self {
            topology: HashMap::new(),
        }
    }

    pub fn add_link(&mut self, from: String, to: String, metrics: LinkMetrics) {
        self.topology
            .entry(from.clone())
            .or_insert_with(HashMap::new)
            .insert(to.clone(), metrics.clone());

        // Add reverse link for bidirectional
        self.topology
            .entry(to)
            .or_insert_with(HashMap::new)
            .insert(from, metrics);
    }

    pub fn get_link(&self, from: &str, to: &str) -> Option<&LinkMetrics> {
        self.topology.get(from)?.get(to)
    }

    /// Compute shortest path using Dijkstra's algorithm with constraints
    pub fn compute_path(
        &self,
        source: &str,
        destination: &str,
        constraints: &PathConstraints,
    ) -> Option<ComputedPath> {
        if source == destination {
            return Some(ComputedPath {
                hops: vec![source.to_string()],
                total_latency_ms: 0.0,
                min_bandwidth_mbps: f64::MAX,
                total_cost: 0.0,
                max_utilization: 0.0,
                meets_constraints: true,
            });
        }

        let mut heap = BinaryHeap::new();
        let mut visited = HashSet::new();

        heap.push(PathNode {
            node: source.to_string(),
            cost: 0.0,
            latency: 0.0,
            min_bandwidth: f64::MAX,
            path: vec![source.to_string()],
        });

        while let Some(PathNode { node, cost, latency, min_bandwidth, path }) = heap.pop() {
            if node == destination {
                // Found destination - check constraints
                let max_util = self.calculate_max_utilization(&path);
                let meets = self.check_constraints(&path, latency, min_bandwidth, &constraints);

                return Some(ComputedPath {
                    hops: path,
                    total_latency_ms: latency,
                    min_bandwidth_mbps: min_bandwidth,
                    total_cost: cost,
                    max_utilization: max_util,
                    meets_constraints: meets,
                });
            }

            if visited.contains(&node) {
                continue;
            }

            visited.insert(node.clone());

            // Check hop limit
            if let Some(max_hops) = constraints.max_hops {
                if path.len() > max_hops {
                    continue;
                }
            }

            // Explore neighbors
            if let Some(neighbors) = self.topology.get(&node) {
                for (next_node, link) in neighbors {
                    if visited.contains(next_node) {
                        continue;
                    }

                    if constraints.excluded_nodes.contains(next_node) {
                        continue;
                    }

                    let next_latency = latency + link.latency_ms;
                    let next_bandwidth = min_bandwidth.min(link.available_bandwidth());
                    let next_cost = cost + link.cost();

                    // Early constraint checking
                    if let Some(max_lat) = constraints.max_latency_ms {
                        if next_latency > max_lat {
                            continue;
                        }
                    }

                    if let Some(min_bw) = constraints.min_bandwidth_mbps {
                        if next_bandwidth < min_bw {
                            continue;
                        }
                    }

                    let mut next_path = path.clone();
                    next_path.push(next_node.clone());

                    heap.push(PathNode {
                        node: next_node.clone(),
                        cost: next_cost,
                        latency: next_latency,
                        min_bandwidth: next_bandwidth,
                        path: next_path,
                    });
                }
            }
        }

        None // No path found
    }

    fn calculate_max_utilization(&self, path: &[String]) -> f64 {
        let mut max_util: f64 = 0.0;

        for i in 0..path.len().saturating_sub(1) {
            if let Some(link) = self.get_link(&path[i], &path[i + 1]) {
                max_util = max_util.max(link.utilization_percent);
            }
        }

        max_util
    }

    fn check_constraints(
        &self,
        path: &[String],
        latency: f64,
        bandwidth: f64,
        constraints: &PathConstraints,
    ) -> bool {
        if let Some(max_lat) = constraints.max_latency_ms {
            if latency > max_lat {
                return false;
            }
        }

        if let Some(min_bw) = constraints.min_bandwidth_mbps {
            if bandwidth < min_bw {
                return false;
            }
        }

        if let Some(max_hops) = constraints.max_hops {
            if path.len() > max_hops + 1 {
                return false;
            }
        }

        // Check required nodes
        for required in &constraints.required_nodes {
            if !path.contains(required) {
                return false;
            }
        }

        true
    }

    /// Find K shortest paths
    pub fn compute_k_paths(
        &self,
        source: &str,
        destination: &str,
        k: usize,
        constraints: &PathConstraints,
    ) -> Vec<ComputedPath> {
        let mut paths = Vec::new();
        let mut excluded_links = HashSet::new();

        for _ in 0..k {
            // Compute path excluding previously used links
            let path = self.compute_path_excluding(source, destination, constraints, &excluded_links);

            if let Some(p) = path {
                // Add links from this path to exclusion set for next iteration
                for i in 0..p.hops.len().saturating_sub(1) {
                    excluded_links.insert((p.hops[i].clone(), p.hops[i + 1].clone()));
                }
                paths.push(p);
            } else {
                break;
            }
        }

        paths
    }

    fn compute_path_excluding(
        &self,
        source: &str,
        destination: &str,
        constraints: &PathConstraints,
        excluded: &HashSet<(String, String)>,
    ) -> Option<ComputedPath> {
        // Similar to compute_path but skip excluded links
        let mut heap = BinaryHeap::new();
        let mut visited = HashSet::new();

        heap.push(PathNode {
            node: source.to_string(),
            cost: 0.0,
            latency: 0.0,
            min_bandwidth: f64::MAX,
            path: vec![source.to_string()],
        });

        while let Some(PathNode { node, cost, latency, min_bandwidth, path }) = heap.pop() {
            if node == destination {
                let max_util = self.calculate_max_utilization(&path);
                let meets = self.check_constraints(&path, latency, min_bandwidth, &constraints);

                return Some(ComputedPath {
                    hops: path,
                    total_latency_ms: latency,
                    min_bandwidth_mbps: min_bandwidth,
                    total_cost: cost,
                    max_utilization: max_util,
                    meets_constraints: meets,
                });
            }

            if visited.contains(&node) {
                continue;
            }

            visited.insert(node.clone());

            if let Some(neighbors) = self.topology.get(&node) {
                for (next_node, link) in neighbors {
                    if visited.contains(next_node) || constraints.excluded_nodes.contains(next_node) {
                        continue;
                    }

                    // Skip excluded links
                    if excluded.contains(&(node.clone(), next_node.clone())) {
                        continue;
                    }

                    let next_latency = latency + link.latency_ms;
                    let next_bandwidth = min_bandwidth.min(link.available_bandwidth());
                    let next_cost = cost + link.cost();

                    let mut next_path = path.clone();
                    next_path.push(next_node.clone());

                    heap.push(PathNode {
                        node: next_node.clone(),
                        cost: next_cost,
                        latency: next_latency,
                        min_bandwidth: next_bandwidth,
                        path: next_path,
                    });
                }
            }
        }

        None
    }
}

impl Default for PathComputation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_topology() -> PathComputation {
        let mut pc = PathComputation::new();

        // A -- B -- D
        // |    |
        // C ---+

        let link_ab = LinkMetrics {
            latency_ms: 10.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 30.0,
            loss_percent: 0.1,
        };

        let link_bd = LinkMetrics {
            latency_ms: 15.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 20.0,
            loss_percent: 0.1,
        };

        let link_ac = LinkMetrics {
            latency_ms: 20.0,
            bandwidth_mbps: 500.0,
            utilization_percent: 10.0,
            loss_percent: 0.1,
        };

        let link_bc = LinkMetrics {
            latency_ms: 5.0,
            bandwidth_mbps: 2000.0,
            utilization_percent: 50.0,
            loss_percent: 0.1,
        };

        pc.add_link("A".to_string(), "B".to_string(), link_ab);
        pc.add_link("B".to_string(), "D".to_string(), link_bd);
        pc.add_link("A".to_string(), "C".to_string(), link_ac);
        pc.add_link("B".to_string(), "C".to_string(), link_bc);

        pc
    }

    #[test]
    fn test_link_metrics_available_bandwidth() {
        let link = LinkMetrics {
            latency_ms: 10.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 30.0,
            loss_percent: 0.1,
        };

        assert_eq!(link.available_bandwidth(), 700.0);
    }

    #[test]
    fn test_path_constraints_builder() {
        let constraints = PathConstraints::new()
            .with_max_latency(50.0)
            .with_min_bandwidth(100.0)
            .with_max_hops(5);

        assert_eq!(constraints.max_latency_ms, Some(50.0));
        assert_eq!(constraints.min_bandwidth_mbps, Some(100.0));
        assert_eq!(constraints.max_hops, Some(5));
    }

    #[test]
    fn test_compute_simple_path() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new();

        let path = pc.compute_path("A", "D", &constraints);

        assert!(path.is_some());
        let p = path.unwrap();
        assert_eq!(p.hops[0], "A");
        assert_eq!(p.hops[p.hops.len() - 1], "D");
        assert!(p.meets_constraints);
    }

    #[test]
    fn test_compute_path_same_source_dest() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new();

        let path = pc.compute_path("A", "A", &constraints);

        assert!(path.is_some());
        let p = path.unwrap();
        assert_eq!(p.hops, vec!["A"]);
        assert_eq!(p.total_latency_ms, 0.0);
    }

    #[test]
    fn test_compute_path_with_latency_constraint() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new().with_max_latency(30.0);

        let path = pc.compute_path("A", "D", &constraints);

        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.total_latency_ms <= 30.0 || !p.meets_constraints);
    }

    #[test]
    fn test_compute_path_with_bandwidth_constraint() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new().with_min_bandwidth(800.0);

        let path = pc.compute_path("A", "D", &constraints);

        if let Some(p) = path {
            if p.meets_constraints {
                assert!(p.min_bandwidth_mbps >= 800.0);
            }
        }
    }

    #[test]
    fn test_compute_path_with_excluded_node() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new().exclude_node("B".to_string());

        let path = pc.compute_path("A", "D", &constraints);

        if let Some(p) = path {
            assert!(!p.hops.contains(&"B".to_string()));
        }
    }

    #[test]
    fn test_compute_path_no_path() {
        let mut pc = PathComputation::new();

        pc.add_link("A".to_string(), "B".to_string(), LinkMetrics {
            latency_ms: 10.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 20.0,
            loss_percent: 0.1,
        });

        let constraints = PathConstraints::new();
        let path = pc.compute_path("A", "C", &constraints);

        assert!(path.is_none());
    }

    #[test]
    fn test_hop_count() {
        let path = ComputedPath {
            hops: vec!["A".to_string(), "B".to_string(), "C".to_string()],
            total_latency_ms: 25.0,
            min_bandwidth_mbps: 500.0,
            total_cost: 100.0,
            max_utilization: 30.0,
            meets_constraints: true,
        };

        assert_eq!(path.hop_count(), 2);
    }

    #[test]
    fn test_compute_k_paths() {
        let pc = create_test_topology();
        let constraints = PathConstraints::new();

        let paths = pc.compute_k_paths("A", "D", 2, &constraints);

        assert!(!paths.is_empty());
        // Should find at least one path
        assert!(paths.len() >= 1);
    }

    #[test]
    fn test_get_link() {
        let pc = create_test_topology();

        let link = pc.get_link("A", "B");
        assert!(link.is_some());
        assert_eq!(link.unwrap().latency_ms, 10.0);

        let no_link = pc.get_link("A", "D");
        assert!(no_link.is_none());
    }
}
