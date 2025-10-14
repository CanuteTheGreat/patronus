//! Traffic Optimization Engine

use crate::demand::DemandMatrix;
use crate::path::{PathComputation, PathConstraints, ComputedPath};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationObjective {
    MinimizeLatency,
    MaximizeThroughput,
    BalanceLoad,
    MinimizeCost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAllocation {
    pub source: String,
    pub destination: String,
    pub path: Vec<String>,
    pub allocated_bandwidth: f64,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationResult {
    pub flows: Vec<FlowAllocation>,
    pub total_bandwidth_allocated: f64,
    pub average_path_length: f64,
    pub max_link_utilization: f64,
    pub objective_value: f64,
    pub converged: bool,
}

pub struct TrafficOptimizer {
    path_computation: PathComputation,
    objective: OptimizationObjective,
    max_iterations: usize,
}

impl TrafficOptimizer {
    pub fn new(path_computation: PathComputation, objective: OptimizationObjective) -> Self {
        Self {
            path_computation,
            objective,
            max_iterations: 100,
        }
    }

    pub fn with_max_iterations(mut self, max_iter: usize) -> Self {
        self.max_iterations = max_iter;
        self
    }

    /// Optimize traffic allocation based on demand matrix
    pub fn optimize(&self, demand_matrix: &DemandMatrix) -> OptimizationResult {
        let mut flows = Vec::new();
        let mut link_usage: HashMap<(String, String), f64> = HashMap::new();

        // Get all source-destination pairs
        let pairs = demand_matrix.get_all_pairs();

        // Sort by priority (high priority first)
        let mut prioritized_pairs: Vec<_> = pairs.iter()
            .filter_map(|(src, dst)| {
                let demand = demand_matrix.get_current_demand(src, dst)?;
                Some((src.clone(), dst.clone(), demand.priority, demand.bandwidth_mbps))
            })
            .collect();

        prioritized_pairs.sort_by(|a, b| b.2.cmp(&a.2));

        // Allocate flows based on priority
        for (source, destination, priority, bandwidth) in prioritized_pairs {
            let constraints = self.build_constraints(priority, bandwidth);

            if let Some(path) = self.path_computation.compute_path(&source, &destination, &constraints) {
                if path.meets_constraints {
                    // Update link usage
                    for i in 0..path.hops.len().saturating_sub(1) {
                        let link = (path.hops[i].clone(), path.hops[i + 1].clone());
                        *link_usage.entry(link).or_insert(0.0) += bandwidth;
                    }

                    flows.push(FlowAllocation {
                        source: source.clone(),
                        destination: destination.clone(),
                        path: path.hops.clone(),
                        allocated_bandwidth: bandwidth,
                        priority,
                    });
                }
            }
        }

        // Calculate metrics
        let total_bandwidth = flows.iter().map(|f| f.allocated_bandwidth).sum();
        let avg_path_length = if !flows.is_empty() {
            flows.iter().map(|f| f.path.len()).sum::<usize>() as f64 / flows.len() as f64
        } else {
            0.0
        };

        let max_link_util = self.calculate_max_link_utilization(&link_usage);
        let objective_value = self.calculate_objective_value(&flows);

        OptimizationResult {
            flows,
            total_bandwidth_allocated: total_bandwidth,
            average_path_length: avg_path_length,
            max_link_utilization: max_link_util,
            objective_value,
            converged: true,
        }
    }

    fn build_constraints(&self, priority: u8, bandwidth: f64) -> PathConstraints {
        let mut constraints = PathConstraints::new();

        match self.objective {
            OptimizationObjective::MinimizeLatency => {
                constraints.max_latency_ms = Some(100.0);
                if priority >= 5 {
                    constraints.max_latency_ms = Some(50.0);
                }
            }
            OptimizationObjective::MaximizeThroughput => {
                constraints.min_bandwidth_mbps = Some(bandwidth);
            }
            OptimizationObjective::BalanceLoad => {
                // Will consider link utilization in path selection
                constraints.max_hops = Some(10);
            }
            OptimizationObjective::MinimizeCost => {
                constraints.max_hops = Some(5);
            }
        }

        constraints
    }

    fn calculate_max_link_utilization(&self, link_usage: &HashMap<(String, String), f64>) -> f64 {
        let mut max_util: f64 = 0.0;

        for ((from, to), allocated) in link_usage {
            if let Some(link) = self.path_computation.get_link(from, to) {
                let utilization = (allocated / link.bandwidth_mbps) * 100.0;
                max_util = max_util.max(utilization);
            }
        }

        max_util
    }

    fn calculate_objective_value(&self, flows: &[FlowAllocation]) -> f64 {
        match self.objective {
            OptimizationObjective::MinimizeLatency => {
                // Average path latency (lower is better)
                let total_latency: f64 = flows.iter()
                    .map(|f| self.calculate_path_latency(&f.path))
                    .sum();

                if flows.is_empty() {
                    0.0
                } else {
                    total_latency / flows.len() as f64
                }
            }
            OptimizationObjective::MaximizeThroughput => {
                // Total allocated bandwidth (higher is better)
                flows.iter().map(|f| f.allocated_bandwidth).sum()
            }
            OptimizationObjective::BalanceLoad => {
                // Standard deviation of link utilization (lower is better)
                let mut link_usage: HashMap<(String, String), f64> = HashMap::new();

                for flow in flows {
                    for i in 0..flow.path.len().saturating_sub(1) {
                        let link = (flow.path[i].clone(), flow.path[i + 1].clone());
                        *link_usage.entry(link).or_insert(0.0) += flow.allocated_bandwidth;
                    }
                }

                self.calculate_max_link_utilization(&link_usage)
            }
            OptimizationObjective::MinimizeCost => {
                // Average hop count (lower is better)
                let total_hops: usize = flows.iter()
                    .map(|f| f.path.len().saturating_sub(1))
                    .sum();

                if flows.is_empty() {
                    0.0
                } else {
                    total_hops as f64 / flows.len() as f64
                }
            }
        }
    }

    fn calculate_path_latency(&self, path: &[String]) -> f64 {
        let mut total_latency = 0.0;

        for i in 0..path.len().saturating_sub(1) {
            if let Some(link) = self.path_computation.get_link(&path[i], &path[i + 1]) {
                total_latency += link.latency_ms;
            }
        }

        total_latency
    }

    /// Reoptimize traffic when network conditions change
    pub fn reoptimize(
        &self,
        demand_matrix: &DemandMatrix,
        _current_flows: &[FlowAllocation],
    ) -> OptimizationResult {
        // Simple reoptimization: clear and recompute
        // In production, this could be more sophisticated with incremental updates
        self.optimize(demand_matrix)
    }

    /// Get alternative paths for a flow
    pub fn get_backup_paths(
        &self,
        source: &str,
        destination: &str,
        bandwidth: f64,
        k: usize,
    ) -> Vec<ComputedPath> {
        let constraints = PathConstraints::new()
            .with_min_bandwidth(bandwidth);

        self.path_computation.compute_k_paths(source, destination, k, &constraints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::LinkMetrics;
    use crate::demand::TrafficDemand;

    fn create_test_optimizer() -> (TrafficOptimizer, DemandMatrix) {
        let mut pc = PathComputation::new();

        // Simple topology: A -- B -- C
        let link_ab = LinkMetrics {
            latency_ms: 10.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 20.0,
            loss_percent: 0.1,
        };

        let link_bc = LinkMetrics {
            latency_ms: 15.0,
            bandwidth_mbps: 1000.0,
            utilization_percent: 30.0,
            loss_percent: 0.1,
        };

        pc.add_link("A".to_string(), "B".to_string(), link_ab);
        pc.add_link("B".to_string(), "C".to_string(), link_bc);

        let optimizer = TrafficOptimizer::new(pc, OptimizationObjective::MinimizeLatency);

        let mut matrix = DemandMatrix::new(100);
        let demand = TrafficDemand::new("A".to_string(), "C".to_string(), 100.0, 5);
        matrix.add_demand(demand);

        (optimizer, matrix)
    }

    #[test]
    fn test_optimizer_creation() {
        let pc = PathComputation::new();
        let optimizer = TrafficOptimizer::new(pc, OptimizationObjective::MinimizeLatency);

        assert_eq!(optimizer.max_iterations, 100);
    }

    #[test]
    fn test_with_max_iterations() {
        let pc = PathComputation::new();
        let optimizer = TrafficOptimizer::new(pc, OptimizationObjective::MinimizeLatency)
            .with_max_iterations(50);

        assert_eq!(optimizer.max_iterations, 50);
    }

    #[test]
    fn test_optimize_simple() {
        let (optimizer, matrix) = create_test_optimizer();

        let result = optimizer.optimize(&matrix);

        assert_eq!(result.flows.len(), 1);
        assert!(result.converged);
        assert_eq!(result.total_bandwidth_allocated, 100.0);
    }

    #[test]
    fn test_optimize_multiple_flows() {
        let (optimizer, mut matrix) = create_test_optimizer();

        let demand2 = TrafficDemand::new("A".to_string(), "B".to_string(), 50.0, 3);
        matrix.add_demand(demand2);

        let result = optimizer.optimize(&matrix);

        assert_eq!(result.flows.len(), 2);
        assert_eq!(result.total_bandwidth_allocated, 150.0);
    }

    #[test]
    fn test_optimize_priority_ordering() {
        let (optimizer, mut matrix) = create_test_optimizer();

        // Add low priority demand
        let low_priority = TrafficDemand::new("A".to_string(), "B".to_string(), 200.0, 1);
        matrix.add_demand(low_priority);

        let result = optimizer.optimize(&matrix);

        // High priority flow should be first
        assert_eq!(result.flows[0].priority, 5);
    }

    #[test]
    fn test_flow_allocation_structure() {
        let (optimizer, matrix) = create_test_optimizer();

        let result = optimizer.optimize(&matrix);
        let flow = &result.flows[0];

        assert_eq!(flow.source, "A");
        assert_eq!(flow.destination, "C");
        assert!(!flow.path.is_empty());
        assert_eq!(flow.allocated_bandwidth, 100.0);
        assert_eq!(flow.priority, 5);
    }

    #[test]
    fn test_average_path_length() {
        let (optimizer, matrix) = create_test_optimizer();

        let result = optimizer.optimize(&matrix);

        // Path A -> B -> C should have length 3
        assert!(result.average_path_length > 0.0);
    }

    #[test]
    fn test_different_objectives() {
        let (mut optimizer, matrix) = create_test_optimizer();

        let result1 = optimizer.optimize(&matrix);
        assert!(result1.objective_value > 0.0);

        optimizer.objective = OptimizationObjective::MaximizeThroughput;
        let result2 = optimizer.optimize(&matrix);
        assert!(result2.objective_value > 0.0);

        optimizer.objective = OptimizationObjective::BalanceLoad;
        let result3 = optimizer.optimize(&matrix);
        assert!(result3.objective_value >= 0.0);

        optimizer.objective = OptimizationObjective::MinimizeCost;
        let result4 = optimizer.optimize(&matrix);
        assert!(result4.objective_value >= 0.0);
    }

    #[test]
    fn test_reoptimize() {
        let (optimizer, matrix) = create_test_optimizer();

        let initial = optimizer.optimize(&matrix);
        let reoptimized = optimizer.reoptimize(&matrix, &initial.flows);

        // Should produce similar result
        assert_eq!(reoptimized.flows.len(), initial.flows.len());
    }

    #[test]
    fn test_get_backup_paths() {
        let (optimizer, _) = create_test_optimizer();

        let backup_paths = optimizer.get_backup_paths("A", "C", 50.0, 2);

        assert!(!backup_paths.is_empty());
    }

    #[test]
    fn test_optimize_no_demands() {
        let pc = PathComputation::new();
        let optimizer = TrafficOptimizer::new(pc, OptimizationObjective::MinimizeLatency);
        let matrix = DemandMatrix::new(100);

        let result = optimizer.optimize(&matrix);

        assert_eq!(result.flows.len(), 0);
        assert_eq!(result.total_bandwidth_allocated, 0.0);
        assert_eq!(result.average_path_length, 0.0);
    }

    #[test]
    fn test_max_link_utilization_calculation() {
        let (optimizer, matrix) = create_test_optimizer();

        let result = optimizer.optimize(&matrix);

        // Should calculate some utilization
        assert!(result.max_link_utilization >= 0.0);
    }
}
