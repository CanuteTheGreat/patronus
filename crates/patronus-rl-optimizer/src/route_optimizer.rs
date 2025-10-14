//! Route Optimizer using Reinforcement Learning

use crate::qlearning::{QLearning, QLearningConfig};
use crate::state::{LinkMetrics, NetworkState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RouteState {
    pub current_node: String,
    pub destination: String,
    pub quality_bucket: u8, // 0-10 for discretization
}

impl RouteState {
    pub fn new(current_node: String, destination: String, quality: f64) -> Self {
        let quality_bucket = ((quality / 10.0).floor() as u8).min(10);
        Self {
            current_node,
            destination,
            quality_bucket,
        }
    }

    pub fn to_index(&self, state_map: &HashMap<RouteState, usize>) -> Option<usize> {
        state_map.get(self).copied()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAction {
    pub next_hop: String,
}

impl RouteAction {
    pub fn new(next_hop: String) -> Self {
        Self { next_hop }
    }
}

pub struct RouteOptimizer {
    q_learning: QLearning,
    network_state: NetworkState,
    state_map: HashMap<RouteState, usize>,
    action_map: HashMap<usize, RouteAction>,
    reverse_action_map: HashMap<String, usize>,
    next_state_id: usize,
    next_action_id: usize,
    training_episodes: u64,
}

impl RouteOptimizer {
    pub fn new(config: QLearningConfig) -> Self {
        // Start with reasonable size, will grow as needed
        let q_learning = QLearning::new(1000, 100, config);

        Self {
            q_learning,
            network_state: NetworkState::new(),
            state_map: HashMap::new(),
            action_map: HashMap::new(),
            reverse_action_map: HashMap::new(),
            next_state_id: 0,
            next_action_id: 0,
            training_episodes: 0,
        }
    }

    pub fn add_link(&mut self, link_id: String, metrics: LinkMetrics) {
        self.network_state.add_link(link_id, metrics);
    }

    pub fn update_link_metrics(&mut self, link_id: &str, metrics: LinkMetrics) {
        self.network_state.update_link_metrics(link_id, metrics);
    }

    fn get_or_create_state_id(&mut self, state: RouteState) -> usize {
        if let Some(&id) = self.state_map.get(&state) {
            id
        } else {
            let id = self.next_state_id;
            self.state_map.insert(state, id);
            self.next_state_id += 1;
            id
        }
    }

    fn get_or_create_action_id(&mut self, action: RouteAction) -> usize {
        let next_hop = action.next_hop.clone();
        if let Some(&id) = self.reverse_action_map.get(&next_hop) {
            id
        } else {
            let id = self.next_action_id;
            self.action_map.insert(id, action);
            self.reverse_action_map.insert(next_hop, id);
            self.next_action_id += 1;
            id
        }
    }

    /// Calculate reward for taking an action
    /// Reward is based on path quality and SLA compliance
    fn calculate_reward(&self, path: &[String], destination: &str) -> f64 {
        let metrics = self.network_state.calculate_path_metrics(path);

        // Base reward on path quality (0-100)
        let quality_reward = metrics.quality_score();

        // Penalty for high latency
        let latency_penalty = if metrics.total_latency_ms > 100.0 {
            -50.0
        } else {
            0.0
        };

        // Penalty for packet loss
        let loss_penalty = if metrics.max_packet_loss_percent > 1.0 {
            -50.0
        } else {
            0.0
        };

        // Penalty for congestion
        let congestion_penalty = if metrics.max_utilization_percent > 80.0 {
            -30.0
        } else {
            0.0
        };

        // Bonus for reaching destination
        let destination_bonus = if path.last().map(|s| s.as_str()) == Some(destination) {
            100.0
        } else {
            0.0
        };

        quality_reward + destination_bonus + latency_penalty + loss_penalty + congestion_penalty
    }

    /// Train the optimizer with a routing episode
    pub fn train_episode(
        &mut self,
        source: &str,
        destination: &str,
        available_paths: Vec<Vec<String>>,
    ) -> f64 {
        let mut total_reward = 0.0;

        for path in available_paths {
            if path.is_empty() {
                continue;
            }

            let mut current_path = Vec::new();

            for (i, next_hop) in path.iter().enumerate() {
                current_path.push(next_hop.clone());

                let current_node = if i == 0 {
                    source.to_string()
                } else {
                    path[i - 1].clone()
                };

                // Calculate current network quality
                let quality = if !current_path.is_empty() {
                    self.network_state
                        .calculate_path_metrics(&current_path)
                        .quality_score()
                } else {
                    100.0
                };

                let state = RouteState::new(current_node.clone(), destination.to_string(), quality);
                let state_id = self.get_or_create_state_id(state.clone());

                let action = RouteAction::new(next_hop.clone());
                let action_id = self.get_or_create_action_id(action);

                // Calculate reward
                let reward = self.calculate_reward(&current_path, destination);
                total_reward += reward;

                // Determine next state
                let next_quality = self
                    .network_state
                    .calculate_path_metrics(&current_path)
                    .quality_score();
                let next_state = RouteState::new(next_hop.clone(), destination.to_string(), next_quality);
                let next_state_id = self.get_or_create_state_id(next_state);

                // Check if we reached destination
                let done = next_hop == destination;

                // Update Q-values
                self.q_learning.update(state_id, action_id, reward, next_state_id, done);

                if done {
                    break;
                }
            }
        }

        self.q_learning.decay_epsilon();
        self.training_episodes += 1;

        total_reward
    }

    /// Get optimal next hop using learned policy
    pub fn get_optimal_next_hop(&self, current_node: &str, destination: &str) -> Option<String> {
        // Use current network state to determine quality
        let quality = 100.0; // Start with perfect quality

        let state = RouteState::new(current_node.to_string(), destination.to_string(), quality);

        if let Some(&state_id) = self.state_map.get(&state) {
            let action_id = self.q_learning.get_best_action(state_id);
            self.action_map.get(&action_id).map(|a| a.next_hop.clone())
        } else {
            None
        }
    }

    /// Get full optimized path from source to destination
    pub fn get_optimal_path(&self, source: &str, destination: &str, max_hops: usize) -> Vec<String> {
        let mut path = Vec::new();
        let mut current = source.to_string();
        let mut visited = std::collections::HashSet::new();

        visited.insert(current.clone());

        for _ in 0..max_hops {
            if current == destination {
                break;
            }

            if let Some(next_hop) = self.get_optimal_next_hop(&current, destination) {
                if visited.contains(&next_hop) {
                    // Avoid loops
                    break;
                }

                path.push(next_hop.clone());
                visited.insert(next_hop.clone());
                current = next_hop;
            } else {
                break;
            }
        }

        path
    }

    pub fn get_training_stats(&self) -> TrainingStats {
        TrainingStats {
            episodes_trained: self.q_learning.episodes_trained(),
            total_reward: self.q_learning.total_reward(),
            average_reward: self.q_learning.average_reward(),
            epsilon: self.q_learning.get_epsilon(),
            state_space_size: self.state_map.len(),
            action_space_size: self.action_map.len(),
            q_table_size: self.q_learning.q_table_size(),
        }
    }

    pub fn get_network_state(&self) -> &NetworkState {
        &self.network_state
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingStats {
    pub episodes_trained: u64,
    pub total_reward: f64,
    pub average_reward: f64,
    pub epsilon: f64,
    pub state_space_size: usize,
    pub action_space_size: usize,
    pub q_table_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_state_creation() {
        let state = RouteState::new("node1".to_string(), "dest".to_string(), 85.0);
        assert_eq!(state.current_node, "node1");
        assert_eq!(state.destination, "dest");
        assert_eq!(state.quality_bucket, 8);
    }

    #[test]
    fn test_route_action_creation() {
        let action = RouteAction::new("node2".to_string());
        assert_eq!(action.next_hop, "node2");
    }

    #[test]
    fn test_route_optimizer_creation() {
        let config = QLearningConfig::default();
        let optimizer = RouteOptimizer::new(config);

        assert_eq!(optimizer.state_map.len(), 0);
        assert_eq!(optimizer.action_map.len(), 0);
    }

    #[test]
    fn test_add_link() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        let metrics = LinkMetrics::new().with_latency(10.0);
        optimizer.add_link("link1".to_string(), metrics);

        assert!(optimizer.network_state.get_link_metrics("link1").is_some());
    }

    #[test]
    fn test_update_link_metrics() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        let metrics1 = LinkMetrics::new().with_latency(10.0);
        optimizer.add_link("link1".to_string(), metrics1);

        let metrics2 = LinkMetrics::new().with_latency(20.0);
        optimizer.update_link_metrics("link1", metrics2);

        let updated = optimizer.network_state.get_link_metrics("link1").unwrap();
        assert_eq!(updated.latency_ms, 20.0);
    }

    #[test]
    fn test_train_episode() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.5,
            epsilon_decay: 0.99,
            min_epsilon: 0.01,
        };
        let mut optimizer = RouteOptimizer::new(config);

        // Add links
        optimizer.add_link("link1".to_string(), LinkMetrics::new().with_latency(10.0));
        optimizer.add_link("link2".to_string(), LinkMetrics::new().with_latency(15.0));

        // Train with a simple path
        let paths = vec![vec!["node2".to_string(), "dest".to_string()]];
        let reward = optimizer.train_episode("source", "dest", paths);

        // Should have received some reward
        assert_ne!(reward, 0.0);

        let stats = optimizer.get_training_stats();
        assert_eq!(stats.episodes_trained, 1);
        assert!(stats.state_space_size > 0);
    }

    #[test]
    fn test_multiple_training_episodes() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        optimizer.add_link("link1".to_string(), LinkMetrics::new());
        optimizer.add_link("link2".to_string(), LinkMetrics::new());

        // Train multiple episodes
        for _ in 0..10 {
            let paths = vec![vec!["node2".to_string(), "dest".to_string()]];
            optimizer.train_episode("source", "dest", paths);
        }

        let stats = optimizer.get_training_stats();
        assert_eq!(stats.episodes_trained, 10);
        assert!(stats.q_table_size > 0);
    }

    #[test]
    fn test_get_optimal_path() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.0, // No exploration for deterministic testing
            epsilon_decay: 1.0,
            min_epsilon: 0.0,
        };
        let mut optimizer = RouteOptimizer::new(config);

        optimizer.add_link("link1".to_string(), LinkMetrics::new());
        optimizer.add_link("link2".to_string(), LinkMetrics::new());

        // Train with multiple episodes
        for _ in 0..20 {
            let paths = vec![
                vec!["node2".to_string(), "node3".to_string(), "dest".to_string()],
            ];
            optimizer.train_episode("source", "dest", paths);
        }

        // Get optimal path
        let path = optimizer.get_optimal_path("source", "dest", 10);
        assert!(!path.is_empty());
    }

    #[test]
    fn test_training_stats() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        optimizer.add_link("link1".to_string(), LinkMetrics::new());

        let initial_stats = optimizer.get_training_stats();
        assert_eq!(initial_stats.episodes_trained, 0);
        assert_eq!(initial_stats.total_reward, 0.0);

        // Train one episode
        let paths = vec![vec!["dest".to_string()]];
        optimizer.train_episode("source", "dest", paths);

        let updated_stats = optimizer.get_training_stats();
        assert_eq!(updated_stats.episodes_trained, 1);
        assert!(updated_stats.q_table_size > 0);
    }

    #[test]
    fn test_reward_calculation_with_good_path() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        // Add good quality links
        optimizer.add_link(
            "link1".to_string(),
            LinkMetrics::new()
                .with_latency(10.0)
                .with_packet_loss(0.1)
                .with_utilization(20.0),
        );

        let path = vec!["link1".to_string()];
        let reward = optimizer.calculate_reward(&path, "dest");

        // Good path should have positive reward
        assert!(reward > 0.0);
    }

    #[test]
    fn test_reward_calculation_with_bad_path() {
        let config = QLearningConfig::default();
        let mut optimizer = RouteOptimizer::new(config);

        // Add poor quality link
        optimizer.add_link(
            "link1".to_string(),
            LinkMetrics::new()
                .with_latency(150.0)
                .with_packet_loss(5.0)
                .with_utilization(95.0),
        );

        let path = vec!["link1".to_string()];
        let reward = optimizer.calculate_reward(&path, "other");

        // Bad path should have negative reward
        assert!(reward < 0.0);
    }

    #[test]
    fn test_epsilon_decay_during_training() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 1.0,
            epsilon_decay: 0.9,
            min_epsilon: 0.1,
        };
        let mut optimizer = RouteOptimizer::new(config);

        optimizer.add_link("link1".to_string(), LinkMetrics::new());

        let initial_epsilon = optimizer.get_training_stats().epsilon;
        assert_eq!(initial_epsilon, 1.0);

        // Train one episode
        let paths = vec![vec!["dest".to_string()]];
        optimizer.train_episode("source", "dest", paths);

        let updated_epsilon = optimizer.get_training_stats().epsilon;
        assert!(updated_epsilon < initial_epsilon);
    }
}
