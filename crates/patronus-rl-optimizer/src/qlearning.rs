//! Q-Learning Implementation
//!
//! Core Q-learning algorithm with epsilon-greedy exploration

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QLearningConfig {
    pub learning_rate: f64,      // α (alpha)
    pub discount_factor: f64,    // γ (gamma)
    pub epsilon: f64,            // ε for exploration
    pub epsilon_decay: f64,      // Decay rate for epsilon
    pub min_epsilon: f64,        // Minimum epsilon value
}

impl Default for QLearningConfig {
    fn default() -> Self {
        Self {
            learning_rate: 0.1,
            discount_factor: 0.95,
            epsilon: 1.0,
            epsilon_decay: 0.995,
            min_epsilon: 0.01,
        }
    }
}

/// Q-Table for storing state-action values
pub struct QTable {
    table: HashMap<(usize, usize), f64>,
    num_states: usize,
    num_actions: usize,
}

impl QTable {
    pub fn new(num_states: usize, num_actions: usize) -> Self {
        Self {
            table: HashMap::new(),
            num_states,
            num_actions,
        }
    }

    pub fn get(&self, state: usize, action: usize) -> f64 {
        *self.table.get(&(state, action)).unwrap_or(&0.0)
    }

    pub fn set(&mut self, state: usize, action: usize, value: f64) {
        self.table.insert((state, action), value);
    }

    pub fn get_best_action(&self, state: usize) -> usize {
        (0..self.num_actions)
            .max_by(|a, b| {
                let q_a = self.get(state, *a);
                let q_b = self.get(state, *b);
                q_a.partial_cmp(&q_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(0)
    }

    pub fn get_max_q_value(&self, state: usize) -> f64 {
        (0..self.num_actions)
            .map(|action| self.get(state, action))
            .fold(f64::NEG_INFINITY, f64::max)
    }

    pub fn size(&self) -> usize {
        self.table.len()
    }
}

pub struct QLearning {
    config: QLearningConfig,
    q_table: QTable,
    current_epsilon: f64,
    episodes_trained: u64,
    total_reward: f64,
}

impl QLearning {
    pub fn new(num_states: usize, num_actions: usize, config: QLearningConfig) -> Self {
        let current_epsilon = config.epsilon;
        Self {
            config,
            q_table: QTable::new(num_states, num_actions),
            current_epsilon,
            episodes_trained: 0,
            total_reward: 0.0,
        }
    }

    /// Select action using epsilon-greedy policy
    pub fn select_action(&self, state: usize) -> usize {
        let mut rng = rand::thread_rng();

        if rng.gen::<f64>() < self.current_epsilon {
            // Explore: random action
            rng.gen_range(0..self.q_table.num_actions)
        } else {
            // Exploit: best known action
            self.q_table.get_best_action(state)
        }
    }

    /// Get best action without exploration
    pub fn get_best_action(&self, state: usize) -> usize {
        self.q_table.get_best_action(state)
    }

    /// Update Q-value using Q-learning update rule
    /// Q(s,a) ← Q(s,a) + α[r + γ max_a' Q(s',a') - Q(s,a)]
    pub fn update(
        &mut self,
        state: usize,
        action: usize,
        reward: f64,
        next_state: usize,
        done: bool,
    ) {
        let current_q = self.q_table.get(state, action);

        let max_next_q = if done {
            0.0 // Terminal state has no future rewards
        } else {
            self.q_table.get_max_q_value(next_state)
        };

        // Q-learning update rule
        let new_q = current_q
            + self.config.learning_rate
                * (reward + self.config.discount_factor * max_next_q - current_q);

        self.q_table.set(state, action, new_q);
        self.total_reward += reward;
    }

    /// Decay exploration rate
    pub fn decay_epsilon(&mut self) {
        self.current_epsilon = (self.current_epsilon * self.config.epsilon_decay)
            .max(self.config.min_epsilon);
        self.episodes_trained += 1;
    }

    pub fn get_epsilon(&self) -> f64 {
        self.current_epsilon
    }

    pub fn episodes_trained(&self) -> u64 {
        self.episodes_trained
    }

    pub fn total_reward(&self) -> f64 {
        self.total_reward
    }

    pub fn average_reward(&self) -> f64 {
        if self.episodes_trained > 0 {
            self.total_reward / self.episodes_trained as f64
        } else {
            0.0
        }
    }

    pub fn q_table_size(&self) -> usize {
        self.q_table.size()
    }

    pub fn get_q_value(&self, state: usize, action: usize) -> f64 {
        self.q_table.get(state, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approx::assert_relative_eq;

    #[test]
    fn test_q_table_creation() {
        let q_table = QTable::new(5, 3);
        assert_eq!(q_table.num_states, 5);
        assert_eq!(q_table.num_actions, 3);
        assert_eq!(q_table.get(0, 0), 0.0);
    }

    #[test]
    fn test_q_table_set_get() {
        let mut q_table = QTable::new(5, 3);
        q_table.set(2, 1, 10.5);
        assert_eq!(q_table.get(2, 1), 10.5);
    }

    #[test]
    fn test_q_table_best_action() {
        let mut q_table = QTable::new(5, 3);
        q_table.set(0, 0, 1.0);
        q_table.set(0, 1, 5.0);
        q_table.set(0, 2, 3.0);

        assert_eq!(q_table.get_best_action(0), 1);
    }

    #[test]
    fn test_q_table_max_q_value() {
        let mut q_table = QTable::new(5, 3);
        q_table.set(0, 0, 1.0);
        q_table.set(0, 1, 5.0);
        q_table.set(0, 2, 3.0);

        assert_eq!(q_table.get_max_q_value(0), 5.0);
    }

    #[test]
    fn test_qlearning_creation() {
        let config = QLearningConfig::default();
        let ql = QLearning::new(10, 4, config);

        assert_eq!(ql.episodes_trained(), 0);
        assert_eq!(ql.total_reward(), 0.0);
        assert_eq!(ql.get_epsilon(), 1.0);
    }

    #[test]
    fn test_qlearning_update() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.0,
            epsilon_decay: 1.0,
            min_epsilon: 0.0,
        };
        let mut ql = QLearning::new(5, 3, config);

        // Initial Q-value should be 0
        assert_eq!(ql.get_q_value(0, 0), 0.0);

        // Update with reward
        ql.update(0, 0, 10.0, 1, false);

        // Q(0,0) = 0 + 0.1 * (10 + 0.9 * 0 - 0) = 1.0
        assert_relative_eq!(ql.get_q_value(0, 0), 1.0, epsilon = 0.001);
    }

    #[test]
    fn test_qlearning_multiple_updates() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.0,
            epsilon_decay: 1.0,
            min_epsilon: 0.0,
        };
        let mut ql = QLearning::new(5, 3, config);

        // First update
        ql.update(0, 0, 10.0, 1, false);
        let q1 = ql.get_q_value(0, 0);

        // Second update (should increase Q-value)
        ql.update(0, 0, 10.0, 1, false);
        let q2 = ql.get_q_value(0, 0);

        assert!(q2 > q1);
    }

    #[test]
    fn test_epsilon_decay() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 1.0,
            epsilon_decay: 0.9,
            min_epsilon: 0.1,
        };
        let mut ql = QLearning::new(5, 3, config);

        assert_eq!(ql.get_epsilon(), 1.0);

        ql.decay_epsilon();
        assert_relative_eq!(ql.get_epsilon(), 0.9, epsilon = 0.001);

        ql.decay_epsilon();
        assert_relative_eq!(ql.get_epsilon(), 0.81, epsilon = 0.001);
    }

    #[test]
    fn test_min_epsilon() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.2,
            epsilon_decay: 0.5,
            min_epsilon: 0.1,
        };
        let mut ql = QLearning::new(5, 3, config);

        ql.decay_epsilon();
        assert_relative_eq!(ql.get_epsilon(), 0.1, epsilon = 0.001);

        ql.decay_epsilon();
        assert_relative_eq!(ql.get_epsilon(), 0.1, epsilon = 0.001);
    }

    #[test]
    fn test_terminal_state() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.0,
            epsilon_decay: 1.0,
            min_epsilon: 0.0,
        };
        let mut ql = QLearning::new(5, 3, config);

        // Update with terminal state (done = true)
        ql.update(0, 0, 10.0, 1, true);

        // Q(0,0) = 0 + 0.1 * (10 + 0 - 0) = 1.0 (no future rewards)
        assert_relative_eq!(ql.get_q_value(0, 0), 1.0, epsilon = 0.001);
    }

    #[test]
    fn test_best_action_selection() {
        let config = QLearningConfig {
            learning_rate: 0.1,
            discount_factor: 0.9,
            epsilon: 0.0, // No exploration
            epsilon_decay: 1.0,
            min_epsilon: 0.0,
        };
        let mut ql = QLearning::new(5, 3, config);

        // Train different actions with different rewards
        ql.update(0, 0, 1.0, 1, false);
        ql.update(0, 1, 10.0, 1, false);
        ql.update(0, 2, 5.0, 1, false);

        // Should select action 1 (highest Q-value)
        assert_eq!(ql.get_best_action(0), 1);
    }

    #[test]
    fn test_average_reward() {
        let config = QLearningConfig::default();
        let mut ql = QLearning::new(5, 3, config);

        assert_eq!(ql.average_reward(), 0.0);

        ql.update(0, 0, 10.0, 1, false);
        ql.decay_epsilon();

        ql.update(1, 1, 20.0, 2, false);
        ql.decay_epsilon();

        assert_eq!(ql.total_reward(), 30.0);
        assert_eq!(ql.average_reward(), 15.0);
    }

    #[test]
    fn test_q_table_size() {
        let config = QLearningConfig::default();
        let mut ql = QLearning::new(5, 3, config);

        assert_eq!(ql.q_table_size(), 0);

        ql.update(0, 0, 10.0, 1, false);
        assert_eq!(ql.q_table_size(), 1);

        ql.update(0, 1, 5.0, 1, false);
        assert_eq!(ql.q_table_size(), 2);
    }
}
