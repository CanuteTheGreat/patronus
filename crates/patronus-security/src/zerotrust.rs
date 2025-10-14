//! Zero Trust Security Model

use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustPolicy {
    pub name: String,
    pub source_identity: String,
    pub destination: String,
    pub allowed_actions: Vec<String>,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub key: String,
    pub operator: Operator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    Equals,
    NotEquals,
    Contains,
    In,
    NotIn,
}

pub struct ZeroTrustEngine {
    policies: Vec<ZeroTrustPolicy>,
    trust_scores: HashMap<String, f64>,
}

impl ZeroTrustEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            trust_scores: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: ZeroTrustPolicy) {
        tracing::info!("Adding Zero Trust policy: {}", policy.name);
        self.policies.push(policy);
    }

    pub fn evaluate(&self, source: &str, destination: &str, action: &str, context: &HashMap<String, String>) -> bool {
        // Find matching policies
        for policy in &self.policies {
            if policy.source_identity != source {
                continue;
            }

            if !policy.destination.is_empty() && policy.destination != destination {
                continue;
            }

            if !policy.allowed_actions.contains(&action.to_string()) {
                continue;
            }

            // Check conditions
            let mut conditions_met = true;
            for condition in &policy.conditions {
                if !self.evaluate_condition(condition, context) {
                    conditions_met = false;
                    break;
                }
            }

            if conditions_met {
                // Check trust score
                if let Some(&score) = self.trust_scores.get(source) {
                    if score < 0.5 {
                        tracing::warn!("Low trust score for {}: {}", source, score);
                        return false;
                    }
                }
                return true;
            }
        }

        false // Deny by default
    }

    fn evaluate_condition(&self, condition: &Condition, context: &HashMap<String, String>) -> bool {
        let actual_value = context.get(&condition.key);

        match &condition.operator {
            Operator::Equals => actual_value == Some(&condition.value),
            Operator::NotEquals => actual_value != Some(&condition.value),
            Operator::Contains => actual_value.map(|v| v.contains(&condition.value)).unwrap_or(false),
            _ => false,
        }
    }

    pub fn update_trust_score(&mut self, identity: String, score: f64) {
        self.trust_scores.insert(identity, score.clamp(0.0, 1.0));
    }
}

impl Default for ZeroTrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_trust_allow() {
        let mut engine = ZeroTrustEngine::new();

        let policy = ZeroTrustPolicy {
            name: "allow-admin".to_string(),
            source_identity: "admin@company.com".to_string(),
            destination: "database".to_string(),
            allowed_actions: vec!["read".to_string(), "write".to_string()],
            conditions: vec![],
        };

        engine.add_policy(policy);
        engine.update_trust_score("admin@company.com".to_string(), 0.9);

        let context = HashMap::new();
        let allowed = engine.evaluate("admin@company.com", "database", "read", &context);
        assert!(allowed);
    }

    #[test]
    fn test_zero_trust_deny() {
        let engine = ZeroTrustEngine::new();
        let context = HashMap::new();

        // No policies = deny
        let allowed = engine.evaluate("user@company.com", "database", "read", &context);
        assert!(!allowed);
    }
}
