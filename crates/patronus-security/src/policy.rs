//! Policy Engine (OPA-compatible)

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub effect: Effect,
    pub conditions: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_policies: Vec<String>,
}

pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: Policy) {
        tracing::info!("Adding policy: {}", policy.name);
        self.policies.insert(policy.id.clone(), policy);
    }

    pub fn evaluate(&self, _input: &Value) -> PolicyDecision {
        let mut allowed = false;
        let mut matched_policies = Vec::new();
        let mut reason = "No matching policies".to_string();

        for policy in self.policies.values() {
            for rule in &policy.rules {
                match rule.effect {
                    Effect::Allow => {
                        allowed = true;
                        matched_policies.push(policy.id.clone());
                        reason = format!("Allowed by policy: {}", policy.name);
                        break;
                    }
                    Effect::Deny => {
                        allowed = false;
                        matched_policies.push(policy.id.clone());
                        reason = format!("Denied by policy: {}", policy.name);
                        break;
                    }
                }
            }
        }

        PolicyDecision {
            allowed,
            reason,
            matched_policies,
        }
    }

    pub fn load_rego(&mut self, _rego_policy: &str) -> anyhow::Result<()> {
        // In production: parse and compile Rego policy
        tracing::info!("Loading Rego policy");
        Ok(())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();

        let policy = Policy {
            id: "pol-1".to_string(),
            name: "Allow admins".to_string(),
            rules: vec![Rule {
                effect: Effect::Allow,
                conditions: vec![],
            }],
        };

        engine.add_policy(policy);

        let input = serde_json::json!({"user": "admin"});
        let decision = engine.evaluate(&input);
        assert!(decision.allowed);
    }
}
