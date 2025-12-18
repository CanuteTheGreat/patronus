//! Routing engine - intelligent path selection
//!
//! Selects optimal paths for flows based on:
//! - Path quality metrics (latency, jitter, loss)
//! - Routing policies (application-aware)
//! - Load balancing
//! - Failover requirements

use crate::{database::Database, netpolicy::PolicyEnforcer, policy::*, types::*, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Routing engine selects best path for each flow
pub struct RoutingEngine {
    db: Arc<Database>,
    running: Arc<RwLock<bool>>,
    policies: Arc<RwLock<Vec<RoutingPolicy>>>,
    active_flows: Arc<RwLock<HashMap<FlowKey, PathId>>>,
    netpolicy_enforcer: Option<Arc<PolicyEnforcer>>,
}

impl RoutingEngine {
    /// Create a new routing engine
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            running: Arc::new(RwLock::new(false)),
            policies: Arc::new(RwLock::new(Vec::new())),
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            netpolicy_enforcer: None,
        }
    }

    /// Create a routing engine with NetworkPolicy enforcement
    pub fn with_netpolicy_enforcement(db: Arc<Database>, enforcer: Arc<PolicyEnforcer>) -> Self {
        Self {
            db,
            running: Arc::new(RwLock::new(false)),
            policies: Arc::new(RwLock::new(Vec::new())),
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            netpolicy_enforcer: Some(enforcer),
        }
    }

    /// Start the routing engine
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }

        info!("Starting routing engine");
        *running = true;

        // Load default routing policies
        self.load_default_policies().await;

        Ok(())
    }

    /// Stop the routing engine
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping routing engine");
        *running = false;

        Ok(())
    }

    /// Load default routing policies
    async fn load_default_policies(&self) {
        let mut policies = self.policies.write().await;

        // VoIP/Video - Prioritize low latency and jitter
        policies.push(RoutingPolicy {
            id: 1,
            name: "VoIP/Video".to_string(),
            priority: 1,
            match_rules: MatchRules {
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port_range: Some((5060, 5061)), // SIP
                protocol: None,
                application_class: None,
            },
            path_preference: PathPreference::Custom(PathScoringWeights::latency_sensitive()),
            enabled: true,
        });

        // Gaming - Ultra-low latency
        policies.push(RoutingPolicy {
            id: 2,
            name: "Gaming".to_string(),
            priority: 2,
            match_rules: MatchRules {
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port_range: Some((27000, 28000)), // Steam/Gaming ports
                protocol: Some(17), // UDP
                application_class: None,
            },
            path_preference: PathPreference::LowestLatency,
            enabled: true,
        });

        // Bulk transfers - Prioritize bandwidth
        policies.push(RoutingPolicy {
            id: 3,
            name: "Bulk Transfers".to_string(),
            priority: 3,
            match_rules: MatchRules {
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port_range: Some((20, 21)), // FTP
                protocol: Some(6), // TCP
                application_class: None,
            },
            path_preference: PathPreference::HighestBandwidth,
            enabled: true,
        });

        // Default policy - Balance all metrics
        policies.push(RoutingPolicy {
            id: 100,
            name: "Default".to_string(),
            priority: 100,
            match_rules: MatchRules {
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port_range: None,
                protocol: None,
                application_class: None,
            },
            path_preference: PathPreference::Custom(PathScoringWeights::latency_sensitive()),
            enabled: true,
        });

        info!("Loaded {} default routing policies", policies.len());
    }

    /// Select best path for a flow
    pub async fn select_path(&self, flow: &FlowKey) -> Result<PathId> {
        debug!(
            src = %flow.src_ip,
            dst = %flow.dst_ip,
            sport = flow.src_port,
            dport = flow.dst_port,
            proto = flow.protocol,
            "Selecting path for flow"
        );

        // Check NetworkPolicy enforcement first
        if let Some(ref enforcer) = self.netpolicy_enforcer {
            use crate::netpolicy::PolicyVerdict;
            let verdict = enforcer.evaluate_flow(flow).await;
            if verdict == PolicyVerdict::Deny {
                warn!(
                    flow = ?flow,
                    "Flow denied by NetworkPolicy"
                );
                return Err(crate::Error::InvalidConfig(
                    "Flow denied by NetworkPolicy".to_string(),
                ));
            }
        }

        // Check if flow already has an assigned path
        let flows = self.active_flows.read().await;
        if let Some(path_id) = flows.get(flow) {
            // Verify path is still healthy
            if let Ok(path) = self.db.get_path(*path_id).await {
                if path.status == PathStatus::Up {
                    debug!(path_id = %path_id, "Using existing path for flow");
                    return Ok(*path_id);
                }
            }
        }
        drop(flows);

        // Find matching policy
        let policy = self.find_matching_policy(flow).await;
        debug!(policy = %policy.name, "Matched routing policy");

        // Get all available paths
        let paths = self.db.list_paths().await?;
        if paths.is_empty() {
            return Err(crate::Error::Network("No paths available".to_string()));
        }

        // Filter to only healthy paths
        let healthy_paths: Vec<_> = paths
            .into_iter()
            .filter(|p| p.status == PathStatus::Up || p.status == PathStatus::Degraded)
            .collect();

        if healthy_paths.is_empty() {
            return Err(crate::Error::Network("No healthy paths available".to_string()));
        }

        // Score each path based on policy preference
        let mut path_scores: Vec<(PathId, f64)> = Vec::new();

        for path in healthy_paths {
            // Get latest metrics
            let metrics = match self.db.get_latest_metrics(path.id).await {
                Ok(m) => m,
                Err(_) => {
                    // No metrics yet, use defaults with low score
                    debug!(path_id = %path.id, "No metrics available for path");
                    path_scores.push((path.id, 0.0));
                    continue;
                }
            };

            // Calculate score based on policy
            let score = PolicyMatcher::score_path(&metrics, &policy.path_preference, None);

            debug!(
                path_id = %path.id,
                score = %score,
                latency = %metrics.latency_ms,
                jitter = %metrics.jitter_ms,
                loss = %metrics.packet_loss_pct,
                "Scored path"
            );

            path_scores.push((path.id, score));
        }

        // Sort by score (descending)
        path_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Select best path
        let best_path_id = path_scores[0].0;
        let best_score = path_scores[0].1;

        info!(
            path_id = %best_path_id,
            score = %best_score,
            policy = %policy.name,
            "Selected best path for flow"
        );

        // Store flow assignment
        let mut flows = self.active_flows.write().await;
        flows.insert(*flow, best_path_id);

        Ok(best_path_id)
    }

    /// Find matching routing policy for a flow
    async fn find_matching_policy(&self, flow: &FlowKey) -> RoutingPolicy {
        let policies = self.policies.read().await;

        // Find first matching policy (sorted by priority)
        for policy in policies.iter() {
            if !policy.enabled {
                continue;
            }

            if PolicyMatcher::matches(flow, &policy.match_rules) {
                return policy.clone();
            }
        }

        // Should never happen since we have a default catch-all policy
        warn!("No matching policy found, using default");
        policies.last().unwrap().clone()
    }

    /// Get path for an active flow
    pub async fn get_flow_path(&self, flow: &FlowKey) -> Option<PathId> {
        self.active_flows.read().await.get(flow).copied()
    }

    /// Remove flow from active tracking
    pub async fn remove_flow(&self, flow: &FlowKey) {
        self.active_flows.write().await.remove(flow);
    }

    /// Get all active flows
    pub async fn list_active_flows(&self) -> Vec<(FlowKey, PathId)> {
        self.active_flows
            .read()
            .await
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    /// Add custom routing policy
    pub async fn add_policy(&self, policy: RoutingPolicy) {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        // Re-sort by priority
        policies.sort_by_key(|p| p.priority);
    }

    /// Remove routing policy by name
    pub async fn remove_policy(&self, name: &str) {
        let mut policies = self.policies.write().await;
        policies.retain(|p| p.name != name);
    }

    /// List all routing policies
    pub async fn list_policies(&self) -> Vec<RoutingPolicy> {
        self.policies.read().await.clone()
    }

    /// Trigger path re-evaluation for all flows
    pub async fn reevaluate_all_flows(&self) -> Result<()> {
        info!("Re-evaluating paths for all active flows");

        let flows: Vec<FlowKey> = self.active_flows.read().await.keys().copied().collect();

        for flow in flows {
            // Remove existing assignment
            self.remove_flow(&flow).await;

            // Re-select path
            if let Err(e) = self.select_path(&flow).await {
                warn!(
                    flow = ?flow,
                    error = %e,
                    "Failed to re-select path for flow"
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_routing_engine_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let engine = RoutingEngine::new(db);

        assert!(engine.start().await.is_ok());
        assert!(engine.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_default_policies() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let engine = RoutingEngine::new(db);
        engine.start().await.unwrap();

        let policies = engine.list_policies().await;
        assert!(policies.len() >= 4); // Should have at least 4 default policies
        assert!(policies.iter().any(|p| p.name == "VoIP/Video"));
        assert!(policies.iter().any(|p| p.name == "Gaming"));
        assert!(policies.iter().any(|p| p.name == "Default"));
    }

    #[tokio::test]
    async fn test_policy_matching() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let engine = RoutingEngine::new(db);
        engine.start().await.unwrap();

        // VoIP flow
        let voip_flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 5060,
            protocol: 17, // UDP
        };

        let policy = engine.find_matching_policy(&voip_flow).await;
        assert_eq!(policy.name, "VoIP/Video");

        // Default flow
        let default_flow = FlowKey {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            protocol: 6, // TCP
        };

        let policy = engine.find_matching_policy(&default_flow).await;
        assert_eq!(policy.name, "Default");
    }
}
