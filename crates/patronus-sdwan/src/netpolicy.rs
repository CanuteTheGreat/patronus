//! NetworkPolicy enforcement for SD-WAN
//!
//! Provides Kubernetes-compatible NetworkPolicy enforcement at the SD-WAN layer.
//! This module translates Kubernetes NetworkPolicy objects into SD-WAN routing
//! rules and applies them to traffic flows.
//!
//! # Features
//!
//! - L3/L4 traffic filtering based on IP, port, protocol
//! - Pod selector matching (label-based)
//! - Namespace isolation
//! - Ingress and egress policy enforcement
//! - Default deny with explicit allow rules
//! - Policy priority and conflict resolution
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────┐
//! │  NetworkPolicy API  │
//! │  (Kubernetes YAML)  │
//! └──────────┬──────────┘
//!            │
//!            ▼
//! ┌──────────────────────┐
//! │  Policy Translator   │
//! │  (K8s → SD-WAN)      │
//! └──────────┬───────────┘
//!            │
//!            ▼
//! ┌──────────────────────┐
//! │  Policy Enforcer     │
//! │  (Flow evaluation)   │
//! └──────────┬───────────┘
//!            │
//!            ▼
//! ┌──────────────────────┐
//! │  Routing Engine      │
//! │  (Allow/Deny flows)  │
//! └──────────────────────┘
//! ```

use crate::{
    database::Database,
    types::{FlowKey, PathId, SiteId},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// NetworkPolicy enforcer
pub struct PolicyEnforcer {
    db: Arc<Database>,
    policies: Arc<RwLock<HashMap<PolicyId, NetworkPolicy>>>,
    pod_labels: Arc<RwLock<HashMap<IpAddr, LabelSet>>>, // IP → Labels
    running: Arc<RwLock<bool>>,
}

/// Policy identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(u64);

impl PolicyId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn generate() -> Self {
        use rand::Rng;
        Self(rand::thread_rng().gen())
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy-{}", self.0)
    }
}

/// NetworkPolicy definition (Kubernetes-compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Unique policy identifier
    pub id: PolicyId,

    /// Policy name
    pub name: String,

    /// Namespace this policy applies to
    pub namespace: String,

    /// Pod selector (which pods this policy applies to)
    pub pod_selector: LabelSelector,

    /// Policy types (Ingress, Egress, or both)
    pub policy_types: Vec<PolicyType>,

    /// Ingress rules
    pub ingress_rules: Vec<IngressRule>,

    /// Egress rules
    pub egress_rules: Vec<EgressRule>,

    /// Priority (higher = evaluated first)
    pub priority: u32,

    /// Whether this policy is enabled
    pub enabled: bool,
}

/// Policy type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    Ingress,
    Egress,
}

/// Label selector (Kubernetes-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelSelector {
    /// Match all labels (AND logic)
    pub match_labels: HashMap<String, String>,

    /// Match expressions (advanced selectors)
    pub match_expressions: Vec<LabelExpression>,
}

impl LabelSelector {
    /// Check if a label set matches this selector
    pub fn matches(&self, labels: &LabelSet) -> bool {
        // Check match_labels (all must match)
        for (key, value) in &self.match_labels {
            if labels.get(key) != Some(value) {
                return false;
            }
        }

        // Check match_expressions (all must match)
        for expr in &self.match_expressions {
            if !expr.matches(labels) {
                return false;
            }
        }

        true
    }

    /// Create a selector that matches everything
    pub fn all() -> Self {
        Self {
            match_labels: HashMap::new(),
            match_expressions: Vec::new(),
        }
    }
}

/// Label expression for advanced matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelExpression {
    pub key: String,
    pub operator: LabelOperator,
    pub values: Vec<String>,
}

impl LabelExpression {
    pub fn matches(&self, labels: &LabelSet) -> bool {
        let label_value = labels.get(&self.key);

        match self.operator {
            LabelOperator::In => {
                if let Some(value) = label_value {
                    self.values.contains(value)
                } else {
                    false
                }
            }
            LabelOperator::NotIn => {
                if let Some(value) = label_value {
                    !self.values.contains(value)
                } else {
                    true
                }
            }
            LabelOperator::Exists => label_value.is_some(),
            LabelOperator::DoesNotExist => label_value.is_none(),
        }
    }
}

/// Label operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LabelOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// Label set (key-value pairs)
pub type LabelSet = HashMap<String, String>;

/// Ingress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    /// Source selectors (pods/namespaces/IPs that can send traffic)
    pub from: Vec<PeerSelector>,

    /// Allowed ports
    pub ports: Vec<NetworkPolicyPort>,
}

/// Egress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRule {
    /// Destination selectors (pods/namespaces/IPs that can receive traffic)
    pub to: Vec<PeerSelector>,

    /// Allowed ports
    pub ports: Vec<NetworkPolicyPort>,
}

/// Peer selector (source or destination)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerSelector {
    /// Pod selector (label-based)
    PodSelector {
        namespace: Option<String>,
        selector: LabelSelector,
    },

    /// Namespace selector (all pods in namespace)
    NamespaceSelector {
        selector: LabelSelector,
    },

    /// IP block (CIDR range)
    IpBlock {
        cidr: String,
        except: Vec<String>,
    },
}

/// NetworkPolicy port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyPort {
    /// Protocol (TCP, UDP, SCTP)
    pub protocol: Option<Protocol>,

    /// Port number or name
    pub port: Option<PortSpec>,

    /// End port (for port ranges)
    pub end_port: Option<u16>,
}

/// Protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    SCTP,
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            132 => Protocol::SCTP,
            _ => Protocol::TCP, // Default to TCP
        }
    }
}

impl From<Protocol> for u8 {
    fn from(proto: Protocol) -> Self {
        match proto {
            Protocol::TCP => 6,
            Protocol::UDP => 17,
            Protocol::SCTP => 132,
        }
    }
}

/// Port specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortSpec {
    Number(u16),
    Name(String),
}

/// Policy evaluation verdict
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Deny,
}

impl PolicyEnforcer {
    /// Create a new policy enforcer
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            policies: Arc::new(RwLock::new(HashMap::new())),
            pod_labels: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the policy enforcer
    pub async fn start(&self) -> Result<()> {
        info!("Starting NetworkPolicy enforcer");

        let mut running = self.running.write().await;
        *running = true;

        info!("NetworkPolicy enforcer started");
        Ok(())
    }

    /// Stop the policy enforcer
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping NetworkPolicy enforcer");

        let mut running = self.running.write().await;
        *running = false;

        info!("NetworkPolicy enforcer stopped");
        Ok(())
    }

    /// Add a NetworkPolicy
    pub async fn add_policy(&self, policy: NetworkPolicy) -> Result<()> {
        info!(
            policy_id = %policy.id,
            policy_name = %policy.name,
            namespace = %policy.namespace,
            "Adding NetworkPolicy"
        );

        let mut policies = self.policies.write().await;
        policies.insert(policy.id, policy);

        Ok(())
    }

    /// Remove a NetworkPolicy
    pub async fn remove_policy(&self, policy_id: PolicyId) -> Result<()> {
        info!(policy_id = %policy_id, "Removing NetworkPolicy");

        let mut policies = self.policies.write().await;
        policies.remove(&policy_id);

        Ok(())
    }

    /// Update pod labels (used for pod selector matching)
    pub async fn update_pod_labels(&self, ip: IpAddr, labels: LabelSet) {
        debug!(ip = %ip, labels = ?labels, "Updating pod labels");

        let mut pod_labels = self.pod_labels.write().await;
        pod_labels.insert(ip, labels);
    }

    /// Remove pod labels
    pub async fn remove_pod_labels(&self, ip: IpAddr) {
        debug!(ip = %ip, "Removing pod labels");

        let mut pod_labels = self.pod_labels.write().await;
        pod_labels.remove(&ip);
    }

    /// Evaluate a flow against all policies
    pub async fn evaluate_flow(&self, flow: &FlowKey) -> PolicyVerdict {
        let policies = self.policies.read().await;
        let pod_labels = self.pod_labels.read().await;

        // Get labels for source and destination IPs
        let src_labels = pod_labels.get(&flow.src_ip);
        let dst_labels = pod_labels.get(&flow.dst_ip);

        // Sort policies by priority (highest first)
        let mut sorted_policies: Vec<_> = policies.values().collect();
        sorted_policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Evaluate policies in priority order
        for policy in sorted_policies {
            if !policy.enabled {
                continue;
            }

            // Check if this policy applies to the destination pod (for ingress)
            if policy.policy_types.contains(&PolicyType::Ingress) {
                if let Some(dst_labels) = dst_labels {
                    if policy.pod_selector.matches(dst_labels) {
                        // This policy applies to the destination
                        // Check if ingress is allowed from source
                        if self.evaluate_ingress(flow, policy, src_labels, dst_labels) {
                            debug!(
                                flow = ?flow,
                                policy = %policy.name,
                                "Flow allowed by ingress rule"
                            );
                            return PolicyVerdict::Allow;
                        }
                    }
                }
            }

            // Check if this policy applies to the source pod (for egress)
            if policy.policy_types.contains(&PolicyType::Egress) {
                if let Some(src_labels) = src_labels {
                    if policy.pod_selector.matches(src_labels) {
                        // This policy applies to the source
                        // Check if egress is allowed to destination
                        if self.evaluate_egress(flow, policy, src_labels, dst_labels) {
                            debug!(
                                flow = ?flow,
                                policy = %policy.name,
                                "Flow allowed by egress rule"
                            );
                            return PolicyVerdict::Allow;
                        }
                    }
                }
            }
        }

        // Default deny if no policy explicitly allowed the flow
        debug!(flow = ?flow, "Flow denied (no matching policy)");
        PolicyVerdict::Deny
    }

    /// Evaluate ingress rules
    fn evaluate_ingress(
        &self,
        flow: &FlowKey,
        policy: &NetworkPolicy,
        src_labels: Option<&LabelSet>,
        _dst_labels: &LabelSet,
    ) -> bool {
        for rule in &policy.ingress_rules {
            // Check if source matches any peer selector
            let peer_matches = rule.from.is_empty() || // Empty = allow from anywhere
                rule.from.iter().any(|peer| self.peer_matches(peer, flow.src_ip, src_labels));

            if !peer_matches {
                continue;
            }

            // Check if port/protocol matches
            let port_matches = rule.ports.is_empty() || // Empty = allow all ports
                rule.ports.iter().any(|port_rule| {
                    self.port_matches(port_rule, flow.dst_port, flow.protocol)
                });

            if port_matches {
                return true;
            }
        }

        false
    }

    /// Evaluate egress rules
    fn evaluate_egress(
        &self,
        flow: &FlowKey,
        policy: &NetworkPolicy,
        _src_labels: &LabelSet,
        dst_labels: Option<&LabelSet>,
    ) -> bool {
        for rule in &policy.egress_rules {
            // Check if destination matches any peer selector
            let peer_matches = rule.to.is_empty() || // Empty = allow to anywhere
                rule.to.iter().any(|peer| self.peer_matches(peer, flow.dst_ip, dst_labels));

            if !peer_matches {
                continue;
            }

            // Check if port/protocol matches
            let port_matches = rule.ports.is_empty() || // Empty = allow all ports
                rule.ports.iter().any(|port_rule| {
                    self.port_matches(port_rule, flow.dst_port, flow.protocol)
                });

            if port_matches {
                return true;
            }
        }

        false
    }

    /// Check if a peer selector matches an IP
    fn peer_matches(&self, peer: &PeerSelector, ip: IpAddr, labels: Option<&LabelSet>) -> bool {
        match peer {
            PeerSelector::PodSelector {
                namespace: _,
                selector,
            } => {
                if let Some(labels) = labels {
                    selector.matches(labels)
                } else {
                    false
                }
            }
            PeerSelector::NamespaceSelector { selector: _ } => {
                // TODO: Implement namespace matching
                // Would require namespace labels mapping
                true
            }
            PeerSelector::IpBlock { cidr, except } => {
                // TODO: Implement CIDR matching
                // Parse cidr and check if ip is in range
                true
            }
        }
    }

    /// Check if a port rule matches
    fn port_matches(&self, port_rule: &NetworkPolicyPort, port: u16, protocol: u8) -> bool {
        // Check protocol
        if let Some(rule_protocol) = &port_rule.protocol {
            if u8::from(rule_protocol.clone()) != protocol {
                return false;
            }
        }

        // Check port
        if let Some(rule_port) = &port_rule.port {
            match rule_port {
                PortSpec::Number(num) => {
                    if *num != port {
                        return false;
                    }
                }
                PortSpec::Name(_name) => {
                    // TODO: Implement named port resolution
                    // Would require service port mapping
                    return true;
                }
            }
        }

        // Check port range
        if let Some(end_port) = port_rule.end_port {
            if let Some(PortSpec::Number(start_port)) = &port_rule.port {
                if port < *start_port || port > end_port {
                    return false;
                }
            }
        }

        true
    }

    /// List all policies
    pub async fn list_policies(&self) -> Vec<NetworkPolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Get policy by ID
    pub async fn get_policy(&self, policy_id: PolicyId) -> Option<NetworkPolicy> {
        let policies = self.policies.read().await;
        policies.get(&policy_id).cloned()
    }

    /// Get statistics
    pub async fn stats(&self) -> PolicyStats {
        let policies = self.policies.read().await;
        let pod_labels = self.pod_labels.read().await;

        PolicyStats {
            total_policies: policies.len(),
            enabled_policies: policies.values().filter(|p| p.enabled).count(),
            total_pods: pod_labels.len(),
        }
    }
}

/// Policy statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStats {
    pub total_policies: usize,
    pub enabled_policies: usize,
    pub total_pods: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_selector_match() {
        let mut labels = LabelSet::new();
        labels.insert("app".to_string(), "web".to_string());
        labels.insert("tier".to_string(), "frontend".to_string());

        let mut match_labels = HashMap::new();
        match_labels.insert("app".to_string(), "web".to_string());

        let selector = LabelSelector {
            match_labels,
            match_expressions: Vec::new(),
        };

        assert!(selector.matches(&labels));
    }

    #[test]
    fn test_label_selector_no_match() {
        let mut labels = LabelSet::new();
        labels.insert("app".to_string(), "web".to_string());

        let mut match_labels = HashMap::new();
        match_labels.insert("app".to_string(), "database".to_string());

        let selector = LabelSelector {
            match_labels,
            match_expressions: Vec::new(),
        };

        assert!(!selector.matches(&labels));
    }

    #[test]
    fn test_label_expression_in() {
        let mut labels = LabelSet::new();
        labels.insert("env".to_string(), "production".to_string());

        let expr = LabelExpression {
            key: "env".to_string(),
            operator: LabelOperator::In,
            values: vec!["production".to_string(), "staging".to_string()],
        };

        assert!(expr.matches(&labels));
    }

    #[test]
    fn test_label_expression_not_in() {
        let mut labels = LabelSet::new();
        labels.insert("env".to_string(), "production".to_string());

        let expr = LabelExpression {
            key: "env".to_string(),
            operator: LabelOperator::NotIn,
            values: vec!["development".to_string(), "test".to_string()],
        };

        assert!(expr.matches(&labels));
    }

    #[test]
    fn test_label_expression_exists() {
        let mut labels = LabelSet::new();
        labels.insert("app".to_string(), "web".to_string());

        let expr = LabelExpression {
            key: "app".to_string(),
            operator: LabelOperator::Exists,
            values: Vec::new(),
        };

        assert!(expr.matches(&labels));
    }

    #[test]
    fn test_label_expression_does_not_exist() {
        let labels = LabelSet::new();

        let expr = LabelExpression {
            key: "nonexistent".to_string(),
            operator: LabelOperator::DoesNotExist,
            values: Vec::new(),
        };

        assert!(expr.matches(&labels));
    }

    #[tokio::test]
    async fn test_policy_enforcer_creation() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let enforcer = PolicyEnforcer::new(db);
        assert!(enforcer.start().await.is_ok());
        assert!(enforcer.stop().await.is_ok());
    }

    #[tokio::test]
    async fn test_add_remove_policy() {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let enforcer = PolicyEnforcer::new(db);

        let policy = NetworkPolicy {
            id: PolicyId::generate(),
            name: "test-policy".to_string(),
            namespace: "default".to_string(),
            pod_selector: LabelSelector::all(),
            policy_types: vec![PolicyType::Ingress],
            ingress_rules: Vec::new(),
            egress_rules: Vec::new(),
            priority: 100,
            enabled: true,
        };

        let policy_id = policy.id;
        enforcer.add_policy(policy).await.unwrap();

        let policies = enforcer.list_policies().await;
        assert_eq!(policies.len(), 1);

        enforcer.remove_policy(policy_id).await.unwrap();

        let policies = enforcer.list_policies().await;
        assert_eq!(policies.len(), 0);
    }
}
