//! Policy Custom Resource Definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Policy Custom Resource
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "sdwan.patronus.dev",
    version = "v1alpha1",
    kind = "Policy",
    plural = "policies",
    shortname = "pol",
    status = "PolicyStatus",
    namespaced
)]
#[kube(printcolumn = r#"{"name":"Priority", "type":"integer", "jsonPath":".spec.priority"}"#)]
#[kube(printcolumn = r#"{"name":"Active", "type":"boolean", "jsonPath":".status.active"}"#)]
#[kube(printcolumn = r#"{"name":"Flows", "type":"integer", "jsonPath":".status.matchedFlows"}"#)]
#[kube(printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#)]
pub struct PolicySpec {
    /// Policy priority (0-1000, higher = more important)
    #[schemars(range(min = 0, max = 1000))]
    pub priority: i32,

    /// Match criteria
    #[serde(rename = "match")]
    pub match_criteria: MatchCriteria,

    /// Action to take
    pub action: PolicyAction,

    /// Failover configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failover: Option<FailoverConfig>,
}

/// Match criteria
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct MatchCriteria {
    /// Protocol (tcp, udp, icmp, any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,

    /// Destination port range (e.g., "80", "80-443", "80,443,8080")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port_range: Option<String>,

    /// Source port range
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port_range: Option<String>,

    /// DSCP value (0-63)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0, max = 63))]
    pub dscp: Option<i32>,
}

/// Protocol
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// Policy action
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PolicyAction {
    /// Action type
    #[serde(rename = "type")]
    pub type_: ActionType,

    /// Primary path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_path: Option<PathReference>,

    /// Backup path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathReference>,

    /// QoS configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos: Option<QoSConfig>,
}

/// Action type
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ActionType {
    Route,
    Drop,
    Forward,
}

/// Path reference
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PathReference {
    /// Site name
    pub site_ref: String,

    /// Path ID
    pub path_id: String,
}

/// QoS configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct QoSConfig {
    /// QoS class
    pub class: QoSClass,

    /// Bandwidth limit (e.g., "10Mbps", "1Gbps")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<String>,
}

/// QoS class
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum QoSClass {
    Realtime,
    BusinessCritical,
    BestEffort,
}

/// Failover configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct FailoverConfig {
    /// Health threshold for failover (0-100)
    #[schemars(range(min = 0, max = 100))]
    pub threshold: i32,

    /// Cooldown period (e.g., "30s", "1m")
    pub cooldown: String,
}

/// Policy status
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PolicyStatus {
    /// Whether policy is active
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    /// Number of flows matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_flows: Option<i64>,

    /// Total bytes routed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_routed: Option<i64>,
}

impl Policy {
    /// Check if policy is active
    pub fn is_active(&self) -> bool {
        self.status
            .as_ref()
            .and_then(|s| s.active)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(
            "test-policy",
            PolicySpec {
                priority: 100,
                match_criteria: MatchCriteria {
                    protocol: Some(Protocol::Tcp),
                    dst_port_range: Some("80,443".to_string()),
                    src_port_range: None,
                    dscp: None,
                },
                action: PolicyAction {
                    type_: ActionType::Route,
                    primary_path: None,
                    backup_path: None,
                    qos: Some(QoSConfig {
                        class: QoSClass::BusinessCritical,
                        bandwidth: Some("100Mbps".to_string()),
                    }),
                },
                failover: None,
            },
        );

        assert_eq!(policy.metadata.name, Some("test-policy".to_string()));
        assert_eq!(policy.spec.priority, 100);
    }

    #[test]
    fn test_policy_active_status() {
        let mut policy = Policy::new(
            "test-policy",
            PolicySpec {
                priority: 50,
                match_criteria: MatchCriteria {
                    protocol: Some(Protocol::Udp),
                    dst_port_range: None,
                    src_port_range: None,
                    dscp: None,
                },
                action: PolicyAction {
                    type_: ActionType::Route,
                    primary_path: None,
                    backup_path: None,
                    qos: None,
                },
                failover: None,
            },
        );

        // Not active without status
        assert!(!policy.is_active());

        // Set as active
        policy.status = Some(PolicyStatus {
            active: Some(true),
            matched_flows: Some(100),
            bytes_routed: Some(1024000),
        });

        assert!(policy.is_active());
    }
}
