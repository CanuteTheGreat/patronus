//! Site Custom Resource Definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Site Custom Resource
#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "sdwan.patronus.dev",
    version = "v1alpha1",
    kind = "Site",
    plural = "sites",
    shortname = "site",
    status = "SiteStatus",
    namespaced
)]
#[kube(printcolumn = r#"{"name":"Phase", "type":"string", "jsonPath":".status.phase"}"#)]
#[kube(printcolumn = r#"{"name":"Peers", "type":"integer", "jsonPath":".status.peers"}"#)]
#[kube(printcolumn = r#"{"name":"Paths", "type":"integer", "jsonPath":".status.activePaths"}"#)]
#[kube(printcolumn = r#"{"name":"Health", "type":"number", "jsonPath":".status.healthScore"}"#)]
#[kube(printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#)]
pub struct SiteSpec {
    /// Physical location of the site
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// WireGuard configuration
    pub wireguard: WireGuardConfig,

    /// Resource requests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Mesh networking configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh: Option<MeshConfig>,
}

/// WireGuard configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct WireGuardConfig {
    /// WireGuard public key (44 characters, base64 encoded)
    pub public_key: String,

    /// Listen port (1-65535)
    pub listen_port: u16,

    /// Endpoints (IP:port)
    pub endpoints: Vec<String>,
}

/// Resource requirements
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ResourceRequirements {
    /// CPU request (e.g., "2" or "2000m")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// Memory request (e.g., "4Gi")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// Storage request (e.g., "10Gi")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
}

/// Mesh configuration
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct MeshConfig {
    /// Enable mesh networking
    #[serde(default)]
    pub enabled: bool,

    /// Sites to peer with
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_with: Vec<String>,
}

/// Site status
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SiteStatus {
    /// Current phase
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<SitePhase>,

    /// Conditions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<SiteCondition>,

    /// Number of peers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<i32>,

    /// Number of active paths
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_paths: Option<i32>,

    /// Health score (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_score: Option<f64>,
}

/// Site phase
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum SitePhase {
    Pending,
    Active,
    Failed,
    Terminating,
}

/// Site condition
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SiteCondition {
    /// Condition type
    #[serde(rename = "type")]
    pub type_: String,

    /// Status
    pub status: ConditionStatus,

    /// Last transition time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,

    /// Reason
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Condition status
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

impl Site {
    /// Check if site is ready
    pub fn is_ready(&self) -> bool {
        self.status
            .as_ref()
            .and_then(|s| s.phase.as_ref())
            .map(|p| p == &SitePhase::Active)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_site_creation() {
        let site = Site::new(
            "test-site",
            SiteSpec {
                location: Some("Test Location".to_string()),
                wireguard: WireGuardConfig {
                    public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                    listen_port: 51820,
                    endpoints: vec!["192.168.1.1:51820".to_string()],
                },
                resources: None,
                mesh: Some(MeshConfig {
                    enabled: true,
                    peer_with: vec![],
                }),
            },
        );

        assert_eq!(site.metadata.name, Some("test-site".to_string()));
        assert_eq!(site.spec.location, Some("Test Location".to_string()));
    }

    #[test]
    fn test_site_ready_status() {
        let mut site = Site::new(
            "test-site",
            SiteSpec {
                location: None,
                wireguard: WireGuardConfig {
                    public_key: "YjE2OTNkMWQxYzYwZGU3ZWZhMDU4MWU3YzU4MTU4MD0=".to_string(),
                    listen_port: 51820,
                    endpoints: vec!["192.168.1.1:51820".to_string()],
                },
                resources: None,
                mesh: None,
            },
        );

        // Not ready without status
        assert!(!site.is_ready());

        // Set as active
        site.status = Some(SiteStatus {
            phase: Some(SitePhase::Active),
            conditions: vec![],
            peers: None,
            active_paths: None,
            health_score: None,
        });

        assert!(site.is_ready());
    }
}
