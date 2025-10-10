//! Policies API endpoints

use axum::{extract::{Path, State}, Json};
use patronus_sdwan::netpolicy::{
    EgressRule, IngressRule, LabelOperator, LabelSelector, NetworkPolicy, NetworkPolicyPort,
    PeerSelector, PolicyId, PolicyType, PortSpec, Protocol,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// List all policies
pub async fn list_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyResponse>>> {
    let policies = state.policy_enforcer.list_policies().await;
    let response: Vec<PolicyResponse> = policies.into_iter().map(|p| p.into()).collect();
    Ok(Json(response))
}

/// Get policy by ID
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<PolicyResponse>> {
    let policy_id = PolicyId::new(
        id.parse()
            .map_err(|_| crate::error::ApiError::InvalidRequest("Invalid policy ID".to_string()))?,
    );

    let policy = state
        .policy_enforcer
        .get_policy(policy_id)
        .await
        .ok_or_else(|| crate::error::ApiError::NotFound(format!("Policy {} not found", id)))?;

    Ok(Json(policy.into()))
}

/// Create policy
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    // Parse the policy from the request
    let policy = parse_policy_request(req)?;

    // Add to enforcer
    state.policy_enforcer.add_policy(policy.clone()).await?;

    Ok(Json(policy.into()))
}

/// Update policy
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    let policy_id = PolicyId::new(
        id.parse()
            .map_err(|_| crate::error::ApiError::InvalidRequest("Invalid policy ID".to_string()))?,
    );

    // Remove old policy
    state.policy_enforcer.remove_policy(policy_id).await?;

    // Create updated policy
    let mut policy = parse_policy_request(CreatePolicyRequest {
        name: req.name,
        namespace: req.namespace,
        spec: req.spec,
    })?;
    policy.id = policy_id; // Keep same ID

    // Add updated policy
    state.policy_enforcer.add_policy(policy.clone()).await?;

    Ok(Json(policy.into()))
}

/// Delete policy
pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let policy_id = PolicyId::new(
        id.parse()
            .map_err(|_| crate::error::ApiError::InvalidRequest("Invalid policy ID".to_string()))?,
    );

    state.policy_enforcer.remove_policy(policy_id).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

/// Policy response
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub pod_selector: LabelSelectorResponse,
    pub policy_types: Vec<String>,
    pub ingress_rules: Vec<IngressRuleResponse>,
    pub egress_rules: Vec<EgressRuleResponse>,
    pub enabled: bool,
    pub priority: u32,
}

impl From<NetworkPolicy> for PolicyResponse {
    fn from(policy: NetworkPolicy) -> Self {
        Self {
            id: policy.id.to_string(),
            name: policy.name,
            namespace: policy.namespace,
            pod_selector: policy.pod_selector.into(),
            policy_types: policy
                .policy_types
                .into_iter()
                .map(|t| format!("{:?}", t))
                .collect(),
            ingress_rules: policy
                .ingress_rules
                .into_iter()
                .map(|r| r.into())
                .collect(),
            egress_rules: policy.egress_rules.into_iter().map(|r| r.into()).collect(),
            enabled: policy.enabled,
            priority: policy.priority,
        }
    }
}

/// Label selector response
#[derive(Debug, Serialize, Deserialize)]
pub struct LabelSelectorResponse {
    pub match_labels: HashMap<String, String>,
    pub match_expressions: Vec<LabelExpressionResponse>,
}

impl From<LabelSelector> for LabelSelectorResponse {
    fn from(selector: LabelSelector) -> Self {
        Self {
            match_labels: selector.match_labels,
            match_expressions: selector
                .match_expressions
                .into_iter()
                .map(|e| LabelExpressionResponse {
                    key: e.key,
                    operator: format!("{:?}", e.operator),
                    values: e.values,
                })
                .collect(),
        }
    }
}

/// Label expression response
#[derive(Debug, Serialize, Deserialize)]
pub struct LabelExpressionResponse {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

/// Ingress rule response
#[derive(Debug, Serialize, Deserialize)]
pub struct IngressRuleResponse {
    pub from: Vec<PeerSelectorResponse>,
    pub ports: Vec<NetworkPolicyPortResponse>,
}

impl From<IngressRule> for IngressRuleResponse {
    fn from(rule: IngressRule) -> Self {
        Self {
            from: rule.from.into_iter().map(|p| p.into()).collect(),
            ports: rule.ports.into_iter().map(|p| p.into()).collect(),
        }
    }
}

/// Egress rule response
#[derive(Debug, Serialize, Deserialize)]
pub struct EgressRuleResponse {
    pub to: Vec<PeerSelectorResponse>,
    pub ports: Vec<NetworkPolicyPortResponse>,
}

impl From<EgressRule> for EgressRuleResponse {
    fn from(rule: EgressRule) -> Self {
        Self {
            to: rule.to.into_iter().map(|p| p.into()).collect(),
            ports: rule.ports.into_iter().map(|p| p.into()).collect(),
        }
    }
}

/// Peer selector response
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PeerSelectorResponse {
    PodSelector {
        namespace: Option<String>,
        selector: LabelSelectorResponse,
    },
    NamespaceSelector {
        selector: LabelSelectorResponse,
    },
    IpBlock {
        cidr: String,
        except: Vec<String>,
    },
}

impl From<PeerSelector> for PeerSelectorResponse {
    fn from(peer: PeerSelector) -> Self {
        match peer {
            PeerSelector::PodSelector {
                namespace,
                selector,
            } => PeerSelectorResponse::PodSelector {
                namespace,
                selector: selector.into(),
            },
            PeerSelector::NamespaceSelector { selector } => {
                PeerSelectorResponse::NamespaceSelector {
                    selector: selector.into(),
                }
            }
            PeerSelector::IpBlock { cidr, except } => {
                PeerSelectorResponse::IpBlock { cidr, except }
            }
        }
    }
}

/// Network policy port response
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkPolicyPortResponse {
    pub protocol: Option<String>,
    pub port: Option<PortSpecResponse>,
    pub end_port: Option<u16>,
}

impl From<NetworkPolicyPort> for NetworkPolicyPortResponse {
    fn from(port: NetworkPolicyPort) -> Self {
        Self {
            protocol: port.protocol.map(|p| format!("{:?}", p)),
            port: port.port.map(|p| p.into()),
            end_port: port.end_port,
        }
    }
}

/// Port spec response
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpecResponse {
    Number(u16),
    Name(String),
}

impl From<PortSpec> for PortSpecResponse {
    fn from(spec: PortSpec) -> Self {
        match spec {
            PortSpec::Number(n) => PortSpecResponse::Number(n),
            PortSpec::Name(s) => PortSpecResponse::Name(s),
        }
    }
}

/// Create policy request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub namespace: String,
    pub spec: PolicySpec,
}

/// Update policy request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePolicyRequest {
    pub name: String,
    pub namespace: String,
    pub spec: PolicySpec,
}

/// Policy specification
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicySpec {
    pub pod_selector: LabelSelectorSpec,
    pub policy_types: Vec<String>,
    #[serde(default)]
    pub ingress: Vec<IngressRuleSpec>,
    #[serde(default)]
    pub egress: Vec<EgressRuleSpec>,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

/// Label selector spec
#[derive(Debug, Serialize, Deserialize)]
pub struct LabelSelectorSpec {
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    #[serde(default)]
    pub match_expressions: Vec<LabelExpressionSpec>,
}

/// Label expression spec
#[derive(Debug, Serialize, Deserialize)]
pub struct LabelExpressionSpec {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

/// Ingress rule spec
#[derive(Debug, Serialize, Deserialize)]
pub struct IngressRuleSpec {
    #[serde(default)]
    pub from: Vec<PeerSelectorSpec>,
    #[serde(default)]
    pub ports: Vec<NetworkPolicyPortSpec>,
}

/// Egress rule spec
#[derive(Debug, Serialize, Deserialize)]
pub struct EgressRuleSpec {
    #[serde(default)]
    pub to: Vec<PeerSelectorSpec>,
    #[serde(default)]
    pub ports: Vec<NetworkPolicyPortSpec>,
}

/// Peer selector spec
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerSelectorSpec {
    PodSelector {
        namespace_selector: Option<LabelSelectorSpec>,
        pod_selector: LabelSelectorSpec,
    },
    IpBlock {
        ip_block: IpBlockSpec,
    },
}

/// IP block spec
#[derive(Debug, Serialize, Deserialize)]
pub struct IpBlockSpec {
    pub cidr: String,
    #[serde(default)]
    pub except: Vec<String>,
}

/// Network policy port spec
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkPolicyPortSpec {
    pub protocol: Option<String>,
    pub port: Option<serde_json::Value>,
    pub end_port: Option<u16>,
}

/// Parse policy request into NetworkPolicy
fn parse_policy_request(req: CreatePolicyRequest) -> Result<NetworkPolicy> {
    let policy_types = req
        .spec
        .policy_types
        .iter()
        .map(|t| match t.as_str() {
            "Ingress" => Ok(PolicyType::Ingress),
            "Egress" => Ok(PolicyType::Egress),
            _ => Err(crate::error::ApiError::InvalidRequest(format!(
                "Invalid policy type: {}",
                t
            ))),
        })
        .collect::<Result<Vec<_>>>()?;

    let pod_selector = parse_label_selector(req.spec.pod_selector)?;

    let ingress_rules = req
        .spec
        .ingress
        .into_iter()
        .map(parse_ingress_rule)
        .collect::<Result<Vec<_>>>()?;

    let egress_rules = req
        .spec
        .egress
        .into_iter()
        .map(parse_egress_rule)
        .collect::<Result<Vec<_>>>()?;

    Ok(NetworkPolicy {
        id: PolicyId::generate(),
        name: req.name,
        namespace: req.namespace,
        pod_selector,
        policy_types,
        ingress_rules,
        egress_rules,
        priority: req.spec.priority,
        enabled: req.spec.enabled,
    })
}

fn parse_label_selector(spec: LabelSelectorSpec) -> Result<LabelSelector> {
    let match_expressions = spec
        .match_expressions
        .into_iter()
        .map(|e| {
            let operator = match e.operator.as_str() {
                "In" => LabelOperator::In,
                "NotIn" => LabelOperator::NotIn,
                "Exists" => LabelOperator::Exists,
                "DoesNotExist" => LabelOperator::DoesNotExist,
                _ => {
                    return Err(crate::error::ApiError::InvalidRequest(format!(
                        "Invalid operator: {}",
                        e.operator
                    )))
                }
            };

            Ok(patronus_sdwan::netpolicy::LabelExpression {
                key: e.key,
                operator,
                values: e.values,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(LabelSelector {
        match_labels: spec.match_labels,
        match_expressions,
    })
}

fn parse_ingress_rule(spec: IngressRuleSpec) -> Result<IngressRule> {
    let from = spec
        .from
        .into_iter()
        .map(parse_peer_selector)
        .collect::<Result<Vec<_>>>()?;

    let ports = spec
        .ports
        .into_iter()
        .map(parse_port)
        .collect::<Result<Vec<_>>>()?;

    Ok(IngressRule { from, ports })
}

fn parse_egress_rule(spec: EgressRuleSpec) -> Result<EgressRule> {
    let to = spec
        .to
        .into_iter()
        .map(parse_peer_selector)
        .collect::<Result<Vec<_>>>()?;

    let ports = spec
        .ports
        .into_iter()
        .map(parse_port)
        .collect::<Result<Vec<_>>>()?;

    Ok(EgressRule { to, ports })
}

fn parse_peer_selector(spec: PeerSelectorSpec) -> Result<PeerSelector> {
    match spec {
        PeerSelectorSpec::PodSelector {
            namespace_selector: _,
            pod_selector,
        } => Ok(PeerSelector::PodSelector {
            namespace: None, // TODO: Parse namespace selector
            selector: parse_label_selector(pod_selector)?,
        }),
        PeerSelectorSpec::IpBlock { ip_block } => Ok(PeerSelector::IpBlock {
            cidr: ip_block.cidr,
            except: ip_block.except,
        }),
    }
}

fn parse_port(spec: NetworkPolicyPortSpec) -> Result<NetworkPolicyPort> {
    let protocol = spec
        .protocol
        .map(|p| match p.as_str() {
            "TCP" => Ok(Protocol::TCP),
            "UDP" => Ok(Protocol::UDP),
            "SCTP" => Ok(Protocol::SCTP),
            _ => Err(crate::error::ApiError::InvalidRequest(format!(
                "Invalid protocol: {}",
                p
            ))),
        })
        .transpose()?;

    let port = spec
        .port
        .map(|p| {
            if p.is_number() {
                Ok(PortSpec::Number(p.as_u64().unwrap() as u16))
            } else if p.is_string() {
                Ok(PortSpec::Name(p.as_str().unwrap().to_string()))
            } else {
                Err(crate::error::ApiError::InvalidRequest(
                    "Invalid port specification".to_string(),
                ))
            }
        })
        .transpose()?;

    Ok(NetworkPolicyPort {
        protocol,
        port,
        end_port: spec.end_port,
    })
}
