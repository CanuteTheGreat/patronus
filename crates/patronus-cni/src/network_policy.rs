use anyhow::{Context, Result};
use futures::StreamExt;
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPort,
};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Client, ResourceExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::ebpf_datapath::{EbpfDatapath, PolicyVerdict};

/// Parsed network policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub namespace: String,
    pub pod_selector: HashMap<String, String>,
    pub policy_type: PolicyType,
    pub ingress_rules: Vec<IngressRule>,
    pub egress_rules: Vec<EgressRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyType {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Clone)]
pub struct IngressRule {
    pub from_sources: Vec<PeerSelector>,
    pub to_ports: Vec<PortRule>,
}

#[derive(Debug, Clone)]
pub struct EgressRule {
    pub to_destinations: Vec<PeerSelector>,
    pub to_ports: Vec<PortRule>,
}

#[derive(Debug, Clone)]
pub enum PeerSelector {
    PodSelector {
        namespace: Option<String>,
        labels: HashMap<String, String>,
    },
    NamespaceSelector {
        labels: HashMap<String, String>,
    },
    IpBlock {
        cidr: String,
        except: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct PortRule {
    pub protocol: String, // TCP, UDP, SCTP
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

/// Network policy controller
pub struct NetworkPolicyController {
    client: Client,
    policies: Arc<RwLock<HashMap<String, PolicyRule>>>,
    datapath: Arc<EbpfDatapath>,
    #[allow(dead_code)]
    pod_to_policy: Arc<RwLock<HashMap<String, Vec<String>>>>, // pod_key -> policy_names
}

/// Parse a single `NetworkPolicyPort` entry into a `PortRule`.
///
/// Returns `None` (dropping the port entry entirely) if a port or
/// end_port value is present but out of the valid u16 range (0-65535) or
/// otherwise unparseable. This must *not* fall back to `port: None`
/// (which in `PortRule` semantics means "no port restriction, matches
/// anything") -- doing so would silently widen a narrowly-scoped rule
/// into an allow-all-ports rule instead of rejecting the malformed
/// input, which is the opposite of fail-safe for a firewall/network
/// policy engine. Previously this used `as u16`, which wraps
/// out-of-range integers (e.g. 70000 -> 4464) instead of rejecting them,
/// silently wiring up a rule for the wrong port.
fn parse_port_rule(p: &NetworkPolicyPort) -> Option<PortRule> {
    let protocol = p.protocol.clone().unwrap_or_else(|| "TCP".to_string());

    let port = match p.port.as_ref() {
        Some(IntOrString::Int(i)) => match u16::try_from(*i) {
            Ok(port) => Some(port),
            Err(_) => {
                warn!(
                    "NetworkPolicy port {} is out of range (0-65535); dropping this port rule instead of silently wrapping it",
                    i
                );
                return None;
            }
        },
        Some(IntOrString::String(s)) => match s.parse::<u16>() {
            Ok(port) => Some(port),
            Err(_) => {
                warn!(
                    "NetworkPolicy named/string port {:?} could not be parsed as a u16 port number; dropping this port rule",
                    s
                );
                return None;
            }
        },
        None => None,
    };

    let end_port = match p.end_port {
        Some(e) => match u16::try_from(e) {
            Ok(end_port) => Some(end_port),
            Err(_) => {
                warn!(
                    "NetworkPolicy end_port {} is out of range (0-65535); dropping this port rule instead of silently wrapping it",
                    e
                );
                return None;
            }
        },
        None => None,
    };

    Some(PortRule {
        protocol,
        port,
        end_port,
    })
}

impl NetworkPolicyController {
    pub async fn new(datapath: Arc<EbpfDatapath>) -> Result<Self> {
        let client = Client::try_default()
            .await
            .context("Failed to create Kubernetes client")?;

        Ok(Self {
            client,
            policies: Arc::new(RwLock::new(HashMap::new())),
            datapath,
            pod_to_policy: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Start watching for NetworkPolicy changes
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Starting Network Policy controller");

        let policies: Api<NetworkPolicy> = Api::all(self.client.clone());

        let watcher_config = watcher::Config::default();
        let mut stream = watcher(policies, watcher_config).applied_objects().boxed();

        while let Some(event) = stream.next().await {
            match event {
                Ok(policy) => {
                    if let Err(e) = self.handle_policy_event(policy).await {
                        warn!("Failed to handle policy event: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Policy watch error: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_policy_event(&self, policy: NetworkPolicy) -> Result<()> {
        let name = policy.name_any();
        let namespace = policy.namespace().unwrap_or_default();

        info!("Processing NetworkPolicy {}/{}", namespace, name);

        // Parse the policy
        let parsed_policy = self.parse_network_policy(&policy)?;

        // Store policy
        let policy_key = format!("{}/{}", namespace, name);
        self.policies
            .write()
            .await
            .insert(policy_key.clone(), parsed_policy.clone());

        // Apply policy to eBPF datapath
        self.apply_policy_to_datapath(&parsed_policy).await?;

        Ok(())
    }

    fn parse_network_policy(&self, policy: &NetworkPolicy) -> Result<PolicyRule> {
        let _name = policy.name_any();
        let namespace = policy.namespace().unwrap_or_default();
        let spec = policy.spec.as_ref().context("Policy has no spec")?;

        // Parse pod selector (convert BTreeMap to HashMap)
        let pod_selector: HashMap<String, String> = spec
            .pod_selector
            .match_labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Determine policy types
        let policy_type = if let Some(types) = &spec.policy_types {
            if types.contains(&"Ingress".to_string()) && types.contains(&"Egress".to_string()) {
                PolicyType::Both
            } else if types.contains(&"Ingress".to_string()) {
                PolicyType::Ingress
            } else {
                PolicyType::Egress
            }
        } else {
            // Default based on what rules are defined
            if spec.ingress.is_some() && spec.egress.is_some() {
                PolicyType::Both
            } else if spec.ingress.is_some() {
                PolicyType::Ingress
            } else {
                PolicyType::Egress
            }
        };

        // Parse ingress rules
        let ingress_rules = if let Some(ingress) = &spec.ingress {
            ingress.iter().map(|r| self.parse_ingress_rule(r)).collect()
        } else {
            Vec::new()
        };

        // Parse egress rules
        let egress_rules = if let Some(egress) = &spec.egress {
            egress.iter().map(|r| self.parse_egress_rule(r)).collect()
        } else {
            Vec::new()
        };

        Ok(PolicyRule {
            namespace,
            pod_selector,
            policy_type,
            ingress_rules,
            egress_rules,
        })
    }

    fn parse_ingress_rule(&self, rule: &NetworkPolicyIngressRule) -> IngressRule {
        let from_sources = if let Some(from) = &rule.from {
            from.iter()
                .filter_map(|peer| {
                    if let Some(pod_sel) = &peer.pod_selector {
                        Some(PeerSelector::PodSelector {
                            namespace: peer.namespace_selector.as_ref().and_then(|ns| {
                                ns.match_labels.as_ref().and_then(|labels| {
                                    labels.get("kubernetes.io/metadata.name").cloned()
                                })
                            }),
                            labels: pod_sel
                                .match_labels
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
                        })
                    } else if let Some(ns_sel) = &peer.namespace_selector {
                        Some(PeerSelector::NamespaceSelector {
                            labels: ns_sel
                                .match_labels
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
                        })
                    } else {
                        peer.ip_block
                            .as_ref()
                            .map(|ip_block| PeerSelector::IpBlock {
                                cidr: ip_block.cidr.clone(),
                                except: ip_block.except.clone().unwrap_or_default(),
                            })
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let to_ports = if let Some(ports) = &rule.ports {
            ports.iter().filter_map(parse_port_rule).collect()
        } else {
            Vec::new()
        };

        IngressRule {
            from_sources,
            to_ports,
        }
    }

    fn parse_egress_rule(&self, rule: &NetworkPolicyEgressRule) -> EgressRule {
        let to_destinations = if let Some(to) = &rule.to {
            to.iter()
                .filter_map(|peer| {
                    if let Some(pod_sel) = &peer.pod_selector {
                        Some(PeerSelector::PodSelector {
                            namespace: peer.namespace_selector.as_ref().and_then(|ns| {
                                ns.match_labels.as_ref().and_then(|labels| {
                                    labels.get("kubernetes.io/metadata.name").cloned()
                                })
                            }),
                            labels: pod_sel
                                .match_labels
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
                        })
                    } else if let Some(ns_sel) = &peer.namespace_selector {
                        Some(PeerSelector::NamespaceSelector {
                            labels: ns_sel
                                .match_labels
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
                        })
                    } else {
                        peer.ip_block
                            .as_ref()
                            .map(|ip_block| PeerSelector::IpBlock {
                                cidr: ip_block.cidr.clone(),
                                except: ip_block.except.clone().unwrap_or_default(),
                            })
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        let to_ports = if let Some(ports) = &rule.ports {
            ports.iter().filter_map(parse_port_rule).collect()
        } else {
            Vec::new()
        };

        EgressRule {
            to_destinations,
            to_ports,
        }
    }

    async fn apply_policy_to_datapath(&self, policy: &PolicyRule) -> Result<()> {
        info!(
            "Applying policy to eBPF datapath for namespace {}",
            policy.namespace
        );

        // Get all pod endpoints
        let endpoints = self.datapath.list_endpoints().await;

        // Find pods that match this policy's selector
        for endpoint in endpoints {
            if endpoint.namespace != policy.namespace {
                continue;
            }

            // Check if pod matches selector (simplified - would need to query pod labels)
            let matches_selector = self
                .pod_matches_selector(&endpoint.pod_name, &policy.pod_selector)
                .await;

            if matches_selector {
                // Apply ingress rules
                for ingress_rule in &policy.ingress_rules {
                    self.apply_ingress_rule_to_pod(&endpoint.pod_ip, ingress_rule)
                        .await?;
                }

                // Apply egress rules
                for egress_rule in &policy.egress_rules {
                    self.apply_egress_rule_from_pod(&endpoint.pod_ip, egress_rule)
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn pod_matches_selector(
        &self,
        _pod_name: &str,
        _selector: &HashMap<String, String>,
    ) -> bool {
        // In production, this would query the pod's labels from Kubernetes API
        // and match against the selector
        // For now, return true (apply to all pods)
        true
    }

    async fn apply_ingress_rule_to_pod(&self, pod_ip: &IpAddr, rule: &IngressRule) -> Result<()> {
        debug!("Applying ingress rule to pod {}", pod_ip);

        // For each source in the rule
        for source in &rule.from_sources {
            match source {
                PeerSelector::IpBlock { cidr, except: _ } => {
                    // Parse CIDR and update eBPF map
                    // Allow traffic from CIDR except the exceptions
                    info!("Allow ingress from CIDR {} to {}", cidr, pod_ip);

                    // Convert CIDR to IP (simplified)
                    let src_ip = self.parse_cidr_to_ip(cidr);
                    self.datapath
                        .update_policy(*pod_ip, src_ip, *pod_ip, PolicyVerdict::Allow)
                        .await?;
                }
                PeerSelector::PodSelector { namespace, labels } => {
                    // Would resolve pod IPs matching the selector
                    debug!(
                        "Allow ingress from pod selector in namespace {:?} with labels {:?}",
                        namespace, labels
                    );
                }
                PeerSelector::NamespaceSelector { labels } => {
                    // Would resolve all pods in matching namespaces
                    debug!("Allow ingress from namespace selector {:?}", labels);
                }
            }
        }

        // If no sources specified, allow from anywhere
        if rule.from_sources.is_empty() {
            debug!("Allow ingress from anywhere to {}", pod_ip);
        }

        Ok(())
    }

    async fn apply_egress_rule_from_pod(&self, pod_ip: &IpAddr, rule: &EgressRule) -> Result<()> {
        debug!("Applying egress rule from pod {}", pod_ip);

        // For each destination in the rule
        for dest in &rule.to_destinations {
            match dest {
                PeerSelector::IpBlock { cidr, except: _ } => {
                    info!("Allow egress to CIDR {} from {}", cidr, pod_ip);

                    let dst_ip = self.parse_cidr_to_ip(cidr);
                    self.datapath
                        .update_policy(*pod_ip, *pod_ip, dst_ip, PolicyVerdict::Allow)
                        .await?;
                }
                PeerSelector::PodSelector { namespace, labels } => {
                    debug!(
                        "Allow egress to pod selector in namespace {:?} with labels {:?}",
                        namespace, labels
                    );
                }
                PeerSelector::NamespaceSelector { labels } => {
                    debug!("Allow egress to namespace selector {:?}", labels);
                }
            }
        }

        Ok(())
    }

    fn parse_cidr_to_ip(&self, cidr: &str) -> IpAddr {
        use std::str::FromStr;

        // Extract IP part from CIDR
        let ip_str = cidr.split('/').next().unwrap_or("0.0.0.0");
        IpAddr::from_str(ip_str).unwrap_or(IpAddr::from_str("0.0.0.0").unwrap())
    }

    /// Get all active policies
    pub async fn list_policies(&self) -> Vec<PolicyRule> {
        self.policies.read().await.values().cloned().collect()
    }

    /// Get policy by name
    pub async fn get_policy(&self, namespace: &str, name: &str) -> Option<PolicyRule> {
        let key = format!("{}/{}", namespace, name);
        self.policies.read().await.get(&key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        use std::str::FromStr;

        // Test CIDR parsing directly without controller
        fn parse_cidr_to_ip(cidr: &str) -> IpAddr {
            let ip_str = cidr.split('/').next().unwrap_or("0.0.0.0");
            IpAddr::from_str(ip_str).unwrap_or(IpAddr::from_str("0.0.0.0").unwrap())
        }

        let ip = parse_cidr_to_ip("192.168.1.0/24");
        assert_eq!(ip.to_string(), "192.168.1.0");

        let ip2 = parse_cidr_to_ip("10.0.0.0/8");
        assert_eq!(ip2.to_string(), "10.0.0.0");
    }

    fn port_spec(port: Option<IntOrString>, end_port: Option<i32>) -> NetworkPolicyPort {
        NetworkPolicyPort {
            end_port,
            port,
            protocol: None,
        }
    }

    #[test]
    fn test_parse_port_rule_valid_numeric_port() {
        let rule = parse_port_rule(&port_spec(Some(IntOrString::Int(443)), None)).unwrap();
        assert_eq!(rule.protocol, "TCP");
        assert_eq!(rule.port, Some(443));
        assert_eq!(rule.end_port, None);
    }

    #[test]
    fn test_parse_port_rule_valid_named_port() {
        let rule =
            parse_port_rule(&port_spec(Some(IntOrString::String("8080".into())), None)).unwrap();
        assert_eq!(rule.port, Some(8080));
    }

    #[test]
    fn test_parse_port_rule_no_port_restriction() {
        // A NetworkPolicyPort with no `port` field at all legitimately means
        // "matches all ports" and must still parse to a rule with `port: None`.
        let rule = parse_port_rule(&port_spec(None, None)).unwrap();
        assert_eq!(rule.port, None);
        assert_eq!(rule.end_port, None);
    }

    #[test]
    fn test_parse_port_rule_rejects_out_of_range_port_instead_of_wrapping() {
        // Regression: this used to silently wrap via `as u16` (70000 -> 4464),
        // wiring up a rule for the wrong port. It must now drop the whole
        // rule instead of letting it through as the wrapped port or as
        // `None` (which would mean "all ports").
        assert!(parse_port_rule(&port_spec(Some(IntOrString::Int(70000)), None)).is_none());
    }

    #[test]
    fn test_parse_port_rule_rejects_negative_port() {
        assert!(parse_port_rule(&port_spec(Some(IntOrString::Int(-1)), None)).is_none());
    }

    #[test]
    fn test_parse_port_rule_rejects_out_of_range_end_port() {
        assert!(parse_port_rule(&port_spec(Some(IntOrString::Int(80)), Some(70000))).is_none());
    }

    #[test]
    fn test_parse_port_rule_rejects_unparseable_named_port() {
        assert!(parse_port_rule(&port_spec(
            Some(IntOrString::String("not-a-port".into())),
            None
        ))
        .is_none());
    }
}
