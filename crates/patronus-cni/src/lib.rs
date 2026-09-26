//! Patronus CNI Plugin - Kubernetes Container Network Interface
//!
//! Provides native Kubernetes integration with:
//! - CNI plugin for pod networking
//! - eBPF datapath for high performance
//! - Network Policy enforcement
//! - Service mesh integration with Envoy

pub mod cni_plugin;
pub mod ebpf_datapath;
pub mod network_policy;
pub mod service_mesh;

pub use cni_plugin::{
    CniCommand, CniConfig, CniError, CniResult, CniRuntimeConfig, DnsConfig, IpamConfig,
    PatronusCniPlugin, Route,
};
pub use ebpf_datapath::{EbpfDatapath, EbpfProgramType, PodEndpoint, PolicyVerdict};
pub use network_policy::{
    EgressRule, IngressRule, NetworkPolicyController, PeerSelector, PolicyRule, PolicyType,
    PortRule,
};
pub use service_mesh::{
    EnvoyConfig, L7Route, ServiceEndpoint, ServiceMeshConfig, ServiceMeshManager, TracingConfig,
    TracingProvider,
};
