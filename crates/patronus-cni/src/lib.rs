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
    PatronusCniPlugin, CniConfig, CniCommand, CniResult, CniError,
    CniRuntimeConfig, IpamConfig, DnsConfig, Route,
};
pub use ebpf_datapath::{
    EbpfDatapath, PodEndpoint, PolicyVerdict, EbpfProgramType,
};
pub use network_policy::{
    NetworkPolicyController, PolicyRule, PolicyType,
    IngressRule, EgressRule, PeerSelector, PortRule,
};
pub use service_mesh::{
    ServiceMeshManager, ServiceMeshConfig, ServiceEndpoint,
    EnvoyConfig, L7Route, TracingConfig, TracingProvider,
};
