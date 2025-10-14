//! Service Mesh Integration
//!
//! Integrates Patronus SD-WAN with service meshes like Istio and Linkerd
//! Provides L7 routing, traffic management, and observability

pub mod istio;
pub mod linkerd;
pub mod smi;
pub mod gateway;

pub use istio::IstioIntegration;
pub use linkerd::LinkerdIntegration;
pub use smi::ServiceMeshInterface;
pub use gateway::MeshGateway;
