//! Service Mesh Integration
//!
//! Integrates Patronus SD-WAN with service meshes like Istio and Linkerd
//! Provides L7 routing, traffic management, and observability

pub mod gateway;
pub mod istio;
pub mod linkerd;
pub mod smi;

pub use gateway::MeshGateway;
pub use istio::IstioIntegration;
pub use linkerd::LinkerdIntegration;
pub use smi::ServiceMeshInterface;
