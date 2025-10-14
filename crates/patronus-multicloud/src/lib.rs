//! Multi-Cloud Connectivity Module
//!
//! Provides SD-WAN connectivity to major cloud providers:
//! - AWS (VPC, Transit Gateway, Direct Connect)
//! - Azure (VNet, Virtual WAN, ExpressRoute)
//! - GCP (VPC, Cloud Interconnect)

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod manager;

pub use aws::AwsConnector;
pub use azure::AzureConnector;
pub use gcp::GcpConnector;
pub use manager::{MultiCloudManager, CloudProvider, CloudConnection};
