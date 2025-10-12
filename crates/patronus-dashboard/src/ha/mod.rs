//! High Availability module for distributed dashboard instances

pub mod cluster;
pub mod election;
pub mod state;

pub use cluster::{ClusterConfig, ClusterNode, NodeRole};
pub use election::LeaderElection;
pub use state::DistributedState;
