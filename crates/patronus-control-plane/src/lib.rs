//! Distributed Control Plane
//!
//! Multi-region control plane with consensus and replication

pub mod consensus;
pub mod region;

pub use consensus::{ConsensusCluster, ConsensusNode, LogEntry, NodeRole};
pub use region::{Region, RegionCapacity, RegionManager, RegionStatus};
