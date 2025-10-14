//! Distributed Control Plane
//!
//! Multi-region control plane with consensus and replication

pub mod region;
pub mod consensus;

pub use region::{Region, RegionManager, RegionStatus, RegionCapacity};
pub use consensus::{ConsensusNode, ConsensusCluster, LogEntry, NodeRole};
