//! Intelligent Traffic Engineering
//!
//! Advanced traffic management with ML-based optimization

pub mod demand;
pub mod path;
pub mod optimizer;
pub mod tunnel;

pub use demand::{TrafficDemand, DemandMatrix, DemandPredictor};
pub use path::{PathComputation, PathConstraints, ComputedPath};
pub use optimizer::{TrafficOptimizer, OptimizationObjective, OptimizationResult};
pub use tunnel::{TunnelManager, Tunnel, TunnelState};
