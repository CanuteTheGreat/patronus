//! Intelligent Traffic Engineering
//!
//! Advanced traffic management with ML-based optimization

pub mod demand;
pub mod optimizer;
pub mod path;
pub mod tunnel;

pub use demand::{DemandMatrix, DemandPredictor, TrafficDemand};
pub use optimizer::{OptimizationObjective, OptimizationResult, TrafficOptimizer};
pub use path::{ComputedPath, PathComputation, PathConstraints};
pub use tunnel::{Tunnel, TunnelManager, TunnelState};
