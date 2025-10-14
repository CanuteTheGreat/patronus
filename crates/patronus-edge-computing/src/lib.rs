//! Edge Computing Integration
//!
//! Support for 5G, IoT devices, and edge node management

pub mod device;
pub mod edge_node;
pub mod fiveg;
pub mod workload;

pub use device::{IoTDevice, DeviceType, DeviceManager, DeviceMetrics};
pub use edge_node::{EdgeNode, EdgeNodeManager, NodeCapabilities, NodeStatus};
pub use fiveg::{FiveGSlice, NetworkSlice, SliceType, SliceManager};
pub use workload::{EdgeWorkload, WorkloadScheduler, WorkloadPlacement, SchedulingPolicy};
