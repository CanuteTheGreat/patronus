//! Edge Computing Integration
//!
//! Support for 5G, IoT devices, and edge node management

pub mod device;
pub mod edge_node;
pub mod fiveg;
pub mod workload;

pub use device::{DeviceManager, DeviceMetrics, DeviceType, IoTDevice};
pub use edge_node::{EdgeNode, EdgeNodeManager, NodeCapabilities, NodeStatus};
pub use fiveg::{FiveGSlice, NetworkSlice, SliceManager, SliceType};
pub use workload::{EdgeWorkload, SchedulingPolicy, WorkloadPlacement, WorkloadScheduler};
