//! Disk operations module
//!
//! Provides disk detection, partitioning, and filesystem formatting.

pub mod detect;
pub mod format;
pub mod partition;

pub use crate::config::Filesystem;
pub use detect::{detect_disks, DiskInfo, PartitionInfo, Transport};
pub use format::format_partition;
pub use partition::{create_partitions, CreatedPartition, PartitionFlag};
