//! Disk operations module
//!
//! Provides disk detection, partitioning, and filesystem formatting.

pub mod detect;
pub mod format;
pub mod partition;
pub mod zfs;

pub use crate::config::Filesystem;
pub use detect::{detect_disks, DiskInfo, PartitionInfo, Transport};
pub use format::format_partition;
pub use partition::{create_partitions, CreatedPartition, PartitionFlag};
pub use zfs::{create_root_pool, export_root_pool, import_root_pool, zfs_tooling_available, ROOT_POOL_NAME};
