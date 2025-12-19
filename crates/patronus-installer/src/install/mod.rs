//! Installation logic module
//!
//! Handles the actual system installation process.

pub mod bootloader;
pub mod network;
pub mod services;
pub mod system;

pub use crate::config::Bootloader;
pub use bootloader::install_bootloader;
pub use network::configure_network;
pub use services::configure_services;
pub use system::{configure_system, install_base_system, mount_partitions, unmount_partitions};
