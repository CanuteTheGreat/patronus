//! Patronus Installer Library
//!
//! Full-featured installer for Patronus firewall/SD-WAN system.
//! Provides both TUI and CLI interfaces for system installation.

pub mod config;
pub mod disk;
pub mod error;
pub mod install;
pub mod tui;

pub use config::InstallConfig;
pub use error::{InstallerError, Result};
