//! Installer error types

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for installer operations
pub type Result<T> = std::result::Result<T, InstallerError>;

/// Installer error types
#[derive(Debug, Error)]
pub enum InstallerError {
    /// Disk-related errors
    #[error("Disk error: {0}")]
    Disk(String),

    /// Partition-related errors
    #[error("Partition error: {0}")]
    Partition(String),

    /// Filesystem formatting error
    #[error("Filesystem error: {0}")]
    Filesystem(String),

    /// Mount/unmount error
    #[error("Mount error: {0}")]
    Mount(String),

    /// Installation error
    #[error("Installation error: {0}")]
    Install(String),

    /// Bootloader error
    #[error("Bootloader error: {0}")]
    Bootloader(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network configuration error
    #[error("Network error: {0}")]
    Network(String),

    /// User creation error
    #[error("User error: {0}")]
    User(String),

    /// Service configuration error
    #[error("Service error: {0}")]
    Service(String),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Command execution error
    #[error("Command failed: {command} - {message}")]
    CommandFailed { command: String, message: String },

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// TUI error
    #[error("TUI error: {0}")]
    Tui(String),

    /// User cancelled operation
    #[error("Operation cancelled by user")]
    Cancelled,

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// System requirement not met
    #[error("System requirement not met: {0}")]
    RequirementNotMet(String),
}
