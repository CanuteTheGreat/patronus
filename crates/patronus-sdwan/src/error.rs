//! Error types for SD-WAN

use thiserror::Error;

/// SD-WAN error type
#[derive(Debug, Error)]
pub enum Error {
    /// Database error
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Site not found
    #[error("site not found: {0}")]
    SiteNotFound(String),

    /// Path not found
    #[error("path not found: {0}")]
    PathNotFound(u64),

    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Network error
    #[error("network error: {0}")]
    Network(String),

    /// Authentication error
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Timeout
    #[error("operation timed out")]
    Timeout,

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Result type for SD-WAN operations
pub type Result<T> = std::result::Result<T, Error>;
