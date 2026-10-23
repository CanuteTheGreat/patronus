//! BGP error types

use thiserror::Error;

/// BGP error type
#[derive(Error, Debug)]
pub enum BgpError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Route error
    #[error("Route error: {0}")]
    RouteError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Timeout error
    #[error("Timeout error: {0}")]
    TimeoutError(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Result type for BGP operations
pub type Result<T> = std::result::Result<T, BgpError>;
