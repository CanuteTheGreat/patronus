//! Patronus Core Library
//!
//! Core types, traits, and utilities shared across all Patronus components.

pub mod error;
pub mod types;
pub mod service;
pub mod validation;

#[cfg(feature = "certificates")]
pub mod certs;

pub mod backup;

pub use error::{Error, Result};
pub use service::{ServiceManager, InitSystem, ServiceState};
pub use backup::{BackupManager, BackupConfig};
pub use validation::*;

#[cfg(feature = "certificates")]
pub use certs::{CertManager, CertBackend};
