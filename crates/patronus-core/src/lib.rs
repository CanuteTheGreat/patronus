//! Patronus Core Library
//!
//! Core types, traits, and utilities shared across all Patronus components.

pub mod error;
pub mod service;
pub mod types;
pub mod validation;

#[cfg(feature = "certificates")]
pub mod certs;

pub mod backup;

pub use backup::{BackupConfig, BackupManager};
pub use error::{Error, Result};
pub use service::{InitSystem, ServiceManager, ServiceState};
pub use validation::*;

#[cfg(feature = "certificates")]
pub use certs::{CertBackend, CertManager};
