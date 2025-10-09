//! Patronus Secrets Management
//!
//! Secure storage and retrieval of sensitive credentials including:
//! - VPN pre-shared keys and passwords
//! - API tokens and secrets
//! - Cloud storage credentials
//! - Database passwords
//! - Certificate private keys
//! - SNMP community strings
//! - Webhook secrets
//!
//! ## Security Features
//!
//! - Encryption at rest using AES-256-GCM or ChaCha20-Poly1305
//! - Key derivation from master password using Argon2id
//! - Memory protection with zeroize on drop
//! - Multiple backend support (memory, file, system keyring, Vault)
//! - Automatic secret rotation
//! - Audit logging of all access

pub mod crypto;
pub mod manager;
pub mod store;
pub mod validation;

pub use manager::{SecretManager, SecretMetadata, SecretType};
pub use store::{SecretStore, MemoryStore, FileStore};
pub use crypto::{encrypt_secret, decrypt_secret, derive_key};
pub use validation::{validate_password_strength, PasswordStrength};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret value that is automatically zeroed on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn from_str(value: &str) -> Self {
        Self(value.to_string())
    }

    /// Expose the secret value (use with caution)
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Convert to owned String (consumes self)
    pub fn into_string(mut self) -> String {
        let value = std::mem::take(&mut self.0);
        value
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
