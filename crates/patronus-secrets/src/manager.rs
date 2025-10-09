//! High-level secret management interface

use crate::{SecretString, SecretStore, validation};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use tracing::{info, warn};

/// Type of secret being stored
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    /// VPN pre-shared key
    VpnPsk,
    /// VPN user password
    VpnPassword,
    /// API token/key
    ApiToken,
    /// Cloud storage credential
    CloudCredential,
    /// Database password
    DatabasePassword,
    /// Certificate private key
    CertificateKey,
    /// SNMP community string
    SnmpCommunity,
    /// Webhook secret
    WebhookSecret,
    /// Git credentials
    GitCredential,
    /// Telegram bot token
    TelegramToken,
    /// RADIUS shared secret
    RadiusSecret,
    /// IPsec PSK
    IpsecPsk,
    /// DDNS credentials
    DdnsCredential,
    /// HA cluster password
    HaPassword,
    /// General secret
    General,
}

/// Metadata about a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub key: String,
    pub secret_type: SecretType,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rotation_days: Option<u32>,
    pub last_rotated: Option<DateTime<Utc>>,
}

impl SecretMetadata {
    /// Check if secret needs rotation
    pub fn needs_rotation(&self) -> bool {
        if let (Some(rotation_days), Some(last_rotated)) = (self.rotation_days, self.last_rotated) {
            let days_since_rotation = (Utc::now() - last_rotated).num_days();
            days_since_rotation >= rotation_days as i64
        } else {
            false
        }
    }
}

/// High-level secret manager
pub struct SecretManager {
    store: Arc<dyn SecretStore>,
    metadata_store: Arc<dyn SecretStore>,
}

impl SecretManager {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self {
            store: Arc::clone(&store),
            metadata_store: store,
        }
    }

    /// Store a secret with metadata
    pub async fn store_secret(
        &self,
        key: &str,
        value: SecretString,
        secret_type: SecretType,
        description: String,
        rotation_days: Option<u32>,
    ) -> Result<()> {
        // Validate the secret based on type
        self.validate_secret(&value, secret_type)?;

        // Store the secret
        self.store.store(key, value).await
            .context("Failed to store secret")?;

        // Store metadata
        let metadata = SecretMetadata {
            key: key.to_string(),
            secret_type,
            description,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            rotation_days,
            last_rotated: Some(Utc::now()),
        };

        let metadata_key = format!("metadata:{}", key);
        let metadata_json = serde_json::to_string(&metadata)?;
        self.metadata_store
            .store(&metadata_key, SecretString::from(metadata_json))
            .await?;

        info!("Stored secret: {} (type: {:?})", key, secret_type);

        Ok(())
    }

    /// Retrieve a secret
    pub async fn get_secret(&self, key: &str) -> Result<Option<SecretString>> {
        self.store.retrieve(key).await
    }

    /// Retrieve secret metadata
    pub async fn get_metadata(&self, key: &str) -> Result<Option<SecretMetadata>> {
        let metadata_key = format!("metadata:{}", key);
        if let Some(metadata_secret) = self.metadata_store.retrieve(&metadata_key).await? {
            let metadata: SecretMetadata = serde_json::from_str(metadata_secret.expose_secret())?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    /// Update a secret (rotates it)
    pub async fn rotate_secret(&self, key: &str, new_value: SecretString) -> Result<()> {
        // Get existing metadata
        let mut metadata = self.get_metadata(key).await?
            .context("Secret not found")?;

        // Validate new secret
        self.validate_secret(&new_value, metadata.secret_type)?;

        // Store new secret
        self.store.store(key, new_value).await?;

        // Update metadata
        metadata.updated_at = Utc::now();
        metadata.last_rotated = Some(Utc::now());

        let metadata_key = format!("metadata:{}", key);
        let metadata_json = serde_json::to_string(&metadata)?;
        self.metadata_store
            .store(&metadata_key, SecretString::from(metadata_json))
            .await?;

        info!("Rotated secret: {}", key);

        Ok(())
    }

    /// Delete a secret and its metadata
    pub async fn delete_secret(&self, key: &str) -> Result<()> {
        self.store.delete(key).await?;

        let metadata_key = format!("metadata:{}", key);
        self.metadata_store.delete(&metadata_key).await?;

        info!("Deleted secret: {}", key);

        Ok(())
    }

    /// List all secrets with their metadata
    pub async fn list_secrets(&self) -> Result<Vec<SecretMetadata>> {
        let keys = self.store.list().await?;
        let mut metadata_list = Vec::new();

        for key in keys {
            // Skip metadata keys
            if key.starts_with("metadata:") {
                continue;
            }

            if let Some(metadata) = self.get_metadata(&key).await? {
                metadata_list.push(metadata);
            }
        }

        Ok(metadata_list)
    }

    /// Find secrets that need rotation
    pub async fn find_secrets_needing_rotation(&self) -> Result<Vec<SecretMetadata>> {
        let all_secrets = self.list_secrets().await?;
        let mut needs_rotation = Vec::new();

        for metadata in all_secrets {
            if metadata.needs_rotation() {
                warn!("Secret needs rotation: {} (last rotated: {:?})",
                      metadata.key, metadata.last_rotated);
                needs_rotation.push(metadata);
            }
        }

        Ok(needs_rotation)
    }

    /// Validate secret based on its type
    fn validate_secret(&self, secret: &SecretString, secret_type: SecretType) -> Result<()> {
        let value = secret.expose_secret();

        match secret_type {
            SecretType::VpnPsk | SecretType::IpsecPsk | SecretType::HaPassword => {
                // PSK should be strong
                let policy = validation::PasswordPolicy::default();
                validation::validate_password(value, &policy)?;
            }
            SecretType::VpnPassword | SecretType::DatabasePassword => {
                // Passwords should be strong
                let policy = validation::PasswordPolicy::default();
                validation::validate_password(value, &policy)?;
            }
            SecretType::ApiToken | SecretType::TelegramToken => {
                // API tokens should be long and not default
                validation::validate_api_key(value)?;
            }
            SecretType::WebhookSecret | SecretType::RadiusSecret => {
                // Webhook secrets should be strong
                validation::validate_secret(value, 32)?;
            }
            SecretType::SnmpCommunity => {
                // SNMP community strings should not be default
                validation::validate_secret(value, 8)?;
                if value == "public" || value == "private" {
                    anyhow::bail!("SNMP community string cannot be 'public' or 'private'");
                }
            }
            SecretType::CloudCredential | SecretType::DdnsCredential | SecretType::GitCredential => {
                // Cloud credentials should not be empty or default
                validation::validate_secret(value, 16)?;
            }
            SecretType::CertificateKey => {
                // Private keys should be PEM format (basic check)
                if !value.contains("BEGIN") || !value.contains("PRIVATE KEY") {
                    anyhow::bail!("Certificate key must be in PEM format");
                }
            }
            SecretType::General => {
                // General secrets should not be obviously weak
                validation::validate_secret(value, 8)?;
            }
        }

        Ok(())
    }

    /// Get or generate a secret (create if doesn't exist)
    pub async fn get_or_generate(
        &self,
        key: &str,
        secret_type: SecretType,
        description: String,
        length: usize,
    ) -> Result<SecretString> {
        if let Some(secret) = self.get_secret(key).await? {
            Ok(secret)
        } else {
            // Generate new secret
            let generated = crate::crypto::generate_token(length);
            let secret = SecretString::from(generated);

            self.store_secret(key, secret.clone(), secret_type, description, None)
                .await?;

            Ok(secret)
        }
    }

    /// Enforce secret rotation policy
    pub async fn enforce_rotation_policy(&self) -> Result<Vec<String>> {
        let needs_rotation = self.find_secrets_needing_rotation().await?;
        let mut rotated = Vec::new();

        for metadata in needs_rotation {
            warn!("Secret '{}' needs rotation but auto-rotation not implemented. Manual rotation required.", metadata.key);
            rotated.push(metadata.key);
        }

        Ok(rotated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;

    #[tokio::test]
    async fn test_secret_manager() {
        let store = Arc::new(MemoryStore::new());
        let manager = SecretManager::new(store);

        // Store a secret
        let secret = SecretString::from("MyStrongPassword123!@#");
        manager
            .store_secret(
                "test_password",
                secret,
                SecretType::VpnPassword,
                "Test VPN password".to_string(),
                Some(90), // Rotate every 90 days
            )
            .await
            .unwrap();

        // Retrieve it
        let retrieved = manager.get_secret("test_password").await.unwrap().unwrap();
        assert_eq!(retrieved.expose_secret(), "MyStrongPassword123!@#");

        // Get metadata
        let metadata = manager.get_metadata("test_password").await.unwrap().unwrap();
        assert_eq!(metadata.secret_type, SecretType::VpnPassword);
        assert_eq!(metadata.rotation_days, Some(90));

        // List secrets
        let secrets = manager.list_secrets().await.unwrap();
        assert_eq!(secrets.len(), 1);
    }

    #[tokio::test]
    async fn test_secret_validation() {
        let store = Arc::new(MemoryStore::new());
        let manager = SecretManager::new(store);

        // Weak password should fail
        let weak_secret = SecretString::from("weak");
        let result = manager
            .store_secret(
                "weak_password",
                weak_secret,
                SecretType::VpnPassword,
                "Weak password".to_string(),
                None,
            )
            .await;
        assert!(result.is_err());

        // Default PSK should fail
        let default_psk = SecretString::from("changeme");
        let result = manager
            .store_secret(
                "default_psk",
                default_psk,
                SecretType::VpnPsk,
                "Default PSK".to_string(),
                None,
            )
            .await;
        assert!(result.is_err());

        // Strong secret should succeed
        let strong_secret = SecretString::from("VeryStrongPassword123!@#$%");
        let result = manager
            .store_secret(
                "strong_password",
                strong_secret,
                SecretType::VpnPassword,
                "Strong password".to_string(),
                None,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_or_generate() {
        let store = Arc::new(MemoryStore::new());
        let manager = SecretManager::new(store);

        // Generate a secret
        let secret1 = manager
            .get_or_generate(
                "auto_token",
                SecretType::ApiToken,
                "Auto-generated token".to_string(),
                32,
            )
            .await
            .unwrap();

        // Get the same secret (should not regenerate)
        let secret2 = manager
            .get_or_generate(
                "auto_token",
                SecretType::ApiToken,
                "Auto-generated token".to_string(),
                32,
            )
            .await
            .unwrap();

        assert_eq!(secret1.expose_secret(), secret2.expose_secret());
    }
}
