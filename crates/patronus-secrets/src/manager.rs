//! High-level secret management interface

use crate::{validation, SecretStore, SecretString};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
        self.store
            .store(key, value)
            .await
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
        let mut metadata = self.get_metadata(key).await?.context("Secret not found")?;

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
                warn!(
                    "Secret needs rotation: {} (last rotated: {:?})",
                    metadata.key, metadata.last_rotated
                );
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
            SecretType::CloudCredential
            | SecretType::DdnsCredential
            | SecretType::GitCredential => {
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

    /// Enforce secret rotation policy.
    ///
    /// Secrets are split into two buckets based on [`is_locally_rotatable`]:
    ///
    /// * Locally-rotatable secret types (locally-generated shared
    ///   secrets/keys with no external system that also needs to agree on
    ///   the new value) are actually regenerated and re-stored here.
    /// * All other secret types are only ever flagged for manual rotation:
    ///   this codebase cannot safely rotate them unattended because doing
    ///   so would desynchronize this secret from an external system of
    ///   record (a database server, a certificate authority, a cloud IAM
    ///   API, or an externally-issued token/credential) that Patronus does
    ///   not control and cannot update automatically.
    pub async fn enforce_rotation_policy(&self) -> Result<RotationResult> {
        let needs_rotation = self.find_secrets_needing_rotation().await?;
        let mut result = RotationResult::default();

        for metadata in needs_rotation {
            if is_locally_rotatable(metadata.secret_type) {
                match self
                    .auto_rotate_secret(&metadata.key, metadata.secret_type)
                    .await
                {
                    Ok(()) => {
                        info!(
                            "Auto-rotated secret: {} (type: {:?})",
                            metadata.key, metadata.secret_type
                        );
                        result.auto_rotated.push(metadata.key);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to auto-rotate secret '{}' (type: {:?}): {}. Falling back to manual rotation.",
                            metadata.key, metadata.secret_type, e
                        );
                        result.needs_manual_rotation.push(metadata.key);
                    }
                }
            } else {
                warn!(
                    "Secret '{}' (type: {:?}) needs rotation but cannot be safely auto-rotated \
                     ({}). Manual rotation required.",
                    metadata.key,
                    metadata.secret_type,
                    manual_rotation_reason(metadata.secret_type)
                );
                result.needs_manual_rotation.push(metadata.key);
            }
        }

        Ok(result)
    }

    /// Generate a new value appropriate for `secret_type` and store it,
    /// preserving the secret's description and rotation policy while
    /// updating `last_rotated`/`updated_at` via [`Self::rotate_secret`].
    async fn auto_rotate_secret(&self, key: &str, secret_type: SecretType) -> Result<()> {
        debug_assert!(
            is_locally_rotatable(secret_type),
            "auto_rotate_secret called for a non-locally-rotatable secret type"
        );

        let new_value = match secret_type {
            // Pre-shared keys / community strings: strong random password-style value.
            SecretType::VpnPsk | SecretType::IpsecPsk | SecretType::SnmpCommunity => {
                crate::crypto::generate_password(32)
            }
            // Webhook secrets: opaque high-entropy token.
            SecretType::WebhookSecret => crate::crypto::generate_token(32),
            other => {
                anyhow::bail!(
                    "internal error: {:?} is marked locally rotatable but has no rotation implementation",
                    other
                );
            }
        };

        self.rotate_secret(key, SecretString::from(new_value)).await
    }
}

/// Result of [`SecretManager::enforce_rotation_policy`]: which keys were
/// actually regenerated and re-stored, versus which keys merely got
/// flagged because they require external coordination this codebase
/// cannot perform unattended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationResult {
    /// Keys whose value was regenerated locally and re-stored.
    pub auto_rotated: Vec<String>,
    /// Keys that need an operator (or an external integration) to rotate
    /// them; the stored value was left untouched.
    pub needs_manual_rotation: Vec<String>,
}

/// Whether `secret_type` can be safely regenerated locally, in place,
/// without any external system also needing to be updated.
///
/// `true`: the secret is a locally-generated shared secret/key whose only
/// consumer is Patronus-managed config that gets rewritten alongside it
/// (VPN/IPsec PSKs, SNMP community strings, webhook signing secrets).
///
/// `false`: rotating the value here would NOT be sufficient to actually
/// rotate the credential, because it is either issued by / shared with an
/// external system of record, or otherwise requires coordinated action
/// this codebase cannot perform unattended. See [`manual_rotation_reason`]
/// for the specific reason per type.
pub fn is_locally_rotatable(secret_type: SecretType) -> bool {
    matches!(
        secret_type,
        SecretType::VpnPsk
            | SecretType::IpsecPsk
            | SecretType::WebhookSecret
            | SecretType::SnmpCommunity
    )
}

/// Human-readable reason a given secret type is not locally rotatable.
/// Panics (via the exhaustive match) if called for a locally-rotatable
/// type, since it only makes sense for the manual-rotation path.
fn manual_rotation_reason(secret_type: SecretType) -> &'static str {
    match secret_type {
        SecretType::VpnPsk
        | SecretType::IpsecPsk
        | SecretType::WebhookSecret
        | SecretType::SnmpCommunity => {
            "this secret type is locally rotatable; this reason should not be shown"
        }
        SecretType::DatabasePassword => {
            "regenerating it here would not update the actual database server's password"
        }
        SecretType::CertificateKey => {
            "a new private key requires re-issuing the certificate via a CA, not just a new local value"
        }
        SecretType::CloudCredential => {
            "rotating it requires calling the cloud provider's IAM API to issue/revoke the credential"
        }
        SecretType::GitCredential => {
            "git credentials are issued by an external Git host and cannot be regenerated locally"
        }
        SecretType::TelegramToken => {
            "bot tokens are issued by Telegram (BotFather) and cannot be regenerated locally"
        }
        SecretType::DdnsCredential => {
            "DDNS credentials are issued by the external DDNS provider and cannot be regenerated locally"
        }
        SecretType::VpnPassword => {
            "this is a user-facing VPN login password; changing it locally without notifying the user would lock them out"
        }
        SecretType::ApiToken => {
            "API tokens are typically validated by an external/consuming service that must also be updated"
        }
        SecretType::RadiusSecret => {
            "the RADIUS shared secret must also be updated on the RADIUS server, which this codebase cannot do unattended"
        }
        SecretType::HaPassword => {
            "the HA cluster password must be changed in lockstep on every peer node, which this codebase cannot coordinate unattended"
        }
        SecretType::General => {
            "general secrets have no known external consumer, so auto-rotation cannot be assumed safe"
        }
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

        // Store a secret (must not contain "password", "changeme", or "default")
        let secret = SecretString::from("MySecurePhrase123!@#");
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
        assert_eq!(retrieved.expose_secret(), "MySecurePhrase123!@#");

        // Get metadata
        let metadata = manager
            .get_metadata("test_password")
            .await
            .unwrap()
            .unwrap();
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

        // Strong secret should succeed (must not contain "password", "changeme", or "default")
        let strong_secret = SecretString::from("VerySecurePhrase123!@#$%");
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
