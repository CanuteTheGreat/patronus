//! Secret storage backends

use crate::{SecretString, crypto};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

/// Secret storage backend trait
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Store a secret
    async fn store(&self, key: &str, value: SecretString) -> Result<()>;

    /// Retrieve a secret
    async fn retrieve(&self, key: &str) -> Result<Option<SecretString>>;

    /// Delete a secret
    async fn delete(&self, key: &str) -> Result<()>;

    /// List all secret keys (not values)
    async fn list(&self) -> Result<Vec<String>>;

    /// Check if a secret exists
    async fn exists(&self, key: &str) -> Result<bool>;
}

/// In-memory secret store (not persistent, for testing/development)
pub struct MemoryStore {
    secrets: Arc<RwLock<HashMap<String, SecretString>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for MemoryStore {
    async fn store(&self, key: &str, value: SecretString) -> Result<()> {
        self.secrets.write().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<SecretString>> {
        Ok(self.secrets.read().await.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.secrets.write().await.remove(key);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(self.secrets.read().await.keys().cloned().collect())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.secrets.read().await.contains_key(key))
    }
}

/// Encrypted file-based secret store
#[derive(Serialize, Deserialize)]
struct EncryptedSecrets {
    salt: Vec<u8>,
    secrets: HashMap<String, Vec<u8>>, // Encrypted values
}

pub struct FileStore {
    file_path: PathBuf,
    master_key: Vec<u8>,
    salt: Vec<u8>,
    cache: Arc<RwLock<HashMap<String, SecretString>>>,
}

impl FileStore {
    /// Create a new file store with a master password
    pub async fn new(file_path: PathBuf, master_password: &str) -> Result<Self> {
        // Load or create the encrypted file
        // Check if file exists AND has content (not empty)
        let file_has_content = file_path.exists() && {
            std::fs::metadata(&file_path)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        };

        let (salt, cache) = if file_has_content {
            Self::load_from_file(&file_path, master_password).await?
        } else {
            // New file or empty file, generate salt
            let salt = crypto::generate_salt();
            (salt, HashMap::new())
        };

        let master_key = crypto::derive_key(master_password, &salt)?;

        Ok(Self {
            file_path,
            master_key,
            salt,
            cache: Arc::new(RwLock::new(cache)),
        })
    }

    async fn load_from_file(
        file_path: &PathBuf,
        master_password: &str,
    ) -> Result<(Vec<u8>, HashMap<String, SecretString>)> {
        let content = tokio::fs::read(file_path).await
            .context("Failed to read secrets file")?;

        let encrypted: EncryptedSecrets = serde_json::from_slice(&content)
            .context("Failed to parse secrets file")?;

        let master_key = crypto::derive_key(master_password, &encrypted.salt)?;

        let mut cache = HashMap::new();
        for (key, encrypted_value) in encrypted.secrets {
            let plaintext = crypto::decrypt_secret(&encrypted_value, &master_key)?;
            let secret = SecretString::new(
                String::from_utf8(plaintext)
                    .context("Invalid UTF-8 in decrypted secret")?
            );
            cache.insert(key, secret);
        }

        Ok((encrypted.salt, cache))
    }

    async fn save_to_file(&self) -> Result<()> {
        let cache = self.cache.read().await;

        // Encrypt all secrets
        let mut encrypted_secrets = HashMap::new();
        for (key, value) in cache.iter() {
            let encrypted = crypto::encrypt_secret(
                value.expose_secret().as_bytes(),
                &self.master_key,
            )?;
            encrypted_secrets.insert(key.clone(), encrypted);
        }

        let encrypted_file = EncryptedSecrets {
            salt: self.salt.clone(),
            secrets: encrypted_secrets,
        };

        let json = serde_json::to_vec_pretty(&encrypted_file)
            .context("Failed to serialize secrets")?;

        tokio::fs::write(&self.file_path, json).await
            .context("Failed to write secrets file")?;

        // Set restrictive permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&self.file_path).await?.permissions();
            perms.set_mode(0o600);
            tokio::fs::set_permissions(&self.file_path, perms).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl SecretStore for FileStore {
    async fn store(&self, key: &str, value: SecretString) -> Result<()> {
        self.cache.write().await.insert(key.to_string(), value);
        self.save_to_file().await?;
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<SecretString>> {
        Ok(self.cache.read().await.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.cache.write().await.remove(key);
        self.save_to_file().await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(self.cache.read().await.keys().cloned().collect())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.cache.read().await.contains_key(key))
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.master_key.zeroize();
        self.salt.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::new();

        store.store("key1", SecretString::from("value1")).await.unwrap();
        store.store("key2", SecretString::from("value2")).await.unwrap();

        assert!(store.exists("key1").await.unwrap());
        assert!(!store.exists("key3").await.unwrap());

        let value = store.retrieve("key1").await.unwrap().unwrap();
        assert_eq!(value.expose_secret(), "value1");

        let keys = store.list().await.unwrap();
        assert_eq!(keys.len(), 2);

        store.delete("key1").await.unwrap();
        assert!(!store.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_file_store() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_path_buf();

        {
            let store = FileStore::new(file_path.clone(), "master_password").await.unwrap();
            store.store("test_key", SecretString::from("test_value")).await.unwrap();
        }

        // Reload from file
        {
            let store = FileStore::new(file_path, "master_password").await.unwrap();
            let value = store.retrieve("test_key").await.unwrap().unwrap();
            assert_eq!(value.expose_secret(), "test_value");
        }
    }
}
