//! API key management for programmatic access

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// API key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_prefix: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub enabled: bool,
}

/// API key with full key (only returned on creation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyWithSecret {
    pub key: ApiKey,
    pub secret: String,
}

/// API key manager
pub struct ApiKeyManager {
    pool: SqlitePool,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Initialize API keys table
    pub async fn init(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                scopes TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT,
                UNIQUE(user_id, name)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Generate a new API key
    pub async fn create_key(
        &self,
        user_id: String,
        name: String,
        scopes: Vec<String>,
        expires_in_days: Option<i64>,
    ) -> Result<ApiKeyWithSecret> {
        // Generate random key (32 bytes = 64 hex chars)
        let key_bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen()).collect();
        let secret = format!("pk_{}", hex::encode(&key_bytes));

        // Hash for storage
        let key_hash = self.hash_key(&secret);

        // Prefix for display (first 8 chars after pk_)
        let key_prefix = format!("pk_{}", &hex::encode(&key_bytes)[0..8]);

        // Generate ID
        let id = uuid::Uuid::new_v4().to_string();

        let created_at = Utc::now();
        let expires_at = expires_in_days.map(|days| created_at + chrono::Duration::days(days));

        let scopes_json = serde_json::to_string(&scopes)?;

        sqlx::query(
            "INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, enabled, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&name)
        .bind(&key_hash)
        .bind(&key_prefix)
        .bind(&scopes_json)
        .bind(created_at.to_rfc3339())
        .bind(expires_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        Ok(ApiKeyWithSecret {
            key: ApiKey {
                id,
                user_id,
                name,
                key_prefix,
                created_at,
                last_used_at: None,
                expires_at,
                scopes,
                enabled: true,
            },
            secret,
        })
    }

    /// Verify an API key and return user ID and scopes
    pub async fn verify_key(&self, key: &str) -> Result<(String, Vec<String>)> {
        let key_hash = self.hash_key(key);

        // Get key prefix for faster lookup
        let prefix = if key.len() >= 11 {
            &key[0..11] // "pk_" + 8 chars
        } else {
            return Err(anyhow!("Invalid API key format"));
        };

        let result: Option<(String, String, i32, Option<String>)> = sqlx::query_as(
            "SELECT user_id, scopes, enabled, expires_at FROM api_keys
             WHERE key_hash = ? AND key_prefix = ?",
        )
        .bind(&key_hash)
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((user_id, scopes_json, enabled, expires_at)) = result {
            // Check if enabled
            if enabled == 0 {
                return Err(anyhow!("API key disabled"));
            }

            // Check if expired
            if let Some(expires_at_str) = expires_at {
                let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)?
                    .with_timezone(&Utc);
                if Utc::now() > expires_at {
                    return Err(anyhow!("API key expired"));
                }
            }

            // Update last used
            let _ = sqlx::query(
                "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
            )
            .bind(Utc::now().to_rfc3339())
            .bind(&key_hash)
            .execute(&self.pool)
            .await;

            let scopes: Vec<String> = serde_json::from_str(&scopes_json)?;

            Ok((user_id, scopes))
        } else {
            Err(anyhow!("Invalid API key"))
        }
    }

    /// List API keys for a user
    pub async fn list_user_keys(&self, user_id: &str) -> Result<Vec<ApiKey>> {
        let keys = sqlx::query_as::<_, (String, String, String, String, String, i32, String, Option<String>, Option<String>)>(
            "SELECT id, user_id, name, key_prefix, scopes, enabled, created_at, last_used_at, expires_at
             FROM api_keys
             WHERE user_id = ?
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(id, user_id, name, key_prefix, scopes_json, enabled, created_at, last_used_at, expires_at)| {
            let scopes: Vec<String> = serde_json::from_str(&scopes_json).unwrap_or_default();

            ApiKey {
                id,
                user_id,
                name,
                key_prefix,
                created_at: DateTime::parse_from_rfc3339(&created_at).unwrap().with_timezone(&Utc),
                last_used_at: last_used_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
                expires_at: expires_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
                scopes,
                enabled: enabled != 0,
            }
        })
        .collect();

        Ok(keys)
    }

    /// Revoke an API key
    pub async fn revoke_key(&self, key_id: &str, user_id: &str) -> Result<()> {
        let result = sqlx::query(
            "UPDATE api_keys SET enabled = 0 WHERE id = ? AND user_id = ?",
        )
        .bind(key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found"));
        }

        Ok(())
    }

    /// Delete an API key
    pub async fn delete_key(&self, key_id: &str, user_id: &str) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
        )
        .bind(key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(anyhow!("API key not found"));
        }

        Ok(())
    }

    /// Clean up expired keys
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let result = sqlx::query(
            "DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < ?",
        )
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Hash API key
    fn hash_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_db() -> SqlitePool {
        SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_api_key_manager_init() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);

        assert!(manager.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_create_api_key() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);
        manager.init().await.unwrap();

        let key_data = manager
            .create_key(
                "user123".to_string(),
                "My API Key".to_string(),
                vec!["read".to_string(), "write".to_string()],
                Some(30),
            )
            .await
            .unwrap();

        assert!(key_data.secret.starts_with("pk_"));
        assert_eq!(key_data.key.scopes.len(), 2);
        assert!(key_data.key.enabled);
    }

    #[tokio::test]
    async fn test_verify_api_key() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);
        manager.init().await.unwrap();

        let key_data = manager
            .create_key(
                "user123".to_string(),
                "Test Key".to_string(),
                vec!["read".to_string()],
                None,
            )
            .await
            .unwrap();

        let (user_id, scopes) = manager.verify_key(&key_data.secret).await.unwrap();

        assert_eq!(user_id, "user123");
        assert_eq!(scopes, vec!["read".to_string()]);
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);
        manager.init().await.unwrap();

        let key_data = manager
            .create_key(
                "user123".to_string(),
                "Test Key".to_string(),
                vec!["read".to_string()],
                None,
            )
            .await
            .unwrap();

        // Should work before revoke
        assert!(manager.verify_key(&key_data.secret).await.is_ok());

        // Revoke
        manager
            .revoke_key(&key_data.key.id, "user123")
            .await
            .unwrap();

        // Should fail after revoke
        assert!(manager.verify_key(&key_data.secret).await.is_err());
    }

    #[tokio::test]
    async fn test_list_user_keys() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);
        manager.init().await.unwrap();

        // Create multiple keys
        for i in 0..3 {
            manager
                .create_key(
                    "user123".to_string(),
                    format!("Key {}", i),
                    vec!["read".to_string()],
                    None,
                )
                .await
                .unwrap();
        }

        let keys = manager.list_user_keys("user123").await.unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    async fn test_expired_key() {
        let pool = setup_test_db().await;
        let manager = ApiKeyManager::new(pool);
        manager.init().await.unwrap();

        // Create key that expires immediately
        let key_data = manager
            .create_key(
                "user123".to_string(),
                "Expired Key".to_string(),
                vec!["read".to_string()],
                Some(-1), // Expired yesterday
            )
            .await
            .unwrap();

        // Should fail due to expiration
        let result = manager.verify_key(&key_data.secret).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }
}
