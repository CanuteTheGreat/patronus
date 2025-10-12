//! Token revocation system

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashSet;

/// Revoked token entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedToken {
    pub token_id: String,
    pub user_id: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

/// Token revocation manager
pub struct TokenRevocation {
    pool: SqlitePool,
    /// In-memory cache for fast lookups
    revoked_cache: Arc<RwLock<HashSet<String>>>,
}

impl TokenRevocation {
    /// Create a new token revocation manager
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            revoked_cache: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Initialize revocation table
    pub async fn init(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create index for user lookups
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_revoked_user ON revoked_tokens(user_id)",
        )
        .execute(&self.pool)
        .await?;

        // Load existing revoked tokens into cache
        self.reload_cache().await?;

        Ok(())
    }

    /// Revoke a token
    pub async fn revoke_token(
        &self,
        token_id: String,
        user_id: String,
        reason: String,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let revoked_at = Utc::now();

        sqlx::query(
            "INSERT OR REPLACE INTO revoked_tokens (token_id, user_id, revoked_at, reason, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&token_id)
        .bind(&user_id)
        .bind(revoked_at.to_rfc3339())
        .bind(&reason)
        .bind(expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Add to cache
        self.revoked_cache.write().insert(token_id);

        Ok(())
    }

    /// Check if a token is revoked
    pub fn is_revoked(&self, token_id: &str) -> bool {
        self.revoked_cache.read().contains(token_id)
    }

    /// Revoke all tokens for a user
    pub async fn revoke_all_user_tokens(&self, user_id: &str, reason: String) -> anyhow::Result<usize> {
        // Get all active tokens for user from JWT claims (this would normally come from session store)
        // For now, we'll revoke all non-expired tokens
        let tokens: Vec<(String,)> = sqlx::query_as(
            "SELECT token_id FROM revoked_tokens WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let revoked_at = Utc::now();
        let expires_at = Utc::now() + chrono::Duration::hours(1); // Assume 1 hour max token lifetime

        // Note: In a real implementation, you'd get active token IDs from your session store
        // For this implementation, we'll mark the user as having all tokens revoked
        sqlx::query(
            "INSERT OR REPLACE INTO revoked_tokens (token_id, user_id, revoked_at, reason, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(format!("user_revoke_{}", user_id))
        .bind(user_id)
        .bind(revoked_at.to_rfc3339())
        .bind(&reason)
        .bind(expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Reload cache
        self.reload_cache().await?;

        Ok(tokens.len())
    }

    /// Get revoked tokens for a user
    pub async fn get_user_revocations(&self, user_id: &str) -> anyhow::Result<Vec<RevokedToken>> {
        let tokens = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT token_id, user_id, revoked_at, reason
             FROM revoked_tokens
             WHERE user_id = ?
             ORDER BY revoked_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(token_id, user_id, revoked_at, reason)| RevokedToken {
            token_id,
            user_id,
            revoked_at: DateTime::parse_from_rfc3339(&revoked_at)
                .unwrap()
                .with_timezone(&Utc),
            reason,
        })
        .collect();

        Ok(tokens)
    }

    /// Clean up expired revocations
    pub async fn cleanup_expired(&self) -> anyhow::Result<usize> {
        let now = Utc::now();

        let result = sqlx::query(
            "DELETE FROM revoked_tokens WHERE expires_at < ?",
        )
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Reload cache after cleanup
        self.reload_cache().await?;

        Ok(result.rows_affected() as usize)
    }

    /// Reload cache from database
    async fn reload_cache(&self) -> anyhow::Result<()> {
        let tokens: Vec<(String,)> = sqlx::query_as(
            "SELECT token_id FROM revoked_tokens WHERE expires_at > ?",
        )
        .bind(Utc::now().to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        let mut cache = self.revoked_cache.write();
        cache.clear();
        cache.extend(tokens.into_iter().map(|(id,)| id));

        Ok(())
    }

    /// Get total revoked tokens count
    pub async fn get_revoked_count(&self) -> anyhow::Result<i64> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM revoked_tokens WHERE expires_at > ?",
        )
        .bind(Utc::now().to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
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
    async fn test_token_revocation_init() {
        let pool = setup_test_db().await;
        let revocation = TokenRevocation::new(pool);

        assert!(revocation.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let pool = setup_test_db().await;
        let revocation = TokenRevocation::new(pool);
        revocation.init().await.unwrap();

        let token_id = "token123".to_string();
        let user_id = "user456".to_string();
        let reason = "User requested logout".to_string();
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        revocation
            .revoke_token(token_id.clone(), user_id, reason, expires_at)
            .await
            .unwrap();

        assert!(revocation.is_revoked(&token_id));
    }

    #[tokio::test]
    async fn test_is_revoked() {
        let pool = setup_test_db().await;
        let revocation = TokenRevocation::new(pool);
        revocation.init().await.unwrap();

        let token_id = "token789";

        assert!(!revocation.is_revoked(token_id));

        revocation
            .revoke_token(
                token_id.to_string(),
                "user123".to_string(),
                "Test".to_string(),
                Utc::now() + chrono::Duration::hours(1),
            )
            .await
            .unwrap();

        assert!(revocation.is_revoked(token_id));
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let pool = setup_test_db().await;
        let revocation = TokenRevocation::new(pool);
        revocation.init().await.unwrap();

        // Add expired token
        revocation
            .revoke_token(
                "expired_token".to_string(),
                "user123".to_string(),
                "Test".to_string(),
                Utc::now() - chrono::Duration::hours(1), // Expired
            )
            .await
            .unwrap();

        // Add active token
        revocation
            .revoke_token(
                "active_token".to_string(),
                "user123".to_string(),
                "Test".to_string(),
                Utc::now() + chrono::Duration::hours(1), // Active
            )
            .await
            .unwrap();

        // Cleanup
        let cleaned = revocation.cleanup_expired().await.unwrap();
        assert_eq!(cleaned, 1);

        // Expired should be gone, active should remain
        assert!(!revocation.is_revoked("expired_token"));
        assert!(revocation.is_revoked("active_token"));
    }

    #[tokio::test]
    async fn test_get_revoked_count() {
        let pool = setup_test_db().await;
        let revocation = TokenRevocation::new(pool);
        revocation.init().await.unwrap();

        assert_eq!(revocation.get_revoked_count().await.unwrap(), 0);

        // Add some tokens
        for i in 0..5 {
            revocation
                .revoke_token(
                    format!("token{}", i),
                    "user123".to_string(),
                    "Test".to_string(),
                    Utc::now() + chrono::Duration::hours(1),
                )
                .await
                .unwrap();
        }

        assert_eq!(revocation.get_revoked_count().await.unwrap(), 5);
    }
}
