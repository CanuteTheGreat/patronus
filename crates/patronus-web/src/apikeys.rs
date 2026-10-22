//! API keys for automation (lane H): long-lived bearer tokens for
//! collectors (Rustinion), Terraform and scripts, so they do not need a
//! web login.
//!
//! - Only a SHA-256 digest is stored (`api_keys.token_hash`); the token
//!   (`pat_` + 40 random letters/digits) is shown once, at creation.
//! - Two scopes: `readonly` (GET/HEAD only) and `operator` (may change
//!   configuration). A key is never an admin: accounts, backups/restores,
//!   key management and the account's own password/2FA need a logged-in
//!   admin session.
//! - Send it as `Authorization: Bearer pat_...` or `X-API-Key: pat_...`.
//!   A bad or expired key is a 401, never a fallback to a cookie.

use crate::auth::UserRole;
use patronus_config::ConfigStore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;

pub const TOKEN_PREFIX: &str = "pat_";

/// A stored key (never the token).
#[derive(Debug, Clone, Serialize)]
pub struct ApiKey {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub scope: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

impl ApiKey {
    pub fn role(&self) -> UserRole {
        match self.scope.as_str() {
            "operator" => UserRole::Operator,
            _ => UserRole::ReadOnly,
        }
    }
}

#[derive(Clone)]
pub struct ApiKeyStore {
    store: Arc<ConfigStore>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn digest(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn generate() -> String {
    use rand::Rng;
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    let body: String = (0..40)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect();
    format!("{TOKEN_PREFIX}{body}")
}

/// 1-40 letters, digits, `-`, `_`, `.`, space.
pub fn check_name(s: &str) -> anyhow::Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 40
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        anyhow::bail!("Invalid key name {s:?}: 1-40 letters, digits, '-', '_', '.' or spaces");
    }
    Ok(s.to_string())
}

fn row(r: &sqlx::sqlite::SqliteRow) -> ApiKey {
    ApiKey {
        id: r.get(0),
        name: r.get(1),
        prefix: r.get(2),
        scope: r.get(3),
        created_by: r.get(4),
        created_at: r.get(5),
        expires_at: r.get(6),
        last_used_at: r.get(7),
    }
}

const COLS: &str = "id, name, prefix, scope, created_by, created_at, expires_at, last_used_at";

impl ApiKeyStore {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self { store }
    }

    fn pool(&self) -> anyhow::Result<&sqlx::SqlitePool> {
        self.store
            .pool()
            .map_err(|e| anyhow::anyhow!("config store: {e}"))
    }

    pub async fn list(&self) -> anyhow::Result<Vec<ApiKey>> {
        let rows = sqlx::query(&format!("SELECT {COLS} FROM api_keys ORDER BY name"))
            .fetch_all(self.pool()?)
            .await?;
        Ok(rows.iter().map(row).collect())
    }

    /// Create a key; returns it with the token (shown once).
    pub async fn create(
        &self,
        name: &str,
        scope: &str,
        expires_in_days: Option<u32>,
        created_by: &str,
    ) -> anyhow::Result<(ApiKey, String)> {
        let name = check_name(name)?;
        if !matches!(scope, "readonly" | "operator") {
            anyhow::bail!("Invalid scope {scope:?}: readonly or operator");
        }
        if matches!(expires_in_days, Some(0) | Some(3651..)) {
            anyhow::bail!("Invalid expiry: 1-3650 days (or none)");
        }
        let token = generate();
        let prefix: String = token.chars().take(TOKEN_PREFIX.len() + 4).collect();
        let created = now();
        let expires = expires_in_days.map(|d| created + i64::from(d) * 86400);
        let r = sqlx::query(
            "INSERT INTO api_keys (name, prefix, token_hash, scope, created_by, created_at, expires_at)
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(&name)
        .bind(&prefix)
        .bind(digest(&token))
        .bind(scope)
        .bind(created_by)
        .bind(created)
        .bind(expires)
        .execute(self.pool()?)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                anyhow::anyhow!("Invalid key name: {name} already exists")
            } else {
                anyhow::anyhow!("saving the key: {e}")
            }
        })?;
        let key = ApiKey {
            id: r.last_insert_rowid(),
            name,
            prefix,
            scope: scope.to_string(),
            created_by: created_by.to_string(),
            created_at: created,
            expires_at: expires,
            last_used_at: None,
        };
        Ok((key, token))
    }

    pub async fn delete(&self, id: i64) -> anyhow::Result<bool> {
        let r = sqlx::query("DELETE FROM api_keys WHERE id=?")
            .bind(id)
            .execute(self.pool()?)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The key a token belongs to, if it exists and has not expired.
    /// `last_used_at` is refreshed at most once a minute.
    pub async fn verify(&self, token: &str) -> Option<ApiKey> {
        if !token.starts_with(TOKEN_PREFIX) || token.len() > 128 {
            return None;
        }
        let pool = self.pool().ok()?;
        let r = sqlx::query(&format!("SELECT {COLS} FROM api_keys WHERE token_hash=?"))
            .bind(digest(token))
            .fetch_optional(pool)
            .await
            .ok()??;
        let key = row(&r);
        let t = now();
        if key.expires_at.is_some_and(|e| e <= t) {
            return None;
        }
        if key.last_used_at.is_none_or(|l| t - l >= 60) {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at=? WHERE id=?")
                .bind(t)
                .bind(key.id)
                .execute(pool)
                .await;
        }
        Some(key)
    }
}

/// The token of a request: `Authorization: Bearer ...` or `X-API-Key`.
pub fn request_token(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(v) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let (scheme, rest) = v.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") {
            return Some(rest.trim().to_string());
        }
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
}

/// Set on a request by the auth gate when it carried a valid key.
#[derive(Debug, Clone)]
pub struct ApiKeyPrincipal(pub ApiKey);

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> ApiKeyStore {
        ApiKeyStore::new(Arc::new(ConfigStore::open_in_memory().await.unwrap()))
    }

    #[tokio::test]
    async fn tokens_are_hashed_verified_expired_and_revoked() {
        let s = store().await;
        let (k, token) = s
            .create("rustinion", "readonly", None, "admin")
            .await
            .unwrap();
        assert!(token.starts_with("pat_") && token.len() == 44, "{token}");
        assert_eq!(k.prefix, &token[..8]);
        // the token is not stored
        let raw: String = sqlx::query_scalar("SELECT token_hash FROM api_keys")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(raw, digest(&token));
        assert!(!raw.contains(&token));

        let v = s.verify(&token).await.expect("valid token");
        assert_eq!(v.name, "rustinion");
        assert_eq!(v.role(), UserRole::ReadOnly);
        assert!(s.verify("pat_nope").await.is_none());
        assert!(s.verify(&token[..43]).await.is_none());
        assert!(s.verify("").await.is_none());
        // last_used is recorded
        assert!(s.list().await.unwrap()[0].last_used_at.is_some());

        // expiry
        let (_, t2) = s
            .create("short", "operator", Some(1), "admin")
            .await
            .unwrap();
        assert_eq!(s.verify(&t2).await.unwrap().role(), UserRole::Operator);
        sqlx::query("UPDATE api_keys SET expires_at = ? WHERE name='short'")
            .bind(now() - 5)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert!(s.verify(&t2).await.is_none(), "expired key still works");

        // revoke
        assert!(s.delete(k.id).await.unwrap());
        assert!(s.verify(&token).await.is_none());
        assert!(!s.delete(k.id).await.unwrap());
    }

    #[tokio::test]
    async fn names_scopes_and_expiry_are_validated() {
        let s = store().await;
        for bad in ["", "  ", "a/b", "x'y", &"n".repeat(41)] {
            let e = s.create(bad, "readonly", None, "a").await.unwrap_err();
            assert!(e.to_string().starts_with("Invalid"), "{bad}: {e}");
        }
        let e = s.create("k", "admin", None, "a").await.unwrap_err();
        assert!(e.to_string().starts_with("Invalid scope"), "{e}");
        let e = s.create("k", "readonly", Some(0), "a").await.unwrap_err();
        assert!(e.to_string().starts_with("Invalid expiry"), "{e}");
        s.create("k", "readonly", Some(30), "a").await.unwrap();
        let e = s.create("k", "readonly", None, "a").await.unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
    }

    #[test]
    fn the_token_is_read_from_either_header() {
        use axum::http::{header, HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        assert_eq!(request_token(&h), None);
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer pat_abc"),
        );
        assert_eq!(request_token(&h).as_deref(), Some("pat_abc"));
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  pat_abc "),
        );
        assert_eq!(request_token(&h).as_deref(), Some("pat_abc"));
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("pat_xyz"));
        assert_eq!(request_token(&h).as_deref(), Some("pat_xyz"));
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9v"),
        );
        assert_eq!(request_token(&h), None);
    }
}
