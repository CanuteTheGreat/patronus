//! Multi-factor authentication (MFA) with TOTP support

use anyhow::{anyhow, Result};
use base32::Alphabet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// MFA method types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
}

/// TOTP secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub secret: String,
    pub qr_code_url: String,
    pub backup_codes: Vec<String>,
}

/// MFA manager
pub struct MfaManager {
    pool: SqlitePool,
    issuer: String,
}

impl MfaManager {
    /// Create a new MFA manager
    pub fn new(pool: SqlitePool, issuer: String) -> Self {
        Self { pool, issuer }
    }

    /// Initialize MFA tables
    pub async fn init(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id TEXT PRIMARY KEY,
                method TEXT NOT NULL,
                secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                verified_at DATETIME
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS mfa_backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                used_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES mfa_secrets(user_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Generate a new TOTP secret for a user
    pub async fn generate_totp_secret(&self, user_id: &str, email: &str) -> Result<TotpSecret> {
        // Generate random secret (20 bytes = 32 base32 chars)
        let secret_bytes: Vec<u8> = (0..20).map(|_| rand::thread_rng().gen()).collect();
        let secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        // Generate QR code URL for authenticator apps
        let qr_code_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            self.issuer,
            urlencoding::encode(email),
            secret,
            urlencoding::encode(&self.issuer)
        );

        // Generate backup codes
        let backup_codes = self.generate_backup_codes(10);

        // Store secret (not yet enabled)
        sqlx::query(
            "INSERT OR REPLACE INTO mfa_secrets (user_id, method, secret, enabled)
             VALUES (?, ?, ?, 0)",
        )
        .bind(user_id)
        .bind("totp")
        .bind(&secret)
        .execute(&self.pool)
        .await?;

        // Store backup codes
        for code in &backup_codes {
            let code_hash = self.hash_backup_code(code);
            sqlx::query(
                "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)",
            )
            .bind(user_id)
            .bind(code_hash)
            .execute(&self.pool)
            .await?;
        }

        Ok(TotpSecret {
            secret,
            qr_code_url,
            backup_codes,
        })
    }

    /// Verify TOTP code and enable MFA
    pub async fn verify_and_enable_totp(&self, user_id: &str, code: &str) -> Result<bool> {
        // Get secret
        let secret: (String,) = sqlx::query_as(
            "SELECT secret FROM mfa_secrets WHERE user_id = ? AND method = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("TOTP not set up for user"))?;

        // Verify code
        if self.verify_totp(&secret.0, code)? {
            // Enable MFA
            sqlx::query(
                "UPDATE mfa_secrets SET enabled = 1, verified_at = CURRENT_TIMESTAMP
                 WHERE user_id = ? AND method = 'totp'",
            )
            .bind(user_id)
            .execute(&self.pool)
            .await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Verify TOTP code for login
    pub async fn verify_totp_login(&self, user_id: &str, code: &str) -> Result<bool> {
        // Check if MFA is enabled
        let mfa_enabled: (i32,) = sqlx::query_as(
            "SELECT enabled FROM mfa_secrets WHERE user_id = ? AND method = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("MFA not enabled"))?;

        if mfa_enabled.0 == 0 {
            return Err(anyhow!("MFA not enabled for user"));
        }

        // Get secret
        let secret: (String,) = sqlx::query_as(
            "SELECT secret FROM mfa_secrets WHERE user_id = ? AND method = 'totp'",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        self.verify_totp(&secret.0, code)
    }

    /// Verify backup code
    pub async fn verify_backup_code(&self, user_id: &str, code: &str) -> Result<bool> {
        let code_hash = self.hash_backup_code(code);

        // Find unused backup code
        let backup_code: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM mfa_backup_codes
             WHERE user_id = ? AND code_hash = ? AND used = 0",
        )
        .bind(user_id)
        .bind(&code_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((id,)) = backup_code {
            // Mark as used
            sqlx::query(
                "UPDATE mfa_backup_codes SET used = 1, used_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
            )
            .bind(id)
            .execute(&self.pool)
            .await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if user has MFA enabled
    pub async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool> {
        let result: Option<(i32,)> = sqlx::query_as(
            "SELECT enabled FROM mfa_secrets WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|(enabled,)| enabled != 0).unwrap_or(false))
    }

    /// Disable MFA for user
    pub async fn disable_mfa(&self, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM mfa_secrets WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        sqlx::query("DELETE FROM mfa_backup_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Generate backup codes
    fn generate_backup_codes(&self, count: usize) -> Vec<String> {
        (0..count)
            .map(|_| {
                let code: String = (0..8)
                    .map(|_| {
                        let idx = rand::thread_rng().gen_range(0..36);
                        if idx < 10 {
                            (b'0' + idx) as char
                        } else {
                            (b'A' + (idx - 10)) as char
                        }
                    })
                    .collect();
                format!("{}-{}", &code[0..4], &code[4..8])
            })
            .collect()
    }

    /// Hash backup code
    fn hash_backup_code(&self, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verify TOTP code
    fn verify_totp(&self, secret: &str, code: &str) -> Result<bool> {
        // Decode base32 secret
        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| anyhow!("Invalid secret"))?;

        // Get current time step (30 second intervals)
        let time_step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            / 30;

        // Check current time step and ±1 for clock drift
        for offset in [-1, 0, 1] {
            let test_step = (time_step as i64 + offset) as u64;
            let generated_code = self.generate_totp(&secret_bytes, test_step)?;

            if generated_code == code {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Generate TOTP code for a given time step
    fn generate_totp(&self, secret: &[u8], time_step: u64) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        // Time step as 8-byte big-endian
        let time_bytes = time_step.to_be_bytes();

        // HMAC-SHA1
        let mut mac = HmacSha1::new_from_slice(secret)
            .map_err(|_| anyhow!("Invalid secret length"))?;
        mac.update(&time_bytes);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        // Dynamic truncation
        let offset = (bytes[19] & 0x0f) as usize;
        let code = u32::from_be_bytes([
            bytes[offset] & 0x7f,
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) % 1_000_000;

        Ok(format!("{:06}", code))
    }

    /// Get remaining backup codes count
    pub async fn get_backup_codes_count(&self, user_id: &str) -> Result<(usize, usize)> {
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT
                COUNT(CASE WHEN used = 0 THEN 1 END) as unused,
                COUNT(*) as total
             FROM mfa_backup_codes WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok((counts.0 as usize, counts.1 as usize))
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
    async fn test_mfa_init() {
        let pool = setup_test_db().await;
        let mfa = MfaManager::new(pool, "Patronus".to_string());

        assert!(mfa.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_generate_totp_secret() {
        let pool = setup_test_db().await;
        let mfa = MfaManager::new(pool, "Patronus".to_string());
        mfa.init().await.unwrap();

        let secret = mfa
            .generate_totp_secret("user123", "user@example.com")
            .await
            .unwrap();

        assert!(!secret.secret.is_empty());
        assert!(secret.qr_code_url.contains("otpauth://totp"));
        assert_eq!(secret.backup_codes.len(), 10);
    }

    #[tokio::test]
    async fn test_totp_verification() {
        let pool = setup_test_db().await;
        let mfa = MfaManager::new(pool, "Patronus".to_string());
        mfa.init().await.unwrap();

        // Generate secret
        let secret_data = mfa
            .generate_totp_secret("user123", "user@example.com")
            .await
            .unwrap();

        // Generate valid code
        let secret_bytes = base32::decode(
            Alphabet::Rfc4648 { padding: false },
            &secret_data.secret,
        )
        .unwrap();
        let time_step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let code = mfa.generate_totp(&secret_bytes, time_step).unwrap();

        // Verify and enable
        let verified = mfa.verify_and_enable_totp("user123", &code).await.unwrap();
        assert!(verified);

        // Check if enabled
        let enabled = mfa.is_mfa_enabled("user123").await.unwrap();
        assert!(enabled);
    }

    #[tokio::test]
    async fn test_backup_codes() {
        let pool = setup_test_db().await;
        let mfa = MfaManager::new(pool, "Patronus".to_string());
        mfa.init().await.unwrap();

        let secret = mfa
            .generate_totp_secret("user123", "user@example.com")
            .await
            .unwrap();

        // Verify one backup code
        let backup_code = &secret.backup_codes[0];
        let verified = mfa
            .verify_backup_code("user123", backup_code)
            .await
            .unwrap();
        assert!(verified);

        // Try to use same code again (should fail)
        let verified_again = mfa
            .verify_backup_code("user123", backup_code)
            .await
            .unwrap();
        assert!(!verified_again);

        // Check counts
        let (unused, total) = mfa.get_backup_codes_count("user123").await.unwrap();
        assert_eq!(unused, 9);
        assert_eq!(total, 10);
    }
}
