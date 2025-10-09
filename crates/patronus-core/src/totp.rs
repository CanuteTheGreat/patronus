//! Two-Factor Authentication (TOTP)
//!
//! Time-based One-Time Password authentication for admin login.
//! Compatible with Google Authenticator, Authy, etc.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// TOTP configuration for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub enabled: bool,
    pub secret: String,           // Base32-encoded secret
    pub issuer: String,           // "Patronus Firewall"
    pub account_name: String,     // Username
    pub digits: u32,              // Usually 6
    pub period: u64,              // Seconds, usually 30
    pub algorithm: TotpAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

/// 2FA settings for the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorConfig {
    pub enabled: bool,
    pub required_for_admin: bool,  // Require for admin login
    pub required_for_users: bool,  // Require for regular users
    pub grace_period_days: u32,    // Days to enroll after enabling
    pub backup_codes_count: u32,   // Number of backup codes to generate
}

/// User's 2FA enrollment status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorEnrollment {
    pub user_id: u32,
    pub username: String,
    pub enrolled: bool,
    pub totp: Option<TotpConfig>,
    pub backup_codes: Vec<String>,
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct TotpManager {
    config: TotpConfig,
}

impl TotpManager {
    pub fn new(config: TotpConfig) -> Self {
        Self { config }
    }

    /// Generate a new TOTP secret
    pub fn generate_secret() -> String {
        use rand::Rng;
        const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        let mut rng = rand::thread_rng();
        let secret: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..BASE32_CHARS.len());
                BASE32_CHARS[idx] as char
            })
            .collect();

        secret
    }

    /// Generate QR code URL for enrollment
    pub fn generate_qr_url(&self) -> String {
        // otpauth://totp/Issuer:account?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={:?}&digits={}&period={}",
            urlencoding::encode(&self.config.issuer),
            urlencoding::encode(&self.config.account_name),
            self.config.secret,
            urlencoding::encode(&self.config.issuer),
            self.config.algorithm,
            self.config.digits,
            self.config.period
        )
    }

    /// Verify a TOTP code
    pub fn verify(&self, code: &str) -> Result<bool> {
        let code_num: u32 = code.parse()
            .map_err(|_| Error::Auth("Invalid TOTP code format".to_string()))?;

        // Get current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Auth("System time error".to_string()))?
            .as_secs();

        // Check current time window
        if self.verify_time_window(code_num, now)? {
            return Ok(true);
        }

        // Check previous time window (allow 30 second skew)
        if now >= self.config.period {
            if self.verify_time_window(code_num, now - self.config.period)? {
                return Ok(true);
            }
        }

        // Check next time window (allow 30 second skew)
        if self.verify_time_window(code_num, now + self.config.period)? {
            return Ok(true);
        }

        Ok(false)
    }

    fn verify_time_window(&self, code: u32, time: u64) -> Result<bool> {
        let expected = self.generate_code_at(time)?;
        Ok(code == expected)
    }

    /// Generate TOTP code for current time
    pub fn generate_code(&self) -> Result<u32> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Auth("System time error".to_string()))?
            .as_secs();

        self.generate_code_at(now)
    }

    fn generate_code_at(&self, time: u64) -> Result<u32> {
        let counter = time / self.config.period;

        // Decode base32 secret
        let key = self.decode_base32(&self.config.secret)?;

        // Generate HMAC
        let hmac = match self.config.algorithm {
            TotpAlgorithm::SHA1 => self.hmac_sha1(&key, counter),
            TotpAlgorithm::SHA256 => self.hmac_sha256(&key, counter),
            TotpAlgorithm::SHA512 => self.hmac_sha512(&key, counter),
        };

        // Dynamic truncation
        let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
        let code = u32::from_be_bytes([
            hmac[offset] & 0x7f,
            hmac[offset + 1],
            hmac[offset + 2],
            hmac[offset + 3],
        ]);

        // Get last N digits
        let modulo = 10_u32.pow(self.config.digits);
        Ok(code % modulo)
    }

    fn decode_base32(&self, input: &str) -> Result<Vec<u8>> {
        // Simplified base32 decoder
        // In production, use a proper base32 library
        let input = input.to_uppercase().replace('=', "");
        let mut output = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;

        for c in input.chars() {
            let value = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                '2'..='7' => c as u32 - '2' as u32 + 26,
                _ => return Err(Error::Auth("Invalid base32 character".to_string())),
            };

            buffer = (buffer << 5) | value;
            bits += 5;

            if bits >= 8 {
                output.push((buffer >> (bits - 8)) as u8);
                bits -= 8;
            }
        }

        Ok(output)
    }

    fn hmac_sha1(&self, key: &[u8], counter: u64) -> Vec<u8> {
        use sha1::{Sha1, Digest};
        use hmac::{Hmac, Mac};

        type HmacSha1 = Hmac<Sha1>;

        let mut mac = HmacSha1::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(&counter.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    fn hmac_sha256(&self, key: &[u8], counter: u64) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(&counter.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    fn hmac_sha512(&self, key: &[u8], counter: u64) -> Vec<u8> {
        use sha2::{Sha512, Digest};
        use hmac::{Hmac, Mac};

        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(&counter.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Generate backup codes
    pub fn generate_backup_codes(count: u32) -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        (0..count)
            .map(|_| {
                format!("{:04}-{:04}-{:04}",
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000))
            })
            .collect()
    }

    /// Hash a backup code for storage
    pub fn hash_backup_code(code: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verify a backup code
    pub fn verify_backup_code(code: &str, hash: &str) -> bool {
        Self::hash_backup_code(code) == hash
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: TotpManager::generate_secret(),
            issuer: "Patronus Firewall".to_string(),
            account_name: "admin".to_string(),
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::SHA1,
        }
    }
}

impl Default for TwoFactorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required_for_admin: true,
            required_for_users: false,
            grace_period_days: 7,
            backup_codes_count: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let secret = TotpManager::generate_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));
    }

    #[test]
    fn test_qr_url_generation() {
        let config = TotpConfig {
            enabled: true,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: "Patronus".to_string(),
            account_name: "test@example.com".to_string(),
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::SHA1,
        };

        let manager = TotpManager::new(config);
        let url = manager.generate_qr_url();

        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("Patronus"));
        assert!(url.contains("test%40example.com"));
        assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_backup_code_generation() {
        let codes = TotpManager::generate_backup_codes(10);
        assert_eq!(codes.len(), 10);

        for code in &codes {
            // Format: XXXX-XXXX-XXXX
            assert_eq!(code.len(), 14);
            assert_eq!(code.chars().nth(4), Some('-'));
            assert_eq!(code.chars().nth(9), Some('-'));
        }
    }

    #[test]
    fn test_backup_code_verification() {
        let code = "1234-5678-9012";
        let hash = TotpManager::hash_backup_code(code);

        assert!(TotpManager::verify_backup_code(code, &hash));
        assert!(!TotpManager::verify_backup_code("0000-0000-0000", &hash));
    }
}
