//! Password and secret validation

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Password strength levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordStrength {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

/// Password validation requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub min_entropy_bits: f64,
    pub reject_common: bool,
    pub reject_defaults: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            min_entropy_bits: 50.0,
            reject_common: true,
            reject_defaults: true,
        }
    }
}

/// Common/default passwords to reject
const WEAK_PASSWORDS: &[&str] = &[
    "password", "Password1", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "shadow", "superman",
    "changeme", "secret", "default", "admin", "root", "test",
];

/// Validate password strength
pub fn validate_password_strength(password: &str) -> PasswordStrength {
    let length = password.len();
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let mut score = 0;

    // Length scoring
    if length >= 8 {
        score += 1;
    }
    if length >= 12 {
        score += 1;
    }
    if length >= 16 {
        score += 1;
    }
    if length >= 20 {
        score += 1;
    }

    // Character variety
    if has_lower {
        score += 1;
    }
    if has_upper {
        score += 1;
    }
    if has_digit {
        score += 1;
    }
    if has_special {
        score += 1;
    }

    // Entropy estimation
    let entropy = estimate_entropy(password);
    if entropy >= 50.0 {
        score += 1;
    }
    if entropy >= 70.0 {
        score += 1;
    }

    match score {
        0..=3 => PasswordStrength::Weak,
        4..=6 => PasswordStrength::Medium,
        7..=8 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

/// Estimate password entropy in bits
fn estimate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let mut charset_size = 0;

    if password.chars().any(|c| c.is_lowercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        charset_size += 26;
    }
    if password.chars().any(|c| c.is_numeric()) {
        charset_size += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        charset_size += 32; // Common special characters
    }

    let length = password.len() as f64;
    let charset = charset_size as f64;

    length * charset.log2()
}

/// Validate password against policy
pub fn validate_password(password: &str, policy: &PasswordPolicy) -> Result<()> {
    // Check length
    if password.len() < policy.min_length {
        bail!(
            "Password must be at least {} characters long",
            policy.min_length
        );
    }

    // Check character requirements
    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        bail!("Password must contain at least one uppercase letter");
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        bail!("Password must contain at least one lowercase letter");
    }

    if policy.require_digit && !password.chars().any(|c| c.is_numeric()) {
        bail!("Password must contain at least one digit");
    }

    if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
        bail!("Password must contain at least one special character");
    }

    // Check entropy
    let entropy = estimate_entropy(password);
    if entropy < policy.min_entropy_bits {
        bail!(
            "Password is too weak (entropy: {:.1} bits, required: {:.1} bits)",
            entropy,
            policy.min_entropy_bits
        );
    }

    // Check against common passwords
    if policy.reject_common {
        let password_lower = password.to_lowercase();
        for weak in WEAK_PASSWORDS {
            if password_lower == weak.to_lowercase() {
                bail!("Password is too common and easily guessable");
            }
        }
    }

    // Check for default/weak patterns
    if policy.reject_defaults {
        if password.to_lowercase().contains("changeme")
            || password.to_lowercase().contains("default")
            || password.to_lowercase().contains("password")
        {
            bail!("Password contains forbidden default patterns");
        }
    }

    Ok(())
}

/// Validate a secret key/token
pub fn validate_secret(secret: &str, min_length: usize) -> Result<()> {
    if secret.is_empty() {
        bail!("Secret cannot be empty");
    }

    if secret.len() < min_length {
        bail!("Secret must be at least {} characters", min_length);
    }

    // Check for common weak secrets
    if secret == "secret" || secret == "changeme" || secret == "default" {
        bail!("Secret is a default/weak value and must be changed");
    }

    Ok(())
}

/// Validate API key format
pub fn validate_api_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("API key cannot be empty");
    }

    if key.len() < 32 {
        bail!("API key must be at least 32 characters");
    }

    // Check for obvious test/default keys
    if key.starts_with("test_") || key.starts_with("demo_") || key == "your_api_key_here" {
        bail!("API key appears to be a placeholder or test key");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength() {
        assert_eq!(
            validate_password_strength("weak"),
            PasswordStrength::Weak
        );
        assert_eq!(
            validate_password_strength("Medium123"),
            PasswordStrength::Medium
        );
        assert_eq!(
            validate_password_strength("Strong123!@#"),
            PasswordStrength::Strong
        );
        assert_eq!(
            validate_password_strength("VeryStrong123!@#$%^&*()"),
            PasswordStrength::VeryStrong
        );
    }

    #[test]
    fn test_entropy_calculation() {
        assert!(estimate_entropy("abc") < 20.0);
        assert!(estimate_entropy("Abc123!@#") > 40.0);
        assert!(estimate_entropy("VeryLongPassword123!@#") > 100.0);
    }

    #[test]
    fn test_password_validation() {
        let policy = PasswordPolicy::default();

        // Too short
        assert!(validate_password("Short1!", &policy).is_err());

        // Missing uppercase
        assert!(validate_password("lowercase123!", &policy).is_err());

        // Missing special char
        assert!(validate_password("NoSpecial123", &policy).is_err());

        // Valid password
        assert!(validate_password("ValidPassword123!", &policy).is_ok());

        // Weak/common password
        assert!(validate_password("Password1!", &policy).is_err());
        assert!(validate_password("changeme123!", &policy).is_err());
    }

    #[test]
    fn test_secret_validation() {
        assert!(validate_secret("", 16).is_err());
        assert!(validate_secret("short", 16).is_err());
        assert!(validate_secret("secret", 16).is_err());
        assert!(validate_secret("changeme", 16).is_err());
        assert!(validate_secret("a_valid_long_secret_key_here", 16).is_ok());
    }

    #[test]
    fn test_api_key_validation() {
        assert!(validate_api_key("").is_err());
        assert!(validate_api_key("short").is_err());
        assert!(validate_api_key("test_key_123456789012345678901234").is_err());
        assert!(validate_api_key("sk_live_1234567890abcdef1234567890abcdef").is_ok());
    }
}
