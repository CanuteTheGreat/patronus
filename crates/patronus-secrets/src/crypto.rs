//! Cryptographic operations for secret encryption and key derivation

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use rand::RngCore;
use zeroize::Zeroize;

const NONCE_SIZE: usize = 12; // 96 bits for GCM

/// Derive an encryption key from a password using Argon2id
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let argon2 = Argon2::default();

    // Use Argon2id for key derivation
    let mut output_key = [0u8; 32]; // 256 bits
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

    Ok(output_key.to_vec())
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypt a secret using AES-256-GCM
pub fn encrypt_secret(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes for AES-256"));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .context("Failed to create cipher")?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a secret using AES-256-GCM
pub fn decrypt_secret(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Key must be 32 bytes for AES-256"));
    }

    if encrypted.len() < NONCE_SIZE {
        return Err(anyhow::anyhow!("Invalid encrypted data: too short"));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .context("Failed to create cipher")?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Hash a password for storage using Argon2id
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| anyhow::anyhow!("Invalid hash format: {}", e))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Secure random token generation
pub fn generate_token(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

/// Generate a cryptographically secure random password
pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut password = Vec::with_capacity(length);
    let mut rng_bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut rng_bytes);

    for byte in rng_bytes {
        let idx = (byte as usize) % CHARSET.len();
        password.push(CHARSET[idx]);
    }

    String::from_utf8(password).expect("Valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let plaintext = b"super secret password";
        let salt = generate_salt();
        let key = derive_key("master_password", &salt).unwrap();

        let encrypted = encrypt_secret(plaintext, &key).unwrap();
        let decrypted = decrypt_secret(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_token_generation() {
        let token1 = generate_token(32);
        let token2 = generate_token(32);

        assert_ne!(token1, token2);
        assert!(token1.len() > 32); // Base64 encoded
    }

    #[test]
    fn test_password_generation() {
        let password = generate_password(20);
        assert_eq!(password.len(), 20);

        // Should contain mix of chars
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
    }
}
