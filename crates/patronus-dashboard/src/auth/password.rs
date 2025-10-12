//! Password hashing and verification using Argon2id

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::{ApiError, Result};

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    Ok(password_hash)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| ApiError::Internal(format!("Invalid password hash: {}", e)))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(ApiError::InvalidRequest(
            "Password must be at least 12 characters long".to_string(),
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase {
        return Err(ApiError::InvalidRequest(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if !has_lowercase {
        return Err(ApiError::InvalidRequest(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if !has_digit {
        return Err(ApiError::InvalidRequest(
            "Password must contain at least one digit".to_string(),
        ));
    }

    if !has_special {
        return Err(ApiError::InvalidRequest(
            "Password must contain at least one special character".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "MySecurePassword123!";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_password_strength_validation() {
        // Valid password
        assert!(validate_password_strength("SecurePass123!").is_ok());

        // Too short
        assert!(validate_password_strength("Short1!").is_err());

        // No uppercase
        assert!(validate_password_strength("noupppercase123!").is_err());

        // No lowercase
        assert!(validate_password_strength("NOLOWERCASE123!").is_err());

        // No digit
        assert!(validate_password_strength("NoDigitPassword!").is_err());

        // No special character
        assert!(validate_password_strength("NoSpecialChar123").is_err());
    }
}
