//! JWT token generation and validation

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, Result};

/// JWT secret key (should be loaded from environment in production)
const JWT_SECRET: &[u8] = b"your-secret-key-change-in-production";

/// Access token expiration (15 minutes)
const ACCESS_TOKEN_EXPIRY: i64 = 15 * 60;

/// Refresh token expiration (7 days)
const REFRESH_TOKEN_EXPIRY: i64 = 7 * 24 * 60 * 60;

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// User email
    pub email: String,

    /// User role
    pub role: String,

    /// Issued at (timestamp)
    pub iat: i64,

    /// Expiration time (timestamp)
    pub exp: i64,

    /// Token type (access or refresh)
    pub token_type: TokenType,

    /// JWT ID (for token revocation)
    pub jti: String,
}

/// Token type
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

/// Token pair (access + refresh)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Generate JWT token pair (access + refresh)
pub fn generate_tokens(user_id: &str, email: &str, role: &str) -> Result<TokenPair> {
    let now = Utc::now();

    // Generate access token
    let access_claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ACCESS_TOKEN_EXPIRY)).timestamp(),
        token_type: TokenType::Access,
        jti: Uuid::new_v4().to_string(),
    };

    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| ApiError::Internal(format!("Failed to generate access token: {}", e)))?;

    // Generate refresh token
    let refresh_claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(REFRESH_TOKEN_EXPIRY)).timestamp(),
        token_type: TokenType::Refresh,
        jti: Uuid::new_v4().to_string(),
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| ApiError::Internal(format!("Failed to generate refresh token: {}", e)))?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_EXPIRY,
    })
}

/// Validate JWT token and extract claims
pub fn validate_token(token: &str) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            ApiError::Unauthorized("Token expired".to_string())
        }
        _ => ApiError::Unauthorized(format!("Invalid token: {}", e)),
    })?;

    Ok(token_data.claims)
}

/// Refresh access token using refresh token
pub fn refresh_access_token(refresh_token: &str) -> Result<TokenPair> {
    let claims = validate_token(refresh_token)?;

    // Verify this is a refresh token
    if claims.token_type != TokenType::Refresh {
        return Err(ApiError::Unauthorized(
            "Invalid token type".to_string(),
        ));
    }

    // Generate new token pair
    generate_tokens(&claims.sub, &claims.email, &claims.role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_validate_tokens() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");

        // Validate access token
        let claims = validate_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_refresh_token() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        // Refresh using refresh token
        let new_tokens = refresh_access_token(&tokens.refresh_token).unwrap();

        assert!(!new_tokens.access_token.is_empty());
        assert_ne!(new_tokens.access_token, tokens.access_token);
    }

    #[test]
    fn test_invalid_token() {
        let result = validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_token_type_for_refresh() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        // Try to refresh using access token (should fail)
        let result = refresh_access_token(&tokens.access_token);
        assert!(result.is_err());
    }
}
