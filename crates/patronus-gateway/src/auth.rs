//! Authentication and Authorization

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub roles: Vec<String>,
}

pub struct JwtValidator {
    secret: String,
}

impl JwtValidator {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }

    pub fn create_token(&self, user_id: &str, roles: Vec<String>, ttl_seconds: u64) -> Result<String> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            + ttl_seconds;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration,
            roles,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )?;

        Ok(token_data.claims)
    }

    pub fn check_permission(&self, claims: &Claims, required_role: &str) -> bool {
        claims.roles.iter().any(|r| r == required_role)
    }
}

pub struct AuthService {
    jwt_validator: JwtValidator,
}

impl AuthService {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            jwt_validator: JwtValidator::new(secret),
        }
    }

    pub fn authenticate(&self, token: &str) -> Result<Claims> {
        self.jwt_validator.validate_token(token)
    }

    pub fn authorize(&self, claims: &Claims, required_role: &str) -> bool {
        self.jwt_validator.check_permission(claims, required_role)
    }

    pub fn create_session(&self, user_id: &str, roles: Vec<String>) -> Result<String> {
        self.jwt_validator.create_token(user_id, roles, 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation_and_validation() {
        let validator = JwtValidator::new("secret");

        let token = validator.create_token("user123", vec!["admin".to_string()], 3600).unwrap();
        let claims = validator.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert!(claims.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_permission_check() {
        let validator = JwtValidator::new("secret");

        let claims = Claims {
            sub: "user123".to_string(),
            exp: u64::MAX,
            roles: vec!["admin".to_string(), "operator".to_string()],
        };

        assert!(validator.check_permission(&claims, "admin"));
        assert!(validator.check_permission(&claims, "operator"));
        assert!(!validator.check_permission(&claims, "superadmin"));
    }

    #[test]
    fn test_auth_service() {
        let service = AuthService::new("secret");

        let token = service.create_session("user123", vec!["viewer".to_string()]).unwrap();
        let claims = service.authenticate(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert!(service.authorize(&claims, "viewer"));
        assert!(!service.authorize(&claims, "admin"));
    }
}
