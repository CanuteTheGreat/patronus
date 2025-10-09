//! Authentication providers for captive portal

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Voucher,
    UsernamePassword,
    Email,
    SMS,
    Facebook,
    Google,
    RADIUS,
    LDAP,
    FreeAccess,  // No authentication, just click-through
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, credentials: &AuthCredentials) -> Result<AuthResult, AuthError>;
    fn name(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub oauth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub user_id: String,
    pub user_info: UserInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Authentication failed: {0}")]
    Failed(String),
    #[error("Provider unavailable")]
    Unavailable,
}

// RADIUS authentication provider
pub struct RadiusAuthProvider {
    server: String,
    secret: String,
    timeout_secs: u64,
}

impl RadiusAuthProvider {
    pub fn new(server: String, secret: String) -> Self {
        Self {
            server,
            secret,
            timeout_secs: 5,
        }
    }
}

#[async_trait]
impl AuthProvider for RadiusAuthProvider {
    async fn authenticate(&self, credentials: &AuthCredentials) -> Result<AuthResult, AuthError> {
        // Implement RADIUS authentication
        // Would use radius crate in production
        Ok(AuthResult {
            success: true,
            user_id: credentials.username.clone().unwrap_or_default(),
            user_info: UserInfo {
                name: credentials.username.clone(),
                email: None,
                groups: vec![],
            },
        })
    }

    fn name(&self) -> &str {
        "RADIUS"
    }
}

// Local username/password provider
pub struct LocalAuthProvider {
    users: std::collections::HashMap<String, String>,  // username -> password hash
}

impl LocalAuthProvider {
    pub fn new() -> Self {
        Self {
            users: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: String, password: String) {
        // In production, hash the password with bcrypt/argon2
        self.users.insert(username, password);
    }
}

#[async_trait]
impl AuthProvider for LocalAuthProvider {
    async fn authenticate(&self, credentials: &AuthCredentials) -> Result<AuthResult, AuthError> {
        let username = credentials.username.as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
        let password = credentials.password.as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        if let Some(stored_hash) = self.users.get(username) {
            if stored_hash == password {  // In production: verify hash
                return Ok(AuthResult {
                    success: true,
                    user_id: username.clone(),
                    user_info: UserInfo {
                        name: Some(username.clone()),
                        email: None,
                        groups: vec!["guests".to_string()],
                    },
                });
            }
        }

        Err(AuthError::InvalidCredentials)
    }

    fn name(&self) -> &str {
        "Local"
    }
}
