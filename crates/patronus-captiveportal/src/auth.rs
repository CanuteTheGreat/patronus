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
    FreeAccess, // No authentication, just click-through
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
    #[allow(dead_code)]
    server: String,
    #[allow(dead_code)]
    secret: String,
    #[allow(dead_code)]
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
    async fn authenticate(&self, _credentials: &AuthCredentials) -> Result<AuthResult, AuthError> {
        // No RADIUS client is wired up yet (no Access-Request is ever sent to
        // `self.server`). This used to return `success: true` for *any*
        // credentials -- including a missing/empty username and password --
        // so registering a RadiusAuthProvider with the captive portal (which
        // `handle_login` now really consults) silently granted network access
        // to every client that typed anything. Fail closed until a real
        // RADIUS exchange is implemented: an unimplemented authenticator must
        // never authenticate.
        Err(AuthError::Unavailable)
    }

    fn name(&self) -> &str {
        "RADIUS"
    }
}

// Local username/password provider
pub struct LocalAuthProvider {
    users: std::collections::HashMap<String, String>, // username -> password hash
}

impl Default for LocalAuthProvider {
    fn default() -> Self {
        Self::new()
    }
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
        let username = credentials
            .username
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
        let password = credentials
            .password
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        if let Some(stored_hash) = self.users.get(username) {
            if stored_hash == password {
                // In production: verify hash
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

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(username: Option<&str>, password: Option<&str>) -> AuthCredentials {
        AuthCredentials {
            username: username.map(str::to_string),
            password: password.map(str::to_string),
            email: None,
            phone: None,
            oauth_token: None,
        }
    }

    #[tokio::test]
    async fn radius_provider_without_a_real_backend_fails_closed() {
        let provider = RadiusAuthProvider::new("127.0.0.1:1812".into(), "secret".into());
        for c in [
            creds(Some("alice"), Some("correct-horse")),
            creds(Some("alice"), Some("")),
            creds(None, None),
        ] {
            assert!(
                matches!(provider.authenticate(&c).await, Err(AuthError::Unavailable)),
                "unimplemented RADIUS provider must never authenticate"
            );
        }
    }

    #[tokio::test]
    async fn local_provider_accepts_only_matching_password() {
        let mut provider = LocalAuthProvider::new();
        provider.add_user("alice".into(), "s3cret".into());
        let ok = provider
            .authenticate(&creds(Some("alice"), Some("s3cret")))
            .await
            .unwrap();
        assert!(ok.success);
        assert_eq!(ok.user_id, "alice");
        assert!(provider
            .authenticate(&creds(Some("alice"), Some("wrong")))
            .await
            .is_err());
        assert!(provider
            .authenticate(&creds(Some("bob"), Some("s3cret")))
            .await
            .is_err());
        assert!(provider.authenticate(&creds(None, None)).await.is_err());
    }
}
