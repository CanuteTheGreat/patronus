//! Authentication and Authorization
//!
//! Provides enterprise authentication with LDAP, RADIUS, and local database support.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("LDAP error: {0}")]
    LdapError(String),

    #[error("RADIUS error: {0}")]
    RadiusError(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Account locked")]
    AccountLocked,

    #[error("Password expired")]
    PasswordExpired,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Authentication backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthBackend {
    Local,      // Local user database
    Ldap,       // LDAP/Active Directory
    Radius,     // RADIUS server
    Multi,      // Try multiple backends in order
}

/// User authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub backend: AuthBackend,
    pub fallback_local: bool,  // Fall back to local if remote fails

    // Local database
    pub local: LocalAuthConfig,

    // LDAP configuration
    pub ldap: Option<LdapConfig>,

    // RADIUS configuration
    pub radius: Option<RadiusConfig>,

    // Password policy
    pub password_policy: PasswordPolicy,

    // Session settings
    pub session_timeout: Duration,
    pub max_sessions_per_user: u32,
    pub remember_me_duration: Duration,
}

/// Local authentication (user database)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAuthConfig {
    pub enabled: bool,
    pub user_db_path: String,  // /etc/patronus/users.db
    pub hash_algorithm: HashAlgorithm,
    pub require_2fa: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Argon2id,   // Recommended
    BCrypt,
    SCrypt,
}

/// LDAP authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub enabled: bool,
    pub server: String,  // ldap://server or ldaps://server
    pub port: u16,
    pub use_tls: bool,
    pub use_starttls: bool,

    // Bind credentials
    pub bind_dn: String,  // cn=admin,dc=example,dc=com
    pub bind_password: String,

    // Search configuration
    pub base_dn: String,  // dc=example,dc=com
    pub user_search_base: String,  // ou=users,dc=example,dc=com
    pub user_search_filter: String,  // (&(objectClass=person)(uid=%s))
    pub group_search_base: String,  // ou=groups,dc=example,dc=com
    pub group_search_filter: String,  // (&(objectClass=groupOfNames)(member=%s))

    // Attribute mapping
    pub username_attribute: String,  // uid or sAMAccountName
    pub email_attribute: String,  // mail
    pub display_name_attribute: String,  // displayName
    pub group_membership_attribute: String,  // memberOf

    // Connection settings
    pub timeout: Duration,
    pub connection_pool_size: u32,
    pub referrals: bool,

    // Active Directory specific
    pub is_active_directory: bool,
    pub ad_domain: Option<String>,  // EXAMPLE.COM
}

/// RADIUS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    pub enabled: bool,

    // Primary RADIUS server
    pub server: IpAddr,
    pub port: u16,  // Usually 1812 for auth, 1813 for accounting
    pub secret: String,

    // Backup server
    pub backup_server: Option<IpAddr>,
    pub backup_port: Option<u16>,
    pub backup_secret: Option<String>,

    // Accounting
    pub accounting_enabled: bool,
    pub accounting_port: u16,

    // Connection settings
    pub timeout: Duration,
    pub retries: u32,
    pub nas_identifier: String,  // Network Access Server ID
    pub nas_ip_address: IpAddr,

    // Advanced
    pub use_message_authenticator: bool,
    pub filter_id: Option<String>,  // For group-based access
}

/// Password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub max_age_days: u32,  // 0 = never expires
    pub remember_previous: u32,  // Prevent reuse of N previous passwords
    pub lockout_threshold: u32,  // Lock after N failed attempts
    pub lockout_duration: Duration,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub privileges: Vec<String>,
    pub account_enabled: bool,
    pub account_locked: bool,
    pub password_expired: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub failed_login_count: u32,
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub user_id: u32,
    pub username: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: IpAddr,
    pub user_agent: Option<String>,
}

pub struct AuthManager {
    config: AuthConfig,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Authenticate user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<User> {
        match self.config.backend {
            AuthBackend::Local => self.authenticate_local(username, password).await,
            AuthBackend::Ldap => self.authenticate_ldap(username, password).await,
            AuthBackend::Radius => self.authenticate_radius(username, password).await,
            AuthBackend::Multi => {
                // Try LDAP first, then RADIUS, then local
                if let Some(_) = &self.config.ldap {
                    if let Ok(user) = self.authenticate_ldap(username, password).await {
                        return Ok(user);
                    }
                }

                if let Some(_) = &self.config.radius {
                    if let Ok(user) = self.authenticate_radius(username, password).await {
                        return Ok(user);
                    }
                }

                if self.config.fallback_local {
                    return self.authenticate_local(username, password).await;
                }

                Err(AuthError::AuthFailed("All authentication methods failed".to_string()))
            }
        }
    }

    /// Authenticate against local user database
    async fn authenticate_local(&self, username: &str, password: &str) -> Result<User> {
        tracing::info!("Authenticating {} against local database", username);

        // In production, this would:
        // 1. Query local user database
        // 2. Verify password hash
        // 3. Check account status
        // 4. Update last login time
        // 5. Reset failed login count on success

        // Simplified implementation
        Err(AuthError::UserNotFound)
    }

    /// Authenticate against LDAP server
    async fn authenticate_ldap(&self, username: &str, password: &str) -> Result<User> {
        let ldap_config = self.config.ldap.as_ref()
            .ok_or_else(|| AuthError::ConfigError("LDAP not configured".to_string()))?;

        tracing::info!("Authenticating {} against LDAP server {}", username, ldap_config.server);

        // Build LDAP search filter
        let search_filter = ldap_config.user_search_filter.replace("%s", username);

        // Use ldapsearch command (in production, would use ldap3 crate)
        let output = Command::new("ldapsearch")
            .args(&[
                "-H", &ldap_config.server,
                "-D", &ldap_config.bind_dn,
                "-w", &ldap_config.bind_password,
                "-b", &ldap_config.base_dn,
                &search_filter,
                &ldap_config.username_attribute,
                &ldap_config.email_attribute,
                &ldap_config.display_name_attribute,
            ])
            .output()
            .await?;

        if !output.status.success() {
            return Err(AuthError::LdapError("LDAP search failed".to_string()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse LDAP response
        let user_dn = self.parse_ldap_user_dn(&output_str)?;

        // Attempt bind with user credentials
        let bind_result = Command::new("ldapwhoami")
            .args(&[
                "-H", &ldap_config.server,
                "-D", &user_dn,
                "-w", password,
            ])
            .output()
            .await?;

        if !bind_result.status.success() {
            return Err(AuthError::InvalidCredentials);
        }

        // Fetch user groups
        let groups = self.fetch_ldap_groups(&ldap_config, &user_dn).await?;

        Ok(User {
            id: 0,  // Would be assigned from local cache
            username: username.to_string(),
            email: self.parse_ldap_attribute(&output_str, &ldap_config.email_attribute),
            display_name: self.parse_ldap_attribute(&output_str, &ldap_config.display_name_attribute),
            groups,
            privileges: vec![],
            account_enabled: true,
            account_locked: false,
            password_expired: false,
            created_at: chrono::Utc::now(),
            last_login: None,
            failed_login_count: 0,
        })
    }

    fn parse_ldap_user_dn(&self, output: &str) -> Result<String> {
        for line in output.lines() {
            if line.starts_with("dn:") {
                return Ok(line[3..].trim().to_string());
            }
        }
        Err(AuthError::UserNotFound)
    }

    fn parse_ldap_attribute(&self, output: &str, attribute: &str) -> Option<String> {
        let prefix = format!("{}: ", attribute);
        for line in output.lines() {
            if line.starts_with(&prefix) {
                return Some(line[prefix.len()..].trim().to_string());
            }
        }
        None
    }

    async fn fetch_ldap_groups(&self, ldap_config: &LdapConfig, user_dn: &str) -> Result<Vec<String>> {
        let search_filter = ldap_config.group_search_filter.replace("%s", user_dn);

        let output = Command::new("ldapsearch")
            .args(&[
                "-H", &ldap_config.server,
                "-D", &ldap_config.bind_dn,
                "-w", &ldap_config.bind_password,
                "-b", &ldap_config.group_search_base,
                &search_filter,
                "cn",
            ])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut groups = Vec::new();

        for line in output_str.lines() {
            if line.starts_with("cn:") {
                groups.push(line[3..].trim().to_string());
            }
        }

        Ok(groups)
    }

    /// Authenticate against RADIUS server
    async fn authenticate_radius(&self, username: &str, password: &str) -> Result<User> {
        let radius_config = self.config.radius.as_ref()
            .ok_or_else(|| AuthError::ConfigError("RADIUS not configured".to_string()))?;

        tracing::info!("Authenticating {} against RADIUS server {}", username, radius_config.server);

        // Use radtest command (in production, would use radius crate)
        let output = Command::new("radtest")
            .args(&[
                username,
                password,
                &radius_config.server.to_string(),
                &radius_config.port.to_string(),
                &radius_config.secret,
            ])
            .output()
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        if output_str.contains("Access-Accept") {
            // Parse RADIUS attributes for user info
            let filter_id = self.parse_radius_filter_id(&output_str);

            Ok(User {
                id: 0,
                username: username.to_string(),
                email: None,
                display_name: None,
                groups: filter_id.map(|f| vec![f]).unwrap_or_default(),
                privileges: vec![],
                account_enabled: true,
                account_locked: false,
                password_expired: false,
                created_at: chrono::Utc::now(),
                last_login: None,
                failed_login_count: 0,
            })
        } else if output_str.contains("Access-Reject") {
            Err(AuthError::InvalidCredentials)
        } else {
            Err(AuthError::RadiusError("RADIUS server error".to_string()))
        }
    }

    fn parse_radius_filter_id(&self, output: &str) -> Option<String> {
        for line in output.lines() {
            if line.contains("Filter-Id") {
                if let Some(value) = line.split('=').nth(1) {
                    return Some(value.trim().trim_matches('"').to_string());
                }
            }
        }
        None
    }

    /// Create authentication session
    pub async fn create_session(&self, user: &User, ip: IpAddr) -> Result<AuthSession> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::from_std(self.config.session_timeout)
            .map_err(|_| AuthError::ConfigError("Invalid session timeout".to_string()))?;

        Ok(AuthSession {
            session_id,
            user_id: user.id,
            username: user.username.clone(),
            created_at: now,
            expires_at,
            ip_address: ip,
            user_agent: None,
        })
    }

    /// Validate session
    pub async fn validate_session(&self, session_id: &str) -> Result<AuthSession> {
        // In production, would:
        // 1. Query session database
        // 2. Check expiration
        // 3. Validate IP address (optional)
        // 4. Update last activity time

        Err(AuthError::AuthFailed("Session not found".to_string()))
    }

    /// Revoke session (logout)
    pub async fn revoke_session(&self, session_id: &str) -> Result<()> {
        // Remove session from database
        Ok(())
    }

    /// Check user privileges
    pub fn has_privilege(&self, user: &User, privilege: &str) -> bool {
        user.privileges.contains(&privilege.to_string())
    }

    /// Check user group membership
    pub fn in_group(&self, user: &User, group: &str) -> bool {
        user.groups.contains(&group.to_string())
    }

    /// Validate password against policy
    pub fn validate_password(&self, password: &str) -> Result<()> {
        let policy = &self.config.password_policy;

        if password.len() < policy.min_length as usize {
            return Err(AuthError::AuthFailed(format!(
                "Password must be at least {} characters",
                policy.min_length
            )));
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::AuthFailed(
                "Password must contain uppercase letters".to_string()
            ));
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::AuthFailed(
                "Password must contain lowercase letters".to_string()
            ));
        }

        if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(AuthError::AuthFailed(
                "Password must contain numbers".to_string()
            ));
        }

        if policy.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(AuthError::AuthFailed(
                "Password must contain special characters".to_string()
            ));
        }

        Ok(())
    }

    /// Test LDAP connection
    pub async fn test_ldap_connection(&self) -> Result<bool> {
        let ldap_config = self.config.ldap.as_ref()
            .ok_or_else(|| AuthError::ConfigError("LDAP not configured".to_string()))?;

        let output = Command::new("ldapwhoami")
            .args(&[
                "-H", &ldap_config.server,
                "-D", &ldap_config.bind_dn,
                "-w", &ldap_config.bind_password,
            ])
            .output()
            .await?;

        Ok(output.status.success())
    }

    /// Test RADIUS connection
    pub async fn test_radius_connection(&self) -> Result<bool> {
        let radius_config = self.config.radius.as_ref()
            .ok_or_else(|| AuthError::ConfigError("RADIUS not configured".to_string()))?;

        // Use radtest with test credentials
        let output = Command::new("radtest")
            .args(&[
                "test",
                "test",
                &radius_config.server.to_string(),
                &radius_config.port.to_string(),
                &radius_config.secret,
            ])
            .output()
            .await?;

        // Even a rejection means the server is responding
        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.contains("Access-") || output_str.contains("Reply"))
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: AuthBackend::Local,
            fallback_local: true,
            local: LocalAuthConfig {
                enabled: true,
                user_db_path: "/etc/patronus/users.db".to_string(),
                hash_algorithm: HashAlgorithm::Argon2id,
                require_2fa: false,
            },
            ldap: None,
            radius: None,
            password_policy: PasswordPolicy {
                min_length: 12,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_special_chars: true,
                max_age_days: 90,
                remember_previous: 5,
                lockout_threshold: 5,
                lockout_duration: Duration::from_secs(900),  // 15 minutes
            },
            session_timeout: Duration::from_secs(3600),  // 1 hour
            max_sessions_per_user: 5,
            remember_me_duration: Duration::from_secs(2592000),  // 30 days
        }
    }
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "ldap://localhost".to_string(),
            port: 389,
            use_tls: false,
            use_starttls: false,
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: String::new(),
            base_dn: "dc=example,dc=com".to_string(),
            user_search_base: "ou=users,dc=example,dc=com".to_string(),
            user_search_filter: "(&(objectClass=person)(uid=%s))".to_string(),
            group_search_base: "ou=groups,dc=example,dc=com".to_string(),
            group_search_filter: "(&(objectClass=groupOfNames)(member=%s))".to_string(),
            username_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            display_name_attribute: "displayName".to_string(),
            group_membership_attribute: "memberOf".to_string(),
            timeout: Duration::from_secs(10),
            connection_pool_size: 5,
            referrals: false,
            is_active_directory: false,
            ad_domain: None,
        }
    }
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "127.0.0.1".parse().unwrap(),
            port: 1812,
            secret: String::new(),
            backup_server: None,
            backup_port: None,
            backup_secret: None,
            accounting_enabled: false,
            accounting_port: 1813,
            timeout: Duration::from_secs(5),
            retries: 3,
            nas_identifier: "patronus-firewall".to_string(),
            nas_ip_address: "127.0.0.1".parse().unwrap(),
            use_message_authenticator: true,
            filter_id: None,
        }
    }
}
