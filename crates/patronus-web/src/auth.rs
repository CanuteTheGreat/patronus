//! Authentication and session management
//!
//! Provides secure authentication using patronus-secrets for password hashing
//! and session management using secure cookies.

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use patronus_secrets::crypto::{hash_password, verify_password};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Session data stored in memory
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: u32,
    pub username: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

/// User roles for authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Operator,
    ReadOnly,
}

impl UserRole {
    pub fn can_modify(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::Operator)
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// User record stored in the user database
#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

/// User database - in-memory for now, can be swapped with real DB later
#[derive(Clone)]
pub struct UserStore {
    users: Arc<RwLock<HashMap<String, User>>>,
    next_id: Arc<RwLock<u32>>,
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Env var holding the admin password (takes precedence over the file).
pub const ADMIN_PASSWORD_ENV: &str = "PATRONUS_ADMIN_PASSWORD";
/// Env var overriding where the generated admin password is persisted.
pub const ADMIN_PASSWORD_FILE_ENV: &str = "PATRONUS_ADMIN_PASSWORD_FILE";
/// Where a per-install admin password is generated on first start.
pub const DEFAULT_ADMIN_PASSWORD_FILE: &str = "/var/lib/patronus/initial-admin-password";
/// Minimum accepted admin password length.
pub const MIN_ADMIN_PASSWORD_LEN: usize = 12;
/// Passwords that shipped as defaults or are trivially guessable.
const KNOWN_DEFAULT_PASSWORDS: &[&str] = &[
    "admin",
    "operator",
    "password",
    "patronus",
    "changeme",
    "change-me",
    "admin123",
    "administrator",
    "pfsense",
    "opnsense",
    "123456789012",
];

/// Where the admin password came from (for the startup log line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminPasswordSource {
    Env,
    ExistingFile(std::path::PathBuf),
    GeneratedFile(std::path::PathBuf),
}

/// Reject publicly known / short admin passwords.
pub fn check_admin_password(pw: &str) -> Result<(), String> {
    let lower = pw.to_ascii_lowercase();
    if KNOWN_DEFAULT_PASSWORDS.contains(&lower.as_str()) {
        return Err("admin password is a publicly known default".to_string());
    }
    if pw.chars().count() < MIN_ADMIN_PASSWORD_LEN {
        return Err(format!(
            "admin password must be at least {} characters",
            MIN_ADMIN_PASSWORD_LEN
        ));
    }
    Ok(())
}

fn generate_admin_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Resolve the per-install admin password: `env` if given (must pass
/// [`check_admin_password`]), else the contents of `file`, else a newly
/// generated random password written to `file` with mode 0600.
pub fn resolve_admin_password(
    env: Option<String>,
    file: &std::path::Path,
) -> Result<(String, AdminPasswordSource), String> {
    if let Some(pw) = env.filter(|p| !p.is_empty()) {
        check_admin_password(&pw).map_err(|e| format!("{}: {}", ADMIN_PASSWORD_ENV, e))?;
        return Ok((pw, AdminPasswordSource::Env));
    }
    match std::fs::read_to_string(file) {
        Ok(contents) => {
            let pw = contents.trim().to_string();
            check_admin_password(&pw)
                .map_err(|e| format!("admin password file {}: {}", file.display(), e))?;
            Ok((pw, AdminPasswordSource::ExistingFile(file.to_path_buf())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let pw = generate_admin_password();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(file).map_err(|e| {
                format!(
                    "cannot create admin password file {} ({}); set {} instead",
                    file.display(),
                    e,
                    ADMIN_PASSWORD_ENV
                )
            })?;
            use std::io::Write;
            writeln!(f, "{}", pw).map_err(|e| format!("cannot write {}: {}", file.display(), e))?;
            Ok((pw, AdminPasswordSource::GeneratedFile(file.to_path_buf())))
        }
        Err(e) => Err(format!(
            "cannot read admin password file {}: {}",
            file.display(),
            e
        )),
    }
}

impl UserStore {
    /// A store whose only account is a *locked* `admin` (random, never
    /// disclosed password). Call [`UserStore::provision_admin_from_env`] at
    /// startup to set the real per-install password. There are no shipped
    /// default credentials (admin/admin and operator/operator used to work
    /// on every install).
    pub fn new() -> Self {
        let mut users = HashMap::new();
        let locked =
            hash_password(&generate_admin_password()).unwrap_or_else(|_| "!locked".to_string());
        users.insert(
            "admin".to_string(),
            User {
                id: 1,
                username: "admin".to_string(),
                password_hash: locked,
                role: UserRole::Admin,
                enabled: true,
                created_at: Utc::now(),
                last_login: None,
            },
        );

        Self {
            users: Arc::new(RwLock::new(users)),
            next_id: Arc::new(RwLock::new(2)),
        }
    }

    /// Set the admin password from `PATRONUS_ADMIN_PASSWORD` or the
    /// per-install password file (generated on first start). Fails -- and
    /// the binary refuses to start -- on a weak/known password.
    pub async fn provision_admin_from_env(&self) -> anyhow::Result<AdminPasswordSource> {
        let file = std::env::var(ADMIN_PASSWORD_FILE_ENV)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_ADMIN_PASSWORD_FILE));
        self.provision_admin(std::env::var(ADMIN_PASSWORD_ENV).ok(), &file)
            .await
    }

    /// See [`UserStore::provision_admin_from_env`].
    pub async fn provision_admin(
        &self,
        env: Option<String>,
        file: &std::path::Path,
    ) -> anyhow::Result<AdminPasswordSource> {
        let (pw, source) = resolve_admin_password(env, file).map_err(|e| anyhow::anyhow!(e))?;
        self.update_password("admin", &pw).await?;
        Ok(source)
    }

    /// Get a user by username
    pub async fn get_user(&self, username: &str) -> Option<User> {
        self.users.read().await.get(username).cloned()
    }

    /// Verify user credentials and return user if valid
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Option<User> {
        let users = self.users.read().await;

        if let Some(user) = users.get(username) {
            if !user.enabled {
                return None;
            }

            // Verify password hash
            match verify_password(password, &user.password_hash) {
                Ok(true) => Some(user.clone()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Update last login time for a user
    pub async fn update_last_login(&self, username: &str) {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(username) {
            user.last_login = Some(Utc::now());
        }
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: String,
        password: &str,
        role: UserRole,
    ) -> anyhow::Result<u32> {
        let mut users = self.users.write().await;

        if users.contains_key(&username) {
            return Err(anyhow::anyhow!("User already exists"));
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let password_hash = hash_password(password)?;

        users.insert(
            username.clone(),
            User {
                id,
                username,
                password_hash,
                role,
                enabled: true,
                created_at: Utc::now(),
                last_login: None,
            },
        );

        Ok(id)
    }

    /// Update a user's password
    pub async fn update_password(&self, username: &str, new_password: &str) -> anyhow::Result<()> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(username) {
            user.password_hash = hash_password(new_password)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    /// Disable a user
    pub async fn disable_user(&self, username: &str) -> anyhow::Result<()> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(username) {
            user.enabled = false;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    /// Enable a user
    pub async fn enable_user(&self, username: &str) -> anyhow::Result<()> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(username) {
            user.enabled = true;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    /// List all users (without password hashes)
    pub async fn list_users(&self) -> Vec<UserInfo> {
        self.users
            .read()
            .await
            .values()
            .map(|u| UserInfo {
                id: u.id,
                username: u.username.clone(),
                role: u.role,
                enabled: u.enabled,
                created_at: u.created_at,
                last_login: u.last_login,
            })
            .collect()
    }
}

/// User info without sensitive data
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub id: u32,
    pub username: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

/// Session store - in-memory for now, can be swapped with Redis/DB later
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session
    pub async fn create_session(&self, user_id: u32, username: String, role: UserRole) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = Session {
            user_id,
            username,
            role,
            created_at: now,
            last_active: now,
        };

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        session_id
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            // Update last active time
            session.last_active = Utc::now();
            Some(session.clone())
        } else {
            None
        }
    }

    /// Delete session (logout)
    pub async fn delete_session(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// Clean up expired sessions (older than 24 hours)
    pub async fn cleanup_expired(&self) {
        let cutoff = Utc::now() - Duration::hours(24);
        self.sessions
            .write()
            .await
            .retain(|_, session| session.last_active > cutoff);
    }
}

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    MissingSession,
    InvalidSession,
    InvalidCredentials,
    UserDisabled,
    Forbidden,
    InternalError,
    /// Too many failed logins; retry after this many seconds.
    TooManyAttempts(u64),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        if let AuthError::TooManyAttempts(secs) = self {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, secs.to_string())],
                Json(serde_json::json!({
                    "error": "Too many failed login attempts; try again later",
                    "retry_after_secs": secs,
                })),
            )
                .into_response();
        }
        let (status, message) = match self {
            AuthError::MissingSession => (StatusCode::UNAUTHORIZED, "No session found"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid or expired session"),
            AuthError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid username or password")
            }
            AuthError::UserDisabled => (StatusCode::FORBIDDEN, "User account is disabled"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::InternalError | AuthError::TooManyAttempts(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        };

        (
            status,
            Json(serde_json::json!({
                "error": message
            })),
        )
            .into_response()
    }
}

/// Authenticated user extractor for protected routes
pub struct AuthUser {
    pub session: Session,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract session cookie
        let session_id = parts
            .headers
            .get(header::COOKIE)
            .and_then(|cookie| cookie.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let mut parts = cookie.trim().splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some("session_id"), Some(id)) => Some(id.to_string()),
                        _ => None,
                    }
                })
            })
            .ok_or(AuthError::MissingSession)?;

        // Get session store from extensions (set by middleware)
        let store = parts
            .extensions
            .get::<SessionStore>()
            .ok_or(AuthError::InternalError)?;

        // Validate session
        let session = store
            .get_session(&session_id)
            .await
            .ok_or(AuthError::InvalidSession)?;

        Ok(AuthUser { session })
    }
}

/// Admin-only extractor for admin routes
pub struct AdminUser {
    pub session: Session,
}

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        if !auth_user.session.role.is_admin() {
            return Err(AuthError::Forbidden);
        }

        Ok(AdminUser {
            session: auth_user.session,
        })
    }
}

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub username: String,
    pub role: UserRole,
}

/// Failed logins allowed per client within [`LOGIN_FAILURE_WINDOW_SECS`]
/// before further attempts from that client are refused with 429.
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// Window (and lockout length) for [`MAX_LOGIN_FAILURES`].
pub const LOGIN_FAILURE_WINDOW_SECS: i64 = 15 * 60;
/// Upper bound on tracked clients, so a spray from many addresses can't
/// grow the table without limit.
const MAX_TRACKED_LOGIN_CLIENTS: usize = 65_536;

/// Per-client brute-force throttle for `POST /api/auth/login`.
///
/// Before this, the login endpoint accepted unlimited password guesses at
/// full speed from any client. Clients are keyed by IP address; IPv6
/// clients by their /64, since one host trivially owns a whole /64. A
/// successful login clears the client's record. While a client is locked
/// out even the *correct* password is refused, otherwise the lockout would
/// not slow down guessing at all.
#[derive(Clone, Default)]
pub struct LoginThrottle {
    failures: Arc<std::sync::Mutex<FailureTable>>,
}

/// Client key -> (failed attempts, start of the current window).
type FailureTable = HashMap<std::net::IpAddr, (u32, DateTime<Utc>)>;

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(ip: std::net::IpAddr) -> std::net::IpAddr {
        match ip {
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => {
                    let mut o = v6.octets();
                    o[8..].fill(0);
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
                }
            },
            v4 => v4,
        }
    }

    fn window() -> Duration {
        Duration::seconds(LOGIN_FAILURE_WINDOW_SECS)
    }

    /// `Some(seconds until the client may try again)` if it is locked out.
    pub fn check(&self, ip: std::net::IpAddr) -> Option<u64> {
        self.check_at(ip, Utc::now())
    }

    fn check_at(&self, ip: std::net::IpAddr, now: DateTime<Utc>) -> Option<u64> {
        let map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let (count, start) = *map.get(&Self::key(ip))?;
        let until = start + Self::window();
        if count >= MAX_LOGIN_FAILURES && now < until {
            Some((until - now).num_seconds().max(1) as u64)
        } else {
            None
        }
    }

    /// Record a failed login from `ip`.
    pub fn record_failure(&self, ip: std::net::IpAddr) {
        self.record_failure_at(ip, Utc::now())
    }

    fn record_failure_at(&self, ip: std::net::IpAddr, now: DateTime<Utc>) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let window = Self::window();
        if map.len() >= MAX_TRACKED_LOGIN_CLIENTS {
            map.retain(|_, (_, start)| now < *start + window);
        }
        let key = Self::key(ip);
        if map.len() >= MAX_TRACKED_LOGIN_CLIENTS && !map.contains_key(&key) {
            tracing::warn!("login throttle table full; not tracking {}", key);
            return;
        }
        let entry = map.entry(key).or_insert((0, now));
        if now >= entry.1 + window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
        if entry.0 == MAX_LOGIN_FAILURES {
            tracing::warn!(
                "{} failed logins from {}; locking it out for {}s",
                MAX_LOGIN_FAILURES,
                key,
                LOGIN_FAILURE_WINDOW_SECS
            );
        }
    }

    /// Forget `ip`'s failures (after a successful login).
    pub fn record_success(&self, ip: std::net::IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&Self::key(ip));
    }

    /// Drop records whose window has passed.
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        let window = Self::window();
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, start)| now < *start + window);
    }
}

/// Authentication state (includes user store and session store)
#[derive(Clone)]
pub struct AuthState {
    pub user_store: UserStore,
    pub session_store: SessionStore,
    pub login_throttle: LoginThrottle,
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            user_store: UserStore::new(),
            session_store: SessionStore::new(),
            login_throttle: LoginThrottle::new(),
        }
    }
}

/// Login handler
pub async fn login(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    // Without connection info (in-process callers) every request shares
    // the unspecified address, which still caps guessing.
    let client = connect_info
        .map(|axum::extract::ConnectInfo(addr)| addr.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let throttle = &app_state.auth.login_throttle;
    if let Some(retry_after) = throttle.check(client) {
        return Err(AuthError::TooManyAttempts(retry_after));
    }

    // Verify credentials
    let Some(user) = app_state
        .auth
        .user_store
        .verify_credentials(&req.username, &req.password)
        .await
    else {
        throttle.record_failure(client);
        tracing::warn!("failed login for {:?} from {}", req.username, client);
        return Err(AuthError::InvalidCredentials);
    };
    throttle.record_success(client);

    // Update last login time
    app_state
        .auth
        .user_store
        .update_last_login(&req.username)
        .await;

    // Create session
    let session_id = app_state
        .auth
        .session_store
        .create_session(user.id, user.username.clone(), user.role)
        .await;

    // Set secure cookie
    let cookie = format!(
        "session_id={}; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/",
        session_id
    );

    let response = Json(LoginResponse {
        success: true,
        username: user.username,
        role: user.role,
    });

    Ok(([(header::SET_COOKIE, cookie)], response).into_response())
}

/// Logout handler
pub async fn logout(
    State(app_state): State<crate::state::AppState>,
    _auth_user: AuthUser,
    parts: Parts,
) -> impl IntoResponse {
    // Extract session ID from cookie
    if let Some(session_id) = parts
        .headers
        .get(header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let mut parts = cookie.trim().splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some("session_id"), Some(id)) => Some(id.to_string()),
                    _ => None,
                }
            })
        })
    {
        app_state
            .auth
            .session_store
            .delete_session(&session_id)
            .await;
    }

    // Clear cookie
    let cookie = "session_id=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/";

    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })),
    )
}

/// Get current user info
pub async fn current_user(auth_user: AuthUser) -> impl IntoResponse {
    Json(serde_json::json!({
        "username": auth_user.session.username,
        "role": auth_user.session.role,
        "user_id": auth_user.session.user_id,
    }))
}

/// Change password request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Change password handler
pub async fn change_password(
    State(app_state): State<crate::state::AppState>,
    auth_user: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Verify current password
    let user = app_state
        .auth
        .user_store
        .verify_credentials(&auth_user.session.username, &req.current_password)
        .await
        .ok_or(AuthError::InvalidCredentials)?;

    // Update password
    app_state
        .auth
        .user_store
        .update_password(&user.username, &req.new_password)
        .await
        .map_err(|_| AuthError::InternalError)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully"
    })))
}

/// List users (admin only)
pub async fn list_users(
    State(app_state): State<crate::state::AppState>,
    _admin: AdminUser,
) -> impl IntoResponse {
    let users = app_state.auth.user_store.list_users().await;
    Json(users)
}

/// Create user request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: UserRole,
}

/// Create user handler (admin only)
pub async fn create_user(
    State(app_state): State<crate::state::AppState>,
    _admin: AdminUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, AuthError> {
    let id = app_state
        .auth
        .user_store
        .create_user(req.username.clone(), &req.password, req.role)
        .await
        .map_err(|_| AuthError::InternalError)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "id": id,
        "username": req.username
    })))
}

/// Middleware to inject session store into request extensions
pub async fn session_middleware(
    State(app_state): State<crate::state::AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    req.extensions_mut()
        .insert(app_state.auth.session_store.clone());
    next.run(req).await
}

#[cfg(test)]
mod default_credential_tests {
    use super::*;

    fn tmp_file() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("patronus-web-auth-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("initial-admin-password")
    }

    #[tokio::test]
    async fn shipped_default_credentials_do_not_work() {
        let store = UserStore::new();
        assert!(store.verify_credentials("admin", "admin").await.is_none());
        assert!(store
            .verify_credentials("operator", "operator")
            .await
            .is_none());
        assert!(store.get_user("operator").await.is_none());
    }

    #[tokio::test]
    async fn first_start_generates_a_private_per_install_password() {
        let file = tmp_file();
        let store = UserStore::new();
        let src = store.provision_admin(None, &file).await.unwrap();
        assert_eq!(src, AdminPasswordSource::GeneratedFile(file.clone()));
        let pw = std::fs::read_to_string(&file).unwrap().trim().to_string();
        assert!(pw.len() >= MIN_ADMIN_PASSWORD_LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(store.verify_credentials("admin", &pw).await.is_some());
        assert!(store.verify_credentials("admin", "admin").await.is_none());

        // Restart: same password is reused, a second install gets another.
        let again = UserStore::new();
        let src = again.provision_admin(None, &file).await.unwrap();
        assert_eq!(src, AdminPasswordSource::ExistingFile(file.clone()));
        assert!(again.verify_credentials("admin", &pw).await.is_some());
        let other = tmp_file();
        UserStore::new()
            .provision_admin(None, &other)
            .await
            .unwrap();
        assert_ne!(std::fs::read_to_string(&other).unwrap().trim(), pw);
    }

    #[tokio::test]
    async fn weak_or_default_admin_password_is_refused() {
        let file = tmp_file();
        for weak in ["admin", "ADMIN", "operator", "changeme", "short-pw"] {
            let err = UserStore::new()
                .provision_admin(Some(weak.to_string()), &file)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(ADMIN_PASSWORD_ENV), "{err}");
        }
        std::fs::write(&file, "admin\n").unwrap();
        assert!(UserStore::new().provision_admin(None, &file).await.is_err());
        let store = UserStore::new();
        store
            .provision_admin(Some("Correct-Horse-Battery-9".to_string()), &file)
            .await
            .unwrap();
        assert!(store
            .verify_credentials("admin", "Correct-Horse-Battery-9")
            .await
            .is_some());
    }
}

#[cfg(test)]
mod login_throttle_tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn locks_out_after_max_failures_until_the_window_passes() {
        let t = LoginThrottle::new();
        let now = Utc::now();
        let a = ip("192.0.2.1");
        for _ in 0..MAX_LOGIN_FAILURES - 1 {
            t.record_failure_at(a, now);
            assert!(t.check_at(a, now).is_none());
        }
        t.record_failure_at(a, now);
        let retry = t.check_at(a, now).expect("locked out");
        assert!(retry > 0 && retry <= LOGIN_FAILURE_WINDOW_SECS as u64);
        // Another client is unaffected.
        assert!(t.check_at(ip("192.0.2.2"), now).is_none());
        // After the window it may try again, with a fresh count.
        let later = now + Duration::seconds(LOGIN_FAILURE_WINDOW_SECS + 1);
        assert!(t.check_at(a, later).is_none());
        t.record_failure_at(a, later);
        assert!(t.check_at(a, later).is_none());
    }

    #[test]
    fn success_clears_the_record() {
        let t = LoginThrottle::new();
        let a = ip("198.51.100.7");
        for _ in 0..MAX_LOGIN_FAILURES - 1 {
            t.record_failure(a);
        }
        t.record_success(a);
        t.record_failure(a);
        assert!(t.check(a).is_none());
    }

    #[test]
    fn ipv6_clients_are_grouped_by_slash_64_and_mapped_v4_by_v4() {
        let t = LoginThrottle::new();
        for i in 0..MAX_LOGIN_FAILURES {
            t.record_failure(ip(&format!("2001:db8:1:2::{:x}", i + 1)));
        }
        assert!(t.check(ip("2001:db8:1:2:ffff::1")).is_some());
        assert!(t.check(ip("2001:db8:1:3::1")).is_none());

        for _ in 0..MAX_LOGIN_FAILURES {
            t.record_failure(ip("::ffff:203.0.113.9"));
        }
        assert!(t.check(ip("203.0.113.9")).is_some());
    }
}
