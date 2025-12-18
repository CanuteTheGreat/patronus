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
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use patronus_secrets::crypto::{hash_password, verify_password};

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

impl UserStore {
    pub fn new() -> Self {
        let mut users = HashMap::new();

        // Create default admin user with hashed password
        let admin_hash = hash_password("admin").unwrap_or_else(|_| "admin".to_string());
        users.insert("admin".to_string(), User {
            id: 1,
            username: "admin".to_string(),
            password_hash: admin_hash,
            role: UserRole::Admin,
            enabled: true,
            created_at: Utc::now(),
            last_login: None,
        });

        // Create operator user
        let operator_hash = hash_password("operator").unwrap_or_else(|_| "operator".to_string());
        users.insert("operator".to_string(), User {
            id: 2,
            username: "operator".to_string(),
            password_hash: operator_hash,
            role: UserRole::Operator,
            enabled: true,
            created_at: Utc::now(),
            last_login: None,
        });

        Self {
            users: Arc::new(RwLock::new(users)),
            next_id: Arc::new(RwLock::new(3)),
        }
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
    pub async fn create_user(&self, username: String, password: &str, role: UserRole) -> anyhow::Result<u32> {
        let mut users = self.users.write().await;

        if users.contains_key(&username) {
            return Err(anyhow::anyhow!("User already exists"));
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let password_hash = hash_password(password)?;

        users.insert(username.clone(), User {
            id,
            username,
            password_hash,
            role,
            enabled: true,
            created_at: Utc::now(),
            last_login: None,
        });

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
        self.users.read().await.values().map(|u| UserInfo {
            id: u.id,
            username: u.username.clone(),
            role: u.role,
            enabled: u.enabled,
            created_at: u.created_at,
            last_login: u.last_login,
        }).collect()
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

        self.sessions.write().await.insert(session_id.clone(), session);
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
        self.sessions.write().await.retain(|_, session| {
            session.last_active > cutoff
        });
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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingSession => (StatusCode::UNAUTHORIZED, "No session found"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid or expired session"),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid username or password"),
            AuthError::UserDisabled => (StatusCode::FORBIDDEN, "User account is disabled"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        (status, Json(serde_json::json!({
            "error": message
        }))).into_response()
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
                cookies
                    .split(';')
                    .find_map(|cookie| {
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

/// Authentication state (includes user store and session store)
#[derive(Clone)]
pub struct AuthState {
    pub user_store: UserStore,
    pub session_store: SessionStore,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            user_store: UserStore::new(),
            session_store: SessionStore::new(),
        }
    }
}

/// Login handler
pub async fn login(
    State(app_state): State<crate::state::AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    // Verify credentials
    let user = app_state.auth.user_store
        .verify_credentials(&req.username, &req.password)
        .await
        .ok_or(AuthError::InvalidCredentials)?;

    // Update last login time
    app_state.auth.user_store.update_last_login(&req.username).await;

    // Create session
    let session_id = app_state.auth.session_store
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

    Ok((
        [(header::SET_COOKIE, cookie)],
        response,
    ).into_response())
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
            cookies
                .split(';')
                .find_map(|cookie| {
                    let mut parts = cookie.trim().splitn(2, '=');
                    match (parts.next(), parts.next()) {
                        (Some("session_id"), Some(id)) => Some(id.to_string()),
                        _ => None,
                    }
                })
        })
    {
        app_state.auth.session_store.delete_session(&session_id).await;
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
    let user = app_state.auth.user_store
        .verify_credentials(&auth_user.session.username, &req.current_password)
        .await
        .ok_or(AuthError::InvalidCredentials)?;

    // Update password
    app_state.auth.user_store
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
    let id = app_state.auth.user_store
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
    req.extensions_mut().insert(app_state.auth.session_store.clone());
    next.run(req).await
}
