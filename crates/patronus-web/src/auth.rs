//! Authentication and session management
//!
//! Provides secure authentication using patronus-secrets for password hashing
//! and session management using secure cookies.

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};

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
    Forbidden,
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingSession => (StatusCode::UNAUTHORIZED, "No session found"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid or expired session"),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid username or password"),
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

/// Temporary user structure for validation
struct ValidatedUser {
    id: u32,
    username: String,
    role: UserRole,
}

/// Validate user credentials
/// TODO: Integrate with patronus-secrets for password hashing
async fn validate_credentials(
    _app_state: &crate::state::AppState,
    username: &str,
    password: &str,
) -> anyhow::Result<ValidatedUser> {
    // TODO: Query database and verify password hash
    // For now, accept admin/admin for development
    if username == "admin" && password == "admin" {
        return Ok(ValidatedUser {
            id: 1,
            username: username.to_string(),
            role: UserRole::Admin,
        });
    }

    anyhow::bail!("Invalid credentials")
}

/// Login handler
pub async fn login(
    State(app_state): State<crate::state::AppState>,
    parts: Parts,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    // Get session store from extensions
    let store = parts
        .extensions
        .get::<SessionStore>()
        .ok_or(AuthError::InternalError)?
        .clone();

    // Validate credentials
    let user = validate_credentials(&app_state, &req.username, &req.password)
        .await
        .map_err(|_| AuthError::InvalidCredentials)?;

    // Create session
    let session_id = store.create_session(user.id, user.username.clone(), user.role).await;

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
pub async fn logout(auth_user: AuthUser, parts: Parts) -> impl IntoResponse {
    // Get session store and session ID to delete
    if let Some(store) = parts.extensions.get::<SessionStore>() {
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
            store.delete_session(&session_id).await;
        }
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

/// Middleware to inject session store into request extensions
pub async fn session_middleware<B>(
    State(store): State<SessionStore>,
    mut req: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> Response {
    req.extensions_mut().insert(store);
    next.run(req).await
}
