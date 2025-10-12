//! Authentication API endpoints

use axum::{
    extract::{Request, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth::{
        generate_tokens, hash_password, refresh_access_token, verify_password,
        ChangePasswordRequest, CreateUserRequest, User, UserRole,
    },
    error::{ApiError, Result},
    state::AppState,
};

/// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// User response (without password)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub created_at: String,
    pub last_login: Option<String>,
    pub is_active: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role.as_str().to_string(),
            created_at: user.created_at.to_rfc3339(),
            last_login: user.last_login.map(|dt| dt.to_rfc3339()),
            is_active: user.is_active,
        }
    }
}

/// Refresh token request
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Login endpoint
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Get user by email
    let user = state
        .user_repository
        .get_user_by_email(&req.email)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".to_string()))?;

    // Verify password
    if !verify_password(&req.password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    // Check if user is active
    if !user.is_active {
        return Err(ApiError::Unauthorized("User is inactive".to_string()));
    }

    // Update last login time
    state.user_repository.update_last_login(&user.id).await?;

    // Generate tokens
    let tokens = generate_tokens(&user.id, &user.email, user.role.as_str())?;

    Ok(Json(LoginResponse {
        user: user.into(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
    }))
}

/// Refresh token endpoint
pub async fn refresh(Json(req): Json<RefreshRequest>) -> Result<Json<LoginResponse>> {
    // Refresh the access token
    let tokens = refresh_access_token(&req.refresh_token)?;

    // We don't have user info here, so we'll return a simplified response
    // In production, you might want to fetch the user from the database

    Ok(Json(LoginResponse {
        user: UserResponse {
            id: String::new(),
            email: String::new(),
            name: String::new(),
            role: String::new(),
            created_at: String::new(),
            last_login: None,
            is_active: true,
        },
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
    }))
}

/// Get current user endpoint
pub async fn me(State(state): State<Arc<AppState>>, req: Request) -> Result<Json<UserResponse>> {
    // Get user ID from request extensions (set by auth middleware)
    let claims = req
        .extensions()
        .get::<crate::auth::jwt::Claims>()
        .ok_or_else(|| ApiError::Unauthorized("Not authenticated".to_string()))?;

    // Get user from database
    let user = state
        .user_repository
        .get_user(&claims.sub)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    Ok(Json(user.into()))
}

/// Create initial admin user (only works if no users exist)
pub async fn init_admin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>> {
    // Check if any users exist
    if state.user_repository.has_users().await? {
        return Err(ApiError::InvalidRequest(
            "Admin user already exists".to_string(),
        ));
    }

    // Validate password strength
    crate::auth::password::validate_password_strength(&req.password)?;

    // Hash password
    let password_hash = hash_password(&req.password)?;

    // Force role to be admin for initial user
    let user = state
        .user_repository
        .create_user(&req.email, &req.name, &password_hash, UserRole::Admin)
        .await?;

    Ok(Json(user.into()))
}

/// Change password endpoint
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<crate::auth::jwt::Claims>,
    Json(change_req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>> {
    // User claims from middleware extension

    // Get user from database
    let user = state
        .user_repository
        .get_user(&claims.sub)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    // Verify old password
    if !verify_password(&change_req.old_password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Invalid old password".to_string()));
    }

    // Validate new password strength
    crate::auth::password::validate_password_strength(&change_req.new_password)?;

    // Hash new password
    let new_password_hash = hash_password(&change_req.new_password)?;

    // Update password
    state
        .user_repository
        .update_password(&user.id, &new_password_hash)
        .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}
