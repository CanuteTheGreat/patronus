//! Authentication middleware for Axum

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::{jwt::validate_token, users::UserRole};
use crate::{error::ApiError, state::AppState};

/// Extract user claims from request
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Extract Authorization header
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("Missing authorization header".to_string()))?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Invalid authorization format".to_string()))?;

    // Validate token
    let claims = validate_token(token)?;

    // Verify user is active
    let user = state
        .user_repository
        .get_user(&claims.sub)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("User not found".to_string()))?;

    if !user.is_active {
        return Err(ApiError::Unauthorized("User is inactive".to_string()));
    }

    // Store claims in request extensions for downstream handlers
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Check if user has required role based on claims
pub fn has_role(claims: &super::jwt::Claims, required_role: &UserRole) -> Result<bool, ApiError> {
    let user_role = UserRole::from_str(&claims.role)?;

    let has_permission = match required_role {
        UserRole::Viewer => true, // Anyone can be a viewer
        UserRole::Operator => {
            user_role == UserRole::Operator || user_role == UserRole::Admin
        }
        UserRole::Admin => user_role == UserRole::Admin,
    };

    Ok(has_permission)
}

/// Extract current user from request extensions
pub fn get_current_user_id(req: &Request) -> Option<String> {
    req.extensions()
        .get::<super::jwt::Claims>()
        .map(|claims| claims.sub.clone())
}
