//! API keys for automation (lane H): list / create / revoke. Admin
//! sessions only (a key can never manage keys). The token is in the
//! answer to the create call and nowhere else.

use crate::auth::AdminUser;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// GET /api/system/api-keys
pub async fn list(State(state): State<AppState>, _admin: AdminUser) -> Response {
    match state.auth.api_keys.list().await {
        Ok(k) => Json(k).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct CreateKey {
    pub name: String,
    /// `readonly` (default) or `operator`
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

/// POST /api/system/api-keys -> 201 `{key, token}` (the token is shown once)
pub async fn create(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CreateKey>,
) -> Response {
    let scope = req.scope.as_deref().unwrap_or("readonly");
    match state
        .auth
        .api_keys
        .create(
            &req.name,
            scope,
            req.expires_in_days,
            &admin.session.username,
        )
        .await
    {
        Ok((key, token)) => (
            StatusCode::CREATED,
            Json(json!({
                "key": key,
                "token": token,
                "note": "Copy the token now: it is not stored and cannot be shown again.",
            })),
        )
            .into_response(),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// DELETE /api/system/api-keys/:id
pub async fn revoke(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    match state.auth.api_keys.delete(id).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such API key"),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/system/api-keys", get(list).post(create))
        .route("/system/api-keys/:id", delete(revoke))
}
