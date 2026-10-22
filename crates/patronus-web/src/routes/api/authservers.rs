//! External authentication servers for the web login (lane H): RADIUS.
//! Admin sessions only; the shared secret is never returned.

use crate::auth::AdminUser;
use crate::radius;
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

/// GET /api/system/auth-servers
pub async fn list(State(state): State<AppState>, _a: AdminUser) -> Response {
    match radius::servers(&state.config_store).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct ServerInput {
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub secret: String,
    #[serde(default)]
    pub default_role: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

/// POST /api/system/auth-servers
pub async fn create(
    State(state): State<AppState>,
    _a: AdminUser,
    Json(i): Json<ServerInput>,
) -> Response {
    match radius::add_server(
        &state.config_store,
        &i.name,
        &i.host,
        i.port,
        &i.secret,
        i.default_role.as_deref(),
        i.timeout_secs,
    )
    .await
    {
        Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// DELETE /api/system/auth-servers/:id
pub async fn remove(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    match radius::delete_server(&state.config_store, id).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such server"),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/system/auth-servers", get(list).post(create))
        .route("/system/auth-servers/:id", delete(remove))
}
