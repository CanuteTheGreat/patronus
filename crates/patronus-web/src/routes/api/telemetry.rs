//! Status summary, metrics, events and webhooks for monitoring systems
//! (lane H). Readable with a session or a read-only API key; webhook
//! management is admin-only.

use crate::auth::AdminUser;
use crate::state::{telemetry, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// GET /api/status/summary
pub async fn summary(State(state): State<AppState>) -> Response {
    Json(telemetry::summary(&state).await).into_response()
}

/// GET /metrics
pub async fn metrics(State(state): State<AppState>) -> Response {
    let s = telemetry::summary(&state).await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        telemetry::prometheus(&s),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct EventQuery {
    /// only events with an id above this (resume point)
    #[serde(default)]
    pub after: i64,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// GET /api/events?after=<id>&kind=<kind>&limit=<n> -- oldest first, so a
/// collector resumes from the last id it saw.
pub async fn list_events(State(state): State<AppState>, Query(q): Query<EventQuery>) -> Response {
    match telemetry::events(
        &state.config_store,
        q.after,
        q.kind.as_deref(),
        q.limit.unwrap_or(200),
    )
    .await
    {
        Ok(e) => Json(e).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// GET /api/events/kinds
pub async fn kinds() -> Response {
    Json(telemetry::EVENT_KINDS).into_response()
}

/// GET /api/system/hooks
pub async fn list_hooks(State(state): State<AppState>, _a: AdminUser) -> Response {
    match telemetry::hooks(&state.config_store).await {
        Ok(h) => Json(h).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct HookInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub secret: String,
    /// comma-separated event kinds; empty = all
    #[serde(default)]
    pub kinds: String,
}

/// POST /api/system/hooks
pub async fn create_hook(
    State(state): State<AppState>,
    _a: AdminUser,
    Json(i): Json<HookInput>,
) -> Response {
    match telemetry::save_hook(&state.config_store, &i.name, &i.url, &i.secret, &i.kinds).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// DELETE /api/system/hooks/:id
pub async fn delete_hook(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    match telemetry::delete_hook(&state.config_store, id).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such webhook"),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/status/summary", get(summary))
        .route("/events", get(list_events))
        .route("/events/kinds", get(kinds))
        .route("/system/hooks", get(list_hooks).post(create_hook))
        .route("/system/hooks/:id", delete(delete_hook))
}
