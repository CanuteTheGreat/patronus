//! Dashboard layout (`/api/v1/dashboard/layout`) and settings
//! (`/api/v1/dashboard/settings`).
//!
//! The layout is scoped to the signed-in web user: the user name comes from
//! the session, never from the request, so one user cannot read or change
//! another one's. Every role (also read-only) may save its OWN layout: it is
//! a display preference, not router configuration. API keys are not web users
//! and have no layout.

use crate::auth::{AdminUser, AuthUser, Session};
use crate::dashboard::{self, Layout, Viewer};
use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

pub fn viewer(s: &Session) -> Viewer {
    Viewer {
        role: s.role,
        access_point: crate::routes::api::wifi::role() == crate::routes::api::setup::DeviceRole::Ap,
    }
}

fn is_web_user(s: &Session) -> bool {
    !s.username.is_empty() && !s.username.starts_with("api-key:")
}

/// The layout `user` sees (stored one resolved against the registry, or the default).
pub async fn resolved(state: &AppState, s: &Session) -> (Layout, bool) {
    let v = viewer(s);
    let saved = match patronus_config::dashboard::get_layout(&state.config_store, &s.username).await
    {
        Ok(Some(j)) => dashboard::parse_stored(&j),
        _ => None,
    };
    let customized = saved.is_some();
    (Layout::resolve(saved, v), customized)
}

fn registry_json(v: Viewer) -> Vec<Value> {
    dashboard::REGISTRY
        .iter()
        .filter(|d| dashboard::eligible(d, v))
        .map(|d| json!({"id": d.id, "title": d.title, "default_on": d.default_on, "wide": d.wide}))
        .collect()
}

async fn answer(state: &AppState, s: &Session) -> Response {
    let (layout, customized) = resolved(state, s).await;
    let v = viewer(s);
    Json(json!({
        "user": s.username,
        "customized": customized,
        "layout": layout,
        "default": Layout::default_for(v),
        "registry": registry_json(v),
    }))
    .into_response()
}

/// GET /api/v1/dashboard/layout
pub async fn get_layout(State(state): State<AppState>, user: AuthUser) -> Response {
    if !is_web_user(&user.session) {
        return error(
            StatusCode::FORBIDDEN,
            "the dashboard layout belongs to a web user, not an API key",
        );
    }
    answer(&state, &user.session).await
}

/// PUT /api/v1/dashboard/layout   `{"widgets":[{"id":"internet","on":true}, ...]}`
pub async fn put_layout(
    State(state): State<AppState>,
    user: AuthUser,
    body: Result<Json<Layout>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !is_web_user(&user.session) {
        return error(
            StatusCode::FORBIDDEN,
            "the dashboard layout belongs to a web user, not an API key",
        );
    }
    let Json(layout) = match body {
        Ok(b) => b,
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("invalid layout: {e}")),
    };
    let layout = match layout.validate(viewer(&user.session)) {
        Ok(l) => l,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let json = serde_json::to_string(&layout).unwrap_or_default();
    if let Err(e) =
        patronus_config::dashboard::put_layout(&state.config_store, &user.session.username, &json)
            .await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    answer(&state, &user.session).await
}

/// DELETE /api/v1/dashboard/layout: back to the default layout.
pub async fn delete_layout(State(state): State<AppState>, user: AuthUser) -> Response {
    if !is_web_user(&user.session) {
        return error(
            StatusCode::FORBIDDEN,
            "the dashboard layout belongs to a web user, not an API key",
        );
    }
    if let Err(e) =
        patronus_config::dashboard::delete_layout(&state.config_store, &user.session.username).await
    {
        return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    answer(&state, &user.session).await
}

/// GET /api/v1/dashboard/settings
pub async fn get_settings(State(state): State<AppState>, _user: AuthUser) -> Response {
    Json(patronus_config::dashboard::load(&state.config_store).await).into_response()
}

/// PUT /api/v1/dashboard/settings (administrators): any of `refresh_seconds`,
/// `activity_sample_secs`, `activity_top`, `tcp_timeout_secs`, `tcp_tests_per_minute`.
pub async fn put_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(patch): Json<Value>,
) -> Response {
    match patronus_config::dashboard::save(&state.config_store, &patch).await {
        Ok(s) => Json(s).into_response(),
        Err(e) if e.to_string().contains("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/dashboard/layout",
            get(get_layout).put(put_layout).delete(delete_layout),
        )
        .route(
            "/v1/dashboard/settings",
            get(get_settings).put(put_settings),
        )
}
