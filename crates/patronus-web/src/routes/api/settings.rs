//! Settings registry over HTTP (`patronus_config::settings`): every
//! operational value that used to be hard-coded, with its type, bounds,
//! default and current value. Reading needs a login; changing needs an
//! administrator. Values live in the config store, so backups, revisions,
//! generations and GitOps carry them.
//!
//! - `GET /api/settings` -> `{"settings": [{key, section, label, doc, kind,
//!   default, unit, effect, value, is_default}]}`
//! - `PUT /api/settings/{key}` `{"value": "..."}` -> the updated entry
//!   (400 for an unknown key or an invalid value)
//! - `DELETE /api/settings/{key}` -> back to the default
//! - page `/settings` (System > Advanced settings)

use crate::auth::{AdminUser, AuthUser};
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, put},
    Json,
};
use patronus_config::settings;
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

fn store_error(e: patronus_core::Error) -> Response {
    let m = e.to_string();
    if m.contains("Invalid setting") {
        error(StatusCode::BAD_REQUEST, m)
    } else {
        error(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
}

/// GET /api/settings
pub async fn list(State(state): State<AppState>, _me: AuthUser) -> Response {
    match settings::list(&state.config_store).await {
        Ok(v) => Json(json!({ "settings": v })).into_response(),
        Err(e) => store_error(e),
    }
}

#[derive(Deserialize)]
pub struct SetValue {
    pub value: serde_json::Value,
}

async fn one(state: &AppState, key: &str) -> Response {
    match settings::list(&state.config_store).await {
        Ok(v) => match v.into_iter().find(|s| s.setting.key == key) {
            Some(s) => Json(s).into_response(),
            None => error(StatusCode::NOT_FOUND, format!("unknown setting {key:?}")),
        },
        Err(e) => store_error(e),
    }
}

async fn after_change(state: &AppState, admin: &AdminUser, action: &str, key: &str, value: &str) {
    if let Err(e) = settings::load_cache(&state.config_store).await {
        tracing::warn!("settings cache refresh: {e}");
    }
    let _ = state
        .config_store
        .audit(
            &admin.session.username,
            action,
            "setting",
            Some(key),
            &json!({ "value": value }),
        )
        .await;
}

/// PUT /api/settings/{key} `{"value": ...}` (admin)
pub async fn set(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(key): Path<String>,
    Json(req): Json<SetValue>,
) -> Response {
    let raw = match &req.value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "value must be a string, number or boolean",
            )
        }
    };
    if settings::find(&key).is_none() {
        return error(StatusCode::NOT_FOUND, format!("unknown setting {key:?}"));
    }
    match settings::set(&state.config_store, &key, &raw).await {
        Ok(v) => {
            after_change(&state, &admin, "update", &key, &v).await;
            one(&state, &key).await
        }
        Err(e) => store_error(e),
    }
}

/// DELETE /api/settings/{key} (admin): back to the default.
pub async fn reset(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(key): Path<String>,
) -> Response {
    if settings::find(&key).is_none() {
        return error(StatusCode::NOT_FOUND, format!("unknown setting {key:?}"));
    }
    match settings::reset(&state.config_store, &key).await {
        Ok(()) => {
            after_change(&state, &admin, "reset", &key, "").await;
            one(&state, &key).await
        }
        Err(e) => store_error(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/settings", get(list))
        .route("/settings/:key", put(set).delete(reset))
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    pub page: &'static str,
    pub is_admin: bool,
}

/// Page: System > Advanced settings (data from `GET /api/settings`).
pub async fn page(me: AuthUser) -> Response {
    let t = SettingsTemplate {
        page: "settings",
        is_admin: me.session.role.is_admin(),
    };
    match t.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render settings page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/settings", get(page))
}
