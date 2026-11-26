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

/// POST /api/system/hooks -- a notification channel: `{"name","channel":
/// "webhook"|"ntfy"|"telegram"|"discord"|"slack"|"email","url","secret",
/// "target","sender","username","kinds","min_severity"}` (see
/// `telemetry::check_spec`; a body without `channel` is a signed webhook).
pub async fn create_hook(
    State(state): State<AppState>,
    _a: AdminUser,
    Json(i): Json<telemetry::HookSpec>,
) -> Response {
    match telemetry::save_channel(&state.config_store, &i).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({"id": id}))).into_response(),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// POST /api/system/hooks/:id/test -- send a test message now.
pub async fn test_hook(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(id): Path<i64>,
) -> Response {
    match telemetry::send_test(&state.config_store, id).await {
        Ok(Some(r)) => Json(json!({"ok": true, "result": r})).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such webhook"),
        Err(e) => error(StatusCode::BAD_GATEWAY, format!("not delivered: {e}")),
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

/// GET /api/system/matchers -- every notification matcher with the channels using it.
pub async fn list_matchers(State(state): State<AppState>, _a: AdminUser) -> Response {
    match patronus_config::notify_matcher::list(&state.config_store).await {
        Ok(m) => Json(m).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// GET /api/system/matchers/limits -- size limits, event kinds and severities
/// the editor offers.
pub async fn matcher_info(State(state): State<AppState>, _a: AdminUser) -> Response {
    let l = patronus_config::notify_matcher::Limits::load(&state.config_store).await;
    Json(json!({
        "max_depth": l.max_depth, "max_nodes": l.max_nodes,
        "max_items": l.max_items, "max_glob_len": l.max_glob_len,
        "kinds": telemetry::EVENT_KINDS, "severities": telemetry::SEVERITIES,
        "days": ["mon","tue","wed","thu","fri","sat","sun"],
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct MatcherBody {
    #[serde(default)]
    pub description: String,
    pub tree: patronus_config::notify_matcher::Matcher,
}

fn matcher_err(e: patronus_core::Error) -> Response {
    let m = e.to_string();
    if m.contains("Invalid") {
        error(StatusCode::BAD_REQUEST, m)
    } else {
        error(StatusCode::INTERNAL_SERVER_ERROR, m)
    }
}

/// PUT /api/system/matchers/:name -- `{"description","tree"}`, created or replaced.
pub async fn put_matcher(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(name): Path<String>,
    Json(b): Json<MatcherBody>,
) -> Response {
    match patronus_config::notify_matcher::upsert(
        &state.config_store,
        &name,
        &b.description,
        b.tree,
        telemetry::EVENT_KINDS,
    )
    .await
    {
        Ok(t) => Json(json!({"ok": true, "tree": t})).into_response(),
        Err(e) => matcher_err(e),
    }
}

/// DELETE /api/system/matchers/:name -- refused while a channel uses it.
pub async fn delete_matcher(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(name): Path<String>,
) -> Response {
    match patronus_config::notify_matcher::delete(&state.config_store, &name).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such matcher"),
        Err(e) => matcher_err(e),
    }
}

/// POST /api/system/matchers/preview -- `{"tree"}` (not saved): the last
/// events of the event log, each marked matched or not.
pub async fn preview_matcher(
    State(state): State<AppState>,
    _a: AdminUser,
    Json(b): Json<MatcherBody>,
) -> Response {
    let lim = patronus_config::notify_matcher::Limits::load(&state.config_store).await;
    let tree = match b.tree.validated(&lim, telemetry::EVENT_KINDS) {
        Ok(t) => t,
        Err(e) => return matcher_err(e),
    };
    match telemetry::preview(&state.config_store, &tree).await {
        Ok(rows) => {
            let n = rows.iter().filter(|r| r.matched).count();
            Json(json!({"matched": n, "total": rows.len(), "events": rows})).into_response()
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(serde::Deserialize)]
pub struct HookMatcherBody {
    #[serde(default)]
    pub matcher: String,
}

/// PUT /api/system/hooks/:id/matcher -- `{"matcher": "name"}` ("" = the channel's own kinds + severity).
pub async fn set_hook_matcher(
    State(state): State<AppState>,
    _a: AdminUser,
    Path(id): Path<i64>,
    Json(b): Json<HookMatcherBody>,
) -> Response {
    match telemetry::set_hook_matcher(&state.config_store, id, &b.matcher).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such webhook"),
        Err(e) if e.to_string().starts_with("Invalid") => {
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get, put};
    axum::Router::new()
        .route("/status/summary", get(summary))
        .route("/events", get(list_events))
        .route("/events/kinds", get(kinds))
        .route("/system/hooks", get(list_hooks).post(create_hook))
        .route("/system/hooks/:id", delete(delete_hook))
        .route("/system/hooks/:id/test", axum::routing::post(test_hook))
        .route("/system/hooks/:id/matcher", put(set_hook_matcher))
        .route("/system/matchers", get(list_matchers))
        .route("/system/matchers/limits", get(matcher_info))
        .route("/system/matchers/preview", axum::routing::post(preview_matcher))
        .route("/system/matchers/:name", put(put_matcher).delete(delete_matcher))
}
