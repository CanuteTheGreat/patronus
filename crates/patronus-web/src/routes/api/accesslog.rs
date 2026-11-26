//! Access log and configuration-change log (admin only, accounts only:
//! API keys never read them).
//!
//! - `GET    /api/system/access-log`          rows (filters: since, until, user,
//!   user_exact, api_key, method, path, client, status, q, after_id (live cursor,
//!   oldest first), before_id, limit)
//! - `GET    /api/system/access-log/stats`    totals, buckets, top lists (same filters, `top`)
//! - `GET    /api/system/access-log/csv`      the same rows as CSV
//! - `DELETE /api/system/access-log`          forget the history
//! - `GET|PUT /api/system/access-log/settings` typed settings (retention, bursts)
//! - `GET    /api/system/audit-log`           configuration changes
//! - `GET    /api/system/audit-log/csv`

#![allow(clippy::result_large_err)]

use crate::auth::AdminUser;
use crate::state::accesslog::{self, AuditFilter, Filter, SettingsInput};
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use askama::Template;
use axum::response::Html;
use serde_json::json;

fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/system/access-log",
            get(list).delete(clear),
        )
        .route("/system/access-log/stats", get(stats))
        .route("/system/access-log/csv", get(csv))
        .route(
            "/system/access-log/settings",
            get(get_settings).put(put_settings),
        )
        .route("/system/audit-log", get(audit))
        .route("/system/audit-log/csv", get(audit_csv))
}

async fn list(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(f): Query<Filter>,
) -> Response {
    match accesslog::search(&state.config_store, &f).await {
        Ok((rows, total)) => {
            let last = rows.iter().map(|r| r.id).max();
            Json(json!({
                "rows": rows,
                "total": total,
                // resume point for the live view
                "last_id": last,
                "writer": state.access_log.status(),
            }))
            .into_response()
        }
        Err(e) => err(e),
    }
}

async fn stats(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(f): Query<Filter>,
) -> Response {
    match accesslog::stats(&state.config_store, &f, f.top.unwrap_or(10)).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => err(e),
    }
}

fn csv_response(name: &'static str, body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        body,
    )
        .into_response()
}

async fn csv(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(mut f): Query<Filter>,
) -> Response {
    // a download takes the whole selection, not one page
    f.limit = Some(f.limit.unwrap_or(accesslog::MAX_LIMIT));
    f.before_id = None;
    match accesslog::search(&state.config_store, &f).await {
        Ok((rows, _)) => csv_response("access-log.csv", accesslog::rows_csv(&rows)),
        Err(e) => err(e),
    }
}

async fn clear(_admin: AdminUser, State(state): State<AppState>) -> Response {
    match accesslog::clear(&state.config_store).await {
        Ok(()) => {
            let _ = state
                .config_store
                .audit("system", "clear", "access_log", None, &json!({}))
                .await;
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => err(e),
    }
}

async fn get_settings(_admin: AdminUser, State(state): State<AppState>) -> Response {
    Json(json!({
        "settings": accesslog::load_settings(&state.config_store).await,
        "writer": state.access_log.status(),
    }))
    .into_response()
}

async fn put_settings(
    admin: AdminUser,
    State(state): State<AppState>,
    Json(i): Json<SettingsInput>,
) -> Response {
    if let Err(e) = accesslog::save_settings(&state.config_store, i).await {
        return err(e);
    }
    let s = accesslog::load_settings(&state.config_store).await;
    let _ = state
        .config_store
        .audit(
            &admin.session.username,
            "update",
            "access_log_settings",
            None,
            &json!(s),
        )
        .await;
    Json(json!({"ok": true, "settings": s})).into_response()
}

async fn audit(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(f): Query<AuditFilter>,
) -> Response {
    match accesslog::audit_search(&state.config_store, &f).await {
        Ok((rows, total)) => Json(json!({ "rows": rows, "total": total })).into_response(),
        Err(e) => err(e),
    }
}

async fn audit_csv(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(mut f): Query<AuditFilter>,
) -> Response {
    f.limit = Some(f.limit.unwrap_or(accesslog::MAX_LIMIT));
    f.before_id = None;
    match accesslog::audit_search(&state.config_store, &f).await {
        Ok((rows, _)) => csv_response("configuration-changes.csv", accesslog::audit_csv(&rows)),
        Err(e) => err(e),
    }
}

#[derive(Template)]
#[template(path = "access_log.html")]
struct AccessLogTemplate {
    page: &'static str,
}

async fn page(_admin: AdminUser) -> Response {
    match (AccessLogTemplate { page: "access-log" }).render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render access log: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// The HTML page (admin only; the data comes from the API above).
pub fn pages() -> Router<AppState> {
    Router::new().route("/system/access-log", get(page))
}
