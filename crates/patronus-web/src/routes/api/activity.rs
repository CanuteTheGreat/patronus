//! `GET /api/v1/system/activity` and the System activity page.
//!
//! Read from `/proc` only, through the cached sampler (`state::activity`), so
//! the request returns at once. Command lines are redacted in
//! `patronus_network::activity` before they get here.

use crate::auth::AuthUser;
use crate::state::{activity::Sampler, AppState};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use patronus_network::activity::{self, ProcessRow};
use serde::Deserialize;
use serde_json::json;

fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct Params {
    /// cpu (default), memory, pid, name, user, threads
    pub sort: Option<String>,
    /// desc (default) or asc
    pub order: Option<String>,
    /// processes returned (default: the `dashboard.activity_top` setting)
    pub limit: Option<usize>,
    /// only the processes of this managed service (a `daemons[].name`)
    pub daemon: Option<String>,
}

/// Largest `limit` the API honours.
pub const MAX_LIMIT: usize = 500;

/// GET /api/v1/system/activity
pub async fn get_activity(
    State(state): State<AppState>,
    _user: AuthUser,
    Query(p): Query<Params>,
) -> Response {
    let sort = p.sort.as_deref().unwrap_or("cpu");
    if !activity::SORT_KEYS.contains(&sort) {
        return crate::i18n::api_error(
            StatusCode::BAD_REQUEST,
            "err-activity-sort",
            &[("v1", activity::SORT_KEYS.join(", "))],
        );
    }
    let descending = match p.order.as_deref().unwrap_or("desc") {
        "desc" => true,
        "asc" => false,
        _ => return crate::i18n::api_error(StatusCode::BAD_REQUEST, "err-activity-order", &[]),
    };
    let settings = patronus_config::dashboard::load(&state.config_store).await;
    let limit = p.limit.unwrap_or(settings.activity_top as usize);
    if limit == 0 || limit > MAX_LIMIT {
        return crate::i18n::api_error(
            StatusCode::BAD_REQUEST,
            "err-activity-limit",
            &[("v1", MAX_LIMIT.to_string())],
        );
    }
    let Some(snap) = Sampler::global().latest(&state.config_store) else {
        return Json(json!({
            "ready": false,
            "note": "the first two samples are being taken; ask again in a second",
            "sort": sort, "order": if descending { "desc" } else { "asc" }, "limit": limit,
            "processes": [], "daemons": [], "process_count": 0,
        }))
        .into_response();
    };
    let mut rows: Vec<ProcessRow> = match &p.daemon {
        Some(d) => snap
            .processes
            .iter()
            .filter(|r| r.daemon.as_deref() == Some(d.as_str()))
            .cloned()
            .collect(),
        None => snap.processes.clone(),
    };
    activity::sort_rows(&mut rows, sort, descending);
    let matched = rows.len();
    rows.truncate(limit);
    Json(json!({
        "ready": true,
        "taken_at": snap.taken_at,
        "age_secs": (chrono::Utc::now().timestamp() - snap.taken_at).max(0),
        "interval_secs": snap.interval_secs,
        "sample_every_secs": settings.activity_sample_secs,
        "cpus": snap.cpus,
        "cpu_percent": snap.cpu_percent,
        "load": snap.load,
        "memory": snap.memory,
        "uptime_secs": snap.uptime_secs,
        "process_count": snap.process_count,
        "matched": matched,
        "sort": sort,
        "order": if descending { "desc" } else { "asc" },
        "limit": limit,
        "processes": rows,
        "daemons": snap.daemons,
    }))
    .into_response()
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/system/activity", get(get_activity))
}

/// The page (`/activity`): a static shell, the data comes from the API.
pub async fn page(_user: AuthUser) -> Response {
    super::super::pages::render(
        &crate::templates::ActivityTemplate { page: "activity" },
        "activity",
    )
}
