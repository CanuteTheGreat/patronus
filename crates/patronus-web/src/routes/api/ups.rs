//! UPS status and history (USE=ups). Settings are the generic feature API (`/api/svc/ups`).
//!
//! - `GET /api/v1/ups`       (alias `/api/ups`) `{enabled, installed, mode, state, reading, message, events}`;
//!                           `state` is online | on_battery | low_battery | unknown, `message` says why there is no reading
//! - `GET /api/v1/ups/history` (alias `/api/ups/history`) `?hours=24&limit=2000`, samples oldest first
//!
//! In a build without the feature both answer 404 naming the USE flag.

use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct HistoryQuery {
    hours: Option<i64>,
    limit: Option<i64>,
}

#[cfg(feature = "ups")]
async fn status(State(state): State<AppState>) -> Response {
    match crate::state::ups::document(&state.config_store).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[cfg(feature = "ups")]
async fn history(State(state): State<AppState>, Query(q): Query<HistoryQuery>) -> Response {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 365);
    match crate::state::ups::history(
        &state.config_store,
        chrono::Utc::now().timestamp(),
        hours * 3600,
        q.limit.unwrap_or(2000),
    )
    .await
    {
        Ok(v) => Json(json!({"hours": hours, "samples": v})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[cfg(not(feature = "ups"))]
async fn status(State(_): State<AppState>) -> Response {
    not_built()
}

#[cfg(not(feature = "ups"))]
async fn history(State(_): State<AppState>, Query(_): Query<HistoryQuery>) -> Response {
    not_built()
}

#[cfg(not(feature = "ups"))]
fn not_built() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "this build has no UPS support; rebuild with USE=ups (cargo feature `ups`)"})),
    )
        .into_response()
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new()
        .route("/ups", get(status))
        .route("/ups/history", get(history))
}

#[cfg(test)]
mod tests {
    #[test]
    fn routes_build() {
        let _ = super::router();
    }
}
