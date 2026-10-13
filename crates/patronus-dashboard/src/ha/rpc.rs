//! HTTP RPC handlers exposing the HA leader-election mechanism on the
//! dashboard's own axum router (`/ha/vote`, `/ha/heartbeat`, `/ha/status`).
//! These are called node-to-node (see `election.rs`'s client side) and are
//! also useful directly for live verification (curl `/ha/status`).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use super::election::{HeartbeatRequest, HeartbeatResponse, VoteRequest, VoteResponse};
use crate::state::AppState;

/// `POST /ha/vote` -- RequestVote RPC.
pub async fn vote_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, StatusCode> {
    match &state.ha {
        Some(ha) => Ok(Json(ha.handle_vote_request(req).await)),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `POST /ha/heartbeat` -- AppendEntries-lite / heartbeat RPC.
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    match &state.ha {
        Some(ha) => Ok(Json(ha.handle_heartbeat(req).await)),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `GET /ha/status` -- role/term/leader snapshot for live verification.
pub async fn status_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<super::election::HaStatus>, StatusCode> {
    match &state.ha {
        Some(ha) => Ok(Json(ha.status().await)),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}
