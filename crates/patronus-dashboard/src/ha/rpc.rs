//! HTTP RPC handlers exposing the HA leader-election + replication mechanism
//! on the dashboard's own axum router (`/ha/vote`, `/ha/heartbeat`,
//! `/ha/submit`, `/ha/status`). The POST endpoints are node-to-node only and
//! require the cluster token (`x-patronus-cluster-token`) derived from the
//! shared signing secret; `/ha/status` is a read-only status view used by
//! operators and the dashboard UI's cluster panel.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

use super::election::{
    HeartbeatRequest, HeartbeatResponse, SubmitError, SubmitRequest, SubmitResponse, VoteRequest,
    VoteResponse,
};
use crate::auth::jwt::{cluster_rpc_token, CLUSTER_TOKEN_HEADER};
use crate::state::AppState;

/// The `/ha/*` routes, mounted on the dashboard router.
pub fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/ha/vote", post(vote_handler))
        .route("/ha/heartbeat", post(heartbeat_handler))
        .route("/ha/submit", post(submit_handler))
        .route("/ha/status", get(status_handler))
        .route("/ha/cluster", get(cluster_handler))
}

/// Constant-time check of the cluster RPC token.
pub fn cluster_token_ok(headers: &HeaderMap) -> bool {
    let Some(got) = headers
        .get(CLUSTER_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let want = cluster_rpc_token().as_bytes();
    let got = got.as_bytes();
    got.len() == want.len() && got.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn guard(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    match &state.ha {
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
        Some(ha) if ha.is_stopped() => Err(StatusCode::SERVICE_UNAVAILABLE),
        Some(_) if !cluster_token_ok(headers) => Err(StatusCode::UNAUTHORIZED),
        Some(_) => Ok(()),
    }
}

/// `POST /ha/vote` -- RequestVote RPC.
pub async fn vote_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, StatusCode> {
    guard(&state, &headers)?;
    let ha = state.ha.as_ref().expect("guarded");
    Ok(Json(ha.handle_vote_request(req).await))
}

/// `POST /ha/heartbeat` -- AppendEntries / heartbeat RPC.
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    guard(&state, &headers)?;
    let ha = state.ha.as_ref().expect("guarded");
    Ok(Json(ha.handle_heartbeat(req).await))
}

/// `POST /ha/submit` -- a follower forwarding a write to the leader.
pub async fn submit_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    guard(&state, &headers).map_err(|s| (s, String::new()))?;
    let ha = state.ha.as_ref().expect("guarded");
    match ha.handle_submit(req).await {
        Ok(r) => Ok(Json(r)),
        Err(SubmitError::NoLeader) => Err((StatusCode::MISDIRECTED_REQUEST, "not leader".into())),
        Err(e) => Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string())),
    }
}

/// `GET /ha/status` -- role/term/leader/replication snapshot.
pub async fn status_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<super::election::HaStatus>, StatusCode> {
    match &state.ha {
        Some(ha) => Ok(Json(ha.status().await)),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// One node as seen from the serving node (`/ha/cluster`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterMember {
    /// Address used to reach it (empty for the serving node itself).
    pub addr: String,
    pub reachable: bool,
    /// True for the node that answered this request.
    pub is_self: bool,
    pub status: Option<super::election::HaStatus>,
}

/// `/ha/cluster` response: the whole cluster, for the dashboard UI's
/// "Cluster" view (which node is leader, term, replication progress).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterView {
    pub ha_enabled: bool,
    pub leader_id: Option<String>,
    pub term: u64,
    pub members: Vec<ClusterMember>,
}

/// `GET /ha/cluster` -- this node's status plus every peer's `/ha/status`.
/// Read-only; works on any node (a single-node install reports HA disabled).
pub async fn cluster_handler(State(state): State<Arc<AppState>>) -> Json<ClusterView> {
    let Some(ha) = &state.ha else {
        return Json(ClusterView {
            ha_enabled: false,
            leader_id: None,
            term: 0,
            members: Vec::new(),
        });
    };
    let me = ha.status().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .expect("http client");
    let mut members = vec![ClusterMember {
        addr: String::new(),
        reachable: true,
        is_self: true,
        status: Some(me.clone()),
    }];
    let futs = me.peers.iter().map(|peer| {
        let client = client.clone();
        let peer = peer.clone();
        async move {
            let status = match client.get(format!("http://{peer}/ha/status")).send().await {
                Ok(r) if r.status().is_success() => {
                    r.json::<super::election::HaStatus>().await.ok()
                }
                _ => None,
            };
            ClusterMember {
                addr: peer,
                reachable: status.is_some(),
                is_self: false,
                status,
            }
        }
    });
    members.extend(futures::future::join_all(futs).await);
    // The leader is whoever claims leadership at the highest term.
    let leader = members
        .iter()
        .filter_map(|m| m.status.as_ref())
        .filter(|s| s.role == super::cluster::NodeRole::Leader)
        .max_by_key(|s| s.term)
        .map(|s| (s.node_id.clone(), s.term));
    let (leader_id, term) = match leader {
        Some((id, t)) => (Some(id), t),
        None => (me.leader_id.clone(), me.term),
    };
    Json(ClusterView {
        ha_enabled: true,
        leader_id,
        term,
        members,
    })
}
