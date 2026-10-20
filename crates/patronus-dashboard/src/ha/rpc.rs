//! HTTP RPC handlers exposing the HA mechanism on the dashboard's own axum
//! router. `/ha/vote`, `/ha/heartbeat` and `/ha/replicate` are node-to-node
//! and require the cluster credential (`x-patronus-cluster-auth`, derived
//! from the shared `PATRONUS_JWT_SECRET`), otherwise anyone who can reach a
//! node could claim leadership or overwrite its data. `/ha/status`,
//! `/ha/leader` and `/ha/cluster` are read-only views for load balancers,
//! operators and the dashboard UI.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Serialize;

use super::election::{
    HaStatus, HeartbeatRequest, HeartbeatResponse, VoteRequest, VoteResponse, CLUSTER_AUTH_HEADER,
};
use super::replication::{
    ApplyError, GENERATION_HEADER, LEADER_ADDR_HEADER, LEADER_HEADER, TERM_HEADER,
};
use crate::state::AppState;

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn authorized(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    match &state.ha {
        Some(ha) if ha.rpc_authorized(header_str(headers, CLUSTER_AUTH_HEADER)) => Ok(()),
        Some(_) => Err(StatusCode::UNAUTHORIZED),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `POST /ha/vote` -- RequestVote RPC.
pub async fn vote_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, StatusCode> {
    authorized(&state, &headers)?;
    let ha = state.ha.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(ha.handle_vote_request(req).await))
}

/// `POST /ha/heartbeat` -- AppendEntries-lite / heartbeat RPC.
pub async fn heartbeat_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    authorized(&state, &headers)?;
    let ha = state.ha.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(ha.handle_heartbeat(req).await))
}

/// `POST /ha/replicate` -- leader pushes a sealed database snapshot.
pub async fn replicate_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    authorized(&state, &headers).map_err(|s| (s, "unauthorized".to_string()))?;
    let replicator = state.replicator.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "replication disabled".to_string(),
    ))?;
    let parse = |name: &str| -> Result<u64, (StatusCode, String)> {
        header_str(&headers, name)
            .and_then(|v| v.parse().ok())
            .ok_or((StatusCode::BAD_REQUEST, format!("missing/invalid {}", name)))
    };
    let term = parse(TERM_HEADER)?;
    let generation = parse(GENERATION_HEADER)?;
    let leader = header_str(&headers, LEADER_HEADER)
        .ok_or((StatusCode::BAD_REQUEST, format!("missing {}", LEADER_HEADER)))?
        .to_string();
    let leader_addr = header_str(&headers, LEADER_ADDR_HEADER).map(|s| s.to_string());

    match replicator
        .apply(term, &leader, leader_addr, generation, &body)
        .await
    {
        Ok(g) => Ok(Json(serde_json::json!({ "generation": g }))),
        Err(ApplyError::StaleTerm { ours }) => Err((
            StatusCode::CONFLICT,
            format!("stale term {} (ours is {})", term, ours),
        )),
        Err(ApplyError::BadEnvelope) => Err((
            StatusCode::UNAUTHORIZED,
            "snapshot failed authentication".to_string(),
        )),
        Err(ApplyError::Internal(e)) => {
            tracing::error!(error = %e, "Applying HA snapshot failed");
            Err((StatusCode::INTERNAL_SERVER_ERROR, e))
        }
    }
}

/// `GET /ha/status` -- role/term/leader snapshot for live verification.
pub async fn status_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HaStatus>, StatusCode> {
    match &state.ha {
        Some(ha) => Ok(Json(ha.status().await)),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// `GET /ha/leader` -- 200 only on the node that should receive traffic
/// (the leader, or any node when HA is disabled), 503 otherwise. haproxy's
/// health check uses this so it only routes to the leader.
pub async fn leader_handler(State(state): State<Arc<AppState>>) -> (StatusCode, &'static str) {
    match &state.ha {
        None => (StatusCode::OK, "standalone"),
        Some(ha) if ha.is_leader() => (StatusCode::OK, "leader"),
        Some(_) => (StatusCode::SERVICE_UNAVAILABLE, "follower"),
    }
}

#[derive(Debug, Serialize)]
pub struct NodeView {
    /// Peer address as configured (`host:port`); this node's own entry uses
    /// its advertise address.
    pub address: String,
    pub reachable: bool,
    pub status: Option<HaStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClusterView {
    pub enabled: bool,
    /// The node that answered this request.
    pub answered_by: Option<String>,
    pub leader_id: Option<String>,
    pub term: u64,
    pub nodes: Vec<NodeView>,
}

async fn fetch_peer_status(client: reqwest::Client, peer: String) -> NodeView {
    let res = client
        .get(format!("http://{}/ha/status", peer))
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => match r.json::<HaStatus>().await {
            Ok(s) => NodeView {
                address: peer,
                reachable: true,
                status: Some(s),
                error: None,
            },
            Err(e) => NodeView {
                address: peer,
                reachable: true,
                status: None,
                error: Some(format!("bad status payload: {}", e)),
            },
        },
        Ok(r) => NodeView {
            address: peer,
            reachable: true,
            status: None,
            error: Some(format!("HTTP {}", r.status())),
        },
        Err(e) => NodeView {
            address: peer,
            reachable: false,
            status: None,
            error: Some(e.to_string()),
        },
    }
}

/// `GET /ha/cluster` -- every node's live HA status in one response (this
/// node's own plus each peer's `/ha/status`), for the dashboard's Cluster
/// page. Nodes that don't answer are reported as unreachable.
pub async fn cluster_handler(State(state): State<Arc<AppState>>) -> Json<ClusterView> {
    let Some(ha) = state.ha.clone() else {
        return Json(ClusterView {
            enabled: false,
            answered_by: None,
            leader_id: None,
            term: 0,
            nodes: Vec::new(),
        });
    };
    let own = ha.status().await;
    let tasks: Vec<_> = ha
        .peers()
        .iter()
        .cloned()
        .map(|peer| tokio::spawn(fetch_peer_status(ha.http_client(), peer)))
        .collect();

    let mut nodes = vec![NodeView {
        address: own.advertise_addr.clone(),
        reachable: true,
        status: Some(own.clone()),
        error: None,
    }];
    for t in tasks {
        if let Ok(view) = t.await {
            nodes.push(view);
        }
    }
    Json(ClusterView {
        enabled: true,
        answered_by: Some(own.node_id.clone()),
        leader_id: own.leader_id.clone(),
        term: own.term,
        nodes,
    })
}
