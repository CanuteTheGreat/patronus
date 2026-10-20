//! Leader gating for the HTTP API in an HA cluster.
//!
//! Only the elected leader serves `/api/*`, so there is exactly one writer
//! and every client sees the same data no matter which node it reaches:
//!
//! * On a follower, `/api/*` requests are forwarded to the leader and its
//!   response is relayed back unchanged. If no leader is known yet (an
//!   election is in progress) the follower answers 503 with `Retry-After`.
//! * On the leader, a request that may have changed the database is only
//!   reported successful once `ha::replication` has the change on a quorum
//!   of nodes; otherwise the caller gets 503 so it can retry instead of
//!   trusting a write a failover could lose.
//!
//! Health checks, `/ha/*` RPCs, static assets and WebSocket upgrades are
//! always served locally.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tracing::warn;

use super::replication::ReplicationError;
use crate::state::AppState;

/// Set on requests a follower forwards, so a node that lost leadership in
/// the meantime answers 503 instead of forwarding again (no loops).
pub const FORWARDED_BY_HEADER: &str = "x-patronus-forwarded-by";

/// Largest request body a follower will forward.
const MAX_FORWARD_BODY: usize = 16 * 1024 * 1024;

fn is_gated_path(path: &str) -> bool {
    path.starts_with("/api/") && !path.starts_with("/api/v2/graphql/ws")
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn unavailable(message: String) -> Response {
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": message })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    resp
}

/// axum middleware enforcing the rules above. A no-op when HA is disabled.
pub async fn leader_gate(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(ha) = state.ha.clone() else {
        return next.run(req).await;
    };
    if !is_gated_path(req.uri().path()) {
        return next.run(req).await;
    }

    if ha.is_leader() {
        let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
        let resp = next.run(req).await;
        if !mutating || !resp.status().is_success() {
            return resp;
        }
        let Some(replicator) = state.replicator.clone() else {
            return resp;
        };
        return match replicator.replicate(false).await {
            Ok(_) => resp,
            Err(ReplicationError::NotLeader) => unavailable(
                "this node lost HA leadership while handling the request; retry".into(),
            ),
            Err(e) => {
                warn!(error = %e, "Write not confirmed by an HA quorum");
                unavailable(e.to_string())
            }
        };
    }

    if req.headers().contains_key(FORWARDED_BY_HEADER) {
        return unavailable("request was forwarded to a node that is not the HA leader".into());
    }
    let Some(leader) = ha.leader_addr().await else {
        return unavailable("no HA leader is elected yet; retry shortly".into());
    };
    forward(&state, ha.node_id(), &leader, req).await
}

async fn forward(state: &AppState, node_id: &str, leader: &str, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = match to_bytes(body, MAX_FORWARD_BODY).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("http://{}{}", leader, path_and_query);

    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    let mut out = state.forward_client.request(method, &url).body(body);
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name) {
            out = out.header(name.as_str(), value.as_bytes());
        }
    }
    out = out.header(FORWARDED_BY_HEADER, node_id);

    let upstream = match out.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(leader = %leader, error = %e, "Forwarding API request to HA leader failed");
            return unavailable(format!("HA leader {} is unreachable; retry shortly", leader));
        }
    };

    let status = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for (name, value) in upstream.headers().iter() {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if !is_hop_by_hop(&n) {
                headers.append(n, v);
            }
        }
    }
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!(leader = %leader, error = %e, "Reading HA leader response failed");
            return unavailable("HA leader response was cut off; retry".into());
        }
    };
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp
}

/// HTTP client used for follower -> leader forwarding.
pub fn forward_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HA forwarding HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gated_paths() {
        assert!(is_gated_path("/api/v1/sites"));
        assert!(is_gated_path("/api/v2/graphql"));
        assert!(!is_gated_path("/api/v2/graphql/ws"));
        assert!(!is_gated_path("/ha/status"));
        assert!(!is_gated_path("/health/ready"));
        assert!(!is_gated_path("/assets/index.js"));
    }
}
