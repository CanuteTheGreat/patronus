//! Edge agent API: enrollment, configuration and heartbeat for the Patronus
//! appliances that form the SD-WAN overlay (`patronus edge run`).
//!
//! - `POST /api/v1/edge/tokens`            operator: create a one-time enrollment token
//! - `GET  /api/v1/edge/edges`             viewer: enrolled edges (overlay address, subnets, last heartbeat)
//! - `DELETE /api/v1/edge/edges/:id`       operator: revoke an edge (credential, record and site removed)
//! - `POST /api/v1/edge/enroll`            public (token in the body): an edge registers its key, endpoints
//!   and LAN subnets and receives its site id, overlay address and a credential
//! - `GET  /api/v1/edge/config`            edge credential (Bearer): peers, their keys/endpoints/subnets
//! - `POST /api/v1/edge/heartbeat`         edge credential (Bearer): path measurements per peer
//!
//! Every state change goes through [`crate::state::AppState::replicate`], so
//! all HA nodes agree on who is enrolled; tokens and credentials are only
//! stored as SHA-256 digests.

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use patronus_sdwan::{
    edge::{self, EdgeRecord},
    types::{Endpoint, PathMetrics, PathStatus, Site, SiteId, SiteStatus},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    error::{ApiError, Result},
    ha::replication::ReplicatedOp,
    state::AppState,
};

/// Seconds between agent polls the dashboard asks for.
pub const INTERVAL_SECS: u64 = 15;
/// An edge silent for this long is shown as inactive.
pub const STALE_SECS: i64 = 90;

/// Serialises enrollments so two edges never get the same overlay address.
static ENROLL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn replicate(state: &AppState, op: ReplicatedOp) -> Result<()> {
    state
        .replicate(op)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// The edge that owns the `Authorization: Bearer <credential>` header.
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<EdgeRecord> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing edge credential".into()))?;
    if !token.starts_with(edge::CREDENTIAL_PREFIX) {
        return Err(ApiError::Unauthorized("Not an edge credential".into()));
    }
    edge::edge_by_digest(state.db.pool(), &edge::digest(token))
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Unknown or revoked edge credential".into()))
}

#[derive(Deserialize)]
pub struct TokenRequest {
    #[serde(default)]
    pub label: Option<String>,
}

pub async fn create_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<Value>> {
    let label = req.label.unwrap_or_default();
    let label = label.trim();
    if label.len() > 64 || label.chars().any(|c| c.is_control()) {
        return Err(ApiError::InvalidRequest(
            "label: at most 64 characters, one line".into(),
        ));
    }
    let token = edge::new_secret(edge::TOKEN_PREFIX);
    replicate(
        &state,
        ReplicatedOp::EdgeToken {
            digest: edge::digest(&token),
            label: label.to_string(),
            created_at: now(),
        },
    )
    .await?;
    Ok(Json(json!({
        "token": token,
        "label": label,
        "note": "shown once; use it with `patronus edge enroll` (or the SD-WAN edge page) on the appliance"
    })))
}

#[derive(Deserialize)]
pub struct EndpointRequest {
    pub address: String,
    #[serde(default)]
    pub interface_type: Option<String>,
    #[serde(default)]
    pub cost_per_gb: Option<f64>,
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub name: String,
    /// WireGuard public key, base64
    pub public_key: String,
    pub endpoints: Vec<EndpointRequest>,
    #[serde(default)]
    pub subnets: Vec<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_kind(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 24
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<Value>> {
    let bad = |m: String| ApiError::InvalidRequest(m);
    let _guard = ENROLL_LOCK.lock().await;
    let token_digest = edge::digest(req.token.trim());
    if !req.token.starts_with(edge::TOKEN_PREFIX)
        || !edge::token_unused(state.db.pool(), &token_digest).await?
    {
        return Err(ApiError::Unauthorized(
            "Unknown, already used or malformed enrollment token".into(),
        ));
    }
    let name = req.name.trim().to_string();
    if !valid_name(&name) {
        return Err(bad("name: 1-63 characters from A-Z a-z 0-9 . _ -".into()));
    }
    let key = B64
        .decode(req.public_key.trim())
        .ok()
        .filter(|k| k.len() == 32)
        .ok_or_else(|| bad("public_key: a base64 WireGuard public key (32 bytes)".into()))?;
    if req.endpoints.is_empty() || req.endpoints.len() > 8 {
        return Err(bad("endpoints: 1 to 8 addresses (ip:port)".into()));
    }
    let mut endpoints = Vec::new();
    for e in &req.endpoints {
        let address: SocketAddr = e
            .address
            .trim()
            .parse()
            .map_err(|_| bad(format!("endpoint {:?}: expected ip:port", e.address)))?;
        let kind = e.interface_type.clone().unwrap_or_else(|| "wan".into());
        if !valid_kind(&kind) {
            return Err(bad(format!("endpoint {:?}: bad interface type", e.address)));
        }
        let cost = e.cost_per_gb.unwrap_or(0.0);
        if !(0.0..=1000.0).contains(&cost) {
            return Err(bad(format!("endpoint {:?}: cost_per_gb 0-1000", e.address)));
        }
        endpoints.push(Endpoint {
            address,
            interface_type: kind,
            cost_per_gb: cost,
            reachable: true,
        });
    }
    let existing = edge::list_edges(state.db.pool()).await?;
    let sites = state.db.list_sites().await?;
    if sites.iter().any(|s| s.public_key == key) {
        return Err(bad("public_key: already used by another site".into()));
    }
    if sites.iter().any(|s| s.name == name) {
        return Err(bad(format!("name {name:?} is already in use")));
    }
    let subnets = edge::check_subnets(&req.subnets, &existing, None).map_err(bad)?;
    let overlay = edge::allocate_overlay(&existing)
        .ok_or_else(|| ApiError::Internal("overlay address space exhausted".into()))?;
    let listen_port = req.listen_port.filter(|p| *p > 0).unwrap_or(51820);
    let credential = edge::new_secret(edge::CREDENTIAL_PREFIX);
    let at = now();
    let site_id = SiteId::generate();
    let site = Site {
        id: site_id,
        name: name.clone(),
        public_key: key,
        endpoints,
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        status: SiteStatus::Active,
    };
    let record = EdgeRecord {
        site_id: site_id.to_string(),
        token_digest: edge::digest(&credential),
        overlay_ip: overlay.to_string(),
        subnets: subnets.clone(),
        listen_port,
        enrolled_at: at,
        last_heartbeat: at,
    };
    replicate(
        &state,
        ReplicatedOp::EdgeEnroll {
            site,
            edge: record,
            used_token: token_digest,
            at,
        },
    )
    .await?;
    tracing::info!(site = %site_id, %name, %overlay, "edge enrolled");
    Ok(Json(json!({
        "site_id": site_id.to_string(),
        "credential": credential,
        "overlay_ip": overlay.to_string(),
        "overlay_cidr": edge::OVERLAY,
        "listen_port": listen_port,
        "subnets": subnets,
        "interval_secs": INTERVAL_SECS,
    })))
}

/// Endpoints cheapest first (then fibre-like before wireless, then address),
/// the order an agent tries them in.
pub fn endpoint_order(endpoints: &[Endpoint]) -> Vec<&Endpoint> {
    let mut v: Vec<&Endpoint> = endpoints.iter().collect();
    v.sort_by(|a, b| {
        a.cost_per_gb
            .partial_cmp(&b.cost_per_gb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.address.to_string().cmp(&b.address.to_string()))
    });
    v
}

pub async fn config(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<Value>> {
    let me = authenticate(&state, &headers).await?;
    let edges = edge::list_edges(state.db.pool()).await?;
    let mut peers = Vec::new();
    for e in edges.iter().filter(|e| e.site_id != me.site_id) {
        let Ok(id) = e.site_id.parse::<SiteId>() else {
            continue;
        };
        let Some(site) = state.db.get_site(&id).await? else {
            continue;
        };
        if site.status == SiteStatus::Inactive {
            continue;
        }
        let eps = state
            .db
            .get_endpoints(&id)
            .await
            .unwrap_or(site.endpoints.clone());
        peers.push(json!({
            "site_id": e.site_id,
            "name": site.name,
            "public_key": B64.encode(&site.public_key),
            "overlay_ip": e.overlay_ip,
            "subnets": e.subnets,
            "listen_port": e.listen_port,
            "endpoints": endpoint_order(&eps).iter().map(|x| json!({
                "address": x.address.to_string(),
                "interface_type": x.interface_type,
                "cost_per_gb": x.cost_per_gb,
            })).collect::<Vec<_>>(),
        }));
    }
    let generation = edge::digest(&serde_json::to_string(&peers).unwrap_or_default());
    Ok(Json(json!({
        "generation": generation,
        "site": {
            "site_id": me.site_id,
            "overlay_ip": me.overlay_ip,
            "subnets": me.subnets,
            "listen_port": me.listen_port,
        },
        "overlay_cidr": edge::OVERLAY,
        "interval_secs": INTERVAL_SECS,
        "peers": peers,
    })))
}

#[derive(Deserialize)]
pub struct PeerReport {
    pub site_id: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub loss_pct: Option<f64>,
    /// seconds since the last WireGuard handshake with the peer
    #[serde(default)]
    pub handshake_age_secs: Option<u64>,
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub peers: Vec<PeerReport>,
}

/// Path status implied by a measurement.
pub fn path_status(r: &PeerReport) -> PathStatus {
    let loss = r.loss_pct.unwrap_or(100.0);
    let age = r.handshake_age_secs;
    if age.is_none_or(|a| a > 180) || loss >= 50.0 {
        PathStatus::Down
    } else if loss > 5.0 || r.latency_ms.unwrap_or(0.0) > 300.0 {
        PathStatus::Degraded
    } else {
        PathStatus::Up
    }
}

fn score(r: &PeerReport) -> u8 {
    let s = 100.0 - r.latency_ms.unwrap_or(0.0) / 5.0 - r.loss_pct.unwrap_or(0.0) * 2.0;
    s.clamp(0.0, 100.0) as u8
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<Value>> {
    let me = authenticate(&state, &headers).await?;
    let my_id: SiteId = me
        .site_id
        .parse()
        .map_err(|_| ApiError::Internal("bad site id".into()))?;
    let my_site = state
        .db
        .get_site(&my_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("site".into()))?;
    let my_ep = my_site
        .endpoints
        .first()
        .map(|e| e.address)
        .ok_or_else(|| ApiError::Internal("site has no endpoint".into()))?;
    let edges = edge::list_edges(state.db.pool()).await?;
    let mut statuses = Vec::new();
    for r in req.peers.iter().take(256) {
        let Some(peer) = edges.iter().find(|e| e.site_id == r.site_id) else {
            continue;
        };
        let Ok(peer_id) = peer.site_id.parse::<SiteId>() else {
            continue;
        };
        let Some(dst) = r
            .endpoint
            .as_deref()
            .and_then(|e| e.parse::<SocketAddr>().ok())
        else {
            continue;
        };
        let status = path_status(r);
        statuses.push(status);
        let existing = state.db.list_paths().await?.into_iter().find(|p| {
            p.src_site == my_id
                && p.dst_site == peer_id
                && p.src_endpoint == my_ep
                && p.dst_endpoint == dst
        });
        let path_id = match existing {
            Some(p) => {
                state.db.update_path_status(p.id, status).await?;
                p.id
            }
            None => {
                state
                    .db
                    .insert_path(&patronus_sdwan::types::Path {
                        id: patronus_sdwan::types::PathId::new(0),
                        src_site: my_id,
                        dst_site: peer_id,
                        src_endpoint: my_ep,
                        dst_endpoint: dst,
                        wg_interface: Some("sdwan0".into()),
                        metrics: PathMetrics::default(),
                        status,
                    })
                    .await?
            }
        };
        state
            .db
            .record_metrics(
                path_id,
                &PathMetrics {
                    latency_ms: r.latency_ms.unwrap_or(0.0),
                    jitter_ms: 0.0,
                    packet_loss_pct: r.loss_pct.unwrap_or(0.0).clamp(0.0, 100.0),
                    bandwidth_mbps: 0.0,
                    mtu: 1420,
                    measured_at: SystemTime::now(),
                    score: score(r),
                },
            )
            .await?;
    }
    let site_status = if !statuses.is_empty() && statuses.iter().all(|s| *s == PathStatus::Down) {
        "degraded"
    } else {
        "active"
    };
    replicate(
        &state,
        ReplicatedOp::EdgeHeartbeat {
            site_id: me.site_id.clone(),
            at: now(),
            status: site_status.into(),
        },
    )
    .await?;
    Ok(Json(json!({"ok": true, "site_status": site_status})))
}

#[derive(Serialize)]
pub struct EdgeResponse {
    pub site_id: String,
    pub name: String,
    pub status: String,
    pub overlay_ip: String,
    pub subnets: Vec<String>,
    pub last_heartbeat: i64,
}

pub async fn list_edges(State(state): State<Arc<AppState>>) -> Result<Json<Vec<EdgeResponse>>> {
    let mut out = Vec::new();
    for e in edge::list_edges(state.db.pool()).await? {
        let site = match e.site_id.parse::<SiteId>() {
            Ok(id) => state.db.get_site(&id).await?,
            Err(_) => None,
        };
        out.push(EdgeResponse {
            name: site.as_ref().map(|s| s.name.clone()).unwrap_or_default(),
            status: site
                .map(|s| s.status.to_string())
                .unwrap_or_else(|| "unknown".into()),
            site_id: e.site_id,
            overlay_ip: e.overlay_ip,
            subnets: e.subnets,
            last_heartbeat: e.last_heartbeat,
        });
    }
    Ok(Json(out))
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    if edge::get_edge(state.db.pool(), &id).await?.is_none() {
        return Err(ApiError::NotFound(format!("Edge {id} not found")));
    }
    replicate(&state, ReplicatedOp::EdgeRevoke(id)).await?;
    Ok(Json(json!({"ok": true})))
}

/// Mark edges that stopped reporting as inactive (leader and followers
/// alike; `replicate` forwards to the leader).
pub fn spawn_staleness_task(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(STALE_SECS as u64 / 3));
        loop {
            t.tick().await;
            let Ok(edges) = edge::list_edges(state.db.pool()).await else {
                continue;
            };
            for e in edges {
                if now() - e.last_heartbeat <= STALE_SECS {
                    continue;
                }
                let Ok(id) = e.site_id.parse::<SiteId>() else {
                    continue;
                };
                if let Ok(Some(site)) = state.db.get_site(&id).await {
                    if site.status != SiteStatus::Inactive {
                        let _ = state
                            .replicate(ReplicatedOp::EdgeHeartbeat {
                                site_id: e.site_id.clone(),
                                at: e.last_heartbeat,
                                status: "inactive".into(),
                            })
                            .await;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(loss: Option<f64>, lat: Option<f64>, age: Option<u64>) -> PeerReport {
        PeerReport {
            site_id: "x".into(),
            endpoint: None,
            latency_ms: lat,
            loss_pct: loss,
            handshake_age_secs: age,
        }
    }

    #[test]
    fn measurements_map_to_path_status() {
        assert_eq!(
            path_status(&rep(Some(0.0), Some(20.0), Some(10))),
            PathStatus::Up
        );
        assert_eq!(
            path_status(&rep(Some(10.0), Some(20.0), Some(10))),
            PathStatus::Degraded
        );
        assert_eq!(
            path_status(&rep(Some(0.0), Some(400.0), Some(10))),
            PathStatus::Degraded
        );
        assert_eq!(
            path_status(&rep(Some(60.0), Some(20.0), Some(10))),
            PathStatus::Down
        );
        assert_eq!(
            path_status(&rep(Some(0.0), Some(20.0), Some(900))),
            PathStatus::Down
        );
        assert_eq!(
            path_status(&rep(Some(0.0), Some(20.0), None)),
            PathStatus::Down,
            "no handshake = down"
        );
        assert_eq!(score(&rep(Some(0.0), Some(50.0), Some(1))), 90);
        assert_eq!(score(&rep(Some(100.0), Some(5000.0), Some(1))), 0);
    }

    #[test]
    fn names_and_endpoints_are_ordered_by_cost() {
        assert!(
            valid_name("site-a.hq_1")
                && !valid_name("a b")
                && !valid_name("")
                && !valid_name("x;y")
        );
        let mk = |a: &str, c: f64| Endpoint {
            address: a.parse().unwrap(),
            interface_type: "wan".into(),
            cost_per_gb: c,
            reachable: true,
        };
        let eps = [
            mk("203.0.113.9:51820", 5.0),
            mk("198.51.100.4:51820", 0.0),
            mk("192.0.2.1:51820", 0.0),
        ];
        let o: Vec<String> = endpoint_order(&eps)
            .iter()
            .map(|e| e.address.to_string())
            .collect();
        assert_eq!(
            o,
            vec!["192.0.2.1:51820", "198.51.100.4:51820", "203.0.113.9:51820"]
        );
    }
}
