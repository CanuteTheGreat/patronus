//! VPN API endpoints. Reads are live (`wg show`, `swanctl --list-sas`);
//! tunnel management is lane F, so the write/config endpoints answer 501
//! with the reason instead of pretending to work.

use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// Request body of POST /api/vpn/wireguard/peers (accepted for API
/// compatibility; refused with 501 until lane F lands).
#[derive(Debug, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub id: Option<u32>,
    pub name: String,
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub enabled: bool,
}

/// What the write endpoints say until tunnels are managed here.
pub const NOT_MANAGED: &str = "WireGuard peers are not managed by Patronus yet: this page shows \
    the live kernel state (`wg show`). Configure peers with wireguard-tools (wg / wg-quick) \
    for now; nothing was changed.";

fn unavailable(msg: String) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn not_implemented() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({ "error": NOT_MANAGED })),
    )
        .into_response()
}

/// GET /api/vpn/wireguard/peers -- live peers of every WireGuard interface.
pub async fn list_wg_peers(State(state): State<AppState>) -> Response {
    match state.vpn.list_wireguard_peers().await {
        Ok(peers) => Json(peers).into_response(),
        Err(e) => unavailable(format!("cannot read WireGuard state: {e}")),
    }
}

/// POST /api/vpn/wireguard/peers -- 501 (used to add a fake "Pending" row).
pub async fn add_wg_peer(Json(_peer): Json<WireGuardPeer>) -> Response {
    not_implemented()
}

/// DELETE /api/vpn/wireguard/peers/:id -- 501.
pub async fn delete_wg_peer(Path(_id): Path<u32>) -> Response {
    not_implemented()
}

/// GET /api/vpn/wireguard/config/:id and the QR code variants -- 501:
/// a client config needs the client's private key, which only exists once
/// Patronus generates peers (lane F). These used to return configs with a
/// placeholder private key and a made-up server endpoint.
pub async fn get_wg_config(Path(_id): Path<u32>) -> Response {
    not_implemented()
}

/// GET /api/vpn/ipsec/tunnels -- live IKE SAs.
pub async fn list_ipsec_tunnels(State(state): State<AppState>) -> Response {
    match state.vpn.list_ipsec_tunnels().await {
        Ok(tunnels) => Json(tunnels).into_response(),
        Err(e) => unavailable(format!("cannot read IPsec state: {e}")),
    }
}

/// GET /api/vpn/openvpn/tunnels -- OpenVPN is neither managed nor
/// monitored: say so rather than return an empty list that reads as "none".
pub async fn list_ovpn_tunnels() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "OpenVPN is not managed or monitored by Patronus"
        })),
    )
        .into_response()
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(vpn::router())` line.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{delete, get};
    axum::Router::new()
        .route("/vpn/wireguard/peers", get(list_wg_peers).post(add_wg_peer))
        .route("/vpn/wireguard/peers/:id", delete(delete_wg_peer))
        .route("/vpn/wireguard/config/:id", get(get_wg_config))
        .route("/vpn/wireguard/qrcode/:id", get(get_wg_config))
        .route("/vpn/wireguard/qrcode/:id/png", get(get_wg_config))
        .route("/vpn/openvpn/tunnels", get(list_ovpn_tunnels))
        .route("/vpn/ipsec/tunnels", get(list_ipsec_tunnels))
}
