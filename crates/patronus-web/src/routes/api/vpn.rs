//! VPN API endpoints

use axum::{
    extract::{Path, State},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenVpnTunnel {
    pub id: u32,
    pub name: String,
    pub status: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub connected_clients: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpsecTunnel {
    pub id: u32,
    pub name: String,
    pub status: String,
    pub local_subnet: String,
    pub remote_subnet: String,
    pub remote_gateway: String,
}

/// GET /api/vpn/wireguard/peers
pub async fn list_wg_peers(State(state): State<AppState>) -> Response {
    match state.vpn.list_wireguard_peers().await {
        Ok(peers) => Json(peers).into_response(),
        Err(e) => {
            tracing::error!("Failed to list WireGuard peers: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list WireGuard peers"
            }))).into_response()
        }
    }
}

/// POST /api/vpn/wireguard/peers
pub async fn add_wg_peer(State(state): State<AppState>, Json(peer): Json<WireGuardPeer>) -> Response {
    match state.vpn.add_wireguard_peer(peer).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": id,
            "message": "WireGuard peer added successfully"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to add WireGuard peer: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to add peer: {}", e)
            }))).into_response()
        }
    }
}

/// DELETE /api/vpn/wireguard/peers/:id
pub async fn delete_wg_peer(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.vpn.delete_wireguard_peer(id).await {
        Ok(_) => Json(serde_json::json!({
            "message": "WireGuard peer deleted successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete WireGuard peer {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to delete peer: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/vpn/wireguard/config/:id
pub async fn get_wg_config(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.vpn.get_wireguard_config(id).await {
        Ok(config) => Json(serde_json::json!({
            "config": config
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to get WireGuard config for peer {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to get config: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/vpn/wireguard/qrcode/:id - Get QR code as SVG
pub async fn get_wg_qrcode_svg(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.vpn.get_wireguard_qrcode_svg(id).await {
        Ok(svg) => (
            [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
            svg
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to generate QR code for peer {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to generate QR code: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/vpn/wireguard/qrcode/:id/png - Get QR code as PNG
pub async fn get_wg_qrcode_png(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.vpn.get_wireguard_qrcode_png(id).await {
        Ok(png_bytes) => (
            [(axum::http::header::CONTENT_TYPE, "image/png")],
            png_bytes
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to generate QR code PNG for peer {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to generate QR code: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/vpn/openvpn/tunnels
pub async fn list_ovpn_tunnels(State(state): State<AppState>) -> Response {
    match state.vpn.list_openvpn_tunnels().await {
        Ok(tunnels) => Json(tunnels).into_response(),
        Err(e) => {
            tracing::error!("Failed to list OpenVPN tunnels: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list OpenVPN tunnels"
            }))).into_response()
        }
    }
}

/// GET /api/vpn/ipsec/tunnels
pub async fn list_ipsec_tunnels(State(state): State<AppState>) -> Response {
    match state.vpn.list_ipsec_tunnels().await {
        Ok(tunnels) => Json(tunnels).into_response(),
        Err(e) => {
            tracing::error!("Failed to list IPsec tunnels: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list IPsec tunnels"
            }))).into_response()
        }
    }
}
