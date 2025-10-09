//! Network API endpoints

use axum::{
    extract::{Path, State},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub state: String,
    pub ip_address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub mac_address: String,
    pub mtu: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpPool {
    pub id: u32,
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: u32,
    pub gateway: String,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_start: String,
    pub lease_end: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: u32,
    pub hostname: String,
    pub ip_address: String,
    pub record_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
}

/// GET /api/network/interfaces
pub async fn list_interfaces(State(state): State<AppState>) -> Response {
    match state.network.list_interfaces().await {
        Ok(interfaces) => Json(interfaces).into_response(),
        Err(e) => {
            tracing::error!("Failed to list interfaces: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list interfaces"
            }))).into_response()
        }
    }
}

/// PUT /api/network/interfaces/:name
pub async fn update_interface(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(interface): Json<NetworkInterface>
) -> Response {
    match state.network.update_interface(name, interface).await {
        Ok(_) => Json(serde_json::json!({
            "message": "Interface updated successfully"
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to update interface: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to update interface: {}", e)
            }))).into_response()
        }
    }
}

/// POST /api/network/interfaces/:name/up
pub async fn interface_up(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.network.bring_interface_up(&name).await {
        Ok(_) => Json(serde_json::json!({
            "message": format!("Interface {} brought up successfully", name)
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to bring up interface {}: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to bring up interface: {}", e)
            }))).into_response()
        }
    }
}

/// POST /api/network/interfaces/:name/down
pub async fn interface_down(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.network.bring_interface_down(&name).await {
        Ok(_) => Json(serde_json::json!({
            "message": format!("Interface {} brought down successfully", name)
        })).into_response(),
        Err(e) => {
            tracing::error!("Failed to bring down interface {}: {}", name, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": format!("Failed to bring down interface: {}", e)
            }))).into_response()
        }
    }
}

/// GET /api/network/dhcp/pools
pub async fn list_dhcp_pools(State(state): State<AppState>) -> Response {
    match state.network.list_dhcp_pools().await {
        Ok(pools) => Json(pools).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DHCP pools: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list DHCP pools"
            }))).into_response()
        }
    }
}

/// GET /api/network/dhcp/leases
pub async fn list_dhcp_leases(State(state): State<AppState>) -> Response {
    match state.network.list_dhcp_leases().await {
        Ok(leases) => Json(leases).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DHCP leases: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list DHCP leases"
            }))).into_response()
        }
    }
}

/// GET /api/network/dns/records
pub async fn list_dns_records(State(state): State<AppState>) -> Response {
    match state.network.list_dns_records().await {
        Ok(records) => Json(records).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DNS records: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list DNS records"
            }))).into_response()
        }
    }
}

/// GET /api/network/routes
pub async fn list_routes(State(state): State<AppState>) -> Response {
    match state.network.list_routes().await {
        Ok(routes) => Json(routes).into_response(),
        Err(e) => {
            tracing::error!("Failed to list routes: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to list routes"
            }))).into_response()
        }
    }
}
