//! Network API endpoints

use crate::state::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

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

/// GET /api/network/dhcp/pools
pub async fn list_dhcp_pools(State(state): State<AppState>) -> Response {
    match state.network.list_dhcp_pools().await {
        Ok(pools) => Json(pools).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DHCP pools: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list DHCP pools"
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/network/dhcp/leases
pub async fn list_dhcp_leases(State(state): State<AppState>) -> Response {
    match state.network.list_dhcp_leases().await {
        Ok(leases) => Json(leases).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DHCP leases: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list DHCP leases"
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/network/dns/records
pub async fn list_dns_records(State(state): State<AppState>) -> Response {
    match state.network.list_dns_records().await {
        Ok(records) => Json(records).into_response(),
        Err(e) => {
            tracing::error!("Failed to list DNS records: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list DNS records"
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/network/routes
pub async fn list_routes(State(state): State<AppState>) -> Response {
    match state.network.list_routes().await {
        Ok(routes) => Json(routes).into_response(),
        Err(e) => {
            tracing::error!("Failed to list routes: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list routes"
                })),
            )
                .into_response()
        }
    }
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(network::router())` line.
pub fn router() -> axum::Router<AppState> {
    // /network/interfaces* moved to routes/api/interfaces.rs (lane C)
    use axum::routing::get;
    axum::Router::new()
        .route("/network/dhcp/pools", get(list_dhcp_pools))
        .route("/network/dhcp/leases", get(list_dhcp_leases))
        .route("/network/dns/records", get(list_dns_records))
        .route("/network/routes", get(list_routes))
}
