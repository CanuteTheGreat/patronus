//! System status API endpoints

use axum::{
    extract::State,
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatus {
    pub uptime: u64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub active_rules: usize,
    pub vpn_connections: usize,
    pub interfaces: Vec<InterfaceStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// GET /api/status
pub async fn system_status(State(state): State<AppState>) -> Response {
    let system_info = match state.system.get_info().await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to fetch system info: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to fetch system info"
            }))).into_response();
        }
    };

    let active_rules = state.firewall.count_active_rules().await.unwrap_or(0);
    let vpn_connections = state.vpn.count_active_connections().await.unwrap_or(0);

    let interfaces = match state.network.list_interfaces().await {
        Ok(ifaces) => ifaces.into_iter().map(|iface| InterfaceStatus {
            name: iface.name,
            state: iface.state,
            rx_bytes: iface.rx_bytes,
            tx_bytes: iface.tx_bytes,
        }).collect(),
        Err(e) => {
            tracing::error!("Failed to fetch interfaces: {}", e);
            vec![]
        }
    };

    let status = SystemStatus {
        uptime: system_info.uptime,
        cpu_usage: system_info.cpu_usage,
        memory_usage: system_info.memory_usage,
        disk_usage: system_info.disk_usage,
        active_rules,
        vpn_connections,
        interfaces,
    };

    Json(status).into_response()
}
