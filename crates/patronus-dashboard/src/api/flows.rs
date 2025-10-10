//! Flows API endpoints

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// List active flows
pub async fn list_flows(State(_state): State<Arc<AppState>>) -> Result<Json<Vec<FlowResponse>>> {
    // TODO: Implement flow tracking in routing engine
    // For now, return empty list
    Ok(Json(vec![]))
}

/// Flow response
#[derive(Debug, Serialize, Deserialize)]
pub struct FlowResponse {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub path_id: u64,
    pub policy_name: String,
    pub status: String,
}
