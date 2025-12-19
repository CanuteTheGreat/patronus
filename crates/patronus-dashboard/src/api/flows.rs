//! Flows API endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// Flow response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowResponse {
    pub flow_id: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub protocol_num: u8,
    pub path_id: u64,
    pub policy_id: Option<u64>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub status: String,
    pub duration_secs: i64,
    pub throughput_bps: f64,
}

/// Flow statistics summary response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStatsResponse {
    pub total_flows: u64,
    pub active_flows: u64,
    pub total_bytes_tx: u64,
    pub total_bytes_rx: u64,
    pub total_packets_tx: u64,
    pub total_packets_rx: u64,
    pub throughput_mbps: f64,
}

/// Query parameters for listing flows
#[derive(Debug, Deserialize)]
pub struct FlowListQuery {
    /// Filter by status (active, idle, closed)
    pub status: Option<String>,
    /// Filter by path ID
    pub path_id: Option<u64>,
    /// Filter by policy ID
    pub policy_id: Option<u64>,
    /// Limit number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Convert protocol number to name
fn protocol_to_name(protocol: u8) -> String {
    match protocol {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        _ => format!("PROTO-{}", protocol),
    }
}

impl From<patronus_sdwan::FlowRecord> for FlowResponse {
    fn from(flow: patronus_sdwan::FlowRecord) -> Self {
        let started_at = DateTime::from_timestamp(
            flow.started_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            0,
        )
        .unwrap_or_else(|| Utc::now());

        let last_seen_at = DateTime::from_timestamp(
            flow.last_seen_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            0,
        )
        .unwrap_or_else(|| Utc::now());

        let duration_secs = (last_seen_at - started_at).num_seconds().max(1);
        let total_bytes = flow.bytes_tx + flow.bytes_rx;
        let throughput_bps = if duration_secs > 0 {
            (total_bytes as f64 * 8.0) / duration_secs as f64
        } else {
            0.0
        };

        Self {
            flow_id: flow.flow_id,
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: protocol_to_name(flow.protocol),
            protocol_num: flow.protocol,
            path_id: flow.path_id,
            policy_id: flow.policy_id,
            started_at,
            last_seen_at,
            bytes_tx: flow.bytes_tx,
            bytes_rx: flow.bytes_rx,
            packets_tx: flow.packets_tx,
            packets_rx: flow.packets_rx,
            status: flow.status,
            duration_secs,
            throughput_bps,
        }
    }
}

/// List active flows
/// GET /api/flows
pub async fn list_flows(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FlowListQuery>,
) -> Result<Json<Vec<FlowResponse>>> {
    let flows = if let Some(path_id) = params.path_id {
        // Filter by path
        state
            .db
            .list_flows_by_path(path_id)
            .await
            .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?
    } else {
        // Get all active flows
        state
            .db
            .list_active_flows()
            .await
            .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?
    };

    // Apply additional filters
    let mut filtered: Vec<FlowResponse> = flows
        .into_iter()
        .filter(|f| {
            if let Some(ref status) = params.status {
                if &f.status != status {
                    return false;
                }
            }
            if let Some(policy_id) = params.policy_id {
                if f.policy_id != Some(policy_id) {
                    return false;
                }
            }
            true
        })
        .map(FlowResponse::from)
        .collect();

    // Apply pagination
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);

    if offset > 0 {
        filtered = filtered.into_iter().skip(offset).collect();
    }
    filtered.truncate(limit);

    Ok(Json(filtered))
}

/// Get flow statistics
/// GET /api/flows/stats
pub async fn get_flow_stats(State(state): State<Arc<AppState>>) -> Result<Json<FlowStatsResponse>> {
    let stats = state
        .db
        .get_flow_stats()
        .await
        .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?;

    // Calculate throughput (rough estimate based on recent data)
    let throughput_mbps = (stats.total_bytes_tx + stats.total_bytes_rx) as f64 * 8.0 / 1_000_000.0;

    Ok(Json(FlowStatsResponse {
        total_flows: stats.total_flows,
        active_flows: stats.active_flows,
        total_bytes_tx: stats.total_bytes_tx,
        total_bytes_rx: stats.total_bytes_rx,
        total_packets_tx: stats.total_packets_tx,
        total_packets_rx: stats.total_packets_rx,
        throughput_mbps,
    }))
}

/// Get flow by path ID
/// GET /api/flows/path/:path_id
pub async fn list_flows_by_path(
    State(state): State<Arc<AppState>>,
    Path(path_id): Path<u64>,
) -> Result<Json<Vec<FlowResponse>>> {
    let flows = state
        .db
        .list_flows_by_path(path_id)
        .await
        .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?;

    let responses: Vec<FlowResponse> = flows.into_iter().map(FlowResponse::from).collect();

    Ok(Json(responses))
}

/// Cleanup stale flows
/// POST /api/flows/cleanup
pub async fn cleanup_flows(State(state): State<Arc<AppState>>) -> Result<Json<CleanupResponse>> {
    // Mark flows idle for 5 minutes as closed, delete flows older than 7 days
    let deleted = state
        .db
        .cleanup_stale_flows(300) // 5 minutes
        .await
        .map_err(|e| crate::error::ApiError::Internal(e.to_string()))?;

    Ok(Json(CleanupResponse {
        flows_deleted: deleted,
    }))
}

#[derive(Debug, Serialize)]
pub struct CleanupResponse {
    pub flows_deleted: u64,
}
