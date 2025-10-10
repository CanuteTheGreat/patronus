//! Paths API endpoints

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// List all paths
pub async fn list_paths(State(state): State<Arc<AppState>>) -> Result<Json<Vec<PathResponse>>> {
    let paths = state.db.list_paths().await?;

    let response: Vec<PathResponse> = paths.into_iter().map(|p| p.into()).collect();

    Ok(Json(response))
}

/// Get path by ID
pub async fn get_path(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Result<Json<PathResponse>> {
    let path_id = patronus_sdwan::types::PathId::new(id);

    let path = state
        .db
        .get_path(path_id)
        .await?;

    Ok(Json(path.into()))
}

/// Get path metrics history
pub async fn get_path_metrics(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Result<Json<PathMetricsResponse>> {
    let path_id = patronus_sdwan::types::PathId::new(id);

    let metrics = state.db.get_latest_metrics(path_id).await?;

    Ok(Json(PathMetricsResponse {
        path_id: id,
        metrics: metrics.into(),
    }))
}

/// Path response
#[derive(Debug, Serialize, Deserialize)]
pub struct PathResponse {
    pub id: u64,
    pub src_site: String,
    pub dst_site: String,
    pub src_endpoint: String,
    pub dst_endpoint: String,
    pub wg_interface: Option<String>,
    pub status: String,
    pub metrics: MetricsResponse,
}

impl From<patronus_sdwan::types::Path> for PathResponse {
    fn from(path: patronus_sdwan::types::Path) -> Self {
        Self {
            id: path.id.as_u64(),
            src_site: path.src_site.to_string(),
            dst_site: path.dst_site.to_string(),
            src_endpoint: path.src_endpoint.to_string(),
            dst_endpoint: path.dst_endpoint.to_string(),
            wg_interface: path.wg_interface,
            status: format!("{:?}", path.status),
            metrics: path.metrics.into(),
        }
    }
}

/// Metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f64,
    pub bandwidth_mbps: f64,
    pub mtu: u16,
    pub score: u8,
    pub measured_at: String,
}

impl From<patronus_sdwan::types::PathMetrics> for MetricsResponse {
    fn from(metrics: patronus_sdwan::types::PathMetrics) -> Self {
        Self {
            latency_ms: metrics.latency_ms,
            jitter_ms: metrics.jitter_ms,
            packet_loss_pct: metrics.packet_loss_pct,
            bandwidth_mbps: metrics.bandwidth_mbps,
            mtu: metrics.mtu,
            score: metrics.score,
            measured_at: chrono::DateTime::<chrono::Utc>::from(metrics.measured_at).to_rfc3339(),
        }
    }
}

/// Path metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct PathMetricsResponse {
    pub path_id: u64,
    pub metrics: MetricsResponse,
}
