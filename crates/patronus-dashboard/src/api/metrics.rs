//! Metrics API endpoints

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{error::Result, state::AppState};

/// Get dashboard summary
pub async fn get_summary(State(state): State<Arc<AppState>>) -> Result<Json<SummaryResponse>> {
    let sites = state.db.list_sites().await?;
    let paths = state.db.list_paths().await?;

    let total_sites = sites.len();
    let active_sites = sites
        .iter()
        .filter(|s| matches!(s.status, patronus_sdwan::types::SiteStatus::Active))
        .count();

    let total_paths = paths.len();
    let up_paths = paths
        .iter()
        .filter(|p| matches!(p.status, patronus_sdwan::types::PathStatus::Up))
        .count();
    let degraded_paths = paths
        .iter()
        .filter(|p| matches!(p.status, patronus_sdwan::types::PathStatus::Degraded))
        .count();

    // Calculate average latency
    let avg_latency = if !paths.is_empty() {
        paths.iter().map(|p| p.metrics.latency_ms).sum::<f64>() / paths.len() as f64
    } else {
        0.0
    };

    Ok(Json(SummaryResponse {
        total_sites,
        active_sites,
        total_paths,
        up_paths,
        degraded_paths,
        avg_latency_ms: avg_latency,
    }))
}

/// Get time-series metrics
pub async fn get_timeseries(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<TimeSeriesResponse>> {
    // TODO: Implement time-series data retrieval
    // For now, return empty data
    Ok(Json(TimeSeriesResponse {
        data_points: vec![],
    }))
}

/// Summary response
#[derive(Debug, Serialize, Deserialize)]
pub struct SummaryResponse {
    pub total_sites: usize,
    pub active_sites: usize,
    pub total_paths: usize,
    pub up_paths: usize,
    pub degraded_paths: usize,
    pub avg_latency_ms: f64,
}

/// Time-series response
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeSeriesResponse {
    pub data_points: Vec<DataPoint>,
}

/// Data point
#[derive(Debug, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: String,
    pub value: f64,
}
