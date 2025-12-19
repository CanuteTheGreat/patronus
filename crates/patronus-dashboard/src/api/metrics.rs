//! Metrics API endpoints

use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;

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

    // Get flow stats
    let flow_stats = state
        .db
        .get_flow_stats()
        .await
        .unwrap_or_default();

    Ok(Json(SummaryResponse {
        total_sites,
        active_sites,
        total_paths,
        up_paths,
        degraded_paths,
        avg_latency_ms: avg_latency,
        active_flows: flow_stats.active_flows as usize,
        total_throughput_mbps: (flow_stats.total_bytes_tx + flow_stats.total_bytes_rx) as f64
            * 8.0
            / 1_000_000.0,
    }))
}

/// Query parameters for time-series metrics
#[derive(Debug, Deserialize)]
pub struct TimeSeriesQuery {
    /// Type of metric: throughput, latency, packet_loss, flows, cpu, memory
    pub metric_type: String,
    /// Start timestamp (Unix timestamp in seconds)
    pub from: Option<i64>,
    /// End timestamp (Unix timestamp in seconds)
    pub to: Option<i64>,
    /// Interval for aggregation: 1m, 5m, 15m, 1h, 1d
    pub interval: Option<String>,
    /// Optional path ID filter
    pub path_id: Option<u64>,
}

/// Get time-series metrics
pub async fn get_timeseries(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TimeSeriesQuery>,
) -> Result<Json<TimeSeriesResponse>> {
    // Parse time range
    let now = Utc::now();
    let to = params
        .to
        .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(now))
        .unwrap_or(now);

    let from = params
        .from
        .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(now - Duration::hours(1)))
        .unwrap_or(now - Duration::hours(1));

    // Convert to SystemTime
    let from_st = SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs(from.timestamp() as u64);
    let to_st =
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(to.timestamp() as u64);

    // Fetch data based on metric type
    let data_points = match params.metric_type.as_str() {
        "throughput" => get_throughput_timeseries(&state, from_st, to_st).await?,
        "latency" => get_latency_timeseries(&state, from_st, to_st, params.path_id).await?,
        "packet_loss" => get_packet_loss_timeseries(&state, from_st, to_st, params.path_id).await?,
        "flows" => get_flow_count_timeseries(&state, from_st, to_st).await?,
        "cpu" => get_cpu_timeseries(&state, from_st, to_st).await?,
        "memory" => get_memory_timeseries(&state, from_st, to_st).await?,
        _ => vec![],
    };

    // Apply aggregation interval if specified
    let aggregated = if let Some(ref interval) = params.interval {
        aggregate_datapoints(data_points, interval)
    } else {
        data_points
    };

    Ok(Json(TimeSeriesResponse {
        metric_type: params.metric_type,
        from: from.to_rfc3339(),
        to: to.to_rfc3339(),
        interval: params.interval,
        data_points: aggregated,
    }))
}

async fn get_throughput_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.throughput_mbps,
                label: None,
            }
        })
        .collect())
}

async fn get_latency_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
    _path_id: Option<u64>,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.avg_latency_ms,
                label: None,
            }
        })
        .collect())
}

async fn get_packet_loss_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
    _path_id: Option<u64>,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.avg_packet_loss,
                label: None,
            }
        })
        .collect())
}

async fn get_flow_count_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.active_flows as f64,
                label: None,
            }
        })
        .collect())
}

async fn get_cpu_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.cpu_usage,
                label: None,
            }
        })
        .collect())
}

async fn get_memory_timeseries(
    state: &AppState,
    from: SystemTime,
    to: SystemTime,
) -> Result<Vec<DataPoint>> {
    let metrics = state.db.get_system_metrics_history(from, to).await?;

    Ok(metrics
        .into_iter()
        .map(|m| {
            let ts = m
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: m.memory_usage,
                label: None,
            }
        })
        .collect())
}

/// Aggregate data points by interval
fn aggregate_datapoints(data_points: Vec<DataPoint>, interval: &str) -> Vec<DataPoint> {
    if data_points.is_empty() {
        return data_points;
    }

    let interval_secs = match interval {
        "1m" => 60,
        "5m" => 300,
        "15m" => 900,
        "1h" => 3600,
        "1d" => 86400,
        _ => return data_points,
    };

    // Group by interval bucket
    let mut buckets: std::collections::BTreeMap<i64, Vec<f64>> = std::collections::BTreeMap::new();

    for dp in data_points {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&dp.timestamp) {
            let bucket = (dt.timestamp() / interval_secs) * interval_secs;
            buckets.entry(bucket).or_default().push(dp.value);
        }
    }

    // Compute averages
    buckets
        .into_iter()
        .map(|(ts, values)| {
            let avg = values.iter().sum::<f64>() / values.len() as f64;
            DataPoint {
                timestamp: DateTime::from_timestamp(ts, 0)
                    .unwrap_or_else(|| Utc::now())
                    .to_rfc3339(),
                value: avg,
                label: None,
            }
        })
        .collect()
}

/// Export metrics in specified format
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: Option<String>, // csv, json
    pub from: Option<i64>,
    pub to: Option<i64>,
}

pub async fn export_metrics(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ExportQuery>,
) -> Result<Json<ExportResponse>> {
    let now = Utc::now();
    let to = params
        .to
        .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(now))
        .unwrap_or(now);
    let from = params
        .from
        .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(now - Duration::hours(24)))
        .unwrap_or(now - Duration::hours(24));

    let from_st = SystemTime::UNIX_EPOCH
        + std::time::Duration::from_secs(from.timestamp() as u64);
    let to_st =
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(to.timestamp() as u64);

    let metrics = state.db.get_system_metrics_history(from_st, to_st).await?;

    let format = params.format.unwrap_or_else(|| "json".to_string());

    let data = match format.as_str() {
        "csv" => {
            let mut csv = String::from("timestamp,throughput_mbps,latency_ms,packet_loss,active_flows,cpu,memory\n");
            for m in &metrics {
                let ts = m
                    .timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                csv.push_str(&format!(
                    "{},{:.2},{:.2},{:.4},{},{:.2},{:.2}\n",
                    ts,
                    m.throughput_mbps,
                    m.avg_latency_ms,
                    m.avg_packet_loss,
                    m.active_flows,
                    m.cpu_usage,
                    m.memory_usage
                ));
            }
            csv
        }
        _ => serde_json::to_string(&metrics).unwrap_or_else(|_| "[]".to_string()),
    };

    Ok(Json(ExportResponse {
        format,
        from: from.to_rfc3339(),
        to: to.to_rfc3339(),
        record_count: metrics.len(),
        data,
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
    pub active_flows: usize,
    pub total_throughput_mbps: f64,
}

/// Time-series response
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeSeriesResponse {
    pub metric_type: String,
    pub from: String,
    pub to: String,
    pub interval: Option<String>,
    pub data_points: Vec<DataPoint>,
}

/// Data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: String,
    pub value: f64,
    pub label: Option<String>,
}

/// Export response
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportResponse {
    pub format: String,
    pub from: String,
    pub to: String,
    pub record_count: usize,
    pub data: String,
}
