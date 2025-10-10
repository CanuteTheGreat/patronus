//! Application state

use patronus_sdwan::database::Database;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state
pub struct AppState {
    /// SD-WAN database
    pub db: Arc<Database>,

    /// WebSocket broadcast channels
    pub metrics_tx: tokio::sync::broadcast::Sender<MetricsUpdate>,
    pub events_tx: tokio::sync::broadcast::Sender<Event>,

    /// Active WebSocket connections counter
    pub ws_connections: Arc<RwLock<u64>>,
}

impl AppState {
    /// Create new application state
    pub async fn new(db_path: &str) -> anyhow::Result<Self> {
        let db = Arc::new(Database::new(db_path).await?);

        // Create broadcast channels for WebSocket
        let (metrics_tx, _) = tokio::sync::broadcast::channel(100);
        let (events_tx, _) = tokio::sync::broadcast::channel(100);

        Ok(Self {
            db,
            metrics_tx,
            events_tx,
            ws_connections: Arc::new(RwLock::new(0)),
        })
    }
}

/// Metrics update message
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsUpdate {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub path_id: String,
    pub metrics: MetricsData,
}

/// Metrics data
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsData {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f64,
    pub bandwidth_mbps: f64,
    pub score: u8,
}

/// Event message
#[derive(Debug, Clone, serde::Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: serde_json::Value,
}
