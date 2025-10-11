//! Application state

use patronus_sdwan::{database::Database, netpolicy::PolicyEnforcer, metrics::MetricsCollector, traffic_stats::TrafficStatsCollector};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::auth::users::UserRepository;
use crate::cache::{MetricsCache, RoutingCache};
use crate::security::audit::AuditLogger;
use crate::security::token_revocation::TokenRevocation;

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub bind_address: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub static_dir: String,
}

/// Shared application state
pub struct AppState {
    /// SD-WAN database
    pub db: Arc<Database>,

    /// NetworkPolicy enforcer
    pub policy_enforcer: Arc<PolicyEnforcer>,

    /// Metrics collector
    pub metrics_collector: Arc<MetricsCollector>,

    /// User repository for authentication
    pub user_repository: Arc<UserRepository>,

    /// Audit logger for tracking all operations (Sprint 25)
    pub audit_logger: Arc<AuditLogger>,

    /// Token revocation manager (Sprint 29)
    pub token_revocation: Arc<TokenRevocation>,

    /// Traffic statistics collector (Sprint 30)
    pub traffic_stats: Arc<TrafficStatsCollector>,

    /// Metrics cache (Sprint 30)
    pub metrics_cache: Arc<MetricsCache>,

    /// Routing cache (Sprint 30)
    pub routing_cache: Arc<RoutingCache>,

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

        // Create policy enforcer
        let policy_enforcer = Arc::new(PolicyEnforcer::new(db.clone()));
        policy_enforcer.start().await?;

        // Create metrics collector
        let metrics_collector = Arc::new(MetricsCollector::new(db.clone()));
        metrics_collector.start().await?;

        // Create user repository with separate database connection
        let pool = SqlitePool::connect(&format!("sqlite:{}?mode=rwc", db_path)).await?;
        let user_repository = Arc::new(UserRepository::new(pool.clone()));
        user_repository.init().await?;

        // Create audit logger (Sprint 25)
        let audit_logger = Arc::new(AuditLogger::new(pool.clone()));
        audit_logger.init().await?;

        // Create token revocation manager (Sprint 29)
        let token_revocation = Arc::new(TokenRevocation::new(pool));
        token_revocation.init().await?;

        // Create traffic statistics collector (Sprint 30)
        let traffic_stats = Arc::new(TrafficStatsCollector::new(Some(db.clone())));

        // Create caches (Sprint 30)
        let metrics_cache = Arc::new(MetricsCache::new(Duration::from_secs(60))); // 1 minute TTL
        let routing_cache = Arc::new(RoutingCache::new(Duration::from_secs(30))); // 30 second TTL

        // Create broadcast channels for WebSocket
        let (metrics_tx, _) = tokio::sync::broadcast::channel(100);
        let (events_tx, _) = tokio::sync::broadcast::channel(100);

        Ok(Self {
            db,
            policy_enforcer,
            metrics_collector,
            user_repository,
            audit_logger,
            token_revocation,
            traffic_stats,
            metrics_cache,
            routing_cache,
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
