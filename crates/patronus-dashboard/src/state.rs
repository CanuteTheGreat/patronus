//! Application state

use patronus_sdwan::{
    database::Database,
    failover::FailoverEngine,
    health::{HealthConfig, HealthMonitor},
    metrics::MetricsCollector,
    netpolicy::PolicyEnforcer,
    routing::RoutingEngine,
    traffic_stats::TrafficStatsCollector,
};
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

    /// SD-WAN routing engine for intelligent path selection
    pub routing_engine: Arc<RoutingEngine>,

    /// Health monitor for path health checking
    pub health_monitor: Arc<HealthMonitor>,

    /// Failover engine for automatic path failover
    pub failover_engine: Arc<FailoverEngine>,

    /// HA leader-election manager (Some when PATRONUS_NODE_ID/PEERS are
    /// configured; None for a plain single-node run).
    pub ha: Option<Arc<crate::ha::election::LeaderElection>>,

    /// Applies replicated operations to this node's stores.
    pub state_machine: Arc<crate::ha::replication::StateMachine>,

    /// Sled-backed distributed state store, shared cluster metadata (Some
    /// alongside `ha`, same enable condition).
    pub distributed_state: Option<Arc<crate::ha::state::DistributedState>>,
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

        let state_machine = Arc::new(crate::ha::replication::StateMachine {
            db: db.clone(),
            policy_enforcer: policy_enforcer.clone(),
            users: user_repository.clone(),
            revocation: token_revocation.clone(),
        });

        // Create traffic statistics collector (Sprint 30)
        let traffic_stats = Arc::new(TrafficStatsCollector::new(Some(db.clone())));

        // Create caches (Sprint 30)
        let metrics_cache = Arc::new(MetricsCache::new(Duration::from_secs(60))); // 1 minute TTL
        let routing_cache = Arc::new(RoutingCache::new(Duration::from_secs(30))); // 30 second TTL

        // Create broadcast channels for WebSocket
        let (metrics_tx, _) = tokio::sync::broadcast::channel(100);
        let (events_tx, _) = tokio::sync::broadcast::channel(100);

        // Create SD-WAN routing engine with NetworkPolicy integration
        let routing_engine = Arc::new(RoutingEngine::with_netpolicy_enforcement(
            db.clone(),
            policy_enforcer.clone(),
        ));
        routing_engine.start().await?;

        // Create health monitor
        let health_config = HealthConfig::default();
        let health_monitor = Arc::new(
            HealthMonitor::new(db.clone(), health_config)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create health monitor: {}", e))?,
        );

        // Create failover engine with health monitoring integration
        let failover_engine = Arc::new(FailoverEngine::new(db.clone(), health_monitor.clone()));

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
            routing_engine,
            health_monitor,
            failover_engine,
            ha: None,
            state_machine,
            distributed_state: None,
        })
    }

    /// Perform a state-changing operation. Standalone: applied locally. HA:
    /// committed through the replicated log on a majority of nodes (forwarded
    /// to the leader when this node is a follower) before returning, so every
    /// node -- including whichever node becomes leader next -- has it.
    pub async fn replicate(&self, op: crate::ha::replication::ReplicatedOp) -> anyhow::Result<()> {
        match &self.ha {
            Some(ha) if ha.has_replication() => {
                ha.submit(op).await.map_err(|e| anyhow::anyhow!(e))?;
                Ok(())
            }
            _ => self.state_machine.apply(&op).await,
        }
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
