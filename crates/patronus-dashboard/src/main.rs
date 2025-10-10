//! Patronus SD-WAN Enterprise Dashboard
//!
//! Centralized management and monitoring interface for multi-site SD-WAN deployments.

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod api;
mod error;
mod state;
mod ws;

use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("patronus_dashboard=info,tower_http=debug")),
        )
        .init();

    info!("Starting Patronus SD-WAN Dashboard");

    // Initialize application state
    let state = AppState::new("dashboard.db").await?;
    let state = Arc::new(state);

    info!("Application state initialized");

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // API v1 routes
        .nest("/api/v1", api_routes())
        // WebSocket routes
        .route("/ws/metrics", get(ws::metrics_handler))
        .route("/ws/events", get(ws::events_handler))
        // Static file serving
        .nest_service("/", ServeDir::new("static"))
        // Add middleware
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().level(Level::INFO)),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("Dashboard server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// API v1 routes
fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Sites
        .route("/sites", get(api::sites::list_sites))
        .route("/sites/:id", get(api::sites::get_site))
        // Paths
        .route("/paths", get(api::paths::list_paths))
        .route("/paths/:id", get(api::paths::get_path))
        .route("/paths/:id/metrics", get(api::paths::get_path_metrics))
        // Flows
        .route("/flows", get(api::flows::list_flows))
        // Policies
        .route("/policies", get(api::policies::list_policies))
        .route("/policies", post(api::policies::create_policy))
        .route("/policies/:id", get(api::policies::get_policy))
        // Metrics
        .route("/metrics/summary", get(api::metrics::get_summary))
        .route("/metrics/timeseries", get(api::metrics::get_timeseries))
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}
