use anyhow::Result;
use axum::{
    Router,
    routing::get,
};
use patronus_web::{AppState, handlers};
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "patronus_web=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Patronus Web Interface v{}", env!("CARGO_PKG_VERSION"));

    // Create application state
    let state = AppState::new().await?;

    // Build application routes
    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/api/status", get(handlers::api_status))
        .route("/api/firewall/rules", get(handlers::firewall_rules))
        .route("/api/interfaces", get(handlers::interfaces))
        .route("/api/vpn/status", get(handlers::vpn_status))
        .route("/api/monitoring/stats", get(handlers::monitoring_stats))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(state);

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("Web interface listening on https://{}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;

    match axum::serve(listener, app).await {
        Ok(_) => info!("Server shutdown gracefully"),
        Err(e) => error!("Server error: {}", e),
    }

    Ok(())
}
