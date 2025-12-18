//! Patronus Web Interface binary
//!
//! This is the main entry point for the web-based management interface.

use anyhow::Result;
use patronus_web::AppState;
use std::net::SocketAddr;
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

    // Create minimal application state with stub services
    let rule_manager = patronus_firewall::rules::RuleManager::new();
    let config_store = patronus_config::store::ConfigStore::new(std::path::PathBuf::from("/tmp/patronus-config"));
    let state = AppState::new(rule_manager, config_store);

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    info!("Web interface listening on http://{}", addr);

    // Start server using the library's serve function
    if let Err(e) = patronus_web::serve(addr, state).await {
        error!("Server error: {}", e);
        return Err(e);
    }

    info!("Server shutdown gracefully");
    Ok(())
}
