//! Patronus Web Interface binary
//!
//! This is the main entry point for the web-based management interface.

use anyhow::Result;
use patronus_web::AppState;
use std::net::SocketAddr;
use tracing::{error, info};
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

    info!(
        "Starting Patronus Web Interface v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Create minimal application state with stub services
    let rule_manager = patronus_firewall::rules::RuleManager::new();
    rule_manager
        .initialize()
        .await
        .map_err(|e| anyhow::anyhow!("failed to initialize nftables table/chains: {e}"))?;
    let config_store =
        patronus_config::store::ConfigStore::new(std::path::PathBuf::from("/tmp/patronus-config"));
    let state = AppState::new(rule_manager, config_store).await?;

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let tls_dir = patronus_web::tls::default_tls_dir();
    info!(
        "Web interface listening on https://{} (self-signed TLS, cert dir: {})",
        addr,
        tls_dir.display()
    );

    // Start server using the library's TLS serve function. The dashboard is
    // documented and configured as HTTPS on 8443, so it serves HTTPS by
    // default (self-signed cert, auto-generated on first run).
    if let Err(e) = patronus_web::serve_tls(addr, state, &tls_dir).await {
        error!("Server error: {}", e);
        return Err(e);
    }

    info!("Server shutdown gracefully");
    Ok(())
}
