//! Patronus Web Interface binary
//!
//! This is the main entry point for the web-based management interface.

use anyhow::Result;
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

    // Open the persistent config store ($PATRONUS_DB or
    // /var/lib/patronus/config.db), seed first-boot defaults if the boot
    // unit hasn't, and load the stored firewall into nftables. (This used
    // to keep every rule in memory, with the store pointed at /tmp and
    // never used, so all rules vanished on restart.)
    let state = patronus_web::state::startup(None).await?;

    // Per-install admin password: PATRONUS_ADMIN_PASSWORD, or generated on
    // first start into /var/lib/patronus/initial-admin-password (0600).
    // Refuses to start with a known/weak password; there are no default
    // credentials.
    match state.auth.user_store.provision_admin_from_env().await? {
        patronus_web::auth::AdminPasswordSource::Env => {
            info!("admin password taken from PATRONUS_ADMIN_PASSWORD")
        }
        patronus_web::auth::AdminPasswordSource::ExistingFile(p) => {
            info!("admin password loaded from {}", p.display())
        }
        patronus_web::auth::AdminPasswordSource::GeneratedFile(p) => info!(
            "generated a per-install admin password; log in as 'admin' with the contents of {}",
            p.display()
        ),
    }

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
