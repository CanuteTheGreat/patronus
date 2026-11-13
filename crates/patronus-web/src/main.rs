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
    let mut state = patronus_web::state::startup(None).await?;
    if state.auth.syslogin.seed_from_env()? {
        info!("web login: account seeded from PATRONUS_ADMIN_PASSWORD (headless/CI)");
    }

    // No built-in account: the web UI signs in system users (PAM, or the
    // shadow files on the embedded tier) by group, see patronus_web::syslogin.
    info!(
        "web login: system users in {:?} (admin); no built-in admin account",
        state.auth.syslogin.cfg.admin_groups
    );

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
