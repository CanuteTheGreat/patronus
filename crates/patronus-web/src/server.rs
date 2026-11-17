//! The web UI server's entry point, shared by the `patronus-web` binary and,
//! on the embedded tier, the multi-call `patronus-cli` (invoked as
//! `patronus-web` through a link: one binary carries std, tokio, SQLite and the
//! appliers once instead of twice, see docs/embedded-routers.md).

use anyhow::Result;
use std::net::SocketAddr;
use tracing::{error, info};

/// The web UI's log setup (`RUST_LOG`, else verbose patronus_web/tower_http).
/// Sign-in outcomes (target `patronus::audit`: who, from where, and why a
/// login was refused) are always logged at info, whatever `RUST_LOG` says,
/// so a refused login can be explained from the log on the box itself.
pub fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(audit_filter(std::env::var("RUST_LOG").ok().as_deref()))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// `RUST_LOG` (or the default) plus `patronus::audit=info`, unless the
/// setting names that target itself.
pub fn audit_filter(rust_log: Option<&str>) -> tracing_subscriber::EnvFilter {
    let base = rust_log
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("patronus_web=debug,tower_http=debug,axum=trace");
    let f = tracing_subscriber::EnvFilter::try_new(base).unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("patronus_web=debug,tower_http=debug,axum=trace")
    });
    if base.contains("patronus::audit") {
        return f;
    }
    match "patronus::audit=info".parse() {
        Ok(d) => f.add_directive(d),
        Err(_) => f,
    }
}

/// Open the store, set up the system login (and the embedded first run),
/// then serve HTTPS (and the optional HTTP redirect) until shutdown.
pub async fn run() -> Result<()> {
    info!(
        "Starting Patronus Web Interface v{}",
        env!("CARGO_PKG_VERSION")
    );

    // Open the persistent config store ($PATRONUS_DB or
    // /var/lib/patronus/config.db), seed first-boot defaults if the boot
    // unit hasn't, and load the stored firewall into nftables. (This used
    // to keep every rule in memory, with the store pointed at /tmp and
    // never used, so all rules vanished on restart.)
    let mut state = crate::state::startup(None).await?;
    if state.auth.syslogin.seed_from_env()? {
        info!("web login: account seeded from PATRONUS_ADMIN_PASSWORD (headless/CI)");
    }

    // No built-in account: the web UI signs in system users (PAM, or the
    // shadow files on the embedded tier) by group, see crate::syslogin.
    info!(
        "web login: system users in {:?} (admin); no built-in admin account",
        state.auth.syslogin.cfg.admin_groups
    );

    // Router images ship with no account at all: PATRONUS_FIRST_RUN_SETUP=1
    // makes the UI serve only /first-run (create the first administrator, a
    // system user in the first admin group) until such a user exists.
    if std::env::var("PATRONUS_FIRST_RUN_SETUP").is_ok_and(|v| v == "1")
        && !state.auth.syslogin.admin_account_exists()
    {
        state.auth.syslogin.set_first_run_pending(true);
        info!("no administrator account yet: the UI serves /first-run until the owner creates one");
    }

    // PATRONUS_HTTPS_PORT (default 8443; the embedded router image uses 443) and
    // PATRONUS_HTTP_REDIRECT_PORT (unset = no plain-HTTP listener; 80 on the router).
    let https_port: u16 = std::env::var("PATRONUS_HTTPS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8443);
    if let Some(p) = std::env::var("PATRONUS_HTTP_REDIRECT_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
    {
        tokio::spawn(async move {
            if let Err(e) =
                crate::serve_http_redirect(SocketAddr::from(([0, 0, 0, 0], p)), https_port).await
            {
                error!("HTTP redirect listener: {}", e);
            }
        });
    }
    let addr = SocketAddr::from(([0, 0, 0, 0], https_port));
    let tls_dir = crate::tls::default_tls_dir();
    info!(
        "Web interface listening on https://{} (self-signed TLS, cert dir: {})",
        addr,
        tls_dir.display()
    );

    // Start server using the library's TLS serve function. The dashboard is
    // documented and configured as HTTPS on 8443, so it serves HTTPS by
    // default (self-signed cert, auto-generated on first run).
    if let Err(e) = crate::serve_tls(addr, state, &tls_dir).await {
        error!("Server error: {}", e);
        return Err(e);
    }

    info!("Server shutdown gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn audit_target_is_always_logged() {
        for (rust_log, want) in [
            (None, "patronus::audit=info"),
            (
                Some("patronus_web=info,tower_http=warn"),
                "patronus::audit=info",
            ),
            (Some("warn"), "patronus::audit=info"),
            (Some("patronus::audit=off"), "patronus::audit=off"),
        ] {
            let f = super::audit_filter(rust_log).to_string();
            assert!(f.contains(want), "{rust_log:?} -> {f}");
        }
    }
}
