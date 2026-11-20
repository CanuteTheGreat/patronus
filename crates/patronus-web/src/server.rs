//! The web UI server's entry point, shared by the `patronus-web` binary and,
//! on the embedded tier, the multi-call `patronus-cli` (invoked as
//! `patronus-web` through a link: one binary carries std, tokio, SQLite and the
//! appliers once instead of twice, see docs/embedded-routers.md).

use anyhow::Result;
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

    // A unit configured by its image (an access point, or a router image
    // that provisioned its network) records setup as complete at its first
    // start: no "not set up yet" banner, no router wizard on an AP.
    let role = crate::routes::api::setup::DeviceRole::from_env();
    match crate::routes::api::setup::record_provisioned(
        &state.config_store,
        role,
        std::env::var("PATRONUS_SETUP_PROVISIONED").ok().as_deref(),
    )
    .await
    {
        Ok(true) => info!("setup recorded as complete (role {})", role.as_str()),
        Ok(false) => {}
        Err(e) => error!("recording provisioned setup: {e}"),
    }

    // Router images ship with no account at all: PATRONUS_FIRST_RUN_SETUP=1
    // makes the UI serve only /first-run (create the first administrator, a
    // system user in the first admin group) until such a user exists. The
    // page asks for proof of ownership: a one-time setup code shown on the
    // console and in a root-only file (or the unit's existing root password,
    // e.g. carried over from OpenWrt), within a window after the service
    // starts, so whoever reaches the LAN first cannot claim the unit.
    if std::env::var("PATRONUS_FIRST_RUN_SETUP").is_ok_and(|v| v == "1")
        && !state.auth.syslogin.admin_account_exists()
    {
        let window = std::env::var("PATRONUS_FIRST_RUN_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or(crate::syslogin::FIRST_RUN_WINDOW);
        let code = state.auth.syslogin.open_first_run(window);
        crate::syslogin::publish_first_run_code(&code, window);
        info!(
            "no administrator account yet: the UI serves /first-run for {} min; the setup code is in {} and on the console",
            window.as_secs() / 60,
            crate::syslogin::first_run_code_path().display()
        );
    }

    // Where to listen: built-in default, environment, patronus.toml [web] and
    // the config store's web.* keys (patronus_config::webui), highest wins.
    let settings = patronus_config::webui::resolve(Some(&state.config_store)).await;
    if let Err(e) = settings.validate() {
        // a stored combination that cannot work must not leave the box without a UI
        error!("{e}; using the built-in web listener defaults");
        return serve_with(patronus_config::webui::WebSettings::default(), state).await;
    }
    serve_with(settings, state).await?;
    info!("Server shutdown gracefully");
    Ok(())
}

async fn serve_with(
    settings: patronus_config::webui::WebSettings,
    state: crate::AppState,
) -> Result<()> {
    let tls_dir = crate::tls::default_tls_dir();
    info!(
        "Web interface: https on {:?} port {} (+ extra {:?}), http redirect port {}, TLS {} (cert dir: {})",
        settings.listen,
        settings.https_port,
        settings.extra_https_ports,
        settings.http_redirect_port,
        if settings.tls_cert.is_empty() {
            "self-signed".to_string()
        } else {
            settings.tls_cert.clone()
        },
        tls_dir.display()
    );
    if let Err(e) = crate::serve_web(settings, state, &tls_dir, None).await {
        error!("Server error: {}", e);
        return Err(e);
    }
    Ok(())
}

/// `--help` / `--version` for the web binary (and the multi-call
/// `patronus-web` link). `None` = no such flag: start the server. The server
/// takes no other arguments, so anything else is refused instead of being
/// ignored and starting a server by accident.
pub fn cli_flags(args: &[String]) -> Option<(String, i32)> {
    let first = args.first()?;
    match first.as_str() {
        "-h" | "--help" => Some((help_text(), 0)),
        "-V" | "--version" => Some((format!("patronus-web {}\n", env!("CARGO_PKG_VERSION")), 0)),
        other => Some((
            format!(
                "patronus-web: unexpected argument '{other}'\n\n{}",
                help_text()
            ),
            2,
        )),
    }
}

fn help_text() -> String {
    r#"patronus-web @VER@
Patronus web UI server. Takes no arguments: it serves the management UI and API
until stopped.

Usage: patronus-web [--help | --version]

Where it listens (each layer replaces the one before it, key by key):
  1. built-in: HTTPS 443 and HTTP 80 that only redirects to HTTPS (no other port)
  2. environment: PATRONUS_WEB_LISTEN, PATRONUS_HTTPS_PORT,
     PATRONUS_HTTP_REDIRECT_PORT (0 = off), PATRONUS_WEB_EXTRA_HTTPS_PORTS
     (comma list, 'none' = off), PATRONUS_TLS_CERT, PATRONUS_TLS_KEY
  3. /etc/patronus/patronus.toml [web]: listen_addr, https_port,
     http_redirect_port, extra_https_ports, tls_cert, tls_key
  4. the config store (System page, PUT /api/system/web): web.listen,
     web.https_port, web.http_redirect_port, web.extra_https_ports,
     web.tls_cert, web.tls_key

Other environment: PATRONUS_DB (config store), PATRONUS_TLS_DIR (self-signed
certificate directory, default /etc/patronus/tls), PATRONUS_TLS_IP /
PATRONUS_TLS_HOSTNAME (names in a generated certificate), RUST_LOG.
Ports below 1024 need CAP_NET_BIND_SERVICE (the shipped OpenRC script and
systemd unit grant it); a listener that cannot be bound is logged and skipped.
"#
    .replace("@VER@", env!("CARGO_PKG_VERSION"))
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

    #[test]
    fn help_and_version_never_start_the_server() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(super::cli_flags(&a(&[])), None);
        let (t, c) = super::cli_flags(&a(&["--help"])).unwrap();
        assert_eq!(c, 0);
        assert!(t.contains("PATRONUS_HTTPS_PORT") && t.contains("Usage: patronus-web"));
        let (t, c) = super::cli_flags(&a(&["--version"])).unwrap();
        assert_eq!(c, 0);
        assert!(t.starts_with("patronus-web "));
        let (_, c) = super::cli_flags(&a(&["--bogus"])).unwrap();
        assert_eq!(c, 2);
    }
}
