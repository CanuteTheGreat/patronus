//! Web command handler
//!
//! Wires the `patronus web` subcommand to the real `patronus-web` crate's
//! HTTP server. Before this, `patronus-web.service`'s
//! `ExecStart=/usr/bin/patronus web --addr 0.0.0.0:8080` referenced a CLI
//! subcommand that simply did not exist in `patronus-cli`'s `Commands` enum
//! -- any fresh systemd start of that unit would fail immediately with a
//! clap "unrecognized subcommand" error. This builds the same
//! store-backed `AppState` startup `patronus-web`'s own `main.rs` uses, and serves plain HTTP on the given `--addr` (matching
//! what the systemd unit actually invokes; `patronus-web`'s own standalone
//! binary defaults to self-signed HTTPS on :8443, which is a separate,
//! still-valid way to run the same router).

#[cfg(feature = "web")]
use colored::Colorize;
#[cfg(feature = "web")]
use std::net::SocketAddr;
use std::path::PathBuf;

pub async fn handle_web_command(
    addr: String,
    _config_path: PathBuf,
    db: Option<PathBuf>,
) -> anyhow::Result<()> {
    #[cfg(feature = "web")]
    {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --addr '{addr}': {e}"))?;

        println!(
            "{}",
            "Starting Patronus Web Interface...".bright_blue().bold()
        );
        println!("  Listening on http://{}", socket_addr);

        // Same startup as the patronus-web binary: open the config store
        // (--db / $PATRONUS_DB / /var/lib/patronus/config.db), seed
        // first-boot defaults, load the stored firewall into nftables.
        let state = patronus_web::state::startup(db).await?;
        // No default credentials: same per-install admin password as the
        // patronus-web binary (PATRONUS_ADMIN_PASSWORD or the generated
        // /var/lib/patronus/initial-admin-password).
        let source = state.auth.user_store.provision_admin_from_env().await?;
        println!("  Admin password source: {:?}", source);

        patronus_web::serve(socket_addr, state).await?;
        Ok(())
    }

    #[cfg(not(feature = "web"))]
    {
        let _ = (addr, _config_path, db);
        anyhow::bail!(
            "this patronus-cli binary was built without the \"web\" feature; rebuild with \
             --features web"
        )
    }
}
