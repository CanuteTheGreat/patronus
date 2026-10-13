//! Web command handler
//!
//! Wires the `patronus web` subcommand to the real `patronus-web` crate's
//! HTTP server. Before this, `patronus-web.service`'s
//! `ExecStart=/usr/bin/patronus web --addr 0.0.0.0:8080` referenced a CLI
//! subcommand that simply did not exist in `patronus-cli`'s `Commands` enum
//! -- any fresh systemd start of that unit would fail immediately with a
//! clap "unrecognized subcommand" error. This builds the same
//! `RuleManager` + `ConfigStore` + `AppState` bootstrap `patronus-web`'s own
//! `main.rs` uses, and serves plain HTTP on the given `--addr` (matching
//! what the systemd unit actually invokes; `patronus-web`'s own standalone
//! binary defaults to self-signed HTTPS on :8443, which is a separate,
//! still-valid way to run the same router).

use colored::Colorize;
use std::net::SocketAddr;
use std::path::PathBuf;

pub async fn handle_web_command(addr: String, _config_path: PathBuf) -> anyhow::Result<()> {
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

        let rule_manager = patronus_firewall::rules::RuleManager::new();
        rule_manager
            .initialize()
            .await
            .map_err(|e| anyhow::anyhow!("failed to initialize nftables table/chains: {e}"))?;

        // Same stub-grade bootstrap patronus-web's own main.rs uses today
        // (tracked follow-up to source these from patronus.toml instead of
        // hardcoded paths); matches /var/lib/patronus which the systemd
        // unit already grants ReadWritePaths= for.
        let config_store =
            patronus_config::store::ConfigStore::new(PathBuf::from("/var/lib/patronus/config.db"));
        let state = patronus_web::AppState::new(rule_manager, config_store).await?;

        patronus_web::serve(socket_addr, state).await?;
        Ok(())
    }

    #[cfg(not(feature = "web"))]
    {
        let _ = (addr, _config_path);
        anyhow::bail!(
            "this patronus-cli binary was built without the \"web\" feature; rebuild with \
             --features web"
        )
    }
}
