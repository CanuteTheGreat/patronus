//! SD-WAN CLI Example
//!
//! This example demonstrates how to use the Patronus SD-WAN library to create
//! an intelligent mesh network with automatic site discovery, WireGuard peering,
//! path monitoring, and application-aware routing.
//!
//! Usage:
//!   cargo run --example sdwan_cli -- --site-name <name> [options]
//!
//! Options:
//!   --site-name <name>         Name of this site (required)
//!   --listen-port <port>       WireGuard listen port (default: 51820)
//!   --database <path>          Database file path (default: sdwan.db)
//!   --interface <name>         WireGuard interface name (default: wg-sdwan)
//!   --multicast-group <addr>   Multicast group for discovery (default: 239.255.77.77:51821)
//!   --help                     Show this help message

use clap::Parser;
use patronus_sdwan::{database::Database, types::SiteId, SdwanConfig, SdwanManager};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "sdwan-cli")]
#[command(about = "Patronus SD-WAN CLI Example", long_about = None)]
struct Args {
    /// Name of this site
    #[arg(long, required = true)]
    site_name: String,

    /// WireGuard listen port
    #[arg(long, default_value = "51820")]
    listen_port: u16,

    /// Database file path
    #[arg(long, default_value = "sdwan.db")]
    database: PathBuf,

    /// WireGuard interface name
    #[arg(long, default_value = "wg-sdwan")]
    interface: String,

    /// Multicast group for site discovery
    #[arg(long, default_value = "239.255.77.77:51821")]
    multicast_group: String,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.debug { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("patronus_sdwan={},sdwan_cli={}", log_level, log_level))),
        )
        .init();

    info!("Starting Patronus SD-WAN CLI");
    info!("Site name: {}", args.site_name);
    info!("Listen port: {}", args.listen_port);
    info!("Database: {}", args.database.display());
    info!("Interface: {}", args.interface);

    // Check for root privileges (required for WireGuard management)
    if !nix::unistd::geteuid().is_root() {
        error!("This program must be run as root to manage WireGuard interfaces");
        error!("Try: sudo -E cargo run --example sdwan_cli -- --site-name {}", args.site_name);
        std::process::exit(1);
    }

    // Create SD-WAN configuration
    let db_path = args.database.to_str().unwrap_or("sdwan.db");
    let control_plane_addr: SocketAddr = args.multicast_group.parse()
        .unwrap_or_else(|_| "239.255.77.77:51821".parse().unwrap());

    let site_id = SiteId::generate();
    let config = SdwanConfig {
        site_id: site_id.clone(),
        site_name: args.site_name.clone(),
        database_path: db_path.to_string(),
        seed_sites: Vec::new(),
        control_plane_addr,
    };

    info!("Creating SD-WAN manager");
    let manager = Arc::new(SdwanManager::new(config).await?);

    // Get database reference for status reporting
    let db = Arc::new(Database::new(db_path).await?);

    // Start SD-WAN services
    info!("Starting SD-WAN services...");
    if let Err(e) = manager.start().await {
        error!("Failed to start SD-WAN manager: {}", e);
        return Err(e.into());
    }

    info!("SD-WAN services started successfully");
    info!("Site ID: {}", site_id);
    info!("Listening on port {} for WireGuard connections", args.listen_port);
    info!("Multicast discovery enabled on {}", args.multicast_group);
    info!("");
    info!("The SD-WAN node is now running. Press Ctrl+C to stop.");
    info!("");
    info!("Features enabled:");
    info!("  ✓ Automatic site discovery via multicast");
    info!("  ✓ Automatic WireGuard peering");
    info!("  ✓ Path quality monitoring (latency, jitter, packet loss, bandwidth)");
    info!("  ✓ Application-aware routing with QoS policies");
    info!("  ✓ Automatic failover on path degradation");
    info!("");
    info!("To monitor the network:");
    info!("  - View discovered sites: sqlite3 {} 'SELECT * FROM sites;'", db_path);
    info!("  - View active paths: sqlite3 {} 'SELECT * FROM paths;'", db_path);
    info!("  - View path metrics: sqlite3 {} 'SELECT * FROM path_metrics ORDER BY measured_at DESC LIMIT 10;'", db_path);
    info!("  - View routing policies: sqlite3 {} 'SELECT * FROM policies;'", db_path);
    info!("");

    // Start status reporting task
    let manager_clone = manager.clone();
    let db_clone = db.clone();
    tokio::spawn(async move {
        status_reporter(manager_clone, db_clone).await;
    });

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("");
            info!("Received shutdown signal, stopping SD-WAN services...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    // Stop SD-WAN services
    if let Err(e) = manager.stop().await {
        warn!("Error stopping SD-WAN manager: {}", e);
    }

    info!("SD-WAN services stopped");
    Ok(())
}

/// Status reporter that periodically prints network statistics
async fn status_reporter(_manager: Arc<SdwanManager>, db: Arc<Database>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        // Get statistics
        match db.list_sites().await {
            Ok(sites) => {
                let active_sites: Vec<_> = sites
                    .iter()
                    .filter(|s| matches!(s.status, patronus_sdwan::types::SiteStatus::Active))
                    .collect();

                if !active_sites.is_empty() {
                    info!("");
                    info!("═══════════════════════════════════════════════════════");
                    info!("Network Status Report");
                    info!("═══════════════════════════════════════════════════════");
                    info!("Active sites: {}", active_sites.len());

                    for site in active_sites {
                        info!("  • {} (ID: {})", site.name, site.id);
                        if !site.endpoints.is_empty() {
                            for endpoint in &site.endpoints {
                                info!("    - Endpoint: {} ({})", endpoint.address, endpoint.interface_type);
                            }
                        }
                    }
                }

                // Get path statistics
                match db.list_paths().await {
                    Ok(paths) => {
                        let up_paths = paths
                            .iter()
                            .filter(|p| matches!(p.status, patronus_sdwan::types::PathStatus::Up))
                            .count();
                        let degraded_paths = paths
                            .iter()
                            .filter(|p| matches!(p.status, patronus_sdwan::types::PathStatus::Degraded))
                            .count();
                        let down_paths = paths
                            .iter()
                            .filter(|p| matches!(p.status, patronus_sdwan::types::PathStatus::Down))
                            .count();

                        if !paths.is_empty() {
                            info!("");
                            info!("Active paths: {} (Up: {}, Degraded: {}, Down: {})",
                                paths.len(), up_paths, degraded_paths, down_paths);

                            // Show best and worst paths
                            let mut sorted_paths = paths.clone();
                            sorted_paths.sort_by(|a, b| b.metrics.score.cmp(&a.metrics.score));

                            if let Some(best) = sorted_paths.first() {
                                info!("  Best path: {} → {} (score: {}, latency: {:.1}ms, loss: {:.2}%)",
                                    best.src_site, best.dst_site, best.metrics.score,
                                    best.metrics.latency_ms, best.metrics.packet_loss_pct);
                            }

                            if sorted_paths.len() > 1 {
                                if let Some(worst) = sorted_paths.last() {
                                    info!("  Worst path: {} → {} (score: {}, latency: {:.1}ms, loss: {:.2}%)",
                                        worst.src_site, worst.dst_site, worst.metrics.score,
                                        worst.metrics.latency_ms, worst.metrics.packet_loss_pct);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get path statistics: {}", e);
                    }
                }

                info!("═══════════════════════════════════════════════════════");
                info!("");
            }
            Err(e) => {
                warn!("Failed to get site statistics: {}", e);
            }
        }
    }
}
