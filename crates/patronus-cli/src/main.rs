//! Patronus CLI - Unified SD-WAN Management Interface

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod commands;
use commands::{
    apply, bgp, captiveportal, daemon, deploy, firewall, init, metrics, policy, site, status,
    tunnel, validate, web,
};

#[derive(Parser)]
#[command(name = "patronus")]
#[command(about = "Patronus SD-WAN - Next-generation Software-Defined Wide Area Network", long_about = None)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/patronus/config.yaml")]
    config: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Config store (SQLite) path [default: $PATRONUS_DB or /var/lib/patronus/config.db]
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply the whole stored configuration to the system, in dependency
    /// order: sysctl -> interfaces/VLANs -> routes -> firewall/NAT ->
    /// services. Seeds the safe default ruleset on first boot. This is what
    /// the boot unit runs.
    Apply {
        /// Bootstrap file with [network] wan_interface/lan_interface
        /// [default: $PATRONUS_BOOTSTRAP or /etc/patronus/patronus.toml]
        #[arg(long)]
        bootstrap: Option<PathBuf>,

        /// Only these phases (sysctl, interfaces, routes, firewall, services)
        #[arg(long = "phase")]
        phases: Vec<String>,

        /// Print what would be applied (nft script, sysctls, ...) and change nothing
        #[arg(long)]
        dry_run: bool,
    },

    /// Root apply broker for patronus-web (runs one named applier on
    /// request over a unix socket; see patronus_network::applyd)
    Applyd {
        /// Socket path [default: $PATRONUS_APPLYD_SOCKET or /run/patronus/applyd.sock]
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Group allowed to connect (patronus-web's group)
        #[arg(long, default_value = "patronus")]
        group: String,
    },

    /// Configuration history
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Initialize a new Patronus deployment
    Init {
        /// Deployment name
        #[arg(short, long)]
        name: String,

        /// Organization name
        #[arg(short, long)]
        org: Option<String>,
    },

    /// Manage sites
    Site {
        #[command(subcommand)]
        action: SiteCommands,
    },

    /// Manage tunnels
    Tunnel {
        #[command(subcommand)]
        action: TunnelCommands,
    },

    /// Manage routing policies
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// BGP routing management
    Bgp {
        #[command(subcommand)]
        action: BgpCommands,
    },

    /// Start the web management interface
    /// (what patronus-web.service's ExecStart actually invokes)
    Web {
        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        addr: String,
    },

    /// Manage nftables firewall rules
    /// (what patronus-firewall.service's ExecStart/ExecStop actually invoke)
    Firewall {
        #[command(subcommand)]
        action: FirewallCommands,
    },

    /// Guest WiFi captive portal
    CaptivePortal {
        #[command(subcommand)]
        action: CaptivePortalCommands,
    },

    /// Show system status
    Status {
        /// Show detailed status
        #[arg(short, long)]
        detailed: bool,
    },

    /// Start the control plane daemon
    Daemon {
        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
    },

    /// Deploy configuration from file
    Deploy {
        /// Configuration file
        file: PathBuf,
    },

    /// Validate configuration
    Validate {
        /// Configuration file
        file: PathBuf,
    },

    /// Show metrics and statistics
    Metrics {
        #[command(subcommand)]
        action: MetricsCommands,
    },
}

#[derive(Subcommand)]
enum SiteCommands {
    /// Create a new site
    Create {
        /// Site name
        name: String,

        /// Site location
        #[arg(short, long)]
        location: String,

        /// Site IP address
        #[arg(short, long)]
        address: String,
    },

    /// List all sites
    List,

    /// Show site details
    Show {
        /// Site name or ID
        site: String,
    },

    /// Delete a site
    Delete {
        /// Site name or ID
        site: String,
    },
}

#[derive(Subcommand)]
enum TunnelCommands {
    /// Create a new tunnel
    Create {
        /// Tunnel name
        name: String,

        /// Source site
        #[arg(short, long)]
        source: String,

        /// Destination site
        #[arg(short, long)]
        destination: String,

        /// Tunnel protocol (wireguard, ipsec, gre)
        #[arg(short, long, default_value = "wireguard")]
        protocol: String,
    },

    /// List all tunnels
    List,

    /// Show tunnel details
    Show {
        /// Tunnel name or ID
        tunnel: String,
    },

    /// Start a tunnel
    Start {
        /// Tunnel name or ID
        tunnel: String,
    },

    /// Stop a tunnel
    Stop {
        /// Tunnel name or ID
        tunnel: String,
    },

    /// Delete a tunnel
    Delete {
        /// Tunnel name or ID
        tunnel: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Create a routing policy
    Create {
        /// Policy name
        name: String,

        /// Source subnet
        #[arg(short, long)]
        source: String,

        /// Destination subnet
        #[arg(short, long)]
        destination: String,

        /// Action (allow, deny, route)
        #[arg(short, long)]
        action: String,

        /// Priority (lower = higher priority)
        #[arg(short, long, default_value = "100")]
        priority: u32,
    },

    /// List all policies
    List,

    /// Show policy details
    Show {
        /// Policy name or ID
        policy: String,
    },

    /// Delete a policy
    Delete {
        /// Policy name or ID
        policy: String,
    },
}

#[derive(Subcommand)]
enum BgpCommands {
    /// Configure BGP peer
    Peer {
        /// Peer IP address
        #[arg(short, long)]
        address: String,

        /// Peer AS number
        #[arg(short = 's', long)]
        asn: u32,
    },

    /// Show BGP status
    Status,

    /// Show BGP routes
    Routes,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// List stored configuration revisions (newest first)
    Revisions,
    /// Restore a revision and apply it
    Rollback {
        /// Revision id (see `patronus config revisions`)
        id: i64,
    },
    /// Write the whole configuration as JSON (a backup)
    Export {
        /// Output file (mode 0600) [default: stdout]
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Replace the configuration with an export and apply it; reverted if
    /// it does not apply
    Import {
        /// File written by `patronus config export`
        file: PathBuf,
        /// Only write the store; apply at the next `patronus apply`/boot
        #[arg(long)]
        no_apply: bool,
    },
}

#[derive(Subcommand)]
enum FirewallCommands {
    /// Load every stored filter + NAT rule into nftables (atomically);
    /// same as `patronus apply --phase firewall`
    Apply {
        /// Bootstrap file (see `patronus apply --help`)
        #[arg(long)]
        bootstrap: Option<PathBuf>,

        /// Print the nft script instead of loading it
        #[arg(long)]
        dry_run: bool,
    },

    /// Flush all Patronus-managed nftables rules
    Flush,
}

#[derive(Subcommand)]
enum CaptivePortalCommands {
    /// Start the captive portal HTTP server
    Serve {
        /// Bind address for the portal HTTP server
        #[arg(short, long)]
        addr: Option<String>,

        /// Network interface to intercept guest traffic on
        #[arg(short, long)]
        interface: Option<String>,
    },
}

#[derive(Subcommand)]
enum MetricsCommands {
    /// Show traffic statistics
    Traffic,

    /// Show link health
    Health,

    /// Show bandwidth usage
    Bandwidth,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    match cli.command {
        Commands::Init { name, org } => {
            println!("{}", "Initializing Patronus SD-WAN...".bright_blue().bold());
            init::handle_init(name, org, cli.config).await?;
        }

        Commands::Site { action } => {
            site::handle_site_command(action, cli.config).await?;
        }

        Commands::Tunnel { action } => {
            tunnel::handle_tunnel_command(action, cli.config).await?;
        }

        Commands::Policy { action } => {
            policy::handle_policy_command(action, cli.config).await?;
        }

        Commands::Bgp { action } => {
            bgp::handle_bgp_command(action, cli.config).await?;
        }

        Commands::Web { addr } => {
            web::handle_web_command(addr, cli.config, cli.db).await?;
        }

        Commands::Firewall { action } => {
            firewall::handle_firewall_command(action, cli.db).await?;
        }

        Commands::Apply {
            bootstrap,
            phases,
            dry_run,
        } => {
            apply::run(apply::ApplyOptions {
                db: cli.db,
                bootstrap,
                phases: apply::parse_phases(&phases)?,
                dry_run,
            })
            .await?;
        }

        Commands::Applyd { socket, group } => {
            let store = apply::open_store(cli.db.as_deref()).await?;
            let socket = socket.unwrap_or_else(patronus_network::applyd::socket_path);
            patronus_network::applyd::serve(apply::registry(), store, &socket, Some(&group))
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        Commands::Config { action } => match action {
            ConfigCommands::Revisions => apply::list_revisions(cli.db.as_deref()).await?,
            ConfigCommands::Rollback { id } => {
                apply::rollback(
                    id,
                    apply::ApplyOptions {
                        db: cli.db,
                        bootstrap: None,
                        phases: None,
                        dry_run: false,
                    },
                )
                .await?
            }
            ConfigCommands::Export { output } => {
                apply::export(cli.db.as_deref(), output.as_deref()).await?
            }
            ConfigCommands::Import { file, no_apply } => {
                apply::import(
                    &file,
                    !no_apply,
                    apply::ApplyOptions {
                        db: cli.db,
                        bootstrap: None,
                        phases: None,
                        dry_run: false,
                    },
                )
                .await?
            }
        },

        Commands::CaptivePortal { action } => match action {
            CaptivePortalCommands::Serve { addr, interface } => {
                captiveportal::handle_captiveportal_command(addr, interface).await?;
            }
        },

        Commands::Status { detailed } => {
            status::handle_status(detailed, cli.config).await?;
        }

        Commands::Daemon { bind } => {
            daemon::handle_daemon(bind, cli.config).await?;
        }

        Commands::Deploy { file } => {
            deploy::handle_deploy(file, cli.config).await?;
        }

        Commands::Validate { file } => {
            validate::handle_validate(file).await?;
        }

        Commands::Metrics { action } => {
            metrics::handle_metrics_command(action, cli.config).await?;
        }
    }

    Ok(())
}
