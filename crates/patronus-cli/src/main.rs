//! Patronus CLI - Unified SD-WAN Management Interface

use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use std::path::PathBuf;
use uuid::Uuid;

mod commands;
use commands::*;

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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
