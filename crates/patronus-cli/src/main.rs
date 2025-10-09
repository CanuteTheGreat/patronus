//! Patronus CLI - Main entry point

use clap::{Parser, Subcommand};
use patronus_config::ConfigStore;
use patronus_firewall::RuleManager;
use patronus_web::{serve, AppState};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "patronus")]
#[command(about = "Patronus Firewall - A Gentoo-based firewall system", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the web interface
    Web {
        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        addr: String,
    },
    /// Manage firewall rules
    Firewall {
        #[command(subcommand)]
        action: FirewallCommands,
    },
    /// Manage network interfaces
    Network {
        #[command(subcommand)]
        action: NetworkCommands,
    },
}

#[derive(Subcommand)]
enum FirewallCommands {
    /// Initialize the firewall
    Init,
    /// List all firewall rules
    List,
    /// Apply all firewall rules
    Apply,
    /// Flush all firewall rules
    Flush,
    /// Check if nftables is available
    Check,
    /// Show current nftables ruleset
    Show,
    /// Enable IP forwarding
    EnableForwarding,
    /// Disable IP forwarding
    DisableForwarding,
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// List all network interfaces
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "patronus=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Web { addr } => {
            let addr: SocketAddr = addr.parse()?;

            // Initialize application state
            let rule_manager = RuleManager::new();
            let config_store = ConfigStore::new(PathBuf::from("/etc/patronus/config.db"));
            config_store.init().await?;

            let state = AppState::new(rule_manager, config_store);

            tracing::info!("Starting Patronus web interface on {}", addr);
            serve(addr, state).await?;
        }
        Commands::Firewall { action } => match action {
            FirewallCommands::Init => {
                let manager = RuleManager::new();
                manager.initialize().await?;
                println!("✓ Firewall initialized");
            }
            FirewallCommands::List => {
                let manager = RuleManager::new();
                let filter_rules = manager.list_filter_rules().await?;
                let nat_rules = manager.list_nat_rules().await?;

                println!("Filter Rules ({}):", filter_rules.len());
                for rule in filter_rules {
                    let status = if rule.enabled { "✓" } else { "✗" };
                    println!("  {} [{}] {} -> {}: {}",
                        status,
                        rule.id.unwrap_or(0),
                        rule.chain,
                        rule.name,
                        rule.action
                    );
                }

                println!("\nNAT Rules ({}):", nat_rules.len());
                for rule in nat_rules {
                    let status = if rule.enabled { "✓" } else { "✗" };
                    println!("  {} [{}] {}: {:?}",
                        status,
                        rule.id.unwrap_or(0),
                        rule.name,
                        rule.nat_type
                    );
                }
            }
            FirewallCommands::Apply => {
                let manager = RuleManager::new();
                manager.apply_all().await?;
                println!("✓ Applied all firewall rules");
            }
            FirewallCommands::Flush => {
                let manager = RuleManager::new();
                manager.flush().await?;
                println!("✓ Flushed all firewall rules");
            }
            FirewallCommands::Check => {
                match patronus_firewall::check_nftables_available() {
                    Ok(true) => println!("✓ nftables is available"),
                    Ok(false) => println!("✗ nftables is not available"),
                    Err(e) => println!("Error checking nftables: {}", e),
                }
            }
            FirewallCommands::Show => {
                let manager = RuleManager::new();
                let ruleset = manager.get_nftables_ruleset().await?;
                println!("{}", ruleset);
            }
            FirewallCommands::EnableForwarding => {
                let manager = RuleManager::new();
                manager.enable_forwarding().await?;
                println!("✓ IP forwarding enabled");
            }
            FirewallCommands::DisableForwarding => {
                let manager = RuleManager::new();
                manager.disable_forwarding().await?;
                println!("✓ IP forwarding disabled");
            }
        },
        Commands::Network { action } => match action {
            NetworkCommands::List => {
                let interfaces = patronus_network::list_interfaces().await?;
                println!("Network Interfaces:");
                for iface in interfaces {
                    println!("  - {} (MTU: {}, Enabled: {})", iface.name, iface.mtu, iface.enabled);
                }
            }
        },
    }

    Ok(())
}
