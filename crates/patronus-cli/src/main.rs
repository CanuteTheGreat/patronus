//! Patronus CLI - Unified SD-WAN Management Interface

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod commands;
#[cfg(feature = "gitops")]
use commands::gitops;
use commands::{
    apply, applyd, bgp, captiveportal, daemon, deploy, edge, firewall, init, metrics, policy, site,
    status, tunnel, users, validate, web,
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

    /// Called by hostapd (through `hostapd_cli -a`) when a station joins with
    /// a Patronus key id: a pending Wi-Fi device learns its MAC (USE=wifi-ap)
    #[cfg(feature = "wifi-ap")]
    #[command(name = "wifi-event", hide = true)]
    WifiEvent {
        /// hostapd interface
        iface: String,
        /// station MAC
        mac: String,
        /// `dev-<id>`
        keyid: String,
    },

    /// Root apply broker for patronus-web (runs one named applier on
    /// request over a unix socket; see patronus_network::applyd) and the
    /// periodic dynamic DNS refresh
    /// Zero-touch provisioning: fetch the configuration named in the
    /// [provisioning] section of patronus.toml (url, optional
    /// passphrase_file for an encrypted bundle), import it and apply it.
    /// Runs once (a marker is kept in the store); --force repeats it.
    Ztp {
        /// Bootstrap file [default: $PATRONUS_BOOTSTRAP or /etc/patronus/patronus.toml]
        #[arg(long)]
        bootstrap: Option<PathBuf>,
        /// Provision again although it already happened
        #[arg(long)]
        force: bool,
    },

    Applyd {
        /// Socket path [default: $PATRONUS_APPLYD_SOCKET or /run/patronus/applyd.sock]
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Group allowed to connect (patronus-web's group)
        #[arg(long, default_value = "patronus")]
        group: String,
    },

    /// DB-IP lite country + ASN databases for the traffic insight (the
    /// monthly update job runs `patronus ipdb update`)
    Ipdb {
        #[command(subcommand)]
        action: IpdbCommands,
    },

    /// Configuration history
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// GitOps: apply the firewall/NAT/interface/route resources kept in a
    /// git repository ([gitops] in patronus.toml; USE=gitops)
    #[cfg(feature = "gitops")]
    Gitops {
        #[command(subcommand)]
        action: GitopsCommands,
    },

    /// Signed plugins: make keys and bundles, check a bundle (USE=plugins)
    #[cfg(feature = "plugins")]
    Plugin {
        #[command(subcommand)]
        action: PluginCommands,
    },

    /// Web UI accounts (recovery on the box: lost second factor)
    Users {
        #[command(subcommand)]
        action: UsersCommands,
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

    /// SD-WAN edge agent (join the overlay of a Patronus SD-WAN dashboard)
    Edge {
        #[command(subcommand)]
        action: EdgeCommands,
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
enum EdgeCommands {
    /// Run the agent (what the patronus-daemon@edge-agent service does)
    Run,
    /// One enroll/sync/measure/report round, then exit
    Sync,
    /// What the agent last did
    Status,
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

        /// Our AS number (default: the stored one, else 65001)
        #[arg(long)]
        local_asn: Option<u32>,

        /// Router ID (an IPv4 address); required the first time
        #[arg(long)]
        router_id: Option<String>,
    },

    /// Show BGP status
    Status,

    /// Show BGP routes
    Routes,
}

#[derive(Subcommand)]
enum UsersCommands {
    /// List the web UI accounts (role, enabled, two-factor)
    List,
    /// Turn an account's two-factor login off (lost authenticator); it can
    /// log in with its password and enrol again
    #[command(name = "reset-2fa")]
    Reset2fa {
        /// Account name
        name: String,
    },
    /// Print the argon2 hash of a password (read from stdin, one line) for a
    /// GitOps `User` resource's `password_hash`
    #[command(name = "hash-password")]
    HashPassword,
}

#[cfg(feature = "plugins")]
#[derive(Subcommand)]
enum PluginCommands {
    /// Make an ed25519 signing key pair (<out>.key private, <out>.pub public)
    Keygen {
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Pack a plugin directory (plugin.json + files/) into a signed bundle
    Pack {
        dir: std::path::PathBuf,
        #[arg(long)]
        key: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Check a bundle against a public key file
    Verify {
        bundle: std::path::PathBuf,
        #[arg(long = "pub")]
        public: std::path::PathBuf,
    },
}

#[cfg(feature = "gitops")]
#[derive(Subcommand)]
enum GitopsCommands {
    /// Fetch the repository once and apply what changed (auto_apply decides
    /// unless --apply / --dry-run is given)
    Sync {
        /// Apply even when auto_apply is off
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
        /// Validate and show what would change, apply nothing
        #[arg(long)]
        dry_run: bool,
        /// Repository URL instead of [gitops] repo_url
        #[arg(long)]
        repo: Option<String>,
        /// patronus.toml with the [gitops] section [default: $PATRONUS_BOOTSTRAP or /etc/patronus/patronus.toml]
        #[arg(long)]
        bootstrap: Option<PathBuf>,
        /// Engine state directory [default: /var/lib/patronus/gitops/state]
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Poll the repository and apply every new commit (the patronus-gitops service)
    Watch {
        /// patronus.toml with the [gitops] section [default: $PATRONUS_BOOTSTRAP or /etc/patronus/patronus.toml]
        #[arg(long)]
        bootstrap: Option<PathBuf>,
        /// Engine state directory [default: /var/lib/patronus/gitops/state]
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum IpdbCommands {
    /// Download the country and ASN databases when they are due
    Update {
        /// Download even if the current files are fresh
        #[arg(long)]
        force: bool,
    },
    /// Show the files, their age and the last result
    Status,
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

/// `patronus ... | head` or `| grep -q`: when the reader goes away, end quietly like other Unix
/// tools (killed by SIGPIPE) instead of panicking in `println!` with "failed printing to
/// stdout: Broken pipe" (Rust starts programs with SIGPIPE ignored).
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: only resets the process-wide disposition of SIGPIPE to the default action; no
    // handler code runs and nothing in this program relies on SIGPIPE being ignored.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    restore_default_sigpipe();
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

        Commands::Edge { action } => {
            edge::handle_edge_command(action, cli.db).await?;
        }

        Commands::Bgp { action } => {
            bgp::handle_bgp_command(action, cli.db).await?;
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

        Commands::Users { action } => match action {
            UsersCommands::List => users::list(cli.db.as_deref()).await?,
            UsersCommands::Reset2fa { name } => users::reset_2fa(cli.db.as_deref(), &name).await?,
            UsersCommands::HashPassword => users::hash_password()?,
        },

        #[cfg(feature = "wifi-ap")]
        Commands::WifiEvent { iface, mac, keyid } => {
            commands::wifi::event(cli.db, iface, mac, keyid).await?;
        }

        Commands::Ztp { bootstrap, force } => {
            commands::ztp::run(cli.db, bootstrap, force).await?;
        }

        Commands::Applyd { socket, group } => {
            applyd::run(cli.db, socket, group).await?;
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

        #[cfg(feature = "plugins")]
        Commands::Plugin { action } => match action {
            PluginCommands::Keygen { out } => commands::plugin::keygen(&out)?,
            PluginCommands::Pack { dir, key, out } => commands::plugin::pack(&dir, &key, &out)?,
            PluginCommands::Verify { bundle, public } => {
                commands::plugin::verify(&bundle, &public)?
            }
        },

        #[cfg(feature = "gitops")]
        Commands::Gitops { action } => match action {
            GitopsCommands::Sync {
                apply,
                dry_run,
                repo,
                bootstrap,
                state_dir,
            } => {
                let mode = if apply {
                    Some(true)
                } else if dry_run {
                    Some(false)
                } else {
                    None
                };
                gitops::sync(
                    gitops::Options {
                        db: cli.db,
                        bootstrap,
                        state_dir,
                        repo,
                    },
                    mode,
                )
                .await?
            }
            GitopsCommands::Watch {
                bootstrap,
                state_dir,
            } => {
                gitops::watch(gitops::Options {
                    db: cli.db,
                    bootstrap,
                    state_dir,
                    repo: None,
                })
                .await?
            }
        },

        Commands::Ipdb { action } => match action {
            IpdbCommands::Update { force } => commands::ipdb::update(cli.db, force).await?,
            IpdbCommands::Status => commands::ipdb::status(cli.db).await?,
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
