//! Patronus Installer CLI
//!
//! Full-featured installer for Patronus firewall/SD-WAN system.

use clap::Parser;
use patronus_installer::{config::InstallConfig, tui::InstallerApp};
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "patronus-install")]
#[command(about = "Patronus Firewall/SD-WAN Installer", long_about = None)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Run in TUI mode (default)
    #[arg(long)]
    tui: bool,

    /// Run non-interactive installation from config file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Target disk for installation (overrides config)
    #[arg(long)]
    disk: Option<PathBuf>,

    /// Skip confirmation prompts (use with --config)
    #[arg(long, short = 'y')]
    yes: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// List available disks and exit
    #[arg(long)]
    list_disks: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .init();

    // List disks mode
    if cli.list_disks {
        return list_disks().await;
    }

    // Config file mode (unattended)
    if let Some(config_path) = cli.config {
        return run_unattended(&config_path, cli.disk, cli.yes).await;
    }

    // TUI mode (default)
    run_tui().await
}

/// Run in TUI mode
async fn run_tui() -> anyhow::Result<()> {
    info!("Starting Patronus Installer (TUI mode)");

    let mut app = InstallerApp::new();

    match app.run().await {
        Ok(()) => {
            println!("\nInstallation completed successfully!");
            println!("Please reboot your system.");
            Ok(())
        }
        Err(patronus_installer::error::InstallerError::Cancelled) => {
            println!("\nInstallation cancelled.");
            std::process::exit(1);
        }
        Err(e) => {
            error!("Installation failed: {}", e);
            eprintln!("\nInstallation failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Run unattended installation from config file
async fn run_unattended(
    config_path: &PathBuf,
    disk_override: Option<PathBuf>,
    skip_confirm: bool,
) -> anyhow::Result<()> {
    info!("Starting Patronus Installer (unattended mode)");

    // Load configuration
    let config_content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;

    let mut config: InstallConfig = toml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;

    // Apply disk override if specified
    if let Some(disk) = disk_override {
        config.disk.device = disk;
    }

    // Confirm
    if !skip_confirm {
        println!("Patronus Unattended Installation");
        println!("================================");
        println!();
        println!("Target disk: {}", config.disk.device.display());
        println!("Partition scheme: {:?}", config.disk.scheme);
        println!("Filesystem: {:?}", config.disk.filesystem);
        println!("Hostname: {}", config.system.hostname);
        println!();
        println!("WARNING: All data on {} will be erased!", config.disk.device.display());
        println!();

        print!("Continue? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Installation cancelled.");
            return Ok(());
        }
    }

    // Run installation
    run_installation(&config).await
}

/// Run the actual installation process
async fn run_installation(config: &InstallConfig) -> anyhow::Result<()> {
    use patronus_installer::disk::{format::format_all_partitions, partition::create_partitions};
    use patronus_installer::install::{
        bootloader::install_bootloader, configure_network, configure_services,
        mount_partitions, system::{configure_system, install_base_system},
        unmount_partitions,
    };

    println!("Starting installation...");

    // Step 1: Create partitions
    println!("[1/8] Creating partitions...");
    let partitions = create_partitions(
        &config.disk.device,
        &config.disk.scheme,
        config.disk.filesystem,
        config.disk.swap_size_mb,
        config.disk.home_size_mb,
    )
    .await?;

    // Step 2: Format partitions
    println!("[2/8] Formatting partitions...");
    format_all_partitions(&partitions).await?;

    // Step 3: Mount partitions
    println!("[3/8] Mounting partitions...");
    mount_partitions(&partitions, &config.target_root).await?;

    // Step 4: Install base system
    println!("[4/8] Installing base system (this may take a while)...");
    install_base_system(config, None).await?;

    // Step 5: Configure system
    println!("[5/8] Configuring system...");
    configure_system(config, &partitions, None).await?;

    // Step 6: Configure network
    println!("[6/8] Configuring network...");
    configure_network(&config.target_root, &config.network).await?;

    // Step 7: Configure services
    println!("[7/8] Configuring services...");
    configure_services(&config.target_root, &config.services, &config.patronus).await?;

    // Step 8: Install bootloader
    println!("[8/8] Installing bootloader...");
    install_bootloader(
        &config.target_root,
        config.system.bootloader,
        &config.disk.scheme,
        &config.disk.device,
        &partitions,
    )
    .await?;

    // Cleanup: Unmount
    println!("Finalizing...");
    unmount_partitions(&partitions, &config.target_root).await?;

    println!();
    println!("Installation completed successfully!");
    println!("Please reboot your system.");

    Ok(())
}

/// List available disks
async fn list_disks() -> anyhow::Result<()> {
    use patronus_installer::disk::detect_disks;

    let disks = detect_disks().await?;

    println!("Available disks:");
    println!();

    for disk in &disks {
        let suitable = if disk.is_suitable_target() {
            ""
        } else {
            " (not suitable)"
        };

        println!("  {}{}", disk.summary(), suitable);

        for part in &disk.partitions {
            let fs = part.filesystem.as_deref().unwrap_or("unknown");
            let mount = part
                .mount_point
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string());

            println!(
                "    └─ {} {} {} ({})",
                part.path.display(),
                patronus_installer::disk::detect::format_size(part.size_bytes),
                fs,
                mount
            );
        }
        println!();
    }

    Ok(())
}
