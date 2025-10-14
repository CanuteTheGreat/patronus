//! Initialize command handler

use colored::Colorize;
use std::path::PathBuf;
use std::fs;

pub async fn handle_init(name: String, org: Option<String>, config_path: PathBuf) -> anyhow::Result<()> {
    println!("{}", "━".repeat(60).bright_blue());
    println!("{}", "  Patronus SD-WAN Initialization  ".bright_blue().bold());
    println!("{}", "━".repeat(60).bright_blue());
    println!();

    // Create configuration directory
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
        println!("{} Created config directory: {}", "✓".green(), parent.display());
    }

    // Generate default configuration
    let config = serde_yaml::to_string(&serde_json::json!({
        "deployment": {
            "name": name,
            "organization": org.unwrap_or_else(|| "default".to_string()),
            "version": "1.0"
        },
        "sites": [],
        "tunnels": [],
        "policies": [],
        "bgp": {
            "enabled": false,
            "asn": null,
            "router_id": null
        },
        "monitoring": {
            "enabled": true,
            "metrics_port": 9090
        }
    }))?;

    fs::write(&config_path, config)?;
    println!("{} Created configuration file: {}", "✓".green(), config_path.display());

    println!();
    println!("{}", "Initialization complete!".bright_green().bold());
    println!();
    println!("Next steps:");
    println!("  1. Create sites:   {} patronus site create <name> --location <location> --address <ip>", "$".bright_yellow());
    println!("  2. Create tunnels: {} patronus tunnel create <name> --source <site1> --destination <site2>", "$".bright_yellow());
    println!("  3. Start daemon:   {} patronus daemon", "$".bright_yellow());
    println!();

    Ok(())
}
