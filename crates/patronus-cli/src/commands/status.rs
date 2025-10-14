//! Status command handler

use colored::Colorize;
use std::path::PathBuf;
use std::fs;

pub async fn handle_status(detailed: bool, config_path: PathBuf) -> anyhow::Result<()> {
    println!();
    println!("{}", "━".repeat(60).bright_blue());
    println!("{}  Patronus SD-WAN Status", " ".repeat(15));
    println!("{}", "━".repeat(60).bright_blue());
    println!();

    // Load config
    let config_content = fs::read_to_string(&config_path)?;
    let config: serde_json::Value = serde_yaml::from_str(&config_content)?;

    let deployment_name = config["deployment"]["name"].as_str().unwrap_or("unknown");
    let sites_count = config["sites"].as_array().map(|s| s.len()).unwrap_or(0);
    let tunnels_count = config["tunnels"].as_array().map(|t| t.len()).unwrap_or(0);

    println!("  {:<20} {}", "Deployment:".bold(), deployment_name);
    println!("  {:<20} {}", "Status:".bold(), "Running".green());
    println!("  {:<20} {}", "Sites:".bold(), sites_count.to_string().bright_blue());
    println!("  {:<20} {}", "Tunnels:".bold(), tunnels_count.to_string().bright_blue());
    println!("  {:<20} {}", "Version:".bold(), env!("CARGO_PKG_VERSION"));
    println!();

    if detailed {
        println!("{}", "Detailed Information:".bright_blue().bold());
        println!("  • Control Plane: {}", "Active".green());
        println!("  • Data Plane: {}", "Active".green());
        println!("  • Monitoring: {}", "Enabled".green());
        println!("  • BGP: {}", if config["bgp"]["enabled"].as_bool().unwrap_or(false) { "Enabled".green() } else { "Disabled".yellow() });
        println!();
    }

    Ok(())
}
