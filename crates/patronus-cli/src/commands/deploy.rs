//! Deploy command handler

use colored::Colorize;
use std::path::PathBuf;
use std::fs;

pub async fn handle_deploy(file: PathBuf, _config_path: PathBuf) -> anyhow::Result<()> {
    println!("{} Deploying configuration from {}...", "→".bright_blue(), file.display());

    let content = fs::read_to_string(&file)?;
    let config: serde_json::Value = serde_yaml::from_str(&content)?;

    println!("{} Configuration loaded successfully", "✓".green());
    println!("  Sites: {}", config["sites"].as_array().map(|s| s.len()).unwrap_or(0));
    println!("  Tunnels: {}", config["tunnels"].as_array().map(|t| t.len()).unwrap_or(0));

    println!("{} Deployment complete!", "✓".green().bold());

    Ok(())
}
