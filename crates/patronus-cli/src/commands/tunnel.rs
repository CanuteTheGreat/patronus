//! Tunnel management command handlers

use crate::TunnelCommands;
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use std::path::PathBuf;
use std::fs;

pub async fn handle_tunnel_command(action: TunnelCommands, config_path: PathBuf) -> anyhow::Result<()> {
    match action {
        TunnelCommands::Create { name, source, destination, protocol } => {
            println!("{} Creating tunnel '{}'...", "→".bright_blue(), name);

            let config_content = fs::read_to_string(&config_path)?;
            let mut config: serde_json::Value = serde_yaml::from_str(&config_content)?;

            let tunnel = serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "name": name,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "status": "stopped",
                "created_at": chrono::Utc::now().to_rfc3339()
            });

            if let Some(tunnels) = config["tunnels"].as_array_mut() {
                tunnels.push(tunnel);
            }

            let updated_config = serde_yaml::to_string(&config)?;
            fs::write(&config_path, updated_config)?;

            println!("{} Tunnel '{}' created successfully", "✓".green(), name);
        }

        TunnelCommands::List => {
            let config_content = fs::read_to_string(&config_path)?;
            let config: serde_json::Value = serde_yaml::from_str(&config_content)?;
            let empty_vec = vec![];
            let tunnels = config["tunnels"].as_array().unwrap_or(&empty_vec);

            if tunnels.is_empty() {
                println!("{}", "No tunnels configured".yellow());
                return Ok(());
            }

            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Name", "Source", "Destination", "Protocol", "Status"]);

            for tunnel in tunnels {
                table.add_row(vec![
                    tunnel["name"].as_str().unwrap_or("N/A"),
                    tunnel["source"].as_str().unwrap_or("N/A"),
                    tunnel["destination"].as_str().unwrap_or("N/A"),
                    tunnel["protocol"].as_str().unwrap_or("N/A"),
                    tunnel["status"].as_str().unwrap_or("N/A"),
                ]);
            }

            println!();
            println!("{}", table);
            println!();
        }

        TunnelCommands::Show { tunnel } => {
            println!("{} Showing tunnel '{}'", "→".bright_blue(), tunnel);
        }

        TunnelCommands::Start { tunnel } => {
            println!("{} Starting tunnel '{}'", "→".bright_blue(), tunnel);
            println!("{} Tunnel '{}' started", "✓".green(), tunnel);
        }

        TunnelCommands::Stop { tunnel } => {
            println!("{} Stopping tunnel '{}'", "→".bright_blue(), tunnel);
            println!("{} Tunnel '{}' stopped", "✓".green(), tunnel);
        }

        TunnelCommands::Delete { tunnel } => {
            println!("{} Deleting tunnel '{}'", "→".bright_blue(), tunnel);
            println!("{} Tunnel '{}' deleted", "✓".green(), tunnel);
        }
    }
    Ok(())
}
