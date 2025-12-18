//! Site management command handlers

use crate::SiteCommands;
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use std::path::PathBuf;
use std::fs;
use uuid::Uuid;

pub async fn handle_site_command(action: SiteCommands, config_path: PathBuf) -> anyhow::Result<()> {
    match action {
        SiteCommands::Create { name, location, address } => {
            create_site(name, location, address, config_path).await?;
        }
        SiteCommands::List => {
            list_sites(config_path).await?;
        }
        SiteCommands::Show { site } => {
            show_site(site, config_path).await?;
        }
        SiteCommands::Delete { site } => {
            delete_site(site, config_path).await?;
        }
    }
    Ok(())
}

async fn create_site(name: String, location: String, address: String, config_path: PathBuf) -> anyhow::Result<()> {
    println!("{} Creating site '{}'...", "→".bright_blue(), name);

    // Load config
    let config_content = fs::read_to_string(&config_path)?;
    let mut config: serde_json::Value = serde_yaml::from_str(&config_content)?;

    // Create site object
    let site = serde_json::json!({
        "id": Uuid::new_v4().to_string(),
        "name": name,
        "location": location,
        "address": address,
        "enabled": true,
        "created_at": chrono::Utc::now().to_rfc3339()
    });

    // Add to config
    if let Some(sites) = config["sites"].as_array_mut() {
        sites.push(site);
    }

    // Save config
    let updated_config = serde_yaml::to_string(&config)?;
    fs::write(&config_path, updated_config)?;

    println!("{} Site '{}' created successfully", "✓".green(), name);
    println!("  Location: {}", location);
    println!("  Address:  {}", address);

    Ok(())
}

async fn list_sites(config_path: PathBuf) -> anyhow::Result<()> {
    // Load config
    let config_content = fs::read_to_string(&config_path)?;
    let config: serde_json::Value = serde_yaml::from_str(&config_content)?;

    let empty_vec = vec![];
    let sites = config["sites"].as_array().unwrap_or(&empty_vec);

    if sites.is_empty() {
        println!("{}", "No sites configured".yellow());
        println!();
        println!("Create a site with: {} patronus site create <name> --location <location> --address <ip>", "$".bright_yellow());
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "Name".bold(),
        "Location".bold(),
        "Address".bold(),
        "Status".bold(),
        "ID".bold()
    ]);

    for site in sites {
        let name = site["name"].as_str().unwrap_or("N/A");
        let location = site["location"].as_str().unwrap_or("N/A");
        let address = site["address"].as_str().unwrap_or("N/A");
        let enabled = site["enabled"].as_bool().unwrap_or(false);
        let id = site["id"].as_str().unwrap_or("N/A");

        let status = if enabled {
            "Active".green().to_string()
        } else {
            "Inactive".red().to_string()
        };

        table.add_row(vec![name, location, address, &status, id]);
    }

    println!();
    println!("{}", table);
    println!();
    println!("Total sites: {}", sites.len().to_string().bright_blue().bold());
    println!();

    Ok(())
}

async fn show_site(site: String, config_path: PathBuf) -> anyhow::Result<()> {
    // Load config
    let config_content = fs::read_to_string(&config_path)?;
    let config: serde_json::Value = serde_yaml::from_str(&config_content)?;

    let empty_vec = vec![];
    let sites = config["sites"].as_array().unwrap_or(&empty_vec);

    // Find site by name or ID
    let found_site = sites.iter().find(|s| {
        s["name"].as_str() == Some(&site) || s["id"].as_str() == Some(&site)
    });

    match found_site {
        Some(site_data) => {
            println!();
            println!("{}", "━".repeat(60).bright_blue());
            println!("  {} {}", "Site:".bright_blue().bold(), site_data["name"].as_str().unwrap_or("N/A"));
            println!("{}", "━".repeat(60).bright_blue());
            println!();
            println!("  {:<15} {}", "ID:".bold(), site_data["id"].as_str().unwrap_or("N/A"));
            println!("  {:<15} {}", "Location:".bold(), site_data["location"].as_str().unwrap_or("N/A"));
            println!("  {:<15} {}", "Address:".bold(), site_data["address"].as_str().unwrap_or("N/A"));
            println!("  {:<15} {}", "Status:".bold(), if site_data["enabled"].as_bool().unwrap_or(false) { "Active".green() } else { "Inactive".red() });
            println!("  {:<15} {}", "Created:".bold(), site_data["created_at"].as_str().unwrap_or("N/A"));
            println!();
        }
        None => {
            println!("{} Site '{}' not found", "✗".red(), site);
        }
    }

    Ok(())
}

async fn delete_site(site: String, config_path: PathBuf) -> anyhow::Result<()> {
    println!("{} Deleting site '{}'...", "→".bright_blue(), site);

    // Load config
    let config_content = fs::read_to_string(&config_path)?;
    let mut config: serde_json::Value = serde_yaml::from_str(&config_content)?;

    // Remove site
    if let Some(sites) = config["sites"].as_array_mut() {
        sites.retain(|s| {
            s["name"].as_str() != Some(&site) && s["id"].as_str() != Some(&site)
        });
    }

    // Save config
    let updated_config = serde_yaml::to_string(&config)?;
    fs::write(&config_path, updated_config)?;

    println!("{} Site '{}' deleted successfully", "✓".green(), site);

    Ok(())
}
