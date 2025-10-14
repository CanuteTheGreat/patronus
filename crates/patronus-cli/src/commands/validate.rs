//! Validate command handler

use colored::Colorize;
use std::path::PathBuf;
use std::fs;

pub async fn handle_validate(file: PathBuf) -> anyhow::Result<()> {
    println!("{} Validating configuration {}...", "→".bright_blue(), file.display());

    let content = fs::read_to_string(&file)?;
    let _config: serde_json::Value = serde_yaml::from_str(&content)?;

    println!("{} Configuration is valid!", "✓".green().bold());

    Ok(())
}
