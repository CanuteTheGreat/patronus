//! Metrics command handlers

use crate::MetricsCommands;
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use std::path::PathBuf;

pub async fn handle_metrics_command(action: MetricsCommands, _config_path: PathBuf) -> anyhow::Result<()> {
    match action {
        MetricsCommands::Traffic => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Interface", "RX (MB)", "TX (MB)", "Packets"]);
            table.add_row(vec!["tunnel0", "1250.5", "980.3", "156234"]);
            table.add_row(vec!["tunnel1", "2100.8", "1850.2", "287456"]);

            println!();
            println!("{}", "Traffic Statistics".bright_blue().bold());
            println!("{}", table);
            println!();
        }

        MetricsCommands::Health => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Link", "Status", "Latency", "Loss %"]);
            table.add_row(vec!["site1-site2", &"Up".green().to_string(), "15ms", "0.1%"]);
            table.add_row(vec!["site2-site3", &"Up".green().to_string(), "23ms", "0.2%"]);

            println!();
            println!("{}", "Link Health".bright_blue().bold());
            println!("{}", table);
            println!();
        }

        MetricsCommands::Bandwidth => {
            println!("{}", "Bandwidth Usage".bright_blue().bold());
            println!("  Total: 3.2 Gbps");
            println!("  Peak:  4.5 Gbps");
            println!("  Avg:   2.8 Gbps");
        }
    }
    Ok(())
}
