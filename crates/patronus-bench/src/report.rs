//! Benchmark reporting and comparison

use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::connection_rate::ConnectionRateResult;
use crate::cpu_memory::ResourceResult;
use crate::firewall_rules::FirewallRuleResult;
use crate::latency::LatencyResult;
use crate::nat_performance::NatResult;
use crate::throughput::ThroughputResult;
use crate::vpn_throughput::VpnResult;

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub timestamp: String,
    pub patronus_version: String,
    pub system_info: SystemInfo,
    pub throughput: Option<ThroughputResult>,
    pub latency: Option<LatencyResult>,
    pub connection_rate: Option<ConnectionRateResult>,
    pub resources: Option<ResourceResult>,
    pub firewall_rules: Option<FirewallRuleResult>,
    pub nat: Option<NatResult>,
    pub vpn: Option<VpnResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub memory_gb: f64,
    pub network_interface: String,
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            os: "Linux".to_string(),
            kernel: "6.1.0".to_string(),
            cpu_model: "Intel Xeon".to_string(),
            cpu_cores: 8,
            memory_gb: 16.0,
            network_interface: "eth0".to_string(),
        }
    }
}

impl BenchmarkReport {
    pub fn new() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            patronus_version: env!("CARGO_PKG_VERSION").to_string(),
            system_info: SystemInfo::default(),
            throughput: None,
            latency: None,
            connection_rate: None,
            resources: None,
            firewall_rules: None,
            nat: None,
            vpn: None,
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let report = serde_json::from_str(&json)?;
        Ok(report)
    }

    pub fn print_summary(&self) {
        println!();
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "   PATRONUS FIREWALL BENCHMARK SUMMARY"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!();

        println!("{}", "System Information:".bright_yellow().bold());
        println!("  OS:              {}", self.system_info.os);
        println!("  Kernel:          {}", self.system_info.kernel);
        println!("  CPU:             {}", self.system_info.cpu_model);
        println!("  Cores:           {}", self.system_info.cpu_cores);
        println!("  Memory:          {:.1} GB", self.system_info.memory_gb);
        println!();

        if let Some(ref tp) = self.throughput {
            println!("{}", "Throughput:".bright_green().bold());
            println!(
                "  {} pps  |  {} Mbps",
                format!("{:.0}", tp.packets_per_second)
                    .bright_white()
                    .bold(),
                format!("{:.0}", tp.megabits_per_second)
                    .bright_white()
                    .bold()
            );
            println!();
        }

        if let Some(ref lat) = self.latency {
            println!("{}", "Latency:".bright_green().bold());
            println!(
                "  Mean: {:.1} μs  |  P95: {:.1} μs  |  P99: {:.1} μs",
                lat.mean_us, lat.p95_us, lat.p99_us
            );
            println!();
        }

        if let Some(ref conn) = self.connection_rate {
            println!("{}", "Connection Rate:".bright_green().bold());
            println!(
                "  {} connections/sec",
                format!("{:.0}", conn.connections_per_second)
                    .bright_white()
                    .bold()
            );
            println!();
        }

        if let Some(ref res) = self.resources {
            println!("{}", "Resource Usage:".bright_green().bold());
            println!(
                "  CPU: {:.1}% avg, {:.1}% peak",
                res.cpu_mean_percent, res.cpu_max_percent
            );
            println!(
                "  Memory: {:.0} MB avg, {:.0} MB peak",
                res.memory_mean_mb, res.memory_max_mb
            );
            println!();
        }

        if let Some(ref nat) = self.nat {
            println!("{}", "NAT Performance:".bright_green().bold());
            println!(
                "  {} concurrent sessions  |  {:.0} new sessions/sec",
                nat.max_concurrent_sessions, nat.new_sessions_per_second
            );
            println!();
        }

        if let Some(ref vpn) = self.vpn {
            println!(
                "{}",
                format!("{} VPN:", vpn.vpn_type.to_uppercase())
                    .bright_green()
                    .bold()
            );
            println!(
                "  {:.0} Mbps throughput  |  {:.1}% CPU overhead",
                vpn.throughput_mbps, vpn.cpu_overhead_percent
            );
            println!();
        }

        println!(
            "{}",
            "═══════════════════════════════════════"
                .bright_cyan()
                .bold()
        );
        println!();
    }

    pub fn compare(&self, other: &BenchmarkReport) {
        println!("{}", "Performance Comparison".bright_cyan().bold());
        println!(
            "{}",
            "─────────────────────────────────────────────────────────".bright_cyan()
        );
        println!(
            "{:30} {:>12} {:>12} {:>12}",
            "Metric".bold(),
            "Patronus".bold(),
            "Competitor".bold(),
            "Difference".bold()
        );
        println!(
            "{}",
            "─────────────────────────────────────────────────────────".bright_cyan()
        );

        if let (Some(ref tp1), Some(ref tp2)) = (&self.throughput, &other.throughput) {
            let diff = ((tp1.megabits_per_second - tp2.megabits_per_second)
                / tp2.megabits_per_second)
                * 100.0;
            let diff_str = if diff > 0.0 {
                format!("+{:.1}%", diff).bright_green().bold()
            } else {
                format!("{:.1}%", diff).bright_red().bold()
            };

            println!(
                "{:30} {:>12} {:>12} {:>12}",
                "Throughput (Mbps)",
                format!("{:.0}", tp1.megabits_per_second),
                format!("{:.0}", tp2.megabits_per_second),
                diff_str
            );
        }

        if let (Some(ref lat1), Some(ref lat2)) = (&self.latency, &other.latency) {
            let diff = ((lat1.mean_us - lat2.mean_us) / lat2.mean_us) * 100.0;
            let diff_str = if diff < 0.0 {
                format!("{:.1}%", diff).bright_green().bold()
            } else {
                format!("+{:.1}%", diff).bright_red().bold()
            };

            println!(
                "{:30} {:>12} {:>12} {:>12}",
                "Latency (μs)",
                format!("{:.1}", lat1.mean_us),
                format!("{:.1}", lat2.mean_us),
                diff_str
            );
        }

        if let (Some(ref conn1), Some(ref conn2)) = (&self.connection_rate, &other.connection_rate)
        {
            let diff = ((conn1.connections_per_second - conn2.connections_per_second)
                / conn2.connections_per_second)
                * 100.0;
            let diff_str = if diff > 0.0 {
                format!("+{:.1}%", diff).bright_green().bold()
            } else {
                format!("{:.1}%", diff).bright_red().bold()
            };

            println!(
                "{:30} {:>12} {:>12} {:>12}",
                "Connections/sec",
                format!("{:.0}", conn1.connections_per_second),
                format!("{:.0}", conn2.connections_per_second),
                diff_str
            );
        }

        if let (Some(ref res1), Some(ref res2)) = (&self.resources, &other.resources) {
            let diff =
                ((res1.cpu_mean_percent - res2.cpu_mean_percent) / res2.cpu_mean_percent) * 100.0;
            let diff_str = if diff < 0.0 {
                format!("{:.1}%", diff).bright_green().bold()
            } else {
                format!("+{:.1}%", diff).bright_red().bold()
            };

            println!(
                "{:30} {:>12} {:>12} {:>12}",
                "CPU Usage (%)",
                format!("{:.1}", res1.cpu_mean_percent),
                format!("{:.1}", res2.cpu_mean_percent),
                diff_str
            );
        }

        println!(
            "{}",
            "─────────────────────────────────────────────────────────".bright_cyan()
        );
        println!();
    }

    pub fn export_html(&self, path: &str) -> Result<()> {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>Patronus Firewall Benchmark Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .metric {{ font-weight: bold; color: #27ae60; }}
    </style>
</head>
<body>
    <h1>Patronus Firewall Benchmark Report</h1>
    <p><strong>Date:</strong> {}</p>
    <p><strong>Version:</strong> {}</p>
    <pre>{}</pre>
</body>
</html>
        "#,
            self.timestamp,
            self.patronus_version,
            serde_json::to_string_pretty(self)?
        );

        fs::write(path, html)?;
        Ok(())
    }

    pub fn export_markdown(&self, path: &str) -> Result<()> {
        let mut md = String::new();
        md.push_str("# Patronus Firewall Benchmark Report\n\n");
        md.push_str(&format!("**Date:** {}\n", self.timestamp));
        md.push_str(&format!("**Version:** {}\n\n", self.patronus_version));

        if let Some(ref tp) = self.throughput {
            md.push_str("## Throughput\n\n");
            md.push_str(&format!("- Packets/sec: {:.0}\n", tp.packets_per_second));
            md.push_str(&format!(
                "- Throughput: {:.2} Mbps\n\n",
                tp.megabits_per_second
            ));
        }

        if let Some(ref lat) = self.latency {
            md.push_str("## Latency\n\n");
            md.push_str(&format!("- Mean: {:.2} μs\n", lat.mean_us));
            md.push_str(&format!("- P95: {:.2} μs\n", lat.p95_us));
            md.push_str(&format!("- P99: {:.2} μs\n\n", lat.p99_us));
        }

        fs::write(path, md)?;
        Ok(())
    }

    pub fn export_pdf(&self, path: &str) -> Result<()> {
        use printpdf::{BuiltinFont, Mm, PdfDocument};
        use std::io::BufWriter;

        const PAGE_WIDTH: f32 = 210.0; // A4 mm
        const PAGE_HEIGHT: f32 = 297.0;
        const MARGIN: f32 = 15.0;
        const LINE_HEIGHT: f32 = 6.0;
        const FONT_SIZE_TITLE: f32 = 16.0;
        const FONT_SIZE_HEADING: f32 = 12.0;
        const FONT_SIZE_BODY: f32 = 10.0;

        // Build the report as a list of (text, is_heading) lines, reusing the
        // same data model as export_markdown/export_html.
        let mut lines: Vec<(String, bool)> = Vec::new();
        lines.push(("Patronus Firewall Benchmark Report".to_string(), true));
        lines.push((format!("Date: {}", self.timestamp), false));
        lines.push((format!("Version: {}", self.patronus_version), false));
        lines.push(("".to_string(), false));

        lines.push(("System Information".to_string(), true));
        lines.push((format!("OS: {}", self.system_info.os), false));
        lines.push((format!("Kernel: {}", self.system_info.kernel), false));
        lines.push((format!("CPU: {}", self.system_info.cpu_model), false));
        lines.push((format!("Cores: {}", self.system_info.cpu_cores), false));
        lines.push((
            format!("Memory: {:.1} GB", self.system_info.memory_gb),
            false,
        ));
        lines.push((
            format!("Network Interface: {}", self.system_info.network_interface),
            false,
        ));
        lines.push(("".to_string(), false));

        if let Some(ref tp) = self.throughput {
            lines.push(("Throughput".to_string(), true));
            lines.push((
                format!("Packets/sec: {:.0}", tp.packets_per_second),
                false,
            ));
            lines.push((
                format!("Throughput: {:.2} Mbps", tp.megabits_per_second),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        if let Some(ref lat) = self.latency {
            lines.push(("Latency".to_string(), true));
            lines.push((format!("Mean: {:.2} us", lat.mean_us), false));
            lines.push((format!("Median: {:.2} us", lat.median_us), false));
            lines.push((format!("Min: {:.2} us", lat.min_us), false));
            lines.push((format!("Max: {:.2} us", lat.max_us), false));
            lines.push((format!("StdDev: {:.2} us", lat.stddev_us), false));
            lines.push((format!("P95: {:.2} us", lat.p95_us), false));
            lines.push((format!("P99: {:.2} us", lat.p99_us), false));
            lines.push(("".to_string(), false));
        }

        if let Some(ref conn) = self.connection_rate {
            lines.push(("Connection Rate".to_string(), true));
            lines.push((
                format!("Duration: {} sec", conn.duration_secs),
                false,
            ));
            lines.push((
                format!("Total Connections: {}", conn.total_connections),
                false,
            ));
            lines.push((
                format!("Successful: {}", conn.successful_connections),
                false,
            ));
            lines.push((format!("Failed: {}", conn.failed_connections), false));
            lines.push((
                format!(
                    "Connections/sec: {:.0}",
                    conn.connections_per_second
                ),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        if let Some(ref res) = self.resources {
            lines.push(("Resource Usage".to_string(), true));
            lines.push((
                format!(
                    "CPU: {:.1}% avg, {:.1}% peak",
                    res.cpu_mean_percent, res.cpu_max_percent
                ),
                false,
            ));
            lines.push((
                format!(
                    "Memory: {:.0} MB avg, {:.0} MB peak",
                    res.memory_mean_mb, res.memory_max_mb
                ),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        if let Some(ref fw) = self.firewall_rules {
            lines.push(("Firewall Rule Performance".to_string(), true));
            lines.push((format!("Rule Count: {}", fw.rule_count), false));
            lines.push((
                format!("Lookup Time: {:.2} ns", fw.lookup_time_ns),
                false,
            ));
            lines.push((
                format!(
                    "Throughput Impact: {:.2}%",
                    fw.throughput_impact_percent
                ),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        if let Some(ref nat) = self.nat {
            lines.push(("NAT Performance".to_string(), true));
            lines.push((
                format!(
                    "Max Concurrent Sessions: {}",
                    nat.max_concurrent_sessions
                ),
                false,
            ));
            lines.push((
                format!(
                    "New Sessions/sec: {:.0}",
                    nat.new_sessions_per_second
                ),
                false,
            ));
            lines.push((
                format!("Throughput: {:.0} Mbps", nat.throughput_mbps),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        if let Some(ref vpn) = self.vpn {
            lines.push((format!("{} VPN", vpn.vpn_type.to_uppercase()), true));
            lines.push((
                format!("Throughput: {:.0} Mbps", vpn.throughput_mbps),
                false,
            ));
            lines.push((
                format!("CPU Overhead: {:.1}%", vpn.cpu_overhead_percent),
                false,
            ));
            lines.push(("".to_string(), false));
        }

        // Render the lines into a paginated PDF document using a built-in
        // font (no embedded font files/assets needed).
        let (doc, page1, layer1) =
            PdfDocument::new("Patronus Firewall Benchmark Report", Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Layer 1");
        let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

        let mut page = page1;
        let mut layer = doc.get_page(page).get_layer(layer1);
        let mut cursor_y = PAGE_HEIGHT - MARGIN;

        for (text, is_heading) in &lines {
            if cursor_y < MARGIN + LINE_HEIGHT {
                let (new_page, new_layer) =
                    doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Layer 1");
                page = new_page;
                layer = doc.get_page(page).get_layer(new_layer);
                cursor_y = PAGE_HEIGHT - MARGIN;
            }

            let (use_font, size) = if *is_heading {
                (&font_bold, if cursor_y > PAGE_HEIGHT - MARGIN - LINE_HEIGHT {
                    FONT_SIZE_TITLE
                } else {
                    FONT_SIZE_HEADING
                })
            } else {
                (&font, FONT_SIZE_BODY)
            };

            if !text.is_empty() {
                layer.use_text(text.as_str(), size, Mm(MARGIN), Mm(cursor_y), use_font);
            }

            cursor_y -= LINE_HEIGHT;
        }

        doc.save(&mut BufWriter::new(fs::File::create(path)?))?;
        Ok(())
    }
}

impl Default for BenchmarkReport {
    fn default() -> Self {
        Self::new()
    }
}
