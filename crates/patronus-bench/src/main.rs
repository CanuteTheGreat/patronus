use clap::{Parser, Subcommand};
use colored::*;
use anyhow::Result;

mod throughput;
mod latency;
mod connection_rate;
mod cpu_memory;
mod firewall_rules;
mod nat_performance;
mod vpn_throughput;
mod report;

use throughput::ThroughputBench;
use latency::LatencyBench;
use connection_rate::ConnectionRateBench;
use cpu_memory::ResourceBench;
use firewall_rules::FirewallRuleBench;
use nat_performance::NatBench;
use vpn_throughput::VpnBench;
use report::BenchmarkReport;

#[derive(Parser)]
#[command(name = "patronus-bench")]
#[command(about = "Patronus Firewall Performance Benchmarking Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all benchmarks
    All {
        /// Output file for results
        #[arg(short, long, default_value = "benchmark-results.json")]
        output: String,

        /// Duration in seconds for each test
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Benchmark packet throughput
    Throughput {
        /// Packet size in bytes
        #[arg(short, long, default_value = "1500")]
        packet_size: usize,

        /// Duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Benchmark latency
    Latency {
        /// Number of pings
        #[arg(short, long, default_value = "1000")]
        count: usize,

        /// Packet size in bytes
        #[arg(short, long, default_value = "64")]
        size: usize,
    },

    /// Benchmark connection rate (new connections per second)
    ConnectionRate {
        /// Duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// Number of parallel workers
        #[arg(short, long, default_value = "4")]
        workers: usize,
    },

    /// Benchmark CPU and memory usage
    Resources {
        /// Monitoring duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,

        /// Sample interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },

    /// Benchmark firewall rule performance
    FirewallRules {
        /// Number of rules to test
        #[arg(short, long, value_parser = clap::value_parser!(u32).range(100..=100000))]
        rules: u32,

        /// Test packet throughput with rules
        #[arg(long)]
        throughput: bool,
    },

    /// Benchmark NAT performance
    Nat {
        /// Number of concurrent NAT sessions
        #[arg(short, long, default_value = "10000")]
        sessions: usize,

        /// Duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Benchmark VPN throughput
    Vpn {
        /// VPN type (wireguard, openvpn, ipsec)
        #[arg(short, long, default_value = "wireguard")]
        vpn_type: String,

        /// Duration in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Compare with pfSense/OPNsense
    Compare {
        /// Path to competitor results JSON
        #[arg(short, long)]
        competitor_results: String,

        /// Run benchmarks first
        #[arg(long)]
        run_first: bool,
    },

    /// Generate benchmark report
    Report {
        /// Input JSON file
        #[arg(short, long)]
        input: String,

        /// Output format (html, markdown, pdf)
        #[arg(short, long, default_value = "html")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    println!("{}", "Patronus Firewall Performance Benchmarking Suite".bright_cyan().bold());
    println!("{}", "==============================================".bright_cyan());
    println!();

    match cli.command {
        Commands::All { output, duration } => {
            run_all_benchmarks(&output, duration).await?;
        }
        Commands::Throughput { packet_size, duration } => {
            let bench = ThroughputBench::new(packet_size, duration);
            let result = bench.run().await?;
            result.print();
        }
        Commands::Latency { count, size } => {
            let bench = LatencyBench::new(count, size);
            let result = bench.run().await?;
            result.print();
        }
        Commands::ConnectionRate { duration, workers } => {
            let bench = ConnectionRateBench::new(duration, workers);
            let result = bench.run().await?;
            result.print();
        }
        Commands::Resources { duration, interval } => {
            let bench = ResourceBench::new(duration, interval);
            let result = bench.run().await?;
            result.print();
        }
        Commands::FirewallRules { rules, throughput } => {
            let bench = FirewallRuleBench::new(rules, throughput);
            let result = bench.run().await?;
            result.print();
        }
        Commands::Nat { sessions, duration } => {
            let bench = NatBench::new(sessions, duration);
            let result = bench.run().await?;
            result.print();
        }
        Commands::Vpn { vpn_type, duration } => {
            let bench = VpnBench::new(&vpn_type, duration);
            let result = bench.run().await?;
            result.print();
        }
        Commands::Compare { competitor_results, run_first } => {
            if run_first {
                run_all_benchmarks("patronus-results.json", 30).await?;
            }
            compare_results("patronus-results.json", &competitor_results)?;
        }
        Commands::Report { input, format } => {
            generate_report(&input, &format)?;
        }
    }

    Ok(())
}

async fn run_all_benchmarks(output: &str, duration: u64) -> Result<()> {
    println!("{}", "Running comprehensive benchmark suite...".yellow());
    println!();

    let mut report = BenchmarkReport::new();

    // 1. Throughput
    println!("{}", "1. Testing packet throughput...".bright_green());
    let throughput = ThroughputBench::new(1500, duration);
    report.throughput = Some(throughput.run().await?);

    // 2. Latency
    println!("{}", "2. Testing latency...".bright_green());
    let latency = LatencyBench::new(1000, 64);
    report.latency = Some(latency.run().await?);

    // 3. Connection rate
    println!("{}", "3. Testing connection rate...".bright_green());
    let conn_rate = ConnectionRateBench::new(duration, 4);
    report.connection_rate = Some(conn_rate.run().await?);

    // 4. Resources
    println!("{}", "4. Monitoring CPU/memory usage...".bright_green());
    let resources = ResourceBench::new(60, 1);
    report.resources = Some(resources.run().await?);

    // 5. Firewall rules
    println!("{}", "5. Testing firewall rule performance...".bright_green());
    let firewall = FirewallRuleBench::new(10000, true);
    report.firewall_rules = Some(firewall.run().await?);

    // 6. NAT
    println!("{}", "6. Testing NAT performance...".bright_green());
    let nat = NatBench::new(10000, duration);
    report.nat = Some(nat.run().await?);

    // 7. VPN
    println!("{}", "7. Testing VPN throughput...".bright_green());
    let vpn = VpnBench::new("wireguard", duration);
    report.vpn = Some(vpn.run().await?);

    // Save results
    report.save(output)?;

    println!();
    println!("{}", format!("✓ All benchmarks complete! Results saved to: {}", output).bright_green().bold());

    // Print summary
    report.print_summary();

    Ok(())
}

fn compare_results(patronus_file: &str, competitor_file: &str) -> Result<()> {
    let patronus = BenchmarkReport::load(patronus_file)?;
    let competitor = BenchmarkReport::load(competitor_file)?;

    println!("{}", "Performance Comparison".bright_cyan().bold());
    println!("{}", "====================".bright_cyan());
    println!();

    patronus.compare(&competitor);

    Ok(())
}

fn generate_report(input: &str, format: &str) -> Result<()> {
    let report = BenchmarkReport::load(input)?;

    match format {
        "html" => report.export_html("benchmark-report.html")?,
        "markdown" => report.export_markdown("benchmark-report.md")?,
        "pdf" => report.export_pdf("benchmark-report.pdf")?,
        _ => anyhow::bail!("Unsupported format: {}", format),
    }

    println!("{}", format!("✓ Report generated: benchmark-report.{}", format).bright_green());

    Ok(())
}
