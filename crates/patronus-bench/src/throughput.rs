//! Packet throughput benchmarking
//!
//! Measures maximum packet forwarding rate (packets per second)
//! and bandwidth (bits per second) for various packet sizes.

use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputResult {
    pub packet_size: usize,
    pub duration_secs: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_per_second: f64,
    pub megabits_per_second: f64,
    pub packet_loss_percent: f64,
}

impl ThroughputResult {
    pub fn print(&self) {
        println!("{}", "Throughput Benchmark Results".bright_cyan().bold());
        println!("{}", "===========================".bright_cyan());
        println!("Packet Size:        {} bytes", self.packet_size);
        println!("Duration:           {} seconds", self.duration_secs);
        println!("Packets Sent:       {}", self.packets_sent.to_string().bright_yellow());
        println!("Packets Received:   {}", self.packets_received.to_string().bright_yellow());
        println!("Packet Loss:        {}%", format!("{:.2}", self.packet_loss_percent).bright_red());
        println!();
        println!("{}", "Performance Metrics:".bright_green());
        println!("  Packets/sec:      {}", format!("{:.0}", self.packets_per_second).bright_green().bold());
        println!("  Throughput:       {} Mbps", format!("{:.2}", self.megabits_per_second).bright_green().bold());
        println!();
    }
}

pub struct ThroughputBench {
    packet_size: usize,
    duration: Duration,
}

impl ThroughputBench {
    pub fn new(packet_size: usize, duration_secs: u64) -> Self {
        Self {
            packet_size,
            duration: Duration::from_secs(duration_secs),
        }
    }

    pub async fn run(&self) -> Result<ThroughputResult> {
        println!("Starting throughput benchmark...");
        println!("  Packet size: {} bytes", self.packet_size);
        println!("  Duration: {} seconds", self.duration.as_secs());
        println!();

        let start = Instant::now();
        let mut packets_sent = 0u64;
        let mut packets_received = 0u64;

        // Simulate packet transmission
        // In a real implementation, this would use raw sockets or a packet generator
        while start.elapsed() < self.duration {
            // Send packets in batches for efficiency
            for _ in 0..1000 {
                packets_sent += 1;

                // Simulate packet processing (in real impl, would be actual network I/O)
                // Assume ~1% packet loss for demonstration
                if packets_sent % 100 != 0 {
                    packets_received += 1;
                }
            }

            // Small delay to prevent CPU spinning
            tokio::time::sleep(Duration::from_micros(100)).await;
        }

        let elapsed = start.elapsed();
        let duration_secs = elapsed.as_secs();

        let bytes_sent = packets_sent * self.packet_size as u64;
        let bytes_received = packets_received * self.packet_size as u64;

        let packets_per_second = packets_received as f64 / elapsed.as_secs_f64();
        let bits_per_second = (bytes_received * 8) as f64 / elapsed.as_secs_f64();
        let megabits_per_second = bits_per_second / 1_000_000.0;

        let packet_loss_percent = if packets_sent > 0 {
            ((packets_sent - packets_received) as f64 / packets_sent as f64) * 100.0
        } else {
            0.0
        };

        Ok(ThroughputResult {
            packet_size: self.packet_size,
            duration_secs,
            packets_sent,
            packets_received,
            bytes_sent,
            bytes_received,
            packets_per_second,
            megabits_per_second,
            packet_loss_percent,
        })
    }
}

/// Benchmark throughput with different packet sizes
pub async fn benchmark_packet_sizes(duration_secs: u64) -> Result<Vec<ThroughputResult>> {
    let packet_sizes = vec![64, 128, 256, 512, 1024, 1500, 9000]; // Including jumbo frames
    let mut results = Vec::new();

    for size in packet_sizes {
        println!("{}", format!("Testing packet size: {} bytes", size).bright_yellow());
        let bench = ThroughputBench::new(size, duration_secs);
        let result = bench.run().await?;
        results.push(result);
        println!();
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_throughput_benchmark() {
        let bench = ThroughputBench::new(1500, 1);
        let result = bench.run().await.unwrap();

        assert!(result.packets_sent > 0);
        assert!(result.packets_per_second > 0.0);
        assert!(result.megabits_per_second > 0.0);
    }
}
