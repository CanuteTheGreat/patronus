//! Latency benchmarking - measures packet round-trip time

use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyResult {
    pub count: usize,
    pub packet_size: usize,
    pub min_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
    pub median_us: f64,
    pub stddev_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
}

impl LatencyResult {
    pub fn print(&self) {
        println!("{}", "Latency Benchmark Results".bright_cyan().bold());
        println!("{}", "========================".bright_cyan());
        println!("Packet Count:       {}", self.count);
        println!("Packet Size:        {} bytes", self.packet_size);
        println!();
        println!("{}", "Latency Statistics (microseconds):".bright_green());
        println!("  Minimum:          {:.2} μs", self.min_us);
        println!("  Maximum:          {:.2} μs", self.max_us);
        println!("  Mean:             {:.2} μs", self.mean_us);
        println!("  Median:           {:.2} μs", self.median_us);
        println!("  Std Deviation:    {:.2} μs", self.stddev_us);
        println!("  95th Percentile:  {:.2} μs", self.p95_us);
        println!("  99th Percentile:  {:.2} μs", self.p99_us);
        println!();
    }
}

pub struct LatencyBench {
    count: usize,
    packet_size: usize,
}

impl LatencyBench {
    pub fn new(count: usize, packet_size: usize) -> Self {
        Self { count, packet_size }
    }

    pub async fn run(&self) -> Result<LatencyResult> {
        println!("Starting latency benchmark...");
        println!("  Packet count: {}", self.count);
        println!("  Packet size: {} bytes", self.packet_size);
        println!();

        let mut latencies: Vec<f64> = Vec::with_capacity(self.count);

        for i in 0..self.count {
            let start = Instant::now();

            // Simulate packet round-trip
            // In real implementation, would send ICMP echo request and wait for reply
            tokio::time::sleep(Duration::from_micros(50 + (i % 10) as u64)).await;

            let elapsed = start.elapsed().as_micros() as f64;
            latencies.push(elapsed);

            if (i + 1) % 100 == 0 {
                print!("\r  Progress: {}/{}", i + 1, self.count);
                use std::io::{self, Write};
                io::stdout().flush().unwrap();
            }
        }
        println!();

        // Calculate statistics
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min_us = latencies[0];
        let max_us = latencies[latencies.len() - 1];
        let mean_us = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let median_us = latencies[latencies.len() / 2];

        // Standard deviation
        let variance = latencies.iter()
            .map(|v| {
                let diff = mean_us - v;
                diff * diff
            })
            .sum::<f64>() / latencies.len() as f64;
        let stddev_us = variance.sqrt();

        // Percentiles
        let p95_index = (latencies.len() as f64 * 0.95) as usize;
        let p99_index = (latencies.len() as f64 * 0.99) as usize;
        let p95_us = latencies[p95_index];
        let p99_us = latencies[p99_index];

        Ok(LatencyResult {
            count: self.count,
            packet_size: self.packet_size,
            min_us,
            max_us,
            mean_us,
            median_us,
            stddev_us,
            p95_us,
            p99_us,
        })
    }
}
