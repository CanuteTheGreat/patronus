//! XDP Statistics

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XdpStats {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub packets_dropped: u64,
    pub packets_passed: u64,
    pub pps: u64,  // Packets per second
    pub gbps: f64,  // Gigabits per second
}

impl XdpStats {
    pub fn throughput_gbps(&self) -> f64 {
        (self.bytes_processed as f64 * 8.0) / 1_000_000_000.0
    }

    pub fn drop_rate(&self) -> f64 {
        if self.packets_processed == 0 {
            0.0
        } else {
            (self.packets_dropped as f64 / self.packets_processed as f64) * 100.0
        }
    }
}
