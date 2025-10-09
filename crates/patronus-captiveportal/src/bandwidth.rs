//! Bandwidth limiting for guest users

use std::collections::HashMap;
use tokio::process::Command;

pub struct BandwidthLimiter {
    limits: tokio::sync::RwLock<HashMap<String, BandwidthLimit>>,
}

#[derive(Debug, Clone)]
pub struct BandwidthLimit {
    pub download_kbps: u64,
    pub upload_kbps: u64,
}

impl BandwidthLimiter {
    pub fn new() -> Self {
        Self {
            limits: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn set_limit(&self, mac: &str, download_kbps: u64, upload_kbps: u64) {
        let limit = BandwidthLimit { download_kbps, upload_kbps };

        // Apply tc rules
        self.apply_tc_limit(mac, &limit).await;

        let mut limits = self.limits.write().await;
        limits.insert(mac.to_string(), limit);
    }

    pub async fn remove_limit(&self, mac: &str) {
        self.remove_tc_limit(mac).await;

        let mut limits = self.limits.write().await;
        limits.remove(mac);
    }

    async fn apply_tc_limit(&self, mac: &str, limit: &BandwidthLimit) {
        // Use Linux tc (traffic control) to limit bandwidth
        // Example: tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ether src AA:BB:CC:DD:EE:FF flowid 1:10
        // Then: tc class add dev eth0 parent 1:0 classid 1:10 htb rate 1mbit ceil 1mbit

        let _ = Command::new("tc")
            .args(&["class", "add", "dev", "eth0", "parent", "1:0"])
            .output()
            .await;
    }

    async fn remove_tc_limit(&self, mac: &str) {
        // Remove tc rules for this MAC
    }
}
