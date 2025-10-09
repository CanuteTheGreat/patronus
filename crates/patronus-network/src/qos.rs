//! Traffic Shaping and Quality of Service (QoS)
//!
//! Provides traffic control using Linux tc (traffic control) with HTB, FQ-CoDel,
//! and other modern queueing disciplines.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Queueing discipline (qdisc) type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QdiscType {
    Htb,       // Hierarchical Token Bucket
    Sfq,       // Stochastic Fairness Queueing
    FqCodel,   // Fair/Flow Queue CoDel
    Cake,      // Common Applications Kept Enhanced
    Tbf,       // Token Bucket Filter
    Pfifo,     // Packet-limited First In, First Out
    Bfifo,     // Byte-limited First In, First Out
}

impl std::fmt::Display for QdiscType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Htb => write!(f, "htb"),
            Self::Sfq => write!(f, "sfq"),
            Self::FqCodel => write!(f, "fq_codel"),
            Self::Cake => write!(f, "cake"),
            Self::Tbf => write!(f, "tbf"),
            Self::Pfifo => write!(f, "pfifo"),
            Self::Bfifo => write!(f, "bfifo"),
        }
    }
}

/// Traffic class priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrafficPriority {
    Realtime,    // VoIP, gaming
    High,        // Interactive, video
    Medium,      // Normal traffic
    Low,         // Bulk transfers
    Lowest,      // Background
}

/// HTB class configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtbClass {
    pub name: String,
    pub interface: String,
    pub parent: Option<String>,  // Parent class ID (e.g., "1:1")
    pub class_id: String,        // This class ID (e.g., "1:10")

    // Rate limits
    pub rate: String,      // Guaranteed rate (e.g., "1mbit", "100kbit")
    pub ceil: String,      // Maximum rate (burst ceiling)
    pub burst: Option<String>,  // Burst size

    // Priority
    pub priority: u8,      // 0-7, lower = higher priority

    // Matching rules
    pub match_dst_port: Option<u16>,
    pub match_src_port: Option<u16>,
    pub match_protocol: Option<String>,  // tcp, udp, icmp
    pub match_dst_network: Option<String>,  // CIDR
    pub match_src_network: Option<String>,
    pub match_tos: Option<u8>,  // Type of Service
    pub match_mark: Option<u32>,  // Packet mark
}

/// Traffic shaping rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapingRule {
    pub name: String,
    pub enabled: bool,
    pub interface: String,
    pub direction: TrafficDirection,

    // Root qdisc
    pub qdisc_type: QdiscType,

    // Classes (for HTB)
    pub classes: Vec<HtbClass>,
}

/// Traffic direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrafficDirection {
    Ingress,   // Incoming traffic
    Egress,    // Outgoing traffic
}

/// Simple bandwidth limiter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthLimit {
    pub interface: String,
    pub download_rate: String,  // e.g., "100mbit"
    pub upload_rate: String,
}

/// QoS manager
pub struct QosManager;

impl QosManager {
    /// Create a new QoS manager
    pub fn new() -> Self {
        Self
    }

    /// Initialize traffic control on an interface
    pub async fn init_interface(&self, interface: &str) -> Result<()> {
        // Remove existing qdisc
        self.clear_interface(interface).await.ok();

        // Add root qdisc (HTB)
        Command::new("tc")
            .args(&["qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"])
            .output()
            .map_err(|e| Error::Network(format!("Failed to initialize QoS: {}", e)))?;

        Ok(())
    }

    /// Clear all traffic control rules from an interface
    pub async fn clear_interface(&self, interface: &str) -> Result<()> {
        Command::new("tc")
            .args(&["qdisc", "del", "dev", interface, "root"])
            .output()
            .ok();  // Ignore errors (might not exist)

        Ok(())
    }

    /// Add an HTB class
    pub async fn add_htb_class(&self, class: &HtbClass) -> Result<()> {
        let mut args = vec![
            "class", "add", "dev", &class.interface,
            "parent", class.parent.as_deref().unwrap_or("1:"),
            "classid", &class.class_id,
            "htb",
            "rate", &class.rate,
            "ceil", &class.ceil,
            "prio", &class.priority.to_string(),
        ];

        if let Some(burst) = &class.burst {
            args.extend(&["burst", burst]);
        }

        Command::new("tc")
            .args(&args)
            .output()
            .map_err(|e| Error::Network(format!("Failed to add HTB class: {}", e)))?;

        // Add leaf qdisc (fq_codel for fair queueing)
        Command::new("tc")
            .args(&[
                "qdisc", "add", "dev", &class.interface,
                "parent", &class.class_id,
                "handle", &format!("{}0:", &class.class_id.replace(":", "")),
                "fq_codel"
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to add leaf qdisc: {}", e)))?;

        Ok(())
    }

    /// Add a filter to match traffic to a class
    pub async fn add_filter(&self, class: &HtbClass) -> Result<()> {
        let class_num = class.class_id.split(':').nth(1)
            .ok_or_else(|| Error::Network("Invalid class ID format".to_string()))?;

        let handle_id = format!("0x{:x}", class_num.parse::<u32>()
            .map_err(|_| Error::Network("Invalid class number".to_string()))?);

        // Add u32 filter
        let mut filter_args = vec![
            "filter", "add", "dev", &class.interface,
            "parent", "1:",
            "protocol", "ip",
            "prio", &class.priority.to_string(),
            "u32"
        ];

        // Build match expression
        let mut match_expr = String::new();

        if let Some(port) = class.match_dst_port {
            match_expr.push_str(&format!("match ip dport {} 0xffff ", port));
        }

        if let Some(port) = class.match_src_port {
            match_expr.push_str(&format!("match ip sport {} 0xffff ", port));
        }

        if let Some(proto) = &class.match_protocol {
            let proto_num = match proto.as_str() {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                _ => return Err(Error::Network("Unknown protocol".to_string())),
            };
            match_expr.push_str(&format!("match ip protocol {} 0xff ", proto_num));
        }

        if !match_expr.is_empty() {
            filter_args.push("match");
            for part in match_expr.split_whitespace() {
                filter_args.push(part);
            }
        }

        filter_args.extend(&["flowid", &class.class_id]);

        Command::new("tc")
            .args(&filter_args)
            .output()
            .map_err(|e| Error::Network(format!("Failed to add filter: {}", e)))?;

        Ok(())
    }

    /// Apply a complete shaping rule
    pub async fn apply_shaping_rule(&self, rule: &ShapingRule) -> Result<()> {
        if !rule.enabled {
            return Ok(());
        }

        // Initialize interface
        self.init_interface(&rule.interface).await?;

        // Add root class
        Command::new("tc")
            .args(&[
                "class", "add", "dev", &rule.interface,
                "parent", "1:",
                "classid", "1:1",
                "htb",
                "rate", "1000mbit"  // Maximum link rate
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to add root class: {}", e)))?;

        // Add all classes
        for class in &rule.classes {
            self.add_htb_class(class).await?;
            self.add_filter(class).await?;
        }

        Ok(())
    }

    /// Apply simple bandwidth limit
    pub async fn apply_bandwidth_limit(&self, limit: &BandwidthLimit) -> Result<()> {
        // Egress (upload) limit
        self.clear_interface(&limit.interface).await.ok();

        Command::new("tc")
            .args(&[
                "qdisc", "add", "dev", &limit.interface,
                "root", "tbf",
                "rate", &limit.upload_rate,
                "burst", "32kbit",
                "latency", "400ms"
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to set upload limit: {}", e)))?;

        // Ingress (download) limit requires IFB (intermediate functional block)
        // This is more complex and would need ifb module loaded
        // For now, just set egress

        Ok(())
    }

    /// Create a preset for gaming traffic
    pub fn create_gaming_preset(&self, interface: &str, total_bandwidth: &str) -> ShapingRule {
        ShapingRule {
            name: "Gaming Priority".to_string(),
            enabled: true,
            interface: interface.to_string(),
            direction: TrafficDirection::Egress,
            qdisc_type: QdiscType::Htb,
            classes: vec![
                // Gaming traffic - highest priority, 30% bandwidth guarantee
                HtbClass {
                    name: "Gaming".to_string(),
                    interface: interface.to_string(),
                    parent: Some("1:1".to_string()),
                    class_id: "1:10".to_string(),
                    rate: format!("{}mbit", 30),  // 30% of bandwidth
                    ceil: total_bandwidth.to_string(),
                    burst: Some("15k".to_string()),
                    priority: 0,
                    match_dst_port: None,  // Would match specific game ports
                    match_src_port: None,
                    match_protocol: Some("udp".to_string()),
                    match_dst_network: None,
                    match_src_network: None,
                    match_tos: Some(0x10),  // Low delay
                    match_mark: Some(1),
                },
                // Video streaming - high priority, 40% guarantee
                HtbClass {
                    name: "Streaming".to_string(),
                    interface: interface.to_string(),
                    parent: Some("1:1".to_string()),
                    class_id: "1:20".to_string(),
                    rate: format!("{}mbit", 40),
                    ceil: total_bandwidth.to_string(),
                    burst: Some("15k".to_string()),
                    priority: 1,
                    match_dst_port: Some(443),  // HTTPS streaming
                    match_src_port: None,
                    match_protocol: Some("tcp".to_string()),
                    match_dst_network: None,
                    match_src_network: None,
                    match_tos: None,
                    match_mark: Some(2),
                },
                // Bulk downloads - lowest priority, 30% guarantee
                HtbClass {
                    name: "Bulk".to_string(),
                    interface: interface.to_string(),
                    parent: Some("1:1".to_string()),
                    class_id: "1:30".to_string(),
                    rate: format!("{}mbit", 30),
                    ceil: total_bandwidth.to_string(),
                    burst: Some("15k".to_string()),
                    priority: 7,
                    match_dst_port: None,
                    match_src_port: None,
                    match_protocol: None,
                    match_dst_network: None,
                    match_src_network: None,
                    match_tos: Some(0x08),  // High throughput
                    match_mark: Some(3),
                },
            ],
        }
    }

    /// Create a preset for VoIP traffic
    pub fn create_voip_preset(&self, interface: &str) -> ShapingRule {
        ShapingRule {
            name: "VoIP Priority".to_string(),
            enabled: true,
            interface: interface.to_string(),
            direction: TrafficDirection::Egress,
            qdisc_type: QdiscType::Htb,
            classes: vec![
                HtbClass {
                    name: "VoIP".to_string(),
                    interface: interface.to_string(),
                    parent: Some("1:1".to_string()),
                    class_id: "1:10".to_string(),
                    rate: "512kbit".to_string(),
                    ceil: "2mbit".to_string(),
                    burst: Some("10k".to_string()),
                    priority: 0,
                    match_dst_port: Some(5060),  // SIP
                    match_src_port: None,
                    match_protocol: Some("udp".to_string()),
                    match_dst_network: None,
                    match_src_network: None,
                    match_tos: Some(0xb8),  // EF (Expedited Forwarding)
                    match_mark: None,
                },
            ],
        }
    }

    /// Get current traffic control statistics
    pub async fn get_stats(&self, interface: &str) -> Result<String> {
        let output = Command::new("tc")
            .args(&["-s", "qdisc", "show", "dev", interface])
            .output()
            .map_err(|e| Error::Network(format!("Failed to get stats: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get class statistics
    pub async fn get_class_stats(&self, interface: &str) -> Result<String> {
        let output = Command::new("tc")
            .args(&["-s", "class", "show", "dev", interface])
            .output()
            .map_err(|e| Error::Network(format!("Failed to get class stats: {}", e)))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Enable CAKE qdisc (modern, all-in-one QoS)
    pub async fn enable_cake(&self, interface: &str, bandwidth: &str) -> Result<()> {
        self.clear_interface(interface).await.ok();

        Command::new("tc")
            .args(&[
                "qdisc", "add", "dev", interface,
                "root", "cake",
                "bandwidth", bandwidth,
                "triple-isolate",  // Per-host + per-flow fairness
                "diffserv4",       // 4-tier priority
                "ack-filter"       // ACK acceleration
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to enable CAKE: {}", e)))?;

        Ok(())
    }

    /// Enable FQ-CoDel (Fair Queue CoDel - simple but effective)
    pub async fn enable_fq_codel(&self, interface: &str) -> Result<()> {
        self.clear_interface(interface).await.ok();

        Command::new("tc")
            .args(&[
                "qdisc", "add", "dev", interface,
                "root", "fq_codel"
            ])
            .output()
            .map_err(|e| Error::Network(format!("Failed to enable FQ-CoDel: {}", e)))?;

        Ok(())
    }
}

impl Default for QosManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaming_preset() {
        let qos = QosManager::new();
        let preset = qos.create_gaming_preset("eth0", "100mbit");

        assert_eq!(preset.classes.len(), 3);
        assert_eq!(preset.classes[0].priority, 0);  // Gaming highest priority
    }

    #[test]
    fn test_voip_preset() {
        let qos = QosManager::new();
        let preset = qos.create_voip_preset("eth0");

        assert_eq!(preset.classes.len(), 1);
        assert_eq!(preset.classes[0].match_dst_port, Some(5060));
    }
}
