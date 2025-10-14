//! Network Address Translation (NAT)
//!
//! Supports SNAT, DNAT, and Port Forwarding

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use anyhow::Result;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NatType {
    /// Source NAT - translate outgoing source address
    Snat,
    /// Destination NAT - translate incoming destination address
    Dnat,
    /// Port forwarding - specific port mapping
    PortForward,
    /// 1:1 NAT - bidirectional mapping
    OneToOne,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Uuid,
    pub name: String,
    pub nat_type: NatType,
    pub enabled: bool,

    // Match criteria
    pub src_address: Option<String>,
    pub dst_address: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>, // tcp, udp, icmp
    pub interface: Option<String>,

    // Translation
    pub translated_address: IpAddr,
    pub translated_port: Option<u16>,

    // Stats
    pub packet_count: u64,
    pub byte_count: u64,
    pub created_at: DateTime<Utc>,
    pub last_matched: Option<DateTime<Utc>>,
}

impl NatRule {
    pub fn new(name: impl Into<String>, nat_type: NatType, translated_address: IpAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            nat_type,
            enabled: true,
            src_address: None,
            dst_address: None,
            src_port: None,
            dst_port: None,
            protocol: None,
            interface: None,
            translated_address,
            translated_port: None,
            packet_count: 0,
            byte_count: 0,
            created_at: Utc::now(),
            last_matched: None,
        }
    }

    pub fn with_src_address(mut self, addr: impl Into<String>) -> Self {
        self.src_address = Some(addr.into());
        self
    }

    pub fn with_dst_address(mut self, addr: impl Into<String>) -> Self {
        self.dst_address = Some(addr.into());
        self
    }

    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    pub fn with_translated_port(mut self, port: u16) -> Self {
        self.translated_port = Some(port);
        self
    }

    pub fn with_protocol(mut self, proto: impl Into<String>) -> Self {
        self.protocol = Some(proto.into());
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    pub fn matches(&self, packet_info: &PacketInfo) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(ref src) = self.src_address {
            if !packet_info.src_addr.to_string().starts_with(src) {
                return false;
            }
        }

        if let Some(ref dst) = self.dst_address {
            if !packet_info.dst_addr.to_string().starts_with(dst) {
                return false;
            }
        }

        if let Some(port) = self.dst_port {
            if packet_info.dst_port != port {
                return false;
            }
        }

        if let Some(ref proto) = self.protocol {
            if packet_info.protocol != *proto {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatSession {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub original_src: IpAddr,
    pub original_dst: IpAddr,
    pub translated_src: IpAddr,
    pub translated_dst: IpAddr,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
}

pub struct NatManager {
    rules: Arc<RwLock<HashMap<Uuid, NatRule>>>,
    sessions: Arc<RwLock<HashMap<Uuid, NatSession>>>,
}

impl NatManager {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_rule(&self, rule: NatRule) -> Uuid {
        let id = rule.id;
        let mut rules = self.rules.write().await;
        rules.insert(id, rule);
        tracing::info!("Added NAT rule: {}", id);
        id
    }

    pub async fn remove_rule(&self, id: &Uuid) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.remove(id)
            .ok_or_else(|| anyhow::anyhow!("NAT rule not found"))?;
        tracing::info!("Removed NAT rule: {}", id);
        Ok(())
    }

    pub async fn get_rule(&self, id: &Uuid) -> Option<NatRule> {
        let rules = self.rules.read().await;
        rules.get(id).cloned()
    }

    pub async fn list_rules(&self) -> Vec<NatRule> {
        let rules = self.rules.read().await;
        rules.values().cloned().collect()
    }

    pub async fn apply_nat(&self, packet: &PacketInfo) -> Option<(IpAddr, Option<u16>)> {
        let result = {
            let mut rules = self.rules.write().await;

            // Find first matching rule
            for rule in rules.values_mut() {
                if rule.matches(packet) {
                    rule.packet_count += 1;
                    rule.last_matched = Some(Utc::now());

                    // Collect data we need before releasing the lock
                    let rule_id = rule.id;
                    let translated_address = rule.translated_address;
                    let translated_port = rule.translated_port;

                    // Release lock before creating session
                    drop(rules);

                    // Create or update session
                    self.create_session(rule_id, packet).await;

                    return Some((translated_address, translated_port));
                }
            }

            None
        };

        result
    }

    async fn create_session(&self, rule_id: Uuid, packet: &PacketInfo) {
        let rule = {
            let rules = self.rules.read().await;
            rules.get(&rule_id).cloned()
        };

        if let Some(rule) = rule {
            let session = NatSession {
                id: Uuid::new_v4(),
                rule_id,
                original_src: packet.src_addr,
                original_dst: packet.dst_addr,
                translated_src: rule.translated_address,
                translated_dst: packet.dst_addr,
                created_at: Utc::now(),
                last_activity: Utc::now(),
                packet_count: 1,
                byte_count: 0,
            };

            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id, session);
        }
    }

    pub async fn get_sessions(&self) -> Vec<NatSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    pub async fn cleanup_stale_sessions(&self, timeout_seconds: i64) {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();

        sessions.retain(|_, session| {
            let elapsed = now.signed_duration_since(session.last_activity).num_seconds();
            elapsed < timeout_seconds
        });

        tracing::debug!("Cleaned up stale NAT sessions");
    }

    pub async fn get_stats(&self) -> NatStats {
        let rules = self.rules.read().await;
        let sessions = self.sessions.read().await;

        let total_packets: u64 = rules.values().map(|r| r.packet_count).sum();
        let total_bytes: u64 = rules.values().map(|r| r.byte_count).sum();

        NatStats {
            total_rules: rules.len(),
            active_sessions: sessions.len(),
            total_packets,
            total_bytes,
        }
    }
}

impl Default for NatManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatStats {
    pub total_rules: usize,
    pub active_sessions: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_nat_rule_creation() {
        let rule = NatRule::new(
            "test-snat",
            NatType::Snat,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        );

        assert_eq!(rule.name, "test-snat");
        assert_eq!(rule.nat_type, NatType::Snat);
        assert!(rule.enabled);
    }

    #[test]
    fn test_nat_rule_builder() {
        let rule = NatRule::new(
            "port-forward-ssh",
            NatType::PortForward,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        )
        .with_dst_port(22)
        .with_translated_port(2222)
        .with_protocol("tcp")
        .with_interface("wan0");

        assert_eq!(rule.dst_port, Some(22));
        assert_eq!(rule.translated_port, Some(2222));
        assert_eq!(rule.protocol, Some("tcp".to_string()));
    }

    #[test]
    fn test_packet_matching() {
        let rule = NatRule::new(
            "test-match",
            NatType::Dnat,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        )
        .with_dst_port(80)
        .with_protocol("tcp");

        let packet = PacketInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            src_port: 54321,
            dst_port: 80,
            protocol: "tcp".to_string(),
            interface: "wan0".to_string(),
        };

        assert!(rule.matches(&packet));
    }

    #[test]
    fn test_packet_no_match() {
        let rule = NatRule::new(
            "test-no-match",
            NatType::Dnat,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        )
        .with_dst_port(80)
        .with_protocol("tcp");

        let packet = PacketInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            src_port: 54321,
            dst_port: 443, // Different port
            protocol: "tcp".to_string(),
            interface: "wan0".to_string(),
        };

        assert!(!rule.matches(&packet));
    }

    #[tokio::test]
    async fn test_nat_manager() {
        let manager = NatManager::new();

        let rule = NatRule::new(
            "test-rule",
            NatType::Snat,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        );

        let id = manager.add_rule(rule).await;

        assert!(manager.get_rule(&id).await.is_some());
        assert_eq!(manager.list_rules().await.len(), 1);
    }

    #[tokio::test]
    async fn test_apply_nat() {
        let manager = NatManager::new();

        let rule = NatRule::new(
            "web-forward",
            NatType::PortForward,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        )
        .with_dst_port(80)
        .with_translated_port(8080)
        .with_protocol("tcp");

        manager.add_rule(rule).await;

        let packet = PacketInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            src_port: 54321,
            dst_port: 80,
            protocol: "tcp".to_string(),
            interface: "wan0".to_string(),
        };

        let result = manager.apply_nat(&packet).await;
        assert!(result.is_some());

        let (addr, port) = result.unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(port, Some(8080));
    }

    #[tokio::test]
    async fn test_session_creation() {
        let manager = NatManager::new();

        let rule = NatRule::new(
            "test-session",
            NatType::Dnat,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        )
        .with_dst_port(443);

        manager.add_rule(rule).await;

        let packet = PacketInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            src_port: 54321,
            dst_port: 443,
            protocol: "tcp".to_string(),
            interface: "wan0".to_string(),
        };

        manager.apply_nat(&packet).await;

        let sessions = manager.get_sessions().await;
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_stats() {
        let manager = NatManager::new();

        let rule = NatRule::new(
            "stats-test",
            NatType::Snat,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        );

        manager.add_rule(rule).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_rules, 1);
        assert_eq!(stats.active_sessions, 0);
    }
}
