//! MPLS Provider Network Integration
//!
//! Integration with MPLS service providers for hybrid SD-WAN deployments

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MplsServiceClass {
    RealTime,      // Voice, video conferencing
    Business,      // Business-critical apps
    BestEffort,    // Internet traffic
}

impl MplsServiceClass {
    pub fn priority(&self) -> u8 {
        match self {
            MplsServiceClass::RealTime => 1,
            MplsServiceClass::Business => 2,
            MplsServiceClass::BestEffort => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MplsLabel {
    pub label: u32,  // 20-bit label
    pub exp: u8,     // 3-bit experimental (QoS)
    pub ttl: u8,     // Time to live
}

impl MplsLabel {
    pub fn new(label: u32, exp: u8, ttl: u8) -> Self {
        Self {
            label: label & 0xFFFFF,  // Mask to 20 bits
            exp: exp & 0x7,           // Mask to 3 bits
            ttl,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelSwitchedPath {
    pub id: Uuid,
    pub name: String,
    pub ingress_router: String,
    pub egress_router: String,
    pub labels: Vec<MplsLabel>,
    pub bandwidth_mbps: f64,
    pub service_class: MplsServiceClass,
    pub active: bool,
}

impl LabelSwitchedPath {
    pub fn new(
        name: String,
        ingress: String,
        egress: String,
        bandwidth_mbps: f64,
        service_class: MplsServiceClass,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            ingress_router: ingress,
            egress_router: egress,
            labels: Vec::new(),
            bandwidth_mbps,
            service_class,
            active: false,
        }
    }

    pub fn push_label(&mut self, label: MplsLabel) {
        self.labels.push(label);
    }

    pub fn pop_label(&mut self) -> Option<MplsLabel> {
        self.labels.pop()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConnection {
    pub id: Uuid,
    pub provider_name: String,
    pub circuit_id: String,
    pub bandwidth_mbps: f64,
    pub ipv4_address: String,
    pub ipv6_address: Option<String>,
    pub vlan_id: Option<u16>,
    pub connected: bool,
}

impl ProviderConnection {
    pub fn new(provider: String, circuit_id: String, bandwidth: f64, ipv4: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            provider_name: provider,
            circuit_id,
            bandwidth_mbps: bandwidth,
            ipv4_address: ipv4,
            ipv6_address: None,
            vlan_id: None,
            connected: false,
        }
    }
}

pub struct MplsManager {
    lsps: Arc<RwLock<HashMap<Uuid, LabelSwitchedPath>>>,
    connections: Arc<RwLock<HashMap<Uuid, ProviderConnection>>>,
}

impl MplsManager {
    pub fn new() -> Self {
        Self {
            lsps: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_lsp(
        &self,
        name: String,
        ingress: String,
        egress: String,
        bandwidth: f64,
        service_class: MplsServiceClass,
    ) -> Uuid {
        let lsp = LabelSwitchedPath::new(name, ingress, egress, bandwidth, service_class);
        let id = lsp.id;

        let mut lsps = self.lsps.write().await;
        lsps.insert(id, lsp);

        id
    }

    pub async fn get_lsp(&self, id: &Uuid) -> Option<LabelSwitchedPath> {
        let lsps = self.lsps.read().await;
        lsps.get(id).cloned()
    }

    pub async fn activate_lsp(&self, id: &Uuid) -> bool {
        let mut lsps = self.lsps.write().await;
        if let Some(lsp) = lsps.get_mut(id) {
            lsp.active = true;
            true
        } else {
            false
        }
    }

    pub async fn deactivate_lsp(&self, id: &Uuid) -> bool {
        let mut lsps = self.lsps.write().await;
        if let Some(lsp) = lsps.get_mut(id) {
            lsp.active = false;
            true
        } else {
            false
        }
    }

    pub async fn add_label_to_lsp(&self, lsp_id: &Uuid, label: MplsLabel) -> bool {
        let mut lsps = self.lsps.write().await;
        if let Some(lsp) = lsps.get_mut(lsp_id) {
            lsp.push_label(label);
            true
        } else {
            false
        }
    }

    pub async fn list_active_lsps(&self) -> Vec<LabelSwitchedPath> {
        let lsps = self.lsps.read().await;
        lsps.values().filter(|l| l.active).cloned().collect()
    }

    pub async fn get_lsps_by_service_class(&self, class: &MplsServiceClass) -> Vec<LabelSwitchedPath> {
        let lsps = self.lsps.read().await;
        lsps.values()
            .filter(|l| &l.service_class == class)
            .cloned()
            .collect()
    }

    pub async fn register_provider_connection(&self, connection: ProviderConnection) -> Uuid {
        let id = connection.id;
        let mut connections = self.connections.write().await;
        connections.insert(id, connection);
        id
    }

    pub async fn get_connection(&self, id: &Uuid) -> Option<ProviderConnection> {
        let connections = self.connections.read().await;
        connections.get(id).cloned()
    }

    pub async fn connect_provider(&self, id: &Uuid) -> bool {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(id) {
            conn.connected = true;
            true
        } else {
            false
        }
    }

    pub async fn disconnect_provider(&self, id: &Uuid) -> bool {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.get_mut(id) {
            conn.connected = false;
            true
        } else {
            false
        }
    }

    pub async fn list_connected_providers(&self) -> Vec<ProviderConnection> {
        let connections = self.connections.read().await;
        connections.values().filter(|c| c.connected).cloned().collect()
    }

    pub async fn get_total_provider_bandwidth(&self) -> f64 {
        let connections = self.connections.read().await;
        connections.values()
            .filter(|c| c.connected)
            .map(|c| c.bandwidth_mbps)
            .sum()
    }
}

impl Default for MplsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_class_priority() {
        assert_eq!(MplsServiceClass::RealTime.priority(), 1);
        assert_eq!(MplsServiceClass::Business.priority(), 2);
        assert_eq!(MplsServiceClass::BestEffort.priority(), 3);
    }

    #[test]
    fn test_mpls_label_creation() {
        let label = MplsLabel::new(12345, 5, 64);
        assert_eq!(label.label, 12345);
        assert_eq!(label.exp, 5);
        assert_eq!(label.ttl, 64);
    }

    #[test]
    fn test_mpls_label_masking() {
        let label = MplsLabel::new(0xFFFFFFFF, 0xFF, 64);
        assert_eq!(label.label, 0xFFFFF);  // 20 bits
        assert_eq!(label.exp, 0x7);         // 3 bits
    }

    #[test]
    fn test_lsp_creation() {
        let lsp = LabelSwitchedPath::new(
            "lsp-1".to_string(),
            "router1".to_string(),
            "router2".to_string(),
            1000.0,
            MplsServiceClass::Business,
        );

        assert_eq!(lsp.name, "lsp-1");
        assert_eq!(lsp.ingress_router, "router1");
        assert_eq!(lsp.egress_router, "router2");
        assert!(!lsp.active);
    }

    #[test]
    fn test_lsp_label_stack() {
        let mut lsp = LabelSwitchedPath::new(
            "test".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            100.0,
            MplsServiceClass::RealTime,
        );

        lsp.push_label(MplsLabel::new(100, 1, 64));
        lsp.push_label(MplsLabel::new(200, 2, 64));

        assert_eq!(lsp.labels.len(), 2);

        let popped = lsp.pop_label();
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().label, 200);
        assert_eq!(lsp.labels.len(), 1);
    }

    #[test]
    fn test_provider_connection_creation() {
        let conn = ProviderConnection::new(
            "AT&T".to_string(),
            "CIRCUIT-12345".to_string(),
            10000.0,
            "192.168.1.1".to_string(),
        );

        assert_eq!(conn.provider_name, "AT&T");
        assert_eq!(conn.circuit_id, "CIRCUIT-12345");
        assert!(!conn.connected);
    }

    #[tokio::test]
    async fn test_mpls_manager_create_lsp() {
        let manager = MplsManager::new();

        let lsp_id = manager.create_lsp(
            "test-lsp".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            1000.0,
            MplsServiceClass::Business,
        ).await;

        let lsp = manager.get_lsp(&lsp_id).await;
        assert!(lsp.is_some());
        assert_eq!(lsp.unwrap().name, "test-lsp");
    }

    #[tokio::test]
    async fn test_activate_lsp() {
        let manager = MplsManager::new();
        let lsp_id = manager.create_lsp(
            "test".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            1000.0,
            MplsServiceClass::RealTime,
        ).await;

        assert!(manager.activate_lsp(&lsp_id).await);

        let lsp = manager.get_lsp(&lsp_id).await.unwrap();
        assert!(lsp.active);
    }

    #[tokio::test]
    async fn test_add_label_to_lsp() {
        let manager = MplsManager::new();
        let lsp_id = manager.create_lsp(
            "test".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            1000.0,
            MplsServiceClass::Business,
        ).await;

        let label = MplsLabel::new(12345, 3, 64);
        assert!(manager.add_label_to_lsp(&lsp_id, label).await);

        let lsp = manager.get_lsp(&lsp_id).await.unwrap();
        assert_eq!(lsp.labels.len(), 1);
        assert_eq!(lsp.labels[0].label, 12345);
    }

    #[tokio::test]
    async fn test_list_active_lsps() {
        let manager = MplsManager::new();

        let lsp1 = manager.create_lsp(
            "lsp1".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            1000.0,
            MplsServiceClass::RealTime,
        ).await;

        let lsp2 = manager.create_lsp(
            "lsp2".to_string(),
            "r2".to_string(),
            "r3".to_string(),
            2000.0,
            MplsServiceClass::Business,
        ).await;

        manager.activate_lsp(&lsp1).await;

        let active = manager.list_active_lsps().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "lsp1");
    }

    #[tokio::test]
    async fn test_get_lsps_by_service_class() {
        let manager = MplsManager::new();

        manager.create_lsp(
            "rt1".to_string(),
            "r1".to_string(),
            "r2".to_string(),
            1000.0,
            MplsServiceClass::RealTime,
        ).await;

        manager.create_lsp(
            "biz1".to_string(),
            "r2".to_string(),
            "r3".to_string(),
            2000.0,
            MplsServiceClass::Business,
        ).await;

        manager.create_lsp(
            "rt2".to_string(),
            "r3".to_string(),
            "r4".to_string(),
            1500.0,
            MplsServiceClass::RealTime,
        ).await;

        let realtime = manager.get_lsps_by_service_class(&MplsServiceClass::RealTime).await;
        assert_eq!(realtime.len(), 2);
    }

    #[tokio::test]
    async fn test_register_provider_connection() {
        let manager = MplsManager::new();

        let conn = ProviderConnection::new(
            "Verizon".to_string(),
            "VZ-123".to_string(),
            5000.0,
            "10.0.0.1".to_string(),
        );
        let conn_id = conn.id;

        manager.register_provider_connection(conn).await;

        let retrieved = manager.get_connection(&conn_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().provider_name, "Verizon");
    }

    #[tokio::test]
    async fn test_connect_disconnect_provider() {
        let manager = MplsManager::new();

        let conn = ProviderConnection::new(
            "CenturyLink".to_string(),
            "CL-456".to_string(),
            10000.0,
            "10.1.1.1".to_string(),
        );
        let conn_id = conn.id;

        manager.register_provider_connection(conn).await;

        assert!(manager.connect_provider(&conn_id).await);
        let conn = manager.get_connection(&conn_id).await.unwrap();
        assert!(conn.connected);

        assert!(manager.disconnect_provider(&conn_id).await);
        let conn = manager.get_connection(&conn_id).await.unwrap();
        assert!(!conn.connected);
    }

    #[tokio::test]
    async fn test_list_connected_providers() {
        let manager = MplsManager::new();

        let conn1 = ProviderConnection::new(
            "Provider1".to_string(),
            "P1-001".to_string(),
            1000.0,
            "10.0.0.1".to_string(),
        );
        let id1 = conn1.id;

        let conn2 = ProviderConnection::new(
            "Provider2".to_string(),
            "P2-002".to_string(),
            2000.0,
            "10.0.0.2".to_string(),
        );
        let id2 = conn2.id;

        manager.register_provider_connection(conn1).await;
        manager.register_provider_connection(conn2).await;

        manager.connect_provider(&id1).await;

        let connected = manager.list_connected_providers().await;
        assert_eq!(connected.len(), 1);
        assert_eq!(connected[0].provider_name, "Provider1");
    }

    #[tokio::test]
    async fn test_get_total_provider_bandwidth() {
        let manager = MplsManager::new();

        let conn1 = ProviderConnection::new(
            "P1".to_string(),
            "C1".to_string(),
            5000.0,
            "10.0.0.1".to_string(),
        );
        let id1 = conn1.id;

        let conn2 = ProviderConnection::new(
            "P2".to_string(),
            "C2".to_string(),
            3000.0,
            "10.0.0.2".to_string(),
        );
        let id2 = conn2.id;

        manager.register_provider_connection(conn1).await;
        manager.register_provider_connection(conn2).await;

        manager.connect_provider(&id1).await;
        manager.connect_provider(&id2).await;

        let total = manager.get_total_provider_bandwidth().await;
        assert_eq!(total, 8000.0);
    }
}
