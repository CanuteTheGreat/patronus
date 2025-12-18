//! Askama template definitions
//!
//! This module defines the template structs that map to HTML templates.

use askama::Template;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Dashboard template
#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub interfaces: Vec<InterfaceInfo>,
    pub active_rules: usize,
    pub vpn_connections: usize,
    pub system_info: SystemInfo,
}

/// Firewall template
#[derive(Template)]
#[template(path = "firewall.html")]
pub struct FirewallTemplate {
    pub rules: Vec<FirewallRule>,
    pub nat_rules: Vec<NatRule>,
    pub aliases: Vec<Alias>,
    // Pre-computed counts for template
    pub filter_rules: Vec<FirewallRule>,
    pub enabled_filter_rules: usize,
    pub enabled_nat_rules: usize,
    pub accept_rules_count: usize,
    pub drop_rules_count: usize,
}

/// VPN template
#[derive(Template)]
#[template(path = "vpn.html")]
pub struct VpnTemplate {
    pub wg_peers: Vec<WireGuardPeer>,
    pub ovpn_tunnels: Vec<OpenVpnTunnel>,
    pub ipsec_tunnels: Vec<IpsecTunnel>,
}

/// Network template
#[derive(Template)]
#[template(path = "network.html")]
pub struct NetworkTemplate {
    pub interfaces: Vec<InterfaceInfo>,
    pub dhcp_pools: Vec<DhcpPool>,
    pub dhcp_leases: Vec<DhcpLease>,
    pub dns_records: Vec<DnsRecord>,
    pub routes: Vec<Route>,
}

/// Monitoring template
#[derive(Template)]
#[template(path = "monitoring.html")]
pub struct MonitoringTemplate {
    pub metrics: SystemMetrics,
    pub interface_stats: Vec<InterfaceStats>,
    pub top_connections: Vec<Connection>,
    pub alerts: Vec<Alert>,
    // AI & Threat Detection
    pub threats_detected_today: u32,
    pub threats_blocked_today: u32,
    pub ai_model_accuracy: f64,
    pub ai_model_confidence: f64,
    pub system_health_score: u32,
    pub active_alerts: u32,
    pub packets_analyzed_rate: u32,
    pub packets_total: u64,
    pub ai_threats: Vec<AiThreat>,
    pub attack_map_data: Vec<AttackEvent>,
    pub model_performance: ModelPerformance,
    pub live_logs: Vec<LogEntry>,
}

/// System template
#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemTemplate {
    pub users: Vec<User>,
    pub backups: Vec<Backup>,
    pub updates: Vec<Update>,
    pub services: Vec<Service>,
    pub config: SystemConfig,
    // System status information
    pub system_health: u32,
    pub uptime_days: u32,
    pub uptime: String,
    pub disk_usage_percent: f64,
    pub disk_used: String,
    pub disk_total: String,
    pub updates_available: u32,
    pub security_updates: u32,
}

// Data structures used in templates

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub uptime: u64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub load_avg: (f64, f64, f64),
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            hostname: "patronus".to_string(),
            uptime: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            load_avg: (0.0, 0.0, 0.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub state: String,
    pub ip_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub mtu: u32,
    pub enabled: bool,
    pub interface_type: String,
    // Pre-computed display strings to avoid complex template expressions
    pub ip_display: String,
    pub mac_display: String,
    pub speed_display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u32,
    pub name: String,
    pub action: String,
    pub interface: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port: String,
    pub description: String,
    pub enabled: bool,
    pub chain: String,
    // Pre-computed display strings to avoid complex template expressions
    pub protocol_display: String,
    pub source_display: String,
    pub destination_display: String,
    pub port_display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: u32,
    pub rule_type: String,
    pub interface: String,
    pub source: String,
    pub destination: String,
    pub target: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub id: u32,
    pub name: String,
    pub alias_type: String,
    pub value: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub id: u32,
    pub name: String,
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub status: String,
    pub last_handshake: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnTunnel {
    pub id: u32,
    pub name: String,
    pub status: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub connected_clients: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecTunnel {
    pub id: u32,
    pub name: String,
    pub status: String,
    pub local_subnet: String,
    pub remote_subnet: String,
    pub remote_gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpPool {
    pub id: u32,
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet: String,
    pub gateway: String,
    pub lease_time: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_start: String,
    pub lease_end: String,
    pub is_active: bool,
    pub hostname_display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: u32,
    pub hostname: String,
    pub ip_address: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
    pub is_static: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub network_rx_rate: u64,
    pub network_tx_rate: u64,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_percent: 0.0,
            memory_percent: 0.0,
            disk_percent: 0.0,
            network_rx_rate: 0,
            network_tx_rate: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_rate: String,
    pub tx_rate: String,
    pub rx_packets: String,
    pub tx_packets: String,
    pub errors: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub bytes: String,
    pub packets: String,
    pub duration: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u32,
    pub alert_type: String,
    pub severity: String,
    pub component: String,
    pub message: String,
    pub timestamp: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub full_name: String,
    pub role: String,
    pub two_factor_enabled: bool,
    pub last_login: Option<String>,
    pub is_active: bool,
    pub is_system_user: bool,
    pub last_login_display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub id: u32,
    pub name: String,
    pub created_at: String,
    pub size: String,
    pub backup_type: String,
    pub is_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    pub package_name: String,
    pub current_version: String,
    pub new_version: String,
    pub security: bool,
    pub size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub status: String,
    pub is_running: bool,
    pub enabled: bool,
    pub uptime_display: String,
    pub memory_display: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
    pub dns_servers: Vec<String>,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "patronus".to_string(),
            domain: "local".to_string(),
            timezone: "UTC".to_string(),
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
        }
    }
}

// Additional monitoring and AI-related structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiThreat {
    pub id: u32,
    pub timestamp: String,
    pub threat_type: String,
    pub source_ip: String,
    pub destination: String,
    pub severity: String,
    pub confidence: f64,
    pub blocked: bool,
    pub description: String,
    pub raw_packet: String,
    pub detection_method: String,
    pub ml_model: String,
    pub anomaly_score: String,
    pub port: String,
    pub protocol: String,
    pub packet_count: String,
    pub bytes: String,
    pub geoip_display: String,
    pub threat_intel_display: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub latitude: f64,
    pub longitude: f64,
    pub source_country: String,
    pub attack_type: String,
    pub timestamp: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPerformance {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
    pub last_trained: String,
    pub training_samples: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub component: String,
    pub message: String,
    pub level_color: String,
}

// Display implementations for template types
impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.state)
    }
}

impl fmt::Display for DhcpLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.mac_address, self.ip_address)
    }
}

impl fmt::Display for DhcpPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} - {}", self.interface, self.range_start, self.range_end)
    }
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.hostname, self.value)
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {} dev {}", self.destination, self.gateway, self.interface)
    }
}

impl fmt::Display for FirewallRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {} -> {}", self.name, self.action, self.source, self.destination)
    }
}

impl fmt::Display for NatRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {} -> {}", self.description, self.rule_type, self.source, self.target)
    }
}

impl fmt::Display for Alias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

impl fmt::Display for WireGuardPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.status)
    }
}

impl fmt::Display for OpenVpnTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.status)
    }
}

impl fmt::Display for IpsecTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.status)
    }
}

impl fmt::Display for InterfaceStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: RX {} TX {}", self.name, self.rx_rate, self.tx_rate)
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} -> {}", self.protocol, self.source, self.destination)
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.alert_type, self.message)
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.username, self.role)
    }
}

impl fmt::Display for Backup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.created_at)
    }
}

impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} -> {}", self.package_name, self.current_version, self.new_version)
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.status)
    }
}

impl fmt::Display for AiThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} from {}", self.threat_type, self.severity, self.source_ip)
    }
}

impl fmt::Display for AttackEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} attack from {}", self.attack_type, self.source_country)
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] [{}] {}", self.level, self.component, self.message)
    }
}

