//! Askama template definitions
//!
//! This module defines the template structs that map to HTML templates.

use askama::Template;
use serde::{Deserialize, Serialize};

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
    pub mac_address: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u32,
    pub action: String,
    pub interface: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub port: String,
    pub description: String,
    pub enabled: bool,
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
    pub lease_time: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: u32,
    pub hostname: String,
    pub ip_address: String,
    pub record_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
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
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub state: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u32,
    pub severity: String,
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub role: String,
    pub last_login: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub id: u32,
    pub filename: String,
    pub created_at: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    pub package: String,
    pub current_version: String,
    pub available_version: String,
    pub security: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub status: String,
    pub enabled: bool,
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
