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
    pub page: &'static str,
    pub interfaces: Vec<InterfaceInfo>,
    pub active_rules: usize,
    pub vpn_connections: usize,
    /// Why (part of) the VPN state could not be read; then
    /// `vpn_connections` is a floor and the tile says so.
    pub vpn_errors: Vec<String>,
    pub system_info: SystemInfo,
    pub uptime: String,
    pub services: Vec<Service>,
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
    /// NAT rules split by tab.
    pub port_forwards: Vec<NatRule>,
    pub one_to_one: Vec<NatRule>,
    pub outbound_rules: Vec<NatRule>,
    pub host_aliases: Vec<Alias>,
    pub port_aliases: Vec<Alias>,
    pub schedules: Vec<FirewallSchedule>,
    /// Interface choices (roles, then devices) for the forms.
    pub interfaces: Vec<InterfaceOption>,
    /// automatic | hybrid | manual | disabled
    pub outbound_mode: String,
    /// WAN interfaces the automatic outbound NAT covers.
    pub auto_nat_interfaces: String,
}

/// A firewall schedule row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallSchedule {
    pub name: String,
    pub days: String,
    pub start: String,
    pub end: String,
    pub description: String,
    /// Active right now.
    pub active: bool,
}

/// A choice in an interface drop-down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceOption {
    pub value: String,
    pub label: String,
}

/// VPN template
#[derive(Template)]
#[template(path = "vpn.html")]
pub struct VpnTemplate {
    pub page: &'static str,
    pub wg_peers: Vec<WireGuardPeer>,
    /// Why WireGuard state could not be read ("" = read fine).
    pub wg_error: String,
    pub ipsec_tunnels: Vec<IpsecTunnel>,
    pub ipsec_error: String,
    /// strongSwan installed, charon not running (normal, not an error).
    pub ipsec_not_running: bool,
}

/// Network template
#[derive(Template)]
#[template(path = "network.html")]
pub struct NetworkTemplate {
    pub interfaces: Vec<InterfaceInfo>,
    pub routes: Vec<Route>,
    /// Why the routing table could not be read ("" = read fine).
    pub routes_error: String,
}

/// Monitoring template. Every number is measured; there is no local ML
/// model, health score or alert producer yet, so none is shown.
#[derive(Template)]
#[template(path = "monitoring.html")]
pub struct MonitoringTemplate {
    pub page: &'static str,
    pub metrics: SystemMetrics,
    pub interface_stats: Vec<InterfaceStats>,
    pub top_connections: Vec<Connection>,
    /// Why the conntrack table could not be read ("" = read fine).
    pub connections_error: String,
    pub alerts: Vec<Alert>,
    /// Threat-intel feed entries currently known.
    pub threats_detected: u32,
    pub threats_blocked: u32,
    pub active_alerts: u32,
    /// Packets/s over all non-loopback interfaces (sampled now).
    pub packet_rate: u64,
    /// Packets since boot over all non-loopback interfaces.
    pub packets_total: u64,
    pub rx_rate: String,
    pub tx_rate: String,
    pub ai_threats: Vec<AiThreat>,
    pub live_logs: Vec<LogEntry>,
    pub logs_error: String,
}

/// System template
#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemTemplate {
    pub page: &'static str,
    pub users: Vec<User>,
    pub backups: Vec<Backup>,
    pub backup_dir: String,
    pub backups_error: String,
    pub services: Vec<Service>,
    pub init_system: String,
    pub config: SystemConfig,
    pub uptime: String,
    pub disk_usage_percent: String,
    pub disk_used: String,
    pub disk_total: String,
    pub memory_total: String,
    pub version: String,
    pub kernel: String,
    pub arch: String,
    pub cpu: String,
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
    /// "LAN"/"WAN"/"MGMT" for role tokens (@lan...), else the device name.
    pub interface_display: String,
    /// "system" (anti-lockout, not deletable), "default", "user", "gitops".
    pub origin: String,
    /// Forward chain: outbound interface token ("any" if none).
    pub interface_out: String,
    pub log: bool,
    /// Schedule name ("" = always).
    pub schedule: String,
    /// ipv4 | ipv6 | any
    pub ip_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: u32,
    pub name: String,
    /// MASQUERADE | SNAT | DNAT | 1:1
    pub rule_type: String,
    /// Display form of the interface (WAN / LAN / device).
    pub interface: String,
    /// The stored interface token (`@wan`, device, `any`), for edit forms.
    pub interface_raw: String,
    pub source: String,
    pub destination: String,
    pub target: String,
    /// 1:1 NAT: external address.
    pub external_address: String,
    pub protocol: String,
    /// Port forward: external port(s) ("any" if none).
    pub external_port: String,
    pub reflection: bool,
    pub description: String,
    pub enabled: bool,
    /// "system", "default", "user" or "gitops".
    pub origin: String,
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
    /// The WireGuard interface the peer belongs to.
    pub interface: String,
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: Option<String>,
    pub status: String,
    /// Handshake within the last 180 s.
    pub connected: bool,
    pub last_handshake: Option<String>,
    pub transfer: String,
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
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
    /// The kernel's route protocol: kernel, boot, static, dhcp, ra, bgp, ...
    pub origin: String,
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

/// A web UI account (from the auth user store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub username: String,
    /// admin | operator | read-only
    pub role: String,
    pub is_active: bool,
    pub created_at: String,
    pub last_login_display: String,
}

/// A configuration backup file (export of the config store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    /// The file name; also the id in /api/system/backups/:id.
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub size: String,
    pub size_bytes: u64,
    pub backup_type: String,
    /// Parses as a config export.
    pub is_valid: bool,
}

/// An init-managed service and its live state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub description: String,
    pub status: String,
    pub is_running: bool,
    pub enabled: bool,
    pub uptime_display: String,
    pub memory_display: String,
}

/// Hostname / DNS / time zone as the system has them. Empty = not set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemConfig {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
    pub dns_servers: Vec<String>,
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

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} via {} dev {}",
            self.destination, self.gateway, self.interface
        )
    }
}

impl fmt::Display for FirewallRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} {} -> {}",
            self.name, self.action, self.source, self.destination
        )
    }
}

impl fmt::Display for NatRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} {} -> {}",
            self.description, self.rule_type, self.source, self.target
        )
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
        write!(
            f,
            "{} {} -> {}",
            self.protocol, self.source, self.destination
        )
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity, self.alert_type, self.message
        )
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

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.status)
    }
}

impl fmt::Display for AiThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} from {}",
            self.threat_type, self.severity, self.source_ip
        )
    }
}

impl fmt::Display for AttackEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} attack from {}",
            self.attack_type, self.source_country
        )
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] [{}] {}", self.level, self.component, self.message)
    }
}

/// Interfaces page (lane C). Static shell; data comes from `/api/interfaces`.
#[derive(Template)]
#[template(path = "interfaces.html")]
pub struct InterfacesTemplate;

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard(vpn_connections: usize, vpn_errors: Vec<String>) -> String {
        DashboardTemplate {
            page: "dashboard",
            interfaces: vec![],
            active_rules: 0,
            vpn_connections,
            vpn_errors,
            system_info: SystemInfo::default(),
            uptime: "1 min".into(),
            services: vec![],
        }
        .render()
        .unwrap()
    }

    /// A failed VPN read must not render as a plain "0" (finding: a box
    /// with a live tunnel showed "VPN connections 0" and no error).
    #[test]
    fn dashboard_vpn_tile_shows_read_errors_instead_of_a_bare_count() {
        let ok = dashboard(2, vec![]);
        assert!(ok.contains(r#"id="vpn-connections">2</div>"#), "{ok}");
        assert!(!ok.contains("vpn-errors"));

        let failed = dashboard(
            0,
            vec!["`wg show all dump` failed: Operation not permitted".into()],
        );
        assert!(failed.contains(r#"id="vpn-connections">unknown</div>"#));
        assert!(!failed.contains(r#"id="vpn-connections">0</div>"#));
        assert!(failed.contains("VPN state could not be read"));
        assert!(failed.contains("Operation not permitted"));
        assert!(failed.contains("stat-card warning"));

        let partial = dashboard(1, vec!["a".into(), "b".into()]);
        assert!(partial.contains(r#"id="vpn-connections">at least 1</div>"#));
        assert!(partial.contains("a; b"));
    }
}
