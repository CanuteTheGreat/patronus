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
    /// Default IPv4 route as `(device, gateway)`; empty = no route to the internet.
    pub internet_dev: String,
    pub internet_gw: String,
    /// Active DHCP leases; `None` = the DHCP server is not configured or its state could not be read (tile hidden).
    pub dhcp_leases: Option<usize>,
    /// Interfaces with their roles, WAN first (kernel placeholder devices without an address left out).
    pub iface_rows: Vec<DashIface>,
    /// How many kernel placeholder devices (gre0, sit0, ...) were left out of `iface_rows`.
    pub hidden_stubs: usize,
    /// Display settings (usage thresholds, live refresh interval).
    pub ui: patronus_config::uiprefs::UiPrefs,
    /// This unit is an access point (`PATRONUS_DEVICE_ROLE=ap`): router tiles are left out.
    pub ap: bool,
    /// ui-kit tone class of CPU / memory / disk usage against the thresholds ("", "warn", "crit").
    pub cpu_level: &'static str,
    pub mem_level: &'static str,
    pub disk_level: &'static str,
    /// "Disk /" or "Disk /data" (read-only root: the data partition is what fills up)
    pub disk_label: &'static str,
    /// One sentence naming what is over a threshold (empty = all fine) and its banner tone.
    pub health_note: String,
    pub health_tone: &'static str,
    /// Live throughput per non-loopback interface (rate over a short sample window).
    pub traffic: Vec<DashTraffic>,
    /// The widgets to draw, in the viewer's order (`crate::dashboard`).
    pub widgets: Vec<crate::dashboard::DashWidget>,
    /// Widgets switched off for the viewer: the "add" list of the customize mode.
    pub hidden_widgets: Vec<crate::dashboard::DashWidget>,
    /// The resolved layout as JSON, read by the customize mode script.
    pub layout_json: String,
    /// The viewer saved their own layout (the "Reset to default" button shows).
    pub customized: bool,
}

/// System activity page template (static shell; data from the API).
#[derive(Template)]
#[template(path = "activity.html")]
pub struct ActivityTemplate {
    pub page: &'static str,
}

/// One row of the dashboard's Traffic widget.
#[derive(Debug, Clone)]
pub struct DashTraffic {
    pub name: String,
    pub rx: String,
    pub tx: String,
}

/// One row of the dashboard's interface table.
#[derive(Debug, Clone, Default)]
pub struct DashIface {
    pub name: String,
    /// Upper-case role label (WAN, LAN, OPT1); empty = no role assigned.
    pub role: String,
    pub up: bool,
    /// Addresses, comma separated; empty = none.
    pub addrs: String,
    pub mac: String,
    /// Live rate "rx / tx" (empty = not sampled).
    pub rate: String,
    /// Byte counters since boot, humanised, and raw (for sorting).
    pub rx: String,
    pub tx: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Firewall template
#[derive(Template)]
#[template(path = "firewall.html")]
pub struct FirewallTemplate {
    /// Active sidebar entry (the shared app shell in `base.html`).
    pub page: &'static str,
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
    pub npt: Vec<NatRule>,
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
    /// Gateways and gateway groups a rule can route through (Routing page).
    pub gateways: Vec<String>,
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
    /// USE=wireguard / USE=ipsec: the configuration forms are built in.
    pub has_wireguard: bool,
    pub has_ipsec: bool,
    /// IPsec is built in but cannot be applied by this process (unprivileged,
    /// no root broker): why, shown instead of the form ("" = usable).
    pub ipsec_unavailable: String,
    /// The session may change configuration (operator / admin).
    pub can_modify: bool,
    /// Stored WireGuard tunnels / peers and IPsec connections (lane F).
    pub tunnels: Vec<WgTunnelRow>,
    pub peers: Vec<WgPeerRow>,
    pub connections: Vec<IpsecConnRow>,
    /// Why the stored VPN configuration could not be read.
    pub config_error: String,
}

/// A stored WireGuard tunnel (never its private key).
#[derive(Debug, Clone)]
pub struct WgTunnelRow {
    pub name: String,
    pub enabled: bool,
    pub public_key: String,
    pub listen_port: u16,
    pub addresses: String,
    pub endpoint: String,
    pub client_dns: String,
    pub client_allowed_ips: String,
    pub description: String,
    pub peers: usize,
}

/// A stored WireGuard peer with its live kernel state.
#[derive(Debug, Clone)]
pub struct WgPeerRow {
    pub id: i64,
    pub interface: String,
    pub name: String,
    pub enabled: bool,
    pub public_key: String,
    pub allowed_ips: String,
    pub endpoint: String,
    pub keepalive: String,
    /// Patronus holds its private key: client config / QR available.
    pub exportable: bool,
    pub has_psk: bool,
    pub status: String,
    pub connected: bool,
    pub handshake: String,
    pub transfer: String,
    pub description: String,
}

/// A stored IPsec tunnel (never its PSK) with its live SA state.
#[derive(Debug, Clone)]
pub struct IpsecConnRow {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub local_address: String,
    pub remote_address: String,
    pub local_id: String,
    pub remote_id: String,
    pub local_ts: String,
    pub remote_ts: String,
    pub start_action: String,
    pub state: String,
    pub established: bool,
    pub description: String,
}

/// A page whose feature this build (or this unit's role) leaves out: rendered in
/// the normal layout with the reason, never a bare error page.
#[allow(dead_code)] // built only by not_in_build (builds without some feature)
#[derive(Template)]
#[template(path = "not_built.html")]
pub struct NotBuiltTemplate {
    pub page: &'static str,
    pub title: String,
    pub heading: String,
    /// Plain text (escaped by askama).
    pub reason: String,
    /// The USE flag that adds it ("" = no rebuild hint, e.g. an access point's router function).
    pub flag: String,
    /// Router-tier image (built as a whole: no USE-flag hint).
    pub embedded: bool,
}

/// Network template
#[derive(Template)]
#[template(path = "network.html")]
pub struct NetworkTemplate {
    /// Active nav entry (the page extends base.html like every other page).
    pub page: &'static str,
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
    /// idle kernel stub devices left out of the interface list
    pub hidden_stubs: usize,
    /// ui-kit usage tone of CPU / memory / disk ("", "warn", "crit": the ui.health_* thresholds)
    pub cpu_level: &'static str,
    pub mem_level: &'static str,
    pub disk_level: &'static str,
    pub disk_label: &'static str,
}

/// System template
#[derive(Template)]
#[template(path = "system.html")]
pub struct SystemTemplate {
    /// Display settings (System > Display) and their defaults for the hints.
    pub ui: patronus_config::uiprefs::UiPrefs,
    pub ui_default: patronus_config::uiprefs::UiPrefs,
    pub page: &'static str,
    /// About card: product site and public source addresses (`about.site_url`, `about.source_url`).
    pub site_url: String,
    pub source_url: String,
    pub users: Vec<User>,
    /// The logged-in account.
    pub me_id: u32,
    pub me_username: String,
    pub me_two_factor: bool,
    pub is_admin: bool,
    pub can_modify: bool,
    /// USE=totp: two-factor enrolment is built in.
    pub totp_available: bool,
    pub backups: Vec<Backup>,
    pub backup_dir: String,
    pub backups_error: String,
    pub services: Vec<Service>,
    pub init_system: String,
    pub config: SystemConfig,
    pub uptime: String,
    pub disk_usage_percent: String,
    /// ui-kit usage tone of the root disk ("", "warn", "crit") and the bar width in percent
    pub disk_level: &'static str,
    pub disk_label: &'static str,
    pub disk_bar: u8,
    pub disk_used: String,
    pub disk_total: String,
    pub memory_total: String,
    pub version: String,
    pub kernel: String,
    pub arch: String,
    pub cpu: String,
    pub ssh_port: u16,
    pub ssh_listen: String,
    pub ssh_password: bool,
    pub ssh_root: String,
    pub ssh_ca: String,
    /// One `user=principal,principal` per line.
    pub ssh_principals: String,
    pub ssh_cert: String,
    pub web_listen: String,
    pub web_https_port: u16,
    pub web_redirect_port: u16,
    pub web_extra_ports: String,
    pub web_cert: String,
    pub web_key: String,
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
    /// Policy routing: gateway or gateway group this traffic is sent
    /// through ("" = the default route).
    #[serde(default)]
    pub gateway: String,
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
    /// Seconds since the last handshake (None = never).
    #[serde(default)]
    pub handshake_age_secs: Option<u64>,
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
    /// admin | operator | readonly (form value)
    pub role_key: String,
    pub is_active: bool,
    /// TOTP two-factor login is on.
    pub two_factor: bool,
    pub recovery_codes_left: usize,
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
    /// ui-kit badge tone: crit / warn / info / "" (neutral)
    pub level_class: String,
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

/// Diagnostics page: ping, traceroute, DNS lookup and the neighbour,
/// routing and socket tables (data from `POST /api/system/diag`).
#[derive(Template)]
#[template(path = "diagnostics.html")]
pub struct DiagnosticsTemplate {
    pub page: &'static str,
    pub is_admin: bool,
}

/// Interfaces page (lane C). Static shell; data comes from `/api/interfaces`.
#[derive(Template)]
#[template(path = "interfaces.html")]
pub struct InterfacesTemplate {
    /// Active sidebar entry (the shared app shell in `base.html`).
    pub page: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header breadcrumb names the page the way the sidebar does:
    /// acronyms stay upper case (it used to read "Dhcp", "Vpn", "Wifi").
    #[test]
    fn breadcrumb_uses_proper_page_names() {
        for (slug, label) in [
            ("dhcp", "DHCP"),
            ("dns", "DNS"),
            ("dns-policy", "DNS policy"),
            ("ntp", "NTP"),
            ("qos", "QoS"),
            ("vpn", "VPN"),
            ("wifi", "Wi-Fi"),
            ("ha", "High availability"),
            ("time-limits", "Time limits"),
            ("firewall", "Firewall"),
        ] {
            let html = InterfacesTemplate { page: slug }.render().unwrap();
            let crumb = html
                .split("class=\"breadcrumbs\"")
                .nth(1)
                .expect("breadcrumbs");
            let crumb = &crumb[..crumb.find("</div>").unwrap()];
            assert!(
                crumb.contains(&format!("<span>{label}</span>")),
                "{slug}: {crumb}"
            );
        }
    }

    fn dash_base() -> DashboardTemplate {
        DashboardTemplate {
            page: "dashboard",
            interfaces: vec![],
            active_rules: 0,
            vpn_connections: 0,
            vpn_errors: vec![],
            system_info: SystemInfo::default(),
            uptime: "1 min".into(),
            services: vec![],
            internet_dev: String::new(),
            internet_gw: String::new(),
            dhcp_leases: None,
            iface_rows: vec![],
            hidden_stubs: 0,
            ui: patronus_config::uiprefs::UiPrefs::default(),
            ap: false,
            cpu_level: "",
            mem_level: "",
            disk_level: "",
            disk_label: "Disk /",
            health_note: String::new(),
            health_tone: "",
            widgets: crate::dashboard::all_on(crate::dashboard::Viewer {
                role: crate::auth::UserRole::Admin,
                access_point: false,
            }),
            hidden_widgets: vec![],
            layout_json: "{\"widgets\":[]}".to_string(),
            customized: false,
            traffic: vec![],
        }
    }

    fn dashboard(vpn_connections: usize, vpn_errors: Vec<String>) -> String {
        DashboardTemplate {
            vpn_connections,
            vpn_errors,
            ..dash_base()
        }
        .render()
        .unwrap()
    }

    /// The dashboard says whether the box has a way out, and through where.
    #[test]
    fn dashboard_shows_the_default_route_or_says_there_is_none() {
        let none = dashboard(0, vec![]);
        assert!(none.contains("No default route"), "{none}");
        let up = DashboardTemplate {
            internet_dev: "enp0s1".into(),
            internet_gw: "10.0.2.2".into(),
            dhcp_leases: Some(3),
            ..dash_base()
        }
        .render()
        .unwrap();
        assert!(
            up.contains("Present") && up.contains("10.0.2.2") && up.contains("enp0s1"),
            "{up}"
        );
    }

    /// The dashboard shows how many DHCP clients hold a lease, linked to the DHCP page.
    #[test]
    fn dashboard_dhcp_tile_counts_leases_and_hides_without_dhcp() {
        let hidden = dashboard(0, vec![]);
        assert!(!hidden.contains("dhcp-leases"), "{hidden}");
        let mut t = DashboardTemplate {
            dhcp_leases: Some(7),
            ..dash_base()
        };
        let shown = t.render().unwrap();
        assert!(
            shown.contains(r#"id="dhcp-leases">7</div>"#) && shown.contains(r#"href="/dhcp""#),
            "{shown}"
        );
        t.dhcp_leases = Some(0);
        assert!(t.render().unwrap().contains(r#"id="dhcp-leases">0</div>"#));
        // an access point leaves addresses to the main router: no router tiles
        t.ap = true;
        let ap = t.render().unwrap();
        assert!(
            !ap.contains(r#"id="dhcp-leases""#)
                && !ap.contains("active rules")
                && !ap.contains(r#"id="vpn-connections""#)
        );
        assert!(ap.contains("internet-card") && ap.contains(r#"id="ap-uplink""#));
    }

    /// The dashboard lists each interface with its WAN/LAN role, state, address, live rate and humanised
    /// byte counters, and one glyph for "no value".
    #[test]
    fn dashboard_lists_interfaces_with_roles() {
        let mut t = DashboardTemplate {
            iface_rows: vec![
                DashIface {
                    name: "enp0s1".into(),
                    role: "WAN".into(),
                    up: true,
                    addrs: "10.0.2.15/24".into(),
                    mac: "52:54:00:12:34:56".into(),
                    rate: "1.5 KB/s / 200 B/s".into(),
                    rx: "1.2 MB".into(),
                    tx: "300 KB".into(),
                    rx_bytes: 1_234_567,
                    tx_bytes: 300_000,
                },
                DashIface {
                    name: "enp0s3".into(),
                    ..Default::default()
                },
            ],
            traffic: vec![DashTraffic {
                name: "enp0s1".into(),
                rx: "1.5 KB/s".into(),
                tx: "200 B/s".into(),
            }],
            hidden_stubs: 3,
            ..dash_base()
        };
        let h = t.render().unwrap();
        assert!(
            h.contains(r#"iface-role">WAN</span>"#)
                && h.contains("enp0s1")
                && h.contains("10.0.2.15/24"),
            "{h}"
        );
        assert!(h.contains("enp0s3") && h.contains("down"), "{h}");
        assert!(
            h.contains(r#"data-traffic="enp0s1">1.5 KB/s / 200 B/s"#),
            "{h}"
        );
        assert!(h.contains(r#"data-v="1234567">1.2 MB"#), "{h}");
        assert!(
            h.contains(r#"<span class="nil" title="no address">&mdash;</span>"#),
            "{h}"
        );
        assert!(h.contains("3 kernel placeholder device(s)"), "{h}");
        t.iface_rows.clear();
        assert!(!t.render().unwrap().contains(r#"iface-role">"#));
    }

    /// Usage values carry their threshold tone and a sentence names what is over it; live refresh follows
    /// `dashboard.refresh_seconds` (0 = the page says it is a snapshot).
    #[test]
    fn dashboard_health_thresholds_and_live_refresh() {
        let mut t = DashboardTemplate {
            disk_level: "crit",
            health_note: "Disk / at 91 % (critical)".into(),
            health_tone: "crit",
            ..dash_base()
        };
        let h = t.render().unwrap();
        assert!(h.contains(r#"<div class="ui-usage crit">"#), "{h}");
        assert!(
            h.contains(r#"class="ui-banner crit" id="health-note""#),
            "{h}"
        );
        assert!(
            h.contains(r#"data-refresh="30""#) && h.contains("dash-live-toggle"),
            "{h}"
        );
        t.ui.refresh_secs = 0;
        t.health_note.clear();
        let h = t.render().unwrap();
        assert!(
            h.contains("snapshot")
                && !h.contains(r#"id="dash-live-toggle""#)
                && !h.contains(r#"id="health-note""#)
        );
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
    fn firewall_page() -> String {
        FirewallTemplate {
            page: "firewall",
            rules: vec![],
            nat_rules: vec![],
            aliases: vec![],
            filter_rules: vec![],
            enabled_filter_rules: 0,
            enabled_nat_rules: 0,
            accept_rules_count: 0,
            drop_rules_count: 0,
            port_forwards: vec![],
            one_to_one: vec![],
            npt: vec![],
            outbound_rules: vec![],
            host_aliases: vec![],
            port_aliases: vec![],
            schedules: vec![],
            interfaces: vec![],
            outbound_mode: "automatic".into(),
            auto_nat_interfaces: String::new(),
            gateways: vec![],
        }
        .render()
        .unwrap()
    }

    /// The app shell every page shares: sidebar, off-canvas phone nav,
    /// header, one `<main>`, the phone table scroll, and the active entry.
    fn assert_app_shell(html: &str, href: &str) {
        for needle in [
            r#"<aside class="sidebar" id="sidebar">"#,
            r#"id="menuToggle""#,
            r#"id="navBackdrop""#,
            r#"<main class="content">"#,
            r#"name="viewport" content="width=device-width"#,
            ".content table {",
            "position: relative;",
        ] {
            assert!(html.contains(needle), "shell markup missing: {needle}");
        }
        let active = format!(r#"<a href="{href}" class="nav-item active">"#);
        assert!(html.contains(&active), "sidebar entry {href} not active");
        assert_eq!(html.matches("<main").count(), 1, "exactly one <main>");
        assert_eq!(html.matches("<!DOCTYPE html>").count(), 1);
        assert!(
            !html.contains("&larr; Dashboard"),
            "bare back link of the old layout is back"
        );
        assert!(
            !html.contains("body { font-family: Arial"),
            "the old per-page body style is back"
        );
    }

    /// Finding 2026-11-18: Firewall and Interfaces still used the old
    /// unstyled standalone layout (no sidebar, no phone nav, 844/921 px
    /// wide at 390 px). Both now render inside `base.html`.
    #[test]
    fn firewall_page_uses_the_app_shell() {
        let html = firewall_page();
        assert_app_shell(&html, "/firewall");
        assert!(html.contains(r#"class="stat-grid""#));
        assert!(html.contains("data-tab=\"tab-rules\""), "tabs kept");
    }

    /// Finding 2026-11-18: the summary cards were dead text. Each now links to
    /// the tab that lists what it counts, and every target tab exists.
    #[test]
    fn firewall_summary_cards_link_to_their_tabs() {
        let html = firewall_page();
        for tab in ["tab-rules", "tab-pf", "tab-outbound"] {
            assert!(
                html.contains(&format!("class=\"stat-card stat-link\" href=\"#{tab}\"")),
                "a summary card links to {tab}"
            );
            assert!(html.contains(&format!("id=\"{tab}\"")), "{tab} exists");
        }
        assert_eq!(html.matches("stat-card stat-link").count(), 5);
    }

    #[test]
    fn interfaces_page_uses_the_app_shell() {
        let html = InterfacesTemplate { page: "interfaces" }.render().unwrap();
        assert_app_shell(&html, "/interfaces");
        assert!(html.contains(r#"id="devices""#), "interface table kept");
        assert!(html.contains(r#"id="edit-card""#), "edit form kept");
    }

    /// Source guard: neither page may go back to a standalone document.
    #[test]
    fn firewall_and_interfaces_templates_extend_base() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        for name in ["firewall.html", "interfaces.html"] {
            let src = std::fs::read_to_string(dir.join(name)).unwrap();
            assert!(
                src.trim_start().starts_with(r#"{% extends "base.html" %}"#),
                "{name} must extend base.html"
            );
            assert!(!src.contains("<!DOCTYPE"), "{name} is a standalone page");
        }
    }

    /// Source guard: on phones every form control is capped to its container, so
    /// `size="40"` inputs and `cols="70"` textareas cannot widen a page (/system +46px at 390px).
    #[test]
    fn base_caps_form_controls_on_phones() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let src = std::fs::read_to_string(dir.join("base.html")).unwrap();
        let mobile = src
            .split("@media (max-width: 900px)")
            .nth(1)
            .expect("mobile block");
        assert!(
            mobile.contains(".content select,"),
            "select not capped on phones"
        );
        assert!(
            mobile.contains("max-width: 100%;") && mobile.contains(".content input:not"),
            "inputs not capped on phones"
        );
    }

    /// Source guard: on desktop widths a table wider than the content column scrolls inside its own box
    /// and `.content` may shrink, so the page itself never scrolls sideways (/firewall +266px at 1280px).
    #[test]
    fn base_scrolls_wide_tables_on_desktop() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let src = std::fs::read_to_string(dir.join("base.html")).unwrap();
        assert!(
            src.contains(".content table.wide-scroll"),
            "wide-scroll rule missing"
        );
        assert!(
            src.contains("classList.add('wide-scroll')"),
            "script that applies it missing"
        );
        let content = src.split(".content {").nth(1).expect(".content rule");
        let content = content.split('}').next().unwrap();
        assert!(
            content.contains("min-width: 0"),
            ".content must be allowed to shrink"
        );
    }

    /// Source guard: pages report outcomes through `patNotice` (kit toast, or the open dialog for a refused
    /// change), never a blocking browser `alert()` box that hides the page and is announced inconsistently.
    #[test]
    fn templates_use_pat_notice_not_alert() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let mut bad = Vec::new();
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            let text = std::fs::read_to_string(&p).unwrap();
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let mut rest = line;
                while let Some(k) = rest.find("alert(") {
                    let before = rest[..k].chars().last();
                    if !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.') {
                        bad.push(format!("{}:{}", p.display(), i + 1));
                    }
                    rest = &rest[k + 6..];
                }
            }
        }
        assert!(bad.is_empty(), "alert() in templates: {bad:?}");
        let base = std::fs::read_to_string(dir.join("base.html")).unwrap();
        assert!(base.contains("function patNotice("), "patNotice missing");
    }
}
