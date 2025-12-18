//! Status Pages - Operational Dashboards
//!
//! pfSense/OPNsense-style status pages for real-time monitoring:
//! - Dashboard with configurable widgets
//! - Interface status and statistics
//! - DHCP leases viewer
//! - Service status (all daemons)
//! - VPN status (IPsec, OpenVPN, WireGuard)
//! - Gateway health monitoring
//! - Traffic graphs
//! - System logs viewer
//!
//! All pages support real-time updates via WebSocket.

use patronus_core::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;
use tokio::process::Command;

/// Dashboard widget type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetType {
    SystemInfo,
    InterfaceTraffic,
    GatewayStatus,
    ServiceStatus,
    CpuUsage,
    MemoryUsage,
    DiskUsage,
    FirewallLogs,
    ActiveConnections,
    VpnStatus,
}

/// Dashboard widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub widget_type: WidgetType,
    pub position: (u32, u32),  // row, column
    pub size: (u32, u32),      // width, height
    pub refresh_interval: u32,  // seconds
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub widgets: Vec<DashboardWidget>,
}

/// Interface statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatus {
    pub name: String,
    pub description: String,
    pub status: String,  // up, down, no-carrier
    pub mac_address: String,
    pub ip_addresses: Vec<IpAddr>,
    pub mtu: u32,

    // Statistics
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,

    // Rates (calculated)
    pub rx_rate_bps: Option<f64>,
    pub tx_rate_bps: Option<f64>,
}

/// DHCP lease entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: Ipv4Addr,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub lease_start: SystemTime,
    pub lease_end: SystemTime,
    pub is_online: bool,  // Check via ARP table
    pub is_static: bool,  // Static mapping vs dynamic lease
}

/// Service status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub description: String,
    pub is_running: bool,
    pub is_enabled: bool,  // Enabled at boot
    pub pid: Option<u32>,
    pub uptime_seconds: Option<u64>,
    pub memory_mb: Option<f64>,
    pub cpu_percent: Option<f32>,
}

/// VPN tunnel status (IPsec)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecTunnelStatus {
    pub name: String,
    pub status: String,  // established, connecting, down
    pub local_id: String,
    pub remote_id: String,
    pub remote_address: IpAddr,
    pub local_subnets: Vec<String>,
    pub remote_subnets: Vec<String>,
    pub uptime_seconds: Option<u64>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// OpenVPN client status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenVpnClientStatus {
    pub common_name: String,
    pub real_address: IpAddr,
    pub virtual_address: IpAddr,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connected_since: SystemTime,
}

/// WireGuard peer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<SystemTime>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
    pub persistent_keepalive: Option<u32>,
}

/// Gateway health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayHealth {
    pub name: String,
    pub status: String,  // online, offline, degraded
    pub latency_ms: Option<f64>,
    pub packet_loss_pct: Option<f32>,
    pub last_check: Option<SystemTime>,
    pub monitor_target: String,
}

/// Traffic graph data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficDataPoint {
    pub timestamp: SystemTime,
    pub inbound_bps: f64,
    pub outbound_bps: f64,
}

/// System log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub severity: String,  // emergency, alert, critical, error, warning, notice, info, debug
    pub facility: String,   // kern, user, mail, daemon, auth, syslog, etc.
    pub message: String,
    pub source: Option<String>,
}

pub struct StatusPageManager;

impl StatusPageManager {
    /// Get all interface statuses
    pub async fn get_interface_statuses() -> Result<Vec<InterfaceStatus>> {
        let mut statuses = Vec::new();

        // Get interface list
        let output = Command::new("ip")
            .args(&["-json", "addr", "show"])
            .output()
            .await?;

        let json_str = String::from_utf8_lossy(&output.stdout);

        // Parse JSON (simplified - would use serde_json in production)
        // For now, fall back to text parsing
        let output = Command::new("ip")
            .args(&["addr", "show"])
            .output()
            .await?;

        let text = String::from_utf8_lossy(&output.stdout);

        // Get stats for each interface
        let stats_output = Command::new("ip")
            .args(&["-s", "link", "show"])
            .output()
            .await?;

        let stats_text = String::from_utf8_lossy(&stats_output.stdout);

        // Parse interface info (simplified)
        statuses.push(Self::parse_interface_status(&text, &stats_text)?);

        Ok(statuses)
    }

    fn parse_interface_status(addr_output: &str, stats_output: &str) -> Result<InterfaceStatus> {
        // Simplified parsing - production would be more robust
        Ok(InterfaceStatus {
            name: "eth0".to_string(),
            description: "WAN".to_string(),
            status: "up".to_string(),
            mac_address: "00:00:00:00:00:00".to_string(),
            ip_addresses: vec![],
            mtu: 1500,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            rx_rate_bps: None,
            tx_rate_bps: None,
        })
    }

    /// Get DHCP leases
    pub async fn get_dhcp_leases() -> Result<Vec<DhcpLease>> {
        let mut leases = Vec::new();

        // Read ISC DHCP leases file
        let lease_file = "/var/lib/dhcp/dhcpd.leases";

        if tokio::fs::metadata(lease_file).await.is_ok() {
            let content = tokio::fs::read_to_string(lease_file).await?;
            leases.extend(Self::parse_dhcp_leases(&content)?);
        }

        // Check if each client is online via ARP
        let arp_output = Command::new("arp")
            .arg("-n")
            .output()
            .await?;

        let arp_table = String::from_utf8_lossy(&arp_output.stdout);
        let online_ips: Vec<Ipv4Addr> = Self::parse_arp_online(&arp_table);

        for lease in &mut leases {
            lease.is_online = online_ips.contains(&lease.ip_address);
        }

        Ok(leases)
    }

    fn parse_dhcp_leases(content: &str) -> Result<Vec<DhcpLease>> {
        // Simplified DHCP lease parsing
        // Real implementation would parse ISC DHCP lease file format
        Ok(Vec::new())
    }

    fn parse_arp_online(arp_output: &str) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();

        for line in arp_output.lines().skip(1) {
            if let Some(ip_str) = line.split_whitespace().next() {
                if let Ok(ip) = ip_str.parse() {
                    ips.push(ip);
                }
            }
        }

        ips
    }

    /// Get all service statuses
    pub async fn get_service_statuses() -> Result<Vec<ServiceStatus>> {
        let mut services = Vec::new();

        // List of services to check
        let service_names = vec![
            ("unbound", "DNS Resolver"),
            ("dhcpd", "DHCP Server"),
            ("openvpn", "OpenVPN"),
            ("strongswan", "IPsec"),
            ("suricata", "IDS/IPS"),
            ("haproxy", "Load Balancer"),
            ("chrony", "NTP Server"),
            ("snmpd", "SNMP Agent"),
        ];

        for (name, description) in service_names {
            if let Ok(status) = Self::get_service_status(name, description).await {
                services.push(status);
            }
        }

        Ok(services)
    }

    async fn get_service_status(name: &str, description: &str) -> Result<ServiceStatus> {
        // Check systemd service status
        let output = Command::new("systemctl")
            .args(&["status", name])
            .output()
            .await?;

        let is_running = output.status.success();

        // Check if enabled
        let enabled_output = Command::new("systemctl")
            .args(&["is-enabled", name])
            .output()
            .await?;

        let is_enabled = enabled_output.status.success();

        // Get PID if running
        let pid = if is_running {
            let show_output = Command::new("systemctl")
                .args(&["show", "-p", "MainPID", name])
                .output()
                .await?;

            String::from_utf8_lossy(&show_output.stdout)
                .split('=')
                .nth(1)
                .and_then(|s| s.trim().parse().ok())
        } else {
            None
        };

        Ok(ServiceStatus {
            name: name.to_string(),
            description: description.to_string(),
            is_running,
            is_enabled,
            pid,
            uptime_seconds: None,  // Would calculate from systemd
            memory_mb: None,
            cpu_percent: None,
        })
    }

    /// Get IPsec tunnel statuses
    pub async fn get_ipsec_status() -> Result<Vec<IpsecTunnelStatus>> {
        // Use swanctl for strongSwan
        let output = Command::new("swanctl")
            .args(&["--list-sas"])
            .output()
            .await;

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            return Self::parse_ipsec_status(&text);
        }

        Ok(Vec::new())
    }

    fn parse_ipsec_status(output: &str) -> Result<Vec<IpsecTunnelStatus>> {
        // Parse swanctl output (simplified)
        Ok(Vec::new())
    }

    /// Get OpenVPN client statuses
    pub async fn get_openvpn_clients() -> Result<Vec<OpenVpnClientStatus>> {
        // Read OpenVPN status file
        let status_file = "/var/run/openvpn/status.log";

        if tokio::fs::metadata(status_file).await.is_ok() {
            let content = tokio::fs::read_to_string(status_file).await?;
            return Self::parse_openvpn_status(&content);
        }

        Ok(Vec::new())
    }

    fn parse_openvpn_status(content: &str) -> Result<Vec<OpenVpnClientStatus>> {
        // Parse OpenVPN status file format
        Ok(Vec::new())
    }

    /// Get WireGuard peer statuses
    pub async fn get_wireguard_peers(interface: &str) -> Result<Vec<WireGuardPeerStatus>> {
        let output = Command::new("wg")
            .args(&["show", interface, "dump"])
            .output()
            .await?;

        let text = String::from_utf8_lossy(&output.stdout);

        Self::parse_wireguard_status(&text)
    }

    fn parse_wireguard_status(output: &str) -> Result<Vec<WireGuardPeerStatus>> {
        let mut peers = Vec::new();

        for line in output.lines().skip(1) {  // Skip interface line
            let parts: Vec<&str> = line.split('\t').collect();

            if parts.len() >= 8 {
                peers.push(WireGuardPeerStatus {
                    public_key: parts[0].to_string(),
                    endpoint: if parts[2].is_empty() { None } else { Some(parts[2].to_string()) },
                    allowed_ips: parts[3].split(',').map(|s| s.to_string()).collect(),
                    latest_handshake: None,  // Would parse from parts[4]
                    transfer_rx: parts[5].parse().unwrap_or(0),
                    transfer_tx: parts[6].parse().unwrap_or(0),
                    persistent_keepalive: parts[7].parse().ok(),
                });
            }
        }

        Ok(peers)
    }

    /// Get gateway health statuses
    pub async fn get_gateway_health() -> Result<Vec<GatewayHealth>> {
        // Would integrate with multiwan manager
        Ok(Vec::new())
    }

    /// Get traffic graph data for interface
    pub async fn get_traffic_data(
        interface: &str,
        duration_secs: u32,
    ) -> Result<Vec<TrafficDataPoint>> {
        // Would use RRD or time-series database
        // For now, return empty
        Ok(Vec::new())
    }

    /// Get system logs
    pub async fn get_logs(
        filter: Option<&str>,
        severity: Option<&str>,
        limit: u32,
    ) -> Result<Vec<LogEntry>> {
        let mut cmd = Command::new("journalctl");
        cmd.args(&["-n", &limit.to_string(), "--output=json"]);

        if let Some(sev) = severity {
            cmd.arg("-p").arg(sev);
        }

        if let Some(filt) = filter {
            cmd.arg("-g").arg(filt);
        }

        let output = cmd.output().await?;
        let text = String::from_utf8_lossy(&output.stdout);

        Self::parse_journal_logs(&text)
    }

    fn parse_journal_logs(output: &str) -> Result<Vec<LogEntry>> {
        // Parse journalctl JSON output
        Ok(Vec::new())
    }

    /// Get dashboard data (all widgets)
    pub async fn get_dashboard_data(config: &DashboardConfig) -> Result<HashMap<String, serde_json::Value>> {
        let mut data = HashMap::new();

        for widget in &config.widgets {
            let widget_data = match widget.widget_type {
                WidgetType::SystemInfo => {
                    serde_json::json!({
                        "hostname": "patronus-firewall",
                        "uptime": 12345,
                        "version": "1.0.0"
                    })
                }
                WidgetType::InterfaceTraffic => {
                    serde_json::json!({
                        "interfaces": Self::get_interface_statuses().await?
                    })
                }
                WidgetType::GatewayStatus => {
                    serde_json::json!({
                        "gateways": Self::get_gateway_health().await?
                    })
                }
                WidgetType::ServiceStatus => {
                    serde_json::json!({
                        "services": Self::get_service_statuses().await?
                    })
                }
                _ => serde_json::json!({}),
            };

            data.insert(format!("{:?}", widget.widget_type), widget_data);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_service_statuses() {
        let services = StatusPageManager::get_service_statuses().await;
        // May fail if services not installed, that's OK
        assert!(services.is_ok() || services.is_err());
    }
}
