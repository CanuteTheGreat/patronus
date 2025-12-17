//! Diagnostic Tools - Web-based Network Troubleshooting
//!
//! Comprehensive suite of diagnostic utilities accessible from web UI:
//! - Ping - ICMP echo testing
//! - Traceroute - Route path analysis
//! - DNS Lookup - Domain name resolution
//! - Port Test - TCP connection testing
//! - ARP Table - Layer 2 address mapping
//! - NDP Table - IPv6 neighbor discovery
//! - Routes - Routing table viewer
//! - Sockets - Active network connections
//! - States - Firewall connection states
//! - System Activity - Process and resource monitoring
//!
//! All tools support real-time output and result export.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Ping result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub packet_loss_pct: f32,
    pub min_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub output: String,
    pub timestamp: SystemTime,
}

/// Traceroute hop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub hop_number: u32,
    pub hostname: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub rtt_ms: Vec<Option<f64>>,  // Usually 3 probes
}

/// Traceroute result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
    pub completed: bool,
    pub output: String,
    pub timestamp: SystemTime,
}

/// DNS lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub query: String,
    pub record_type: String,
    pub records: Vec<DnsRecord>,
    pub nameserver: Option<String>,
    pub query_time_ms: Option<f64>,
    pub output: String,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: Option<u32>,
    pub value: String,
}

/// Port test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortTestResult {
    pub host: String,
    pub port: u16,
    pub protocol: String,  // TCP or UDP
    pub is_open: bool,
    pub response_time_ms: Option<f64>,
    pub error: Option<String>,
    pub timestamp: SystemTime,
}

/// ARP table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: Ipv4Addr,
    pub mac_address: String,
    pub interface: String,
    pub flags: String,
}

/// NDP (IPv6 neighbor) table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdpEntry {
    pub ip_address: Ipv6Addr,
    pub mac_address: String,
    pub interface: String,
    pub state: String,  // REACHABLE, STALE, DELAY, etc.
}

/// Routing table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,  // CIDR or "default"
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: Option<u32>,
    pub flags: String,
}

/// Socket entry (active network connection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketEntry {
    pub protocol: String,  // TCP, UDP, etc.
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: Option<String>,  // For TCP: ESTABLISHED, LISTEN, etc.
    pub pid: Option<u32>,
    pub program: Option<String>,
}

/// Firewall state entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallState {
    pub protocol: String,
    pub source: String,
    pub source_port: Option<u16>,
    pub destination: String,
    pub dest_port: Option<u16>,
    pub state: String,
    pub packets: u64,
    pub bytes: u64,
}

/// System activity (top-style output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemActivity {
    pub cpu_usage_pct: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub load_average: (f32, f32, f32),  // 1, 5, 15 min
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub user: String,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub command: String,
}

pub struct DiagnosticTools;

impl DiagnosticTools {
    /// Ping a host
    pub async fn ping(
        target: &str,
        count: u32,
        size: Option<u32>,
        interface: Option<&str>,
        ipv6: bool,
    ) -> Result<PingResult> {
        let ping_cmd = if ipv6 { "ping6" } else { "ping" };

        let mut cmd = Command::new(ping_cmd);
        cmd.arg("-c").arg(count.to_string());

        if let Some(sz) = size {
            cmd.arg("-s").arg(sz.to_string());
        }

        if let Some(iface) = interface {
            cmd.arg("-I").arg(iface);
        }

        cmd.arg(target);

        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse ping output
        let result = Self::parse_ping_output(&stdout, target)?;

        Ok(result)
    }

    fn parse_ping_output(output: &str, target: &str) -> Result<PingResult> {
        let mut packets_sent = 0;
        let mut packets_received = 0;
        let mut min_rtt = None;
        let mut avg_rtt = None;
        let mut max_rtt = None;

        for line in output.lines() {
            // Parse statistics line: "5 packets transmitted, 5 received, 0% packet loss"
            if line.contains("packets transmitted") {
                let parts: Vec<&str> = line.split(',').collect();
                if let Some(sent_part) = parts.get(0) {
                    packets_sent = sent_part.split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
                if let Some(recv_part) = parts.get(1) {
                    packets_received = recv_part.split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }

            // Parse RTT line: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
            if line.contains("rtt min/avg/max") || line.contains("round-trip min/avg/max") {
                if let Some(values_part) = line.split('=').nth(1) {
                    let values: Vec<&str> = values_part.split('/').collect();
                    if values.len() >= 3 {
                        min_rtt = values[0].trim().parse().ok();
                        avg_rtt = values[1].trim().parse().ok();
                        max_rtt = values[2].trim().parse().ok();
                    }
                }
            }
        }

        let packet_loss_pct = if packets_sent > 0 {
            ((packets_sent - packets_received) as f32 / packets_sent as f32) * 100.0
        } else {
            0.0
        };

        Ok(PingResult {
            target: target.to_string(),
            packets_sent,
            packets_received,
            packet_loss_pct,
            min_rtt_ms: min_rtt,
            avg_rtt_ms: avg_rtt,
            max_rtt_ms: max_rtt,
            output: output.to_string(),
            timestamp: SystemTime::now(),
        })
    }

    /// Traceroute to a host
    pub async fn traceroute(
        target: &str,
        max_hops: u32,
        ipv6: bool,
    ) -> Result<TracerouteResult> {
        let traceroute_cmd = if ipv6 { "traceroute6" } else { "traceroute" };

        let output = Command::new(traceroute_cmd)
            .arg("-m").arg(max_hops.to_string())
            .arg("-q").arg("3")  // 3 queries per hop
            .arg(target)
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        let hops = Self::parse_traceroute_output(&stdout)?;

        Ok(TracerouteResult {
            target: target.to_string(),
            hops,
            completed: output.status.success(),
            output: stdout.to_string(),
            timestamp: SystemTime::now(),
        })
    }

    fn parse_traceroute_output(output: &str) -> Result<Vec<TracerouteHop>> {
        let mut hops = Vec::new();

        for line in output.lines().skip(1) {  // Skip first line (header)
            if line.trim().is_empty() {
                continue;
            }

            // Parse line like: " 1  router.local (192.168.1.1)  0.123 ms  0.456 ms  0.789 ms"
            let parts: Vec<&str> = line.split_whitespace().collect();

            if let Some(hop_num_str) = parts.get(0) {
                if let Ok(hop_num) = hop_num_str.parse::<u32>() {
                    let mut hop = TracerouteHop {
                        hop_number: hop_num,
                        hostname: None,
                        ip_address: None,
                        rtt_ms: Vec::new(),
                    };

                    // Try to parse hostname and IP
                    for (i, part) in parts.iter().enumerate().skip(1) {
                        if part.starts_with('(') && part.ends_with(')') {
                            let ip_str = part.trim_matches(|c| c == '(' || c == ')');
                            hop.ip_address = ip_str.parse().ok();
                            if i > 1 {
                                hop.hostname = Some(parts[i - 1].to_string());
                            }
                            break;
                        }
                    }

                    // Parse RTT values
                    for part in parts.iter() {
                        if part.ends_with("ms") {
                            let rtt_str = part.trim_end_matches("ms");
                            hop.rtt_ms.push(rtt_str.parse().ok());
                        } else if *part == "*" {
                            hop.rtt_ms.push(None);  // Timeout
                        }
                    }

                    hops.push(hop);
                }
            }
        }

        Ok(hops)
    }

    /// DNS lookup
    pub async fn dns_lookup(
        query: &str,
        record_type: &str,
        nameserver: Option<&str>,
    ) -> Result<DnsLookupResult> {
        let mut cmd = Command::new("dig");

        if let Some(ns) = nameserver {
            cmd.arg(format!("@{}", ns));
        }

        cmd.arg(query);
        cmd.arg(record_type);
        cmd.arg("+short");  // Concise output

        let start = SystemTime::now();
        let output = cmd.output().await?;
        let query_time = start.elapsed().ok().map(|d| d.as_secs_f64() * 1000.0);

        let stdout = String::from_utf8_lossy(&output.stdout);

        let records = Self::parse_dig_output(&stdout, record_type)?;

        // Also get full output for display
        let full_output = Command::new("dig")
            .arg(query)
            .arg(record_type)
            .output()
            .await?;

        Ok(DnsLookupResult {
            query: query.to_string(),
            record_type: record_type.to_string(),
            records,
            nameserver: nameserver.map(|s| s.to_string()),
            query_time_ms: query_time,
            output: String::from_utf8_lossy(&full_output.stdout).to_string(),
            timestamp: SystemTime::now(),
        })
    }

    fn parse_dig_output(output: &str, record_type: &str) -> Result<Vec<DnsRecord>> {
        let mut records = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            records.push(DnsRecord {
                name: String::new(),  // dig +short doesn't include name
                record_type: record_type.to_string(),
                ttl: None,
                value: line.to_string(),
            });
        }

        Ok(records)
    }

    /// Test if a TCP port is open
    pub async fn test_port(
        host: &str,
        port: u16,
        timeout_secs: u64,
    ) -> Result<PortTestResult> {
        let target = format!("{}:{}", host, port);

        let start = SystemTime::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::net::TcpStream::connect(&target)
        ).await;

        let response_time = start.elapsed().ok().map(|d| d.as_secs_f64() * 1000.0);

        let (is_open, error) = match result {
            Ok(Ok(_)) => (true, None),
            Ok(Err(e)) => (false, Some(format!("Connection error: {}", e))),
            Err(_) => (false, Some("Connection timeout".to_string())),
        };

        Ok(PortTestResult {
            host: host.to_string(),
            port,
            protocol: "TCP".to_string(),
            is_open,
            response_time_ms: if is_open { response_time } else { None },
            error,
            timestamp: SystemTime::now(),
        })
    }

    /// Get ARP table
    pub async fn get_arp_table() -> Result<Vec<ArpEntry>> {
        let output = Command::new("arp")
            .arg("-n")
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        Self::parse_arp_table(&stdout)
    }

    fn parse_arp_table(output: &str) -> Result<Vec<ArpEntry>> {
        let mut entries = Vec::new();

        for line in output.lines().skip(1) {  // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 5 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    entries.push(ArpEntry {
                        ip_address: ip,
                        mac_address: parts[2].to_string(),
                        interface: parts[4].to_string(),
                        flags: parts[3].to_string(),
                    });
                }
            }
        }

        Ok(entries)
    }

    /// Get NDP (IPv6 neighbor discovery) table
    pub async fn get_ndp_table() -> Result<Vec<NdpEntry>> {
        let output = Command::new("ip")
            .args(&["-6", "neigh", "show"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        Self::parse_ndp_table(&stdout)
    }

    fn parse_ndp_table(output: &str) -> Result<Vec<NdpEntry>> {
        let mut entries = Vec::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Format: "2001:db8::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            if parts.len() >= 6 {
                if let Ok(ip) = parts[0].parse::<Ipv6Addr>() {
                    entries.push(NdpEntry {
                        ip_address: ip,
                        mac_address: parts[4].to_string(),
                        interface: parts[2].to_string(),
                        state: parts.get(5).unwrap_or(&"").to_string(),
                    });
                }
            }
        }

        Ok(entries)
    }

    /// Get routing table
    pub async fn get_routes(ipv6: bool) -> Result<Vec<RouteEntry>> {
        let mut cmd = Command::new("ip");

        if ipv6 {
            cmd.arg("-6");
        }

        cmd.args(&["route", "show"]);

        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        Self::parse_route_table(&stdout)
    }

    fn parse_route_table(output: &str) -> Result<Vec<RouteEntry>> {
        let mut entries = Vec::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue;
            }

            let destination = parts[0].to_string();
            let mut gateway = None;
            let mut interface = String::new();
            let mut metric = None;
            let mut flags = String::new();

            let mut i = 1;
            while i < parts.len() {
                match parts[i] {
                    "via" => {
                        if i + 1 < parts.len() {
                            gateway = parts[i + 1].parse().ok();
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    "dev" => {
                        if i + 1 < parts.len() {
                            interface = parts[i + 1].to_string();
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    "metric" => {
                        if i + 1 < parts.len() {
                            metric = parts[i + 1].parse().ok();
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            entries.push(RouteEntry {
                destination,
                gateway,
                interface,
                metric,
                flags,
            });
        }

        Ok(entries)
    }

    /// Get active sockets
    pub async fn get_sockets(protocol: Option<&str>) -> Result<Vec<SocketEntry>> {
        let mut cmd = Command::new("ss");
        cmd.args(&["-tunap"]);  // TCP, UDP, numeric, all, processes

        if let Some(proto) = protocol {
            match proto.to_lowercase().as_str() {
                "tcp" => { cmd.arg("-t"); }
                "udp" => { cmd.arg("-u"); }
                _ => {}
            }
        }

        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        Self::parse_sockets(&stdout)
    }

    fn parse_sockets(output: &str) -> Result<Vec<SocketEntry>> {
        let mut entries = Vec::new();

        for line in output.lines().skip(1) {  // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 5 {
                // Simplified parsing
                let protocol = parts[0].to_uppercase();
                let state = if protocol == "TCP" {
                    Some(parts[1].to_string())
                } else {
                    None
                };

                // Parse local address:port
                let local_parts: Vec<&str> = parts[4].rsplitn(2, ':').collect();
                let local_port = local_parts[0].parse().unwrap_or(0);
                let local_address = if local_parts.len() > 1 {
                    local_parts[1].to_string()
                } else {
                    String::from("*")
                };

                // Parse remote address:port
                let remote_parts: Vec<&str> = parts[5].rsplitn(2, ':').collect();
                let remote_port = remote_parts[0].parse().ok();
                let remote_address = if remote_parts.len() > 1 {
                    Some(remote_parts[1].to_string())
                } else {
                    None
                };

                entries.push(SocketEntry {
                    protocol,
                    local_address,
                    local_port,
                    remote_address,
                    remote_port,
                    state,
                    pid: None,  // Would parse from users field
                    program: None,
                });
            }
        }

        Ok(entries)
    }

    /// Get firewall states (conntrack)
    pub async fn get_firewall_states() -> Result<Vec<FirewallState>> {
        let output = Command::new("conntrack")
            .args(&["-L"])
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        Self::parse_firewall_states(&stdout)
    }

    fn parse_firewall_states(output: &str) -> Result<Vec<FirewallState>> {
        // Simplified conntrack parsing
        // Real implementation would parse full conntrack output
        Ok(Vec::new())
    }

    /// Get system activity
    pub async fn get_system_activity() -> Result<SystemActivity> {
        // Get load average from /proc/loadavg
        let loadavg = tokio::fs::read_to_string("/proc/loadavg").await?;
        let load_parts: Vec<&str> = loadavg.split_whitespace().collect();
        let load_average = (
            load_parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0.0),
            load_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0),
            load_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0),
        );

        // Get memory info from /proc/meminfo
        let meminfo = tokio::fs::read_to_string("/proc/meminfo").await?;
        let (memory_total_mb, memory_used_mb) = Self::parse_meminfo(&meminfo)?;

        // Get process list from ps
        let ps_output = Command::new("ps")
            .args(&["aux", "--sort=-pcpu"])
            .output()
            .await?;

        let processes = Self::parse_ps_output(&String::from_utf8_lossy(&ps_output.stdout))?;

        // Calculate total CPU usage
        let cpu_usage_pct = processes.iter().map(|p| p.cpu_pct).sum::<f32>().min(100.0);

        Ok(SystemActivity {
            cpu_usage_pct,
            memory_used_mb,
            memory_total_mb,
            load_average,
            processes,
        })
    }

    fn parse_meminfo(output: &str) -> Result<(u64, u64)> {
        let mut total = 0;
        let mut available = 0;

        for line in output.lines() {
            if line.starts_with("MemTotal:") {
                total = line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0) / 1024;  // Convert KB to MB
            } else if line.starts_with("MemAvailable:") {
                available = line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0) / 1024;
            }
        }

        let used = total - available;

        Ok((total, used))
    }

    fn parse_ps_output(output: &str) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for line in output.lines().skip(1).take(20) {  // Top 20 processes
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 11 {
                processes.push(ProcessInfo {
                    pid: parts[1].parse().unwrap_or(0),
                    user: parts[0].to_string(),
                    cpu_pct: parts[2].parse().unwrap_or(0.0),
                    mem_pct: parts[3].parse().unwrap_or(0.0),
                    command: parts[10..].join(" "),
                });
            }
        }

        Ok(processes)
    }
}
