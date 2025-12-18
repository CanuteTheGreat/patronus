//! Web request handlers

use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
};
use askama::Template;
use patronus_network;
use serde_json::json;
use sysinfo::{System, Disks, Networks};

use crate::{
    state::AppState,
    templates::{DashboardTemplate, SystemInfo, InterfaceInfo, FirewallTemplate, Alias},
};

/// Get system metrics using sysinfo
fn get_system_metrics() -> (f32, f32, f32, (f64, f64, f64), u64) {
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU usage (average across all cores)
    let cpu_usage = sys.global_cpu_usage();

    // Memory usage (percentage)
    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let memory_usage = if total_memory > 0 {
        (used_memory as f32 / total_memory as f32) * 100.0
    } else {
        0.0
    };

    // Disk usage (percentage of root filesystem)
    let disks = Disks::new_with_refreshed_list();
    let disk_usage = disks.list().iter()
        .find(|d| d.mount_point() == std::path::Path::new("/"))
        .map(|d| {
            let total = d.total_space();
            let available = d.available_space();
            if total > 0 {
                ((total - available) as f32 / total as f32) * 100.0
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    // Load average
    let load_avg = System::load_average();

    // Uptime
    let uptime = System::uptime();

    (cpu_usage, memory_usage, disk_usage, (load_avg.one, load_avg.five, load_avg.fifteen), uptime)
}

/// Get network interface traffic stats
fn get_interface_traffic() -> std::collections::HashMap<String, (u64, u64)> {
    let networks = Networks::new_with_refreshed_list();
    networks.list()
        .iter()
        .map(|(name, data)| {
            (name.clone(), (data.received(), data.transmitted()))
        })
        .collect()
}

/// Index page handler (dashboard)
pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    // Get actual system metrics
    let (cpu_usage, memory_usage, disk_usage, load_avg, uptime) = get_system_metrics();
    let traffic_stats = get_interface_traffic();

    // Convert interfaces to template format
    let interfaces = patronus_network::list_interfaces().await
        .unwrap_or_default()
        .into_iter()
        .map(|iface| {
            let (rx_bytes, tx_bytes) = traffic_stats.get(&iface.name)
                .copied()
                .unwrap_or((0, 0));

            InterfaceInfo {
                name: iface.name.clone(),
                state: if iface.enabled { "UP".to_string() } else { "DOWN".to_string() },
                ip_address: iface.ip_addresses.first().map(|ip| ip.to_string()),
                ip_addresses: iface.ip_addresses.iter().map(|ip| ip.to_string()).collect(),
                mac_address: iface.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                rx_bytes,
                tx_bytes,
                mtu: iface.mtu,
                enabled: iface.enabled,
                interface_type: "Ethernet".to_string(), // Default type
                ip_display: iface.ip_addresses.first().map(|ip| ip.to_string()).unwrap_or_else(|| "N/A".to_string()),
                mac_display: iface.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
                speed_display: "1 Gbps".to_string(), // Default speed
            }
        })
        .collect();

    let active_rules = state.firewall.list_rules().await.unwrap_or_default().len();

    // Count VPN interfaces (wg* or tun* interfaces)
    let vpn_connections = patronus_network::list_interfaces().await
        .unwrap_or_default()
        .iter()
        .filter(|iface| iface.name.starts_with("wg") || iface.name.starts_with("tun"))
        .filter(|iface| iface.enabled)
        .count();

    let system_info = SystemInfo {
        hostname: std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "patronus".to_string())
            .trim()
            .to_string(),
        uptime,
        cpu_usage: cpu_usage as f64,
        memory_usage: memory_usage as f64,
        disk_usage: disk_usage as f64,
        load_avg,
    };

    let template = DashboardTemplate {
        interfaces,
        active_rules,
        vpn_connections,
        system_info,
    };

    Html(template.render().unwrap())
}

/// List network interfaces (JSON API)
pub async fn list_interfaces() -> impl IntoResponse {
    match patronus_network::list_interfaces().await {
        Ok(interfaces) => Json(json!({ "interfaces": interfaces })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}


/// Firewall management page
pub async fn firewall_page(State(state): State<AppState>) -> impl IntoResponse {
    // The firewall service already returns template types directly
    let filter_rules = state.firewall.list_rules().await.unwrap_or_default();
    let nat_rules = state.firewall.list_nat_rules().await.unwrap_or_default();

    let aliases: Vec<Alias> = vec![]; // TODO: Get actual aliases
    let enabled_filter_rules = filter_rules.iter().filter(|r| r.enabled).count();
    let enabled_nat_rules = nat_rules.iter().filter(|r| r.enabled).count();
    let accept_rules_count = filter_rules.iter().filter(|r| r.action == "Accept").count();
    let drop_rules_count = filter_rules.iter().filter(|r| r.action == "Drop").count();

    let template = FirewallTemplate {
        rules: filter_rules.clone(),
        nat_rules,
        aliases,
        filter_rules,
        enabled_filter_rules,
        enabled_nat_rules,
        accept_rules_count,
        drop_rules_count,
    };

    Html(template.render().unwrap())
}

/// List firewall rules (JSON API)
pub async fn list_firewall_rules(State(state): State<AppState>) -> impl IntoResponse {
    match state.firewall.list_rules().await {
        Ok(rules) => Json(json!({ "rules": rules })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}
