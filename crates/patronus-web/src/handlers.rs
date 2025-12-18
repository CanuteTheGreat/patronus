//! Web request handlers

use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
};
use askama::Template;
use patronus_network;
use serde_json::json;

use crate::{
    state::AppState,
    templates::{DashboardTemplate, SystemInfo, InterfaceInfo, FirewallTemplate, Alias},
};

/// Index page handler (dashboard)
pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    // Convert interfaces to template format
    let interfaces = patronus_network::list_interfaces().await
        .unwrap_or_default()
        .into_iter()
        .map(|iface| InterfaceInfo {
            name: iface.name.clone(),
            state: if iface.enabled { "UP".to_string() } else { "DOWN".to_string() },
            ip_address: iface.ip_addresses.first().map(|ip| ip.to_string()),
            ip_addresses: iface.ip_addresses.iter().map(|ip| ip.to_string()).collect(),
            mac_address: iface.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
            rx_bytes: 0, // TODO: Get from system stats
            tx_bytes: 0, // TODO: Get from system stats
            mtu: iface.mtu,
            enabled: iface.enabled,
            interface_type: "Ethernet".to_string(), // Default type
            ip_display: iface.ip_addresses.first().map(|ip| ip.to_string()).unwrap_or_else(|| "N/A".to_string()),
            mac_display: iface.mac_address.clone().unwrap_or_else(|| "N/A".to_string()),
            speed_display: "1 Gbps".to_string(), // Default speed
        })
        .collect();

    let active_rules = state.firewall.list_rules().await.unwrap_or_default().len();
    let vpn_connections = 0; // TODO: Get actual VPN connection count

    let system_info = SystemInfo {
        hostname: std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "patronus".to_string())
            .trim()
            .to_string(),
        uptime: 0, // TODO: Get actual uptime
        cpu_usage: 0.0, // TODO: Get actual CPU usage
        memory_usage: 0.0, // TODO: Get actual memory usage
        disk_usage: 0.0, // TODO: Get actual disk usage
        load_avg: (0.0, 0.0, 0.0), // TODO: Get actual load average
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
