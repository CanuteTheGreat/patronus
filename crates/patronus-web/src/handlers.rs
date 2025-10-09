//! Web request handlers

use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
};
use askama::Template;
use patronus_core::types::{FirewallRule, Interface};
use patronus_network;
use serde_json::json;

use crate::state::AppState;

/// Dashboard template
#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    page: String,
    firewall_status: String,
    filter_rules_count: usize,
    nat_rules_count: usize,
    interfaces_count: usize,
    interfaces_up: usize,
    interfaces_down: usize,
    routes_count: usize,
    load_avg: String,
    interfaces: Vec<Interface>,
    filter_rules: Vec<FirewallRule>,
    hostname: String,
    kernel_version: String,
    uptime: String,
    arch: String,
}

/// Index page handler (dashboard)
pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    // Get system information
    let interfaces = patronus_network::list_interfaces().await.unwrap_or_default();
    let filter_rules = state.rule_manager.list_filter_rules().await.unwrap_or_default();
    let nat_rules = state.rule_manager.list_nat_rules().await.unwrap_or_default();

    let interfaces_up = interfaces.iter().filter(|i| i.enabled).count();
    let interfaces_down = interfaces.len() - interfaces_up;

    // Get system info
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "patronus".to_string())
        .trim()
        .to_string();

    let kernel_version = std::fs::read_to_string("/proc/version")
        .map(|v| v.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|_| "Unknown".to_string());

    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()))
        .map(|secs| format!("{:.0} hours", secs / 3600.0))
        .unwrap_or_else(|| "Unknown".to_string());

    let load_avg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .unwrap_or_else(|| "0.00".to_string());

    let arch = std::env::consts::ARCH.to_string();

    // Get route count
    let routes_count = std::fs::read_to_string("/proc/net/route")
        .ok()
        .map(|content| content.lines().count().saturating_sub(1)) // Subtract header line
        .unwrap_or(0);

    let template = DashboardTemplate {
        page: "dashboard".to_string(),
        firewall_status: "Active".to_string(),
        filter_rules_count: filter_rules.len(),
        nat_rules_count: nat_rules.len(),
        interfaces_count: interfaces.len(),
        interfaces_up,
        interfaces_down,
        routes_count,
        load_avg,
        interfaces,
        filter_rules: filter_rules.into_iter().take(10).collect(), // Show first 10
        hostname,
        kernel_version,
        uptime,
        arch,
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

/// Firewall rules page template
#[derive(Template)]
#[template(path = "firewall.html")]
struct FirewallTemplate {
    page: String,
    filter_rules: Vec<FirewallRule>,
    nat_rules: Vec<patronus_core::types::NatRule>,
}

/// Firewall management page
pub async fn firewall_page(State(state): State<AppState>) -> impl IntoResponse {
    let filter_rules = state.rule_manager.list_filter_rules().await.unwrap_or_default();
    let nat_rules = state.rule_manager.list_nat_rules().await.unwrap_or_default();

    let template = FirewallTemplate {
        page: "firewall".to_string(),
        filter_rules,
        nat_rules,
    };

    Html(template.render().unwrap())
}

/// List firewall rules (JSON API)
pub async fn list_firewall_rules(State(state): State<AppState>) -> impl IntoResponse {
    match state.rule_manager.list_filter_rules().await {
        Ok(rules) => Json(json!({ "rules": rules })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}
