//! HTML page handlers
//!
//! These handlers render Askama templates with data from the application
//! state. Every value on these pages is read from the store or the live
//! system; where nothing exists the page says so (empty state), it never
//! fills in sample values.

use crate::{
    state::{host, AppState},
    templates::{
        DashboardTemplate, MonitoringTemplate, NetworkTemplate, SystemTemplate, VpnTemplate,
    },
};
use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

/// Login page template
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate;

fn render(t: &impl Template, what: &str) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render {what} template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Login page (public)
pub async fn login_page() -> Response {
    render(&LoginTemplate, "login")
}

/// Dashboard page (`/`).
pub async fn dashboard(State(state): State<AppState>) -> Response {
    let interfaces = state.interfaces.list_template().await.unwrap_or_else(|e| {
        tracing::error!("Failed to fetch interfaces: {}", e);
        vec![]
    });
    let active_rules = state
        .firewall
        .count_active_rules()
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to count firewall rules: {}", e);
            0
        });
    let vpn = state.vpn.snapshot().await;
    let vpn_connections = vpn.active_connections();
    // A failed read makes the count a floor (a live tunnel may hide behind
    // it), so the tile shows the error instead of a bare number.
    let vpn_errors = vpn.read_errors();
    let system_info = state.system.get_info().await.unwrap_or_default();
    let services = state.system.list_services().await.unwrap_or_default();
    let template = DashboardTemplate {
        page: "dashboard",
        uptime: host::format_duration(system_info.uptime),
        interfaces,
        active_rules,
        vpn_connections,
        vpn_errors,
        system_info,
        services,
    };
    render(&template, "dashboard")
}

/// Firewall rules page (rules, NAT, aliases, schedules).
pub async fn firewall(State(state): State<AppState>) -> Response {
    let template = match state.firewall.page().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to load the firewall page: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load the firewall configuration: {e}"),
            )
                .into_response();
        }
    };
    render(&template, "firewall")
}

/// VPN page: live WireGuard peers and IPsec SAs.
pub async fn vpn(State(state): State<AppState>) -> Response {
    let s = state.vpn.snapshot().await;
    let template = VpnTemplate {
        page: "vpn",
        wg_peers: s.wg_peers,
        wg_error: s.wg_error.unwrap_or_default(),
        ipsec_tunnels: s.ipsec_tunnels,
        ipsec_error: s.ipsec_error.unwrap_or_default(),
        ipsec_not_running: s.ipsec_not_running,
    };
    render(&template, "VPN")
}

/// Network page: interfaces and the kernel routing table.
pub async fn network(State(state): State<AppState>) -> Response {
    let interfaces = state.interfaces.list_template().await.unwrap_or_else(|e| {
        tracing::error!("Failed to fetch interfaces: {}", e);
        vec![]
    });
    let (routes, routes_error) = match state.network.list_routes().await {
        Ok(r) => (r, String::new()),
        Err(e) => (vec![], e.to_string()),
    };
    let template = NetworkTemplate {
        interfaces,
        routes,
        routes_error,
    };
    render(&template, "network")
}

/// Monitoring page
pub async fn monitoring(State(state): State<AppState>) -> Response {
    let sample = host::sample(std::time::Duration::from_millis(500)).await;
    let metrics = state.monitoring.metrics_from(&sample);
    let interface_stats = state.monitoring.interface_stats_from(&sample);
    let (top_connections, connections_error) = match state.monitoring.get_top_connections(20).await
    {
        Ok(c) => (c, String::new()),
        Err(e) => (vec![], e.to_string()),
    };
    let alerts = state
        .monitoring
        .get_recent_alerts(20)
        .await
        .unwrap_or_default();
    let ai_threats = state
        .monitoring
        .get_ai_threats(50)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to fetch threat feed: {}", e);
            vec![]
        });
    let (live_logs, logs_error) = match state.monitoring.get_live_logs(200).await {
        Ok(l) => (l, String::new()),
        Err(e) => (vec![], e.to_string()),
    };

    let template = MonitoringTemplate {
        page: "monitoring",
        rx_rate: crate::state::monitoring::format_rate(metrics.network_rx_rate),
        tx_rate: crate::state::monitoring::format_rate(metrics.network_tx_rate),
        metrics,
        interface_stats,
        top_connections,
        connections_error,
        threats_detected: ai_threats.len() as u32,
        threats_blocked: ai_threats.iter().filter(|t| t.blocked).count() as u32,
        active_alerts: alerts.len() as u32,
        alerts,
        packet_rate: sample.packet_rate(),
        packets_total: sample.packets_total(),
        ai_threats,
        live_logs,
        logs_error,
    };
    render(&template, "monitoring")
}

/// System page: host facts, users, backups, services.
pub async fn system(State(state): State<AppState>) -> Response {
    let users = crate::routes::api::system::users(&state).await;
    let (backups, backups_error) = match state.system.list_backups().await {
        Ok(b) => (b, String::new()),
        Err(e) => (vec![], e.to_string()),
    };
    let services = state.system.list_services().await.unwrap_or_default();
    let config = state.system.get_config().await.unwrap_or_default();
    let disk = host::disk("/");
    let dash = || "unknown".to_string();
    let template = SystemTemplate {
        page: "system",
        users,
        backups,
        backup_dir: state.system.backup_dir().display().to_string(),
        backups_error,
        services,
        init_system: format!("{:?}", patronus_core::ServiceManager::detect_init_system()),
        config,
        uptime: host::uptime_secs()
            .map(host::format_duration)
            .unwrap_or_else(dash),
        disk_usage_percent: disk
            .map(|(u, t)| format!("{:.1}", u as f64 * 100.0 / t as f64))
            .unwrap_or_else(dash),
        disk_used: disk
            .map(|d| crate::state::vpn::format_bytes(d.0))
            .unwrap_or_else(dash),
        disk_total: disk
            .map(|d| crate::state::vpn::format_bytes(d.1))
            .unwrap_or_else(dash),
        memory_total: host::memory()
            .map(|m| crate::state::vpn::format_bytes(m.1))
            .unwrap_or_else(dash),
        version: env!("CARGO_PKG_VERSION").to_string(),
        kernel: host::kernel(),
        arch: std::env::consts::ARCH.to_string(),
        cpu: host::cpu_model(),
    };
    render(&template, "system")
}
