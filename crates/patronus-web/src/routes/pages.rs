//! HTML page handlers
//!
//! These handlers render Askama templates with data from the application state.

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    http::StatusCode,
};
use askama::Template;
use crate::{
    state::AppState,
    auth::AuthUser,
    templates::{
        DashboardTemplate,
        FirewallTemplate,
        VpnTemplate,
        NetworkTemplate,
        MonitoringTemplate,
        SystemTemplate,
    },
};

/// Login page template
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate;

/// Login page (public)
pub async fn login_page() -> Response {
    let template = LoginTemplate;
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render login template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Dashboard page
pub async fn dashboard(State(state): State<AppState>) -> Response {
    // Fetch dashboard data
    let interfaces = match state.network.list_interfaces().await {
        Ok(ifaces) => ifaces,
        Err(e) => {
            tracing::error!("Failed to fetch interfaces: {}", e);
            vec![]
        }
    };

    let active_rules = match state.firewall.count_active_rules().await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Failed to count firewall rules: {}", e);
            0
        }
    };

    let vpn_connections = match state.vpn.count_active_connections().await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Failed to count VPN connections: {}", e);
            0
        }
    };

    let system_info = match state.system.get_info().await {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to fetch system info: {}", e);
            Default::default()
        }
    };

    let template = DashboardTemplate {
        interfaces,
        active_rules,
        vpn_connections,
        system_info,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render dashboard template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Firewall rules page
pub async fn firewall(State(state): State<AppState>) -> Response {
    // Fetch firewall data
    let rules = match state.firewall.list_rules().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch firewall rules: {}", e);
            vec![]
        }
    };

    let nat_rules = match state.firewall.list_nat_rules().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch NAT rules: {}", e);
            vec![]
        }
    };

    let aliases = match state.firewall.list_aliases().await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to fetch aliases: {}", e);
            vec![]
        }
    };

    let template = FirewallTemplate {
        rules,
        nat_rules,
        aliases,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render firewall template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// VPN management page
pub async fn vpn(State(state): State<AppState>) -> Response {
    // Fetch VPN data
    let wg_peers = match state.vpn.list_wireguard_peers().await {
        Ok(peers) => peers,
        Err(e) => {
            tracing::error!("Failed to fetch WireGuard peers: {}", e);
            vec![]
        }
    };

    let ovpn_tunnels = match state.vpn.list_openvpn_tunnels().await {
        Ok(tunnels) => tunnels,
        Err(e) => {
            tracing::error!("Failed to fetch OpenVPN tunnels: {}", e);
            vec![]
        }
    };

    let ipsec_tunnels = match state.vpn.list_ipsec_tunnels().await {
        Ok(tunnels) => tunnels,
        Err(e) => {
            tracing::error!("Failed to fetch IPsec tunnels: {}", e);
            vec![]
        }
    };

    let template = VpnTemplate {
        wg_peers,
        ovpn_tunnels,
        ipsec_tunnels,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render VPN template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Network services page
pub async fn network(State(state): State<AppState>) -> Response {
    // Fetch network data
    let interfaces = match state.network.list_interfaces().await {
        Ok(ifaces) => ifaces,
        Err(e) => {
            tracing::error!("Failed to fetch interfaces: {}", e);
            vec![]
        }
    };

    let dhcp_pools = match state.network.list_dhcp_pools().await {
        Ok(pools) => pools,
        Err(e) => {
            tracing::error!("Failed to fetch DHCP pools: {}", e);
            vec![]
        }
    };

    let dhcp_leases = match state.network.list_dhcp_leases().await {
        Ok(leases) => leases,
        Err(e) => {
            tracing::error!("Failed to fetch DHCP leases: {}", e);
            vec![]
        }
    };

    let dns_records = match state.network.list_dns_records().await {
        Ok(records) => records,
        Err(e) => {
            tracing::error!("Failed to fetch DNS records: {}", e);
            vec![]
        }
    };

    let routes = match state.network.list_routes().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to fetch routes: {}", e);
            vec![]
        }
    };

    let template = NetworkTemplate {
        interfaces,
        dhcp_pools,
        dhcp_leases,
        dns_records,
        routes,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render network template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Monitoring page
pub async fn monitoring(State(state): State<AppState>) -> Response {
    // Fetch monitoring data
    let metrics = match state.monitoring.get_current_metrics().await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to fetch metrics: {}", e);
            Default::default()
        }
    };

    let interface_stats = match state.monitoring.get_interface_stats().await {
        Ok(stats) => stats,
        Err(e) => {
            tracing::error!("Failed to fetch interface stats: {}", e);
            vec![]
        }
    };

    let top_connections = match state.monitoring.get_top_connections(10).await {
        Ok(conns) => conns,
        Err(e) => {
            tracing::error!("Failed to fetch top connections: {}", e);
            vec![]
        }
    };

    let alerts = match state.monitoring.get_recent_alerts(20).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("Failed to fetch alerts: {}", e);
            vec![]
        }
    };

    let template = MonitoringTemplate {
        metrics,
        interface_stats,
        top_connections,
        alerts,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render monitoring template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// System settings page
pub async fn system(State(state): State<AppState>) -> Response {
    // Fetch system data
    let users = match state.system.list_users().await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to fetch users: {}", e);
            vec![]
        }
    };

    let backups = match state.system.list_backups().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to fetch backups: {}", e);
            vec![]
        }
    };

    let updates = match state.system.check_updates().await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to check updates: {}", e);
            vec![]
        }
    };

    let services = match state.system.list_services().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to fetch services: {}", e);
            vec![]
        }
    };

    let config = match state.system.get_config().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to fetch config: {}", e);
            Default::default()
        }
    };

    let template = SystemTemplate {
        users,
        backups,
        updates,
        services,
        config,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Failed to render system template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}
