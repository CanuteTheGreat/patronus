//! HTML page handlers
//!
//! These handlers render Askama templates with data from the application
//! state. Every value on these pages is read from the store or the live
//! system; where nothing exists the page says so (empty state), it never
//! fills in sample values.

use crate::{
    state::{host, AppState},
    templates::{DashboardTemplate, MonitoringTemplate, NetworkTemplate, SystemTemplate},
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

pub(crate) fn render(t: &impl Template, what: &str) -> Response {
    match t.render() {
        Ok(html) => {
            Html(html.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to render {what} template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

/// Login page (public).
///
/// The address of a router often served another firmware's admin page
/// before Patronus (the vendor UI, LuCI). What that left in the browser must
/// not break signing in, so the login page clears it: the browser's HTTP
/// cache for this address (a cached old page for `/` would otherwise be
/// shown instead of the dashboard), and every cookie Patronus does not set.
/// It leaves the session cookie and site storage (the theme choice) alone;
/// the page's script removes service workers and Cache Storage, which
/// Patronus does not use.
pub async fn login_page(headers: axum::http::HeaderMap) -> Response {
    let mut r = render(&LoginTemplate, "login");
    if r.status().is_success() {
        let h = r.headers_mut();
        h.insert(
            axum::http::HeaderName::from_static("clear-site-data"),
            axum::http::HeaderValue::from_static("\"cache\""),
        );
        for del in crate::auth::foreign_cookie_deletions(&headers) {
            if let Ok(v) = axum::http::HeaderValue::from_str(&del) {
                h.append(axum::http::header::SET_COOKIE, v);
            }
        }
    }
    r
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
    let gw = patronus_network::apwifi::default_gateway(
        &std::fs::read_to_string("/proc/net/route").unwrap_or_default(),
    )
    .unwrap_or_default();
    // Lease count for the DHCP tile: only when the server answers with a lease list.
    let dhcp_leases = state
        .lan
        .status("dhcp")
        .await
        .ok()
        .and_then(|v| v.get("leases").and_then(|l| l.as_array()).map(|a| a.len()));
    let roles = state.interfaces.roles().await;
    let mut iface_rows: Vec<crate::templates::DashIface> = interfaces
        .iter()
        .map(|i| crate::templates::DashIface {
            name: i.name.clone(),
            role: roles
                .get(&i.name)
                .map(|r| r.to_uppercase())
                .unwrap_or_default(),
            up: i.state == "UP",
            addrs: i.ip_display.clone(),
        })
        .collect();
    // WAN first, then LAN, then other roles, then unassigned devices.
    iface_rows.sort_by_key(|r| {
        (
            match r.role.as_str() {
                "WAN" => 0,
                "LAN" => 1,
                "" => 3,
                _ => 2,
            },
            r.name.clone(),
        )
    });
    // Live rates over a short window (same sampler the Monitoring page uses).
    let sample = host::sample(std::time::Duration::from_millis(300)).await;
    let traffic: Vec<crate::templates::DashTraffic> = state
        .monitoring
        .interface_stats_from(&sample)
        .into_iter()
        .filter(|s| s.name != "lo")
        .map(|s| crate::templates::DashTraffic {
            name: s.name,
            rx: s.rx_rate,
            tx: s.tx_rate,
        })
        .collect();
    let template = DashboardTemplate {
        page: "dashboard",
        uptime: host::format_duration(system_info.uptime),
        interfaces,
        active_rules,
        vpn_connections,
        vpn_errors,
        system_info,
        services,
        internet_dev: gw.0,
        internet_gw: gw.1,
        dhcp_leases,
        iface_rows,
        traffic,
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
/// Diagnostics page (static shell; the tools run through `/api/system/diag`).
pub async fn diagnostics(me: crate::auth::AuthUser) -> Response {
    let t = crate::templates::DiagnosticsTemplate {
        page: "diagnostics",
        is_admin: me.session.role.is_admin(),
    };
    match t.render() {
        Ok(h) => Html(h.replace("@PATRONUS_VERSION@", env!("CARGO_PKG_VERSION"))).into_response(),
        Err(e) => {
            tracing::error!("render diagnostics page: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub async fn system(State(state): State<AppState>, me: crate::auth::AuthUser) -> Response {
    let users = crate::routes::api::system::users(&state).await;
    let me_two_factor = users
        .iter()
        .any(|u| u.id == me.session.user_id && u.two_factor);
    let (backups, backups_error) = match state.system.list_backups().await {
        Ok(b) => (b, String::new()),
        Err(e) => (vec![], e.to_string()),
    };
    let services = state.system.list_services().await.unwrap_or_default();
    let config = state.system.get_config().await.unwrap_or_default();
    let disk = host::disk("/");
    let about = crate::routes::legal::about_links(&state).await;
    let dash = || "unknown".to_string();
    let ssh = patronus_network::ssh::settings(state.lan.store())
        .await
        .unwrap_or_default();
    let web = patronus_config::webui::resolve(Some(state.lan.store())).await;
    let template = SystemTemplate {
        web_listen: web.listen.join(", "),
        web_https_port: web.https_port,
        web_redirect_port: web.http_redirect_port,
        web_extra_ports: web
            .extra_https_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        web_cert: web.tls_cert.clone(),
        web_key: web.tls_key.clone(),
        ssh_port: ssh.port,
        ssh_listen: ssh.listen.join(", "),
        ssh_password: ssh.password_auth,
        ssh_root: ssh.root_login.clone(),
        ssh_ca: ssh.trusted_user_ca_keys.join("\n"),
        ssh_principals: ssh
            .authorized_principals
            .iter()
            .map(|(u, p)| format!("{u}={}", p.join(",")))
            .collect::<Vec<_>>()
            .join("\n"),
        ssh_cert: ssh.host_certificate.clone(),
        page: "system",
        site_url: about.site_url,
        source_url: about.source_url,
        users,
        me_id: me.session.user_id,
        me_username: me.session.username.clone(),
        me_two_factor,
        is_admin: me.session.role.is_admin(),
        can_modify: me.session.role.can_modify(),
        totp_available: cfg!(feature = "totp"),
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

#[cfg(test)]
mod version_footer_tests {
    use super::*;

    #[test]
    fn shell_shows_version_in_sidebar_footer() {
        let r = render(&LoginTemplate, "login");
        assert!(r.status().is_success());
        let src = include_str!("../../templates/base.html");
        assert!(src.contains("sidebar-version"));
        assert!(src.contains("@PATRONUS_VERSION@"));
    }
}
