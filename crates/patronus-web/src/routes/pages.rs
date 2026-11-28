//! HTML page handlers
//!
//! These handlers render Askama templates with data from the application
//! state. Every value on these pages is read from the store or the live
//! system; where nothing exists the page says so (empty state), it never
//! fills in sample values.

use crate::{
    state::{host, AppState},
    templates::{
        DashboardTemplate, MonitoringTemplate, NetworkTemplate, NotBuiltTemplate, SystemTemplate,
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

/// The page of a feature this build leaves out (`flag` = its USE flag), or that
/// `reason` explains (`flag` empty), inside the normal layout with the menu.
/// `status` stays what the caller always answered (501 / 404) for scripts.
/// Only builds without some feature call it (a full build has no caller).
#[allow(dead_code)]
pub(crate) fn not_in_build(
    status: StatusCode,
    title: &str,
    heading: &str,
    reason: &str,
    flag: &str,
) -> Response {
    let embedded = crate::routes::release_info().1 == "embedded";
    let ap = crate::routes::api::wifi::role() == crate::routes::api::setup::DeviceRole::Ap;
    let ap_job = ap && crate::routes::AP_ROUTER_JOBS.contains(&flag);
    let reason = if !reason.is_empty() {
        reason.to_string()
    } else if ap_job {
        format!("{heading} is not used here: this unit is an access point and the main router does this for the network.")
    } else if embedded {
        format!(
            "{} is not part of this router-tier image: it is left out to keep the device's flash and memory small.",
            heading
        )
    } else {
        format!(
            "{} is not part of this installation (its USE flag is off).",
            heading
        )
    };
    let t = NotBuiltTemplate {
        page: "",
        title: title.to_string(),
        heading: heading.to_string(),
        reason,
        flag: if ap_job {
            String::new()
        } else {
            flag.to_string()
        },
        embedded,
    };
    let mut r = render(&t, "not_built");
    if r.status().is_success() {
        *r.status_mut() = status;
    }
    r
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
pub async fn dashboard(State(state): State<AppState>, user: crate::auth::AuthUser) -> Response {
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
    // The viewer's own widget layout (their saved one, else the default).
    let (layout, customized) = crate::routes::api::dashboard::resolved(&state, &user.session).await;
    let drawn = |id: &str| layout.widgets.iter().any(|w| w.id == id && w.on);
    // Live rates over a short window (same sampler the Monitoring page uses), read once for the
    // Interfaces table and the Traffic widget; skipped when neither is drawn.
    let stats = if drawn("interfaces") || drawn("traffic") {
        let sample = host::sample(std::time::Duration::from_millis(300)).await;
        state.monitoring.interface_stats_from(&sample)
    } else {
        vec![]
    };
    let rates: std::collections::HashMap<String, String> = stats
        .iter()
        .map(|s| (s.name.clone(), format!("{} / {}", s.rx_rate, s.tx_rate)))
        .collect();
    let traffic: Vec<crate::templates::DashTraffic> = if drawn("traffic") {
        stats
            .into_iter()
            .filter(|s| s.name != "lo")
            .map(|s| crate::templates::DashTraffic {
                name: s.name,
                rx: s.rx_rate,
                tx: s.tx_rate,
            })
            .collect()
    } else {
        vec![]
    };
    let (iface_rows, hidden_stubs) = dash_iface_rows(&interfaces, &roles, &rates);
    let (mut widgets, hidden_widgets) = crate::dashboard::split(&layout);
    // A tile without data draws nothing (no DHCP server, no interface rates).
    widgets.retain(|w| match w.id {
        "dhcp" => dhcp_leases.is_some(),
        "traffic" => !traffic.is_empty(),
        _ => true,
    });
    let ui = patronus_config::uiprefs::resolve(&state.config_store).await;
    let (cpu_level, mem_level, disk_level) = (
        ui.level(system_info.cpu_usage as f64),
        ui.level(system_info.memory_usage as f64),
        ui.level(system_info.disk_usage as f64),
    );
    let (health_note, health_tone) = health_note(&[
        ("CPU", system_info.cpu_usage as f64, cpu_level),
        ("Memory", system_info.memory_usage as f64, mem_level),
        (
            host::storage_label(),
            system_info.disk_usage as f64,
            disk_level,
        ),
    ]);
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
        hidden_stubs,
        ui,
        cpu_level: cpu_level.class(),
        mem_level: mem_level.class(),
        disk_level: disk_level.class(),
        disk_label: host::storage_label(),
        health_note,
        health_tone,
        traffic,
        widgets,
        hidden_widgets,
        layout_json: serde_json::to_string(&layout).unwrap_or_else(|_| "{\"widgets\":[]}".into()),
        customized,
    };
    render(&template, "dashboard")
}

/// Kernel fallback devices that tunnel/bridge modules create in every network namespace (`gre0`, `sit0`, ...).
/// They carry no traffic until configured, so the dashboard leaves them out while they have no address; the
/// Interfaces page still lists every device. These names are fixed by the kernel, not configuration.
use crate::state::interfaces::KERNEL_STUB_DEVICES;

/// The dashboard's interface rows: WAN first, then LAN, other roles, unassigned; kernel stub devices without an
/// address are dropped (returned count says how many).
pub(crate) fn dash_iface_rows(
    interfaces: &[crate::templates::InterfaceInfo],
    roles: &std::collections::BTreeMap<String, String>,
    rates: &std::collections::HashMap<String, String>,
) -> (Vec<crate::templates::DashIface>, usize) {
    let mut hidden = 0;
    let mut rows: Vec<crate::templates::DashIface> = interfaces
        .iter()
        .filter(|i| i.name != "lo")
        .filter(|i| {
            let stub = KERNEL_STUB_DEVICES.contains(&i.name.as_str())
                && i.ip_addresses.is_empty()
                && i.ip_address.is_none()
                && !roles.contains_key(&i.name);
            hidden += stub as usize;
            !stub
        })
        .map(|i| {
            let addrs = if i.ip_addresses.is_empty() {
                i.ip_address.clone().unwrap_or_default()
            } else {
                i.ip_addresses.join(", ")
            };
            let mac = i.mac_address.trim();
            crate::templates::DashIface {
                name: i.name.clone(),
                role: roles
                    .get(&i.name)
                    .map(|r| r.to_uppercase())
                    .unwrap_or_default(),
                up: i.state == "UP",
                addrs,
                mac: if mac.is_empty() || mac == "00:00:00:00:00:00" {
                    String::new()
                } else {
                    mac.to_string()
                },
                rate: rates.get(&i.name).cloned().unwrap_or_default(),
                rx: crate::state::vpn::format_bytes(i.rx_bytes),
                tx: crate::state::vpn::format_bytes(i.tx_bytes),
                rx_bytes: i.rx_bytes,
                tx_bytes: i.tx_bytes,
            }
        })
        .collect();
    rows.sort_by_key(|r| {
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
    (rows, hidden)
}

/// "Disk / at 91 % (critical from 90 %)" for every value over a threshold, and the banner tone of the worst.
pub(crate) fn health_note(
    vals: &[(&str, f64, patronus_config::uiprefs::Level)],
) -> (String, &'static str) {
    use patronus_config::uiprefs::Level;
    let over: Vec<String> = vals
        .iter()
        .filter(|(_, _, l)| *l != Level::Ok)
        .map(|(n, v, l)| {
            format!(
                "{n} at {v:.0}% ({})",
                if *l == Level::Crit {
                    "critical"
                } else {
                    "high"
                }
            )
        })
        .collect();
    let tone = if vals.iter().any(|v| v.2 == Level::Crit) {
        "crit"
    } else if over.is_empty() {
        ""
    } else {
        "warn"
    };
    (over.join(", "), tone)
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
        page: "interfaces",
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
    // idle kernel stub devices (gre0, sit0, ...) are counted, not listed
    let (interface_stats, stubs): (Vec<_>, Vec<_>) = state
        .monitoring
        .interface_stats_from(&sample)
        .into_iter()
        .partition(|s| {
            !(KERNEL_STUB_DEVICES.contains(&s.name.as_str())
                && s.rx_packets == "0"
                && s.tx_packets == "0")
        });
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

    let ui = patronus_config::uiprefs::resolve(&state.config_store).await;
    let template = MonitoringTemplate {
        page: "monitoring",
        hidden_stubs: stubs.len(),
        cpu_level: ui.level(metrics.cpu_percent).class(),
        mem_level: ui.level(metrics.memory_percent).class(),
        disk_level: ui.level(metrics.disk_percent).class(),
        disk_label: host::storage_label(),
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
    let disk = host::disk(host::storage_path());
    let about = crate::routes::legal::about_links(&state).await;
    let dash = || "unknown".to_string();
    let ssh = patronus_network::ssh::settings(state.lan.store())
        .await
        .unwrap_or_default();
    let web = patronus_config::webui::resolve(Some(state.lan.store())).await;
    let ui = patronus_config::uiprefs::resolve(&state.config_store).await;
    let disk_pct = disk.map(|(u, t)| u as f64 * 100.0 / (t.max(1)) as f64);
    let template = SystemTemplate {
        disk_level: disk_pct.map(|p| ui.level(p).class()).unwrap_or(""),
        disk_label: host::storage_label(),
        disk_bar: disk_pct
            .map(|p| p.round().clamp(0.0, 100.0) as u8)
            .unwrap_or(0),
        ui,
        ui_default: patronus_config::uiprefs::UiPrefs::default(),
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
