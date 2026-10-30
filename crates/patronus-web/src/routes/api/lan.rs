//! LAN services API and pages (lane D): `/api/dhcp/*`, `/api/dns/*`,
//! `/api/ddns/*`, `/api/ntp` and the `/dhcp`, `/dns`, `/ntp` pages.
//!
//! Each block is compiled only with its cargo feature (USE=dhcp, dns,
//! ntp); without it the page explains what is missing instead of 404ing
//! from the sidebar.
#![cfg_attr(
    not(all(feature = "dhcp", feature = "dns", feature = "ntp")),
    allow(dead_code, unused_imports)
)]

use crate::state::AppState;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;

/// "Invalid ..." errors are the caller's fault (400), "not found" 404,
/// everything else (daemon failed to start, applyd down) 500.
fn err(e: anyhow::Error) -> Response {
    let msg = e.to_string();
    let code = if msg.contains("Invalid") {
        StatusCode::BAD_REQUEST
    } else if msg.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, Json(json!({ "error": msg }))).into_response()
}

fn ok_json(v: serde_json::Value) -> Response {
    Json(v).into_response()
}

fn created(id: i64) -> Response {
    (StatusCode::CREATED, Json(json!({ "id": id }))).into_response()
}

fn done() -> Response {
    Json(json!({ "ok": true })).into_response()
}

fn render<T: askama::Template>(t: T) -> Response {
    match t.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

#[cfg(not(all(feature = "dhcp", feature = "dns", feature = "ntp")))]
fn not_built(what: &str, flag: &str) -> Response {
    Html(format!(
        "<!DOCTYPE html><html><head><title>{what} - Patronus</title></head><body>\
         <h1>{what}</h1><p>This Patronus build does not include the {what} service. \
         Rebuild with <code>USE={flag}</code> (emerge net-firewall/patronus).</p>\
         <p><a href=\"/\">Back to the dashboard</a></p></body></html>"
    ))
    .into_response()
}

fn fmt_time(ts: i64) -> String {
    if ts <= 0 {
        return "never".into();
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn opt_s(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

fn ips(v: &[std::net::IpAddr]) -> String {
    v.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ===========================================================================
// DHCP
// ===========================================================================

#[cfg(feature = "dhcp")]
mod dhcp_routes {
    use super::*;
    use askama::Template;
    use axum::extract::{Path, State};
    use patronus_network::{dhcp, dhcp6, ra};
    use serde::Deserialize;

    pub struct StaticView {
        pub id: i64,
        pub mac: String,
        pub ip: String,
        pub hostname: String,
    }
    pub struct PoolView {
        pub id: i64,
        pub interface: String,
        pub enabled: bool,
        pub range_start: String,
        pub range_end: String,
        pub lease_time: u32,
        pub gateway: String,
        pub dns: String,
        pub domain: String,
        pub ntp: String,
        pub description: String,
        pub statics: Vec<StaticView>,
    }
    pub struct LeaseView {
        pub ip: String,
        pub mac: String,
        pub hostname: String,
        pub expires: String,
        pub state: String,
        pub family: String,
        pub source: String,
        pub is_static: bool,
    }
    pub struct V6View {
        pub id: i64,
        pub interface: String,
        pub enabled: bool,
        pub range: String,
        pub prefix_len: u8,
        pub lease_time: u32,
        pub dns: String,
    }
    pub struct RaView {
        pub id: i64,
        pub interface: String,
        pub enabled: bool,
        pub mode: String,
        pub prefix: String,
        pub dns: String,
        pub interval: String,
    }
    pub struct RelayView {
        pub id: i64,
        pub interface: String,
        pub enabled: bool,
        pub servers: String,
    }

    #[derive(Template)]
    #[template(path = "dhcp.html")]
    pub struct DhcpTemplate {
        pub page: &'static str,
        pub backend: String,
        pub ra_backend: String,
        pub backend_effective: String,
        pub ra_effective: String,
        pub available: String,
        pub services: Vec<(String, bool)>,
        pub pools: Vec<PoolView>,
        pub leases: Vec<LeaseView>,
        pub v6: Vec<V6View>,
        pub ras: Vec<RaView>,
        pub relays: Vec<RelayView>,
        pub error: String,
    }

    pub async fn page(State(state): State<AppState>) -> Response {
        let lan = &state.lan;
        let s = lan.store();
        let mut error = String::new();
        let status = match lan.status("dhcp").await {
            Ok(v) => v,
            Err(e) => {
                error = format!("Could not read the DHCP server state: {e}");
                serde_json::Value::Null
            }
        };
        let pools = dhcp::list_pools(s).await.unwrap_or_default();
        let leases = status["leases"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|l| LeaseView {
                ip: l["ip"].as_str().unwrap_or_default().into(),
                mac: l["mac"].as_str().unwrap_or_default().into(),
                hostname: l["hostname"].as_str().unwrap_or_default().into(),
                expires: fmt_time(l["expires"].as_i64().unwrap_or(0)),
                state: l["state"].as_str().unwrap_or_default().into(),
                family: l["family"].as_str().unwrap_or_default().into(),
                source: l["source"].as_str().unwrap_or_default().into(),
                is_static: l["is_static"].as_bool().unwrap_or(false),
            })
            .collect();
        let services = status["services"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false)))
                    .collect()
            })
            .unwrap_or_default();
        let available = status["available"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.as_bool() == Some(true))
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let t = DhcpTemplate {
            page: "dhcp",
            backend: patronus_network::lan::setting_or(s, "dhcp.backend", "auto")
                .await
                .unwrap_or_default(),
            ra_backend: patronus_network::lan::setting_or(s, "dhcp.ra_backend", "auto")
                .await
                .unwrap_or_default(),
            backend_effective: status["backend"].as_str().unwrap_or("?").into(),
            ra_effective: status["ra_backend"].as_str().unwrap_or("?").into(),
            available,
            services,
            pools: pools
                .iter()
                .map(|p| PoolView {
                    id: p.id,
                    interface: p.interface.clone(),
                    enabled: p.enabled,
                    range_start: p.range_start.to_string(),
                    range_end: p.range_end.to_string(),
                    lease_time: p.lease_time,
                    gateway: p.gateway.map(|g| g.to_string()).unwrap_or_default(),
                    dns: ips(&p.dns_servers),
                    domain: opt_s(&p.domain),
                    ntp: ips(&p.ntp_servers),
                    description: opt_s(&p.description),
                    statics: p
                        .static_mappings
                        .iter()
                        .map(|m| StaticView {
                            id: m.id,
                            mac: m.mac.clone(),
                            ip: m.ip.to_string(),
                            hostname: opt_s(&m.hostname),
                        })
                        .collect(),
                })
                .collect(),
            leases,
            v6: dhcp6::list(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|p| V6View {
                    id: p.id,
                    interface: p.interface.clone(),
                    enabled: p.enabled,
                    range: format!("{} - {}", p.range_start, p.range_end),
                    prefix_len: p.prefix_len,
                    lease_time: p.lease_time,
                    dns: ips(&p.dns_servers),
                })
                .collect(),
            ras: ra::list(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|r| RaView {
                    id: r.id,
                    interface: r.interface.clone(),
                    enabled: r.enabled,
                    mode: r.mode.clone(),
                    prefix: r
                        .prefix
                        .clone()
                        .unwrap_or_else(|| "all /64s on the interface".into()),
                    dns: ips(&r.dns_servers),
                    interval: format!("{}-{} s", r.min_interval, r.max_interval),
                })
                .collect(),
            relays: dhcp::list_relays(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|r| RelayView {
                    id: r.id,
                    interface: r.interface.clone(),
                    enabled: r.enabled,
                    servers: ips(&r.servers),
                })
                .collect(),
            error,
        };
        render(t)
    }

    async fn overview(State(state): State<AppState>) -> Response {
        state
            .lan
            .dhcp_overview()
            .await
            .map(ok_json)
            .unwrap_or_else(err)
    }

    async fn leases(State(state): State<AppState>) -> Response {
        match state.lan.status("dhcp").await {
            Ok(v) => ok_json(v["leases"].clone()),
            Err(e) => err(e),
        }
    }

    #[derive(Deserialize)]
    struct Backends {
        backend: Option<String>,
        ra_backend: Option<String>,
    }

    async fn set_backends(State(state): State<AppState>, Json(b): Json<Backends>) -> Response {
        state
            .lan
            .set_dhcp_backends(b.backend, b.ra_backend)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }

    async fn add_pool(State(state): State<AppState>, Json(i): Json<dhcp::PoolInput>) -> Response {
        state
            .lan
            .save_pool(None, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn put_pool(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<dhcp::PoolInput>,
    ) -> Response {
        state
            .lan
            .save_pool(Some(id), i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn del_pool(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_pool(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn add_static(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<dhcp::StaticInput>,
    ) -> Response {
        state
            .lan
            .add_static(id, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn del_static(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_static(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn add_v6(State(state): State<AppState>, Json(i): Json<dhcp6::Dhcp6Input>) -> Response {
        state
            .lan
            .save_dhcp6(None, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn put_v6(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<dhcp6::Dhcp6Input>,
    ) -> Response {
        state
            .lan
            .save_dhcp6(Some(id), i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn del_v6(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_dhcp6(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn add_ra(State(state): State<AppState>, Json(i): Json<ra::RaInput>) -> Response {
        state
            .lan
            .save_ra(None, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn put_ra(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<ra::RaInput>,
    ) -> Response {
        state
            .lan
            .save_ra(Some(id), i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn del_ra(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_ra(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn add_relay(State(state): State<AppState>, Json(i): Json<dhcp::RelayInput>) -> Response {
        state
            .lan
            .save_relay(None, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn del_relay(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_relay(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn apply(State(state): State<AppState>) -> Response {
        state
            .lan
            .reapply("dhcp")
            .await
            .map(|r| ok_json(json!({ "applied": r })))
            .unwrap_or_else(err)
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::{delete, get, post, put};
        axum::Router::new()
            .route("/dhcp", get(overview))
            .route("/dhcp/leases", get(leases))
            .route("/dhcp/apply", post(apply))
            .route("/dhcp/settings", put(set_backends))
            .route("/dhcp/pools", post(add_pool))
            .route("/dhcp/pools/:id", put(put_pool).delete(del_pool))
            .route("/dhcp/pools/:id/static", post(add_static))
            .route("/dhcp/static/:id", delete(del_static))
            .route("/dhcp/v6", post(add_v6))
            .route("/dhcp/v6/:id", put(put_v6).delete(del_v6))
            .route("/dhcp/ra", post(add_ra))
            .route("/dhcp/ra/:id", put(put_ra).delete(del_ra))
            .route("/dhcp/relays", post(add_relay))
            .route("/dhcp/relays/:id", delete(del_relay))
    }
}

// ===========================================================================
// DNS + DDNS
// ===========================================================================

#[cfg(feature = "dns")]
mod dns_routes {
    use super::*;
    use askama::Template;
    use axum::extract::{Path, State};
    use patronus_network::{ddns, dns};

    pub struct HostView {
        pub id: i64,
        pub name: String,
        pub address: String,
        pub description: String,
    }
    pub struct DomainView {
        pub id: i64,
        pub domain: String,
        pub server: String,
        pub description: String,
    }
    pub struct BlockView {
        pub id: i64,
        pub domain: String,
        pub description: String,
    }
    pub struct DdnsView {
        pub id: i64,
        pub enabled: bool,
        pub provider: String,
        pub hostname: String,
        pub interface: String,
        pub username: String,
        pub server: String,
        pub ip: String,
        pub last_update: String,
        pub result: String,
        pub ok: bool,
    }

    #[derive(Template)]
    #[template(path = "dns.html")]
    pub struct DnsTemplate {
        pub page: &'static str,
        pub mode: String,
        pub effective_mode: String,
        pub upstreams: String,
        pub dnssec: bool,
        pub interfaces: String,
        pub blocklist_urls: String,
        pub block_mode: String,
        pub rebind_protection: bool,
        pub rebind_exceptions: String,
        pub services: Vec<(String, bool)>,
        pub hosts: Vec<HostView>,
        pub domains: Vec<DomainView>,
        pub blocked: Vec<BlockView>,
        pub ddns: Vec<DdnsView>,
        pub error: String,
    }

    pub async fn page(State(state): State<AppState>) -> Response {
        let lan = &state.lan;
        let s = lan.store();
        let mut error = String::new();
        let status = lan.status("dns").await.unwrap_or_else(|e| {
            error = format!("Could not read the DNS service state: {e}");
            serde_json::Value::Null
        });
        let dstatus = lan.status("ddns").await.unwrap_or_default();
        let set = match dns::settings(s).await {
            Ok(v) => v,
            Err(e) => return err(anyhow::anyhow!("{e}")),
        };
        let services = status["services"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false)))
                    .collect()
            })
            .unwrap_or_default();
        let t = DnsTemplate {
            page: "dns",
            mode: set.mode.clone(),
            effective_mode: status["effective_mode"].as_str().unwrap_or("?").into(),
            upstreams: ips(&set.upstreams),
            dnssec: set.dnssec,
            interfaces: set.interfaces.join(", "),
            blocklist_urls: set.blocklist_urls.join("\n"),
            block_mode: set.block_mode.clone(),
            rebind_protection: set.rebind_protection,
            rebind_exceptions: set.rebind_exceptions.join(", "),
            services,
            hosts: dns::list_hosts(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|h| HostView {
                    id: h.id,
                    name: format!("{}.{}", h.hostname, h.domain),
                    address: h.address.to_string(),
                    description: opt_s(&h.description),
                })
                .collect(),
            domains: dns::list_domains(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|d| DomainView {
                    id: d.id,
                    domain: d.domain.clone(),
                    server: format!("{}@{}", d.server, d.port),
                    description: opt_s(&d.description),
                })
                .collect(),
            blocked: dns::list_blocked(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|b| BlockView {
                    id: b.id,
                    domain: b.domain.clone(),
                    description: opt_s(&b.description),
                })
                .collect(),
            ddns: ddns::list(s)
                .await
                .unwrap_or_default()
                .iter()
                .map(|c| {
                    let st = &dstatus[c.key()];
                    DdnsView {
                        id: c.id,
                        enabled: c.enabled,
                        provider: c.provider.clone(),
                        hostname: c.hostname.clone(),
                        interface: c.interface.clone(),
                        username: opt_s(&c.username),
                        server: opt_s(&c.server),
                        ip: st["ip"].as_str().unwrap_or("-").into(),
                        last_update: fmt_time(st["last_update"].as_i64().unwrap_or(0)),
                        result: st["message"].as_str().unwrap_or("not run yet").into(),
                        ok: st["ok"].as_bool().unwrap_or(false),
                    }
                })
                .collect(),
            error,
        };
        render(t)
    }

    async fn overview(State(state): State<AppState>) -> Response {
        state
            .lan
            .dns_overview()
            .await
            .map(ok_json)
            .unwrap_or_else(err)
    }
    async fn put_settings(
        State(state): State<AppState>,
        Json(i): Json<dns::DnsSettingsInput>,
    ) -> Response {
        state
            .lan
            .save_dns_settings(i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn add_host(State(state): State<AppState>, Json(i): Json<dns::HostInput>) -> Response {
        state.lan.add_host(i).await.map(created).unwrap_or_else(err)
    }
    async fn add_domain(
        State(state): State<AppState>,
        Json(i): Json<dns::DomainInput>,
    ) -> Response {
        state
            .lan
            .add_domain(i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn add_block(State(state): State<AppState>, Json(i): Json<dns::BlockInput>) -> Response {
        state
            .lan
            .add_blocked(i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn del(
        State(state): State<AppState>,
        Path((table, id)): Path<(String, i64)>,
    ) -> Response {
        state
            .lan
            .delete_dns(&table, id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn apply(State(state): State<AppState>) -> Response {
        state
            .lan
            .reapply("dns")
            .await
            .map(|r| ok_json(json!({ "applied": r })))
            .unwrap_or_else(err)
    }
    async fn ddns_list(State(state): State<AppState>) -> Response {
        state
            .lan
            .ddns_overview()
            .await
            .map(ok_json)
            .unwrap_or_else(err)
    }
    async fn ddns_add(State(state): State<AppState>, Json(i): Json<ddns::DdnsInput>) -> Response {
        state
            .lan
            .save_ddns(None, i)
            .await
            .map(created)
            .unwrap_or_else(err)
    }
    async fn ddns_put(
        State(state): State<AppState>,
        Path(id): Path<i64>,
        Json(i): Json<ddns::DdnsInput>,
    ) -> Response {
        state
            .lan
            .save_ddns(Some(id), i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn ddns_del(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
        state
            .lan
            .delete_ddns(id)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }
    async fn ddns_update(State(state): State<AppState>) -> Response {
        state
            .lan
            .ddns_update_now()
            .await
            .map(|r| ok_json(json!({ "applied": r })))
            .unwrap_or_else(err)
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::{delete, get, post, put};
        axum::Router::new()
            .route("/dns", get(overview))
            .route("/dns/settings", put(put_settings))
            .route("/dns/apply", post(apply))
            .route("/dns/hosts", post(add_host))
            .route("/dns/domains", post(add_domain))
            .route("/dns/blocklist", post(add_block))
            .route("/dns/:table/:id", delete(del))
            .route("/ddns", get(ddns_list).post(ddns_add))
            .route("/ddns/update", post(ddns_update))
            .route("/ddns/:id", put(ddns_put).delete(ddns_del))
    }
}

// ===========================================================================
// NTP
// ===========================================================================

#[cfg(feature = "ntp")]
mod ntp_routes {
    use super::*;
    use askama::Template;
    use axum::extract::State;
    use patronus_network::ntp;

    #[derive(Template)]
    #[template(path = "ntp.html")]
    pub struct NtpTemplate {
        pub page: &'static str,
        pub enabled: bool,
        pub servers: String,
        pub interfaces: String,
        pub available: bool,
        pub running: bool,
        pub error: String,
    }

    pub async fn page(State(state): State<AppState>) -> Response {
        let mut error = String::new();
        let st = state.lan.status("ntp").await.unwrap_or_else(|e| {
            error = format!("Could not read the NTP service state: {e}");
            serde_json::Value::Null
        });
        let s = match ntp::settings(state.lan.store()).await {
            Ok(s) => s,
            Err(e) => return err(anyhow::anyhow!("{e}")),
        };
        render(NtpTemplate {
            page: "ntp",
            enabled: s.enabled,
            servers: s.servers.join(", "),
            interfaces: s.interfaces.join(", "),
            available: st["available"].as_bool().unwrap_or(false),
            running: st["running"].as_bool().unwrap_or(false),
            error,
        })
    }

    async fn get_ntp(State(state): State<AppState>) -> Response {
        state
            .lan
            .ntp_overview()
            .await
            .map(ok_json)
            .unwrap_or_else(err)
    }
    async fn put_ntp(State(state): State<AppState>, Json(i): Json<ntp::NtpInput>) -> Response {
        state
            .lan
            .save_ntp(i)
            .await
            .map(|_| done())
            .unwrap_or_else(err)
    }

    pub fn router() -> axum::Router<AppState> {
        use axum::routing::get;
        axum::Router::new().route("/ntp", get(get_ntp).put(put_ntp))
    }
}

/// API routes, mounted under `/api` with one `.merge(lan::router())`.
pub fn router() -> axum::Router<AppState> {
    let r = axum::Router::new();
    #[cfg(feature = "dhcp")]
    let r = r.merge(dhcp_routes::router());
    #[cfg(feature = "dns")]
    let r = r.merge(dns_routes::router());
    #[cfg(feature = "ntp")]
    let r = r.merge(ntp_routes::router());
    r
}

/// HTML pages, merged into the page router with one line.
pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    #[cfg(feature = "dhcp")]
    let dhcp = get(dhcp_routes::page);
    #[cfg(not(feature = "dhcp"))]
    let dhcp = get(|| async { not_built("DHCP", "dhcp") });
    #[cfg(feature = "dns")]
    let dns = get(dns_routes::page);
    #[cfg(not(feature = "dns"))]
    let dns = get(|| async { not_built("DNS", "dns") });
    #[cfg(feature = "ntp")]
    let ntp = get(ntp_routes::page);
    #[cfg(not(feature = "ntp"))]
    let ntp = get(|| async { not_built("NTP", "ntp") });
    axum::Router::new()
        .route("/dhcp", dhcp)
        .route("/dns", dns)
        .route("/ntp", ntp)
}
