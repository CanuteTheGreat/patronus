//! First-boot setup wizard (`/setup`, `/api/setup/*`). One guided pass over
//! the settings a new router needs: which port is WAN and which is LAN, how
//! the WAN gets its address, the LAN address, and a DHCP pool for LAN
//! clients. It drives the same managers as the Interfaces and DHCP pages
//! (store -> applier -> kernel/daemon), so the result is persisted and
//! survives reboot; it adds only the "wizard completed" marker.
//!
//! The wizard is for routers. A unit whose role is set at build time
//! (`PATRONUS_DEVICE_ROLE=ap`: a wired access point with every port bridged
//! and no WAN, DHCP or DNS of its own) is configured by its image and needs
//! no wizard: its first start records setup as complete
//! ([`record_provisioned`]), the status always says so, and the wizard
//! refuses to run there. `PATRONUS_SETUP_PROVISIONED=1` does the same for a
//! router image whose network was provisioned at build or first boot.

// Askama resolves the `t` / `crumb` / ... template filters (`{{ "key"|t }}`) here
#[allow(unused_imports)]
use crate::i18n::filters;
use crate::state::interfaces::InterfaceUpdate;
use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

const DONE_KEY: &str = "setup.completed";

/// What this unit is, from the image (`PATRONUS_DEVICE_ROLE`): `router`
/// (default) or `ap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Router,
    Ap,
}

impl DeviceRole {
    pub fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("ap") | Some("access-point") => DeviceRole::Ap,
            _ => DeviceRole::Router,
        }
    }
    pub fn from_env() -> Self {
        Self::parse(std::env::var("PATRONUS_DEVICE_ROLE").ok().as_deref())
    }
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceRole::Router => "router",
            DeviceRole::Ap => "ap",
        }
    }
    /// The router wizard (WAN/LAN/DHCP) applies to this role.
    pub fn wizard_applies(self) -> bool {
        self == DeviceRole::Router
    }
}

/// Why setup counts as done without the wizard, if it does: the role, or an
/// image that provisioned its network (`PATRONUS_SETUP_PROVISIONED=1`).
pub fn provisioned_reason(role: DeviceRole, provisioned_env: Option<&str>) -> Option<&'static str> {
    if role == DeviceRole::Ap {
        Some("access point: configured by its image, the router wizard does not apply")
    } else if provisioned_env.is_some_and(|v| v.trim() == "1") {
        Some("network provisioned by the image")
    } else {
        None
    }
}

/// First start of a provisioned unit: record setup as complete (once, with an
/// audit row), so the "not set up yet" banner never appears. Returns whether
/// it wrote the marker now.
pub async fn record_provisioned(
    store: &patronus_config::ConfigStore,
    role: DeviceRole,
    provisioned_env: Option<&str>,
) -> anyhow::Result<bool> {
    let Some(reason) = provisioned_reason(role, provisioned_env) else {
        return Ok(false);
    };
    if patronus_network::lan::get_setting(store, DONE_KEY)
        .await?
        .is_some_and(|v| v == "1")
    {
        return Ok(false);
    }
    patronus_network::lan::set_setting(store, DONE_KEY, "1").await?;
    let _ = store
        .audit(
            "system",
            "provisioned",
            "setup-wizard",
            None,
            &json!({"role": role.as_str(), "reason": reason}),
        )
        .await;
    Ok(true)
}

#[derive(Template)]
#[template(path = "setup.html")]
pub struct SetupTemplate {
    pub page: &'static str,
    pub can_modify: bool,
    pub ap_mode: bool,
}

pub async fn page(me: crate::auth::AuthUser) -> Response {
    match (SetupTemplate {
        page: "setup",
        can_modify: me.session.role.can_modify(),
        ap_mode: !DeviceRole::from_env().wizard_applies(),
    })
    .render()
    {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render setup: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

fn error(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "error": m.into() }))).into_response()
}

/// One readable sentence for a failed wizard step: whitespace collapsed
/// (daemon output often carries newlines and padding), no trailing noise.
/// The raw text stays in the server log.
pub fn friendly_failure(stage: &str, raw: &str) -> String {
    let flat = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let flat = flat.trim().trim_end_matches(['.', ';', ':']).to_string();
    let flat = if flat.is_empty() {
        "no further detail was reported".to_string()
    } else {
        flat
    };
    format!("Setup was not applied and nothing was changed. {stage} failed: {flat}.")
}

/// Fail the wizard: put the interface configuration back to what it was
/// before the first step (no half-applied setup), log the raw error, and
/// answer with the readable message.
async fn abort(
    state: &AppState,
    cp: &crate::state::interfaces::Checkpoint,
    code: StatusCode,
    stage: &str,
    raw: &str,
) -> Response {
    tracing::warn!("setup wizard: {stage} failed, rolling back: {raw}");
    state.interfaces.rollback(cp).await;
    let msg = friendly_failure(stage, raw);
    (
        code,
        Json(json!({ "error": msg, "stage": stage, "rolled_back": true })),
    )
        .into_response()
}

async fn completed(state: &AppState) -> bool {
    patronus_network::lan::get_setting(&state.config_store, DONE_KEY)
        .await
        .ok()
        .flatten()
        .is_some_and(|v| v == "1")
}

/// Wizard defaults from what the box already has. An installed image's LAN port carries the installer's address (for
/// example 10.77.0.1/24); a form that defaults to 192.168.1.1/24 would, on a plain Apply, move the router away from the
/// address the operator is connected to. Returns `{interface, ipv4, dhcp_start, dhcp_end}` for the first non-WAN port with a
/// permanent IPv4 address (the port with role `lan` wins).
pub fn suggest_lan(ifs: &[serde_json::Value]) -> Option<serde_json::Value> {
    let permanent_v4 = |d: &serde_json::Value| -> Option<(std::net::Ipv4Addr, u32)> {
        d["addresses"].as_array()?.iter().find_map(|a| {
            if a["dynamic"].as_bool().unwrap_or(false) {
                return None;
            }
            let (ip, len) = a["address"].as_str()?.split_once('/')?;
            let ip: std::net::Ipv4Addr = ip.parse().ok()?;
            let len: u32 = len.parse().ok()?;
            (8..=29).contains(&len).then_some((ip, len))
        })
    };
    let candidates = || ifs.iter().filter(|d| d["role"].as_str() != Some("wan"));
    let pick = candidates()
        .filter(|d| d["role"].as_str() == Some("lan"))
        .find_map(|d| permanent_v4(d).map(|a| (d, a)))
        .or_else(|| candidates().find_map(|d| permanent_v4(d).map(|a| (d, a))))?;
    let (d, (ip, len)) = pick;
    let mask = u32::MAX << (32 - len);
    let net = u32::from(ip) & mask;
    let size = 1u64 << (32 - len);
    // the pool lives in the upper part of the subnet and never covers the router's own address
    let (lo, hi) = if size >= 256 {
        (100u32, 199u32)
    } else {
        ((size / 2) as u32, (size - 2) as u32)
    };
    let off = u32::from(ip) - net;
    let (lo, hi) = if (lo..=hi).contains(&off) {
        if size >= 256 {
            (200, 249)
        } else {
            (0, 0)
        }
    } else {
        (lo, hi)
    };
    let mut out = json!({
        "interface": d["name"],
        "ipv4": format!("{ip}/{len}"),
    });
    if hi >= lo && hi != 0 {
        out["dhcp_start"] = json!(std::net::Ipv4Addr::from(net + lo).to_string());
        out["dhcp_end"] = json!(std::net::Ipv4Addr::from(net + hi).to_string());
    }
    Some(out)
}

/// GET /api/setup/status -> {completed, interfaces: [{name, role, up, addresses}]}
pub async fn status(State(state): State<AppState>) -> Response {
    let ov = match state.interfaces.overview(None).await {
        Ok(v) => v,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let ifs: Vec<_> = ov["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| {
            matches!(
                d["kind"].as_str(),
                Some("ethernet") | Some("wlan") | Some("veth") | None
            ) && d["master"].is_null()
        })
        .map(|d| {
            json!({
                "name": d["name"],
                "up": d["up"],
                "mac": d["mac"],
                "role": d["config"]["role"],
                "addresses": d["addresses"],
            })
        })
        .collect();
    let role = DeviceRole::from_env();
    // an AP never waits for the router wizard, whatever the store says
    let done = completed(&state).await || !role.wizard_applies();
    let suggested_lan = suggest_lan(&ifs);
    Json(json!({
        "completed": done,
        "suggested_lan": suggested_lan,
        "role": role.as_str(),
        "wizard": role.wizard_applies(),
        "interfaces": ifs,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct SetupBody {
    pub wan_interface: String,
    /// `dhcp` (default) or `static`
    #[serde(default)]
    pub wan_mode: Option<String>,
    #[serde(default)]
    pub wan_ipv4: Option<String>,
    #[serde(default)]
    pub wan_gateway: Option<String>,
    pub lan_interface: String,
    /// CIDR, e.g. 192.168.1.1/24
    pub lan_ipv4: String,
    #[serde(default)]
    pub dhcp: bool,
    #[serde(default)]
    pub dhcp_start: Option<String>,
    #[serde(default)]
    pub dhcp_end: Option<String>,
    #[serde(default)]
    pub dns_servers: Option<String>,
    #[serde(default)]
    pub force: bool,
}

/// POST /api/setup/apply
pub async fn apply(
    State(state): State<AppState>,
    ci: Option<ConnectInfo<SocketAddr>>,
    _admin: crate::auth::AdminUser,
    Json(b): Json<SetupBody>,
) -> Response {
    if !DeviceRole::from_env().wizard_applies() {
        return error(
            StatusCode::CONFLICT,
            "this unit is an access point: the router setup wizard (WAN, LAN address, DHCP) does not apply",
        );
    }
    if b.wan_interface == b.lan_interface {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid setup: WAN and LAN need different interfaces",
        );
    }
    if b.dhcp
        && (b.dhcp_start.as_deref().unwrap_or("").is_empty()
            || b.dhcp_end.as_deref().unwrap_or("").is_empty())
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Invalid setup: the DHCP pool needs a start and an end address",
        );
    }
    // both ports must exist on this box: a typo would otherwise be stored as a phantom interface and "applied"
    if let Ok(ov) = state.interfaces.overview(None).await {
        let known: Vec<String> = ov["devices"]
            .as_array()
            .map(|d| {
                d.iter()
                    .filter_map(|x| x["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for (role, port) in [("WAN", &b.wan_interface), ("LAN", &b.lan_interface)] {
            if !known.is_empty() && !known.contains(port) {
                return error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Invalid setup: the {role} port {port:?} does not exist on this box (ports: {}). Nothing was changed.",
                        known.join(", ")
                    ),
                );
            }
        }
    }
    let client = ci.map(|ConnectInfo(a)| a.ip());
    let static_wan = b.wan_mode.as_deref() == Some("static");
    let wan = InterfaceUpdate {
        role: Some("wan".into()),
        ipv4_mode: if static_wan { "static" } else { "dhcp" }.into(),
        ipv4: b.wan_ipv4.iter().cloned().collect(),
        gateway4: b.wan_gateway.clone().filter(|g| !g.is_empty()),
        ipv6_mode: "none".into(),
        force: b.force,
        ..Default::default()
    };
    let lan = InterfaceUpdate {
        role: Some("lan".into()),
        ipv4_mode: "static".into(),
        ipv4: vec![b.lan_ipv4.clone()],
        ipv6_mode: "none".into(),
        force: b.force,
        ..Default::default()
    };
    let cp = match state.interfaces.checkpoint().await {
        Ok(c) => c,
        Err(e) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                friendly_failure("Reading the current network configuration", &e.to_string()),
            )
        }
    };
    let mut applied = Vec::new();
    for (name, u) in [(&b.lan_interface, lan), (&b.wan_interface, wan)] {
        match state.interfaces.update_interface(name, u, client).await {
            Ok(r) => applied.extend(r.applied),
            Err(e) => {
                let m = e.to_string();
                let code = if m.starts_with(crate::state::interfaces::LOCKOUT) {
                    StatusCode::CONFLICT
                } else if m.contains("Invalid") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                let role = if *name == b.lan_interface {
                    "LAN"
                } else {
                    "WAN"
                };
                return abort(
                    &state,
                    &cp,
                    code,
                    &format!("Configuring the {role} port {name}"),
                    &m,
                )
                .await;
            }
        }
    }
    #[cfg(feature = "dhcp")]
    if b.dhcp {
        let (Some(s), Some(e)) = (b.dhcp_start.clone(), b.dhcp_end.clone()) else {
            return abort(
                &state,
                &cp,
                StatusCode::BAD_REQUEST,
                "Checking the DHCP pool",
                "Invalid setup: the DHCP pool needs a start and an end address",
            )
            .await;
        };
        let lan_ip = b.lan_ipv4.split('/').next().unwrap_or("").to_string();
        // Running the wizard again re-applies it ("running it again re-applies the settings below"): a pool the wizard (or the DHCP
        // page) already made on this port is updated in place, keeping its lease time, domain, NTP servers and reservations.
        let existing = patronus_network::dhcp::list_pools(&state.config_store)
            .await
            .ok()
            .and_then(|v| v.into_iter().find(|p| p.interface == b.lan_interface));
        let mut pool = patronus_network::dhcp::PoolInput {
            interface: b.lan_interface.clone(),
            enabled: true,
            range_start: s,
            range_end: e,
            gateway: Some(lan_ip.clone()),
            dns_servers: b
                .dns_servers
                .clone()
                .filter(|d| !d.is_empty())
                .or(Some(lan_ip)),
            description: Some("created by the setup wizard".into()),
            ..Default::default()
        };
        if let Some(old) = &existing {
            pool.lease_time = Some(old.lease_time);
            pool.domain = old.domain.clone();
            pool.ntp_servers = (!old.ntp_servers.is_empty()).then(|| {
                old.ntp_servers
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            });
        }
        if let Err(e) = state.lan.save_pool(existing.map(|p| p.id), pool).await {
            let m = e.to_string();
            let code = if m.contains("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return abort(&state, &cp, code, "Creating the LAN DHCP pool", &m).await;
        }
        applied.push("dhcp".into());
    }
    #[cfg(not(feature = "dhcp"))]
    if b.dhcp {
        return error(
            StatusCode::NOT_IMPLEMENTED,
            "this build has no DHCP server (USE=dhcp)",
        );
    }
    let _ = patronus_network::lan::set_setting(&state.config_store, DONE_KEY, "1").await;
    let _ = state
        .config_store
        .audit(
            "web",
            "apply",
            "setup-wizard",
            None,
            &json!({"wan": b.wan_interface, "lan": b.lan_interface}),
        )
        .await;
    Json(json!({ "message": "applied", "applied": applied, "completed": true })).into_response()
}

/// POST /api/setup/complete: leave the wizard without changing anything.
pub async fn complete(State(state): State<AppState>, _admin: crate::auth::AdminUser) -> Response {
    match patronus_network::lan::set_setting(&state.config_store, DONE_KEY, "1").await {
        Ok(()) => Json(json!({ "completed": true })).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/setup/status", get(status))
        .route("/setup/apply", post(apply))
        .route("/setup/complete", post(complete))
}

pub fn pages() -> axum::Router<AppState> {
    use axum::routing::get;
    axum::Router::new().route("/setup", get(page))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> patronus_config::ConfigStore {
        let dir = std::env::temp_dir().join(format!("patronus-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap()
    }

    async fn done(s: &patronus_config::ConfigStore) -> bool {
        patronus_network::lan::get_setting(s, DONE_KEY)
            .await
            .unwrap()
            .is_some_and(|v| v == "1")
    }

    #[test]
    fn a_failed_step_is_one_readable_sentence() {
        let m = friendly_failure(
            "Configuring the WAN port enp0s1",
            "failed to apply interfaces (interface enp0s1): rc-service: service\n  patronus-dhcpc.enp0s1 does not exist\n",
        );
        assert!(m.starts_with("Setup was not applied and nothing was changed. Configuring the WAN port enp0s1 failed: "));
        assert!(m.ends_with("does not exist."), "{m}");
        assert!(!m.contains('\n') && !m.contains("  "), "{m:?}");
        assert!(friendly_failure("X", "").contains("no further detail"));
    }

    #[test]
    fn role_parsing_defaults_to_router() {
        assert_eq!(DeviceRole::parse(None), DeviceRole::Router);
        assert_eq!(DeviceRole::parse(Some("")), DeviceRole::Router);
        assert_eq!(DeviceRole::parse(Some("router")), DeviceRole::Router);
        assert_eq!(DeviceRole::parse(Some(" AP ")), DeviceRole::Ap);
        assert_eq!(DeviceRole::parse(Some("access-point")), DeviceRole::Ap);
        assert!(DeviceRole::Router.wizard_applies());
        assert!(!DeviceRole::Ap.wizard_applies());
    }

    #[tokio::test]
    async fn an_access_point_records_setup_complete_at_first_start() {
        let s = store().await;
        assert!(!done(&s).await);
        assert!(record_provisioned(&s, DeviceRole::Ap, None).await.unwrap());
        assert!(done(&s).await);
        // once only: a second start writes nothing (and no second audit row)
        assert!(!record_provisioned(&s, DeviceRole::Ap, None).await.unwrap());
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT action FROM audit_log WHERE entity_type = 'setup-wizard'")
                .fetch_all(s.pool().unwrap())
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "provisioned");
    }

    #[tokio::test]
    async fn a_fresh_router_still_needs_the_wizard() {
        let s = store().await;
        assert!(!record_provisioned(&s, DeviceRole::Router, None)
            .await
            .unwrap());
        assert!(!record_provisioned(&s, DeviceRole::Router, Some("0"))
            .await
            .unwrap());
        assert!(!done(&s).await, "a router-mode unit must keep the banner");
        // a router image that provisioned its network says so explicitly
        assert!(record_provisioned(&s, DeviceRole::Router, Some("1"))
            .await
            .unwrap());
        assert!(done(&s).await);
    }

    #[test]
    fn lan_defaults_follow_the_address_the_port_already_has() {
        let ifs = vec![
            json!({"name": "enp0s1", "role": "wan", "addresses": [{"address": "10.0.2.15/24", "dynamic": true}]}),
            json!({"name": "enp0s2", "role": null, "addresses": [{"address": "10.77.0.1/24", "dynamic": false}]}),
        ];
        let s = suggest_lan(&ifs).unwrap();
        assert_eq!(s["interface"], "enp0s2");
        assert_eq!(s["ipv4"], "10.77.0.1/24");
        assert_eq!(s["dhcp_start"], "10.77.0.100");
        assert_eq!(s["dhcp_end"], "10.77.0.199");
        // the router address inside the usual pool range moves the pool out of the way
        let ifs = vec![
            json!({"name": "lan0", "role": "lan", "addresses": [{"address": "192.168.5.150/24", "dynamic": false}]}),
        ];
        let s = suggest_lan(&ifs).unwrap();
        assert_eq!(s["dhcp_start"], "192.168.5.200");
        assert_eq!(s["dhcp_end"], "192.168.5.249");
        // a /25 gets the upper half
        let ifs = vec![
            json!({"name": "lan0", "role": "lan", "addresses": [{"address": "172.16.0.1/25", "dynamic": false}]}),
        ];
        let s = suggest_lan(&ifs).unwrap();
        assert_eq!(s["dhcp_start"], "172.16.0.64");
        assert_eq!(s["dhcp_end"], "172.16.0.126");
    }

    #[test]
    fn no_lan_suggestion_without_a_permanent_address() {
        // a WAN port, a DHCP lease and a loopback-sized prefix are never offered as the LAN
        let ifs = vec![
            json!({"name": "wan0", "role": "wan", "addresses": [{"address": "10.0.0.2/24", "dynamic": false}]}),
            json!({"name": "eth1", "role": null, "addresses": [{"address": "10.1.0.5/24", "dynamic": true}]}),
            json!({"name": "eth2", "role": null, "addresses": [{"address": "fe80::1/64", "dynamic": false}]}),
        ];
        assert!(suggest_lan(&ifs).is_none());
    }
}
