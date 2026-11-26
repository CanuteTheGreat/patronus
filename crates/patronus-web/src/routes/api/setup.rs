//! First-boot setup wizard (`/setup`, `/api/setup/*`). One guided pass over
//! the settings a new router needs: host name, DNS domain, time zone and NTP
//! servers; which port is WAN and which is LAN; how the WAN gets its address
//! (DHCP, static or PPPoE) and its IPv6 (DHCPv6 with prefix delegation of a
//! chosen size, SLAAC, static or none); the LAN address, its IPv6 (track the
//! WAN's delegated prefix, static or none) and a DHCP pool for LAN clients. It drives the same managers as the Interfaces and DHCP pages
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
        "features": wizard_features(),
        "interfaces": ifs,
    }))
    .into_response()
}

/// Default name of the ppp device a PPPoE WAN creates (the WAN role moves to it).
pub const DEFAULT_PPPOE_DEVICE: &str = "pppoe0";
/// MTU of a PPPoE link when the wizard is not given one (RFC 2516: 1500 - 8).
pub const DEFAULT_PPPOE_MTU: u32 = 1492;

/// What this build can set up in the wizard (the router image of the embedded tier is built with fewer features).
pub fn wizard_features() -> serde_json::Value {
    json!({
        "pppoe": cfg!(feature = "pppoe"),
        "dhcp": cfg!(feature = "dhcp"),
        "ntp": cfg!(feature = "ntp"),
        "ipv6": true,
    })
}

#[derive(Debug, Default, Deserialize)]
pub struct SetupBody {
    /// Host name (one label); absent or empty = unchanged.
    #[serde(default)]
    pub hostname: Option<String>,
    /// DNS domain; absent = unchanged.
    #[serde(default)]
    pub domain: Option<String>,
    /// zoneinfo name (`Europe/Berlin`, `UTC`); absent or empty = unchanged.
    #[serde(default)]
    pub timezone: Option<String>,
    /// Upstream NTP servers (comma/space separated); absent or empty = unchanged.
    #[serde(default)]
    pub ntp_servers: Option<String>,
    pub wan_interface: String,
    /// `dhcp` (default), `static` or `pppoe`
    #[serde(default)]
    pub wan_mode: Option<String>,
    /// PPPoE: user name and password from the ISP, optional service name, MTU and ppp device name.
    #[serde(default)]
    pub pppoe_username: Option<String>,
    #[serde(default)]
    pub pppoe_password: Option<String>,
    #[serde(default)]
    pub pppoe_service_name: Option<String>,
    #[serde(default)]
    pub pppoe_mtu: Option<u32>,
    #[serde(default)]
    pub pppoe_device: Option<String>,
    /// WAN IPv6: `none` (default), `dhcp6`, `slaac` or `static`
    #[serde(default)]
    pub wan_ipv6_mode: Option<String>,
    /// Static WAN IPv6 address (CIDR) and gateway.
    #[serde(default)]
    pub wan_ipv6: Option<String>,
    #[serde(default)]
    pub wan_gateway6: Option<String>,
    /// Size of the prefix to ask the ISP to delegate (48-64), with LAN IPv6 `track`.
    #[serde(default)]
    pub wan_pd_len: Option<u8>,
    /// LAN IPv6: `none` (default), `track` (a /64 of the WAN's delegated prefix) or `static`
    #[serde(default)]
    pub lan_ipv6_mode: Option<String>,
    /// Static LAN IPv6 address (CIDR).
    #[serde(default)]
    pub lan_ipv6: Option<String>,
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

/// What the wizard will do with the WAN and LAN, checked before anything is changed.
#[derive(Debug, Clone, PartialEq)]
pub struct SetupPlan {
    pub wan_mode: &'static str,
    pub wan_v6: &'static str,
    pub lan_v6: &'static str,
    /// ppp device when `wan_mode` is pppoe
    pub pppoe_device: Option<String>,
    pub pd_len: Option<u8>,
}

fn nonempty(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Validate the wizard body as a whole (plain-words "Invalid setup: ..." errors). Field-level checks (address syntax, host
/// name, time zone) are done again by the managers that store them.
pub fn plan(b: &SetupBody) -> Result<SetupPlan, String> {
    let bad = |m: String| Err(format!("Invalid setup: {m}"));
    if b.wan_interface == b.lan_interface {
        return bad("WAN and LAN need different interfaces".into());
    }
    let wan_mode = match b.wan_mode.as_deref().map(str::trim).unwrap_or("dhcp") {
        "" | "dhcp" => "dhcp",
        "static" => "static",
        "pppoe" => "pppoe",
        o => return bad(format!("WAN mode {o:?} (dhcp, static or pppoe)")),
    };
    if wan_mode == "static" && nonempty(&b.wan_ipv4).is_none() {
        return bad("a static WAN needs its address (CIDR, e.g. 203.0.113.2/29)".into());
    }
    let mut pppoe_device = None;
    if wan_mode == "pppoe" {
        if !cfg!(feature = "pppoe") {
            return bad("this build has no PPPoE support (USE=pppoe)".into());
        }
        if nonempty(&b.pppoe_username).is_none() {
            return bad("PPPoE needs the user name your ISP gave you".into());
        }
        if nonempty(&b.pppoe_password).is_none() {
            return bad("PPPoE needs the password your ISP gave you".into());
        }
        let dev = nonempty(&b.pppoe_device).unwrap_or_else(|| DEFAULT_PPPOE_DEVICE.into());
        if !patronus_network::netconf::is_valid_ifname(&dev)
            || dev == b.wan_interface
            || dev == b.lan_interface
        {
            return bad(format!("PPPoE device name {dev:?}"));
        }
        if let Some(m) = b.pppoe_mtu {
            if !(576..=1500).contains(&m) {
                return bad(format!("PPPoE MTU {m} (576-1500; 1492 is usual)"));
            }
        }
        pppoe_device = Some(dev);
    }
    let wan_v6 = match b.wan_ipv6_mode.as_deref().map(str::trim).unwrap_or("none") {
        "" | "none" => "none",
        "dhcp6" | "dhcpv6" => "dhcp6",
        "slaac" => "slaac",
        "static" => "static",
        o => {
            return bad(format!(
                "WAN IPv6 mode {o:?} (none, dhcp6, slaac or static)"
            ))
        }
    };
    if wan_v6 == "static" && nonempty(&b.wan_ipv6).is_none() {
        return bad("static WAN IPv6 needs an address (CIDR)".into());
    }
    let lan_v6 = match b.lan_ipv6_mode.as_deref().map(str::trim).unwrap_or("none") {
        "" | "none" => "none",
        "track" => "track",
        "static" => "static",
        o => return bad(format!("LAN IPv6 mode {o:?} (none, track or static)")),
    };
    if lan_v6 == "track" && wan_v6 != "dhcp6" {
        return bad("LAN IPv6 'track the WAN' needs WAN IPv6 DHCPv6 (the ISP delegates the prefix over DHCPv6)".into());
    }
    if lan_v6 == "static" && nonempty(&b.lan_ipv6).is_none() {
        return bad("static LAN IPv6 needs an address (CIDR)".into());
    }
    let pd_len = if lan_v6 == "track" {
        b.wan_pd_len
    } else {
        None
    };
    if let Some(n) = b.wan_pd_len {
        use patronus_network::netconf::{PD_LEN_MAX, PD_LEN_MIN};
        if !(PD_LEN_MIN..=PD_LEN_MAX).contains(&n) {
            return bad(format!(
                "delegated prefix size /{n} (/{PD_LEN_MIN} to /{PD_LEN_MAX}; /56 is the usual home allocation)"
            ));
        }
        if lan_v6 != "track" {
            return bad(
                "a delegated prefix size is only used with LAN IPv6 'track the WAN'".into(),
            );
        }
    }
    if b.dhcp && (nonempty(&b.dhcp_start).is_none() || nonempty(&b.dhcp_end).is_none()) {
        return bad("the DHCP pool needs a start and an end address".into());
    }
    if let Some(h) = nonempty(&b.hostname) {
        patronus_network::general::check_hostname(&h).map_err(|e| format!("Invalid setup: {e}"))?;
    }
    if let Some(t) = nonempty(&b.timezone) {
        patronus_network::general::check_timezone(&t).map_err(|e| format!("Invalid setup: {e}"))?;
    }
    if nonempty(&b.ntp_servers).is_some() && !cfg!(feature = "ntp") {
        return bad("this build has no NTP service (USE=ntp)".into());
    }
    Ok(SetupPlan {
        wan_mode,
        wan_v6,
        lan_v6,
        pppoe_device,
        pd_len,
    })
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
    let pl = match plan(&b) {
        Ok(p) => p,
        Err(m) => return error(StatusCode::BAD_REQUEST, m),
    };
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
    // the device that carries the WAN role: the port itself, or the ppp device of a PPPoE WAN
    let wan_dev = pl
        .pppoe_device
        .clone()
        .unwrap_or_else(|| b.wan_interface.clone());
    let wan = InterfaceUpdate {
        role: Some("wan".into()),
        ipv4_mode: match pl.wan_mode {
            "static" => "static",
            // pppd puts the address on the ppp device
            "pppoe" => "unmanaged",
            _ => "dhcp",
        }
        .into(),
        ipv4: if pl.wan_mode == "static" {
            nonempty(&b.wan_ipv4).into_iter().collect()
        } else {
            Vec::new()
        },
        gateway4: if pl.wan_mode == "static" {
            nonempty(&b.wan_gateway)
        } else {
            None
        },
        ipv6_mode: pl.wan_v6.into(),
        ipv6: if pl.wan_v6 == "static" {
            nonempty(&b.wan_ipv6).into_iter().collect()
        } else {
            Vec::new()
        },
        gateway6: if pl.wan_v6 == "static" {
            nonempty(&b.wan_gateway6)
        } else {
            None
        },
        pd_downstream: if pl.lan_v6 == "track" {
            vec![b.lan_interface.clone()]
        } else {
            Vec::new()
        },
        dhcp6_pd_len: pl.pd_len,
        force: b.force,
        ..Default::default()
    };
    let lan = InterfaceUpdate {
        role: Some("lan".into()),
        ipv4_mode: "static".into(),
        ipv4: vec![b.lan_ipv4.clone()],
        // `track`: the WAN's DHCPv6 client puts a /64 of the delegated prefix here (LAN mode none keeps RA/SLAAC off the LAN
        // port itself; router advertisements for the clients are set up below)
        ipv6_mode: if pl.lan_v6 == "static" {
            "static"
        } else {
            "none"
        }
        .into(),
        ipv6: if pl.lan_v6 == "static" {
            nonempty(&b.lan_ipv6).into_iter().collect()
        } else {
            Vec::new()
        },
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
    let mut steps: Vec<(String, InterfaceUpdate)> = vec![(b.lan_interface.clone(), lan)];
    if let Some(dev) = &pl.pppoe_device {
        // the session runs on the port; the port itself carries no role and no address
        let body = crate::state::interfaces::PppoeBody {
            name: dev.clone(),
            parent: b.wan_interface.clone(),
            username: nonempty(&b.pppoe_username).unwrap_or_default(),
            password: nonempty(&b.pppoe_password).unwrap_or_default(),
            service_name: nonempty(&b.pppoe_service_name),
            mtu: Some(b.pppoe_mtu.unwrap_or(DEFAULT_PPPOE_MTU)),
            default_route: Some(true),
            use_peer_dns: Some(true),
            // IPv6CP on the session, so the WAN's DHCPv6/SLAAC run over the ppp link
            ipv6: pl.wan_v6 != "none",
            enabled: Some(true),
            description: Some("created by the setup wizard".into()),
            force: b.force,
        };
        match state.interfaces.upsert_pppoe(body, client).await {
            Ok(r) => applied.extend(r.applied),
            Err(e) => {
                let m = e.to_string();
                let code = if m.contains("Invalid") {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                return abort(
                    &state,
                    &cp,
                    code,
                    &format!("Creating the PPPoE link {dev}"),
                    &m,
                )
                .await;
            }
        }
        steps.push((
            b.wan_interface.clone(),
            InterfaceUpdate {
                role: None,
                ipv4_mode: "none".into(),
                ipv6_mode: "none".into(),
                force: b.force,
                ..Default::default()
            },
        ));
    }
    steps.push((wan_dev.clone(), wan));
    for (name, u) in steps {
        let name = &name;
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
                } else if pl.pppoe_device.is_some() && *name == b.wan_interface {
                    "PPPoE parent"
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
    // LAN clients learn the IPv6 prefix from router advertisements: turn them on for the LAN (an existing RA entry is kept)
    #[cfg(feature = "dhcp")]
    if pl.lan_v6 != "none" {
        let have = patronus_network::ra::list(&state.config_store)
            .await
            .map(|v| v.iter().any(|r| r.interface == b.lan_interface))
            .unwrap_or(false);
        if !have {
            let ra = patronus_network::ra::RaInput {
                interface: b.lan_interface.clone(),
                enabled: true,
                mode: Some("slaac".into()),
                description: Some("created by the setup wizard".into()),
                ..Default::default()
            };
            if let Err(e) = state.lan.save_ra(None, ra).await {
                return abort(
                    &state,
                    &cp,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Turning on router advertisements on the LAN",
                    &e.to_string(),
                )
                .await;
            }
            applied.push("ra".into());
        }
    }
    let general = patronus_network::general::GeneralInput {
        hostname: nonempty(&b.hostname),
        domain: b.domain.as_ref().map(|d| d.trim().to_string()),
        timezone: nonempty(&b.timezone),
    };
    if general.hostname.is_some() || general.domain.is_some() || general.timezone.is_some() {
        if let Err(e) = state.lan.save_general(general).await {
            let m = e.to_string();
            let code = if m.contains("Invalid") || m.contains("invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return abort(
                &state,
                &cp,
                code,
                "Setting the host name, domain and time zone",
                &m,
            )
            .await;
        }
        applied.push("general".into());
    }
    #[cfg(feature = "ntp")]
    if let Some(servers) = nonempty(&b.ntp_servers) {
        let i = patronus_network::ntp::NtpInput {
            enabled: None,
            servers: Some(servers),
            interfaces: None,
        };
        if let Err(e) = state.lan.save_ntp(i).await {
            let m = e.to_string();
            let code = if m.contains("Invalid") || m.contains("invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return abort(&state, &cp, code, "Setting the NTP servers", &m).await;
        }
        applied.push("ntp".into());
    }
    let _ = patronus_network::lan::set_setting(&state.config_store, DONE_KEY, "1").await;
    let _ = state
        .config_store
        .audit(
            "web",
            "apply",
            "setup-wizard",
            None,
            &json!({"wan": wan_dev, "wan_port": b.wan_interface, "wan_mode": pl.wan_mode,
                    "wan_ipv6": pl.wan_v6, "lan": b.lan_interface, "lan_ipv6": pl.lan_v6}),
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

    fn body(v: serde_json::Value) -> SetupBody {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn the_plan_checks_the_whole_body_first() {
        let base =
            json!({"wan_interface": "wan0", "lan_interface": "lan0", "lan_ipv4": "192.168.1.1/24"});
        let p = plan(&body(base.clone())).unwrap();
        assert_eq!((p.wan_mode, p.wan_v6, p.lan_v6), ("dhcp", "none", "none"));
        let mut b = base.clone();
        b["lan_interface"] = json!("wan0");
        assert!(plan(&body(b)).unwrap_err().contains("different interfaces"));
        // PPPoE needs user + password; the WAN role moves to the ppp device
        let mut b = base.clone();
        b["wan_mode"] = json!("pppoe");
        if cfg!(feature = "pppoe") {
            assert!(plan(&body(b.clone())).unwrap_err().contains("user name"));
            b["pppoe_username"] = json!("user@isp");
            assert!(plan(&body(b.clone())).unwrap_err().contains("password"));
            b["pppoe_password"] = json!("pw");
            assert_eq!(
                plan(&body(b.clone())).unwrap().pppoe_device.as_deref(),
                Some("pppoe0")
            );
            b["pppoe_device"] = json!("wan0");
            assert!(plan(&body(b.clone())).unwrap_err().contains("device name"));
            b["pppoe_device"] = json!("ppp7");
            b["pppoe_mtu"] = json!(9000);
            assert!(plan(&body(b)).unwrap_err().contains("MTU"));
        } else {
            assert!(plan(&body(b)).unwrap_err().contains("USE=pppoe"));
        }
        // LAN tracking needs DHCPv6 on the WAN; the prefix size only goes with tracking and stays in 48..=64
        let mut b = base.clone();
        b["lan_ipv6_mode"] = json!("track");
        assert!(plan(&body(b.clone())).unwrap_err().contains("DHCPv6"));
        b["wan_ipv6_mode"] = json!("dhcp6");
        b["wan_pd_len"] = json!(56);
        let p = plan(&body(b.clone())).unwrap();
        assert_eq!((p.wan_v6, p.lan_v6, p.pd_len), ("dhcp6", "track", Some(56)));
        b["wan_pd_len"] = json!(40);
        assert!(plan(&body(b)).unwrap_err().contains("/40"));
        let mut b = base.clone();
        b["wan_ipv6_mode"] = json!("slaac");
        b["wan_pd_len"] = json!(56);
        assert!(plan(&body(b)).unwrap_err().contains("only used"));
        let mut b = base.clone();
        b["wan_ipv6_mode"] = json!("static");
        assert!(plan(&body(b)).unwrap_err().contains("address"));
        let mut b = base.clone();
        b["wan_ipv6_mode"] = json!("dhcp7");
        assert!(plan(&body(b)).is_err());
        // identity fields are checked before anything changes
        let mut b = base.clone();
        b["hostname"] = json!("fw.example.org");
        assert!(plan(&body(b)).unwrap_err().contains("host name"));
        let mut b = base.clone();
        b["timezone"] = json!("../etc/passwd");
        assert!(plan(&body(b)).unwrap_err().contains("time zone"));
        let mut b = base;
        b["hostname"] = json!("fw1");
        b["timezone"] = json!("Europe/Berlin");
        b["dhcp"] = json!(true);
        assert!(plan(&body(b)).unwrap_err().contains("DHCP pool"));
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
