//! Firewall API endpoints

use crate::state::firewall::FirewallManager;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// Map an error coming out of `FirewallManager::add_rule`/`add_nat_rule`
/// into the right HTTP status: the rule-validation layer (nftables
/// ruleset-injection checks in `patronus_firewall::nftables`, and the
/// NAT-type/target parsing in `patronus_web::state`) always prefixes its
/// rejections with "Invalid " -- those are client-input problems (400), not
/// server/backend failures (500, e.g. the `nft` binary itself erroring or
/// being unreachable).
fn status_for_apply_error(e: &anyhow::Error) -> StatusCode {
    if e.to_string().contains("Invalid ") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Option<u32>,
    /// Display name (defaults to `description`).
    #[serde(default)]
    pub name: Option<String>,
    /// input (default), forward or output.
    #[serde(default)]
    pub chain: Option<String>,
    /// accept, drop (silently discard) or reject (TCP reset / ICMP
    /// unreachable).
    pub action: String,
    /// Inbound interface (outbound for the output chain): `any`, a role
    /// (`@wan`, `@lan`, `@optN`, `@mgmt`) or a device name.
    pub interface: String,
    /// Forward chain only: the outbound interface (`any` by default).
    #[serde(default)]
    pub interface_out: Option<String>,
    #[serde(default)]
    pub protocol: String,
    /// IPv4/IPv6 address or CIDR, `any`, or `$alias` (host alias).
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub destination: String,
    /// Destination port(s): `80`, `8000-8010`, `22,443`, `$alias`, `any`.
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Log matching packets.
    #[serde(default)]
    pub log: bool,
    /// Name of a schedule; the rule is enforced only while it is active.
    #[serde(default)]
    pub schedule: Option<String>,
    /// `ipv4`, `ipv6` or `any` (default: implied by the addresses).
    #[serde(default)]
    pub ip_version: Option<String>,
    /// Policy routing: a gateway or gateway group (Routing page) that
    /// traffic this accept rule matches is sent through.
    #[serde(default)]
    pub gateway: Option<String>,
    /// Create only: place the new rule just before rule `before`.
    #[serde(default)]
    pub before: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    /// MASQUERADE, SNAT, DNAT (port forward) or 1:1.
    pub rule_type: String,
    /// Outbound interface for MASQUERADE/SNAT; inbound interface for a
    /// port forward or 1:1 NAT (`@wan`, a device, or `any`).
    pub interface: String,
    #[serde(default)]
    pub source: String,
    /// Port forward: the external address to match (default: any
    /// address on the interface).
    #[serde(default)]
    pub destination: String,
    /// `masquerade`, the SNAT address, the port-forward target
    /// `address[:port]` (`[v6]:port`), or the internal address of a 1:1.
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// tcp or udp (port forwards / port-limited outbound rules).
    #[serde(default)]
    pub protocol: Option<String>,
    /// Port forward: external port(s) (`8022`, `8000-8010`).
    #[serde(default)]
    pub external_port: Option<String>,
    /// 1:1 NAT: the external (WAN-side) address.
    #[serde(default)]
    pub external_address: Option<String>,
    /// Port forward: NAT reflection (LAN clients may use the WAN address).
    #[serde(default)]
    pub reflection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasBody {
    /// Required on create (the path names it on update).
    #[serde(default)]
    pub name: Option<String>,
    /// `host` or `port`.
    #[serde(rename = "type", alias = "alias_type")]
    pub alias_type: String,
    /// Entries; each string may hold several separated by commas,
    /// spaces or newlines.
    #[serde(default)]
    pub entries: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// URL table / GeoIP / threat-feed source (type `geoip`, `urltable`
    /// and `urltable_ports` fill it from `entries` when omitted).
    #[serde(default)]
    pub source: Option<patronus_firewall::aliases::AliasSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleBody {
    /// `mon`..`sun` (each string may hold a comma list).
    #[serde(default)]
    pub days: Vec<String>,
    /// HH:MM
    pub start: String,
    /// HH:MM (end <= start wraps past midnight)
    pub end: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedScheduleBody {
    pub name: String,
    #[serde(flatten)]
    pub body: ScheduleBody,
}

#[derive(Debug, Deserialize)]
pub struct MoveBody {
    /// up, down, top or bottom
    pub direction: String,
}

#[derive(Debug, Deserialize)]
pub struct OrderBody {
    /// Every non-system rule id, in the new order.
    pub ids: Vec<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ModeBody {
    /// automatic, hybrid, manual or disabled
    pub mode: String,
}

/// JSON error with the right status ("Invalid ..." -> 400, "not found" ->
/// 404, else 500).
fn err(what: &str, e: anyhow::Error) -> Response {
    let m = e.to_string();
    let code = if m.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        status_for_apply_error(&e)
    };
    tracing::error!("{what}: {m}");
    (
        code,
        Json(serde_json::json!({ "error": format!("{what}: {m}") })),
    )
        .into_response()
}

fn ok(msg: &str) -> Response {
    Json(serde_json::json!({ "message": msg })).into_response()
}

/// GET /api/firewall/rules
pub async fn list_rules(State(state): State<AppState>) -> Response {
    match state.firewall.list_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!("Failed to list firewall rules: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list firewall rules"
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/firewall/rules/:id
pub async fn get_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.get_rule(id).await {
        Ok(Some(rule)) => Json(rule).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Rule not found"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to get firewall rule {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to get firewall rule"
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/firewall/rules
pub async fn add_rule(State(state): State<AppState>, Json(rule): Json<FirewallRule>) -> Response {
    match state.firewall.add_rule(rule).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": id,
                "message": "Rule created successfully"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to add firewall rule: {}", e);
            (
                status_for_apply_error(&e),
                Json(serde_json::json!({
                    "error": format!("Failed to add rule: {}", e)
                })),
            )
                .into_response()
        }
    }
}

/// PUT /api/firewall/rules/:id
pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(rule): Json<FirewallRule>,
) -> Response {
    match state.firewall.update_rule(id, rule).await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rule updated successfully"
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to update firewall rule {}: {}", id, e);
            (
                if e.to_string().contains("not found") {
                    StatusCode::NOT_FOUND
                } else {
                    status_for_apply_error(&e)
                },
                Json(serde_json::json!({
                    "error": format!("Failed to update rule: {}", e)
                })),
            )
                .into_response()
        }
    }
}

/// DELETE /api/firewall/rules/:id
pub async fn delete_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.delete_rule(id).await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rule deleted successfully"
        }))
        .into_response(),
        Err(e) => err("Failed to delete rule", e),
    }
}

/// POST /api/firewall/rules/apply
pub async fn apply_rules(State(state): State<AppState>) -> Response {
    match state.firewall.apply_rules().await {
        Ok(_) => Json(serde_json::json!({
            "message": "Rules applied successfully"
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("Failed to apply firewall rules: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to apply rules: {}", e)
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/firewall/nat
pub async fn list_nat_rules(State(state): State<AppState>) -> Response {
    match state.firewall.list_nat_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!("Failed to list NAT rules: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to list NAT rules"
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/firewall/nat
pub async fn add_nat_rule(State(state): State<AppState>, Json(rule): Json<NatRule>) -> Response {
    match state.firewall.add_nat_rule(rule).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": id,
                "message": "NAT rule created successfully"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to add NAT rule: {}", e);
            (
                status_for_apply_error(&e),
                Json(serde_json::json!({
                    "error": format!("Failed to add NAT rule: {}", e)
                })),
            )
                .into_response()
        }
    }
}

/// DELETE /api/firewall/nat/:id
pub async fn delete_nat_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.delete_nat_rule(id).await {
        Ok(_) => Json(serde_json::json!({
            "message": "NAT rule deleted successfully"
        }))
        .into_response(),
        Err(e) => err("Failed to delete NAT rule", e),
    }
}

/// GET /api/firewall/nat/:id
pub async fn get_nat_rule(State(state): State<AppState>, Path(id): Path<u32>) -> Response {
    match state.firewall.get_nat_rule(id).await {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => err("NAT rule", anyhow::anyhow!("NAT rule {id} not found")),
        Err(e) => err("Failed to get NAT rule", e),
    }
}

/// PUT /api/firewall/nat/:id
pub async fn update_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(rule): Json<NatRule>,
) -> Response {
    match state.firewall.update_nat_rule(id, rule).await {
        Ok(_) => ok("NAT rule updated successfully"),
        Err(e) => err("Failed to update NAT rule", e),
    }
}

/// POST /api/firewall/rules/:id/move  {"direction": "up"|"down"|"top"|"bottom"}
pub async fn move_rule(
    State(state): State<AppState>,
    Path(id): Path<u32>,
    Json(b): Json<MoveBody>,
) -> Response {
    let dir = match crate::state::firewall::Move::parse(&b.direction) {
        Ok(d) => d,
        Err(e) => return err("Failed to move rule", e),
    };
    match state.firewall.move_rule(id, dir).await {
        Ok(_) => ok("Rule moved"),
        Err(e) => err("Failed to move rule", e),
    }
}

/// PUT /api/firewall/rules/order  {"ids": [..every non-system rule..]}
pub async fn reorder_rules(State(state): State<AppState>, Json(b): Json<OrderBody>) -> Response {
    match state.firewall.reorder(b.ids).await {
        Ok(_) => ok("Rules reordered"),
        Err(e) => err("Failed to reorder rules", e),
    }
}

/// GET /api/firewall/nat/outbound
pub async fn get_outbound(State(state): State<AppState>) -> Response {
    match (
        state.firewall.outbound_mode().await,
        state.firewall.auto_nat_interfaces().await,
    ) {
        (Ok(m), Ok(ifs)) => Json(serde_json::json!({
            "mode": m.as_str(),
            "automatic_interfaces": ifs,
        }))
        .into_response(),
        (Err(e), _) | (_, Err(e)) => err("Failed to read outbound NAT mode", e),
    }
}

/// PUT /api/firewall/nat/outbound  {"mode": "automatic"|"hybrid"|"manual"|"disabled"}
pub async fn set_outbound(State(state): State<AppState>, Json(b): Json<ModeBody>) -> Response {
    match state.firewall.set_outbound_mode(&b.mode).await {
        Ok(_) => ok("Outbound NAT mode updated"),
        Err(e) => err("Failed to set outbound NAT mode", e),
    }
}

/// GET /api/firewall/aliases
pub async fn list_aliases(State(state): State<AppState>) -> Response {
    match state.firewall.list_alias_objects().await {
        Ok(a) => Json(a).into_response(),
        Err(e) => err("Failed to list aliases", e),
    }
}

/// POST /api/firewall/aliases
pub async fn create_alias(State(state): State<AppState>, Json(b): Json<AliasBody>) -> Response {
    let name = b.name.clone().unwrap_or_default().trim().to_string();
    match state.firewall.create_alias(b).await {
        Ok(_) => {
            FirewallManager::spawn_refresh(state.firewall.clone(), name);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "message": "Alias created" })),
            )
                .into_response()
        }
        Err(e) => err("Failed to create alias", e),
    }
}

/// GET /api/firewall/aliases/:name
pub async fn get_alias(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.firewall.list_alias_objects().await {
        Ok(a) => match a.into_iter().find(|a| a.name == name) {
            Some(a) => Json(a).into_response(),
            None => err("Alias", anyhow::anyhow!("Alias {name} not found")),
        },
        Err(e) => err("Failed to get alias", e),
    }
}

/// PUT /api/firewall/aliases/:name -- swaps the nft set elements live.
pub async fn update_alias(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(b): Json<AliasBody>,
) -> Response {
    match state.firewall.update_alias(&name, b).await {
        Ok(live) => {
            FirewallManager::spawn_refresh(state.firewall.clone(), name.clone());
            Json(serde_json::json!({
                "message": "Alias updated",
                "live": live,
            }))
            .into_response()
        }
        Err(e) => err("Failed to update alias", e),
    }
}

/// DELETE /api/firewall/aliases/:name
pub async fn delete_alias(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.firewall.delete_alias(&name).await {
        Ok(_) => ok("Alias deleted"),
        Err(e) => err("Failed to delete alias", e),
    }
}

/// POST /api/firewall/aliases/refresh  {"names": [..]} (empty = every
/// URL table, GeoIP and threat alias)
pub async fn refresh_aliases(
    State(state): State<AppState>,
    body: Option<Json<RefreshBody>>,
) -> Response {
    let names = body.map(|Json(b)| b.names).unwrap_or_default();
    let only = if names.is_empty() {
        match state.firewall.list_alias_objects().await {
            Ok(a) => Some(
                a.into_iter()
                    .filter(|a| a.source.is_some())
                    .map(|a| a.name)
                    .collect::<Vec<_>>(),
            ),
            Err(e) => return err("Failed to refresh aliases", e),
        }
    } else {
        Some(names)
    };
    match state.firewall.refresh_feeds(only).await {
        Ok(o) => Json(serde_json::json!({
            "results": o.iter().map(|x| serde_json::json!({
                "alias": x.alias, "ok": x.ok, "status": x.status, "count": x.count,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => err("Failed to refresh aliases", e),
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct RefreshBody {
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GeoConfigBody {
    #[serde(default)]
    pub db_url: String,
    #[serde(default = "thirty")]
    pub refresh_days: u64,
}

fn thirty() -> u64 {
    30
}

/// GET /api/firewall/geoip
pub async fn get_geoip(State(state): State<AppState>) -> Response {
    match state.firewall.geoip_overview().await {
        Ok(o) => Json(o).into_response(),
        Err(e) => err("Failed to read the GeoIP settings", e),
    }
}

/// PUT /api/firewall/geoip  {"db_url": "", "refresh_days": 30}
pub async fn put_geoip(State(state): State<AppState>, Json(b): Json<GeoConfigBody>) -> Response {
    match state
        .firewall
        .set_geoip_config(&b.db_url, b.refresh_days)
        .await
    {
        Ok(_) => ok("GeoIP database settings saved"),
        Err(e) => err("Failed to save the GeoIP settings", e),
    }
}

/// POST /api/firewall/geoip/refresh -- download the database now
pub async fn refresh_geoip(State(state): State<AppState>) -> Response {
    match state.firewall.refresh_geoip().await {
        Ok(o) => Json(serde_json::json!({
            "results": o.iter().map(|x| serde_json::json!({
                "alias": x.alias, "ok": x.ok, "status": x.status, "count": x.count,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => err("Failed to refresh the GeoIP database", e),
    }
}

#[derive(Debug, Deserialize)]
pub struct IpQuery {
    pub ip: String,
}

/// GET /api/firewall/geoip/lookup?ip=1.2.3.4
pub async fn geoip_lookup(State(state): State<AppState>, Query(q): Query<IpQuery>) -> Response {
    let Ok(ip) = q.ip.trim().parse::<std::net::IpAddr>() else {
        return err(
            "Invalid request",
            anyhow::anyhow!("Invalid request: not an IP address"),
        );
    };
    match state.firewall.geoip_lookup(ip).await {
        Ok(c) => Json(serde_json::json!({ "ip": ip.to_string(), "country": c })).into_response(),
        Err(e) => err("GeoIP lookup failed", e),
    }
}

/// GET /api/firewall/threatintel
pub async fn get_threat(State(state): State<AppState>) -> Response {
    match state.firewall.threat_overview().await {
        Ok(o) => Json(o).into_response(),
        Err(e) => err("Failed to read the threat feeds", e),
    }
}

/// PUT /api/firewall/threatintel/:id -- enable/configure a feed
pub async fn put_threat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(b): Json<crate::state::fwfeeds::ThreatBody>,
) -> Response {
    match state.firewall.set_threat_feed(&id, b).await {
        Ok(_) => {
            FirewallManager::spawn_refresh(
                state.firewall.clone(),
                patronus_firewall::feeds::threat_alias_name(&id),
            );
            ok("Threat feed saved")
        }
        Err(e) => err("Failed to save the threat feed", e),
    }
}

/// DELETE /api/firewall/threatintel/:id
pub async fn delete_threat(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match state.firewall.delete_threat_feed(&id).await {
        Ok(_) => ok("Threat feed removed"),
        Err(e) => err("Failed to remove the threat feed", e),
    }
}

#[derive(Debug, Deserialize)]
pub struct BudgetBody {
    pub max_total: u64,
}

/// PUT /api/firewall/threatintel-budget  {"max_total": 400000}
pub async fn put_threat_budget(
    State(state): State<AppState>,
    Json(b): Json<BudgetBody>,
) -> Response {
    match state.firewall.set_threat_max_total(b.max_total).await {
        Ok(_) => ok("Threat-feed budget saved"),
        Err(e) => err("Failed to save the budget", e),
    }
}

/// GET /api/firewall/logs?rule=&action=&src=&dst=&proto=&port=&iface=&q=&minutes=&since_id=&limit=
pub async fn get_logs(
    State(state): State<AppState>,
    Query(q): Query<crate::state::fwlog::LogQuery>,
) -> Response {
    match crate::state::fwlog::search(&state.firewall.store, &q).await {
        Ok((entries, last_id)) => Json(serde_json::json!({
            "entries": entries,
            "last_id": last_id,
            "collector": crate::state::fwlog::collector_status(),
            "log_default_deny": state.firewall.log_default_deny().await.unwrap_or(false),
        }))
        .into_response(),
        Err(e) => err("Failed to read the firewall log", e),
    }
}

/// DELETE /api/firewall/logs
pub async fn clear_logs(State(state): State<AppState>) -> Response {
    match crate::state::fwlog::clear(&state.firewall.store).await {
        Ok(_) => ok("Firewall log cleared"),
        Err(e) => err("Failed to clear the firewall log", e),
    }
}

#[derive(Debug, Deserialize)]
pub struct DefaultDenyBody {
    pub enabled: bool,
}

/// PUT /api/firewall/logs/default-deny  {"enabled": true}
pub async fn put_default_deny(
    State(state): State<AppState>,
    Json(b): Json<DefaultDenyBody>,
) -> Response {
    match state.firewall.set_log_default_deny(b.enabled).await {
        Ok(_) => ok("Default-deny logging updated"),
        Err(e) => err("Failed to change default-deny logging", e),
    }
}

/// GET /api/firewall/schedules
pub async fn list_schedules(State(state): State<AppState>) -> Response {
    match state.firewall.list_schedules().await {
        Ok(s) => Json(s).into_response(),
        Err(e) => err("Failed to list schedules", e),
    }
}

/// POST /api/firewall/schedules
pub async fn create_schedule(
    State(state): State<AppState>,
    Json(b): Json<NamedScheduleBody>,
) -> Response {
    match state.firewall.save_schedule(&b.name, b.body, true).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "message": "Schedule created" })),
        )
            .into_response(),
        Err(e) => err("Failed to create schedule", e),
    }
}

/// PUT /api/firewall/schedules/:name
pub async fn update_schedule(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(b): Json<ScheduleBody>,
) -> Response {
    match state.firewall.save_schedule(&name, b, false).await {
        Ok(_) => ok("Schedule updated"),
        Err(e) => err("Failed to update schedule", e),
    }
}

/// DELETE /api/firewall/schedules/:name
pub async fn delete_schedule(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match state.firewall.delete_schedule(&name).await {
        Ok(_) => ok("Schedule deleted"),
        Err(e) => err("Failed to delete schedule", e),
    }
}

/// GET /api/firewall/interfaces -- choices for the rule/NAT forms.
pub async fn list_interfaces(State(state): State<AppState>) -> Response {
    match state.firewall.interface_options().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => err("Failed to list interfaces", e),
    }
}

/// This lane's API routes, mounted under `/api` by `routes::api_routes`
/// with one `.merge(firewall::router())` line.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route("/firewall/rules", get(list_rules).post(add_rule))
        .route("/firewall/rules/order", put(reorder_rules))
        .route("/firewall/rules/apply", post(apply_rules))
        .route(
            "/firewall/rules/:id",
            get(get_rule).put(update_rule).delete(delete_rule),
        )
        .route("/firewall/rules/:id/move", post(move_rule))
        .route("/firewall/nat", get(list_nat_rules).post(add_nat_rule))
        .route(
            "/firewall/nat/outbound",
            get(get_outbound).put(set_outbound),
        )
        .route(
            "/firewall/nat/:id",
            get(get_nat_rule)
                .put(update_nat_rule)
                .delete(delete_nat_rule),
        )
        .route("/firewall/aliases", get(list_aliases).post(create_alias))
        .route("/firewall/aliases/refresh", post(refresh_aliases))
        .route("/firewall/logs", get(get_logs).delete(clear_logs))
        .route("/firewall/logs/default-deny", put(put_default_deny))
        .route("/firewall/geoip", get(get_geoip).put(put_geoip))
        .route("/firewall/geoip/refresh", post(refresh_geoip))
        .route("/firewall/geoip/lookup", get(geoip_lookup))
        .route("/firewall/threatintel", get(get_threat))
        .route("/firewall/threatintel-budget", put(put_threat_budget))
        .route(
            "/firewall/threatintel/:id",
            put(put_threat).delete(delete_threat),
        )
        .route(
            "/firewall/aliases/:name",
            get(get_alias).put(update_alias).delete(delete_alias),
        )
        .route(
            "/firewall/schedules",
            get(list_schedules).post(create_schedule),
        )
        .route(
            "/firewall/schedules/:name",
            put(update_schedule).delete(delete_schedule),
        )
        .route("/firewall/interfaces", get(list_interfaces))
}
