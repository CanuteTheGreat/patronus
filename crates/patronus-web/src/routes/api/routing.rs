//! Routing API and page (lane E): `/api/routing/*` and `/routing`.
//!
//! - `GET  /api/routing`                    gateways (+ live state), groups, default, routes
//! - `POST /api/routing/gateways`           add a gateway
//! - `PUT|DELETE /api/routing/gateways/:name`
//! - `POST /api/routing/groups`             add a gateway group (USE=multiwan)
//! - `PUT|DELETE /api/routing/groups/:name`
//! - `PUT  /api/routing/default`            `{"ipv4": name|"", "ipv6": name|""}`
//! - `POST /api/routing/routes`             add a static route
//! - `PUT|DELETE /api/routing/routes/:id`
//! - `POST /api/routing/apply`              re-run the routes phase

use crate::state::AppState;
use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use patronus_network::routes;
use serde::Deserialize;
use serde_json::{json, Value};

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

/// Applied; `warnings`: what the kernel only partly took (e.g. load balancing
/// without port hashing in a container), never dropped.
fn done(warnings: Vec<String>) -> Response {
    Json(json!({ "ok": true, "warnings": warnings })).into_response()
}

fn created(warnings: Vec<String>) -> Response {
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "warnings": warnings })),
    )
        .into_response()
}

async fn overview(State(state): State<AppState>) -> Response {
    state
        .routing
        .status()
        .await
        .map(|v| Json(v).into_response())
        .unwrap_or_else(err)
}

async fn add_gateway(
    State(state): State<AppState>,
    Json(i): Json<routes::GatewayInput>,
) -> Response {
    match state.routing.save_gateway(None, i).await {
        Ok(w) => created(w),
        Err(e) => err(e),
    }
}

async fn put_gateway(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(i): Json<routes::GatewayInput>,
) -> Response {
    state
        .routing
        .save_gateway(Some(name), i)
        .await
        .map(done)
        .unwrap_or_else(err)
}

async fn del_gateway(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    state
        .routing
        .delete_gateway(name)
        .await
        .map(done)
        .unwrap_or_else(err)
}

async fn add_group(State(state): State<AppState>, Json(i): Json<routes::GroupInput>) -> Response {
    match state.routing.save_group(None, i).await {
        Ok(w) => created(w),
        Err(e) => err(e),
    }
}

async fn put_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(i): Json<routes::GroupInput>,
) -> Response {
    state
        .routing
        .save_group(Some(name), i)
        .await
        .map(done)
        .unwrap_or_else(err)
}

async fn del_group(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    state
        .routing
        .delete_group(name)
        .await
        .map(done)
        .unwrap_or_else(err)
}

/// Absent = unchanged; "" = automatic.
#[derive(Debug, Deserialize)]
pub struct DefaultInput {
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
}

async fn put_default(State(state): State<AppState>, Json(i): Json<DefaultInput>) -> Response {
    state
        .routing
        .set_defaults(i.ipv4, i.ipv6)
        .await
        .map(done)
        .unwrap_or_else(err)
}

async fn add_route(State(state): State<AppState>, Json(i): Json<routes::RouteInput>) -> Response {
    match state.routing.save_route(None, i).await {
        Ok((id, w)) => (
            StatusCode::CREATED,
            Json(json!({ "id": id, "warnings": w })),
        )
            .into_response(),
        Err(e) => err(e),
    }
}

async fn put_route(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(i): Json<routes::RouteInput>,
) -> Response {
    state
        .routing
        .save_route(Some(id), i)
        .await
        .map(|(_, w)| done(w))
        .unwrap_or_else(err)
}

async fn del_route(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    state
        .routing
        .delete_route(id)
        .await
        .map(done)
        .unwrap_or_else(err)
}

async fn reapply(State(state): State<AppState>) -> Response {
    state
        .routing
        .apply()
        .await
        .map(|r| Json(json!({ "applied": r })).into_response())
        .unwrap_or_else(err)
}

/// API routes, mounted under `/api` with one `.merge(routing::router())`.
pub fn router() -> axum::Router<AppState> {
    use axum::routing::{get, post, put};
    axum::Router::new()
        .route("/routing", get(overview))
        .route("/routing/apply", post(reapply))
        .route("/routing/default", put(put_default))
        .route("/routing/gateways", post(add_gateway))
        .route(
            "/routing/gateways/:name",
            put(put_gateway).delete(del_gateway),
        )
        .route("/routing/groups", post(add_group))
        .route("/routing/groups/:name", put(put_group).delete(del_group))
        .route("/routing/routes", post(add_route))
        .route("/routing/routes/:id", put(put_route).delete(del_route))
}

// ---------------------------------------------------------------------------
// page
// ---------------------------------------------------------------------------

pub struct GatewayView {
    pub name: String,
    pub interface: String,
    pub family: String,
    pub address: String,
    pub dynamic: bool,
    pub dev: String,
    pub resolved: String,
    pub monitor_ip: String,
    pub monitor_enabled: bool,
    pub loss_threshold: u64,
    pub latency_threshold: u64,
    pub state: String,
    pub state_class: &'static str,
    pub loss: String,
    pub rtt: String,
    pub problem: String,
    pub description: String,
}

pub struct MemberView {
    pub gateway: String,
    pub tier: u64,
    pub weight: u64,
    pub state: String,
    pub active: bool,
}

pub struct GroupView {
    pub name: String,
    pub trigger: String,
    pub members: Vec<MemberView>,
    pub members_spec: String,
    pub description: String,
}

pub struct RouteView {
    pub id: i64,
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: String,
    pub enabled: bool,
    pub description: String,
}

#[derive(Template)]
#[template(path = "routing.html")]
pub struct RoutingTemplate {
    pub page: &'static str,
    pub multiwan: bool,
    pub monitor_running: bool,
    pub gateways: Vec<GatewayView>,
    pub groups: Vec<GroupView>,
    pub routes: Vec<RouteView>,
    /// (name, family) of every gateway and group, for the default selects
    pub choices4: Vec<String>,
    pub choices6: Vec<String>,
    pub default4: String,
    pub default6: String,
    pub default_via4: String,
    pub default_via6: String,
    pub warnings: Vec<String>,
    pub kernel_routes: Vec<crate::templates::Route>,
    pub kernel_error: String,
    pub error: String,
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn state_class(state: &str) -> &'static str {
    match state {
        "online" | "unmonitored" => "ok",
        "pending" => "",
        _ => "bad",
    }
}

pub fn views(st: &Value) -> (Vec<GatewayView>, Vec<GroupView>, Vec<RouteView>) {
    let arr = |k: &str| {
        st.get(k)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let gateways = arr("gateways")
        .iter()
        .map(|g| {
            let state = s(g, "state");
            GatewayView {
                name: s(g, "name"),
                interface: s(g, "interface"),
                family: s(g, "family"),
                address: s(g, "address"),
                dynamic: g["dynamic"].as_bool().unwrap_or(false),
                dev: s(g, "dev"),
                resolved: if g["ptp"].as_bool().unwrap_or(false) {
                    "point-to-point".into()
                } else {
                    s(g, "resolved_address")
                },
                monitor_ip: s(g, "monitor_ip"),
                monitor_enabled: g["monitor_enabled"].as_bool().unwrap_or(true),
                loss_threshold: g["loss_threshold"].as_u64().unwrap_or(20),
                latency_threshold: g["latency_threshold"].as_u64().unwrap_or(500),
                state_class: state_class(&state),
                state,
                loss: g["loss_pct"]
                    .as_u64()
                    .map(|l| format!("{l} %"))
                    .unwrap_or_default(),
                rtt: g["rtt_ms"]
                    .as_f64()
                    .map(|r| format!("{r:.1} ms"))
                    .unwrap_or_default(),
                problem: [s(g, "problem"), s(g, "detail")]
                    .into_iter()
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
                    .join("; "),
                description: s(g, "description"),
            }
        })
        .collect();
    let groups = arr("groups")
        .iter()
        .map(|g| {
            let members: Vec<MemberView> = g["members"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|m| MemberView {
                    gateway: s(m, "gateway"),
                    tier: m["tier"].as_u64().unwrap_or(1),
                    weight: m["weight"].as_u64().unwrap_or(1),
                    state: s(m, "state"),
                    active: m["active"].as_bool().unwrap_or(false),
                })
                .collect();
            GroupView {
                name: s(g, "name"),
                trigger: s(g, "trigger"),
                members_spec: members
                    .iter()
                    .map(|m| format!("{}:{}:{}", m.gateway, m.tier, m.weight))
                    .collect::<Vec<_>>()
                    .join(", "),
                members,
                description: s(g, "description"),
            }
        })
        .collect();
    let routes = arr("routes")
        .iter()
        .map(|r| RouteView {
            id: r["id"].as_i64().unwrap_or(0),
            destination: s(r, "destination"),
            gateway: s(r, "gateway"),
            interface: s(r, "interface"),
            metric: s(r, "metric"),
            enabled: r["enabled"].as_bool().unwrap_or(true),
            description: s(r, "description"),
        })
        .collect();
    (gateways, groups, routes)
}

pub async fn page(State(state): State<AppState>) -> Response {
    let mut error = String::new();
    let st = state.routing.status().await.unwrap_or_else(|e| {
        error = format!("Could not read the routing state: {e}");
        Value::Null
    });
    let (gateways, groups, routes) = views(&st);
    let mut choices4 = Vec::new();
    let mut choices6 = Vec::new();
    for g in &gateways {
        if g.family == "inet6" {
            choices6.push(g.name.clone());
        } else {
            choices4.push(g.name.clone());
        }
    }
    for g in &groups {
        let fam = g
            .members
            .first()
            .and_then(|m| gateways.iter().find(|x| x.name == m.gateway))
            .map(|x| x.family.clone())
            .unwrap_or_default();
        if fam == "inet6" {
            choices6.push(g.name.clone());
        } else {
            choices4.push(g.name.clone());
        }
    }
    let via = |f: &str| {
        st["default_via"][f]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" + ")
            })
            .unwrap_or_default()
    };
    let (kernel_routes, kernel_error) = match state.network.list_routes().await {
        Ok(r) => (r, String::new()),
        Err(e) => (vec![], e.to_string()),
    };
    let t = RoutingTemplate {
        page: "routing",
        multiwan: st["multiwan"].as_bool().unwrap_or(routes::MULTIWAN),
        monitor_running: st["monitor_running"].as_bool().unwrap_or(false),
        gateways,
        groups,
        routes,
        choices4,
        choices6,
        default4: s(&st, "default4"),
        default6: s(&st, "default6"),
        default_via4: via("inet"),
        default_via6: via("inet6"),
        warnings: st["warnings"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        kernel_routes,
        kernel_error,
        error,
    };
    match t.render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render routing: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}
