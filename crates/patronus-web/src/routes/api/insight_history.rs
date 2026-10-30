//! Insight history and uplink health API (device segmentation, part d).
//!
//! Insight (area `dashboard`, like `/api/insights`):
//! - `GET  /api/insights/countries?window=24h&device=&limit=`  top countries
//! - `GET  /api/insights/asns?window=24h&device=&limit=`       top ASNs
//! - `GET  /api/insights/devices?window=24h`                    per device / address totals
//! - `GET  /api/insights/devices/{key}?window=24h`              drill-down (key = IP, device id or name)
//! - `GET|PUT /api/insights/settings`                           collection on/off, retention, top-N
//! - `GET|POST|DELETE /api/insights/exclusions`                 addresses / devices / groups never recorded
//! - `DELETE /api/insights/history`                             forget everything recorded
//! - `GET|PUT /api/insights/database`, `POST .../database/refresh`  DB-IP country + ASN files
//!
//! Uplinks (area `routing`):
//! - `GET  /api/uplinks/status`    gateways now + 24 h SLA
//! - `GET  /api/uplinks/health?gateway=&since=24h&points=240`  sample series
//! - `GET  /api/uplinks/sla?window=24h&gateway=&series=1`      availability, quality, RTT, loss
//! - `GET  /api/uplinks/outages?window=7d&gateway=`
//! - `GET|POST /api/uplinks/probes`, `PUT|DELETE /api/uplinks/probes/{id}`
//! - `GET|PUT /api/uplinks/settings`

use crate::state::{insight, uplink, AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json,
};
use patronus_firewall::{asn, feeds};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

type Q = Query<HashMap<String, String>>;

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

fn bad(msg: &str) -> Response {
    err(anyhow::anyhow!("Invalid request: {msg}"))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn window(q: &Q, key: &str, default: &str) -> Result<i64, Response> {
    let w = q.get(key).map(String::as_str).unwrap_or(default);
    insight::parse_window(w).ok_or_else(|| {
        bad(&format!(
            "{key}: use a number of hours or days such as 6h, 24h, 7d (got {w:?})"
        ))
    })
}

fn limit(q: &Q) -> Result<i64, Response> {
    match q.get("limit") {
        None => Ok(20),
        Some(l) => l
            .parse::<i64>()
            .ok()
            .filter(|n| (1..=1000).contains(n))
            .ok_or_else(|| bad("limit: 1 to 1000")),
    }
}

/// What the lookup databases look like right now, for honest empty states.
async fn databases(state: &AppState) -> Value {
    let geo = feeds::geoip_status(&state.config_store).await.ok();
    let asn = asn::asn_status(&state.config_store).await.ok();
    json!({
        "country": geo.map(|g| json!({"present": g.present, "status": g.status, "updated": g.updated})),
        "asn": asn.map(|a| json!({"present": a.present, "status": a.status, "updated": a.updated})),
        "attribution": "IP geolocation by DB-IP.com (CC BY 4.0)",
    })
}

async fn selector(
    state: &AppState,
    q: &Q,
) -> Result<Option<(Vec<String>, Option<insight::DeviceRef>)>, Response> {
    match q.get("device").map(|d| d.trim()).filter(|d| !d.is_empty()) {
        None => Ok(None),
        Some(d) => insight::resolve_device(&state.config_store, d)
            .await
            .map(Some)
            .map_err(err),
    }
}

async fn ranked(state: AppState, q: Q, by: insight::By) -> Response {
    let (w, l) = match (window(&q, "window", "24h"), limit(&q)) {
        (Ok(w), Ok(l)) => (w, l),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let sel = match selector(&state, &q).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ips = sel.as_ref().map(|(i, _)| i.as_slice());
    match insight::top(&state.config_store, by, now(), w, ips, l).await {
        Ok(rows) => Json(json!({
            "window_secs": w,
            "device": sel.as_ref().and_then(|(_, d)| d.as_ref()),
            "rows": rows,
            "databases": databases(&state).await,
            "recorded_rows": insight::row_count(&state.config_store).await,
            "settings": insight::load_settings(&state.config_store).await,
        }))
        .into_response(),
        Err(e) => err(e),
    }
}

async fn countries(State(s): State<AppState>, q: Q) -> Response {
    ranked(s, q, insight::By::Country).await
}

async fn asns(State(s): State<AppState>, q: Q) -> Response {
    ranked(s, q, insight::By::Asn).await
}

async fn device_list(State(s): State<AppState>, q: Q) -> Response {
    let (w, l) = match (window(&q, "window", "24h"), limit(&q)) {
        (Ok(w), Ok(l)) => (w, l),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    match insight::device_totals(&s.config_store, now(), w, l).await {
        Ok(rows) => Json(json!({
            "window_secs": w,
            "rows": rows,
            "segmentation": !insight::devices(&s.config_store).await.is_empty(),
        }))
        .into_response(),
        Err(e) => err(e),
    }
}

async fn device_detail(State(s): State<AppState>, Path(key): Path<String>, q: Q) -> Response {
    let w = match window(&q, "window", "24h") {
        Ok(w) => w,
        Err(e) => return e,
    };
    let (ips, dev) = match insight::resolve_device(&s.config_store, &key).await {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let n = now();
    let st = &s.config_store;
    let (c, a, t) = tokio::join!(
        insight::top(st, insight::By::Country, n, w, Some(&ips), 10),
        insight::top(st, insight::By::Asn, n, w, Some(&ips), 10),
        insight::timeline(st, n, w, Some(&ips)),
    );
    match (c, a, t) {
        (Ok(c), Ok(a), Ok(t)) => Json(json!({
            "key": key, "device": dev, "ips": ips, "window_secs": w,
            "countries": c, "asns": a, "timeline": t,
        }))
        .into_response(),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => err(e),
    }
}

async fn timeline(State(s): State<AppState>, q: Q) -> Response {
    let w = match window(&q, "window", "24h") {
        Ok(w) => w,
        Err(e) => return e,
    };
    let sel = match selector(&s, &q).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    match insight::timeline(
        &s.config_store,
        now(),
        w,
        sel.as_ref().map(|(i, _)| i.as_slice()),
    )
    .await
    {
        Ok(t) => Json(json!({"window_secs": w, "points": t})).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct InsightSettings {
    enabled: Option<bool>,
    retention_days: Option<i64>,
    top_n: Option<i64>,
}

async fn get_settings(State(s): State<AppState>) -> Response {
    Json(insight::load_settings(&s.config_store).await).into_response()
}

async fn put_settings(State(s): State<AppState>, Json(i): Json<InsightSettings>) -> Response {
    if let Err(e) =
        insight::save_settings(&s.config_store, i.enabled, i.retention_days, i.top_n).await
    {
        return err(e);
    }
    let _ = s
        .config_store
        .audit(
            "web",
            "update",
            "insight_settings",
            None,
            &json!({"enabled": i.enabled, "retention_days": i.retention_days, "top_n": i.top_n}),
        )
        .await;
    Json(insight::load_settings(&s.config_store).await).into_response()
}

async fn list_exclusions(State(s): State<AppState>) -> Response {
    match insight::list_exclusions(&s.config_store).await {
        Ok(v) => Json(json!({"rows": v.into_iter().map(|(k, r)| json!({"kind": k, "ref": r})).collect::<Vec<_>>()})).into_response(),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct Exclusion {
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
}

async fn add_exclusion(State(s): State<AppState>, Json(x): Json<Exclusion>) -> Response {
    match insight::add_exclusion(&s.config_store, &x.kind, &x.reference).await {
        Ok(removed) => {
            let _ = s
                .config_store
                .audit(
                    "web",
                    "create",
                    "insight_exclusion",
                    Some(&x.reference),
                    &json!({"kind": x.kind, "forgotten_rows": removed}),
                )
                .await;
            (
                StatusCode::CREATED,
                Json(json!({"ok": true, "forgotten_rows": removed})),
            )
                .into_response()
        }
        Err(e) => err(e),
    }
}

async fn del_exclusion(State(s): State<AppState>, q: Q) -> Response {
    let (Some(k), Some(r)) = (q.get("kind"), q.get("ref")) else {
        return bad("give ?kind= and ?ref=");
    };
    match insight::remove_exclusion(&s.config_store, k, r).await {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => err(anyhow::anyhow!("not found: no such exclusion")),
        Err(e) => err(e),
    }
}

async fn clear_history(State(s): State<AppState>) -> Response {
    let r = match s.config_store.pool() {
        Ok(p) => sqlx::query("DELETE FROM ins_usage")
            .execute(p)
            .await
            .map_err(anyhow::Error::from),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    };
    match r {
        Ok(r) => {
            let _ = s
                .config_store
                .audit(
                    "web",
                    "delete",
                    "insight_history",
                    None,
                    &json!({"rows": r.rows_affected()}),
                )
                .await;
            Json(json!({"ok": true, "deleted_rows": r.rows_affected()})).into_response()
        }
        Err(e) => err(e),
    }
}

async fn database_status(State(s): State<AppState>) -> Response {
    let geo = feeds::geoip_status(&s.config_store).await;
    let asn = asn::asn_status(&s.config_store).await;
    match (geo, asn) {
        (Ok(g), Ok(a)) => Json(json!({
            "country": g, "asn": a,
            "default_asn_url": asn::default_asn_urls(now()).remove(0),
            "attribution": "IP geolocation by DB-IP.com (CC BY 4.0)",
        }))
        .into_response(),
        (Err(e), _) | (_, Err(e)) => err(anyhow::anyhow!("{e}")),
    }
}

#[derive(Deserialize)]
struct DbConfig {
    asn_url: Option<String>,
    refresh_days: Option<u64>,
}

async fn put_database(State(s): State<AppState>, Json(c): Json<DbConfig>) -> Response {
    let cur = match asn::asn_status(&s.config_store).await {
        Ok(c) => c,
        Err(e) => return err(anyhow::anyhow!("{e}")),
    };
    let url = c.asn_url.unwrap_or(cur.db_url);
    let days = c.refresh_days.unwrap_or(cur.refresh_days);
    match asn::set_asn_config(&s.config_store, &url, days).await {
        Ok(()) => database_status(State(s)).await,
        Err(e) => err(anyhow::anyhow!("{e}")),
    }
}

async fn refresh_database(State(s): State<AppState>) -> Response {
    let out = asn::refresh_ip_databases(&s.config_store, &feeds::CurlFetcher, true, now()).await;
    let ok = out.iter().all(|(_, r)| r.is_ok());
    let rows: Vec<Value> = out
        .into_iter()
        .map(|(n, r)| match r {
            Ok(w) => json!({"database": n, "ok": true, "updated": w}),
            Err(e) => json!({"database": n, "ok": false, "error": e}),
        })
        .collect();
    let _ = s
        .config_store
        .audit("web", "refresh", "ip_databases", None, &json!({"ok": ok}))
        .await;
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::BAD_GATEWAY
        },
        Json(json!({"ok": ok, "results": rows})),
    )
        .into_response()
}

// ------------------------------------------------------------------ uplinks

/// `since=24h` (a window) or `since=<unix time>`.
fn since(q: &Q, default: &str, n: i64) -> Result<i64, Response> {
    let v = q.get("since").map(String::as_str).unwrap_or(default);
    if let Some(w) = insight::parse_window(v) {
        return Ok(n - w);
    }
    v.parse::<i64>()
        .ok()
        .filter(|t| *t > 0 && *t <= n)
        .ok_or_else(|| bad("since: a window such as 24h or a unix time in the past"))
}

fn gw(q: &Q) -> Option<&str> {
    q.get("gateway")
        .map(String::as_str)
        .filter(|g| !g.is_empty())
}

async fn uplink_status(State(s): State<AppState>) -> Response {
    let st = match s.routing.status().await {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let n = now();
    let sla = uplink::sla(&s.config_store, None, n, 86_400)
        .await
        .unwrap_or_default();
    let gws: Vec<Value> = st["gateways"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|g| {
            let name = g["name"].as_str().unwrap_or("");
            let active_in: Vec<&str> = st["groups"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|grp| grp["members"].as_array().into_iter().flatten().any(|m| m["gateway"] == name && m["active"] == true))
                .filter_map(|grp| grp["name"].as_str())
                .collect();
            json!({
                "name": name, "interface": g["interface"], "dev": g["dev"], "state": g["state"],
                "rtt_ms": g["rtt_ms"], "loss_pct": g["loss_pct"], "since": g["since"], "detail": g["detail"],
                "probes": g["probes"], "monitor_enabled": g["monitor_enabled"],
                "active_in_groups": active_in,
                "sla_24h": sla.iter().find(|r| r.gateway == name),
            })
        })
        .collect();
    Json(json!({
        "monitor_running": st["monitor_running"],
        "gateways": gws,
        "history_enabled": true,
        "settings": uplink::load_settings(&s.config_store).await,
    }))
    .into_response()
}

async fn uplink_health(State(s): State<AppState>, q: Q) -> Response {
    let n = now();
    let from = match since(&q, "24h", n) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let points = match q.get("points") {
        None => 240,
        Some(p) => match p.parse::<i64>().ok().filter(|p| (10..=2000).contains(p)) {
            Some(p) => p,
            None => return bad("points: 10 to 2000"),
        },
    };
    match uplink::health(&s.config_store, gw(&q), from, n, points).await {
        Ok(rows) => Json(json!({"since": from, "until": n, "samples": rows})).into_response(),
        Err(e) => err(e),
    }
}

async fn uplink_sla(State(s): State<AppState>, q: Q) -> Response {
    let w = match window(&q, "window", "24h") {
        Ok(w) => w,
        Err(e) => return e,
    };
    let n = now();
    let rows = match uplink::sla(&s.config_store, gw(&q), n, w).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let mut series = serde_json::Map::new();
    if q.get("series").is_some_and(|v| v == "1" || v == "true") {
        for r in &rows {
            if let Ok(x) = uplink::sla_series(&s.config_store, &r.gateway, n, w).await {
                series.insert(r.gateway.clone(), Value::Array(x));
            }
        }
    }
    Json(json!({
        "window_secs": w, "sla": rows, "series": series,
        "target": uplink::load_settings(&s.config_store).await.sla_target,
    }))
    .into_response()
}

async fn uplink_outages(State(s): State<AppState>, q: Q) -> Response {
    let w = match window(&q, "window", "7d") {
        Ok(w) => w,
        Err(e) => return e,
    };
    let n = now();
    match uplink::outages(&s.config_store, gw(&q), n - w, n).await {
        Ok(o) => Json(json!({"window_secs": w, "outages": o})).into_response(),
        Err(e) => err(e),
    }
}

async fn probe_list(State(s): State<AppState>) -> Response {
    Json(json!({"rows": uplink::list_probes(&s.config_store).await})).into_response()
}

#[derive(Deserialize)]
struct ProbeInput {
    gateway: String,
    kind: String,
    target: String,
    port: Option<u16>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    critical: bool,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

async fn probe_save(s: AppState, id: Option<i64>, p: ProbeInput) -> Response {
    let created = id.is_none();
    match uplink::save_probe(
        &s.config_store,
        id,
        &p.gateway,
        &p.kind,
        &p.target,
        p.port,
        &p.name,
        p.critical,
        p.enabled,
    )
    .await
    {
        Ok(id) => {
            // pin the probe's target to its gateway (host route) right away
            let _ = s.routing.apply().await;
            let _ = s.config_store.audit("web", if created { "create" } else { "update" }, "uplink_probe", Some(&id.to_string()), &json!({"gateway": p.gateway, "kind": p.kind, "target": p.target, "critical": p.critical})).await;
            (if created { StatusCode::CREATED } else { StatusCode::OK }, Json(json!({"ok": true, "id": id, "note": "picked up by the gateway monitor within a few seconds"}))).into_response()
        }
        Err(e) => err(e),
    }
}

async fn probe_add(State(s): State<AppState>, Json(p): Json<ProbeInput>) -> Response {
    probe_save(s, None, p).await
}

async fn probe_put(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(p): Json<ProbeInput>,
) -> Response {
    probe_save(s, Some(id), p).await
}

async fn probe_del(State(s): State<AppState>, Path(id): Path<i64>) -> Response {
    match uplink::delete_probe(&s.config_store, id).await {
        Ok(()) => {
            let _ = s.routing.apply().await;
            let _ = s
                .config_store
                .audit(
                    "web",
                    "delete",
                    "uplink_probe",
                    Some(&id.to_string()),
                    &json!({}),
                )
                .await;
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
struct UplinkSettings {
    sample_retention_days: Option<i64>,
    sla_retention_days: Option<i64>,
    sla_target: Option<f64>,
}

async fn uplink_settings(State(s): State<AppState>) -> Response {
    Json(uplink::load_settings(&s.config_store).await).into_response()
}

async fn uplink_put_settings(State(s): State<AppState>, Json(i): Json<UplinkSettings>) -> Response {
    match uplink::save_settings(
        &s.config_store,
        i.sample_retention_days,
        i.sla_retention_days,
        i.sla_target,
    )
    .await
    {
        Ok(()) => Json(uplink::load_settings(&s.config_store).await).into_response(),
        Err(e) => err(e),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/insights/countries", get(countries))
        .route("/insights/asns", get(asns))
        .route("/insights/devices", get(device_list))
        .route("/insights/devices/:key", get(device_detail))
        .route("/insights/timeline", get(timeline))
        .route("/insights/settings", get(get_settings).put(put_settings))
        .route(
            "/insights/exclusions",
            get(list_exclusions)
                .post(add_exclusion)
                .delete(del_exclusion),
        )
        .route("/insights/history", axum::routing::delete(clear_history))
        .route("/insights/database", get(database_status).put(put_database))
        .route("/insights/database/refresh", post(refresh_database))
        .route("/uplinks/status", get(uplink_status))
        .route("/uplinks/health", get(uplink_health))
        .route("/uplinks/sla", get(uplink_sla))
        .route("/uplinks/outages", get(uplink_outages))
        .route("/uplinks/probes", get(probe_list).post(probe_add))
        .route("/uplinks/probes/:id", put(probe_put).delete(probe_del))
        .route(
            "/uplinks/settings",
            get(uplink_settings).put(uplink_put_settings),
        )
}
