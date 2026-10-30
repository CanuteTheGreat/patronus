//! Status summary, Prometheus metrics, the event log and outbound
//! webhooks (lane H), for monitoring systems such as Rustinion:
//!
//! - [`summary`]: one JSON document with the facts a collector needs
//!   (gateways, tunnels, conntrack, DHCP leases, services, HA, firewall
//!   rule fingerprint, last configuration change).
//! - [`prometheus`]: the same as OpenMetrics text (`GET /metrics`).
//! - [`Watcher`]: every few seconds compares the live state with the last
//!   look and records an event (`system_events`) for each change:
//!   gateway up/down/degraded, gateway-group failover, tunnel up/down, HA
//!   state change, configuration change. Each event is POSTed to the
//!   enabled webhooks (`event_hooks`), signed with HMAC-SHA256 in
//!   `X-Patronus-Signature: sha256=<hex>`.

use super::{host, AppState};
use patronus_config::ConfigStore;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Events kept in the store.
const KEEP_EVENTS: i64 = 2000;

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub detail: String,
}

fn ev(kind: &str, subject: &str, severity: &str, detail: String) -> Event {
    Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: kind.into(),
        subject: subject.into(),
        severity: severity.into(),
        detail,
    }
}

/// What changed between two looks. Keys are `gateway:<name>`,
/// `group:<name>` (active members), `tunnel:<name>`, `ha:state`; values
/// are the state strings. A key that is new is only reported when its
/// state is a problem (a tunnel that never came up is not news; a gateway
/// that appears down is).
pub fn diff(prev: &BTreeMap<String, String>, cur: &BTreeMap<String, String>) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, new) in cur {
        let old = prev.get(k);
        if old == Some(new) {
            continue;
        }
        let Some((class, name)) = k.split_once(':') else {
            continue;
        };
        match class {
            "gateway" => {
                let was = old.map(String::as_str).unwrap_or("");
                let (kind, sev) = match new.as_str() {
                    "down" => ("gateway_down", "critical"),
                    "loss" | "latency" => ("gateway_degraded", "warning"),
                    "online" | "unmonitored" if matches!(was, "down" | "loss" | "latency") => {
                        ("gateway_up", "info")
                    }
                    _ => continue,
                };
                out.push(ev(
                    kind,
                    name,
                    sev,
                    format!(
                        "gateway {name}: {} -> {new}",
                        if was.is_empty() { "unknown" } else { was }
                    ),
                ));
            }
            "group" => {
                if let Some(old) = old {
                    out.push(ev(
                        "group_failover",
                        name,
                        "warning",
                        format!(
                            "gateway group {name}: active {} -> {}",
                            if old.is_empty() { "(none)" } else { old },
                            if new.is_empty() { "(none)" } else { new }
                        ),
                    ));
                }
            }
            "tunnel" => {
                let up = new == "up";
                let was_up = old.is_some_and(|o| o == "up");
                if up || was_up {
                    out.push(ev(
                        if up { "tunnel_up" } else { "tunnel_down" },
                        name,
                        if up { "info" } else { "warning" },
                        format!("tunnel {name} is {new}"),
                    ));
                }
            }
            "ha" => {
                // a state appearing for the first time (HA just came up) is news too
                out.push(ev(
                    "ha_state",
                    name,
                    if new == "MASTER" { "warning" } else { "info" },
                    format!(
                        "HA state {} -> {new}",
                        old.map_or("unknown", String::as_str)
                    ),
                ));
            }
            _ => {}
        }
    }
    // a tunnel / gateway that vanished from the list while up is not
    // reported: the configuration changed (reported as config_changed)
    out
}

pub async fn record(store: &ConfigStore, e: &Event) -> anyhow::Result<i64> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let r = sqlx::query(
        "INSERT INTO system_events (ts, kind, subject, severity, detail) VALUES (?,?,?,?,?)",
    )
    .bind(e.ts)
    .bind(&e.kind)
    .bind(&e.subject)
    .bind(&e.severity)
    .bind(&e.detail)
    .execute(pool)
    .await?;
    let id = r.last_insert_rowid();
    sqlx::query("DELETE FROM system_events WHERE id <= ?")
        .bind(id - KEEP_EVENTS)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Events newer than `after_id`, oldest first (so a collector can resume
/// with the last id it saw), optionally one `kind`.
pub async fn events(
    store: &ConfigStore,
    after_id: i64,
    kind: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<Event>> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let rows = sqlx::query(
        "SELECT id, ts, kind, subject, severity, detail FROM system_events
         WHERE id > ? AND (? IS NULL OR kind = ?) ORDER BY id ASC LIMIT ?",
    )
    .bind(after_id)
    .bind(kind)
    .bind(kind)
    .bind(limit.clamp(1, 1000))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Event {
            id: r.get(0),
            ts: r.get(1),
            kind: r.get(2),
            subject: r.get(3),
            severity: r.get(4),
            detail: r.get(5),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// webhooks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Hook {
    pub id: i64,
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub secret: String,
    pub has_secret: bool,
    pub kinds: String,
    pub enabled: bool,
    pub last_attempt_at: Option<i64>,
    pub last_result: Option<String>,
}

pub async fn hooks(store: &ConfigStore) -> anyhow::Result<Vec<Hook>> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let rows = sqlx::query(
        "SELECT id, name, url, secret, kinds, enabled, last_attempt_at, last_result
         FROM event_hooks ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let secret: String = r.get(3);
            Hook {
                id: r.get(0),
                name: r.get(1),
                url: r.get(2),
                has_secret: !secret.is_empty(),
                secret,
                kinds: r.get(4),
                enabled: r.get::<i64, _>(5) != 0,
                last_attempt_at: r.get(6),
                last_result: r.get(7),
            }
        })
        .collect())
}

pub const EVENT_KINDS: &[&str] = &[
    "gateway_down",
    "gateway_up",
    "gateway_degraded",
    "uplink_probe_failed",
    "uplink_probe_recovered",
    "uplink_sla_breach",
    "uplink_sla_ok",
    "group_failover",
    "tunnel_up",
    "tunnel_down",
    "ha_state",
    "config_changed",
];

pub async fn save_hook(
    store: &ConfigStore,
    name: &str,
    url: &str,
    secret: &str,
    kinds: &str,
) -> anyhow::Result<i64> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        anyhow::bail!(
            "Invalid webhook name {name:?}: 1-40 letters, digits, '-', '_', '.' or spaces"
        );
    }
    let url = url.trim();
    let ok_scheme = url.starts_with("http://") || url.starts_with("https://");
    if !ok_scheme
        || url.len() > 500
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"')
    {
        anyhow::bail!("Invalid webhook URL: an http:// or https:// address");
    }
    if secret.len() > 200 || secret.chars().any(|c| c.is_control()) {
        anyhow::bail!("Invalid secret: up to 200 printable characters");
    }
    let mut ks = Vec::new();
    for k in kinds
        .split([',', ' '])
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        if !EVENT_KINDS.contains(&k) {
            anyhow::bail!(
                "Invalid event kind {k:?}: one of {}",
                EVENT_KINDS.join(", ")
            );
        }
        ks.push(k);
    }
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let r = sqlx::query(
        "INSERT INTO event_hooks (name, url, secret, kinds, enabled, created_at) VALUES (?,?,?,?,1,?)",
    )
    .bind(name)
    .bind(url)
    .bind(secret)
    .bind(ks.join(","))
    .bind(chrono::Utc::now().timestamp())
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow::anyhow!("Invalid webhook name: {name} already exists")
        } else {
            anyhow::anyhow!("saving the webhook: {e}")
        }
    })?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_hook(store: &ConfigStore, id: i64) -> anyhow::Result<bool> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    Ok(sqlx::query("DELETE FROM event_hooks WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        > 0)
}

/// HMAC-SHA256 (RFC 2104), hex.
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn curl_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// POST `body` to `url` with curl (headers, and so the signature, on
/// stdin rather than in `ps`). Ok on a 2xx answer.
pub async fn post_json(url: &str, headers: &[String], body: &str) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut cfg = format!(
        "url = {}\nrequest = \"POST\"\nsilent\nshow-error\nfail\nmax-time = 15\n\
         user-agent = \"Patronus-Events/1.0\"\nheader = \"Content-Type: application/json\"\n",
        curl_quote(url)
    );
    for h in headers {
        cfg.push_str(&format!("header = {}\n", curl_quote(h)));
    }
    cfg.push_str(&format!("data = {}\n", curl_quote(body)));
    let mut child = tokio::process::Command::new("curl")
        .args(["-K", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run curl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim())
    }
}

/// The body and headers of one delivery.
pub fn delivery(host: &str, hook: &Hook, e: &Event) -> (String, Vec<String>) {
    let body = json!({
        "id": e.id, "time": e.ts, "kind": e.kind, "subject": e.subject,
        "severity": e.severity, "detail": e.detail, "host": host,
    })
    .to_string();
    let mut headers = vec![format!("X-Patronus-Event: {}", e.kind)];
    if hook.has_secret {
        headers.push(format!(
            "X-Patronus-Signature: sha256={}",
            hmac_sha256_hex(hook.secret.as_bytes(), body.as_bytes())
        ));
    }
    (body, headers)
}

fn wants(hook: &Hook, kind: &str) -> bool {
    hook.enabled && (hook.kinds.is_empty() || hook.kinds.split(',').any(|k| k == kind))
}

/// Send `e` to every hook that wants it (up to 3 tries each, 2 s / 6 s
/// apart), and note the outcome on the hook.
pub async fn deliver(store: Arc<ConfigStore>, e: Event) {
    let Ok(all) = hooks(&store).await else { return };
    let me = host::hostname();
    for h in all.into_iter().filter(|h| wants(h, &e.kind)) {
        let (store, e, me) = (store.clone(), e.clone(), me.clone());
        tokio::spawn(async move {
            let (body, headers) = delivery(&me, &h, &e);
            let mut result = String::new();
            for (i, wait) in [0u64, 2, 6].iter().enumerate() {
                if *wait > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(*wait)).await;
                }
                match post_json(&h.url, &headers, &body).await {
                    Ok(()) => {
                        result = "ok".into();
                        break;
                    }
                    Err(err) => {
                        result = format!("attempt {}: {err}", i + 1);
                    }
                }
            }
            if let Ok(pool) = store.pool() {
                let _ = sqlx::query(
                    "UPDATE event_hooks SET last_attempt_at=?, last_result=? WHERE id=?",
                )
                .bind(chrono::Utc::now().timestamp())
                .bind(result)
                .bind(h.id)
                .execute(pool)
                .await;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// live state
// ---------------------------------------------------------------------------

fn conntrack() -> (Option<u64>, Option<u64>) {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    (
        read("/proc/sys/net/netfilter/nf_conntrack_count"),
        read("/proc/sys/net/netfilter/nf_conntrack_max"),
    )
}

/// A fingerprint of the firewall + NAT rule set (changes when a rule is
/// added, edited, reordered or removed), for drift detection.
pub async fn rules_hash(store: &ConfigStore) -> String {
    let Ok(doc) = store.export_json().await else {
        return String::new();
    };
    let mut h = Sha256::new();
    if let Some(t) = doc.get("tables").and_then(Value::as_object) {
        for name in ["firewall_rules", "nat_rules"] {
            if let Some(rows) = t.get(name) {
                // volatile columns do not count
                let s = rows.to_string();
                h.update(name.as_bytes());
                h.update(s.as_bytes());
            }
        }
    }
    h.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn wg_names(store: &ConfigStore) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(pool) = store.pool() {
        if let Ok(rows) = sqlx::query("SELECT public_key, name FROM wg_peers")
            .fetch_all(pool)
            .await
        {
            for r in rows {
                m.insert(r.get::<String, _>(0), r.get::<String, _>(1));
            }
        }
    }
    m
}

/// Everything a collector wants, read live.
pub async fn summary(state: &AppState) -> Value {
    let store = &state.config_store;
    let routing = state.routing.status().await.unwrap_or(Value::Null);
    let vpn = state.vpn.snapshot().await;
    let names = wg_names(store).await;
    let (ct, ct_max) = conntrack();
    let dhcp = state.lan.status("dhcp").await.unwrap_or(Value::Null);
    let leases = dhcp
        .get("leases")
        .and_then(Value::as_array)
        .map(|a| a.len());
    let services: Vec<Value> = state
        .system
        .list_services()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| json!({"name": s.name, "running": s.is_running}))
        .collect();
    let revisions = store.list_revisions().await.unwrap_or_default();
    let last_rev = revisions.first().map(
        |(id, at, user, summary)| json!({"id": id, "at": at, "user": user, "summary": summary}),
    );
    let load = host::load_average();
    let mem = host::memory();
    let gateways: Vec<Value> = routing
        .get("gateways")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            json!({
                "name": g["name"], "interface": g["interface"], "dev": g["dev"],
                "address": g["resolved_address"], "state": g["state"],
                "rtt_ms": g["rtt_ms"], "loss_pct": g["loss_pct"], "since": g["since"],
                "link_up": g["link_up"],
            })
        })
        .collect();
    let groups: Vec<Value> = routing
        .get("groups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            let active: Vec<Value> = g["members"]
                .as_array()
                .map(|m| {
                    m.iter()
                        .filter(|x| x["active"] == true)
                        .map(|x| x["gateway"].clone())
                        .collect()
                })
                .unwrap_or_default();
            json!({"name": g["name"], "active": active})
        })
        .collect();
    let wireguard: Vec<Value> = vpn
        .wg_peers
        .iter()
        .map(|p| {
            json!({
                "interface": p.interface,
                "peer": names.get(&p.public_key).cloned().unwrap_or_else(|| p.public_key.chars().take(8).collect()),
                "public_key": p.public_key,
                "connected": p.connected,
                "handshake_age_secs": p.handshake_age_secs,
                "endpoint": p.endpoint,
            })
        })
        .collect();
    let ipsec: Vec<Value> = vpn
        .ipsec_tunnels
        .iter()
        .map(|t| json!({"name": t.name, "status": t.status, "established": t.status.eq_ignore_ascii_case("ESTABLISHED")}))
        .collect();
    json!({
        "product": "patronus",
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": host::hostname(),
        "time": chrono::Utc::now().timestamp(),
        "uptime_secs": host::uptime_secs(),
        "load": load.map(|l| json!([l.0, l.1, l.2])),
        "memory_used_percent": mem.map(|m| m.0),
        "disk_used_percent": host::disk_percent("/"),
        "firewall": {
            "active_rules": state.firewall.count_active_rules().await.unwrap_or(0),
            "rules_hash": rules_hash(store).await,
        },
        "config": { "last_change": last_rev, "revisions": revisions.len() },
        "gateways": gateways,
        "gateway_groups": groups,
        "default_via": routing.get("default_via").cloned().unwrap_or(Value::Null),
        "vpn": {
            "active_connections": vpn.active_connections(),
            "wireguard": wireguard,
            "ipsec": ipsec,
            "errors": vpn.read_errors(),
        },
        "conntrack": { "count": ct, "max": ct_max },
        "dhcp": { "leases": leases },
        "services": services,
        "ha": ha_summary(state).await,
    })
}

/// HA state for the summary: null while HA is off or not built.
async fn ha_summary(state: &AppState) -> Value {
    match state.lan.status("ha").await {
        Ok(v) if v["enabled"] == true => json!({
            "enabled": true, "state": v["state"], "since": v["since"],
            "maintenance": v["maintenance"], "keepalived": v["keepalived"],
            "conntrackd": v["conntrackd"], "vips": v["vips"],
        }),
        _ => Value::Null,
    }
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_u64().map(|u| u as f64))
}

/// OpenMetrics / Prometheus text for a [`summary`].
pub fn prometheus(s: &Value) -> String {
    let mut o = String::new();
    let mut m = |name: &str, help: &str, kind: &str, rows: Vec<(String, f64)>| {
        if rows.is_empty() {
            return;
        }
        o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, v) in rows {
            if labels.is_empty() {
                o.push_str(&format!("{name} {v}\n"));
            } else {
                o.push_str(&format!("{name}{{{labels}}} {v}\n"));
            }
        }
    };
    m(
        "patronus_info",
        "Patronus build and host",
        "gauge",
        vec![(
            format!(
                "version=\"{}\",hostname=\"{}\"",
                esc(s["version"].as_str().unwrap_or("")),
                esc(s["hostname"].as_str().unwrap_or(""))
            ),
            1.0,
        )],
    );
    m(
        "patronus_uptime_seconds",
        "Host uptime",
        "gauge",
        num(&s["uptime_secs"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_memory_used_percent",
        "Memory in use",
        "gauge",
        num(&s["memory_used_percent"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_disk_used_percent",
        "Root filesystem in use",
        "gauge",
        num(&s["disk_used_percent"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_firewall_active_rules",
        "Enabled firewall rules",
        "gauge",
        num(&s["firewall"]["active_rules"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    let gws = s["gateways"].as_array().cloned().unwrap_or_default();
    let label = |g: &Value| format!("gateway=\"{}\"", esc(g["name"].as_str().unwrap_or("")));
    m(
        "patronus_gateway_up",
        "1 when the gateway is online (or unmonitored), 0 when down, loss or latency",
        "gauge",
        gws.iter()
            .map(|g| {
                let up = matches!(
                    g["state"].as_str(),
                    Some("online" | "unmonitored" | "pending")
                );
                (label(g), if up { 1.0 } else { 0.0 })
            })
            .collect(),
    );
    m(
        "patronus_gateway_rtt_ms",
        "Gateway round-trip time",
        "gauge",
        gws.iter()
            .filter_map(|g| num(&g["rtt_ms"]).map(|v| (label(g), v)))
            .collect(),
    );
    m(
        "patronus_gateway_loss_percent",
        "Gateway packet loss",
        "gauge",
        gws.iter()
            .filter_map(|g| num(&g["loss_pct"]).map(|v| (label(g), v)))
            .collect(),
    );
    let wg = s["vpn"]["wireguard"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let wl = |p: &Value| {
        format!(
            "interface=\"{}\",peer=\"{}\"",
            esc(p["interface"].as_str().unwrap_or("")),
            esc(p["peer"].as_str().unwrap_or(""))
        )
    };
    m(
        "patronus_wireguard_peer_connected",
        "1 when the peer shook hands in the last 180 s",
        "gauge",
        wg.iter()
            .map(|p| (wl(p), if p["connected"] == true { 1.0 } else { 0.0 }))
            .collect(),
    );
    m(
        "patronus_wireguard_handshake_age_seconds",
        "Seconds since the peer's last handshake",
        "gauge",
        wg.iter()
            .filter_map(|p| num(&p["handshake_age_secs"]).map(|v| (wl(p), v)))
            .collect(),
    );
    m(
        "patronus_ipsec_sa_established",
        "1 when the IPsec tunnel's IKE SA is established",
        "gauge",
        s["vpn"]["ipsec"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|t| {
                (
                    format!("tunnel=\"{}\"", esc(t["name"].as_str().unwrap_or(""))),
                    if t["established"] == true { 1.0 } else { 0.0 },
                )
            })
            .collect(),
    );
    m(
        "patronus_conntrack_entries",
        "Tracked connections",
        "gauge",
        num(&s["conntrack"]["count"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_conntrack_max",
        "Connection tracking table size",
        "gauge",
        num(&s["conntrack"]["max"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_dhcp_leases",
        "Active DHCP leases",
        "gauge",
        num(&s["dhcp"]["leases"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_service_up",
        "1 when the service is running",
        "gauge",
        s["services"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|x| {
                (
                    format!("service=\"{}\"", esc(x["name"].as_str().unwrap_or(""))),
                    if x["running"] == true { 1.0 } else { 0.0 },
                )
            })
            .collect(),
    );
    m(
        "patronus_config_revision",
        "Id of the latest configuration revision",
        "gauge",
        num(&s["config"]["last_change"]["id"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_ha_master",
        "1 when this node holds the HA virtual addresses",
        "gauge",
        s["ha"]["state"]
            .as_str()
            .map(|st| (String::new(), if st == "MASTER" { 1.0 } else { 0.0 }))
            .into_iter()
            .collect(),
    );
    o
}

// ---------------------------------------------------------------------------
// the watcher
// ---------------------------------------------------------------------------

/// The state strings [`diff`] compares, from a [`summary`].
pub fn state_vector(s: &Value) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for g in s["gateways"].as_array().into_iter().flatten() {
        if let (Some(n), Some(st)) = (g["name"].as_str(), g["state"].as_str()) {
            m.insert(format!("gateway:{n}"), st.to_string());
        }
    }
    for g in s["gateway_groups"].as_array().into_iter().flatten() {
        if let Some(n) = g["name"].as_str() {
            let mut a: Vec<&str> = g["active"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            a.sort_unstable();
            m.insert(format!("group:{n}"), a.join(","));
        }
    }
    for p in s["vpn"]["wireguard"].as_array().into_iter().flatten() {
        let n = format!(
            "{}/{}",
            p["interface"].as_str().unwrap_or(""),
            p["peer"].as_str().unwrap_or("")
        );
        m.insert(
            format!("tunnel:wg {n}"),
            if p["connected"] == true { "up" } else { "down" }.into(),
        );
    }
    for t in s["vpn"]["ipsec"].as_array().into_iter().flatten() {
        if let Some(n) = t["name"].as_str() {
            m.insert(
                format!("tunnel:ipsec {n}"),
                if t["established"] == true {
                    "up"
                } else {
                    "down"
                }
                .into(),
            );
        }
    }
    if let Some(st) = s["ha"]["state"].as_str() {
        m.insert("ha:state".into(), st.to_string());
    }
    m
}

pub struct Watcher {
    state: AppState,
    prev: Option<BTreeMap<String, String>>,
    last_rev: Option<i64>,
}

impl Watcher {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            prev: None,
            last_rev: None,
        }
    }

    /// One look; records and delivers what changed. Returns the events.
    pub async fn tick(&mut self) -> Vec<Event> {
        let store = self.state.config_store.clone();
        let s = summary(&self.state).await;
        let cur = state_vector(&s);
        let mut out = match &self.prev {
            Some(prev) => diff(prev, &cur),
            None => Vec::new(),
        };
        self.prev = Some(cur);
        let rev = s["config"]["last_change"]["id"].as_i64();
        if let (Some(old), Some(new)) = (self.last_rev, rev) {
            if new != old {
                let what = s["config"]["last_change"]["summary"].as_str().unwrap_or("");
                out.push(ev(
                    "config_changed",
                    "config",
                    "info",
                    format!("configuration revision {new}: {what}"),
                ));
            }
        }
        self.last_rev = rev.or(self.last_rev);
        for e in out.iter_mut() {
            match record(&store, e).await {
                Ok(id) => e.id = id,
                Err(err) => tracing::warn!("recording event {}: {err}", e.kind),
            }
            deliver(store.clone(), e.clone()).await;
        }
        out
    }
}

/// Start the watcher: a look every 10 seconds.
pub fn spawn_watcher(state: AppState) {
    tokio::spawn(async move {
        let mut w = Watcher::new(state);
        let mut t = tokio::time::interval(std::time::Duration::from_secs(10));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            w.tick().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(v: &[(&str, &str)]) -> BTreeMap<String, String> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn kinds(v: &[Event]) -> Vec<(&str, &str)> {
        v.iter()
            .map(|e| (e.kind.as_str(), e.subject.as_str()))
            .collect()
    }

    #[test]
    fn gateway_and_tunnel_changes_become_events() {
        let a = m(&[
            ("gateway:WAN", "online"),
            ("gateway:OPT", "online"),
            ("group:FAIL", "WAN"),
            ("tunnel:wg wg0/phone", "up"),
            ("tunnel:ipsec hq", "down"),
            ("ha:state", "BACKUP"),
        ]);
        assert!(diff(&a, &a).is_empty());
        let b = m(&[
            ("gateway:WAN", "down"),
            ("gateway:OPT", "latency"),
            ("group:FAIL", "OPT"),
            ("tunnel:wg wg0/phone", "down"),
            ("tunnel:ipsec hq", "up"),
            ("ha:state", "MASTER"),
        ]);
        let e = diff(&a, &b);
        assert_eq!(
            kinds(&e),
            vec![
                ("gateway_degraded", "OPT"),
                ("gateway_down", "WAN"),
                ("group_failover", "FAIL"),
                ("ha_state", "state"),
                ("tunnel_up", "ipsec hq"),
                ("tunnel_down", "wg wg0/phone"),
            ]
        );
        assert_eq!(
            e.iter()
                .find(|x| x.kind == "gateway_down")
                .unwrap()
                .severity,
            "critical"
        );
        // recovery
        let c = m(&[("gateway:WAN", "online"), ("gateway:OPT", "online")]);
        let e = diff(&b, &c);
        assert_eq!(kinds(&e).iter().filter(|k| k.0 == "gateway_up").count(), 2);
    }

    #[test]
    fn new_keys_only_matter_when_they_are_a_problem() {
        let prev = BTreeMap::new();
        let cur = m(&[
            ("gateway:A", "online"),
            ("gateway:B", "down"),
            ("tunnel:ipsec x", "down"),
            ("tunnel:ipsec y", "up"),
            ("group:G", "A"),
            ("ha:state", "BACKUP"),
        ]);
        assert_eq!(
            kinds(&diff(&prev, &cur)),
            vec![
                ("gateway_down", "B"),
                ("ha_state", "state"),
                ("tunnel_up", "ipsec y")
            ]
        );
        // a pending gateway turning online is not a recovery
        let e = diff(
            &m(&[("gateway:A", "pending")]),
            &m(&[("gateway:A", "online")]),
        );
        assert!(e.is_empty());
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        assert_eq!(
            hmac_sha256_hex(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // keys longer than the block size are hashed first
        assert_eq!(
            hmac_sha256_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[tokio::test]
    async fn events_and_hooks_are_stored_and_validated() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let id1 = record(&store, &ev("gateway_down", "WAN", "critical", "x".into()))
            .await
            .unwrap();
        let id2 = record(&store, &ev("tunnel_up", "hq", "info", "y".into()))
            .await
            .unwrap();
        assert!(id2 > id1);
        let all = events(&store, 0, None, 100).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(events(&store, id1, None, 100).await.unwrap().len(), 1);
        assert_eq!(
            events(&store, 0, Some("tunnel_up"), 100).await.unwrap()[0].subject,
            "hq"
        );

        let h = save_hook(
            &store,
            "rustinion",
            "https://rustinion.example/ev",
            "s3cret",
            "gateway_down, tunnel_down",
        )
        .await
        .unwrap();
        let hs = hooks(&store).await.unwrap();
        assert_eq!(hs[0].kinds, "gateway_down,tunnel_down");
        assert!(hs[0].has_secret);
        assert!(!serde_json::to_string(&hs[0]).unwrap().contains("s3cret"));
        assert!(wants(&hs[0], "gateway_down") && !wants(&hs[0], "tunnel_up"));
        let (body, headers) = delivery("fw1", &hs[0], &all[0]);
        let sig = headers
            .iter()
            .find(|h| h.starts_with("X-Patronus-Signature: sha256="))
            .unwrap();
        assert!(sig.ends_with(&hmac_sha256_hex(b"s3cret", body.as_bytes())));
        for (n, u, k) in [
            ("", "https://a", ""),
            ("x", "ftp://a", ""),
            ("x", "https://a b", ""),
            ("x", "https://a", "nonsense"),
        ] {
            let e = save_hook(&store, n, u, "", k).await.unwrap_err();
            assert!(e.to_string().starts_with("Invalid"), "{n} {u} {k}: {e}");
        }
        assert!(delete_hook(&store, h).await.unwrap());
        assert!(!delete_hook(&store, h).await.unwrap());
    }

    #[test]
    fn metrics_are_prometheus_text() {
        let s = json!({
            "version": "1.2.3", "hostname": "fw\"1", "uptime_secs": 99,
            "firewall": {"active_rules": 12},
            "gateways": [{"name": "WAN", "state": "online", "rtt_ms": 4.5, "loss_pct": 0},
                         {"name": "OPT", "state": "down", "rtt_ms": null, "loss_pct": 100}],
            "vpn": {"wireguard": [{"interface": "wg0", "peer": "phone", "connected": true, "handshake_age_secs": 12}],
                    "ipsec": [{"name": "hq", "established": false}]},
            "conntrack": {"count": 321, "max": 262144},
            "dhcp": {"leases": 4},
            "services": [{"name": "unbound", "running": true}],
            "config": {"last_change": {"id": 7}},
            "ha": {"state": "MASTER"},
        });
        let t = prometheus(&s);
        for want in [
            "patronus_info{version=\"1.2.3\",hostname=\"fw\\\"1\"} 1",
            "patronus_gateway_up{gateway=\"WAN\"} 1",
            "patronus_gateway_up{gateway=\"OPT\"} 0",
            "patronus_gateway_rtt_ms{gateway=\"WAN\"} 4.5",
            "patronus_wireguard_peer_connected{interface=\"wg0\",peer=\"phone\"} 1",
            "patronus_wireguard_handshake_age_seconds{interface=\"wg0\",peer=\"phone\"} 12",
            "patronus_ipsec_sa_established{tunnel=\"hq\"} 0",
            "patronus_conntrack_entries 321",
            "patronus_dhcp_leases 4",
            "patronus_service_up{service=\"unbound\"} 1",
            "patronus_config_revision 7",
            "patronus_ha_master 1",
            "# TYPE patronus_uptime_seconds gauge",
        ] {
            assert!(t.contains(want), "missing {want:?} in:\n{t}");
        }
        // no value -> no sample (a null RTT is not 0)
        assert!(!t.contains("patronus_gateway_rtt_ms{gateway=\"OPT\"}"));
    }
}
