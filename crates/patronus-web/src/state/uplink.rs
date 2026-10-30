//! Uplink health history, extra probes and SLA (device segmentation, part d).
//!
//! The gateway monitor (`patronus applyd`, or patronus-web when no applyd
//! runs) pings every gateway once a second and, for gateways that have extra
//! tcp / http / dns probes (`ins_uplink_probes`), probes those every five
//! seconds through the gateway's own device. This module is the *history*:
//! a recorder reads the published results every 15 s and
//!
//! - writes one sample per gateway per minute to `ins_uplink_samples`
//!   (state, RTT, loss, which probe kinds worked, a degraded flag),
//! - rolls the samples into `ins_uplink_hourly` (SLA numbers outlive the raw
//!   minutes: 7 days of samples, 90 days of hours by default),
//! - raises events (`uplink_probe_failed` / `uplink_probe_recovered`,
//!   `uplink_sla_breach` / `uplink_sla_ok`) through the normal event log and
//!   signed webhooks of [`super::telemetry`], next to the gateway
//!   up/down/degraded events that already existed.
//!
//! A *critical* probe also feeds multi-WAN failover: while it fails the
//! monitor counts the sample as lost (see `patronus_network::uplink_probe`).

use super::telemetry::{self, Event};
use patronus_config::ConfigStore;
use patronus_network::uplink_probe::{self, ProbeKind, ProbeResult, ProbeSpec};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use std::collections::{BTreeMap, HashSet};

pub const CFG_SAMPLE_DAYS: &str = "uplink.sample_retention_days";
pub const CFG_SLA_DAYS: &str = "uplink.sla_retention_days";
pub const CFG_SLA_TARGET: &str = "uplink.sla_target";
pub const DEFAULT_SAMPLE_DAYS: i64 = 7;
pub const DEFAULT_SLA_DAYS: i64 = 90;
pub const RECORD_SECS: u64 = 15;

fn pool(store: &ConfigStore) -> anyhow::Result<&SqlitePool> {
    store.pool().map_err(|e| anyhow::anyhow!("{e}"))
}

// ---------------------------------------------------------------------------
// reading the monitor's output
// ---------------------------------------------------------------------------

/// One gateway as the recorder sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct GwView {
    pub name: String,
    pub state: String,
    pub rtt_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub probes: Vec<ProbeResult>,
}

/// `gateways` of `RoutingManager::status()`.
pub fn gateways_of(status: &Value) -> Vec<GwView> {
    status["gateways"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|g| {
            Some(GwView {
                name: g["name"].as_str()?.to_string(),
                state: g["state"].as_str()?.to_string(),
                rtt_ms: g["rtt_ms"].as_f64(),
                loss_pct: g["loss_pct"].as_f64(),
                probes: g["probes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| serde_json::from_value(p.clone()).ok())
                    .collect(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Good,
    Degraded,
    Down,
}

/// `None` = nothing measured (pending, unmonitored without probes).
pub fn classify(g: &GwView) -> Option<Class> {
    let probe_failing = g.probes.iter().any(|p| !p.ok);
    match g.state.as_str() {
        "down" => Some(Class::Down),
        "loss" | "latency" => Some(Class::Degraded),
        "online" => Some(if probe_failing {
            Class::Degraded
        } else {
            Class::Good
        }),
        "unmonitored" if !g.probes.is_empty() => Some(if probe_failing {
            Class::Degraded
        } else {
            Class::Good
        }),
        _ => None,
    }
}

/// `Some(all probes of that kind ok)`, `None` when the gateway has none.
fn kind_ok(g: &GwView, k: ProbeKind) -> Option<i64> {
    let of: Vec<&ProbeResult> = g.probes.iter().filter(|p| p.kind == k).collect();
    (!of.is_empty()).then(|| i64::from(of.iter().all(|p| p.ok)))
}

// ---------------------------------------------------------------------------
// recording
// ---------------------------------------------------------------------------

/// Write the minute's sample of every measured gateway and update the hourly
/// rollup. A second call within the same minute adds nothing. Returns the
/// number of samples written.
pub async fn record(store: &ConfigStore, now: i64, gws: &[GwView]) -> anyhow::Result<usize> {
    let ts = now - now.rem_euclid(60);
    let hour = now - now.rem_euclid(3600);
    let p = pool(store)?;
    let mut n = 0;
    for g in gws {
        let Some(class) = classify(g) else { continue };
        let degraded =
            matches!(class, Class::Degraded) && g.probes.iter().any(|p| !p.ok) && g.state != "down";
        let icmp_ok = match g.state.as_str() {
            "unmonitored" | "pending" => None,
            s => Some(i64::from(s != "down")),
        };
        let r = sqlx::query(
            "INSERT OR IGNORE INTO ins_uplink_samples \
             (ts, gateway, state, rtt_ms, loss_pct, icmp_ok, tcp_ok, dns_ok, http_ok, degraded, probes) \
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(ts)
        .bind(&g.name)
        .bind(&g.state)
        .bind(g.rtt_ms)
        .bind(g.loss_pct)
        .bind(icmp_ok)
        .bind(kind_ok(g, ProbeKind::Tcp))
        .bind(kind_ok(g, ProbeKind::Dns))
        .bind(kind_ok(g, ProbeKind::Http))
        .bind(i64::from(degraded))
        .bind(serde_json::to_string(&g.probes).unwrap_or_else(|_| "[]".into()))
        .execute(p)
        .await?;
        if r.rows_affected() == 0 {
            continue;
        }
        n += 1;
        let (up, good, deg, down) = match class {
            Class::Good => (1, 1, 0, 0),
            Class::Degraded => (1, 0, 1, 0),
            Class::Down => (0, 0, 0, 1),
        };
        sqlx::query(
            "INSERT INTO ins_uplink_hourly (hour, gateway, samples, up, good, degraded, down, rtt_sum, rtt_n, rtt_max, loss_sum) \
             VALUES (?,?,1,?,?,?,?,?,?,?,?) \
             ON CONFLICT(hour, gateway) DO UPDATE SET samples = samples + 1, up = up + excluded.up, \
               good = good + excluded.good, degraded = degraded + excluded.degraded, down = down + excluded.down, \
               rtt_sum = rtt_sum + excluded.rtt_sum, rtt_n = rtt_n + excluded.rtt_n, \
               rtt_max = CASE WHEN excluded.rtt_max IS NULL THEN rtt_max \
                              WHEN rtt_max IS NULL OR excluded.rtt_max > rtt_max THEN excluded.rtt_max ELSE rtt_max END, \
               loss_sum = loss_sum + excluded.loss_sum",
        )
        .bind(hour)
        .bind(&g.name)
        .bind(up)
        .bind(good)
        .bind(deg)
        .bind(down)
        .bind(g.rtt_ms.unwrap_or(0.0))
        .bind(i64::from(g.rtt_ms.is_some()))
        .bind(g.rtt_ms)
        .bind(g.loss_pct.unwrap_or(if class == Class::Down { 100.0 } else { 0.0 }))
        .execute(p)
        .await?;
    }
    Ok(n)
}

async fn days(store: &ConfigStore, key: &str, default: i64) -> i64 {
    store
        .load_system_config(key)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .filter(|d| (1..=3650).contains(d))
        .unwrap_or(default)
}

/// Delete raw samples and hourly rows past their retention.
pub async fn prune(store: &ConfigStore, now: i64) -> anyhow::Result<(u64, u64)> {
    let s = now - days(store, CFG_SAMPLE_DAYS, DEFAULT_SAMPLE_DAYS).await * 86_400;
    let h = now - days(store, CFG_SLA_DAYS, DEFAULT_SLA_DAYS).await * 86_400;
    let p = pool(store)?;
    let a = sqlx::query("DELETE FROM ins_uplink_samples WHERE ts < ?")
        .bind(s)
        .execute(p)
        .await?
        .rows_affected();
    let b = sqlx::query("DELETE FROM ins_uplink_hourly WHERE hour < ?")
        .bind(h)
        .execute(p)
        .await?
        .rows_affected();
    Ok((a, b))
}

/// Forget gateways that no longer exist? No: history stays (an SLA report of
/// a retired uplink is still wanted); it ages out with the retention.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Settings {
    pub sample_retention_days: i64,
    pub sla_retention_days: i64,
    /// Availability percent below which `uplink_sla_breach` fires (0 = off).
    pub sla_target: f64,
}

pub async fn load_settings(store: &ConfigStore) -> Settings {
    Settings {
        sample_retention_days: days(store, CFG_SAMPLE_DAYS, DEFAULT_SAMPLE_DAYS).await,
        sla_retention_days: days(store, CFG_SLA_DAYS, DEFAULT_SLA_DAYS).await,
        sla_target: store
            .load_system_config(CFG_SLA_TARGET)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .filter(|t: &f64| (0.0..=100.0).contains(t))
            .unwrap_or(0.0),
    }
}

pub async fn save_settings(
    store: &ConfigStore,
    sample_days: Option<i64>,
    sla_days: Option<i64>,
    sla_target: Option<f64>,
) -> anyhow::Result<()> {
    for (v, what) in [
        (sample_days, "sample retention"),
        (sla_days, "SLA retention"),
    ] {
        if let Some(d) = v {
            if !(1..=3650).contains(&d) {
                anyhow::bail!("Invalid request: {what} is 1 to 3650 days");
            }
        }
    }
    if let Some(t) = sla_target {
        if !(0.0..=100.0).contains(&t) || t.is_nan() {
            anyhow::bail!("Invalid request: the SLA target is 0 (off) to 100 percent");
        }
    }
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    if let Some(d) = sample_days {
        store
            .save_system_config(CFG_SAMPLE_DAYS, &d.to_string())
            .await
            .map_err(e)?;
    }
    if let Some(d) = sla_days {
        store
            .save_system_config(CFG_SLA_DAYS, &d.to_string())
            .await
            .map_err(e)?;
    }
    if let Some(t) = sla_target {
        store
            .save_system_config(CFG_SLA_TARGET, &t.to_string())
            .await
            .map_err(e)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

fn ev(now: i64, kind: &str, subject: &str, severity: &str, detail: String) -> Event {
    Event {
        id: 0,
        ts: now,
        kind: kind.into(),
        subject: subject.into(),
        severity: severity.into(),
        detail,
    }
}

/// Events for probes that started or stopped failing since the last look.
/// `failing` is the recorder's memory of `(gateway, probe id)` that failed.
pub fn probe_events(failing: &mut HashSet<(String, i64)>, gws: &[GwView], now: i64) -> Vec<Event> {
    let mut out = vec![];
    let mut seen = HashSet::new();
    for g in gws {
        for p in &g.probes {
            let key = (g.name.clone(), p.id);
            seen.insert(key.clone());
            let was = failing.contains(&key);
            if !p.ok && !was {
                failing.insert(key);
                out.push(ev(
                    now,
                    "uplink_probe_failed",
                    &g.name,
                    if p.critical { "critical" } else { "warning" },
                    format!(
                        "{} probe {} through {} failed: {}{}",
                        p.kind.as_str(),
                        p.target,
                        g.name,
                        p.error.as_deref().unwrap_or("no answer"),
                        if p.critical {
                            " (critical: counts as packet loss for failover)"
                        } else {
                            ""
                        }
                    ),
                ));
            } else if p.ok && was {
                failing.remove(&key);
                out.push(ev(
                    now,
                    "uplink_probe_recovered",
                    &g.name,
                    "info",
                    format!(
                        "{} probe {} through {} answers again",
                        p.kind.as_str(),
                        p.target,
                        g.name
                    ),
                ));
            }
        }
    }
    // a removed probe or gateway stops being tracked without an event
    failing.retain(|k| seen.contains(k));
    out
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Sla {
    pub gateway: String,
    pub samples: i64,
    pub availability_pct: Option<f64>,
    pub quality_pct: Option<f64>,
    pub down_minutes: i64,
    pub degraded_minutes: i64,
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    pub loss_avg_pct: Option<f64>,
}

fn pct(n: i64, d: i64) -> Option<f64> {
    (d > 0).then(|| ((n as f64 / d as f64) * 10_000.0).round() / 100.0)
}

/// Fire `uplink_sla_breach` when a gateway's availability over the window
/// drops below `target`, `uplink_sla_ok` when it is back above it.
pub fn sla_events(
    breached: &mut HashSet<String>,
    rows: &[Sla],
    target: f64,
    window: &str,
    now: i64,
) -> Vec<Event> {
    let mut out = vec![];
    if target <= 0.0 {
        breached.clear();
        return out;
    }
    for r in rows {
        let Some(a) = r.availability_pct else {
            continue;
        };
        if a < target && breached.insert(r.gateway.clone()) {
            out.push(ev(
                now,
                "uplink_sla_breach",
                &r.gateway,
                "warning",
                format!("availability of {} is {a:.2}% over {window}, below the {target:.2}% target ({} minutes down)", r.gateway, r.down_minutes),
            ));
        } else if a >= target && breached.remove(&r.gateway) {
            out.push(ev(
                now,
                "uplink_sla_ok",
                &r.gateway,
                "info",
                format!("availability of {} is {a:.2}% over {window}, back within the {target:.2}% target", r.gateway),
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

/// SLA numbers per gateway over the window (from the hourly rollup).
pub async fn sla(
    store: &ConfigStore,
    gateway: Option<&str>,
    now: i64,
    window_secs: i64,
) -> anyhow::Result<Vec<Sla>> {
    let from = (now - window_secs) - (now - window_secs).rem_euclid(3600);
    let mut sql = "SELECT gateway, SUM(samples), SUM(up), SUM(good), SUM(degraded), SUM(down), \
                   SUM(rtt_sum), SUM(rtt_n), MAX(rtt_max), SUM(loss_sum) FROM ins_uplink_hourly WHERE hour >= ?"
        .to_string();
    if gateway.is_some() {
        sql += " AND gateway = ?";
    }
    sql += " GROUP BY gateway ORDER BY gateway";
    let mut q = sqlx::query(&sql).bind(from);
    if let Some(g) = gateway {
        q = q.bind(g);
    }
    Ok(q.fetch_all(pool(store)?)
        .await?
        .into_iter()
        .map(|r| {
            let (samples, up, good, deg, down): (i64, i64, i64, i64, i64) =
                (r.get(1), r.get(2), r.get(3), r.get(4), r.get(5));
            let (rsum, rn): (f64, i64) = (r.get(6), r.get(7));
            Sla {
                gateway: r.get(0),
                samples,
                availability_pct: pct(up, samples),
                quality_pct: pct(good, samples),
                down_minutes: down,
                degraded_minutes: deg,
                rtt_avg_ms: (rn > 0).then(|| (rsum / rn as f64 * 100.0).round() / 100.0),
                rtt_max_ms: r.get(8),
                loss_avg_pct: (samples > 0)
                    .then(|| (r.get::<f64, _>(9) / samples as f64 * 100.0).round() / 100.0),
            }
        })
        .collect())
}

/// One point per rollup hour for the SLA graph.
pub async fn sla_series(
    store: &ConfigStore,
    gateway: &str,
    now: i64,
    window_secs: i64,
) -> anyhow::Result<Vec<Value>> {
    let from = (now - window_secs) - (now - window_secs).rem_euclid(3600);
    Ok(sqlx::query(
        "SELECT hour, samples, up, good, down, rtt_sum, rtt_n, rtt_max, loss_sum FROM ins_uplink_hourly \
         WHERE gateway = ? AND hour >= ? ORDER BY hour",
    )
    .bind(gateway)
    .bind(from)
    .fetch_all(pool(store)?)
    .await?
    .into_iter()
    .map(|r| {
        let (samples, up, good, down): (i64, i64, i64, i64) = (r.get(1), r.get(2), r.get(3), r.get(4));
        let (rsum, rn): (f64, i64) = (r.get(5), r.get(6));
        json!({
            "hour": r.get::<i64, _>(0),
            "samples": samples,
            "availability_pct": pct(up, samples),
            "quality_pct": pct(good, samples),
            "down_minutes": down,
            "rtt_avg_ms": (rn > 0).then(|| (rsum / rn as f64 * 100.0).round() / 100.0),
            "rtt_max_ms": r.get::<Option<f64>, _>(7),
            "loss_avg_pct": (samples > 0).then(|| (r.get::<f64, _>(8) / samples as f64 * 100.0).round() / 100.0),
        })
    })
    .collect())
}

fn rank(state: &str) -> u8 {
    match state {
        "down" => 5,
        "loss" => 4,
        "latency" => 3,
        "online" => 1,
        _ => 0,
    }
}

/// The sample series of one gateway since `since`, thinned to at most
/// `max_points` points (worst state, mean RTT / loss, any failing kind).
pub async fn health(
    store: &ConfigStore,
    gateway: Option<&str>,
    since: i64,
    now: i64,
    max_points: i64,
) -> anyhow::Result<Vec<Value>> {
    let span = (now - since).max(60);
    let step = ((span / max_points.max(1) + 59) / 60 * 60).max(60);
    let mut sql =
        "SELECT ts, gateway, state, rtt_ms, loss_pct, icmp_ok, tcp_ok, dns_ok, http_ok, degraded \
                   FROM ins_uplink_samples WHERE ts >= ? AND ts <= ?"
            .to_string();
    if gateway.is_some() {
        sql += " AND gateway = ?";
    }
    sql += " ORDER BY gateway, ts";
    let mut q = sqlx::query(&sql).bind(since).bind(now);
    if let Some(g) = gateway {
        q = q.bind(g);
    }
    #[derive(Default)]
    struct B {
        state: String,
        rtt: (f64, i64),
        loss: (f64, i64),
        fail: [bool; 3],
        degraded: bool,
        n: i64,
    }
    let mut buckets: BTreeMap<(String, i64), B> = BTreeMap::new();
    for r in q.fetch_all(pool(store)?).await? {
        let (ts, gw): (i64, String) = (r.get(0), r.get(1));
        let b = buckets.entry((gw, ts - ts.rem_euclid(step))).or_default();
        let st: String = r.get(2);
        if rank(&st) >= rank(&b.state) {
            b.state = st;
        }
        if let Some(v) = r.get::<Option<f64>, _>(3) {
            b.rtt = (b.rtt.0 + v, b.rtt.1 + 1);
        }
        if let Some(v) = r.get::<Option<f64>, _>(4) {
            b.loss = (b.loss.0 + v, b.loss.1 + 1);
        }
        for (i, col) in [6usize, 7, 8].into_iter().enumerate() {
            if r.get::<Option<i64>, _>(col) == Some(0) {
                b.fail[i] = true;
            }
        }
        b.degraded |= r.get::<i64, _>(9) != 0;
        b.n += 1;
    }
    Ok(buckets
        .into_iter()
        .map(|((gw, ts), b)| {
            json!({
                "ts": ts, "gateway": gw, "state": b.state, "samples": b.n,
                "rtt_ms": (b.rtt.1 > 0).then(|| (b.rtt.0 / b.rtt.1 as f64 * 100.0).round() / 100.0),
                "loss_pct": (b.loss.1 > 0).then(|| (b.loss.0 / b.loss.1 as f64 * 100.0).round() / 100.0),
                "tcp_failed": b.fail[0], "dns_failed": b.fail[1], "http_failed": b.fail[2],
                "degraded": b.degraded,
            })
        })
        .collect())
}

/// Outages (runs of `down` samples, gaps up to 2 minutes bridged) since `since`.
pub async fn outages(
    store: &ConfigStore,
    gateway: Option<&str>,
    since: i64,
    now: i64,
) -> anyhow::Result<Vec<Value>> {
    let mut sql = "SELECT gateway, ts, state FROM ins_uplink_samples WHERE ts >= ?".to_string();
    if gateway.is_some() {
        sql += " AND gateway = ?";
    }
    sql += " ORDER BY gateway, ts";
    let mut q = sqlx::query(&sql).bind(since);
    if let Some(g) = gateway {
        q = q.bind(g);
    }
    let rows: Vec<(String, i64, String)> = q
        .fetch_all(pool(store)?)
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    Ok(outages_of(&rows, now))
}

/// Pure part of [`outages`]: rows are `(gateway, ts, state)` ordered by gateway then time.
pub fn outages_of(rows: &[(String, i64, String)], now: i64) -> Vec<Value> {
    let mut out = vec![];
    let mut cur: Option<(String, i64, i64)> = None; // gateway, start, last down ts
    let flush = |c: Option<(String, i64, i64)>, ongoing: bool, out: &mut Vec<Value>| {
        if let Some((g, s, l)) = c {
            let end = l + 60;
            out.push(json!({"gateway": g, "start": s, "end": end, "minutes": (end - s) / 60, "ongoing": ongoing}));
        }
    };
    for (g, ts, st) in rows {
        let is_down = st == "down";
        match (&mut cur, is_down) {
            (Some(c), true) if c.0 == *g && *ts - c.2 <= 120 => c.2 = *ts,
            (_, true) => {
                let prev = cur.take();
                flush(prev, false, &mut out);
                cur = Some((g.clone(), *ts, *ts));
            }
            (Some(c), false) if c.0 == *g => {
                let prev = cur.take();
                flush(prev, false, &mut out);
            }
            _ => {}
        }
    }
    let ongoing = cur.as_ref().is_some_and(|c| now - c.2 <= 180);
    flush(cur, ongoing, &mut out);
    out
}

// ---------------------------------------------------------------------------
// probe configuration
// ---------------------------------------------------------------------------

pub async fn list_probes(store: &ConfigStore) -> Vec<ProbeSpec> {
    patronus_network::routes::load_probes(store).await
}

/// Create (`id` None) or update a probe. The gateway must exist.
#[allow(clippy::too_many_arguments)]
pub async fn save_probe(
    store: &ConfigStore,
    id: Option<i64>,
    gateway: &str,
    kind: &str,
    target: &str,
    port: Option<u16>,
    name: &str,
    critical: bool,
    enabled: bool,
) -> anyhow::Result<i64> {
    let kind = ProbeKind::parse(kind).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (target, port, name) =
        uplink_probe::validate(kind, target, port, name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let cfg = patronus_network::routes::load(store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if cfg.gateway(gateway).is_none() {
        anyhow::bail!("Invalid request: gateway {gateway:?} does not exist");
    }
    let p = pool(store)?;
    let dup = sqlx::query(
        "SELECT id FROM ins_uplink_probes WHERE gateway=? AND kind=? AND target=? AND COALESCE(port,0)=? AND name=?",
    )
    .bind(gateway)
    .bind(kind.as_str())
    .bind(&target)
    .bind(port.map(i64::from).unwrap_or(0))
    .bind(&name)
    .fetch_optional(p)
    .await?;
    if let Some(d) = dup {
        if Some(d.get::<i64, _>(0)) != id {
            anyhow::bail!("Invalid request: that probe already exists on {gateway}");
        }
    }
    match id {
        None => Ok(sqlx::query(
            "INSERT INTO ins_uplink_probes (gateway, kind, target, port, name, critical, enabled) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(gateway)
        .bind(kind.as_str())
        .bind(&target)
        .bind(port.map(i64::from))
        .bind(&name)
        .bind(i64::from(critical))
        .bind(i64::from(enabled))
        .execute(p)
        .await?
        .last_insert_rowid()),
        Some(id) => {
            let r = sqlx::query(
                "UPDATE ins_uplink_probes SET gateway=?, kind=?, target=?, port=?, name=?, critical=?, enabled=? WHERE id=?",
            )
            .bind(gateway)
            .bind(kind.as_str())
            .bind(&target)
            .bind(port.map(i64::from))
            .bind(&name)
            .bind(i64::from(critical))
            .bind(i64::from(enabled))
            .bind(id)
            .execute(p)
            .await?;
            if r.rows_affected() == 0 {
                anyhow::bail!("not found: probe {id}");
            }
            Ok(id)
        }
    }
}

pub async fn delete_probe(store: &ConfigStore, id: i64) -> anyhow::Result<()> {
    let r = sqlx::query("DELETE FROM ins_uplink_probes WHERE id=?")
        .bind(id)
        .execute(pool(store)?)
        .await?;
    if r.rows_affected() == 0 {
        anyhow::bail!("not found: probe {id}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the background recorder
// ---------------------------------------------------------------------------

/// Start the recorder: every [`RECORD_SECS`] read the monitor's results,
/// record the minute's sample, raise events, prune once an hour.
/// `PATRONUS_UPLINK_TICK_SECS` overrides the interval (tests).
pub fn spawn_recorder(state: super::AppState) {
    let secs = std::env::var("PATRONUS_UPLINK_TICK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(RECORD_SECS);
    tokio::spawn(async move {
        let mut failing: HashSet<(String, i64)> = HashSet::new();
        let mut breached: HashSet<String> = HashSet::new();
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_prune = 0;
        loop {
            t.tick().await;
            let now = chrono::Utc::now().timestamp();
            let store = state.config_store.clone();
            let Ok(status) = state.routing.status().await else {
                continue;
            };
            let gws = gateways_of(&status);
            if let Err(e) = record(&store, now, &gws).await {
                tracing::warn!("uplink recorder: {e}");
            }
            let mut events = probe_events(&mut failing, &gws, now);
            let target = load_settings(&store).await.sla_target;
            if let Ok(rows) = sla(&store, None, now, 86_400).await {
                events.extend(sla_events(&mut breached, &rows, target, "24 h", now));
            }
            for mut e in events {
                match telemetry::record(&store, &e).await {
                    Ok(id) => e.id = id,
                    Err(err) => tracing::warn!("recording event {}: {err}", e.kind),
                }
                telemetry::deliver(store.clone(), e).await;
            }
            if now - last_prune > 3600 {
                last_prune = now;
                if let Err(e) = prune(&store, now).await {
                    tracing::warn!("uplink prune: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(id: i64, kind: ProbeKind, ok: bool, critical: bool) -> ProbeResult {
        ProbeResult {
            id,
            kind,
            target: match kind {
                ProbeKind::Dns => "example.com @1.1.1.1".into(),
                _ => "1.1.1.1:443".into(),
            },
            critical,
            ok,
            last_ok: ok,
            rtt_ms: ok.then_some(12.0),
            fails: u32::from(!ok) * 2,
            error: (!ok).then(|| "timed out".to_string()),
        }
    }

    fn gw(
        name: &str,
        state: &str,
        rtt: Option<f64>,
        loss: Option<f64>,
        probes: Vec<ProbeResult>,
    ) -> GwView {
        GwView {
            name: name.into(),
            state: state.into(),
            rtt_ms: rtt,
            loss_pct: loss,
            probes,
        }
    }

    async fn store() -> ConfigStore {
        ConfigStore::open_in_memory().await.unwrap()
    }

    #[test]
    fn classification_of_states_and_probes() {
        let c = |g: GwView| classify(&g);
        assert_eq!(
            c(gw("A", "online", Some(5.0), Some(0.0), vec![])),
            Some(Class::Good)
        );
        assert_eq!(
            c(gw(
                "A",
                "online",
                Some(5.0),
                Some(0.0),
                vec![probe(1, ProbeKind::Dns, true, false)]
            )),
            Some(Class::Good)
        );
        assert_eq!(
            c(gw(
                "A",
                "online",
                Some(5.0),
                Some(0.0),
                vec![probe(1, ProbeKind::Dns, false, false)]
            )),
            Some(Class::Degraded),
            "ping works, DNS is dead"
        );
        assert_eq!(
            c(gw("A", "loss", None, None, vec![])),
            Some(Class::Degraded)
        );
        assert_eq!(
            c(gw("A", "latency", None, None, vec![])),
            Some(Class::Degraded)
        );
        assert_eq!(c(gw("A", "down", None, None, vec![])), Some(Class::Down));
        assert_eq!(c(gw("A", "pending", None, None, vec![])), None);
        assert_eq!(c(gw("A", "unmonitored", None, None, vec![])), None);
        assert_eq!(
            c(gw(
                "A",
                "unmonitored",
                None,
                None,
                vec![probe(1, ProbeKind::Tcp, true, false)]
            )),
            Some(Class::Good),
            "probes alone are a measurement"
        );
    }

    #[test]
    fn gateways_are_read_from_the_routing_status() {
        let st = json!({"gateways": [
            {"name": "WAN", "state": "online", "rtt_ms": 4.5, "loss_pct": 0,
             "probes": [serde_json::to_value(probe(7, ProbeKind::Http, false, true)).unwrap()]},
            {"name": "OPT", "state": "down", "rtt_ms": null, "loss_pct": 100},
            {"state": "online"}]});
        let g = gateways_of(&st);
        assert_eq!(g.len(), 2, "a gateway without a name is skipped");
        assert_eq!(g[0].probes.len(), 1);
        assert_eq!(g[0].probes[0].kind, ProbeKind::Http);
        assert_eq!(g[1].rtt_ms, None);
        assert!(gateways_of(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn one_sample_per_minute_and_rollup_per_hour() {
        let s = store().await;
        let t = 1_800_000_000 - (1_800_000_000 % 3600) + 120;
        let probes = vec![
            probe(1, ProbeKind::Dns, false, false),
            probe(2, ProbeKind::Tcp, true, false),
        ];
        let g = vec![
            gw("WAN", "online", Some(10.0), Some(0.0), probes),
            gw("LTE", "down", None, None, vec![]),
            gw("X", "pending", None, None, vec![]),
        ];
        assert_eq!(
            record(&s, t + 5, &g).await.unwrap(),
            2,
            "pending is not recorded"
        );
        assert_eq!(
            record(&s, t + 30, &g).await.unwrap(),
            0,
            "same minute: nothing added"
        );
        let r = sqlx::query("SELECT state, rtt_ms, icmp_ok, tcp_ok, dns_ok, http_ok, degraded FROM ins_uplink_samples WHERE gateway='WAN'")
            .fetch_one(s.pool().unwrap()).await.unwrap();
        assert_eq!(r.get::<String, _>(0), "online");
        assert_eq!(r.get::<Option<i64>, _>(2), Some(1));
        assert_eq!(r.get::<Option<i64>, _>(3), Some(1), "tcp ok");
        assert_eq!(r.get::<Option<i64>, _>(4), Some(0), "dns failed");
        assert_eq!(r.get::<Option<i64>, _>(5), None, "no http probe configured");
        assert_eq!(r.get::<i64, _>(6), 1, "degraded: ping works, dns does not");
        let l = sqlx::query("SELECT icmp_ok FROM ins_uplink_samples WHERE gateway='LTE'")
            .fetch_one(s.pool().unwrap())
            .await
            .unwrap();
        assert_eq!(l.get::<Option<i64>, _>(0), Some(0));
        // more minutes: 1 down, rest ok
        record(&s, t + 60, &[gw("LTE", "down", None, None, vec![])])
            .await
            .unwrap();
        record(
            &s,
            t + 120,
            &[gw("LTE", "online", Some(30.0), Some(0.0), vec![])],
        )
        .await
        .unwrap();
        record(
            &s,
            t + 180,
            &[gw("LTE", "online", Some(50.0), Some(0.0), vec![])],
        )
        .await
        .unwrap();
        let sl = sla(&s, Some("LTE"), t + 200, 3600).await.unwrap();
        assert_eq!(sl.len(), 1);
        assert_eq!(sl[0].samples, 4);
        assert_eq!(sl[0].down_minutes, 2);
        assert_eq!(sl[0].availability_pct, Some(50.0));
        assert_eq!(sl[0].quality_pct, Some(50.0));
        assert_eq!(
            sl[0].rtt_avg_ms,
            Some(40.0),
            "mean over the samples that had an RTT"
        );
        assert_eq!(sl[0].rtt_max_ms, Some(50.0));
        assert_eq!(
            sl[0].loss_avg_pct,
            Some(50.0),
            "two samples at 100 % loss (down), two at 0"
        );
        let wan = sla(&s, Some("WAN"), t + 200, 3600).await.unwrap();
        assert_eq!(
            (
                wan[0].availability_pct,
                wan[0].quality_pct,
                wan[0].degraded_minutes
            ),
            (Some(100.0), Some(0.0), 1),
            "degraded counts as up but not good"
        );
        assert_eq!(sla(&s, None, t + 200, 3600).await.unwrap().len(), 2);
        assert!(sla(&s, Some("nope"), t + 200, 3600)
            .await
            .unwrap()
            .is_empty());
        let series = sla_series(&s, "LTE", t + 200, 3600).await.unwrap();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0]["availability_pct"], 50.0);
    }

    #[tokio::test]
    async fn sla_window_excludes_older_hours() {
        let s = store().await;
        let t0 = 1_800_000_000 - (1_800_000_000 % 3600);
        record(&s, t0, &[gw("A", "down", None, None, vec![])])
            .await
            .unwrap();
        record(
            &s,
            t0 + 3 * 3600,
            &[gw("A", "online", Some(1.0), Some(0.0), vec![])],
        )
        .await
        .unwrap();
        let wide = sla(&s, None, t0 + 3 * 3600, 4 * 3600).await.unwrap();
        assert_eq!(wide[0].availability_pct, Some(50.0));
        let narrow = sla(&s, None, t0 + 3 * 3600, 3600).await.unwrap();
        assert_eq!(
            narrow[0].availability_pct,
            Some(100.0),
            "the down hour is outside a 1 h window"
        );
    }

    #[tokio::test]
    async fn retention_keeps_hours_longer_than_samples() {
        let s = store().await;
        let now = 1_800_000_000;
        let old = now - 10 * 86_400;
        record(&s, old, &[gw("A", "online", Some(1.0), Some(0.0), vec![])])
            .await
            .unwrap();
        record(&s, now, &[gw("A", "online", Some(1.0), Some(0.0), vec![])])
            .await
            .unwrap();
        assert_eq!(
            prune(&s, now).await.unwrap(),
            (1, 0),
            "7 days of samples, 90 days of hours"
        );
        assert_eq!(sla(&s, None, now, 30 * 86_400).await.unwrap()[0].samples, 2);
        save_settings(&s, Some(1), Some(5), None).await.unwrap();
        assert_eq!(prune(&s, now).await.unwrap(), (0, 1));
        assert!(save_settings(&s, Some(0), None, None).await.is_err());
        assert!(save_settings(&s, None, Some(4000), None).await.is_err());
        assert!(save_settings(&s, None, None, Some(100.5)).await.is_err());
        assert!(save_settings(&s, None, None, Some(f64::NAN)).await.is_err());
        save_settings(&s, None, None, Some(99.5)).await.unwrap();
        assert_eq!(
            load_settings(&s).await,
            Settings {
                sample_retention_days: 1,
                sla_retention_days: 5,
                sla_target: 99.5
            }
        );
    }

    #[tokio::test]
    async fn health_series_is_thinned_and_shows_the_worst_state() {
        let s = store().await;
        let t0 = 1_800_000_000 - (1_800_000_000 % 3600);
        for i in 0..120 {
            let (st, rtt) = if i == 50 {
                ("down", None)
            } else {
                ("online", Some(10.0 + (i % 2) as f64 * 10.0))
            };
            let probes = if i == 70 {
                vec![probe(1, ProbeKind::Dns, false, false)]
            } else {
                vec![]
            };
            record(&s, t0 + i * 60, &[gw("A", st, rtt, Some(0.0), probes)])
                .await
                .unwrap();
        }
        let all = health(&s, Some("A"), t0, t0 + 7200, 1000).await.unwrap();
        assert_eq!(
            all.len(),
            120,
            "one point per minute while the series is short"
        );
        let thin = health(&s, Some("A"), t0, t0 + 7200, 12).await.unwrap();
        assert!(thin.len() <= 12, "{}", thin.len());
        assert!(
            thin.iter().any(|p| p["state"] == "down"),
            "the outage minute survives thinning"
        );
        assert!(thin.iter().any(|p| p["dns_failed"] == true));
        let first = &thin[0];
        assert!(
            first["rtt_ms"].as_f64().unwrap() > 9.0 && first["rtt_ms"].as_f64().unwrap() < 21.0
        );
        assert!(health(&s, Some("B"), t0, t0 + 7200, 100)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            health(&s, None, t0 + 3600, t0 + 7200, 1000)
                .await
                .unwrap()
                .len(),
            60,
            "since is respected"
        );
    }

    #[test]
    fn outage_runs_are_found_and_bridged() {
        let r = |g: &str, ts: i64, st: &str| (g.to_string(), ts, st.to_string());
        let rows = vec![
            r("A", 0, "online"),
            r("A", 60, "down"),
            r("A", 120, "down"),
            r("A", 240, "down"), // a missed minute inside the outage
            r("A", 300, "online"),
            r("A", 360, "down"),
            r("A", 420, "online"),
            r("B", 0, "down"),
            r("B", 60, "down"),
        ];
        let o = outages_of(&rows, 100_000);
        assert_eq!(o.len(), 3);
        assert_eq!(
            (
                o[0]["gateway"].as_str(),
                o[0]["start"].as_i64(),
                o[0]["end"].as_i64(),
                o[0]["minutes"].as_i64()
            ),
            (Some("A"), Some(60), Some(300), Some(4))
        );
        assert_eq!(o[1]["minutes"], 1);
        assert_eq!(o[2]["gateway"], "B");
        assert_eq!(o[2]["ongoing"], false, "ended long ago");
        let live = outages_of(&[r("A", 1000, "down"), r("A", 1060, "down")], 1100);
        assert_eq!(live[0]["ongoing"], true, "still down at the last sample");
        assert!(outages_of(&[], 0).is_empty());
        // a gap above 2 minutes splits runs
        let split = outages_of(&[r("A", 0, "down"), r("A", 600, "down")], 100_000);
        assert_eq!(split.len(), 2);
    }

    #[test]
    fn probe_events_fire_once_per_change() {
        let mut f = HashSet::new();
        let bad = vec![gw(
            "WAN",
            "online",
            Some(5.0),
            Some(0.0),
            vec![
                probe(1, ProbeKind::Dns, false, true),
                probe(2, ProbeKind::Tcp, true, false),
            ],
        )];
        let e = probe_events(&mut f, &bad, 100);
        assert_eq!(e.len(), 1);
        assert_eq!(
            (
                e[0].kind.as_str(),
                e[0].severity.as_str(),
                e[0].subject.as_str()
            ),
            ("uplink_probe_failed", "critical", "WAN")
        );
        assert!(
            e[0].detail.contains("dns")
                && e[0].detail.contains("timed out")
                && e[0].detail.contains("failover"),
            "{}",
            e[0].detail
        );
        assert!(
            probe_events(&mut f, &bad, 115).is_empty(),
            "no repeat while it keeps failing"
        );
        let noncrit = vec![gw(
            "WAN",
            "online",
            None,
            None,
            vec![
                probe(1, ProbeKind::Dns, false, true),
                probe(3, ProbeKind::Http, false, false),
            ],
        )];
        let e = probe_events(&mut f, &noncrit, 130);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].severity, "warning");
        let ok = vec![gw(
            "WAN",
            "online",
            None,
            None,
            vec![
                probe(1, ProbeKind::Dns, true, true),
                probe(3, ProbeKind::Http, true, false),
            ],
        )];
        let e = probe_events(&mut f, &ok, 145);
        assert_eq!(
            e.iter().map(|x| x.kind.as_str()).collect::<Vec<_>>(),
            ["uplink_probe_recovered", "uplink_probe_recovered"]
        );
        assert!(f.is_empty());
        // a probe that vanishes while failing is dropped silently
        probe_events(&mut f, &bad, 160);
        assert!(!f.is_empty());
        assert!(probe_events(&mut f, &[], 175).is_empty());
        assert!(f.is_empty());
    }

    #[test]
    fn sla_breach_and_recovery_events() {
        let row = |g: &str, a: Option<f64>| Sla {
            gateway: g.into(),
            samples: 100,
            availability_pct: a,
            quality_pct: a,
            down_minutes: 3,
            degraded_minutes: 0,
            rtt_avg_ms: None,
            rtt_max_ms: None,
            loss_avg_pct: None,
        };
        let mut b = HashSet::new();
        assert!(
            sla_events(&mut b, &[row("A", Some(50.0))], 0.0, "24 h", 1).is_empty(),
            "target 0 = off"
        );
        let e = sla_events(
            &mut b,
            &[row("A", Some(99.0)), row("B", Some(100.0)), row("C", None)],
            99.5,
            "24 h",
            2,
        );
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].kind.as_str(), e[0].subject.as_str()),
            ("uplink_sla_breach", "A")
        );
        assert!(
            e[0].detail.contains("99.00%") && e[0].detail.contains("99.50%"),
            "{}",
            e[0].detail
        );
        assert!(
            sla_events(&mut b, &[row("A", Some(99.0))], 99.5, "24 h", 3).is_empty(),
            "once"
        );
        let e = sla_events(&mut b, &[row("A", Some(99.5))], 99.5, "24 h", 4);
        assert_eq!(
            e[0].kind, "uplink_sla_ok",
            "exactly at the target is within it"
        );
        assert!(sla_events(&mut b, &[row("A", Some(99.9))], 99.5, "24 h", 5).is_empty());
    }

    async fn with_gateways(s: &ConfigStore) {
        sqlx::query("INSERT INTO route_gateways (name, interface, family, monitor_enabled, loss_threshold, latency_threshold, updated_at) VALUES ('WAN','@wan','inet',1,20,500,0),('LTE','opt1','inet',1,20,500,0)")
            .execute(s.pool().unwrap()).await.unwrap();
    }

    #[tokio::test]
    async fn probe_crud_validates_and_deduplicates() {
        let s = store().await;
        with_gateways(&s).await;
        let id = save_probe(
            &s,
            None,
            "WAN",
            "dns",
            "1.1.1.1",
            None,
            "example.com",
            true,
            true,
        )
        .await
        .unwrap();
        let l = list_probes(&s).await;
        assert_eq!(l.len(), 1);
        assert_eq!(
            (l[0].kind, l[0].port, l[0].critical, l[0].name.as_str()),
            (ProbeKind::Dns, Some(53), true, "example.com")
        );
        let e = save_probe(
            &s,
            None,
            "WAN",
            "dns",
            "1.1.1.1",
            None,
            "example.com",
            false,
            true,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(e.contains("already exists"), "{e}");
        save_probe(
            &s,
            None,
            "LTE",
            "dns",
            "1.1.1.1",
            None,
            "example.com",
            false,
            true,
        )
        .await
        .unwrap();
        for (gw, kind, target, port) in [
            ("NOPE", "tcp", "1.1.1.1", Some(443)),
            ("WAN", "icmp", "1.1.1.1", None),
            ("WAN", "tcp", "1.1.1.1", None),
            ("WAN", "tcp", "not-an-ip", Some(80)),
            ("WAN", "http", "ftp://x", None),
        ] {
            let e = save_probe(&s, None, gw, kind, target, port, "", false, true)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("Invalid"), "{gw} {kind}: {e}");
        }
        save_probe(
            &s,
            Some(id),
            "WAN",
            "dns",
            "9.9.9.9",
            None,
            "example.org",
            false,
            false,
        )
        .await
        .unwrap();
        let l = list_probes(&s).await;
        let me = l.iter().find(|p| p.id == id).unwrap();
        assert_eq!(
            (me.target.as_str(), me.critical, me.enabled),
            ("9.9.9.9", false, false)
        );
        assert!(save_probe(
            &s,
            Some(999),
            "WAN",
            "tcp",
            "1.1.1.1",
            Some(443),
            "",
            false,
            true
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("not found"));
        delete_probe(&s, id).await.unwrap();
        assert!(delete_probe(&s, id)
            .await
            .unwrap_err()
            .to_string()
            .contains("not found"));
        assert_eq!(list_probes(&s).await.len(), 1);
    }
}
