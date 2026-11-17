//! Historical statistics (lane H): CPU, memory and per-interface throughput
//! history for graphs (RRD-style, 5-minute averages), and per-interface
//! daily traffic totals for monthly data accounting (vnStat-style) with an
//! optional data cap that raises `data_cap` events (sent to the notification
//! channels like every other event).
//!
//! A sampler reads /proc/stat, /proc/meminfo and /proc/net/dev every tick
//! (60 s; `PATRONUS_STATS_TICK_SECS` for tests), keeps the samples of the
//! current bucket in memory and writes one averaged point per metric per
//! bucket (5 ticks). Counter deltas are added to `traffic_daily` every tick,
//! so a restart loses at most one tick of traffic. Counter resets (reboot,
//! interface re-created) count the new value as the delta.

use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const CFG_MONTH_START: &str = "stats.month_start_day";
pub const CFG_CAP_GB: &str = "stats.cap_gb";
pub const CFG_CAP_IFACE: &str = "stats.cap_interface";
pub const CFG_RETENTION_DAYS: &str = "stats.retention_days";
/// Last cap level announced, `YYYY-MM-DD:<pct>` (month start + 80 / 100).
pub const CFG_CAP_NOTIFIED: &str = "stats.cap_notified";

pub const BUCKET_TICKS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Day of the month the data allowance resets (1-28).
    pub month_start_day: u32,
    /// Monthly allowance in GB (10^9 bytes), 0 = none.
    pub cap_gb: f64,
    /// Interface the allowance counts (empty = every interface named like
    /// the WAN role, i.e. the caller passes it; default the busiest).
    pub cap_interface: String,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsInput {
    pub month_start_day: Option<u32>,
    pub cap_gb: Option<f64>,
    pub cap_interface: Option<String>,
    pub retention_days: Option<u32>,
}

fn e(x: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{x}")
}

pub async fn settings(store: &ConfigStore) -> anyhow::Result<Settings> {
    let get = |k: &'static str| async move { store.load_system_config(k).await.map_err(e) };
    let num = |v: Option<String>| v.and_then(|s| s.trim().parse::<f64>().ok());
    Ok(Settings {
        month_start_day: num(get(CFG_MONTH_START).await?)
            .map(|v| v as u32)
            .unwrap_or(1),
        cap_gb: num(get(CFG_CAP_GB).await?).unwrap_or(0.0),
        cap_interface: get(CFG_CAP_IFACE).await?.unwrap_or_default(),
        retention_days: num(get(CFG_RETENTION_DAYS).await?)
            .map(|v| v as u32)
            .unwrap_or(30),
    })
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

pub async fn save_settings(store: &ConfigStore, i: &SettingsInput) -> anyhow::Result<Settings> {
    let mut kv: Vec<(&str, String)> = Vec::new();
    if let Some(d) = i.month_start_day {
        if !(1..=28).contains(&d) {
            anyhow::bail!("Invalid month start day: 1 to 28");
        }
        kv.push((CFG_MONTH_START, d.to_string()));
    }
    if let Some(c) = i.cap_gb {
        if !(0.0..=1_000_000.0).contains(&c) || !c.is_finite() {
            anyhow::bail!("Invalid data cap: 0 (none) to 1000000 GB");
        }
        kv.push((CFG_CAP_GB, c.to_string()));
    }
    if let Some(n) = &i.cap_interface {
        let n = n.trim();
        if !n.is_empty() && !valid_ifname(n) {
            anyhow::bail!("Invalid interface name {n:?}");
        }
        kv.push((CFG_CAP_IFACE, n.to_string()));
    }
    if let Some(r) = i.retention_days {
        if !(1..=400).contains(&r) {
            anyhow::bail!("Invalid retention: 1 to 400 days");
        }
        kv.push((CFG_RETENTION_DAYS, r.to_string()));
    }
    for (k, v) in kv {
        store.save_system_config(k, &v).await.map_err(e)?;
    }
    settings(store).await
}

// ---------------------------------------------------------------------------
// readers
// ---------------------------------------------------------------------------

/// `/proc/net/dev` -> name -> (rx bytes, tx bytes), loopback excluded.
pub fn parse_net_dev(s: &str) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    for l in s.lines().skip(2) {
        let Some((name, rest)) = l.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if f.len() >= 9 {
            out.insert(name.to_string(), (f[0], f[8]));
        }
    }
    out
}

/// `/proc/stat` first line -> (busy, total) jiffies.
pub fn parse_cpu(s: &str) -> Option<(u64, u64)> {
    let l = s.lines().next()?;
    let v: Vec<u64> = l
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() < 4 {
        return None;
    }
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some((total - idle, total))
}

/// `/proc/meminfo` -> used percent (MemTotal - MemAvailable).
pub fn parse_mem(s: &str) -> Option<f64> {
    let get = |k: &str| {
        s.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<f64>().ok())
    };
    let (t, a) = (get("MemTotal:")?, get("MemAvailable:")?);
    (t > 0.0).then(|| ((t - a) / t * 1000.0).round() / 10.0)
}

/// Bytes moved since the previous reading (a smaller value = counter reset).
pub fn delta(prev: u64, cur: u64) -> u64 {
    if cur >= prev {
        cur - prev
    } else {
        cur
    }
}

// ---------------------------------------------------------------------------
// month arithmetic
// ---------------------------------------------------------------------------

/// First day of the accounting month that contains `day`.
pub fn period_start(day: chrono::NaiveDate, start_day: u32) -> chrono::NaiveDate {
    use chrono::Datelike;
    let sd = start_day.clamp(1, 28);
    if day.day() >= sd {
        day.with_day(sd).unwrap_or(day)
    } else {
        let (y, m) = if day.month() == 1 {
            (day.year() - 1, 12)
        } else {
            (day.year(), day.month() - 1)
        };
        chrono::NaiveDate::from_ymd_opt(y, m, sd).unwrap_or(day)
    }
}

/// Which cap level (0, 80, 100) `used` of `cap` bytes has reached.
pub fn cap_level(used: u64, cap: u64) -> u32 {
    if cap == 0 {
        0
    } else if used >= cap {
        100
    } else if used * 10 >= cap * 8 {
        80
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Point {
    pub ts: i64,
    pub value: f64,
}

/// Metrics with points newer than `since`.
pub async fn metrics(store: &ConfigStore, since: i64) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query("SELECT DISTINCT metric FROM stat_points WHERE ts >= ? ORDER BY metric")
        .bind(since)
        .fetch_all(store.pool().map_err(e)?)
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

pub async fn series(store: &ConfigStore, metric: &str, since: i64) -> anyhow::Result<Vec<Point>> {
    let rows =
        sqlx::query("SELECT ts, value FROM stat_points WHERE metric = ? AND ts >= ? ORDER BY ts")
            .bind(metric)
            .bind(since)
            .fetch_all(store.pool().map_err(e)?)
            .await?;
    Ok(rows
        .iter()
        .map(|r| Point {
            ts: r.get(0),
            value: r.get(1),
        })
        .collect())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Usage {
    pub iface: String,
    pub rx: u64,
    pub tx: u64,
}

/// Per-interface totals from `from` (inclusive) to `to` (exclusive).
pub async fn usage(
    store: &ConfigStore,
    from: chrono::NaiveDate,
    to: chrono::NaiveDate,
) -> anyhow::Result<Vec<Usage>> {
    let rows = sqlx::query(
        "SELECT iface, SUM(rx), SUM(tx) FROM traffic_daily WHERE day >= ? AND day < ?
         GROUP BY iface ORDER BY SUM(rx) + SUM(tx) DESC",
    )
    .bind(from.to_string())
    .bind(to.to_string())
    .fetch_all(store.pool().map_err(e)?)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Usage {
            iface: r.get(0),
            rx: r.get::<i64, _>(1) as u64,
            tx: r.get::<i64, _>(2) as u64,
        })
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct Period {
    pub start: String,
    pub end: String,
    pub usage: Vec<Usage>,
}

/// The current accounting month and the `n - 1` before it.
pub async fn periods(store: &ConfigStore, n: usize) -> anyhow::Result<Vec<Period>> {
    use chrono::Months;
    let s = settings(store).await?;
    let today = chrono::Utc::now().date_naive();
    let mut start = period_start(today, s.month_start_day);
    let mut out = Vec::new();
    for _ in 0..n.max(1) {
        let end = start + Months::new(1);
        out.push(Period {
            start: start.to_string(),
            end: end.to_string(),
            usage: usage(store, start, end).await?,
        });
        start = start - Months::new(1);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// sampler
// ---------------------------------------------------------------------------

/// Per-interface (rx, tx) byte deltas of one tick.
pub type Deltas = BTreeMap<String, (u64, u64)>;
/// Averaged (metric, value) points of a closed bucket.
pub type Points = Vec<(String, f64)>;

#[derive(Default)]
pub struct Sampler {
    cpu: Option<(u64, u64)>,
    net: BTreeMap<String, (u64, u64)>,
    last_ts: Option<f64>,
    acc: BTreeMap<String, (f64, u32)>,
    ticks: u32,
}

impl Sampler {
    /// One tick: `now` in seconds, the three /proc files. Returns
    /// (per-interface byte deltas, averaged points when a bucket closed).
    pub fn tick(&mut self, now: f64, stat: &str, meminfo: &str, net_dev: &str) -> (Deltas, Points) {
        let mut add = |k: String, v: f64| {
            let a = self.acc.entry(k).or_insert((0.0, 0));
            a.0 += v;
            a.1 += 1;
        };
        if let (Some((b0, t0)), Some((b1, t1))) = (self.cpu, parse_cpu(stat)) {
            if t1 > t0 {
                add(
                    "cpu".into(),
                    ((b1 - b0) as f64 / (t1 - t0) as f64 * 1000.0).round() / 10.0,
                );
            }
        }
        self.cpu = parse_cpu(stat);
        if let Some(m) = parse_mem(meminfo) {
            add("mem".into(), m);
        }
        let cur = parse_net_dev(net_dev);
        let mut deltas = BTreeMap::new();
        let dt = self.last_ts.map(|t| now - t).filter(|d| *d > 0.0);
        for (name, &(rx, tx)) in &cur {
            if let Some(&(prx, ptx)) = self.net.get(name) {
                let (dr, dtx) = (delta(prx, rx), delta(ptx, tx));
                deltas.insert(name.clone(), (dr, dtx));
                if let Some(dt) = dt {
                    add(format!("rx:{name}"), dr as f64 * 8.0 / dt);
                    add(format!("tx:{name}"), dtx as f64 * 8.0 / dt);
                }
            }
        }
        self.net = cur;
        self.last_ts = Some(now);
        self.ticks += 1;
        let mut points = Vec::new();
        if self.ticks >= BUCKET_TICKS {
            self.ticks = 0;
            for (k, (sum, n)) in std::mem::take(&mut self.acc) {
                if n > 0 {
                    points.push((k, (sum / n as f64 * 100.0).round() / 100.0));
                }
            }
        }
        (deltas, points)
    }
}

async fn write_tick(
    store: &ConfigStore,
    now: i64,
    deltas: &BTreeMap<String, (u64, u64)>,
    points: &[(String, f64)],
) -> anyhow::Result<()> {
    let pool = store.pool().map_err(e)?;
    let day = chrono::DateTime::from_timestamp(now, 0)
        .unwrap_or_default()
        .date_naive()
        .to_string();
    let mut tx = pool.begin().await?;
    for (iface, (rx, txb)) in deltas {
        if *rx == 0 && *txb == 0 {
            continue;
        }
        sqlx::query(
            "INSERT INTO traffic_daily (day, iface, rx, tx) VALUES (?,?,?,?)
             ON CONFLICT(day, iface) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx",
        )
        .bind(&day)
        .bind(iface)
        .bind(*rx as i64)
        .bind(*txb as i64)
        .execute(&mut *tx)
        .await?;
    }
    for (m, v) in points {
        sqlx::query("INSERT INTO stat_points (ts, metric, value) VALUES (?,?,?)")
            .bind(now)
            .bind(m)
            .bind(v)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn prune(store: &ConfigStore, retention_days: u32, now: i64) -> anyhow::Result<()> {
    let pool = store.pool().map_err(e)?;
    sqlx::query("DELETE FROM stat_points WHERE ts < ?")
        .bind(now - retention_days as i64 * 86400)
        .execute(pool)
        .await?;
    // daily totals are small: keep two years
    let cutoff = chrono::DateTime::from_timestamp(now - 730 * 86400, 0)
        .unwrap_or_default()
        .date_naive()
        .to_string();
    sqlx::query("DELETE FROM traffic_daily WHERE day < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(())
}

/// Raise a `data_cap` event once per level (80 %, 100 %) and month.
async fn check_cap(store: &Arc<ConfigStore>) -> anyhow::Result<()> {
    let s = settings(store).await?;
    if s.cap_gb <= 0.0 {
        return Ok(());
    }
    let today = chrono::Utc::now().date_naive();
    let start = period_start(today, s.month_start_day);
    let all = usage(store, start, today + chrono::Days::new(1)).await?;
    let pick = if s.cap_interface.is_empty() {
        all.first()
    } else {
        all.iter().find(|u| u.iface == s.cap_interface)
    };
    let Some(u) = pick else { return Ok(()) };
    let used = u.rx + u.tx;
    let cap = (s.cap_gb * 1e9) as u64;
    let level = cap_level(used, cap);
    if level == 0 {
        return Ok(());
    }
    let key = format!("{start}:{level}");
    let prev = store
        .load_system_config(CFG_CAP_NOTIFIED)
        .await
        .map_err(e)?;
    let prev_level = prev
        .as_deref()
        .and_then(|p| p.strip_prefix(&format!("{start}:")))
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(0);
    if level <= prev_level {
        return Ok(());
    }
    store
        .save_system_config(CFG_CAP_NOTIFIED, &key)
        .await
        .map_err(e)?;
    let ev = crate::state::telemetry::Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: "data_cap".into(),
        subject: u.iface.clone(),
        severity: if level >= 100 { "critical" } else { "warning" }.into(),
        detail: format!(
            "{:.2} GB of the {} GB monthly allowance used on {} ({}%) since {start}",
            used as f64 / 1e9,
            s.cap_gb,
            u.iface,
            used * 100 / cap.max(1)
        ),
    };
    crate::state::telemetry::record(store, &ev).await?;
    crate::state::telemetry::deliver(store.clone(), ev).await;
    Ok(())
}

fn tick_secs() -> u64 {
    std::env::var("PATRONUS_STATS_TICK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| (1..=3600).contains(v))
        .unwrap_or(60)
}

pub fn spawn_sampler(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        let mut s = Sampler::default();
        let mut t = tokio::time::interval(std::time::Duration::from_secs(tick_secs()));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut n: u64 = 0;
        loop {
            t.tick().await;
            let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
            let now = chrono::Utc::now();
            let secs = now.timestamp_millis() as f64 / 1000.0;
            let (deltas, points) = s.tick(
                secs,
                &rd("/proc/stat"),
                &rd("/proc/meminfo"),
                &rd("/proc/net/dev"),
            );
            if let Err(err) = write_tick(&store, now.timestamp(), &deltas, &points).await {
                tracing::warn!("statistics: {err}");
            }
            if let Err(err) = check_cap(&store).await {
                tracing::warn!("data cap check: {err}");
            }
            n += 1;
            if n % 60 == 1 {
                let r = settings(&store)
                    .await
                    .map(|s| s.retention_days)
                    .unwrap_or(30);
                let _ = prune(&store, r, now.timestamp()).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV1: &str = "Inter-|   Receive |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
    const DEV2: &str = "Inter-|   Receive |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 900 9 0 0 0 0 0 0 900 9 0 0 0 0 0 0\n  eth0: 76000 10 0 0 0 0 0 0 2500 20 0 0 0 0 0 0\n";

    #[test]
    fn parsers() {
        let d = parse_net_dev(DEV1);
        assert_eq!(d.get("eth0"), Some(&(1000, 2000)));
        assert!(!d.contains_key("lo"));
        assert_eq!(
            parse_cpu("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1"),
            Some((200, 1000))
        );
        assert_eq!(
            parse_mem("MemTotal: 1000 kB\nMemFree: 1 kB\nMemAvailable: 250 kB\n"),
            Some(75.0)
        );
        assert_eq!(delta(10, 15), 5);
        assert_eq!(delta(10, 3), 3);
    }

    #[test]
    fn sampler_buckets_and_rates() {
        let mut s = Sampler::default();
        let mem = "MemTotal: 1000 kB\nMemAvailable: 500 kB\n";
        let (d, p) = s.tick(0.0, "cpu 0 0 0 100 0", mem, DEV1);
        assert!(d.is_empty() && p.is_empty());
        let (d, _) = s.tick(10.0, "cpu 50 0 0 150 0", mem, DEV2);
        assert_eq!(d.get("eth0"), Some(&(75000, 500)));
        for i in 2..BUCKET_TICKS {
            let (_, p) = s.tick(10.0 * (i as f64 + 1.0), "cpu 50 0 0 150 0", mem, DEV2);
            if i + 1 < BUCKET_TICKS {
                assert!(p.is_empty());
            } else {
                let m: BTreeMap<_, _> = p.into_iter().collect();
                assert_eq!(m["mem"], 50.0);
                // one tick at 60000 bit/s, the rest idle
                assert_eq!(m["rx:eth0"], 60000.0 / (BUCKET_TICKS - 1) as f64);
                assert!(m.contains_key("cpu"));
            }
        }
    }

    #[test]
    fn months_and_caps() {
        let d = |y, m, dd| chrono::NaiveDate::from_ymd_opt(y, m, dd).unwrap();
        assert_eq!(period_start(d(2026, 11, 17), 1), d(2026, 11, 1));
        assert_eq!(period_start(d(2026, 11, 17), 20), d(2026, 10, 20));
        assert_eq!(period_start(d(2026, 1, 5), 15), d(2025, 12, 15));
        assert_eq!(period_start(d(2026, 3, 15), 15), d(2026, 3, 15));
        assert_eq!(cap_level(79, 100), 0);
        assert_eq!(cap_level(80, 100), 80);
        assert_eq!(cap_level(100, 100), 100);
        assert_eq!(cap_level(5, 0), 0);
    }
}
