//! UPS history and power events (USE=ups).
//!
//! Every `PATRONUS_UPS_TICK_SECS` (default `ups.poll_secs`, 5 s; never more
//! often than 2 s) the recorder asks upsd (`upsc`) and
//!
//! - stores one row per tick in `ups_samples` when the reading changed
//!   enough to matter or a minute passed (a steady UPS is one row a minute,
//!   an outage is a row per tick),
//! - raises events through the normal event log and webhooks: `ups_on_battery`,
//!   `ups_online`, `ups_low_battery`, `ups_replace_battery`, `ups_unreachable`,
//!   `ups_reachable`,
//! - prunes samples past `ups.retention_days` (default 30) hourly.
//!
//! Event decisions are a pure function of (previous look, this look), so a
//! restart does not repeat an alert and the first look after boot only
//! reports a problem (like the gateway watcher).

use super::telemetry::{self, Event};
use patronus_config::ConfigStore;
use patronus_network::ups::{self, Cfg, Outcome, PowerState, Snapshot};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};

const SAMPLE_EVERY_SECS: i64 = 60;

fn pool(store: &ConfigStore) -> anyhow::Result<&SqlitePool> {
    store.pool().map_err(|e| anyhow::anyhow!("{e}"))
}

/// What the recorder remembers between looks.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Look {
    pub reachable: Option<bool>,
    pub state: Option<PowerState>,
    pub replace: bool,
}

fn event(kind: &str, sev: &str, name: &str, detail: String, now: i64) -> Event {
    Event {
        id: 0,
        ts: now,
        kind: kind.into(),
        subject: format!("ups:{name}"),
        severity: sev.into(),
        detail,
    }
}

fn describe(s: &Snapshot) -> String {
    let mut p = Vec::new();
    if let Some(c) = s.charge_pct {
        p.push(format!("battery {c:.0}%"));
    }
    if let Some(r) = s.runtime_secs {
        p.push(format!("about {} min left", (r + 30) / 60));
    }
    if let Some(l) = s.load_pct {
        p.push(format!("load {l:.0}%"));
    }
    if p.is_empty() {
        "no battery data".into()
    } else {
        p.join(", ")
    }
}

/// The events for going from `prev` to `outcome`; updates `prev`.
pub fn events_for(prev: &mut Look, name: &str, outcome: &Outcome, now: i64) -> Vec<Event> {
    let mut out = Vec::new();
    match outcome {
        Outcome::Reading(s) => {
            if prev.reachable == Some(false) {
                out.push(event(
                    "ups_reachable",
                    "info",
                    name,
                    "the UPS answers again".into(),
                    now,
                ));
            }
            prev.reachable = Some(true);
            let was = prev.state;
            if was != Some(s.state) {
                let first = was.is_none();
                match s.state {
                    PowerState::LowBattery => out.push(event(
                        "ups_low_battery",
                        "critical",
                        name,
                        format!("on battery and the battery is low ({}); shutdown follows", describe(s)),
                        now,
                    )),
                    PowerState::OnBattery => out.push(event(
                        "ups_on_battery",
                        "warning",
                        name,
                        format!("mains power failed; running on battery ({})", describe(s)),
                        now,
                    )),
                    PowerState::Online if !first => out.push(event(
                        "ups_online",
                        "info",
                        name,
                        format!("mains power is back ({})", describe(s)),
                        now,
                    )),
                    _ => {}
                }
                prev.state = Some(s.state);
            }
            if s.replace_battery && !prev.replace {
                out.push(event(
                    "ups_replace_battery",
                    "warning",
                    name,
                    "the UPS asks for a new battery".into(),
                    now,
                ));
            }
            prev.replace = s.replace_battery;
        }
        Outcome::NoUps(why) | Outcome::Unreachable(why) => {
            if prev.reachable != Some(false) {
                out.push(event(
                    "ups_unreachable",
                    "warning",
                    name,
                    format!("no UPS data: {why}"),
                    now,
                ));
            }
            prev.reachable = Some(false);
        }
    }
    out
}

/// Store a sample unless the last one is recent and unchanged.
pub async fn record_sample(
    store: &ConfigStore,
    name: &str,
    s: &Snapshot,
    now: i64,
) -> anyhow::Result<bool> {
    let p = pool(store)?;
    if let Some(r) = sqlx::query("SELECT ts, state, charge_pct FROM ups_samples WHERE ups = ? ORDER BY ts DESC LIMIT 1")
        .bind(name)
        .fetch_optional(p)
        .await?
    {
        let (ts, state, charge): (i64, String, Option<f64>) = (r.get(0), r.get(1), r.get(2));
        let same = state == s.state.as_str() && charge == s.charge_pct;
        if same && now - ts < SAMPLE_EVERY_SECS {
            return Ok(false);
        }
    }
    sqlx::query(
        "INSERT OR REPLACE INTO ups_samples (ts, ups, state, flags, charge_pct, runtime_s, load_pct, input_v, output_v, battery_v)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(now)
    .bind(name)
    .bind(s.state.as_str())
    .bind(s.flags.join(" "))
    .bind(s.charge_pct)
    .bind(s.runtime_secs)
    .bind(s.load_pct)
    .bind(s.input_voltage)
    .bind(s.output_voltage)
    .bind(s.battery_voltage)
    .execute(p)
    .await?;
    Ok(true)
}

pub async fn prune(store: &ConfigStore, days: i64, now: i64) -> anyhow::Result<u64> {
    let cut = now - days.clamp(1, 365) * 86_400;
    Ok(sqlx::query("DELETE FROM ups_samples WHERE ts < ?")
        .bind(cut)
        .execute(pool(store)?)
        .await?
        .rows_affected())
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Sample {
    pub ts: i64,
    pub ups: String,
    pub state: String,
    pub flags: String,
    pub charge_pct: Option<f64>,
    pub runtime_s: Option<i64>,
    pub load_pct: Option<f64>,
    pub input_v: Option<f64>,
    pub output_v: Option<f64>,
    pub battery_v: Option<f64>,
}

/// Samples of the last `secs` seconds, oldest first, at most `limit`
/// (the newest ones when there are more).
pub async fn history(
    store: &ConfigStore,
    now: i64,
    secs: i64,
    limit: i64,
) -> anyhow::Result<Vec<Sample>> {
    let rows = sqlx::query(
        "SELECT ts, ups, state, flags, charge_pct, runtime_s, load_pct, input_v, output_v, battery_v
         FROM ups_samples WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
    )
    .bind(now - secs)
    .bind(limit.clamp(1, 20_000))
    .fetch_all(pool(store)?)
    .await?;
    let mut v: Vec<Sample> = rows
        .iter()
        .map(|r| Sample {
            ts: r.get(0),
            ups: r.get(1),
            state: r.get(2),
            flags: r.get(3),
            charge_pct: r.get(4),
            runtime_s: r.get(5),
            load_pct: r.get(6),
            input_v: r.get(7),
            output_v: r.get(8),
            battery_v: r.get(9),
        })
        .collect();
    v.reverse();
    Ok(v)
}

/// The document of `GET /api/ups`: the live status plus the recent events.
pub async fn document(store: &ConfigStore) -> anyhow::Result<Value> {
    let mut d = ups::status_document(store).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = sqlx::query(
        "SELECT id, ts, kind, subject, severity, detail FROM system_events
         WHERE substr(kind, 1, 4) = 'ups_' ORDER BY id DESC LIMIT 20",
    )
    .fetch_all(pool(store)?)
    .await?;
    let recent: Vec<Event> = rows
        .iter()
        .map(|r| Event {
            id: r.get(0),
            ts: r.get(1),
            kind: r.get(2),
            subject: r.get(3),
            severity: r.get(4),
            detail: r.get(5),
        })
        .collect();
    d["events"] = json!(recent);
    Ok(d)
}

pub fn spawn_recorder(state: super::AppState) {
    let forced = std::env::var("PATRONUS_UPS_TICK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0);
    tokio::spawn(async move {
        let mut look = Look::default();
        let mut last_prune = 0;
        loop {
            let store = state.config_store.clone();
            let mut wait = forced.unwrap_or(5);
            if let Ok(c) = Cfg::load(&store).await {
                if forced.is_none() {
                    wait = (c.poll_secs.max(2)) as u64;
                }
                if c.enabled && ups::find_bin("upsc").is_some() {
                    let now = chrono::Utc::now().timestamp();
                    let (host, port, name) = c.target();
                    let outcome = ups::query(&host, port, &name).await;
                    if let Outcome::Reading(s) = &outcome {
                        if let Err(e) = record_sample(&store, &name, s, now).await {
                            tracing::warn!("ups recorder: {e}");
                        }
                    }
                    for mut e in events_for(&mut look, &name, &outcome, now) {
                        match telemetry::record(&store, &e).await {
                            Ok(id) => e.id = id,
                            Err(err) => tracing::warn!("recording event {}: {err}", e.kind),
                        }
                        telemetry::deliver(store.clone(), e).await;
                    }
                    if now - last_prune > 3600 {
                        last_prune = now;
                        if let Err(e) = prune(&store, c.retention_days, now).await {
                            tracing::warn!("ups prune: {e}");
                        }
                    }
                } else {
                    look = Look::default();
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_network::ups::interpret;

    const ONLINE: &str = include_str!("../../../patronus-network/tests/fixtures/ups/online.txt");
    const BATT: &str = include_str!("../../../patronus-network/tests/fixtures/ups/on_battery.txt");
    const LOW: &str = include_str!("../../../patronus-network/tests/fixtures/ups/low_battery.txt");
    const REPL: &str = include_str!("../../../patronus-network/tests/fixtures/ups/replace_battery.txt");
    const REFUSED: &str = include_str!("../../../patronus-network/tests/fixtures/ups/no_ups_refused.txt");

    fn kinds(v: &[Event]) -> Vec<&str> {
        v.iter().map(|e| e.kind.as_str()).collect()
    }

    #[test]
    fn outage_sequence_raises_each_event_once() {
        let mut l = Look::default();
        assert!(events_for(&mut l, "ups", &interpret(ONLINE), 1).is_empty(), "boot while online is not news");
        assert!(events_for(&mut l, "ups", &interpret(ONLINE), 2).is_empty());
        let e = events_for(&mut l, "ups", &interpret(BATT), 3);
        assert_eq!(kinds(&e), ["ups_on_battery"]);
        assert_eq!(e[0].severity, "warning");
        assert!(e[0].detail.contains("71%"), "{}", e[0].detail);
        assert!(events_for(&mut l, "ups", &interpret(BATT), 4).is_empty());
        let e = events_for(&mut l, "ups", &interpret(LOW), 5);
        assert_eq!(kinds(&e), ["ups_low_battery"]);
        assert_eq!(e[0].severity, "critical");
        assert_eq!(e[0].subject, "ups:ups");
        let e = events_for(&mut l, "ups", &interpret(REPL), 6);
        assert_eq!(kinds(&e), ["ups_online", "ups_replace_battery"]);
        assert!(events_for(&mut l, "ups", &interpret(REPL), 7).is_empty());
    }

    #[test]
    fn booting_on_battery_alerts_and_unreachable_is_reported_once() {
        let mut l = Look::default();
        assert_eq!(kinds(&events_for(&mut l, "ups", &interpret(BATT), 1)), ["ups_on_battery"]);
        let mut l = Look::default();
        let down = interpret(REFUSED);
        assert_eq!(kinds(&events_for(&mut l, "ups", &down, 1)), ["ups_unreachable"]);
        assert!(events_for(&mut l, "ups", &down, 2).is_empty());
        assert_eq!(kinds(&events_for(&mut l, "ups", &interpret(ONLINE), 3)), ["ups_reachable"]);
    }

    #[tokio::test]
    async fn samples_are_thinned_pruned_and_read_back() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let on = match interpret(ONLINE) { Outcome::Reading(s) => s, o => panic!("{o:?}") };
        let batt = match interpret(BATT) { Outcome::Reading(s) => s, o => panic!("{o:?}") };
        assert!(record_sample(&store, "ups", &on, 1000).await.unwrap());
        assert!(!record_sample(&store, "ups", &on, 1005).await.unwrap(), "unchanged within a minute");
        assert!(record_sample(&store, "ups", &batt, 1010).await.unwrap(), "state change is stored at once");
        assert!(record_sample(&store, "ups", &batt, 1100).await.unwrap(), "a minute later");
        let h = history(&store, 1100, 3600, 100).await.unwrap();
        assert_eq!(h.iter().map(|s| s.ts).collect::<Vec<_>>(), [1000, 1010, 1100]);
        assert_eq!(h[1].state, "on_battery");
        assert_eq!(h[1].charge_pct, Some(71.0));
        assert_eq!(h[0].runtime_s, Some(2610));
        assert_eq!(history(&store, 1100, 3600, 2).await.unwrap().len(), 2);
        assert_eq!(prune(&store, 1, 1000 + 86_400 + 50).await.unwrap(), 1);
        assert_eq!(history(&store, 1100, 99_999, 100).await.unwrap().len(), 2);
    }
}
