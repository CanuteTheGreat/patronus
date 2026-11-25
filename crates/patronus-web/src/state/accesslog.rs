//! Web/API access log (`web_access_log`) with statistics, and the
//! configuration-change (audit) log reader.
//!
//! One row per answered request: time, client address, principal (account,
//! API key or anonymous), method, PATH GROUP (the matched route template,
//! never a raw path, id, query string or token), status, duration and body
//! size. Failed sign-ins carry the attempted account name.
//!
//! Writing is off the request path: the middleware pushes an [`Entry`] into
//! a bounded channel (a full queue drops the entry and counts it, a request
//! never waits) and one writer task inserts batches in a single transaction
//! every `flush_ms`, then enforces the row and age caps. The same task
//! watches for bursts (failed sign-ins, 5xx answers) and records
//! `system_events` so notification channels can route them.
//!
//! Every operational value is a typed setting (`accesslog.*` in the config
//! store, so export/plan/apply carry them). Layers, low to high: built-in
//! default, environment (`PATRONUS_ACCESS_LOG_*`, how an image such as the
//! router tier ships smaller caps), config store.

use crate::state::telemetry;
use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, Sqlite};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub const PATH_UNMATCHED: &str = "(unmatched)";
pub const LOGIN_GROUP: &str = "/api/auth/login";

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

pub const K_ENABLED: &str = "accesslog.enabled";
pub const K_ROWS: &str = "accesslog.retention_rows";
pub const K_DAYS: &str = "accesslog.retention_days";
pub const K_FLUSH_MS: &str = "accesslog.flush_ms";
pub const K_QUEUE: &str = "accesslog.queue";
pub const K_LOGIN_BURST: &str = "accesslog.login_burst";
pub const K_LOGIN_WINDOW: &str = "accesslog.login_window_secs";
pub const K_ERROR_BURST: &str = "accesslog.error_burst";
pub const K_ERROR_WINDOW: &str = "accesslog.error_window_secs";
pub const K_COOLDOWN: &str = "accesslog.event_cooldown_secs";
pub const KEYS: &[&str] = &[
    K_ENABLED,
    K_ROWS,
    K_DAYS,
    K_FLUSH_MS,
    K_QUEUE,
    K_LOGIN_BURST,
    K_LOGIN_WINDOW,
    K_ERROR_BURST,
    K_ERROR_WINDOW,
    K_COOLDOWN,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    /// Keep at most this many rows (newest win).
    pub retention_rows: i64,
    /// Keep rows at most this many days.
    pub retention_days: i64,
    /// How often the writer inserts the queued rows.
    pub flush_ms: i64,
    /// Queue length between the requests and the writer (read at start).
    pub queue: i64,
    /// Failed sign-ins within `login_window_secs` that raise an event (0 = off).
    pub login_burst: i64,
    pub login_window_secs: i64,
    /// 5xx answers within `error_window_secs` that raise an event (0 = off).
    pub error_burst: i64,
    pub error_window_secs: i64,
    /// Minimum seconds between two events of the same kind.
    pub event_cooldown_secs: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_rows: 100_000,
            retention_days: 30,
            flush_ms: 1000,
            queue: 4096,
            login_burst: 10,
            login_window_secs: 60,
            error_burst: 20,
            error_window_secs: 60,
            event_cooldown_secs: 300,
        }
    }
}

/// (key, min, max) of the numeric settings.
pub const LIMITS: &[(&str, i64, i64)] = &[
    (K_ROWS, 100, 10_000_000),
    (K_DAYS, 1, 3650),
    (K_FLUSH_MS, 100, 60_000),
    (K_QUEUE, 64, 1_000_000),
    (K_LOGIN_BURST, 0, 100_000),
    (K_LOGIN_WINDOW, 1, 86_400),
    (K_ERROR_BURST, 0, 1_000_000),
    (K_ERROR_WINDOW, 1, 86_400),
    (K_COOLDOWN, 1, 86_400),
];

fn in_range(key: &str, v: i64) -> bool {
    LIMITS
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, lo, hi)| (*lo..=*hi).contains(&v))
        .unwrap_or(false)
}

impl Settings {
    /// Built-in defaults replaced by the environment (`get` = a variable
    /// lookup, for tests). Out-of-range values are ignored.
    pub fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Self {
        let mut s = Self::default();
        let num = |name: &str, key: &str| -> Option<i64> {
            get(name)
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|v| in_range(key, *v))
        };
        if let Some(v) = get("PATRONUS_ACCESS_LOG_ENABLED") {
            s.enabled = !matches!(v.trim(), "0" | "false" | "off" | "no");
        }
        if let Some(v) = num("PATRONUS_ACCESS_LOG_RETENTION_ROWS", K_ROWS) {
            s.retention_rows = v;
        }
        if let Some(v) = num("PATRONUS_ACCESS_LOG_RETENTION_DAYS", K_DAYS) {
            s.retention_days = v;
        }
        if let Some(v) = num("PATRONUS_ACCESS_LOG_FLUSH_MS", K_FLUSH_MS) {
            s.flush_ms = v;
        }
        if let Some(v) = num("PATRONUS_ACCESS_LOG_QUEUE", K_QUEUE) {
            s.queue = v;
        }
        s
    }

    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    fn field(&mut self, key: &str) -> Option<&mut i64> {
        Some(match key {
            K_ROWS => &mut self.retention_rows,
            K_DAYS => &mut self.retention_days,
            K_FLUSH_MS => &mut self.flush_ms,
            K_QUEUE => &mut self.queue,
            K_LOGIN_BURST => &mut self.login_burst,
            K_LOGIN_WINDOW => &mut self.login_window_secs,
            K_ERROR_BURST => &mut self.error_burst,
            K_ERROR_WINDOW => &mut self.error_window_secs,
            K_COOLDOWN => &mut self.event_cooldown_secs,
            _ => return None,
        })
    }
}

/// Effective settings: environment layer, then the store's values.
pub async fn load_settings(store: &ConfigStore) -> Settings {
    let mut s = Settings::from_env();
    if let Ok(Some(v)) = store.load_system_config(K_ENABLED).await {
        s.enabled = v != "0";
    }
    for (key, _, _) in LIMITS {
        if let Ok(Some(v)) = store.load_system_config(key).await {
            if let Some(n) = v.parse::<i64>().ok().filter(|n| in_range(key, *n)) {
                if let Some(f) = s.field(key) {
                    *f = n;
                }
            }
        }
    }
    s
}

/// A partial update, as the API receives it.
#[derive(Debug, Default, Deserialize)]
pub struct SettingsInput {
    pub enabled: Option<bool>,
    pub retention_rows: Option<i64>,
    pub retention_days: Option<i64>,
    pub flush_ms: Option<i64>,
    pub queue: Option<i64>,
    pub login_burst: Option<i64>,
    pub login_window_secs: Option<i64>,
    pub error_burst: Option<i64>,
    pub error_window_secs: Option<i64>,
    pub event_cooldown_secs: Option<i64>,
}

pub async fn save_settings(store: &ConfigStore, i: SettingsInput) -> anyhow::Result<()> {
    let pairs = [
        (K_ROWS, i.retention_rows),
        (K_DAYS, i.retention_days),
        (K_FLUSH_MS, i.flush_ms),
        (K_QUEUE, i.queue),
        (K_LOGIN_BURST, i.login_burst),
        (K_LOGIN_WINDOW, i.login_window_secs),
        (K_ERROR_BURST, i.error_burst),
        (K_ERROR_WINDOW, i.error_window_secs),
        (K_COOLDOWN, i.event_cooldown_secs),
    ];
    for (key, v) in pairs {
        if let Some(v) = v {
            if !in_range(key, v) {
                let (_, lo, hi) = LIMITS.iter().find(|(k, _, _)| *k == key).unwrap();
                anyhow::bail!("Invalid request: {key} is {lo} to {hi}");
            }
        }
    }
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    if let Some(v) = i.enabled {
        store
            .save_system_config(K_ENABLED, if v { "1" } else { "0" })
            .await
            .map_err(e)?;
    }
    for (key, v) in pairs {
        if let Some(v) = v {
            store
                .save_system_config(key, &v.to_string())
                .await
                .map_err(e)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// path grouping, sanitising
// ---------------------------------------------------------------------------

/// The path group of a request: the matched route template. A request no
/// route matched (404s, scanners, anything with an arbitrary path) is
/// `(unmatched)`, never its raw path: raw paths carry ids and tokens. The
/// query string is never an input.
pub fn path_group(matched: Option<&str>) -> String {
    let Some(m) = matched else {
        return PATH_UNMATCHED.to_string();
    };
    let m = m.trim();
    if m.is_empty() || !m.starts_with('/') {
        return PATH_UNMATCHED.to_string();
    }
    // axum names the tail of a nested service `*__private__axum_nest_tail_param`
    let mut g = m.replace("__private__axum_nest_tail_param", "");
    if g.len() > 200 {
        g.truncate(200);
    }
    g
}

/// An account name typed on the login form: bounded, no control characters.
pub fn clean_name(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// entries, the per-request slot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub timestamp_ms: i64,
    pub client: String,
    pub principal_kind: &'static str,
    pub principal_name: Option<String>,
    pub api_key_id: Option<i64>,
    pub attempted_user: Option<String>,
    pub method: String,
    pub path_group: String,
    pub status: u16,
    pub duration_ms: i64,
    pub bytes: Option<i64>,
}

#[derive(Debug, Default, Clone)]
pub struct SlotInner {
    pub principal: Option<(&'static str, String, Option<i64>)>,
    pub attempted_user: Option<String>,
}

/// Filled by the layers inside the access-log middleware (the session gate,
/// the login handler) to say who made the request.
#[derive(Debug, Clone, Default)]
pub struct Slot(Arc<Mutex<SlotInner>>);

impl Slot {
    pub fn user(&self, name: &str) {
        if let Ok(mut g) = self.0.lock() {
            g.principal = Some(("user", clean_name(name), None));
        }
    }
    pub fn api_key(&self, id: i64, name: &str) {
        if let Ok(mut g) = self.0.lock() {
            g.principal = Some(("api_key", clean_name(name), Some(id)));
        }
    }
    pub fn attempted(&self, name: &str) {
        if let Ok(mut g) = self.0.lock() {
            g.attempted_user = Some(clean_name(name));
        }
    }
    pub fn get(&self) -> SlotInner {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// bursts
// ---------------------------------------------------------------------------

/// "N hits within W seconds" detector with a cooldown between firings.
#[derive(Debug, Default)]
pub struct Burst {
    hits: VecDeque<i64>,
    last_fired: Option<i64>,
}

impl Burst {
    /// Record a hit at `ts` (seconds); true when this hit makes `threshold`
    /// hits within `window` seconds and the cooldown has passed.
    pub fn observe(&mut self, ts: i64, threshold: i64, window: i64, cooldown: i64) -> bool {
        self.hits.push_back(ts);
        while self.hits.front().is_some_and(|t| *t <= ts - window) {
            self.hits.pop_front();
        }
        // bounded memory even when the threshold is huge
        while self.hits.len() > 100_000 {
            self.hits.pop_front();
        }
        if threshold <= 0 || (self.hits.len() as i64) < threshold {
            return false;
        }
        if self.last_fired.is_some_and(|f| ts - f < cooldown) {
            return false;
        }
        self.last_fired = Some(ts);
        true
    }

    pub fn count(&self) -> usize {
        self.hits.len()
    }
}

fn is_failed_login(e: &Entry) -> bool {
    e.path_group == LOGIN_GROUP && e.method == "POST" && matches!(e.status, 401 | 403 | 429)
}

// ---------------------------------------------------------------------------
// the writer
// ---------------------------------------------------------------------------

enum Msg {
    Entry(Box<Entry>),
    Flush(oneshot::Sender<()>),
}

/// What the middleware holds: the queue and two counters.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::Sender<Msg>,
    enabled: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
}

#[derive(Debug, Serialize)]
pub struct WriterStatus {
    pub enabled: bool,
    pub queued_dropped: u64,
    pub written: u64,
}

impl Handle {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Queue an entry; never waits. A full queue drops it (counted).
    pub fn record(&self, e: Entry) {
        if !self.enabled() {
            return;
        }
        if self.tx.try_send(Msg::Entry(Box::new(e))).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Insert everything queued so far and wait for it (shutdown, tests).
    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(10), rx).await;
        }
    }

    pub fn status(&self) -> WriterStatus {
        WriterStatus {
            enabled: self.enabled(),
            queued_dropped: self.dropped.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
        }
    }
}

/// Start the writer task over `store`.
pub async fn spawn(store: Arc<ConfigStore>) -> Handle {
    let settings = load_settings(&store).await;
    let (tx, rx) = mpsc::channel::<Msg>(settings.queue.max(64) as usize);
    let h = Handle {
        tx,
        enabled: Arc::new(AtomicBool::new(settings.enabled)),
        dropped: Arc::new(AtomicU64::new(0)),
        written: Arc::new(AtomicU64::new(0)),
    };
    tokio::spawn(writer(store, rx, h.clone(), settings));
    h
}

async fn writer(
    store: Arc<ConfigStore>,
    mut rx: mpsc::Receiver<Msg>,
    h: Handle,
    mut settings: Settings,
) {
    let mut buf: Vec<Entry> = Vec::new();
    let mut logins = Burst::default();
    let mut errors = Burst::default();
    let mut last_settings = std::time::Instant::now();
    let mut last_days_prune = std::time::Instant::now() - Duration::from_secs(3600);
    loop {
        let wait = Duration::from_millis(settings.flush_ms.max(100) as u64);
        let mut flush_ack: Option<oneshot::Sender<()>> = None;
        let deadline = tokio::time::sleep(wait);
        tokio::pin!(deadline);
        let mut closed = false;
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(Msg::Entry(e)) => {
                        buf.push(*e);
                        if buf.len() >= 1000 {
                            break;
                        }
                    }
                    Some(Msg::Flush(a)) => {
                        flush_ack = Some(a);
                        break;
                    }
                    None => {
                        closed = true;
                        break;
                    }
                },
                _ = &mut deadline => break,
            }
        }
        if !buf.is_empty() {
            let batch = std::mem::take(&mut buf);
            let n = batch.len() as u64;
            match insert_batch(&store, &batch).await {
                Ok(()) => {
                    h.written.fetch_add(n, Ordering::Relaxed);
                }
                Err(e) => tracing::warn!("access log: could not write {n} rows: {e}"),
            }
            if let Err(e) = prune_rows(&store, settings.retention_rows).await {
                tracing::warn!("access log: prune: {e}");
            }
            detect(&store, &settings, &batch, &mut logins, &mut errors).await;
        }
        if last_days_prune.elapsed() >= Duration::from_secs(60) {
            last_days_prune = std::time::Instant::now();
            let cutoff = chrono::Utc::now().timestamp_millis() - settings.retention_days * 86_400_000;
            if let Err(e) = prune_age(&store, cutoff).await {
                tracing::warn!("access log: age prune: {e}");
            }
        }
        if last_settings.elapsed() >= Duration::from_secs(10) || flush_ack.is_some() {
            last_settings = std::time::Instant::now();
            settings = load_settings(&store).await;
            h.enabled.store(settings.enabled, Ordering::Relaxed);
        }
        if let Some(a) = flush_ack {
            let _ = a.send(());
        }
        if closed {
            return;
        }
    }
}

async fn detect(
    store: &ConfigStore,
    s: &Settings,
    batch: &[Entry],
    logins: &mut Burst,
    errors: &mut Burst,
) {
    for e in batch {
        let ts = e.timestamp_ms / 1000;
        if is_failed_login(e)
            && logins.observe(ts, s.login_burst, s.login_window_secs, s.event_cooldown_secs)
        {
            let ev = telemetry::new_event(
                "login_failures",
                "web",
                "warning",
                format!(
                    "{} failed sign-ins within {} s (latest from {})",
                    logins.count(),
                    s.login_window_secs,
                    e.client
                ),
            );
            let _ = telemetry::record(store, &ev).await;
        }
        if e.status >= 500
            && errors.observe(ts, s.error_burst, s.error_window_secs, s.event_cooldown_secs)
        {
            let ev = telemetry::new_event(
                "server_errors",
                "web",
                "critical",
                format!(
                    "{} server errors (5xx) within {} s (latest {} {})",
                    errors.count(),
                    s.error_window_secs,
                    e.method,
                    e.path_group
                ),
            );
            let _ = telemetry::record(store, &ev).await;
        }
    }
}

pub async fn insert_batch(store: &ConfigStore, batch: &[Entry]) -> anyhow::Result<()> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let mut tx = pool.begin().await?;
    for e in batch {
        sqlx::query(
            "INSERT INTO web_access_log (timestamp_ms, client, principal_kind, principal_name,
               api_key_id, attempted_user, method, path_group, status, duration_ms, bytes)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(e.timestamp_ms)
        .bind(&e.client)
        .bind(e.principal_kind)
        .bind(&e.principal_name)
        .bind(e.api_key_id)
        .bind(&e.attempted_user)
        .bind(&e.method)
        .bind(&e.path_group)
        .bind(e.status as i64)
        .bind(e.duration_ms.max(0))
        .bind(e.bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn prune_rows(store: &ConfigStore, keep: i64) -> anyhow::Result<()> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    sqlx::query("DELETE FROM web_access_log WHERE id <= (SELECT MAX(id) FROM web_access_log) - ?")
        .bind(keep)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn prune_age(store: &ConfigStore, cutoff_ms: i64) -> anyhow::Result<()> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    sqlx::query("DELETE FROM web_access_log WHERE timestamp_ms < ?")
        .bind(cutoff_ms)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn clear(store: &ConfigStore) -> anyhow::Result<()> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    sqlx::query("DELETE FROM web_access_log").execute(pool).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// queries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Filter {
    /// epoch seconds/milliseconds, RFC 3339, or an age such as `1h`, `30m`, `7d`
    pub since: Option<String>,
    pub until: Option<String>,
    pub user: Option<String>,
    /// `user` must match exactly (default: contains)
    #[serde(default)]
    pub user_exact: bool,
    /// API key id or name
    pub api_key: Option<String>,
    pub method: Option<String>,
    /// path group contains
    pub path: Option<String>,
    pub client: Option<String>,
    /// `2xx`..`5xx`, or an exact code
    pub status: Option<String>,
    /// free text over client, principal, attempted user, path group, method
    pub q: Option<String>,
    /// live cursor: only rows with an id above this, oldest first
    pub after_id: Option<i64>,
    /// paging: only rows with an id below this
    pub before_id: Option<i64>,
    pub limit: Option<i64>,
    /// statistics: entries per top list
    pub top: Option<i64>,
}

fn nz(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn like(s: &str) -> String {
    let mut o = String::from("%");
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('%');
    o
}

/// Parse a time filter into epoch milliseconds.
pub fn parse_time(s: &str, now_ms: i64) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let n: i64 = s.parse().ok()?;
        return Some(if n >= 100_000_000_000 { n } else { n * 1000 });
    }
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp_millis());
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.trim_start_matches('-').parse().ok()?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    Some(now_ms - n.checked_mul(secs)?.checked_mul(1000)?)
}

fn apply<'a>(
    qb: &mut QueryBuilder<'a, Sqlite>,
    f: &'a Filter,
    now_ms: i64,
    with_cursor: bool,
) -> Result<(), String> {
    if let Some(s) = nz(&f.since) {
        let t = parse_time(s, now_ms).ok_or_else(|| format!("since: cannot read {s:?}"))?;
        qb.push(" AND timestamp_ms >= ").push_bind(t);
    }
    if let Some(s) = nz(&f.until) {
        let t = parse_time(s, now_ms).ok_or_else(|| format!("until: cannot read {s:?}"))?;
        qb.push(" AND timestamp_ms <= ").push_bind(t);
    }
    if let Some(u) = nz(&f.user) {
        if f.user_exact {
            qb.push(" AND (principal_name = ").push_bind(u.to_string());
            qb.push(" OR attempted_user = ").push_bind(u.to_string());
            qb.push(")");
        } else {
            qb.push(" AND (principal_name LIKE ").push_bind(like(u));
            qb.push(" ESCAPE '\\' OR attempted_user LIKE ").push_bind(like(u));
            qb.push(" ESCAPE '\\')");
        }
    }
    if let Some(k) = nz(&f.api_key) {
        match k.parse::<i64>() {
            Ok(id) => {
                qb.push(" AND api_key_id = ").push_bind(id);
            }
            Err(_) => {
                qb.push(" AND principal_kind = 'api_key' AND principal_name = ")
                    .push_bind(k.to_string());
            }
        }
    }
    if let Some(m) = nz(&f.method) {
        qb.push(" AND method = ").push_bind(m.to_ascii_uppercase());
    }
    if let Some(p) = nz(&f.path) {
        qb.push(" AND path_group LIKE ").push_bind(like(p));
        qb.push(" ESCAPE '\\'");
    }
    if let Some(c) = nz(&f.client) {
        qb.push(" AND client LIKE ").push_bind(like(c));
        qb.push(" ESCAPE '\\'");
    }
    if let Some(s) = nz(&f.status) {
        let s = s.to_ascii_lowercase();
        if let Some(c) = s.strip_suffix("xx").and_then(|d| d.parse::<i64>().ok()) {
            if !(1..=5).contains(&c) {
                return Err(format!("status: {s:?}"));
            }
            qb.push(" AND status >= ").push_bind(c * 100);
            qb.push(" AND status < ").push_bind(c * 100 + 100);
        } else if let Ok(n) = s.parse::<i64>() {
            qb.push(" AND status = ").push_bind(n);
        } else {
            return Err(format!("status: use 2xx, 4xx, 5xx or a code (got {s:?})"));
        }
    }
    if let Some(q) = nz(&f.q) {
        let l = like(q);
        qb.push(" AND (client LIKE ").push_bind(l.clone());
        qb.push(" ESCAPE '\\' OR principal_name LIKE ").push_bind(l.clone());
        qb.push(" ESCAPE '\\' OR attempted_user LIKE ").push_bind(l.clone());
        qb.push(" ESCAPE '\\' OR path_group LIKE ").push_bind(l.clone());
        qb.push(" ESCAPE '\\' OR method LIKE ").push_bind(l);
        qb.push(" ESCAPE '\\')");
    }
    if with_cursor {
        if let Some(a) = f.after_id {
            qb.push(" AND id > ").push_bind(a);
        }
        if let Some(b) = f.before_id {
            qb.push(" AND id < ").push_bind(b);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LogRow {
    pub id: i64,
    pub timestamp_ms: i64,
    pub client: String,
    pub principal_kind: String,
    pub principal_name: Option<String>,
    pub api_key_id: Option<i64>,
    pub attempted_user: Option<String>,
    pub method: String,
    pub path_group: String,
    pub status: i64,
    pub duration_ms: i64,
    pub bytes: Option<i64>,
}

pub const MAX_LIMIT: i64 = 5000;

/// Matching rows. Newest first, except with a live cursor (`after_id`):
/// oldest first, so the caller resumes from the last id it saw. The second
/// value is the number of matching rows overall.
pub async fn search(store: &ConfigStore, f: &Filter) -> anyhow::Result<(Vec<LogRow>, i64)> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let now = chrono::Utc::now().timestamp_millis();
    let limit = f.limit.unwrap_or(500).clamp(1, MAX_LIMIT);
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, timestamp_ms, client, principal_kind, principal_name, api_key_id,
                attempted_user, method, path_group, status, duration_ms, bytes
         FROM web_access_log WHERE 1=1",
    );
    apply(&mut qb, f, now, true).map_err(|m| anyhow::anyhow!("Invalid request: {m}"))?;
    if f.after_id.is_some() {
        qb.push(" ORDER BY id ASC LIMIT ").push_bind(limit);
    } else {
        qb.push(" ORDER BY id DESC LIMIT ").push_bind(limit);
    }
    let rows = qb.build().fetch_all(pool).await?;
    let out = rows
        .iter()
        .map(|r| LogRow {
            id: r.get(0),
            timestamp_ms: r.get(1),
            client: r.get(2),
            principal_kind: r.get(3),
            principal_name: r.get(4),
            api_key_id: r.get(5),
            attempted_user: r.get(6),
            method: r.get(7),
            path_group: r.get(8),
            status: r.get(9),
            duration_ms: r.get(10),
            bytes: r.get(11),
        })
        .collect();
    let mut cq = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM web_access_log WHERE 1=1");
    apply(&mut cq, f, now, false).map_err(|m| anyhow::anyhow!("Invalid request: {m}"))?;
    let total: i64 = cq.build().fetch_one(pool).await?.get(0);
    Ok((out, total))
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Top {
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Bucket {
    /// bucket start, epoch ms
    pub t: i64,
    pub requests: i64,
    pub client_errors: i64,
    pub server_errors: i64,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Stats {
    pub requests: i64,
    pub client_errors: i64,
    pub server_errors: i64,
    pub since_ms: i64,
    pub until_ms: i64,
    pub bucket_ms: i64,
    pub buckets: Vec<Bucket>,
    pub top_client: Vec<Top>,
    pub top_principal: Vec<Top>,
    pub top_path_group: Vec<Top>,
    pub top_status: Vec<Top>,
}

/// Bucket size (ms) so a span is drawn with at most ~120 buckets.
pub fn bucket_ms(span_ms: i64) -> i64 {
    const STEPS: &[i64] = &[
        10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 10_800_000, 21_600_000, 86_400_000,
    ];
    STEPS
        .iter()
        .copied()
        .find(|s| span_ms / s <= 120)
        .unwrap_or(86_400_000)
}

/// The principal a row is attributed to in statistics.
const PRINCIPAL_SQL: &str = "CASE principal_kind
    WHEN 'user' THEN principal_name
    WHEN 'api_key' THEN 'key:' || principal_name
    ELSE COALESCE(NULLIF('? ' || attempted_user, '? '), 'anonymous') END";

pub async fn stats(store: &ConfigStore, f: &Filter, top_n: i64) -> anyhow::Result<Stats> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let now = chrono::Utc::now().timestamp_millis();
    let bad = |m: String| anyhow::anyhow!("Invalid request: {m}");
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT COUNT(*), COALESCE(SUM(status >= 400 AND status < 500),0),
                COALESCE(SUM(status >= 500),0), MIN(timestamp_ms), MAX(timestamp_ms)
         FROM web_access_log WHERE 1=1",
    );
    apply(&mut qb, f, now, false).map_err(bad)?;
    let r = qb.build().fetch_one(pool).await?;
    let (requests, c4, c5): (i64, i64, i64) = (r.get(0), r.get(1), r.get(2));
    let min: Option<i64> = r.get(3);
    let max: Option<i64> = r.get(4);
    let since = nz(&f.since)
        .and_then(|s| parse_time(s, now))
        .or(min)
        .unwrap_or(now - 3_600_000);
    let until = nz(&f.until)
        .and_then(|s| parse_time(s, now))
        .or(max)
        .unwrap_or(now)
        .max(since + 1);
    let size = bucket_ms((until - since).max(1));
    let first = since - since.rem_euclid(size);

    let mut bq = QueryBuilder::<Sqlite>::new(
        "SELECT (timestamp_ms / ",
    );
    bq.push_bind(size);
    bq.push(") * ");
    bq.push_bind(size);
    bq.push(
        " AS b, COUNT(*), SUM(status >= 400 AND status < 500), SUM(status >= 500)
         FROM web_access_log WHERE 1=1",
    );
    apply(&mut bq, f, now, false).map_err(bad)?;
    bq.push(" GROUP BY b ORDER BY b");
    let mut have = std::collections::BTreeMap::new();
    for r in bq.build().fetch_all(pool).await? {
        let t: i64 = r.get(0);
        have.insert(t, (r.get::<i64, _>(1), r.get::<i64, _>(2), r.get::<i64, _>(3)));
    }
    let mut buckets = Vec::new();
    let mut t = first;
    while t <= until && buckets.len() < 2000 {
        let (a, b, c) = have.get(&t).copied().unwrap_or((0, 0, 0));
        buckets.push(Bucket {
            t,
            requests: a,
            client_errors: b,
            server_errors: c,
        });
        t += size;
    }

    async fn top(
        pool: &sqlx::SqlitePool,
        expr: &str,
        f: &Filter,
        now: i64,
        n: i64,
    ) -> anyhow::Result<Vec<Top>> {
        let mut q = QueryBuilder::<Sqlite>::new(format!(
            "SELECT {expr} AS v, COUNT(*) AS c FROM web_access_log WHERE 1=1"
        ));
        apply(&mut q, f, now, false).map_err(|m| anyhow::anyhow!("Invalid request: {m}"))?;
        q.push(" GROUP BY v ORDER BY c DESC, v ASC LIMIT ").push_bind(n);
        Ok(q.build()
            .fetch_all(pool)
            .await?
            .iter()
            .map(|r| Top {
                value: r.get::<Option<String>, _>(0).unwrap_or_default(),
                count: r.get(1),
            })
            .collect())
    }
    let n = top_n.clamp(1, 100);
    Ok(Stats {
        requests,
        client_errors: c4,
        server_errors: c5,
        since_ms: since,
        until_ms: until,
        bucket_ms: size,
        buckets,
        top_client: top(pool, "client", f, now, n).await?,
        top_principal: top(pool, PRINCIPAL_SQL, f, now, n).await?,
        top_path_group: top(pool, "path_group", f, now, n).await?,
        top_status: top(pool, "CAST(status AS TEXT)", f, now, n).await?,
    })
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// One CSV cell. Quoted when needed; a cell that a spreadsheet would read as
/// a formula (`=`, `+`, `-`, `@`, tab, CR first) gets a leading apostrophe,
/// because account names typed on the login page are attacker-controlled.
pub fn csv_cell(s: &str) -> String {
    let mut v = s.to_string();
    if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        v.insert(0, '\'');
    }
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

fn iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

pub fn rows_csv(rows: &[LogRow]) -> String {
    let mut o = String::from(
        "time,client,principal_kind,principal,api_key_id,attempted_user,method,path_group,status,duration_ms,bytes\r\n",
    );
    for r in rows {
        let cells = [
            iso(r.timestamp_ms),
            r.client.clone(),
            r.principal_kind.clone(),
            r.principal_name.clone().unwrap_or_default(),
            r.api_key_id.map(|i| i.to_string()).unwrap_or_default(),
            r.attempted_user.clone().unwrap_or_default(),
            r.method.clone(),
            r.path_group.clone(),
            r.status.to_string(),
            r.duration_ms.to_string(),
            r.bytes.map(|b| b.to_string()).unwrap_or_default(),
        ];
        o.push_str(&cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        o.push_str("\r\n");
    }
    o
}

// ---------------------------------------------------------------------------
// configuration changes (audit_log)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditFilter {
    pub since: Option<String>,
    pub until: Option<String>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub entity: Option<String>,
    pub q: Option<String>,
    pub before_id: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct AuditRow {
    pub id: i64,
    /// epoch seconds
    pub timestamp: i64,
    pub user: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<String>,
    pub details: Option<String>,
}

pub async fn audit_search(
    store: &ConfigStore,
    f: &AuditFilter,
) -> anyhow::Result<(Vec<AuditRow>, i64)> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let now = chrono::Utc::now().timestamp_millis();
    let limit = f.limit.unwrap_or(500).clamp(1, MAX_LIMIT);
    let build = |select: &str, with_page: bool| -> Result<QueryBuilder<'_, Sqlite>, String> {
        let mut qb = QueryBuilder::<Sqlite>::new(format!(
            "SELECT {select} FROM audit_log WHERE 1=1"
        ));
        if let Some(s) = nz(&f.since) {
            let t = parse_time(s, now).ok_or_else(|| format!("since: cannot read {s:?}"))?;
            qb.push(" AND timestamp >= ").push_bind(t / 1000);
        }
        if let Some(s) = nz(&f.until) {
            let t = parse_time(s, now).ok_or_else(|| format!("until: cannot read {s:?}"))?;
            qb.push(" AND timestamp <= ").push_bind(t / 1000);
        }
        if let Some(u) = nz(&f.user) {
            qb.push(" AND user LIKE ").push_bind(like(u));
            qb.push(" ESCAPE '\\'");
        }
        if let Some(a) = nz(&f.action) {
            qb.push(" AND action LIKE ").push_bind(like(a));
            qb.push(" ESCAPE '\\'");
        }
        if let Some(e) = nz(&f.entity) {
            qb.push(" AND entity_type LIKE ").push_bind(like(e));
            qb.push(" ESCAPE '\\'");
        }
        if let Some(q) = nz(&f.q) {
            let l = like(q);
            qb.push(" AND (user LIKE ").push_bind(l.clone());
            qb.push(" ESCAPE '\\' OR action LIKE ").push_bind(l.clone());
            qb.push(" ESCAPE '\\' OR entity_type LIKE ").push_bind(l.clone());
            qb.push(" ESCAPE '\\' OR entity_id LIKE ").push_bind(l.clone());
            qb.push(" ESCAPE '\\' OR details LIKE ").push_bind(l);
            qb.push(" ESCAPE '\\')");
        }
        if with_page {
            if let Some(b) = f.before_id {
                qb.push(" AND id < ").push_bind(b);
            }
        }
        Ok(qb)
    };
    let mut qb = build(
        "id, timestamp, COALESCE(user,'system'), action, entity_type, entity_id, details",
        true,
    )
    .map_err(|m| anyhow::anyhow!("Invalid request: {m}"))?;
    qb.push(" ORDER BY id DESC LIMIT ").push_bind(limit);
    let rows = qb
        .build()
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| AuditRow {
            id: r.get(0),
            timestamp: r.get(1),
            user: r.get(2),
            action: r.get(3),
            entity_type: r.get(4),
            entity_id: r.get(5),
            details: r.get(6),
        })
        .collect();
    let cq = build("COUNT(*)", false).map_err(|m| anyhow::anyhow!("Invalid request: {m}"))?;
    let mut cq = cq;
    let total: i64 = cq.build().fetch_one(pool).await?.get(0);
    Ok((rows, total))
}

pub fn audit_csv(rows: &[AuditRow]) -> String {
    let mut o = String::from("time,user,action,entity_type,entity_id,details\r\n");
    for r in rows {
        let t = chrono::DateTime::from_timestamp(r.timestamp, 0)
            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        let cells = [
            t,
            r.user.clone(),
            r.action.clone(),
            r.entity_type.clone(),
            r.entity_id.clone().unwrap_or_default(),
            r.details.clone().unwrap_or_default(),
        ];
        o.push_str(&cells.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        o.push_str("\r\n");
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (Arc<ConfigStore>, ()) {
        (Arc::new(ConfigStore::open_in_memory().await.unwrap()), ())
    }

    fn entry(ts: i64, status: u16, path: &str) -> Entry {
        Entry {
            timestamp_ms: ts,
            client: "10.0.0.5".into(),
            principal_kind: "user",
            principal_name: Some("admin".into()),
            api_key_id: None,
            attempted_user: None,
            method: "GET".into(),
            path_group: path.into(),
            status,
            duration_ms: 3,
            bytes: Some(10),
        }
    }

    #[test]
    fn path_group_never_keeps_raw_paths() {
        assert_eq!(path_group(Some("/api/firewall/rules/:id")), "/api/firewall/rules/:id");
        assert_eq!(path_group(None), PATH_UNMATCHED);
        assert_eq!(path_group(Some("")), PATH_UNMATCHED);
        assert_eq!(
            path_group(Some("/static/*__private__axum_nest_tail_param")),
            "/static/*"
        );
        assert!(path_group(Some(&format!("/{}", "a".repeat(500)))).len() <= 200);
    }

    #[test]
    fn names_are_bounded_and_clean() {
        assert_eq!(clean_name("bob\n\u{7}x"), "bobx");
        assert_eq!(clean_name(&"a".repeat(200)).len(), 64);
    }

    #[test]
    fn csv_cells_are_quoted_and_formula_safe() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=1+1"), "'=1+1");
        assert_eq!(csv_cell("@x"), "'@x");
    }

    #[test]
    fn time_filters_parse() {
        let now = 1_700_000_000_000;
        assert_eq!(parse_time("1700000000", now), Some(1_700_000_000_000));
        assert_eq!(parse_time("1700000000123", now), Some(1_700_000_000_123));
        assert_eq!(parse_time("1h", now), Some(now - 3_600_000));
        assert_eq!(parse_time("-30m", now), Some(now - 1_800_000));
        assert_eq!(
            parse_time("2023-11-14T22:13:20Z", now),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_time("soon", now), None);
        assert_eq!(parse_time("", now), None);
    }

    #[test]
    fn bucket_size_follows_the_span() {
        assert_eq!(bucket_ms(60_000), 10_000);
        assert_eq!(bucket_ms(3_600_000), 30_000);
        assert_eq!(bucket_ms(7_200_000), 60_000);
        assert_eq!(bucket_ms(86_400_000), 900_000);
        assert_eq!(bucket_ms(30 * 86_400_000), 86_400_000);
        for span in [1_000, 600_000, 7_200_000, 86_400_000, 604_800_000] {
            assert!(span / bucket_ms(span) <= 120);
        }
    }

    #[test]
    fn burst_fires_at_threshold_once_per_cooldown() {
        let mut b = Burst::default();
        for t in 0..4 {
            assert!(!b.observe(t, 5, 60, 300));
        }
        assert!(b.observe(4, 5, 60, 300));
        // still above the threshold but cooling down
        assert!(!b.observe(5, 5, 60, 300));
        // after the cooldown and a fresh burst
        let mut fired = false;
        for t in 400..406 {
            fired |= b.observe(t, 5, 60, 300);
        }
        assert!(fired);
        // hits outside the window do not count
        let mut b = Burst::default();
        for t in 0..4 {
            b.observe(t * 100, 3, 60, 1);
        }
        assert!(!b.observe(400, 3, 60, 1));
        // threshold 0 = off
        assert!(!Burst::default().observe(1, 0, 60, 1));
    }

    #[test]
    fn env_layer_applies_and_ignores_bad_values() {
        let s = Settings::from_env_with(|k| match k {
            "PATRONUS_ACCESS_LOG_RETENTION_ROWS" => Some("20000".into()),
            "PATRONUS_ACCESS_LOG_RETENTION_DAYS" => Some("0".into()),
            _ => None,
        });
        assert_eq!(s.retention_rows, 20_000);
        assert_eq!(s.retention_days, Settings::default().retention_days);
    }

    #[tokio::test]
    async fn settings_round_trip_and_validate() {
        let (s, _d) = store().await;
        assert_eq!(load_settings(&s).await.retention_rows, Settings::from_env().retention_rows);
        save_settings(
            &s,
            SettingsInput {
                retention_rows: Some(500),
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let l = load_settings(&s).await;
        assert_eq!(l.retention_rows, 500);
        assert!(!l.enabled);
        assert!(save_settings(
            &s,
            SettingsInput {
                retention_days: Some(0),
                ..Default::default()
            }
        )
        .await
        .is_err());
        assert_eq!(load_settings(&s).await.retention_rows, 500);
    }

    #[tokio::test]
    async fn retention_by_rows_and_days() {
        let (s, _d) = store().await;
        let now = chrono::Utc::now().timestamp_millis();
        let batch: Vec<Entry> = (0..50).map(|i| entry(now + i, 200, "/api/x")).collect();
        insert_batch(&s, &batch).await.unwrap();
        prune_rows(&s, 10).await.unwrap();
        let (rows, total) = search(&s, &Filter::default()).await.unwrap();
        assert_eq!(total, 10);
        assert_eq!(rows[0].timestamp_ms, now + 49);
        // age cap
        insert_batch(&s, &[entry(now - 40 * 86_400_000, 200, "/old")])
            .await
            .unwrap();
        prune_age(&s, now - 30 * 86_400_000).await.unwrap();
        let (_, total) = search(&s, &Filter::default()).await.unwrap();
        assert_eq!(total, 10);
    }

    #[tokio::test]
    async fn writer_batches_and_caps_rows_under_a_burst() {
        let (s, _d) = store().await;
        save_settings(
            &s,
            SettingsInput {
                retention_rows: Some(200),
                flush_ms: Some(100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let h = spawn(s.clone()).await;
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..1500 {
            h.record(entry(now + i, 200, "/api/burst"));
            if i % 200 == 0 {
                tokio::task::yield_now().await;
            }
        }
        h.flush().await;
        let (_, total) = search(&s, &Filter::default()).await.unwrap();
        let st = h.status();
        assert_eq!(st.written + st.queued_dropped, 1500);
        assert!(total <= 200, "cap held: {total}");
        assert!(total > 0);
    }

    #[tokio::test]
    async fn disabled_writes_nothing() {
        let (s, _d) = store().await;
        save_settings(&s, SettingsInput { enabled: Some(false), ..Default::default() })
            .await
            .unwrap();
        let h = spawn(s.clone()).await;
        h.record(entry(1, 200, "/a"));
        h.flush().await;
        let (_, total) = search(&s, &Filter::default()).await.unwrap();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn filters_and_cursor() {
        let (s, _d) = store().await;
        let now = chrono::Utc::now().timestamp_millis();
        let mut a = entry(now, 200, "/api/firewall/rules");
        a.client = "192.0.2.1".into();
        let mut b = entry(now + 1, 404, "(unmatched)");
        b.principal_kind = "anonymous";
        b.principal_name = None;
        let mut c = entry(now + 2, 401, LOGIN_GROUP);
        c.principal_kind = "anonymous";
        c.principal_name = None;
        c.method = "POST".into();
        c.attempted_user = Some("mallory".into());
        let mut d = entry(now + 3, 200, "/api/firewall/rules");
        d.principal_kind = "api_key";
        d.principal_name = Some("ci".into());
        d.api_key_id = Some(7);
        insert_batch(&s, &[a, b, c, d]).await.unwrap();
        async fn q(s: &Arc<ConfigStore>, f: Filter) -> (Vec<LogRow>, i64) {
            search(s, &f).await.unwrap()
        }
        assert_eq!(q(&s, Filter::default()).await.1, 4);
        assert_eq!(q(&s, Filter { status: Some("4xx".into()), ..Default::default() }).await.1, 2);
        assert_eq!(q(&s, Filter { status: Some("401".into()), ..Default::default() }).await.1, 1);
        assert_eq!(q(&s, Filter { method: Some("post".into()), ..Default::default() }).await.1, 1);
        assert_eq!(q(&s, Filter { user: Some("mall".into()), ..Default::default() }).await.1, 1);
        assert_eq!(
            q(&s, Filter { user: Some("mall".into()), user_exact: true, ..Default::default() }).await.1,
            0
        );
        assert_eq!(q(&s, Filter { api_key: Some("7".into()), ..Default::default() }).await.1, 1);
        assert_eq!(q(&s, Filter { api_key: Some("ci".into()), ..Default::default() }).await.1, 1);
        assert_eq!(q(&s, Filter { path: Some("firewall".into()), ..Default::default() }).await.1, 2);
        assert_eq!(q(&s, Filter { client: Some("192.0.2".into()), ..Default::default() }).await.1, 1);
        assert_eq!(q(&s, Filter { q: Some("mallory".into()), ..Default::default() }).await.1, 1);
        // wildcard characters in a filter are literal
        assert_eq!(q(&s, Filter { q: Some("%".into()), ..Default::default() }).await.1, 0);
        let (rows, _) = q(&s, Filter::default()).await;
        assert!(rows[0].id > rows[3].id, "newest first");
        let first = rows[3].id;
        let (live, _) = q(&s, Filter { after_id: Some(first), ..Default::default() }).await;
        assert_eq!(live.len(), 3);
        assert!(live[0].id < live[2].id, "cursor reads oldest first");
        let (page, _) = q(&s, Filter { before_id: Some(rows[1].id), limit: Some(1), ..Default::default() }).await;
        assert_eq!(page[0].id, rows[2].id);
        assert!(search(&s, &Filter { status: Some("abc".into()), ..Default::default() })
            .await
            .is_err());
        assert!(search(&s, &Filter { since: Some("never".into()), ..Default::default() })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stats_maths_match_the_rows() {
        let (s, _d) = store().await;
        let now = chrono::Utc::now().timestamp_millis();
        let mut rows = Vec::new();
        for i in 0..10 {
            rows.push(entry(now - 1000 + i, 200, "/a"));
        }
        for i in 0..3 {
            rows.push(entry(now - 500 + i, 404, "(unmatched)"));
        }
        for i in 0..2 {
            let mut e = entry(now - 100 + i, 500, "/b");
            e.client = "10.9.9.9".into();
            rows.push(e);
        }
        insert_batch(&s, &rows).await.unwrap();
        let st = stats(&s, &Filter::default(), 10).await.unwrap();
        assert_eq!((st.requests, st.client_errors, st.server_errors), (15, 3, 2));
        let sum: i64 = st.buckets.iter().map(|b| b.requests).sum();
        assert_eq!(sum, 15);
        assert_eq!(st.top_client[0], Top { value: "10.0.0.5".into(), count: 13 });
        assert_eq!(st.top_path_group[0], Top { value: "/a".into(), count: 10 });
        assert_eq!(st.top_status[0].value, "200");
        assert_eq!(st.top_principal[0], Top { value: "admin".into(), count: 15 });
        // filtered statistics only count the filtered rows
        let st = stats(&s, &Filter { status: Some("5xx".into()), ..Default::default() }, 10)
            .await
            .unwrap();
        assert_eq!(st.requests, 2);
        assert_eq!(st.top_client[0].value, "10.9.9.9");
        // an empty log still answers
        clear(&s).await.unwrap();
        let st = stats(&s, &Filter::default(), 10).await.unwrap();
        assert_eq!(st.requests, 0);
        assert!(st.top_client.is_empty());
    }

    #[tokio::test]
    async fn bursts_become_system_events() {
        let (s, _d) = store().await;
        save_settings(
            &s,
            SettingsInput {
                login_burst: Some(3),
                error_burst: Some(4),
                flush_ms: Some(100),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let h = spawn(s.clone()).await;
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..3 {
            let mut e = entry(now + i, 401, LOGIN_GROUP);
            e.method = "POST".into();
            h.record(e);
        }
        for i in 0..4 {
            h.record(entry(now + i, 503, "/api/x"));
        }
        h.flush().await;
        let ev = telemetry::events(&s, 0, None, 100).await.unwrap();
        let kinds: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"login_failures"), "{kinds:?}");
        assert!(kinds.contains(&"server_errors"), "{kinds:?}");
        assert_eq!(kinds.iter().filter(|k| **k == "login_failures").count(), 1);
    }

    #[tokio::test]
    async fn audit_log_search_and_csv() {
        let (s, _d) = store().await;
        s.audit("ron", "update", "firewall_rule", Some("3"), &serde_json::json!({"a":1}))
            .await
            .unwrap();
        s.audit("=evil", "delete", "nat_rule", None, &serde_json::json!({}))
            .await
            .unwrap();
        let (rows, total) = audit_search(&s, &AuditFilter::default()).await.unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows[0].user, "=evil");
        let (rows, total) = audit_search(
            &s,
            &AuditFilter { entity: Some("firewall".into()), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!((rows.len(), total), (1, 1));
        let csv = audit_csv(&audit_search(&s, &AuditFilter::default()).await.unwrap().0);
        assert!(csv.starts_with("time,user,action"));
        assert!(csv.contains("'=evil"));
    }
}
