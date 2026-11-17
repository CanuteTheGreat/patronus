//! Internet speed test with history (lane H): latency, download and upload
//! measured from the router itself with curl against an HTTP(S) test server
//! (default: Cloudflare's speed endpoints, any server with the same shape
//! works: `GET <down_url>` returns at least `{bytes}` bytes, `POST <up_url>`
//! accepts a body). Results go to `speedtests`; an optional interval runs it
//! on a schedule. One test at a time.

use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::OnceLock;
use tokio::sync::Mutex;

pub const CFG_DOWN_URL: &str = "speedtest.down_url";
pub const CFG_UP_URL: &str = "speedtest.up_url";
pub const CFG_BYTES_DOWN: &str = "speedtest.bytes_down";
pub const CFG_BYTES_UP: &str = "speedtest.bytes_up";
pub const CFG_INTERVAL_HOURS: &str = "speedtest.interval_hours";

pub const DEFAULT_DOWN_URL: &str = "https://speed.cloudflare.com/__down?bytes={bytes}";
pub const DEFAULT_UP_URL: &str = "https://speed.cloudflare.com/__up";
pub const DEFAULT_BYTES_DOWN: u64 = 25_000_000;
pub const DEFAULT_BYTES_UP: u64 = 10_000_000;
/// Results kept.
pub const KEEP: i64 = 500;
/// Per-direction time limit (seconds): a slow link still gets a rate from
/// what arrived by then.
pub const MAX_SECS: u32 = 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    pub down_url: String,
    /// Empty = no upload test.
    pub up_url: String,
    pub bytes_down: u64,
    pub bytes_up: u64,
    /// 0 = only on demand.
    pub interval_hours: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsInput {
    pub down_url: Option<String>,
    pub up_url: Option<String>,
    pub bytes_down: Option<u64>,
    pub bytes_up: Option<u64>,
    pub interval_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Result {
    pub id: i64,
    pub ts: i64,
    pub server: String,
    pub latency_ms: Option<f64>,
    pub down_bps: Option<u64>,
    pub up_bps: Option<u64>,
    pub ok: bool,
    pub error: Option<String>,
    /// manual | schedule
    pub trigger: String,
}

fn lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

pub fn running() -> bool {
    lock().try_lock().is_err()
}

pub fn check_url(what: &str, u: &str, allow_empty: bool) -> anyhow::Result<String> {
    let u = u.trim();
    if u.is_empty() && allow_empty {
        return Ok(String::new());
    }
    let host_ok = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .and_then(|r| r.split('/').next())
        .is_some_and(|h| !h.is_empty() && !h.contains('@'));
    if !host_ok
        || u.len() > 300
        || u.chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '\'' | '`'))
    {
        anyhow::bail!("Invalid {what}: an http:// or https:// address");
    }
    Ok(u.to_string())
}

pub async fn settings(store: &ConfigStore) -> anyhow::Result<Settings> {
    let g = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    let get = |k: &'static str| async move {
        store
            .load_system_config(k)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    };
    Ok(Settings {
        down_url: g(get(CFG_DOWN_URL).await?).unwrap_or_else(|| DEFAULT_DOWN_URL.into()),
        // an explicit empty value turns the upload test off
        up_url: get(CFG_UP_URL)
            .await?
            .unwrap_or_else(|| DEFAULT_UP_URL.into()),
        bytes_down: g(get(CFG_BYTES_DOWN).await?)
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BYTES_DOWN),
        bytes_up: g(get(CFG_BYTES_UP).await?)
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BYTES_UP),
        interval_hours: g(get(CFG_INTERVAL_HOURS).await?)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    })
}

pub async fn save_settings(store: &ConfigStore, i: &SettingsInput) -> anyhow::Result<Settings> {
    let mut kv: Vec<(&str, String)> = Vec::new();
    if let Some(u) = &i.down_url {
        kv.push((CFG_DOWN_URL, check_url("download URL", u, false)?));
    }
    if let Some(u) = &i.up_url {
        kv.push((CFG_UP_URL, check_url("upload URL", u, true)?));
    }
    for (k, v, what) in [
        (CFG_BYTES_DOWN, i.bytes_down, "download size"),
        (CFG_BYTES_UP, i.bytes_up, "upload size"),
    ] {
        if let Some(b) = v {
            if !(100_000..=1_000_000_000).contains(&b) {
                anyhow::bail!("Invalid {what}: 100000 to 1000000000 bytes");
            }
            kv.push((k, b.to_string()));
        }
    }
    if let Some(h) = i.interval_hours {
        if h > 168 {
            anyhow::bail!("Invalid interval: 0 (off) to 168 hours");
        }
        kv.push((CFG_INTERVAL_HOURS, h.to_string()));
    }
    for (k, v) in kv {
        store
            .save_system_config(k, &v)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    settings(store).await
}

pub async fn history(store: &ConfigStore, limit: i64) -> anyhow::Result<Vec<Result>> {
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = sqlx::query(
        "SELECT id, ts, server, latency_ms, down_bps, up_bps, ok, error, trigger
         FROM speedtests ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Result {
            id: r.get(0),
            ts: r.get(1),
            server: r.get(2),
            latency_ms: r.get(3),
            down_bps: r.get::<Option<i64>, _>(4).map(|v| v as u64),
            up_bps: r.get::<Option<i64>, _>(5).map(|v| v as u64),
            ok: r.get::<i64, _>(6) != 0,
            error: r.get(7),
            trigger: r.get(8),
        })
        .collect())
}

/// The host part of a URL, for the result list.
pub fn server_of(u: &str) -> String {
    u.split("://")
        .nth(1)
        .and_then(|r| r.split(['/', '?']).next())
        .unwrap_or(u)
        .to_string()
}

pub fn down_url(s: &Settings) -> String {
    s.down_url.replace("{bytes}", &s.bytes_down.to_string())
}

/// Parse curl's `-w '%{speed_...} %{size_...}'` output: (bytes/s, bytes).
pub fn parse_speed(out: &str) -> Option<(f64, f64)> {
    let mut it = out.split_whitespace();
    let speed: f64 = it.next()?.parse().ok()?;
    let size: f64 = it.next()?.parse().ok()?;
    Some((speed, size))
}

async fn curl(args: &[String], stdin_bytes: Option<u64>) -> anyhow::Result<(i32, String)> {
    use tokio::io::AsyncWriteExt;
    let mut c = tokio::process::Command::new("curl");
    c.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(if stdin_bytes.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .kill_on_drop(true);
    let mut child = c
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run curl: {e}"))?;
    if let (Some(n), Some(mut si)) = (stdin_bytes, child.stdin.take()) {
        tokio::spawn(async move {
            let chunk = vec![0u8; 64 * 1024];
            let mut left = n;
            while left > 0 {
                let k = left.min(chunk.len() as u64) as usize;
                if si.write_all(&chunk[..k]).await.is_err() {
                    break;
                }
                left -= k as u64;
            }
        });
    }
    let o = tokio::time::timeout(
        std::time::Duration::from_secs(MAX_SECS as u64 + 15),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("curl did not finish"))??;
    Ok((
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).trim().to_string(),
    ))
}

fn base_args() -> Vec<String> {
    [
        "-s",
        "-o",
        "/dev/null",
        "--connect-timeout",
        "8",
        "-A",
        "Patronus-Speedtest/1.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Lowest TCP connect time of three small requests (ms).
async fn latency(s: &Settings) -> Option<f64> {
    let url = s.down_url.replace("{bytes}", "0");
    let mut best: Option<f64> = None;
    for _ in 0..3 {
        let mut a = base_args();
        a.extend([
            "--max-time".into(),
            "8".into(),
            "-w".into(),
            "%{time_connect}".into(),
            url.clone(),
        ]);
        if let Ok((0, out)) = curl(&a, None).await {
            if let Ok(t) = out.parse::<f64>() {
                if t > 0.0 {
                    best = Some(best.map_or(t, |b: f64| b.min(t)));
                }
            }
        }
    }
    best.map(|t| (t * 100_000.0).round() / 100.0)
}

/// One direction; a transfer cut by the time limit still counts when at
/// least 1 MB moved.
async fn transfer(url: &str, upload: Option<u64>) -> anyhow::Result<u64> {
    let mut a = base_args();
    a.extend(["--max-time".into(), MAX_SECS.to_string()]);
    match upload {
        Some(_) => a.extend([
            "-X".into(),
            "POST".into(),
            "-H".into(),
            "Content-Type: application/octet-stream".into(),
            "--data-binary".into(),
            "@-".into(),
            "-w".into(),
            "%{speed_upload} %{size_upload}".into(),
        ]),
        None => a.extend(["-w".into(), "%{speed_download} %{size_download}".into()]),
    }
    a.push(url.to_string());
    let (rc, out) = curl(&a, upload).await?;
    let (speed, size) =
        parse_speed(&out).ok_or_else(|| anyhow::anyhow!("no result from curl (exit {rc})"))?;
    if (rc == 0 || rc == 28) && size >= 1_000_000.0 && speed > 0.0 {
        Ok((speed * 8.0) as u64)
    } else if rc == 0 {
        anyhow::bail!("the server sent too little ({size} bytes)")
    } else {
        anyhow::bail!("transfer failed (curl exit {rc})")
    }
}

/// Run one test now and store it. Err if another test is running.
pub async fn run(store: &ConfigStore, trigger: &str) -> anyhow::Result<Result> {
    let _g = lock()
        .try_lock()
        .map_err(|_| anyhow::anyhow!("a speed test is already running"))?;
    let s = settings(store).await?;
    let lat = latency(&s).await;
    let down = transfer(&down_url(&s), None).await;
    let up = if s.up_url.is_empty() {
        None
    } else {
        Some(transfer(&s.up_url, Some(s.bytes_up)).await)
    };
    let mut errs = Vec::new();
    if lat.is_none() {
        errs.push("latency: no connection".to_string());
    }
    if let Err(e) = &down {
        errs.push(format!("download: {e}"));
    }
    if let Some(Err(e)) = &up {
        errs.push(format!("upload: {e}"));
    }
    let r = Result {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        server: server_of(&s.down_url),
        latency_ms: lat,
        down_bps: down.as_ref().ok().copied(),
        up_bps: up.as_ref().and_then(|u| u.as_ref().ok().copied()),
        ok: errs.is_empty(),
        error: (!errs.is_empty()).then(|| errs.join("; ")),
        trigger: trigger.to_string(),
    };
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = sqlx::query(
        "INSERT INTO speedtests (ts, server, latency_ms, down_bps, up_bps, ok, error, trigger)
         VALUES (?,?,?,?,?,?,?,?)",
    )
    .bind(r.ts)
    .bind(&r.server)
    .bind(r.latency_ms)
    .bind(r.down_bps.map(|v| v as i64))
    .bind(r.up_bps.map(|v| v as i64))
    .bind(r.ok as i64)
    .bind(&r.error)
    .bind(&r.trigger)
    .execute(pool)
    .await?
    .last_insert_rowid();
    let _ = sqlx::query("DELETE FROM speedtests WHERE id <= ?")
        .bind(id - KEEP)
        .execute(pool)
        .await;
    Ok(Result { id, ..r })
}

/// Is a scheduled run due at `now`?
pub fn due(interval_hours: u32, last_ts: Option<i64>, now: i64) -> bool {
    interval_hours > 0 && last_ts.is_none_or(|t| now - t >= interval_hours as i64 * 3600)
}

/// Scheduled tests (checked every minute).
pub fn spawn_scheduler(store: std::sync::Arc<ConfigStore>) {
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            let Ok(s) = settings(&store).await else {
                continue;
            };
            if s.interval_hours == 0 || running() {
                continue;
            }
            let last = history(&store, 1)
                .await
                .ok()
                .and_then(|h| h.first().map(|r| r.ts));
            if due(s.interval_hours, last, chrono::Utc::now().timestamp()) {
                if let Err(e) = run(&store, "schedule").await {
                    tracing::warn!("scheduled speed test: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_parsing() {
        assert!(check_url("u", "https://speed.example/__down?bytes={bytes}", false).is_ok());
        assert!(check_url("u", "http://198.51.100.10:8080/up", false).is_ok());
        assert_eq!(check_url("u", "  ", true).unwrap(), "");
        for bad in [
            "",
            "ftp://x",
            "https://",
            "https://a b",
            "https://u@h/x",
            "https://h/\"x",
            "file:///etc/passwd",
        ] {
            assert!(check_url("u", bad, false).is_err(), "{bad}");
        }
        assert_eq!(
            parse_speed("1250000.000 25000000"),
            Some((1_250_000.0, 25_000_000.0))
        );
        assert_eq!(parse_speed("garbage"), None);
        assert_eq!(
            server_of("https://speed.cloudflare.com/__down?bytes=1"),
            "speed.cloudflare.com"
        );
        let s = Settings {
            down_url: DEFAULT_DOWN_URL.into(),
            up_url: DEFAULT_UP_URL.into(),
            bytes_down: 1000,
            bytes_up: 10,
            interval_hours: 0,
        };
        assert_eq!(
            down_url(&s),
            "https://speed.cloudflare.com/__down?bytes=1000"
        );
    }

    #[test]
    fn schedule() {
        assert!(!due(0, None, 100));
        assert!(due(6, None, 100));
        assert!(!due(6, Some(0), 6 * 3600 - 1));
        assert!(due(6, Some(0), 6 * 3600));
    }
}
