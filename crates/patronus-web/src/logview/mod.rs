//! System log viewer: one query model over journald and syslog files.
//!
//! The back end is chosen at RUN time ([`choose`]): journald when it is running and
//! `journalctl` exists, else the syslog file(s) named by the settings
//! (`patronus_config::logview`). Both produce the same [`Page`]: chronological
//! records, "boot" separator items, a cursor for older pages and one to resume a
//! live stream from.

pub mod files;
pub mod journal;
pub mod parse;

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use files::{Backwards, Pos};
use parse::{boot_id_of, glob_match, parse_priority, Ctx, Entry, LEVEL_NAMES};
use patronus_config::logview::LogViewSettings;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Journald,
    Files,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::Journald => "journald",
            Backend::Files => "files",
        }
    }
}

fn which(cmd: &str) -> bool {
    if cmd.contains('/') {
        return std::path::Path::new(cmd).exists();
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(cmd).exists()))
        .unwrap_or(false)
}

/// journald back end when it is chosen or (auto) running; files otherwise.
pub fn choose(s: &LogViewSettings) -> Backend {
    match s.backend.as_str() {
        "journald" => Backend::Journald,
        "files" => Backend::Files,
        _ => {
            if std::path::Path::new("/run/systemd/journal/socket").exists() && which(&s.journalctl)
            {
                Backend::Journald
            } else {
                Backend::Files
            }
        }
    }
}

/// Filters of a view (all optional).
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub since: Option<i64>,
    pub until: Option<i64>,
    /// Entries at least this severe (0 emerg .. 7 debug).
    pub min_priority: Option<u8>,
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub kernel: bool,
    pub q: Option<String>,
}

/// A time as epoch seconds / milliseconds, RFC 3339, or `YYYY-MM-DD HH:MM[:SS]` in the
/// box's local time.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let n: i64 = s.parse().ok()?;
        return Some(if n > 100_000_000_000 { n } else { n * 1000 });
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp_millis());
    }
    for f in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, f) {
            return Local
                .from_local_datetime(&n)
                .earliest()
                .map(|d| d.timestamp_millis());
        }
    }
    None
}

impl Filter {
    pub fn from_query(q: &HashMap<String, String>) -> Result<Filter, String> {
        let get = |k: &str| {
            q.get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let time = |k: &str| -> Result<Option<i64>, String> {
            match get(k) {
                None => Ok(None),
                Some(v) => parse_time(&v).map(Some).ok_or_else(|| {
                    format!(
                        "Invalid {k}: use epoch seconds, RFC 3339 or YYYY-MM-DD HH:MM (got {v:?})"
                    )
                }),
            }
        };
        let min_priority = match get("min_priority") {
            None => None,
            Some(v) => Some(parse_priority(&v).ok_or_else(|| {
                format!("Invalid min_priority {v:?}: emerg, alert, crit, err, warning, notice, info, debug or 0-7")
            })?),
        };
        let since = time("since")?;
        let until = time("until")?;
        if let (Some(a), Some(b)) = (since, until) {
            if a > b {
                return Err("Invalid time span: since is after until".into());
            }
        }
        let kernel = matches!(get("kernel").as_deref(), Some("1" | "true" | "yes" | "on"));
        Ok(Filter {
            since,
            until,
            min_priority,
            unit: get("unit"),
            identifier: get("identifier"),
            kernel,
            q: get("q"),
        })
    }

    /// Does `e` pass? `journal`: the unit/priority/kernel filters were already applied
    /// by journalctl (its `-u` also returns the manager's lines ABOUT the unit).
    pub fn matches(&self, e: &Entry, journal: bool, pairs: &[(String, String)]) -> bool {
        if self.since.is_some_and(|s| e.ts < s) || self.until.is_some_and(|u| e.ts > u) {
            return false;
        }
        if let Some(m) = self.min_priority {
            if !e.priority.is_some_and(|p| p <= m) {
                return false;
            }
        }
        if self.kernel && !e.kernel {
            return false;
        }
        if let Some(id) = &self.identifier {
            if !glob_match(id, &e.ident) {
                return false;
            }
        }
        if !journal {
            if let Some(u) = &self.unit {
                if !unit_matches(u, e, pairs) {
                    return false;
                }
            }
        }
        if let Some(q) = &self.q {
            let q = q.to_lowercase();
            if !e.message.to_lowercase().contains(&q) && !e.ident.to_lowercase().contains(&q) {
                return false;
            }
        }
        true
    }
}

fn unit_matches(u: &str, e: &Entry, pairs: &[(String, String)]) -> bool {
    let strip = |s: &str| s.trim_end_matches(".service").to_ascii_lowercase();
    let u = strip(u);
    if e.unit.as_deref().is_some_and(|x| strip(x) == u) {
        return true;
    }
    if strip(&e.ident) == u {
        return true;
    }
    pairs
        .iter()
        .any(|(id, svc)| id.eq_ignore_ascii_case(&e.ident) && strip(svc) == u)
}

pub fn line_json(e: &Entry, cursor: &str) -> Value {
    json!({
        "type": "line", "cursor": cursor, "ts": e.ts, "priority": e.priority, "level": e.level(),
        "facility": e.facility, "host": e.host, "ident": e.ident, "pid": e.pid, "unit": e.unit,
        "message": e.message, "kernel": e.kernel,
    })
}

pub fn boot_json(ts: i64, id: Option<&str>) -> Value {
    json!({"type": "boot", "ts": ts, "boot_id": id})
}

/// Plain text of an entry (download, tests).
pub fn text_line(e: &Entry) -> String {
    let t = DateTime::<Utc>::from_timestamp_millis(e.ts)
        .map(|d| {
            d.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_default();
    let who = if e.ident.is_empty() {
        String::new()
    } else if let Some(p) = e.pid {
        format!(" {}[{}]:", e.ident, p)
    } else {
        format!(" {}:", e.ident)
    };
    format!("{t} {:<7}{who} {}", e.level(), e.message)
}

/// Plain text of a page's items (the download): one line per record, `-- boot ... --` separators.
pub fn download_text(items: &[Value]) -> String {
    let mut t = String::new();
    for i in items {
        if i["type"] == "boot" {
            let id = i["boot_id"]
                .as_str()
                .map(|b| b.chars().take(8).collect::<String>());
            t.push_str(&format!(
                "-- boot {} --\n",
                id.unwrap_or_else(|| "started".into())
            ));
            continue;
        }
        let e = Entry {
            ts: i["ts"].as_i64().unwrap_or(0),
            host: String::new(),
            facility: None,
            priority: i["priority"].as_u64().map(|p| p as u8),
            ident: i["ident"].as_str().unwrap_or("").to_string(),
            pid: i["pid"].as_u64().map(|p| p as u32),
            unit: None,
            message: i["message"].as_str().unwrap_or("").to_string(),
            kernel: false,
            boot_id: None,
            boot_marker: false,
        };
        t.push_str(&text_line(&e));
        t.push('\n');
    }
    t
}

#[derive(Debug, Default)]
pub struct Page {
    pub backend: &'static str,
    pub source: String,
    pub items: Vec<Value>,
    /// Pass as `cursor` to get the next older page (None = nothing older was left).
    pub older_cursor: Option<String>,
    /// Pass to the live stream to continue after the newest record of this page.
    pub newest_cursor: String,
    pub identifiers: Vec<String>,
    /// The scan budget ran out before the page was full: narrow the filters.
    pub scan_limited: bool,
    /// At least one record in the scanned part carried a priority.
    pub priority_known: bool,
    pub scanned_lines: u64,
    pub note: Option<String>,
}

impl Page {
    pub fn to_json(&self) -> Value {
        json!({
            "backend": self.backend, "source": self.source, "entries": self.items,
            "older_cursor": self.older_cursor, "newest_cursor": self.newest_cursor,
            "identifiers": self.identifiers, "scan_limited": self.scan_limited,
            "priority_known": self.priority_known, "levels": LEVEL_NAMES,
            "note": self.note, "count": self.items.iter().filter(|i| i["type"] == "line").count(),
        })
    }
}

/// Chronological items with a "boot" separator before every boot marker (files) or boot id change (journald).
fn with_separators(entries: Vec<(Entry, String)>, files: bool) -> Vec<Value> {
    let mut out = Vec::with_capacity(entries.len() + 2);
    let mut last: Option<String> = None;
    let mut seen_any = false;
    for (e, cur) in entries {
        if files {
            if e.boot_marker {
                let id = boot_id_of(&e.message);
                if id.is_none() || id != last {
                    out.push(boot_json(e.ts, id.as_deref()));
                }
                if id.is_some() {
                    last = id;
                }
            }
        } else if let Some(b) = &e.boot_id {
            if seen_any && last.as_deref() != Some(b.as_str()) {
                out.push(boot_json(e.ts, Some(b)));
            }
            last = Some(b.clone());
        }
        seen_any = true;
        out.push(line_json(&e, &cur));
    }
    out
}

/// One page from the syslog files: the newest `limit` records matching `f`.
pub fn query_files(s: &LogViewSettings, f: &Filter, limit: usize, cursor: Option<&str>) -> Page {
    let active = files::pick_active(&s.managed_file, &s.file_path);
    let chain = files::chain(&active, s.rotated_files);
    let markers = s.markers();
    let pairs = s.unit_pairs();
    let from = cursor.and_then(Pos::parse);
    let mut b = Backwards::new(&chain, from, Ctx::now(), &markers, s.max_scan_bytes);
    let mut got: Vec<(Entry, Pos, Pos)> = Vec::new();
    let mut idents: BTreeSet<String> = BTreeSet::new();
    let (mut known, mut older_run, mut lines) = (false, 0u32, 0u64);
    let mut full = false;
    while let Some(r) = b.next_record() {
        lines += 1;
        let e = r.entry;
        known |= e.priority.is_some();
        if idents.len() < 200 && !e.ident.is_empty() {
            idents.insert(e.ident.clone());
        }
        if f.until.is_some_and(|u| e.ts > u) {
            continue;
        }
        if f.since.is_some_and(|sn| e.ts < sn) {
            // clocks step at boot (no RTC), so one old record is no proof: stop after a run
            older_run += 1;
            if older_run >= 64 {
                break;
            }
            continue;
        }
        older_run = 0;
        if f.matches(&e, false, &pairs) {
            got.push((e, r.start, r.end));
            if got.len() >= limit {
                full = true;
                break;
            }
        }
    }
    let scan_limited = b.over_budget;
    let older_cursor = if full || scan_limited {
        got.last().map(|g| g.1.cursor())
    } else {
        None
    };
    let newest_cursor = got
        .first()
        .map(|g| g.2.cursor())
        .or_else(|| {
            chain.first().map(|c| {
                Pos {
                    ino: c.ino,
                    off: c.len,
                }
                .cursor()
            })
        })
        .unwrap_or_default();
    got.reverse();
    let entries = got
        .into_iter()
        .map(|(e, _, end)| (e, end.cursor()))
        .collect();
    Page {
        backend: "files",
        source: active.display().to_string(),
        items: with_separators(entries, true),
        older_cursor,
        newest_cursor,
        identifiers: idents.into_iter().collect(),
        scan_limited,
        priority_known: known,
        scanned_lines: lines,
        note: if chain.is_empty() {
            Some(format!(
                "{} does not exist (no system logger writes it)",
                active.display()
            ))
        } else {
            None
        },
    }
}

/// One page, whichever back end is in use (journald falls back to files when it cannot run).
pub async fn query(s: &LogViewSettings, f: &Filter, limit: usize, cursor: Option<&str>) -> Page {
    if choose(s) == Backend::Journald {
        match journal::query(s, f, limit, cursor).await {
            Ok(p) => return p,
            Err(e) => {
                tracing::warn!("journald read failed, using the syslog file: {e}");
                let mut p = query_files(s, f, limit, cursor);
                p.note = Some(format!("journald unavailable ({e}); showing {}", p.source));
                return p;
            }
        }
    }
    query_files(s, f, limit, cursor)
}

/// Follow new records until the receiver is gone or `stream_max_secs` ends it. Items are
/// `line` / `boot` JSON values (a `line` carries the cursor to resume from).
pub async fn follow(
    s: LogViewSettings,
    f: Filter,
    cursor: Option<String>,
    tx: tokio::sync::mpsc::Sender<Value>,
) {
    if choose(&s) == Backend::Journald
        && journal::follow(&s, &f, cursor.as_deref(), &tx)
            .await
            .is_ok()
    {
        return;
    }
    follow_files(s, f, cursor, tx).await
}

async fn follow_files(
    s: LogViewSettings,
    f: Filter,
    cursor: Option<String>,
    tx: tokio::sync::mpsc::Sender<Value>,
) {
    let markers = s.markers();
    let pairs = s.unit_pairs();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(s.stream_max_secs);
    let mut pos: Option<Pos> = cursor.as_deref().and_then(Pos::parse);
    let mut last_boot: Option<String> = None;
    loop {
        if tx.is_closed() || std::time::Instant::now() >= deadline {
            return;
        }
        let active = files::pick_active(&s.managed_file, &s.file_path);
        let chain = files::chain(&active, s.rotated_files);
        if let Some(first) = chain.first() {
            let from = *pos.get_or_insert(Pos {
                ino: first.ino,
                off: first.len,
            });
            let (recs, np) =
                files::read_after(&chain, from, &Ctx::now(), &markers, s.max_scan_bytes);
            pos = Some(np);
            for (e, end) in recs {
                if e.boot_marker {
                    let id = boot_id_of(&e.message);
                    if (id.is_none() || id != last_boot)
                        && tx.send(boot_json(e.ts, id.as_deref())).await.is_err()
                    {
                        return;
                    }
                    if id.is_some() {
                        last_boot = id;
                    }
                }
                // a live view shows what arrives now: the time span filter does not apply
                let mut live = f.clone();
                live.since = None;
                live.until = None;
                if live.matches(&e, false, &pairs)
                    && tx.send(line_json(&e, &end.cursor())).await.is_err()
                {
                    return;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(s.live_poll_ms)).await;
    }
}

/// The Monitoring page preview: the newest `preview_lines` records, newest first.
pub async fn preview(
    store: &patronus_config::ConfigStore,
) -> (Vec<crate::templates::LogEntry>, String) {
    let s = patronus_config::logview::resolve(Some(store)).await;
    if s.preview_lines == 0 {
        return (Vec::new(), String::new());
    }
    let p = query(&s, &Filter::default(), s.preview_lines as usize, None).await;
    let mut v: Vec<crate::templates::LogEntry> = p
        .items
        .iter()
        .filter(|i| i["type"] == "line")
        .map(|i| crate::templates::LogEntry {
            timestamp: DateTime::<Utc>::from_timestamp_millis(i["ts"].as_i64().unwrap_or(0))
                .map(|d| d.with_timezone(&Local).format("%b %e %H:%M:%S").to_string())
                .unwrap_or_default(),
            level: i["level"].as_str().unwrap_or("unknown").to_string(),
            component: i["ident"].as_str().unwrap_or("").to_string(),
            message: i["message"].as_str().unwrap_or("").to_string(),
            level_class: match i["priority"].as_u64() {
                Some(n) => format!("lv{n}"),
                None => "lvu".to_string(),
            },
        })
        .collect();
    v.reverse();
    (v, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn settings(dir: &std::path::Path) -> LogViewSettings {
        LogViewSettings {
            file_path: dir.join("messages").display().to_string(),
            managed_file: dir.join("none.log").display().to_string(),
            ..LogViewSettings::default()
        }
    }

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn sample(dir: &std::path::Path) {
        let mut f = std::fs::File::create(dir.join("messages")).unwrap();
        for l in [
            "Nov 25 11:59:00 ap kern.notice kernel: [    0.000000] Linux version 6.12.118",
            "Nov 25 11:59:01 ap daemon.info hostapd[301]: wl5: AP-ENABLED",
            "Nov 25 11:59:02 ap daemon.err dnsmasq[88]: failed to bind",
            "Nov 25 11:59:03 ap daemon.warn test-ident: link flapping",
            "Nov 25 11:59:04 ap kern.info kernel: [   12.5] eth0: link up",
            "Nov 25 12:00:00 ap daemon.notice patronus-boot: boot 3f2a9c1e-1111-4222-8333-444455556666",
            "Nov 25 12:00:01 ap daemon.info test-ident: after the reboot",
        ] {
            writeln!(f, "{l}").unwrap();
        }
    }

    #[test]
    fn filters_priority_identifier_kernel_text_and_unit() {
        let d = tempfile::tempdir().unwrap();
        sample(d.path());
        let s = settings(d.path());
        let run = |pairs: &[(&str, &str)]| {
            let f = Filter::from_query(&q(pairs)).unwrap();
            let p = query_files(&s, &f, 100, None);
            p.items
                .iter()
                .filter(|i| i["type"] == "line")
                .map(|i| i["message"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(run(&[("min_priority", "err")]), ["failed to bind"]);
        assert_eq!(run(&[("min_priority", "warning")]).len(), 2);
        assert_eq!(run(&[("identifier", "test-*")]).len(), 2);
        assert_eq!(run(&[("identifier", "test-ident")]).len(), 2);
        assert_eq!(run(&[("kernel", "1")]).len(), 2);
        assert_eq!(run(&[("q", "FLAPPING")]).len(), 1);
        assert_eq!(run(&[("unit", "hostapd.service")]).len(), 1);
        assert_eq!(run(&[]).len(), 7);
    }

    #[test]
    fn separators_for_kernel_marker_and_boot_record_without_duplicates() {
        let d = tempfile::tempdir().unwrap();
        sample(d.path());
        let s = settings(d.path());
        let p = query_files(&s, &Filter::default(), 100, None);
        let types: Vec<&str> = p
            .items
            .iter()
            .map(|i| i["type"].as_str().unwrap())
            .collect();
        assert_eq!(types.iter().filter(|t| **t == "boot").count(), 2);
        assert_eq!(types[0], "boot");
        assert!(p.priority_known);
        assert!(p.identifiers.contains(&"hostapd".to_string()));
    }

    #[test]
    fn page_limit_gives_an_older_cursor_that_continues() {
        let d = tempfile::tempdir().unwrap();
        sample(d.path());
        let s = settings(d.path());
        let p1 = query_files(&s, &Filter::default(), 3, None);
        assert_eq!(p1.items.iter().filter(|i| i["type"] == "line").count(), 3);
        let cur = p1.older_cursor.clone().unwrap();
        let p2 = query_files(&s, &Filter::default(), 3, Some(&cur));
        let m2: Vec<&str> = p2
            .items
            .iter()
            .filter(|i| i["type"] == "line")
            .map(|i| i["message"].as_str().unwrap())
            .collect();
        assert_eq!(m2, ["wl5: AP-ENABLED", "failed to bind", "link flapping"]);
    }

    #[test]
    fn lines_without_priority_are_excluded_by_a_priority_filter_and_flagged() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("messages"),
            "Nov 25 12:00:00 gw sshd[1]: error: bad thing\n",
        )
        .unwrap();
        let s = settings(d.path());
        let p = query_files(
            &s,
            &Filter::from_query(&q(&[("min_priority", "err")])).unwrap(),
            10,
            None,
        );
        assert!(p.items.is_empty());
        assert!(!p.priority_known);
        let p = query_files(&s, &Filter::default(), 10, None);
        assert_eq!(p.items[0]["level"], "unknown");
    }

    #[test]
    fn time_parsing_and_validation() {
        assert_eq!(parse_time("1764100800"), Some(1764100800000));
        assert_eq!(
            parse_time("2026-11-25T20:00:00Z"),
            Some(
                Utc.with_ymd_and_hms(2026, 11, 25, 20, 0, 0)
                    .unwrap()
                    .timestamp_millis()
            )
        );
        assert!(parse_time("2026-11-25 12:30").is_some());
        assert!(parse_time("yesterday").is_none());
        assert!(Filter::from_query(&q(&[
            ("since", "2026-11-25 12:00"),
            ("until", "2026-11-25 11:00")
        ]))
        .is_err());
        assert!(Filter::from_query(&q(&[("min_priority", "loud")])).is_err());
    }

    #[tokio::test]
    async fn follow_delivers_new_lines_and_a_boot_separator() {
        let d = tempfile::tempdir().unwrap();
        sample(d.path());
        let mut s = settings(d.path());
        s.live_poll_ms = 100;
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(follow(s.clone(), Filter::default(), None, tx));
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(d.path().join("messages"))
            .unwrap();
        writeln!(f, "Nov 25 12:01:00 ap daemon.warn live-ident: hello").unwrap();
        writeln!(f, "Nov 25 12:01:05 ap daemon.notice patronus-boot: boot aaaaaaaa-1111-4222-8333-444455556666").unwrap();
        let a = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a["message"], "hello");
        let b = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b["type"], "boot");
    }
}
