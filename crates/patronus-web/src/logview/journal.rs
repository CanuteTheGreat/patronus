//! journald back end: `journalctl -o json` run per request, bounded.
//!
//! A page reads newest-first (`-r`) and stops at the page limit or the scan budget, so
//! a busy journal is never loaded whole. Unit, priority, kernel, time span and plain
//! identifiers are filtered by journalctl itself; wildcard identifiers and free text
//! are filtered here while reading.

use super::parse::{parse_journal, Entry};
use super::{line_json, Filter, Page};
use chrono::{DateTime, Utc};
use patronus_config::logview::LogViewSettings;
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

fn utc(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn args(f: &Filter, follow: bool) -> Vec<String> {
    let mut a: Vec<String> = vec!["-o".into(), "json".into(), "--no-pager".into()];
    if !follow {
        a.push("-r".into());
    }
    if let Some(s) = f.since {
        a.push(format!("--since={}", utc(s)));
    }
    if let Some(u) = f.until {
        a.push(format!("--until={}", utc(u)));
    }
    if let Some(p) = f.min_priority {
        a.push(format!("--priority={p}"));
    }
    if let Some(u) = &f.unit {
        a.push(format!("--unit={u}"));
    }
    if f.kernel {
        a.push("--dmesg".into());
    }
    if let Some(i) = &f.identifier {
        if !i.contains('*') {
            a.push(format!("--identifier={i}"));
        }
    }
    a
}

fn spawn(s: &LogViewSettings, a: &[String]) -> std::io::Result<tokio::process::Child> {
    Command::new(&s.journalctl)
        .args(a)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
}

pub async fn query(
    s: &LogViewSettings,
    f: &Filter,
    limit: usize,
    cursor: Option<&str>,
) -> Result<Page, String> {
    let mut a = args(f, false);
    let skip = cursor.and_then(|c| c.strip_prefix("j:")).map(String::from);
    if let Some(c) = &skip {
        a.push(format!("--cursor={c}"));
    }
    let mut child = spawn(s, &a).map_err(|e| format!("cannot run {}: {e}", s.journalctl))?;
    let out = child.stdout.take().ok_or("no output")?;
    let mut lines = BufReader::new(out).lines();
    let budget = s.max_scan_bytes.saturating_mul(2);
    let (mut bytes, mut seen) = (0u64, 0u64);
    let mut got: Vec<(Entry, String)> = Vec::new();
    let mut idents = std::collections::BTreeSet::new();
    let mut known = false;
    let (mut full, mut limited, mut any) = (false, false, false);
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        any = true;
        bytes += line.len() as u64 + 1;
        if bytes > budget {
            limited = true;
            break;
        }
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some((e, cur)) = parse_journal(&v) else {
            continue;
        };
        if skip.as_deref() == Some(cur.as_str()) {
            continue;
        }
        seen += 1;
        known |= e.priority.is_some();
        if idents.len() < 200 && !e.ident.is_empty() {
            idents.insert(e.ident.clone());
        }
        if f.matches(&e, true, &[]) {
            got.push((e, format!("j:{cur}")));
            if got.len() >= limit {
                full = true;
                break;
            }
        }
    }
    let _ = child.kill().await;
    if !any {
        // no output at all: journalctl missing rights or an empty journal; tell empty from broken
        if let Ok(st) = child.wait().await {
            if !st.success() {
                return Err(format!("{} exited with {st}", s.journalctl));
            }
        }
    }
    let older_cursor = if full || limited {
        got.last().map(|g| g.1.clone())
    } else {
        None
    };
    let newest_cursor = got.first().map(|g| g.1.clone()).unwrap_or_default();
    got.reverse();
    Ok(Page {
        backend: "journald",
        source: "journald".into(),
        items: super::with_separators(got, false),
        older_cursor,
        newest_cursor,
        identifiers: idents.into_iter().collect(),
        scan_limited: limited,
        priority_known: known || !any,
        scanned_lines: seen,
        note: None,
    })
}

/// Follow `journalctl -f`; `Err` only when it cannot be started (the caller falls back to files).
pub async fn follow(
    s: &LogViewSettings,
    f: &Filter,
    cursor: Option<&str>,
    tx: &tokio::sync::mpsc::Sender<Value>,
) -> Result<(), String> {
    let mut live = f.clone();
    live.since = None;
    live.until = None;
    let mut a = args(&live, true);
    a.push("--follow".into());
    match cursor.and_then(|c| c.strip_prefix("j:")) {
        Some(c) => a.push(format!("--after-cursor={c}")),
        None => {
            a.push("--lines=0".into());
        }
    }
    let mut child = spawn(s, &a).map_err(|e| format!("cannot run {}: {e}", s.journalctl))?;
    let out = child.stdout.take().ok_or("no output")?;
    let mut lines = BufReader::new(out).lines();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(s.stream_max_secs);
    let mut last_boot: Option<String> = None;
    loop {
        let next = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
            lines.next_line(),
        )
        .await;
        if tx.is_closed() || tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        let Ok(r) = next else { continue };
        let Ok(Some(line)) = r else { return Ok(()) };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some((e, cur)) = parse_journal(&v) else {
            continue;
        };
        if !live.matches(&e, true, &[]) {
            continue;
        }
        if let Some(b) = &e.boot_id {
            if last_boot.as_deref().is_some_and(|l| l != b)
                && tx.send(super::boot_json(e.ts, Some(b))).await.is_err()
            {
                return Ok(());
            }
            last_boot = Some(b.clone());
        }
        if tx.send(line_json(&e, &format!("j:{cur}"))).await.is_err() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journalctl_arguments_follow_the_filters() {
        let f = Filter {
            since: Some(1764100800000),
            min_priority: Some(3),
            unit: Some("unbound".into()),
            identifier: Some("patronus-*".into()),
            kernel: true,
            ..Filter::default()
        };
        let a = args(&f, false);
        assert!(a.contains(&"-r".to_string()));
        assert!(a.contains(&"--since=2025-11-25 20:00:00 UTC".to_string()));
        assert!(a.contains(&"--priority=3".to_string()));
        assert!(a.contains(&"--unit=unbound".to_string()));
        assert!(a.contains(&"--dmesg".to_string()));
        // a wildcard identifier is matched here, not by journalctl
        assert!(!a.iter().any(|x| x.starts_with("--identifier")));
        let plain = args(
            &Filter {
                identifier: Some("sshd".into()),
                ..Filter::default()
            },
            true,
        );
        assert!(plain.contains(&"--identifier=sshd".to_string()));
        assert!(!plain.contains(&"-r".to_string()));
    }

    #[tokio::test]
    async fn reads_a_fake_journalctl_newest_first_with_boot_change() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let sh = d.path().join("journalctl");
        std::fs::write(
            &sh,
            r#"#!/bin/sh
echo '{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"3000000","PRIORITY":"3","_BOOT_ID":"bbbb","SYSLOG_IDENTIFIER":"unbound","MESSAGE":"third"}'
echo '{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"2000000","PRIORITY":"6","_BOOT_ID":"bbbb","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"second"}'
echo '{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1000000","PRIORITY":"4","_BOOT_ID":"aaaa","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"first"}'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = LogViewSettings {
            journalctl: sh.display().to_string(),
            ..LogViewSettings::default()
        };
        let p = query(&s, &Filter::default(), 10, None).await.unwrap();
        let kinds: Vec<&str> = p
            .items
            .iter()
            .map(|i| i["type"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["line", "boot", "line", "line"]);
        assert_eq!(p.items[0]["message"], "first");
        assert_eq!(p.newest_cursor, "j:c3");
        let f = Filter {
            identifier: Some("sshd".into()),
            ..Filter::default()
        };
        let p = query(&s, &f, 1, None).await.unwrap();
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0]["message"], "second");
        assert_eq!(p.older_cursor.as_deref(), Some("j:c2"));
    }
}
