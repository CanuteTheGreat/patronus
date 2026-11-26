//! IDS/IPS rule-set manager (USE=intrusion-detection, docs/IDS-RULESETS.md).
//!
//! - **Sources** (`ids_sources`, typed config: key, URL, format, licence, enabled, size cap): rule
//!   sets such as ET Open or the abuse.ch lists. The product downloads them itself (`curl`, the
//!   nightly window of the page's settings, or the "Update now" button), unpacks the `*.rules`
//!   files into `<state>/suricata/sources/<key>/next/`, and only after a full `suricata -T` of the
//!   merged candidate set accepts them does `next` become `current` (the old `current` is kept as
//!   `prev`). A download Suricata rejects, an empty or oversized one never replaces anything: the
//!   old rule set keeps running and the source shows `rejected` / `failed` with the reason.
//! - **Policy**: per rule set, per category (the rule file, `emerging-malware`) and per classtype
//!   an action `alert` / `drop` / `disable`; a per-SID override beats all of them. Applied while
//!   the merged `sources.rules` is written, so the downloaded files stay untouched.
//! - **Suppress / threshold** entries become `threshold.config`.
//!
//! Rule files, state of the downloads and the alert history are data, not configuration: the
//! `ids_source_state`, `ids_alerts`, `ids_alert_pos` and `ids_update_request` tables are in
//! `NON_CONFIG_TABLES` (alerts have retention, see `ids_alerts`).

use crate::lan::{self, db_err, invalid, now};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const SOURCES_DIR: &str = "sources";
/// Suricata rule actions a rule line may start with.
const ACTIONS: &[&str] = &[
    "alert",
    "drop",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
    "pass",
];

/// What a policy or override does to a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Alert,
    Drop,
    Disable,
}

impl Act {
    pub fn parse(s: &str) -> Option<Act> {
        match s {
            "alert" => Some(Act::Alert),
            "drop" => Some(Act::Drop),
            "disable" => Some(Act::Disable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Source {
    pub key: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub licence: String,
    pub enabled: bool,
    pub max_mb: i64,
}

pub async fn sources(store: &ConfigStore) -> Result<Vec<Source>> {
    let rows = sqlx::query(
        "SELECT key, name, url, format, COALESCE(licence,''), enabled, max_mb FROM ids_sources ORDER BY id",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ids_sources"))?;
    Ok(rows
        .iter()
        .map(|r| Source {
            key: r.get(0),
            name: r.get(1),
            url: r.get(2),
            format: r.get(3),
            licence: r.get(4),
            enabled: r.get::<i64, _>(5) != 0,
            max_mb: r.get(6),
        })
        .collect())
}

/// A download URL: http(s) only, one printable token.
pub fn check_url(u: &str) -> Result<()> {
    let ok = (u.starts_with("http://") || u.starts_with("https://"))
        && u.len() <= 400
        && u.len() > 10
        && u.bytes().all(|b| {
            (0x21..0x7f).contains(&b) && !matches!(b, b'"' | b'\'' | b'\\' | b'`' | b'<' | b'>')
        });
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "rule source URL {u:?} (http:// or https://, no spaces or quotes)"
        )))
    }
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct Policies {
    pub rulesets: HashMap<String, Act>,
    pub categories: HashMap<String, Act>,
    pub classtypes: HashMap<String, Act>,
    pub sids: HashMap<u64, Act>,
}

impl Policies {
    pub async fn load(store: &ConfigStore) -> Result<Self> {
        let mut p = Policies::default();
        let rows = sqlx::query(
            "SELECT scope, target, action FROM ids_policies WHERE enabled = 1 ORDER BY id",
        )
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read ids_policies"))?;
        for r in rows {
            let (scope, target, action): (String, String, String) = (r.get(0), r.get(1), r.get(2));
            let Some(a) = Act::parse(&action) else {
                continue;
            };
            let m = match scope.as_str() {
                "ruleset" => &mut p.rulesets,
                "category" => &mut p.categories,
                "classtype" => &mut p.classtypes,
                _ => continue,
            };
            m.insert(target, a);
        }
        let rows =
            sqlx::query("SELECT sid, action FROM ids_overrides WHERE enabled = 1 ORDER BY id")
                .fetch_all(store.pool()?)
                .await
                .map_err(db_err("read ids_overrides"))?;
        for r in rows {
            let (sid, action): (i64, String) = (r.get(0), r.get(1));
            if let Some(a) = Act::parse(&action) {
                p.sids.insert(sid as u64, a);
            }
        }
        Ok(p)
    }
}

// ---------------------------------------------------------------------------
// rule files
// ---------------------------------------------------------------------------

/// One rule line split into what the policy needs.
#[derive(Debug)]
pub struct Parsed<'a> {
    /// The rule was commented out (`# alert ...`) as shipped.
    pub shipped_off: bool,
    pub action: &'a str,
    /// Everything after the action keyword.
    pub body: &'a str,
    pub sid: u64,
    pub classtype: Option<&'a str>,
}

pub fn parse_rule(line: &str) -> Option<Parsed<'_>> {
    let t = line.trim();
    let rest = t.trim_start_matches('#');
    let off = rest.len() != t.len();
    let rest = rest.trim_start();
    let (action, body) = rest.split_once(char::is_whitespace)?;
    if !ACTIONS.contains(&action) {
        return None;
    }
    let sid = {
        let mut found = None;
        let mut from = body.len();
        while let Some(i) = body[..from].rfind("sid:") {
            let before = body[..i].chars().next_back().unwrap_or(' ');
            if before == ';' || before == '(' || before.is_whitespace() {
                let digits: String = body[i + 4..]
                    .trim_start()
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                if let Ok(n) = digits.parse::<u64>() {
                    found = Some(n);
                    break;
                }
            }
            from = i;
        }
        found?
    };
    let classtype = body.find("classtype:").map(|i| {
        let v = &body[i + 10..];
        v[..v.find(';').unwrap_or(v.len())].trim()
    });
    Some(Parsed {
        shipped_off: off,
        action,
        body,
        sid,
        classtype,
    })
}

/// Join `\`-continued lines.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for l in text.lines() {
        if let Some(stripped) = l.strip_suffix('\\') {
            cur.push_str(stripped);
            continue;
        }
        cur.push_str(l);
        out.push(std::mem::take(&mut cur));
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Number of rules in a file as shipped and of those switched on.
pub fn count_rules(text: &str) -> (usize, usize) {
    let (mut all, mut on) = (0, 0);
    for l in logical_lines(text) {
        if let Some(p) = parse_rule(&l) {
            all += 1;
            if !p.shipped_off {
                on += 1;
            }
        }
    }
    (all, on)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub loaded: usize,
    pub dropping: usize,
    pub disabled_by_policy: usize,
    pub off_as_shipped: usize,
}

/// Apply the policy to the rules of one file; returns the rules to load.
pub fn transform(text: &str, ruleset: &str, category: &str, pol: &Policies) -> (String, Stats) {
    let mut out = String::new();
    let mut st = Stats::default();
    for l in logical_lines(text) {
        let Some(p) = parse_rule(&l) else { continue };
        let by_sid = pol.sids.get(&p.sid).copied();
        let policy = by_sid
            .or_else(|| p.classtype.and_then(|c| pol.classtypes.get(c).copied()))
            .or_else(|| pol.categories.get(category).copied())
            .or_else(|| pol.rulesets.get(ruleset).copied());
        if policy == Some(Act::Disable) {
            st.disabled_by_policy += 1;
            continue;
        }
        // a rule shipped switched off stays off, unless its SID is overridden to alert/drop
        if p.shipped_off && by_sid.is_none() {
            st.off_as_shipped += 1;
            continue;
        }
        let act = match policy {
            Some(Act::Alert) if p.action != "pass" || by_sid.is_some() => "alert",
            Some(Act::Drop) if p.action != "pass" || by_sid.is_some() => "drop",
            _ => p.action,
        };
        if act == "drop" || act.starts_with("reject") {
            st.dropping += 1;
        }
        st.loaded += 1;
        out.push_str(act);
        out.push(' ');
        out.push_str(p.body);
        out.push('\n');
    }
    (out, st)
}

fn src_dir(base: &Path, key: &str) -> PathBuf {
    base.join(SOURCES_DIR).join(key)
}

/// `*.rules` files of a directory as (category = file stem, path), sorted.
fn rule_files(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_str()?.to_string();
            let stem = name.strip_suffix(".rules")?.to_string();
            let md = std::fs::symlink_metadata(&p).ok()?;
            md.is_file().then_some((stem, p))
        })
        .collect();
    v.sort();
    v
}

#[derive(Debug, Default)]
pub struct Rendered {
    pub text: String,
    pub per_source: BTreeMap<String, Stats>,
    /// category -> rule count (as shipped), for the policy form.
    pub categories: BTreeMap<String, usize>,
}

impl Rendered {
    pub fn loaded(&self) -> usize {
        self.per_source.values().map(|s| s.loaded).sum()
    }
}

/// The merged `sources.rules`: every enabled source's `current` files (or `replace` for one key)
/// with the policy applied.
pub async fn render_sources(
    store: &ConfigStore,
    base: &Path,
    replace: Option<(&str, &Path)>,
) -> Result<Rendered> {
    let pol = Policies::load(store).await?;
    let mut r = Rendered {
        text: lan::header("#", "Suricata rule sets"),
        ..Default::default()
    };
    for s in sources(store).await?.into_iter().filter(|s| s.enabled) {
        let dir = match replace {
            Some((k, d)) if k == s.key => d.to_path_buf(),
            _ => src_dir(base, &s.key).join("current"),
        };
        let mut st = Stats::default();
        for (cat, path) in rule_files(&dir) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (body, fs) = transform(&text, &s.key, &cat, &pol);
            *r.categories.entry(cat.clone()).or_default() += fs.loaded;
            r.text.push_str(&format!("# {} / {cat}\n", s.key));
            r.text.push_str(&body);
            st.loaded += fs.loaded;
            st.dropping += fs.dropping;
            st.disabled_by_policy += fs.disabled_by_policy;
            st.off_as_shipped += fs.off_as_shipped;
        }
        r.per_source.insert(s.key.clone(), st);
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// suppress / threshold -> threshold.config
// ---------------------------------------------------------------------------

/// `threshold.config` lines of the enabled `ids_suppress` rows.
pub async fn render_threshold(store: &ConfigStore) -> Result<String> {
    let rows = sqlx::query(
        "SELECT sid, kind, COALESCE(track,''), COALESCE(ip,''), COALESCE(count,0), COALESCE(seconds,0) \
         FROM ids_suppress WHERE enabled = 1 ORDER BY id",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ids_suppress"))?;
    let mut c = lan::header("#", "Suricata suppress / threshold");
    for r in rows {
        let (sid, kind, track, ip, count, secs): (i64, String, String, String, i64, i64) =
            (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5));
        let tr = if track == "by_dst" {
            "by_dst"
        } else {
            "by_src"
        };
        if kind == "suppress" {
            if (track == "by_src" || track == "by_dst") && !ip.is_empty() {
                c.push_str(&format!(
                    "suppress gen_id 1, sig_id {sid}, track {tr}, ip {ip}\n"
                ));
            } else {
                c.push_str(&format!("suppress gen_id 1, sig_id {sid}\n"));
            }
        } else if matches!(kind.as_str(), "limit" | "threshold" | "both") {
            c.push_str(&format!(
                "threshold gen_id 1, sig_id {sid}, type {kind}, track {tr}, count {}, seconds {}\n",
                count.max(1),
                secs.max(1)
            ));
        }
    }
    Ok(c)
}

// ---------------------------------------------------------------------------
// state of the downloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct SourceState {
    pub checked_at: Option<i64>,
    pub ok_at: Option<i64>,
    pub status: String,
    pub message: String,
    pub rules: i64,
    pub bytes: i64,
    pub sha256: String,
}

pub async fn state(store: &ConfigStore) -> Result<HashMap<String, SourceState>> {
    let rows = sqlx::query(
        "SELECT key, checked_at, ok_at, status, message, rules, bytes, sha256 FROM ids_source_state",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ids_source_state"))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<String, _>(0),
                SourceState {
                    checked_at: r.get(1),
                    ok_at: r.get(2),
                    status: r.get(3),
                    message: r.get(4),
                    rules: r.get(5),
                    bytes: r.get(6),
                    sha256: r.get(7),
                },
            )
        })
        .collect())
}

async fn put_state(store: &ConfigStore, key: &str, s: &SourceState) -> Result<()> {
    sqlx::query(
        "INSERT INTO ids_source_state (key, checked_at, ok_at, status, message, rules, bytes, sha256) \
         VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET checked_at=excluded.checked_at, \
         ok_at=excluded.ok_at, status=excluded.status, message=excluded.message, rules=excluded.rules, \
         bytes=excluded.bytes, sha256=excluded.sha256",
    )
    .bind(key)
    .bind(s.checked_at)
    .bind(s.ok_at)
    .bind(&s.status)
    .bind(&s.message)
    .bind(s.rules)
    .bind(s.bytes)
    .bind(&s.sha256)
    .execute(store.pool()?)
    .await
    .map_err(db_err("write ids_source_state"))?;
    Ok(())
}

/// (requested_at, done_at) of the "Update now" button.
pub async fn update_request(store: &ConfigStore) -> (i64, i64) {
    let Ok(pool) = store.pool() else {
        return (0, 0);
    };
    sqlx::query("SELECT requested_at, done_at FROM ids_update_request WHERE id = 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| (r.get(0), r.get(1)))
        .unwrap_or((0, 0))
}

pub async fn request_update(store: &ConfigStore) -> Result<()> {
    sqlx::query(
        "INSERT INTO ids_update_request (id, requested_at, done_at) VALUES (1, ?, 0) \
         ON CONFLICT(id) DO UPDATE SET requested_at = excluded.requested_at",
    )
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db_err("write ids_update_request"))?;
    Ok(())
}

pub async fn mark_update_done(store: &ConfigStore, at: i64) {
    if let Ok(pool) = store.pool() {
        let _ = sqlx::query(
            "INSERT INTO ids_update_request (id, requested_at, done_at) VALUES (1, 0, ?) \
             ON CONFLICT(id) DO UPDATE SET done_at = excluded.done_at",
        )
        .bind(at)
        .execute(pool)
        .await;
    }
}

// ---------------------------------------------------------------------------
// schedule
// ---------------------------------------------------------------------------

/// The page's update schedule.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    pub enabled: bool,
    /// Local hour the nightly window opens.
    pub hour: i64,
    pub window_hours: i64,
    pub interval_hours: i64,
    /// Hold-off between two attempts of a source that failed or was rejected (minutes).
    pub retry_minutes: i64,
}

impl Schedule {
    /// Is local `hour` inside the window (it may wrap midnight)?
    pub fn in_window(&self, hour: i64) -> bool {
        let start = self.hour.rem_euclid(24);
        (hour - start).rem_euclid(24) < self.window_hours.clamp(1, 24)
    }

    /// Does `s` need a download now? A source never fetched is fetched at once (outside the
    /// window too: a rule set the owner just switched on must not wait for the night); an older
    /// one when its interval is up and the window is open. A failure waits `retry_minutes`.
    pub fn due(&self, st: Option<&SourceState>, now: i64, local_hour: i64) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(st) = st else { return true };
        let retry = self.retry_minutes.max(1) * 60;
        if let Some(c) = st.checked_at {
            if matches!(st.status.as_str(), "failed" | "rejected") && now - c < retry {
                return false;
            }
        }
        match st.ok_at {
            None => st.checked_at.map(|c| now - c >= retry).unwrap_or(true),
            Some(ok) => {
                now - ok >= self.interval_hours.max(1) * 3600
                    && self.in_window(local_hour)
                    && st.checked_at.map(|c| now - c >= retry).unwrap_or(true)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// download
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Fetch: Send + Sync {
    async fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>>;
}

/// `curl` (the same tool the threat feeds use).
pub struct CurlFetch {
    pub tmp: PathBuf,
}

#[async_trait]
impl Fetch for CurlFetch {
    async fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        check_url(url)?;
        std::fs::create_dir_all(&self.tmp)
            .map_err(|e| Error::Service(format!("{}: {e}", self.tmp.display())))?;
        let tmp = self.tmp.join(format!(".dl-{}", std::process::id()));
        let out = tokio::process::Command::new("curl")
            .args([
                "-fsSL",
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--max-time",
                "300",
                "--connect-timeout",
                "20",
                "--max-filesize",
                &max_bytes.to_string(),
                "-A",
                "Patronus-ids/1.0",
                "-o",
            ])
            .arg(&tmp)
            .arg("--")
            .arg(url)
            .output()
            .await
            .map_err(|e| Error::Service(format!("cannot run curl: {e}")))?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Service(format!(
                "download failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let b = std::fs::read(&tmp).map_err(|e| Error::Service(format!("read download: {e}")));
        let _ = std::fs::remove_file(&tmp);
        b
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Unpack a download into `dest` (flat `*.rules` files). Returns the file count.
pub fn extract(format: &str, key: &str, data: &[u8], dest: &Path, max_out: u64) -> Result<usize> {
    let fail = |m: String| Error::Service(m);
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest).map_err(|e| fail(format!("{}: {e}", dest.display())))?;
    match format {
        "rules" => {
            if data.len() as u64 > max_out {
                return Err(fail("download is larger than the size cap".into()));
            }
            std::fs::write(dest.join(format!("{key}.rules")), data)
                .map_err(|e| fail(format!("write rules: {e}")))?;
            Ok(1)
        }
        "rules.gz" => {
            let plain = gunzip(data, max_out)?;
            std::fs::write(dest.join(format!("{key}.rules")), plain)
                .map_err(|e| fail(format!("write rules: {e}")))?;
            Ok(1)
        }
        "tar.gz" => {
            let stage = dest.join(".x");
            std::fs::create_dir_all(&stage)
                .map_err(|e| fail(format!("{}: {e}", stage.display())))?;
            let tgz = dest.join(".x.tgz");
            std::fs::write(&tgz, data).map_err(|e| fail(format!("write archive: {e}")))?;
            let list = std::process::Command::new("tar")
                .arg("-tzf")
                .arg(&tgz)
                .output()
                .map_err(|e| fail(format!("cannot run tar: {e}")))?;
            if !list.status.success() {
                return Err(fail(format!(
                    "not a tar.gz archive: {}",
                    String::from_utf8_lossy(&list.stderr).trim()
                )));
            }
            for name in String::from_utf8_lossy(&list.stdout).lines() {
                if name.starts_with('/') || name.split('/').any(|c| c == "..") {
                    return Err(fail(format!("unsafe path in the archive: {name:?}")));
                }
            }
            let x = std::process::Command::new("tar")
                .arg("-xzf")
                .arg(&tgz)
                .arg("-C")
                .arg(&stage)
                .arg("--no-same-owner")
                .output()
                .map_err(|e| fail(format!("cannot run tar: {e}")))?;
            if !x.status.success() {
                return Err(fail(format!(
                    "unpacking failed: {}",
                    String::from_utf8_lossy(&x.stderr).trim()
                )));
            }
            let mut n = 0;
            let mut total = 0u64;
            let mut stack = vec![stage.clone()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let p = e.path();
                    let Ok(md) = std::fs::symlink_metadata(&p) else {
                        continue;
                    };
                    if md.is_dir() {
                        stack.push(p);
                    } else if md.is_file() && p.extension().is_some_and(|x| x == "rules") {
                        total += md.len();
                        if total > max_out {
                            return Err(fail("unpacked rules are larger than the size cap".into()));
                        }
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("x.rules");
                        if std::fs::copy(&p, dest.join(name)).is_ok() {
                            n += 1;
                        }
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&stage);
            let _ = std::fs::remove_file(&tgz);
            Ok(n)
        }
        other => Err(fail(format!("unknown format {other:?}"))),
    }
}

fn gunzip(data: &[u8], max_out: u64) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    let mut ch = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| Error::Service(format!("cannot run gzip: {e}")))?;
    let mut stdin = ch.stdin.take().expect("piped");
    let input = data.to_vec();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = Vec::new();
    let mut so = ch.stdout.take().expect("piped").take(max_out + 1);
    so.read_to_end(&mut out)
        .map_err(|e| Error::Service(format!("gzip: {e}")))?;
    if out.len() as u64 > max_out {
        let _ = ch.kill();
        return Err(Error::Service(
            "unpacked rules are larger than the size cap".into(),
        ));
    }
    let _ = w.join();
    let st = ch
        .wait()
        .map_err(|e| Error::Service(format!("gzip: {e}")))?;
    if !st.success() {
        return Err(Error::Service("not gzip data".into()));
    }
    Ok(out)
}

/// Installed Suricata's version (`7.0.8`), for the `{suricata_version}` URL placeholder.
pub fn suricata_version(bin: &Path) -> Option<String> {
    let o = std::process::Command::new(bin).arg("-V").output().ok()?;
    let t = String::from_utf8_lossy(&o.stdout);
    t.split_whitespace()
        .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()) && w.contains('.'))
        .map(|w| {
            w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                .to_string()
        })
}

/// Result of one source in one run.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub key: String,
    pub status: String,
    pub message: String,
}

/// The files a candidate rule bundle needs besides the downloaded sets.
pub struct Extra<'a> {
    pub files: Vec<(&'a str, String)>,
}

/// Download, check and swap in the sources that are due (`force`: every enabled one).
/// `validate(dir)` must load the bundle in `dir` (`sources.rules` plus the `extra` files) the way
/// Suricata would (`suricata -T`); an `Err` refuses that source's new rules.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    store: &ConfigStore,
    base: &Path,
    fetch: &dyn Fetch,
    sched: &Schedule,
    force: bool,
    version: Option<&str>,
    extra: &Extra<'_>,
    validate: &mut (dyn FnMut(&Path) -> std::result::Result<(), String> + Send),
) -> Result<Vec<Outcome>> {
    let states = state(store).await?;
    let t = now();
    let hour = {
        use chrono::Timelike;
        chrono::Local::now().hour() as i64
    };
    let mut outs = Vec::new();
    for s in sources(store).await? {
        if !s.enabled {
            continue;
        }
        if !force && !sched.due(states.get(&s.key), t, hour) {
            continue;
        }
        let mut st = states.get(&s.key).cloned().unwrap_or_default();
        st.checked_at = Some(t);
        let res = fetch_one(store, base, fetch, &s, version, extra, validate).await;
        match res {
            Ok((status, rules, bytes, sha, msg)) => {
                if status == "ok" || status == "unchanged" {
                    st.ok_at = Some(t);
                    st.rules = rules;
                    st.bytes = bytes;
                    st.sha256 = sha;
                }
                st.status = status.clone();
                st.message = msg.clone();
                outs.push(Outcome {
                    key: s.key.clone(),
                    status,
                    message: msg,
                });
            }
            Err((status, msg)) => {
                st.status = status.clone();
                st.message = msg.clone();
                outs.push(Outcome {
                    key: s.key.clone(),
                    status,
                    message: msg,
                });
            }
        }
        put_state(store, &s.key, &st).await?;
    }
    Ok(outs)
}

type Ok1 = (String, i64, i64, String, String);

async fn fetch_one(
    store: &ConfigStore,
    base: &Path,
    fetch: &dyn Fetch,
    s: &Source,
    version: Option<&str>,
    extra: &Extra<'_>,
    validate: &mut (dyn FnMut(&Path) -> std::result::Result<(), String> + Send),
) -> std::result::Result<Ok1, (String, String)> {
    let failed = |m: String| ("failed".to_string(), m);
    let mut url = s.url.clone();
    if url.contains("{suricata_version}") {
        let v = version.ok_or_else(|| {
            failed("this URL needs the Suricata version, which could not be read".into())
        })?;
        url = url.replace("{suricata_version}", v);
    }
    let cap = (s.max_mb.max(1) as u64) * 1024 * 1024;
    let data = fetch
        .get(&url, cap)
        .await
        .map_err(|e| failed(e.to_string()))?;
    if data.is_empty() || data.len() as u64 > cap {
        return Err(failed("empty download or larger than the size cap".into()));
    }
    let sha = sha256_hex(&data);
    let dir = src_dir(base, &s.key);
    let cur = dir.join("current");
    let next = dir.join("next");
    let same = std::fs::read_to_string(dir.join("sha256")).ok().as_deref() == Some(sha.as_str())
        && !rule_files(&cur).is_empty();
    if same {
        let rules: i64 = rule_files(&cur)
            .iter()
            .map(|(_, p)| count_rules(&std::fs::read_to_string(p).unwrap_or_default()).0 as i64)
            .sum();
        return Ok((
            "unchanged".into(),
            rules,
            data.len() as i64,
            sha,
            "no change since the last download".into(),
        ));
    }
    let files =
        extract(&s.format, &s.key, &data, &next, cap * 8).map_err(|e| failed(e.to_string()))?;
    if files == 0 {
        let _ = std::fs::remove_dir_all(&next);
        return Err(failed("the download holds no .rules file".into()));
    }
    let mut total = 0usize;
    for (_, p) in rule_files(&next) {
        total += count_rules(&std::fs::read_to_string(&p).unwrap_or_default()).0;
    }
    if total == 0 {
        let _ = std::fs::remove_dir_all(&next);
        return Err(failed("the download holds no rules".into()));
    }
    // the whole candidate set (this source's new files, everything else as it runs now)
    let cand = base.join("cand");
    let _ = std::fs::remove_dir_all(&cand);
    std::fs::create_dir_all(&cand).map_err(|e| failed(format!("{}: {e}", cand.display())))?;
    let r = render_sources(store, base, Some((&s.key, &next)))
        .await
        .map_err(|e| failed(e.to_string()))?;
    std::fs::write(cand.join("sources.rules"), &r.text)
        .map_err(|e| failed(format!("write candidate: {e}")))?;
    for (n, t) in &extra.files {
        std::fs::write(cand.join(n), t).map_err(|e| failed(format!("write candidate: {e}")))?;
    }
    let verdict = validate(&cand);
    let _ = std::fs::remove_dir_all(&cand);
    if let Err(why) = verdict {
        let _ = std::fs::remove_dir_all(&next);
        return Err((
            "rejected".into(),
            format!("rejected by suricata -T, the previous rules stay in use: {why}"),
        ));
    }
    // swap: current -> prev, next -> current (the last good set is always one of the two)
    let prev = dir.join("prev");
    let _ = std::fs::remove_dir_all(&prev);
    if cur.exists() {
        std::fs::rename(&cur, &prev).map_err(|e| failed(format!("keep the old rules: {e}")))?;
    }
    std::fs::rename(&next, &cur).map_err(|e| failed(format!("install the new rules: {e}")))?;
    let _ = std::fs::write(dir.join("sha256"), &sha);
    Ok((
        "ok".into(),
        total as i64,
        data.len() as i64,
        sha,
        format!("{total} rules in {files} file(s)"),
    ))
}

/// For the API/UI: one entry per source with its state.
pub async fn overview(store: &ConfigStore, base: &Path) -> Result<Value> {
    let st = state(store).await?;
    let mut v = Vec::new();
    for s in sources(store).await? {
        let x = st.get(&s.key).cloned().unwrap_or_default();
        let have = !rule_files(&src_dir(base, &s.key).join("current")).is_empty();
        v.push(json!({
            "key": s.key, "name": s.name, "licence": s.licence, "enabled": s.enabled,
            "status": if x.status.is_empty() { if s.enabled { "waiting" } else { "disabled" } } else { x.status.as_str() },
            "message": x.message, "rules": x.rules, "bytes": x.bytes,
            "checked_at": x.checked_at, "updated_at": x.ok_at, "downloaded": have,
        }));
    }
    Ok(Value::Array(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ET: &str = "# comment\n\
alert tcp any any -> any 80 (msg:\"A\"; content:\"aaa\"; classtype:trojan-activity; sid:100; rev:1;)\n\
#alert tcp any any -> any 80 (msg:\"B off\"; content:\"bbb\"; classtype:misc-activity; sid:101; rev:1;)\n\
drop udp any any -> any 53 (msg:\"C\"; classtype:bad-unknown; sid:102; rev:2;)\n\
pass ip any any -> any any (msg:\"D\"; sid:103; rev:1;)\n\
alert http any any -> any any (msg:\"E multi\"; \\\n  content:\"eee\"; sid:104; rev:1;)\n";

    #[test]
    fn rules_are_parsed_with_sid_classtype_and_shipped_state() {
        let p =
            parse_rule("#alert tcp any any -> any 80 (msg:\"x\"; classtype:a-b; sid:7; rev:1;)")
                .unwrap();
        assert!(p.shipped_off && p.sid == 7 && p.classtype == Some("a-b") && p.action == "alert");
        assert!(parse_rule("# just a comment sid:5").is_none());
        assert!(parse_rule("alert tcp any any -> any any (msg:\"no sid\";)").is_none());
        assert_eq!(count_rules(ET), (5, 4));
    }

    #[test]
    fn policy_precedence_is_sid_then_classtype_then_category_then_ruleset() {
        let mut pol = Policies::default();
        let (t, st) = transform(ET, "et", "emerging-x", &pol);
        assert_eq!(st.loaded, 4);
        assert_eq!(st.off_as_shipped, 1);
        assert!(t.contains("drop udp any any -> any 53") && !t.contains("B off"));
        assert!(
            t.contains("msg:\"E multi\";") && t.contains("content:\"eee\""),
            "{t}"
        );
        pol.rulesets.insert("et".into(), Act::Drop);
        let (t, st) = transform(ET, "et", "emerging-x", &pol);
        assert!(t.contains("drop tcp any any -> any 80 (msg:\"A\""), "{t}");
        assert!(
            t.contains("pass ip"),
            "pass rules are not turned into drops by a bulk policy"
        );
        assert_eq!(st.dropping, 3);
        pol.categories.insert("emerging-x".into(), Act::Alert);
        let (t, st) = transform(ET, "et", "emerging-x", &pol);
        assert!(t.contains("alert udp any any -> any 53") && st.dropping == 0);
        pol.classtypes
            .insert("trojan-activity".into(), Act::Disable);
        let (t, st) = transform(ET, "et", "emerging-x", &pol);
        assert!(!t.contains("sid:100;") && st.disabled_by_policy == 1);
        pol.sids.insert(100, Act::Drop);
        let (t, _) = transform(ET, "et", "emerging-x", &pol);
        assert!(t.contains("drop tcp any any -> any 80 (msg:\"A\""));
        // an override turns a rule that shipped switched off on
        pol.sids.insert(101, Act::Alert);
        let (t, _) = transform(ET, "et", "emerging-x", &pol);
        assert!(
            t.contains("alert tcp any any -> any 80 (msg:\"B off\""),
            "{t}"
        );
        // a category the policy does not name keeps its own action
        let (t, _) = transform(ET, "et", "other", &Policies::default());
        assert!(t.contains("drop udp"));
    }

    #[test]
    fn schedule_waits_for_the_window_but_not_for_a_first_download() {
        let s = Schedule {
            enabled: true,
            hour: 3,
            window_hours: 3,
            interval_hours: 24,
            retry_minutes: 60,
        };
        assert!(s.in_window(3) && s.in_window(5) && !s.in_window(6) && !s.in_window(2));
        let wrap = Schedule {
            hour: 23,
            window_hours: 3,
            ..s
        };
        assert!(wrap.in_window(23) && wrap.in_window(1) && !wrap.in_window(2));
        let day = 86_400;
        assert!(s.due(None, 1000, 14), "a new source is fetched at once");
        let ok = SourceState {
            checked_at: Some(1000),
            ok_at: Some(1000),
            status: "ok".into(),
            ..Default::default()
        };
        assert!(!s.due(Some(&ok), 1000 + day / 2, 4), "not yet 24 h");
        assert!(
            !s.due(Some(&ok), 1000 + day + 10, 14),
            "old enough but outside the window"
        );
        assert!(
            s.due(Some(&ok), 1000 + day + 10, 4),
            "old enough and in the window"
        );
        let bad = SourceState {
            checked_at: Some(5000),
            status: "failed".into(),
            ..Default::default()
        };
        assert!(
            !s.due(Some(&bad), 5000 + 600, 14),
            "a failure waits an hour"
        );
        assert!(s.due(Some(&bad), 5000 + 3600 + 1, 14));
        assert!(!Schedule {
            enabled: false,
            ..s
        }
        .due(None, 0, 4));
    }

    #[test]
    fn urls_are_http_only() {
        assert!(check_url("https://rules.example.net/a/b.tar.gz?x=1").is_ok());
        for bad in [
            "ftp://x.example/a",
            "https://x y",
            "https://x\"y.example",
            "file:///etc/passwd",
            "http://",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    struct Fake(std::sync::Mutex<HashMap<String, std::result::Result<Vec<u8>, String>>>);
    #[async_trait]
    impl Fetch for Fake {
        async fn get(&self, url: &str, _m: u64) -> Result<Vec<u8>> {
            match self.0.lock().unwrap().get(url) {
                Some(Ok(b)) => Ok(b.clone()),
                Some(Err(e)) => Err(Error::Service(e.clone())),
                None => Err(Error::Service(format!("404 {url}"))),
            }
        }
    }

    #[tokio::test]
    async fn update_swaps_good_rules_in_and_refuses_bad_ones() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        sqlx::query("UPDATE ids_sources SET enabled = 1 WHERE key = 'oisf-trafficid'")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let url = "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules".to_string();
        let good = b"alert tcp any any -> any 80 (msg:\"one\"; sid:1; rev:1;)\n".to_vec();
        let f = Fake(std::sync::Mutex::new(HashMap::from([(
            url.clone(),
            Ok(good.clone()),
        )])));
        let sched = Schedule {
            enabled: true,
            hour: 3,
            window_hours: 3,
            interval_hours: 24,
            retry_minutes: 60,
        };
        let extra = Extra {
            files: vec![("patronus.rules", String::new())],
        };
        let mut ok = |_: &Path| Ok(());
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
            .await
            .unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].status, "ok", "{o:?}");
        let r = render_sources(&s, d.path(), None).await.unwrap();
        assert!(r.text.contains("sid:1;") && r.loaded() == 1);
        // the same bytes again: unchanged
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
            .await
            .unwrap();
        assert_eq!(o[0].status, "unchanged");
        // new bytes that the validator refuses: old set stays, state says rejected
        f.0.lock().unwrap().insert(
            url.clone(),
            Ok(b"alert tcp any any -> any 80 (msg:\"two\"; sid:2; rev:1;)\n".to_vec()),
        );
        let mut no = |_: &Path| Err("rule 2 is broken".to_string());
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut no)
            .await
            .unwrap();
        assert_eq!(o[0].status, "rejected", "{o:?}");
        assert!(o[0].message.contains("rule 2 is broken"));
        let r = render_sources(&s, d.path(), None).await.unwrap();
        assert!(r.text.contains("sid:1;") && !r.text.contains("sid:2;"));
        assert!(!d.path().join("sources/oisf-trafficid/next").exists());
        assert!(!d.path().join("cand").exists());
        // a failed download and an empty one change nothing
        f.0.lock()
            .unwrap()
            .insert(url.clone(), Err("connection refused".into()));
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
            .await
            .unwrap();
        assert_eq!(o[0].status, "failed");
        f.0.lock()
            .unwrap()
            .insert(url.clone(), Ok(b"<html>not rules</html>".to_vec()));
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
            .await
            .unwrap();
        assert_eq!(o[0].status, "failed", "{o:?}");
        let r = render_sources(&s, d.path(), None).await.unwrap();
        assert!(r.text.contains("sid:1;"));
        // a good new set: the old one is kept as prev
        f.0.lock().unwrap().insert(
            url,
            Ok(b"alert tcp any any -> any 80 (msg:\"three\"; sid:3; rev:1;)\n".to_vec()),
        );
        let o = update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
            .await
            .unwrap();
        assert_eq!(o[0].status, "ok");
        assert!(d
            .path()
            .join("sources/oisf-trafficid/prev/oisf-trafficid.rules")
            .exists());
        let st = state(&s).await.unwrap();
        assert_eq!(st["oisf-trafficid"].status, "ok");
        assert_eq!(st["oisf-trafficid"].rules, 1);
    }

    #[tokio::test]
    async fn due_sources_only_unless_forced() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        sqlx::query("UPDATE ids_sources SET enabled = 1 WHERE key = 'oisf-trafficid'")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let f = Fake(std::sync::Mutex::new(HashMap::from([(
            "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules".to_string(),
            Ok(b"alert tcp any any -> any 80 (msg:\"one\"; sid:1; rev:1;)\n".to_vec()),
        )])));
        let sched = Schedule {
            enabled: true,
            hour: 3,
            window_hours: 1,
            interval_hours: 24,
            retry_minutes: 60,
        };
        let extra = Extra { files: vec![] };
        let mut ok = |_: &Path| Ok(());
        assert_eq!(
            update(&s, d.path(), &f, &sched, false, None, &extra, &mut ok)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            update(&s, d.path(), &f, &sched, false, None, &extra, &mut ok)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            update(&s, d.path(), &f, &sched, true, None, &extra, &mut ok)
                .await
                .unwrap()
                .len(),
            1
        );
        let off = Schedule {
            enabled: false,
            ..sched
        };
        assert!(update(&s, d.path(), &f, &off, false, None, &extra, &mut ok)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn threshold_config_is_rendered_from_the_rows() {
        let s = crate::lan::testutil::store().await;
        for (sid, kind, track, ip, c, secs) in [
            (10, "suppress", "none", "", 0, 0),
            (11, "suppress", "by_src", "10.1.2.3", 0, 0),
            (12, "limit", "by_dst", "", 2, 60),
        ] {
            sqlx::query("INSERT INTO ids_suppress (sid, kind, track, ip, count, seconds, enabled, updated_at) VALUES (?,?,?,?,?,?,1,0)")
                .bind(sid).bind(kind).bind(track).bind(ip).bind(c).bind(secs)
                .execute(s.pool().unwrap()).await.unwrap();
        }
        let t = render_threshold(&s).await.unwrap();
        assert!(t.contains("suppress gen_id 1, sig_id 10\n"), "{t}");
        assert!(
            t.contains("suppress gen_id 1, sig_id 11, track by_src, ip 10.1.2.3\n"),
            "{t}"
        );
        assert!(
            t.contains(
                "threshold gen_id 1, sig_id 12, type limit, track by_dst, count 2, seconds 60\n"
            ),
            "{t}"
        );
    }

    #[test]
    fn archives_are_unpacked_flat_and_unsafe_paths_refused() {
        if std::process::Command::new("tar")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src/rules");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("a.rules"),
            "alert tcp any any -> any 80 (msg:\"a\"; sid:1; rev:1;)\n",
        )
        .unwrap();
        std::fs::write(src.join("notes.txt"), "x").unwrap();
        let tgz = d.path().join("x.tgz");
        let st = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&tgz)
            .arg("-C")
            .arg(d.path().join("src"))
            .arg("rules")
            .status()
            .unwrap();
        assert!(st.success());
        let data = std::fs::read(&tgz).unwrap();
        let dest = d.path().join("out");
        assert_eq!(extract("tar.gz", "k", &data, &dest, 1 << 20).unwrap(), 1);
        assert!(dest.join("a.rules").exists() && !dest.join("notes.txt").exists());
        assert!(extract("tar.gz", "k", b"not an archive", &dest, 1 << 20).is_err());
        assert!(
            extract("tar.gz", "k", &data, &dest, 10).is_err(),
            "size cap"
        );
        let gz = {
            let p = d.path().join("g.rules");
            std::fs::write(
                &p,
                "alert ip any any -> any any (msg:\"g\"; sid:9; rev:1;)\n",
            )
            .unwrap();
            std::process::Command::new("gzip")
                .arg("-kf")
                .arg(&p)
                .status()
                .unwrap();
            std::fs::read(d.path().join("g.rules.gz")).unwrap()
        };
        assert_eq!(
            extract("rules.gz", "g", &gz, &d.path().join("o2"), 1 << 20).unwrap(),
            1
        );
        assert!(extract("rules.gz", "g", b"plain", &d.path().join("o3"), 1 << 20).is_err());
    }
}
