//! Router CVE exposure (lane B, docs/CVE-EXPOSURE.md): which of the software on the box
//! has a published security advisory, which version fixes it, and whether the fix is
//! available to install.
//!
//! - **Standard tier (Gentoo)**: the installed packages (`/var/db/pkg`) against the
//!   Gentoo Linux Security Advisories in the local tree (`glsa`), the fix available
//!   from `portageq best_visible`, and the Rust crates compiled into the Patronus
//!   binaries against the OSV crates.io advisories (`osv`, `inventory`).
//! - **Router tier (image)**: the image's package manifest with the result of the
//!   advisory gate that ran when the image was built (`inventory::Manifest`), plus
//!   the same crate check.
//!
//! The view never says "clean" without data: a missing or old advisory set is
//! `unknown` or `stale` and the page says how old the data is. Downloads are scheduled,
//! size-capped and cached; offline, the last data keeps working.
//!
//! One engine (`spawn_task`) does the scans, downloads and (policy `apply`) installs
//! GLSA fixes inside the update window; patronus-web only reads the stored report and
//! leaves requests in `cve_state`.

pub mod glsa;
pub mod inventory;
pub mod osv;
pub mod settings;
pub mod version;

use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use settings::Settings;
use sqlx::Row;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use settings::{load, save, write, SettingsIn};

fn db_err(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub source: String,
    pub subject: String,
    pub binary: String,
    pub installed: String,
    pub advisory: String,
    pub aliases: Vec<String>,
    pub title: String,
    pub severity: String,
    pub fixed_in: Vec<String>,
    /// `available`, `none`, `needs-release` or `unknown`
    pub update: String,
    pub update_version: String,
    pub url: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

impl Finding {
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.source, self.subject, self.binary, self.advisory
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataAge {
    pub present: bool,
    pub updated_at: Option<i64>,
    pub age_secs: Option<i64>,
    pub stale: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub at: i64,
    /// `standard`, `router` or `unknown`
    pub tier: String,
    /// `affected`, `clean`, `stale` or `unknown`
    pub verdict: String,
    pub reasons: Vec<String>,
    pub packages_checked: usize,
    pub crates_checked: usize,
    pub glsa: DataAge,
    pub osv: DataAge,
    pub binaries: Vec<inventory::BinaryInventory>,
    pub manifest: Option<inventory::Manifest>,
    pub findings: Vec<Finding>,
    pub ms: u64,
}

fn age(now: i64, t: Option<i64>, stale_days: u32) -> (Option<i64>, bool) {
    match t {
        Some(t) => {
            let a = (now - t).max(0);
            (Some(a), a > stale_days as i64 * 86400)
        }
        None => (None, false),
    }
}

fn impact_to_severity(i: &str) -> String {
    match i {
        "high" => "high",
        "normal" => "medium",
        "low" | "trivial" => "low",
        _ => "unknown",
    }
    .into()
}

// ---------------------------------------------------------------------------
// OSV data cache
// ---------------------------------------------------------------------------

fn osv_cache_path(s: &Settings) -> PathBuf {
    Path::new(&s.data_dir).join("osv-crates.json")
}

pub fn load_osv(s: &Settings) -> Option<osv::OsvDb> {
    let p = osv_cache_path(s);
    let md = std::fs::metadata(&p).ok()?;
    if md.len() > s.osv_max_bytes.saturating_mul(2) {
        return None;
    }
    serde_json::from_slice(&std::fs::read(&p).ok()?).ok()
}

/// Download the archive with curl (`--max-filesize`), reduce it and replace the cache
/// atomically. A failed download keeps the old cache.
pub async fn fetch_osv(s: &Settings, now: i64) -> Result<osv::OsvDb> {
    std::fs::create_dir_all(&s.data_dir)
        .map_err(|e| Error::Config(format!("create {}: {e}", s.data_dir)))?;
    let tmp = Path::new(&s.data_dir).join(format!(".dl-{}", std::process::id()));
    let out = tokio::process::Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "--connect-timeout",
            "20",
            "--max-time",
            "300",
            "--max-filesize",
            &s.osv_max_bytes.to_string(),
            "-A",
            "Patronus-cve/1.0",
            "-o",
        ])
        .arg(&tmp)
        .arg("--")
        .arg(&s.osv_url)
        .output()
        .await
        .map_err(|e| Error::Config(format!("cannot run curl: {e}")))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Config(format!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let bytes = std::fs::read(&tmp).map_err(|e| Error::Config(format!("read download: {e}")));
    let _ = std::fs::remove_file(&tmp);
    let bytes = bytes?;
    if bytes.len() as u64 > s.osv_max_bytes {
        return Err(Error::Config(
            "download is larger than cve.osv_max_bytes".into(),
        ));
    }
    let url = s.osv_url.clone();
    let db = tokio::task::spawn_blocking(move || osv::build_from_zip(&bytes, &url, now))
        .await
        .map_err(|e| Error::Config(format!("reduce: {e}")))?
        .map_err(Error::Config)?;
    let json = serde_json::to_vec(&db).map_err(|e| Error::Config(format!("encode: {e}")))?;
    if json.len() as u64 > s.osv_max_bytes.saturating_mul(2) {
        return Err(Error::Config(
            "reduced advisory data exceeds the size cap".into(),
        ));
    }
    let dst = osv_cache_path(s);
    let part = dst.with_extension("json.part");
    std::fs::write(&part, &json).map_err(|e| Error::Config(format!("write cache: {e}")))?;
    std::fs::rename(&part, &dst).map_err(|e| Error::Config(format!("replace cache: {e}")))?;
    Ok(db)
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// `portageq best_visible / ATOM` -> the version Portage would install now.
async fn best_visible(s: &Settings, atom: &str) -> Option<String> {
    let fut = tokio::process::Command::new(&s.portageq)
        .args(["best_visible", "/", atom])
        .output();
    let out = tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let pf = line.rsplit('/').next()?.to_string();
    version::split_pf(&pf).map(|(_, v)| v.raw)
}

/// One scan of everything this box can check. `now` is a parameter for tests.
pub async fn scan(s: &Settings, now: i64) -> Report {
    let t0 = std::time::Instant::now();
    let mut r = Report {
        at: now,
        tier: "unknown".into(),
        ..Default::default()
    };

    // --- the data sets and their age
    let glsa_dir = PathBuf::from(&s.glsa_dir);
    let pkg_db = PathBuf::from(&s.pkg_db);
    let installed = tokio::task::block_in_place(|| glsa::installed(&pkg_db));
    let manifest = inventory::read_manifest(Path::new(&s.manifest_path));
    r.tier = if !installed.is_empty() {
        "standard"
    } else if manifest.is_some() {
        "router"
    } else {
        "unknown"
    }
    .into();
    r.packages_checked = if r.tier == "standard" {
        installed.len()
    } else {
        manifest.as_ref().map(|m| m.packages.len()).unwrap_or(0)
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut verdict_unknown = false;
    let mut verdict_stale = false;
    let mut hidden_notices = 0usize;

    if r.tier == "standard" {
        let set = tokio::task::block_in_place(|| glsa::load_dir(&glsa_dir));
        let (a, stale) = age(now, set.newest_mtime, s.glsa_stale_days);
        r.glsa = DataAge {
            present: set.files > 0,
            updated_at: set.newest_mtime,
            age_secs: a,
            stale,
            detail: format!("{} advisories from {}", set.advisories.len(), s.glsa_dir),
        };
        if set.files == 0 {
            verdict_unknown = true;
            r.reasons.push(format!(
                "no Gentoo security advisories at {} (sync the Portage tree)",
                s.glsa_dir
            ));
        } else {
            if stale {
                verdict_stale = true;
                r.reasons.push(format!(
                    "the Gentoo advisory data is {} days old (limit {})",
                    a.unwrap_or(0) / 86400,
                    s.glsa_stale_days
                ));
            }
            for h in glsa::find_hits(&set, &installed) {
                let pkg = set
                    .advisories
                    .iter()
                    .find(|g| g.id == h.glsa)
                    .and_then(|g| g.packages.iter().find(|p| p.name == h.package));
                let slot = installed
                    .iter()
                    .find(|i| i.name == h.package && i.version == h.installed)
                    .and_then(|i| i.slot.clone());
                let atom = match &slot {
                    Some(sl) => format!("{}:{}", h.package, sl),
                    None => h.package.clone(),
                };
                let (update, update_version) = match best_visible(s, &atom).await {
                    Some(best) => {
                        let still =
                            pkg.zip(version::GentooVersion::parse(&best))
                                .map(|(p, v)| {
                                    p.vulnerable.iter().any(|x| {
                                        version::gentoo_range_matches(&x.op, &x.version, &v)
                                    }) && !p.unaffected.iter().any(|x| {
                                        version::gentoo_range_matches(&x.op, &x.version, &v)
                                    })
                                })
                                .unwrap_or(true);
                        let newer = version::GentooVersion::parse(&best)
                            .zip(version::GentooVersion::parse(&h.installed))
                            .map(|(b, i)| b > i)
                            .unwrap_or(false);
                        if newer && !still {
                            ("available".to_string(), best)
                        } else {
                            ("none".to_string(), String::new())
                        }
                    }
                    None => ("unknown".to_string(), String::new()),
                };
                let aliases: Vec<String> = set
                    .advisories
                    .iter()
                    .find(|g| g.id == h.glsa)
                    .map(|g| {
                        g.references
                            .iter()
                            .map(|(_, t)| t.clone())
                            .filter(|t| t.starts_with("CVE-"))
                            .collect()
                    })
                    .unwrap_or_default();
                findings.push(Finding {
                    source: "glsa".into(),
                    subject: h.package,
                    binary: String::new(),
                    installed: h.installed,
                    advisory: format!("GLSA-{}", h.glsa),
                    aliases,
                    title: h.title,
                    severity: impact_to_severity(&h.impact),
                    fixed_in: h.fixed_in,
                    update,
                    update_version,
                    url: h.url,
                    first_seen: now,
                    last_seen: now,
                });
            }
        }
    } else if r.tier == "router" {
        let m = manifest.clone().unwrap_or_default();
        r.glsa = DataAge {
            present: m.gate.is_some(),
            updated_at: None,
            age_secs: None,
            stale: false,
            detail: m
                .gate
                .as_ref()
                .map(|g| {
                    format!(
                        "advisory gate at image build ({}) against {}",
                        g.checked_at, g.source
                    )
                })
                .unwrap_or_else(|| "this image has no advisory gate result".into()),
        };
        match &m.gate {
            None => {
                verdict_unknown = true;
                r.reasons
                    .push("the image carries no advisory gate result".into());
            }
            Some(g) => {
                // the gate's age: the build date of the image, as written by the gate
                if let Ok(d) = chrono::NaiveDate::parse_from_str(
                    &g.checked_at[..g.checked_at.len().min(10)],
                    "%Y-%m-%d",
                ) {
                    let t = d.and_hms_opt(0, 0, 0).map(|x| x.and_utc().timestamp());
                    let (a, stale) = age(now, t, s.glsa_stale_days.max(60));
                    r.glsa.updated_at = t;
                    r.glsa.age_secs = a;
                    r.glsa.stale = stale;
                    if stale {
                        verdict_stale = true;
                        r.reasons.push(format!(
                            "the image was checked {} days ago; newer advisories are only known after a new image",
                            a.unwrap_or(0) / 86400
                        ));
                    }
                }
                for f in &g.findings {
                    findings.push(Finding {
                        source: "image".into(),
                        subject: f.package.clone(),
                        binary: String::new(),
                        installed: f.installed.clone(),
                        advisory: f.advisory.clone(),
                        aliases: Vec::new(),
                        title: f.title.clone(),
                        severity: "unknown".into(),
                        fixed_in: f.fixed_in.clone(),
                        update: "needs-release".into(),
                        update_version: String::new(),
                        url: f.url.clone(),
                        first_seen: now,
                        last_seen: now,
                    });
                }
            }
        }
        r.manifest = manifest.clone();
    } else {
        verdict_unknown = true;
        r.reasons
            .push("no package database and no image manifest on this system".into());
    }

    // --- Rust crates compiled into the Patronus binaries
    let paths =
        inventory::candidate_binaries(&s.binaries, &["/usr/bin", "/usr/sbin", "/usr/local/bin"]);
    let bins: Vec<inventory::BinaryInventory> = tokio::task::block_in_place(|| {
        paths
            .iter()
            .filter_map(|p| inventory::read_embedded(p, 1 << 30))
            .collect()
    });
    let osv_db = load_osv(s);
    match &osv_db {
        Some(db) => {
            let (a, stale) = age(now, Some(db.fetched_at), s.osv_stale_days);
            r.osv = DataAge {
                present: true,
                updated_at: Some(db.fetched_at),
                age_secs: a,
                stale,
                detail: format!(
                    "{} advisories for {} crates from {}",
                    db.advisories,
                    db.crates.len(),
                    db.source_url
                ),
            };
            if stale {
                verdict_stale = true;
                r.reasons.push(format!(
                    "the crate advisory data is {} days old (limit {})",
                    a.unwrap_or(0) / 86400,
                    s.osv_stale_days
                ));
            }
        }
        None => {
            r.osv = DataAge {
                present: false,
                detail: "no crate advisory data downloaded yet".into(),
                ..Default::default()
            };
            if !bins.is_empty() {
                verdict_unknown = true;
                r.reasons
                    .push("the crate advisory data has not been downloaded".into());
            }
        }
    }
    if bins.is_empty() {
        verdict_unknown = true;
        r.reasons.push(
            "no Patronus binary with an embedded dependency list was found, so crates are not checked"
                .into(),
        );
    }
    for b in &bins {
        if b.scope == "unavailable" {
            verdict_unknown = true;
            r.reasons.push(format!(
                "{} was built without a Cargo.lock: its crates are unknown",
                b.binary
            ));
            continue;
        }
        r.crates_checked += b.crates.len();
        if let Some(db) = &osv_db {
            let list: Vec<(String, String)> = b
                .crates
                .iter()
                .map(|(n, v, _)| (n.clone(), v.clone()))
                .collect();
            for h in osv::find_hits(db, &b.binary, &list) {
                if h.informational.is_some() && !s.show_informational {
                    hidden_notices += 1;
                    continue;
                }
                findings.push(Finding {
                    source: "osv".into(),
                    subject: h.name,
                    binary: h.binary,
                    installed: h.version,
                    advisory: h.id,
                    aliases: h.aliases,
                    title: h.summary,
                    severity: if h.severity.is_empty() {
                        "unknown".into()
                    } else {
                        h.severity
                    },
                    fixed_in: h.fixed_in,
                    update: "needs-release".into(),
                    update_version: String::new(),
                    url: h.url,
                    first_seen: now,
                    last_seen: now,
                });
            }
        }
    }
    r.binaries = bins;
    if hidden_notices > 0 {
        r.reasons.push(format!(
            "{hidden_notices} notice(s) about unmaintained or unsound crates are not counted (setting show_informational)"
        ));
    }

    findings.sort_by(|a, b| {
        let rank = |s: &str| match s {
            "high" => 0,
            "medium" => 1,
            "low" => 2,
            _ => 3,
        };
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then(a.subject.cmp(&b.subject))
            .then(a.advisory.cmp(&b.advisory))
    });
    r.verdict = if !findings.is_empty() {
        "affected"
    } else if verdict_unknown {
        "unknown"
    } else if verdict_stale {
        "stale"
    } else {
        "clean"
    }
    .into();
    r.findings = findings;
    r.ms = t0.elapsed().as_millis() as u64;
    r
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

pub async fn state_get(store: &ConfigStore, key: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT value FROM cve_state WHERE key = ?")
        .bind(key)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db_err("cve state"))?;
    Ok(row.map(|r| r.get(0)))
}

pub async fn state_set(store: &ConfigStore, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO cve_state (key, value, updated_at) VALUES (?,?,?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db_err("cve state"))?;
    Ok(())
}

pub async fn last_report(store: &ConfigStore) -> Result<Option<Report>> {
    Ok(state_get(store, "report")
        .await?
        .and_then(|j| serde_json::from_str(&j).ok()))
}

pub async fn log(store: &ConfigStore, kind: &str, ok: bool, detail: &str) {
    let _ = sqlx::query("INSERT INTO cve_log (at, kind, ok, detail) VALUES (?,?,?,?)")
        .bind(now())
        .bind(kind)
        .bind(ok as i64)
        .bind(detail.chars().take(2000).collect::<String>())
        .execute(match store.pool() {
            Ok(p) => p,
            Err(_) => return,
        })
        .await;
}

/// Keep first_seen of findings that persist, store the report and the scan row.
pub async fn record(store: &ConfigStore, s: &Settings, mut r: Report) -> Result<Report> {
    let pool = store.pool()?;
    let mut new_high = 0usize;
    let mut new_total = 0usize;
    let mut keys = Vec::new();
    for f in r.findings.iter_mut() {
        let key = f.key();
        let prev = sqlx::query("SELECT first_seen FROM cve_findings WHERE fkey = ?")
            .bind(&key)
            .fetch_optional(pool)
            .await
            .map_err(db_err("cve findings"))?;
        match prev {
            Some(p) => f.first_seen = p.get(0),
            None => {
                new_total += 1;
                if f.severity == "high" {
                    new_high += 1;
                }
            }
        }
        sqlx::query(
            "INSERT INTO cve_findings (fkey, source, subject, binary, installed, advisory, aliases, title,
                severity, fixed_in, update_state, update_version, url, first_seen, last_seen)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(fkey) DO UPDATE SET installed=excluded.installed, aliases=excluded.aliases,
                title=excluded.title, severity=excluded.severity, fixed_in=excluded.fixed_in,
                update_state=excluded.update_state, update_version=excluded.update_version,
                url=excluded.url, last_seen=excluded.last_seen",
        )
        .bind(&key)
        .bind(&f.source)
        .bind(&f.subject)
        .bind(&f.binary)
        .bind(&f.installed)
        .bind(&f.advisory)
        .bind(f.aliases.join(","))
        .bind(&f.title)
        .bind(&f.severity)
        .bind(f.fixed_in.join(","))
        .bind(&f.update)
        .bind(&f.update_version)
        .bind(&f.url)
        .bind(f.first_seen)
        .bind(f.last_seen)
        .execute(pool)
        .await
        .map_err(db_err("cve findings"))?;
        keys.push(key);
    }
    // what this scan did not find again is gone (fixed, removed or no longer affected)
    let rows = sqlx::query("SELECT fkey FROM cve_findings")
        .fetch_all(pool)
        .await
        .map_err(db_err("cve findings"))?;
    for row in rows {
        let k: String = row.get(0);
        if !keys.contains(&k) {
            sqlx::query("DELETE FROM cve_findings WHERE fkey = ?")
                .bind(&k)
                .execute(pool)
                .await
                .map_err(db_err("cve findings"))?;
        }
    }
    sqlx::query(
        "INSERT INTO cve_scans (at, tier, verdict, affected, packages, crates, glsa_age, osv_age, ms, note)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(r.at)
    .bind(&r.tier)
    .bind(&r.verdict)
    .bind(r.findings.len() as i64)
    .bind(r.packages_checked as i64)
    .bind(r.crates_checked as i64)
    .bind(r.glsa.age_secs)
    .bind(r.osv.age_secs)
    .bind(r.ms as i64)
    .bind(r.reasons.join("; "))
    .execute(pool)
    .await
    .map_err(db_err("cve scans"))?;
    // retention
    let cutoff = r.at - s.history_days as i64 * 86400;
    for t in ["cve_scans", "cve_log"] {
        sqlx::query(&format!("DELETE FROM {t} WHERE at < ?"))
            .bind(cutoff)
            .execute(pool)
            .await
            .map_err(db_err("cve history"))?;
        sqlx::query(&format!(
            "DELETE FROM {t} WHERE id <= (SELECT COALESCE(MAX(id),0) FROM {t}) - ?"
        ))
        .bind(s.history_max_rows as i64)
        .execute(pool)
        .await
        .map_err(db_err("cve history"))?;
    }
    state_set(
        store,
        "report",
        &serde_json::to_string(&r).map_err(|e| Error::Config(format!("encode report: {e}")))?,
    )
    .await?;
    if new_total > 0 {
        // one event per scan with new findings, for the notification matchers / alert routing
        let _ = sqlx::query(
            "INSERT INTO system_events (ts, kind, subject, severity, detail) VALUES (?,?,?,?,?)",
        )
        .bind(r.at)
        .bind("cve_exposure")
        .bind("router")
        .bind(if new_high > 0 { "critical" } else { "warning" })
        .bind(format!(
            "{new_total} new security advisor{} affect this router ({} in total)",
            if new_total == 1 { "y" } else { "ies" },
            r.findings.len()
        ))
        .execute(pool)
        .await;
    }
    Ok(r)
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRow {
    pub at: i64,
    pub tier: String,
    pub verdict: String,
    pub affected: i64,
    pub packages: i64,
    pub crates: i64,
    pub glsa_age: Option<i64>,
    pub osv_age: Option<i64>,
    pub ms: i64,
    pub note: String,
}

pub async fn scan_history(store: &ConfigStore, limit: i64) -> Result<Vec<ScanRow>> {
    let rows = sqlx::query(
        "SELECT at, tier, verdict, affected, packages, crates, glsa_age, osv_age, ms, note
         FROM cve_scans ORDER BY id DESC LIMIT ?",
    )
    .bind(limit.clamp(1, 5000))
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("cve scans"))?;
    Ok(rows
        .into_iter()
        .map(|r| ScanRow {
            at: r.get(0),
            tier: r.get(1),
            verdict: r.get(2),
            affected: r.get(3),
            packages: r.get(4),
            crates: r.get(5),
            glsa_age: r.get(6),
            osv_age: r.get(7),
            ms: r.get(8),
            note: r.get(9),
        })
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct LogRow {
    pub at: i64,
    pub kind: String,
    pub ok: bool,
    pub detail: String,
}

pub async fn log_history(store: &ConfigStore, limit: i64) -> Result<Vec<LogRow>> {
    let rows = sqlx::query("SELECT at, kind, ok, detail FROM cve_log ORDER BY id DESC LIMIT ?")
        .bind(limit.clamp(1, 5000))
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("cve log"))?;
    Ok(rows
        .into_iter()
        .map(|r| LogRow {
            at: r.get(0),
            kind: r.get(1),
            ok: r.get::<i64, _>(2) != 0,
            detail: r.get(3),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// the update policy: security updates in the window
// ---------------------------------------------------------------------------

/// The emerge atoms that fix what the report found and for which Portage has the fix.
pub fn apply_atoms(r: &Report, max: usize) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for f in &r.findings {
        if f.source != "glsa" || f.update != "available" {
            continue;
        }
        if let Some(fix) = f.fixed_in.first() {
            let a = format!(">={}-{}", f.subject, fix);
            if !v.contains(&a) {
                v.push(a);
            }
        }
        if v.len() >= max {
            break;
        }
    }
    v
}

/// Run `emerge` for the atoms. No reboot, no service restart beyond what the
/// packages' own ebuilds do; the result goes to `cve_log`.
pub async fn apply_updates(store: &ConfigStore, s: &Settings, atoms: &[String]) -> bool {
    let mut cmd = tokio::process::Command::new(&s.emerge);
    cmd.args([
        "--oneshot",
        "--update",
        "--changed-use",
        "--deep",
        "--with-bdeps=y",
        "--quiet-build=y",
        "--color=n",
    ])
    .args(atoms)
    .kill_on_drop(true);
    let res = tokio::time::timeout(Duration::from_secs(s.apply_timeout_secs), cmd.output()).await;
    let (ok, detail) = match res {
        Ok(Ok(o)) => {
            let tail = |b: &[u8]| {
                let t = String::from_utf8_lossy(b);
                let l: Vec<&str> = t.lines().rev().take(8).collect();
                l.into_iter().rev().collect::<Vec<_>>().join("\n")
            };
            (
                o.status.success(),
                format!(
                    "emerge {} -> {}\n{}{}",
                    atoms.join(" "),
                    o.status,
                    tail(&o.stdout),
                    tail(&o.stderr)
                ),
            )
        }
        Ok(Err(e)) => (false, format!("cannot run {}: {e}", s.emerge)),
        Err(_) => (
            false,
            format!("emerge timed out after {} s", s.apply_timeout_secs),
        ),
    };
    log(store, "apply", ok, &detail).await;
    ok
}

fn local_minute_of_day() -> u32 {
    use chrono::Timelike;
    let n = chrono::Local::now();
    n.hour() * 60 + n.minute()
}

/// One engine round. Returns the new report when a scan ran.
pub async fn tick(store: &ConfigStore) -> Result<Option<Report>> {
    let s = load(store).await?;
    if !s.enabled {
        return Ok(None);
    }
    let t = now();
    let last = last_report(store).await?;
    let requested: i64 = state_get(store, "scan_requested")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let served: i64 = state_get(store, "scan_served")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let fetch_requested: i64 = state_get(store, "fetch_requested")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let fetch_served: i64 = state_get(store, "fetch_served")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let last_at = last.as_ref().map(|l| l.at).unwrap_or(0);
    let due = t - last_at >= s.scan_interval_secs as i64;
    let asked = requested > served;
    if !(due || asked) {
        return Ok(None);
    }
    state_set(store, "scan_served", &requested.max(served).to_string()).await?;
    let fetch_asked = fetch_requested > fetch_served;
    if fetch_asked {
        state_set(store, "fetch_served", &fetch_requested.to_string()).await?;
    }
    // data download when due (or asked for): only the crate archive uses the network
    if s.fetch {
        let have = load_osv(&s).map(|d| d.fetched_at).unwrap_or(0);
        let fetch_due = t - have >= s.osv_refresh_hours as i64 * 3600;
        if fetch_due || fetch_asked || (asked && have == 0) {
            match fetch_osv(&s, t).await {
                Ok(db) => {
                    log(
                        store,
                        "fetch",
                        true,
                        &format!(
                            "{} advisories for {} crates ({} bytes)",
                            db.advisories,
                            db.crates.len(),
                            db.archive_bytes
                        ),
                    )
                    .await
                }
                Err(e) => log(store, "fetch", false, &e.to_string()).await,
            }
        }
    }
    let mut report = record(store, &s, scan(&s, t).await).await?;
    log(
        store,
        "scan",
        true,
        &format!(
            "{}: {} finding(s), {} packages, {} crates",
            report.verdict,
            report.findings.len(),
            report.packages_checked,
            report.crates_checked
        ),
    )
    .await;

    // security updates: only the policy "apply", only inside the window, rate limited
    if s.security_updates == "apply" && settings::in_window(&s.window, local_minute_of_day()) {
        let atoms = apply_atoms(&report, s.apply_max_packages as usize);
        let last_apply: i64 = state_get(store, "last_apply")
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if !atoms.is_empty() && t - last_apply >= s.apply_min_interval_secs as i64 {
            state_set(store, "last_apply", &t.to_string()).await?;
            if apply_updates(store, &s, &atoms).await {
                // look again: the report should show what is left
                report = record(store, &s, scan(&s, now()).await).await?;
            }
        }
    }
    Ok(Some(report))
}

/// Run the engine forever. `only_without_applyd`: skip rounds while the root broker's
/// socket exists (patronus-web runs it only when there is no `patronus applyd`).
pub fn spawn_task(
    store: std::sync::Arc<ConfigStore>,
    only_without_applyd: bool,
    applyd_socket: PathBuf,
) {
    tokio::spawn(async move {
        let mut last_err = String::new();
        loop {
            // sleep in short slices and re-read the interval: a settings change (or a scan request) must not
            // wait out a long previous interval
            let mut waited = 0u64;
            loop {
                let secs = load(&store).await.map(|s| s.tick_secs).unwrap_or(5);
                if waited >= secs {
                    break;
                }
                let step = (secs - waited).min(2);
                tokio::time::sleep(Duration::from_secs(step)).await;
                waited += step;
            }
            if only_without_applyd && applyd_socket.exists() {
                continue;
            }
            match tick(&store).await {
                Ok(_) => last_err.clear(),
                Err(e) => {
                    if last_err != e.to_string() {
                        tracing::error!("CVE exposure: {e}");
                        last_err = e.to_string();
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
