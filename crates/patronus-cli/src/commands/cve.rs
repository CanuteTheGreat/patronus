//! `patronus cve`: router CVE exposure on the box (docs/CVE-EXPOSURE.md). Works without the
//! web UI: `status` prints the stored report, `scan` makes a scan in this process (and
//! `--fetch` downloads the crate advisory data first), `apply` installs the fixes the last
//! scan found, `set KEY=VALUE ...` changes settings.

use super::apply::open_store;
use patronus_network::cve;
use std::path::Path;

fn ago(secs: Option<i64>) -> String {
    match secs {
        None => "none".into(),
        Some(a) if a >= 172_800 => format!("{} days old", a / 86400),
        Some(a) if a >= 7200 => format!("{} hours old", a / 3600),
        Some(a) => format!("{} min old", (a / 60).max(1)),
    }
}

fn print_report(r: &cve::Report) {
    println!(
        "{}: {} finding(s)  [{} tier, {} packages, {} crates]",
        r.verdict,
        r.findings.len(),
        r.tier,
        r.packages_checked,
        r.crates_checked
    );
    println!(
        "advisory data: system {} · crates {}",
        ago(r.glsa.age_secs),
        ago(r.osv.age_secs)
    );
    for x in &r.reasons {
        println!("note: {x}");
    }
    for f in &r.findings {
        let fix = match f.update.as_str() {
            "available" => format!("installable now: {}", f.update_version),
            "needs-release" => "needs a new Patronus release".to_string(),
            "none" => "no fixed version offered yet".to_string(),
            _ => "update state not known".to_string(),
        };
        println!(
            "{:<7} {:<34} {:<12} fixed in {:<18} {}  {}  {}",
            f.severity,
            if f.binary.is_empty() {
                f.subject.clone()
            } else {
                format!("{} ({})", f.subject, f.binary)
            },
            f.installed,
            if f.fixed_in.is_empty() {
                "not known".into()
            } else {
                f.fixed_in.join(",")
            },
            fix,
            f.advisory,
            f.url
        );
    }
}

pub async fn status(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    patronus_network::cve::inventory::keep(crate::PATRONUS_DEP_LIST);
    let store = open_store(db).await?;
    let s = cve::load(&store).await?;
    let r = cve::last_report(&store).await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "settings": s, "report": r }))?
        );
        return Ok(());
    }
    println!(
        "CVE exposure: {} · security updates: {} (window {})",
        if s.enabled { "on" } else { "off" },
        s.security_updates,
        s.window
    );
    match r {
        Some(r) => print_report(&r),
        None => println!("no scan has run yet (patronus cve scan)"),
    }
    Ok(())
}

pub async fn scan(db: Option<&Path>, fetch: bool, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let s = cve::load(&store).await?;
    if fetch {
        match cve::fetch_osv(&s, cve::now()).await {
            Ok(d) => {
                cve::log(
                    &store,
                    "fetch",
                    true,
                    &format!(
                        "{} advisories for {} crates ({} bytes)",
                        d.advisories,
                        d.crates.len(),
                        d.archive_bytes
                    ),
                )
                .await;
                eprintln!(
                    "crate advisory data: {} advisories for {} crates",
                    d.advisories,
                    d.crates.len()
                );
            }
            Err(e) => {
                cve::log(&store, "fetch", false, &e.to_string()).await;
                eprintln!("crate advisory data not refreshed: {e} (using the older data, if any)");
            }
        }
    }
    let r = cve::record(&store, &s, cve::scan(&s, cve::now()).await).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        print_report(&r);
    }
    Ok(())
}

pub async fn apply(db: Option<&Path>, dry_run: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let s = cve::load(&store).await?;
    let Some(r) = cve::last_report(&store).await? else {
        anyhow::bail!("no scan has run yet (patronus cve scan)");
    };
    let atoms = cve::apply_atoms(&r, s.apply_max_packages as usize);
    if atoms.is_empty() {
        println!("nothing to install: no affected package has a fixed version in the tree");
        return Ok(());
    }
    for a in &atoms {
        println!("{a}");
    }
    if dry_run {
        return Ok(());
    }
    if cve::apply_updates(&store, &s, &atoms).await {
        let r = cve::record(&store, &s, cve::scan(&s, cve::now()).await).await?;
        println!("installed; {} finding(s) left", r.findings.len());
        Ok(())
    } else {
        anyhow::bail!(
            "the update failed; see `patronus cve status --json` or the page's action list"
        )
    }
}

pub async fn set(db: Option<&Path>, pairs: &[String]) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let mut m = serde_json::Map::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got {p:?}"))?;
        let k = k.trim().trim_start_matches("cve.");
        let v = v.trim();
        let val = match k {
            "enabled" | "fetch" => {
                serde_json::Value::Bool(matches!(v, "1" | "true" | "yes" | "on"))
            }
            "binaries" => serde_json::Value::Array(
                v.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(|x| serde_json::Value::String(x.into()))
                    .collect(),
            ),
            "osv_url" | "glsa_dir" | "pkg_db" | "manifest_path" | "data_dir" | "portageq"
            | "emerge" | "security_updates" | "window" => serde_json::Value::String(v.into()),
            _ => serde_json::Value::Number(
                v.parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("{k}: a number expected, got {v:?}"))?
                    .into(),
            ),
        };
        m.insert(k.to_string(), val);
    }
    let i: cve::SettingsIn = serde_json::from_value(serde_json::Value::Object(m))
        .map_err(|e| anyhow::anyhow!("unknown setting: {e}"))?;
    cve::save(&store, &i).await?;
    status(db, false).await
}
