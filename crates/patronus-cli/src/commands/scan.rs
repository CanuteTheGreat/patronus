//! `patronus scan`: LAN security audit on the box (docs/LAN-AUDIT.md). Works
//! without the web UI: `now` runs a scan, `list` shows past scans, `show ID`
//! prints one scan's findings and open ports, `export ID` writes the CSV or
//! PDF report, `set KEY=VALUE ...` changes the settings.

use super::apply::open_store;
use patronus_network::lanaudit;
use std::path::Path;

pub async fn now(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let id = lanaudit::run_scan(&store, "manual", None).await?;
    if json {
        println!("{}", lanaudit::scan_detail(&store, id).await?);
    } else {
        show(db, id, false).await?;
    }
    Ok(())
}

pub async fn status(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let s = lanaudit::load(&store).await?;
    let (nmap, rustscan) = lanaudit::tools_present();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "settings": s, "tools": { "nmap": nmap, "rustscan": rustscan },
            }))?
        );
        return Ok(());
    }
    println!(
        "LAN audit: scheduled {}  (every {} h, quiet {}-{}, segments {})",
        if s.enabled { "on" } else { "off" },
        s.interval_hours,
        min_hm(s.quiet_start_min),
        min_hm(s.quiet_end_min),
        if s.segments.is_empty() {
            "every LAN".into()
        } else {
            s.segments.join(",")
        },
    );
    println!(
        "scanner: {}",
        if nmap {
            if rustscan {
                "rustscan + nmap"
            } else {
                "nmap"
            }
        } else {
            "built-in TCP connect (nmap/rustscan not installed)"
        }
    );
    Ok(())
}

fn min_hm(m: u32) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

pub async fn list(db: Option<&Path>, limit: i64) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let scans = lanaudit::list_scans(&store, limit).await?;
    if scans.is_empty() {
        println!("no scans yet");
        return Ok(());
    }
    for s in scans {
        println!(
            "#{:<4} {}  {:<9} hosts {:<3} ports {:<4} findings {:<3} {}",
            s.id,
            super_ts(s.started_at),
            s.trigger,
            s.hosts_up,
            s.ports_open,
            s.findings,
            s.state,
        );
    }
    Ok(())
}

fn super_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

pub async fn show(db: Option<&Path>, id: i64, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let d = lanaudit::scan_detail(&store, id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&d)?);
        return Ok(());
    }
    let scan = &d["scan"];
    println!(
        "scan #{}  {}  {}  hosts {}  open ports {}  findings {}",
        scan["id"].as_i64().unwrap_or(0),
        super_ts(scan["started_at"].as_i64().unwrap_or(0)),
        scan["engine"].as_str().unwrap_or(""),
        scan["hosts_up"].as_i64().unwrap_or(0),
        scan["ports_open"].as_i64().unwrap_or(0),
        scan["findings"].as_i64().unwrap_or(0),
    );
    println!("\nfindings:");
    let fs = d["findings"].as_array().cloned().unwrap_or_default();
    if fs.is_empty() {
        println!("  none");
    }
    for f in fs {
        let port = f["port"]
            .as_i64()
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        println!(
            "  [{}] {}{}  {}",
            f["severity"].as_str().unwrap_or(""),
            f["name"]
                .as_str()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| f["address"].as_str().unwrap_or("")),
            port,
            f["title"].as_str().unwrap_or(""),
        );
    }
    println!("\ndevices:");
    for h in d["hosts"].as_array().cloned().unwrap_or_default() {
        println!(
            "  {} {}",
            h["address"].as_str().unwrap_or(""),
            h["name"].as_str().unwrap_or(""),
        );
        for p in h["ports"].as_array().cloned().unwrap_or_default() {
            let v = [
                p["service"].as_str().unwrap_or(""),
                p["product"].as_str().unwrap_or(""),
                p["version"].as_str().unwrap_or(""),
            ]
            .iter()
            .filter(|x| !x.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
            println!(
                "      {}/{}  {}",
                p["port"].as_i64().unwrap_or(0),
                p["proto"].as_str().unwrap_or("tcp"),
                v
            );
        }
    }
    Ok(())
}

pub async fn export(
    db: Option<&Path>,
    id: i64,
    pdf: bool,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let (bytes, default) = if pdf {
        (
            lanaudit::scan_pdf(&store, id).await?,
            format!("lan-audit-{id}.pdf"),
        )
    } else {
        (
            lanaudit::scan_csv(&store, id).await?.into_bytes(),
            format!("lan-audit-{id}.csv"),
        )
    };
    match out {
        Some(p) => {
            std::fs::write(p, &bytes)?;
            println!("wrote {}", p.display());
        }
        None if pdf => {
            std::fs::write(&default, &bytes)?;
            println!("wrote {default}");
        }
        None => {
            // CSV to stdout
            print!("{}", String::from_utf8_lossy(&bytes));
        }
    }
    Ok(())
}

pub async fn set(db: Option<&Path>, pairs: &[String]) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let mut i = lanaudit::SettingsIn::default();
    for kv in pairs {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected KEY=VALUE, got {kv:?}"))?;
        apply_kv(&mut i, k.trim(), v.trim())?;
    }
    let s = lanaudit::save(&store, &i).await?;
    println!(
        "saved. scheduled scans {}",
        if s.enabled { "on" } else { "off" }
    );
    Ok(())
}

fn apply_kv(i: &mut lanaudit::SettingsIn, k: &str, v: &str) -> anyhow::Result<()> {
    let b = |v: &str| matches!(v, "1" | "true" | "yes" | "on");
    match k {
        "enabled" => i.enabled = Some(b(v)),
        "discover_neighbours" => i.discover_neighbours = Some(b(v)),
        "segments" => {
            i.segments = Some(
                v.split([',', ' '])
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect(),
            )
        }
        "alert_min_severity" => i.alert_min_severity = Some(v.to_string()),
        "interval_hours" => i.interval_hours = Some(v.parse()?),
        "quiet_start_min" => i.quiet_start_min = Some(v.parse()?),
        "quiet_end_min" => i.quiet_end_min = Some(v.parse()?),
        "max_parallel" => i.max_parallel = Some(v.parse()?),
        "max_rate" => i.max_rate = Some(v.parse()?),
        "connect_timeout_ms" => i.connect_timeout_ms = Some(v.parse()?),
        "keep_scans" => i.keep_scans = Some(v.parse()?),
        other => anyhow::bail!("unknown setting {other:?}"),
    }
    Ok(())
}
