//! `patronus smart`: the S.M.A.R.T. poller service, a single look, and the disk list.

use super::apply;
use patronus_network::smart;
use std::path::PathBuf;

/// The supervised poller (`patronus-daemon@smart`): settings are re-read every turn.
pub async fn run(db: Option<PathBuf>) -> anyhow::Result<()> {
    let store = apply::open_store(db.as_deref()).await?;
    smart::run_loop(&store, None).await?;
    Ok(())
}

/// One look now.
pub async fn poll(db: Option<PathBuf>) -> anyhow::Result<()> {
    use chrono::Timelike;
    let store = apply::open_store(db.as_deref()).await?;
    let run = smart::SystemSmartctl::new(30)?;
    let r = smart::poll_once(
        &store,
        &run,
        patronus_network::lan::now(),
        chrono::Local::now().hour(),
    )
    .await?;
    println!("{}", r.describe());
    Ok(())
}

pub async fn status(db: Option<PathBuf>, json: bool) -> anyhow::Result<()> {
    let store = apply::open_store(db.as_deref()).await?;
    let disks = smart::latest(&store).await?;
    if json {
        let v: Vec<_> = disks.iter().map(smart::summary_json).collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    if disks.is_empty() {
        println!("no S.M.A.R.T. capable disk found yet (monitoring off, or no disk polled)");
        return Ok(());
    }
    for d in disks {
        println!(
            "{:<14} {:<11} {:<10} {} \u{b0}C  {}",
            d.disk.device,
            d.level.as_str(),
            d.disk.health.map_or("-", |h| if h { "PASSED" } else { "FAILED" }),
            d.disk.temperature.map_or("-".into(), |t| t.to_string()),
            d.disk.model
        );
        for r in &d.reasons {
            println!("    - {r}");
        }
    }
    Ok(())
}
