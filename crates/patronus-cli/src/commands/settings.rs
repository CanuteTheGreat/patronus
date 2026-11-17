//! `patronus settings`: the typed settings registry
//! (`patronus_config::settings`) from the shell. Same keys, validation and
//! store as `/api/settings` and System > Advanced settings. A running web
//! UI picks changes up within a minute.

use super::apply::open_store;
use patronus_config::settings;
use std::path::Path;

fn e(err: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{err}")
}

/// `patronus settings list [--json]`
pub async fn list(db: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let all = settings::list(&store).await.map_err(e)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&all)?);
        return Ok(());
    }
    for v in all {
        let note = if v.is_default {
            String::new()
        } else {
            format!("  (changed; default {})", v.setting.default)
        };
        println!(
            "{:<36} {:<12} {}{note}",
            v.setting.key, v.value, v.setting.unit
        );
    }
    Ok(())
}

/// `patronus settings get KEY`
pub async fn get(db: Option<&Path>, key: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    println!("{}", settings::get(&store, key).await.map_err(e)?);
    Ok(())
}

/// `patronus settings set KEY VALUE`
pub async fn set(db: Option<&Path>, key: &str, value: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let v = settings::set(&store, key, value).await.map_err(e)?;
    let _ = store
        .audit(
            "cli",
            "update",
            "setting",
            Some(key),
            &serde_json::json!({ "value": v }),
        )
        .await;
    println!("{key} = {v}");
    Ok(())
}

/// `patronus settings reset KEY`
pub async fn reset(db: Option<&Path>, key: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    settings::reset(&store, key).await.map_err(e)?;
    let _ = store
        .audit(
            "cli",
            "reset",
            "setting",
            Some(key),
            &serde_json::Value::Null,
        )
        .await;
    println!(
        "{key} = {} (default)",
        settings::get(&store, key).await.map_err(e)?
    );
    Ok(())
}

/// `patronus settings env [--output FILE]`: every value as shell variables
/// for boot scripts (written atomically when a file is given).
pub async fn env(db: Option<&Path>, output: Option<&Path>) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let text = settings::render_env(&settings::list(&store).await.map_err(e)?);
    match output {
        None => print!("{text}"),
        Some(p) => {
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, text)?;
            std::fs::rename(&tmp, p)?;
        }
    }
    Ok(())
}
