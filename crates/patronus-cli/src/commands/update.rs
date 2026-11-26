//! `patronus update`: the update channel and mirror from the console or a
//! script, plus the same check/apply jobs as System > Updates (run as root).
//!
//! * `patronus update channel` shows the effective settings;
//!   `--set stable|testing|development`, `--mirror URI` (empty = default),
//!   `--binhost URI|none` store them in the config store (`update.*`) and write
//!   Portage's configuration (`patronus_network::update_channel`).
//! * `patronus update check [--no-sync]` / `patronus update apply [--scope patronus|world]`
//!   start the background job; `patronus update status` prints it.

use super::apply::open_store;
use patronus_config::updates::{self, UpdateInput};
use serde_json::{json, Value};
use std::path::Path;

fn print_settings(s: &updates::UpdateSettings) {
    println!(
        "channel:  {} ({})",
        s.channel.as_str(),
        s.channel.describe()
    );
    println!("mirror:   {} (sync-type {})", s.overlay_uri, s.sync_type());
    println!(
        "binhost:  {}",
        if s.binhost_uri.is_empty() {
            "none (built from source)"
        } else {
            &s.binhost_uri
        }
    );
    println!("overlay:  {}", s.repo_location);
}

pub async fn channel(
    db: Option<&Path>,
    set: Option<String>,
    mirror: Option<String>,
    binhost: Option<String>,
) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let change = set.is_some() || mirror.is_some() || binhost.is_some();
    if change {
        let before = updates::save(
            &store,
            &UpdateInput {
                channel: set,
                overlay_uri: mirror,
                binhost_uri: binhost,
                ..Default::default()
            },
        )
        .await?;
        let eff = updates::resolve(Some(&store)).await;
        if patronus_network::sysops::has_portage() {
            if let Err(e) = patronus_network::update_channel::apply(
                &eff,
                &patronus_network::update_channel::PortagePaths::default(),
            ) {
                updates::restore(&store, &before).await?;
                anyhow::bail!("writing Portage's configuration failed, nothing changed: {e}");
            }
        }
        let _ = store
            .audit(
                "console",
                "update",
                "update-channel",
                None,
                &json!({"channel": eff.channel.as_str(), "overlay_uri": eff.overlay_uri}),
            )
            .await;
    }
    print_settings(&updates::resolve(Some(&store)).await);
    Ok(())
}

fn print_job(v: &Value) {
    let j = v.get("job").unwrap_or(v);
    println!(
        "job: {} {} {}{}",
        j["kind"].as_str().unwrap_or("-"),
        j["scope"].as_str().unwrap_or(""),
        j["state"].as_str().unwrap_or("none"),
        j["exit_code"]
            .as_i64()
            .map(|c| format!(" (exit {c})"))
            .unwrap_or_default()
    );
    if let Some(t) = j["log_tail"].as_str() {
        if !t.is_empty() {
            println!("{t}");
        }
    }
}

/// `check` / `apply` with the configured channel (same as the web UI).
pub async fn job(db: Option<&Path>, action: &str, sync: bool, scope: &str) -> anyhow::Result<()> {
    let store = open_store(db).await?;
    let chan = updates::resolve(Some(&store)).await;
    let v = patronus_network::sysops::handle(
        action,
        &json!({"sync": sync, "scope": scope, "channel_settings": chan}),
    )?;
    print_job(&v);
    println!("follow it with `patronus update status`");
    Ok(())
}

pub fn status() -> anyhow::Result<()> {
    let v = patronus_network::sysops::handle("update_status", &Value::Null)?;
    let lc = &v["last_check"];
    if let Some(p) = lc["pending"].as_array() {
        println!("last check: {} package(s) pending", p.len());
        for x in p {
            println!(
                "  {} {} -> {}",
                x["atom"].as_str().unwrap_or(""),
                x["from"].as_str().unwrap_or("new"),
                x["version"].as_str().unwrap_or("")
            );
        }
    } else {
        println!("last check: none");
    }
    print_job(&v);
    Ok(())
}
