//! The metrics snapshot the monitoring agents read.
//!
//! While the Zabbix agent (or Telegraf's Patronus input) is switched on, the
//! web UI writes the same text `/metrics` serves to `<monagent dir>/metrics.prom`
//! every 30 s (mode 0644, in a directory the applier created). The agents run
//! as their own unprivileged accounts and read that file; they never log in
//! and never open the configuration database. When nobody wants the file,
//! nothing is written (and a stale one is removed).

use super::{telemetry, AppState};
use patronus_network::monagent::{self, SNAPSHOT};
use patronus_network::supervise::{write_atomic, NetPaths};
use std::time::Duration;

/// Seconds between snapshots (`PATRONUS_MONAGENT_SNAPSHOT_SECS`).
fn period() -> Duration {
    Duration::from_secs(
        std::env::var("PATRONUS_MONAGENT_SNAPSHOT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(30),
    )
}

/// Does an enabled agent read the snapshot?
pub async fn wanted(store: &patronus_config::ConfigStore) -> bool {
    let flag =
        |v: Option<String>| v.is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"));
    let get = |k: &'static str| async move {
        patronus_network::lan::get_setting(store, k)
            .await
            .ok()
            .flatten()
    };
    if cfg!(feature = "zabbix-agent") && flag(get("zabbix.enabled").await) {
        return true;
    }
    cfg!(feature = "telegraf")
        && flag(get("telegraf.enabled").await)
        // the Patronus input is on by default
        && get("telegraf.in_patronus")
            .await
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true)
}

/// One refresh. Returns whether a file was written.
pub async fn tick(state: &AppState, dir: &std::path::Path) -> bool {
    let file = dir.join(SNAPSHOT);
    if !wanted(&state.config_store).await {
        let _ = std::fs::remove_file(&file);
        return false;
    }
    if !dir.is_dir() {
        // the agent applier creates it (with the right owner)
        return false;
    }
    let text = telemetry::prometheus(&telemetry::summary(state).await);
    match write_atomic(&file, &text, 0o644) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("monitoring agents: cannot write {}: {e}", file.display());
            false
        }
    }
}

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let dir = monagent::base_dir(&NetPaths::default());
        loop {
            tick(&state, &dir).await;
            tokio::time::sleep(period()).await;
        }
    });
}
