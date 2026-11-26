//! `patronus ha-event`: what keepalived's notify script runs on every VRRP
//! transition (USE=ha). The script has already recorded the new state in
//! `/run/patronus/ha-state`; this re-applies the services that follow the
//! virtual IP (WireGuard, OpenVPN, IPsec). Each applier asks the state file
//! whether it may run, so a node that becomes MASTER brings its tunnels up
//! and one that goes to BACKUP/FAULT takes them down.

use super::apply;
use std::path::PathBuf;

pub async fn event(db: Option<PathBuf>, state: String) -> anyhow::Result<()> {
    let store = apply::open_store(db.as_deref()).await?;
    let lines = patronus_network::ha_follow::apply_followers(&store).await;
    println!("ha-event {state}: {}", lines.join("; "));
    let _ = store
        .audit(
            "system",
            "ha-event",
            "ha",
            Some(&state),
            &serde_json::json!({ "services": lines }),
        )
        .await;
    store.close().await;
    if lines.iter().any(|l| l.contains(": FAILED ")) {
        anyhow::bail!(
            "a service that follows the virtual IP failed: {}",
            lines.join("; ")
        );
    }
    Ok(())
}
