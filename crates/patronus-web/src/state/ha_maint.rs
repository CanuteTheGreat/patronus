//! HA maintenance procedure for the web layer: confirmed hand-off, automatic maintenance around
//! upgrades / restarts, and leaving it again once the node is back and healthy.
//!
//! The procedure itself (checks, waiting, timeouts) is `patronus_network::ha_maint`; this file
//! wires it to the config store (generations), the HA applier status, the progress the page shows
//! and the `system_events` log.

#![cfg(feature = "ha")]

use crate::state::{telemetry, AppState};
use patronus_network::ha;
use patronus_network::ha_maint::{self, MaintenanceSetter, Outcome, Progress, SystemNode};
use std::sync::Mutex;

static PROGRESS: Mutex<Option<Progress>> = Mutex::new(None);
/// one hand-off at a time
static BUSY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the HA page banner shows: the procedure's latest progress.
pub fn progress() -> Progress {
    PROGRESS
        .lock()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(Progress::idle)
}

fn set_progress(p: Progress) {
    if let Ok(mut g) = PROGRESS.lock() {
        *g = Some(p);
    }
}

struct Setter<'a>(&'a AppState);

#[async_trait::async_trait]
impl MaintenanceSetter for Setter<'_> {
    async fn set(&self, on: bool, auto: bool) -> anyhow::Result<()> {
        self.0
            .lan
            .save_ha_settings(ha::SettingsInput {
                maintenance: Some(on),
                maintenance_auto: Some(auto),
                ..Default::default()
            })
            .await
    }
}

async fn event(state: &AppState, subject: &str, severity: &str, detail: String) {
    let e = telemetry::Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: "ha_maintenance".into(),
        subject: subject.into(),
        severity: severity.into(),
        detail,
    };
    if let Err(err) = telemetry::record(&state.config_store, &e).await {
        tracing::warn!("ha maintenance event not recorded: {err}");
    }
}

fn node<'a>(
    state: &'a AppState,
    setter: &'a Setter<'a>,
    status: &'a (dyn Fn() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send>,
    > + Send
             + Sync),
) -> SystemNode<'a> {
    SystemNode {
        store: &state.config_store,
        status,
        setter,
    }
}

/// Enter maintenance: check the peer, lower the priority, wait for the hand-over.
pub async fn enter(
    state: &AppState,
    force: bool,
    auto: bool,
    reason: &str,
) -> anyhow::Result<Outcome> {
    let _g = BUSY.lock().await;
    let st = state.clone();
    let status = move || {
        let st = st.clone();
        Box::pin(async move { st.lan.status("ha").await })
            as std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<_>> + Send>>
    };
    let setter = Setter(state);
    let n = node(state, &setter, &status);
    let r = ha_maint::enter(&n, force, auto, reason, &set_progress).await;
    match &r {
        Ok(o) if o.maintenance => {
            event(
                state,
                reason,
                "info",
                format!("maintenance on ({reason}): {}", o.message),
            )
            .await
        }
        Ok(_) => {}
        Err(e) => {
            event(
                state,
                reason,
                "warning",
                format!("maintenance refused or failed ({reason}): {e}"),
            )
            .await
        }
    }
    r.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Leave maintenance and wait for the node to be healthy again.
pub async fn leave(state: &AppState, reason: &str) -> anyhow::Result<Outcome> {
    let _g = BUSY.lock().await;
    let st = state.clone();
    let status = move || {
        let st = st.clone();
        Box::pin(async move { st.lan.status("ha").await })
            as std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<_>> + Send>>
    };
    let setter = Setter(state);
    let n = node(state, &setter, &status);
    let r = ha_maint::leave(&n, reason, &set_progress).await;
    match &r {
        Ok(o) => {
            event(
                state,
                reason,
                "info",
                format!("maintenance off ({reason}): {}", o.message),
            )
            .await
        }
        Err(e) => {
            event(
                state,
                reason,
                "warning",
                format!("maintenance off, node not healthy ({reason}): {e}"),
            )
            .await
        }
    }
    r.map_err(|e| anyhow::anyhow!("{e}"))
}

/// Run before a firmware upgrade, a package update that restarts services, a restart or a
/// shutdown. Returns `Ok(true)` when the node entered automatic maintenance (the caller leaves it
/// again after a package update; after a restart / upgrade the next start does), `Ok(false)` when
/// there is nothing to do (HA off, automatic maintenance switched off) and an error with the
/// reasons when the peer is not healthy (unless `force`).
pub async fn before_disruption(
    state: &AppState,
    reason: &str,
    force: bool,
) -> anyhow::Result<bool> {
    let s = ha::settings(&state.config_store)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !s.enabled || !s.auto_maintenance {
        return Ok(false);
    }
    if s.maintenance {
        // already in maintenance (by hand or an earlier step): nothing to hand over
        return Ok(false);
    }
    let o = enter(state, force, true, reason).await?;
    Ok(o.maintenance)
}

/// After a package update job: leave the automatic maintenance when the job has ended.
pub fn leave_after_update(state: AppState) {
    tokio::spawn(async move {
        // the job is polled for at most 3 hours; a restart of the web UI is covered by `resume_at_start`
        for _ in 0..(3 * 3600 / 5) {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let v = match state
                .system
                .system_op("update_status", serde_json::Value::Null)
                .await
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v["job"]["state"] != "running" {
                break;
            }
        }
        if let Err(e) = leave(&state, "package update").await {
            tracing::warn!("HA: leaving maintenance after the update: {e}");
        }
    });
}

/// At start: a node that went into automatic maintenance before a restart / upgrade leaves it
/// once it is back and healthy (typed `ha.rejoin_timeout`).
pub fn resume_at_start(state: AppState) {
    tokio::spawn(async move {
        let Ok(s) = ha::settings(&state.config_store).await else {
            return;
        };
        if !(s.enabled && s.maintenance && s.maintenance_auto) {
            return;
        }
        tracing::info!("HA: leaving the automatic maintenance mode entered before the restart");
        // give keepalived a moment to start and hear the peer
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Err(e) = leave(&state, "restart").await {
            tracing::warn!("HA: {e}");
        }
    });
}
