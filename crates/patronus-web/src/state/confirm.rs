//! Confirm-or-revert timer for risky changes (config history, `history.confirm_seconds`).
//!
//! With the setting at 0 (the default) nothing here runs. With N seconds, a
//! change made on the Interfaces or Firewall pages (and a restore from the
//! history page) starts a countdown: the change stays in force, a banner on
//! every page asks to confirm it, and when the countdown ends without a
//! confirmation the box puts the configuration back by itself, like pfSense's
//! "revert" and OpenWrt's LuCI rollback. The countdown runs in the server, so a
//! change that cut the admin off (a wrong address, a rule that drops the web UI)
//! heals even when the browser can never answer.

use super::AppState;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct Pending {
    id: u64,
    what: String,
    deadline: i64,
    /// The configuration before the change (without the web accounts: the
    /// timer never rolls back accounts, so it cannot lock anyone out or end
    /// their sessions).
    before: Value,
}

#[derive(Default)]
pub struct ConfirmTimer {
    next: Mutex<u64>,
    pending: Mutex<Option<Pending>>,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct PendingView {
    pub active: bool,
    pub what: String,
    pub seconds_left: i64,
    pub deadline: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl ConfirmTimer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn is_pending(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }

    pub fn view(&self) -> PendingView {
        match &*self.pending.lock().unwrap() {
            Some(p) => PendingView {
                active: true,
                what: p.what.clone(),
                seconds_left: (p.deadline - now()).max(0),
                deadline: p.deadline,
            },
            None => PendingView {
                active: false,
                what: String::new(),
                seconds_left: 0,
                deadline: 0,
            },
        }
    }

    /// Start the countdown for a change that is already in force. `before`
    /// is the exported configuration from before it. Does nothing when a
    /// countdown is already running (the first change's rollback point stays).
    pub async fn arm(&self, state: &AppState, seconds: u32, what: String, mut before: Value) {
        if let Some(t) = before.get_mut("tables").and_then(Value::as_object_mut) {
            t.remove("web_users");
        }
        let id = {
            let mut p = self.pending.lock().unwrap();
            if p.is_some() {
                return;
            }
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *p = Some(Pending {
                id: *n,
                what: what.clone(),
                deadline: now() + i64::from(seconds),
                before,
            });
            *n
        };
        let _ = state
            .config_store
            .audit(
                "web",
                "confirm_armed",
                "config",
                Some(&what),
                &json!({ "seconds": seconds }),
            )
            .await;
        let st = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(seconds))).await;
            let _ = st.confirm.revert_if(&st, id, "timeout").await;
        });
    }

    /// The change is kept. False when nothing was pending.
    pub async fn confirm(&self, state: &AppState, user: &str) -> bool {
        let p = self.pending.lock().unwrap().take();
        match p {
            Some(p) => {
                let _ = state
                    .config_store
                    .audit(user, "confirm", "config", Some(&p.what), &Value::Null)
                    .await;
                true
            }
            None => false,
        }
    }

    /// Put the configuration back now (the banner's Revert button).
    pub async fn revert_now(&self, state: &AppState, user: &str) -> anyhow::Result<Option<String>> {
        let id = self.pending.lock().unwrap().as_ref().map(|p| p.id);
        match id {
            Some(id) => self.revert_if(state, id, user).await,
            None => Ok(None),
        }
    }

    async fn revert_if(
        &self,
        state: &AppState,
        id: u64,
        who: &str,
    ) -> anyhow::Result<Option<String>> {
        let p = {
            let mut g = self.pending.lock().unwrap();
            if g.as_ref().map(|p| p.id) != Some(id) {
                return Ok(None);
            }
            g.take().unwrap()
        };
        let by = if who == "timeout" { "web" } else { who };
        let r = state
            .system
            .restore(
                &state.config_store,
                &p.before,
                &format!("unconfirmed change: {}", p.what),
            )
            .await;
        let _ = state
            .config_store
            .audit(
                by,
                if who == "timeout" {
                    "confirm_timeout_revert"
                } else {
                    "confirm_revert"
                },
                "config",
                Some(&p.what),
                &json!({ "ok": r.is_ok(), "error": r.as_ref().err().map(|e| e.to_string()) }),
            )
            .await;
        if let Err(e) = &r {
            tracing::error!("reverting the unconfirmed change ({}) failed: {e}", p.what);
        }
        r.map(|_| Some(p.what))
    }
}

/// Paths whose changes can cut an admin off from the box.
pub fn is_risky(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if !matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    ) {
        return false;
    }
    if path.ends_with("/refresh") || path.contains("/lookup") {
        return false;
    }
    [
        "/api/firewall/rules",
        "/api/firewall/nat",
        "/api/firewall/aliases",
    ]
    .iter()
    .chain(&["/api/interfaces", "/api/network/interfaces"])
    .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// Layer: a successful risky change starts the countdown when the setting is on.
pub async fn guard(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    if !is_risky(&method, &path) {
        return next.run(req).await;
    }
    let secs = patronus_config::history::confirm_seconds(&state.config_store).await;
    if secs == 0 || state.confirm.is_pending() {
        return next.run(req).await;
    }
    let before = state.config_store.export_json().await.ok();
    let resp = next.run(req).await;
    if let (true, Some(before)) = (resp.status().is_success(), before) {
        state
            .confirm
            .arm(&state, secs, format!("{method} {path}"), before)
            .await;
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn only_changes_to_interfaces_and_firewall_are_risky() {
        assert!(is_risky(&Method::POST, "/api/firewall/rules"));
        assert!(is_risky(&Method::PUT, "/api/interfaces/enp0s1"));
        assert!(is_risky(&Method::DELETE, "/api/firewall/nat/3"));
        assert!(!is_risky(&Method::GET, "/api/firewall/rules"));
        assert!(!is_risky(&Method::POST, "/api/firewall/aliases/refresh"));
        assert!(!is_risky(&Method::POST, "/api/system/history/1/restore"));
        assert!(!is_risky(&Method::PUT, "/api/interfacesx"));
    }
}
