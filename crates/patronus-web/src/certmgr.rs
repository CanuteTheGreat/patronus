//! Certificate manager, web side: the renewal task (issue what is missing,
//! renew what is inside its window, report failures as `cert_renewal_failed`
//! events through the normal notification pipeline) and the live reload of
//! the web UI's TLS certificate after an issue or renewal.

use crate::state::telemetry::{self, Event};
use crate::state::AppState;

fn event(kind: &str, subject: &str, severity: &str, detail: String) -> Event {
    Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: kind.into(),
        subject: subject.into(),
        severity: severity.into(),
        detail,
    }
}

/// Re-read the certificate files the web UI is configured with and swap them
/// into the running listeners.  Existing connections keep their session; new
/// handshakes get the new certificate.
pub async fn reload_web_tls(store: &patronus_config::store::ConfigStore) {
    let s = patronus_config::webui::resolve(Some(store)).await;
    if s.tls_cert.is_empty() || s.tls_key.is_empty() {
        return;
    }
    match crate::tls::reload(&s.tls_cert, &s.tls_key).await {
        Ok(()) => tracing::info!("web UI now serves {}", s.tls_cert),
        Err(e) => tracing::error!("reloading the web UI certificate: {e:#}"),
    }
}

/// One pass: returns after acting on every due certificate.
pub async fn run_once(state: &AppState) {
    let outcomes = patronus_network::certs::tick(&state.config_store).await;
    let notify = patronus_network::svc::Settings::load(
        &state.config_store,
        patronus_network::svc::find("certs").map(|s| s.spec()).unwrap_or_else(|| unreachable!()),
    )
    .await
    .map(|s| s.b("notify"))
    .unwrap_or(true);
    for o in outcomes {
        if o.ok && o.use_for_web {
            reload_web_tls(&state.config_store).await;
        }
        let e = if o.ok {
            event("cert_renewed", &o.name, "info", o.detail.clone())
        } else {
            event("cert_renewal_failed", &o.name, "warning", o.detail.clone())
        };
        if let Err(err) = telemetry::record(&state.config_store, &e).await {
            tracing::warn!("recording certificate event: {err}");
        }
        if notify && !o.ok {
            telemetry::deliver(state.config_store.clone(), e).await;
        }
    }
}

/// Spawn the periodic task.  The interval is the `certs.check_mins` setting,
/// re-read every round; the first look is shortly after start (the port-80
/// listener must be up before an HTTP-01 order).
pub fn spawn_task(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            std::env::var("PATRONUS_CERTS_FIRST_CHECK_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
        ))
        .await;
        loop {
            if patronus_network::certs::any_enabled(&state.config_store).await {
                run_once(&state).await;
            }
            let mins = patronus_network::svc::Settings::load(
                &state.config_store,
                patronus_network::svc::find("certs").map(|s| s.spec()).unwrap_or_else(|| unreachable!()),
            )
            .await
            .map(|s| s.s("check_mins").parse::<u64>().unwrap_or(60))
            .unwrap_or(60)
            .max(1);
            let secs = std::env::var("PATRONUS_CERTS_CHECK_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(mins * 60);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        }
    });
}
