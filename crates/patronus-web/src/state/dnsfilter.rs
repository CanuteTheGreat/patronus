//! DNS filter background task (docs/DNS-FILTERING.md): tail the resolver log into the
//! per-list counters / recent blocked names / query log, refresh lists that are due.

use super::LanManager;
use patronus_config::store::ConfigStore;
use patronus_network::dnsfilter as f;
use patronus_network::lan::LanEnv;
use std::sync::{Arc, Mutex};

/// Last tailer pass (for the status line of the page).
pub static LAST_INGEST: Mutex<Option<(i64, f::IngestStats)>> = Mutex::new(None);

/// Log files are emptied once they are fully read and bigger than this.
const TRUNCATE_AT: u64 = 8 * 1024 * 1024;

pub fn spawn_filter_task(store: Arc<ConfigStore>, lan: Arc<LanManager>) {
    tokio::spawn(async move {
        let secs = std::env::var("PATRONUS_DNSFILTER_TICK_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(5);
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        // how often to look for lists that are due (the netlab lane shortens it)
        let due_every = std::env::var("PATRONUS_DNSFILTER_DUE_SECS")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(300);
        let env = LanEnv::system();
        let mut attr = f::Attributor::default();
        let (mut last_prune, mut last_due, mut last_err) = (0i64, 0i64, String::new());
        loop {
            t.tick().await;
            if !f::wants_tail(&store).await {
                continue;
            }
            let _ = attr.refresh(&store, &env).await;
            for p in [f::UNBOUND_LOG, f::DNSMASQ_LOG] {
                let path = std::path::Path::new(p);
                match f::ingest(&store, path, &attr).await {
                    Ok(st) => {
                        last_err.clear();
                        if st.lines > 0 {
                            if let Ok(mut g) = LAST_INGEST.lock() {
                                *g = Some((chrono::Utc::now().timestamp(), st));
                            }
                        }
                        f::truncate_if_big(path, TRUNCATE_AT);
                    }
                    Err(e) => {
                        if last_err != e.to_string() {
                            tracing::error!("DNS filter log: {e}");
                            last_err = e.to_string();
                        }
                    }
                }
            }
            let now = chrono::Utc::now().timestamp();
            if now - last_prune >= 600 {
                last_prune = now;
                if let Err(e) = f::prune(&store).await {
                    tracing::error!("DNS filter prune: {e}");
                }
            }
            // scheduled refresh: a list is due after its refresh interval (a failed one after an hour)
            if now - last_due >= due_every {
                last_due = now;
                if matches!(f::refresh_due(&store).await, Ok(true)) {
                    if let Err(e) = lan.reapply("dns").await {
                        tracing::warn!("DNS filter refresh: {e}");
                    }
                }
            }
        }
    });
}
