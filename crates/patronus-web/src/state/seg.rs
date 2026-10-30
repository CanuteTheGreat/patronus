//! Device segmentation, lane 3: per-device/group DNS policy (mutations with
//! undo through the LAN manager), the DNS query-log collector and the
//! parental time-limit ticker + "time's up" page server.

use patronus_config::ConfigStore;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// DNS policies (feature `dns`: needs the unbound applier)
// ---------------------------------------------------------------------------

#[cfg(feature = "dns")]
mod dns_impl {
    use super::*;
    use crate::state::lan::LanManager;
    use std::sync::Mutex;

    fn e(e: patronus_core::Error) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }
    use patronus_network::seg_dns::{self, PolicyInput, RuleInput};

    impl LanManager {
        pub async fn seg_dns_save_policy(
            &self,
            id: Option<i64>,
            i: PolicyInput,
        ) -> anyhow::Result<i64> {
            let _g = self.edit.lock().await;
            let what = format!("DNS policy {}", i.name.as_deref().unwrap_or("(edit)"));
            let snap = self.begin(&what).await?;
            let pid = match id {
                Some(id) => {
                    seg_dns::update_policy(&self.store, id, &i)
                        .await
                        .map_err(e)?;
                    id
                }
                None => seg_dns::create_policy(&self.store, &i).await.map_err(e)?,
            };
            self.commit(&what, snap, &["dns"]).await?;
            Ok(pid)
        }

        pub async fn seg_dns_delete_policy(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DNS policy {id}");
            let snap = self.begin(&what).await?;
            // the assignments live in the segmentation tables, which the LAN
            // undo does not cover: remember who used the policy
            let users = policy_users(&self.store, id).await;
            seg_dns::delete_policy(&self.store, id).await.map_err(e)?;
            if let Err(err) = self.commit(&what, snap, &["dns"]).await {
                for (kind, uid) in users {
                    let _ = seg_dns::assign(&self.store, kind, uid, Some(id)).await;
                }
                return Err(err);
            }
            Ok(())
        }

        pub async fn seg_dns_add_rule(&self, policy: i64, i: RuleInput) -> anyhow::Result<i64> {
            let _g = self.edit.lock().await;
            let what = format!("DNS rule {} {}", i.action, i.domain);
            let snap = self.begin(&what).await?;
            let id = seg_dns::add_rule(&self.store, policy, &i)
                .await
                .map_err(e)?;
            self.commit(&what, snap, &["dns"]).await?;
            Ok(id)
        }

        pub async fn seg_dns_delete_rule(&self, policy: i64, rule: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DNS rule {rule}");
            let snap = self.begin(&what).await?;
            seg_dns::delete_rule(&self.store, policy, rule)
                .await
                .map_err(e)?;
            self.commit(&what, snap, &["dns"]).await
        }

        pub async fn seg_dns_assign(
            &self,
            kind: &str,
            id: i64,
            policy: Option<i64>,
        ) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("assign DNS policy to {kind} {id}");
            let before = seg_dns::assignment(&self.store, kind, id)
                .await
                .map_err(e)?;
            let snap = self.begin(&what).await?;
            seg_dns::assign(&self.store, kind, id, policy)
                .await
                .map_err(e)?;
            if let Err(err) = self.commit(&what, snap, &["dns"]).await {
                let _ = seg_dns::assign(&self.store, kind, id, before).await;
                return Err(err);
            }
            Ok(())
        }

        pub async fn seg_dns_overview(&self) -> anyhow::Result<serde_json::Value> {
            let s = &*self.store;
            let policies = seg_dns::list_policies(s).await.map_err(e)?;
            let mut out = Vec::new();
            for p in policies {
                let rules = seg_dns::list_rules(s, p.id).await.map_err(e)?;
                let groups: Vec<String> = sqlx::query_scalar(
                    "SELECT name FROM seg_groups WHERE dns_policy_id = ? ORDER BY name",
                )
                .bind(p.id)
                .fetch_all(s.pool().map_err(e)?)
                .await
                .unwrap_or_default();
                let devices: Vec<String> = sqlx::query_scalar(
                    "SELECT name FROM seg_devices WHERE dns_policy_id = ? ORDER BY name",
                )
                .bind(p.id)
                .fetch_all(s.pool().map_err(e)?)
                .await
                .unwrap_or_default();
                let mut v = serde_json::to_value(&p)?;
                v["rules"] = serde_json::to_value(rules)?;
                v["groups"] = serde_json::json!(groups);
                v["devices"] = serde_json::json!(devices);
                out.push(v);
            }
            let clients = seg_dns::clients(s).await.map_err(e)?;
            Ok(serde_json::json!({
                "policies": out,
                "clients": clients,
                "status": self.status("dns").await?,
            }))
        }
    }

    async fn policy_users(store: &ConfigStore, id: i64) -> Vec<(&'static str, i64)> {
        let Ok(pool) = store.pool() else {
            return Vec::new();
        };
        let mut v = Vec::new();
        for (kind, table) in [("group", "seg_groups"), ("device", "seg_devices")] {
            let ids: Vec<i64> =
                sqlx::query_scalar(&format!("SELECT id FROM {table} WHERE dns_policy_id = ?"))
                    .bind(id)
                    .fetch_all(pool)
                    .await
                    .unwrap_or_default();
            v.extend(ids.into_iter().map(|i| (kind, i)));
        }
        v
    }

    /// Last collector pass (for the status card).
    pub static LAST_INGEST: Mutex<Option<(i64, seg_dns::IngestStats)>> = Mutex::new(None);

    /// Tail the unbound query log into the store (and prune it) for ever.
    pub fn spawn_dns_log_collector(store: Arc<ConfigStore>) {
        tokio::spawn(async move {
            let secs = std::env::var("PATRONUS_DNSLOG_TICK_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|s| *s > 0)
                .unwrap_or(5);
            let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
            let mut last_prune = 0i64;
            let mut last_err = String::new();
            loop {
                t.tick().await;
                let path = seg_dns::log_path();
                match seg_dns::ingest(&store, &path).await {
                    Ok(st) => {
                        last_err.clear();
                        if st.lines > 0 {
                            if let Ok(mut g) = LAST_INGEST.lock() {
                                *g = Some((chrono::Utc::now().timestamp(), st));
                            }
                        }
                    }
                    Err(err) => {
                        if last_err != err.to_string() {
                            tracing::error!("DNS query log: {err}");
                            last_err = err.to_string();
                        }
                    }
                }
                let now = chrono::Utc::now().timestamp();
                if now - last_prune >= 600 {
                    last_prune = now;
                    if let Err(err) = seg_dns::prune(&store, now, 200_000).await {
                        tracing::error!("DNS query log prune: {err}");
                    }
                }
            }
        });
    }
}

#[cfg(feature = "dns")]
pub use dns_impl::{spawn_dns_log_collector, LAST_INGEST};

// ---------------------------------------------------------------------------
// parental time limits
// ---------------------------------------------------------------------------

/// Flows with byte counters: `/proc/net/nf_conntrack` when the kernel has it
/// (CONFIG_NF_CONNTRACK_PROCFS is off in newer kernels), else
/// `conntrack -L -o extended` (the same fallback as the insights page).
fn read_conntrack() -> String {
    if let Ok(t) = std::fs::read_to_string("/proc/net/nf_conntrack") {
        return t;
    }
    std::process::Command::new("conntrack")
        .args(["-L", "-o", "extended"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Test handshake for the injectable clock: with `PATRONUS_FAKE_TIME_FILE`
/// set, the ticker publishes the number of COMPLETED ticks in
/// `<that file>.ack` (atomically). A scenario that moves the clock or
/// generates traffic waits until the counter has advanced by two (the tick in
/// flight may have read conntrack before the traffic, the next one cannot
/// have), so it never has to guess with a sleep. No effect without the
/// fake clock.
fn publish_tick_ack(seq: u64) {
    if let Some(f) = std::env::var_os(patronus_firewall::schedule::FAKE_TIME_ENV) {
        let mut ack = f;
        ack.push(".ack");
        let ack = std::path::PathBuf::from(ack);
        let tmp = ack.with_extension("ack.tmp");
        if std::fs::write(&tmp, seq.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &ack);
        }
    }
}

/// Minute ticker: account active time from conntrack, decide, move device
/// addresses in and out of the nft sets (`patronus_firewall::seg_time`).
pub fn spawn_time_ticker(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        let secs = std::env::var("PATRONUS_TIME_TICK_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .unwrap_or(5);
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        let mut ticker = patronus_firewall::seg_time::TimeTicker::new();
        let mut last_err = String::new();
        let mut last_prune = 0i64;
        let mut seq = 0u64;
        loop {
            t.tick().await;
            let ct = tokio::task::spawn_blocking(read_conntrack)
                .await
                .unwrap_or_default();
            let at = patronus_firewall::schedule::now();
            match ticker.tick(&store, at, &ct, true).await {
                Ok(_) => last_err.clear(),
                Err(err) => {
                    if last_err != err.to_string() {
                        tracing::error!("time limits: {err}");
                        last_err = err.to_string();
                    }
                }
            }
            let now = chrono::Utc::now().timestamp();
            if now - last_prune >= 3600 {
                last_prune = now;
                let _ = patronus_firewall::seg_time::prune_usage(&store, at, 60).await;
            }
            seq += 1;
            publish_tick_ack(seq);
        }
    });
}

/// The plain-HTTP "time's up" / grace page (patronus-captiveportal).
pub fn spawn_timeup_portal(store: Arc<ConfigStore>) {
    tokio::spawn(async move {
        let port = patronus_firewall::seg_time::portal_port(&store).await;
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        if let Err(err) = patronus_captiveportal::timeup::serve(store, addr).await {
            tracing::error!("time's-up page on {addr}: {err}");
        }
    });
}
