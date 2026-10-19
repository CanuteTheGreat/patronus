//! Routing state (lane E): gateways, gateway groups (multi-WAN), the default
//! gateway and static routes, over the config store and
//! `patronus_network::routes::RoutesApplier`.
//!
//! A mutation = validate -> snapshot (config revision + lane-table copy) ->
//! write the store -> run the routes phase -> on failure restore the lane's
//! tables, re-apply and return the error ("Invalid ..." errors become HTTP
//! 400). Gateway state (online / loss / latency / down) comes from the
//! gateway monitor running in `patronus applyd` (or in this process when
//! there is no applyd, e.g. the container image: it runs as user patronus
//! with CAP_NET_ADMIN file capabilities on ip/wg/nft, see the Dockerfile).

use patronus_config::{Applier, ConfigStore};
use patronus_network::routes::{self, Family};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct RoutingManager {
    store: Arc<ConfigStore>,
    /// The in-process applier (also what a local gateway monitor drives,
    /// so both share one apply lock).
    local: Arc<dyn Applier>,
    /// `local`, or applyd when its socket exists.
    applier: Arc<dyn Applier>,
    /// Re-applied when gateways change: every interface with an IPv4
    /// gateway gets automatic outbound NAT.
    firewall: Option<Arc<dyn Applier>>,
    edit: Mutex<()>,
}

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

impl RoutingManager {
    /// The real applier: through `patronus applyd` when it runs, else local.
    pub fn new(store: Arc<ConfigStore>, firewall: Arc<dyn Applier>) -> Self {
        let local: Arc<dyn Applier> = Arc::new(routes::RoutesApplier::default());
        Self {
            store,
            applier: patronus_network::applyd::RemoteApplier::wrap(local.clone()),
            local,
            firewall: Some(firewall),
            edit: Mutex::new(()),
        }
    }

    /// Custom appliers (tests).
    pub fn with_applier(
        store: Arc<ConfigStore>,
        applier: Arc<dyn Applier>,
        firewall: Option<Arc<dyn Applier>>,
    ) -> Self {
        Self {
            store,
            local: applier.clone(),
            applier,
            firewall,
            edit: Mutex::new(()),
        }
    }

    /// Without `patronus applyd` (container image, or root) nothing else
    /// runs the gateway monitor: run it in this process, pausing whenever
    /// the applyd socket exists (applyd's own monitor is in charge then).
    pub fn spawn_local_monitor(&self) {
        let mut m = routes::Monitor::system(self.local.clone());
        let store = self.store.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut announced = false;
            loop {
                t.tick().await;
                if patronus_network::applyd::socket_path().exists() {
                    continue;
                }
                if !announced {
                    tracing::info!(
                        "no patronus applyd: running the gateway monitor in patronus-web"
                    );
                    announced = true;
                }
                if let Err(e) = m.tick(&store).await {
                    tracing::warn!("gateway monitor: {e}");
                }
            }
        });
    }

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    /// Gateways with their live state, groups with their active members,
    /// the default gateway and the static routes.
    pub async fn status(&self) -> anyhow::Result<Value> {
        self.applier.status(&self.store).await.map_err(e)
    }

    /// Run the routes phase from the store (startup, "Re-apply").
    pub async fn apply(&self) -> anyhow::Result<Vec<String>> {
        let _g = self.edit.lock().await;
        let r = self.applier.apply(&self.store).await.map_err(e)?;
        Ok(r.applied.into_iter().chain(r.warnings).collect())
    }

    /// Returns `f`'s result and the routes apply's warnings (e.g. load
    /// balancing without port hashing), which the API passes on.
    async fn change<F, Fut, T>(
        &self,
        what: &str,
        gateways: bool,
        f: F,
    ) -> anyhow::Result<(T, Vec<String>)>
    where
        F: FnOnce(Arc<ConfigStore>) -> Fut,
        Fut: std::future::Future<Output = patronus_core::Result<T>>,
    {
        let _g = self.edit.lock().await;
        self.store
            .snapshot("web", &format!("before {what}"))
            .await
            .map_err(e)?;
        let snap = routes::snapshot_tables(&self.store).await.map_err(e)?;
        let out = f(self.store.clone()).await.map_err(e)?;
        let fw = self.firewall.as_ref().filter(|_| gateways);
        let mut warnings = Vec::new();
        let mut res = self
            .applier
            .apply(&self.store)
            .await
            .map(|r| warnings = r.warnings);
        if let (Ok(()), Some(fw)) = (&res, fw) {
            res = fw.apply(&self.store).await.map(|_| ());
        }
        match res {
            Ok(_) => {
                let _ = self
                    .store
                    .audit("web", "update", "routing", Some(what), &Value::Null)
                    .await;
                Ok((out, warnings))
            }
            Err(err) => {
                if let Err(re) = routes::restore_tables(&self.store, &snap).await {
                    tracing::error!("could not undo {what} after a failed apply: {re}");
                }
                if let Err(re) = self.applier.apply(&self.store).await {
                    tracing::warn!("re-applying the previous routes: {re}");
                }
                if let Some(fw) = fw {
                    if let Err(re) = fw.apply(&self.store).await {
                        tracing::warn!("re-applying the previous firewall: {re}");
                    }
                }
                Err(anyhow::anyhow!("{err}"))
            }
        }
    }

    pub async fn save_gateway(
        &self,
        existing: Option<String>,
        i: routes::GatewayInput,
    ) -> anyhow::Result<Vec<String>> {
        let g = i.validated().map_err(e)?;
        self.change(&format!("gateway {}", g.name), true, |s| async move {
            routes::save_gateway(&s, existing.as_deref(), &g).await
        })
        .await
        .map(|(_, w)| w)
    }

    pub async fn delete_gateway(&self, name: String) -> anyhow::Result<Vec<String>> {
        self.change(&format!("delete gateway {name}"), true, |s| async move {
            routes::delete_gateway(&s, &name).await
        })
        .await
        .map(|(_, w)| w)
    }

    pub async fn save_group(
        &self,
        existing: Option<String>,
        i: routes::GroupInput,
    ) -> anyhow::Result<Vec<String>> {
        let g = i.validated().map_err(e)?;
        self.change(
            &format!("gateway group {}", g.name),
            false,
            |s| async move { routes::save_group(&s, existing.as_deref(), &g).await },
        )
        .await
        .map(|(_, w)| w)
    }

    pub async fn delete_group(&self, name: String) -> anyhow::Result<Vec<String>> {
        self.change(
            &format!("delete gateway group {name}"),
            false,
            |s| async move { routes::delete_group(&s, &name).await },
        )
        .await
        .map(|(_, w)| w)
    }

    pub async fn set_defaults(
        &self,
        v4: Option<String>,
        v6: Option<String>,
    ) -> anyhow::Result<Vec<String>> {
        self.change("default gateway", false, |s| async move {
            if let Some(v) = v4 {
                routes::set_default(&s, Family::Inet, Some(&v)).await?;
            }
            if let Some(v) = v6 {
                routes::set_default(&s, Family::Inet6, Some(&v)).await?;
            }
            Ok(())
        })
        .await
        .map(|(_, w)| w)
    }

    pub async fn save_route(
        &self,
        id: Option<i64>,
        i: routes::RouteInput,
    ) -> anyhow::Result<(i64, Vec<String>)> {
        let cfg = routes::load(&self.store).await.map_err(e)?;
        let r = i.validated(&cfg, id.unwrap_or(0)).map_err(e)?;
        self.change(
            &format!("static route {}", r.destination),
            false,
            |s| async move { routes::save_route(&s, id, &r).await },
        )
        .await
    }

    pub async fn delete_route(&self, id: i64) -> anyhow::Result<Vec<String>> {
        self.change(
            &format!("delete static route {id}"),
            false,
            |s| async move { routes::delete_route(&s, id).await },
        )
        .await
        .map(|(_, w)| w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::{ApplyReport, Phase};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Counts applies; fails while `fail` is set (as the kernel refusing a
    /// route would).
    #[derive(Default)]
    struct Recording {
        applies: AtomicU32,
        fail: AtomicBool,
        /// Warnings every successful apply reports.
        warnings: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Applier for Recording {
        fn name(&self) -> &'static str {
            "routes"
        }
        fn phase(&self) -> Phase {
            Phase::Routes
        }
        async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(patronus_core::Error::Network(
                    "`ip -4 route replace 10.9.0.0/16` failed: Nexthop has invalid gateway".into(),
                ));
            }
            let mut r = ApplyReport::default();
            for w in self.warnings.lock().unwrap().iter() {
                r.warn(w.clone());
            }
            Ok(r)
        }
        async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
            Ok(String::new())
        }
    }

    async fn mgr() -> (RoutingManager, Arc<Recording>) {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        store.set_interface_role("eth0", Some("wan")).await.unwrap();
        let rec = Arc::new(Recording::default());
        (RoutingManager::with_applier(store, rec.clone(), None), rec)
    }

    fn gw(name: &str) -> routes::GatewayInput {
        routes::GatewayInput {
            name: name.into(),
            interface: "@wan".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn every_change_is_stored_applied_and_recorded_as_a_revision() {
        let (m, rec) = mgr().await;
        m.save_gateway(None, gw("WAN1")).await.unwrap();
        let id = m
            .save_route(
                None,
                routes::RouteInput {
                    destination: "10.20.0.0/16".into(),
                    gateway: Some("WAN1".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .0;
        m.set_defaults(Some("WAN1".into()), None).await.unwrap();
        assert_eq!(rec.applies.load(Ordering::SeqCst), 3);
        let cfg = routes::load(m.store()).await.unwrap();
        assert_eq!(cfg.default4.as_deref(), Some("WAN1"));
        assert_eq!(cfg.routes[0].id, id);
        assert!(m.store().list_revisions().await.unwrap().len() >= 3);
        // gateway changes also re-apply the firewall (outbound NAT per
        // gateway interface), other changes do not
        let fw = Arc::new(Recording::default());
        let m2 = RoutingManager::with_applier(m.store.clone(), rec.clone(), Some(fw.clone()));
        let mut g2 = gw("WAN2");
        g2.interface = "eth9".into();
        m2.save_gateway(None, g2).await.unwrap();
        assert_eq!(fw.applies.load(Ordering::SeqCst), 1);
        m2.set_defaults(Some("WAN2".into()), None).await.unwrap();
        assert_eq!(fw.applies.load(Ordering::SeqCst), 1);
        m2.set_defaults(Some("WAN1".into()), None).await.unwrap();
        m2.delete_gateway("WAN2".into()).await.unwrap();
        assert_eq!(fw.applies.load(Ordering::SeqCst), 2);
        // a firewall the kernel refuses undoes the gateway change too
        fw.fail.store(true, Ordering::SeqCst);
        assert!(m2.save_gateway(None, gw("WAN3")).await.is_err());
        assert!(routes::load(m2.store())
            .await
            .unwrap()
            .gateway("WAN3")
            .is_none());
        fw.fail.store(false, Ordering::SeqCst);
        // automatic again
        m.set_defaults(Some(String::new()), None).await.unwrap();
        assert_eq!(routes::load(m.store()).await.unwrap().default4, None);
        m.delete_route(id).await.unwrap();
        m.delete_gateway("WAN1".into()).await.unwrap();
        assert!(routes::load(m.store()).await.unwrap().gateways.is_empty());
    }

    /// Load balancing the kernel only half applied (no port hashing in a
    /// container) is saved, but the caller gets the warning instead of a
    /// bare ok.
    #[tokio::test]
    async fn apply_warnings_are_returned_to_the_caller() {
        let (m, rec) = mgr().await;
        assert!(m.save_gateway(None, gw("WAN1")).await.unwrap().is_empty());
        rec.warnings
            .lock()
            .unwrap()
            .push("net.ipv4.fib_multipath_hash_policy should be 1 but it is 0".into());
        let w = m.set_defaults(Some("WAN1".into()), None).await.unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("fib_multipath_hash_policy"), "{w:?}");
        assert_eq!(
            routes::load(m.store()).await.unwrap().default4.as_deref(),
            Some("WAN1"),
            "a warning does not undo the change"
        );
    }

    #[tokio::test]
    async fn a_change_the_kernel_refuses_is_undone_in_the_store() {
        let (m, rec) = mgr().await;
        m.save_gateway(None, gw("WAN1")).await.unwrap();
        rec.fail.store(true, Ordering::SeqCst);
        let e = m
            .save_route(
                None,
                routes::RouteInput {
                    destination: "10.9.0.0/16".into(),
                    gateway: Some("192.0.2.99".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Nexthop has invalid gateway"), "{e}");
        let e = m
            .delete_gateway("WAN1".into())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Nexthop"), "{e}");
        let cfg = routes::load(m.store()).await.unwrap();
        assert!(cfg.routes.is_empty(), "the refused route is not kept");
        assert_eq!(cfg.gateways.len(), 1, "the gateway delete was undone");
        // re-applied the previous config after each failure
        assert_eq!(rec.applies.load(Ordering::SeqCst), 1 + 2 + 2);
        // validation errors never reach the applier
        rec.fail.store(false, Ordering::SeqCst);
        let before = rec.applies.load(Ordering::SeqCst);
        let e = m
            .save_gateway(None, gw("bad name"))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Invalid"), "{e}");
        assert_eq!(rec.applies.load(Ordering::SeqCst), before);
    }
}
