//! VPN configuration (lane F): WireGuard tunnels/peers and IPsec tunnels
//! over the config store and the `patronus_network` WireGuard / IPsec
//! appliers (through `patronus applyd` when it runs, as root).
//!
//! A mutation = validate -> snapshot (config revision + lane-table copy) ->
//! write the store -> apply the VPN subsystem and the firewall (listen
//! ports, IPsec rules) -> on failure restore the lane's tables, re-apply and
//! return the error ("Invalid ..." errors become HTTP 400). Live tunnel
//! state comes from `VpnManager` (wg show / swanctl --list-sas).

use patronus_config::{Applier, ConfigStore};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct TunnelsManager {
    store: Arc<ConfigStore>,
    wireguard: Option<Arc<dyn Applier>>,
    ipsec: Option<Arc<dyn Applier>>,
    firewall: Arc<dyn Applier>,
    edit: Mutex<()>,
}

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WireGuard,
    Ipsec,
}

impl TunnelsManager {
    /// The real appliers compiled into this build (USE=wireguard / ipsec).
    pub fn new(store: Arc<ConfigStore>, firewall: Arc<dyn Applier>) -> Self {
        let mut wg = None;
        let mut ipsec = None;
        for a in patronus_network::vpn_appliers() {
            match a.name() {
                "wireguard" => wg = Some(patronus_network::applyd::RemoteApplier::wrap(a)),
                "ipsec" => ipsec = Some(patronus_network::applyd::RemoteApplier::wrap(a)),
                _ => {}
            }
        }
        Self::with_appliers(store, wg, ipsec, firewall)
    }

    /// Custom appliers (tests).
    pub fn with_appliers(
        store: Arc<ConfigStore>,
        wireguard: Option<Arc<dyn Applier>>,
        ipsec: Option<Arc<dyn Applier>>,
        firewall: Arc<dyn Applier>,
    ) -> Self {
        Self {
            store,
            wireguard,
            ipsec,
            firewall,
            edit: Mutex::new(()),
        }
    }

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    pub fn has(&self, k: Kind) -> bool {
        match k {
            Kind::WireGuard => self.wireguard.is_some(),
            Kind::Ipsec => self.ipsec.is_some(),
        }
    }

    /// The IPsec applier (live SAs are read through it, as root).
    pub fn ipsec_applier(&self) -> Option<Arc<dyn Applier>> {
        self.ipsec.clone()
    }

    fn applier(&self, k: Kind) -> anyhow::Result<&Arc<dyn Applier>> {
        let a = match k {
            Kind::WireGuard => self.wireguard.as_ref(),
            Kind::Ipsec => self.ipsec.as_ref(),
        };
        a.ok_or_else(|| {
            anyhow::anyhow!(
                "{} support is not built into this Patronus (rebuild with USE={})",
                if k == Kind::WireGuard {
                    "WireGuard"
                } else {
                    "IPsec"
                },
                if k == Kind::WireGuard {
                    "wireguard"
                } else {
                    "ipsec"
                }
            )
        })
    }

    /// Write the store with `f`, apply `k` + the firewall, undo on failure.
    pub async fn change<F, Fut, T>(&self, k: Kind, what: &str, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(Arc<ConfigStore>) -> Fut,
        Fut: std::future::Future<Output = patronus_core::Result<T>>,
    {
        let applier = self.applier(k)?.clone();
        let _g = self.edit.lock().await;
        self.store
            .snapshot("web", &format!("before {what}"))
            .await
            .map_err(e)?;
        let snap = patronus_network::vpn::snapshot_tables(&self.store)
            .await
            .map_err(e)?;
        let out = f(self.store.clone()).await.map_err(e)?;
        let mut res = applier.apply(&self.store).await.map(|_| ());
        if res.is_ok() {
            res = self.firewall.apply(&self.store).await.map(|_| ());
        }
        match res {
            Ok(()) => {
                let _ = self
                    .store
                    .audit("web", "update", "vpn", Some(what), &Value::Null)
                    .await;
                Ok(out)
            }
            Err(err) => {
                if let Err(re) = patronus_network::vpn::restore_tables(&self.store, &snap).await {
                    tracing::error!("could not undo {what} after a failed apply: {re}");
                }
                if let Err(re) = applier.apply(&self.store).await {
                    tracing::warn!("re-applying the previous VPN config: {re}");
                }
                if let Err(re) = self.firewall.apply(&self.store).await {
                    tracing::warn!("re-applying the previous firewall: {re}");
                }
                Err(anyhow::anyhow!("{err}"))
            }
        }
    }

    /// Re-run one VPN subsystem from the store.
    pub async fn reapply(&self, k: Kind) -> anyhow::Result<Vec<String>> {
        let a = self.applier(k)?.clone();
        let _g = self.edit.lock().await;
        let r = a.apply(&self.store).await.map_err(e)?;
        Ok(r.applied.into_iter().chain(r.warnings).collect())
    }

    /// Live status of the IPsec applier (`installed`, `running`, `sas`).
    pub async fn ipsec_status(&self) -> anyhow::Result<Value> {
        match &self.ipsec {
            Some(a) => a.status(&self.store).await.map_err(e),
            None => Ok(Value::Null),
        }
    }
}

#[cfg(all(test, feature = "wireguard", feature = "ipsec"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use patronus_config::applier::{ApplyReport, Phase};

    /// Fails while the stored tunnel has a given name.
    struct Picky(&'static str);
    #[async_trait]
    impl Applier for Picky {
        fn name(&self) -> &'static str {
            "wireguard"
        }
        fn phase(&self) -> Phase {
            Phase::Interfaces
        }
        async fn apply(&self, s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
            let t = patronus_network::wireguard::list_interfaces(s).await?;
            if t.iter().any(|i| i.name == self.0) {
                return Err(patronus_core::Error::Network("kernel said no".into()));
            }
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn a_refused_apply_leaves_the_store_as_it_was() {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        let m = TunnelsManager::with_appliers(
            store.clone(),
            Some(Arc::new(Picky("wg9"))),
            None,
            Arc::new(crate::state::firewall::NoopApplier),
        );
        use patronus_network::wireguard::{save_interface, InterfaceInput};
        m.change(Kind::WireGuard, "add wg0", |s| async move {
            save_interface(&s, None, &InterfaceInput::default()).await
        })
        .await
        .unwrap();
        let err = m
            .change(Kind::WireGuard, "add wg9", |s| async move {
                save_interface(
                    &s,
                    None,
                    &InterfaceInput {
                        name: Some("wg9".into()),
                        ..Default::default()
                    },
                )
                .await
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("kernel said no"));
        let names: Vec<String> = patronus_network::wireguard::list_interfaces(&store)
            .await
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert_eq!(names, vec!["wg0"], "wg9 was rolled back");
        // IPsec is not built in here: say so instead of pretending
        let e = m.reapply(Kind::Ipsec).await.unwrap_err().to_string();
        assert!(e.contains("USE=ipsec"), "{e}");
    }
}
