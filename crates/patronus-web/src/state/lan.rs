//! LAN services state (lane D): DHCP (v4, v6, RA, relay), DNS (resolver /
//! forwarder, overrides, DNSBL), NTP and dynamic DNS, over the config store
//! and the `patronus_network` LAN appliers.
//!
//! A mutation = validate -> snapshot (config revision + lane-table copy) ->
//! write the store -> run the affected appliers -> on failure restore the
//! lane's tables, re-apply the previous config and return the error
//! ("Invalid ..." errors become HTTP 400). There are no fixtures: the pages
//! show exactly what the store holds and what the daemons report (leases
//! come from the DHCP server's own lease database).
//!
//! The shipped web UI runs as the unprivileged `patronus` user, so the
//! appliers run in `patronus applyd` (root) through its socket whenever
//! that socket exists; otherwise (root, or the container image) in-process.

use patronus_config::{Applier, ConfigStore};
use patronus_network::lan;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct LanManager {
    pub(super) store: Arc<ConfigStore>,
    appliers: BTreeMap<&'static str, Arc<dyn Applier>>,
    pub(super) edit: Mutex<()>,
}

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

impl LanManager {
    /// Real appliers: through `patronus applyd` when it runs, else local.
    pub fn new(store: Arc<ConfigStore>) -> Self {
        let v = lan::appliers()
            .into_iter()
            .map(patronus_network::applyd::RemoteApplier::wrap)
            .collect();
        Self::with_appliers(store, v)
    }

    /// Also drive the firewall after changes that need firewall rules
    /// (IGMP proxy, NAT64, L2TP, inline IDS, dynamic routing, HA): the
    /// state's firewall applier is registered as `firewall`.
    pub fn with_firewall(mut self, fw: Arc<dyn Applier>) -> Self {
        self.appliers.insert("firewall", fw);
        self
    }

    /// Custom appliers (tests).
    pub fn with_appliers(store: Arc<ConfigStore>, v: Vec<Arc<dyn Applier>>) -> Self {
        Self {
            store,
            appliers: v.into_iter().map(|a| (a.name(), a)).collect(),
            edit: Mutex::new(()),
        }
    }

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    /// Live status of one subsystem (`dhcp`, `dns`, `ntp`, `ddns`).
    pub async fn status(&self, name: &str) -> anyhow::Result<Value> {
        match self.appliers.get(name) {
            Some(a) => a.status(&self.store).await.map_err(e),
            None => Ok(Value::Null),
        }
    }

    // used by every LAN page; dead only in a build without any of them
    #[cfg_attr(
        not(any(
            feature = "dhcp",
            feature = "dns",
            feature = "ntp",
            feature = "segmentation"
        )),
        allow(dead_code)
    )]
    pub(super) async fn begin(&self, what: &str) -> anyhow::Result<Value> {
        self.store
            .snapshot("web", &format!("before {what}"))
            .await
            .map_err(e)?;
        lan::snapshot_tables(&self.store).await.map_err(e)
    }

    /// Run `names` after a store write; undo the write on failure.
    #[cfg_attr(
        not(any(
            feature = "dhcp",
            feature = "dns",
            feature = "ntp",
            feature = "segmentation"
        )),
        allow(dead_code)
    )]
    pub(super) async fn commit(
        &self,
        what: &str,
        snap: Value,
        names: &[&str],
    ) -> anyhow::Result<()> {
        let mut failure = None;
        for n in names {
            if let Some(a) = self.appliers.get(n) {
                if let Err(err) = a.apply(&self.store).await {
                    failure = Some(format!("{err}"));
                    break;
                }
            }
        }
        match failure {
            None => {
                let _ = self
                    .store
                    .audit("web", "update", "lan", Some(what), &Value::Null)
                    .await;
                Ok(())
            }
            Some(msg) => {
                if let Err(re) = lan::restore_tables(&self.store, &snap).await {
                    tracing::error!("could not undo {what} after a failed apply: {re}");
                }
                for n in names {
                    if let Some(a) = self.appliers.get(n) {
                        if let Err(re) = a.apply(&self.store).await {
                            tracing::warn!("re-applying the previous {n} config: {re}");
                        }
                    }
                }
                Err(anyhow::anyhow!("{msg}"))
            }
        }
    }

    /// Re-apply a subsystem from the store (the "Apply" / "Update now" buttons).
    pub async fn reapply(&self, name: &str) -> anyhow::Result<Vec<String>> {
        let _g = self.edit.lock().await;
        let a = self
            .appliers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("{name} is not built into this binary"))?;
        let r = a.apply(&self.store).await.map_err(e)?;
        Ok(r.applied.into_iter().chain(r.warnings).collect())
    }
}

// ---------------------------------------------------------------------------
// Feature pages (patronus_network::svc): syslog, NetFlow, IGMP proxy, NAT64,
// L2TP, IDS, dynamic routing, Wake-on-LAN
// ---------------------------------------------------------------------------

/// Appliers to run after a change to feature `slug`: its own, plus the
/// firewall (auto rules) and DNS (DNS64) where the feature needs them.
fn svc_appliers(spec: &patronus_network::svc::Spec) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    if !spec.applier.is_empty() {
        v.push(spec.applier);
    }
    if matches!(
        spec.slug,
        "igmp"
            | "mdns"
            | "tailscale"
            | "nat64"
            | "l2tp"
            | "upnp"
            | "openvpn"
            | "proxy"
            | "revproxy"
            | "ids"
            | "frr"
            | "edge"
            | "vrf"
            | "guest"
    ) {
        v.push("firewall");
    }
    if spec.slug == "nat64" {
        v.push("dns");
    }
    v
}

#[cfg(feature = "plugins")]
impl LanManager {
    pub fn plugin_store(&self) -> Arc<ConfigStore> {
        self.store.clone()
    }

    pub async fn plugin_install(
        &self,
        bundle: &str,
    ) -> anyhow::Result<(patronus_network::plugins::Manifest, bool)> {
        let _g = self.edit.lock().await;
        let snap = self.begin("install a plugin").await?;
        let sup = patronus_network::supervise::Supervisor::detect();
        let r = patronus_network::plugins::install(&self.store, &sup, bundle)
            .await
            .map_err(e)?;
        self.commit("plugins", snap, &["plugins", "firewall"])
            .await?;
        Ok(r)
    }

    pub async fn plugin_remove(&self, name: &str) -> anyhow::Result<bool> {
        let _g = self.edit.lock().await;
        let snap = self.begin("remove a plugin").await?;
        let sup = patronus_network::supervise::Supervisor::detect();
        let gone = patronus_network::plugins::remove(&self.store, &sup, name)
            .await
            .map_err(e)?;
        self.commit("plugins", snap, &["plugins", "firewall"])
            .await?;
        Ok(gone)
    }

    pub async fn plugin_enable(&self, name: &str, on: bool) -> anyhow::Result<bool> {
        let _g = self.edit.lock().await;
        let snap = self.begin("switch a plugin").await?;
        let found = patronus_network::plugins::set_enabled(&self.store, name, on)
            .await
            .map_err(e)?;
        self.commit("plugins", snap, &["plugins", "firewall"])
            .await?;
        Ok(found)
    }

    pub async fn plugin_key_add(&self, label: &str, public: &str) -> anyhow::Result<String> {
        let _g = self.edit.lock().await;
        let snap = self.begin("trust a plugin key").await?;
        let id = patronus_network::plugins::add_key(&self.store, label, public)
            .await
            .map_err(e)?;
        self.commit("plugins", snap, &["plugins", "firewall"])
            .await?;
        Ok(id)
    }

    pub async fn plugin_key_delete(&self, id: &str) -> anyhow::Result<bool> {
        let _g = self.edit.lock().await;
        let snap = self.begin("revoke a plugin key").await?;
        let gone = patronus_network::plugins::delete_key(&self.store, id)
            .await
            .map_err(e)?;
        self.commit("plugins", snap, &["plugins", "firewall"])
            .await?;
        Ok(gone)
    }
}

impl LanManager {
    fn svc_model(slug: &str) -> anyhow::Result<Arc<dyn patronus_network::svc::Svc>> {
        patronus_network::svc::find(slug).ok_or_else(|| {
            anyhow::anyhow!("no {slug} in this build (rebuild with the matching USE flag)")
        })
    }

    pub async fn svc_overview(&self, slug: &str) -> anyhow::Result<Value> {
        let m = Self::svc_model(slug)?;
        let spec = m.spec();
        let mut v = m.get(&self.store).await.map_err(e)?;
        v["schema"] = patronus_network::svc::schema(spec);
        v["status"] = if spec.applier.is_empty() {
            Value::Null
        } else {
            self.status(spec.applier).await.unwrap_or(Value::Null)
        };
        Ok(v)
    }

    pub async fn svc_put(&self, slug: &str, body: Value) -> anyhow::Result<()> {
        let m = Self::svc_model(slug)?;
        let _g = self.edit.lock().await;
        let snap = self.begin(&format!("change {slug} settings")).await?;
        m.put(&self.store, &body).await.map_err(e)?;
        self.commit(&format!("{slug} settings"), snap, &svc_appliers(m.spec()))
            .await
    }

    pub async fn svc_save_row(
        &self,
        slug: &str,
        coll: &str,
        id: Option<i64>,
        body: Value,
    ) -> anyhow::Result<i64> {
        let m = Self::svc_model(slug)?;
        let _g = self.edit.lock().await;
        let snap = self.begin(&format!("change {slug} {coll}")).await?;
        let id = m.save_row(&self.store, coll, id, &body).await.map_err(e)?;
        self.commit(&format!("{slug} {coll}"), snap, &svc_appliers(m.spec()))
            .await?;
        Ok(id)
    }

    pub async fn svc_delete_row(&self, slug: &str, coll: &str, id: i64) -> anyhow::Result<()> {
        let m = Self::svc_model(slug)?;
        let _g = self.edit.lock().await;
        let snap = self.begin(&format!("delete a {slug} row")).await?;
        m.delete_row(&self.store, coll, id).await.map_err(e)?;
        self.commit(&format!("{slug} {coll}"), snap, &svc_appliers(m.spec()))
            .await
    }

    pub async fn svc_action(&self, slug: &str, name: &str, body: Value) -> anyhow::Result<Value> {
        let m = Self::svc_model(slug)?;
        if !m.action_applies(name) {
            let mut out = m.action(&self.store, name, &body).await.map_err(e)?;
            // the guest Wi-Fi share card: add the QR code of the "join this network" text
            if slug == "guest" && name == "share" {
                if let Some(uri) = out["uri"].as_str() {
                    out["qr_svg"] = crate::qrcode::generate_qr_code_svg(uri)
                        .map(Value::String)
                        .unwrap_or(Value::Null);
                }
            }
            return Ok(out);
        }
        // a button that changes stored settings: snapshot, act, apply, undo on failure
        let _g = self.edit.lock().await;
        let snap = self.begin(&format!("{slug} {name}")).await?;
        let out = m.action(&self.store, name, &body).await.map_err(e)?;
        self.commit(&format!("{slug} {name}"), snap, &svc_appliers(m.spec()))
            .await?;
        Ok(out)
    }

    /// Guest network watcher tick: re-apply the guest network when a Wi-Fi
    /// voucher has expired (or was added) since the last look, or when the
    /// local UTC offset changed (the schedule's nft `meta hour` rules are
    /// converted from local time when they are loaded).
    #[cfg(feature = "guest")]
    pub async fn guest_tick(&self, last: &mut Option<(Vec<i64>, i32)>) {
        if !patronus_network::guest::is_enabled(&self.store).await {
            *last = None;
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let offset = chrono::Local::now().offset().local_minus_utc();
        let ids = patronus_network::guest::active_voucher_ids(&self.store, now)
            .await
            .unwrap_or_default();
        let cur = (ids, offset);
        match last {
            Some(prev) if *prev != cur => {
                match self.reapply("guest").await {
                    Ok(_) => tracing::info!(
                        "guest network re-applied (voucher set or UTC offset changed)"
                    ),
                    Err(err) => tracing::error!("guest network re-apply: {err}"),
                }
                *last = Some(cur);
            }
            Some(_) => {}
            None => *last = Some(cur),
        }
    }
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

#[cfg(feature = "dhcp")]
mod dhcp_impl {
    use super::*;
    use patronus_network::{dhcp, dhcp6, ra};

    impl LanManager {
        pub async fn dhcp_overview(&self) -> anyhow::Result<Value> {
            let s = &*self.store;
            Ok(serde_json::json!({
                "settings": {
                    "backend": lan::setting_or(s, "dhcp.backend", "auto").await.map_err(e)?,
                    "ra_backend": lan::setting_or(s, "dhcp.ra_backend", "auto").await.map_err(e)?,
                },
                "pools": dhcp::list_pools(s).await.map_err(e)?,
                "dhcp6": dhcp6::list(s).await.map_err(e)?,
                "ra": ra::list(s).await.map_err(e)?,
                "relays": dhcp::list_relays(s).await.map_err(e)?,
                "status": self.status("dhcp").await?,
            }))
        }

        pub async fn set_dhcp_backends(
            &self,
            backend: Option<String>,
            ra_backend: Option<String>,
        ) -> anyhow::Result<()> {
            let b = backend
                .map(|v| dhcp::check_backend_setting(&v, &["auto", "kea", "dnsmasq"]))
                .transpose()
                .map_err(e)?;
            let r = ra_backend
                .map(|v| dhcp::check_backend_setting(&v, &["auto", "radvd", "dnsmasq"]))
                .transpose()
                .map_err(e)?;
            let _g = self.edit.lock().await;
            let snap = self.begin("change DHCP backend").await?;
            if let Some(b) = b {
                lan::set_setting(&self.store, "dhcp.backend", &b)
                    .await
                    .map_err(e)?;
            }
            if let Some(r) = r {
                lan::set_setting(&self.store, "dhcp.ra_backend", &r)
                    .await
                    .map_err(e)?;
            }
            self.commit("DHCP backend", snap, &["dhcp"]).await
        }

        pub async fn save_pool(&self, id: Option<i64>, i: dhcp::PoolInput) -> anyhow::Result<i64> {
            let p = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DHCP pool on {}", p.interface);
            let snap = self.begin(&what).await?;
            let id = dhcp::upsert_pool(&self.store, id, &p).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await?;
            Ok(id)
        }

        pub async fn delete_pool(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DHCP pool {id}");
            let snap = self.begin(&what).await?;
            dhcp::delete_pool(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }

        pub async fn add_static(&self, pool_id: i64, i: dhcp::StaticInput) -> anyhow::Result<i64> {
            let pool = dhcp::get_pool(&self.store, pool_id)
                .await
                .map_err(e)?
                .ok_or_else(|| anyhow::anyhow!("DHCP pool {pool_id} not found"))?;
            let m = i.validate(&pool).map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("static mapping {} -> {}", m.mac, m.ip);
            let snap = self.begin(&what).await?;
            let id = dhcp::add_static(&self.store, &m).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await?;
            Ok(id)
        }

        pub async fn save_static(&self, id: i64, i: dhcp::StaticInput) -> anyhow::Result<()> {
            let pools = dhcp::list_pools(&self.store).await.map_err(e)?;
            let pool = pools
                .into_iter()
                .find(|p| p.static_mappings.iter().any(|m| m.id == id))
                .ok_or_else(|| anyhow::anyhow!("static mapping {id} not found"))?;
            let m = i.validate(&pool).map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("static mapping {} -> {}", m.mac, m.ip);
            let snap = self.begin(&what).await?;
            dhcp::update_static(&self.store, id, &m).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }

        pub async fn delete_static(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete static mapping {id}");
            let snap = self.begin(&what).await?;
            dhcp::delete_static(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }

        pub async fn save_dhcp6(
            &self,
            id: Option<i64>,
            i: dhcp6::Dhcp6Input,
        ) -> anyhow::Result<i64> {
            let p = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DHCPv6 pool on {}", p.interface);
            let snap = self.begin(&what).await?;
            let id = dhcp6::upsert(&self.store, id, &p).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await?;
            Ok(id)
        }

        pub async fn delete_dhcp6(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DHCPv6 pool {id}");
            let snap = self.begin(&what).await?;
            dhcp6::delete(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }

        pub async fn save_ra(&self, id: Option<i64>, i: ra::RaInput) -> anyhow::Result<i64> {
            let r = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("router advertisements on {}", r.interface);
            let snap = self.begin(&what).await?;
            let id = ra::upsert(&self.store, id, &r).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await?;
            Ok(id)
        }

        pub async fn delete_ra(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete RA config {id}");
            let snap = self.begin(&what).await?;
            ra::delete(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }

        pub async fn save_relay(
            &self,
            id: Option<i64>,
            i: dhcp::RelayInput,
        ) -> anyhow::Result<i64> {
            let r = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DHCP relay on {}", r.interface);
            let snap = self.begin(&what).await?;
            let id = dhcp::upsert_relay(&self.store, id, &r).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await?;
            Ok(id)
        }

        pub async fn delete_relay(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DHCP relay {id}");
            let snap = self.begin(&what).await?;
            dhcp::delete_relay(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["dhcp"]).await
        }
    }
}

// ---------------------------------------------------------------------------
// DNS + DDNS
// ---------------------------------------------------------------------------

#[cfg(feature = "dns")]
mod dns_impl {
    use super::*;
    use patronus_network::{ddns, dns};

    impl LanManager {
        pub async fn dns_overview(&self) -> anyhow::Result<Value> {
            let s = &*self.store;
            Ok(serde_json::json!({
                "settings": dns::settings(s).await.map_err(e)?,
                "hosts": dns::list_hosts(s).await.map_err(e)?,
                "domains": dns::list_domains(s).await.map_err(e)?,
                "blocklist": dns::list_blocked(s).await.map_err(e)?,
                "status": self.status("dns").await?,
            }))
        }

        pub async fn save_dns_settings(&self, i: dns::DnsSettingsInput) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let snap = self.begin("change DNS settings").await?;
            dns::save_settings(&self.store, &i).await.map_err(e)?;
            // the DNS server handed out by DHCP/RA follows the DNS mode; DNS on
            // extra interfaces (dns.interfaces) opens port 53 there (firewall)
            self.commit("DNS settings", snap, &["dns", "dhcp", "firewall"])
                .await
        }

        pub async fn add_host(&self, i: dns::HostInput) -> anyhow::Result<i64> {
            let h = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DNS host override {}.{}", h.hostname, h.domain);
            let snap = self.begin(&what).await?;
            let id = dns::add_host(&self.store, &h).await.map_err(e)?;
            self.commit(&what, snap, &["dns"]).await?;
            Ok(id)
        }

        pub async fn add_domain(&self, i: dns::DomainInput) -> anyhow::Result<i64> {
            let d = i.validate().map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DNS domain override {}", d.domain);
            let snap = self.begin(&what).await?;
            let id = dns::add_domain(&self.store, &d).await.map_err(e)?;
            self.commit(&what, snap, &["dns"]).await?;
            Ok(id)
        }

        pub async fn add_blocked(&self, i: dns::BlockInput) -> anyhow::Result<i64> {
            let _g = self.edit.lock().await;
            let what = format!("DNSBL entry {}", i.domain.trim());
            let snap = self.begin(&what).await?;
            let id = dns::add_blocked(&self.store, &i).await.map_err(e)?;
            self.commit(&what, snap, &["dns"]).await?;
            Ok(id)
        }

        pub async fn delete_dns(&self, table: &str, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DNS {table} entry {id}");
            let snap = self.begin(&what).await?;
            dns::delete_row(&self.store, table, id).await.map_err(e)?;
            self.commit(&what, snap, &["dns"]).await
        }

        pub async fn ddns_overview(&self) -> anyhow::Result<Value> {
            let clients: Vec<Value> = ddns::list(&self.store)
                .await
                .map_err(e)?
                .iter()
                .map(|c| {
                    let mut v = c.public();
                    v["key"] = Value::from(c.key());
                    v
                })
                .collect();
            Ok(serde_json::json!({
                "clients": clients,
                "status": self.status("ddns").await?,
            }))
        }

        pub async fn save_ddns(&self, id: Option<i64>, i: ddns::DdnsInput) -> anyhow::Result<i64> {
            let old = match id {
                Some(id) => Some(
                    ddns::get(&self.store, id)
                        .await
                        .map_err(e)?
                        .ok_or_else(|| anyhow::anyhow!("DDNS client {id} not found"))?,
                ),
                None => None,
            };
            let c = i.validate(old.as_ref()).map_err(e)?;
            let _g = self.edit.lock().await;
            let what = format!("DDNS client {}", c.hostname);
            let snap = self.begin(&what).await?;
            let id = ddns::upsert(&self.store, id, &c).await.map_err(e)?;
            self.commit(&what, snap, &["ddns"]).await?;
            Ok(id)
        }

        pub async fn delete_ddns(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let what = format!("delete DDNS client {id}");
            let snap = self.begin(&what).await?;
            ddns::delete(&self.store, id).await.map_err(e)?;
            self.commit(&what, snap, &["ddns"]).await
        }

        /// "Update now": force every client to update on this apply.
        pub async fn ddns_update_now(&self) -> anyhow::Result<Vec<String>> {
            ddns::request_force(&self.store).await.map_err(e)?;
            self.reapply("ddns").await
        }
    }
}

// ---------------------------------------------------------------------------
// General setup: host name, DNS domain, time zone
// ---------------------------------------------------------------------------

impl LanManager {
    pub async fn general_overview(&self) -> anyhow::Result<Value> {
        Ok(serde_json::json!({
            "settings": patronus_network::general::settings(&self.store).await.map_err(e)?,
        }))
    }

    pub async fn save_general(
        &self,
        i: patronus_network::general::GeneralInput,
    ) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let snap = self.begin("change general setup").await?;
        patronus_network::general::save_settings(&self.store, &i)
            .await
            .map_err(e)?;
        self.commit("general setup", snap, &["general"]).await
    }
}

// ---------------------------------------------------------------------------
// SSH server (System page): port, listen addresses, CA / principals / host cert
// ---------------------------------------------------------------------------

impl LanManager {
    pub async fn ssh_overview(&self) -> anyhow::Result<Value> {
        Ok(serde_json::json!({
            "settings": patronus_network::ssh::settings(&self.store).await.map_err(e)?,
            "status": self.status("ssh").await?,
        }))
    }

    /// Store, apply sshd, then the firewall (the anti-lockout rule follows
    /// `ssh.port`); undo the store write when either fails.
    pub async fn save_ssh(&self, i: patronus_network::ssh::SshInput) -> anyhow::Result<()> {
        use patronus_network::ssh;
        let _g = self.edit.lock().await;
        let snap = ssh::snapshot(&self.store).await.map_err(e)?;
        self.store
            .snapshot("web", "before change SSH server settings")
            .await
            .map_err(e)?;
        ssh::save_settings(&self.store, &i).await.map_err(e)?;
        let names = ["ssh", "firewall"];
        let mut failure = None;
        for n in names {
            if let Some(a) = self.appliers.get(n) {
                if let Err(err) = a.apply(&self.store).await {
                    failure = Some(format!("{err}"));
                    break;
                }
            }
        }
        match failure {
            None => {
                let _ = self
                    .store
                    .audit("web", "update", "ssh", None, &Value::Null)
                    .await;
                Ok(())
            }
            Some(msg) => {
                if let Err(re) = ssh::restore(&self.store, &snap).await {
                    tracing::error!("could not undo the SSH settings after a failed apply: {re}");
                }
                for n in names {
                    if let Some(a) = self.appliers.get(n) {
                        if let Err(re) = a.apply(&self.store).await {
                            tracing::warn!("re-applying the previous {n} config: {re}");
                        }
                    }
                }
                Err(anyhow::anyhow!("{msg}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Web UI listeners (System page): HTTPS port, HTTP redirect, extra ports, cert
// ---------------------------------------------------------------------------

impl LanManager {
    /// The effective settings, what is stored, and where each value comes from
    /// is implied by the layers (store > patronus.toml > environment > built-in).
    pub async fn web_overview(&self) -> anyhow::Result<Value> {
        use patronus_config::webui;
        let effective = webui::resolve(Some(&self.store)).await;
        let stored: serde_json::Map<String, Value> = webui::stored(&self.store)
            .await
            .into_iter()
            .map(|(k, v)| (k.to_string(), Value::String(v)))
            .collect();
        Ok(serde_json::json!({
            "effective": effective,
            "stored": stored,
            "ports_open_in_firewall": effective.all_ports(),
            "applies": "after a restart of the web UI (POST /api/system/services/patronus-web/restart)",
        }))
    }

    /// Validate and store the `web.*` keys, then re-apply the firewall so the
    /// anti-lockout rule already opens the new ports before the web UI is
    /// restarted onto them; undo the store write when the apply fails.
    pub async fn save_web(&self, i: patronus_config::webui::WebInput) -> anyhow::Result<()> {
        use patronus_config::webui;
        let _g = self.edit.lock().await;
        self.store
            .snapshot("web", "before change web UI listeners")
            .await
            .map_err(e)?;
        let before = webui::save(&self.store, &i).await.map_err(e)?;
        let mut failure = None;
        if let Some(a) = self.appliers.get("firewall") {
            if let Err(err) = a.apply(&self.store).await {
                failure = Some(format!("{err}"));
            }
        }
        match failure {
            None => {
                let _ = self
                    .store
                    .audit("web", "update", "web-ui", None, &Value::Null)
                    .await;
                Ok(())
            }
            Some(msg) => {
                if let Err(re) = webui::restore(&self.store, &before).await {
                    tracing::error!(
                        "could not undo the web UI settings after a failed apply: {re}"
                    );
                }
                if let Some(a) = self.appliers.get("firewall") {
                    if let Err(re) = a.apply(&self.store).await {
                        tracing::warn!("re-applying the previous firewall: {re}");
                    }
                }
                Err(anyhow::anyhow!("{msg}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

#[cfg(feature = "ntp")]
mod ntp_impl {
    use super::*;
    use patronus_network::ntp;

    impl LanManager {
        pub async fn ntp_overview(&self) -> anyhow::Result<Value> {
            Ok(serde_json::json!({
                "settings": ntp::settings(&self.store).await.map_err(e)?,
                "status": self.status("ntp").await?,
            }))
        }

        pub async fn save_ntp(&self, i: ntp::NtpInput) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let snap = self.begin("change NTP settings").await?;
            ntp::save_settings(&self.store, &i).await.map_err(e)?;
            // DHCP hands out the router as NTP server when it serves time
            self.commit("NTP settings", snap, &["ntp", "dhcp"]).await
        }
    }
}

// ---------------------------------------------------------------------------
// High availability (lane G)
// ---------------------------------------------------------------------------

#[cfg(feature = "ha")]
mod ha_impl {
    use super::*;
    use patronus_network::ha;

    impl LanManager {
        pub async fn ha_overview(&self) -> anyhow::Result<Value> {
            Ok(serde_json::json!({
                "settings": ha::settings(&self.store).await.map_err(e)?,
                "vips": ha::list_vips(&self.store).await.map_err(e)?,
                "status": self.status("ha").await?,
            }))
        }

        pub async fn save_ha_settings(&self, i: ha::SettingsInput) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let snap = self.begin("change HA settings").await?;
            ha::save_settings(&self.store, &i).await.map_err(e)?;
            self.commit("HA settings", snap, &["ha"]).await
        }

        pub async fn save_vip(&self, id: Option<i64>, i: ha::VipInput) -> anyhow::Result<i64> {
            let _g = self.edit.lock().await;
            let snap = self.begin("change virtual IPs").await?;
            let id = match ha::save_vip(&self.store, id, &i).await {
                Ok(id) => id,
                Err(err) => return Err(e(err)),
            };
            self.commit("virtual IP", snap, &["ha"]).await?;
            Ok(id)
        }

        pub async fn delete_vip(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let snap = self.begin("delete a virtual IP").await?;
            ha::delete_vip(&self.store, id).await.map_err(e)?;
            self.commit("virtual IP", snap, &["ha"]).await
        }
    }
}

// ---------------------------------------------------------------------------
// Traffic shaping (lane C, USE=qos)
// ---------------------------------------------------------------------------

#[cfg(feature = "qos")]
mod qos_impl {
    use super::*;
    use patronus_network::shaping;

    impl LanManager {
        pub async fn qos_overview(&self) -> anyhow::Result<Value> {
            Ok(serde_json::json!({
                "shapers": shaping::list(&self.store).await.map_err(e)?,
                "status": self.status("qos").await?,
            }))
        }

        pub async fn save_shaper(
            &self,
            id: Option<i64>,
            i: shaping::ShaperInput,
        ) -> anyhow::Result<i64> {
            let _g = self.edit.lock().await;
            let snap = self.begin("change traffic shaping").await?;
            let id = shaping::save(&self.store, id, &i).await.map_err(e)?;
            self.commit("traffic shaping", snap, &["qos"]).await?;
            Ok(id)
        }

        pub async fn delete_shaper(&self, id: i64) -> anyhow::Result<()> {
            let _g = self.edit.lock().await;
            let snap = self.begin("delete a shaper").await?;
            shaping::delete(&self.store, id).await.map_err(e)?;
            self.commit("traffic shaping", snap, &["qos"]).await
        }
    }
}

#[cfg(all(test, feature = "dhcp", feature = "dns"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use patronus_config::{ApplyReport, Phase};
    use patronus_core::Result;

    /// Fails while `fail` holds (like a daemon rejecting its config).
    struct Flaky {
        name: &'static str,
        fail: std::sync::atomic::AtomicBool,
        runs: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl Applier for Flaky {
        fn name(&self) -> &'static str {
            self.name
        }
        fn phase(&self) -> Phase {
            Phase::Services
        }
        async fn apply(&self, _s: &ConfigStore) -> Result<ApplyReport> {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(patronus_core::Error::Config(
                    "Invalid generated /etc/kea/kea-dhcp4.conf".into(),
                ));
            }
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> Result<String> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn failed_apply_undoes_the_store_write() {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        let dhcp = Arc::new(Flaky {
            name: "dhcp",
            fail: false.into(),
            runs: 0.into(),
        });
        let m = LanManager::with_appliers(store.clone(), vec![dhcp.clone()]);
        let pool = |a: &str| patronus_network::dhcp::PoolInput {
            interface: "@lan".into(),
            enabled: true,
            range_start: format!("192.168.{a}.100"),
            range_end: format!("192.168.{a}.199"),
            ..Default::default()
        };
        m.save_pool(None, pool("50")).await.unwrap();
        dhcp.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = m.save_pool(Some(1), pool("51")).await.unwrap_err();
        assert!(err.to_string().contains("Invalid"), "{err}");
        let pools = patronus_network::dhcp::list_pools(&store).await.unwrap();
        assert_eq!(pools[0].range_start.to_string(), "192.168.50.100");
        // bad input never reaches the store or the applier
        let runs = dhcp.runs.load(std::sync::atomic::Ordering::SeqCst);
        assert!(m.save_pool(None, pool("x")).await.is_err());
        assert_eq!(dhcp.runs.load(std::sync::atomic::Ordering::SeqCst), runs);
        // every accepted change left a config revision
        assert!(!store.list_revisions().await.unwrap().is_empty());
    }
}
