//! Self-filling firewall aliases in the web process (lane B): the refresh
//! task, the GeoIP database settings and the threat-intelligence feed
//! list. The parsing, capping and rules live in `patronus_firewall::feeds`;
//! this adds the live nft set swap (or a full apply when the swap cannot
//! run), the audit trail and the shapes the API returns.

use super::firewall::FirewallManager;
use patronus_firewall::aliases::{self, Alias, AliasSource};
use patronus_firewall::feeds::{self, Fetcher, Outcome};
use patronus_firewall::nftables::AliasKind;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Body of `PUT /api/firewall/hardening`; every field optional.
#[derive(Debug, Default, Deserialize)]
pub struct HardeningBody {
    /// drop | reject
    pub inbound_action: Option<String>,
    pub synflood_protect: Option<bool>,
    /// e.g. `25/second`
    pub synflood_rate: Option<String>,
    pub synflood_burst: Option<u32>,
    /// comma list of `@wan` / `@optN` / device; empty turns clamping off
    pub mss_clamp: Option<String>,
    pub drop_ipv4_options: Option<bool>,
}

/// One row of the threat-intel page.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatFeed {
    pub id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub custom: bool,
    pub configured: bool,
    pub enabled: bool,
    pub direction: String,
    pub refresh_secs: u64,
    pub max_entries: u64,
    pub count: i64,
    pub status: String,
    pub last_refresh: Option<i64>,
    /// `drop` or `alert` (count and log only).
    pub action: String,
    /// Packets that matched the feed in the last 24 hours / 7 days (the
    /// security overview's sampler, `sec_feed_hits`).
    pub hits_24h: u64,
    pub hits_7d: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatOverview {
    pub max_total: u64,
    pub total_entries: i64,
    pub feeds: Vec<ThreatFeed>,
}

/// Body of `PUT /api/firewall/threatintel/:id`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ThreatBody {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub refresh_secs: Option<u64>,
    #[serde(default)]
    pub max_entries: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
    /// `drop` (default) or `alert`.
    #[serde(default)]
    pub action: Option<String>,
}

/// One GeoIP alias for the GeoIP page.
#[derive(Debug, Clone, Serialize)]
pub struct GeoAlias {
    pub name: String,
    pub countries: Vec<String>,
    pub ranges: usize,
    pub status: String,
    pub last_refresh: Option<i64>,
    pub used_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoOverview {
    pub database: feeds::GeoDbStatus,
    pub default_url: String,
    pub countries: Vec<GeoCountry>,
    pub aliases: Vec<GeoAlias>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoCountry {
    pub code: &'static str,
    pub name: &'static str,
}

fn valid_feed_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 24
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && id != "allow"
}

impl FirewallManager {
    /// Use another source of list bytes (tests).
    pub fn set_fetcher(&self, f: Arc<dyn Fetcher>) {
        *self.fetcher.write().expect("fetcher lock") = f;
    }

    /// After an alias was saved: if it fills itself, fetch it now (in the
    /// background; the periodic task would also pick it up within a minute).
    pub fn spawn_refresh(fw: Arc<FirewallManager>, name: String) {
        tokio::spawn(async move {
            let has = aliases::get_alias(&fw.store, &name)
                .await
                .ok()
                .flatten()
                .map(|a| a.source.is_some())
                .unwrap_or(false);
            if has {
                if let Err(e) = fw.refresh_feeds(Some(vec![name.clone()])).await {
                    tracing::warn!("refresh of alias {name}: {e}");
                }
            }
        });
    }

    fn fetcher(&self) -> Arc<dyn Fetcher> {
        self.fetcher.read().expect("fetcher lock").clone()
    }

    /// Refresh aliases now (`None` = whatever is due). Entries that
    /// changed are swapped into the live nft sets in one transaction each
    /// (no ruleset reload); if that cannot run, or a threat feed changed
    /// from empty to filled (its rules appear), the ruleset is re-applied.
    pub async fn refresh_feeds(&self, only: Option<Vec<String>>) -> anyhow::Result<Vec<Outcome>> {
        let f = self.fetcher();
        let outcomes = feeds::refresh_due(&self.store, f.as_ref(), only.as_deref(), now())
            .await
            .map_err(Self::e)?;
        let changed: Vec<&Alias> = outcomes.iter().filter_map(|o| o.changed.as_ref()).collect();
        if changed.is_empty() {
            return Ok(outcomes);
        }
        let _g = self.edit.lock().await;
        let mut need_push = false;
        for a in &changed {
            // a threat feed whose rules did not exist yet needs a full render
            let first_fill = a
                .source
                .as_ref()
                .map(|s| s.kind == feeds::KIND_THREAT)
                .unwrap_or(false)
                && a.source.as_ref().and_then(|s| s.last_count).unwrap_or(0) == 0;
            let script = aliases::update_sets_script(a).map_err(Self::e)?;
            match patronus_firewall::nftables::execute_nft_script(&script) {
                Ok(_) if !first_fill => {}
                Ok(_) => need_push = true,
                Err(e) => {
                    tracing::warn!("live update of alias {} failed ({e}); re-applying", a.name);
                    need_push = true;
                }
            }
        }
        if need_push {
            self.push().await?;
        }
        for a in &changed {
            self.audit(
                "refresh",
                "alias",
                &a.name,
                serde_json::json!({ "entries": a.entries.len() }),
            )
            .await;
        }
        Ok(outcomes)
    }

    /// Re-download the GeoIP database now and re-evaluate every GeoIP alias.
    pub async fn refresh_geoip(&self) -> anyhow::Result<Vec<Outcome>> {
        let f = self.fetcher();
        feeds::refresh_geoip_db(&self.store, f.as_ref(), true, now())
            .await
            .map_err(Self::e)?;
        let names: Vec<String> = aliases::load_aliases(&self.store)
            .await
            .map_err(Self::e)?
            .into_iter()
            .filter(|a| a.source.as_ref().map(|s| s.kind.as_str()) == Some(feeds::KIND_GEOIP))
            .map(|a| a.name)
            .collect();
        self.refresh_feeds(Some(names)).await
    }

    // ---------------- log viewer settings ----------------

    pub async fn log_default_deny(&self) -> anyhow::Result<bool> {
        Ok(self
            .store
            .load_system_config(feeds::CFG_LOG_DEFAULT_DENY)
            .await
            .map_err(Self::e)?
            .map(|v| v == "1")
            .unwrap_or(false))
    }

    /// Log (rate limited) what the default policy drops.
    pub async fn set_log_default_deny(&self, on: bool) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let old = self.log_default_deny().await?;
        self.snapshot("default-deny logging".into()).await?;
        self.store
            .save_system_config(feeds::CFG_LOG_DEFAULT_DENY, if on { "1" } else { "0" })
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = self
                .store
                .save_system_config(feeds::CFG_LOG_DEFAULT_DENY, if old { "1" } else { "0" })
                .await;
            return Err(e);
        }
        self.audit(
            "update",
            "firewall-log",
            "default-deny",
            serde_json::json!({ "enabled": on }),
        )
        .await;
        Ok(())
    }

    // ---------------- WAN source guard ----------------

    pub async fn wan_guard(&self) -> anyhow::Result<patronus_firewall::wanguard::WanGuard> {
        patronus_firewall::wanguard::load(&self.store)
            .await
            .map_err(Self::e)
    }

    /// Block private / bogon source addresses on the WAN (rolled back when
    /// the ruleset does not load).
    pub async fn set_wan_guard(
        &self,
        g: patronus_firewall::wanguard::WanGuard,
    ) -> anyhow::Result<()> {
        let _gl = self.edit.lock().await;
        let old = self.wan_guard().await?;
        self.snapshot("WAN source guard".into()).await?;
        patronus_firewall::wanguard::save(&self.store, g)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = patronus_firewall::wanguard::save(&self.store, old).await;
            return Err(e);
        }
        self.audit(
            "update",
            "firewall-wan-guard",
            "wan",
            serde_json::json!({ "block_private": g.block_private, "block_bogons": g.block_bogons }),
        )
        .await;
        Ok(())
    }

    // ---------------- hardening (fw4 parity) ----------------

    pub async fn hardening(&self) -> anyhow::Result<serde_json::Value> {
        use patronus_firewall::hardening as h;
        let c = h::load(&self.store).await.map_err(Self::e)?;
        Ok(serde_json::json!({
            "inbound_action": if c.reject { "reject" } else { "drop" },
            "synflood_protect": c.synflood,
            "synflood_rate": c.synflood_rate,
            "synflood_burst": c.synflood_burst,
            "mss_clamp": c.mss_clamp.join(","),
            "drop_ipv4_options": c.drop_ipv4_options,
        }))
    }

    /// Change any of the hardening settings (omitted ones stay), validate,
    /// apply, and put the old values back when the apply fails.
    pub async fn set_hardening(&self, b: HardeningBody) -> anyhow::Result<()> {
        use patronus_firewall::hardening as h;
        let mut kv: Vec<(&str, String)> = Vec::new();
        if let Some(a) = &b.inbound_action {
            let a = a.trim().to_ascii_lowercase();
            if a != "drop" && a != "reject" {
                anyhow::bail!("Invalid inbound action {a:?} (drop or reject)");
            }
            kv.push((h::INBOUND_ACTION_KEY, a));
        }
        if let Some(v) = b.synflood_protect {
            kv.push((h::SYNFLOOD_KEY, if v { "1" } else { "0" }.into()));
        }
        if let Some(r) = &b.synflood_rate {
            kv.push((h::SYNFLOOD_RATE_KEY, h::normalize_rate(r).map_err(Self::e)?));
        }
        if let Some(n) = b.synflood_burst {
            if n == 0 || n > 1_000_000 {
                anyhow::bail!("Invalid SYN flood burst {n} (1 to 1000000)");
            }
            kv.push((h::SYNFLOOD_BURST_KEY, n.to_string()));
        }
        if let Some(m) = &b.mss_clamp {
            kv.push((
                h::MSS_CLAMP_KEY,
                h::parse_mss_list(m).map_err(Self::e)?.join(","),
            ));
        }
        if let Some(v) = b.drop_ipv4_options {
            kv.push((h::DROP_IPV4_OPTIONS_KEY, if v { "1" } else { "0" }.into()));
        }
        let _g = self.edit.lock().await;
        let mut old = Vec::new();
        for (k, _) in &kv {
            old.push((*k, self.store.load_system_config(k).await.map_err(Self::e)?));
        }
        self.snapshot("firewall hardening".into()).await?;
        for (k, v) in &kv {
            self.store.save_system_config(k, v).await.map_err(Self::e)?;
        }
        if let Err(e) = self.push().await {
            for (k, v) in old {
                let _ = self
                    .store
                    .save_system_config(k, v.as_deref().unwrap_or(""))
                    .await;
            }
            return Err(e);
        }
        self.audit(
            "update",
            "firewall-hardening",
            "settings",
            serde_json::json!({ "changed": kv.iter().map(|(k, _)| *k).collect::<Vec<_>>() }),
        )
        .await;
        Ok(())
    }

    // ---------------- GeoIP ----------------

    pub async fn geoip_overview(&self) -> anyhow::Result<GeoOverview> {
        let all = aliases::load_aliases(&self.store).await.map_err(Self::e)?;
        let mut out = Vec::new();
        for a in all {
            let Some(s) = a.source.clone().filter(|s| s.kind == feeds::KIND_GEOIP) else {
                continue;
            };
            let used_by = aliases::alias_users(&self.store, &a.name)
                .await
                .map_err(Self::e)?;
            out.push(GeoAlias {
                ranges: a.entries.len(),
                name: a.name,
                countries: s.countries,
                status: s.last_status.unwrap_or_else(|| "not built yet".into()),
                last_refresh: s.last_refresh,
                used_by,
            });
        }
        Ok(GeoOverview {
            database: feeds::geoip_status(&self.store).await.map_err(Self::e)?,
            default_url: feeds::default_geoip_urls(now()).remove(0),
            countries: feeds::COUNTRIES
                .iter()
                .map(|(code, name)| GeoCountry { code, name })
                .collect(),
            aliases: out,
        })
    }

    pub async fn set_geoip_config(&self, db_url: &str, refresh_days: u64) -> anyhow::Result<()> {
        feeds::set_geoip_config(&self.store, db_url, refresh_days)
            .await
            .map_err(Self::e)?;
        self.audit(
            "update",
            "geoip",
            "database",
            serde_json::json!({ "db_url": db_url, "refresh_days": refresh_days }),
        )
        .await;
        Ok(())
    }

    /// Which country does the downloaded database say `ip` is in?
    pub async fn geoip_lookup(&self, ip: std::net::IpAddr) -> anyhow::Result<Option<String>> {
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
            let db = feeds::load_geoip_db()
                .ok_or_else(|| anyhow::anyhow!("the GeoIP database has not been downloaded yet"))?;
            Ok(db.lookup(ip))
        })
        .await?
    }

    // ---------------- threat intelligence ----------------

    pub async fn threat_overview(&self) -> anyhow::Result<ThreatOverview> {
        let all = aliases::load_aliases(&self.store).await.map_err(Self::e)?;
        let now = chrono::Utc::now().timestamp();
        let h24 = crate::security::feed_hits_since(&self.store, now - 86_400)
            .await
            .unwrap_or_default();
        let h7 = crate::security::feed_hits_since(&self.store, now - 7 * 86_400)
            .await
            .unwrap_or_default();
        let mut feeds_out: Vec<ThreatFeed> = Vec::new();
        let row = |id: &str, name: &str, desc: &str, url: &str, custom: bool, a: Option<&Alias>| {
            let s = a.and_then(|a| a.source.as_ref());
            ThreatFeed {
                action: s.map(|s| s.action.clone()).unwrap_or_else(|| "drop".into()),
                hits_24h: h24.get(id).copied().unwrap_or(0),
                hits_7d: h7.get(id).copied().unwrap_or(0),
                id: id.to_string(),
                name: name.to_string(),
                description: desc.to_string(),
                url: s
                    .and_then(|s| s.url.clone())
                    .unwrap_or_else(|| url.to_string()),
                custom,
                configured: a.is_some(),
                enabled: s.map(|s| s.enabled).unwrap_or(false),
                direction: s
                    .map(|s| s.direction.clone())
                    .unwrap_or_else(|| "both".into()),
                refresh_secs: s.map(|s| s.refresh_secs).unwrap_or(86_400),
                max_entries: s.map(|s| s.max_entries).unwrap_or(100_000),
                count: s.and_then(|s| s.last_count).unwrap_or(0),
                status: s.and_then(|s| s.last_status.clone()).unwrap_or_else(|| {
                    if a.is_some() {
                        "not fetched yet".into()
                    } else {
                        "off".into()
                    }
                }),
                last_refresh: s.and_then(|s| s.last_refresh),
            }
        };
        for c in feeds::CATALOG {
            let a = all
                .iter()
                .find(|a| a.name == feeds::threat_alias_name(c.id));
            feeds_out.push(row(c.id, c.name, c.description, c.url, false, a));
        }
        for a in &all {
            let is_threat = a
                .source
                .as_ref()
                .map(|s| s.kind == feeds::KIND_THREAT)
                .unwrap_or(false);
            let id = a.name.trim_start_matches(feeds::THREAT_PREFIX);
            if is_threat && feeds::catalog_feed(id).is_none() {
                feeds_out.push(row(
                    id,
                    id,
                    a.description.as_deref().unwrap_or("custom feed"),
                    "",
                    true,
                    Some(a),
                ));
            }
        }
        let total = feeds_out
            .iter()
            .filter(|f| f.enabled)
            .map(|f| f.count)
            .sum();
        let max_total = self
            .store
            .load_system_config(feeds::CFG_THREAT_TOTAL)
            .await
            .map_err(Self::e)?
            .and_then(|v| v.parse().ok())
            .filter(|v: &u64| *v > 0)
            .unwrap_or(feeds::DEFAULT_THREAT_TOTAL);
        Ok(ThreatOverview {
            max_total,
            total_entries: total,
            feeds: feeds_out,
        })
    }

    pub async fn set_threat_max_total(&self, n: u64) -> anyhow::Result<()> {
        if !(1000..=2 * feeds::HARD_MAX_ENTRIES).contains(&n) {
            anyhow::bail!("Invalid request: total budget between 1000 and 1000000 entries");
        }
        self.store
            .save_system_config(feeds::CFG_THREAT_TOTAL, &n.to_string())
            .await
            .map_err(Self::e)?;
        self.audit(
            "update",
            "threatintel",
            "budget",
            serde_json::json!({ "max_total": n }),
        )
        .await;
        Ok(())
    }

    /// Create or change a threat feed (`ti_<id>` alias with a threat
    /// source) and apply the ruleset.
    pub async fn set_threat_feed(&self, id: &str, b: ThreatBody) -> anyhow::Result<()> {
        if !valid_feed_id(id) {
            anyhow::bail!("Invalid request: feed id {id:?} (lower-case letters, digits, _; at most 24; not \"allow\")");
        }
        let name = feeds::threat_alias_name(id);
        let _g = self.edit.lock().await;
        let old = aliases::get_alias(&self.store, &name)
            .await
            .map_err(Self::e)?;
        let cat = feeds::catalog_feed(id);
        let mut src = old
            .as_ref()
            .and_then(|a| a.source.clone())
            .unwrap_or_else(|| AliasSource::new(feeds::KIND_THREAT));
        src.kind = feeds::KIND_THREAT.into();
        if let Some(u) = b.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            src.url = Some(u.to_string());
        }
        if src.url.is_none() {
            src.url = cat.map(|c| c.url.to_string());
        }
        if src.url.is_none() {
            anyhow::bail!("Invalid request: a custom feed needs a url");
        }
        if let Some(v) = b.enabled {
            src.enabled = v;
        }
        if let Some(v) = b.direction {
            src.direction = v;
        }
        if let Some(v) = b.action {
            src.action = v;
        }
        if let Some(v) = b.refresh_secs {
            src.refresh_secs = v;
        }
        if let Some(v) = b.max_entries {
            src.max_entries = v;
        }
        let a = Alias {
            name: name.clone(),
            kind: AliasKind::Host,
            entries: old.as_ref().map(|a| a.entries.clone()).unwrap_or_default(),
            description: b
                .description
                .filter(|d| !d.trim().is_empty())
                .or_else(|| cat.map(|c| c.name.to_string()))
                .or_else(|| old.as_ref().and_then(|a| a.description.clone())),
            source: Some(src),
        }
        .validated()
        .map_err(Self::e)?;
        let src =
            feeds::check_source(&a, a.source.as_ref().expect("set above")).map_err(Self::e)?;
        let a = Alias {
            source: Some(src),
            ..a
        };
        self.snapshot(format!("threat feed {id}")).await?;
        aliases::save_alias(&self.store, &a)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            match old {
                Some(o) => {
                    let _ = aliases::save_alias(&self.store, &o).await;
                }
                None => {
                    let _ = aliases::delete_alias(&self.store, &name).await;
                }
            }
            return Err(e);
        }
        self.audit(
            "update",
            "threatintel",
            id,
            serde_json::json!({ "enabled": a.source.as_ref().map(|s| s.enabled) }),
        )
        .await;
        Ok(())
    }

    pub async fn delete_threat_feed(&self, id: &str) -> anyhow::Result<()> {
        if !valid_feed_id(id) {
            anyhow::bail!("Invalid request: feed id {id:?}");
        }
        let name = feeds::threat_alias_name(id);
        let _g = self.edit.lock().await;
        let Some(old) = aliases::get_alias(&self.store, &name)
            .await
            .map_err(Self::e)?
        else {
            anyhow::bail!("Feed {id} is not configured");
        };
        self.snapshot(format!("delete threat feed {id}")).await?;
        aliases::delete_alias(&self.store, &name)
            .await
            .map_err(Self::e)?;
        if let Err(e) = self.push().await {
            let _ = aliases::save_alias(&self.store, &old).await;
            return Err(e);
        }
        self.audit("delete", "threatintel", id, serde_json::Value::Null)
            .await;
        Ok(())
    }
}

/// Background task: refresh whatever is due, once a minute
/// (`PATRONUS_FEEDS_TICK_SECS` overrides, for tests).
pub fn spawn_feed_task(fw: Arc<FirewallManager>) {
    let secs = std::env::var("PATRONUS_FEEDS_TICK_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(60);
    tokio::spawn(async move {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        loop {
            t.tick().await;
            match fw.refresh_feeds(None).await {
                Ok(o) => {
                    for x in o {
                        if x.ok {
                            tracing::info!("alias {}: {}", x.alias, x.status);
                        } else {
                            tracing::warn!("alias {}: {}", x.alias, x.status);
                        }
                    }
                }
                Err(e) => tracing::error!("alias refresh failed: {e}"),
            }
        }
    });
}
