//! `patronus edge`: the SD-WAN edge agent (USE=sdwan).
//!
//! `run` is the long-lived agent (started by the edge applier as
//! `patronus-daemon@edge-agent`); `sync` does one round and exits; `status`
//! prints what the agent last did. One round:
//!
//! 1. enroll with the dashboard if there is no credential yet (WireGuard key
//!    pair = the key of the tunnel `sdwan0` in the store, one-time token from
//!    the page; the token is erased once used);
//! 2. pull the desired overlay config (`GET /api/v1/edge/config`): the other
//!    sites with their public keys, overlay addresses, subnets and endpoints;
//! 3. reconcile the store's tunnel `sdwan0` and its peers (one per site,
//!    allowed IPs = its overlay address + subnets) and apply WireGuard and the
//!    firewall when something changed;
//! 4. measure every peer (WireGuard handshake age, ping over the tunnel) and
//!    steer: a peer whose current endpoint never completes a handshake is moved
//!    to its next endpoint; after a while the preferred endpoint is retried;
//! 5. report the measurements (`POST /api/v1/edge/heartbeat`).

use crate::EdgeCommands;
use std::path::PathBuf;

#[cfg(not(feature = "sdwan-edge"))]
pub async fn handle_edge_command(_a: EdgeCommands, _db: Option<PathBuf>) -> anyhow::Result<()> {
    anyhow::bail!("this Patronus build has no SD-WAN edge agent: rebuild with USE=sdwan")
}

#[cfg(feature = "sdwan-edge")]
pub async fn handle_edge_command(action: EdgeCommands, db: Option<PathBuf>) -> anyhow::Result<()> {
    match action {
        EdgeCommands::Run => agent::run(db, false).await,
        EdgeCommands::Sync => agent::run(db, true).await,
        EdgeCommands::Status => agent::status(db).await,
    }
}

#[cfg(feature = "sdwan-edge")]
pub mod agent {
    use anyhow::{anyhow, bail, Context, Result};
    use patronus_config::{Applier, ConfigStore};
    use patronus_network::edge::{self, EdgeSettings, PEER_PREFIX, WG_IF};
    use patronus_network::supervise::Supervisor;
    use patronus_network::wireguard::{self, InterfaceInput, PeerInput};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const CONFIG_PATH: &str = "/api/v1/edge/config";
    const ENROLL_PATH: &str = "/api/v1/edge/enroll";
    const HEARTBEAT_PATH: &str = "/api/v1/edge/heartbeat";
    /// Seconds an endpoint gets to complete a handshake before the next one is tried.
    pub const ENDPOINT_PATIENCE: u64 = 20;
    /// Seconds between tries of the preferred endpoint while on a fallback
    /// (`PATRONUS_EDGE_FAILBACK_SECS` overrides it; the netlab shortens it).
    pub const FAILBACK_EVERY: u64 = 90;
    /// A confirmed endpoint whose handshake is older than this is treated as dead.
    pub const HANDSHAKE_DEAD: u64 = 135;
    /// Rounds in a row without a single ping answer after which a confirmed
    /// endpoint is treated as dead.
    pub const DEAD_ROUNDS: u32 = 3;

    fn failback_every() -> u64 {
        std::env::var("PATRONUS_EDGE_FAILBACK_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v >= 5)
            .unwrap_or(FAILBACK_EVERY)
    }

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    pub struct PeerSteer {
        pub idx: usize,
        pub since: u64,
        pub confirmed: bool,
        pub prev_idx: Option<usize>,
        pub last_try: u64,
        /// consecutive rounds without any ping answer while confirmed
        #[serde(default)]
        pub bad_rounds: u32,
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct AgentState {
        pub steer: BTreeMap<String, PeerSteer>,
        pub last_sync: u64,
        pub last_error: Option<String>,
        pub generation: String,
        pub peers: Vec<Value>,
    }

    impl AgentState {
        fn load(sup: &Supervisor) -> Self {
            std::fs::read_to_string(edge::state_path(sup))
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default()
        }
        fn save(&self, sup: &Supervisor) {
            if let Ok(t) = serde_json::to_string_pretty(self) {
                let _ =
                    patronus_network::supervise::write_atomic(&edge::state_path(sup), &t, 0o600);
            }
        }
    }

    /// Next steering decision for one peer given what we observe.
    /// `hs` = unix time of the latest handshake (0 = never), `n` = number of
    /// endpoints. Returns true when the endpoint index changed.
    pub fn steer(st: &mut PeerSteer, n: usize, hs: u64, now: u64, ping_ok: bool) -> bool {
        if n == 0 {
            return false;
        }
        st.idx %= n;
        if hs >= st.since && hs > 0 {
            st.confirmed = true;
            st.prev_idx = None;
        }
        if st.confirmed {
            st.bad_rounds = if ping_ok { 0 } else { st.bad_rounds + 1 };
            if st.bad_rounds >= DEAD_ROUNDS || now.saturating_sub(hs) > HANDSHAKE_DEAD {
                // it worked, then the link went quiet and stayed dead: move on at once
                st.confirmed = false;
                st.bad_rounds = 0;
                st.since = 0;
            }
        }
        if !st.confirmed && n > 1 && now.saturating_sub(st.since) > ENDPOINT_PATIENCE {
            st.idx = match st.prev_idx.take() {
                Some(p) => {
                    st.confirmed = true; // the previous endpoint was working
                    p
                }
                None => (st.idx + 1) % n,
            };
            st.since = now;
            return true;
        }
        if st.confirmed
            && st.idx != 0
            && now.saturating_sub(st.last_try.max(st.since)) > failback_every()
        {
            st.prev_idx = Some(st.idx);
            st.idx = 0;
            st.since = now;
            st.last_try = now;
            st.confirmed = false;
            return true;
        }
        false
    }

    fn run_cmd(prog: &str, args: &[&str]) -> Result<String> {
        let o = std::process::Command::new(prog)
            .args(args)
            .output()
            .with_context(|| format!("run {prog}"))?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).into_owned())
        } else {
            bail!(
                "`{prog} {}`: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            )
        }
    }

    /// public key -> unix time of the latest handshake (0 = never)
    pub fn parse_handshakes(out: &str) -> BTreeMap<String, u64> {
        out.lines()
            .filter_map(|l| {
                let mut p = l.split_whitespace();
                Some((p.next()?.to_string(), p.next()?.parse().ok()?))
            })
            .collect()
    }

    /// (loss %, average rtt ms) from `ping` output.
    pub fn parse_ping(out: &str) -> (f64, Option<f64>) {
        let loss = out
            .lines()
            .find(|l| l.contains("packet loss"))
            .and_then(|l| l.split(',').find(|p| p.contains("packet loss")))
            .and_then(|p| p.trim().split('%').next().map(str::to_string))
            .and_then(|p| p.trim().parse::<f64>().ok())
            .unwrap_or(100.0);
        let rtt = out
            .lines()
            .find(|l| l.contains("min/avg/max"))
            .and_then(|l| l.split('=').nth(1))
            .and_then(|v| v.trim().split('/').nth(1).map(str::to_string))
            .and_then(|v| v.parse::<f64>().ok());
        (loss, rtt)
    }

    fn http() -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("patronus-edge/", env!("CARGO_PKG_VERSION")))
            .build()?)
    }

    async fn api_error(r: reqwest::Response) -> anyhow::Error {
        let code = r.status();
        let body = r.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or(body);
        anyhow!("dashboard answered {code}: {msg}")
    }

    /// The tunnel's public key; creates `sdwan0` (disabled, no address yet) if needed.
    async fn ensure_interface(store: &ConfigStore, e: &EdgeSettings) -> Result<String> {
        let ifs = wireguard::list_interfaces(store).await?;
        if let Some(i) = ifs.iter().find(|i| i.name == WG_IF) {
            return Ok(i.public_key.clone());
        }
        wireguard::save_interface(
            store,
            None,
            &InterfaceInput {
                name: Some(WG_IF.into()),
                enabled: Some(false),
                listen_port: Some(e.listen_port),
                description: Some("SD-WAN overlay (managed by the edge agent)".into()),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("{e}"))?;
        let ifs = wireguard::list_interfaces(store).await?;
        ifs.iter()
            .find(|i| i.name == WG_IF)
            .map(|i| i.public_key.clone())
            .ok_or_else(|| anyhow!("tunnel {WG_IF} was not created"))
    }

    async fn enroll(store: &ConfigStore, e: &EdgeSettings) -> Result<()> {
        if e.token.is_empty() {
            bail!("not enrolled and no enrollment token is set");
        }
        let public_key = ensure_interface(store, e).await?;
        let body = json!({
            "token": e.token,
            "name": e.name,
            "public_key": public_key,
            "listen_port": e.listen_port,
            "subnets": e.subnets,
            "endpoints": e.endpoints.iter().map(|(a, k, c)| json!({"address": a, "interface_type": k, "cost_per_gb": c})).collect::<Vec<_>>(),
        });
        let r = http()?
            .post(format!("{}{ENROLL_PATH}", e.dashboard_url))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("reach the dashboard at {}", e.dashboard_url))?;
        if !r.status().is_success() {
            return Err(api_error(r).await);
        }
        let v: Value = r.json().await?;
        let cred = v["credential"]
            .as_str()
            .ok_or_else(|| anyhow!("no credential in the enrollment answer"))?;
        let overlay = v["overlay_ip"]
            .as_str()
            .ok_or_else(|| anyhow!("no overlay address in the enrollment answer"))?;
        let site_id = v["site_id"].as_str().unwrap_or("");
        edge::state_set(store, edge::KEY_CREDENTIAL, cred).await?;
        edge::state_set(store, edge::KEY_SITE_ID, site_id).await?;
        edge::state_set(store, edge::KEY_OVERLAY_IP, overlay).await?;
        edge::state_set(store, edge::KEY_DASHBOARD, &e.dashboard_url).await?;
        // the one-time token is used up: erase it
        patronus_network::lan::set_setting(store, "edge.enrollment_token", "").await?;
        tracing::info!(site = site_id, overlay, "enrolled with the dashboard");
        Ok(())
    }

    fn norm_ips(s: &str) -> BTreeSet<String> {
        s.split([',', ' '])
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect()
    }

    fn peer_name(name: &str) -> String {
        let clean: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!("{PEER_PREFIX}{clean}").chars().take(40).collect()
    }

    /// Bring the store's `sdwan0` and its peers in line with the dashboard's
    /// config. Returns true when something changed (WireGuard must be applied).
    async fn reconcile(
        store: &ConfigStore,
        e: &EdgeSettings,
        cfg: &Value,
        steer_state: &mut BTreeMap<String, PeerSteer>,
    ) -> Result<bool> {
        let overlay = cfg["site"]["overlay_ip"]
            .as_str()
            .ok_or_else(|| anyhow!("config without an overlay address"))?;
        let want_addr = format!(
            "{overlay}/{}",
            overlay_prefix(cfg["overlay_cidr"].as_str().unwrap_or("10.99.0.0/16"))
        );
        let mut changed = false;
        ensure_interface(store, e).await?;
        let cur = wireguard::list_interfaces(store).await?;
        let cur = cur
            .iter()
            .find(|i| i.name == WG_IF)
            .cloned()
            .ok_or_else(|| anyhow!("no {WG_IF}"))?;
        if !cur.enabled || cur.addresses != want_addr || cur.listen_port != e.listen_port {
            wireguard::save_interface(
                store,
                Some(WG_IF),
                &InterfaceInput {
                    enabled: Some(true),
                    addresses: Some(want_addr),
                    listen_port: Some(e.listen_port),
                    mtu: Some(1420),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| anyhow!("{e}"))?;
            changed = true;
        }
        let existing: Vec<_> = wireguard::list_peers(store)
            .await?
            .into_iter()
            .filter(|p| p.interface == WG_IF)
            .collect();
        let peers = cfg["peers"].as_array().cloned().unwrap_or_default();
        let mut keep = BTreeSet::new();
        for p in &peers {
            let site_id = p["site_id"].as_str().unwrap_or("").to_string();
            let name = peer_name(p["name"].as_str().unwrap_or(&site_id));
            let eps: Vec<String> = p["endpoints"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x["address"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let st = steer_state
                .entry(site_id.clone())
                .or_insert_with(|| PeerSteer {
                    since: now(),
                    ..Default::default()
                });
            if !eps.is_empty() {
                st.idx %= eps.len();
            }
            let endpoint = eps.get(st.idx).cloned();
            let mut ips = vec![format!("{}/32", p["overlay_ip"].as_str().unwrap_or(""))];
            ips.extend(
                p["subnets"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            );
            let input = PeerInput {
                interface: Some(WG_IF.into()),
                name: Some(name.clone()),
                enabled: Some(true),
                public_key: p["public_key"].as_str().map(String::from),
                allowed_ips: Some(ips.join(",")),
                endpoint: endpoint.clone(),
                persistent_keepalive: Some(25),
                description: Some(format!("SD-WAN site {site_id}")),
                ..Default::default()
            };
            keep.insert(name.clone());
            match existing.iter().find(|x| x.name == name) {
                Some(x) => {
                    let same = x.public_key == input.public_key.clone().unwrap_or_default()
                        && norm_ips(&x.allowed_ips) == norm_ips(&ips.join(","))
                        && x.endpoint == endpoint
                        && x.enabled;
                    if !same {
                        wireguard::save_peer(store, Some(x.id), &input)
                            .await
                            .map_err(|e| anyhow!("peer {name}: {e}"))?;
                        changed = true;
                    }
                }
                None => {
                    wireguard::save_peer(store, None, &input)
                        .await
                        .map_err(|e| anyhow!("peer {name}: {e}"))?;
                    changed = true;
                }
            }
        }
        for x in existing
            .iter()
            .filter(|x| x.name.starts_with(PEER_PREFIX) && !keep.contains(&x.name))
        {
            wireguard::delete_peer(store, x.id).await?;
            changed = true;
        }
        let live: BTreeSet<String> = peers
            .iter()
            .filter_map(|p| p["site_id"].as_str().map(String::from))
            .collect();
        steer_state.retain(|k, _| live.contains(k));
        Ok(changed)
    }

    fn overlay_prefix(c: &str) -> u8 {
        c.rsplit_once('/')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(16)
    }

    async fn apply_all(store: &ConfigStore) -> Result<()> {
        wireguard::WireGuardApplier::default()
            .apply(store)
            .await
            .map_err(|e| anyhow!("WireGuard: {e}"))?;
        patronus_firewall::FirewallApplier
            .apply(store)
            .await
            .map_err(|e| anyhow!("firewall: {e}"))?;
        Ok(())
    }

    /// One round. Returns the number of seconds to wait for the next.
    pub async fn sync_once(store: &ConfigStore, st: &mut AgentState) -> Result<u64> {
        let mut e = edge::load(store).await?;
        if !e.enabled {
            return Ok(15);
        }
        if e.dashboard_url.is_empty() || e.name.is_empty() {
            bail!("set the dashboard URL and site name on the SD-WAN edge page");
        }
        let enrolled_with = edge::state_get(store, edge::KEY_DASHBOARD).await?;
        if e.credential.is_some() && enrolled_with.as_deref() != Some(e.dashboard_url.as_str()) {
            if e.token.is_empty() {
                bail!("the dashboard URL changed since enrollment: paste a new enrollment token to enroll with the new dashboard");
            }
            for k in [
                edge::KEY_CREDENTIAL,
                edge::KEY_SITE_ID,
                edge::KEY_OVERLAY_IP,
                edge::KEY_DASHBOARD,
            ] {
                edge::state_set(store, k, "").await?;
            }
            e = edge::load(store).await?;
        }
        if e.credential.is_none() {
            enroll(store, &e).await?;
            e = edge::load(store).await?;
        }
        let cred = e
            .credential
            .clone()
            .ok_or_else(|| anyhow!("no credential after enrollment"))?;
        let client = http()?;
        let r = client
            .get(format!("{}{CONFIG_PATH}", e.dashboard_url))
            .bearer_auth(&cred)
            .send()
            .await
            .with_context(|| format!("reach the dashboard at {}", e.dashboard_url))?;
        if r.status() == reqwest::StatusCode::UNAUTHORIZED {
            // revoked: forget the credential so a new token can enroll again
            edge::state_set(store, edge::KEY_CREDENTIAL, "").await?;
            bail!("the dashboard no longer accepts this edge's credential (revoked?): enter a new enrollment token");
        }
        if !r.status().is_success() {
            return Err(api_error(r).await);
        }
        let cfg: Value = r.json().await?;
        let interval = cfg["interval_secs"].as_u64().unwrap_or(15).clamp(5, 300);
        let changed = reconcile(store, &e, &cfg, &mut st.steer).await?;
        if changed {
            apply_all(store).await?;
        }

        // measure + steer
        let peers = cfg["peers"].as_array().cloned().unwrap_or_default();
        let mut reports = Vec::new();
        let mut view = Vec::new();
        let mut steered = false;
        // ping first: it also triggers the handshake of a fresh peer
        let mut pings: BTreeMap<String, (f64, Option<f64>)> = BTreeMap::new();
        for p in &peers {
            if let (Some(site), Some(ip)) = (p["site_id"].as_str(), p["overlay_ip"].as_str()) {
                let out = run_cmd(
                    "ping",
                    &["-n", "-c", "3", "-W", "1", "-i", "0.2", "-I", WG_IF, ip],
                )
                .unwrap_or_default();
                pings.insert(site.to_string(), parse_ping(&out));
            }
        }
        let hs = parse_handshakes(
            &run_cmd("wg", &["show", WG_IF, "latest-handshakes"]).unwrap_or_default(),
        );
        let t = now();
        for p in &peers {
            let site = p["site_id"].as_str().unwrap_or("").to_string();
            let key = p["public_key"].as_str().unwrap_or("");
            let eps: Vec<String> = p["endpoints"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x["address"].as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let hts = hs.get(key).copied().unwrap_or(0);
            let (loss, rtt) = pings.get(&site).copied().unwrap_or((100.0, None));
            if let Some(s) = st.steer.get_mut(&site) {
                if steer(s, eps.len(), hts, t, loss < 100.0) {
                    steered = true;
                    tracing::warn!(site = %site, endpoint = ?eps.get(s.idx), "switching endpoint");
                }
            }
            let idx = st.steer.get(&site).map(|s| s.idx).unwrap_or(0);
            let age = (hts > 0).then(|| t.saturating_sub(hts));
            let endpoint = eps.get(idx).cloned();
            reports.push(json!({"site_id": site, "endpoint": endpoint, "latency_ms": rtt, "loss_pct": loss, "handshake_age_secs": age}));
            view.push(json!({
                "name": p["name"], "site_id": site, "overlay_ip": p["overlay_ip"], "endpoint": endpoint,
                "endpoint_index": idx, "endpoints": eps.len(), "handshake_age_secs": age,
                "latency_ms": rtt, "loss_pct": loss,
                "state": if loss < 100.0 && age.is_some() { "up" } else { "down" },
            }));
        }
        if steered {
            reconcile(store, &e, &cfg, &mut st.steer).await?;
            apply_all(store).await?;
        }
        let r = client
            .post(format!("{}{HEARTBEAT_PATH}", e.dashboard_url))
            .bearer_auth(&cred)
            .json(&json!({"peers": reports}))
            .send()
            .await
            .context("send heartbeat")?;
        if !r.status().is_success() {
            return Err(api_error(r).await);
        }
        st.generation = cfg["generation"].as_str().unwrap_or("").to_string();
        st.peers = view;
        st.last_sync = t;
        Ok(interval)
    }

    pub async fn run(db: Option<PathBuf>, once: bool) -> Result<()> {
        let store = crate::commands::apply::open_store(db.as_deref()).await?;
        let sup = Supervisor::detect();
        let mut st = AgentState::load(&sup);
        loop {
            let res = sync_once(&store, &mut st).await;
            let wait = match &res {
                Ok(i) => {
                    st.last_error = None;
                    *i
                }
                Err(e) => {
                    tracing::warn!("edge sync failed: {e:#}");
                    st.last_error = Some(format!("{e:#}"));
                    15
                }
            };
            st.save(&sup);
            if once {
                return res.map(|_| ());
            }
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
    }

    pub async fn status(db: Option<PathBuf>) -> Result<()> {
        let store = crate::commands::apply::open_store(db.as_deref()).await?;
        let sup = Supervisor::detect();
        let e = edge::load(&store).await?;
        let st = AgentState::load(&sup);
        println!(
            "enabled: {}  enrolled: {}  site: {}  overlay: {}",
            e.enabled,
            e.credential.is_some(),
            e.site_id.unwrap_or_default(),
            e.overlay_ip.unwrap_or_default()
        );
        if let Some(err) = &st.last_error {
            println!("last error: {err}");
        }
        for p in &st.peers {
            println!(
                "  {:<20} {:<12} via {:<22} handshake {:>5}s ago  rtt {:>7}  loss {}%",
                p["name"].as_str().unwrap_or("?"),
                p["state"].as_str().unwrap_or("?"),
                p["endpoint"].as_str().unwrap_or("-"),
                p["handshake_age_secs"]
                    .as_u64()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into()),
                p["latency_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.1}ms"))
                    .unwrap_or_else(|| "-".into()),
                p["loss_pct"]
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_dead_endpoint_is_replaced_after_the_patience_and_the_working_one_kept() {
            let mut s = PeerSteer {
                since: 1000,
                ..Default::default()
            };
            // no handshake yet, still patient
            assert!(!steer(&mut s, 2, 0, 1010, true));
            assert_eq!(s.idx, 0);
            // patience over: next endpoint
            assert!(steer(&mut s, 2, 0, 1021, true));
            assert_eq!((s.idx, s.since), (1, 1021));
            // a handshake after the switch confirms it
            assert!(!steer(&mut s, 2, 1030, 1035, true));
            assert!(s.confirmed);
            // a single endpoint never rotates
            let mut one = PeerSteer {
                since: 1,
                ..Default::default()
            };
            assert!(!steer(&mut one, 1, 0, 9999, false));
        }

        #[test]
        fn the_preferred_endpoint_is_retried_and_dropped_again_if_it_stays_dead() {
            let mut s = PeerSteer {
                idx: 1,
                since: 1000,
                confirmed: true,
                ..Default::default()
            };
            assert!(!steer(&mut s, 2, 1500, 1060, true), "not yet");
            // time to try the preferred endpoint again
            assert!(steer(&mut s, 2, 1500, 1100, true));
            assert_eq!((s.idx, s.prev_idx, s.confirmed), (0, Some(1), false));
            // no handshake on it within the patience: back to the one that worked
            assert!(steer(&mut s, 2, 1090, 1125, true));
            assert_eq!((s.idx, s.confirmed), (1, true));
            // a successful trial sticks
            let mut t = PeerSteer {
                idx: 1,
                since: 1000,
                confirmed: true,
                ..Default::default()
            };
            assert!(steer(&mut t, 2, 1090, 1100, true));
            assert!(!steer(&mut t, 2, 1105, 1110, true));
            assert_eq!((t.idx, t.confirmed, t.prev_idx), (0, true, None));
        }

        #[test]
        fn a_link_that_goes_quiet_for_good_is_rotated() {
            let mut s = PeerSteer {
                idx: 0,
                since: 100,
                confirmed: true,
                ..Default::default()
            };
            assert!(!steer(&mut s, 2, 150, 200, true), "recent enough");
            assert!(steer(&mut s, 2, 150, 400, true), "quiet for 250 s");
            assert_eq!(s.idx, 1);
            // or: the handshake looks fresh but nothing answers pings for three rounds
            let mut p = PeerSteer {
                idx: 0,
                since: 100,
                confirmed: true,
                ..Default::default()
            };
            assert!(!steer(&mut p, 2, 150, 160, false));
            assert!(!steer(&mut p, 2, 150, 175, false));
            assert!(
                steer(&mut p, 2, 150, 190, false),
                "third silent round moves to the next endpoint"
            );
            assert_eq!(p.idx, 1);
            // a single answer resets the count
            let mut q = PeerSteer {
                idx: 0,
                since: 100,
                confirmed: true,
                ..Default::default()
            };
            assert!(!steer(&mut q, 2, 150, 160, false));
            assert!(!steer(&mut q, 2, 150, 175, true));
            assert!(!steer(&mut q, 2, 150, 190, false));
        }

        #[test]
        fn wg_and_ping_output_are_parsed() {
            let h = parse_handshakes("AAAA=\t1700000000\nBBBB=\t0\n");
            assert_eq!(h["AAAA="], 1_700_000_000);
            assert_eq!(h["BBBB="], 0);
            let (loss, rtt) = parse_ping("3 packets transmitted, 3 received, 0% packet loss, time 400ms\nrtt min/avg/max/mdev = 0.3/0.5/0.9/0.2 ms\n");
            assert_eq!(loss, 0.0);
            assert_eq!(rtt, Some(0.5));
            let (loss, rtt) =
                parse_ping("3 packets transmitted, 0 received, 100% packet loss, time 2000ms\n");
            assert_eq!((loss, rtt), (100.0, None));
            assert_eq!(parse_ping("").0, 100.0);
        }

        #[test]
        fn peer_names_are_safe_interface_peer_names() {
            assert_eq!(peer_name("site-b.hq"), "sdwan-site-b-hq");
            assert!(peer_name(&"x".repeat(100)).len() <= 40);
            assert_eq!(overlay_prefix("10.99.0.0/16"), 16);
        }
    }
}
