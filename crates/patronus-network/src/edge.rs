//! SD-WAN edge (USE=sdwan): this appliance joins the overlay run by a Patronus
//! SD-WAN dashboard.
//!
//! The page here holds what the edge announces (name, WireGuard port, public
//! endpoints, LAN subnets) and the one-time enrollment token. The work is done
//! by the **edge agent** (`patronus edge run`, supervised as
//! `patronus-daemon@edge-agent` by [`EdgeApplier`]): it enrolls with the
//! dashboard, creates the WireGuard tunnel `sdwan0` (overlay address, a peer per
//! remote site with its subnets routed through it), keeps the peer list in step
//! with the dashboard, switches a peer to its next endpoint when the handshake
//! fails, and reports measured latency/loss/handshake age so the dashboard
//! shows real paths. The agent's progress is read back from its state file for
//! the status card. See `crates/patronus-cli/src/commands/edge.rs`.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use crate::wireguard;
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "edge-agent";
pub const WG_IF: &str = "sdwan0";
pub const PEER_PREFIX: &str = "sdwan-";
/// Keys the agent keeps in the `edge_state` table (not part of the page's
/// fields, and outside the web UI's undo snapshot so a refused page edit can
/// never rewind a credential the agent just received).
pub const KEY_SITE_ID: &str = "site_id";
pub const KEY_CREDENTIAL: &str = "credential";
pub const KEY_OVERLAY_IP: &str = "overlay_ip";
pub const KEY_DASHBOARD: &str = "enrolled_with";

static FIELDS: [Field; 5] = [
    Field::new("enabled", "Join the SD-WAN overlay", Kind::Bool).def("0"),
    Field::new("dashboard_url", "Dashboard URL", Kind::Text)
        .help("for example https://sdwan.example.com:8443 (the dashboard's address, no path)"),
    Field::new("name", "Site name", Kind::Token)
        .help("how this site appears in the dashboard (letters, digits, . _ -)"),
    Field::new("listen_port", "WireGuard port", Kind::Int(1, 65535)).def("51820"),
    Field::new("enrollment_token", "Enrollment token", Kind::Secret).help(
        "a one-time token from the dashboard (POST /api/v1/edge/tokens); used on first start",
    ),
];

static ENDPOINT_FIELDS: [Field; 3] = [
    Field::new("address", "Public address:port", Kind::Token)
        .req()
        .help("how other sites reach this one over this uplink, e.g. 203.0.113.2:51820. A second uplink needs source-based routing so it answers from its own address"),
    Field::new("interface_type", "Uplink type", Kind::Token)
        .def("wan")
        .help("fiber, lte, starlink, ..."),
    Field::new("cost_per_gb", "Cost per GB", Kind::Int(0, 1000))
        .def("0")
        .help("cheaper endpoints are tried first"),
];

static SUBNET_FIELDS: [Field; 1] = [Field::new("prefix", "LAN subnet", Kind::Cidr4)
    .req()
    .help("a network behind this site that the other sites should reach")];

static SPEC: Spec = Spec {
    slug: "edge",
    title: "SD-WAN edge",
    blurb: "Join a Patronus SD-WAN overlay. The edge agent enrolls with the dashboard, builds an \
            encrypted WireGuard mesh to the other sites, routes their subnets through it, fails \
            over between a site's endpoints and reports path quality back to the dashboard.",
    applier: "edge",
    fields: &FIELDS,
    colls: &[
        Coll {
            key: "endpoints",
            title: "This site's public endpoints",
            table: "edge_endpoints",
            fields: &ENDPOINT_FIELDS,
            unique: Some("address"),
        },
        Coll {
            key: "subnets",
            title: "Subnets behind this site",
            table: "edge_subnets",
            fields: &SUBNET_FIELDS,
            unique: Some("prefix"),
        },
    ],
    actions: &[],
};

pub struct EdgeSvc;

/// Dashboard URL: http(s)://host[:port], no path/query/credentials.
pub fn check_url(u: &str) -> Result<String> {
    let u = u.trim().trim_end_matches('/');
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .ok_or_else(|| invalid(format!("dashboard URL {u:?} (http:// or https://)")))?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !rest.ends_with(']') && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, Some(p))
        }
        _ => (rest, None),
    };
    let host_ok = host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
        .is_ok()
        || lan::valid_dns_name(host, false);
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|n| n > 0));
    if u.len() <= 200 && host_ok && port_ok {
        Ok(u.to_string())
    } else {
        Err(invalid(format!(
            "dashboard URL {u:?} (http(s)://host[:port])"
        )))
    }
}

pub fn check_endpoint_addr(a: &str) -> Result<String> {
    a.trim()
        .parse::<std::net::SocketAddr>()
        .map(|s| s.to_string())
        .map_err(|_| {
            invalid(format!(
                "endpoint {a:?} (ip:port, for example 203.0.113.2:51820)"
            ))
        })
}

#[async_trait]
impl Svc for EdgeSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        if let Some(u) = body.get("dashboard_url").and_then(Value::as_str) {
            if !u.trim().is_empty() {
                let u = check_url(u)?;
                let mut b = body.clone();
                b["dashboard_url"] = json!(u);
                return svc::put_settings(store, &SPEC, &b).await;
            }
        }
        svc::put_settings(store, &SPEC, body).await
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let mut b = body.clone();
        if coll == "endpoints" {
            if let Some(a) = body.get("address").and_then(Value::as_str) {
                b["address"] = json!(check_endpoint_addr(a)?);
            }
        }
        let c = svc::find_coll(&SPEC, coll)?;
        svc::save_row(store, c, id, &b).await
    }
}

pub async fn state_get(store: &ConfigStore, key: &str) -> Result<Option<String>> {
    use sqlx::Row;
    let r = sqlx::query("SELECT value FROM edge_state WHERE key = ?")
        .bind(key)
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read edge state: {e}")))?;
    Ok(r.map(|r| r.get::<String, _>(0)).filter(|v| !v.is_empty()))
}

pub async fn state_set(store: &ConfigStore, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT INTO edge_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("write edge state: {e}")))?;
    Ok(())
}

/// What the agent needs from the page.
#[derive(Debug, Clone)]
pub struct EdgeSettings {
    pub enabled: bool,
    pub dashboard_url: String,
    pub name: String,
    pub listen_port: u16,
    pub token: String,
    /// (address, interface_type, cost_per_gb)
    pub endpoints: Vec<(String, String, i64)>,
    pub subnets: Vec<String>,
    pub site_id: Option<String>,
    pub credential: Option<String>,
    pub overlay_ip: Option<String>,
}

pub async fn load(store: &ConfigStore) -> Result<EdgeSettings> {
    let s = Settings::load(store, &SPEC).await?;
    let internal = |k: &'static str| async move { state_get(store, k).await };
    let mut endpoints = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        endpoints.push((
            r["address"].as_str().unwrap_or("").to_string(),
            r["interface_type"]
                .as_str()
                .filter(|x| !x.is_empty())
                .unwrap_or("wan")
                .to_string(),
            r["cost_per_gb"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        ));
    }
    let subnets = svc::raw_rows(store, &SPEC.colls[1])
        .await?
        .iter()
        .map(|r| r["prefix"].as_str().unwrap_or("").to_string())
        .collect();
    Ok(EdgeSettings {
        enabled: s.b("enabled"),
        dashboard_url: s.s("dashboard_url"),
        name: s.s("name"),
        listen_port: s.n("listen_port") as u16,
        token: s.s("enrollment_token"),
        endpoints,
        subnets,
        site_id: internal(KEY_SITE_ID).await?,
        credential: internal(KEY_CREDENTIAL).await?,
        overlay_ip: internal(KEY_OVERLAY_IP).await?,
    })
}

/// The agent's progress file.
pub fn state_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.state_dir.join("edge-state.json")
}

#[derive(Clone)]
pub struct EdgeApplier {
    sup: Supervisor,
    /// Path of the `patronus` binary the agent is started from.
    bin: Option<std::path::PathBuf>,
}

impl Default for EdgeApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            bin: None,
        }
    }
}

impl EdgeApplier {
    pub fn with(sup: Supervisor, bin: Option<std::path::PathBuf>) -> Self {
        Self { sup, bin }
    }

    fn patronus(&self) -> Option<std::path::PathBuf> {
        self.bin.clone().or_else(|| which("patronus"))
    }
}

#[async_trait]
impl Applier for EdgeApplier {
    fn name(&self) -> &'static str {
        "edge"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let e = load(store).await?;
        if !e.enabled {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            // leaving the overlay: the tunnel and its peers go
            if wireguard::list_interfaces(store)
                .await?
                .iter()
                .any(|i| i.name == WG_IF)
            {
                wireguard::delete_interface(store, WG_IF).await?;
                wireguard::WireGuardApplier::default().apply(store).await?;
                rep.applied(format!("left the overlay: tunnel {WG_IF} removed"));
            } else if was {
                rep.applied("edge agent stopped");
            } else {
                rep.applied("SD-WAN edge is off");
            }
            return Ok(rep);
        }
        if e.dashboard_url.is_empty() {
            return Err(invalid("SD-WAN edge: set the dashboard URL"));
        }
        if e.name.is_empty() {
            return Err(invalid("SD-WAN edge: set a site name"));
        }
        if e.credential.is_none() && e.token.is_empty() {
            return Err(invalid(
                "SD-WAN edge: paste an enrollment token from the dashboard (not enrolled yet)",
            ));
        }
        if e.endpoints.is_empty() {
            return Err(invalid("SD-WAN edge: add at least one public endpoint"));
        }
        let bin = self.patronus().ok_or_else(|| {
            Error::Service("the edge agent needs the `patronus` binary on the PATH".into())
        })?;
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        // a fingerprint file so changed settings restart the agent (it re-reads the store anyway)
        let fp = format!(
            "{}|{}|{}|{:?}|{:?}\n",
            e.dashboard_url, e.name, e.listen_port, e.endpoints, e.subnets
        );
        let fp_path = self.sup.paths.state_dir.join("edge-settings.fp");
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "--db".into(),
                store.path().to_string_lossy().into(),
                "edge".into(),
                "run".into(),
            ],
            vec![(fp_path, fp, 0o600)],
        )
        .await?;
        rep.applied(format!(
            "edge agent {} ({} endpoint(s), {} subnet(s), dashboard {})",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            e.endpoints.len(),
            e.subnets.len(),
            e.dashboard_url
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let e = load(store).await?;
        if !e.enabled {
            return Ok("# SD-WAN edge off\n".into());
        }
        Ok(format!(
            "patronus edge run   # enrolls with {} as {:?}, tunnel {WG_IF}, endpoints {:?}, subnets {:?}\n",
            e.dashboard_url, e.name, e.endpoints, e.subnets
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let e = load(store).await?;
        let state: Value = std::fs::read_to_string(state_path(&self.sup))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null);
        Ok(json!({
            "enabled": e.enabled,
            "enrolled": e.credential.is_some(),
            "site_id": e.site_id,
            "overlay_ip": e.overlay_ip,
            "agent_running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "agent": state,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn dashboard_urls_and_endpoints_are_validated() {
        assert_eq!(
            check_url("https://sdwan.example.com:8443/").unwrap(),
            "https://sdwan.example.com:8443"
        );
        assert_eq!(
            check_url("http://10.0.0.5:8443").unwrap(),
            "http://10.0.0.5:8443"
        );
        assert!(check_url("ftp://x").is_err());
        assert!(check_url("https://a b").is_err());
        assert!(check_url("https://x:99999").is_err());
        assert!(check_url("https://x\nHost: y").is_err());
        assert_eq!(
            check_endpoint_addr("203.0.113.2:51820").unwrap(),
            "203.0.113.2:51820"
        );
        assert!(check_endpoint_addr("example.com:51820").is_err());
        assert!(check_endpoint_addr("203.0.113.2").is_err());
    }

    #[tokio::test]
    async fn settings_rows_and_apply_preconditions() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = EdgeApplier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            Some("/bin/true".into()),
        );
        a.apply(&s).await.unwrap();
        assert!(EdgeSvc
            .put(&s, &json!({"dashboard_url": "nope"}))
            .await
            .is_err());
        EdgeSvc
            .put(&s, &json!({"enabled": true, "dashboard_url": "https://sdwan.example.com:8443/", "name": "site-a"}))
            .await
            .unwrap();
        assert!(a.apply(&s).await.unwrap_err().to_string().contains("token"));
        EdgeSvc
            .put(&s, &json!({"enrollment_token": "pedge_enroll_abc123"}))
            .await
            .unwrap();
        assert!(a
            .apply(&s)
            .await
            .unwrap_err()
            .to_string()
            .contains("endpoint"));
        assert!(EdgeSvc
            .save_row(&s, "endpoints", None, &json!({"address": "example.com:1"}))
            .await
            .is_err());
        EdgeSvc
            .save_row(
                &s,
                "endpoints",
                None,
                &json!({"address": "203.0.113.2:51820", "interface_type": "fiber"}),
            )
            .await
            .unwrap();
        assert!(EdgeSvc
            .save_row(&s, "subnets", None, &json!({"prefix": "fd00::/64"}))
            .await
            .is_err());
        EdgeSvc
            .save_row(&s, "subnets", None, &json!({"prefix": "192.168.50.0/24"}))
            .await
            .unwrap();
        let e = load(&s).await.unwrap();
        assert_eq!(e.dashboard_url, "https://sdwan.example.com:8443");
        assert_eq!(
            e.endpoints,
            vec![("203.0.113.2:51820".into(), "fiber".into(), 0)]
        );
        assert_eq!(e.subnets, vec!["192.168.50.0/24".to_string()]);
        assert_eq!(e.token, "pedge_enroll_abc123");
        assert!(a.render(&s).await.unwrap().contains("patronus edge run"));
        // the token is never returned by the page
        let v = EdgeSvc.get(&s).await.unwrap();
        assert_eq!(v["settings"]["enrollment_token"], json!(svc::SECRET_MASK));
    }
}
