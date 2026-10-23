//! IGMP proxy (USE=igmp): forward multicast (IPTV, mDNS-free multicast
//! streams) from an upstream interface to downstream LAN interfaces with
//! `igmpproxy`, which answers IGMP membership queries on the LAN side and
//! joins the groups upstream on behalf of the clients.
//!
//! The daemon runs through the supervisor (`patronus-daemon@igmpproxy`) with
//! a generated config under the net state dir. The firewall allows IGMP on the
//! proxied interfaces and forwards multicast (224.0.0.0/4) upstream ->
//! downstream (`patronus_firewall::igmp_rules`), because the default ruleset
//! drops forwarded traffic.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "igmpproxy";

static FIELDS: [Field; 2] = [
    Field::new("enabled", "IGMP proxy", Kind::Bool).def("0"),
    Field::new("upstream", "Upstream interface", Kind::Iface)
        .def("@wan")
        .help("where the multicast streams come from (one interface)"),
];

static DOWN_FIELDS: [Field; 2] = [
    Field::new("iface", "Downstream interface", Kind::Iface)
        .req()
        .help("device or @lan / @optN: the clients that join groups"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: "igmp",
    title: "IGMP proxy",
    blurb: "Forward multicast streams (for example IPTV) from the upstream interface to LAN \
            interfaces. Clients join groups with IGMP on the LAN; the proxy joins them upstream \
            and the firewall forwards the multicast traffic. Runs igmpproxy.",
    applier: "igmp",
    fields: &FIELDS,
    colls: &[Coll {
        key: "downstream",
        title: "Downstream interfaces",
        table: "igmp_interfaces",
        fields: &DOWN_FIELDS,
        unique: Some("iface"),
    }],
    actions: &[],
};

pub struct IgmpSvc;

#[async_trait]
impl Svc for IgmpSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// igmpproxy.conf for one upstream and the downstream devices.
pub fn render(upstream: &str, downstream: &[String]) -> String {
    let mut c = lan::header("#", "igmpproxy");
    c.push_str("quickleave\n\n");
    c.push_str(&format!(
        "phyint {upstream} upstream ratelimit 0 threshold 1\n\taltnet 0.0.0.0/0\n\n"
    ));
    for d in downstream {
        c.push_str(&format!(
            "phyint {d} downstream ratelimit 0 threshold 1\n\n"
        ));
    }
    c
}

/// (upstream device, downstream devices) from the store.
pub async fn devices(store: &ConfigStore) -> Result<(Option<String>, Vec<String>)> {
    let s = Settings::load(store, &SPEC).await?;
    let up = lan::resolve_iface(store, &s.s("upstream"))
        .await?
        .into_iter()
        .next();
    let mut down = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        for d in lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await? {
            if Some(&d) != up.as_ref() && !down.contains(&d) {
                down.push(d);
            }
        }
    }
    Ok((up, down))
}

#[derive(Clone)]
pub struct IgmpApplier {
    sup: Supervisor,
}

impl Default for IgmpApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl IgmpApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }

    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("igmpproxy.conf")
    }
}

#[async_trait]
impl Applier for IgmpApplier {
    fn name(&self) -> &'static str {
        "igmp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("IGMP proxy stopped");
            } else {
                rep.applied("IGMP proxy is off");
            }
            return Ok(rep);
        }
        let (up, down) = devices(store).await?;
        let Some(up) = up else {
            return Err(invalid(format!(
                "IGMP proxy: upstream interface {} is not assigned to any device",
                s.s("upstream")
            )));
        };
        if down.is_empty() {
            return Err(invalid(
                "IGMP proxy: add at least one downstream interface (the LAN)",
            ));
        }
        let bin = which("igmpproxy").ok_or_else(|| {
            Error::Service(
                "the IGMP proxy needs igmpproxy, which is not installed (emerge \
                 net-misc/igmpproxy, USE=igmp)"
                    .into(),
            )
        })?;
        let conf = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "-n".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, render(&up, &down), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "igmpproxy {}: upstream {up}, downstream {}",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            down.join(", ")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# IGMP proxy off\n".into());
        }
        let (up, down) = devices(store).await?;
        Ok(match up {
            Some(u) => format!("## igmpproxy.conf\n{}", render(&u, &down)),
            None => "# IGMP proxy: no upstream device\n".into(),
        })
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        // /proc/net/ip_mr_vif: one line per interface the kernel's multicast router holds
        let vifs: Vec<String> = std::fs::read_to_string("/proc/net/ip_mr_vif")
            .map(|t| {
                t.lines()
                    .skip(1)
                    .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("igmpproxy").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "multicast_router_interfaces": vifs,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn config_has_one_upstream_and_the_downstream_devices() {
        let c = render("rtr-wan", &["rtr-lan".into(), "rtr-opt1".into()]);
        assert!(c.contains("phyint rtr-wan upstream ratelimit 0 threshold 1\n\taltnet 0.0.0.0/0\n"));
        assert!(c.contains("phyint rtr-lan downstream"));
        assert!(c.contains("phyint rtr-opt1 downstream"));
        assert!(c.lines().take(3).any(|l| l.contains(lan::MARKER)));
    }

    #[tokio::test]
    async fn needs_an_upstream_a_downstream_and_the_daemon() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = IgmpApplier::with_supervisor(Supervisor::new(
            InitMode::Direct,
            NetPaths::under(d.path()),
        ));
        a.apply(&s).await.unwrap();
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("downstream"), "{e}");
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "lan;x"}))
                .await
                .is_err()
        );
        svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "@lan"}))
            .await
            .unwrap();
        // the same interface twice is refused
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "@lan"}))
                .await
                .is_err()
        );
        let (up, down) = devices(&s).await.unwrap();
        assert_eq!(up.as_deref(), Some("rtr-wan"));
        assert_eq!(down, vec!["rtr-lan".to_string()]);
        if which("igmpproxy").is_none() {
            let e = a.apply(&s).await.unwrap_err();
            assert!(e.to_string().contains("igmpproxy"), "{e}");
        }
    }
}
