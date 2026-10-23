//! NetFlow / IPFIX export (USE=netflow): `softflowd` watches an interface and
//! exports flow records (NetFlow v5/v9 or IPFIX) to a collector.
//!
//! One `softflowd` instance per device of the chosen interface, run through
//! the supervisor (`patronus-daemon@softflowd-<dev>`; systemd template unit,
//! OpenRC multiplexed script or direct), restarted only when its command line
//! changes. Disabling the export stops the instances.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const PREFIX: &str = "softflowd-";

static FIELDS: [Field; 5] = [
    Field::new("enabled", "Export flows", Kind::Bool).def("0"),
    Field::new("interface", "Interface to watch", Kind::Iface)
        .def("@wan")
        .help("device or @wan / @lan: every flow crossing it is exported"),
    Field::new("collector", "Collector host", Kind::Host)
        .help("IP address or name of the NetFlow / IPFIX collector"),
    Field::new("port", "Collector port", Kind::Int(1, 65535)).def("2055"),
    Field::new("version", "Export format", Kind::Select(&["5", "9", "10"]))
        .def("9")
        .help("5 = NetFlow v5, 9 = NetFlow v9, 10 = IPFIX"),
];

static SPEC: Spec = Spec {
    slug: "netflow",
    title: "NetFlow / IPFIX export",
    blurb: "Export flow records (NetFlow v5/v9 or IPFIX) for an interface to a collector such as \
            ntopng, nfsen or ElastiFlow. Runs softflowd, one process per device.",
    applier: "netflow",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct NetflowSvc;

#[async_trait]
impl Svc for NetflowSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// `host:port` (IPv6 literals in brackets).
pub fn target(host: &str, port: i64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The softflowd command line for one device.
pub fn argv(
    bin: &str,
    dev: &str,
    collector: &str,
    port: i64,
    version: &str,
    run: &std::path::Path,
) -> Vec<String> {
    vec![
        bin.into(),
        "-d".into(),
        "-i".into(),
        dev.into(),
        "-n".into(),
        target(collector, port),
        "-v".into(),
        version.into(),
        "-p".into(),
        run.join(format!("softflowd-{dev}.pid"))
            .to_string_lossy()
            .into(),
        "-c".into(),
        run.join(format!("softflowd-{dev}.ctl"))
            .to_string_lossy()
            .into(),
    ]
}

#[derive(Clone)]
pub struct NetflowApplier {
    sup: Supervisor,
}

impl Default for NetflowApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl NetflowApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

#[async_trait]
impl Applier for NetflowApplier {
    fn name(&self) -> &'static str {
        "netflow"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            let stopped = svc::stop_daemons(&self.sup, PREFIX, &[]).await?;
            if stopped.is_empty() {
                rep.applied("NetFlow export is off");
            } else {
                rep.applied(format!("NetFlow export stopped ({})", stopped.join(", ")));
            }
            return Ok(rep);
        }
        let collector = s.s("collector");
        if collector.is_empty() {
            return Err(invalid(
                "NetFlow: set a collector host before enabling the export",
            ));
        }
        let bin = which("softflowd").ok_or_else(|| {
            Error::Service(
                "NetFlow export needs softflowd, which is not installed (emerge \
                 net-analyzer/softflowd, USE=netflow)"
                    .into(),
            )
        })?;
        let devs = lan::resolve_iface(store, &s.s("interface")).await?;
        if devs.is_empty() {
            return Err(invalid(format!(
                "NetFlow: interface {} is not assigned to any device",
                s.s("interface")
            )));
        }
        std::fs::create_dir_all(&self.sup.paths.run_dir)
            .map_err(|e| Error::Service(format!("{}: {e}", self.sup.paths.run_dir.display())))?;
        let mut keep = Vec::new();
        for d in &devs {
            let inst = format!("{PREFIX}{d}");
            let a = argv(
                &bin.to_string_lossy(),
                d,
                &collector,
                s.n("port"),
                &s.s("version"),
                &self.sup.paths.run_dir,
            );
            if svc::ensure_daemon(&self.sup, &inst, a, vec![]).await? {
                rep.applied(format!("softflowd on {d} (re)started"));
            }
            keep.push(inst);
        }
        svc::stop_daemons(&self.sup, PREFIX, &keep).await?;
        rep.applied(format!(
            "exporting flows of {} to {} (format {})",
            devs.join(", "),
            target(&collector, s.n("port")),
            s.s("version")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# NetFlow export off\n".into());
        }
        let devs = lan::resolve_iface(store, &s.s("interface")).await?;
        Ok(devs
            .iter()
            .map(|d| {
                argv(
                    "softflowd",
                    d,
                    &s.s("collector"),
                    s.n("port"),
                    &s.s("version"),
                    &self.sup.paths.run_dir,
                )
                .join(" ")
                    + "\n"
            })
            .collect())
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("softflowd").is_some(),
            "exporters": svc::daemon_states(&self.sup, PREFIX)
                .into_iter()
                .map(|(i, r)| json!({"instance": i, "running": r}))
                .collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn command_line_per_device_and_ipv6_collectors() {
        let a = argv(
            "/usr/sbin/softflowd",
            "eth1",
            "10.1.1.1",
            2055,
            "9",
            std::path::Path::new("/run/patronus"),
        );
        assert_eq!(
            a.join(" "),
            "/usr/sbin/softflowd -d -i eth1 -n 10.1.1.1:2055 -v 9 -p /run/patronus/softflowd-eth1.pid -c /run/patronus/softflowd-eth1.ctl"
        );
        assert_eq!(target("2001:db8::5", 4739), "[2001:db8::5]:4739");
    }

    #[tokio::test]
    async fn export_is_validated_and_needs_a_collector_and_the_daemon() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = NetflowApplier::with_supervisor(Supervisor::new(
            InitMode::Direct,
            NetPaths::under(d.path()),
        ));
        a.apply(&s).await.unwrap();
        for bad in [
            json!({"version": "7"}),
            json!({"port": 70000}),
            json!({"collector": "a b"}),
            json!({"interface": "eth0;x"}),
        ] {
            assert!(svc::put_settings(&s, &SPEC, &bad).await.is_err(), "{bad}");
        }
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("collector"), "{e}");
        svc::put_settings(
            &s,
            &SPEC,
            &json!({"collector": "192.0.2.50", "interface": "@wan"}),
        )
        .await
        .unwrap();
        if which("softflowd").is_none() {
            let e = a.apply(&s).await.unwrap_err();
            assert!(e.to_string().contains("softflowd"), "{e}");
        }
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("-i rtr-wan -n 192.0.2.50:2055 -v 9"), "{r}");
    }
}
