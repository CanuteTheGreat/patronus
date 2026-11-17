//! mDNS repeater (USE=mdns): make Bonjour/AirPlay/Chromecast/printer
//! discovery work across LAN segments (VLANs, OPT interfaces, a guest or IoT
//! network), like the pfSense/OPNsense "mDNS repeater" / Avahi reflector and
//! UniFi's "Multicast DNS" toggle.
//!
//! mDNS (224.0.0.251 / ff02::fb, UDP 5353) is link-local: a phone on one
//! segment never sees a printer's announcements on another. avahi-daemon in
//! reflector mode repeats queries and answers between the chosen interfaces.
//! Patronus runs its own avahi-daemon through the supervisor
//! (`patronus-daemon@avahi`, OpenRC and systemd) with a generated config:
//! reflector on, D-Bus off, nothing published about the router itself. The
//! firewall accepts UDP 5353 from the reflected interfaces
//! (`patronus_firewall::svc_rules`); the service traffic itself (the printer's
//! IPP port, AirPlay) still needs a firewall rule between the segments, which
//! is deliberate: discovery is not access.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "avahi";

static FIELDS: [Field; 3] = [
    Field::new("enabled", "mDNS repeater", Kind::Bool).def("0"),
    Field::new("ipv6", "Repeat over IPv6 too", Kind::Bool)
        .def("1")
        .help("also reflect ff02::fb (most devices announce on both)"),
    Field::new("reflect_ipv", "Cross IP versions", Kind::Bool)
        .def("0")
        .help("answer IPv6 queries with IPv4 records and the other way round"),
];

static IFACE_FIELDS: [Field; 3] = [
    Field::new("iface", "Interface", Kind::Iface)
        .req()
        .help("device or @lan / @optN: a segment whose devices should see each other's services"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "mdns",
    title: "mDNS repeater",
    blurb: "Let devices discover printers, AirPlay/Chromecast receivers and other Bonjour \
            services on another LAN segment (VLAN, guest or IoT network). Queries and answers \
            for 224.0.0.251 / ff02::fb are repeated between the interfaces listed here (at \
            least two). Discovery only: reaching the service still needs a firewall rule \
            between the segments. Runs avahi-daemon as a reflector.",
    applier: "mdns",
    fields: &FIELDS,
    colls: &[Coll {
        key: "interfaces",
        title: "Interfaces",
        table: "mdns_interfaces",
        fields: &IFACE_FIELDS,
        unique: Some("iface"),
    }],
    actions: &[],
};

pub struct MdnsSvc;

#[async_trait]
impl Svc for MdnsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// avahi-daemon.conf for a reflector on `ifaces`.
pub fn render(ifaces: &[String], ipv6: bool, reflect_ipv: bool) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    let mut c = lan::header("#", "avahi-daemon (mDNS repeater)");
    c.push_str(&format!(
        "[server]\nuse-ipv4=yes\nuse-ipv6={}\nallow-interfaces={}\nenable-dbus=no\n\
         ratelimit-interval-usec=1000000\nratelimit-burst=1000\n\n\
         [wide-area]\nenable-wide-area=no\n\n\
         [publish]\ndisable-publishing=yes\ndisable-user-service-publishing=yes\n\
         publish-hinfo=no\npublish-workstation=no\n\n\
         [reflector]\nenable-reflector=yes\nreflect-ipv={}\n\n\
         [rlimits]\nrlimit-core=0\nrlimit-nofile=768\n",
        yn(ipv6),
        ifaces.join(","),
        yn(reflect_ipv),
    ));
    c
}

/// The enabled interfaces, resolved to devices (deduplicated, in order).
pub async fn devices(store: &ConfigStore) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        for d in lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await? {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    Ok(out)
}

#[derive(Clone)]
pub struct MdnsApplier {
    sup: Supervisor,
}

impl Default for MdnsApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl MdnsApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }

    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("avahi-daemon.conf")
    }
}

#[async_trait]
impl Applier for MdnsApplier {
    fn name(&self) -> &'static str {
        "mdns"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("mDNS repeater stopped");
            } else {
                rep.applied("mDNS repeater is off");
            }
            return Ok(rep);
        }
        let devs = devices(store).await?;
        if devs.len() < 2 {
            return Err(invalid(
                "mDNS repeater: list at least two interfaces (assigned to devices) to repeat between",
            ));
        }
        let bin = which("avahi-daemon").ok_or_else(|| {
            Error::Service(
                "the mDNS repeater needs avahi-daemon, which is not installed (emerge \
                 net-dns/avahi, USE=mdns)"
                    .into(),
            )
        })?;
        // avahi-daemon keeps its pid file there and refuses to start without it
        let _ = std::fs::create_dir_all("/run/avahi-daemon");
        let conf = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "--no-drop-root".into(),
                "--no-chroot".into(),
                "--no-proc-title".into(),
                "-f".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, render(&devs, s.b("ipv6"), s.b("reflect_ipv")), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "mDNS repeater {} between {}",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            devs.join(", ")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# mDNS repeater off\n".into());
        }
        let devs = devices(store).await?;
        Ok(format!(
            "## avahi-daemon.conf\n{}",
            render(&devs, s.b("ipv6"), s.b("reflect_ipv"))
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("avahi-daemon").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "interfaces": devices(store).await.unwrap_or_default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn reflector_config() {
        let c = render(&["rtr-lan".into(), "rtr-opt1".into()], true, false);
        assert!(c.contains("allow-interfaces=rtr-lan,rtr-opt1\n"));
        assert!(c.contains("enable-reflector=yes\nreflect-ipv=no\n"));
        assert!(c.contains("enable-dbus=no\n"));
        assert!(c.contains("use-ipv6=yes\n"));
        assert!(c.contains("disable-publishing=yes\n"));
        assert!(c.lines().take(3).any(|l| l.contains(lan::MARKER)));
        let c = render(&["a".into(), "b".into()], false, true);
        assert!(c.contains("use-ipv6=no\n") && c.contains("reflect-ipv=yes\n"));
    }

    #[tokio::test]
    async fn needs_two_interfaces_and_the_daemon() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = MdnsApplier::with_supervisor(Supervisor::new(
            InitMode::Direct,
            NetPaths::under(d.path()),
        ));
        // off: nothing to do
        assert!(a.apply(&s).await.is_ok());
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least two"), "{e}");
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "lan;x"}))
                .await
                .is_err()
        );
        svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "@lan"}))
            .await
            .unwrap();
        assert!(
            svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "@lan"}))
                .await
                .is_err(),
            "the same interface twice is refused"
        );
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least two"), "{e}");
        svc::save_row(&s, &SPEC.colls[0], None, &json!({"iface": "eth9"}))
            .await
            .unwrap();
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("allow-interfaces="), "{r}");
        assert!(r.contains("eth9"), "{r}");
    }
}
