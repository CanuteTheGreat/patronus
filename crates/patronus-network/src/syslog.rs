//! Syslog (USE=syslog): forward the system log to remote collectors and
//! read the local log from the web UI.
//!
//! Patronus owns one rsyslog drop-in, `/etc/rsyslog.d/50-patronus.conf`
//! (Gentoo `app-admin/rsyslog`, Debian rsyslog), with one `omfwd` action per
//! enabled target (UDP, or TCP with a disk-assisted-free in-memory queue so a
//! collector outage does not block the logger). The candidate file is checked
//! with `rsyslogd -N1` before it replaces the live one, and rsyslog is
//! restarted only when the file changed. The main `rsyslog.conf` must include
//! `/etc/rsyslog.d`; if it does not, apply fails with that message rather
//! than pretending to forward.

use crate::lan::{self, LanEnv, ManagedFile};
use crate::svc::{self, Coll, Field, Kind, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const CONF: &str = "/etc/rsyslog.d/50-patronus.conf";
pub const BIN: &str = "/usr/sbin/rsyslogd";
pub const SERVICE: &str = "rsyslog";

const SEVERITIES: &[&str] = &[
    "debug", "info", "notice", "warning", "err", "crit", "alert", "emerg",
];

static TARGET_FIELDS: [Field; 6] = [
    Field::new("host", "Collector host", Kind::Host)
        .req()
        .help("IP address or name of the syslog server"),
    Field::new("port", "Port", Kind::Int(1, 65535)).def("514"),
    Field::new("proto", "Protocol", Kind::Select(&["udp", "tcp"])).def("udp"),
    Field::new(
        "severity",
        "Forward from severity",
        Kind::Select(SEVERITIES),
    )
    .def("info")
    .help("this severity and everything more serious"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "syslog",
    title: "Syslog",
    blurb: "Forward the system log to remote syslog collectors (rsyslog) and read the local log. \
            Targets are written to /etc/rsyslog.d/50-patronus.conf and rsyslog is restarted when \
            they change.",
    applier: "syslog",
    fields: &[],
    colls: &[Coll {
        key: "targets",
        title: "Remote collectors",
        table: "syslog_targets",
        fields: &TARGET_FIELDS,
        unique: None,
    }],
    actions: &[("test", "Send a test message")],
};

pub struct SyslogSvc;

#[async_trait]
impl Svc for SyslogSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn action(&self, _store: &ConfigStore, name: &str, _body: &Value) -> Result<Value> {
        if name != "test" {
            return Err(Error::Config(format!(
                "Invalid request: no action {name:?}"
            )));
        }
        let msg = format!("Patronus syslog test message {}", lan::now());
        let out = std::process::Command::new("logger")
            .args(["-t", "patronus-test", "-p", "user.notice", &msg])
            .output()
            .map_err(|e| Error::Service(format!("logger: {e}")))?;
        if !out.status.success() {
            return Err(Error::Service(format!(
                "logger failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(json!({"sent": msg}))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub proto: String,
    pub severity: String,
}

pub async fn targets(store: &ConfigStore) -> Result<Vec<Target>> {
    let rows = svc::raw_rows(store, &SPEC.colls[0]).await?;
    Ok(rows
        .iter()
        .filter(|r| lan::flag(r["enabled"].as_str().unwrap_or("")))
        .map(|r| Target {
            host: r["host"].as_str().unwrap_or("").into(),
            port: r["port"]
                .as_str()
                .and_then(|p| p.parse().ok())
                .unwrap_or(514),
            proto: r["proto"].as_str().unwrap_or("udp").into(),
            severity: r["severity"].as_str().unwrap_or("info").into(),
        })
        .collect())
}

/// The drop-in file.
pub fn render(t: &[Target]) -> String {
    let mut c = lan::header("#", "rsyslog: remote forwarding");
    if t.is_empty() {
        c.push_str("# no remote collectors configured\n");
        return c;
    }
    for x in t {
        let queue = if x.proto == "tcp" {
            " action.resumeRetryCount=\"-1\" queue.type=\"LinkedList\" queue.size=\"10000\" queue.dequeueBatchSize=\"100\""
        } else {
            ""
        };
        c.push_str(&format!(
            "*.{} action(type=\"omfwd\" target=\"{}\" port=\"{}\" protocol=\"{}\"{queue})\n",
            x.severity, x.host, x.port, x.proto
        ));
    }
    c
}

/// Does the main rsyslog config read `/etc/rsyslog.d`?
pub fn includes_dropins(main_conf: &str) -> bool {
    main_conf
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| l.contains("/etc/rsyslog.d"))
}

/// Last lines of the local system log: the log file rsyslog writes, else the journal.
pub fn recent_log(env: &LanEnv, n: usize) -> Vec<String> {
    for f in ["/var/log/syslog", "/var/log/messages"] {
        let p = env.path(f);
        if p.exists() {
            let v = svc::tail_lines(&p, n);
            if !v.is_empty() {
                return v;
            }
        }
    }
    if env.root == std::path::Path::new("/") {
        if let Ok(o) = std::process::Command::new("journalctl")
            .args(["-n", &n.to_string(), "--no-pager", "-o", "short"])
            .output()
        {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(String::from)
                    .collect();
            }
        }
    }
    Vec::new()
}

#[derive(Clone, Default)]
pub struct SyslogApplier {
    env: LanEnv,
}

impl SyslogApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }
}

#[async_trait]
impl Applier for SyslogApplier {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let t = targets(store).await?;
        let managed = lan::is_managed(&self.env, CONF);
        if t.is_empty() && !managed {
            rep.applied("no syslog forwarding configured (rsyslog untouched)");
            return Ok(rep);
        }
        if !self.env.has_binary(BIN) {
            return Err(Error::Service(
                "syslog forwarding needs rsyslog but /usr/sbin/rsyslogd is not installed \
                 (emerge app-admin/rsyslog, USE=syslog)"
                    .into(),
            ));
        }
        let main = std::fs::read_to_string(self.env.path("/etc/rsyslog.conf")).unwrap_or_default();
        if !t.is_empty() && !includes_dropins(&main) {
            return Err(Error::Service(
                "/etc/rsyslog.conf does not include /etc/rsyslog.d (add \
                 `$IncludeConfig /etc/rsyslog.d/*.conf`); forwarding would not take effect"
                    .into(),
            ));
        }
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: CONF,
                content: render(&t),
                mode: 0o644,
                group: None,
                // an empty file (no targets) has no action: rsyslogd refuses it, so only check real ones
                check: (!t.is_empty()).then(|| vec![BIN, "-N1", "-f", "{}"]),
            },
        )?;
        if changed {
            rep.applied(format!("wrote {CONF}"));
        }
        let running = self.env.services.is_running(SERVICE);
        if changed || (!t.is_empty() && !running) {
            self.env.services.restart(SERVICE)?;
            rep.applied(format!("{SERVICE} restarted"));
        }
        rep.applied(format!("{} remote syslog target(s)", t.len()));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(format!("## {CONF}\n{}", render(&targets(store).await?)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let t = targets(store).await?;
        Ok(json!({
            "installed": self.env.has_binary(BIN),
            "running": self.env.services.is_running(SERVICE),
            "managed_file": lan::is_managed(&self.env, CONF),
            "forwarding_to": t.iter().map(|x| format!("{}:{}/{} (>= {})", x.host, x.port, x.proto, x.severity)).collect::<Vec<_>>(),
            "recent_log": recent_log(&self.env, 40),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;

    async fn add(s: &ConfigStore, body: Value) -> Result<i64> {
        svc::save_row(s, &SPEC.colls[0], None, &body).await
    }

    #[test]
    fn drop_in_has_one_action_per_target() {
        let c = render(&[
            Target {
                host: "10.0.0.5".into(),
                port: 514,
                proto: "udp".into(),
                severity: "warning".into(),
            },
            Target {
                host: "log.example.com".into(),
                port: 6514,
                proto: "tcp".into(),
                severity: "info".into(),
            },
        ]);
        assert!(c.contains(
            "*.warning action(type=\"omfwd\" target=\"10.0.0.5\" port=\"514\" protocol=\"udp\")"
        ));
        assert!(c.contains("*.info action(type=\"omfwd\" target=\"log.example.com\" port=\"6514\" protocol=\"tcp\" action.resumeRetryCount=\"-1\""));
        assert!(includes_dropins("$IncludeConfig /etc/rsyslog.d/*.conf\n"));
        assert!(!includes_dropins(
            "# $IncludeConfig /etc/rsyslog.d/*.conf\n"
        ));
    }

    #[tokio::test]
    async fn targets_are_validated_stored_written_and_removed() {
        let t = testutil::env(&[BIN]);
        let s = testutil::store().await;
        std::fs::create_dir_all(t.env.path("/etc/rsyslog.d")).unwrap();
        std::fs::write(
            t.env.path("/etc/rsyslog.conf"),
            "$IncludeConfig /etc/rsyslog.d/*.conf\n",
        )
        .unwrap();
        let a = SyslogApplier::new(t.env.clone());
        // nothing configured, nothing touched
        a.apply(&s).await.unwrap();
        assert!(!t.env.has_binary(CONF));
        for bad in [
            json!({"host": "x y"}),
            json!({"host": "1.2.3.4", "port": 0}),
            json!({"host": "1.2.3.4", "proto": "icmp"}),
            json!({"host": "1.2.3.4", "severity": "loud"}),
            json!({"host": "1.2.3.4\n*.* action(type=\"omprog\")"}),
            json!({}),
        ] {
            assert!(add(&s, bad.clone()).await.is_err(), "accepted {bad}");
        }
        let id = add(
            &s,
            json!({"host": "192.0.2.9", "port": 5140, "severity": "warning"}),
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CONF);
        assert!(c.contains(
            "*.warning action(type=\"omfwd\" target=\"192.0.2.9\" port=\"5140\" protocol=\"udp\")"
        ));
        assert!(t.services.is_running(SERVICE));
        let before = t.services.log.lock().unwrap().len();
        a.apply(&s).await.unwrap();
        assert_eq!(
            t.services.log.lock().unwrap().len(),
            before,
            "unchanged apply must not restart"
        );
        svc::delete_row(&s, &SPEC.colls[0], id).await.unwrap();
        a.apply(&s).await.unwrap();
        assert!(!read(&t, CONF).contains("omfwd"));
        assert!(
            t.services.log.lock().unwrap().len() > before,
            "removal restarts rsyslog"
        );
    }

    #[tokio::test]
    async fn refuses_when_rsyslog_does_not_read_the_drop_in_directory() {
        let t = testutil::env(&[BIN]);
        let s = testutil::store().await;
        std::fs::create_dir_all(t.env.path("/etc")).unwrap();
        std::fs::write(t.env.path("/etc/rsyslog.conf"), "*.* /var/log/all\n").unwrap();
        add(&s, json!({"host": "192.0.2.9"})).await.unwrap();
        let e = SyslogApplier::new(t.env.clone())
            .apply(&s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("rsyslog.d"), "{e}");
        let t2 = testutil::env(&[]);
        let e = SyslogApplier::new(t2.env.clone())
            .apply(&s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not installed"), "{e}");
    }
}
