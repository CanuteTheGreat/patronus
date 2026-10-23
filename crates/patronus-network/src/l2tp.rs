//! L2TP server (USE=l2tp): road-warrior and site clients dial in with L2TP
//! (UDP 1701) and authenticate with PPP MS-CHAPv2.
//!
//! `xl2tpd` runs through the supervisor (`patronus-daemon@xl2tpd`) with a
//! generated config under the net state dir; it starts `pppd` per session
//! with a generated options file. User passwords are written to a Patronus
//! block of `/etc/ppp/chap-secrets` (the only place pppd reads them from; the
//! rest of the file is preserved, mode 0600). The firewall opens UDP 1701 on
//! the listening interface only (`patronus_firewall::svc_rules`); what the
//! clients may reach is decided by your rules on their `ppp` interface.
//!
//! Plain L2TP does not encrypt the tunnel: pair it with IPsec transport mode
//! (or a VPN) for anything that crosses the internet.

use crate::lan::{self, invalid};
use crate::supervise::{which, write_atomic, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "xl2tpd";
pub const CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
const BEGIN: &str = "# BEGIN Managed by Patronus (L2TP users)";
const END: &str = "# END Managed by Patronus (L2TP users)";

static FIELDS: [Field; 6] = [
    Field::new("enabled", "L2TP server", Kind::Bool).def("0"),
    Field::new("interface", "Listen on", Kind::Iface)
        .def("@wan")
        .help("UDP 1701 is opened on this interface"),
    Field::new("local_ip", "Server tunnel address", Kind::Ipv4).def("10.88.0.1"),
    Field::new("range_start", "Client pool: first address", Kind::Ipv4).def("10.88.0.10"),
    Field::new("range_end", "Client pool: last address", Kind::Ipv4).def("10.88.0.50"),
    Field::new("dns", "DNS server for clients", Kind::Ip)
        .help("optional; usually the LAN address of this firewall"),
];

static USER_FIELDS: [Field; 3] = [
    Field::new("username", "User name", Kind::Token).req(),
    Field::new("password", "Password", Kind::Secret).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: "l2tp",
    title: "L2TP server",
    blurb: "Dial-in L2TP (UDP 1701) with PPP MS-CHAPv2 users. Runs xl2tpd + pppd. L2TP itself is \
            not encrypted: use it over IPsec or another VPN on untrusted networks.",
    applier: "l2tp",
    fields: &FIELDS,
    colls: &[Coll {
        key: "users",
        title: "Users",
        table: "l2tp_users",
        fields: &USER_FIELDS,
        unique: Some("username"),
    }],
    actions: &[],
};

pub struct L2tpSvc;

/// The tunnel address and client pool must be IPv4, the pool ordered, and the
/// server address outside it.
pub fn check_pool(local: &str, start: &str, end: &str) -> Result<()> {
    let (Ok(l), Ok(a), Ok(b)) = (
        local.parse::<std::net::Ipv4Addr>(),
        start.parse::<std::net::Ipv4Addr>(),
        end.parse::<std::net::Ipv4Addr>(),
    ) else {
        return Err(invalid(
            "L2TP: the tunnel address and client pool must be IPv4 addresses",
        ));
    };
    if u32::from(a) > u32::from(b) {
        return Err(invalid(
            "L2TP: the client pool's first address is after its last",
        ));
    }
    if (u32::from(a)..=u32::from(b)).contains(&u32::from(l)) {
        return Err(invalid(
            "L2TP: the server tunnel address must be outside the client pool",
        ));
    }
    Ok(())
}

#[async_trait]
impl Svc for L2tpSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        // check the pool as it will be after this change, before storing anything
        let cur = Settings::load(store, &SPEC).await?;
        let pick = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| cur.s(k))
        };
        check_pool(&pick("local_ip"), &pick("range_start"), &pick("range_end"))?;
        svc::put_settings(store, &SPEC, body).await
    }
}

pub fn render_xl2tpd(s: &Settings, options: &str) -> String {
    let mut c = lan::header(";", "xl2tpd");
    c.push_str("[global]\nport = 1701\n\n[lns default]\n");
    c.push_str(&format!(
        "ip range = {}-{}\nlocal ip = {}\nrequire authentication = yes\nrefuse pap = yes\nrefuse chap = yes\nppp debug = no\nlength bit = yes\npppoptfile = {options}\n",
        s.s("range_start"),
        s.s("range_end"),
        s.s("local_ip")
    ));
    c
}

pub fn render_options(s: &Settings) -> String {
    let mut c = lan::header("#", "pppd options for L2TP sessions");
    c.push_str("auth\nrequire-mschap-v2\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nnoccp\nnodefaultroute\nproxyarp\nlcp-echo-interval 30\nlcp-echo-failure 4\nmtu 1400\nmru 1400\n");
    let dns = s.s("dns");
    if !dns.is_empty() {
        c.push_str(&format!("ms-dns {dns}\n"));
    }
    c
}

/// `chap-secrets` with the Patronus block replaced (or appended).
pub fn merge_secrets(existing: &str, users: &[(String, String)]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for l in existing.lines() {
        if l.trim() == BEGIN {
            skipping = true;
            continue;
        }
        if l.trim() == END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(l);
            out.push('\n');
        }
    }
    if !users.is_empty() {
        out.push_str(BEGIN);
        out.push('\n');
        for (u, p) in users {
            out.push_str(&format!("\"{u}\" * \"{p}\" *\n"));
        }
        out.push_str(END);
        out.push('\n');
    }
    out
}

async fn users(store: &ConfigStore) -> Result<Vec<(String, String)>> {
    Ok(svc::raw_rows(store, &SPEC.colls[0])
        .await?
        .iter()
        .filter(|r| lan::flag(r["enabled"].as_str().unwrap_or("")))
        .map(|r| {
            (
                r["username"].as_str().unwrap_or("").to_string(),
                r["password"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect())
}

#[derive(Clone)]
pub struct L2tpApplier {
    sup: Supervisor,
    secrets: std::path::PathBuf,
}

impl Default for L2tpApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            secrets: CHAP_SECRETS.into(),
        }
    }
}

impl L2tpApplier {
    pub fn with_supervisor(sup: Supervisor, secrets: std::path::PathBuf) -> Self {
        Self { sup, secrets }
    }
}

#[async_trait]
impl Applier for L2tpApplier {
    fn name(&self) -> &'static str {
        "l2tp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        let u = users(store).await?;
        let existing = std::fs::read_to_string(&self.secrets).unwrap_or_default();
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            if existing.contains(BEGIN) {
                write_atomic(&self.secrets, &merge_secrets(&existing, &[]), 0o600)?;
            }
            rep.applied(if was {
                "L2TP server stopped"
            } else {
                "L2TP server is off"
            });
            return Ok(rep);
        }
        check_pool(&s.s("local_ip"), &s.s("range_start"), &s.s("range_end"))?;
        let (a, b, l) = (s.s("range_start"), s.s("range_end"), s.s("local_ip"));
        if u.is_empty() {
            return Err(invalid(
                "L2TP: add at least one user before enabling the server",
            ));
        }
        let xl2tpd = which("xl2tpd").ok_or_else(|| {
            Error::Service(
                "the L2TP server needs xl2tpd, which is not installed (emerge net-dialup/xl2tpd, USE=l2tp)"
                    .into(),
            )
        })?;
        if which("pppd").is_none() {
            return Err(Error::Service(
                "the L2TP server needs pppd (emerge net-dialup/ppp)".into(),
            ));
        }
        if write_atomic(&self.secrets, &merge_secrets(&existing, &u), 0o600)? {
            rep.applied(format!(
                "wrote {} L2TP user(s) to {}",
                u.len(),
                self.secrets.display()
            ));
        }
        let dir = &self.sup.paths.state_dir;
        let conf = dir.join("xl2tpd.conf");
        let opts = dir.join("options.xl2tpd");
        std::fs::create_dir_all(&self.sup.paths.run_dir)
            .map_err(|e| Error::Service(format!("{}: {e}", self.sup.paths.run_dir.display())))?;
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                xl2tpd.to_string_lossy().into(),
                "-D".into(),
                "-c".into(),
                conf.to_string_lossy().into(),
                "-C".into(),
                self.sup
                    .paths
                    .run_dir
                    .join("l2tp-control")
                    .to_string_lossy()
                    .into(),
                "-p".into(),
                self.sup
                    .paths
                    .run_dir
                    .join("xl2tpd.pid")
                    .to_string_lossy()
                    .into(),
            ],
            vec![
                (
                    conf.clone(),
                    render_xl2tpd(&s, &opts.to_string_lossy()),
                    0o644,
                ),
                (opts, render_options(&s), 0o644),
            ],
        )
        .await?;
        rep.applied(format!(
            "xl2tpd {}: {} user(s), clients {a}-{b}, server {l}",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            u.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# L2TP server off\n".into());
        }
        let opts = self.sup.paths.state_dir.join("options.xl2tpd");
        Ok(format!(
            "## xl2tpd.conf\n{}\n## options.xl2tpd\n{}",
            render_xl2tpd(&s, &opts.to_string_lossy()),
            render_options(&s)
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let sessions: Vec<String> = std::fs::read_dir("/sys/class/net")
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n.starts_with("ppp"))
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("xl2tpd").is_some() && which("pppd").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "ppp_sessions": sessions,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn secrets_block_replaces_only_its_own_lines() {
        let base = "# mine\n\"x\" * \"y\" *\n";
        let one = merge_secrets(base, &[("alice".into(), "pw-123456".into())]);
        assert!(one.starts_with(base));
        assert!(one.contains("\"alice\" * \"pw-123456\" *"));
        let two = merge_secrets(&one, &[("bob".into(), "pw-abcdefg".into())]);
        assert!(!two.contains("alice") && two.contains("bob") && two.starts_with(base));
        let none = merge_secrets(&two, &[]);
        assert_eq!(none, base);
    }

    #[tokio::test]
    async fn validation_and_apply_preconditions() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let secrets = d.path().join("chap-secrets");
        let a = L2tpApplier::with_supervisor(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            secrets.clone(),
        );
        a.apply(&s).await.unwrap();
        let c = &SPEC.colls[0];
        for bad in [
            json!({"username": "a b", "password": "longenough1"}),
            json!({"username": "alice", "password": "short"}),
            json!({"username": "alice", "password": "pass\"word123"}),
            json!({"username": "alice"}),
        ] {
            assert!(svc::save_row(&s, c, None, &bad).await.is_err(), "{bad}");
        }
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        assert!(a.apply(&s).await.unwrap_err().to_string().contains("user"));
        let id = svc::save_row(
            &s,
            c,
            None,
            &json!({"username": "alice", "password": "alice-secret-1"}),
        )
        .await
        .unwrap();
        // the password never comes back out
        let rows = svc::list_rows(&s, c).await.unwrap();
        assert_eq!(rows[0]["password"], json!(svc::SECRET_MASK));
        // editing without a password keeps it
        svc::save_row(
            &s,
            c,
            Some(id),
            &json!({"enabled": true, "password": svc::SECRET_MASK}),
        )
        .await
        .unwrap();
        assert_eq!(users(&s).await.unwrap()[0].1, "alice-secret-1");
        svc::put_settings(
            &s,
            &SPEC,
            &json!({"range_start": "10.88.0.1", "range_end": "10.88.0.20"}),
        )
        .await
        .unwrap();
        assert!(a
            .apply(&s)
            .await
            .unwrap_err()
            .to_string()
            .contains("outside the client pool"));
        let st = Settings::load(&s, &SPEC).await.unwrap();
        assert!(render_xl2tpd(&st, "/o").contains("ip range = 10.88.0.1-10.88.0.20"));
        assert!(render_options(&st).contains("require-mschap-v2"));
    }
}
