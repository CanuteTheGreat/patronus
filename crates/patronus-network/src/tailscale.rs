//! Tailscale mesh VPN client (USE=tailscale), an optional packaged feature
//! (net-vpn/tailscale): join the router to a tailnet (Tailscale's own control
//! plane or a self-hosted Headscale), advertise LAN routes and/or an exit node,
//! and keep the tailnet interface behind the Patronus firewall.
//!
//! - `tailscaled` runs as a Patronus supervised daemon (`patronus-daemon@tailscaled`,
//!   OpenRC and systemd) with the kernel TUN device named by `interface`, the
//!   state directory and the control socket from the settings.
//! - The node joins with `tailscale up --reset ...`; the pre-auth key is read by
//!   tailscale from a FILE (`--auth-key file:PATH`), so no key is ever stored in
//!   the configuration, the API or a log. `up` runs only when the wanted flags
//!   changed or the node is not Running.
//! - Patronus owns the firewall: tailscale's own netfilter handling is off
//!   (`--netfilter-mode=off`). Nothing from the tailnet reaches the router or the
//!   LAN until the matching setting is on (`patronus_firewall::svc_rules`).
//! - A node that needs a login but has no key file is refused with a plain error
//!   (tailscale would otherwise wait for a browser login that never comes).

use crate::lan::invalid;
use crate::linkstate::{argv, Cmd, SystemCmd};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use crate::vpn::check_networks;
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

pub const INSTANCE: &str = "tailscaled";
/// Where the last `tailscale up` flags are remembered (under the state dir of Patronus).
const UP_STAMP: &str = "tailscale-up.args";

static FIELDS: [Field; 16] = [
    Field::new("enabled", "Tailscale", Kind::Bool).def("0"),
    Field::new("login_server", "Control server", Kind::Token)
        .help("URL of a self-hosted Headscale (https://hs.example.net); empty = Tailscale's own service"),
    Field::new("auth_key_file", "Pre-auth key file", Kind::Token).help(
        "absolute path of a file holding a pre-auth key; read by tailscale, never stored here. \
         Only needed to join; once the node is logged in it can stay empty",
    ),
    Field::new("hostname", "Node name", Kind::Token)
        .help("name in the tailnet (empty = this machine's host name)"),
    Field::new("advertise_routes", "Advertise routes", Kind::Text)
        .help("networks of this router that tailnet devices may reach, comma separated (192.168.1.0/24, fd00:1::/64); the tailnet admin must approve them"),
    Field::new("advertise_exit_node", "Offer as exit node", Kind::Bool).def("0"),
    Field::new("accept_routes", "Use routes other nodes advertise", Kind::Bool).def("0"),
    Field::new("accept_dns", "Use the tailnet's DNS settings", Kind::Bool)
        .def("0")
        .help("off keeps Patronus' own resolver in charge"),
    Field::new("interface", "Interface", Kind::Token)
        .def("tailscale0")
        .help("kernel device name of the tailnet interface"),
    Field::new("port", "UDP port", Kind::Int(1, 65535)).def("41641"),
    Field::new("open_port", "Accept direct connections on the WAN", Kind::Bool)
        .def("0")
        .help("opens the UDP port on the firewall so peers can connect directly; off still works through NAT traversal and relays"),
    Field::new("allow_input", "Let tailnet devices reach this router", Kind::Bool)
        .def("0")
        .help("web interface, SSH, DNS: off keeps the router closed to the tailnet"),
    Field::new("allow_lan", "Let tailnet devices reach the LAN", Kind::Bool)
        .def("0")
        .help("needed for advertised routes to carry traffic"),
    Field::new("tailnet_range", "Tailnet address range", Kind::Cidr4)
        .def("100.64.0.0/10")
        .help("where the tailnet's addresses live (Tailscale and Headscale both default to this); used for the exit-node masquerade"),
    Field::new("state_dir", "State directory", Kind::Token)
        .def("/var/lib/tailscale")
        .help("keeps the node's identity across restarts"),
    Field::new("socket", "Control socket", Kind::Token).def("/run/tailscale/tailscaled.sock"),
];

static SPEC: Spec = Spec {
    slug: "tailscale",
    title: "Tailscale",
    blurb: "Join this router to a Tailscale network (or your own Headscale server) so your \
            devices reach each other and, if you allow it, your LAN, from anywhere. \
            The tailnet interface stays behind the firewall: nothing gets in until you allow \
            access to this router or to the LAN below. Needs the net-vpn/tailscale package.",
    applier: "tailscale",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct TailscaleSvc;

fn check_login_server(s: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    let ok = ["https://", "http://"].iter().any(|p| {
        s.strip_prefix(p)
            .is_some_and(|r| !r.is_empty() && !r.starts_with('/'))
    });
    if !ok {
        return Err(invalid(format!(
            "control server {s:?}: a URL starting with https:// (or http:// for a lab)"
        )));
    }
    Ok(())
}

fn check_abs(what: &str, s: &str) -> Result<()> {
    if !s.is_empty() && (!s.starts_with('/') || s.contains("..")) {
        return Err(invalid(format!("{what} {s:?}: an absolute path")));
    }
    Ok(())
}

fn check_dev(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 15
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(invalid(format!(
            "interface {s:?}: a kernel device name (up to 15 characters)"
        )));
    }
    Ok(())
}

/// The settings as they will be after `body` is stored: refuse bad ones before storing anything.
pub fn validate(s: &Settings) -> Result<()> {
    check_login_server(&s.s("login_server"))?;
    check_abs("pre-auth key file", &s.s("auth_key_file"))?;
    check_abs("state directory", &s.s("state_dir"))?;
    check_abs("control socket", &s.s("socket"))?;
    check_dev(&s.s("interface"))?;
    let h = s.s("hostname");
    if !h.is_empty()
        && !h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        return Err(invalid(format!(
            "node name {h:?}: letters, digits, - and ."
        )));
    }
    let r = s.s("advertise_routes");
    if !r.trim().is_empty() {
        check_networks("advertised routes", &r, false)?;
    }
    Ok(())
}

#[async_trait]
impl Svc for TailscaleSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        let mut cur = Settings::load(store, &SPEC).await?;
        if let Some(o) = body.as_object() {
            for (k, v) in o {
                if let Some(t) = v.as_str() {
                    cur.0.insert(k.clone(), Value::String(t.trim().to_string()));
                } else if let Some(b) = v.as_bool() {
                    cur.0
                        .insert(k.clone(), Value::String(if b { "1" } else { "0" }.into()));
                }
            }
        }
        validate(&cur)?;
        svc::put_settings(store, &SPEC, body).await
    }
}

/// `tailscaled` command line.
pub fn daemon_argv(bin: &str, s: &Settings) -> Vec<String> {
    vec![
        bin.to_string(),
        format!(
            "--state={}/tailscaled.state",
            s.s("state_dir").trim_end_matches('/')
        ),
        format!("--socket={}", s.s("socket")),
        format!("--port={}", s.s("port")),
        format!("--tun={}", s.s("interface")),
    ]
}

/// Arguments of `tailscale up` (after the `--socket` option).
pub fn up_args(s: &Settings) -> Vec<String> {
    let mut a = argv(&["up", "--reset", "--timeout=60s", "--netfilter-mode=off"]);
    let ls = s.s("login_server");
    if !ls.is_empty() {
        a.push(format!("--login-server={ls}"));
    }
    let key = s.s("auth_key_file");
    if !key.is_empty() {
        a.push(format!("--auth-key=file:{key}"));
    }
    let h = s.s("hostname");
    if !h.is_empty() {
        a.push(format!("--hostname={h}"));
    }
    let routes: Vec<String> = s
        .s("advertise_routes")
        .split([',', ' ', '\n'])
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect();
    if !routes.is_empty() {
        a.push(format!("--advertise-routes={}", routes.join(",")));
    }
    if s.b("advertise_exit_node") {
        a.push("--advertise-exit-node".into());
    }
    if s.b("accept_routes") {
        a.push("--accept-routes".into());
    }
    a.push(format!("--accept-dns={}", s.b("accept_dns")));
    a
}

#[derive(Clone)]
pub struct TailscaleApplier {
    sup: Supervisor,
    cmd: Arc<dyn Cmd>,
    /// (tailscaled, tailscale); looked up on PATH when None.
    bins: Option<(PathBuf, PathBuf)>,
}

impl Default for TailscaleApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            cmd: Arc::new(SystemCmd),
            bins: None,
        }
    }
}

impl TailscaleApplier {
    pub fn new(sup: Supervisor, cmd: Arc<dyn Cmd>, bins: Option<(PathBuf, PathBuf)>) -> Self {
        Self { sup, cmd, bins }
    }

    fn binaries(&self) -> Option<(PathBuf, PathBuf)> {
        match &self.bins {
            Some(b) => Some(b.clone()),
            None => Some((which("tailscaled")?, which("tailscale")?)),
        }
    }

    async fn ts(&self, bin: &std::path::Path, socket: &str, args: &[String]) -> Result<String> {
        let mut a = vec![format!("--socket={socket}")];
        a.extend(args.iter().cloned());
        self.cmd.run(&bin.to_string_lossy(), &a).await
    }

    /// `tailscale status --json`, parsed (an error while the daemon is still coming up).
    async fn status_json(&self, bin: &std::path::Path, socket: &str) -> Result<Value> {
        let out = self.ts(bin, socket, &argv(&["status", "--json"])).await?;
        serde_json::from_str(out.trim())
            .map_err(|e| Error::Service(format!("tailscale status: {e}")))
    }

    fn stamp(&self) -> PathBuf {
        self.sup.paths.state_dir.join(UP_STAMP)
    }
}

#[async_trait]
impl Applier for TailscaleApplier {
    fn name(&self) -> &'static str {
        "tailscale"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                let _ = std::fs::remove_file(self.stamp());
                rep.applied("Tailscale stopped (the node's identity is kept)");
            } else {
                rep.applied("Tailscale is off");
            }
            return Ok(rep);
        }
        validate(&s)?;
        let (daemon, cli) = self.binaries().ok_or_else(|| {
            Error::Service(
                "Tailscale needs net-vpn/tailscale, which is not installed (emerge \
                 net-vpn/tailscale, USE=tailscale)"
                    .into(),
            )
        })?;
        let socket = s.s("socket");
        if let Some(dir) = std::path::Path::new(&socket).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::create_dir_all(s.s("state_dir"));
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            daemon_argv(&daemon.to_string_lossy(), &s),
            vec![],
        )
        .await?;
        if started {
            rep.applied(format!("tailscaled (re)started on {}", s.s("interface")));
        }
        // the daemon needs a moment before its socket answers, and a moment more
        // before it has read its saved state ("NoState" until then)
        let mut st = None;
        for _ in 0..80 {
            if let Ok(v) = self.status_json(&cli, &socket).await {
                let settled = !matches!(v["BackendState"].as_str(), Some("NoState") | None);
                st = Some(v);
                if settled {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        let st =
            st.ok_or_else(|| Error::Service("tailscaled did not answer on its socket".into()))?;
        let state = st["BackendState"].as_str().unwrap_or("").to_string();
        // The pre-auth key only matters for the first login: a node that already has an
        // identity (its state directory survived) needs no key, and a missing or expired
        // key file must not stop it from coming back after a reboot.
        let logged_in = matches!(
            state.as_str(),
            "Running" | "Starting" | "Stopped" | "NeedsMachineAuth"
        );
        let all_args = up_args(&s);
        let without_key: Vec<String> = all_args
            .iter()
            .filter(|a| !a.starts_with("--auth-key="))
            .cloned()
            .collect();
        let want = without_key.join("\n");
        let have = std::fs::read_to_string(self.stamp()).unwrap_or_default();
        if state == "Running" && have == want && !started {
            rep.applied("Tailscale is running, unchanged");
            return Ok(rep);
        }
        let key = s.s("auth_key_file");
        let server_changed = |h: &str| {
            !h.is_empty()
                && h.lines().find(|l| l.starts_with("--login-server="))
                    != want.lines().find(|l| l.starts_with("--login-server="))
        };
        if logged_in && server_changed(&have) {
            // another control server needs a new login: forget the old identity first
            self.ts(&cli, &socket, &argv(&["logout"])).await.ok();
        }
        let needs_login = !logged_in || server_changed(&have);
        let args = if needs_login { all_args } else { without_key };
        if needs_login && key.is_empty() {
            return Err(invalid(
                "Tailscale: this node is not logged in: give a pre-auth key file (a new key from \
                 the Tailscale admin console or `headscale preauthkeys create`)",
            ));
        }
        if needs_login && !std::path::Path::new(&key).exists() {
            return Err(invalid(format!(
                "Tailscale: the pre-auth key file {key} does not exist"
            )));
        }
        self.ts(&cli, &socket, &args)
            .await
            .map_err(|e| Error::Service(format!("tailscale up: {e}")))?;
        if let Some(dir) = self.stamp().parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(self.stamp(), want);
        rep.applied(format!("joined the tailnet on {}", s.s("interface")));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# Tailscale off\n".into());
        }
        Ok(format!(
            "## tailscaled\n{}\n## tailscale\n--socket={} {}\n",
            daemon_argv("tailscaled", &s).join(" "),
            s.s("socket"),
            up_args(&s).join(" ")
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let bins = self.binaries();
        let mut out = json!({
            "enabled": s.b("enabled"),
            "installed": bins.is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "interface": s.s("interface"),
        });
        if let (Some((_, cli)), true) = (bins, out["running"] == true) {
            if let Ok(st) = self.status_json(&cli, &s.s("socket")).await {
                out["backend_state"] = st["BackendState"].clone();
                out["addresses"] = st["Self"]["TailscaleIPs"].clone();
                out["health"] = st["Health"].clone();
                let peers = st["Peer"].as_object().cloned().unwrap_or_default();
                out["peers"] = json!(peers.len());
                out["peers_online"] = json!(peers.values().filter(|p| p["Online"] == true).count());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let mut m = serde_json::Map::new();
        for f in SPEC.fields {
            m.insert(f.key.into(), json!(f.default));
        }
        for (k, v) in pairs {
            m.insert((*k).into(), json!(v));
        }
        Settings(m)
    }

    #[test]
    fn up_flags_follow_the_settings_and_never_carry_the_key_itself() {
        let a = up_args(&settings(&[]));
        assert_eq!(
            a,
            argv(&[
                "up",
                "--reset",
                "--timeout=60s",
                "--netfilter-mode=off",
                "--accept-dns=false"
            ])
        );
        let a = up_args(&settings(&[
            ("login_server", "https://hs.example.net"),
            ("auth_key_file", "/etc/patronus/secrets/ts.key"),
            ("hostname", "gw1"),
            ("advertise_routes", "192.168.50.0/24, fd00:50::/64"),
            ("advertise_exit_node", "1"),
            ("accept_routes", "1"),
            ("accept_dns", "1"),
        ]));
        for want in [
            "--login-server=https://hs.example.net",
            "--auth-key=file:/etc/patronus/secrets/ts.key",
            "--hostname=gw1",
            "--advertise-routes=192.168.50.0/24,fd00:50::/64",
            "--advertise-exit-node",
            "--accept-routes",
            "--accept-dns=true",
        ] {
            assert!(a.contains(&want.to_string()), "missing {want}: {a:?}");
        }
        let d = daemon_argv(
            "/usr/sbin/tailscaled",
            &settings(&[("port", "5555"), ("interface", "ts9")]),
        );
        assert_eq!(
            d,
            vec![
                "/usr/sbin/tailscaled",
                "--state=/var/lib/tailscale/tailscaled.state",
                "--socket=/run/tailscale/tailscaled.sock",
                "--port=5555",
                "--tun=ts9"
            ]
        );
    }

    #[test]
    fn bad_settings_are_refused() {
        for (k, v) in [
            ("login_server", "hs.example.net"),
            ("login_server", "https://"),
            ("auth_key_file", "relative/key"),
            ("state_dir", "/var/../etc"),
            ("interface", "a b"),
            ("interface", "much-too-long-device-name"),
            ("hostname", "bad host"),
            ("advertise_routes", "10.0.0.0/99"),
        ] {
            assert!(
                validate(&settings(&[(k, v)])).is_err(),
                "{k}={v} was accepted"
            );
        }
        assert!(validate(&settings(&[("login_server", "http://10.0.0.5:8080")])).is_ok());
    }

    #[tokio::test]
    async fn bad_settings_are_not_stored() {
        let s = crate::lan::testutil::store().await;
        assert!(TailscaleSvc
            .put(&s, &json!({"login_server": "nonsense"}))
            .await
            .is_err());
        TailscaleSvc
            .put(
                &s,
                &json!({"login_server": "https://hs.example.net", "enabled": true}),
            )
            .await
            .unwrap();
        let g = Settings::load(&s, &SPEC).await.unwrap();
        assert_eq!(g.s("login_server"), "https://hs.example.net");
        assert!(g.b("enabled"));
    }

    /// `tailscale` stand-in: records its arguments, answers `status --json`.
    #[derive(Default)]
    struct FakeTs {
        calls: Mutex<Vec<String>>,
        state: Mutex<String>,
    }
    #[async_trait]
    impl Cmd for FakeTs {
        async fn run(&self, _prog: &str, args: &[String]) -> Result<String> {
            self.calls.lock().unwrap().push(args.join(" "));
            if args.iter().any(|a| a == "status") {
                return Ok(json!({"BackendState": *self.state.lock().unwrap(),
                    "Self": {"TailscaleIPs": ["100.64.0.1"]},
                    "Peer": {"a": {"Online": true}, "b": {"Online": false}}})
                .to_string());
            }
            if args.iter().any(|a| a == "up") {
                *self.state.lock().unwrap() = "Running".into();
            }
            Ok(String::new())
        }
    }

    fn fake_bin(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(
            &p,
            "#!/bin/sh\nsleep 300 &\ntrap 'kill $!; exit 0' TERM\nwait\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[tokio::test]
    async fn joins_once_runs_unchanged_and_stops_when_switched_off() {
        let st = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let sup = Supervisor::new(InitMode::Direct, NetPaths::under(d.path()));
        let cmd = Arc::new(FakeTs::default());
        *cmd.state.lock().unwrap() = "NeedsLogin".into();
        let a = TailscaleApplier::new(
            sup.clone(),
            cmd.clone(),
            Some((fake_bin(d.path(), "tailscaled"), d.path().join("tailscale"))),
        );
        // off: nothing happens
        a.apply(&st).await.unwrap();
        assert!(cmd.calls.lock().unwrap().is_empty());

        let key = d.path().join("ts.key");
        let state_dir = d.path().join("state");
        let sock = d.path().join("run/ts.sock");
        let put = |extra: Value| {
            let mut b = json!({"enabled": true, "state_dir": state_dir.to_str().unwrap(),
                "socket": sock.to_str().unwrap()});
            b.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            b
        };
        TailscaleSvc.put(&st, &put(json!({}))).await.unwrap();
        // not logged in and no key: a plain error, no login attempt
        let e = a.apply(&st).await.unwrap_err().to_string();
        assert!(e.contains("pre-auth key file"), "{e}");
        assert!(!cmd
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains(" up ") || c.contains("up ")));
        sup.stop(svc::DAEMON_SERVICE, INSTANCE).await.unwrap();

        TailscaleSvc
            .put(&st, &put(json!({"auth_key_file": key.to_str().unwrap()})))
            .await
            .unwrap();
        let e = a.apply(&st).await.unwrap_err().to_string();
        assert!(e.contains("does not exist"), "{e}");
        std::fs::write(&key, "tskey-lab\n").unwrap();
        a.apply(&st).await.unwrap();
        let ups = |c: &FakeTs| {
            c.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains("up --reset"))
                .count()
        };
        assert_eq!(ups(&cmd), 1, "{:?}", cmd.calls.lock().unwrap());
        assert!(
            sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "tailscaled runs"
        );
        // unchanged: no second `up`, daemon not restarted
        let r = a.apply(&st).await.unwrap();
        assert_eq!(ups(&cmd), 1);
        assert!(r.applied.join(" ").contains("unchanged"), "{r:?}");
        // a changed flag runs `up` again
        TailscaleSvc
            .put(&st, &put(json!({"advertise_exit_node": true})))
            .await
            .unwrap();
        a.apply(&st).await.unwrap();
        assert_eq!(ups(&cmd), 2);
        // a logged-in node needs no key: a deleted key file does not stop a later change
        std::fs::remove_file(&key).unwrap();
        TailscaleSvc
            .put(&st, &put(json!({"hostname": "gw2"})))
            .await
            .unwrap();
        a.apply(&st).await.unwrap();
        let last = cmd
            .calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|l| l.contains("up --reset"))
            .cloned()
            .unwrap();
        assert!(
            !last.contains("--auth-key") && last.contains("--hostname=gw2"),
            "{last}"
        );
        // status
        let v = a.status(&st).await.unwrap();
        assert_eq!(v["backend_state"], "Running");
        assert_eq!(v["peers"], 2);
        assert_eq!(v["peers_online"], 1);
        assert_eq!(v["addresses"][0], "100.64.0.1");
        let r = a.render(&st).await.unwrap();
        assert!(
            r.contains("--advertise-exit-node") && !r.contains("tskey"),
            "{r}"
        );
        // off again: the daemon stops
        TailscaleSvc
            .put(&st, &json!({"enabled": false}))
            .await
            .unwrap();
        a.apply(&st).await.unwrap();
        assert!(!sup.is_running(svc::DAEMON_SERVICE, INSTANCE));
    }

    #[tokio::test]
    async fn a_missing_package_is_reported_not_faked() {
        let st = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let sup = Supervisor::new(InitMode::Direct, NetPaths::under(d.path()));
        TailscaleSvc
            .put(&st, &json!({"enabled": true}))
            .await
            .unwrap();
        let a = TailscaleApplier {
            sup,
            cmd: Arc::new(FakeTs::default()),
            bins: Some((PathBuf::from("/nonexistent/tailscaled"), PathBuf::new())),
        };
        // an applier with no binaries on PATH
        let b = TailscaleApplier::new(a.sup.clone(), a.cmd.clone(), None);
        if which("tailscaled").is_none() {
            let e = b.apply(&st).await.unwrap_err().to_string();
            assert!(e.contains("net-vpn/tailscale"), "{e}");
            assert_eq!(b.status(&st).await.unwrap()["installed"], false);
        }
    }
}
