//! Reverse proxy / load balancer (USE=reverse-proxy): HAProxy for the LAN's
//! published services.
//!
//! Frontends (a listener: address, port, optional TLS, optional plain-HTTP to
//! HTTPS redirect) send requests to backends (a pool of servers with a
//! balance algorithm and a health check). Routing rules pick the backend by
//! host name (the `Host` header, or the TLS server name in TCP mode) and/or
//! path prefix; a frontend's default backend takes the rest.
//!
//! The generated `haproxy.cfg` is validated with `haproxy -c` as a candidate
//! file BEFORE it replaces the running one: a refused config leaves the
//! daemon and its config untouched. Listener ports that clash with the web UI
//! (or with each other) are refused with an explanation. Statistics come from
//! haproxy's own admin socket (`show stat`), never invented. The firewall
//! opens each frontend's port on the interface chosen for it (see
//! `patronus-firewall/src/svc_rules.rs`).
//!
//! Slug `revproxy` (the existing `proxy` slug is the Squid forward proxy).

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const INSTANCE: &str = "haproxy";
pub const SLUG: &str = "revproxy";

static FIELDS: [Field; 7] = [
    Field::new("enabled", "Reverse proxy / load balancer", Kind::Bool)
        .def("0")
        .help("Off by default. Listeners only open when this is on and a frontend is enabled"),
    Field::new(
        "max_conn",
        "Maximum concurrent connections",
        Kind::Int(10, 1_000_000),
    )
    .def("4000"),
    Field::new(
        "timeout_connect",
        "Backend connect timeout (s)",
        Kind::Int(1, 600),
    )
    .def("5"),
    Field::new(
        "timeout_client",
        "Client idle timeout (s)",
        Kind::Int(1, 86400),
    )
    .def("30"),
    Field::new(
        "timeout_server",
        "Backend idle timeout (s)",
        Kind::Int(1, 86400),
    )
    .def("30"),
    Field::new(
        "tls_min",
        "Oldest TLS version accepted",
        Kind::Select(&["TLSv1.2", "TLSv1.3"]),
    )
    .def("TLSv1.2"),
    Field::new("stats", "Live statistics", Kind::Bool)
        .def("1")
        .help("read from haproxy's local admin socket; nothing is exposed on the network"),
];

static FRONTEND_FIELDS: [Field; 11] = [
    Field::new("name", "Name", Kind::Token).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("interface", "Open the firewall on", Kind::Iface)
        .def("@wan")
        .help("clients reach this listener through this interface (@wan, @lan or a device)"),
    Field::new("bind", "Listen address", Kind::Ip)
        .def("0.0.0.0")
        .help("0.0.0.0 = every IPv4 address; :: = every IPv6 address"),
    Field::new("port", "Port", Kind::Int(1, 65535)).req(),
    Field::new("mode", "Mode", Kind::Select(&["http", "tcp"]))
        .def("http")
        .help("http: route by Host/path. tcp: pass bytes through (TLS is routed by its server name)"),
    Field::new("tls", "Terminate TLS here", Kind::Bool)
        .def("0")
        .help("http mode only; needs a certificate file"),
    Field::new("cert_file", "Certificate + key (PEM file)", Kind::Token)
        .help("absolute path to one PEM file holding the certificate chain and its private key"),
    Field::new("redirect_https", "Redirect to HTTPS", Kind::Bool)
        .def("0")
        .help("answers every request with a 301 to the https:// address (use on a plain-HTTP frontend)"),
    Field::new("default_backend", "Default backend", Kind::Token)
        .help("takes every request no rule matched"),
    Field::new("note", "Note", Kind::Text),
];

static BACKEND_FIELDS: [Field; 10] = [
    Field::new("name", "Name", Kind::Token).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("mode", "Mode", Kind::Select(&["http", "tcp"])).def("http"),
    Field::new(
        "balance",
        "Balance",
        Kind::Select(&["roundrobin", "leastconn", "source", "uri", "random"]),
    )
    .def("roundrobin"),
    Field::new(
        "health",
        "Health check",
        Kind::Select(&["none", "tcp", "http"]),
    )
    .def("tcp")
    .help("a server that fails its check gets no traffic until it passes again"),
    Field::new("check_uri", "Health check path", Kind::Token).def("/"),
    Field::new("check_interval", "Check every (s)", Kind::Int(1, 3600)).def("2"),
    Field::new("rise", "Checks to mark up", Kind::Int(1, 100)).def("2"),
    Field::new("fall", "Checks to mark down", Kind::Int(1, 100)).def("3"),
    Field::new("sticky", "Keep a client on one server", Kind::Bool)
        .def("0")
        .help("http mode: sets a cookie naming the server"),
];

static SERVER_FIELDS: [Field; 7] = [
    Field::new("backend", "Backend", Kind::Token).req(),
    Field::new("name", "Server name", Kind::Token).req(),
    Field::new("address", "Address", Kind::Host).req(),
    Field::new("port", "Port", Kind::Int(1, 65535)).req(),
    Field::new("weight", "Weight", Kind::Int(0, 256)).def("100"),
    Field::new("backup", "Backup only", Kind::Bool)
        .def("0")
        .help("used only while every other server is down"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static RULE_FIELDS: [Field; 6] = [
    Field::new("frontend", "Frontend", Kind::Token).req(),
    Field::new("host", "Host name", Kind::Host)
        .help("matches the Host header (http) or the TLS server name (tcp); a leading *. is not needed: sub-domains are not matched"),
    Field::new("path_prefix", "Path begins with", Kind::Token).help("http mode, e.g. /api"),
    Field::new("backend", "Send to backend", Kind::Token).req(),
    Field::new("priority", "Order (lowest first)", Kind::Int(1, 10000)).def("100"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: SLUG,
    title: "Reverse proxy / load balancer",
    blurb: "Publishes LAN services through HAProxy: listeners with optional TLS, backends with health \
            checks and load balancing, host and path routing, live statistics. A new configuration is \
            checked with haproxy -c first; a refused one leaves the running proxy alone. \"Publish a LAN \
            service\" creates the listener, the backend, the routing rule and the firewall rule in one step.",
    applier: "revproxy",
    fields: &FIELDS,
    colls: &[
        Coll {
            key: "frontends",
            title: "Frontends (listeners)",
            table: "revproxy_frontends",
            fields: &FRONTEND_FIELDS,
            unique: Some("name"),
        },
        Coll {
            key: "backends",
            title: "Backends (server pools)",
            table: "revproxy_backends",
            fields: &BACKEND_FIELDS,
            unique: Some("name"),
        },
        Coll {
            key: "servers",
            title: "Backend servers",
            table: "revproxy_servers",
            fields: &SERVER_FIELDS,
            unique: None,
        },
        Coll {
            key: "rules",
            title: "Routing rules (host / path)",
            table: "revproxy_rules",
            fields: &RULE_FIELDS,
            unique: None,
        },
    ],
    actions: &[
        ("publish", "Publish a LAN service"),
        ("check", "Check the configuration"),
        ("stats", "Live statistics"),
    ],
};

pub const TABLES: &[&str] = &[
    "revproxy_frontends",
    "revproxy_backends",
    "revproxy_servers",
    "revproxy_rules",
];

// ---------------------------------------------------------------------------
// the model read from the store
// ---------------------------------------------------------------------------

type Row = Map<String, Value>;

fn g(r: &Row, k: &str) -> String {
    r.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}
fn gb(r: &Row, k: &str) -> bool {
    lan::flag(&g(r, k))
}
fn gn(r: &Row, k: &str) -> i64 {
    g(r, k).parse().unwrap_or(0)
}

#[derive(Debug, Clone, Default)]
pub struct Model {
    pub frontends: Vec<Row>,
    pub backends: Vec<Row>,
    pub servers: Vec<Row>,
    pub rules: Vec<Row>,
}

impl Model {
    pub async fn load(store: &ConfigStore) -> Result<Self> {
        let coll = |k: &str| svc::find_coll(&SPEC, k).copied();
        Ok(Self {
            frontends: svc::raw_rows(store, &coll("frontends")?).await?,
            backends: svc::raw_rows(store, &coll("backends")?).await?,
            servers: svc::raw_rows(store, &coll("servers")?).await?,
            rules: svc::raw_rows(store, &coll("rules")?).await?,
        })
    }

    fn active_frontends(&self) -> impl Iterator<Item = &Row> {
        self.frontends.iter().filter(|f| gb(f, "enabled"))
    }

    fn backend(&self, name: &str) -> Option<&Row> {
        self.backends.iter().find(|b| g(b, "name") == name)
    }
}

/// Web UI listener view used for conflict detection.
#[derive(Debug, Clone)]
pub struct WebListen {
    pub addrs: Vec<String>,
    pub ports: Vec<u16>,
}

fn wild(a: &str) -> bool {
    a == "0.0.0.0" || a == "::"
}

fn addrs_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // a wildcard covers every address of its own family
    a.contains(':') == b.contains(':') && (wild(a) || wild(b))
}

/// Everything wrong with the stored model, in words a user can act on.
/// `web` is what the web UI listens on (None = not known, e.g. a unit test).
pub fn problems(m: &Model, web: Option<&WebListen>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for f in m.active_frontends() {
        let (name, bind, port) = (g(f, "name"), g(f, "bind"), gn(f, "port"));
        let mode = g(f, "mode");
        let key = format!("{bind}:{port}");
        if let Some(other) = m
            .active_frontends()
            .filter(|o| g(o, "name") < name)
            .find(|o| gn(o, "port") == port && addrs_overlap(&g(o, "bind"), &bind))
        {
            out.push(format!(
                "Frontend {name:?} and {:?} both listen on port {port}: change the port or the listen address of one of them",
                g(other, "name")
            ));
        } else {
            seen.insert(key);
        }
        if let Some(w) = web {
            if w.ports.iter().any(|p| i64::from(*p) == port)
                && w.addrs.iter().any(|a| addrs_overlap(a, &bind))
            {
                out.push(format!(
                    "Frontend {name:?} wants port {port} on {bind}, which the Patronus web UI already uses. \
                     Move the web UI to another port or to a management address (System > Web UI), \
                     or give this frontend a different port or a listen address the web UI does not use"
                ));
            }
        }
        if gb(f, "tls") {
            if mode != "http" {
                out.push(format!(
                    "Frontend {name:?}: TLS termination needs mode http (tcp mode passes TLS through untouched)"
                ));
            }
            let c = g(f, "cert_file");
            if c.is_empty() || !c.starts_with('/') || c.contains("..") {
                out.push(format!(
                    "Frontend {name:?}: TLS needs the absolute path of a PEM file with the certificate and key"
                ));
            }
        }
        if gb(f, "redirect_https") && (mode != "http" || gb(f, "tls")) {
            out.push(format!(
                "Frontend {name:?}: the HTTPS redirect belongs on a plain-HTTP frontend (mode http, TLS off)"
            ));
        }
        let db = g(f, "default_backend");
        if db.is_empty() && !gb(f, "redirect_https") {
            let routed = m
                .rules
                .iter()
                .any(|r| gb(r, "enabled") && g(r, "frontend") == name);
            if !routed {
                out.push(format!(
                    "Frontend {name:?} has no default backend and no routing rule: it would have nowhere to send requests"
                ));
            }
        } else if !db.is_empty() {
            match m.backend(&db) {
                None => out.push(format!(
                    "Frontend {name:?}: default backend {db:?} does not exist (create the backend first)"
                )),
                Some(b) if g(b, "mode") != mode => out.push(format!(
                    "Frontend {name:?} (mode {mode}) and backend {db:?} (mode {}) must use the same mode",
                    g(b, "mode")
                )),
                _ => {}
            }
        }
    }
    for r in m.rules.iter().filter(|r| gb(r, "enabled")) {
        let (fe, be) = (g(r, "frontend"), g(r, "backend"));
        let Some(f) = m.frontends.iter().find(|f| g(f, "name") == fe) else {
            out.push(format!(
                "Routing rule for frontend {fe:?}: no such frontend"
            ));
            continue;
        };
        match m.backend(&be) {
            None => out.push(format!(
                "Routing rule for frontend {fe:?}: backend {be:?} does not exist"
            )),
            Some(b) if g(b, "mode") != g(f, "mode") => out.push(format!(
                "Routing rule {fe:?} -> {be:?}: the frontend and the backend use different modes"
            )),
            _ => {}
        }
        let (h, p) = (g(r, "host"), g(r, "path_prefix"));
        if h.is_empty() && p.is_empty() {
            out.push(format!(
                "Routing rule {fe:?} -> {be:?} has neither a host name nor a path: use the frontend's default backend instead"
            ));
        }
        if !p.is_empty() && !p.starts_with('/') {
            out.push(format!(
                "Routing rule {fe:?} -> {be:?}: the path must begin with /"
            ));
        }
        if !p.is_empty() && g(f, "mode") == "tcp" {
            out.push(format!(
                "Routing rule {fe:?} -> {be:?}: a path cannot be matched in tcp mode (use a host name)"
            ));
        }
    }
    for b in m.backends.iter().filter(|b| gb(b, "enabled")) {
        let name = g(b, "name");
        if g(b, "health") == "http" && g(b, "mode") == "tcp" {
            out.push(format!(
                "Backend {name:?}: an HTTP health check needs mode http"
            ));
        }
        let uri = g(b, "check_uri");
        if g(b, "health") == "http" && !uri.starts_with('/') {
            out.push(format!(
                "Backend {name:?}: the health check path must begin with /"
            ));
        }
    }
    for s in &m.servers {
        let (be, n) = (g(s, "backend"), g(s, "name"));
        if m.backend(&be).is_none() {
            out.push(format!("Server {n:?}: backend {be:?} does not exist"));
        }
        if m.servers
            .iter()
            .filter(|o| g(o, "backend") == be && g(o, "name") == n)
            .count()
            > 1
        {
            out.push(format!("Backend {be:?} has two servers named {n:?}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Things that are legal but probably not what the user wants (shown, never refused).
pub fn warnings(m: &Model) -> Vec<String> {
    let mut out = Vec::new();
    for b in m.backends.iter().filter(|b| gb(b, "enabled")) {
        let name = g(b, "name");
        let n = m
            .servers
            .iter()
            .filter(|s| g(s, "backend") == name && gb(s, "enabled"))
            .count();
        if n == 0 {
            out.push(format!(
                "Backend {name:?} has no enabled server: requests sent to it get a 503 answer until one is added"
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// haproxy.cfg
// ---------------------------------------------------------------------------

fn acl_name(i: usize) -> String {
    format!("r{i}")
}

/// `haproxy.cfg`. `sock` is the admin socket path (empty = none).
pub fn render_conf(s: &Settings, m: &Model, sock: &str) -> String {
    let mut c = lan::header("#", "haproxy");
    c.push_str(&format!(
        "global\n    maxconn {}\n    ssl-default-bind-options ssl-min-ver {} no-tls-tickets\n",
        s.n("max_conn"),
        s.s("tls_min")
    ));
    if s.b("stats") && !sock.is_empty() {
        c.push_str(&format!("    stats socket {sock} mode 600 level admin\n"));
    }
    c.push_str(&format!(
        "\ndefaults\n    timeout connect {}s\n    timeout client {}s\n    timeout server {}s\n    retries 2\n    option redispatch\n\n",
        s.n("timeout_connect"),
        s.n("timeout_client"),
        s.n("timeout_server")
    ));
    for f in m.active_frontends() {
        let name = g(f, "name");
        let mode = g(f, "mode");
        let addr = g(f, "bind");
        let bind = if addr.contains(':') {
            format!("[{addr}]")
        } else {
            addr.clone()
        };
        let mut b = format!("    bind {bind}:{}", gn(f, "port"));
        if gb(f, "tls") {
            b.push_str(&format!(" ssl crt {}", g(f, "cert_file")));
        }
        c.push_str(&format!("frontend fe_{name}\n    mode {mode}\n{b}\n"));
        if mode == "http" {
            c.push_str("    option forwardfor\n");
            if gb(f, "tls") {
                c.push_str("    http-request set-header X-Forwarded-Proto https\n");
            }
        } else {
            c.push_str("    tcp-request inspect-delay 5s\n    tcp-request content accept if { req_ssl_hello_type 1 }\n");
        }
        if gb(f, "redirect_https") {
            c.push_str("    http-request redirect scheme https code 301\n");
        }
        let mut rules: Vec<&Row> = m
            .rules
            .iter()
            .filter(|r| gb(r, "enabled") && g(r, "frontend") == name)
            .collect();
        rules.sort_by_key(|r| (gn(r, "priority"), gn(r, "id")));
        for (i, r) in rules.iter().enumerate() {
            let a = acl_name(i);
            let (h, p) = (g(r, "host"), g(r, "path_prefix"));
            let mut conds: Vec<String> = Vec::new();
            if !h.is_empty() {
                let hn = format!("{a}h");
                if mode == "http" {
                    c.push_str(&format!("    acl {hn} hdr(host),field(1,:) -i {h}\n"));
                } else {
                    c.push_str(&format!("    acl {hn} req_ssl_sni -i {h}\n"));
                }
                conds.push(hn);
            }
            if !p.is_empty() && mode == "http" {
                let pn = format!("{a}p");
                c.push_str(&format!("    acl {pn} path_beg {p}\n"));
                conds.push(pn);
            }
            c.push_str(&format!(
                "    use_backend be_{} if {}\n",
                g(r, "backend"),
                conds.join(" ")
            ));
        }
        let db = g(f, "default_backend");
        if !db.is_empty() {
            c.push_str(&format!("    default_backend be_{db}\n"));
        }
        c.push('\n');
    }
    for b in m.backends.iter().filter(|b| gb(b, "enabled")) {
        let name = g(b, "name");
        let mode = g(b, "mode");
        c.push_str(&format!(
            "backend be_{name}\n    mode {mode}\n    balance {}\n",
            g(b, "balance")
        ));
        let check = g(b, "health");
        if check == "http" {
            c.push_str(&format!("    option httpchk GET {}\n", g(b, "check_uri")));
        }
        let sticky = gb(b, "sticky") && mode == "http";
        if sticky {
            c.push_str("    cookie PATRONUS insert indirect nocache\n");
        }
        for sv in m
            .servers
            .iter()
            .filter(|s| g(s, "backend") == name && gb(s, "enabled"))
        {
            let addr = g(sv, "address");
            let a = if addr.contains(':') {
                format!("[{addr}]")
            } else {
                addr
            };
            let mut line = format!(
                "    server {} {a}:{} weight {}",
                g(sv, "name"),
                gn(sv, "port"),
                gn(sv, "weight")
            );
            if check != "none" {
                line.push_str(&format!(
                    " check inter {}s rise {} fall {}",
                    gn(b, "check_interval"),
                    gn(b, "rise"),
                    gn(b, "fall")
                ));
            }
            if sticky {
                line.push_str(&format!(" cookie {}", g(sv, "name")));
            }
            if gb(sv, "backup") {
                line.push_str(" backup");
            }
            c.push_str(&line);
            c.push('\n');
        }
        c.push('\n');
    }
    c
}

/// Run `haproxy -c -f FILE`: Ok(()) or the daemon's own complaint.
pub fn check_config(bin: &std::path::Path, file: &std::path::Path) -> Result<()> {
    let out = std::process::Command::new(bin)
        .args(["-c", "-f"])
        .arg(file)
        .output()
        .map_err(|e| Error::Service(format!("haproxy: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let mut msg = String::from_utf8_lossy(&out.stderr).to_string();
    msg.push_str(&String::from_utf8_lossy(&out.stdout));
    let msg: Vec<&str> = msg
        .lines()
        .filter(|l| l.contains("[ALERT]") || l.contains("[ERROR]") || l.contains("error"))
        .take(6)
        .collect();
    Err(Error::Config(format!(
        "Invalid reverse proxy configuration (haproxy -c refused it; the running proxy was left alone): {}",
        if msg.is_empty() {
            "no details".to_string()
        } else {
            msg.join(" | ")
        }
    )))
}

pub async fn web_listen(store: &ConfigStore) -> WebListen {
    let w = patronus_config::webui::resolve(Some(store)).await;
    WebListen {
        addrs: w.listen.clone(),
        ports: w.all_ports(),
    }
}

// ---------------------------------------------------------------------------
// statistics
// ---------------------------------------------------------------------------

/// Parse `show stat` CSV into rows of {proxy, server, status, scur, stot, bin, bout, ...}.
pub fn parse_stats(csv: &str) -> Vec<Value> {
    let mut lines = csv.lines();
    let Some(head) = lines.next() else {
        return Vec::new();
    };
    let cols: Vec<&str> = head.trim_start_matches("# ").split(',').collect();
    let mut out = Vec::new();
    for l in lines {
        let f: Vec<&str> = l.split(',').collect();
        if f.len() < 4 {
            continue;
        }
        let mut m = Map::new();
        for (i, c) in cols.iter().enumerate() {
            if let Some(v) = f.get(i) {
                if matches!(
                    *c,
                    "pxname"
                        | "svname"
                        | "status"
                        | "scur"
                        | "stot"
                        | "bin"
                        | "bout"
                        | "rate"
                        | "chkfail"
                        | "check_status"
                        | "weight"
                        | "act"
                        | "bck"
                        | "hrsp_2xx"
                        | "hrsp_5xx"
                        | "ereq"
                        | "econ"
                        | "dreq"
                ) {
                    m.insert((*c).into(), Value::String((*v).into()));
                }
            }
        }
        out.push(Value::Object(m));
    }
    out
}

fn admin_command(sock: &std::path::Path, cmd: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(sock)
        .map_err(|e| Error::Service(format!("the proxy is not running (admin socket: {e})")))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    s.write_all(format!("{cmd}\n").as_bytes())
        .map_err(|e| Error::Service(format!("admin socket: {e}")))?;
    let mut out = String::new();
    s.read_to_string(&mut out)
        .map_err(|e| Error::Service(format!("admin socket: {e}")))?;
    Ok(out)
}

pub fn sock_path(sup: &Supervisor) -> std::path::PathBuf {
    sup.paths.run_dir.join("haproxy.sock")
}

// ---------------------------------------------------------------------------
// the page
// ---------------------------------------------------------------------------

pub struct RevProxySvc;

fn s_of(body: &Value, k: &str) -> String {
    match body.get(k) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

#[async_trait]
impl Svc for RevProxySvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn get(&self, store: &ConfigStore) -> Result<Value> {
        let spec = &SPEC;
        let mut cols = Map::new();
        for c in spec.colls {
            cols.insert(c.key.into(), Value::Array(svc::list_rows(store, c).await?));
        }
        let m = Model::load(store).await?;
        let web = web_listen(store).await;
        Ok(json!({
            "settings": svc::get_settings(store, spec).await?,
            "collections": cols,
            "problems": problems(&m, Some(&web)),
            "warnings": warnings(&m),
        }))
    }

    fn action_applier(&self) -> bool {
        true
    }

    fn action_applies(&self, name: &str) -> bool {
        name == "publish"
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        match name {
            "check" => {
                let m = Model::load(store).await?;
                let web = web_listen(store).await;
                let p = problems(&m, Some(&web));
                let w = warnings(&m);
                let s = Settings::load(store, &SPEC).await?;
                let mut haproxy = Value::Null;
                if p.is_empty() {
                    if let Some(bin) = which("haproxy") {
                        let sup = Supervisor::detect();
                        let tmp = sup.paths.state_dir.join("haproxy.check.cfg");
                        std::fs::create_dir_all(&sup.paths.state_dir).ok();
                        std::fs::write(&tmp, render_conf(&s, &m, ""))
                            .map_err(|e| Error::Service(format!("write {}: {e}", tmp.display())))?;
                        let r = check_config(&bin, &tmp);
                        let _ = std::fs::remove_file(&tmp);
                        haproxy = match r {
                            Ok(()) => json!("valid"),
                            Err(e) => json!(e.to_string()),
                        };
                    } else {
                        haproxy = json!("haproxy is not installed (emerge net-proxy/haproxy)");
                    }
                }
                Ok(json!({"problems": p, "warnings": w, "haproxy": haproxy}))
            }
            "stats" => {
                let sup = Supervisor::detect();
                let sock = sock_path(&sup);
                let csv = admin_command(&sock, "show stat")?;
                let rows = parse_stats(&csv);
                Ok(json!({"running": sup.is_running(svc::DAEMON_SERVICE, INSTANCE), "stats": rows}))
            }
            "publish" => publish(store, body).await,
            _ => Err(invalid(format!("request: no action {name:?}"))),
        }
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let c = *svc::find_coll(&SPEC, coll)?;
        if coll == "rules" || coll == "servers" || coll == "frontends" {
            // cheap checks that need no other row
            if let Some(p) = body.get("path_prefix").and_then(Value::as_str) {
                if !p.is_empty() && !p.starts_with('/') {
                    return Err(invalid("path begins with (must start with /)"));
                }
            }
        }
        if coll == "frontends" {
            check_listener(store, id, body).await?;
        }
        svc::save_row(store, &c, id, body).await
    }
}

/// Refuse a listener that clashes with the web UI or another frontend when it is SAVED (not only
/// when the feature is switched on), with the explanation.
async fn check_listener(store: &ConfigStore, id: Option<i64>, body: &Value) -> Result<()> {
    let mut m = Model::load(store).await?;
    let cur = id.and_then(|i| {
        m.frontends
            .iter()
            .find(|r| r.get("id").and_then(Value::as_i64) == Some(i))
            .cloned()
    });
    m.frontends
        .retain(|r| r.get("id").and_then(Value::as_i64) != id || id.is_none());
    let mut row = cur.unwrap_or_default();
    for (k, d) in [("bind", "0.0.0.0"), ("enabled", "1"), ("mode", "http")] {
        row.entry(k.to_string()).or_insert_with(|| json!(d));
    }
    if let Some(o) = body.as_object() {
        for (k, v) in o {
            let t = match v {
                Value::String(s) => s.trim().to_string(),
                Value::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            let t = if k == "enabled" && t == "true" {
                "1".into()
            } else {
                t
            };
            if t.is_empty() && matches!(k.as_str(), "bind" | "mode") {
                continue;
            }
            row.insert(k.clone(), json!(t));
        }
    }
    if row
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
    {
        return Ok(()); // the row validation reports the missing name
    }
    let name = g(&row, "name");
    m.frontends.push(row);
    let web = web_listen(store).await;
    let bad: Vec<String> = problems(&m, Some(&web))
        .into_iter()
        .filter(|p| {
            p.starts_with(&format!("Frontend {name:?} wants port"))
                || (p.contains("both listen on port") && p.contains(&format!("{name:?}")))
        })
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(invalid(bad.join("; ")))
    }
}

/// "Publish a LAN service": frontend + backend + server + rule in one step.
/// Body: `name`, `address`, `port` (LAN server), `public_port` (default 80 or
/// 443 with TLS), `host` (optional name to route by), `tls` + `cert_file`,
/// `interface` (default @wan).
async fn publish(store: &ConfigStore, body: &Value) -> Result<Value> {
    let name = s_of(body, "name");
    let address = s_of(body, "address");
    let port = s_of(body, "port");
    if name.is_empty() || address.is_empty() || port.is_empty() {
        return Err(invalid(
            "request: publish needs name, address (the LAN server) and port",
        ));
    }
    let tls = lan::flag(&s_of(body, "tls"));
    let public = {
        let p = s_of(body, "public_port");
        if p.is_empty() {
            (if tls { "443" } else { "80" }).to_string()
        } else {
            p
        }
    };
    let (cb, cs, cf, cr) = (
        *svc::find_coll(&SPEC, "backends")?,
        *svc::find_coll(&SPEC, "servers")?,
        *svc::find_coll(&SPEC, "frontends")?,
        *svc::find_coll(&SPEC, "rules")?,
    );
    let beid = svc::save_row(
        store,
        &cb,
        None,
        &json!({"name": name, "mode": "http", "health": "tcp"}),
    )
    .await?;
    let sv =
        json!({"backend": name, "name": format!("{name}-1"), "address": address, "port": port});
    let sid = match svc::save_row(store, &cs, None, &sv).await {
        Ok(i) => i,
        Err(e) => {
            let _ = svc::delete_row(store, &cb, beid).await;
            return Err(e);
        }
    };
    let mut fe = json!({"name": name, "port": public, "tls": tls, "default_backend": name});
    for k in ["cert_file", "interface", "bind"] {
        let v = s_of(body, k);
        if !v.is_empty() {
            fe[k] = json!(v);
        }
    }
    let host = s_of(body, "host");
    let fid = match svc::save_row(store, &cf, None, &fe).await {
        Ok(i) => i,
        Err(e) => {
            let _ = svc::delete_row(store, &cs, sid).await;
            let _ = svc::delete_row(store, &cb, beid).await;
            return Err(e);
        }
    };
    if !host.is_empty() {
        // route by name; the default backend stays as the catch-all of this listener
        let r = json!({"frontend": name, "host": host, "backend": name});
        if let Err(e) = svc::save_row(store, &cr, None, &r).await {
            let _ = svc::delete_row(store, &cf, fid).await;
            let _ = svc::delete_row(store, &cs, sid).await;
            let _ = svc::delete_row(store, &cb, beid).await;
            return Err(e);
        }
    }
    // switch the feature on: publishing is a request to serve it
    svc::put_settings(store, &SPEC, &json!({"enabled": true})).await?;
    Ok(json!({
        "published": name, "frontend_id": fid, "port": public,
        "note": "the listener, the backend, the firewall rule and the service are set up"
    }))
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RevProxyApplier {
    sup: Supervisor,
}

impl Default for RevProxyApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl RevProxyApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

#[async_trait]
impl Applier for RevProxyApplier {
    fn name(&self) -> &'static str {
        "revproxy"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        let m = Model::load(store).await?;
        if !s.b("enabled") || m.active_frontends().next().is_none() {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            rep.applied(if was {
                "reverse proxy stopped"
            } else {
                "reverse proxy is off"
            });
            return Ok(rep);
        }
        let web = web_listen(store).await;
        let p = problems(&m, Some(&web));
        if !p.is_empty() {
            return Err(invalid(format!("reverse proxy: {}", p.join("; "))));
        }
        let bin = which("haproxy").ok_or_else(|| {
            Error::Service(
                "the reverse proxy needs haproxy, which is not installed (emerge net-proxy/haproxy, USE=reverse-proxy)"
                    .into(),
            )
        })?;
        let conf = self.sup.paths.state_dir.join("haproxy.cfg");
        let cand = self.sup.paths.state_dir.join("haproxy.cfg.candidate");
        let sock = sock_path(&self.sup);
        let text = render_conf(&s, &m, &sock.to_string_lossy());
        std::fs::create_dir_all(&self.sup.paths.state_dir)
            .map_err(|e| Error::Service(format!("state dir: {e}")))?;
        std::fs::create_dir_all(&self.sup.paths.run_dir)
            .map_err(|e| Error::Service(format!("run dir: {e}")))?;
        // validate the candidate first: a refused config never replaces the live one
        std::fs::write(&cand, &text)
            .map_err(|e| Error::Service(format!("write {}: {e}", cand.display())))?;
        let checked = check_config(&bin, &cand);
        let _ = std::fs::remove_file(&cand);
        checked?;
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "-db".into(),
                "-f".into(),
                conf.to_string_lossy().into(),
            ],
            vec![(conf, text, 0o640)],
        )
        .await?;
        rep.applied(format!(
            "haproxy {} ({} frontend(s), {} backend(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            m.active_frontends().count(),
            m.backends.iter().filter(|b| gb(b, "enabled")).count()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# reverse proxy off\n".into());
        }
        let m = Model::load(store).await?;
        Ok(render_conf(&s, &m, "/run/patronus/haproxy.sock"))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("haproxy").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> Row {
        let mut m = Map::new();
        for (k, v) in pairs {
            m.insert((*k).into(), json!(v));
        }
        m
    }

    fn settings() -> Settings {
        let mut m = Map::new();
        for (k, v) in [
            ("enabled", "1"),
            ("max_conn", "4000"),
            ("timeout_connect", "5"),
            ("timeout_client", "30"),
            ("timeout_server", "30"),
            ("tls_min", "TLSv1.2"),
            ("stats", "1"),
        ] {
            m.insert(k.into(), json!(v));
        }
        Settings(m)
    }

    fn model() -> Model {
        Model {
            frontends: vec![row(&[
                ("id", "1"),
                ("name", "web"),
                ("enabled", "1"),
                ("bind", "0.0.0.0"),
                ("port", "80"),
                ("mode", "http"),
                ("tls", "0"),
                ("default_backend", "app"),
            ])],
            backends: vec![row(&[
                ("name", "app"),
                ("enabled", "1"),
                ("mode", "http"),
                ("balance", "leastconn"),
                ("health", "http"),
                ("check_uri", "/health"),
                ("check_interval", "3"),
                ("rise", "2"),
                ("fall", "3"),
                ("sticky", "0"),
            ])],
            servers: vec![
                row(&[
                    ("backend", "app"),
                    ("name", "a"),
                    ("address", "192.168.50.10"),
                    ("port", "8080"),
                    ("weight", "100"),
                    ("backup", "0"),
                    ("enabled", "1"),
                ]),
                row(&[
                    ("backend", "app"),
                    ("name", "b"),
                    ("address", "192.168.50.11"),
                    ("port", "8080"),
                    ("weight", "50"),
                    ("backup", "1"),
                    ("enabled", "1"),
                ]),
            ],
            rules: vec![],
        }
    }

    #[test]
    fn config_follows_the_model() {
        let c = render_conf(&settings(), &model(), "/run/h.sock");
        assert!(c.contains("frontend fe_web\n    mode http\n    bind 0.0.0.0:80\n"));
        assert!(c.contains("default_backend be_app"));
        assert!(c.contains("balance leastconn"));
        assert!(c.contains("option httpchk GET /health"));
        assert!(c.contains("server a 192.168.50.10:8080 weight 100 check inter 3s rise 2 fall 3\n"));
        assert!(c.contains(
            "server b 192.168.50.11:8080 weight 50 check inter 3s rise 2 fall 3 backup\n"
        ));
        assert!(c.contains("stats socket /run/h.sock mode 600 level admin"));
        assert!(c.contains("timeout connect 5s"));
        assert!(
            problems(&model(), None).is_empty(),
            "{:?}",
            problems(&model(), None)
        );
    }

    #[test]
    fn host_and_path_rules_and_tls() {
        let mut m = model();
        m.frontends[0].insert("tls".into(), json!("1"));
        m.frontends[0].insert("cert_file".into(), json!("/etc/ssl/site.pem"));
        m.frontends[0].insert("port".into(), json!("443"));
        m.backends.push(row(&[
            ("name", "api"),
            ("enabled", "1"),
            ("mode", "http"),
            ("balance", "roundrobin"),
            ("health", "none"),
        ]));
        m.servers.push(row(&[
            ("backend", "api"),
            ("name", "x"),
            ("address", "10.0.0.5"),
            ("port", "9000"),
            ("weight", "100"),
            ("enabled", "1"),
        ]));
        m.rules.push(row(&[
            ("id", "1"),
            ("frontend", "web"),
            ("host", "api.example.org"),
            ("path_prefix", "/v1"),
            ("backend", "api"),
            ("priority", "10"),
            ("enabled", "1"),
        ]));
        let c = render_conf(&settings(), &m, "");
        assert!(c.contains("bind 0.0.0.0:443 ssl crt /etc/ssl/site.pem"));
        assert!(c.contains("acl r0h hdr(host),field(1,:) -i api.example.org"));
        assert!(c.contains("acl r0p path_beg /v1"));
        assert!(c.contains("use_backend be_api if r0h r0p"));
        assert!(!c.contains("stats socket"));
        assert!(problems(&m, None).is_empty());
    }

    #[test]
    fn problems_are_explained() {
        let mut m = model();
        // web UI clash
        let web = WebListen {
            addrs: vec!["0.0.0.0".into()],
            ports: vec![443, 80],
        };
        let p = problems(&m, Some(&web));
        assert!(
            p.iter()
                .any(|x| x.contains("web UI already uses") && x.contains("port 80")),
            "{p:?}"
        );
        // missing backend / empty backend / mode clash
        m.frontends[0].insert("default_backend".into(), json!("nope"));
        assert!(problems(&m, None)
            .iter()
            .any(|x| x.contains("does not exist")));
        m.frontends[0].insert("default_backend".into(), json!("app"));
        m.servers.clear();
        assert!(warnings(&m).iter().any(|x| x.contains("no enabled server")));
        assert!(problems(&m, None).is_empty());
        // TLS without a cert
        let mut m = model();
        m.frontends[0].insert("tls".into(), json!("1"));
        assert!(problems(&m, None).iter().any(|x| x.contains("PEM")));
        // two frontends on the same port
        let mut m = model();
        let mut f2 = m.frontends[0].clone();
        f2.insert("name".into(), json!("web2"));
        m.frontends.push(f2);
        assert!(problems(&m, None)
            .iter()
            .any(|x| x.contains("both listen on port 80")));
        // a specific address does not clash with another specific one
        m.frontends[1].insert("bind".into(), json!("10.0.0.1"));
        m.frontends[0].insert("bind".into(), json!("10.0.0.2"));
        assert!(!problems(&m, None).iter().any(|x| x.contains("both listen")));
    }

    #[test]
    fn addresses_overlap_like_the_kernel_says() {
        assert!(addrs_overlap("0.0.0.0", "10.0.0.1"));
        assert!(addrs_overlap("10.0.0.1", "0.0.0.0"));
        assert!(addrs_overlap("10.0.0.1", "10.0.0.1"));
        assert!(!addrs_overlap("10.0.0.1", "10.0.0.2"));
        assert!(!addrs_overlap("0.0.0.0", "::"));
        assert!(addrs_overlap("::", "fd00::1"));
    }

    #[test]
    fn stats_csv_is_parsed() {
        let csv = "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail\n\
                   be_app,a,0,0,1,1,,5,100,200,,,,0,0,0,0,UP,100,1,0,0\n\
                   be_app,b,0,0,0,0,,0,0,0,,,,0,0,0,0,DOWN,100,1,0,3\n";
        let r = parse_stats(csv);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["svname"], "a");
        assert_eq!(r[0]["status"], "UP");
        assert_eq!(r[1]["status"], "DOWN");
        assert_eq!(r[0]["stot"], "5");
    }

    #[tokio::test]
    async fn publish_creates_everything_and_rolls_back_a_half_made_backend() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let r = RevProxySvc
            .action(
                &store,
                "publish",
                &json!({"name": "blog", "address": "192.168.50.20", "port": 8080, "host": "blog.example.org"}),
            )
            .await
            .unwrap();
        assert_eq!(r["port"], "80");
        let m = Model::load(&store).await.unwrap();
        assert_eq!(m.frontends.len(), 1);
        assert_eq!(g(&m.frontends[0], "default_backend"), "blog");
        assert_eq!(m.servers.len(), 1);
        assert_eq!(m.rules.len(), 1);
        assert!(problems(&m, None).is_empty(), "{:?}", problems(&m, None));
        let s = Settings::load(&store, &SPEC).await.unwrap();
        assert!(s.b("enabled"));
        // a bad address leaves no orphan backend behind
        assert!(RevProxySvc
            .action(
                &store,
                "publish",
                &json!({"name": "bad", "address": "not an ip!", "port": 1})
            )
            .await
            .is_err());
        let m = Model::load(&store).await.unwrap();
        assert!(m.backend("bad").is_none());
        // same name twice is refused
        assert!(RevProxySvc
            .action(
                &store,
                "publish",
                &json!({"name": "blog", "address": "10.0.0.1", "port": 1})
            )
            .await
            .is_err());
    }
}
