//! TFTP server (USE=tftp): network boot (PXE/iPXE boot loaders, kernels,
//! answer files), firmware and configuration transfers for devices that speak
//! nothing else (IP phones, switches, access points, embedded boards), like the
//! TFTP packages of pfSense and OPNsense and OpenWrt's dnsmasq TFTP.
//!
//! There is no external daemon: the server is `patronus tftp run`, run by the
//! supervisor (`patronus-daemon@tftp`, OpenRC and systemd) from a generated JSON
//! file, and its engine is in this module ([`engine`], RFC 1350 with the option
//! extensions of RFC 2347/2348/2349: `blksize`, `timeout`, `tsize`; binary
//! (`octet`) mode only). A built-in engine keeps the router tier small and gives
//! one behaviour on every tier.
//!
//! Safety, because TFTP has no authentication at all:
//!
//! * read-only by default; uploads (`allow_write`) create new files only unless
//!   `overwrite` is on, are written to a hidden temporary file and published
//!   atomically, and are capped (`max_write_kb`);
//! * every file name is resolved *beneath* the root directory with `openat2(2)`
//!   (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`) against a
//!   directory descriptor opened before privileges are dropped, so `..`, absolute
//!   names and symlinks cannot leave it; hidden names (leading dot) are refused;
//! * the process drops to an unprivileged account (`run_as`) keeping only
//!   `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` (late binds, `SO_BINDTODEVICE`);
//! * it listens per interface (every IPv4 address of the chosen interfaces,
//!   bound to the device), optionally only answers listed client networks, and
//!   bounds concurrent transfers (`max_sessions`).
//!
//! A transfer moves to a fresh UDP port on both sides, so the firewall opens the
//! request port and the typed `data_ports` range on the serving interfaces only
//! (`patronus_firewall::svc_rules`, restricted to the client networks when set).
//! IPv6 is not served.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const INSTANCE: &str = "tftp";

/// Where a root directory may live (the setting is free text; this keeps it away
/// from system directories).
pub const ROOT_PREFIXES: &[&str] = &["/var/lib/", "/srv/", "/mnt/", "/media/", "/opt/"];

static FIELDS: [Field; 14] = [
    Field::new("enabled", "TFTP server", Kind::Bool).def("0"),
    Field::new("interfaces", "Serve on", Kind::Ifaces)
        .def("@lan")
        .help("interfaces whose IPv4 addresses answer requests, e.g. @lan or @lan,@opt1 (never the WAN unless you list it)"),
    Field::new("port", "Request port", Kind::Int(1, 65535))
        .def("69")
        .help("UDP port that takes the requests (69 is the standard)"),
    Field::new("root", "Root directory", Kind::Token)
        .def("/var/lib/patronus/tftp")
        .help("files served and received live here; under /var/lib, /srv, /mnt, /media, /opt or /tftpboot"),
    Field::new("allow_write", "Allow uploads (WRQ)", Kind::Bool)
        .def("0")
        .help("off = read only; TFTP has no login, so anyone allowed on the interface can upload"),
    Field::new("overwrite", "Uploads may replace files", Kind::Bool)
        .def("0")
        .help("off = an upload to an existing name is refused"),
    Field::new("max_write_kb", "Largest upload (KiB)", Kind::Int(1, 1_048_576))
        .def("16384")
        .help("an upload that grows past this is aborted and removed"),
    Field::new("blksize_max", "Largest block size (bytes)", Kind::Int(512, 65464))
        .def("1468")
        .help("RFC 2348 negotiation ceiling; 1468 fits a 1500-byte MTU without fragmentation"),
    Field::new("timeout", "Retransmit timeout (s)", Kind::Int(1, 60)).def("5"),
    Field::new("retries", "Retransmissions before giving up", Kind::Int(1, 20)).def("5"),
    Field::new("max_sessions", "Concurrent transfers", Kind::Int(1, 256))
        .def("16")
        .help("more requests than this are answered with a busy error"),
    Field::new("data_ports", "Data ports", Kind::Ports)
        .def("49152-49407")
        .help("each transfer continues from one of these UDP ports (must hold at least as many ports as concurrent transfers)"),
    Field::new("run_as", "Run as user", Kind::Token)
        .def("nobody")
        .help("account the server drops to after binding; it must be able to read the files"),
    Field::new("ui_upload_kb", "Largest upload through this page (KiB)", Kind::Int(1, 1024))
        .def("1024")
        .help("bigger files: put them in the root directory with scp/sftp"),
];

static CLIENT_FIELDS: [Field; 3] = [
    Field::new("cidr", "Client network", Kind::Cidr4)
        .req()
        .help("an IPv4 network (a single host is /32); with none listed every client on the serving interfaces may use the server"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "tftp",
    title: "TFTP server",
    blurb: "Serve boot loaders, kernels and configuration files to devices over TFTP, and \
            optionally receive uploads. Read only by default. TFTP has no login: restrict it to \
            the interfaces and client networks that need it.",
    applier: "tftp",
    fields: &FIELDS,
    colls: &[Coll {
        key: "clients",
        title: "Allowed client networks",
        table: "tftp_clients",
        fields: &CLIENT_FIELDS,
        unique: Some("cidr"),
    }],
    actions: &[],
};

pub struct TftpSvc;

#[async_trait]
impl Svc for TftpSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        if let Some(r) = body.get("root").and_then(Value::as_str) {
            if !r.trim().is_empty() {
                check_root(r.trim())?;
            }
        }
        svc::put_settings(store, &SPEC, body).await
    }

    /// `files` (list), `upload` (`{name, data: base64, overwrite?}`), `delete`
    /// (`{name}`): the root directory as the page's file manager sees it.
    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let root = s.s("root");
        check_root(&root)?;
        let root = Path::new(&root);
        match name {
            "files" => files::list(root),
            "upload" => {
                let n = body["name"].as_str().unwrap_or("");
                let data = body["data"].as_str().unwrap_or("");
                let limit = (s.n("ui_upload_kb").max(1) as usize) * 1024;
                use base64::Engine as _;
                if data.len() > limit * 4 / 3 + 8 {
                    return Err(invalid(format!(
                        "upload: larger than {} KiB (copy big files into {} directly)",
                        limit / 1024,
                        root.display()
                    )));
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(data.trim())
                    .map_err(|_| invalid("upload: data is not base64"))?;
                if bytes.len() > limit {
                    return Err(invalid(format!(
                        "upload: {} bytes is more than the {} KiB this page accepts",
                        bytes.len(),
                        limit / 1024
                    )));
                }
                let overwrite = body["overwrite"].as_bool().unwrap_or(false);
                files::upload(root, n, &bytes, overwrite)
            }
            "delete" => files::delete(root, body["name"].as_str().unwrap_or("")),
            _ => Err(invalid(format!("request: no action {name:?}"))),
        }
    }
}

/// Is `root` an acceptable root directory?
pub fn check_root(root: &str) -> Result<()> {
    let bad = |why: &str| invalid(format!("root directory {root:?} ({why})"));
    if !root.starts_with('/') || root.len() > 64 {
        return Err(bad("an absolute path of at most 64 characters"));
    }
    if root
        .split('/')
        .skip(1)
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(bad("no empty, . or .. parts and no trailing slash"));
    }
    let below = |p: &str| root.starts_with(p) && root.len() > p.len();
    if !(ROOT_PREFIXES.iter().any(|p| below(p)) || root == "/tftpboot" || below("/tftpboot/")) {
        return Err(bad(
            "must be below /var/lib, /srv, /mnt, /media, /opt or /tftpboot",
        ));
    }
    // the state directory holds the configuration database and keys
    if root.starts_with("/var/lib/patronus")
        && root != "/var/lib/patronus/tftp"
        && !root.starts_with("/var/lib/patronus/tftp/")
    {
        return Err(bad("the Patronus state directory is not a TFTP root"));
    }
    Ok(())
}

/// The effective, validated configuration the engine runs with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TftpConf {
    pub port: u16,
    pub root: String,
    /// Devices (roles resolved) whose IPv4 addresses answer.
    pub listen: Vec<String>,
    pub allow_write: bool,
    pub overwrite: bool,
    pub max_write_kb: u64,
    pub blksize_max: u32,
    pub timeout: u32,
    pub retries: u32,
    pub max_sessions: u32,
    pub data_ports: Vec<(u16, u16)>,
    pub run_as: String,
    /// Client networks (empty = anyone on the serving interfaces).
    pub clients: Vec<String>,
}

pub fn render(c: &TftpConf) -> String {
    let mut s = serde_json::to_string_pretty(c).unwrap_or_default();
    s.push('\n');
    s
}

pub async fn load(store: &ConfigStore) -> Result<TftpConf> {
    let s = Settings::load(store, &SPEC).await?;
    let root = s.s("root");
    check_root(&root)?;
    let port = s.n("port") as u16;
    let data_ports = svc::parse_ports(&s.s("data_ports"))
        .map_err(|e| invalid(format!("TFTP data ports: {e}")))?;
    let width: u64 = data_ports.iter().map(|&(a, b)| (b - a) as u64 + 1).sum();
    let max_sessions = s.n("max_sessions") as u32;
    if width < max_sessions as u64 {
        return Err(invalid(format!(
            "TFTP data ports hold {width} ports but {max_sessions} concurrent transfers are allowed"
        )));
    }
    if data_ports.iter().any(|&(a, b)| (a..=b).contains(&port)) {
        return Err(invalid(format!(
            "TFTP data ports must not contain the request port {port}"
        )));
    }
    let mut listen: Vec<String> = Vec::new();
    for spec in s.s("interfaces").split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        for d in lan::resolve_iface(store, spec).await? {
            if !listen.contains(&d) {
                listen.push(d);
            }
        }
    }
    let mut clients = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if lan::flag(r["enabled"].as_str().unwrap_or("")) {
            let c = r["cidr"].as_str().unwrap_or("").to_string();
            if !c.is_empty() {
                clients.push(c);
            }
        }
    }
    let run_as = s.s("run_as");
    if run_as.is_empty() {
        return Err(invalid("TFTP run as user (required)"));
    }
    Ok(TftpConf {
        port,
        root,
        listen,
        allow_write: s.b("allow_write"),
        overwrite: s.b("overwrite"),
        max_write_kb: s.n("max_write_kb").max(1) as u64,
        blksize_max: s.n("blksize_max") as u32,
        timeout: s.n("timeout") as u32,
        retries: s.n("retries") as u32,
        max_sessions,
        data_ports,
        run_as,
        clients,
    })
}

#[derive(Clone)]
pub struct TftpApplier {
    sup: Supervisor,
    bin: Option<PathBuf>,
}

impl Default for TftpApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            bin: None,
        }
    }
}

impl TftpApplier {
    pub fn with(sup: Supervisor, bin: Option<PathBuf>) -> Self {
        Self { sup, bin }
    }
    fn patronus(&self) -> Option<PathBuf> {
        // the router tier ships the multi-call binary as `patronus-cli` only
        self.bin
            .clone()
            .or_else(|| which("patronus"))
            .or_else(|| which("patronus-cli"))
    }
    fn conf_path(&self) -> PathBuf {
        self.sup.paths.state_dir.join("tftp.json")
    }
    pub fn stats_path(&self) -> PathBuf {
        self.sup.paths.run_dir.join("tftp.stats")
    }
}

/// Create the root directory when it is missing. As root it is owned by the web
/// account (uploads from the page) and grouped with the server's account (reads
/// and writes of the server), mode 0775.
fn ensure_root(conf: &TftpConf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = Path::new(&conf.root);
    if root.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(root)
        .map_err(|e| Error::Service(format!("create {}: {e}", root.display())))?;
    if nix::unistd::geteuid().is_root() {
        let uid = nix::unistd::User::from_name("patronus")
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
            .unwrap_or(0);
        let gid = nix::unistd::User::from_name(&conf.run_as)
            .ok()
            .flatten()
            .map(|u| u.gid.as_raw());
        let _ = std::os::unix::fs::chown(root, Some(uid), gid);
        let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o775));
    }
    Ok(())
}

#[async_trait]
impl Applier for TftpApplier {
    fn name(&self) -> &'static str {
        "tftp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("TFTP server stopped");
            } else {
                rep.applied("TFTP server is off");
            }
            return Ok(rep);
        }
        let conf = load(store).await?;
        if conf.listen.is_empty() {
            return Err(invalid(
                "TFTP server: no interface to serve on (set 'Serve on' to @lan or a device)",
            ));
        }
        if nix::unistd::geteuid().is_root()
            && nix::unistd::User::from_name(&conf.run_as)
                .ok()
                .flatten()
                .is_none()
        {
            return Err(invalid(format!(
                "TFTP server: the account {:?} does not exist",
                conf.run_as
            )));
        }
        let bin = self.patronus().ok_or_else(|| {
            Error::Service("the TFTP server needs the `patronus` binary on the PATH".into())
        })?;
        ensure_root(&conf)?;
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        let cp = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "tftp".into(),
                "run".into(),
                "--conf".into(),
                cp.to_string_lossy().into(),
                "--stats".into(),
                self.stats_path().to_string_lossy().into(),
            ],
            vec![(cp, render(&conf), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "TFTP server {} (port {}, {} interface(s), {})",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            conf.port,
            conf.listen.len(),
            if conf.allow_write {
                "uploads allowed"
            } else {
                "read only"
            }
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# TFTP server off\n".into());
        }
        Ok(format!("## tftp.json\n{}", render(&load(store).await?)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let stats: Value = std::fs::read_to_string(self.stats_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null);
        let root = s.s("root");
        let listing = if check_root(&root).is_ok() {
            files::list(Path::new(&root)).ok()
        } else {
            None
        };
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": self.patronus().is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "mode": if s.b("allow_write") { "uploads allowed" } else { "read only" },
            "root": root,
            "files": listing.as_ref().map(|l| l["files"].as_array().map(|a| a.len()).unwrap_or(0)),
            "stats": stats,
        }))
    }
}

/// The root directory as a file manager: list, upload, delete. Runs in the web
/// account (the directory is writable by it); names are checked part by part.
pub mod files {
    use super::invalid;
    use patronus_core::{Error, Result};
    use serde_json::{json, Value};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    pub const MAX_ENTRIES: usize = 500;
    const MAX_DEPTH: usize = 3;

    /// One file-name part: letters, digits and `. _ + -`, not starting with a dot.
    pub fn valid_part(p: &str) -> bool {
        !p.is_empty()
            && p.len() <= 100
            && !p.starts_with('.')
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    }

    /// `a/b/c.bin` -> parts, at most three, each valid.
    pub fn parts(name: &str) -> Result<Vec<String>> {
        let ps: Vec<String> = name
            
            .trim_start_matches('/')
            .split('/')
            .map(String::from)
            .collect();
        if ps.is_empty() || ps.len() > MAX_DEPTH || ps.iter().any(|p| !valid_part(p)) {
            return Err(invalid(format!(
                "file name {name:?} (letters, digits and . _ + - in up to {MAX_DEPTH} parts separated by /, no part starting with a dot)"
            )));
        }
        Ok(ps)
    }

    fn walk(dir: &Path, rel: &str, depth: usize, out: &mut Vec<Value>, truncated: &mut bool) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut ents: Vec<_> = rd.flatten().collect();
        ents.sort_by_key(|e| e.file_name());
        for e in ents {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let Ok(md) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            let rp = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if md.is_file() {
                if out.len() >= MAX_ENTRIES {
                    *truncated = true;
                    return;
                }
                out.push(json!({"name": rp, "size": md.len(), "modified": md.mtime()}));
            } else if md.is_dir() && depth + 1 < MAX_DEPTH {
                walk(&e.path(), &rp, depth + 1, out, truncated);
            }
        }
    }

    pub fn list(root: &Path) -> Result<Value> {
        let mut out = Vec::new();
        let mut truncated = false;
        walk(root, "", 0, &mut out, &mut truncated);
        Ok(json!({
            "root": root.to_string_lossy(),
            "exists": root.is_dir(),
            "files": out,
            "truncated": truncated,
        }))
    }

    fn resolve(root: &Path, ps: &[String]) -> PathBuf {
        let mut p = root.to_path_buf();
        for part in ps {
            p.push(part);
        }
        p
    }

    /// No part of `root/ps[..n]` may be a symlink.
    fn no_symlinks(root: &Path, ps: &[String]) -> Result<()> {
        let mut p = root.to_path_buf();
        for part in ps {
            p.push(part);
            if let Ok(md) = std::fs::symlink_metadata(&p) {
                if md.file_type().is_symlink() {
                    return Err(invalid(format!("{} is a symbolic link", part)));
                }
            }
        }
        Ok(())
    }

    pub fn upload(root: &Path, name: &str, data: &[u8], overwrite: bool) -> Result<Value> {
        let ps = parts(name)?;
        if !root.is_dir() {
            std::fs::create_dir_all(root).map_err(|e| {
                Error::Service(format!(
                    "create {}: {e} (enable the server once)",
                    root.display()
                ))
            })?;
        }
        no_symlinks(root, &ps)?;
        let target = resolve(root, &ps);
        let parent = target.parent().unwrap_or(root).to_path_buf();
        if !parent.is_dir() {
            std::fs::create_dir_all(&parent)
                .map_err(|e| Error::Service(format!("create {}: {e}", parent.display())))?;
            let _ = std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775));
        }
        if let Ok(md) = std::fs::symlink_metadata(&target) {
            if !md.is_file() {
                return Err(invalid(format!("{name:?} is not a regular file")));
            }
            if !overwrite {
                return Err(invalid(format!(
                    "{name:?} already exists (tick 'replace' to overwrite it)"
                )));
            }
        }
        let leaf = ps.last().cloned().unwrap_or_default();
        let tmp = parent.join(format!(".{leaf}.upload"));
        let _ = std::fs::remove_file(&tmp);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o644)
                .open(&tmp)
                .map_err(|e| Error::Service(format!("write {}: {e}", tmp.display())))?;
            f.write_all(data).and_then(|_| f.sync_all()).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                Error::Service(format!("write {}: {e}", tmp.display()))
            })?;
        }
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::Service(format!("publish {}: {e}", target.display()))
        })?;
        Ok(json!({"ok": true, "name": ps.join("/"), "size": data.len()}))
    }

    pub fn delete(root: &Path, name: &str) -> Result<Value> {
        let ps = parts(name)?;
        no_symlinks(root, &ps)?;
        let target = resolve(root, &ps);
        match std::fs::symlink_metadata(&target) {
            Ok(md) if md.is_file() => {
                std::fs::remove_file(&target)
                    .map_err(|e| Error::Service(format!("delete {}: {e}", target.display())))?;
                Ok(json!({"ok": true, "name": ps.join("/")}))
            }
            Ok(_) => Err(invalid(format!("{name:?} is not a regular file"))),
            Err(_) => Err(Error::Config(format!("no file {name:?}"))),
        }
    }
}

/// The protocol without sockets: packet parsing/building, name checks and option
/// negotiation. Pure, so it is unit-tested.
pub mod proto {
    pub const RRQ: u16 = 1;
    pub const WRQ: u16 = 2;
    pub const DATA: u16 = 3;
    pub const ACK: u16 = 4;
    pub const ERROR: u16 = 5;
    pub const OACK: u16 = 6;

    pub const E_UNDEFINED: u16 = 0;
    pub const E_NOT_FOUND: u16 = 1;
    pub const E_ACCESS: u16 = 2;
    pub const E_DISK_FULL: u16 = 3;
    pub const E_ILLEGAL: u16 = 4;
    pub const E_UNKNOWN_TID: u16 = 5;
    pub const E_EXISTS: u16 = 6;
    pub const E_OPTION: u16 = 8;

    pub const DEFAULT_BLKSIZE: usize = 512;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Request {
        pub write: bool,
        pub filename: String,
        pub mode: String,
        /// Option names lower-cased, values as sent.
        pub opts: Vec<(String, String)>,
    }

    pub fn opcode(p: &[u8]) -> Option<u16> {
        (p.len() >= 2).then(|| u16::from_be_bytes([p[0], p[1]]))
    }

    /// Parse a read or write request.
    pub fn parse_request(p: &[u8]) -> Result<Request, &'static str> {
        let op = opcode(p).ok_or("short packet")?;
        if op != RRQ && op != WRQ {
            return Err("not a request");
        }
        let body = &p[2..];
        if body.last() != Some(&0) {
            return Err("unterminated request");
        }
        let fields: Vec<&[u8]> = body[..body.len() - 1].split(|&b| b == 0).collect();
        if fields.len() < 2 || !fields.len().is_multiple_of(2) || fields.len() > 2 + 2 * 8 {
            return Err("malformed request");
        }
        let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "name is not UTF-8");
        let filename = text(fields[0])?;
        if filename.is_empty() || filename.len() > 255 {
            return Err("bad file name length");
        }
        let mode = text(fields[1])?.to_ascii_lowercase();
        let mut opts = Vec::new();
        for pair in fields[2..].chunks(2) {
            opts.push((text(pair[0])?.to_ascii_lowercase(), text(pair[1])?));
        }
        Ok(Request {
            write: op == WRQ,
            filename,
            mode,
            opts,
        })
    }

    pub fn data(block: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + payload.len());
        v.extend_from_slice(&DATA.to_be_bytes());
        v.extend_from_slice(&block.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    pub fn ack(block: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(4);
        v.extend_from_slice(&ACK.to_be_bytes());
        v.extend_from_slice(&block.to_be_bytes());
        v
    }

    pub fn error(code: u16, msg: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + msg.len());
        v.extend_from_slice(&ERROR.to_be_bytes());
        v.extend_from_slice(&code.to_be_bytes());
        v.extend(msg.bytes().filter(|&b| b != 0));
        v.push(0);
        v
    }

    pub fn oack(opts: &[(String, String)]) -> Vec<u8> {
        let mut v = OACK.to_be_bytes().to_vec();
        for (k, val) in opts {
            v.extend_from_slice(k.as_bytes());
            v.push(0);
            v.extend_from_slice(val.as_bytes());
            v.push(0);
        }
        v
    }

    /// Path parts of a requested name: a leading `/` and repeated slashes are
    /// ignored, `.`/`..` and hidden parts (leading dot) are refused, as are
    /// control characters.
    pub fn name_parts(name: &str) -> Result<Vec<String>, &'static str> {
        if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err("control character in the file name");
        }
        let parts: Vec<String> = name
            .split('/')
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();
        if parts.is_empty() {
            return Err("empty file name");
        }
        if parts.len() > 16 {
            return Err("path too deep");
        }
        if parts.iter().any(|p| p.starts_with('.') || p.len() > 200) {
            return Err("hidden or overlong name part");
        }
        Ok(parts)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Negotiated {
        pub blksize: usize,
        pub timeout_secs: Option<u64>,
        /// A write request's announced size (`tsize`).
        pub tsize_request: Option<u64>,
        /// Options to answer with (empty = plain ACK/DATA, no OACK).
        pub reply: Vec<(String, String)>,
    }

    /// RFC 2347 negotiation: accept `blksize` (clamped to `blksize_max`),
    /// `timeout` (1..=60) and `tsize`; ignore everything else (the options
    /// extension lets a server drop options it does not know).
    pub fn negotiate(
        opts: &[(String, String)],
        blksize_max: u32,
        read_size: Option<u64>,
    ) -> Negotiated {
        let mut n = Negotiated {
            blksize: DEFAULT_BLKSIZE,
            timeout_secs: None,
            tsize_request: None,
            reply: Vec::new(),
        };
        for (k, v) in opts {
            match k.as_str() {
                "blksize" => {
                    if let Ok(x) = v.trim().parse::<u32>() {
                        if x >= 8 {
                            let b = x.min(65464).min(blksize_max.max(8));
                            n.blksize = b as usize;
                            n.reply.push(("blksize".into(), b.to_string()));
                        }
                    }
                }
                "timeout" => {
                    if let Ok(x) = v.trim().parse::<u64>() {
                        if (1..=255).contains(&x) {
                            let t = x.min(60);
                            n.timeout_secs = Some(t);
                            n.reply.push(("timeout".into(), t.to_string()));
                        }
                    }
                }
                "tsize" => {
                    if let Ok(x) = v.trim().parse::<u64>() {
                        match read_size {
                            Some(sz) => n.reply.push(("tsize".into(), sz.to_string())),
                            None => {
                                n.tsize_request = Some(x);
                                n.reply.push(("tsize".into(), x.to_string()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        n
    }
}

/// The runtime: what `patronus tftp run` executes.
pub mod engine {
    use super::proto::{self, Request};
    use super::TftpConf;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// `openat2` below `dirfd`: no `..` escape, no symlinks, no magic links.
    fn open_beneath(dirfd: i32, rel: &str, flags: i32, mode: u32) -> std::io::Result<OwnedFd> {
        let c = CString::new(rel).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: mode as u64,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct Recent {
        pub time: u64,
        pub client: String,
        pub file: String,
        pub direction: &'static str,
        pub bytes: u64,
        pub result: String,
    }

    #[derive(Default)]
    pub struct Stats {
        pub requests: AtomicU64,
        pub reads_ok: AtomicU64,
        pub writes_ok: AtomicU64,
        pub failed: AtomicU64,
        pub denied_client: AtomicU64,
        pub denied_write: AtomicU64,
        pub busy: AtomicU64,
        pub bad_requests: AtomicU64,
        pub bytes_sent: AtomicU64,
        pub bytes_received: AtomicU64,
        pub recent: Mutex<VecDeque<Recent>>,
        pub listening: Mutex<Vec<String>>,
    }

    pub struct Ctx {
        pub conf: TftpConf,
        root: OwnedFd,
        acl: Vec<ipnetwork::Ipv4Network>,
        pub stats: Stats,
        sessions: AtomicUsize,
        pub stop: AtomicBool,
        started: u64,
    }

    impl Ctx {
        pub fn new(conf: TftpConf) -> Result<Arc<Ctx>, String> {
            let c = CString::new(conf.root.clone()).map_err(|_| "root has a NUL".to_string())?;
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "open root {}: {}",
                    conf.root,
                    std::io::Error::last_os_error()
                ));
            }
            let root = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut acl = Vec::new();
            for c in &conf.clients {
                acl.push(
                    c.parse::<ipnetwork::Ipv4Network>()
                        .map_err(|e| format!("client network {c:?}: {e}"))?,
                );
            }
            Ok(Arc::new(Ctx {
                conf,
                root,
                acl,
                stats: Stats::default(),
                sessions: AtomicUsize::new(0),
                stop: AtomicBool::new(false),
                started: now(),
            }))
        }

        fn client_allowed(&self, ip: Ipv4Addr) -> bool {
            self.acl.is_empty() || self.acl.iter().any(|n| n.contains(ip))
        }

        fn record(&self, r: Recent) {
            let mut q = self.stats.recent.lock().unwrap();
            if q.len() >= 20 {
                q.pop_front();
            }
            q.push_back(r);
        }

        pub fn stats_json(&self) -> serde_json::Value {
            let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
            let s = &self.stats;
            serde_json::json!({
                "started": self.started,
                "updated": now(),
                "requests": g(&s.requests),
                "reads_ok": g(&s.reads_ok),
                "writes_ok": g(&s.writes_ok),
                "failed": g(&s.failed),
                "denied_client": g(&s.denied_client),
                "denied_write": g(&s.denied_write),
                "busy": g(&s.busy),
                "bad_requests": g(&s.bad_requests),
                "bytes_sent": g(&s.bytes_sent),
                "bytes_received": g(&s.bytes_received),
                "active": self.sessions.load(Ordering::Relaxed),
                "listening": *s.listening.lock().unwrap(),
                "recent": *s.recent.lock().unwrap(),
            })
        }
    }

    /// IPv4 addresses of a device.
    pub fn dev_addrs(dev: &str) -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        if let Ok(it) = nix::ifaddrs::getifaddrs() {
            for a in it {
                if a.interface_name != dev {
                    continue;
                }
                if let Some(ad) = a.address.as_ref().and_then(|a| a.as_sockaddr_in()) {
                    let ip = ad.ip();
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
        out
    }

    fn udp_socket(dev: &str, addr: SocketAddrV4) -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.bind_device(Some(dev.as_bytes()))?;
        s.bind(&SockAddr::from(SocketAddr::V4(addr)))?;
        Ok(s.into())
    }

    fn rand_u64() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    }

    /// Bind a data socket on one of the configured ports.
    fn data_socket(ctx: &Ctx, dev: &str, local: Ipv4Addr) -> std::io::Result<UdpSocket> {
        let ports: Vec<u16> = ctx
            .conf
            .data_ports
            .iter()
            .flat_map(|&(a, b)| a..=b)
            .collect();
        if ports.is_empty() {
            return Err(std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL));
        }
        let start = (rand_u64() as usize) % ports.len();
        for i in 0..ports.len() {
            let p = ports[(start + i) % ports.len()];
            match udp_socket(dev, SocketAddrV4::new(local, p)) {
                Ok(s) => return Ok(s),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::from_raw_os_error(libc::EADDRINUSE))
    }

    fn err_for(e: &std::io::Error) -> (u16, &'static str) {
        match e.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => (proto::E_NOT_FOUND, "File not found"),
            Some(libc::ENOSPC) | Some(libc::EDQUOT) | Some(libc::EFBIG) => {
                (proto::E_DISK_FULL, "Disk full or allocation exceeded")
            }
            Some(libc::EEXIST) => (proto::E_EXISTS, "File already exists"),
            Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EXDEV) | Some(libc::ELOOP)
            | Some(libc::EISDIR) | Some(libc::EROFS) => (proto::E_ACCESS, "Access violation"),
            _ => (proto::E_UNDEFINED, "Cannot serve this request"),
        }
    }

    enum Wait {
        Ack,
        Data(Vec<u8>),
    }

    #[derive(Clone)]
    struct Session<'a> {
        sock: &'a UdpSocket,
        peer: SocketAddrV4,
        timeout: Duration,
        retries: u32,
    }

    impl Session<'_> {
        fn send(&self, p: &[u8]) {
            let _ = self.sock.send_to(p, self.peer);
        }

        /// Send `pkt`, then wait for the answer `want` (ACK of `block` or DATA
        /// `block`), resending on silence. Packets from other ports get ERROR 5.
        fn exchange(
            &self,
            pkt: &[u8],
            block: u16,
            data: bool,
            buf: &mut [u8],
        ) -> Result<Wait, String> {
            for _ in 0..=self.retries {
                self.send(pkt);
                let deadline = Instant::now() + self.timeout;
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    let _ = self
                        .sock
                        .set_read_timeout(Some(left.max(Duration::from_millis(1))));
                    match self.sock.recv_from(buf) {
                        Ok((n, from)) => {
                            if from != SocketAddr::V4(self.peer) {
                                let _ = self.sock.send_to(
                                    &proto::error(proto::E_UNKNOWN_TID, "Unknown transfer ID"),
                                    from,
                                );
                                continue;
                            }
                            let p = &buf[..n];
                            match proto::opcode(p) {
                                Some(proto::ERROR) => {
                                    let msg = String::from_utf8_lossy(
                                        p.get(4..n.saturating_sub(1)).unwrap_or(&[]),
                                    )
                                    .to_string();
                                    return Err(format!("client error: {msg:?}"));
                                }
                                // an old duplicate ACK or DATA falls through: resending on it would
                                // double the data (the sorcerer's apprentice bug)
                                Some(proto::ACK)
                                    if !data
                                        && n >= 4
                                        && u16::from_be_bytes([p[2], p[3]]) == block =>
                                {
                                    return Ok(Wait::Ack);
                                }
                                Some(proto::DATA)
                                    if data
                                        && n >= 4
                                        && u16::from_be_bytes([p[2], p[3]]) == block =>
                                {
                                    return Ok(Wait::Data(p[4..].to_vec()));
                                }
                                _ => {}
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break
                        }
                        Err(e) => return Err(format!("receive: {e}")),
                    }
                }
            }
            Err("timeout".into())
        }
    }

    struct Guard<'a>(&'a AtomicUsize);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn fstat_regular(fd: i32) -> std::io::Result<u64> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(std::io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(st.st_size as u64)
    }

    /// Why a transfer did not complete. `Refuse` happened before anything was
    /// exchanged (the caller answers with an ERROR packet); `Aborted` ended
    /// mid-transfer and the client already knows (timeout, its own error, an
    /// ERROR we sent).
    enum Fail {
        Refuse(u16, String),
        Aborted(String),
    }

    type Outcome = Result<u64, Fail>;

    fn refuse_io(e: std::io::Error) -> Fail {
        let (c, m) = err_for(&e);
        Fail::Refuse(c, m.to_string())
    }

    fn serve_read(ctx: &Ctx, base: &Session, req: &Request, rel: &str) -> Outcome {
        let fd = open_beneath(
            ctx.root.as_raw_fd(),
            rel,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .map_err(refuse_io)?;
        let size = fstat_regular(fd.as_raw_fd()).map_err(refuse_io)?;
        let mut file = File::from(fd);
        let neg = proto::negotiate(&req.opts, ctx.conf.blksize_max, Some(size));
        let sess = Session {
            timeout: neg
                .timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(base.timeout),
            ..base.clone()
        };
        let mut buf = vec![0u8; 4 + neg.blksize + 16];
        if !neg.reply.is_empty() {
            // OACK, then the client's ACK of block 0
            sess.exchange(&proto::oack(&neg.reply), 0, false, &mut buf)
                .map_err(Fail::Aborted)?;
        }
        let mut block: u16 = 1;
        let mut total = 0u64;
        let mut chunk = vec![0u8; neg.blksize];
        loop {
            let mut n = 0;
            while n < chunk.len() {
                match file.read(&mut chunk[n..]) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) => {
                        let (c, m) = err_for(&e);
                        sess.send(&proto::error(c, m));
                        return Err(Fail::Aborted(m.to_string()));
                    }
                }
            }
            let pkt = proto::data(block, &chunk[..n]);
            sess.exchange(&pkt, block, false, &mut buf)
                .map_err(Fail::Aborted)?;
            total += n as u64;
            ctx.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            if n < neg.blksize {
                return Ok(total);
            }
            block = block.wrapping_add(1);
        }
    }

    fn cstr(s: &str) -> std::io::Result<CString> {
        CString::new(s).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn serve_write(ctx: &Ctx, base: &Session, req: &Request, parts: &[String]) -> Outcome {
        let (leaf, dirs) = parts
            .split_last()
            .ok_or_else(|| Fail::Refuse(proto::E_ACCESS, "Access violation".into()))?;
        if leaf.len() > 200 {
            return Err(Fail::Refuse(proto::E_ACCESS, "Name too long".into()));
        }
        let rel_dir = if dirs.is_empty() {
            ".".to_string()
        } else {
            dirs.join("/")
        };
        let dir = open_beneath(
            ctx.root.as_raw_fd(),
            &rel_dir,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(refuse_io)?;
        let dfd = dir.as_raw_fd();
        let c_leaf = cstr(leaf).map_err(refuse_io)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let exists =
            unsafe { libc::fstatat(dfd, c_leaf.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
        if exists {
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(Fail::Refuse(proto::E_ACCESS, "Access violation".into()));
            }
            if !ctx.conf.overwrite {
                return Err(Fail::Refuse(proto::E_EXISTS, "File already exists".into()));
            }
        }
        let neg = proto::negotiate(&req.opts, ctx.conf.blksize_max, None);
        let limit = ctx.conf.max_write_kb.saturating_mul(1024);
        if neg.tsize_request.is_some_and(|t| t > limit) {
            return Err(Fail::Refuse(
                proto::E_DISK_FULL,
                "Disk full or allocation exceeded".into(),
            ));
        }
        let c_tmp = cstr(&format!(".{leaf}.part")).map_err(refuse_io)?;
        let tfd = unsafe {
            libc::openat(
                dfd,
                c_tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if tfd < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EEXIST) {
                return Err(Fail::Refuse(
                    proto::E_UNDEFINED,
                    "Another upload of this name is running".into(),
                ));
            }
            return Err(refuse_io(e));
        }
        let mut file = unsafe { File::from_raw_fd(tfd) };
        let cleanup = || unsafe {
            libc::unlinkat(dfd, c_tmp.as_ptr(), 0);
        };
        let sess = Session {
            timeout: neg
                .timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(base.timeout),
            ..base.clone()
        };
        let mut buf = vec![0u8; 4 + neg.blksize + 16];
        let mut last = if neg.reply.is_empty() {
            proto::ack(0)
        } else {
            proto::oack(&neg.reply)
        };
        let mut block: u16 = 1;
        let mut total = 0u64;
        let received: Result<(), String> = loop {
            let payload = match sess.exchange(&last, block, true, &mut buf) {
                Ok(Wait::Data(d)) => d,
                Ok(Wait::Ack) => break Err("protocol error".into()),
                Err(e) => break Err(e),
            };
            if payload.len() > neg.blksize {
                sess.send(&proto::error(
                    proto::E_ILLEGAL,
                    "Block larger than negotiated",
                ));
                break Err("block larger than negotiated".into());
            }
            total += payload.len() as u64;
            if total > limit {
                sess.send(&proto::error(proto::E_DISK_FULL, "Upload too large"));
                break Err("upload too large".into());
            }
            if let Err(e) = file.write_all(&payload) {
                let (c, m) = err_for(&e);
                sess.send(&proto::error(c, m));
                break Err(m.to_string());
            }
            ctx.stats
                .bytes_received
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            if payload.len() < neg.blksize {
                break Ok(());
            }
            last = proto::ack(block);
            block = block.wrapping_add(1);
        };
        if let Err(e) = received {
            drop(file);
            cleanup();
            return Err(Fail::Aborted(e));
        }
        // publish before the final ACK: the client must not see success for a
        // file that was not stored
        let published = file.sync_all().and_then(|_| {
            drop(file);
            if ctx.conf.overwrite {
                let rc = unsafe { libc::renameat(dfd, c_tmp.as_ptr(), dfd, c_leaf.as_ptr()) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            } else {
                let rc = unsafe { libc::linkat(dfd, c_tmp.as_ptr(), dfd, c_leaf.as_ptr(), 0) };
                let e = std::io::Error::last_os_error();
                cleanup();
                if rc < 0 {
                    Err(e)
                } else {
                    Ok(())
                }
            }
        });
        match published {
            Ok(()) => {
                sess.send(&proto::ack(block));
                Ok(total)
            }
            Err(e) => {
                cleanup();
                let (c, m) = err_for(&e);
                sess.send(&proto::error(c, m));
                Err(Fail::Aborted(m.to_string()))
            }
        }
    }

    fn handle(ctx: Arc<Ctx>, dev: String, local: Ipv4Addr, client: SocketAddrV4, req: Request) {
        let _g = Guard(&ctx.sessions);
        let dir = if req.write { "write" } else { "read" };
        let finish = |res: Result<u64, String>| {
            let (bytes, result) = match &res {
                Ok(b) => {
                    if req.write {
                        ctx.stats.writes_ok.fetch_add(1, Ordering::Relaxed);
                    } else {
                        ctx.stats.reads_ok.fetch_add(1, Ordering::Relaxed);
                    }
                    (*b, "ok".to_string())
                }
                Err(m) => {
                    ctx.stats.failed.fetch_add(1, Ordering::Relaxed);
                    (0, format!("failed: {m}"))
                }
            };
            eprintln!(
                "tftp: {client} {dir} {:?} {result} ({bytes} bytes)",
                req.filename
            );
            ctx.record(Recent {
                time: now(),
                client: client.ip().to_string(),
                file: req.filename.chars().take(120).collect(),
                direction: if req.write { "write" } else { "read" },
                bytes,
                result,
            });
        };
        let sock = match data_socket(&ctx, &dev, local) {
            Ok(s) => s,
            Err(e) => {
                finish(Err(format!("no data port: {e}")));
                return;
            }
        };
        let sess = Session {
            sock: &sock,
            peer: client,
            timeout: Duration::from_secs(ctx.conf.timeout as u64),
            retries: ctx.conf.retries,
        };
        let refuse = |code: u16, msg: &str| {
            sess.send(&proto::error(code, msg));
            finish(Err(msg.to_string()));
        };
        if req.mode != "octet" {
            return refuse(proto::E_ILLEGAL, "Only binary (octet) mode is supported");
        }
        let parts = match proto::name_parts(&req.filename) {
            Ok(p) => p,
            Err(m) => return refuse(proto::E_ACCESS, m),
        };
        let res = if req.write {
            if !ctx.conf.allow_write {
                ctx.stats.denied_write.fetch_add(1, Ordering::Relaxed);
                return refuse(proto::E_ACCESS, "Write access is disabled");
            }
            serve_write(&ctx, &sess, &req, &parts)
        } else {
            serve_read(&ctx, &sess, &req, &parts.join("/"))
        };
        match res {
            Ok(b) => finish(Ok(b)),
            Err(Fail::Refuse(c, m)) => refuse(c, &m),
            Err(Fail::Aborted(m)) => finish(Err(m)),
        }
    }

    fn listener(ctx: Arc<Ctx>, dev: String, addr: Ipv4Addr, stop: Arc<AtomicBool>, port: u16) {
        let sock = match udp_socket(&dev, SocketAddrV4::new(addr, port)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tftp: {dev} {addr}:{port}: {e}");
                return;
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = vec![0u8; 2048];
        while !stop.load(Ordering::Relaxed) && !ctx.stop.load(Ordering::Relaxed) {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => continue,
            };
            let SocketAddr::V4(client) = from else {
                continue;
            };
            let req = match proto::parse_request(&buf[..n]) {
                Ok(r) => r,
                Err(_) => {
                    ctx.stats.bad_requests.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            ctx.stats.requests.fetch_add(1, Ordering::Relaxed);
            if !ctx.client_allowed(*client.ip()) {
                ctx.stats.denied_client.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&proto::error(proto::E_ACCESS, "Access violation"), client);
                continue;
            }
            if ctx.sessions.fetch_add(1, Ordering::Relaxed) >= ctx.conf.max_sessions as usize {
                ctx.sessions.fetch_sub(1, Ordering::Relaxed);
                ctx.stats.busy.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&proto::error(proto::E_UNDEFINED, "Server busy"), client);
                continue;
            }
            let (c2, d2) = (ctx.clone(), dev.clone());
            let spawned = std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn(move || handle(c2, d2, addr, client, req));
            if spawned.is_err() {
                ctx.sessions.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Open and close listeners as the interfaces' addresses come and go; also
    /// refresh the statistics file. Returns when `ctx.stop` is set.
    pub fn serve(ctx: Arc<Ctx>, mut stats_file: Option<File>) {
        let mut live: BTreeMap<(String, Ipv4Addr), Arc<AtomicBool>> = BTreeMap::new();
        while !ctx.stop.load(Ordering::Relaxed) {
            let mut want: Vec<(String, Ipv4Addr)> = Vec::new();
            for d in &ctx.conf.listen {
                for a in dev_addrs(d) {
                    want.push((d.clone(), a));
                }
            }
            for k in want.iter() {
                if !live.contains_key(k) {
                    let stop = Arc::new(AtomicBool::new(false));
                    let (c2, s2, d, a, p) =
                        (ctx.clone(), stop.clone(), k.0.clone(), k.1, ctx.conf.port);
                    if std::thread::Builder::new()
                        .spawn(move || listener(c2, d, a, s2, p))
                        .is_ok()
                    {
                        live.insert(k.clone(), stop);
                    }
                }
            }
            live.retain(|k, stop| {
                if want.contains(k) {
                    true
                } else {
                    stop.store(true, Ordering::Relaxed);
                    false
                }
            });
            *ctx.stats.listening.lock().unwrap() = live
                .keys()
                .map(|(d, a)| format!("{d} {a}:{}", ctx.conf.port))
                .collect();
            if let Some(f) = stats_file.as_mut() {
                let mut text = ctx.stats_json().to_string();
                text.push('\n');
                use std::io::{Seek, SeekFrom};
                let _ = f.seek(SeekFrom::Start(0));
                let _ = f.write_all(text.as_bytes());
                let _ = f.set_len(text.len() as u64);
            }
            for _ in 0..20 {
                if ctx.stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        for stop in live.values() {
            stop.store(true, Ordering::Relaxed);
        }
    }

    /// Drop to `user`, keeping CAP_NET_BIND_SERVICE and CAP_NET_RAW.
    fn drop_privileges(user: &str) -> Result<(), String> {
        let u = nix::unistd::User::from_name(user)
            .map_err(|e| format!("look up {user}: {e}"))?
            .ok_or_else(|| format!("account {user:?} does not exist"))?;
        unsafe {
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 {
                return Err(format!(
                    "PR_SET_KEEPCAPS: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if libc::setgroups(0, std::ptr::null()) < 0 {
                return Err(format!("setgroups: {}", std::io::Error::last_os_error()));
            }
            if libc::setgid(u.gid.as_raw()) < 0 {
                return Err(format!("setgid: {}", std::io::Error::last_os_error()));
            }
            if libc::setuid(u.uid.as_raw()) < 0 {
                return Err(format!("setuid: {}", std::io::Error::last_os_error()));
            }
            #[repr(C)]
            struct Hdr {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let hdr = Hdr {
                version: 0x2008_0522,
                pid: 0,
            };
            let keep: u32 = (1 << 10) | (1 << 13); // NET_BIND_SERVICE, NET_RAW
            let data = [
                Data {
                    effective: keep,
                    permitted: keep,
                    inheritable: 0,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &hdr as *const Hdr, data.as_ptr()) < 0 {
                return Err(format!("capset: {}", std::io::Error::last_os_error()));
            }
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if libc::setuid(0) == 0 {
                return Err("dropping privileges did not stick".into());
            }
        }
        Ok(())
    }

    /// `patronus tftp run`: read the generated file, drop privileges, serve.
    pub fn run(conf_path: &std::path::Path, stats: Option<&std::path::Path>) -> Result<(), String> {
        let text = std::fs::read_to_string(conf_path)
            .map_err(|e| format!("read {}: {e}", conf_path.display()))?;
        let conf: TftpConf = serde_json::from_str(&text)
            .map_err(|e| format!("parse {}: {e}", conf_path.display()))?;
        let run_as = conf.run_as.clone();
        let ctx = Ctx::new(conf)?;
        let stats_file = match stats {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(p)
                    .map_err(|e| format!("open {}: {e}", p.display()))?,
            ),
            None => None,
        };
        if nix::unistd::geteuid().is_root() {
            drop_privileges(&run_as)?;
            eprintln!("tftp: running as {run_as} (net-bind and raw-socket capabilities only)");
        } else {
            eprintln!("tftp: not root, serving with the current account");
        }
        serve(ctx, stats_file);
        Ok(())
    }

    /// Does this kernel have openat2 (Linux 5.6+)?
    pub fn kernel_ok() -> bool {
        let r = open_beneath(libc::AT_FDCWD, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0);
        !matches!(&r, Err(e) if e.raw_os_error() == Some(libc::ENOSYS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result::Result;
    use crate::supervise::{InitMode, NetPaths};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // ---- settings, validation, rendering -----------------------------------

    #[test]
    fn roots_stay_out_of_system_and_state_directories() {
        for ok in [
            "/var/lib/patronus/tftp",
            "/var/lib/patronus/tftp/boot",
            "/srv/tftp",
            "/mnt/data/boot",
            "/tftpboot",
            "/tftpboot/x",
            "/opt/boot",
        ] {
            assert!(check_root(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "tftp",
            "/",
            "/etc",
            "/etc/patronus",
            "/var/lib",
            "/var/lib/patronus",
            "/var/lib/patronus-monagent/x",
            "/var/lib/patronus/config",
            "/srv/../etc",
            "/srv//x",
            "/srv/tftp/",
            "/srv/./x",
            "/tftpbootx",
            "/root",
        ] {
            assert!(check_root(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn settings_rows_and_rendering() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = TftpApplier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            Some("/bin/true".into()),
        );
        assert!(a.apply(&s).await.is_ok(), "off: nothing to do");
        assert!(a.render(&s).await.unwrap().contains("off"));
        // typed values are validated before they are stored
        for bad in [
            json!({"port": 0}),
            json!({"port": "69; x"}),
            json!({"blksize_max": 100}),
            json!({"timeout": 0}),
            json!({"root": "/etc"}),
            json!({"root": "/srv/../etc"}),
            json!({"interfaces": "lan;x"}),
            json!({"data_ports": "abc"}),
            json!({"unknown": 1}),
        ] {
            assert!(TftpSvc.put(&s, &bad).await.is_err(), "{bad}");
        }
        let c = &SPEC.colls[0];
        for bad in [
            json!({"cidr": "10.0.0.0/33"}),
            json!({"cidr": "fd00::/64"}),
            json!({"cidr": "x"}),
            json!({}),
        ] {
            assert!(svc::save_row(&s, c, None, &bad).await.is_err(), "{bad}");
        }
        TftpSvc
            .put(
                &s,
                &json!({"enabled": true, "interfaces": "eth1", "root": "/srv/tftp-test"}),
            )
            .await
            .unwrap();
        svc::save_row(&s, c, None, &json!({"cidr": "10.9.0.0/24"}))
            .await
            .unwrap();
        svc::save_row(
            &s,
            c,
            None,
            &json!({"cidr": "10.8.0.1/32", "enabled": false}),
        )
        .await
        .unwrap();
        assert!(
            svc::save_row(&s, c, None, &json!({"cidr": "10.9.0.0/24"}))
                .await
                .is_err(),
            "duplicate"
        );
        let conf = load(&s).await.unwrap();
        assert_eq!(conf.port, 69);
        assert_eq!(conf.listen, vec!["eth1"]);
        assert!(!conf.allow_write && !conf.overwrite);
        assert_eq!(
            conf.clients,
            vec!["10.9.0.0/24"],
            "disabled rows are left out"
        );
        assert_eq!(conf.data_ports, vec![(49152, 49407)]);
        assert_eq!(conf.run_as, "nobody");
        let r = a.render(&s).await.unwrap();
        let back: TftpConf = serde_json::from_str(r.trim_start_matches("## tftp.json\n")).unwrap();
        assert_eq!(back, conf);
        // cross-field checks at apply time
        TftpSvc
            .put(
                &s,
                &json!({"max_sessions": 256, "data_ports": "50000-50009"}),
            )
            .await
            .unwrap();
        let e = load(&s).await.unwrap_err().to_string();
        assert!(e.contains("concurrent"), "{e}");
        TftpSvc
            .put(&s, &json!({"max_sessions": 4, "port": 50005}))
            .await
            .unwrap();
        let e = load(&s).await.unwrap_err().to_string();
        assert!(e.contains("request port"), "{e}");
        // no interface at all (an unassigned role) is an error, not "serve everywhere"
        TftpSvc
            .put(&s, &json!({"port": 69, "interfaces": "@opt3"}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("no interface"), "{e}");
    }

    // ---- protocol -----------------------------------------------------------

    fn rrq(name: &str, mode: &str, opts: &[(&str, &str)]) -> Vec<u8> {
        let mut p = vec![0, 1];
        p.extend_from_slice(name.as_bytes());
        p.push(0);
        p.extend_from_slice(mode.as_bytes());
        p.push(0);
        for (k, v) in opts {
            p.extend_from_slice(k.as_bytes());
            p.push(0);
            p.extend_from_slice(v.as_bytes());
            p.push(0);
        }
        p
    }

    #[test]
    fn requests_are_parsed_strictly() {
        let r = proto::parse_request(&rrq("pxelinux.0", "OCTET", &[("BlkSize", "1024")])).unwrap();
        assert!(!r.write);
        assert_eq!(r.filename, "pxelinux.0");
        assert_eq!(r.mode, "octet");
        assert_eq!(r.opts, vec![("blksize".to_string(), "1024".to_string())]);
        let mut w = rrq("up.bin", "octet", &[]);
        w[1] = 2;
        assert!(proto::parse_request(&w).unwrap().write);
        for bad in [
            vec![],
            vec![0, 1],
            vec![0, 3, 0, 1, 0],
            rrq("a", "octet", &[])[..6].to_vec(), // not terminated
            rrq("", "octet", &[]),
            rrq(
                "a",
                "octet",
                &[
                    ("blksize", "8"),
                    ("x", "1"),
                    ("y", "1"),
                    ("z", "1"),
                    ("a", "1"),
                    ("b", "1"),
                    ("c", "1"),
                    ("d", "1"),
                    ("e", "1"),
                ],
            ),
            vec![0, 1, b'a', 0, b'o', 0, b'x', 0], // option without a value
            vec![0, 1, 0xff, 0xfe, 0, b'o', 0],
        ] {
            assert!(proto::parse_request(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_cannot_climb_or_hide() {
        assert_eq!(
            proto::name_parts("/boot//grub/grub.cfg").unwrap(),
            vec!["boot", "grub", "grub.cfg"]
        );
        for bad in [
            "",
            "/",
            "..",
            "../etc/passwd",
            "a/../../b",
            "a/./b",
            ".hidden",
            "dir/.x",
            ".x.part",
            "a\u{0}b",
            "a\nb",
        ] {
            assert!(proto::name_parts(bad).is_err(), "{bad:?}");
        }
        assert!(proto::name_parts(&"a/".repeat(20)).is_err());
    }

    #[test]
    fn options_are_negotiated_within_the_limits() {
        let o = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        let n = proto::negotiate(&o(&[("blksize", "8192"), ("tsize", "0")]), 1468, Some(1000));
        assert_eq!(n.blksize, 1468);
        assert_eq!(n.reply, o(&[("blksize", "1468"), ("tsize", "1000")]));
        let n = proto::negotiate(
            &o(&[("blksize", "1024"), ("timeout", "200"), ("windowsize", "8")]),
            1468,
            None,
        );
        assert_eq!(n.blksize, 1024);
        assert_eq!(n.timeout_secs, Some(60));
        assert_eq!(
            n.reply,
            o(&[("blksize", "1024"), ("timeout", "60")]),
            "unknown options are dropped"
        );
        let n = proto::negotiate(
            &o(&[("blksize", "4"), ("timeout", "0"), ("tsize", "x")]),
            1468,
            None,
        );
        assert_eq!(n.blksize, 512);
        assert!(
            n.reply.is_empty(),
            "invalid values are ignored: plain transfer"
        );
        let n = proto::negotiate(&o(&[("tsize", "4096")]), 1468, None);
        assert_eq!(n.tsize_request, Some(4096));
        let n = proto::negotiate(&o(&[("blksize", "65535")]), 65464, None);
        assert_eq!(n.blksize, 65464);
    }

    #[test]
    fn packets_have_the_rfc_layout() {
        assert_eq!(proto::ack(7), vec![0, 4, 0, 7]);
        assert_eq!(proto::data(2, b"ab"), vec![0, 3, 0, 2, b'a', b'b']);
        assert_eq!(proto::error(1, "x"), vec![0, 5, 0, 1, b'x', 0]);
        assert_eq!(
            proto::oack(&[("blksize".into(), "8".into())]),
            [&[0u8, 6][..], b"blksize\0", b"8\0"].concat()
        );
    }

    // ---- the file manager of the page ----------------------------------------

    #[test]
    fn file_manager_is_confined_to_the_root() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("tftp");
        let v = files::upload(&root, "pxelinux.0", b"abc", false).unwrap();
        assert_eq!(v["size"], 3);
        assert!(
            files::upload(&root, "pxelinux.0", b"x", false).is_err(),
            "exists"
        );
        files::upload(&root, "pxelinux.0", b"abcd", true).unwrap();
        files::upload(&root, "grub/x86_64/grub.cfg", b"cfg", false).unwrap();
        for bad in [
            "../x",
            ".x",
            "a/../b",
            "a b",
            "a;b",
            "",
            "a/b/c/d",
            "x\n",
        ] {
            assert!(files::upload(&root, bad, b"x", true).is_err(), "{bad:?}");
            assert!(files::delete(&root, bad).is_err(), "{bad:?}");
        }
        let l = files::list(&root).unwrap();
        let names: Vec<String> = l["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["grub/x86_64/grub.cfg", "pxelinux.0"]);
        // a planted symlink is neither followed on upload nor on delete, nor listed
        let outside = d.path().join("outside");
        std::fs::write(&outside, "secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link.bin")).unwrap();
        std::os::unix::fs::symlink(d.path(), root.join("dirlink")).unwrap();
        assert!(files::upload(&root, "link.bin", b"x", true).is_err());
        assert!(files::upload(&root, "dirlink/y", b"x", true).is_err());
        assert!(files::delete(&root, "link.bin").is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
        let l = files::list(&root).unwrap();
        assert!(!l.to_string().contains("link"), "{l}");
        files::delete(&root, "pxelinux.0").unwrap();
        assert!(files::delete(&root, "pxelinux.0").is_err());
        // file modes: world readable so the unprivileged server can read it
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(root.join("grub/x86_64/grub.cfg")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o644);
    }

    #[tokio::test]
    async fn upload_action_enforces_the_page_limit() {
        let s = crate::lan::testutil::store().await;
        let root = format!("/var/lib/tftp-test-{}", std::process::id());
        // the root must pass check_root but need not exist for the refusal paths
        TftpSvc
            .put(&s, &json!({"root": root, "ui_upload_kb": 1}))
            .await
            .unwrap();
        use base64::Engine as _;
        let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 2048]);
        let e = TftpSvc
            .action(&s, "upload", &json!({"name": "a.bin", "data": big}))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("1 KiB"), "{e}");
        let e = TftpSvc
            .action(&s, "upload", &json!({"name": "a.bin", "data": "!!!"}))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("base64"), "{e}");
        assert!(TftpSvc.action(&s, "nope", &json!({})).await.is_err());
    }

    // ---- the engine over real UDP on loopback ----------------------------------

    static NEXT_PORTS: AtomicU16 = AtomicU16::new(42000);

    struct Server {
        ctx: Arc<engine::Ctx>,
        port: u16,
        _dir: tempfile::TempDir,
        root: PathBuf,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.ctx.stop.store(true, Ordering::Relaxed);
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    fn start(tweak: impl FnOnce(&mut TftpConf)) -> Option<Server> {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let free = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap().port()
        };
        let base = NEXT_PORTS.fetch_add(40, Ordering::Relaxed);
        let mut conf = TftpConf {
            port: free,
            root: root.to_string_lossy().into(),
            listen: vec!["lo".into()],
            allow_write: false,
            overwrite: false,
            max_write_kb: 64,
            blksize_max: 1468,
            timeout: 1,
            retries: 3,
            max_sessions: 8,
            data_ports: vec![(base, base + 31)],
            run_as: "nobody".into(),
            clients: vec![],
        };
        tweak(&mut conf);
        let ctx = engine::Ctx::new(conf).unwrap();
        // the sandbox must let an unprivileged socket bind to a device (Linux 5.7+)
        let probe = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        if probe.bind_device(Some(b"lo")).is_err() {
            eprintln!("SKIP: SO_BINDTODEVICE not permitted here");
            return None;
        }
        assert!(engine::kernel_ok(), "openat2 needs Linux 5.6+");
        let c2 = ctx.clone();
        let join = std::thread::spawn(move || engine::serve(c2, None));
        // wait for the listener
        for _ in 0..50 {
            if !ctx.stats.listening.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(100));
        Some(Server {
            ctx,
            port: free,
            _dir: dir,
            root,
            join: Some(join),
        })
    }

    type Opts = Vec<(String, String)>;

    fn udp() -> UdpSocket {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        s
    }

    /// Minimal TFTP client: (data, OACK options) or (error code, message).
    fn get(port: u16, name: &str, opts: &[(&str, &str)]) -> Result<(Vec<u8>, Opts), (u16, String)> {
        let s = udp();
        s.send_to(&rrq(name, "octet", opts), ("127.0.0.1", port))
            .unwrap();
        let mut out = Vec::new();
        let mut oack: Opts = Vec::new();
        let mut buf = vec![0u8; 70000];
        let mut tid: Option<SocketAddr> = None;
        let mut blk = 0u16;
        loop {
            let (n, from) = s.recv_from(&mut buf).map_err(|e| (999, format!("{e}")))?;
            if tid.is_none() {
                tid = Some(from);
            } else if tid != Some(from) {
                continue;
            }
            let p = &buf[..n];
            match proto::opcode(p).unwrap() {
                proto::ERROR => {
                    return Err((
                        u16::from_be_bytes([p[2], p[3]]),
                        String::from_utf8_lossy(&p[4..n - 1]).into(),
                    ))
                }
                proto::OACK => {
                    let f: Vec<&[u8]> = p[2..n - 1].split(|&b| b == 0).collect();
                    for c in f.chunks(2) {
                        oack.push((
                            String::from_utf8_lossy(c[0]).into(),
                            String::from_utf8_lossy(c[1]).into(),
                        ));
                    }
                    s.send_to(&proto::ack(0), from).unwrap();
                }
                proto::DATA => {
                    let b = u16::from_be_bytes([p[2], p[3]]);
                    if b == blk.wrapping_add(1) {
                        out.extend_from_slice(&p[4..]);
                        blk = b;
                    }
                    s.send_to(&proto::ack(b), from).unwrap();
                    let bs = oack
                        .iter()
                        .find(|(k, _)| k == "blksize")
                        .and_then(|(_, v)| v.parse::<usize>().ok())
                        .unwrap_or(512);
                    if p.len() - 4 < bs {
                        return Ok((out, oack));
                    }
                }
                _ => {}
            }
        }
    }

    fn put(
        port: u16,
        name: &str,
        data: &[u8],
        opts: &[(&str, &str)],
    ) -> Result<Opts, (u16, String)> {
        let s = udp();
        let mut w = rrq(name, "octet", opts);
        w[1] = 2;
        s.send_to(&w, ("127.0.0.1", port)).unwrap();
        let mut buf = vec![0u8; 70000];
        let (n, from) = s.recv_from(&mut buf).map_err(|e| (999, format!("{e}")))?;
        let mut oack: Opts = Vec::new();
        match proto::opcode(&buf[..n]).unwrap() {
            proto::ERROR => {
                return Err((
                    u16::from_be_bytes([buf[2], buf[3]]),
                    String::from_utf8_lossy(&buf[4..n - 1]).into(),
                ))
            }
            proto::OACK => {
                let f: Vec<&[u8]> = buf[2..n - 1].split(|&b| b == 0).collect();
                for c in f.chunks(2) {
                    oack.push((
                        String::from_utf8_lossy(c[0]).into(),
                        String::from_utf8_lossy(c[1]).into(),
                    ));
                }
            }
            proto::ACK => {}
            _ => return Err((998, "unexpected".into())),
        }
        let bs = oack
            .iter()
            .find(|(k, _)| k == "blksize")
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(512);
        let mut block = 1u16;
        let mut chunks: Vec<&[u8]> = data.chunks(bs).collect();
        if data.len().is_multiple_of(bs) {
            chunks.push(&[]);
        }
        for c in chunks {
            s.send_to(&proto::data(block, c), from).unwrap();
            let (n, f2) = s.recv_from(&mut buf).map_err(|e| (999, format!("{e}")))?;
            assert_eq!(f2, from);
            match proto::opcode(&buf[..n]).unwrap() {
                proto::ACK => assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), block),
                proto::ERROR => {
                    return Err((
                        u16::from_be_bytes([buf[2], buf[3]]),
                        String::from_utf8_lossy(&buf[4..n - 1]).into(),
                    ))
                }
                _ => return Err((998, "unexpected".into())),
            }
            block = block.wrapping_add(1);
        }
        Ok(oack)
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn reads_work_for_every_size_and_option() {
        let Some(srv) = start(|_| {}) else { return };
        // sizes around block boundaries (512): empty, exact multiple, one over
        for (i, n) in [0usize, 1, 511, 512, 513, 1024, 100_000]
            .into_iter()
            .enumerate()
        {
            let name = format!("f{i}.bin");
            std::fs::write(srv.root.join(&name), pattern(n)).unwrap();
            let (d, o) = get(srv.port, &name, &[]).unwrap();
            assert_eq!(d, pattern(n), "{n} bytes");
            assert!(o.is_empty());
        }
        std::fs::write(srv.root.join("sub/deep.bin"), pattern(5000)).unwrap();
        let (d, _) = get(srv.port, "/sub//deep.bin", &[]).unwrap();
        assert_eq!(d, pattern(5000));
        // negotiated block size is clamped to the configured ceiling; tsize is answered
        let (d, o) = get(srv.port, "f6.bin", &[("blksize", "8192"), ("tsize", "0")]).unwrap();
        assert_eq!(d, pattern(100_000));
        assert!(
            o.contains(&("blksize".to_string(), "1468".to_string())),
            "{o:?}"
        );
        assert!(
            o.contains(&("tsize".to_string(), "100000".to_string())),
            "{o:?}"
        );
        let (d, _) = get(srv.port, "f6.bin", &[("blksize", "1024"), ("timeout", "2")]).unwrap();
        assert_eq!(d.len(), 100_000);
        // a size that is an exact multiple of the negotiated block size ends with an empty block
        std::fs::write(srv.root.join("exact.bin"), pattern(2048)).unwrap();
        let (d, _) = get(srv.port, "exact.bin", &[("blksize", "1024")]).unwrap();
        assert_eq!(d.len(), 2048);
        assert!(srv.ctx.stats.reads_ok.load(Ordering::Relaxed) >= 10);
        assert!(srv.ctx.stats.bytes_sent.load(Ordering::Relaxed) > 200_000);
        let j = srv.ctx.stats_json();
        assert!(j["recent"].as_array().unwrap().len() <= 20);
    }

    #[test]
    fn nothing_outside_the_root_is_readable() {
        let Some(srv) = start(|_| {}) else { return };
        let outside = srv._dir.path().join("secret.txt");
        std::fs::write(&outside, "top secret").unwrap();
        std::fs::write(srv.root.join(".hidden"), "h").unwrap();
        std::os::unix::fs::symlink(&outside, srv.root.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(srv._dir.path(), srv.root.join("dirlink")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", srv.root.join("abs")).unwrap();
        for name in [
            "../secret.txt",
            "sub/../../secret.txt",
            "..%2fsecret.txt",
            "/etc/passwd",
            ".hidden",
            "link.txt",
            "dirlink/secret.txt",
            "abs",
            "sub",
            "missing.bin",
            "a\\..\\secret.txt",
        ] {
            let r = get(srv.port, name, &[]);
            assert!(
                matches!(&r, Err((c, _)) if (1..=2).contains(c)),
                "{name:?} must be refused with 'not found' or 'access violation', got {:?}",
                r.map(|(d, _)| d.len())
            );
        }
        // netascii and mail modes are refused (binary only)
        let s = udp();
        s.send_to(&rrq("x", "netascii", &[]), ("127.0.0.1", srv.port))
            .unwrap();
        let mut b = [0u8; 600];
        let (n, _) = s.recv_from(&mut b).unwrap();
        assert_eq!(proto::opcode(&b[..n]), Some(proto::ERROR));
        assert_eq!(b[3], 4);
    }

    #[test]
    fn a_device_node_or_fifo_is_not_served() {
        let Some(srv) = start(|_| {}) else { return };
        let fifo = srv.root.join("pipe");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let r = get(srv.port, "pipe", &[]);
        assert!(matches!(r, Err((2, _))), "{:?}", r.map(|x| x.0.len()));
    }

    #[test]
    fn uploads_are_off_by_default_and_safe_when_on() {
        let Some(ro) = start(|_| {}) else { return };
        let r = put(ro.port, "new.bin", b"data", &[]);
        assert!(
            matches!(r, Err((2, ref m)) if m.contains("disabled")),
            "{r:?}"
        );
        assert!(!ro.root.join("new.bin").exists());
        assert_eq!(ro.ctx.stats.denied_write.load(Ordering::Relaxed), 1);
        drop(ro);

        let Some(srv) = start(|c| c.allow_write = true) else {
            return;
        };
        // new file, odd size, multi-block, with a negotiated block size
        put(srv.port, "new.bin", &pattern(5000), &[]).unwrap();
        assert_eq!(
            std::fs::read(srv.root.join("new.bin")).unwrap(),
            pattern(5000)
        );
        put(
            srv.port,
            "sub/b.bin",
            &pattern(4096),
            &[("blksize", "1024"), ("tsize", "4096")],
        )
        .unwrap();
        assert_eq!(
            std::fs::read(srv.root.join("sub/b.bin")).unwrap(),
            pattern(4096)
        );
        // an empty upload and an exact multiple of the block size
        put(srv.port, "empty.bin", b"", &[]).unwrap();
        assert_eq!(std::fs::read(srv.root.join("empty.bin")).unwrap().len(), 0);
        // existing files are not replaced without `overwrite`
        let r = put(srv.port, "new.bin", b"other", &[]);
        assert!(matches!(r, Err((6, _))), "{r:?}");
        assert_eq!(
            std::fs::read(srv.root.join("new.bin")).unwrap(),
            pattern(5000)
        );
        // names that climb, hide, or land in a missing directory are refused
        for bad in ["../esc.bin", ".dot", "nodir/x.bin", "/etc/x", "sub"] {
            assert!(put(srv.port, bad, b"x", &[]).is_err(), "{bad}");
        }
        assert!(!srv._dir.path().join("esc.bin").exists());
        // a symlink in the root is never followed for a write
        let outside = srv._dir.path().join("victim");
        std::fs::write(&outside, "keep").unwrap();
        std::os::unix::fs::symlink(&outside, srv.root.join("ln")).unwrap();
        assert!(put(srv.port, "ln", b"overwritten", &[]).is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        // size cap (64 KiB): announced size refused up front, unannounced aborted and removed
        let r = put(
            srv.port,
            "big1.bin",
            &vec![1u8; 70_000],
            &[("tsize", "70000")],
        );
        assert!(matches!(r, Err((3, _))), "{r:?}");
        let r = put(srv.port, "big2.bin", &vec![1u8; 70_000], &[]);
        assert!(r.is_err(), "{r:?}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!srv.root.join("big2.bin").exists());
        let left: Vec<String> = std::fs::read_dir(&srv.root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into())
            .collect();
        assert!(!left.iter().any(|n| n.ends_with(".part")), "{left:?}");
        assert!(srv.ctx.stats.writes_ok.load(Ordering::Relaxed) >= 3);
    }

    #[test]
    fn overwrite_replaces_atomically() {
        let Some(srv) = start(|c| {
            c.allow_write = true;
            c.overwrite = true;
        }) else {
            return;
        };
        std::fs::write(srv.root.join("cfg.txt"), "old").unwrap();
        put(srv.port, "cfg.txt", &pattern(3000), &[]).unwrap();
        assert_eq!(
            std::fs::read(srv.root.join("cfg.txt")).unwrap(),
            pattern(3000)
        );
    }

    #[test]
    fn only_listed_client_networks_are_served() {
        let Some(srv) = start(|c| c.clients = vec!["10.99.0.0/24".into()]) else {
            return;
        };
        std::fs::write(srv.root.join("a.bin"), "x").unwrap();
        let r = get(srv.port, "a.bin", &[]);
        assert!(matches!(r, Err((2, _))), "{:?}", r.map(|x| x.0));
        assert_eq!(srv.ctx.stats.denied_client.load(Ordering::Relaxed), 1);
        drop(srv);
        let Some(srv) = start(|c| c.clients = vec!["127.0.0.0/8".into()]) else {
            return;
        };
        std::fs::write(srv.root.join("a.bin"), "x").unwrap();
        assert_eq!(get(srv.port, "a.bin", &[]).unwrap().0, b"x");
    }

    #[test]
    fn concurrent_transfers_are_bounded_and_a_wrong_tid_is_rejected() {
        let Some(srv) = start(|c| c.max_sessions = 2) else {
            return;
        };
        std::fs::write(srv.root.join("a.bin"), pattern(10_000)).unwrap();
        // two transfers started and left unanswered occupy both slots
        let mut held = Vec::new();
        for _ in 0..2 {
            let s = udp();
            s.send_to(&rrq("a.bin", "octet", &[]), ("127.0.0.1", srv.port))
                .unwrap();
            let mut b = [0u8; 600];
            let (_, from) = s.recv_from(&mut b).unwrap(); // block 1, never acknowledged
            held.push((s, from));
        }
        let r = get(srv.port, "a.bin", &[]);
        assert!(matches!(r, Err((0, ref m)) if m.contains("busy")), "{r:?}");
        assert_eq!(srv.ctx.stats.busy.load(Ordering::Relaxed), 1);
        // a stranger writing to a transfer's port gets ERROR 5 and does not disturb it
        let stranger = udp();
        stranger.send_to(&proto::ack(1), held[0].1).unwrap();
        let mut b = [0u8; 600];
        let (n, _) = stranger.recv_from(&mut b).unwrap();
        assert_eq!(proto::opcode(&b[..n]), Some(proto::ERROR));
        assert_eq!(b[3], 5);
        // the held client finishes normally afterwards
        let (s, from) = &held[0];
        s.send_to(&proto::ack(1), from).unwrap();
        let (n, _) = s.recv_from(&mut b).unwrap();
        assert_eq!(proto::opcode(&b[..n]), Some(proto::DATA));
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 2);
        // garbage on the request port is counted and ignored
        let g = udp();
        g.send_to(&[1, 2, 3], ("127.0.0.1", srv.port)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(srv.ctx.stats.bad_requests.load(Ordering::Relaxed) >= 1);
        let _ = Ipv4Addr::LOCALHOST;
    }

    #[test]
    fn lost_packets_are_retransmitted() {
        let Some(srv) = start(|_| {}) else { return };
        std::fs::write(srv.root.join("a.bin"), pattern(3000)).unwrap();
        let s = udp();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.send_to(&rrq("a.bin", "octet", &[]), ("127.0.0.1", srv.port))
            .unwrap();
        let mut b = [0u8; 700];
        let (n1, from) = s.recv_from(&mut b).unwrap();
        let first = b[..n1].to_vec();
        // do not acknowledge: the server must send the same block again
        let (n2, _) = s.recv_from(&mut b).unwrap();
        assert_eq!(&b[..n2], &first[..], "retransmission of block 1");
        s.send_to(&proto::ack(1), from).unwrap();
        let (_, _) = s.recv_from(&mut b).unwrap();
    }
}
