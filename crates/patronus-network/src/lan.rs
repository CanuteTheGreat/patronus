//! Shared plumbing for the LAN-service appliers (lane D): DHCP
//! ([`crate::dhcp`]), DNS ([`crate::dns`]), NTP ([`crate::ntp`]) and DDNS
//! ([`crate::ddns`]).
//!
//! How every LAN service is applied:
//! 1. read the subsystem's rows from the config store (tables created by
//!    `patronus-config/migrations/0300_d_lan_services.sql`),
//! 2. resolve interface roles (`@lan`, `@opt1`) to devices and look up the
//!    router's live addresses on them,
//! 3. render the daemon's config **at the path the Gentoo package's own
//!    OpenRC script and systemd unit read** (`/etc/kea/kea-dhcp4.conf`,
//!    `/etc/dnsmasq.conf`, `/etc/unbound/unbound.conf`, `/etc/radvd.conf`,
//!    `/etc/chrony/chrony.conf`), checked with the daemon's own validator
//!    *before* it replaces the live file (temp file + rename),
//! 4. (re)start or stop the daemon through [`patronus_core::ServiceManager`],
//!    which drives OpenRC (`rc-service`) or systemd (`systemctl`).
//!
//! Patronus only stops a daemon whose config file carries its
//! [`MARKER`], so a hand-maintained daemon on the same box is left alone.

use patronus_config::store::ConfigStore;
use patronus_config::ApplyReport;
use patronus_core::service::{InitSystem, ServiceManager};
use patronus_core::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// First-line marker of every config file Patronus owns.
pub const MARKER: &str = "Managed by Patronus";

/// Every table lane D owns (web undo + docs).
pub const LAN_TABLES: &[&str] = &[
    "lan_settings",
    "dhcp_pools",
    "dhcp_static_mappings",
    "dhcp6_pools",
    "ra_interfaces",
    "dhcp_relays",
    "dns_host_overrides",
    "dns_domain_overrides",
    "dns_blocklist",
    "ddns_clients",
];

pub(crate) fn db_err(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn invalid(msg: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {msg}"))
}

/// A UNIQUE-constraint failure is a client error ("Invalid ..." -> 400).
pub(crate) fn unique_err(e: sqlx::Error, what: &str) -> Error {
    if e.to_string().contains("UNIQUE") {
        invalid(format!("request: {what} is already configured"))
    } else {
        Error::Config(format!("store: {e}"))
    }
}

// ---------------------------------------------------------------------------
// settings (lan_settings key/value)
// ---------------------------------------------------------------------------

pub async fn get_setting(store: &ConfigStore, key: &str) -> Result<Option<String>> {
    let row = sqlx::query("SELECT value FROM lan_settings WHERE key = ?")
        .bind(key)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db_err("read lan setting"))?;
    Ok(row.map(|r| r.get::<String, _>(0)))
}

pub async fn setting_or(store: &ConfigStore, key: &str, default: &str) -> Result<String> {
    Ok(get_setting(store, key)
        .await?
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string()))
}

pub async fn set_setting(store: &ConfigStore, key: &str, value: &str) -> Result<()> {
    if value.contains('\n') || value.contains('\r') {
        return Err(invalid(format!("value for {key}")));
    }
    sqlx::query(
        "INSERT INTO lan_settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(db_err("write lan setting"))?;
    Ok(())
}

pub async fn settings_with_prefix(
    store: &ConfigStore,
    prefix: &str,
) -> Result<BTreeMap<String, String>> {
    let rows = sqlx::query("SELECT key, value FROM lan_settings WHERE key LIKE ? ORDER BY key")
        .bind(format!("{prefix}%"))
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read lan settings"))?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))
        .collect())
}

pub fn flag(v: &str) -> bool {
    matches!(v.trim(), "1" | "true" | "yes" | "on")
}

// ---------------------------------------------------------------------------
// validation (everything that ends up in a daemon config goes through here)
// ---------------------------------------------------------------------------

/// `@wan` / `@lan` / `@optN` role token or a kernel device name.
pub fn valid_iface_spec(s: &str) -> bool {
    if let Some(role) = s.strip_prefix('@') {
        return patronus_config::store::is_valid_role(role);
    }
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub fn check_iface_spec(s: &str) -> Result<String> {
    let s = s.trim();
    if valid_iface_spec(s) {
        Ok(s.to_string())
    } else {
        Err(invalid(format!(
            "interface {s:?} (use @lan, @optN or a device name)"
        )))
    }
}

/// DNS name (hostname or domain), letters/digits/hyphen labels; `_`
/// allowed when `allow_underscore` (block lists contain such names).
pub fn valid_dns_name(s: &str, allow_underscore: bool) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (allow_underscore && b == b'_'))
    })
}

pub fn check_dns_name(what: &str, s: &str) -> Result<String> {
    let t = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if valid_dns_name(&t, false) {
        Ok(t)
    } else {
        Err(invalid(format!("{what} {s:?}")))
    }
}

/// Single DNS label (a host name without domain).
pub fn check_label(what: &str, s: &str) -> Result<String> {
    let t = s.trim().to_ascii_lowercase();
    if valid_dns_name(&t, false) && !t.contains('.') {
        Ok(t)
    } else {
        Err(invalid(format!("{what} {s:?}")))
    }
}

/// MAC address, normalised to lowercase `aa:bb:cc:dd:ee:ff`.
pub fn check_mac(s: &str) -> Result<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        Ok(parts.join(":").to_ascii_lowercase())
    } else {
        Err(invalid(format!("MAC address {s:?}")))
    }
}

/// Comma/space separated IP list; empty input = empty list.
pub fn parse_ip_list(what: &str, s: &str) -> Result<Vec<IpAddr>> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            t.parse::<IpAddr>()
                .map_err(|_| invalid(format!("{what} address {t:?}")))
        })
        .collect()
}

pub fn join_ips(v: &[IpAddr]) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        Some(
            v.iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

/// Free-text description: one line, no control characters.
pub fn check_description(s: Option<&str>) -> Result<Option<String>> {
    match s.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(d) if d.len() <= 200 && !d.chars().any(|c| c.is_control()) => Ok(Some(d.into())),
        Some(_) => Err(invalid("description (one line, at most 200 characters)")),
    }
}

// ---------------------------------------------------------------------------
// interfaces and addresses
// ---------------------------------------------------------------------------

/// One address configured on an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IfAddr {
    pub ifname: String,
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IfAddr {
    pub fn network(&self) -> Option<ipnetwork::IpNetwork> {
        ipnetwork::IpNetwork::new(self.addr, self.prefix)
            .ok()
            .and_then(|n| ipnetwork::IpNetwork::new(n.network(), self.prefix).ok())
    }
    pub fn is_global_v6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) != 0xfe80 && !a.is_loopback())
    }
}

/// Where the live interface addresses come from (`ip -j addr` on a box,
/// a fixed list in tests).
pub trait AddrSource: Send + Sync {
    fn addrs(&self) -> Result<Vec<IfAddr>>;
}

/// `ip -j addr show`.
pub struct LiveAddrs;

impl AddrSource for LiveAddrs {
    fn addrs(&self) -> Result<Vec<IfAddr>> {
        let out = Command::new("ip")
            .args(["-j", "addr", "show"])
            .output()
            .map_err(|e| Error::Network(format!("ip -j addr show: {e}")))?;
        if !out.status.success() {
            return Err(Error::Network(format!(
                "ip -j addr show: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        parse_ip_json(&String::from_utf8_lossy(&out.stdout))
    }
}

pub fn parse_ip_json(s: &str) -> Result<Vec<IfAddr>> {
    let v: Value = serde_json::from_str(s)
        .map_err(|e| Error::Network(format!("parse ip -j addr output: {e}")))?;
    let mut out = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        let Some(ifname) = link.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        for a in link
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(local), Some(prefix)) = (
                a.get("local").and_then(Value::as_str),
                a.get("prefixlen").and_then(Value::as_u64),
            ) else {
                continue;
            };
            if let Ok(addr) = local.parse() {
                out.push(IfAddr {
                    ifname: ifname.to_string(),
                    addr,
                    prefix: prefix as u8,
                });
            }
        }
    }
    Ok(out)
}

/// Fixed address list (tests).
pub struct StaticAddrs(pub Vec<IfAddr>);

impl AddrSource for StaticAddrs {
    fn addrs(&self) -> Result<Vec<IfAddr>> {
        Ok(self.0.clone())
    }
}

/// Resolve an interface spec to devices: a role token gives every enabled
/// interface carrying that role (none if unassigned), a device name gives
/// itself.
pub async fn resolve_iface(store: &ConfigStore, spec: &str) -> Result<Vec<String>> {
    match spec.strip_prefix('@') {
        Some(role) => store.interfaces_with_role(role).await,
        None => Ok(vec![spec.to_string()]),
    }
}

// ---------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------

/// Start/stop daemons (OpenRC or systemd via [`ServiceManager`]; a recorder
/// in tests).
pub trait ServiceControl: Send + Sync {
    fn is_running(&self, svc: &str) -> bool;
    /// (Re)start `svc` so it runs with its current config.
    fn restart(&self, svc: &str) -> Result<()>;
    fn stop(&self, svc: &str) -> Result<()>;
}

/// The real init system.
///
/// Boot-time caveat: the boot unit (`patronus-firewall`) runs before the
/// network target, while the distro units of dnsmasq/unbound/kea are
/// ordered after it, so a blocking `systemctl restart` from inside the boot
/// unit would deadlock. While the system is still booting (systemd
/// `is-system-running` = initializing/starting, or
/// `PATRONUS_DEFER_SERVICES=1`, which the OpenRC boot script exports) the
/// start is queued instead (`systemctl --no-block`, a detached
/// `rc-service`), after the config has been validated.
pub struct SystemServices;

impl SystemServices {
    fn manager() -> ServiceManager {
        ServiceManager::new()
    }

    fn defer() -> bool {
        if std::env::var("PATRONUS_DEFER_SERVICES").is_ok_and(|v| flag(&v)) {
            return true;
        }
        if ServiceManager::detect_init_system() == InitSystem::Systemd {
            if let Ok(o) = Command::new("systemctl").arg("is-system-running").output() {
                let s = String::from_utf8_lossy(&o.stdout);
                return matches!(s.trim(), "initializing" | "starting");
            }
        }
        false
    }
}

impl ServiceControl for SystemServices {
    fn is_running(&self, svc: &str) -> bool {
        Self::manager().is_running(svc).unwrap_or(false)
    }

    fn restart(&self, svc: &str) -> Result<()> {
        let m = Self::manager();
        if Self::defer() {
            let mut c = match m.init_system() {
                InitSystem::Systemd => {
                    let mut c = Command::new("systemctl");
                    c.args(["--no-block", "restart", svc]);
                    c
                }
                _ => {
                    let mut c = Command::new("rc-service");
                    c.args([svc, "restart"]);
                    c
                }
            };
            c.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| Error::Service(format!("queue start of {svc}: {e}")))?;
            return Ok(());
        }
        m.restart(svc)?;
        // Type=simple units report "active" at once even if the daemon dies
        // on its config a moment later: look again before calling it done.
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(300));
            if m.is_running(svc).unwrap_or(false) {
                return Ok(());
            }
        }
        let hint = match m.init_system() {
            InitSystem::Systemd => format!("see `journalctl -u {svc}`"),
            _ => format!("see `rc-service {svc} status` and the system log"),
        };
        Err(Error::Service(format!(
            "{svc} did not stay running ({hint})"
        )))
    }

    fn stop(&self, svc: &str) -> Result<()> {
        Self::manager().stop(svc)
    }
}

/// Records calls instead of touching the system (tests).
#[derive(Default)]
pub struct RecordingServices {
    pub log: std::sync::Mutex<Vec<String>>,
    pub running: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl ServiceControl for RecordingServices {
    fn is_running(&self, svc: &str) -> bool {
        self.running.lock().unwrap().contains(svc)
    }
    fn restart(&self, svc: &str) -> Result<()> {
        self.log.lock().unwrap().push(format!("restart {svc}"));
        self.running.lock().unwrap().insert(svc.to_string());
        Ok(())
    }
    fn stop(&self, svc: &str) -> Result<()> {
        self.log.lock().unwrap().push(format!("stop {svc}"));
        self.running.lock().unwrap().remove(svc);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// environment: filesystem root + services + addresses
// ---------------------------------------------------------------------------

/// What the LAN appliers act on. [`LanEnv::system`] in production; tests
/// point `root` at a temp dir and use fakes.
#[derive(Clone)]
pub struct LanEnv {
    pub root: PathBuf,
    pub services: Arc<dyn ServiceControl>,
    pub addrs: Arc<dyn AddrSource>,
    /// Run the daemons' own config validators before installing a file.
    pub check_configs: bool,
}

impl Default for LanEnv {
    fn default() -> Self {
        Self::system()
    }
}

impl LanEnv {
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            services: Arc::new(SystemServices),
            addrs: Arc::new(LiveAddrs),
            check_configs: true,
        }
    }

    /// Absolute system path under this environment's root.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn has_binary(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }

    pub fn addrs(&self) -> Result<Vec<IfAddr>> {
        self.addrs.addrs()
    }
}

/// A config file Patronus owns.
pub struct ManagedFile {
    /// Absolute path on the system (joined under [`LanEnv::root`]).
    pub path: &'static str,
    pub content: String,
    pub mode: u32,
    /// Group that must own the file (the daemon's group), if it exists.
    pub group: Option<&'static str>,
    /// Validator argv; `{}` is replaced by the candidate file's path.
    pub check: Option<Vec<&'static str>>,
}

/// Header for a managed file (`comment` = the file's comment leader).
pub fn header(comment: &str, what: &str) -> String {
    format!(
        "{comment} {MARKER} ({what}). Do not edit: `patronus apply` and the web UI\n\
         {comment} regenerate this file from /var/lib/patronus/config.db.\n"
    )
}

/// Does the file at `abs` carry the [`MARKER`]?
pub fn is_managed(env: &LanEnv, abs: &str) -> bool {
    std::fs::read_to_string(env.path(abs))
        .map(|s| s.lines().take(3).any(|l| l.contains(MARKER)))
        .unwrap_or(false)
}

fn chown_group(path: &Path, group: &str) {
    if let Ok(Some(g)) = nix::unistd::Group::from_name(group) {
        if let Err(e) = nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(g.gid)) {
            tracing::warn!("chown root:{group} {}: {e}", path.display());
        }
    }
}

/// Create a runtime/state directory for a daemon if it is missing.
pub fn ensure_dir(env: &LanEnv, abs: &str, mode: u32, owner: Option<(&str, &str)>) {
    let p = env.path(abs);
    if p.is_dir() {
        return;
    }
    if std::fs::create_dir_all(&p).is_err() {
        return;
    }
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode));
    if let Some((u, g)) = owner {
        let uid = nix::unistd::User::from_name(u)
            .ok()
            .flatten()
            .map(|u| u.uid);
        let gid = nix::unistd::Group::from_name(g)
            .ok()
            .flatten()
            .map(|g| g.gid);
        let _ = nix::unistd::chown(&p, uid, gid);
    }
}

/// Install `f` if its content differs: write a temp file next to it, run
/// the validator on it, then rename over the live file. Returns whether the
/// file changed. A file that fails validation never replaces the live one.
pub fn install(env: &LanEnv, f: &ManagedFile) -> Result<bool> {
    let path = env.path(f.path);
    if std::fs::read_to_string(&path).ok().as_deref() == Some(f.content.as_str()) {
        // still enforce ownership (kea's OpenRC script insists on root:dhcp)
        if let Some(g) = f.group {
            chown_group(&path, g);
        }
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.patronus-new",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("conf")
    ));
    std::fs::write(&tmp, &f.content)
        .map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(f.mode));
    if let Some(g) = f.group {
        chown_group(&tmp, g);
    }
    if env.check_configs {
        if let Some(argv) = &f.check {
            let args: Vec<String> = argv
                .iter()
                .map(|a| a.replace("{}", &tmp.to_string_lossy()))
                .collect();
            let res = Command::new(&args[0]).args(&args[1..]).output();
            let failure = match res {
                Ok(o) if o.status.success() => None,
                Ok(o) => Some(format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )),
                Err(e) => Some(format!("cannot run {}: {e}", args[0])),
            };
            if let Some(msg) = failure {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::Config(format!(
                    "Invalid generated {} (rejected by {}, live file left unchanged): {}",
                    f.path,
                    args[0],
                    msg.trim()
                )));
            }
        }
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| Error::Config(format!("install {}: {e}", path.display())))?;
    Ok(true)
}

/// Bring one daemon in line: needed -> running with the current config
/// (restart when the config changed or it is down); not needed -> stopped,
/// but only if Patronus owns its config file.
pub fn reconcile(
    env: &LanEnv,
    svc: &str,
    needed: bool,
    changed: bool,
    managed_path: &str,
    rep: &mut ApplyReport,
) -> Result<()> {
    if needed {
        let running = env.services.is_running(svc);
        if changed || !running {
            env.services.restart(svc)?;
            rep.applied(format!(
                "{svc} {}",
                if running {
                    "restarted with the new config"
                } else {
                    "started"
                }
            ));
        } else {
            rep.applied(format!("{svc} running, config unchanged"));
        }
    } else if is_managed(env, managed_path) && env.services.is_running(svc) {
        env.services.stop(svc)?;
        rep.applied(format!("{svc} stopped (nothing configured)"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// dnsmasq: shared by DHCP (v4/v6/RA/relay) and DNS (forwarder mode)
// ---------------------------------------------------------------------------

pub const DNSMASQ_CONF: &str = "/etc/dnsmasq.conf";
pub const DNSMASQ_BIN: &str = "/usr/sbin/dnsmasq";
pub const DNSMASQ_LEASES: &str = "/var/lib/misc/dnsmasq.leases";

/// Lines a subsystem contributes to `/etc/dnsmasq.conf`.
#[derive(Debug, Default, Clone)]
pub struct DnsmasqPart {
    /// Devices dnsmasq must listen on.
    pub interfaces: Vec<String>,
    pub lines: Vec<String>,
    /// This part serves DNS (otherwise `port=0`).
    pub dns: bool,
}

/// Render the whole dnsmasq config from the store (DHCP + DNS parts).
/// `None` = dnsmasq is not needed.
pub async fn render_dnsmasq(
    store: &ConfigStore,
    env: &LanEnv,
    rep: &mut ApplyReport,
) -> Result<Option<String>> {
    #[allow(unused_mut)]
    let mut parts: Vec<(&str, DnsmasqPart)> = Vec::new();
    #[cfg(feature = "dhcp")]
    parts.push(("DHCP", crate::dhcp::dnsmasq_part(store, env, rep).await?));
    #[cfg(feature = "dns")]
    parts.push(("DNS", crate::dns::dnsmasq_part(store, env, rep).await?));
    let _ = (&store, &env, &rep);
    if parts.iter().all(|(_, p)| p.lines.is_empty()) {
        return Ok(None);
    }
    let mut ifaces: Vec<String> = parts
        .iter()
        .flat_map(|(_, p)| p.interfaces.clone())
        .collect();
    ifaces.sort();
    ifaces.dedup();
    let dns = parts.iter().any(|(_, p)| p.dns);
    let mut s = header(
        "#",
        "dnsmasq: DHCP, router advertisements, relay, DNS forwarder",
    );
    s.push_str("bind-dynamic\n");
    for i in &ifaces {
        s.push_str(&format!("interface={i}\n"));
    }
    if !dns {
        s.push_str("# DNS is served by the resolver (or disabled): DHCP/RA only\nport=0\n");
    }
    for (name, p) in &parts {
        if p.lines.is_empty() {
            continue;
        }
        s.push_str(&format!("\n# --- {name} ---\n"));
        for l in &p.lines {
            s.push_str(l);
            s.push('\n');
        }
    }
    Ok(Some(s))
}

/// Install `/etc/dnsmasq.conf` and (re)start/stop dnsmasq. Called by both
/// the DHCP and the DNS applier; full state each time, so idempotent.
pub async fn sync_dnsmasq(store: &ConfigStore, env: &LanEnv, rep: &mut ApplyReport) -> Result<()> {
    match render_dnsmasq(store, env, rep).await? {
        Some(conf) => {
            if !env.has_binary(DNSMASQ_BIN) {
                return Err(Error::Service(
                    "dnsmasq is needed for this configuration but /usr/sbin/dnsmasq is not \
                     installed (emerge net-dns/dnsmasq, USE=dnsmasq or USE=dhcp)"
                        .into(),
                ));
            }
            if let Some(dir) = env.path(DNSMASQ_LEASES).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let changed = install(
                env,
                &ManagedFile {
                    path: DNSMASQ_CONF,
                    content: conf,
                    mode: 0o644,
                    group: None,
                    check: Some(vec![DNSMASQ_BIN, "--test", "-C", "{}"]),
                },
            )?;
            if changed {
                rep.applied(format!("wrote {DNSMASQ_CONF}"));
            }
            reconcile(env, "dnsmasq", true, changed, DNSMASQ_CONF, rep)
        }
        None => reconcile(env, "dnsmasq", false, false, DNSMASQ_CONF, rep),
    }
}

// ---------------------------------------------------------------------------
// web undo: lane-scoped table snapshot
// ---------------------------------------------------------------------------

/// Rows of every lane-D table (used by the web UI to undo a store write
/// when the applier rejects it).
pub async fn snapshot_tables(store: &ConfigStore) -> Result<Value> {
    let doc = store.export_json().await?;
    let mut out = serde_json::Map::new();
    if let Some(t) = doc.get("tables").and_then(Value::as_object) {
        for name in LAN_TABLES {
            if let Some(rows) = t.get(*name) {
                out.insert((*name).to_string(), rows.clone());
            }
        }
    }
    Ok(Value::Object(out))
}

/// Put lane-D tables back to a [`snapshot_tables`] state.
pub async fn restore_tables(store: &ConfigStore, snap: &Value) -> Result<()> {
    let Some(tables) = snap.as_object() else {
        return Ok(());
    };
    let mut tx = store
        .pool()?
        .begin()
        .await
        .map_err(db_err("begin restore"))?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await
        .map_err(db_err("defer fks"))?;
    for name in LAN_TABLES {
        let Some(rows) = tables.get(*name).and_then(Value::as_array) else {
            continue;
        };
        sqlx::query(&format!("DELETE FROM \"{name}\""))
            .execute(&mut *tx)
            .await
            .map_err(db_err("clear table"))?;
        for row in rows {
            let Some(obj) = row.as_object() else { continue };
            let cols: Vec<&String> = obj.keys().collect();
            if cols.is_empty()
                || !cols
                    .iter()
                    .all(|c| c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            {
                continue;
            }
            let sql = format!(
                "INSERT INTO \"{name}\" ({}) VALUES ({})",
                cols.iter()
                    .map(|c| format!("\"{c}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                vec!["?"; cols.len()].join(", ")
            );
            let mut q = sqlx::query(&sql);
            for c in &cols {
                q = match &obj[*c] {
                    Value::Null => q.bind(None::<String>),
                    Value::Bool(b) => q.bind(*b as i64),
                    Value::Number(n) if n.is_i64() => q.bind(n.as_i64()),
                    Value::Number(n) => q.bind(n.as_f64()),
                    Value::String(s) => q.bind(s.clone()),
                    other => q.bind(other.to_string()),
                };
            }
            q.execute(&mut *tx).await.map_err(db_err("restore row"))?;
        }
    }
    tx.commit().await.map_err(db_err("commit restore"))?;
    Ok(())
}

/// Every LAN-service applier compiled into this build, in apply order
/// (`patronus apply` registers these in the services phase).
pub fn appliers() -> Vec<Arc<dyn patronus_config::Applier>> {
    appliers_with(LanEnv::system())
}

/// [`appliers`] over a custom environment (tests).
// cfg-gated pushes: vec![] cannot express them
#[allow(clippy::vec_init_then_push)]
pub fn appliers_with(env: LanEnv) -> Vec<Arc<dyn patronus_config::Applier>> {
    #[allow(unused_mut)]
    let mut v: Vec<Arc<dyn patronus_config::Applier>> = Vec::new();
    #[cfg(feature = "dns")]
    v.push(Arc::new(crate::dns::DnsApplier::new(env.clone())));
    #[cfg(feature = "dhcp")]
    v.push(Arc::new(crate::dhcp::DhcpApplier::new(env.clone())));
    #[cfg(feature = "ntp")]
    v.push(Arc::new(crate::ntp::NtpApplier::new(env.clone())));
    #[cfg(feature = "dns")]
    v.push(Arc::new(crate::ddns::DdnsApplier::new(env.clone())));
    let _ = env;
    v
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    pub struct TestEnv {
        pub env: LanEnv,
        pub services: Arc<RecordingServices>,
        _dir: tempfile::TempDir,
    }

    /// LAN box: rtr-lan 192.168.50.1/24 + fd00:50::1/64, rtr-wan
    /// 203.0.113.2/24, with dnsmasq/kea/unbound/radvd/chronyd "installed".
    pub fn env(binaries: &[&str]) -> TestEnv {
        let dir = tempfile::tempdir().unwrap();
        for b in binaries {
            let p = dir.path().join(b.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "").unwrap();
        }
        let services = Arc::new(RecordingServices::default());
        let a = |i: &str, s: &str, p| IfAddr {
            ifname: i.into(),
            addr: s.parse().unwrap(),
            prefix: p,
        };
        let env = LanEnv {
            root: dir.path().to_path_buf(),
            services: services.clone(),
            addrs: Arc::new(StaticAddrs(vec![
                a("lo", "127.0.0.1", 8),
                a("rtr-lan", "192.168.50.1", 24),
                a("rtr-lan", "fd00:50::1", 64),
                a("rtr-lan", "fe80::1", 64),
                a("rtr-wan", "203.0.113.2", 24),
                a("rtr-opt1", "192.168.60.1", 24),
            ])),
            check_configs: false,
        };
        TestEnv {
            env,
            services,
            _dir: dir,
        }
    }

    pub async fn store() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_interface_role("rtr-lan", Some("lan")).await.unwrap();
        s.set_interface_role("rtr-wan", Some("wan")).await.unwrap();
        s
    }

    pub fn read(t: &TestEnv, abs: &str) -> String {
        std::fs::read_to_string(t.env.path(abs)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_config_injection() {
        assert!(
            valid_iface_spec("@lan") && valid_iface_spec("@opt3") && valid_iface_spec("eth0.100")
        );
        assert!(!valid_iface_spec("@dmz") && !valid_iface_spec("eth0\ninterface=wan"));
        assert!(check_dns_name("domain", "corp.example.").is_ok());
        assert!(check_dns_name("domain", "a\"b.example").is_err());
        assert!(check_dns_name("domain", "x.example\nserver=1.2.3.4").is_err());
        assert!(check_label("host", "nas").is_ok() && check_label("host", "nas.lan").is_err());
        assert_eq!(check_mac("AA-BB-CC-00-00-02").unwrap(), "aa:bb:cc:00:00:02");
        assert!(check_mac("aa:bb:cc:00:00").is_err());
        assert!(
            parse_ip_list("dns", "1.1.1.1, 2606:4700::1111")
                .unwrap()
                .len()
                == 2
        );
        assert!(parse_ip_list("dns", "1.1.1.1;rm").is_err());
        assert!(check_description(Some("a\nb")).is_err());
    }

    #[test]
    fn parses_ip_json() {
        let j = r#"[{"ifindex":2,"ifname":"rtr-lan","addr_info":[{"family":"inet","local":"192.168.50.1","prefixlen":24},{"family":"inet6","local":"fd00:50::1","prefixlen":64}]}]"#;
        let v = parse_ip_json(j).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(
            v[0].network().unwrap().to_string(),
            "192.168.50.0/24".to_string()
        );
        assert!(v[1].is_global_v6());
    }

    #[tokio::test]
    async fn install_is_atomic_and_idempotent_and_reconcile_respects_ownership() {
        let t = testutil::env(&[]);
        let f = ManagedFile {
            path: "/etc/x.conf",
            content: header("#", "x") + "a=1\n",
            mode: 0o644,
            group: None,
            check: None,
        };
        assert!(install(&t.env, &f).unwrap());
        assert!(!install(&t.env, &f).unwrap(), "second install is a no-op");
        assert!(is_managed(&t.env, "/etc/x.conf"));
        let mut rep = ApplyReport::default();
        // a hand-maintained daemon is never stopped
        std::fs::write(t.env.path("/etc/y.conf"), "mine\n").unwrap();
        t.services.restart("y").unwrap();
        reconcile(&t.env, "y", false, false, "/etc/y.conf", &mut rep).unwrap();
        assert!(t.services.is_running("y"));
        t.services.restart("x").unwrap();
        reconcile(&t.env, "x", false, false, "/etc/x.conf", &mut rep).unwrap();
        assert!(!t.services.is_running("x"));
    }

    #[tokio::test]
    async fn lane_snapshot_restores_rows() {
        let s = testutil::store().await;
        set_setting(&s, "dns.mode", "resolver").await.unwrap();
        let snap = snapshot_tables(&s).await.unwrap();
        set_setting(&s, "dns.mode", "forwarder").await.unwrap();
        set_setting(&s, "ntp.enabled", "1").await.unwrap();
        restore_tables(&s, &snap).await.unwrap();
        assert_eq!(
            get_setting(&s, "dns.mode").await.unwrap().unwrap(),
            "resolver"
        );
        assert!(get_setting(&s, "ntp.enabled").await.unwrap().is_none());
    }
}
