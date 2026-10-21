//! System state: host facts, configuration backups (real files) and the
//! init-managed services Patronus depends on (real systemd/OpenRC state).
//!
//! This file used to hold fixtures: two backups from January 2024 with
//! made-up sizes, a "Create backup" that only inserted a "0 MB" row, five
//! services "Running" for "15d 8h 42m", an always-available
//! `patronus-core 0.1.1` update and invented users. Users now come from the
//! auth store (`state.auth.user_store`); update checks are not implemented
//! (Gentoo updates through Portage) and the API says so.

use patronus_config::{Applier, ConfigStore};
use patronus_core::service::{InitSystem, ServiceManager, ServiceState};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use patronus_network::services::KNOWN_SERVICES;

/// Whether restoring export document `doc` replaces the web accounts:
/// only a document whose `web_users` has an enabled admin does;
/// [`SystemManager::restore`] keeps the current accounts otherwise, so a
/// restore can never lock everyone out.
pub fn restores_accounts(doc: &Value) -> bool {
    doc.get("tables")
        .and_then(|t| t.get("web_users"))
        .is_some_and(has_enabled_admin)
}

fn has_enabled_admin(users: &Value) -> bool {
    users.as_array().is_some_and(|rows| {
        rows.iter().any(|r| {
            r.get("role").and_then(Value::as_str) == Some("admin")
                && r.get("enabled").and_then(Value::as_i64).unwrap_or(1) != 0
        })
    })
}

/// System management operations.
pub struct SystemManager {
    backup_dir: PathBuf,
    /// Every subsystem applier this process can drive (through applyd when
    /// it runs), used to apply a restored configuration.
    appliers: Vec<Arc<dyn Applier>>,
}

/// Where configuration backups live: `$PATRONUS_BACKUP_DIR`, else a
/// `backups` directory next to the config store
/// (`/var/lib/patronus/backups` on an installed box).
pub fn backup_dir_for(db_path: &Path) -> PathBuf {
    if let Some(d) = std::env::var_os("PATRONUS_BACKUP_DIR") {
        return PathBuf::from(d);
    }
    db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("backups")
}

/// A backup name the API accepts: what [`SystemManager::create_backup`]
/// writes, nothing that could leave the backup directory.
pub fn is_backup_name(name: &str) -> bool {
    name.starts_with("patronus-config-")
        && name.ends_with(".json")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

#[derive(Debug)]
pub enum ServiceError {
    /// Not one of [`KNOWN_SERVICES`] or not installed on this box.
    NotManaged(String),
    /// The init system refused or failed (e.g. permission denied).
    Failed(String),
}

impl std::error::Error for ServiceError {}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::NotManaged(n) => write!(
                f,
                "{n} is not a Patronus-managed service installed on this system"
            ),
            ServiceError::Failed(e) => f.write_str(e),
        }
    }
}

impl SystemManager {
    pub fn new(backup_dir: PathBuf) -> Self {
        Self {
            backup_dir,
            appliers: Vec::new(),
        }
    }

    /// The appliers a restore runs, in any order (sorted by boot phase).
    pub fn with_appliers(mut self, mut v: Vec<Arc<dyn Applier>>) -> Self {
        v.sort_by_key(|a| a.phase());
        self.appliers = v;
        self
    }

    async fn apply_all(&self, store: &ConfigStore) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for a in &self.appliers {
            match a.apply(store).await {
                Ok(r) => {
                    out.extend(r.applied.into_iter().map(|l| format!("{}: {l}", a.name())));
                    out.extend(
                        r.warnings
                            .into_iter()
                            .map(|l| format!("{}: warning: {l}", a.name())),
                    );
                }
                Err(e) => return Err(format!("{}: {e}", a.name())),
            }
        }
        Ok(out)
    }

    /// Replace the configuration with an export document and apply it to
    /// the whole system. The previous configuration is kept as a revision;
    /// if any subsystem refuses the restored configuration it is put back
    /// (and re-applied) and the error says which one. A document without
    /// an enabled admin account keeps the current accounts, so a restore
    /// can never lock everyone out.
    pub async fn restore(
        &self,
        store: &ConfigStore,
        doc: &Value,
        what: &str,
    ) -> anyhow::Result<Vec<String>> {
        let mut doc = doc.clone();
        let tables = doc
            .get_mut("tables")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid backup: not a Patronus configuration export (no \"tables\")"
                )
            })?;
        let mut notes = Vec::new();
        if tables
            .get("web_users")
            .is_some_and(|users| !has_enabled_admin(users))
        {
            tables.remove("web_users");
            notes.push(
                "the backup has no enabled admin account: kept the current web accounts"
                    .to_string(),
            );
        }
        let rev = store
            .snapshot("web", &format!("before restore of {what}"))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        store
            .import_json(&doc)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        match self.apply_all(store).await {
            Ok(lines) => {
                let _ = store
                    .audit("web", "restore", "config", Some(what), &Value::Null)
                    .await;
                notes.extend(lines);
                Ok(notes)
            }
            Err(failed) => {
                if let Err(e) = store.restore_revision(rev, "web").await {
                    tracing::error!(
                        "could not put the configuration back after a failed restore: {e}"
                    );
                }
                if let Err(e) = self.apply_all(store).await {
                    tracing::warn!("re-applying the previous configuration: {e}");
                }
                Err(anyhow::anyhow!(
                    "restore of {what} was undone because it could not be applied: {failed}"
                ))
            }
        }
    }

    /// Store an uploaded export as a backup file (so it is listed, can be
    /// downloaded again and restored), after checking it is one.
    pub async fn save_upload(
        &self,
        bytes: &[u8],
    ) -> anyhow::Result<(crate::templates::Backup, Value)> {
        let doc: Value = serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("Invalid backup file: not JSON ({e})"))?;
        if !doc.get("tables").is_some_and(Value::is_object) {
            anyhow::bail!(
                "Invalid backup file: not a Patronus configuration export (no \"tables\")"
            );
        }
        let text = String::from_utf8_lossy(bytes).into_owned();
        let b = self.write_backup_file(text, "-upload").await?;
        Ok((b, doc))
    }

    /// Read a stored backup as a document.
    pub async fn backup_doc(&self, name: &str) -> anyhow::Result<Option<Value>> {
        match self.read_backup(name).await? {
            None => Ok(None),
            Some(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| {
                anyhow::anyhow!("Invalid backup {name}: not JSON ({e})")
            })?)),
        }
    }

    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Dashboard / status facts, measured now.
    pub async fn get_info(&self) -> anyhow::Result<crate::templates::SystemInfo> {
        let s = super::host::sample(std::time::Duration::from_millis(250)).await;
        Ok(crate::templates::SystemInfo {
            hostname: super::host::hostname(),
            uptime: super::host::uptime_secs().unwrap_or(0),
            cpu_usage: s.cpu_percent.unwrap_or(0.0),
            memory_usage: super::host::memory().map(|m| m.0).unwrap_or(0.0),
            disk_usage: super::host::disk_percent("/").unwrap_or(0.0),
            load_avg: super::host::load_average().unwrap_or((0.0, 0.0, 0.0)),
        })
    }

    // --- backups ------------------------------------------------------------

    /// The backup files in the backup directory, newest first, with their
    /// real size and whether they parse as a config export.
    pub async fn list_backups(&self) -> anyhow::Result<Vec<crate::templates::Backup>> {
        let dir = self.backup_dir.clone();
        tokio::task::spawn_blocking(move || {
            let rd = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => anyhow::bail!("{}: {e}", dir.display()),
            };
            let mut out = Vec::new();
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if !is_backup_name(&name) {
                    continue;
                }
                out.push(describe_backup(&ent.path(), &name)?);
            }
            out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.name.cmp(&a.name)));
            Ok(out)
        })
        .await?
    }

    /// Export the whole config store into a new backup file (0600) and
    /// return what was written.
    pub async fn create_backup(
        &self,
        store: &patronus_config::ConfigStore,
    ) -> anyhow::Result<crate::templates::Backup> {
        let doc = store
            .export_json()
            .await
            .map_err(|e| anyhow::anyhow!("exporting the configuration: {e}"))?;
        let text = serde_json::to_string_pretty(&doc)? + "\n";
        self.write_backup_file(text, "").await
    }

    /// Write `text` to a new 0600 file `patronus-config-<time><suffix>.json`.
    async fn write_backup_file(
        &self,
        text: String,
        suffix: &'static str,
    ) -> anyhow::Result<crate::templates::Backup> {
        let dir = self.backup_dir.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
            let now = chrono::Utc::now();
            let base = format!(
                "patronus-config-{}-{:03}{suffix}",
                now.format("%Y%m%d-%H%M%S"),
                now.timestamp_subsec_millis()
            );
            for n in 0..100 {
                let name = if n == 0 {
                    format!("{base}.json")
                } else {
                    format!("{base}-{n}.json")
                };
                let path = dir.join(&name);
                let mut f = match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => anyhow::bail!("{}: {e}", path.display()),
                };
                f.write_all(text.as_bytes())?;
                f.sync_all()?;
                return describe_backup(&path, &name);
            }
            anyhow::bail!(
                "could not pick a free backup file name in {}",
                dir.display()
            )
        })
        .await?
    }

    fn backup_path(&self, name: &str) -> anyhow::Result<PathBuf> {
        if !is_backup_name(name) {
            anyhow::bail!("not a backup name: {name:?}");
        }
        Ok(self.backup_dir.join(name))
    }

    /// The bytes of one backup (for download). `Ok(None)` if absent.
    pub async fn read_backup(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.backup_path(name)?;
        match tokio::fs::read(&path).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("{}: {e}", path.display())),
        }
    }

    /// Delete one backup. `Ok(false)` if it did not exist.
    pub async fn delete_backup(&self, name: &str) -> anyhow::Result<bool> {
        let path = self.backup_path(name)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(anyhow::anyhow!("{}: {e}", path.display())),
        }
    }

    // --- services -----------------------------------------------------------

    /// The installed [`KNOWN_SERVICES`] with their real init-system state.
    pub async fn list_services(&self) -> anyhow::Result<Vec<crate::templates::Service>> {
        Ok(tokio::task::spawn_blocking(|| {
            let mgr = ServiceManager::new();
            installed_services(mgr.init_system())
                .into_iter()
                .map(|(name, description)| probe_service(&mgr, name, description))
                .collect()
        })
        .await?)
    }

    /// start / stop / restart through systemd or OpenRC. Only installed
    /// [`KNOWN_SERVICES`] can be controlled. patronus-web runs unprivileged,
    /// so the request goes to `patronus applyd` (root) whenever its socket
    /// exists; as root (containers) it runs here.
    pub async fn control_service(&self, name: &str, action: &str) -> Result<(), ServiceError> {
        let mgr = ServiceManager::new();
        let installed = installed_services(mgr.init_system());
        if !installed.iter().any(|(n, _)| *n == name) {
            return Err(ServiceError::NotManaged(name.to_string()));
        }
        patronus_network::services::check(name, action, &installed)
            .map_err(|e| ServiceError::Failed(e.to_string()))?;
        let socket = patronus_network::applyd::socket_path();
        if !nix::unistd::geteuid().is_root() && socket.exists() {
            return patronus_network::applyd::request_service(&socket, name, action)
                .await
                .map_err(|e| ServiceError::Failed(e.to_string()));
        }
        let name = name.to_string();
        let action = action.to_string();
        tokio::task::spawn_blocking(move || {
            patronus_network::services::control(&name, &action)
                .map_err(|e| ServiceError::Failed(e.to_string()))
        })
        .await
        .map_err(|e| ServiceError::Failed(e.to_string()))?
    }

    /// Hostname, DNS domain, time zone and resolvers as the system has them.
    pub async fn get_config(&self) -> anyhow::Result<crate::templates::SystemConfig> {
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let (domain, dns_servers) = parse_resolv_conf(&resolv);
        Ok(crate::templates::SystemConfig {
            hostname: super::host::hostname(),
            domain: domain.unwrap_or_default(),
            timezone: timezone(),
            dns_servers,
        })
    }
}

fn describe_backup(path: &Path, name: &str) -> anyhow::Result<crate::templates::Backup> {
    let meta = std::fs::metadata(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let created: chrono::DateTime<chrono::Utc> = meta
        .modified()
        .map(Into::into)
        .unwrap_or_else(|_| chrono::Utc::now());
    let is_valid = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v.get("tables").is_some_and(|t| t.is_object()));
    Ok(crate::templates::Backup {
        id: name.to_string(),
        name: name.to_string(),
        created_at: created.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        size: super::vpn::format_bytes(meta.len()),
        size_bytes: meta.len(),
        backup_type: "Configuration (config store export)".to_string(),
        is_valid,
    })
}

fn installed_services(init: InitSystem) -> Vec<(&'static str, &'static str)> {
    patronus_network::services::installed(init)
}

fn probe_service(
    mgr: &ServiceManager,
    name: &'static str,
    description: &'static str,
) -> crate::templates::Service {
    let state = mgr.status(name);
    let (status, is_running) = match &state {
        Ok(ServiceState::Running) => ("Running".to_string(), true),
        Ok(ServiceState::Stopped) => ("Stopped".to_string(), false),
        Ok(ServiceState::Failed) => ("Failed".to_string(), false),
        Ok(ServiceState::Unknown) => ("Unknown".to_string(), false),
        Err(e) => (format!("Unknown ({e})"), false),
    };
    let pid = is_running
        .then(|| main_pid(mgr.init_system(), name))
        .flatten();
    let uptime = pid.and_then(process_age_secs);
    let rss = pid.and_then(process_rss_bytes);
    crate::templates::Service {
        name: name.to_string(),
        description: description.to_string(),
        status,
        is_running,
        enabled: mgr.is_enabled(name).unwrap_or(false),
        uptime_display: uptime
            .map(super::host::format_duration)
            .unwrap_or_else(|| "—".to_string()),
        memory_display: rss
            .map(super::vpn::format_bytes)
            .unwrap_or_else(|| "—".to_string()),
    }
}

fn main_pid(init: InitSystem, name: &str) -> Option<u32> {
    let pid = match init {
        InitSystem::Systemd => {
            let o = std::process::Command::new("systemctl")
                .args(["show", "-p", "MainPID", "--value", name])
                .output()
                .ok()?;
            String::from_utf8_lossy(&o.stdout).trim().parse().ok()?
        }
        _ => ["/run", "/var/run"]
            .iter()
            .find_map(|d| std::fs::read_to_string(format!("{d}/{name}.pid")).ok())?
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()?,
    };
    (pid > 0).then_some(pid)
}

/// Seconds a process has been running (start time from /proc/PID/stat).
fn process_age_secs(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start_ticks = parse_stat_starttime(&stat)?;
    let hz = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .filter(|h| *h > 0)? as u64;
    Some(super::host::uptime_secs()?.saturating_sub(start_ticks / hz))
}

/// Field 22 (starttime) of /proc/PID/stat; the command name (field 2) may
/// contain spaces and parentheses, so count from the last ')'.
pub fn parse_stat_starttime(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

fn process_rss_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_vmrss(&status)
}

pub fn parse_vmrss(status: &str) -> Option<u64> {
    let kb: u64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kb * 1024)
}

/// (search/domain, nameservers) from resolv.conf text.
pub fn parse_resolv_conf(text: &str) -> (Option<String>, Vec<String>) {
    let mut domain = None;
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("nameserver") => servers.extend(w.next().map(str::to_string)),
            Some("domain") => domain = w.next().map(str::to_string),
            Some("search") if domain.is_none() => domain = w.next().map(str::to_string),
            _ => {}
        }
    }
    (domain, servers)
}

/// Time zone: /etc/timezone (Gentoo/OpenRC), else the /etc/localtime link.
fn timezone() -> String {
    if let Ok(t) = std::fs::read_to_string("/etc/timezone") {
        let t = t.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    match std::fs::read_link("/etc/localtime") {
        Ok(p) => {
            let s = p.to_string_lossy();
            s.split_once("zoneinfo/")
                .map(|(_, z)| z.to_string())
                .unwrap_or_else(|| s.into_owned())
        }
        Err(_) if Path::new("/etc/localtime").exists() => {
            "set (/etc/localtime is a copy, zone name unknown)".to_string()
        }
        Err(_) => "UTC (no /etc/localtime)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store(dir: &Path) -> patronus_config::ConfigStore {
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap()
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("patronus-web-sys-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn backups_are_real_files_with_real_sizes() {
        let dir = tmp();
        let st = store(&dir).await;
        let sys = SystemManager::new(backup_dir_for(&dir.join("config.db")));
        assert_eq!(sys.backup_dir(), dir.join("backups"));
        assert!(
            sys.list_backups().await.unwrap().is_empty(),
            "a new box has no backups"
        );

        let b = sys.create_backup(&st).await.unwrap();
        let path = dir.join("backups").join(&b.name);
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(b.size_bytes, on_disk.len() as u64);
        assert!(b.size_bytes > 0, "an export is never empty");
        assert!(!b.size.starts_with("0 "), "{}", b.size);
        assert!(b.is_valid);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The file is a real export: it imports into a fresh store.
        let doc: serde_json::Value = serde_json::from_slice(&on_disk).unwrap();
        let other = tmp();
        store(&other).await.import_json(&doc).await.unwrap();

        let b2 = sys.create_backup(&st).await.unwrap();
        assert_ne!(b.name, b2.name);
        let list = sys.list_backups().await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|x| x
            .created_at
            .starts_with(&chrono::Utc::now().format("%Y-").to_string())));
        assert_eq!(
            sys.read_backup(&b.name).await.unwrap().unwrap(),
            on_disk,
            "download returns the file"
        );
        assert!(sys.delete_backup(&b.name).await.unwrap());
        assert!(!sys.delete_backup(&b.name).await.unwrap());
        assert_eq!(sys.list_backups().await.unwrap().len(), 1);

        // A corrupt file is listed as such, other files are ignored.
        std::fs::write(dir.join("backups/patronus-config-broken.json"), b"{").unwrap();
        std::fs::write(dir.join("backups/notes.txt"), b"x").unwrap();
        let list = sys.list_backups().await.unwrap();
        assert_eq!(list.len(), 2);
        assert!(
            !list
                .iter()
                .find(|x| x.name == "patronus-config-broken.json")
                .unwrap()
                .is_valid
        );
    }

    #[tokio::test]
    async fn backup_names_cannot_escape_the_directory() {
        let dir = tmp();
        let sys = SystemManager::new(dir.join("backups"));
        for bad in [
            "../config.db",
            "patronus-config-../../etc/passwd.json",
            "/etc/passwd",
            "patronus-config-x/../y.json",
            "config.db",
        ] {
            assert!(!is_backup_name(bad), "{bad}");
            assert!(sys.read_backup(bad).await.is_err(), "{bad}");
            assert!(sys.delete_backup(bad).await.is_err(), "{bad}");
        }
        assert!(is_backup_name("patronus-config-20261017-101010-123.json"));
    }

    #[tokio::test]
    async fn only_installed_known_services_can_be_controlled() {
        let sys = SystemManager::new(tmp());
        match sys.control_service("not-a-patronus-service", "stop").await {
            Err(ServiceError::NotManaged(_)) => {}
            other => panic!("expected NotManaged, got {other:?}"),
        }
        // Whatever is listed is really installed here and has a real state.
        for s in sys.list_services().await.unwrap() {
            assert!(KNOWN_SERVICES.iter().any(|(n, _)| *n == s.name));
            assert!(!s.uptime_display.contains("15d"));
        }
    }

    #[test]
    fn proc_and_resolv_parsers() {
        let stat = "1234 (my (odd) daemon) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 98765 1000 50";
        assert_eq!(parse_stat_starttime(stat), Some(98765));
        assert_eq!(
            parse_vmrss("Name:\tx\nVmRSS:\t  2048 kB\n"),
            Some(2048 * 1024)
        );
        assert_eq!(parse_vmrss("Name: kthread\n"), None);
        let (d, s) = parse_resolv_conf(
            "# generated\nsearch lan.example corp.example\nnameserver 192.168.50.1\nnameserver fd00::1\noptions edns0\n",
        );
        assert_eq!(d.as_deref(), Some("lan.example"));
        assert_eq!(s, vec!["192.168.50.1", "fd00::1"]);
        let (d, s) = parse_resolv_conf("");
        assert_eq!(d, None);
        assert!(s.is_empty(), "no invented resolvers");
    }
}
