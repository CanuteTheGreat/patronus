//! Service management abstraction
//!
//! One interface ([`ServiceManager`]) over the init systems Patronus ships
//! for: OpenRC and systemd (plus a plain SysV fallback). The backend is
//! picked at run time ([`ServiceManager::detect_init_system`]: systemd iff
//! `/run/systemd/system` exists, the same test `sd_booted(3)` uses), so one
//! binary serves both images. Every backend is an [`InitBackend`] that talks
//! to the system through a [`Runner`], which unit tests replace with a
//! recorder: both command sets are covered without either init system being
//! installed.
//!
//! Rule (docs/design/init-parity.md): nothing outside this module may spawn
//! `rc-service`, `rc-update` or `systemctl` for service control. Callers use
//! the logical names below; [`native_name`] maps the few that differ.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Init system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitSystem {
    Systemd,
    OpenRC,
    SysVInit,
    Unknown,
}

/// Service state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Running,
    Stopped,
    Failed,
    Unknown,
}

/// start / stop / restart / reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
}

impl ServiceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Reload => "reload",
        }
    }
}

/// Logical service name -> (OpenRC name, systemd name), for the services whose
/// names differ between the init systems on Gentoo. Everything not listed has
/// the same name in both.
const NAME_TABLE: &[(&str, &str, &str)] = &[
    // strongSwan (swanctl/charon): OpenRC script `ipsec`, systemd unit
    // `strongswan` (charon-systemd). Same convention as ci/netlab/vpn-services-test.sh.
    ("ipsec", "ipsec", "strongswan"),
];

/// The distro service name for a logical `name` under `init`.
pub fn native_name(init: InitSystem, name: &str) -> &str {
    for (logical, openrc, systemd) in NAME_TABLE {
        if *logical == name {
            return match init {
                InitSystem::Systemd => systemd,
                _ => openrc,
            };
        }
    }
    name
}

/// Output of one command.
#[derive(Debug, Clone, Default)]
pub struct CmdOut {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// How a backend runs programs. [`SystemRunner`] spawns them; tests record.
pub trait Runner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CmdOut>;
    /// Fire and forget (no output, not waited for).
    fn spawn_detached(&self, program: &str, args: &[&str]) -> std::io::Result<()>;
}

/// Spawns real processes.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CmdOut> {
        let o = Command::new(program).args(args).output()?;
        Ok(CmdOut {
            success: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }

    fn spawn_detached(&self, program: &str, args: &[&str]) -> std::io::Result<()> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
    }
}

/// What every init system must be able to do for Patronus.
pub trait InitBackend: Send + Sync {
    fn kind(&self) -> InitSystem;
    /// start / stop / restart / reload `name` (already a native name).
    fn act(&self, action: ServiceAction, name: &str) -> Result<()>;
    /// Queue a restart without waiting (used while the system is still booting:
    /// a synchronous start of a unit that is ordered after the caller would
    /// deadlock).
    fn restart_queued(&self, name: &str) -> Result<()>;
    fn enable(&self, name: &str) -> Result<()>;
    fn disable(&self, name: &str) -> Result<()>;
    fn status(&self, name: &str) -> Result<ServiceState>;
    fn is_enabled(&self, name: &str) -> Result<bool>;
    /// Main PID of a running service, if the init system knows it.
    fn main_pid(&self, name: &str) -> Option<u32>;
    /// Is the system still booting?
    fn is_booting(&self) -> bool;
    /// Re-read unit files (systemd `daemon-reload`; nothing to do on OpenRC).
    fn reload_definitions(&self) -> Result<()>;
    /// Where to look when a service will not stay up.
    fn log_hint(&self, name: &str) -> String;
}

fn fail(what: &str, action: &str, detail: impl std::fmt::Display) -> Error {
    Error::Service(format!("Failed to {action} {what}: {detail}"))
}

// ---------------------------------------------------------------- systemd --

/// systemd backend (`systemctl`).
pub struct SystemdBackend {
    run: Arc<dyn Runner>,
}

impl SystemdBackend {
    pub fn new(run: Arc<dyn Runner>) -> Self {
        Self { run }
    }

    fn ctl(&self, args: &[&str]) -> Result<CmdOut> {
        self.run
            .run("systemctl", args)
            .map_err(|e| fail("service", args.first().copied().unwrap_or("run"), e))
    }
}

impl InitBackend for SystemdBackend {
    fn kind(&self) -> InitSystem {
        InitSystem::Systemd
    }

    fn act(&self, action: ServiceAction, name: &str) -> Result<()> {
        let a = action.as_str();
        let mut out = self.ctl(&[a, name])?;
        // systemd refuses more than 5 starts in 10 s ("start of the service was
        // attempted too often"). Config changes made through the API (one
        // restart each, e.g. a script adding DNS rules) can hit that limit
        // although nothing is crash-looping: clear the counter and retry once.
        if !out.success
            && matches!(action, ServiceAction::Start | ServiceAction::Restart)
            && out.stderr.contains("attempted too often")
        {
            let _ = self.ctl(&["reset-failed", name]);
            out = self.ctl(&[a, name])?;
        }
        if out.success {
            Ok(())
        } else {
            Err(fail("service", a, out.stderr))
        }
    }

    fn restart_queued(&self, name: &str) -> Result<()> {
        self.run
            .spawn_detached("systemctl", &["--no-block", "restart", name])
            .map_err(|e| Error::Service(format!("queue start of {name}: {e}")))
    }

    fn enable(&self, name: &str) -> Result<()> {
        let o = self.ctl(&["enable", name])?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", "enable", o.stderr))
        }
    }

    fn disable(&self, name: &str) -> Result<()> {
        let o = self.ctl(&["disable", name])?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", "disable", o.stderr))
        }
    }

    fn status(&self, name: &str) -> Result<ServiceState> {
        let o = self.ctl(&["is-active", name])?;
        Ok(match o.stdout.trim() {
            "active" | "activating" | "reloading" => ServiceState::Running,
            "inactive" | "deactivating" => ServiceState::Stopped,
            "failed" => ServiceState::Failed,
            _ => ServiceState::Unknown,
        })
    }

    fn is_enabled(&self, name: &str) -> Result<bool> {
        Ok(self.ctl(&["is-enabled", name])?.success)
    }

    fn main_pid(&self, name: &str) -> Option<u32> {
        let o = self
            .run
            .run("systemctl", &["show", "-p", "MainPID", "--value", name])
            .ok()?;
        o.stdout.trim().parse().ok().filter(|p| *p > 0)
    }

    fn is_booting(&self) -> bool {
        self.run
            .run("systemctl", &["is-system-running"])
            .map(|o| matches!(o.stdout.trim(), "initializing" | "starting"))
            .unwrap_or(false)
    }

    fn reload_definitions(&self) -> Result<()> {
        let o = self.ctl(&["daemon-reload"])?;
        if o.success {
            Ok(())
        } else {
            Err(fail("systemd", "reload", o.stderr))
        }
    }

    fn log_hint(&self, name: &str) -> String {
        format!("see `journalctl -u {name}`")
    }
}

// ----------------------------------------------------------------- OpenRC --

/// Where OpenRC records service states (`$RC_SVCDIR`: /run/openrc on Linux,
/// /lib/rc/init.d on old installs).
const OPENRC_STATE_DIRS: &[&str] = &["/run/openrc", "/lib/rc/init.d"];

/// OpenRC backend (`rc-service`, `rc-update`).
pub struct OpenRcBackend {
    run: Arc<dyn Runner>,
    state_dirs: Vec<PathBuf>,
}

impl OpenRcBackend {
    pub fn new(run: Arc<dyn Runner>) -> Self {
        Self::with_state_dirs(run, OPENRC_STATE_DIRS.iter().map(PathBuf::from).collect())
    }

    pub fn with_state_dirs(run: Arc<dyn Runner>, state_dirs: Vec<PathBuf>) -> Self {
        Self { run, state_dirs }
    }
}

impl InitBackend for OpenRcBackend {
    fn kind(&self) -> InitSystem {
        InitSystem::OpenRC
    }

    fn act(&self, action: ServiceAction, name: &str) -> Result<()> {
        let a = action.as_str();
        let o = self
            .run
            .run("rc-service", &[name, a])
            .map_err(|e| fail("service", a, e))?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", a, o.stderr))
        }
    }

    fn restart_queued(&self, name: &str) -> Result<()> {
        self.run
            .spawn_detached("rc-service", &[name, "restart"])
            .map_err(|e| Error::Service(format!("queue start of {name}: {e}")))
    }

    fn enable(&self, name: &str) -> Result<()> {
        let o = self
            .run
            .run("rc-update", &["add", name, "default"])
            .map_err(|e| fail("service", "enable", e))?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", "enable", o.stderr))
        }
    }

    fn disable(&self, name: &str) -> Result<()> {
        let o = self
            .run
            .run("rc-update", &["del", name])
            .map_err(|e| fail("service", "disable", e))?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", "disable", o.stderr))
        }
    }

    fn status(&self, name: &str) -> Result<ServiceState> {
        // OpenRC's own records first: readable by any user and what
        // `rc-service status` reports for ordinary scripts. Scripts with their
        // own status() never say started / stopped and may need root: Gentoo's
        // strongSwan `ipsec` runs `ipsec statusall`, so an unprivileged
        // patronus-web saw a running ipsec as Unknown or Stopped.
        let recorded = openrc_recorded_state(self.state_dirs.iter().map(|p| p.as_path()), name);
        if matches!(recorded, ServiceState::Stopped | ServiceState::Failed) {
            return Ok(recorded);
        }
        let o = self
            .run
            .run("rc-service", &[name, "status"])
            .map_err(|e| fail("service status", "get", e))?;
        Ok(if o.stdout.contains("crashed") {
            // marked started, daemon gone
            ServiceState::Failed
        } else if recorded == ServiceState::Running {
            ServiceState::Running
        } else if !o.success {
            ServiceState::Stopped
        } else if o.stdout.contains("started") {
            ServiceState::Running
        } else if o.stdout.contains("stopped") {
            ServiceState::Stopped
        } else {
            ServiceState::Unknown
        })
    }

    fn is_enabled(&self, name: &str) -> Result<bool> {
        let o = self
            .run
            .run("rc-update", &["show"])
            .map_err(|e| fail("service", "check", e))?;
        // `rc-update show` prints `<service> | <runlevel> ...`: match the
        // whole service column, not a substring ("patronus-web" is not
        // "patronus-web-extra").
        Ok(o.stdout
            .lines()
            .any(|l| l.split('|').next().map(str::trim) == Some(name)))
    }

    fn main_pid(&self, name: &str) -> Option<u32> {
        ["/run", "/var/run"]
            .iter()
            .find_map(|d| std::fs::read_to_string(format!("{d}/{name}.pid")).ok())?
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()
            .filter(|p| *p > 0)
    }

    fn is_booting(&self) -> bool {
        // the OpenRC boot script exports this while it applies the config
        std::env::var("PATRONUS_DEFER_SERVICES")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    }

    fn reload_definitions(&self) -> Result<()> {
        Ok(())
    }

    fn log_hint(&self, name: &str) -> String {
        format!("see `rc-service {name} status` and the system log")
    }
}

// ------------------------------------------------------------------- SysV --

/// Plain SysV `/etc/init.d/<name> <action>` fallback.
pub struct SysVBackend {
    run: Arc<dyn Runner>,
}

impl SysVBackend {
    pub fn new(run: Arc<dyn Runner>) -> Self {
        Self { run }
    }

    fn chk(&self, args: &[&str]) -> Result<()> {
        let prog = if Path::new("/usr/sbin/update-rc.d").exists() {
            "update-rc.d"
        } else if Path::new("/sbin/chkconfig").exists() {
            "chkconfig"
        } else {
            return Ok(());
        };
        let o = self
            .run
            .run(prog, args)
            .map_err(|e| fail("service", "enable", e))?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", "enable", o.stderr))
        }
    }
}

impl InitBackend for SysVBackend {
    fn kind(&self) -> InitSystem {
        InitSystem::SysVInit
    }

    fn act(&self, action: ServiceAction, name: &str) -> Result<()> {
        let a = action.as_str();
        let o = self
            .run
            .run(&format!("/etc/init.d/{name}"), &[a])
            .map_err(|e| fail("service", a, e))?;
        if o.success {
            Ok(())
        } else {
            Err(fail("service", a, o.stderr))
        }
    }

    fn restart_queued(&self, name: &str) -> Result<()> {
        self.run
            .spawn_detached(&format!("/etc/init.d/{name}"), &["restart"])
            .map_err(|e| Error::Service(format!("queue start of {name}: {e}")))
    }

    fn enable(&self, name: &str) -> Result<()> {
        if Path::new("/usr/sbin/update-rc.d").exists() {
            self.chk(&[name, "defaults"])
        } else {
            self.chk(&[name, "on"])
        }
    }

    fn disable(&self, name: &str) -> Result<()> {
        if Path::new("/usr/sbin/update-rc.d").exists() {
            self.chk(&[name, "remove"])
        } else {
            self.chk(&[name, "off"])
        }
    }

    fn status(&self, name: &str) -> Result<ServiceState> {
        let o = self
            .run
            .run(&format!("/etc/init.d/{name}"), &["status"])
            .map_err(|e| fail("service status", "get", e))?;
        Ok(if o.success {
            ServiceState::Running
        } else {
            ServiceState::Stopped
        })
    }

    fn is_enabled(&self, _name: &str) -> Result<bool> {
        // depends on the distribution
        Ok(false)
    }

    fn main_pid(&self, _name: &str) -> Option<u32> {
        None
    }

    fn is_booting(&self) -> bool {
        false
    }

    fn reload_definitions(&self) -> Result<()> {
        Ok(())
    }

    fn log_hint(&self, name: &str) -> String {
        format!("see `/etc/init.d/{name} status` and the system log")
    }
}

/// No init system found: every operation says so.
struct NoInit;

impl InitBackend for NoInit {
    fn kind(&self) -> InitSystem {
        InitSystem::Unknown
    }
    fn act(&self, _: ServiceAction, _: &str) -> Result<()> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn restart_queued(&self, _: &str) -> Result<()> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn enable(&self, _: &str) -> Result<()> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn disable(&self, _: &str) -> Result<()> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn status(&self, _: &str) -> Result<ServiceState> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn is_enabled(&self, _: &str) -> Result<bool> {
        Err(Error::Service("Unknown init system".to_string()))
    }
    fn main_pid(&self, _: &str) -> Option<u32> {
        None
    }
    fn is_booting(&self) -> bool {
        false
    }
    fn reload_definitions(&self) -> Result<()> {
        Ok(())
    }
    fn log_hint(&self, _: &str) -> String {
        "no init system detected".to_string()
    }
}

/// Backend for `init` over `run`.
pub fn backend_for(init: InitSystem, run: Arc<dyn Runner>) -> Box<dyn InitBackend> {
    match init {
        InitSystem::Systemd => Box::new(SystemdBackend::new(run)),
        InitSystem::OpenRC => Box::new(OpenRcBackend::new(run)),
        InitSystem::SysVInit => Box::new(SysVBackend::new(run)),
        InitSystem::Unknown => Box::new(NoInit),
    }
}

// ---------------------------------------------------------------- facade --

/// Service manager: the one entry point callers use.
pub struct ServiceManager {
    init_system: InitSystem,
    backend: Box<dyn InitBackend>,
}

impl ServiceManager {
    /// Create a new service manager (auto-detects init system)
    pub fn new() -> Self {
        Self::with_init_system(Self::detect_init_system())
    }

    /// Create a service manager for a specific init system
    pub fn with_init_system(init_system: InitSystem) -> Self {
        Self::with_runner(init_system, Arc::new(SystemRunner))
    }

    /// A manager for `init_system` that runs its commands through `run`.
    pub fn with_runner(init_system: InitSystem, run: Arc<dyn Runner>) -> Self {
        Self {
            init_system,
            backend: backend_for(init_system, run),
        }
    }

    /// A manager around an explicit backend (tests, custom state dirs).
    pub fn with_backend(backend: Box<dyn InitBackend>) -> Self {
        Self {
            init_system: backend.kind(),
            backend,
        }
    }

    /// Detect the running init system
    pub fn detect_init_system() -> InitSystem {
        Self::detect_under(Path::new("/"))
    }

    /// [`Self::detect_init_system`] against another root (unit tests).
    /// systemd wins when `/run/systemd/system` exists (it is only there while
    /// systemd is PID 1), so a box with both packages installed is judged by
    /// what actually booted it.
    pub fn detect_under(root: &Path) -> InitSystem {
        let p = |s: &str| root.join(s.trim_start_matches('/'));
        if p("/run/systemd/system").exists() {
            return InitSystem::Systemd;
        }
        if p("/run/openrc").exists() || p("/etc/init.d/functions.sh").exists() {
            return InitSystem::OpenRC;
        }
        if p("/etc/init.d").exists() {
            return InitSystem::SysVInit;
        }
        InitSystem::Unknown
    }

    /// Get the current init system
    pub fn init_system(&self) -> InitSystem {
        self.init_system
    }

    fn native<'a>(&self, name: &'a str) -> &'a str {
        native_name(self.init_system, name)
    }

    /// Start a service
    pub fn start(&self, service_name: &str) -> Result<()> {
        self.backend
            .act(ServiceAction::Start, self.native(service_name))
    }

    /// Stop a service
    pub fn stop(&self, service_name: &str) -> Result<()> {
        self.backend
            .act(ServiceAction::Stop, self.native(service_name))
    }

    /// Restart a service
    pub fn restart(&self, service_name: &str) -> Result<()> {
        self.backend
            .act(ServiceAction::Restart, self.native(service_name))
    }

    /// Reload a service configuration
    pub fn reload(&self, service_name: &str) -> Result<()> {
        self.backend
            .act(ServiceAction::Reload, self.native(service_name))
    }

    /// Queue a restart and return at once (boot-time config applies).
    pub fn restart_queued(&self, service_name: &str) -> Result<()> {
        self.backend.restart_queued(self.native(service_name))
    }

    /// Enable a service to start on boot
    pub fn enable(&self, service_name: &str) -> Result<()> {
        self.backend.enable(self.native(service_name))
    }

    /// Disable a service from starting on boot
    pub fn disable(&self, service_name: &str) -> Result<()> {
        self.backend.disable(self.native(service_name))
    }

    /// Get service status
    pub fn status(&self, service_name: &str) -> Result<ServiceState> {
        self.backend.status(self.native(service_name))
    }

    /// Check if a service is running
    pub fn is_running(&self, service_name: &str) -> Result<bool> {
        Ok(self.status(service_name)? == ServiceState::Running)
    }

    /// Check if a service is enabled
    pub fn is_enabled(&self, service_name: &str) -> Result<bool> {
        self.backend.is_enabled(self.native(service_name))
    }

    /// Main PID of a running service (None when unknown).
    pub fn main_pid(&self, service_name: &str) -> Option<u32> {
        self.backend.main_pid(self.native(service_name))
    }

    /// Is the system still booting (config applies must not wait on services)?
    pub fn is_booting(&self) -> bool {
        self.backend.is_booting()
    }

    /// Re-read unit definitions after a drop-in changed (systemd only).
    pub fn reload_definitions(&self) -> Result<()> {
        self.backend.reload_definitions()
    }

    /// Where to look when `service_name` will not stay up.
    pub fn log_hint(&self, service_name: &str) -> String {
        self.backend.log_hint(self.native(service_name))
    }
}

/// The state OpenRC itself recorded for `name`: a `started/<name>` (or
/// `starting`/`failed`/...) entry in the first state directory that exists.
/// No entry = stopped (OpenRC removes it on stop).
fn openrc_recorded_state<'a>(
    dirs: impl IntoIterator<Item = &'a std::path::Path>,
    name: &str,
) -> ServiceState {
    let Some(dir) = dirs.into_iter().find(|d| d.join("started").is_dir()) else {
        return ServiceState::Unknown;
    };
    let has = |state: &str| dir.join(state).join(name).symlink_metadata().is_ok();
    if has("started") || has("starting") {
        ServiceState::Running
    } else if has("failed") {
        ServiceState::Failed
    } else {
        ServiceState::Stopped
    }
}

/// Run one service action off the async executor (the backends spawn and
/// wait for `rc-service` / `systemctl`).
pub async fn act_blocking(action: ServiceAction, name: &str) -> Result<()> {
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        let m = ServiceManager::new();
        match action {
            ServiceAction::Start => m.start(&name),
            ServiceAction::Stop => m.stop(&name),
            ServiceAction::Restart => m.restart(&name),
            ServiceAction::Reload => m.reload(&name),
        }
    })
    .await
    .map_err(|e| Error::Service(format!("service task: {e}")))?
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every command and answers from a script (`(prefix, reply)`,
    /// first match wins; no match = success with empty output).
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        replies: Mutex<Vec<(String, CmdOut)>>,
    }

    impl Fake {
        fn reply(self: &Arc<Self>, prefix: &str, success: bool, stdout: &str, stderr: &str) {
            self.replies.lock().unwrap().push((
                prefix.to_string(),
                CmdOut {
                    success,
                    stdout: stdout.into(),
                    stderr: stderr.into(),
                },
            ));
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CmdOut> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.lock().unwrap().push(line.clone());
            let mut r = self.replies.lock().unwrap();
            if let Some(i) = r.iter().position(|(p, _)| line.starts_with(p.as_str())) {
                let (_, o) = r.remove(i);
                return Ok(o);
            }
            Ok(CmdOut {
                success: true,
                ..Default::default()
            })
        }
        fn spawn_detached(&self, program: &str, args: &[&str]) -> std::io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("detached {program} {}", args.join(" ")));
            Ok(())
        }
    }

    fn mgr(init: InitSystem) -> (ServiceManager, Arc<Fake>) {
        let f = Arc::new(Fake::default());
        (ServiceManager::with_runner(init, f.clone()), f)
    }

    fn root_with(dirs: &[&str]) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let r = std::env::temp_dir().join(format!(
            "patronus-init-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).unwrap();
        for d in dirs {
            std::fs::create_dir_all(r.join(d.trim_start_matches('/'))).unwrap();
        }
        r
    }

    #[test]
    fn detection_follows_what_booted_the_box() {
        let none = root_with(&[]);
        assert_eq!(ServiceManager::detect_under(&none), InitSystem::Unknown);
        let sysv = root_with(&["/etc/init.d"]);
        assert_eq!(ServiceManager::detect_under(&sysv), InitSystem::SysVInit);
        let rc = root_with(&["/run/openrc", "/etc/init.d"]);
        assert_eq!(ServiceManager::detect_under(&rc), InitSystem::OpenRC);
        // both installed (Gentoo with both USE flags): /run/systemd/system decides
        let both = root_with(&["/run/systemd/system", "/etc/init.d", "/run/openrc"]);
        assert_eq!(ServiceManager::detect_under(&both), InitSystem::Systemd);
        let sd_only_installed = root_with(&["/etc/init.d/functions.sh-dir", "/usr/lib/systemd"]);
        assert_ne!(
            ServiceManager::detect_under(&sd_only_installed),
            InitSystem::Systemd
        );
        for r in [none, sysv, rc, both, sd_only_installed] {
            let _ = std::fs::remove_dir_all(r);
        }
    }

    #[test]
    fn detect_matches_the_running_host() {
        // Whatever this builder runs, the live probe and the rooted probe agree.
        assert_eq!(
            ServiceManager::detect_init_system(),
            ServiceManager::detect_under(Path::new("/"))
        );
    }

    #[test]
    fn systemd_commands() {
        let (m, f) = mgr(InitSystem::Systemd);
        m.start("patronus-web").unwrap();
        m.stop("patronus-web").unwrap();
        m.restart("unbound").unwrap();
        m.reload("haproxy").unwrap();
        m.enable("patronus-web").unwrap();
        m.disable("patronus-web").unwrap();
        m.reload_definitions().unwrap();
        m.restart_queued("kea-dhcp4").unwrap();
        assert_eq!(
            f.calls(),
            [
                "systemctl start patronus-web",
                "systemctl stop patronus-web",
                "systemctl restart unbound",
                "systemctl reload haproxy",
                "systemctl enable patronus-web",
                "systemctl disable patronus-web",
                "systemctl daemon-reload",
                "detached systemctl --no-block restart kea-dhcp4",
            ]
        );
    }

    #[test]
    fn openrc_commands() {
        let (m, f) = mgr(InitSystem::OpenRC);
        m.start("patronus-web").unwrap();
        m.stop("patronus-web").unwrap();
        m.restart("unbound").unwrap();
        m.reload("haproxy").unwrap();
        m.enable("patronus-web").unwrap();
        m.disable("patronus-web").unwrap();
        m.reload_definitions().unwrap(); // nothing to do, must not spawn
        m.restart_queued("kea-dhcp4").unwrap();
        assert_eq!(
            f.calls(),
            [
                "rc-service patronus-web start",
                "rc-service patronus-web stop",
                "rc-service unbound restart",
                "rc-service haproxy reload",
                "rc-update add patronus-web default",
                "rc-update del patronus-web",
                "detached rc-service kea-dhcp4 restart",
            ]
        );
    }

    #[test]
    fn names_that_differ_map_per_init_system() {
        assert_eq!(native_name(InitSystem::Systemd, "ipsec"), "strongswan");
        assert_eq!(native_name(InitSystem::OpenRC, "ipsec"), "ipsec");
        // other distros name it strongswan on both: left alone
        assert_eq!(native_name(InitSystem::OpenRC, "strongswan"), "strongswan");
        assert_eq!(native_name(InitSystem::Systemd, "unbound"), "unbound");
        let (m, f) = mgr(InitSystem::Systemd);
        m.start("ipsec").unwrap();
        let (r, g) = mgr(InitSystem::OpenRC);
        r.start("ipsec").unwrap();
        assert_eq!(f.calls(), ["systemctl start strongswan"]);
        assert_eq!(g.calls(), ["rc-service ipsec start"]);
    }

    #[test]
    fn failures_carry_stderr_on_both_backends() {
        for init in [InitSystem::Systemd, InitSystem::OpenRC] {
            let (m, f) = mgr(init);
            f.reply("", false, "", "boom");
            let e = m.start("x").unwrap_err().to_string();
            assert!(e.contains("boom") && e.contains("start"), "{init:?}: {e}");
        }
    }

    #[test]
    fn systemd_start_rate_limit_is_cleared_and_retried_once() {
        let (m, f) = mgr(InitSystem::Systemd);
        f.reply(
            "systemctl restart",
            false,
            "",
            "start request repeated too quickly: attempted too often",
        );
        m.restart("unbound").unwrap();
        assert_eq!(
            f.calls(),
            [
                "systemctl restart unbound",
                "systemctl reset-failed unbound",
                "systemctl restart unbound"
            ]
        );
    }

    #[test]
    fn systemd_status_mapping() {
        for (out, want) in [
            ("active\n", ServiceState::Running),
            ("activating\n", ServiceState::Running),
            ("inactive\n", ServiceState::Stopped),
            ("failed\n", ServiceState::Failed),
            ("", ServiceState::Unknown),
        ] {
            let (m, f) = mgr(InitSystem::Systemd);
            f.reply("systemctl is-active", out == "active\n", out, "");
            assert_eq!(m.status("x").unwrap(), want, "{out:?}");
        }
    }

    #[test]
    fn systemd_main_pid_and_booting() {
        let (m, f) = mgr(InitSystem::Systemd);
        f.reply("systemctl show", true, "4242\n", "");
        assert_eq!(m.main_pid("x"), Some(4242));
        f.reply("systemctl show", true, "0\n", "");
        assert_eq!(m.main_pid("x"), None);
        f.reply("systemctl is-system-running", false, "starting\n", "");
        assert!(m.is_booting());
        f.reply("systemctl is-system-running", false, "degraded\n", "");
        assert!(!m.is_booting());
    }

    #[test]
    fn openrc_enabled_matches_the_service_column_only() {
        let (m, f) = mgr(InitSystem::OpenRC);
        let show = "  patronus-web-extra | default\n        sshd | default\n";
        f.reply("rc-update show", true, show, "");
        assert!(!m.is_enabled("patronus-web").unwrap());
        f.reply("rc-update show", true, show, "");
        assert!(m.is_enabled("sshd").unwrap());
    }

    #[test]
    fn openrc_status_uses_its_records_then_the_script() {
        let root = root_with(&["/rc/started", "/rc/failed", "/rc/starting"]);
        let rc = root.join("rc");
        std::os::unix::fs::symlink("/etc/init.d/a", rc.join("started/a")).unwrap();
        std::os::unix::fs::symlink("/etc/init.d/b", rc.join("failed/b")).unwrap();
        let f = Arc::new(Fake::default());
        let m = ServiceManager::with_backend(Box::new(OpenRcBackend::with_state_dirs(
            f.clone(),
            vec![rc.clone()],
        )));
        // recorded as failed: no command needed
        assert_eq!(m.status("b").unwrap(), ServiceState::Failed);
        assert!(f.calls().is_empty());
        // recorded as started, script has its own status() (no "started")
        f.reply("rc-service a status", true, "Status: ESTABLISHED\n", "");
        assert_eq!(m.status("a").unwrap(), ServiceState::Running);
        // started in the records but the daemon is gone
        f.reply("rc-service a status", false, " * status: crashed\n", "");
        assert_eq!(m.status("a").unwrap(), ServiceState::Failed);
        // no record: recorded state dir exists -> Stopped without asking
        assert_eq!(m.status("c").unwrap(), ServiceState::Stopped);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn openrc_booting_follows_the_boot_script_flag() {
        // (reads the process environment: set and clear in one test only)
        let (m, _) = mgr(InitSystem::OpenRC);
        std::env::remove_var("PATRONUS_DEFER_SERVICES");
        assert!(!m.is_booting());
        std::env::set_var("PATRONUS_DEFER_SERVICES", "1");
        assert!(m.is_booting());
        std::env::remove_var("PATRONUS_DEFER_SERVICES");
    }

    #[test]
    fn unknown_init_refuses_everything() {
        let m = ServiceManager::with_init_system(InitSystem::Unknown);
        assert!(m.start("x").is_err());
        assert!(m.status("x").is_err());
        assert!(m.enable("x").is_err());
        assert!(!m.is_booting());
    }

    #[test]
    fn test_service_manager_creation() {
        let manager = ServiceManager::new();
        assert_eq!(manager.init_system(), ServiceManager::detect_init_system());
    }

    /// Gentoo's strongSwan `ipsec` script answers `status` with `ipsec
    /// statusall` (no started/stopped word): the state comes from OpenRC's
    /// own records, so the System page shows Running/Stopped, not Unknown.
    #[test]
    fn openrc_state_comes_from_its_state_directory() {
        let root = std::env::temp_dir().join(format!("patronus-openrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let rc = root.join("run-openrc");
        for d in ["started", "failed", "starting"] {
            std::fs::create_dir_all(rc.join(d)).unwrap();
        }
        std::os::unix::fs::symlink("/etc/init.d/ipsec", rc.join("started/ipsec")).unwrap();
        std::os::unix::fs::symlink("/etc/init.d/unbound", rc.join("failed/unbound")).unwrap();
        let missing = root.join("nope");
        let dirs = [missing.as_path(), rc.as_path()];
        assert_eq!(openrc_recorded_state(dirs, "ipsec"), ServiceState::Running);
        assert_eq!(openrc_recorded_state(dirs, "unbound"), ServiceState::Failed);
        assert_eq!(
            openrc_recorded_state(dirs, "kea-dhcp4"),
            ServiceState::Stopped
        );
        // no OpenRC state directory at all: cannot tell
        assert_eq!(
            openrc_recorded_state([missing.as_path()], "ipsec"),
            ServiceState::Unknown
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
