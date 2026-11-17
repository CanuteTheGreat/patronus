//! Web login with system accounts.
//!
//! Patronus has no account set of its own for the web UI: you sign in with a
//! user of the box (PAM on the full Linux tier, the platform's shadow files
//! on the embedded tier; see `patronus_network::sysauth`). What the user may
//! do comes from the system groups, resolved on the same side that checked
//! the password:
//!
//! * `patronus-admin` or `wheel` -> admin (`admin_groups`, overridable)
//! * `operator_groups` -> operator, `readonly_groups` -> read-only
//! * a user in none of them is refused; root is refused unless `allow_root`
//!
//! `/etc/patronus/web-auth.toml` (or `$PATRONUS_WEB_AUTH_CONF`) overrides the
//! defaults. The check itself runs as root: in `patronus applyd` (the web UI
//! runs unprivileged), or in-process when the web UI is root.

use crate::auth::UserRole;
use patronus_network::sysauth::{self, Backend, Identity};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_CONF: &str = "/etc/patronus/web-auth.toml";
pub const CONF_ENV: &str = "PATRONUS_WEB_AUTH_CONF";
/// Directory of passwd/group/shadow files for a non-root web UI without a
/// broker (the container image sets it to /var/lib/patronus/auth).
pub const AUTH_ETC_ENV: &str = "PATRONUS_AUTH_ETC";

/// Every failed login takes at least this long (longer than the usual
/// pam_unix fail delay): wrong password, unknown user, not-in-a-group and
/// root-refused are one generic 401 with the same timing; only the audit
/// log tells them apart.
pub const FAIL_FLOOR: Duration = Duration::from_millis(4000);

/// `[auth]` settings that decide who may sign in and with which role.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WebAuthConfig {
    pub admin_groups: Vec<String>,
    pub operator_groups: Vec<String>,
    pub readonly_groups: Vec<String>,
    /// Allow root (uid 0) to sign in to the web UI (off by default).
    pub allow_root: bool,
    /// Keep the pre-PAM Patronus-only accounts signing in, read-only, for
    /// one release (migration). Off = refused now.
    pub legacy_local_login: bool,
}

impl Default for WebAuthConfig {
    fn default() -> Self {
        Self {
            admin_groups: vec!["patronus-admin".into(), "wheel".into()],
            operator_groups: vec![],
            readonly_groups: vec![],
            allow_root: false,
            legacy_local_login: true,
        }
    }
}

impl WebAuthConfig {
    /// The config file, or the defaults when it does not exist. A file that
    /// cannot be parsed is logged and ignored (the defaults are the strict
    /// ones: nobody gains access from a typo).
    pub fn load() -> Self {
        let path = std::env::var_os(CONF_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONF));
        match std::fs::read_to_string(&path) {
            Ok(t) => Self::parse(&t).unwrap_or_else(|e| {
                tracing::error!("{}: {e}; using the defaults", path.display());
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// The role for a user with this uid and these groups: the highest
    /// matching role wins (admin > operator > read-only).
    pub fn decide(&self, username: &str, uid: Option<u32>, groups: &[String]) -> Decision {
        if (uid == Some(0) || username == "root") && !self.allow_root {
            return Decision::DeniedRoot;
        }
        let has = |wanted: &[String]| {
            wanted
                .iter()
                .filter(|g| !g.is_empty())
                .any(|g| groups.iter().any(|m| m == g))
        };
        if has(&self.admin_groups) {
            Decision::Role(UserRole::Admin)
        } else if has(&self.operator_groups) {
            Decision::Role(UserRole::Operator)
        } else if has(&self.readonly_groups) {
            Decision::Role(UserRole::ReadOnly)
        } else {
            Decision::DeniedNoGroup
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Role(UserRole),
    DeniedRoot,
    DeniedNoGroup,
}

/// Why a system login failed (the response is always the same generic 401;
/// this goes to the audit log only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fail {
    BadCredentials,
    Backoff,
    Root,
    NoGroup,
    Unavailable,
}

impl Fail {
    pub fn reason(self) -> &'static str {
        match self {
            Fail::BadCredentials => "bad credentials",
            Fail::Backoff => "too many failures for this name: backing off",
            Fail::Root => "root web login disabled",
            Fail::NoGroup => "not in an authorized group",
            Fail::Unavailable => "authentication mechanism unavailable",
        }
    }
}

/// Where the password check runs.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Ask `patronus applyd` (root) over its socket.
    Broker(PathBuf),
    /// Check in this process (the web UI itself is root, or tests).
    Direct(Backend),
}

type FailMap = HashMap<String, (u32, Instant)>;

#[derive(Clone)]
pub struct SysLogin {
    pub cfg: WebAuthConfig,
    pub mode: Mode,
    pub fail_floor: Duration,
    /// Legacy local accounts are clamped to read-only (always on outside
    /// unit tests, where fixtures log in as seeded admins).
    pub legacy_clamp: bool,
    fails: Arc<Mutex<FailMap>>,
    /// First-run setup is pending (see `first_run_pending`). Per instance, not a
    /// process global: parallel unit tests each build their own SysLogin.
    first_run: Arc<std::sync::atomic::AtomicBool>,
    /// The open first-run window and its one-time setup code.
    first_run_gate: Arc<Mutex<Option<FirstRunGate>>>,
}

/// How long `/first-run` accepts a claim after the web service starts.
pub const FIRST_RUN_WINDOW: Duration = Duration::from_secs(60 * 60);
/// Wrong setup codes accepted before the window closes early.
pub const FIRST_RUN_MAX_FAILS: u32 = 10;
/// Where the setup code is written (root-only), unless
/// `$PATRONUS_FIRST_RUN_CODE_FILE` says otherwise.
pub const FIRST_RUN_CODE_FILE: &str = "/run/patronus/first-run-code";

/// The embedded first run's proof of ownership: a random code that only
/// someone with the console or a root shell can read, valid for a window
/// after the service starts and for a few wrong tries.
#[derive(Debug)]
struct FirstRunGate {
    code: String,
    opened: Instant,
    window: Duration,
    fails: u32,
}

/// State of the first-run window, for the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstRunWindow {
    /// open, this many whole minutes left (at least 1)
    Open(u64),
    /// the window ran out
    Expired,
    /// too many wrong setup codes
    Locked,
    /// no first run is pending / no window was opened
    Closed,
}

/// The setup code file path (`$PATRONUS_FIRST_RUN_CODE_FILE`, else
/// [`FIRST_RUN_CODE_FILE`]).
pub fn first_run_code_path() -> PathBuf {
    std::env::var_os("PATRONUS_FIRST_RUN_CODE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(FIRST_RUN_CODE_FILE))
}

/// A setup code: 12 characters from an alphabet without look-alikes (60
/// bits), grouped `XXXX-XXXX-XXXX`.
pub fn new_setup_code() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::OsRng;
    let mut s = String::with_capacity(14);
    for i in 0..12 {
        if i > 0 && i % 4 == 0 {
            s.push('-');
        }
        s.push(ALPHABET[rng.gen_range(0..ALPHABET.len())] as char);
    }
    s
}

/// Codes are compared without case, spaces or dashes.
fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Write the setup code where the owner can read it: a root-only file
/// (`cat /run/patronus/first-run-code` over ssh) and the system console
/// (serial), unless `PATRONUS_FIRST_RUN_CONSOLE=0`. Best effort: a failure
/// is logged; the window stays usable through whichever one worked.
pub fn publish_first_run_code(code: &str, window: Duration) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = first_run_code_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::remove_file(&path);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(format!("{code}\n").as_bytes()))
    {
        Ok(()) => {}
        Err(e) => tracing::warn!("first-run setup code file {}: {e}", path.display()),
    }
    if std::env::var("PATRONUS_FIRST_RUN_CONSOLE").is_ok_and(|v| v == "0") {
        return;
    }
    let msg = format!(
        "\r\nPatronus first-run setup code: {code}\r\n(valid for {} min after the web UI starts; also in {})\r\n",
        window.as_secs() / 60,
        path.display()
    );
    if let Ok(mut c) = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open("/dev/console")
    {
        let _ = c.write_all(msg.as_bytes());
    }
}

/// Remove the setup code file once the administrator exists.
pub fn retire_first_run_code() {
    let _ = std::fs::remove_file(first_run_code_path());
}

/// After this many failures for a name within [`BACKOFF_WINDOW`] it is not
/// even offered to PAM for [`BACKOFF_PAUSE`] after the last failure (on top
/// of the per-IP throttle and pam_faillock).
const BACKOFF_FAILS: u32 = 5;
const BACKOFF_WINDOW: Duration = Duration::from_secs(600);
const BACKOFF_PAUSE: Duration = Duration::from_secs(60);

impl SysLogin {
    pub fn new(cfg: WebAuthConfig, mode: Mode) -> Self {
        Self {
            cfg,
            mode,
            // unit tests of the whole app log in wrongly a lot: only the
            // login tests that assert the floor set it
            fail_floor: if cfg!(test) {
                Duration::ZERO
            } else {
                FAIL_FLOOR
            },
            legacy_clamp: !cfg!(test),
            fails: Arc::default(),
            first_run: Arc::default(),
            first_run_gate: Arc::default(),
        }
    }

    /// Open the first-run window: setup pending, a new setup code valid for
    /// `window` (returned, for [`publish_first_run_code`]).
    pub fn open_first_run(&self, window: Duration) -> String {
        let code = new_setup_code();
        *self.gate() = Some(FirstRunGate {
            code: normalize_code(&code),
            opened: Instant::now(),
            window,
            fails: 0,
        });
        self.set_first_run_pending(true);
        code
    }

    fn gate(&self) -> std::sync::MutexGuard<'_, Option<FirstRunGate>> {
        self.first_run_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Where the first-run window stands.
    pub fn first_run_window(&self) -> FirstRunWindow {
        if !self.first_run_pending() {
            return FirstRunWindow::Closed;
        }
        match &*self.gate() {
            None => FirstRunWindow::Closed,
            Some(g) if g.fails >= FIRST_RUN_MAX_FAILS => FirstRunWindow::Locked,
            Some(g) => match g.window.checked_sub(g.opened.elapsed()) {
                Some(left) if !left.is_zero() => {
                    FirstRunWindow::Open(left.as_secs().div_ceil(60).max(1))
                }
                _ => FirstRunWindow::Expired,
            },
        }
    }

    /// Does `proof` show ownership of this unit for the first run: the
    /// setup code of the open window, or the password of the unit's existing
    /// root account (e.g. carried over from OpenWrt or the vendor firmware)?
    /// Wrong proofs count towards [`FIRST_RUN_MAX_FAILS`]. Blocking (the root
    /// password check runs the password hash).
    pub fn check_first_run_proof(&self, proof: &str) -> Result<(), String> {
        match self.first_run_window() {
            FirstRunWindow::Open(_) => {}
            FirstRunWindow::Expired => {
                return Err("the setup window has closed: restart the router (or its web service) and enter the new setup code within the hour".into())
            }
            FirstRunWindow::Locked => {
                return Err("too many wrong setup codes: restart the router (or its web service) to get a new one".into())
            }
            FirstRunWindow::Closed => return Err("first-run setup is not open".into()),
        }
        let want = normalize_code(proof);
        let code_ok = {
            let g = self.gate();
            g.as_ref()
                .is_some_and(|g| !want.is_empty() && same_bytes(want.as_bytes(), g.code.as_bytes()))
        };
        let ok = code_ok || (!proof.is_empty() && self.root_password_matches(proof));
        if ok {
            return Ok(());
        }
        if let Some(g) = self.gate().as_mut() {
            g.fails += 1;
        }
        Err("Invalid setup code: use the code shown on the router's console or in /run/patronus/first-run-code, or the router's root password".into())
    }

    /// The unit's root account has a usable password and `password` is it.
    fn root_password_matches(&self, password: &str) -> bool {
        match &self.mode {
            Mode::Direct(b) => sysauth::authenticate(b, "root", password).unwrap_or(false),
            Mode::Broker(_) => false,
        }
    }

    /// A router that shipped without any account waits for its owner to create the first
    /// administrator: every page and API except `/first-run` answers "create the administrator first".
    pub fn first_run_pending(&self) -> bool {
        self.first_run.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_first_run_pending(&self, pending: bool) {
        self.first_run
            .store(pending, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn from_env() -> Self {
        // unit tests of the app never read the machine's real accounts
        if cfg!(test) {
            return Self::new(
                WebAuthConfig::default(),
                Mode::Direct(Backend::Shadow("/nonexistent-patronus-test-etc".into())),
            );
        }
        let applyd = patronus_network::applyd::socket_path();
        let mode = if unsafe { libc::geteuid() } == 0 {
            Mode::Direct(sysauth::auto_backend())
        } else if applyd.exists() {
            Mode::Broker(applyd)
        } else if let Some(etc) = std::env::var_os(AUTH_ETC_ENV) {
            // container image: no root broker, the accounts are passwd/group/shadow
            // files the unprivileged web user owns (`patronus users add-local-account`)
            Mode::Direct(Backend::Shadow(PathBuf::from(etc)))
        } else {
            Mode::Broker(applyd)
        };
        Self::new(WebAuthConfig::load(), mode)
    }

    fn fails(&self) -> std::sync::MutexGuard<'_, FailMap> {
        self.fails.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn backoff_ok(&self, name: &str) -> bool {
        self.backoff_remaining(name).is_none()
    }

    /// Forget `name`'s failures: its password was just proven by another
    /// way in (a legacy or directory account of that name). Without this,
    /// the system check that runs first, and fails for such accounts, kept
    /// counting their successful logins as failures.
    pub fn clear_failures(&self, name: &str) {
        self.fails().remove(name);
    }

    /// Seconds until `name` is offered to the password check again, while
    /// its per-name back-off is active.
    pub fn backoff_remaining(&self, name: &str) -> Option<u64> {
        match self.fails().get(name) {
            Some((n, at)) if *n >= BACKOFF_FAILS => {
                let left = BACKOFF_PAUSE.saturating_sub(at.elapsed());
                (!left.is_zero()).then(|| left.as_secs().max(1))
            }
            _ => None,
        }
    }

    fn backoff_fail(&self, name: &str) {
        let mut m = self.fails();
        if m.len() > 10_000 {
            m.retain(|_, (_, at)| at.elapsed() < BACKOFF_WINDOW);
        }
        let e = m.entry(name.to_string()).or_insert((0, Instant::now()));
        if e.1.elapsed() > BACKOFF_WINDOW {
            e.0 = 0;
        }
        e.0 += 1;
        e.1 = Instant::now();
    }

    /// uid + groups of a system user, without a password (is this name a
    /// system user at all?). None for unknown names or when this process
    /// cannot read the accounts directly.
    pub fn known(&self, name: &str) -> bool {
        match &self.mode {
            Mode::Direct(b) => sysauth::lookup(b, name).is_some(),
            // not root: cannot read shadow/NSS reliably; the broker answers at login
            Mode::Broker(_) => sysauth::valid_name(name),
        }
    }

    /// Headless / CI / container seam, never a default: with
    /// `PATRONUS_ADMIN_PASSWORD` set, an account (`PATRONUS_ADMIN_USER`,
    /// default `admin`) in the first admin group is written into the shadow
    /// files of `$PATRONUS_AUTH_ETC` (default: `auth/` beside `$PATRONUS_ADMIN_PASSWORD_FILE`, else /var/lib/patronus/auth) and
    /// the web UI reads its accounts from there. Unset = nothing happens.
    pub fn seed_from_env(&mut self) -> anyhow::Result<bool> {
        let Some(pw) = std::env::var("PATRONUS_ADMIN_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty())
        else {
            return Ok(false);
        };
        let user = std::env::var("PATRONUS_ADMIN_USER").unwrap_or_else(|_| "admin".into());
        let etc = std::env::var_os(AUTH_ETC_ENV)
            .map(PathBuf::from)
            .or_else(|| {
                // beside the per-install password file when one is named (CI lanes)
                let f = std::env::var_os("PATRONUS_ADMIN_PASSWORD_FILE")?;
                Some(Path::new(&f).parent()?.join("auth"))
            })
            .unwrap_or_else(|| "/var/lib/patronus/auth".into());
        let group = self
            .cfg
            .admin_groups
            .first()
            .cloned()
            .unwrap_or_else(|| "patronus-admin".into());
        sysauth::add_account(&etc, &user, &pw, &[group]).map_err(|e| anyhow::anyhow!(e))?;
        self.mode = Mode::Direct(Backend::Shadow(etc));
        Ok(true)
    }

    /// The passwd/group/shadow directory this login reads directly (the
    /// shadow backend's, else `$PATRONUS_AUTH_ETC` or /etc for PAM, whose
    /// pam_unix reads the same files). None behind the broker.
    fn local_etc(&self) -> Option<PathBuf> {
        match &self.mode {
            Mode::Direct(Backend::Shadow(etc)) => Some(etc.clone()),
            Mode::Direct(Backend::Pam) => Some(
                std::env::var_os(AUTH_ETC_ENV)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/etc")),
            ),
            Mode::Broker(_) => None,
        }
    }

    /// Embedded first run: does a non-root system user in an admin group
    /// exist? Behind the broker (full tier, accounts come from the installer)
    /// this is always true: the first-run page is a router-image feature.
    pub fn admin_account_exists(&self) -> bool {
        match self.local_etc() {
            Some(etc) => !sysauth::group_members(&etc, &self.cfg.admin_groups).is_empty(),
            None => true,
        }
    }

    /// Embedded first run: create the first administrator as a system user
    /// (passwd/group/shadow, sha512-crypt, member of the first admin group),
    /// who then signs in through PAM (or the shadow backend) like any other
    /// account. Refused once any administrator exists and for weak passwords.
    pub fn create_first_account(&self, name: &str, password: &str) -> Result<(), String> {
        static LOCK: Mutex<()> = Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let etc = self
            .local_etc()
            .ok_or("first-run setup needs the web UI to manage the accounts itself (root)")?;
        if !sysauth::group_members(&etc, &self.cfg.admin_groups).is_empty() {
            return Err("an administrator account already exists".into());
        }
        if !sysauth::valid_name(name) || name == "root" {
            return Err(
                "Invalid user name: use letters, digits, '.', '_' or '-' (not root)".into(),
            );
        }
        if sysauth::lookup(&Backend::Shadow(etc.clone()), name).is_some() {
            return Err(format!("Invalid user name: {name} already exists"));
        }
        crate::auth::check_admin_password(password).map_err(|e| format!("Invalid {e}"))?;
        let group = self
            .cfg
            .admin_groups
            .iter()
            .find(|g| !g.is_empty())
            .cloned()
            .unwrap_or_else(|| "patronus-admin".into());
        sysauth::add_account(&etc, name, password, &[group])?;
        self.set_first_run_pending(false);
        Ok(())
    }

    /// Is `password` this system user's password (own-account re-entry:
    /// groups are not looked at again)?
    pub async fn confirm(&self, name: &str, password: &str) -> bool {
        sysauth::valid_name(name) && matches!(self.check(name, password).await, Ok(Some(_)))
    }

    async fn check(&self, name: &str, password: &str) -> Result<Option<Identity>, Fail> {
        match &self.mode {
            Mode::Direct(b) => {
                let (b, n, p) = (b.clone(), name.to_string(), password.to_string());
                tokio::task::spawn_blocking(move || sysauth::check(&b, &n, &p))
                    .await
                    .map_err(|_| Fail::Unavailable)?
                    .map_err(|e| {
                        tracing::warn!("system authentication error: {e}");
                        Fail::Unavailable
                    })
            }
            Mode::Broker(sock) => patronus_network::applyd::request_auth(sock, name, password)
                .await
                .map_err(|e| {
                    tracing::warn!("system authentication error: {e}");
                    Fail::Unavailable
                }),
        }
    }

    /// Sign a system user in: the password is checked (also for unknown
    /// names, so the cost does not reveal them), then the groups decide the
    /// role. `name` is the exact account name.
    pub async fn verify(&self, name: &str, password: &str) -> Result<UserRole, Fail> {
        if !sysauth::valid_name(name) {
            return Err(Fail::BadCredentials);
        }
        if !self.backoff_ok(name) {
            return Err(Fail::Backoff);
        }
        let r = self.verify_checked(name, password).await;
        match &r {
            Ok(_) => {
                self.fails().remove(name);
            }
            Err(_) => self.backoff_fail(name),
        }
        r
    }

    async fn verify_checked(&self, name: &str, password: &str) -> Result<UserRole, Fail> {
        // root is refused before any password is tried against it
        if name == "root" && !self.cfg.allow_root {
            return Err(Fail::Root);
        }
        let id = self
            .check(name, password)
            .await?
            .ok_or(Fail::BadCredentials)?;
        match self.cfg.decide(name, Some(id.uid), &id.groups) {
            Decision::Role(r) => Ok(r),
            Decision::DeniedRoot => Err(Fail::Root),
            Decision::DeniedNoGroup => Err(Fail::NoGroup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn wheel_and_patronus_admin_are_admin_by_default() {
        let c = WebAuthConfig::default();
        for grp in ["wheel", "patronus-admin"] {
            assert_eq!(
                c.decide("alice", Some(1000), &g(&["users", grp])),
                Decision::Role(UserRole::Admin)
            );
        }
    }

    #[test]
    fn user_outside_every_mapped_group_is_denied() {
        let c = WebAuthConfig::default();
        assert_eq!(
            c.decide("bob", Some(1001), &g(&["users", "audio"])),
            Decision::DeniedNoGroup
        );
        assert_eq!(c.decide("bob", Some(1001), &[]), Decision::DeniedNoGroup);
    }

    #[test]
    fn root_is_denied_unless_allowed_even_in_wheel() {
        let mut c = WebAuthConfig::default();
        assert_eq!(
            c.decide("root", Some(0), &g(&["root", "wheel"])),
            Decision::DeniedRoot
        );
        // a uid-0 alias is root too
        assert_eq!(
            c.decide("toor", Some(0), &g(&["wheel"])),
            Decision::DeniedRoot
        );
        c.allow_root = true;
        assert_eq!(
            c.decide("root", Some(0), &g(&["wheel"])),
            Decision::Role(UserRole::Admin)
        );
    }

    #[test]
    fn operator_and_readonly_groups_map_and_highest_wins() {
        let c = WebAuthConfig {
            operator_groups: g(&["ops"]),
            readonly_groups: g(&["auditors", "ops"]),
            ..Default::default()
        };
        assert_eq!(
            c.decide("o", Some(1), &g(&["ops"])),
            Decision::Role(UserRole::Operator)
        );
        assert_eq!(
            c.decide("a", Some(2), &g(&["auditors"])),
            Decision::Role(UserRole::ReadOnly)
        );
        assert_eq!(
            c.decide("x", Some(3), &g(&["auditors", "ops", "wheel"])),
            Decision::Role(UserRole::Admin)
        );
    }

    #[test]
    fn empty_group_names_never_match() {
        let c = WebAuthConfig {
            admin_groups: g(&[""]),
            ..Default::default()
        };
        assert_eq!(c.decide("a", Some(1), &g(&[""])), Decision::DeniedNoGroup);
    }

    #[test]
    fn config_file_overrides_and_defaults_stay_strict() {
        let c = WebAuthConfig::parse(
            "admin_groups = [\"netadmins\"]\noperator_groups = [\"ops\"]\nallow_root = false\n",
        )
        .unwrap();
        assert_eq!(c.admin_groups, g(&["netadmins"]));
        assert!(c.legacy_local_login && !c.allow_root);
        assert_eq!(
            c.decide("a", Some(5), &g(&["wheel"])),
            Decision::DeniedNoGroup,
            "wheel is not special once admin_groups is set"
        );
        assert!(WebAuthConfig::parse("admin_groups = 3").is_err());
        assert_eq!(WebAuthConfig::parse("").unwrap(), WebAuthConfig::default());
    }

    #[test]
    fn floor_is_four_seconds() {
        assert_eq!(FAIL_FLOOR, Duration::from_millis(4000));
    }

    fn etc() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let h = pwhash::sha512_crypt::hash("Correct-Horse-9").unwrap();
        std::fs::write(
            d.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\nadm:x:1000:1000::/h:/bin/sh\nops:x:1001:1001::/h:/bin/sh\nplain:x:1002:1002::/h:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("group"),
            "root:x:0:\nwheel:x:10:adm,root\nadm:x:1000:\nops:x:1001:\nplain:x:1002:\nopsgrp:x:2000:ops\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("shadow"),
            format!("root:{h}:1::::::\nadm:{h}:1::::::\nops:{h}:1::::::\nplain:{h}:1::::::\n"),
        )
        .unwrap();
        d
    }

    fn login(d: &tempfile::TempDir) -> SysLogin {
        SysLogin::new(
            WebAuthConfig {
                operator_groups: g(&["opsgrp"]),
                ..Default::default()
            },
            Mode::Direct(Backend::Shadow(d.path().into())),
        )
    }

    #[tokio::test]
    async fn verify_maps_groups_and_refuses_everything_else() {
        let d = etc();
        let s = login(&d);
        let pw = "Correct-Horse-9";
        assert_eq!(s.verify("adm", pw).await, Ok(UserRole::Admin));
        assert_eq!(s.verify("ops", pw).await, Ok(UserRole::Operator));
        assert_eq!(s.verify("plain", pw).await, Err(Fail::NoGroup));
        assert_eq!(s.verify("root", pw).await, Err(Fail::Root));
        assert_eq!(s.verify("adm", "nope").await, Err(Fail::BadCredentials));
        assert_eq!(s.verify("ghost", pw).await, Err(Fail::BadCredentials));
        assert_eq!(s.verify("a;b", pw).await, Err(Fail::BadCredentials));
        assert_eq!(s.verify("", pw).await, Err(Fail::BadCredentials));
    }

    #[tokio::test]
    async fn per_name_backoff_after_five_failures_even_for_the_right_password() {
        let d = etc();
        let s = login(&d);
        for _ in 0..5 {
            assert_eq!(s.verify("adm", "wrong").await, Err(Fail::BadCredentials));
        }
        assert_eq!(s.verify("adm", "Correct-Horse-9").await, Err(Fail::Backoff));
        // the refusal can say how long it lasts
        let left = s.backoff_remaining("adm").expect("backing off");
        assert!((1..=BACKOFF_PAUSE.as_secs()).contains(&left), "{left}");
        assert_eq!(s.backoff_remaining("ops"), None);
        // other names are unaffected
        assert_eq!(
            s.verify("ops", "Correct-Horse-9").await,
            Ok(UserRole::Operator)
        );
    }

    #[tokio::test]
    async fn success_clears_the_failure_count() {
        let d = etc();
        let s = login(&d);
        for _ in 0..4 {
            let _ = s.verify("adm", "wrong").await;
        }
        assert_eq!(
            s.verify("adm", "Correct-Horse-9").await,
            Ok(UserRole::Admin)
        );
        for _ in 0..4 {
            let _ = s.verify("adm", "wrong").await;
        }
        assert_eq!(
            s.verify("adm", "Correct-Horse-9").await,
            Ok(UserRole::Admin)
        );
    }

    #[tokio::test]
    async fn without_a_reachable_broker_login_fails_closed() {
        let s = SysLogin::new(
            WebAuthConfig::default(),
            Mode::Broker("/nonexistent/applyd.sock".into()),
        );
        assert_eq!(s.verify("adm", "x").await, Err(Fail::Unavailable));
    }
}
