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
        }
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
        match self.fails().get(name) {
            Some((n, at)) if *n >= BACKOFF_FAILS => at.elapsed() >= BACKOFF_PAUSE,
            _ => true,
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
            return Err("Invalid user name: use letters, digits, '.', '_' or '-' (not root)".into());
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
        crate::auth::FIRST_RUN_PENDING.store(false, std::sync::atomic::Ordering::SeqCst);
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
