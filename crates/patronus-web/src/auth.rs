//! Authentication, web accounts and sessions.
//!
//! Accounts live in the config store (`web_users`, lane H): they survive
//! restarts, are part of backups/revisions, and can be managed from the
//! System page (admins) -- add, change role, disable, reset 2FA, delete;
//! the last enabled admin can never be removed. Passwords are argon2
//! hashes (patronus-secrets). With USE=totp an account can enrol a TOTP
//! second factor (RFC 6238) plus one-time recovery codes; login then needs
//! the code. Sessions are in memory (a restart logs everyone out) and are
//! dropped when the account is disabled, deleted, demoted or its password
//! changes.

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use patronus_config::ConfigStore;
use patronus_secrets::crypto::{hash_password, verify_password};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A fixed argon2 hash (same parameters as every account's) that logins
/// for unknown or disabled accounts are checked against; no account can
/// have it, since it never leaves this process.
fn decoy_hash() -> &'static str {
    static DECOY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DECOY.get_or_init(|| {
        hash_password(&patronus_secrets::crypto::generate_token(32)).unwrap_or_default()
    })
}

/// The hash a login attempt is verified against: the account's own if it
/// exists and is enabled, else [`decoy_hash`] (equal work either way).
fn hash_to_check(user: Option<&User>) -> &str {
    match user {
        Some(u) if u.enabled => &u.password_hash,
        _ => decoy_hash(),
    }
}

/// `web_users.password_hash` of an account whose password lives on an
/// external server: not a PHC string, so no local password ever verifies.
pub const EXTERNAL_PREFIX: &str = "!external:";

/// Session data stored in memory
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: u32,
    pub username: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

/// User roles for authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Operator,
    ReadOnly,
}

impl UserRole {
    pub fn can_modify(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::Operator)
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }

    /// The stored form (`admin`, `operator`, `readonly`).
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Operator => "operator",
            UserRole::ReadOnly => "readonly",
        }
    }

    /// For display (`read-only`).
    pub fn label(&self) -> &'static str {
        match self {
            UserRole::ReadOnly => "read-only",
            r => r.as_str(),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "admin" => Some(UserRole::Admin),
            "operator" => Some(UserRole::Operator),
            "readonly" | "read-only" | "read_only" => Some(UserRole::ReadOnly),
            _ => None,
        }
    }
}

/// A web account.
#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    /// Confirmed TOTP secret (base32): two-factor login is on.
    pub totp_secret: Option<String>,
    /// Enrolment started, not confirmed yet.
    pub totp_pending: Option<String>,
    pub totp_last_step: Option<u64>,
    /// SHA-256 digests of the unused recovery codes.
    pub recovery_codes: Vec<String>,
}

impl User {
    pub fn two_factor(&self) -> bool {
        self.totp_secret.is_some()
    }
}

/// Web accounts over the config store.
#[derive(Clone)]
pub struct UserStore {
    store: Arc<ConfigStore>,
}

/// Env var holding the admin password (takes precedence over the file).
pub const ADMIN_PASSWORD_ENV: &str = "PATRONUS_ADMIN_PASSWORD";
/// Env var overriding where the generated admin password is persisted.
pub const ADMIN_PASSWORD_FILE_ENV: &str = "PATRONUS_ADMIN_PASSWORD_FILE";
/// Where a per-install admin password is generated on first start.
pub const DEFAULT_ADMIN_PASSWORD_FILE: &str = "/var/lib/patronus/initial-admin-password";
/// Minimum accepted password length (every account).
pub const MIN_ADMIN_PASSWORD_LEN: usize = 12;
/// Passwords that shipped as defaults or are trivially guessable.
const KNOWN_DEFAULT_PASSWORDS: &[&str] = &[
    "admin",
    "operator",
    "password",
    "patronus",
    "changeme",
    "change-me",
    "admin123",
    "administrator",
    "pfsense",
    "opnsense",
    "123456789012",
];

/// Where the admin password came from (for the startup log line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminPasswordSource {
    Env,
    ExistingFile(std::path::PathBuf),
    GeneratedFile(std::path::PathBuf),
    /// The admin account already exists in the store; its password is
    /// whatever was last set (the UI's "change password" sticks).
    Stored,
}

/// Reject publicly known / short admin passwords.
pub fn check_admin_password(pw: &str) -> Result<(), String> {
    let lower = pw.to_ascii_lowercase();
    if KNOWN_DEFAULT_PASSWORDS.contains(&lower.as_str()) {
        return Err("admin password is a publicly known default".to_string());
    }
    if pw.chars().count() < MIN_ADMIN_PASSWORD_LEN {
        return Err(format!(
            "admin password must be at least {} characters",
            MIN_ADMIN_PASSWORD_LEN
        ));
    }
    Ok(())
}

/// The same policy for every account ("Invalid ..." -> HTTP 400).
pub fn check_password(pw: &str) -> anyhow::Result<()> {
    check_admin_password(pw).map_err(|e| anyhow::anyhow!("Invalid {}", e.replacen("admin ", "", 1)))
}

/// 1-32 of `[a-z0-9._-]`, starting with a letter or digit.
pub fn check_username(u: &str) -> anyhow::Result<String> {
    let u = u.trim().to_ascii_lowercase();
    let ok = !u.is_empty()
        && u.len() <= 32
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && u.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(u)
    } else {
        Err(anyhow::anyhow!(
            "Invalid username {u:?}: 1-32 letters, digits, '.', '_' or '-'"
        ))
    }
}

fn generate_admin_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Resolve the per-install admin password: `env` if given (must pass
/// [`check_admin_password`]), else the contents of `file`, else a newly
/// generated random password written to `file` with mode 0600.
pub fn resolve_admin_password(
    env: Option<String>,
    file: &std::path::Path,
) -> Result<(String, AdminPasswordSource), String> {
    if let Some(pw) = env.filter(|p| !p.is_empty()) {
        check_admin_password(&pw).map_err(|e| format!("{}: {}", ADMIN_PASSWORD_ENV, e))?;
        return Ok((pw, AdminPasswordSource::Env));
    }
    match std::fs::read_to_string(file) {
        Ok(contents) => {
            let pw = contents.trim().to_string();
            check_admin_password(&pw)
                .map_err(|e| format!("admin password file {}: {}", file.display(), e))?;
            Ok((pw, AdminPasswordSource::ExistingFile(file.to_path_buf())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let pw = generate_admin_password();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(file).map_err(|e| {
                format!(
                    "cannot create admin password file {} ({}); set {} instead",
                    file.display(),
                    e,
                    ADMIN_PASSWORD_ENV
                )
            })?;
            use std::io::Write;
            writeln!(f, "{}", pw).map_err(|e| format!("cannot write {}: {}", file.display(), e))?;
            Ok((pw, AdminPasswordSource::GeneratedFile(file.to_path_buf())))
        }
        Err(e) => Err(format!(
            "cannot read admin password file {}: {}",
            file.display(),
            e
        )),
    }
}

fn now_ts() -> i64 {
    Utc::now().timestamp()
}

fn ts(v: Option<i64>) -> Option<DateTime<Utc>> {
    v.and_then(|t| Utc.timestamp_opt(t, 0).single())
}

const USER_COLS: &str = "id, username, password_hash, role, enabled, created_at, last_login, \
     totp_secret, totp_pending, totp_last_step, recovery_codes";

fn row_user(r: &sqlx::sqlite::SqliteRow) -> User {
    let codes: Option<String> = r.get(10);
    User {
        id: r.get::<i64, _>(0) as u32,
        username: r.get(1),
        password_hash: r.get(2),
        role: UserRole::parse(&r.get::<String, _>(3)).unwrap_or(UserRole::ReadOnly),
        enabled: r.get::<i64, _>(4) != 0,
        created_at: ts(Some(r.get(5))).unwrap_or_else(Utc::now),
        last_login: ts(r.get(6)),
        totp_secret: r.get(7),
        totp_pending: r.get(8),
        totp_last_step: r.get::<Option<i64>, _>(9).map(|s| s as u64),
        recovery_codes: codes
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default(),
    }
}

/// What [`UserStore::update_user`] may change.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct UserUpdate {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
}

impl UserStore {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self { store }
    }

    /// A store of its own in memory (tests).
    pub async fn in_memory() -> Self {
        Self::new(Arc::new(
            ConfigStore::open_in_memory()
                .await
                .expect("in-memory config store"),
        ))
    }

    fn pool(&self) -> anyhow::Result<&sqlx::SqlitePool> {
        self.store.pool().map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Set the admin password from `PATRONUS_ADMIN_PASSWORD` or the
    /// per-install password file (generated on first start). Fails -- and
    /// the binary refuses to start -- on a weak/known password.
    pub async fn provision_admin_from_env(&self) -> anyhow::Result<AdminPasswordSource> {
        let file = std::env::var(ADMIN_PASSWORD_FILE_ENV)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_ADMIN_PASSWORD_FILE));
        self.provision_admin(std::env::var(ADMIN_PASSWORD_ENV).ok(), &file)
            .await
    }

    /// Make sure the `admin` account exists: created from `env` / the
    /// password file on first start; afterwards its stored password stands
    /// unless `env` (`PATRONUS_ADMIN_PASSWORD`) is set, which re-applies
    /// that password (and re-enables the account) on every start -- the
    /// way back in when the admin password is lost.
    pub async fn provision_admin(
        &self,
        env: Option<String>,
        file: &std::path::Path,
    ) -> anyhow::Result<AdminPasswordSource> {
        let env = env.filter(|p| !p.is_empty());
        let existing = self.get_user("admin").await;
        if existing.is_some() && env.is_none() {
            return Ok(AdminPasswordSource::Stored);
        }
        let (pw, source) = resolve_admin_password(env, file).map_err(|e| anyhow::anyhow!(e))?;
        match existing {
            Some(u) => {
                self.update_password("admin", &pw).await?;
                sqlx::query(
                    "UPDATE web_users SET enabled = 1, role = 'admin', updated_at = ? WHERE id = ?",
                )
                .bind(now_ts())
                .bind(u.id as i64)
                .execute(self.pool()?)
                .await?;
            }
            None => {
                self.insert("admin", &pw, UserRole::Admin).await?;
            }
        }
        Ok(source)
    }

    async fn insert(&self, username: &str, password: &str, role: UserRole) -> anyhow::Result<u32> {
        let hash = hash_password(password)?;
        let r = sqlx::query(
            "INSERT INTO web_users (username, password_hash, role, enabled, created_at, updated_at)
             VALUES (?, ?, ?, 1, ?, ?)",
        )
        .bind(username)
        .bind(hash)
        .bind(role.as_str())
        .bind(now_ts())
        .bind(now_ts())
        .execute(self.pool()?)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                anyhow::anyhow!("Invalid username: {username} already exists")
            } else {
                anyhow::anyhow!("store: {e}")
            }
        })?;
        Ok(r.last_insert_rowid() as u32)
    }

    /// Get a user by username
    pub async fn get_user(&self, username: &str) -> Option<User> {
        let q = format!("SELECT {USER_COLS} FROM web_users WHERE username = ?");
        sqlx::query(&q)
            .bind(username)
            .fetch_optional(self.pool().ok()?)
            .await
            .ok()
            .flatten()
            .map(|r| row_user(&r))
    }

    pub async fn get_by_id(&self, id: u32) -> Option<User> {
        let q = format!("SELECT {USER_COLS} FROM web_users WHERE id = ?");
        sqlx::query(&q)
            .bind(id as i64)
            .fetch_optional(self.pool().ok()?)
            .await
            .ok()
            .flatten()
            .map(|r| row_user(&r))
    }

    /// Verify user credentials and return user if valid
    ///
    /// Unknown and disabled accounts are checked against a decoy argon2 hash, so
    /// they take as long as a wrong password for a real account. Before
    /// this they returned before any argon2 work, and the response time
    /// told an unauthenticated client which usernames exist (and are
    /// enabled): it could then spend the login throttle's budget on real
    /// accounts only.
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Option<User> {
        let user = self.get_user(&username.trim().to_ascii_lowercase()).await;
        let ok = matches!(
            verify_password(password, hash_to_check(user.as_ref())),
            Ok(true)
        );
        user.filter(|u| u.enabled && ok)
    }

    /// Is this a password-less account whose login is checked by an
    /// external server (RADIUS)?
    pub fn is_external(u: &User) -> bool {
        u.password_hash.starts_with(EXTERNAL_PREFIX)
    }

    /// The account of a person authenticated by an external server: the
    /// existing one (kept as an admin left it: role, enabled), or a new
    /// password-less account with `role`.
    pub async fn external_user(
        &self,
        username: &str,
        role: UserRole,
    ) -> anyhow::Result<Option<User>> {
        let name = check_username(username)?;
        if let Some(u) = self.get_user(&name).await {
            // a local-password account is never taken over by an external login
            return Ok(Self::is_external(&u).then_some(u));
        }
        let r = sqlx::query(
            "INSERT INTO web_users (username, password_hash, role, enabled, created_at, updated_at)
             VALUES (?, ?, ?, 1, ?, ?)",
        )
        .bind(&name)
        .bind(format!("{EXTERNAL_PREFIX}radius"))
        .bind(role.as_str())
        .bind(now_ts())
        .bind(now_ts())
        .execute(self.pool()?)
        .await;
        match r {
            Ok(_) => Ok(self.get_user(&name).await),
            // created by a parallel login
            Err(_) => Ok(self.get_user(&name).await.filter(Self::is_external)),
        }
    }

    /// Update last login time for a user
    pub async fn update_last_login(&self, username: &str) {
        if let Ok(p) = self.pool() {
            let _ = sqlx::query("UPDATE web_users SET last_login = ? WHERE username = ?")
                .bind(now_ts())
                .bind(username)
                .execute(p)
                .await;
        }
    }

    /// Create a new account (username and password policy checked).
    pub async fn create_user(
        &self,
        username: String,
        password: &str,
        role: UserRole,
    ) -> anyhow::Result<u32> {
        let username = check_username(&username)?;
        check_password(password)?;
        self.insert(&username, password, role).await
    }

    /// Update a user's password (no policy check: callers check).
    pub async fn update_password(&self, username: &str, new_password: &str) -> anyhow::Result<()> {
        let hash = hash_password(new_password)?;
        let r = sqlx::query(
            "UPDATE web_users SET password_hash = ?, updated_at = ? WHERE username = ?",
        )
        .bind(hash)
        .bind(now_ts())
        .bind(username)
        .execute(self.pool()?)
        .await?;
        if r.rows_affected() == 0 {
            anyhow::bail!("User not found");
        }
        Ok(())
    }

    async fn enabled_admins_except(&self, id: u32) -> anyhow::Result<i64> {
        Ok(sqlx::query(
            "SELECT COUNT(*) FROM web_users WHERE role = 'admin' AND enabled = 1 AND id != ?",
        )
        .bind(id as i64)
        .fetch_one(self.pool()?)
        .await?
        .get(0))
    }

    /// Change role / enabled / password of account `id`. The last enabled
    /// admin cannot be demoted or disabled.
    pub async fn update_user(&self, id: u32, u: &UserUpdate) -> anyhow::Result<User> {
        let cur = self
            .get_by_id(id)
            .await
            .ok_or_else(|| anyhow::anyhow!("no such user {id}"))?;
        let role = match &u.role {
            Some(r) => UserRole::parse(r).ok_or_else(|| {
                anyhow::anyhow!("Invalid role {r:?}: admin, operator or readonly")
            })?,
            None => cur.role,
        };
        let enabled = u.enabled.unwrap_or(cur.enabled);
        if cur.role == UserRole::Admin
            && cur.enabled
            && (role != UserRole::Admin || !enabled)
            && self.enabled_admins_except(id).await? == 0
        {
            anyhow::bail!("Invalid change: at least one enabled admin account must remain");
        }
        if let Some(pw) = &u.password {
            check_password(pw)?;
            self.update_password(&cur.username, pw).await?;
        }
        sqlx::query("UPDATE web_users SET role = ?, enabled = ?, updated_at = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(enabled as i64)
            .bind(now_ts())
            .bind(id as i64)
            .execute(self.pool()?)
            .await?;
        self.get_by_id(id)
            .await
            .ok_or_else(|| anyhow::anyhow!("no such user {id}"))
    }

    /// Delete account `id` (never the last enabled admin).
    pub async fn delete_user(&self, id: u32) -> anyhow::Result<bool> {
        let Some(cur) = self.get_by_id(id).await else {
            return Ok(false);
        };
        if cur.role == UserRole::Admin && cur.enabled && self.enabled_admins_except(id).await? == 0
        {
            anyhow::bail!("Invalid change: at least one enabled admin account must remain");
        }
        sqlx::query("DELETE FROM web_users WHERE id = ?")
            .bind(id as i64)
            .execute(self.pool()?)
            .await?;
        Ok(true)
    }

    /// Disable a user
    pub async fn disable_user(&self, username: &str) -> anyhow::Result<()> {
        let u = self
            .get_user(username)
            .await
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        self.update_user(
            u.id,
            &UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .map(|_| ())
    }

    /// Enable a user
    pub async fn enable_user(&self, username: &str) -> anyhow::Result<()> {
        let u = self
            .get_user(username)
            .await
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        self.update_user(
            u.id,
            &UserUpdate {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .map(|_| ())
    }

    /// List all users (without password hashes or secrets), by id.
    pub async fn list_users(&self) -> Vec<UserInfo> {
        let q = format!("SELECT {USER_COLS} FROM web_users ORDER BY id");
        let Ok(pool) = self.pool() else {
            return Vec::new();
        };
        sqlx::query(&q)
            .fetch_all(pool)
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| UserInfo::from(&row_user(r)))
            .collect()
    }

    // --- second factor (TOTP) -------------------------------------------

    /// Turn two-factor login off for account `id` (admin reset, the
    /// account's own "disable", `patronus users reset-2fa`).
    pub async fn totp_reset(&self, id: u32) -> anyhow::Result<bool> {
        let r = sqlx::query(
            "UPDATE web_users SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL,
                recovery_codes = NULL, updated_at = ? WHERE id = ?",
        )
        .bind(now_ts())
        .bind(id as i64)
        .execute(self.pool()?)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Start enrolment: a new pending secret (base32).
    #[cfg(feature = "totp")]
    pub async fn totp_begin(&self, id: u32) -> anyhow::Result<String> {
        let secret = crate::totp::generate_secret();
        sqlx::query("UPDATE web_users SET totp_pending = ?, updated_at = ? WHERE id = ?")
            .bind(&secret)
            .bind(now_ts())
            .bind(id as i64)
            .execute(self.pool()?)
            .await?;
        Ok(secret)
    }

    /// Confirm enrolment with a code from the app: two-factor login is on;
    /// returns the one-time recovery codes (shown once, stored hashed).
    /// A code that does not match fails with [`WrongTotpCode`].
    ///
    /// Only the first confirmation of a pending secret wins. The write is a
    /// compare-and-set on "two-factor still off and this secret still
    /// pending": without it, two confirmations racing (a double-clicked
    /// "Enable", two tabs) both passed the read, both wrote, and the second
    /// write replaced the recovery codes the first response had already
    /// shown -- the owner could save a set that no longer works. A
    /// confirmation for an account whose two-factor login is already on is
    /// refused and changes nothing (secret, last step and recovery codes
    /// stay as they are).
    #[cfg(feature = "totp")]
    pub async fn totp_confirm(&self, id: u32, code: &str) -> anyhow::Result<Vec<String>> {
        let u = self
            .get_by_id(id)
            .await
            .ok_or_else(|| anyhow::anyhow!("no such user {id}"))?;
        if u.two_factor() {
            anyhow::bail!("Invalid request: two-factor login is already on (disable it first)");
        }
        let secret = u
            .totp_pending
            .ok_or_else(|| anyhow::anyhow!("Invalid request: start the two-factor setup first"))?;
        let step =
            crate::totp::verify(&secret, code, now_ts() as u64, None).ok_or(WrongTotpCode)?;
        let (codes, hashes) = crate::totp::generate_recovery_codes();
        let r = sqlx::query(
            "UPDATE web_users SET totp_secret = ?, totp_pending = NULL, totp_last_step = ?,
                recovery_codes = ?, updated_at = ?
              WHERE id = ? AND totp_secret IS NULL AND totp_pending = ?",
        )
        .bind(&secret)
        .bind(step as i64)
        .bind(serde_json::to_string(&hashes)?)
        .bind(now_ts())
        .bind(id as i64)
        .bind(&secret)
        .execute(self.pool()?)
        .await?;
        if r.rows_affected() != 1 {
            anyhow::bail!(
                "Invalid request: the two-factor setup was already confirmed or restarted (reload and check)"
            );
        }
        Ok(codes)
    }

    /// Check a login's second factor: a TOTP code newer than the last one
    /// accepted, or an unused recovery code (consumed).
    #[cfg(feature = "totp")]
    pub async fn totp_check(&self, user: &User, code: &str) -> bool {
        let Some(secret) = &user.totp_secret else {
            return true;
        };
        let Ok(pool) = self.pool() else { return false };
        if let Some(step) = crate::totp::verify(secret, code, now_ts() as u64, user.totp_last_step)
        {
            // only advance: a concurrent login with the same code loses
            let r = sqlx::query(
                "UPDATE web_users SET totp_last_step = ? WHERE id = ?
                   AND (totp_last_step IS NULL OR totp_last_step < ?)",
            )
            .bind(step as i64)
            .bind(user.id as i64)
            .bind(step as i64)
            .execute(pool)
            .await;
            return matches!(r, Ok(r) if r.rows_affected() == 1);
        }
        let digest = crate::totp::recovery_digest(code);
        if code.trim().len() >= 10 && user.recovery_codes.contains(&digest) {
            let left: Vec<&String> = user
                .recovery_codes
                .iter()
                .filter(|h| **h != digest)
                .collect();
            let r = sqlx::query(
                "UPDATE web_users SET recovery_codes = ? WHERE id = ? AND recovery_codes = ?",
            )
            .bind(serde_json::to_string(&left).unwrap_or_default())
            .bind(user.id as i64)
            .bind(serde_json::to_string(&user.recovery_codes).unwrap_or_default())
            .execute(pool)
            .await;
            return matches!(r, Ok(r) if r.rows_affected() == 1);
        }
        false
    }
}

/// User info without sensitive data
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub id: u32,
    pub username: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub two_factor: bool,
    pub recovery_codes_left: usize,
}

impl From<&User> for UserInfo {
    fn from(u: &User) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            role: u.role,
            enabled: u.enabled,
            created_at: u.created_at,
            last_login: u.last_login,
            two_factor: u.two_factor(),
            recovery_codes_left: u.recovery_codes.len(),
        }
    }
}

/// Session store - in memory (a restart logs everyone out)
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session
    pub async fn create_session(&self, user_id: u32, username: String, role: UserRole) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = Session {
            user_id,
            username,
            role,
            created_at: now,
            last_active: now,
        };

        self.sessions
            .write()
            .await
            .insert(session_id.clone(), session);
        session_id
    }

    /// Get session by ID. A session older than [`SESSION_LIFETIME_SECS`]
    /// (counted from login, not from last use) is gone: it is removed and
    /// `None` is returned, so a copied cookie value cannot be kept alive
    /// forever by using it, and an expired session does not keep working
    /// until the hourly [`Self::cleanup_expired`] sweep.
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        self.get_session_at(session_id, Utc::now()).await
    }

    async fn get_session_at(&self, session_id: &str, now: DateTime<Utc>) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(session_id)?;
        if !session_alive(session, now) {
            sessions.remove(session_id);
            return None;
        }
        session.last_active = now;
        Some(session.clone())
    }

    /// Delete session (logout)
    pub async fn delete_session(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// End every session of account `user_id` except `keep`.
    pub async fn drop_user(&self, user_id: u32, keep: Option<&str>) {
        self.sessions
            .write()
            .await
            .retain(|id, s| s.user_id != user_id || Some(id.as_str()) == keep);
    }

    /// End every session except `keep` (a restore that replaced the
    /// accounts: a session's cached user id and role may no longer mean
    /// the account it was opened for).
    pub async fn drop_all(&self, keep: Option<&str>) {
        self.sessions
            .write()
            .await
            .retain(|id, _| Some(id.as_str()) == keep);
    }

    /// Remove sessions past [`SESSION_LIFETIME_SECS`].
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();
        self.sessions
            .write()
            .await
            .retain(|_, session| session_alive(session, now));
    }
}

/// How long a web session lasts from login. The session cookie's
/// `Max-Age` is the same, so the browser and the server agree.
pub const SESSION_LIFETIME_SECS: i64 = 24 * 60 * 60;

fn session_alive(s: &Session, now: DateTime<Utc>) -> bool {
    s.created_at > now - Duration::seconds(SESSION_LIFETIME_SECS)
}

/// Authentication errors
#[derive(Debug)]
pub enum AuthError {
    MissingSession,
    InvalidSession,
    InvalidCredentials,
    UserDisabled,
    Forbidden,
    InternalError,
    /// Too many failed logins; retry after this many seconds.
    TooManyAttempts(u64),
    /// Password right, the account has two-factor login: send `totp_code`.
    TotpRequired,
    /// The two-factor code was wrong (or already used).
    InvalidTotp,
    /// The account has two-factor login but this build has no TOTP.
    TotpUnavailable,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::TooManyAttempts(secs) => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, secs.to_string())],
                    Json(serde_json::json!({
                        "error": "Too many failed login attempts; try again later",
                        "retry_after_secs": secs,
                    })),
                )
                    .into_response();
            }
            AuthError::TotpRequired | AuthError::InvalidTotp => {
                let msg = if matches!(self, AuthError::TotpRequired) {
                    "Two-factor code required"
                } else {
                    "Invalid two-factor code"
                };
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": msg, "totp_required": true })),
                )
                    .into_response();
            }
            _ => {}
        }
        let (status, message) = match self {
            AuthError::MissingSession => (StatusCode::UNAUTHORIZED, "No session found"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid or expired session"),
            AuthError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid username or password")
            }
            AuthError::UserDisabled => (StatusCode::FORBIDDEN, "User account is disabled"),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::TotpUnavailable => (
                StatusCode::FORBIDDEN,
                "This account uses two-factor login, but this Patronus is built without TOTP \
                 (USE=totp). Rebuild with it, or turn the account's 2FA off on the box with \
                 `patronus users reset-2fa <name>`.",
            ),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        (
            status,
            Json(serde_json::json!({
                "error": message
            })),
        )
            .into_response()
    }
}

/// The `session_id` cookie of a request.
pub fn session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let mut parts = cookie.trim().splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some("session_id"), Some(id)) => Some(id.to_string()),
                    _ => None,
                }
            })
        })
}

/// Authenticated user extractor for protected routes
pub struct AuthUser {
    pub session: Session,
    pub session_id: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // A request the gate authenticated with an API key: a synthetic
        // session (user id 0, never an admin).
        if let Some(p) = parts.extensions.get::<crate::apikeys::ApiKeyPrincipal>() {
            let now = Utc::now();
            return Ok(AuthUser {
                session: Session {
                    user_id: 0,
                    username: format!("api-key:{}", p.0.name),
                    role: p.0.role(),
                    created_at: now,
                    last_active: now,
                },
                session_id: String::new(),
            });
        }
        let session_id = session_cookie(&parts.headers).ok_or(AuthError::MissingSession)?;

        // Get session store from extensions (set by middleware)
        let store = parts
            .extensions
            .get::<SessionStore>()
            .ok_or(AuthError::InternalError)?;

        // Validate session
        let session = store
            .get_session(&session_id)
            .await
            .ok_or(AuthError::InvalidSession)?;

        Ok(AuthUser {
            session,
            session_id,
        })
    }
}

/// Admin-only extractor for admin routes
pub struct AdminUser {
    pub session: Session,
    pub session_id: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        if !auth_user.session.role.is_admin() {
            return Err(AuthError::Forbidden);
        }

        Ok(AdminUser {
            session: auth_user.session,
            session_id: auth_user.session_id,
        })
    }
}

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// TOTP code (or a recovery code) for accounts with two-factor login.
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub username: String,
    pub role: UserRole,
}

/// Failed logins allowed per client within [`LOGIN_FAILURE_WINDOW_SECS`]
/// before further attempts from that client are refused with 429.
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// Window (and lockout length) for [`MAX_LOGIN_FAILURES`].
pub const LOGIN_FAILURE_WINDOW_SECS: i64 = 15 * 60;
/// Upper bound on tracked clients, so a spray from many addresses can't
/// grow the table without limit.
const MAX_TRACKED_LOGIN_CLIENTS: usize = 65_536;

/// [`UserStore::totp_confirm`]'s error for a code that does not match the
/// pending secret -- the failure a code guesser produces, as opposed to
/// "no setup started".
#[cfg(feature = "totp")]
#[derive(Debug)]
pub struct WrongTotpCode;

#[cfg(feature = "totp")]
impl std::fmt::Display for WrongTotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid two-factor code (check the phone's clock)")
    }
}

#[cfg(feature = "totp")]
impl std::error::Error for WrongTotpCode {}

/// Per-client brute-force throttle for `POST /api/auth/login`.
///
/// Before this, the login endpoint accepted unlimited password guesses at
/// full speed from any client. Clients are keyed by IP address; IPv6
/// clients by their /64, since one host trivially owns a whole /64. A
/// successful login clears the client's record. While a client is locked
/// out even the *correct* password is refused, otherwise the lockout would
/// not slow down guessing at all. Wrong two-factor codes count as failures.
#[derive(Clone, Default)]
pub struct LoginThrottle {
    failures: Arc<std::sync::Mutex<FailureTable>>,
}

/// Client key -> (failed attempts, start of the current window).
type FailureTable = HashMap<std::net::IpAddr, (u32, DateTime<Utc>)>;

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(ip: std::net::IpAddr) -> std::net::IpAddr {
        match ip {
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => {
                    let mut o = v6.octets();
                    o[8..].fill(0);
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
                }
            },
            v4 => v4,
        }
    }

    fn window() -> Duration {
        Duration::seconds(LOGIN_FAILURE_WINDOW_SECS)
    }

    /// `Some(seconds until the client may try again)` if it is locked out.
    pub fn check(&self, ip: std::net::IpAddr) -> Option<u64> {
        self.check_at(ip, Utc::now())
    }

    fn check_at(&self, ip: std::net::IpAddr, now: DateTime<Utc>) -> Option<u64> {
        let map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let (count, start) = *map.get(&Self::key(ip))?;
        let until = start + Self::window();
        if count >= MAX_LOGIN_FAILURES && now < until {
            Some((until - now).num_seconds().max(1) as u64)
        } else {
            None
        }
    }

    /// Record a failed login from `ip`.
    pub fn record_failure(&self, ip: std::net::IpAddr) {
        self.record_failure_at(ip, Utc::now())
    }

    fn record_failure_at(&self, ip: std::net::IpAddr, now: DateTime<Utc>) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let window = Self::window();
        if map.len() >= MAX_TRACKED_LOGIN_CLIENTS {
            map.retain(|_, (_, start)| now < *start + window);
        }
        let key = Self::key(ip);
        if map.len() >= MAX_TRACKED_LOGIN_CLIENTS && !map.contains_key(&key) {
            tracing::warn!("login throttle table full; not tracking {}", key);
            return;
        }
        let entry = map.entry(key).or_insert((0, now));
        if now >= entry.1 + window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
        if entry.0 == MAX_LOGIN_FAILURES {
            tracing::warn!(
                "{} failed logins from {}; locking it out for {}s",
                MAX_LOGIN_FAILURES,
                key,
                LOGIN_FAILURE_WINDOW_SECS
            );
        }
    }

    /// Forget `ip`'s failures (after a successful login).
    pub fn record_success(&self, ip: std::net::IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&Self::key(ip));
    }

    /// Drop records whose window has passed.
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        let window = Self::window();
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, start)| now < *start + window);
    }
}

/// Authentication state (includes user store and session store)
#[derive(Clone)]
pub struct AuthState {
    pub user_store: UserStore,
    pub session_store: SessionStore,
    pub login_throttle: LoginThrottle,
    /// API keys for automation (bearer tokens), see `crate::apikeys`.
    pub api_keys: crate::apikeys::ApiKeyStore,
    pub rbac: crate::rbac::RbacStore,
}

impl AuthState {
    pub fn new(store: Arc<ConfigStore>) -> Self {
        Self {
            user_store: UserStore::new(store.clone()),
            session_store: SessionStore::new(),
            login_throttle: LoginThrottle::new(),
            api_keys: crate::apikeys::ApiKeyStore::new(store.clone()),
            rbac: crate::rbac::RbacStore::new(store),
        }
    }
}

/// The client address [`LoginThrottle`] keys on. Without connection info
/// (in-process callers) every request shares the unspecified address,
/// which still caps guessing.
fn client_ip(
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> std::net::IpAddr {
    connect_info
        .map(|axum::extract::ConnectInfo(addr)| addr.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Re-check the session owner's password before an own-account change
/// (password change, 2FA setup/disable), under the same per-client
/// [`LoginThrottle`] as `POST /api/auth/login`.
///
/// These endpoints used to call `verify_credentials` with no throttle, so
/// anyone holding a session cookie (a stolen or forgotten one) could guess
/// the account's password -- and, through `2fa/disable`, its TOTP codes --
/// at full speed, then change the password and lock the owner out. Wrong
/// guesses here count as failed logins, and a locked-out client is refused
/// (429) even with the right password.
async fn reauth(
    app_state: &crate::state::AppState,
    client: std::net::IpAddr,
    username: &str,
    password: &str,
) -> Result<User, AuthError> {
    let throttle = &app_state.auth.login_throttle;
    if let Some(retry_after) = throttle.check(client) {
        return Err(AuthError::TooManyAttempts(retry_after));
    }
    match app_state
        .auth
        .user_store
        .verify_credentials(username, password)
        .await
    {
        Some(user) => Ok(user),
        None => {
            throttle.record_failure(client);
            tracing::warn!(
                "wrong password re-entered for {:?} from {}",
                username,
                client
            );
            Err(AuthError::InvalidCredentials)
        }
    }
}

/// Login handler
pub async fn login(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AuthError> {
    let client = client_ip(connect_info);
    let throttle = &app_state.auth.login_throttle;
    if let Some(retry_after) = throttle.check(client) {
        return Err(AuthError::TooManyAttempts(retry_after));
    }

    // Verify credentials: the local account, else (for names that are not a
    // local-password account) the RADIUS servers
    let local = app_state
        .auth
        .user_store
        .verify_credentials(&req.username, &req.password)
        .await;
    let user = match local {
        Some(u) => Some(u),
        None => external_login(&app_state, &req.username, &req.password).await,
    };
    let Some(user) = user else {
        throttle.record_failure(client);
        tracing::warn!("failed login for {:?} from {}", req.username, client);
        return Err(AuthError::InvalidCredentials);
    };

    // Second factor
    if user.two_factor() {
        #[cfg(feature = "totp")]
        {
            let code = req.totp_code.as_deref().map(str::trim).unwrap_or("");
            if code.is_empty() {
                return Err(AuthError::TotpRequired);
            }
            if !app_state.auth.user_store.totp_check(&user, code).await {
                throttle.record_failure(client);
                tracing::warn!(
                    "wrong two-factor code for {:?} from {}",
                    user.username,
                    client
                );
                return Err(AuthError::InvalidTotp);
            }
        }
        #[cfg(not(feature = "totp"))]
        {
            let _ = &req.totp_code;
            return Err(AuthError::TotpUnavailable);
        }
    }
    throttle.record_success(client);

    // Update last login time
    app_state
        .auth
        .user_store
        .update_last_login(&user.username)
        .await;

    // Create session
    let session_id = app_state
        .auth
        .session_store
        .create_session(user.id, user.username.clone(), user.role)
        .await;

    // Set secure cookie
    let cookie = format!(
        "session_id={}; HttpOnly; SameSite=Strict; Max-Age={}; Path=/",
        session_id, SESSION_LIFETIME_SECS
    );

    let response = Json(LoginResponse {
        success: true,
        username: user.username,
        role: user.role,
    });

    Ok(([(header::SET_COOKIE, cookie)], response).into_response())
}

/// A login the local store did not accept, offered to the RADIUS servers.
/// Local-password accounts never get here with success (their failed
/// password stays failed); a disabled external account stays refused.
async fn external_login(
    app_state: &crate::state::AppState,
    username: &str,
    password: &str,
) -> Option<User> {
    let name = username.trim().to_ascii_lowercase();
    if let Some(u) = app_state.auth.user_store.get_user(&name).await {
        if !UserStore::is_external(&u) || !u.enabled {
            return None;
        }
    }
    // user names that could not be an account are not offered to a directory
    check_username(&name).ok()?;
    let role = if let Some(server) =
        crate::radius::check_login(&app_state.config_store, &name, password).await
    {
        UserRole::parse(&server.default_role).unwrap_or(UserRole::ReadOnly)
    } else {
        #[cfg(feature = "ldap")]
        {
            let (server, found) =
                crate::ldap::check_login(&app_state.config_store, &name, password).await?;
            if found.operator {
                UserRole::Operator
            } else {
                UserRole::parse(&server.default_role).unwrap_or(UserRole::ReadOnly)
            }
        }
        #[cfg(not(feature = "ldap"))]
        return None;
    };
    let u = app_state
        .auth
        .user_store
        .external_user(&name, role)
        .await
        .ok()??;
    u.enabled.then_some(u)
}

/// Logout handler
pub async fn logout(
    State(app_state): State<crate::state::AppState>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    app_state
        .auth
        .session_store
        .delete_session(&auth_user.session_id)
        .await;

    // Clear cookie
    let cookie = "session_id=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/";

    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "success": true,
            "message": "Logged out successfully"
        })),
    )
}

/// Get current user info
pub async fn current_user(
    State(app_state): State<crate::state::AppState>,
    auth_user: AuthUser,
) -> impl IntoResponse {
    let u = app_state
        .auth
        .user_store
        .get_by_id(auth_user.session.user_id)
        .await;
    Json(serde_json::json!({
        "username": auth_user.session.username,
        "role": auth_user.session.role,
        "user_id": auth_user.session.user_id,
        "two_factor": u.as_ref().is_some_and(|u| u.two_factor()),
        "totp_available": cfg!(feature = "totp"),
    }))
}

/// Change password request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

fn bad_request(msg: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}

/// POST /api/auth/password -- change one's own password (any role). Other
/// sessions of the account end.
pub async fn change_password(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    auth_user: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let us = &app_state.auth.user_store;
    let user = match reauth(
        &app_state,
        client_ip(connect_info),
        &auth_user.session.username,
        &req.current_password,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_password(&req.new_password) {
        return bad_request(e.to_string());
    }
    if us
        .update_password(&user.username, &req.new_password)
        .await
        .is_err()
    {
        return AuthError::InternalError.into_response();
    }
    app_state
        .auth
        .session_store
        .drop_user(user.id, Some(&auth_user.session_id))
        .await;
    Json(serde_json::json!({
        "success": true,
        "message": "Password changed"
    }))
    .into_response()
}

// --- two-factor enrolment (own account) --------------------------------------

#[derive(Debug, Deserialize)]
pub struct TotpSetupRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpCodeRequest {
    pub code: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[cfg(not(feature = "totp"))]
fn totp_not_built() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "two-factor authentication is not built into this Patronus (rebuild with USE=totp)"
        })),
    )
        .into_response()
}

/// POST /api/auth/2fa/setup {password} -> {secret, otpauth_uri, qr_svg}:
/// a new secret to scan; nothing changes for login until it is confirmed.
pub async fn totp_setup(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    auth_user: AuthUser,
    Json(req): Json<TotpSetupRequest>,
) -> Response {
    #[cfg(feature = "totp")]
    {
        let us = &app_state.auth.user_store;
        let user = match reauth(
            &app_state,
            client_ip(connect_info),
            &auth_user.session.username,
            &req.password,
        )
        .await
        {
            Ok(u) => u,
            Err(e) => return e.into_response(),
        };
        if user.two_factor() {
            return bad_request(
                "Invalid request: two-factor login is already on (disable it first)",
            );
        }
        let secret = match us.totp_begin(user.id).await {
            Ok(s) => s,
            Err(_) => return AuthError::InternalError.into_response(),
        };
        let uri = crate::totp::otpauth_uri(&user.username, &secret);
        let qr = crate::qrcode::generate_qr_code_svg(&uri).unwrap_or_default();
        Json(serde_json::json!({ "secret": secret, "otpauth_uri": uri, "qr_svg": qr }))
            .into_response()
    }
    #[cfg(not(feature = "totp"))]
    {
        let _ = (&app_state, &connect_info, &auth_user, &req.password);
        totp_not_built()
    }
}

/// POST /api/auth/2fa/enable {code} -> {recovery_codes}: confirm with a
/// code from the app; from now on login needs a code. Other sessions of the
/// account end: one opened with the password alone (say, by whoever made the
/// owner turn two-factor on) must not outlive the switch.
///
/// Wrong codes count as failed logins in the [`LoginThrottle`], and a
/// locked-out client is refused (429). Without that, a session holder could
/// try all 10^6 codes against a pending setup at full speed (about three
/// codes are valid at any moment), turn two-factor on with a secret the
/// owner may never have scanned, and walk off with the recovery codes.
pub async fn totp_enable(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    auth_user: AuthUser,
    Json(req): Json<TotpCodeRequest>,
) -> Response {
    #[cfg(feature = "totp")]
    {
        let client = client_ip(connect_info);
        let throttle = &app_state.auth.login_throttle;
        if let Some(retry_after) = throttle.check(client) {
            return AuthError::TooManyAttempts(retry_after).into_response();
        }
        match app_state
            .auth
            .user_store
            .totp_confirm(auth_user.session.user_id, &req.code)
            .await
        {
            Ok(codes) => {
                app_state
                    .auth
                    .session_store
                    .drop_user(auth_user.session.user_id, Some(&auth_user.session_id))
                    .await;
                Json(serde_json::json!({ "enabled": true, "recovery_codes": codes }))
                    .into_response()
            }
            Err(e) => {
                if e.is::<WrongTotpCode>() {
                    throttle.record_failure(client);
                    tracing::warn!(
                        "wrong two-factor code confirming setup for {:?} from {}",
                        auth_user.session.username,
                        client
                    );
                }
                bad_request(e.to_string())
            }
        }
    }
    #[cfg(not(feature = "totp"))]
    {
        let _ = (&app_state, &connect_info, &auth_user, &req.code);
        totp_not_built()
    }
}

/// POST /api/auth/2fa/disable {password, code}: turn one's own two-factor
/// login off (needs both factors). Other sessions of the account end, as on
/// a password change.
pub async fn totp_disable(
    State(app_state): State<crate::state::AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    auth_user: AuthUser,
    Json(req): Json<TotpCodeRequest>,
) -> Response {
    #[cfg(feature = "totp")]
    {
        let us = &app_state.auth.user_store;
        let client = client_ip(connect_info);
        let user = match reauth(
            &app_state,
            client,
            &auth_user.session.username,
            req.password.as_deref().unwrap_or(""),
        )
        .await
        {
            Ok(u) => u,
            Err(e) => return e.into_response(),
        };
        if !user.two_factor() {
            return bad_request("Invalid request: two-factor login is not on");
        }
        if !us.totp_check(&user, &req.code).await {
            app_state.auth.login_throttle.record_failure(client);
            return AuthError::InvalidTotp.into_response();
        }
        match us.totp_reset(user.id).await {
            Ok(_) => {
                app_state
                    .auth
                    .session_store
                    .drop_user(user.id, Some(&auth_user.session_id))
                    .await;
                Json(serde_json::json!({ "enabled": false })).into_response()
            }
            Err(_) => AuthError::InternalError.into_response(),
        }
    }
    #[cfg(not(feature = "totp"))]
    {
        let _ = (&app_state, &connect_info, &auth_user, &req.code);
        totp_not_built()
    }
}

/// Middleware to inject session store into request extensions
pub async fn session_middleware(
    State(app_state): State<crate::state::AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    req.extensions_mut()
        .insert(app_state.auth.session_store.clone());
    req.extensions_mut().insert(app_state.auth.api_keys.clone());
    req.extensions_mut().insert(app_state.auth.rbac.clone());
    next.run(req).await
}

#[cfg(test)]
mod default_credential_tests {
    use super::*;

    fn tmp_file() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("patronus-web-auth-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("initial-admin-password")
    }

    #[tokio::test]
    async fn shipped_default_credentials_do_not_work() {
        let store = UserStore::in_memory().await;
        store.provision_admin(None, &tmp_file()).await.unwrap();
        assert!(store.verify_credentials("admin", "admin").await.is_none());
        assert!(store
            .verify_credentials("operator", "operator")
            .await
            .is_none());
        assert!(store.get_user("operator").await.is_none());
    }

    #[tokio::test]
    async fn first_start_generates_a_private_per_install_password() {
        let file = tmp_file();
        let db = file.with_file_name("config.db");
        let cs = Arc::new(ConfigStore::open(&db).await.unwrap());
        let store = UserStore::new(cs.clone());
        let src = store.provision_admin(None, &file).await.unwrap();
        assert_eq!(src, AdminPasswordSource::GeneratedFile(file.clone()));
        let pw = std::fs::read_to_string(&file).unwrap().trim().to_string();
        assert!(pw.len() >= MIN_ADMIN_PASSWORD_LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(store.verify_credentials("admin", &pw).await.is_some());
        assert!(store.verify_credentials("admin", "admin").await.is_none());

        // Restart (a new process over the same store): the account and its
        // password persist; a password changed in the UI sticks.
        let again = UserStore::new(Arc::new(ConfigStore::open(&db).await.unwrap()));
        assert_eq!(
            again.provision_admin(None, &file).await.unwrap(),
            AdminPasswordSource::Stored
        );
        assert!(again.verify_credentials("admin", &pw).await.is_some());
        again
            .update_password("admin", "Changed-In-The-UI-42")
            .await
            .unwrap();
        let third = UserStore::new(Arc::new(ConfigStore::open(&db).await.unwrap()));
        third.provision_admin(None, &file).await.unwrap();
        assert!(third
            .verify_credentials("admin", "Changed-In-The-UI-42")
            .await
            .is_some());
        // ... unless PATRONUS_ADMIN_PASSWORD is set: the way back in
        third
            .provision_admin(Some("Recovery-Passw0rd-1".into()), &file)
            .await
            .unwrap();
        assert!(third
            .verify_credentials("admin", "Recovery-Passw0rd-1")
            .await
            .is_some());

        // a second install gets another password
        let other = tmp_file();
        UserStore::in_memory()
            .await
            .provision_admin(None, &other)
            .await
            .unwrap();
        assert_ne!(std::fs::read_to_string(&other).unwrap().trim(), pw);
    }

    #[tokio::test]
    async fn weak_or_default_admin_password_is_refused() {
        let file = tmp_file();
        for weak in ["admin", "ADMIN", "operator", "changeme", "short-pw"] {
            let err = UserStore::in_memory()
                .await
                .provision_admin(Some(weak.to_string()), &file)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(ADMIN_PASSWORD_ENV), "{err}");
        }
        std::fs::write(&file, "admin\n").unwrap();
        assert!(UserStore::in_memory()
            .await
            .provision_admin(None, &file)
            .await
            .is_err());
        let store = UserStore::in_memory().await;
        store
            .provision_admin(Some("Correct-Horse-Battery-9".to_string()), &file)
            .await
            .unwrap();
        assert!(store
            .verify_credentials("admin", "Correct-Horse-Battery-9")
            .await
            .is_some());
    }
}

#[cfg(test)]
mod account_tests {
    use super::*;

    async fn store() -> UserStore {
        let s = UserStore::in_memory().await;
        s.provision_admin(
            Some("Admin-Passw0rd-123".into()),
            &std::env::temp_dir().join("unused"),
        )
        .await
        .unwrap();
        s
    }

    /// Unknown or disabled usernames must cost the same argon2 check as a
    /// wrong password for a real account, or the response time tells an
    /// unauthenticated client which accounts exist.
    #[tokio::test]
    async fn unknown_and_disabled_accounts_cost_a_full_password_check() {
        let s = store().await;
        let id = s
            .create_user("carol".into(), "Carol-Passw0rd-1", UserRole::Operator)
            .await
            .unwrap();
        let carol = s.get_by_id(id).await.unwrap();
        // "$argon2id$v=19$m=..,t=..,p=.." -- algorithm, version and cost
        let params = |h: &str| h.rsplitn(3, '$').nth(2).unwrap_or_default().to_string();
        assert!(
            params(decoy_hash()).starts_with("$argon2"),
            "{}",
            decoy_hash()
        );
        assert_eq!(params(decoy_hash()), params(&carol.password_hash));
        // a well-formed hash: verifying against it does the full work
        assert!(matches!(
            verify_password("Carol-Passw0rd-1", decoy_hash()),
            Ok(false)
        ));

        assert_eq!(hash_to_check(Some(&carol)), carol.password_hash);
        assert_eq!(hash_to_check(None), decoy_hash());
        let mut off = carol.clone();
        off.enabled = false;
        assert_eq!(hash_to_check(Some(&off)), decoy_hash());

        assert!(s
            .verify_credentials("nobody", "Carol-Passw0rd-1")
            .await
            .is_none());
        assert!(s
            .verify_credentials("carol", "Wrong-Passw0rd-1")
            .await
            .is_none());
        assert!(s
            .verify_credentials("carol", "Carol-Passw0rd-1")
            .await
            .is_some());
        s.update_user(
            id,
            &UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(s
            .verify_credentials("carol", "Carol-Passw0rd-1")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn accounts_are_created_validated_and_the_last_admin_stays() {
        let s = store().await;
        let id = s
            .create_user("Alice".into(), "Alice-Passw0rd-1", UserRole::Operator)
            .await
            .unwrap();
        let a = s.get_by_id(id).await.unwrap();
        assert_eq!((a.username.as_str(), a.role), ("alice", UserRole::Operator));
        assert!(s
            .verify_credentials("ALICE", "Alice-Passw0rd-1")
            .await
            .is_some());
        for (u, p) in [
            ("alice", "Another-Passw0rd"),
            ("bad name", "Another-Passw0rd"),
            ("-x", "Another-Passw0rd"),
            ("bob", "short"),
            ("bob", "changeme"),
        ] {
            let e = s
                .create_user(u.into(), p, UserRole::ReadOnly)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.starts_with("Invalid"), "{u}/{p}: {e}");
        }
        // disabled accounts cannot log in
        s.update_user(
            id,
            &UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(s
            .verify_credentials("alice", "Alice-Passw0rd-1")
            .await
            .is_none());

        let admin = s.get_user("admin").await.unwrap();
        for u in [
            UserUpdate {
                role: Some("operator".into()),
                ..Default::default()
            },
            UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        ] {
            let e = s.update_user(admin.id, &u).await.unwrap_err().to_string();
            assert!(e.contains("at least one enabled admin"), "{e}");
        }
        assert!(s.delete_user(admin.id).await.is_err());
        // with a second admin the first may go
        s.update_user(
            id,
            &UserUpdate {
                role: Some("admin".into()),
                enabled: Some(true),
                password: Some("Alice-New-Passw0rd".into()),
            },
        )
        .await
        .unwrap();
        assert!(s
            .verify_credentials("alice", "Alice-New-Passw0rd")
            .await
            .is_some());
        assert!(s.delete_user(admin.id).await.unwrap());
        assert!(!s.delete_user(admin.id).await.unwrap());
        let list = s.list_users().await;
        assert_eq!(list.len(), 1);
        let json = serde_json::to_string(&list).unwrap();
        assert!(
            !json.contains("argon2"),
            "no hashes in the API view: {json}"
        );
        assert!(s
            .update_user(
                id,
                &UserUpdate {
                    role: Some("root".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err());
    }

    #[cfg(feature = "totp")]
    #[tokio::test]
    async fn totp_enrolment_codes_and_recovery_codes() {
        let s = store().await;
        let admin = s.get_user("admin").await.unwrap();
        assert!(!admin.two_factor());
        let secret = s.totp_begin(admin.id).await.unwrap();
        // pending: login does not need a code yet
        assert!(!s.get_by_id(admin.id).await.unwrap().two_factor());
        let now = Utc::now().timestamp() as u64;
        let code = crate::totp::code_at(&secret, now).unwrap();
        // a wrong code (none of the accepted steps') does not enrol
        let wrong = (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| crate::totp::verify(&secret, c, now, None).is_none())
            .unwrap();
        assert!(s.totp_confirm(admin.id, &wrong).await.is_err());
        assert!(!s.get_by_id(admin.id).await.unwrap().two_factor());
        let recovery = s.totp_confirm(admin.id, &code).await.unwrap();
        assert_eq!(recovery.len(), crate::totp::RECOVERY_CODES);
        let u = s.get_by_id(admin.id).await.unwrap();
        assert!(u.two_factor() && u.totp_pending.is_none());
        // the confirming code cannot be replayed at login
        assert!(!s.totp_check(&u, &code).await);
        // the next step's code works once
        let next = crate::totp::code_at(&secret, now + crate::totp::PERIOD).unwrap();
        assert!(s.totp_check(&u, &next).await);
        let u = s.get_by_id(admin.id).await.unwrap();
        assert!(!s.totp_check(&u, &next).await, "replay refused");
        // a recovery code works once
        assert!(s.totp_check(&u, &recovery[0].to_uppercase()).await);
        let u = s.get_by_id(admin.id).await.unwrap();
        assert_eq!(u.recovery_codes.len(), crate::totp::RECOVERY_CODES - 1);
        assert!(!s.totp_check(&u, &recovery[0]).await);
        assert!(!s.totp_check(&u, "garbage-code").await);
        // reset (admin / CLI) turns it off
        assert!(s.totp_reset(admin.id).await.unwrap());
        assert!(!s.get_by_id(admin.id).await.unwrap().two_factor());
    }

    /// Two confirmations of the same pending setup (double-clicked
    /// "Enable", two tabs) must not both "succeed": the later write used to
    /// replace the recovery codes the earlier response had shown.
    #[cfg(feature = "totp")]
    #[tokio::test]
    async fn only_one_confirmation_of_a_pending_setup_wins() {
        let s = store().await;
        let admin = s.get_user("admin").await.unwrap();
        let secret = s.totp_begin(admin.id).await.unwrap();
        let now = Utc::now().timestamp() as u64;
        let code = crate::totp::code_at(&secret, now).unwrap();
        let (a, b) = tokio::join!(
            s.totp_confirm(admin.id, &code),
            s.totp_confirm(admin.id, &code)
        );
        let won: Vec<Vec<String>> = [a, b].into_iter().filter_map(Result::ok).collect();
        assert_eq!(won.len(), 1, "exactly one confirmation succeeds");
        // the codes that response showed are the ones stored
        let u = s.get_by_id(admin.id).await.unwrap();
        assert!(u.two_factor());
        assert!(s.totp_check(&u, &won[0][0]).await);

        // two-factor already on and a pending secret left over (say, from a
        // restored backup): confirming it is refused and changes nothing
        let other = crate::totp::generate_secret();
        sqlx::query("UPDATE web_users SET totp_pending = ? WHERE id = ?")
            .bind(&other)
            .bind(admin.id as i64)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let before = s.get_by_id(admin.id).await.unwrap();
        let other_code = crate::totp::code_at(&other, now).unwrap();
        let e = s.totp_confirm(admin.id, &other_code).await.unwrap_err();
        assert!(e.to_string().contains("already on"), "{e}");
        let after = s.get_by_id(admin.id).await.unwrap();
        assert_eq!(after.totp_secret, before.totp_secret);
        assert_eq!(after.recovery_codes, before.recovery_codes);
        assert_eq!(after.totp_last_step, before.totp_last_step);
    }

    #[tokio::test]
    async fn sessions_of_a_user_can_be_ended() {
        let ss = SessionStore::new();
        let a = ss.create_session(1, "a".into(), UserRole::Admin).await;
        let b = ss.create_session(1, "a".into(), UserRole::Admin).await;
        let c = ss.create_session(2, "c".into(), UserRole::ReadOnly).await;
        ss.drop_user(1, Some(&a)).await;
        assert!(ss.get_session(&a).await.is_some());
        assert!(ss.get_session(&b).await.is_none());
        assert!(ss.get_session(&c).await.is_some());
        ss.drop_user(2, None).await;
        assert!(ss.get_session(&c).await.is_none());
    }

    #[tokio::test]
    async fn a_session_ends_a_day_after_login_even_if_it_keeps_being_used() {
        let ss = SessionStore::new();
        let id = ss.create_session(1, "a".into(), UserRole::Admin).await;
        let login = ss.sessions.read().await[&id].created_at;
        let life = Duration::seconds(SESSION_LIFETIME_SECS);
        // used every hour for most of a day: still valid
        for h in 1..24 {
            let at = login + Duration::hours(h);
            assert!(ss.get_session_at(&id, at).await.is_some(), "hour {h}");
        }
        // one second before the lifetime: valid
        let edge = login + life - Duration::seconds(1);
        assert!(ss.get_session_at(&id, edge).await.is_some());
        // at the lifetime: gone, although it was used a second ago,
        // and it is removed from the table, not just refused
        assert!(ss.get_session_at(&id, login + life).await.is_none());
        assert!(!ss.sessions.read().await.contains_key(&id));
        assert!(ss.get_session_at(&id, edge).await.is_none());
    }

    #[tokio::test]
    async fn the_sweep_removes_sessions_past_their_lifetime() {
        let ss = SessionStore::new();
        let old = ss.create_session(1, "a".into(), UserRole::Admin).await;
        let new = ss.create_session(2, "b".into(), UserRole::ReadOnly).await;
        {
            let mut t = ss.sessions.write().await;
            let s = t.get_mut(&old).unwrap();
            s.created_at -= Duration::seconds(SESSION_LIFETIME_SECS + 1);
            s.last_active = Utc::now(); // recent use does not save it
        }
        ss.cleanup_expired().await;
        let t = ss.sessions.read().await;
        assert!(!t.contains_key(&old));
        assert!(t.contains_key(&new));
    }
}

#[cfg(test)]
mod login_throttle_tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn locks_out_after_max_failures_until_the_window_passes() {
        let t = LoginThrottle::new();
        let now = Utc::now();
        let a = ip("192.0.2.1");
        for _ in 0..MAX_LOGIN_FAILURES - 1 {
            t.record_failure_at(a, now);
            assert!(t.check_at(a, now).is_none());
        }
        t.record_failure_at(a, now);
        let retry = t.check_at(a, now).expect("locked out");
        assert!(retry > 0 && retry <= LOGIN_FAILURE_WINDOW_SECS as u64);
        // Another client is unaffected.
        assert!(t.check_at(ip("192.0.2.2"), now).is_none());
        // After the window it may try again, with a fresh count.
        let later = now + Duration::seconds(LOGIN_FAILURE_WINDOW_SECS + 1);
        assert!(t.check_at(a, later).is_none());
        t.record_failure_at(a, later);
        assert!(t.check_at(a, later).is_none());
    }

    #[test]
    fn success_clears_the_record() {
        let t = LoginThrottle::new();
        let a = ip("198.51.100.7");
        for _ in 0..MAX_LOGIN_FAILURES - 1 {
            t.record_failure(a);
        }
        t.record_success(a);
        t.record_failure(a);
        assert!(t.check(a).is_none());
    }

    #[test]
    fn ipv6_clients_are_grouped_by_slash_64_and_mapped_v4_by_v4() {
        let t = LoginThrottle::new();
        for i in 0..MAX_LOGIN_FAILURES {
            t.record_failure(ip(&format!("2001:db8:1:2::{:x}", i + 1)));
        }
        assert!(t.check(ip("2001:db8:1:2:ffff::1")).is_some());
        assert!(t.check(ip("2001:db8:1:3::1")).is_none());

        for _ in 0..MAX_LOGIN_FAILURES {
            t.record_failure(ip("::ffff:203.0.113.9"));
        }
        assert!(t.check(ip("203.0.113.9")).is_some());
    }
}
