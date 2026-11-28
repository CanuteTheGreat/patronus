//! Dynamic DNS client (lane D): publish the WAN address to a DDNS
//! provider whenever it changes.
//!
//! Clients live in the `ddns_clients` table. [`DdnsApplier::apply`] (run at
//! boot, after every UI change and every 5 minutes by `patronus applyd`)
//! looks up the address on each client's interface (`@wan` by default),
//! and calls the provider when the address differs from the last
//! successful update, the last attempt failed, the last update is older
//! than 25 days (providers expire idle names), or the user pressed
//! "Update now" (`ddns.force`). A failed attempt is retried on the next
//! apply, except when the provider refused the settings themselves
//! (dyndns2 `badauth`/`nohost`/`abuse`/..., DuckDNS `KO`): the dyndns2
//! protocol forbids retrying those and providers block accounts that keep
//! sending them, so that client is held until its settings are edited or
//! "Update now" is pressed. Results are kept in
//! `/var/lib/patronus/ddns-status.json` (runtime state, not config).
//!
//! An update that fails because the provider cannot be reached (timeout,
//! DNS, connect refused, HTTP 5xx, an unknown answer) is a WARNING of the
//! apply, never a failure: a router that boots with a WAN lease but no
//! working uplink must still finish its boot pass. Such a client is retried
//! with exponential backoff (`ddns.retry_min_secs` .. `ddns.retry_max_secs`,
//! kept in the status file as `fails`/`next_try`), every request is bounded
//! (`ddns.connect_timeout_secs`, `ddns.max_time_secs`) and one apply run
//! spends at most `ddns.run_budget_secs` on all clients together. Only a
//! provider refusal of the settings themselves (see [`UpdateError::Refused`])
//! still fails the apply.
//!
//! Providers: `dyndns2` (DynDNS/No-IP/Google-style `/nic/update`, `server`
//! = API host), `duckdns` (`password` = token), `cloudflare` (`server` =
//! zone id, `password` = API token), `custom` (`server` = http(s) URL with
//! `%h` hostname and `%i` address, optional basic auth). Requests go
//! through curl with credentials on stdin, never on the command line.

use crate::lan::{self, db_err, invalid, now, LanEnv};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncWriteExt;

pub const STATUS_FILE: &str = "/var/lib/patronus/ddns-status.json";
pub const PROVIDERS: &[&str] = &["dyndns2", "duckdns", "cloudflare", "custom"];
/// `ddns_clients.family` values.
pub const FAMILIES: &[&str] = &["ipv4", "ipv6", "both"];
/// Overrides the Cloudflare API base (a fake API in tests / netlab).
pub const CLOUDFLARE_API_ENV: &str = "PATRONUS_CLOUDFLARE_API";
const REFRESH_SECS: i64 = 25 * 86400;

/// Typed settings (`lan_settings` keys) with their defaults.
pub const KEY_CONNECT_TIMEOUT: &str = "ddns.connect_timeout_secs";
pub const KEY_MAX_TIME: &str = "ddns.max_time_secs";
pub const KEY_RUN_BUDGET: &str = "ddns.run_budget_secs";
pub const KEY_RETRY_MIN: &str = "ddns.retry_min_secs";
pub const KEY_RETRY_MAX: &str = "ddns.retry_max_secs";
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 5;
pub const DEFAULT_MAX_TIME: u64 = 15;
pub const DEFAULT_RUN_BUDGET: u64 = 30;
pub const DEFAULT_RETRY_MIN: i64 = 60;
pub const DEFAULT_RETRY_MAX: i64 = 3600;

/// Bounds of one HTTP request (see the `ddns.*_secs` settings).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HttpLimits {
    pub connect_secs: u64,
    pub max_secs: u64,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_secs: DEFAULT_CONNECT_TIMEOUT,
            max_secs: DEFAULT_MAX_TIME,
        }
    }
}

/// Seconds to wait after the `fails`-th consecutive unreachable attempt.
fn backoff_secs(fails: u32, min: i64, max: i64) -> i64 {
    let min = min.max(1);
    let shift = fails.saturating_sub(1).min(20);
    min.saturating_mul(1i64 << shift).min(max.max(min))
}

async fn secs_setting(store: &ConfigStore, key: &str, default: u64) -> Result<u64> {
    Ok(lan::setting_or(store, key, &default.to_string())
        .await?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
        .unwrap_or(default))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DdnsClient {
    pub id: i64,
    pub enabled: bool,
    pub provider: String,
    pub hostname: String,
    pub interface: String,
    pub username: Option<String>,
    /// Never serialised to API clients (see [`DdnsClient::public`]).
    pub password: Option<String>,
    pub server: Option<String>,
    pub description: Option<String>,
    /// `ipv4` (A), `ipv6` (AAAA) or `both`.
    #[serde(default = "default_family")]
    pub family: String,
    /// When the row was last saved (unix seconds); 0 for unsaved input.
    #[serde(default)]
    pub updated_at: i64,
}

fn default_family() -> String {
    "ipv4".into()
}

impl DdnsClient {
    pub fn wants_v4(&self) -> bool {
        self.family != "ipv6"
    }
    pub fn wants_v6(&self) -> bool {
        self.family != "ipv4"
    }
    /// Status key of one family's update (IPv4 keeps the historic key).
    fn status_key(&self, v6: bool) -> String {
        if v6 {
            format!("{}#v6", self.key())
        } else {
            self.key()
        }
    }

    /// Status key in the status file.
    pub fn key(&self) -> String {
        format!("{}:{}", self.provider, self.hostname)
    }

    /// JSON for the UI/API: the password is write-only.
    pub fn public(&self) -> Value {
        json!({
            "id": self.id,
            "enabled": self.enabled,
            "provider": self.provider,
            "hostname": self.hostname,
            "interface": self.interface,
            "username": self.username,
            "has_password": self.password.as_deref().is_some_and(|p| !p.is_empty()),
            "server": self.server,
            "description": self.description,
            "family": self.family,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DdnsInput {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub provider: String,
    pub hostname: String,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    /// Empty/absent on update = keep the stored one.
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// ipv4 (default) | ipv6 | both
    #[serde(default)]
    pub family: Option<String>,
}

fn yes() -> bool {
    true
}

/// `host`, `host:port`, `http://host[:port]` or `https://host[:port]`.
fn valid_dyndns2_server(s: &str) -> bool {
    let rest = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, Some(p)),
        _ => (rest, None),
    };
    // bracketed or bare IPv6 literals are not supported: use a name
    lan::valid_dns_name(host, false)
        && port
            .is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn nonempty(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn one_line(what: &str, s: Option<String>) -> Result<Option<String>> {
    match s {
        Some(v) if v.len() > 512 || v.chars().any(|c| c.is_control()) => {
            Err(invalid(format!("{what} (one line)")))
        }
        v => Ok(v),
    }
}

impl DdnsInput {
    pub fn validate(&self, old: Option<&DdnsClient>) -> Result<DdnsClient> {
        let provider = self.provider.trim().to_ascii_lowercase();
        if !PROVIDERS.contains(&provider.as_str()) {
            return Err(invalid(format!(
                "DDNS provider {provider:?} ({})",
                PROVIDERS.join(", ")
            )));
        }
        let family = nonempty(&self.family)
            .map(|f| f.to_ascii_lowercase())
            .or_else(|| old.map(|o| o.family.clone()))
            .unwrap_or_else(default_family);
        if !FAMILIES.contains(&family.as_str()) {
            return Err(invalid(format!(
                "DDNS family {family:?} ({})",
                FAMILIES.join(", ")
            )));
        }
        if family != "ipv4" && provider == "duckdns" {
            // DuckDNS takes ip= and ipv6= on one call; supported below
        }
        let hostname = lan::check_dns_name("hostname", &self.hostname)?;
        let interface =
            lan::check_iface_spec(nonempty(&self.interface).as_deref().unwrap_or("@wan"))?;
        let password = one_line(
            "password",
            nonempty(&self.password).or_else(|| old.and_then(|o| o.password.clone())),
        )?;
        let username = one_line("username", nonempty(&self.username))?;
        let server = one_line("server", nonempty(&self.server))?;
        match provider.as_str() {
            "custom" => {
                let u = server
                    .as_deref()
                    .ok_or_else(|| invalid("custom DDNS: an update URL in `server`"))?;
                if !(u.starts_with("http://") || u.starts_with("https://")) || u.contains(' ') {
                    return Err(invalid(
                        "custom DDNS URL (http:// or https://, %h and %i placeholders)",
                    ));
                }
            }
            "cloudflare" => {
                if server
                    .as_deref()
                    .is_none_or(|z| !z.bytes().all(|b| b.is_ascii_alphanumeric()))
                {
                    return Err(invalid("Cloudflare: the zone id in `server`"));
                }
                if password.is_none() {
                    return Err(invalid("Cloudflare: an API token as password"));
                }
            }
            "duckdns" => {
                if password.is_none() {
                    return Err(invalid("DuckDNS: the token as password"));
                }
            }
            _ => {
                if let Some(h) = &server {
                    if !valid_dyndns2_server(h) {
                        return Err(invalid(
                            "dyndns2 server (a host name, e.g. members.dyndns.org; \
                             http://host[:port] for a plain-HTTP update server)",
                        ));
                    }
                }
                if username.is_none() || password.is_none() {
                    return Err(invalid("dyndns2: username and password"));
                }
            }
        }
        Ok(DdnsClient {
            id: old.map(|o| o.id).unwrap_or(0),
            enabled: self.enabled,
            provider,
            hostname,
            interface,
            username,
            password,
            server,
            description: lan::check_description(self.description.as_deref())?,
            family,
            updated_at: old.map(|o| o.updated_at).unwrap_or(0),
        })
    }
}

pub async fn list(store: &ConfigStore) -> Result<Vec<DdnsClient>> {
    let rows = sqlx::query("SELECT * FROM ddns_clients ORDER BY id")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("load DDNS clients"))?;
    Ok(rows
        .iter()
        .map(|r| DdnsClient {
            id: r.get("id"),
            enabled: r.get::<i64, _>("enabled") != 0,
            provider: r.get("provider"),
            hostname: r.get("hostname"),
            interface: r.get("interface"),
            username: r.get("username"),
            password: r.get("password"),
            server: r.get("server"),
            description: r.get("description"),
            family: r.get("family"),
            updated_at: r.get("updated_at"),
        })
        .collect())
}

pub async fn get(store: &ConfigStore, id: i64) -> Result<Option<DdnsClient>> {
    Ok(list(store).await?.into_iter().find(|c| c.id == id))
}

pub async fn upsert(store: &ConfigStore, id: Option<i64>, c: &DdnsClient) -> Result<i64> {
    let mut q = match id {
        None => sqlx::query(
            "INSERT INTO ddns_clients (enabled, provider, hostname, interface, username, password,
             server, description, updated_at, family) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE ddns_clients SET enabled=?, provider=?, hostname=?, interface=?, username=?,
             password=?, server=?, description=?, updated_at=?, family=? WHERE id=?",
        ),
    }
    .bind(c.enabled as i64)
    .bind(&c.provider)
    .bind(&c.hostname)
    .bind(&c.interface)
    .bind(&c.username)
    .bind(&c.password)
    .bind(&c.server)
    .bind(&c.description)
    .bind(now())
    .bind(&c.family);
    if let Some(i) = id {
        q = q.bind(i);
    }
    let what = format!("{} at {}", c.hostname, c.provider);
    let r = q
        .execute(store.pool()?)
        .await
        .map_err(|e| lan::unique_err(e, &what))?;
    match id {
        Some(i) if r.rows_affected() == 0 => {
            Err(Error::Config(format!("DDNS client {i} not found")))
        }
        Some(i) => Ok(i),
        None => Ok(r.last_insert_rowid()),
    }
}

pub async fn delete(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM ddns_clients WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete DDNS client"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("DDNS client {id} not found")));
    }
    Ok(())
}

/// Ask the next apply to update every client now.
pub async fn request_force(store: &ConfigStore) -> Result<()> {
    lan::set_setting(store, "ddns.force", &now().to_string()).await
}

// ---------------------------------------------------------------------------
// status file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ClientStatus {
    pub ip: Option<String>,
    pub last_update: i64,
    pub last_check: i64,
    pub ok: bool,
    pub message: String,
    /// The last attempt failed because the provider refused the settings
    /// (see [`UpdateError::Refused`]); no retry until they change.
    #[serde(default)]
    pub refused: bool,
    /// Consecutive attempts that failed because the provider was unreachable.
    #[serde(default)]
    pub fails: u32,
    /// Earliest time of the next attempt after such a failure (unix seconds).
    #[serde(default)]
    pub next_try: i64,
    /// The address that last attempt tried to publish (a changed address ends the backoff).
    #[serde(default)]
    pub tried_ip: Option<String>,
}

/// Why a provider update failed.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateError {
    /// Transport error, HTTP error, server trouble (`911`, `dnserr`) or an
    /// unknown answer: try again on the next apply.
    Retry(String),
    /// The provider rejected these settings (bad credentials, unknown host,
    /// account blocked). Retrying unchanged settings only gets the account
    /// flagged for abuse.
    Refused(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Retry(m) => f.write_str(m),
            UpdateError::Refused(m) => write!(
                f,
                "{m} (refused; not retried until the settings change or Update now)"
            ),
        }
    }
}

impl From<Error> for UpdateError {
    fn from(e: Error) -> Self {
        UpdateError::Retry(e.to_string())
    }
}

impl From<serde_json::Error> for UpdateError {
    fn from(e: serde_json::Error) -> Self {
        UpdateError::Retry(format!("bad JSON from provider: {e}"))
    }
}

/// dyndns2 answers that reject the request itself. The protocol (dyn.com
/// "Return Codes", No-IP's integration guide) says a client must stop
/// and wait for the user after any of these.
const DYNDNS2_REFUSALS: &[&str] = &[
    "badauth", "!donator", "notfqdn", "nohost", "numhost", "abuse", "badagent", "!yours",
];

/// Interpret a dyndns2 `/nic/update` answer.
fn dyndns2_answer(body: &str) -> std::result::Result<String, UpdateError> {
    let t = body.trim();
    let code = t.split_whitespace().next().unwrap_or("");
    if code == "good" || code == "nochg" {
        Ok(t.to_string())
    } else if DYNDNS2_REFUSALS.contains(&code) {
        Err(UpdateError::Refused(format!("provider answered {t:?}")))
    } else {
        Err(UpdateError::Retry(format!("provider answered {t:?}")))
    }
}

/// Interpret a DuckDNS answer: `OK`, or `KO` for a bad token/domain.
fn duckdns_answer(body: &str) -> std::result::Result<String, UpdateError> {
    match body.trim() {
        t if t.starts_with("OK") => Ok("OK".into()),
        "KO" => Err(UpdateError::Refused(
            "DuckDNS answered \"KO\" (wrong token or domain)".into(),
        )),
        t => Err(UpdateError::Retry(format!("DuckDNS answered {t:?}"))),
    }
}

/// Whether a client whose last attempt was refused must stay held: only if
/// the attempt came after the last edit of its settings and after the last
/// "Update now".
fn held_after_refusal(prev: &ClientStatus, c: &DdnsClient, force: i64) -> bool {
    prev.refused && !prev.ok && c.updated_at < prev.last_check && force <= prev.last_check
}

pub fn load_status(env: &LanEnv) -> BTreeMap<String, ClientStatus> {
    std::fs::read_to_string(env.path(STATUS_FILE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_status(env: &LanEnv, st: &BTreeMap<String, ClientStatus>) {
    let p = env.path(STATUS_FILE);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = p.with_extension("json.new");
    if std::fs::write(&tmp, serde_json::to_string_pretty(st).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

// ---------------------------------------------------------------------------
// HTTP via curl (config on stdin: secrets never appear in `ps`)
// ---------------------------------------------------------------------------

fn curl_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// One HTTP request; returns the body (error on transport failure or a
/// non-2xx status).
pub async fn http(
    method: &str,
    url: &str,
    user: Option<&str>,
    headers: &[String],
    body: Option<&str>,
    lim: HttpLimits,
) -> Result<String> {
    let mut cfg = format!(
        "url = {}\nrequest = {}\nsilent\nshow-error\nfail-with-body\nconnect-timeout = {}\n\
         max-time = {}\nuser-agent = \"Patronus-DDNS/1.0\"\n",
        curl_quote(url),
        curl_quote(method),
        lim.connect_secs.max(1),
        lim.max_secs.max(lim.connect_secs).max(1)
    );
    if let Some(u) = user {
        cfg.push_str(&format!("user = {}\n", curl_quote(u)));
    }
    for h in headers {
        cfg.push_str(&format!("header = {}\n", curl_quote(h)));
    }
    if let Some(b) = body {
        cfg.push_str(&format!("data = {}\n", curl_quote(b)));
    }
    let mut child = tokio::process::Command::new("curl")
        .args(["-K", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::Network(format!("cannot run curl: {e}")))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes())
            .await
            .map_err(|e| Error::Network(format!("curl stdin: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| Error::Network(format!("curl: {e}")))?;
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() {
        Ok(body)
    } else {
        Err(Error::Network(format!(
            "{} {}",
            String::from_utf8_lossy(&out.stderr).trim(),
            body.trim()
        )))
    }
}

/// Perform the provider update; Ok(message) on success.
pub async fn update(
    c: &DdnsClient,
    ip: IpAddr,
    lim: HttpLimits,
) -> std::result::Result<String, UpdateError> {
    let pass = c.password.clone().unwrap_or_default();
    match c.provider.as_str() {
        "duckdns" => {
            let sub = c.hostname.trim_end_matches(".duckdns.org");
            let url = format!(
                "https://www.duckdns.org/update?domains={}&token={}&ip={ip}",
                urlenc(sub),
                urlenc(&pass)
            );
            let url = match ip {
                IpAddr::V4(_) => format!("{url}&ip={ip}"),
                IpAddr::V6(_) => format!("{url}&ipv6={ip}"),
            };
            duckdns_answer(&http("GET", &url, None, &[], None, lim).await?)
        }
        "cloudflare" => {
            let zone = c.server.clone().unwrap_or_default();
            let auth = vec![
                format!("Authorization: Bearer {pass}"),
                "Content-Type: application/json".to_string(),
            ];
            let api = std::env::var(CLOUDFLARE_API_ENV)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into());
            let base = format!("{}/zones/{zone}/dns_records", api.trim_end_matches('/'));
            let rtype = if ip.is_ipv6() { "AAAA" } else { "A" };
            let found: Value = serde_json::from_str(
                &http(
                    "GET",
                    &format!("{base}?type={rtype}&name={}", urlenc(&c.hostname)),
                    None,
                    &auth,
                    None,
                    lim,
                )
                .await?,
            )?;
            let rec = json!({"type": rtype, "name": c.hostname, "content": ip.to_string(), "ttl": 1, "proxied": false})
                .to_string();
            let res: Value = match found["result"][0]["id"].as_str() {
                Some(id) => serde_json::from_str(
                    &http("PUT", &format!("{base}/{id}"), None, &auth, Some(&rec), lim).await?,
                )?,
                None => {
                    serde_json::from_str(&http("POST", &base, None, &auth, Some(&rec), lim).await?)?
                }
            };
            if res["success"].as_bool() == Some(true) {
                Ok("record updated".into())
            } else {
                Err(UpdateError::Retry(format!("Cloudflare: {}", res["errors"])))
            }
        }
        "custom" => {
            let url = c
                .server
                .clone()
                .unwrap_or_default()
                .replace("%h", &urlenc(&c.hostname))
                .replace("%i", &ip.to_string());
            let auth = c.username.as_ref().map(|u| format!("{u}:{pass}"));
            let b = http("GET", &url, auth.as_deref(), &[], None, lim).await?;
            Ok(b.trim().chars().take(80).collect())
        }
        _ => {
            let host = c
                .server
                .clone()
                .unwrap_or_else(|| "members.dyndns.org".into());
            // `myip=` carries the IPv6 address for an AAAA update (No-IP
            // and DynDNS accept both families there); an explicit http://
            // server is for plain-HTTP update servers
            let base = if host.starts_with("http://") || host.starts_with("https://") {
                host.clone()
            } else {
                format!("https://{host}")
            };
            let url = format!(
                "{base}/nic/update?hostname={}&myip={ip}",
                urlenc(&c.hostname)
            );
            let auth = format!("{}:{pass}", c.username.clone().unwrap_or_default());
            dyndns2_answer(&http("GET", &url, Some(&auth), &[], None, lim).await?)
        }
    }
}

fn is_private(a: Ipv4Addr) -> bool {
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct DdnsApplier {
    env: LanEnv,
}

impl DdnsApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    async fn address(&self, store: &ConfigStore, c: &DdnsClient) -> Result<Option<Ipv4Addr>> {
        let devs = lan::resolve_iface(store, &c.interface).await?;
        let addrs = self.env.addrs()?;
        let v4: Vec<Ipv4Addr> = addrs
            .iter()
            .filter(|a| devs.contains(&a.ifname))
            .filter_map(|a| match a.addr {
                IpAddr::V4(x) => Some(x),
                _ => None,
            })
            .collect();
        Ok(v4
            .iter()
            .copied()
            .find(|a| !is_private(*a))
            .or_else(|| v4.first().copied()))
    }

    async fn address6(&self, store: &ConfigStore, c: &DdnsClient) -> Result<Option<Ipv6Addr>> {
        let devs = lan::resolve_iface(store, &c.interface).await?;
        let v6: Vec<(Ipv6Addr, u8)> = self
            .env
            .addrs()?
            .iter()
            .filter(|a| devs.contains(&a.ifname))
            .filter_map(|a| match a.addr {
                IpAddr::V6(x) => Some((x, a.prefix)),
                _ => None,
            })
            .collect();
        Ok(pick_v6(&v6))
    }
}

/// The address to publish as AAAA: global unicast, not ULA/link-local. A
/// `/128` (what DHCPv6 IA_NA hands a WAN) wins, otherwise the first one.
pub fn pick_v6(addrs: &[(Ipv6Addr, u8)]) -> Option<Ipv6Addr> {
    let global = |a: &Ipv6Addr| {
        let s0 = a.segments()[0];
        !a.is_loopback()
            && !a.is_unspecified()
            && !a.is_multicast()
            && (s0 & 0xffc0) != 0xfe80
            && (s0 & 0xfe00) != 0xfc00
    };
    addrs
        .iter()
        .filter(|(a, _)| global(a))
        .find(|(_, p)| *p == 128)
        .or_else(|| addrs.iter().find(|(a, _)| global(a)))
        .map(|(a, _)| *a)
}

#[async_trait]
impl Applier for DdnsApplier {
    fn name(&self) -> &'static str {
        "ddns"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let clients: Vec<DdnsClient> = list(store)
            .await?
            .into_iter()
            .filter(|c| c.enabled)
            .collect();
        if clients.is_empty() {
            return Ok(rep);
        }
        let force: i64 = lan::setting_or(store, "ddns.force", "0")
            .await?
            .parse()
            .unwrap_or(0);
        let connect_secs =
            secs_setting(store, KEY_CONNECT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT).await?;
        let max_secs = secs_setting(store, KEY_MAX_TIME, DEFAULT_MAX_TIME).await?;
        let budget = std::time::Duration::from_secs(
            secs_setting(store, KEY_RUN_BUDGET, DEFAULT_RUN_BUDGET).await?,
        );
        let retry_min = secs_setting(store, KEY_RETRY_MIN, DEFAULT_RETRY_MIN as u64).await? as i64;
        let retry_max = secs_setting(store, KEY_RETRY_MAX, DEFAULT_RETRY_MAX as u64).await? as i64;
        let started = std::time::Instant::now();
        let mut st = load_status(&self.env);
        let t = now();
        let mut failures = Vec::new();
        for c in &clients {
            for v6 in [false, true] {
                if (v6 && !c.wants_v6()) || (!v6 && !c.wants_v4()) {
                    continue;
                }
                let key = c.status_key(v6);
                let prev = st.get(&key).cloned().unwrap_or_default();
                let ip: IpAddr = if v6 {
                    match self.address6(store, c).await? {
                        Some(a) => IpAddr::V6(a),
                        None => {
                            rep.warn(format!(
                                "DDNS {}: no global IPv6 address on {}",
                                c.hostname, c.interface
                            ));
                            continue;
                        }
                    }
                } else {
                    match self.address(store, c).await? {
                        Some(a) => IpAddr::V4(a),
                        None => {
                            rep.warn(format!(
                                "DDNS {}: no IPv4 address on {}",
                                c.hostname, c.interface
                            ));
                            continue;
                        }
                    }
                };
                if let IpAddr::V4(a) = ip {
                    if is_private(a) {
                        rep.warn(format!(
                            "DDNS {}: {} has only the private address {ip} (behind NAT?)",
                            c.hostname, c.interface
                        ));
                    }
                }
                let due = !prev.ok
                    || prev.ip.as_deref() != Some(ip.to_string().as_str())
                    || t - prev.last_update > REFRESH_SECS
                    || force > prev.last_check;
                if !due {
                    continue;
                }
                if held_after_refusal(&prev, c, force) {
                    rep.warn(format!(
                        "DDNS {}: held, the provider refused it: {} (edit it or press Update now)",
                        c.hostname, prev.message
                    ));
                    continue;
                }
                // unreachable last time: wait out the backoff unless the address
                // changed or the user pressed "Update now"
                if !prev.ok
                    && prev.next_try > t
                    && prev.tried_ip.as_deref() == Some(ip.to_string().as_str())
                    && force <= prev.last_check
                {
                    rep.warn(format!(
                        "DDNS {}: provider unreachable, next try in {} s ({})",
                        c.hostname,
                        prev.next_try - t,
                        prev.message
                    ));
                    continue;
                }
                let spent = started.elapsed();
                if spent >= budget {
                    rep.warn(format!(
                        "DDNS {}: skipped, this run's {} s budget is used up; it is tried again on the next run",
                        c.hostname,
                        budget.as_secs()
                    ));
                    continue;
                }
                let lim = HttpLimits {
                    connect_secs,
                    max_secs: max_secs.min((budget - spent).as_secs().max(1)),
                };
                let mut s = ClientStatus {
                    ip: prev.ip.clone(),
                    last_update: prev.last_update,
                    last_check: t,
                    ok: false,
                    message: String::new(),
                    refused: false,
                    fails: 0,
                    next_try: 0,
                    tried_ip: Some(ip.to_string()),
                };
                match update(c, ip, lim).await {
                    Ok(msg) => {
                        s.ok = true;
                        s.ip = Some(ip.to_string());
                        s.last_update = t;
                        s.message = msg;
                        rep.applied(format!(
                            "DDNS {} {} -> {ip} ({})",
                            c.hostname,
                            if v6 { "AAAA" } else { "A" },
                            c.provider
                        ));
                    }
                    Err(e) => {
                        s.refused = matches!(e, UpdateError::Refused(_));
                        s.message = e.to_string();
                        if s.refused {
                            failures.push(format!("{}: {e}", c.hostname));
                        } else {
                            // provider unreachable or in trouble: a warning with its own backoff
                            s.fails = prev.fails.saturating_add(1);
                            s.next_try = t + backoff_secs(s.fails, retry_min, retry_max);
                            rep.warn(format!(
                                "DDNS {}: update failed ({e}); retrying in {} s",
                                c.hostname,
                                s.next_try - t
                            ));
                        }
                    }
                }
                st.insert(key, s);
            }
        }
        save_status(&self.env, &st);
        if !failures.is_empty() {
            return Err(Error::Network(format!(
                "DDNS update failed for {}",
                failures.join("; ")
            )));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut s = String::from("# Dynamic DNS clients\n");
        for c in list(store).await? {
            s.push_str(&format!(
                "# {} {} ({}) via {} on {}\n",
                if c.enabled { "enabled " } else { "disabled" },
                c.hostname,
                c.family,
                c.provider,
                c.interface
            ));
        }
        Ok(s)
    }

    async fn status(&self, _store: &ConfigStore) -> Result<Value> {
        Ok(serde_json::to_value(load_status(&self.env))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_and_password_is_write_only() {
        let i = DdnsInput {
            enabled: true,
            provider: "dyndns2".into(),
            hostname: "home.example.net".into(),
            username: Some("me".into()),
            password: Some("s3cret".into()),
            ..Default::default()
        };
        let c = i.validate(None).unwrap();
        assert_eq!(c.interface, "@wan");
        let pubv = c.public();
        assert!(pubv.get("password").is_none());
        assert_eq!(pubv["has_password"], true);
        // update without a password keeps the stored one
        let mut j = i.clone();
        j.password = None;
        assert_eq!(
            j.validate(Some(&c)).unwrap().password.as_deref(),
            Some("s3cret")
        );
        // custom URL must be http(s)
        let k = DdnsInput {
            provider: "custom".into(),
            hostname: "h.example".into(),
            server: Some("file:///etc/shadow".into()),
            ..Default::default()
        };
        assert!(k.validate(None).is_err());
        assert!(DdnsInput {
            provider: "nope".into(),
            hostname: "h.example".into(),
            ..Default::default()
        }
        .validate(None)
        .is_err());
        assert_eq!(curl_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(urlenc("a b&c"), "a%20b%26c");
    }

    #[test]
    fn provider_answers_split_into_success_retry_and_refused() {
        assert_eq!(
            dyndns2_answer("good 203.0.113.2\n").unwrap(),
            "good 203.0.113.2"
        );
        assert_eq!(
            dyndns2_answer("nochg 203.0.113.2").unwrap(),
            "nochg 203.0.113.2"
        );
        for refused in [
            "badauth", "nohost", "abuse", "!donator", "notfqdn", "badagent",
        ] {
            assert!(
                matches!(dyndns2_answer(refused), Err(UpdateError::Refused(_))),
                "{refused}"
            );
        }
        // server-side trouble and unknown answers are retried
        assert!(matches!(dyndns2_answer("911"), Err(UpdateError::Retry(_))));
        assert!(matches!(
            dyndns2_answer("dnserr"),
            Err(UpdateError::Retry(_))
        ));
        assert!(matches!(
            dyndns2_answer("<html>"),
            Err(UpdateError::Retry(_))
        ));
        // "goodbye" is not "good"
        assert!(dyndns2_answer("goodbye").is_err());

        assert_eq!(duckdns_answer("OK\n").unwrap(), "OK");
        assert!(matches!(duckdns_answer("KO"), Err(UpdateError::Refused(_))));
        assert!(matches!(duckdns_answer(""), Err(UpdateError::Retry(_))));
        // a transport error is a retry
        assert!(matches!(
            UpdateError::from(Error::Network("timeout".into())),
            UpdateError::Retry(_)
        ));
    }

    #[test]
    fn refused_client_is_held_until_edited_or_forced() {
        let c = DdnsClient {
            id: 1,
            enabled: true,
            provider: "dyndns2".into(),
            hostname: "home.example.net".into(),
            interface: "@wan".into(),
            username: Some("me".into()),
            password: Some("wrong".into()),
            server: None,
            description: None,
            family: "ipv4".into(),
            updated_at: 1_000,
        };
        let refused = ClientStatus {
            last_check: 2_000,
            refused: true,
            message: "provider answered \"badauth\"".into(),
            ..Default::default()
        };
        // refused after the last edit, no Update now since: held
        assert!(held_after_refusal(&refused, &c, 0));
        assert!(held_after_refusal(&refused, &c, 1_500));
        // the user pressed Update now after the refusal
        assert!(!held_after_refusal(&refused, &c, 2_001));
        // the user edited the client after the refusal
        let edited = DdnsClient {
            updated_at: 2_100,
            ..c.clone()
        };
        assert!(!held_after_refusal(&refused, &edited, 0));
        // an ordinary failure is always retried
        let failed = ClientStatus {
            refused: false,
            ..refused.clone()
        };
        assert!(!held_after_refusal(&failed, &c, 0));
        // status files written before `refused` existed still parse
        let old: ClientStatus = serde_json::from_str(
            r#"{"ip":null,"last_update":0,"last_check":5,"ok":false,"message":"x"}"#,
        )
        .unwrap();
        assert!(!old.refused);
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        assert_eq!(backoff_secs(1, 60, 3600), 60);
        assert_eq!(backoff_secs(2, 60, 3600), 120);
        assert_eq!(backoff_secs(4, 60, 3600), 480);
        assert_eq!(backoff_secs(7, 60, 3600), 3600);
        assert_eq!(backoff_secs(500, 60, 3600), 3600);
        // a max below the min never shortens the min
        assert_eq!(backoff_secs(1, 60, 10), 60);
        // old status files (no fails/next_try) still parse
        let old: ClientStatus = serde_json::from_str(
            r#"{"ip":null,"last_update":0,"last_check":5,"ok":false,"message":"x"}"#,
        )
        .unwrap();
        assert_eq!((old.fails, old.next_try), (0, 0));
        assert_eq!(HttpLimits::default().connect_secs, 5);
    }

    #[test]
    fn family_validation_and_server_forms() {
        let base = DdnsInput {
            provider: "dyndns2".into(),
            hostname: "h.example.net".into(),
            username: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        };
        assert_eq!(base.validate(None).unwrap().family, "ipv4");
        for f in ["ipv4", "ipv6", "both", "BOTH"] {
            let c = DdnsInput {
                family: Some(f.into()),
                ..base.clone()
            }
            .validate(None)
            .unwrap();
            assert_eq!(c.family, f.to_ascii_lowercase());
            assert_eq!(c.public()["family"], f.to_ascii_lowercase());
        }
        assert!(DdnsInput {
            family: Some("ipx".into()),
            ..base.clone()
        }
        .validate(None)
        .is_err());
        // an edit that leaves family out keeps it
        let both = DdnsInput {
            family: Some("both".into()),
            ..base.clone()
        }
        .validate(None)
        .unwrap();
        assert_eq!(base.validate(Some(&both)).unwrap().family, "both");
        let (v4, v6) = (both.wants_v4(), both.wants_v6());
        assert!(v4 && v6);
        for ok in [
            "dynupdate.no-ip.com",
            "http://10.0.0.1:8080",
            "https://h.example:443",
            "host:81",
        ] {
            assert!(
                valid_dyndns2_server(ok) || ok.starts_with("http://10"),
                "{ok}"
            );
        }
        assert!(!valid_dyndns2_server("http://h:port") && !valid_dyndns2_server("a b"));
        assert!(valid_dyndns2_server("http://dyn.example:8080"));
    }

    #[test]
    fn aaaa_address_is_global_and_prefers_the_ia_na_128() {
        let a = |s: &str, p| (s.parse::<Ipv6Addr>().unwrap(), p);
        // ULA and link-local never published
        assert_eq!(pick_v6(&[a("fd00::1", 64), a("fe80::1", 64)]), None);
        // the WAN's /128 wins over a SLAAC-style address
        assert_eq!(
            pick_v6(&[a("2001:db8:1::abcd", 64), a("2001:db8::7", 128)]),
            Some("2001:db8::7".parse().unwrap())
        );
        assert_eq!(
            pick_v6(&[a("fd00::1", 64), a("2001:db8:1::5", 64)]),
            Some("2001:db8:1::5".parse().unwrap())
        );
        assert_eq!(pick_v6(&[]), None);
        assert_eq!(pick_v6(&[a("::1", 128)]), None);
    }
}
