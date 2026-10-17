//! Dynamic DNS client (lane D): publish the WAN address to a DDNS
//! provider whenever it changes.
//!
//! Clients live in the `ddns_clients` table. [`DdnsApplier::apply`] (run at
//! boot, after every UI change and every 5 minutes by `patronus applyd`)
//! looks up the address on each client's interface (`@wan` by default),
//! and calls the provider when the address differs from the last
//! successful update, the last attempt failed, the last update is older
//! than 25 days (providers expire idle names), or the user pressed
//! "Update now" (`ddns.force`). Results are kept in
//! `/var/lib/patronus/ddns-status.json` (runtime state, not config).
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
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::AsyncWriteExt;

pub const STATUS_FILE: &str = "/var/lib/patronus/ddns-status.json";
pub const PROVIDERS: &[&str] = &["dyndns2", "duckdns", "cloudflare", "custom"];
const REFRESH_SECS: i64 = 25 * 86400;

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
}

impl DdnsClient {
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
}

fn yes() -> bool {
    true
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
                    if !lan::valid_dns_name(h, false) {
                        return Err(invalid(
                            "dyndns2 server (a host name, e.g. members.dyndns.org)",
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
             server, description, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ),
        Some(_) => sqlx::query(
            "UPDATE ddns_clients SET enabled=?, provider=?, hostname=?, interface=?, username=?,
             password=?, server=?, description=?, updated_at=? WHERE id=?",
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
    .bind(now());
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
) -> Result<String> {
    let mut cfg = format!(
        "url = {}\nrequest = {}\nsilent\nshow-error\nfail-with-body\nmax-time = 30\n\
         user-agent = \"Patronus-DDNS/1.0\"\n",
        curl_quote(url),
        curl_quote(method)
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
pub async fn update(c: &DdnsClient, ip: Ipv4Addr) -> Result<String> {
    let pass = c.password.clone().unwrap_or_default();
    match c.provider.as_str() {
        "duckdns" => {
            let sub = c.hostname.trim_end_matches(".duckdns.org");
            let url = format!(
                "https://www.duckdns.org/update?domains={}&token={}&ip={ip}",
                urlenc(sub),
                urlenc(&pass)
            );
            let b = http("GET", &url, None, &[], None).await?;
            if b.trim().starts_with("OK") {
                Ok("OK".into())
            } else {
                Err(Error::Network(format!("DuckDNS answered {:?}", b.trim())))
            }
        }
        "cloudflare" => {
            let zone = c.server.clone().unwrap_or_default();
            let auth = vec![
                format!("Authorization: Bearer {pass}"),
                "Content-Type: application/json".to_string(),
            ];
            let base = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records");
            let found: Value = serde_json::from_str(
                &http(
                    "GET",
                    &format!("{base}?type=A&name={}", urlenc(&c.hostname)),
                    None,
                    &auth,
                    None,
                )
                .await?,
            )?;
            let rec = json!({"type": "A", "name": c.hostname, "content": ip.to_string(), "ttl": 1, "proxied": false})
                .to_string();
            let res: Value = match found["result"][0]["id"].as_str() {
                Some(id) => serde_json::from_str(
                    &http("PUT", &format!("{base}/{id}"), None, &auth, Some(&rec)).await?,
                )?,
                None => serde_json::from_str(&http("POST", &base, None, &auth, Some(&rec)).await?)?,
            };
            if res["success"].as_bool() == Some(true) {
                Ok("record updated".into())
            } else {
                Err(Error::Network(format!("Cloudflare: {}", res["errors"])))
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
            let b = http("GET", &url, auth.as_deref(), &[], None).await?;
            Ok(b.trim().chars().take(80).collect())
        }
        _ => {
            let host = c
                .server
                .clone()
                .unwrap_or_else(|| "members.dyndns.org".into());
            let url = format!(
                "https://{host}/nic/update?hostname={}&myip={ip}",
                urlenc(&c.hostname)
            );
            let auth = format!("{}:{pass}", c.username.clone().unwrap_or_default());
            let b = http("GET", &url, Some(&auth), &[], None).await?;
            let t = b.trim();
            if t.starts_with("good") || t.starts_with("nochg") {
                Ok(t.to_string())
            } else {
                Err(Error::Network(format!("provider answered {t:?}")))
            }
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
        let mut st = load_status(&self.env);
        let t = now();
        let mut failures = Vec::new();
        for c in &clients {
            let key = c.key();
            let prev = st.get(&key).cloned().unwrap_or_default();
            let Some(ip) = self.address(store, c).await? else {
                rep.warn(format!(
                    "DDNS {}: no IPv4 address on {}",
                    c.hostname, c.interface
                ));
                continue;
            };
            if is_private(ip) {
                rep.warn(format!(
                    "DDNS {}: {} has only the private address {ip} (behind NAT?)",
                    c.hostname, c.interface
                ));
            }
            let due = !prev.ok
                || prev.ip.as_deref() != Some(ip.to_string().as_str())
                || t - prev.last_update > REFRESH_SECS
                || force > prev.last_check;
            if !due {
                continue;
            }
            let mut s = ClientStatus {
                ip: prev.ip.clone(),
                last_update: prev.last_update,
                last_check: t,
                ok: false,
                message: String::new(),
            };
            match update(c, ip).await {
                Ok(msg) => {
                    s.ok = true;
                    s.ip = Some(ip.to_string());
                    s.last_update = t;
                    s.message = msg;
                    rep.applied(format!("DDNS {} -> {ip} ({})", c.hostname, c.provider));
                }
                Err(e) => {
                    s.message = e.to_string();
                    failures.push(format!("{}: {e}", c.hostname));
                }
            }
            st.insert(key, s);
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
                "# {} {} via {} on {}\n",
                if c.enabled { "enabled " } else { "disabled" },
                c.hostname,
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
}
