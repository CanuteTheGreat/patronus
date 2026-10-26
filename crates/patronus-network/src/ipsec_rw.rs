//! IPsec road warriors (lane F): IKEv2 remote-access VPN for phones and
//! laptops, next to the site-to-site tunnels of [`crate::ipsec`].
//!
//! A **profile** is one strongSwan connection that hands out virtual IPs from
//! a pool and authenticates clients either with
//!
//! * `eap`: EAP-MSCHAPv2 (a username and password per user; every phone and
//!   Windows has a built-in client), or
//! * `cert`: a client certificate Patronus issues per user and pins (deleting
//!   or disabling the user removes the pinned certificate, which revokes
//!   access without a CRL).
//!
//! The server presents a certificate from Patronus' own IPsec CA (EC P-256,
//! made with the `openssl` binary like the OpenVPN PKI) whose subject
//! alternative name is the profile's `server_id` (the name or address clients
//! connect to). Everything is stored in `ipsec_rw_profiles`, `ipsec_rw_users`
//! and `ipsec_pki`; [`crate::ipsec::IpsecApplier`] writes the pieces into
//! `/etc/swanctl` and loads them.
//!
//! Client setup files ([`mobileconfig`], [`sswan`], [`powershell`]) are
//! generated from the same rows: an iOS/macOS configuration profile, an
//! Android strongSwan app profile and a Windows PowerShell script.

use crate::lan::{check_description, db_err, invalid, now};
use crate::vpn::{check_host, check_networks, split_list};
use base64::Engine;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::path::Path;
use std::process::Command;

/// Prefix of every connection / pool / credential file Patronus loads for a
/// road-warrior profile (`patronus-rw-<profile>`).
pub const RW_PREFIX: &str = "patronus-rw-";
pub const CA_FILE: &str = "patronus-rw-ca.pem";
pub const X509_DIR: &str = "/etc/swanctl/x509";
pub const X509CA_DIR: &str = "/etc/swanctl/x509ca";
pub const PRIVATE_DIR: &str = "/etc/swanctl/private";

/// IKE/ESP proposals offered to phones and Windows (what iOS, Android's
/// strongSwan app and Windows' built-in client all support).
pub const RW_IKE: &str = "aes256gcm16-prfsha256-ecp256,aes256-sha256-ecp256,aes256-sha256-modp2048";
pub const RW_ESP: &str = "aes256gcm16-ecp256,aes256-sha256-ecp256,aes256-sha256-modp2048";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RwProfile {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    /// `eap` or `cert`.
    pub auth: String,
    pub local_address: Option<String>,
    pub server_id: String,
    pub pool: String,
    pub dns: String,
    pub local_ts: String,
    pub ike_proposals: String,
    pub esp_proposals: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RwUser {
    pub id: i64,
    pub profile: String,
    pub username: String,
    pub enabled: bool,
    #[serde(skip_serializing, default)]
    pub password: Option<String>,
    pub has_password: bool,
    pub has_cert: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default)]
    pub server_id: Option<String>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub local_ts: Option<String>,
    #[serde(default)]
    pub ike_proposals: Option<String>,
    #[serde(default)]
    pub esp_proposals: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserInput {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// EAP profiles: empty on create = generate one (shown once).
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn opt(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

pub fn check_profile_name(s: &str) -> Result<String> {
    crate::ipsec::check_tunnel_name(s)
}

pub fn check_username(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 64
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err(invalid(format!(
            "user name {s:?}: 1-64 letters, digits, '.', '_', '-' or '@'"
        )));
    }
    Ok(s.to_string())
}

/// EAP passwords end up in a quoted swanctl string.
pub fn check_user_password(s: &str) -> Result<String> {
    if !(8..=128).contains(&s.len())
        || !s
            .chars()
            .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
    {
        return Err(invalid(
            "password: 8-128 printable characters without quotes or backslashes",
        ));
    }
    Ok(s.to_string())
}

fn generate_password() -> String {
    use rand::Rng;
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    (0..20)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
}

/// DNS servers pushed to clients: addresses only.
fn check_dns(s: &str) -> Result<String> {
    let v = split_list(s);
    for a in &v {
        if a.parse::<std::net::IpAddr>().is_err() {
            return Err(invalid(format!("DNS server {a:?} is not an address")));
        }
    }
    Ok(v.join(","))
}

fn check_proposals(what: &str, s: &str) -> Result<String> {
    let v = split_list(s);
    if v.is_empty()
        || !v.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    {
        return Err(invalid(format!("{what}: e.g. {RW_IKE}")));
    }
    Ok(v.join(","))
}

/// A server identity goes into a certificate's subject alternative name.
fn check_server_id(s: &str) -> Result<String> {
    check_host("server name or address", s)
}

pub async fn list_profiles(store: &ConfigStore) -> Result<Vec<RwProfile>> {
    let rows = sqlx::query(
        "SELECT id, name, enabled, auth, local_address, server_id, pool, dns, local_ts,
                ike_proposals, esp_proposals, description FROM ipsec_rw_profiles ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ipsec_rw_profiles"))?;
    Ok(rows
        .iter()
        .map(|r| RwProfile {
            id: r.get(0),
            name: r.get(1),
            enabled: r.get::<i64, _>(2) != 0,
            auth: r.get(3),
            local_address: r.get(4),
            server_id: r.get(5),
            pool: r.get(6),
            dns: r.get(7),
            local_ts: r.get(8),
            ike_proposals: r.get(9),
            esp_proposals: r.get(10),
            description: r.get(11),
        })
        .collect())
}

pub async fn list_users(store: &ConfigStore) -> Result<Vec<RwUser>> {
    let rows = sqlx::query(
        "SELECT id, profile, username, enabled, password, description
         FROM ipsec_rw_users ORDER BY profile, username",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ipsec_rw_users"))?;
    let certs: std::collections::HashSet<String> =
        sqlx::query_scalar("SELECT name FROM ipsec_pki WHERE name LIKE 'user:%:crt'")
            .fetch_all(store.pool()?)
            .await
            .map_err(db_err("read ipsec_pki"))?
            .into_iter()
            .collect();
    Ok(rows
        .iter()
        .map(|r| {
            let password: Option<String> = r.get(4);
            let (profile, username): (String, String) = (r.get(1), r.get(2));
            RwUser {
                id: r.get(0),
                has_cert: certs.contains(&format!("user:{profile}:{username}:crt")),
                profile,
                username,
                enabled: r.get::<i64, _>(3) != 0,
                has_password: password.is_some(),
                password,
                description: r.get(5),
            }
        })
        .collect())
}

/// Create (`id` = None) or edit a profile. Returns its id.
pub async fn save_profile(store: &ConfigStore, id: Option<i64>, t: &ProfileInput) -> Result<i64> {
    let all = list_profiles(store).await?;
    let cur = match id {
        Some(id) => Some(
            all.iter()
                .find(|x| x.id == id)
                .cloned()
                .ok_or_else(|| Error::Config(format!("no road-warrior profile {id}")))?,
        ),
        None => None,
    };
    let name = match (opt(&t.name), &cur) {
        (Some(n), _) => check_profile_name(n)?,
        (None, Some(c)) => c.name.clone(),
        (None, None) => return Err(invalid("profile: a name is required")),
    };
    if all.iter().any(|x| x.name == name && Some(x.id) != id) {
        return Err(invalid(format!("profile: {name} already exists")));
    }
    if cur.as_ref().is_some_and(|c| c.name != name) {
        return Err(invalid(
            "profile: a profile cannot be renamed (delete and add it)",
        ));
    }
    let auth = match (opt(&t.auth), &cur) {
        (Some(v @ ("eap" | "cert")), _) => v.to_string(),
        (Some(v), _) => return Err(invalid(format!("authentication {v:?}: eap or cert"))),
        (None, Some(c)) => c.auth.clone(),
        (None, None) => "eap".into(),
    };
    if cur.as_ref().is_some_and(|c| c.auth != auth) {
        return Err(invalid(
            "authentication: cannot change on a profile (its users hold passwords or certificates); add a new profile",
        ));
    }
    let local_address = match (&t.local_address, &cur) {
        (Some(a), _) if a.trim().is_empty() => None,
        (Some(a), _) => Some(check_host("local address", a)?),
        (None, Some(c)) => c.local_address.clone(),
        (None, None) => None,
    };
    let server_id = match (opt(&t.server_id), &cur) {
        (Some(v), _) => check_server_id(v)?,
        (None, Some(c)) => c.server_id.clone(),
        (None, None) => return Err(invalid("server name or address: required")),
    };
    let pool = match (opt(&t.pool), &cur) {
        (Some(v), _) => {
            let p = check_networks("address pool", v, false)?;
            if split_list(&p).len() != 1 || p.parse::<ipnetwork::IpNetwork>().is_err() {
                return Err(invalid(
                    "address pool: exactly one network, e.g. 10.99.50.0/24",
                ));
            }
            let n: ipnetwork::IpNetwork = p.parse().expect("checked");
            if n.prefix() > if n.is_ipv4() { 30 } else { 126 } {
                return Err(invalid("address pool: too small"));
            }
            n.to_string()
        }
        (None, Some(c)) => c.pool.clone(),
        (None, None) => return Err(invalid("address pool: required")),
    };
    let dns = match (&t.dns, &cur) {
        (Some(v), _) => check_dns(v)?,
        (None, Some(c)) => c.dns.clone(),
        (None, None) => String::new(),
    };
    let local_ts = match (&t.local_ts, &cur) {
        (Some(v), _) if v.trim().is_empty() => "0.0.0.0/0, ::/0".to_string(),
        (Some(v), _) => check_networks("networks behind the firewall", v, false)?,
        (None, Some(c)) => c.local_ts.clone(),
        (None, None) => "0.0.0.0/0, ::/0".into(),
    };
    let ike_proposals = match (opt(&t.ike_proposals), &cur) {
        (Some(v), _) => check_proposals("IKE proposals", v)?,
        (None, Some(c)) => c.ike_proposals.clone(),
        (None, None) => RW_IKE.into(),
    };
    let esp_proposals = match (opt(&t.esp_proposals), &cur) {
        (Some(v), _) => check_proposals("ESP proposals", v)?,
        (None, Some(c)) => c.esp_proposals.clone(),
        (None, None) => RW_ESP.into(),
    };
    let description = match (&t.description, &cur) {
        (Some(d), _) => check_description(Some(d))?,
        (None, Some(c)) => c.description.clone(),
        (None, None) => None,
    };
    let enabled = t
        .enabled
        .or(cur.as_ref().map(|c| c.enabled))
        .unwrap_or(true);
    let sql = if id.is_some() {
        "UPDATE ipsec_rw_profiles SET name=?, enabled=?, auth=?, local_address=?, server_id=?,
            pool=?, dns=?, local_ts=?, ike_proposals=?, esp_proposals=?, description=?,
            updated_at=? WHERE id=?"
    } else {
        "INSERT INTO ipsec_rw_profiles (name, enabled, auth, local_address, server_id, pool, dns,
            local_ts, ike_proposals, esp_proposals, description, updated_at, id)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
    };
    let r = sqlx::query(sql)
        .bind(&name)
        .bind(enabled as i64)
        .bind(&auth)
        .bind(&local_address)
        .bind(&server_id)
        .bind(&pool)
        .bind(&dns)
        .bind(&local_ts)
        .bind(&ike_proposals)
        .bind(&esp_proposals)
        .bind(&description)
        .bind(now())
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("save road-warrior profile"))?;
    // a new server name needs a new server certificate
    if cur.as_ref().is_some_and(|c| c.server_id != server_id) {
        sqlx::query("DELETE FROM ipsec_pki WHERE name IN (?, ?, ?)")
            .bind(format!("server:{name}:crt"))
            .bind(format!("server:{name}:key"))
            .bind(format!("server:{name}:id"))
            .execute(store.pool()?)
            .await
            .map_err(db_err("reset the server certificate"))?;
    }
    Ok(id.unwrap_or_else(|| r.last_insert_rowid()))
}

pub async fn delete_profile(store: &ConfigStore, id: i64) -> Result<bool> {
    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM ipsec_rw_profiles WHERE id = ?")
            .bind(id)
            .fetch_optional(store.pool()?)
            .await
            .map_err(db_err("read profile"))?;
    let Some(name) = name else { return Ok(false) };
    sqlx::query("DELETE FROM ipsec_rw_users WHERE profile = ?")
        .bind(&name)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete road-warrior users"))?;
    sqlx::query("DELETE FROM ipsec_rw_profiles WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete road-warrior profile"))?;
    sqlx::query("DELETE FROM ipsec_pki WHERE name LIKE ?")
        .bind(format!("%:{name}:%"))
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete road-warrior certificates"))?;
    Ok(true)
}

/// Add a user to a profile (`id` = None) or edit one. Returns (id, generated
/// password for an EAP user created without one).
pub async fn save_user(
    store: &ConfigStore,
    profile: &str,
    id: Option<i64>,
    t: &UserInput,
) -> Result<(i64, Option<String>)> {
    let profiles = list_profiles(store).await?;
    let p = profiles
        .iter()
        .find(|p| p.name == profile)
        .ok_or_else(|| Error::Config(format!("no road-warrior profile {profile:?}")))?;
    let users = list_users(store).await?;
    let cur = match id {
        Some(id) => Some(
            users
                .iter()
                .find(|u| u.id == id && u.profile == profile)
                .cloned()
                .ok_or_else(|| Error::Config(format!("no road-warrior user {id}")))?,
        ),
        None => None,
    };
    let username = match (opt(&t.username), &cur) {
        (Some(n), _) => check_username(n)?,
        (None, Some(c)) => c.username.clone(),
        (None, None) => return Err(invalid("user: a name is required")),
    };
    if users
        .iter()
        .any(|u| u.profile == profile && u.username == username && Some(u.id) != id)
    {
        return Err(invalid(format!(
            "user: {username} already exists in {profile}"
        )));
    }
    let mut generated = None;
    let password = if p.auth == "eap" {
        Some(match (opt(&t.password), &cur) {
            (Some(pw), _) => check_user_password(pw)?,
            (None, Some(c)) if c.password.is_some() => c.password.clone().expect("checked"),
            _ => {
                let pw = generate_password();
                generated = Some(pw.clone());
                pw
            }
        })
    } else {
        if opt(&t.password).is_some() {
            return Err(invalid("password: a certificate profile has no passwords"));
        }
        None
    };
    let description = match (&t.description, &cur) {
        (Some(d), _) => check_description(Some(d))?,
        (None, Some(c)) => c.description.clone(),
        (None, None) => None,
    };
    let enabled = t
        .enabled
        .or(cur.as_ref().map(|c| c.enabled))
        .unwrap_or(true);
    let r = match id {
        Some(i) => sqlx::query(
            "UPDATE ipsec_rw_users SET username=?, enabled=?, password=?, description=?,
                updated_at=? WHERE id=?",
        )
        .bind(&username)
        .bind(enabled as i64)
        .bind(&password)
        .bind(&description)
        .bind(now())
        .bind(i)
        .execute(store.pool()?)
        .await
        .map_err(db_err("save road-warrior user"))?,
        None => sqlx::query(
            "INSERT INTO ipsec_rw_users (username, enabled, password, description, updated_at, profile)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(&username)
        .bind(enabled as i64)
        .bind(&password)
        .bind(&description)
        .bind(now())
        .bind(profile)
        .execute(store.pool()?)
        .await
        .map_err(db_err("save road-warrior user"))?,
    };
    Ok((id.unwrap_or_else(|| r.last_insert_rowid()), generated))
}

pub async fn delete_user(store: &ConfigStore, id: i64) -> Result<bool> {
    if let Some((p, u)) = sqlx::query_as::<_, (String, String)>(
        "SELECT profile, username FROM ipsec_rw_users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db_err("read road-warrior user"))?
    {
        sqlx::query("DELETE FROM ipsec_pki WHERE name IN (?, ?)")
            .bind(format!("user:{p}:{u}:crt"))
            .bind(format!("user:{p}:{u}:key"))
            .execute(store.pool()?)
            .await
            .map_err(db_err("delete the user's certificate"))?;
    }
    let r = sqlx::query("DELETE FROM ipsec_rw_users WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete road-warrior user"))?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------------
// GitOps
// ---------------------------------------------------------------------

/// `kind: IpsecRoadWarrior` from a repository: the profile form's fields
/// (`auth, server_id, local_address, pool, dns, local_ts, ike_proposals,
/// esp_proposals, enabled, description`) and its users:
///
/// ```yaml
/// users:
///   - { username: alice, password_file: /etc/patronus/secrets/alice }   # eap
///   - { username: bob }                                                 # cert
/// ```
///
/// The user list is authoritative: users not listed are removed. A new EAP
/// user needs `password` or `password_file`; an existing one keeps its
/// password when neither is given.
pub async fn gitops_upsert_profile(
    store: &ConfigStore,
    name: &str,
    spec: &serde_json::Value,
) -> Result<()> {
    let mut input: ProfileInput = serde_json::from_value(spec.clone())
        .map_err(|e| invalid(format!("road-warrior profile {name}: {e}")))?;
    input.name = Some(name.to_string());
    let users: Vec<serde_json::Value> = spec
        .get("users")
        .and_then(|u| u.as_array())
        .cloned()
        .unwrap_or_default();
    // validate the whole list before touching anything
    let mut wanted = Vec::new();
    for u in &users {
        let uname = u.get("username").and_then(|n| n.as_str()).ok_or_else(|| {
            invalid(format!(
                "road-warrior profile {name}: a user needs a username"
            ))
        })?;
        wanted.push(check_username(uname)?);
    }
    let cur = list_profiles(store)
        .await?
        .into_iter()
        .find(|p| p.name == name);
    // refuse a list that cannot be applied before anything is written
    let auth = opt(&input.auth)
        .map(str::to_string)
        .or_else(|| cur.as_ref().map(|c| c.auth.clone()))
        .unwrap_or_else(|| "eap".into());
    let known: Vec<String> = list_users(store)
        .await?
        .into_iter()
        .filter(|u| u.profile == name)
        .map(|u| u.username)
        .collect();
    for (u, uname) in users.iter().zip(&wanted) {
        if auth == "eap"
            && !known.contains(uname)
            && crate::ipsec::secret_from(u, "password", "password_file")?.is_none()
        {
            return Err(invalid(format!(
                "road-warrior user {uname}: a new EAP user needs password or password_file"
            )));
        }
    }
    let id = save_profile(store, cur.as_ref().map(|p| p.id), &input).await?;
    let profile = list_profiles(store)
        .await?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| Error::Config("profile vanished".into()))?;
    let existing: Vec<RwUser> = list_users(store)
        .await?
        .into_iter()
        .filter(|u| u.profile == name)
        .collect();
    for e in &existing {
        if !wanted.contains(&e.username) {
            delete_user(store, e.id).await?;
        }
    }
    for (u, uname) in users.iter().zip(&wanted) {
        let password = crate::ipsec::secret_from(u, "password", "password_file")?;
        let cur = existing.iter().find(|e| &e.username == uname);
        if profile.auth == "eap" && cur.is_none() && password.is_none() {
            return Err(invalid(format!(
                "road-warrior user {uname}: a new EAP user needs password or password_file"
            )));
        }
        let ui = UserInput {
            username: Some(uname.clone()),
            enabled: u.get("enabled").and_then(|v| v.as_bool()),
            password,
            description: u
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        save_user(store, name, cur.map(|c| c.id), &ui).await?;
    }
    Ok(())
}

pub async fn gitops_delete_profile(store: &ConfigStore, name: &str) -> Result<()> {
    if let Some(p) = list_profiles(store)
        .await?
        .into_iter()
        .find(|p| p.name == name)
    {
        delete_profile(store, p.id).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// PKI (openssl)
// ---------------------------------------------------------------------

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd
        .output()
        .map_err(|e| Error::Service(format!("IPsec PKI ({what}): {e} (is openssl installed?)")))?;
    if !out.status.success() {
        return Err(Error::Service(format!(
            "IPsec PKI ({what}): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

async fn pki_get(store: &ConfigStore, name: &str) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT pem FROM ipsec_pki WHERE name = ?")
        .bind(name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db_err("read the IPsec PKI"))
}

async fn pki_put(store: &ConfigStore, name: &str, pem: &str) -> Result<()> {
    sqlx::query("INSERT OR REPLACE INTO ipsec_pki (name, pem) VALUES (?, ?)")
        .bind(name)
        .bind(pem)
        .execute(store.pool()?)
        .await
        .map_err(db_err("store the IPsec PKI"))?;
    Ok(())
}

/// A key + certificate signed by the CA in `dir`.
fn issue(dir: &Path, cn: &str, eku: &str, san: Option<&str>) -> Result<(String, String)> {
    let stem: String = cn
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let (key, csr, crt, ext) = (
        dir.join(format!("{stem}.key")),
        dir.join(format!("{stem}.csr")),
        dir.join(format!("{stem}.crt")),
        dir.join(format!("{stem}.ext")),
    );
    run(
        Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key),
        "key",
    )?;
    run(
        Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", &format!("/CN={cn}"), "-out"])
            .arg(&csr),
        "request",
    )?;
    let mut e =
        format!("basicConstraints=CA:FALSE\nextendedKeyUsage={eku}\nkeyUsage=digitalSignature\n");
    if let Some(s) = san {
        e.push_str(&format!("subjectAltName={s}\n"));
    }
    std::fs::write(&ext, e).map_err(|x| Error::Service(format!("{}: {x}", ext.display())))?;
    run(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "1825", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(dir.join("ca.crt"))
            .arg("-CAkey")
            .arg(dir.join("ca.key"))
            .args(["-CAcreateserial", "-extfile"])
            .arg(&ext)
            .arg("-out")
            .arg(&crt),
        "sign",
    )?;
    let rd = |p: &Path| {
        std::fs::read_to_string(p).map_err(|e| Error::Service(format!("{}: {e}", p.display())))
    };
    Ok((rd(&crt)?, rd(&key)?))
}

fn san_for(server_id: &str) -> String {
    if server_id.parse::<std::net::IpAddr>().is_ok() {
        format!("IP:{server_id}")
    } else {
        format!("DNS:{server_id}")
    }
}

/// Create the CA, every profile's server certificate and every certificate
/// user's client certificate that is missing.
pub async fn ensure_pki(store: &ConfigStore) -> Result<()> {
    let profiles = list_profiles(store).await?;
    if profiles.is_empty() {
        return Ok(());
    }
    let users = list_users(store).await?;
    let mut need = pki_get(store, "ca.crt").await?.is_none();
    for p in &profiles {
        if pki_get(store, &format!("server:{}:crt", p.name))
            .await?
            .is_none()
        {
            need = true;
        }
    }
    for u in &users {
        let p = profiles.iter().find(|p| p.name == u.profile);
        if p.is_some_and(|p| p.auth == "cert")
            && pki_get(store, &format!("user:{}:{}:crt", u.profile, u.username))
                .await?
                .is_none()
        {
            need = true;
        }
    }
    if !need {
        return Ok(());
    }
    let tmp = std::env::temp_dir().join(format!(".patronus-ipsec-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .map_err(|e| Error::Service(format!("{}: {e}", tmp.display())))?;
    }
    let res = async {
        if let (Some(crt), Some(key)) = (
            pki_get(store, "ca.crt").await?,
            pki_get(store, "ca.key").await?,
        ) {
            std::fs::write(tmp.join("ca.crt"), crt).ok();
            std::fs::write(tmp.join("ca.key"), key).ok();
        } else {
            run(
                Command::new("openssl")
                    .args([
                        "ecparam",
                        "-name",
                        "prime256v1",
                        "-genkey",
                        "-noout",
                        "-out",
                    ])
                    .arg(tmp.join("ca.key")),
                "CA key",
            )?;
            run(
                Command::new("openssl")
                    .args(["req", "-new", "-x509", "-days", "3650", "-key"])
                    .arg(tmp.join("ca.key"))
                    .args([
                        "-subj",
                        "/CN=Patronus IPsec CA",
                        "-addext",
                        "basicConstraints=critical,CA:TRUE",
                        "-addext",
                        "keyUsage=critical,keyCertSign,cRLSign",
                        "-out",
                    ])
                    .arg(tmp.join("ca.crt")),
                "CA certificate",
            )?;
            for f in ["ca.crt", "ca.key"] {
                pki_put(
                    store,
                    f,
                    &std::fs::read_to_string(tmp.join(f)).unwrap_or_default(),
                )
                .await?;
            }
        }
        for p in &profiles {
            let k = format!("server:{}:crt", p.name);
            if pki_get(store, &k).await?.is_none() {
                let (crt, key) = issue(
                    &tmp,
                    &p.server_id,
                    "serverAuth,1.3.6.1.5.5.8.2.2",
                    Some(&san_for(&p.server_id)),
                )?;
                pki_put(store, &k, &crt).await?;
                pki_put(store, &format!("server:{}:key", p.name), &key).await?;
                pki_put(store, &format!("server:{}:id", p.name), &p.server_id).await?;
            }
        }
        for u in &users {
            let p = profiles.iter().find(|p| p.name == u.profile);
            if !p.is_some_and(|p| p.auth == "cert") {
                continue;
            }
            let k = format!("user:{}:{}:crt", u.profile, u.username);
            if pki_get(store, &k).await?.is_none() {
                let (crt, key) = issue(&tmp, &u.username, "clientAuth", None)?;
                pki_put(store, &k, &crt).await?;
                pki_put(
                    store,
                    &format!("user:{}:{}:key", u.profile, u.username),
                    &key,
                )
                .await?;
            }
        }
        Ok::<(), Error>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// The CA certificate (PEM), once there is one.
pub async fn ca_pem(store: &ConfigStore) -> Result<Option<String>> {
    pki_get(store, "ca.crt").await
}

/// When a stored certificate stops being valid (`openssl x509 -enddate`).
pub fn cert_expiry(pem: &str) -> Option<String> {
    use std::io::Write;
    let mut c = Command::new("openssl")
        .args(["x509", "-noout", "-enddate"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    c.stdin.take()?.write_all(pem.as_bytes()).ok()?;
    let o = c.wait_with_output().ok()?;
    String::from_utf8_lossy(&o.stdout)
        .trim()
        .strip_prefix("notAfter=")
        .map(str::to_string)
}

fn der_b64(pem: &str) -> Result<String> {
    // PEM body is base64 of the DER already
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| Error::Config(format!("certificate is not PEM: {e}")))?;
    Ok(body)
}

/// The client's PKCS#12 bundle (key + certificate + CA), protected with
/// `password`.
pub async fn client_p12(
    store: &ConfigStore,
    profile: &str,
    username: &str,
    password: &str,
) -> Result<Vec<u8>> {
    check_user_password(password)?;
    let (Some(crt), Some(key), Some(ca)) = (
        pki_get(store, &format!("user:{profile}:{username}:crt")).await?,
        pki_get(store, &format!("user:{profile}:{username}:key")).await?,
        pki_get(store, "ca.crt").await?,
    ) else {
        return Err(Error::Config(format!(
            "no client certificate for {username} in {profile} yet (apply the IPsec configuration)"
        )));
    };
    let tmp = std::env::temp_dir().join(format!(".patronus-p12-{}-{}", std::process::id(), now()));
    let _ = std::fs::remove_dir_all(&tmp);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .map_err(|e| Error::Service(format!("{}: {e}", tmp.display())))?;
    }
    let res = (|| {
        for (n, v) in [("c.crt", &crt), ("c.key", &key), ("ca.crt", &ca)] {
            std::fs::write(tmp.join(n), v).map_err(|e| Error::Service(e.to_string()))?;
        }
        run(
            Command::new("openssl")
                .args(["pkcs12", "-export", "-inkey"])
                .arg(tmp.join("c.key"))
                .arg("-in")
                .arg(tmp.join("c.crt"))
                .arg("-certfile")
                .arg(tmp.join("ca.crt"))
                .args(["-name", username, "-passout", "env:PATRONUS_P12_PW", "-out"])
                .arg(tmp.join("c.p12"))
                .env("PATRONUS_P12_PW", password),
            "pkcs12",
        )?;
        std::fs::read(tmp.join("c.p12")).map_err(|e| Error::Service(e.to_string()))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

// ---------------------------------------------------------------------
// swanctl pieces
// ---------------------------------------------------------------------

/// What the road-warrior profiles add to `patronus.conf` and the files
/// charon needs next to it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RwConfig {
    /// `name { ... }` blocks inside `connections { }`
    pub connections: String,
    pub pools: String,
    pub secrets: String,
    /// (directory, file name, content, mode)
    pub files: Vec<(&'static str, String, String, u32)>,
}

impl RwConfig {
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

fn user_file(profile: &str, user: &str) -> String {
    let u: String = user
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{RW_PREFIX}{profile}-{u}.pem")
}

/// Build the swanctl pieces for the enabled profiles (PKI material must
/// exist: [`ensure_pki`]). With `redact` the secrets are hidden.
pub async fn build_config(store: &ConfigStore, redact: bool) -> Result<RwConfig> {
    let profiles: Vec<RwProfile> = list_profiles(store)
        .await?
        .into_iter()
        .filter(|p| p.enabled)
        .collect();
    let mut cfg = RwConfig::default();
    if profiles.is_empty() {
        return Ok(cfg);
    }
    let users = list_users(store).await?;
    if let Some(ca) = pki_get(store, "ca.crt").await? {
        cfg.files.push((X509CA_DIR, CA_FILE.into(), ca, 0o644));
    }
    for p in &profiles {
        let conn = format!("{RW_PREFIX}{}", p.name);
        let local = p.local_address.as_deref().unwrap_or("%any");
        let cert_file = format!("{conn}.pem");
        if let (Some(crt), Some(key)) = (
            pki_get(store, &format!("server:{}:crt", p.name)).await?,
            pki_get(store, &format!("server:{}:key", p.name)).await?,
        ) {
            cfg.files.push((X509_DIR, cert_file.clone(), crt, 0o644));
            cfg.files.push((PRIVATE_DIR, cert_file.clone(), key, 0o600));
        }
        let mut remote = String::new();
        let active: Vec<&RwUser> = users
            .iter()
            .filter(|u| u.profile == p.name && u.enabled)
            .collect();
        if p.auth == "eap" {
            remote.push_str("            auth = eap-mschapv2\n            eap_id = %any\n");
            for (n, u) in active.iter().enumerate() {
                let Some(pw) = &u.password else { continue };
                cfg.secrets.push_str(&format!(
                    "    eap-{conn}-{n} {{\n        id = {}\n        secret = \"{}\"\n    }}\n",
                    u.username,
                    if redact { "(hidden)" } else { pw }
                ));
            }
        } else {
            remote.push_str("            auth = pubkey\n");
            remote.push_str(&format!("            cacerts = {CA_FILE}\n"));
            let mut pinned = Vec::new();
            for u in &active {
                if let Some(crt) =
                    pki_get(store, &format!("user:{}:{}:crt", p.name, u.username)).await?
                {
                    let f = user_file(&p.name, &u.username);
                    cfg.files.push((X509_DIR, f.clone(), crt, 0o644));
                    pinned.push(f);
                }
            }
            if pinned.is_empty() {
                // nobody may connect: no connection until a user has a certificate
                cfg.files.retain(|f| f.1 != cert_file);
                continue;
            }
            remote.push_str(&format!("            certs = {}\n", pinned.join(",")));
        }
        cfg.connections.push_str(&format!(
            "    {conn} {{\n        version = 2\n        local_addrs = {local}\n        pools = {conn}\n        \
             proposals = {ike}\n        send_cert = always\n        unique = replace\n        \
             fragmentation = yes\n        dpd_delay = 30s\n        local {{\n            auth = pubkey\n            \
             certs = {cert_file}\n            id = {sid}\n        }}\n        remote {{\n{remote}        }}\n        \
             children {{\n            {name} {{\n                local_ts = {lts}\n                \
             esp_proposals = {esp}\n                dpd_action = clear\n            }}\n        }}\n    }}\n",
            ike = p.ike_proposals,
            sid = p.server_id,
            name = p.name,
            lts = split_list(&p.local_ts).join(","),
            esp = p.esp_proposals,
        ));
        cfg.pools.push_str(&format!(
            "    {conn} {{\n        addrs = {}\n{}    }}\n",
            p.pool,
            if p.dns.is_empty() {
                String::new()
            } else {
                format!("        dns = {}\n", p.dns)
            }
        ));
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------
// client setup files
// ---------------------------------------------------------------------

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A stable UUID derived from `seed` (re-importing a profile replaces it
/// instead of adding a copy).
fn uuid_for(seed: &str) -> String {
    let mut h: [u64; 2] = [0xcbf29ce484222325, 0x84222325cbf29ce4];
    for (i, b) in seed.bytes().enumerate() {
        let k = i % 2;
        h[k] ^= b as u64;
        h[k] = h[k].wrapping_mul(0x100000001b3);
        h[1 - k] = h[1 - k].rotate_left(5) ^ h[k];
    }
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&h[0].to_be_bytes());
    b[8..].copy_from_slice(&h[1].to_be_bytes());
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x = |r: std::ops::Range<usize>| b[r].iter().map(|v| format!("{v:02X}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        x(0..4),
        x(4..6),
        x(6..8),
        x(8..10),
        x(10..16)
    )
}

fn is_full_tunnel(p: &RwProfile) -> bool {
    split_list(&p.local_ts)
        .iter()
        .any(|n| n == "0.0.0.0/0" || n == "::/0")
}

fn wrap(b64: &str) -> String {
    b64.as_bytes()
        .chunks(68)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// iOS / macOS configuration profile (`.mobileconfig`): an IKEv2 VPN, the
/// CA as a trusted root and (certificate profiles) the user's PKCS#12.
pub fn mobileconfig(
    p: &RwProfile,
    user: &str,
    ca_pem: &str,
    p12: Option<(&[u8], &str)>,
) -> Result<String> {
    let ca = der_b64(ca_pem)?;
    let id = format!("app.patronus.ipsec.{}.{}", p.name, user);
    let vpn_uuid = uuid_for(&format!("{id}:vpn"));
    let ca_uuid = uuid_for(&format!("{id}:ca"));
    let p12_uuid = uuid_for(&format!("{id}:p12"));
    let auth = if p.auth == "cert" {
        format!(
            "<key>AuthenticationMethod</key><string>Certificate</string>\n\
             \t\t\t<key>PayloadCertificateUUID</key><string>{p12_uuid}</string>"
        )
    } else {
        format!(
            "<key>AuthenticationMethod</key><string>None</string>\n\
             \t\t\t<key>ExtendedAuthEnabled</key><integer>1</integer>\n\
             \t\t\t<key>AuthName</key><string>{}</string>",
            xml(user)
        )
    };
    let sa = "<dict>\n\t\t\t\t<key>EncryptionAlgorithm</key><string>AES-256-GCM</string>\n\
              \t\t\t\t<key>IntegrityAlgorithm</key><string>SHA2-256</string>\n\
              \t\t\t\t<key>DiffieHellmanGroup</key><integer>19</integer>\n\
              \t\t\t\t<key>LifeTimeInMinutes</key><integer>1440</integer>\n\t\t\t</dict>";
    let mut payloads = format!(
        "\t\t<dict>\n\t\t\t<key>PayloadType</key><string>com.apple.vpn.managed</string>\n\
         \t\t\t<key>PayloadVersion</key><integer>1</integer>\n\
         \t\t\t<key>PayloadIdentifier</key><string>{id}.vpn</string>\n\
         \t\t\t<key>PayloadUUID</key><string>{vpn_uuid}</string>\n\
         \t\t\t<key>PayloadDisplayName</key><string>{name} VPN</string>\n\
         \t\t\t<key>UserDefinedName</key><string>{name}</string>\n\
         \t\t\t<key>VPNType</key><string>IKEv2</string>\n\
         \t\t\t<key>IKEv2</key>\n\t\t\t<dict>\n\
         \t\t\t<key>RemoteAddress</key><string>{server}</string>\n\
         \t\t\t<key>RemoteIdentifier</key><string>{server}</string>\n\
         \t\t\t<key>LocalIdentifier</key><string>{user_x}</string>\n\
         \t\t\t{auth}\n\
         \t\t\t<key>ServerCertificateIssuerCommonName</key><string>Patronus IPsec CA</string>\n\
         \t\t\t<key>ServerCertificateCommonName</key><string>{server}</string>\n\
         \t\t\t<key>DeadPeerDetectionRate</key><string>Medium</string>\n\
         \t\t\t<key>EnablePFS</key><integer>1</integer>\n\
         \t\t\t<key>IKESecurityAssociationParameters</key>\n\t\t\t{sa}\n\
         \t\t\t<key>ChildSecurityAssociationParameters</key>\n\t\t\t{sa}\n\
         \t\t\t</dict>\n\t\t</dict>\n",
        name = xml(&p.name),
        server = xml(&p.server_id),
        user_x = xml(user),
    );
    payloads.push_str(&format!(
        "\t\t<dict>\n\t\t\t<key>PayloadType</key><string>com.apple.security.root</string>\n\
         \t\t\t<key>PayloadVersion</key><integer>1</integer>\n\
         \t\t\t<key>PayloadIdentifier</key><string>{id}.ca</string>\n\
         \t\t\t<key>PayloadUUID</key><string>{ca_uuid}</string>\n\
         \t\t\t<key>PayloadDisplayName</key><string>Patronus IPsec CA</string>\n\
         \t\t\t<key>PayloadContent</key>\n\t\t\t<data>\n{}\n\t\t\t</data>\n\t\t</dict>\n",
        wrap(&ca)
    ));
    if let Some((p12, pw)) = p12 {
        let b = base64::engine::general_purpose::STANDARD.encode(p12);
        payloads.push_str(&format!(
            "\t\t<dict>\n\t\t\t<key>PayloadType</key><string>com.apple.security.pkcs12</string>\n\
             \t\t\t<key>PayloadVersion</key><integer>1</integer>\n\
             \t\t\t<key>PayloadIdentifier</key><string>{id}.p12</string>\n\
             \t\t\t<key>PayloadUUID</key><string>{p12_uuid}</string>\n\
             \t\t\t<key>PayloadDisplayName</key><string>{} certificate</string>\n\
             \t\t\t<key>Password</key><string>{}</string>\n\
             \t\t\t<key>PayloadContent</key>\n\t\t\t<data>\n{}\n\t\t\t</data>\n\t\t</dict>\n",
            xml(user),
            xml(pw),
            wrap(&b)
        ));
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\t<key>PayloadContent</key>\n\t<array>\n{payloads}\t</array>\n\
         \t<key>PayloadDisplayName</key><string>{name} (Patronus)</string>\n\
         \t<key>PayloadIdentifier</key><string>{id}</string>\n\
         \t<key>PayloadType</key><string>Configuration</string>\n\
         \t<key>PayloadUUID</key><string>{uuid}</string>\n\
         \t<key>PayloadVersion</key><integer>1</integer>\n</dict>\n</plist>\n",
        name = xml(&p.name),
        uuid = uuid_for(&id),
    ))
}

/// Android strongSwan app profile (`.sswan`).
pub fn sswan(
    p: &RwProfile,
    user: &str,
    ca_pem: &str,
    p12: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let ca = der_b64(ca_pem)?;
    let mut local = serde_json::Map::new();
    let ty = if p.auth == "cert" {
        if let Some(b) = p12 {
            local.insert(
                "p12".into(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(b)),
            );
        }
        "ikev2-cert"
    } else {
        local.insert("eap_id".into(), serde_json::Value::String(user.into()));
        "ikev2-eap"
    };
    let first = |s: &str| s.split(',').next().unwrap_or("").to_string();
    let mut v = serde_json::json!({
        "uuid": uuid_for(&format!("app.patronus.ipsec.{}.{}", p.name, user)).to_lowercase(),
        "name": format!("{} ({})", p.name, p.server_id),
        "type": ty,
        "remote": { "addr": p.server_id, "id": p.server_id, "cert": ca },
        "local": local,
        "ike-proposal": first(&p.ike_proposals),
        "esp-proposal": first(&p.esp_proposals),
    });
    if !is_full_tunnel(p) {
        v["split-tunneling"] = serde_json::json!({ "subnets": split_list(&p.local_ts).join(" ") });
    }
    Ok(v)
}

fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Windows setup script: trusts the CA, adds the IKEv2 connection, sets the
/// IPsec parameters to what the server offers.
pub fn powershell(p: &RwProfile, user: &str, ca_pem: &str, p12: Option<(&[u8], &str)>) -> String {
    let name = ps_quote(&p.name);
    let server = ps_quote(&p.server_id);
    let full = is_full_tunnel(p);
    let mut s = format!(
        "# Patronus IPsec (IKEv2) road-warrior setup: {name} for {user}\n\
         # Run in an elevated PowerShell (right-click, Run as administrator).\n\
         $ErrorActionPreference = 'Stop'\n\n\
         $caPem = @'\n{ca}\n'@\n\
         $caFile = Join-Path $env:TEMP 'patronus-ipsec-ca.pem'\n\
         Set-Content -Path $caFile -Value $caPem -Encoding ascii\n\
         Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null\n\
         Remove-Item $caFile\n\n",
        ca = ca_pem.trim(),
        user = ps_quote(user),
    );
    if let (true, Some((b, pw))) = (p.auth == "cert", p12) {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b);
        s.push_str(&format!(
            "$p12 = [Convert]::FromBase64String(@'\n{}\n'@)\n\
             $p12File = Join-Path $env:TEMP 'patronus-ipsec-client.p12'\n\
             [IO.File]::WriteAllBytes($p12File, $p12)\n\
             Import-PfxCertificate -FilePath $p12File -CertStoreLocation Cert:\\LocalMachine\\My `\n    \
             -Password (ConvertTo-SecureString '{}' -AsPlainText -Force) | Out-Null\n\
             Remove-Item $p12File\n\n",
            wrap(&b64),
            ps_quote(pw)
        ));
    }
    let method = if p.auth == "cert" {
        "MachineCertificate"
    } else {
        "MSChapv2"
    };
    s.push_str(&format!(
        "if (Get-VpnConnection -Name '{name}' -ErrorAction SilentlyContinue) {{\n    \
         Remove-VpnConnection -Name '{name}' -Force\n}}\n\
         Add-VpnConnection -Name '{name}' -ServerAddress '{server}' -TunnelType Ikev2 `\n    \
         -AuthenticationMethod {method} -EncryptionLevel Required `\n    \
         -SplitTunneling:${split} -RememberCredential:$false -PassThru | Out-Null\n\
         Set-VpnConnectionIPsecConfiguration -ConnectionName '{name}' `\n    \
         -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 `\n    \
         -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup ECP256 -PfsGroup ECP256 -Force\n",
        split = if full { "false" } else { "true" },
    ));
    if !full {
        for n in split_list(&p.local_ts) {
            if n.contains(':') {
                continue;
            }
            s.push_str(&format!(
                "Add-VpnConnectionRoute -ConnectionName '{name}' -DestinationPrefix '{}' | Out-Null\n",
                ps_quote(&n)
            ));
        }
    }
    s.push_str(&if p.auth == "cert" {
        format!("\nWrite-Host \"Done. Connect with: rasdial '{name}'\"\n")
    } else {
        format!(
            "\nWrite-Host \"Done. Connect from the network menu or: rasdial '{name}' {} <password>\"\n",
            ps_quote(user)
        )
    });
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;

    fn p(auth: &str) -> ProfileInput {
        ProfileInput {
            name: Some("rw".into()),
            auth: Some(auth.into()),
            server_id: Some("vpn.example.test".into()),
            pool: Some("10.99.50.0/24".into()),
            dns: Some("192.168.50.1, 1.1.1.1".into()),
            local_ts: Some("192.168.50.0/24".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn profiles_and_users_are_validated_and_stored() {
        let s = testutil::store().await;
        let id = save_profile(&s, None, &p("eap")).await.unwrap();
        let all = list_profiles(&s).await.unwrap();
        assert_eq!(all[0].pool, "10.99.50.0/24");
        assert_eq!(all[0].dns, "192.168.50.1,1.1.1.1");
        assert_eq!(all[0].ike_proposals, RW_IKE);
        assert!(
            save_profile(&s, None, &p("eap")).await.is_err(),
            "duplicate name"
        );
        for bad in [
            ProfileInput {
                auth: Some("psk".into()),
                name: Some("x".into()),
                ..p("eap")
            },
            ProfileInput {
                name: Some("x".into()),
                pool: Some("10.99.0.0/24, 10.98.0.0/24".into()),
                ..p("eap")
            },
            ProfileInput {
                name: Some("x".into()),
                pool: Some("10.99.0.1/31".into()),
                ..p("eap")
            },
            ProfileInput {
                name: Some("x".into()),
                dns: Some("dns.example".into()),
                ..p("eap")
            },
            ProfileInput {
                name: Some("x".into()),
                server_id: Some("bad host!".into()),
                ..p("eap")
            },
            ProfileInput {
                name: Some("x y".into()),
                ..p("eap")
            },
        ] {
            let e = save_profile(&s, None, &bad).await.unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{e}");
        }
        assert!(save_profile(
            &s,
            Some(id),
            &ProfileInput {
                auth: Some("cert".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());

        // users: EAP gets a generated password once; usernames and passwords are checked
        let (uid, generated) = save_user(
            &s,
            "rw",
            None,
            &UserInput {
                username: Some("alice".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let g = generated.expect("generated");
        assert_eq!(g.len(), 20);
        let (_, none) = save_user(
            &s,
            "rw",
            None,
            &UserInput {
                username: Some("bob".into()),
                password: Some("correct-horse-12".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(none.is_none());
        for (u, pw) in [
            ("bad name", "longenough1"),
            ("x", "short"),
            ("y", "has\"quote12"),
            ("z", "back\\slash12"),
        ] {
            assert!(
                save_user(
                    &s,
                    "rw",
                    None,
                    &UserInput {
                        username: Some(u.into()),
                        password: Some(pw.into()),
                        ..Default::default()
                    }
                )
                .await
                .is_err(),
                "{u}/{pw}"
            );
        }
        assert!(save_user(
            &s,
            "nope",
            None,
            &UserInput {
                username: Some("q".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        let users = list_users(&s).await.unwrap();
        assert_eq!(users.len(), 2);
        assert!(users.iter().all(|u| u.has_password));
        // the API never serializes the password
        assert!(!serde_json::to_string(&users).unwrap().contains(&g));
        // editing keeps the password unless a new one is given
        save_user(
            &s,
            "rw",
            Some(uid),
            &UserInput {
                description: Some("phone".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let again = list_users(&s).await.unwrap();
        assert_eq!(
            again
                .iter()
                .find(|u| u.id == uid)
                .unwrap()
                .password
                .as_deref(),
            Some(g.as_str())
        );
        // a certificate profile has no passwords
        save_profile(
            &s,
            None,
            &ProfileInput {
                name: Some("rwc".into()),
                ..p("cert")
            },
        )
        .await
        .unwrap();
        assert!(save_user(
            &s,
            "rwc",
            None,
            &UserInput {
                username: Some("carol".into()),
                password: Some("longenough1".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
        save_user(
            &s,
            "rwc",
            None,
            &UserInput {
                username: Some("carol".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // deleting a profile deletes its users
        assert!(delete_profile(&s, id).await.unwrap());
        assert!(list_users(&s)
            .await
            .unwrap()
            .iter()
            .all(|u| u.profile == "rwc"));
        assert!(!delete_user(&s, uid).await.unwrap());
    }

    #[tokio::test]
    async fn road_warrior_profiles_from_a_repository_reconcile_their_users() {
        let s = testutil::store().await;
        let spec = serde_json::json!({
            "auth": "eap", "server_id": "vpn.example.test", "pool": "10.99.50.0/24",
            "local_ts": "192.168.50.0/24",
            "users": [
                { "username": "alice", "password": "alice-secret-pw" },
                { "username": "bob", "password": "bob-secret-pw12", "enabled": false },
            ],
        });
        gitops_upsert_profile(&s, "rw", &spec).await.unwrap();
        let u = list_users(&s).await.unwrap();
        assert_eq!(u.len(), 2);
        assert!(u.iter().any(|x| x.username == "bob" && !x.enabled));
        // the user list is authoritative; an existing user keeps its password
        let spec2 = serde_json::json!({
            "auth": "eap", "server_id": "vpn.example.test", "pool": "10.99.50.0/24",
            "users": [ { "username": "alice" }, { "username": "carol", "password": "carol-secret-1" } ],
        });
        gitops_upsert_profile(&s, "rw", &spec2).await.unwrap();
        let u = list_users(&s).await.unwrap();
        let names: Vec<&str> = u.iter().map(|x| x.username.as_str()).collect();
        assert_eq!(names, vec!["alice", "carol"]);
        assert_eq!(u[0].password.as_deref(), Some("alice-secret-pw"));
        assert_eq!(
            list_profiles(&s).await.unwrap()[0].local_ts,
            "192.168.50.0/24",
            "edit keeps unset fields"
        );
        // a new EAP user needs a password; nothing is half-applied on a bad list
        let bad = serde_json::json!({
            "auth": "eap", "server_id": "vpn.example.test", "pool": "10.99.50.0/24",
            "users": [ { "username": "dave" } ],
        });
        assert!(gitops_upsert_profile(&s, "rw", &bad).await.is_err());
        let bad = serde_json::json!({ "auth": "eap", "server_id": "vpn.example.test", "pool": "10.99.50.0/24", "users": [ { "username": "bad name", "password": "longenough12" } ] });
        assert!(gitops_upsert_profile(&s, "rw", &bad).await.is_err());
        let names: Vec<String> = list_users(&s)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.username)
            .collect();
        assert_eq!(
            names,
            vec!["alice", "carol"],
            "a refused list changes nothing"
        );
        gitops_delete_profile(&s, "rw").await.unwrap();
        gitops_delete_profile(&s, "rw").await.unwrap();
        assert!(
            list_profiles(&s).await.unwrap().is_empty() && list_users(&s).await.unwrap().is_empty()
        );
    }

    fn have_openssl() -> bool {
        Command::new("openssl")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn pki_swanctl_config_and_exports() {
        if !have_openssl() {
            eprintln!("openssl not installed: skipping");
            return;
        }
        let s = testutil::store().await;
        save_profile(&s, None, &p("eap")).await.unwrap();
        save_user(
            &s,
            "rw",
            None,
            &UserInput {
                username: Some("alice".into()),
                password: Some("alice-secret-pw".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        save_user(
            &s,
            "rw",
            None,
            &UserInput {
                username: Some("off".into()),
                password: Some("off-secret-pw1".into()),
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        save_profile(
            &s,
            None,
            &ProfileInput {
                name: Some("rwc".into()),
                server_id: Some("203.0.113.2".into()),
                pool: Some("10.99.60.0/24".into()),
                ..p("cert")
            },
        )
        .await
        .unwrap();
        save_user(
            &s,
            "rwc",
            None,
            &UserInput {
                username: Some("bob".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        ensure_pki(&s).await.unwrap();
        let c = build_config(&s, false).await.unwrap();
        for want in [
            "patronus-rw-rw {",
            "pools = patronus-rw-rw",
            "auth = eap-mschapv2",
            "id = vpn.example.test",
            "local_ts = 192.168.50.0/24",
            "patronus-rw-rwc {",
            "auth = pubkey",
            "certs = patronus-rw-rwc-bob.pem",
            "cacerts = patronus-rw-ca.pem",
            "id = 203.0.113.2",
        ] {
            assert!(c.connections.contains(want), "{want}\\n{}", c.connections);
        }
        assert!(
            c.pools.contains("addrs = 10.99.50.0/24")
                && c.pools.contains("dns = 192.168.50.1,1.1.1.1"),
            "{}",
            c.pools
        );
        assert!(
            c.secrets.contains("id = alice") && c.secrets.contains("secret = \"alice-secret-pw\"")
        );
        assert!(
            !c.secrets.contains("off-secret"),
            "a disabled user gets no credentials"
        );
        assert!(!build_config(&s, true)
            .await
            .unwrap()
            .secrets
            .contains("alice-secret-pw"));
        assert!(c
            .files
            .iter()
            .any(|f| f.0 == PRIVATE_DIR && f.1 == "patronus-rw-rw.pem" && f.3 == 0o600));
        assert!(c
            .files
            .iter()
            .any(|f| f.0 == X509_DIR && f.1 == "patronus-rw-rwc-bob.pem"));
        // idempotent: a second pass makes nothing new
        let ca1 = ca_pem(&s).await.unwrap().unwrap();
        ensure_pki(&s).await.unwrap();
        assert_eq!(ca_pem(&s).await.unwrap().unwrap(), ca1);
        // the server certificate carries the profile's name as a SAN and is signed by the CA
        let tmp = std::env::temp_dir().join(format!("pa-rw-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let (crt, _) = c
            .files
            .iter()
            .find(|f| f.0 == X509_DIR && f.1 == "patronus-rw-rw.pem")
            .map(|f| (f.2.clone(), ()))
            .unwrap();
        std::fs::write(tmp.join("s.pem"), &crt).unwrap();
        std::fs::write(tmp.join("ca.pem"), &ca1).unwrap();
        let o = Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(tmp.join("ca.pem"))
            .arg(tmp.join("s.pem"))
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let o = Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-ext",
                "subjectAltName,extendedKeyUsage",
                "-in",
            ])
            .arg(tmp.join("s.pem"))
            .output()
            .unwrap();
        let txt = String::from_utf8_lossy(&o.stdout);
        assert!(
            txt.contains("DNS:vpn.example.test") && txt.contains("TLS Web Server Authentication"),
            "{txt}"
        );
        assert!(cert_expiry(&crt).unwrap().contains("20"));
        // a cert user's PKCS#12 opens with its password
        let p12 = client_p12(&s, "rwc", "bob", "p12-export-pw").await.unwrap();
        std::fs::write(tmp.join("b.p12"), &p12).unwrap();
        let o = Command::new("openssl")
            .args([
                "pkcs12",
                "-info",
                "-noout",
                "-passin",
                "pass:p12-export-pw",
                "-in",
            ])
            .arg(tmp.join("b.p12"))
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(client_p12(&s, "rwc", "ghost", "p12-export-pw")
            .await
            .is_err());
        assert!(client_p12(&s, "rwc", "bob", "short").await.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
        // changing the server name replaces the server certificate
        let id = list_profiles(&s)
            .await
            .unwrap()
            .iter()
            .find(|p| p.name == "rw")
            .unwrap()
            .id;
        save_profile(
            &s,
            Some(id),
            &ProfileInput {
                server_id: Some("other.example.test".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        ensure_pki(&s).await.unwrap();
        let c2 = build_config(&s, false).await.unwrap();
        let crt2 = &c2
            .files
            .iter()
            .find(|f| f.0 == X509_DIR && f.1 == "patronus-rw-rw.pem")
            .unwrap()
            .2;
        assert_ne!(crt2, &crt);
        // a cert profile with no enabled user lets nobody in
        let bid = list_users(&s)
            .await
            .unwrap()
            .iter()
            .find(|u| u.username == "bob")
            .unwrap()
            .id;
        save_user(
            &s,
            "rwc",
            Some(bid),
            &UserInput {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let c3 = build_config(&s, false).await.unwrap();
        assert!(
            !c3.connections.contains("patronus-rw-rwc {"),
            "a certificate profile without a user has no connection"
        );
        assert!(
            !c3.files.iter().any(|f| f.1 == "patronus-rw-rwc-bob.pem"),
            "the pinned certificate is removed"
        );
    }

    #[test]
    fn client_files_have_what_each_platform_needs() {
        let prof = RwProfile {
            id: 1,
            name: "rw".into(),
            enabled: true,
            auth: "eap".into(),
            local_address: None,
            server_id: "vpn.example.test".into(),
            pool: "10.99.50.0/24".into(),
            dns: String::new(),
            local_ts: "192.168.50.0/24".into(),
            ike_proposals: RW_IKE.into(),
            esp_proposals: RW_ESP.into(),
            description: None,
        };
        let ca = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let m = mobileconfig(&prof, "al<ice>", ca, None).unwrap();
        for want in [
            "com.apple.vpn.managed",
            "<key>VPNType</key><string>IKEv2</string>",
            "<key>RemoteAddress</key><string>vpn.example.test</string>",
            "<key>ExtendedAuthEnabled</key><integer>1</integer>",
            "al&lt;ice&gt;",
            "com.apple.security.root",
        ] {
            assert!(m.contains(want), "{want}\\n{m}");
        }
        assert!(
            !m.contains("pkcs12"),
            "an EAP profile carries no certificate"
        );
        assert_eq!(
            m,
            mobileconfig(&prof, "al<ice>", ca, None).unwrap(),
            "stable UUIDs"
        );
        let mut cert = prof.clone();
        cert.auth = "cert".into();
        let m = mobileconfig(&cert, "bob", ca, Some((b"p12bytes", "pw"))).unwrap();
        assert!(
            m.contains("com.apple.security.pkcs12")
                && m.contains("<string>Certificate</string>")
                && m.contains("PayloadCertificateUUID"),
            "{m}"
        );
        let j = sswan(&prof, "alice", ca, None).unwrap();
        assert_eq!(j["type"], "ikev2-eap");
        assert_eq!(j["local"]["eap_id"], "alice");
        assert_eq!(j["remote"]["addr"], "vpn.example.test");
        assert_eq!(j["split-tunneling"]["subnets"], "192.168.50.0/24");
        assert_eq!(j["ike-proposal"], "aes256gcm16-prfsha256-ecp256");
        let jc = sswan(&cert, "bob", ca, Some(b"xx")).unwrap();
        assert_eq!(jc["type"], "ikev2-cert");
        assert!(jc["local"]["p12"].is_string());
        let mut full = prof.clone();
        full.local_ts = "0.0.0.0/0, ::/0".into();
        assert!(sswan(&full, "a", ca, None)
            .unwrap()
            .get("split-tunneling")
            .is_none());
        let ps = powershell(&prof, "al'ice", ca, None);
        for want in [
            "Import-Certificate",
            "Cert:\\LocalMachine\\Root",
            "Add-VpnConnection -Name 'rw' -ServerAddress 'vpn.example.test' -TunnelType Ikev2",
            "-AuthenticationMethod MSChapv2",
            "Set-VpnConnectionIPsecConfiguration",
            "-DHGroup ECP256",
            "-SplitTunneling:$true",
            "Add-VpnConnectionRoute -ConnectionName 'rw' -DestinationPrefix '192.168.50.0/24'",
            "al''ice",
        ] {
            assert!(ps.contains(want), "{want}\\n{ps}");
        }
        let psc = powershell(&cert, "bob", ca, Some((b"p12", "pw")));
        assert!(
            psc.contains("MachineCertificate") && psc.contains("Import-PfxCertificate"),
            "{psc}"
        );
        assert!(powershell(&full, "a", ca, None).contains("-SplitTunneling:$false"));
    }
}
