//! Certificate manager, ACME part (USE=certs): certificates the router gets
//! and renews itself from Let's Encrypt or any RFC 8555 CA, the way pfSense's
//! ACME package and OPNsense's os-acme-client do, built on the native Rust
//! client in `patronus_security::acme` (no acme.sh, no certbot, no shell).
//!
//! Every value is a stored setting: the directory (staging / production /
//! custom URL plus an optional extra trust bundle), the challenge (HTTP-01
//! served by patronus-web on its port-80 listener, or DNS-01 through
//! Cloudflare or RFC 2136 with TSIG), renewal window, check interval, retry
//! backoff and the directory the files live in.  The issued chain and key are
//! written atomically (key 0600) under `<certs.dir>/<name>/`; a certificate
//! flagged `use_for_web` is also what the web UI serves (`web.tls_cert` /
//! `web.tls_key` are pointed at it and the listener reloads it in place).
//! Private keys never appear in the API, logs or exports.

use crate::lan;
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use patronus_security::acme::{
    self, AcmeSettings, Challenge, DirectoryKind, DnsProviderConfig, RenewalState,
};
use serde_json::{json, Map, Value};
use sqlx::Row;
use std::path::{Path, PathBuf};

static FIELDS: [Field; 5] = [
    Field::new("dir", "Certificate directory", Kind::Token)
        .def("/var/lib/patronus/certs")
        .help("where issued certificates, keys and ACME account keys are stored (keys mode 0600)"),
    Field::new("check_mins", "Renewal check interval (minutes)", Kind::Int(1, 1440)).def("60"),
    Field::new("retry_mins", "Retry a failed issue after (minutes)", Kind::Int(1, 10080))
        .def("360")
        .help("keeps a broken setup from hammering the CA and hitting its rate limits"),
    Field::new("challenge_iface", "Open port 80 for HTTP-01 on", Kind::Iface)
        .def("@wan")
        .help("while a certificate uses the http-01 challenge the firewall accepts tcp/80 from here, so the CA can reach this router; empty = add no rule (write your own)"),
    Field::new("notify", "Notify when issuing or renewal fails", Kind::Bool).def("1"),
];

static ACME_FIELDS: [Field; 20] = [
    Field::new("name", "Name", Kind::Token)
        .req()
        .help("consumers pick the certificate by this name"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("domains", "Domain names", Kind::Text)
        .req()
        .help(
        "comma separated; the first is the primary name; a wildcard (*.example.org) needs DNS-01",
    ),
    Field::new("email", "Account e-mail", Kind::Text)
        .help("the CA's expiry and problem notices go here"),
    Field::new("tos", "I agree to the CA's terms of service", Kind::Bool).def("0"),
    Field::new(
        "directory",
        "ACME directory",
        Kind::Select(&["staging", "production", "custom"]),
    )
    .def("staging")
    .help("staging issues untrusted test certificates with generous limits: start there"),
    Field::new("directory_url", "Custom directory URL", Kind::Text)
        .help("only for directory = custom (an internal CA, ZeroSSL, Pebble)"),
    Field::new(
        "ca_bundle",
        "Extra CA bundle for the ACME server",
        Kind::Token,
    )
    .help("PEM file path trusted for the ACME server's own TLS (private CAs)"),
    Field::new(
        "challenge",
        "Challenge",
        Kind::Select(&["http-01", "dns-01"]),
    )
    .def("http-01")
    .help("http-01 answers on this router's port 80; dns-01 publishes a TXT record"),
    Field::new(
        "dns_provider",
        "DNS provider (dns-01)",
        Kind::Select(&["none", "cloudflare", "rfc2136"]),
    )
    .def("none"),
    Field::new("cf_token", "Cloudflare API token", Kind::Secret)
        .help("needs Zone:DNS:Edit on the zone"),
    Field::new("cf_api_base", "Cloudflare API base URL", Kind::Text)
        .help("empty = the public Cloudflare API"),
    Field::new("dns_server", "RFC 2136 server (host:port)", Kind::Token),
    Field::new("dns_zone", "RFC 2136 zone", Kind::Host),
    Field::new("tsig_key_name", "TSIG key name", Kind::Token),
    Field::new(
        "tsig_algorithm",
        "TSIG algorithm",
        Kind::Select(&["hmac-sha256", "hmac-sha384", "hmac-sha512"]),
    )
    .def("hmac-sha256"),
    Field::new("tsig_secret", "TSIG secret (base64)", Kind::Secret),
    Field::new(
        "propagation_secs",
        "DNS propagation wait (seconds)",
        Kind::Int(0, 3600),
    )
    .def("5"),
    Field::new(
        "renew_days",
        "Renew when this many days remain",
        Kind::Int(1, 60),
    )
    .def("30"),
    Field::new("use_for_web", "Use for the web interface", Kind::Bool)
        .def("0")
        .help("the web UI serves this certificate and picks up every renewal without a restart"),
];

static SPEC: Spec = Spec {
    slug: "certs",
    title: "Certificates (ACME)",
    blurb: "Certificates this router obtains and renews by itself from Let's Encrypt or any \
            ACME CA: HTTP-01 on port 80, or DNS-01 with Cloudflare or a dynamic-update-capable \
            name server (RFC 2136 + TSIG). Start on the staging directory. A certificate marked \
            for the web interface is served at once and renewed in place.",
    applier: "",
    fields: &FIELDS,
    colls: &[Coll {
        key: "acme",
        title: "ACME certificates",
        table: "acme_certs",
        fields: &ACME_FIELDS,
        unique: Some("name"),
    }],
    actions: &[
        ("issue", "Issue / renew now"),
        ("revoke", "Revoke at the CA"),
        ("status", "Refresh status"),
    ],
};

pub struct CertsSvc;

#[async_trait]
impl Svc for CertsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn get(&self, store: &ConfigStore) -> Result<Value> {
        let st = statuses(store).await.unwrap_or_default();
        let mut list = svc::list_rows(store, &SPEC.colls[0]).await?;
        for r in &mut list {
            let name = r["name"].as_str().unwrap_or("").to_string();
            r["status"] = st.get(&name).cloned().unwrap_or(Value::Null);
        }
        Ok(json!({
            "settings": svc::get_settings(store, &SPEC).await?,
            "collections": { "acme": list },
        }))
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        match name {
            "issue" => match body["name"].as_str() {
                Some(n) => issue(store, n, true).await,
                // the page's button sends no name: every enabled certificate
                None => {
                    let mut done = Vec::new();
                    for r in rows(store).await? {
                        if lan::flag(r["enabled"].as_str().unwrap_or("")) {
                            let n = r["name"].as_str().unwrap_or("");
                            done.push(issue(store, n, true).await?);
                        }
                    }
                    Ok(json!({ "issued": done }))
                }
            },
            "revoke" => {
                let n = body["name"]
                    .as_str()
                    .ok_or_else(|| lan::invalid("request: name of the certificate"))?;
                revoke(store, n).await
            }
            "status" => Ok(json!({ "status": statuses(store).await? })),
            other => Err(lan::invalid(format!("request: no action {other:?}"))),
        }
    }
}

/// Where a certificate's files live.
pub fn cert_dir(dir: &str, name: &str) -> PathBuf {
    Path::new(dir).join(name)
}

pub fn chain_path(dir: &str, name: &str) -> PathBuf {
    cert_dir(dir, name).join("fullchain.pem")
}

pub fn key_path(dir: &str, name: &str) -> PathBuf {
    cert_dir(dir, name).join("key.pem")
}

fn bad_name(n: &str) -> bool {
    n.is_empty() || n.contains('/') || n.contains("..") || n.starts_with('.')
}

/// Build the typed ACME settings from a stored row.
pub fn settings_from_row(r: &Map<String, Value>) -> std::result::Result<AcmeSettings, String> {
    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let b = |k: &str| lan::flag(&s(k));
    let n = |k: &str, d: u64| s(k).parse::<u64>().unwrap_or(d);
    let challenge = match s("challenge").as_str() {
        "dns-01" => Challenge::Dns01,
        _ => Challenge::Http01,
    };
    let dns = if challenge == Challenge::Dns01 {
        match s("dns_provider").as_str() {
            "cloudflare" => Some(DnsProviderConfig::Cloudflare {
                api_token: s("cf_token"),
                api_base: if s("cf_api_base").is_empty() {
                    "https://api.cloudflare.com/client/v4".into()
                } else {
                    s("cf_api_base")
                },
                ttl: 60,
                timeout_secs: 15,
            }),
            "rfc2136" => Some(DnsProviderConfig::Rfc2136 {
                server: s("dns_server"),
                zone: s("dns_zone"),
                tsig_key_name: s("tsig_key_name"),
                tsig_algorithm: s("tsig_algorithm"),
                tsig_secret: s("tsig_secret"),
                ttl: 60,
                timeout_secs: 10,
            }),
            _ => None,
        }
    } else {
        None
    };
    let st = AcmeSettings {
        directory: match s("directory").as_str() {
            "production" => DirectoryKind::Production,
            "custom" => DirectoryKind::Custom,
            _ => DirectoryKind::Staging,
        },
        directory_url: s("directory_url"),
        ca_bundle: Some(s("ca_bundle"))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from),
        email: s("email"),
        terms_of_service_agreed: b("tos"),
        domains: s("domains")
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect(),
        challenge,
        dns,
        dns_propagation_secs: n("propagation_secs", 5),
        renew_days_before: n("renew_days", 30) as u32,
        poll_timeout_secs: 180,
    };
    st.validate().map_err(|e| e.to_string())?;
    Ok(st)
}

async fn rows(store: &ConfigStore) -> Result<Vec<Map<String, Value>>> {
    svc::raw_rows(store, &SPEC.colls[0]).await
}

async fn row(store: &ConfigStore, name: &str) -> Result<Map<String, Value>> {
    rows(store)
        .await?
        .into_iter()
        .find(|r| r["name"].as_str() == Some(name))
        .ok_or_else(|| lan::invalid(format!("request: no certificate named {name:?}")))
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f")
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn io_err(what: &str, e: std::io::Error) -> Error {
    Error::Config(format!("{what}: {e}"))
}

fn sql(e: sqlx::Error) -> Error {
    Error::Config(format!("database: {e}"))
}

async fn set_status(
    store: &ConfigStore,
    name: &str,
    ok: bool,
    err: &str,
    not_after: Option<i64>,
) -> Result<()> {
    let pool = store.pool()?;
    let now = lan::now();
    sqlx::query("INSERT OR IGNORE INTO acme_status (name) VALUES (?)")
        .bind(name)
        .execute(pool)
        .await
        .map_err(sql)?;
    if ok {
        sqlx::query(
            "UPDATE acme_status SET last_attempt=?, last_ok=?, last_error='', attempts_failed=0, \
             not_after=COALESCE(?, not_after) WHERE name=?",
        )
        .bind(now)
        .bind(now)
        .bind(not_after)
        .bind(name)
        .execute(pool)
        .await
        .map_err(sql)?;
    } else {
        sqlx::query(
            "UPDATE acme_status SET last_attempt=?, last_error=?, attempts_failed=attempts_failed+1 WHERE name=?",
        )
        .bind(now)
        .bind(err)
        .bind(name)
        .execute(pool)
        .await
        .map_err(sql)?;
    }
    Ok(())
}

/// Per-certificate state: files present, expiry, last attempt.
pub async fn statuses(store: &ConfigStore) -> Result<Map<String, Value>> {
    let st = Settings::load(store, &SPEC).await?;
    let dir = st.s("dir");
    let pool = store.pool()?;
    let mut db: std::collections::HashMap<String, (i64, i64, String, i64)> = Default::default();
    for r in sqlx::query(
        "SELECT name, last_attempt, last_ok, last_error, attempts_failed FROM acme_status",
    )
    .fetch_all(pool)
    .await
    .map_err(sql)?
    {
        db.insert(
            r.get::<String, _>(0),
            (r.get(1), r.get(2), r.get(3), r.get(4)),
        );
    }
    let now = lan::now();
    let mut out = Map::new();
    for r in rows(store).await? {
        let name = r["name"].as_str().unwrap_or("").to_string();
        let renew = r["renew_days"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let (la, lo, le, nf) = db.get(&name).cloned().unwrap_or_default();
        let pem = std::fs::read_to_string(chain_path(&dir, &name)).ok();
        let state = match &pem {
            None => json!({"state": "none"}),
            Some(p) => match acme::renewal_state(p, renew, now) {
                Ok(s) => serde_json::to_value(s).unwrap_or(Value::Null),
                Err(e) => json!({"state": "unreadable", "error": e.to_string()}),
            },
        };
        out.insert(
            name,
            json!({
                "certificate": state,
                "last_attempt": la,
                "last_ok": lo,
                "last_error": le,
                "failed_attempts": nf,
                "files": pem.is_some(),
            }),
        );
    }
    Ok(out)
}

/// Obtain (or force-renew) the named certificate.  Returns the new status.
pub async fn issue(store: &ConfigStore, name: &str, force: bool) -> Result<Value> {
    if bad_name(name) {
        return Err(lan::invalid("request: bad certificate name"));
    }
    let r = row(store, name).await?;
    let global = Settings::load(store, &SPEC).await?;
    let dir = global.s("dir");
    let settings = settings_from_row(&r).map_err(lan::invalid)?;
    let have = std::fs::read_to_string(chain_path(&dir, name)).ok();
    if !force {
        if let Some(p) = &have {
            if matches!(
                acme::renewal_state(p, settings.renew_days_before, lan::now()),
                Ok(RenewalState::Valid { .. })
            ) {
                return Ok(json!({"name": name, "issued": false, "reason": "still valid"}));
            }
        }
    }
    let acct_path = cert_dir(&dir, name).join("account.json");
    let account = std::fs::read_to_string(&acct_path).ok();
    // a stored account belongs to one directory: a changed directory = new account
    let fp = format!("{:?}|{}", settings.directory, settings.directory_url());
    let fp_path = cert_dir(&dir, name).join("account.directory");
    let account =
        account.filter(|_| std::fs::read_to_string(&fp_path).ok().as_deref() == Some(&fp));

    match acme::issue(&settings, account.as_deref(), acme::global_http01()).await {
        Ok(issued) => {
            write_atomic(&acct_path, issued.account_json.as_bytes(), 0o600)
                .map_err(|e| io_err("write ACME account", e))?;
            write_atomic(&fp_path, fp.as_bytes(), 0o600)
                .map_err(|e| io_err("write account note", e))?;
            // key first, then chain: a reader that sees the new chain always finds its key
            write_atomic(&key_path(&dir, name), issued.key_pem.as_bytes(), 0o600)
                .map_err(|e| io_err("write key", e))?;
            write_atomic(&chain_path(&dir, name), issued.chain_pem.as_bytes(), 0o644)
                .map_err(|e| io_err("write certificate", e))?;
            let na = acme::not_after(&issued.chain_pem).ok();
            set_status(store, name, true, "", na).await?;
            if lan::flag(r["use_for_web"].as_str().unwrap_or("")) {
                point_web_at(store, &dir, name).await?;
            }
            Ok(json!({"name": name, "issued": true, "not_after": na}))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!("ACME issue for {name} failed: {msg}");
            set_status(store, name, false, &msg, None).await.ok();
            Err(Error::Config(format!(
                "ACME issue for {name} failed: {msg}"
            )))
        }
    }
}

/// Revoke the named certificate at its CA.  The files are moved aside
/// (`*.revoked`) so nothing serves the revoked certificate again, the web UI
/// falls back to what it can load, and the next renewal pass requests a new
/// certificate at once.
pub async fn revoke(store: &ConfigStore, name: &str) -> Result<Value> {
    if bad_name(name) {
        return Err(lan::invalid("request: bad certificate name"));
    }
    let r = row(store, name).await?;
    let dir = Settings::load(store, &SPEC).await?.s("dir");
    let settings = settings_from_row(&r).map_err(lan::invalid)?;
    let pem = std::fs::read_to_string(chain_path(&dir, name))
        .map_err(|_| lan::invalid(format!("request: {name} has no issued certificate")))?;
    let account = std::fs::read_to_string(cert_dir(&dir, name).join("account.json"))
        .map_err(|_| Error::Config("the ACME account of this certificate is missing".into()))?;
    acme::revoke(&settings, &account, &pem)
        .await
        .map_err(|e| Error::Config(format!("revocation refused: {e}")))?;
    for f in ["fullchain.pem", "key.pem"] {
        let from = cert_dir(&dir, name).join(f);
        let to = cert_dir(&dir, name).join(format!("{f}.revoked"));
        std::fs::rename(&from, &to).map_err(|e| io_err("set revoked files aside", e))?;
    }
    let pool = store.pool()?;
    sqlx::query("INSERT OR IGNORE INTO acme_status (name) VALUES (?)")
        .bind(name)
        .execute(pool)
        .await
        .map_err(sql)?;
    sqlx::query("UPDATE acme_status SET last_error=?, attempts_failed=0, last_attempt=0, not_after=0 WHERE name=?")
        .bind("revoked at the CA; a replacement is requested on the next renewal pass")
        .bind(name)
        .execute(pool)
        .await
        .map_err(sql)?;
    Ok(json!({"name": name, "revoked": true}))
}

async fn point_web_at(store: &ConfigStore, dir: &str, name: &str) -> Result<()> {
    let cert = chain_path(dir, name).to_string_lossy().into_owned();
    let key = key_path(dir, name).to_string_lossy().into_owned();
    let cur = patronus_config::webui::stored(store).await;
    let get = |k: &str| {
        cur.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    if get(patronus_config::webui::K_TLS_CERT) == cert
        && get(patronus_config::webui::K_TLS_KEY) == key
    {
        return Ok(());
    }
    patronus_config::webui::save(
        store,
        &patronus_config::webui::WebInput {
            tls_cert: Some(cert),
            tls_key: Some(key),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// What one renewal pass did for one certificate.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub use_for_web: bool,
}

/// One pass of the renewal task: issue what has no certificate yet, renew
/// what is inside its window or expired.  A failed certificate is retried
/// after `certs.retry_mins`.  Returns only the certificates it acted on.
pub async fn tick(store: &ConfigStore) -> Vec<Outcome> {
    let mut out = Vec::new();
    let Ok(global) = Settings::load(store, &SPEC).await else {
        return out;
    };
    let retry = global.s("retry_mins").parse::<i64>().unwrap_or(360) * 60;
    let Ok(all) = rows(store).await else {
        return out;
    };
    let st = statuses(store).await.unwrap_or_default();
    for r in all {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        let name = r["name"].as_str().unwrap_or("").to_string();
        if bad_name(&name) {
            continue;
        }
        let web = lan::flag(r["use_for_web"].as_str().unwrap_or(""));
        let s = &st[&name];
        let last = s["last_attempt"].as_i64().unwrap_or(0);
        let failed = s["failed_attempts"].as_i64().unwrap_or(0) > 0;
        if failed && lan::now() - last < retry {
            continue;
        }
        let due = !matches!(s["certificate"]["state"].as_str(), Some("valid"));
        if !due {
            continue;
        }
        match issue(store, &name, false).await {
            Ok(v) if v["issued"].as_bool() == Some(true) => out.push(Outcome {
                name,
                ok: true,
                detail: "certificate issued".into(),
                use_for_web: web,
            }),
            Ok(_) => {}
            Err(e) => out.push(Outcome {
                name,
                ok: false,
                detail: e.to_string(),
                use_for_web: web,
            }),
        }
    }
    out
}

/// Is the page configured at all (any enabled ACME row)?
pub async fn any_enabled(store: &ConfigStore) -> bool {
    rows(store)
        .await
        .map(|r| {
            r.iter()
                .any(|r| lan::flag(r["enabled"].as_str().unwrap_or("")))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> Map<String, Value> {
        let mut m = Map::new();
        for (k, v) in pairs {
            m.insert((*k).into(), Value::String((*v).into()));
        }
        m
    }

    #[test]
    fn row_to_settings_http01() {
        let r = row(&[
            ("domains", "Router.Example.org, b.example.org"),
            ("tos", "1"),
            ("directory", "custom"),
            ("directory_url", "https://ca.test/dir"),
            ("challenge", "http-01"),
            ("renew_days", "20"),
            ("ca_bundle", "/etc/ssl/pebble.pem"),
        ]);
        let s = settings_from_row(&r).unwrap();
        assert_eq!(s.domains, vec!["router.example.org", "b.example.org"]);
        assert_eq!(s.renew_days_before, 20);
        assert_eq!(s.directory_url(), "https://ca.test/dir");
        assert!(s.ca_bundle.is_some());
    }

    #[test]
    fn row_requires_tos_and_provider() {
        assert!(settings_from_row(&row(&[("domains", "a.example.org")])).is_err());
        let r = row(&[
            ("domains", "*.example.org"),
            ("tos", "1"),
            ("challenge", "dns-01"),
            ("dns_provider", "none"),
        ]);
        assert!(settings_from_row(&r).is_err());
        let r = row(&[
            ("domains", "*.example.org"),
            ("tos", "1"),
            ("challenge", "dns-01"),
            ("dns_provider", "rfc2136"),
            ("dns_server", "10.0.0.1:53"),
            ("dns_zone", "example.org"),
        ]);
        assert!(settings_from_row(&r).is_ok());
    }

    #[test]
    fn names_cannot_escape_the_directory() {
        assert!(bad_name("../x"));
        assert!(bad_name("a/b"));
        assert!(bad_name(".hidden"));
        assert!(!bad_name("web-cert"));
    }

    #[test]
    fn atomic_write_modes() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("n/key.pem");
        write_atomic(&p, b"K", 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_atomic(&p, b"K2", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"K2");
    }
}
