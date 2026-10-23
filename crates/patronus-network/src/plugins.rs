//! Signed plugins (USE=plugins): extension bundles an operator installs,
//! updates and removes from the Packages page or `patronus plugin`.
//!
//! A bundle is one JSON file: `{"manifest": "<json text>", "key_id": "...",
//! "signature": "<base64 ed25519 over the manifest text>"}`. The manifest
//! carries the plugin's files (base64 content + sha256) and an optional
//! supervised service. Nothing is installed unless the signature verifies
//! against a *trusted key* (added on the Packages page or dropped into
//! `/etc/patronus/plugin-keys.d/*.pub`), every file matches its digest, the
//! paths stay inside the plugin directory, and an update has a higher version
//! than the one installed (no downgrade). The bundle is kept in the store and
//! re-verified at every `patronus apply`: removing a key (or a file changed
//! on disk) stops the plugin. A plugin's service runs as root under the
//! supervisor (OpenRC/systemd), so only trust keys you control.

use crate::lan;
use crate::supervise::Supervisor;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::path::{Path, PathBuf};

pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const KEY_DIR: &str = "/etc/patronus/plugin-keys.d";
const SVC_PREFIX: &str = "plugin-";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub mode: u32,
    pub sha256: String,
    /// base64 content
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// argv; `exec[0]` is a path inside the plugin directory
    pub exec: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "tcp")]
    pub proto: String,
    /// "lan" opens `port` on the LAN interfaces; "none" opens nothing
    #[serde(default = "none")]
    pub expose: String,
}
fn tcp() -> String {
    "tcp".into()
}
fn none() -> String {
    "none".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub service: Option<Service>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    manifest: String,
    key_id: String,
    signature: String,
}

fn invalid(m: impl Into<String>) -> Error {
    lan::invalid(m.into())
}

pub fn key_id(public_b64: &str) -> String {
    let d = Sha256::digest(public_b64.trim().as_bytes());
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// (secret key, public key), both base64.
pub fn keygen() -> (String, String) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    (B64.encode(seed), B64.encode(sk.verifying_key().to_bytes()))
}

fn parse_public(p: &str) -> Result<VerifyingKey> {
    let raw = B64
        .decode(p.trim())
        .map_err(|_| invalid("public key: not base64"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| invalid("public key: 32 bytes expected"))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| invalid("public key: not a valid ed25519 key"))
}

pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 31
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// "1", "1.2" or "1.2.3" -> comparable tuple.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let mut n = [0u64; 3];
    for slot in n.iter_mut() {
        match it.next() {
            Some(p) if !p.is_empty() && p.len() <= 9 && p.bytes().all(|c| c.is_ascii_digit()) => {
                *slot = p.parse().ok()?
            }
            Some(_) => return None,
            None => break,
        }
    }
    if it.next().is_some() || v.is_empty() {
        return None;
    }
    Some((n[0], n[1], n[2]))
}

fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 200
        && !p.starts_with('/')
        && p.split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.starts_with('.'))
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// Check a manifest on its own (what a signature cannot vouch for).
pub fn check_manifest(m: &Manifest) -> Result<()> {
    if !valid_name(&m.name) {
        return Err(invalid(format!(
            "plugin name {:?}: lowercase letters, digits and '-', starting with a letter, at most 31",
            m.name
        )));
    }
    if parse_version(&m.version).is_none() {
        return Err(invalid(format!(
            "plugin version {:?}: use 1, 1.2 or 1.2.3",
            m.version
        )));
    }
    let mut total = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for f in &m.files {
        if !safe_rel(&f.path) {
            return Err(invalid(format!(
                "file path {:?} is not a plain relative path",
                f.path
            )));
        }
        if !seen.insert(&f.path) {
            return Err(invalid(format!("file {:?} listed twice", f.path)));
        }
        if !matches!(f.mode, 0o644 | 0o755 | 0o600 | 0o700) {
            return Err(invalid(format!(
                "file {:?}: mode must be 644, 755, 600 or 700",
                f.path
            )));
        }
        let data = B64
            .decode(&f.data)
            .map_err(|_| invalid(format!("file {:?}: content is not base64", f.path)))?;
        total += data.len();
        if total > MAX_BUNDLE_BYTES {
            return Err(invalid("plugin files exceed 16 MiB"));
        }
        let want = format!("{:x}", Sha256::digest(&data));
        if want != f.sha256.to_ascii_lowercase() {
            return Err(invalid(format!(
                "file {:?}: sha256 does not match its content",
                f.path
            )));
        }
    }
    if let Some(s) = &m.service {
        let Some(first) = s.exec.first() else {
            return Err(invalid("service.exec is empty"));
        };
        if !safe_rel(first)
            || !m
                .files
                .iter()
                .any(|f| &f.path == first && f.mode & 0o100 != 0)
        {
            return Err(invalid(
                "service.exec[0] must be an executable file shipped in the plugin",
            ));
        }
        if s.exec.len() > 32 || s.exec.iter().any(|a| a.len() > 256 || a.contains('\0')) {
            return Err(invalid("service.exec: too many or too long arguments"));
        }
        if !matches!(s.proto.as_str(), "tcp" | "udp")
            || !matches!(s.expose.as_str(), "lan" | "none")
        {
            return Err(invalid(
                "service: proto is tcp or udp, expose is lan or none",
            ));
        }
        if s.expose == "lan" && !s.port.is_some_and(|p| p >= 1024) {
            return Err(invalid(
                "service: exposing to the LAN needs a port of 1024 or more",
            ));
        }
    }
    Ok(())
}

/// A signed bundle from a plugin directory: `plugin.json` (name, version,
/// description, author, service) plus everything under `files/`.
pub fn pack(dir: &Path, secret_b64: &str) -> Result<String> {
    let io = |e: std::io::Error| Error::Config(format!("{}: {e}", dir.display()));
    let head: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("plugin.json")).map_err(io)?)
            .map_err(|e| invalid(format!("plugin.json: {e}")))?;
    let mut files = Vec::new();
    fn walk(base: &Path, cur: &Path, out: &mut Vec<FileEntry>) -> std::io::Result<()> {
        let mut es: Vec<_> = std::fs::read_dir(cur)?.collect::<std::result::Result<_, _>>()?;
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else {
                use std::os::unix::fs::PermissionsExt;
                let data = std::fs::read(&p)?;
                let mode = if p.metadata()?.permissions().mode() & 0o100 != 0 {
                    0o755
                } else {
                    0o644
                };
                out.push(FileEntry {
                    path: p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                    mode,
                    sha256: format!("{:x}", Sha256::digest(&data)),
                    data: B64.encode(&data),
                });
            }
        }
        Ok(())
    }
    let fdir = dir.join("files");
    if fdir.is_dir() {
        walk(&fdir, &fdir, &mut files).map_err(io)?;
    }
    let mut m: Manifest =
        serde_json::from_value(head).map_err(|e| invalid(format!("plugin.json: {e}")))?;
    m.files = files;
    check_manifest(&m)?;
    let text = serde_json::to_string(&m).map_err(|e| Error::Config(e.to_string()))?;
    let seed: [u8; 32] = B64
        .decode(secret_b64.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| invalid("secret key: 32 bytes, base64"))?;
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(text.as_bytes());
    let pub_b64 = B64.encode(sk.verifying_key().to_bytes());
    serde_json::to_string_pretty(&Bundle {
        manifest: text,
        key_id: key_id(&pub_b64),
        signature: B64.encode(sig.to_bytes()),
    })
    .map_err(|e| Error::Config(e.to_string()))
}

/// Verify a bundle against `trusted` (key id, public key b64). Returns the
/// manifest and the id of the key that signed it.
pub fn verify(bundle: &str, trusted: &[(String, String)]) -> Result<(Manifest, String)> {
    if bundle.len() > MAX_BUNDLE_BYTES * 2 {
        return Err(invalid("bundle is too large"));
    }
    let b: Bundle =
        serde_json::from_str(bundle).map_err(|e| invalid(format!("not a plugin bundle: {e}")))?;
    let (_, public) = trusted
        .iter()
        .find(|(id, _)| *id == b.key_id)
        .ok_or_else(|| invalid(format!("signed by key {}, which is not trusted", b.key_id)))?;
    let vk = parse_public(public)?;
    let sig: [u8; 64] = B64
        .decode(&b.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| invalid("signature is malformed"))?;
    vk.verify(b.manifest.as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| {
            invalid("the signature does not match the contents (tampered or wrong key)")
        })?;
    let m: Manifest =
        serde_json::from_str(&b.manifest).map_err(|e| invalid(format!("manifest: {e}")))?;
    check_manifest(&m)?;
    Ok((m, b.key_id))
}

// ---------------------------------------------------------------- store

pub async fn trusted_keys(store: &ConfigStore) -> Result<Vec<(String, String)>> {
    let mut v: Vec<(String, String)> = sqlx::query("SELECT key_id, public_key FROM plugin_keys")
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read plugin_keys: {e}")))?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let dir = std::env::var_os("PATRONUS_PLUGIN_KEYS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(KEY_DIR));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().extension().is_some_and(|x| x == "pub") {
                if let Ok(t) = std::fs::read_to_string(e.path()) {
                    let t = t.trim().to_string();
                    if parse_public(&t).is_ok() {
                        v.push((key_id(&t), t));
                    }
                }
            }
        }
    }
    Ok(v)
}

pub async fn add_key(store: &ConfigStore, label: &str, public: &str) -> Result<String> {
    let public = public.trim();
    parse_public(public)?;
    let label = label.trim();
    if label.is_empty() || label.len() > 60 || label.chars().any(|c| c.is_control()) {
        return Err(invalid("label: 1-60 printable characters"));
    }
    let id = key_id(public);
    sqlx::query("INSERT OR REPLACE INTO plugin_keys (key_id, label, public_key, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(label)
        .bind(public)
        .bind(chrono::Utc::now().timestamp())
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("save key: {e}")))?;
    Ok(id)
}

pub async fn delete_key(store: &ConfigStore, id: &str) -> Result<bool> {
    Ok(sqlx::query("DELETE FROM plugin_keys WHERE key_id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("delete key: {e}")))?
        .rows_affected()
        > 0)
}

pub fn plugins_dir(sup: &Supervisor) -> PathBuf {
    sup.paths.state_dir.join("plugins")
}

/// Verify and install (or update) a bundle: files under
/// `<plugins>/<name>/<version>/`, the bundle in the store. A plugin that is
/// already installed must be updated to a HIGHER version.
pub async fn install(
    store: &ConfigStore,
    sup: &Supervisor,
    bundle: &str,
) -> Result<(Manifest, bool)> {
    let keys = trusted_keys(store).await?;
    let (m, kid) = verify(bundle, &keys)?;
    let old = sqlx::query("SELECT version FROM plugins WHERE name = ?")
        .bind(&m.name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read plugins: {e}")))?
        .map(|r| r.get::<String, _>(0));
    if let Some(o) = &old {
        if parse_version(&m.version) <= parse_version(o) {
            return Err(invalid(format!(
                "{} {} is not newer than the installed {o} (downgrades and reinstalls are refused)",
                m.name, m.version
            )));
        }
    }
    let base = plugins_dir(sup).join(&m.name);
    let dest = base.join(&m.version);
    write_files(&m, &dest)?;
    sqlx::query(
        "INSERT INTO plugins (name, version, key_id, enabled, bundle, installed_at, expose_proto, expose_port)
         VALUES (?, ?, ?, 1, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET version = excluded.version, key_id = excluded.key_id,
             bundle = excluded.bundle, installed_at = excluded.installed_at,
             expose_proto = excluded.expose_proto, expose_port = excluded.expose_port",
    )
    .bind(&m.name)
    .bind(&m.version)
    .bind(&kid)
    .bind(bundle)
    .bind(chrono::Utc::now().timestamp())
    .bind(exposure(&m).0)
    .bind(exposure(&m).1)
    .execute(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("save plugin: {e}")))?;
    prune_versions(&base, &m.version);
    Ok((m, old.is_some()))
}

/// (proto, port) the firewall opens on the LAN for this plugin; port 0 = none.
fn exposure(m: &Manifest) -> (String, i64) {
    match &m.service {
        Some(s) if s.expose == "lan" => (s.proto.clone(), i64::from(s.port.unwrap_or(0))),
        _ => ("tcp".into(), 0),
    }
}

async fn set_exposure(store: &ConfigStore, name: &str, m: Option<&Manifest>) {
    let (proto, port) = m.map(exposure).unwrap_or(("tcp".into(), 0));
    if let Ok(pool) = store.pool() {
        let _ = sqlx::query("UPDATE plugins SET expose_proto = ?, expose_port = ? WHERE name = ?")
            .bind(proto)
            .bind(port)
            .bind(name)
            .execute(pool)
            .await;
    }
}

fn write_files(m: &Manifest, dest: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let io = |e: std::io::Error| Error::Config(format!("{}: {e}", dest.display()));
    let _ = std::fs::remove_dir_all(dest);
    std::fs::create_dir_all(dest).map_err(io)?;
    for f in &m.files {
        let p = dest.join(&f.path);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(io)?;
        }
        let data = B64.decode(&f.data).unwrap_or_default();
        std::fs::write(&p, data).map_err(io)?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(f.mode)).map_err(io)?;
    }
    Ok(())
}

fn prune_versions(base: &Path, keep: &str) {
    if let Ok(rd) = std::fs::read_dir(base) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy() != keep {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

pub async fn remove(store: &ConfigStore, sup: &Supervisor, name: &str) -> Result<bool> {
    let n = sqlx::query("DELETE FROM plugins WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("delete plugin: {e}")))?
        .rows_affected();
    if valid_name(name) {
        let _ = std::fs::remove_dir_all(plugins_dir(sup).join(name));
    }
    Ok(n > 0)
}

pub async fn set_enabled(store: &ConfigStore, name: &str, on: bool) -> Result<bool> {
    Ok(sqlx::query("UPDATE plugins SET enabled = ? WHERE name = ?")
        .bind(on as i64)
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("update plugin: {e}")))?
        .rows_affected()
        > 0)
}

/// One installed plugin as the API shows it.
pub async fn list(store: &ConfigStore, sup: &Supervisor) -> Result<Vec<Value>> {
    let keys = trusted_keys(store).await?;
    let rows = sqlx::query(
        "SELECT name, version, key_id, enabled, bundle, installed_at FROM plugins ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("read plugins: {e}")))?;
    Ok(rows
        .iter()
        .map(|r| {
            let name: String = r.get(0);
            let bundle: String = r.get(4);
            let (m, trust) = match verify(&bundle, &keys) {
                Ok((m, _)) => (Some(m), "verified".to_string()),
                Err(e) => (None, e.to_string()),
            };
            let running = m.as_ref().is_some_and(|m| m.service.is_some())
                && sup.is_running(crate::svc::DAEMON_SERVICE, &format!("{SVC_PREFIX}{name}"));
            json!({
                "name": name, "version": r.get::<String,_>(1), "key_id": r.get::<String,_>(2),
                "enabled": r.get::<i64,_>(3) != 0, "installed_at": r.get::<i64,_>(5),
                "description": m.as_ref().map(|m| m.description.clone()).unwrap_or_default(),
                "author": m.as_ref().map(|m| m.author.clone()).unwrap_or_default(),
                "service": m.as_ref().and_then(|m| m.service.clone()),
                "trust": trust, "running": running,
            })
        })
        .collect())
}

fn files_intact(m: &Manifest, dir: &Path) -> Option<String> {
    for f in &m.files {
        match std::fs::read(dir.join(&f.path)) {
            Ok(d) if format!("{:x}", Sha256::digest(&d)) == f.sha256.to_ascii_lowercase() => {}
            Ok(_) => return Some(format!("{} changed on disk", f.path)),
            Err(e) => return Some(format!("{}: {e}", f.path)),
        }
    }
    None
}

#[derive(Clone)]
pub struct PluginsApplier {
    sup: Supervisor,
}

impl Default for PluginsApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl PluginsApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

#[async_trait]
impl Applier for PluginsApplier {
    fn name(&self) -> &'static str {
        "plugins"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let keys = trusted_keys(store).await?;
        let rows = sqlx::query("SELECT name, enabled, bundle FROM plugins ORDER BY name")
            .fetch_all(store.pool()?)
            .await
            .map_err(|e| Error::Config(format!("read plugins: {e}")))?;
        let mut keep = Vec::new();
        for r in rows {
            let name: String = r.get(0);
            if r.get::<i64, _>(1) == 0 {
                set_exposure(store, &name, None).await;
                rep.applied(format!("plugin {name} is disabled"));
                continue;
            }
            let m = match verify(&r.get::<String, _>(2), &keys) {
                Ok((m, _)) => m,
                Err(e) => {
                    set_exposure(store, &name, None).await;
                    rep.warn(format!("plugin {name} not started: {e}"));
                    continue;
                }
            };
            let dir = plugins_dir(&self.sup).join(&name).join(&m.version);
            if let Some(why) = files_intact(&m, &dir) {
                set_exposure(store, &name, None).await;
                rep.warn(format!("plugin {name} not started: {why}"));
                continue;
            }
            set_exposure(store, &name, Some(&m)).await;
            let Some(s) = &m.service else {
                rep.applied(format!("plugin {name} {} installed", m.version));
                continue;
            };
            let mut argv: Vec<String> = s.exec.clone();
            argv[0] = dir.join(&s.exec[0]).to_string_lossy().into_owned();
            let inst = format!("{SVC_PREFIX}{name}");
            let started = crate::svc::ensure_daemon(&self.sup, &inst, argv, Vec::new()).await?;
            keep.push(inst);
            rep.applied(format!(
                "plugin {name} {} {}",
                m.version,
                if started {
                    "(re)started"
                } else {
                    "running, unchanged"
                }
            ));
        }
        for s in crate::svc::stop_daemons(&self.sup, SVC_PREFIX, &keep).await? {
            rep.applied(format!("stopped {s}"));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(format!(
            "# {} plugin(s) installed\n",
            list(store, &self.sup).await?.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(dir: &Path, version: &str, body: &str) {
        std::fs::create_dir_all(dir.join("files/bin")).unwrap();
        std::fs::write(
            dir.join("plugin.json"),
            format!(
                r#"{{"name":"hello","version":"{version}","description":"d","author":"a",
                "service":{{"exec":["bin/run"],"port":18099,"proto":"tcp","expose":"lan"}}}}"#
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("files/bin/run");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn signed_bundles_verify_and_tampering_is_caught() {
        let d = tempfile::tempdir().unwrap();
        make(d.path(), "1.0.0", "#!/bin/sh\nexit 0\n");
        let (sec, public) = keygen();
        let bundle = pack(d.path(), &sec).unwrap();
        let trusted = vec![(key_id(&public), public.clone())];
        let (m, kid) = verify(&bundle, &trusted).unwrap();
        assert_eq!((m.name.as_str(), m.version.as_str()), ("hello", "1.0.0"));
        assert_eq!(kid, key_id(&public));
        // not trusted
        assert!(verify(&bundle, &[])
            .unwrap_err()
            .to_string()
            .contains("not trusted"));
        // another key's claim
        let (_, other) = keygen();
        let forged = bundle.replace(&key_id(&public), &key_id(&other));
        assert!(verify(&forged, &[(key_id(&other), other)]).is_err());
        // content changed after signing (manifest text edited)
        let tampered = bundle.replace("hello", "hellp");
        assert!(verify(&tampered, &trusted)
            .unwrap_err()
            .to_string()
            .contains("signature"));
    }

    #[test]
    fn manifests_are_checked_beyond_the_signature() {
        let mk = |path: &str, mode: u32| Manifest {
            name: "x".into(),
            version: "1".into(),
            description: String::new(),
            author: String::new(),
            files: vec![FileEntry {
                path: path.into(),
                mode,
                sha256: format!("{:x}", Sha256::digest(b"a")),
                data: B64.encode(b"a"),
            }],
            service: None,
        };
        assert!(check_manifest(&mk("bin/a", 0o755)).is_ok());
        for bad in ["../x", "/etc/passwd", "a//b", ".hidden", "a/./b", ""] {
            assert!(check_manifest(&mk(bad, 0o644)).is_err(), "{bad}");
        }
        assert!(check_manifest(&mk("a", 0o4755)).is_err());
        let mut m = mk("a", 0o644);
        m.files[0].sha256 = "00".into();
        assert!(check_manifest(&m).is_err());
        let mut m = mk("a", 0o755);
        m.service = Some(Service {
            exec: vec!["/bin/sh".into()],
            port: None,
            proto: "tcp".into(),
            expose: "none".into(),
        });
        assert!(check_manifest(&m).is_err(), "exec outside the plugin");
        assert!(parse_version("1.10.0") > parse_version("1.9.9"));
        assert!(parse_version("1.0.0") <= parse_version("1"));
        assert!(parse_version("1.x").is_none());
        assert!(!valid_name("Bad") && !valid_name("1a") && valid_name("a-b1"));
    }

    #[tokio::test]
    async fn install_update_downgrade_and_key_revocation() {
        let d = tempfile::tempdir().unwrap();
        let store = ConfigStore::open_in_memory().await.unwrap();
        let sup = Supervisor::new(
            crate::supervise::InitMode::Direct,
            crate::supervise::NetPaths::under(d.path()),
        );
        let (sec, public) = keygen();
        let src = d.path().join("src");
        make(&src, "1.0.0", "#!/bin/sh\nexit 0\n");
        let b1 = pack(&src, &sec).unwrap();
        assert!(
            install(&store, &sup, &b1).await.is_err(),
            "no trusted key yet"
        );
        add_key(&store, "test", &public).await.unwrap();
        let (m, updated) = install(&store, &sup, &b1).await.unwrap();
        assert_eq!((m.version.as_str(), updated), ("1.0.0", false));
        assert!(plugins_dir(&sup).join("hello/1.0.0/bin/run").exists());
        assert!(
            install(&store, &sup, &b1).await.is_err(),
            "same version refused"
        );
        make(&src, "1.1.0", "#!/bin/sh\nexit 1\n");
        let b2 = pack(&src, &sec).unwrap();
        let (_, updated) = install(&store, &sup, &b2).await.unwrap();
        assert!(updated);
        assert!(plugins_dir(&sup).join("hello/1.1.0").exists());
        assert!(
            !plugins_dir(&sup).join("hello/1.0.0").exists(),
            "old version pruned"
        );
        assert!(
            install(&store, &sup, &b1).await.is_err(),
            "downgrade refused"
        );
        let port = || async {
            sqlx::query("SELECT expose_port FROM plugins WHERE name = 'hello'")
                .fetch_one(store.pool().unwrap())
                .await
                .unwrap()
                .get::<i64, _>(0)
        };
        assert_eq!(port().await, 18099);
        delete_key(&store, &key_id(&public)).await.unwrap();
        let rep = PluginsApplier::with_supervisor(sup.clone())
            .apply(&store)
            .await
            .unwrap();
        assert!(
            rep.warnings.iter().any(|w| w.contains("not trusted")),
            "{:?}",
            rep.warnings
        );
        assert_eq!(port().await, 0, "no trust, no exposure");
        let l = list(&store, &sup).await.unwrap();
        assert!(l[0]["trust"].as_str().unwrap().contains("not trusted"));
        assert!(remove(&store, &sup, "hello").await.unwrap());
        assert!(!plugins_dir(&sup).join("hello").exists());
    }
}
