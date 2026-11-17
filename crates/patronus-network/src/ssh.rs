//! Managed OpenSSH server (OpenWrt parity: custom port, listen addresses,
//! key-only login, SSH user CA with per-user principals, host certificate).
//!
//! Store (`system_config`, empty/absent = default): `ssh.port` (1-65535,
//! default 22), `ssh.listen` (comma list of interface specs `@lan`, `@optN`,
//! device names, or literal IP addresses; empty = all addresses),
//! `ssh.password_auth` (0/1, default 0), `ssh.root_login`
//! (`prohibit-password` | `yes` | `no`), `ssh.trusted_user_ca_keys`
//! (newline-separated OpenSSH public keys), `ssh.authorized_principals`
//! (JSON object user -> [principals]) and `ssh.host_certificate` (OpenSSH
//! host certificate text for a host key under `/etc/ssh`).
//!
//! Applying: Patronus owns exactly `/etc/ssh/sshd_config.d/50-patronus.conf`
//! and `/etc/ssh/patronus/` (CA keys, per-user principals files, host
//! certificate). The drop-in is validated with `sshd -t` before it replaces
//! the live one and sshd is then reloaded through the init system (OpenRC or
//! systemd). Nothing is touched while no `ssh.*` key was ever stored, so a
//! hand-maintained sshd keeps working until the settings are used. The
//! firewall's anti-lockout rule follows `ssh.port`.

use crate::lan::{self, invalid, LanEnv, ManagedFile};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const SSHD_BIN: &str = "/usr/sbin/sshd";
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
pub const DROPIN: &str = "/etc/ssh/sshd_config.d/50-patronus.conf";
pub const STATE_DIR: &str = "/etc/ssh/patronus";
pub const CA_FILE: &str = "/etc/ssh/patronus/trusted_user_ca_keys";
pub const PRINCIPALS_DIR: &str = "/etc/ssh/patronus/principals";
pub const HOSTCERT_FILE: &str = "/etc/ssh/patronus/host_key-cert.pub";
pub const SERVICE: &str = "sshd";

pub const K_PORT: &str = "ssh.port";
pub const K_LISTEN: &str = "ssh.listen";
pub const K_PASSWORD: &str = "ssh.password_auth";
pub const K_ROOT: &str = "ssh.root_login";
pub const K_CA: &str = "ssh.trusted_user_ca_keys";
pub const K_PRINCIPALS: &str = "ssh.authorized_principals";
pub const K_HOSTCERT: &str = "ssh.host_certificate";
const KEYS: &[&str] = &[
    K_PORT,
    K_LISTEN,
    K_PASSWORD,
    K_ROOT,
    K_CA,
    K_PRINCIPALS,
    K_HOSTCERT,
];

const HOST_KEYS: &[&str] = &[
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_rsa_key",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshSettings {
    pub port: u16,
    pub listen: Vec<String>,
    pub password_auth: bool,
    pub root_login: String,
    pub trusted_user_ca_keys: Vec<String>,
    pub authorized_principals: BTreeMap<String, Vec<String>>,
    /// Whether a host certificate is set (the certificate text is public,
    /// but the API only reports its presence and key id).
    pub host_certificate: String,
}

impl Default for SshSettings {
    fn default() -> Self {
        Self {
            port: 22,
            listen: Vec::new(),
            password_auth: false,
            root_login: "prohibit-password".into(),
            trusted_user_ca_keys: Vec::new(),
            authorized_principals: BTreeMap::new(),
            host_certificate: String::new(),
        }
    }
}

/// Fields of `PUT /api/system/ssh`; absent = unchanged, empty = back to the
/// default / off.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshInput {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub password_auth: Option<bool>,
    #[serde(default)]
    pub root_login: Option<String>,
    #[serde(default)]
    pub trusted_user_ca_keys: Option<String>,
    #[serde(default)]
    pub authorized_principals: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub host_certificate: Option<String>,
}

fn split(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

/// The `ssh.port` the firewall anti-lockout rule must keep open.
pub async fn configured_port(store: &ConfigStore) -> u16 {
    store
        .load_system_config(K_PORT)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p != 0)
        .unwrap_or(22)
}

async fn get(store: &ConfigStore, k: &str) -> Result<String> {
    Ok(store.load_system_config(k).await?.unwrap_or_default())
}

pub async fn settings(store: &ConfigStore) -> Result<SshSettings> {
    let mut s = SshSettings::default();
    let v = get(store, K_PORT).await?;
    if let Ok(p) = v.trim().parse::<u16>() {
        if p != 0 {
            s.port = p;
        }
    }
    s.listen = split(&get(store, K_LISTEN).await?);
    s.password_auth = lan::flag(&get(store, K_PASSWORD).await?);
    let r = get(store, K_ROOT).await?;
    if !r.trim().is_empty() {
        s.root_login = r.trim().to_string();
    }
    s.trusted_user_ca_keys = get(store, K_CA)
        .await?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let p = get(store, K_PRINCIPALS).await?;
    if !p.trim().is_empty() {
        s.authorized_principals = serde_json::from_str(&p)
            .map_err(|e| Error::Config(format!("ssh.authorized_principals is not JSON: {e}")))?;
    }
    s.host_certificate = get(store, K_HOSTCERT).await?.trim().to_string();
    Ok(s)
}

fn check_key_line(what: &str, l: &str, cert: bool) -> Result<String> {
    let l = l.trim();
    let mut it = l.split_whitespace();
    let (Some(ty), Some(b64)) = (it.next(), it.next()) else {
        return Err(invalid(format!(
            "{what}: expected `<type> <base64> [comment]`"
        )));
    };
    let ok_ty = ty.starts_with("ssh-")
        || ty.starts_with("ecdsa-")
        || ty.starts_with("sk-")
        || ty.starts_with("rsa-");
    let is_cert = ty.contains("-cert-v01@openssh.com");
    if !ok_ty || is_cert != cert {
        return Err(invalid(format!(
            "{what}: {ty:?} is not a {}",
            if cert {
                "host certificate"
            } else {
                "public key"
            }
        )));
    }
    if !b64
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return Err(invalid(format!("{what}: bad base64 data")));
    }
    if l.bytes().any(|b| b.is_ascii_control()) {
        return Err(invalid(format!("{what}: control characters")));
    }
    Ok(l.to_string())
}

fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        && !u.starts_with(['-', '.'])
}

fn valid_principal(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && p.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@' | b':' | b'+')
        })
}

/// Validate + store. Nothing is written when anything is invalid.
pub async fn save_settings(store: &ConfigStore, i: &SshInput) -> Result<()> {
    let mut kv: Vec<(&str, String)> = Vec::new();
    if let Some(p) = i.port {
        if p == 0 {
            return Err(invalid("SSH port 0 (use 1-65535)"));
        }
        kv.push((K_PORT, p.to_string()));
    }
    if let Some(l) = &i.listen {
        let mut v = Vec::new();
        for t in split(l) {
            if t.parse::<IpAddr>().is_ok() {
                v.push(t);
            } else {
                v.push(lan::check_iface_spec(&t)?);
            }
        }
        kv.push((K_LISTEN, v.join(",")));
    }
    if let Some(b) = i.password_auth {
        kv.push((K_PASSWORD, if b { "1" } else { "0" }.into()));
    }
    if let Some(r) = &i.root_login {
        let r = r.trim();
        if !r.is_empty() && !matches!(r, "prohibit-password" | "yes" | "no") {
            return Err(invalid(format!(
                "root login {r:?} (prohibit-password, yes or no)"
            )));
        }
        kv.push((K_ROOT, r.to_string()));
    }
    if let Some(c) = &i.trusted_user_ca_keys {
        let v = c
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| check_key_line("trusted user CA key", l, false))
            .collect::<Result<Vec<_>>>()?;
        kv.push((K_CA, v.join("\n")));
    }
    if let Some(p) = &i.authorized_principals {
        for (u, ps) in p {
            if !valid_user(u) {
                return Err(invalid(format!("principals: user name {u:?}")));
            }
            if let Some(bad) = ps.iter().find(|x| !valid_principal(x)) {
                return Err(invalid(format!("principals for {u}: {bad:?}")));
            }
        }
        let doc = if p.is_empty() {
            String::new()
        } else {
            serde_json::to_string(p).unwrap_or_default()
        };
        kv.push((K_PRINCIPALS, doc));
    }
    if let Some(h) = &i.host_certificate {
        let h = h.trim();
        let v = if h.is_empty() {
            String::new()
        } else {
            if h.lines().count() != 1 {
                return Err(invalid("host certificate: exactly one line"));
            }
            check_key_line("host certificate", h, true)?
        };
        kv.push((K_HOSTCERT, v));
    }
    for (k, v) in kv {
        store.save_system_config(k, &v).await?;
    }
    Ok(())
}

/// The raw stored values (for undo after a failed apply).
pub async fn snapshot(store: &ConfigStore) -> Result<Vec<(&'static str, Option<String>)>> {
    let mut v = Vec::new();
    for k in KEYS {
        v.push((*k, store.load_system_config(k).await?));
    }
    Ok(v)
}

pub async fn restore(store: &ConfigStore, snap: &[(&'static str, Option<String>)]) -> Result<()> {
    for (k, v) in snap {
        store
            .save_system_config(k, v.as_deref().unwrap_or(""))
            .await?;
    }
    Ok(())
}

/// What a render needs besides the settings: resolved listen addresses and
/// which host keys exist.
pub struct RenderCtx {
    pub listen_addrs: Vec<String>,
    pub host_keys: Vec<String>,
}

/// `/etc/ssh/sshd_config.d/50-patronus.conf`.
pub fn render(s: &SshSettings, ctx: &RenderCtx) -> String {
    let mut c = lan::header("#", "OpenSSH server drop-in");
    c.push_str(&format!("Port {}\n", s.port));
    for a in &ctx.listen_addrs {
        if a.contains(':') {
            c.push_str(&format!("ListenAddress [{a}]\n"));
        } else {
            c.push_str(&format!("ListenAddress {a}\n"));
        }
    }
    c.push_str("PubkeyAuthentication yes\n");
    if s.password_auth {
        c.push_str("PasswordAuthentication yes\n");
    } else {
        c.push_str("PasswordAuthentication no\nKbdInteractiveAuthentication no\n");
    }
    c.push_str(&format!("PermitRootLogin {}\n", s.root_login));
    if !s.trusted_user_ca_keys.is_empty() {
        c.push_str(&format!("TrustedUserCAKeys {CA_FILE}\n"));
        c.push_str(&format!("AuthorizedPrincipalsFile {PRINCIPALS_DIR}/%u\n"));
    }
    if !s.host_certificate.is_empty() {
        // naming any HostKey disables sshd's implicit defaults: list them all
        for k in &ctx.host_keys {
            c.push_str(&format!("HostKey {k}\n"));
        }
        c.push_str(&format!("HostCertificate {HOSTCERT_FILE}\n"));
    }
    c
}

#[derive(Clone, Default)]
pub struct SshApplier {
    env: LanEnv,
}

impl SshApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    async fn ctx(&self, store: &ConfigStore, s: &SshSettings) -> Result<RenderCtx> {
        let mut addrs: Vec<IpAddr> = Vec::new();
        if !s.listen.is_empty() {
            let live = self.env.addrs()?;
            for spec in &s.listen {
                if let Ok(ip) = spec.parse::<IpAddr>() {
                    addrs.push(ip);
                    continue;
                }
                let devs = lan::resolve_iface(store, spec).await?;
                for a in live.iter().filter(|a| devs.contains(&a.ifname)) {
                    let ll =
                        matches!(a.addr, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
                    if !ll {
                        addrs.push(a.addr);
                    }
                }
            }
            addrs.sort_by_key(|a| (a.is_ipv6(), *a));
            addrs.dedup();
            if addrs.is_empty() {
                // never widen "listen on X" into "listen everywhere"
                return Err(Error::Config(format!(
                    "ssh.listen {:?} resolves to no address (interface down, role unassigned or \
                     no address yet); sshd left as it was",
                    s.listen.join(",")
                )));
            }
        }
        let host_keys = HOST_KEYS
            .iter()
            .filter(|k| self.env.has_binary(k))
            .map(|k| k.to_string())
            .collect();
        Ok(RenderCtx {
            listen_addrs: addrs.iter().map(|a| a.to_string()).collect(),
            host_keys,
        })
    }

    fn write_plain(&self, abs: &str, content: &str, mode: u32) -> Result<bool> {
        use std::os::unix::fs::PermissionsExt;
        let p = self.env.path(abs);
        if std::fs::read_to_string(&p).ok().as_deref() == Some(content) {
            return Ok(false);
        }
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)
                .map_err(|e| Error::Config(format!("create {}: {e}", d.display())))?;
        }
        std::fs::write(&p, content)
            .map_err(|e| Error::Config(format!("write {}: {e}", p.display())))?;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode));
        Ok(true)
    }

    /// The CA file, the per-user principals files and the host certificate;
    /// stale principals files of removed users are deleted.
    fn write_aux(&self, s: &SshSettings) -> Result<bool> {
        let mut changed = false;
        let ca = if s.trusted_user_ca_keys.is_empty() {
            String::new()
        } else {
            format!("{}\n", s.trusted_user_ca_keys.join("\n"))
        };
        changed |= self.write_plain(CA_FILE, &ca, 0o644)?;
        let hc = if s.host_certificate.is_empty() {
            String::new()
        } else {
            format!("{}\n", s.host_certificate)
        };
        changed |= self.write_plain(HOSTCERT_FILE, &hc, 0o644)?;
        let dir = self.env.path(PRINCIPALS_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Config(format!("create {}: {e}", dir.display())))?;
        for (u, ps) in &s.authorized_principals {
            let body = ps.iter().map(|p| format!("{p}\n")).collect::<String>();
            changed |= self.write_plain(&format!("{PRINCIPALS_DIR}/{u}"), &body, 0o644)?;
        }
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if !s.authorized_principals.contains_key(&n) {
                    let _ = std::fs::remove_file(e.path());
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    /// sshd reads drop-ins only through an `Include` line, and the first
    /// value of a keyword wins: make sure the main config includes the
    /// drop-in directory before anything else.
    fn ensure_include(&self, rep: &mut ApplyReport) -> Result<bool> {
        let p = self.env.path(SSHD_CONFIG);
        let cur = std::fs::read_to_string(&p).unwrap_or_default();
        let has = cur.lines().any(|l| {
            let l = l.trim();
            !l.starts_with('#')
                && l.to_ascii_lowercase().starts_with("include")
                && l.contains("sshd_config.d")
        });
        if has {
            return Ok(false);
        }
        let new = format!(
            "# {} (sshd_config.d drop-ins, first so they take precedence)\n\
             Include /etc/ssh/sshd_config.d/*.conf\n\n{cur}",
            lan::MARKER
        );
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).ok();
        }
        let tmp = p.with_file_name(".sshd_config.patronus-new");
        std::fs::write(&tmp, &new)
            .map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
        if self.env.check_configs {
            let o = std::process::Command::new(SSHD_BIN)
                .args(["-t", "-f"])
                .arg(&tmp)
                .output();
            match o {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(Error::Config(format!(
                        "sshd -t rejected {SSHD_CONFIG} with the Include line added: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    )));
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(Error::Config(format!("cannot run sshd: {e}")));
                }
            }
        }
        if let Ok(m) = std::fs::metadata(&p) {
            let _ = std::fs::set_permissions(&tmp, m.permissions());
        }
        std::fs::rename(&tmp, &p)
            .map_err(|e| Error::Config(format!("install {}: {e}", p.display())))?;
        rep.applied(format!("added the sshd_config.d Include to {SSHD_CONFIG}"));
        Ok(true)
    }
}

async fn any_set(store: &ConfigStore) -> Result<bool> {
    for k in KEYS {
        if store
            .load_system_config(k)
            .await?
            .is_some_and(|v| !v.trim().is_empty())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[async_trait]
impl Applier for SshApplier {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let managed = lan::is_managed(&self.env, DROPIN);
        // "was ever set" includes explicit resets back to defaults
        let touched = any_set(store).await? || managed || {
            let mut t = false;
            for k in KEYS {
                t |= store.load_system_config(k).await?.is_some();
            }
            t
        };
        if !touched {
            rep.applied("SSH server not managed by Patronus (sshd config untouched)");
            return Ok(rep);
        }
        if !self.env.has_binary(SSHD_BIN) {
            return Err(Error::Service(
                "the SSH server settings need OpenSSH but /usr/sbin/sshd is not installed \
                 (emerge net-misc/openssh)"
                    .into(),
            ));
        }
        let s = settings(store).await?;
        let ctx = self.ctx(store, &s).await?;
        let mut changed = self.ensure_include(&mut rep)?;
        changed |= self.write_aux(&s)?;
        if lan::install(
            &self.env,
            &ManagedFile {
                path: DROPIN,
                content: render(&s, &ctx),
                mode: 0o644,
                group: None,
                check: Some(vec![SSHD_BIN, "-t", "-f", "{}"]),
            },
        )? {
            rep.applied(format!("wrote {DROPIN}"));
            changed = true;
        }
        if changed || !self.env.services.is_running(SERVICE) {
            self.env.services.reload(SERVICE)?;
            rep.applied("sshd reloaded with the new config");
        } else {
            rep.applied("sshd running, config unchanged");
        }
        rep.applied(format!(
            "SSH on port {}{}",
            s.port,
            if ctx.listen_addrs.is_empty() {
                " (all addresses)".to_string()
            } else {
                format!(", listening on {}", ctx.listen_addrs.join(", "))
            }
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        if !any_set(store).await? {
            return Ok("# SSH server not managed\n".into());
        }
        let s = settings(store).await?;
        let ctx = self.ctx(store, &s).await?;
        Ok(format!("## {DROPIN}\n{}", render(&s, &ctx)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        Ok(json!({
            "managed": lan::is_managed(&self.env, DROPIN),
            "available": self.env.has_binary(SSHD_BIN),
            "running": self.env.services.is_running(SERVICE),
            "port": s.port,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;

    const CA: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestonlytestonlytestonlytestonlytestonly ca@example.com";
    const HC: &str =
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxtest host@example.com";

    #[tokio::test]
    async fn untouched_store_leaves_sshd_alone() {
        let t = testutil::env(&[SSHD_BIN]);
        let s = testutil::store().await;
        let a = SshApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert!(t.services.log.lock().unwrap().is_empty());
        assert!(!t.env.path(DROPIN).exists());
    }

    #[tokio::test]
    async fn renders_port_listen_ca_principals_and_cert() {
        let t = testutil::env(&[SSHD_BIN, "/etc/ssh/ssh_host_ed25519_key"]);
        let s = testutil::store().await;
        let mut pr = BTreeMap::new();
        pr.insert(
            "root".to_string(),
            vec!["admin".to_string(), "ops".to_string()],
        );
        save_settings(
            &s,
            &SshInput {
                port: Some(2222),
                listen: Some("@lan, 198.51.100.7, rtr-lan".into()),
                trusted_user_ca_keys: Some(format!("{CA}\n\n# comment\n")),
                authorized_principals: Some(pr),
                host_certificate: Some(HC.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = SshApplier::new(t.env.clone());
        let rep = a.apply(&s).await.unwrap();
        assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
        let d = testutil::read(&t, DROPIN);
        assert!(d.contains("Port 2222\n"), "{d}");
        assert!(d.contains("ListenAddress 192.168.50.1\n"));
        assert!(d.contains("ListenAddress 198.51.100.7\n"));
        assert!(d.contains("ListenAddress [fd00:50::1]\n"));
        assert!(!d.contains("fe80"), "link-local not listened on: {d}");
        assert!(!d.contains("203.0.113.2"), "wan address must not appear");
        assert!(d.contains("PasswordAuthentication no\n"));
        assert!(d.contains("PermitRootLogin prohibit-password\n"));
        assert!(d.contains("TrustedUserCAKeys /etc/ssh/patronus/trusted_user_ca_keys\n"));
        assert!(d.contains("AuthorizedPrincipalsFile /etc/ssh/patronus/principals/%u\n"));
        assert!(d.contains("HostKey /etc/ssh/ssh_host_ed25519_key\n"));
        assert!(d.contains("HostCertificate /etc/ssh/patronus/host_key-cert.pub\n"));
        assert_eq!(testutil::read(&t, CA_FILE), format!("{CA}\n"));
        assert_eq!(
            testutil::read(&t, "/etc/ssh/patronus/principals/root"),
            "admin\nops\n"
        );
        assert_eq!(testutil::read(&t, HOSTCERT_FILE), format!("{HC}\n"));
        assert!(testutil::read(&t, SSHD_CONFIG).contains("Include /etc/ssh/sshd_config.d/*.conf"));
        assert_eq!(t.services.log.lock().unwrap().as_slice(), ["reload sshd"]);

        // unchanged config: no second reload; removed user's file is deleted
        a.apply(&s).await.unwrap();
        assert_eq!(t.services.log.lock().unwrap().len(), 1);
        save_settings(
            &s,
            &SshInput {
                authorized_principals: Some(BTreeMap::new()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!t.env.path("/etc/ssh/patronus/principals/root").exists());
        assert_eq!(t.services.log.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn password_login_and_root_policy() {
        let s = testutil::store().await;
        save_settings(
            &s,
            &SshInput {
                password_auth: Some(true),
                root_login: Some("no".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let st = settings(&s).await.unwrap();
        let out = render(
            &st,
            &RenderCtx {
                listen_addrs: vec![],
                host_keys: vec![],
            },
        );
        assert!(out.contains("PasswordAuthentication yes\n"));
        assert!(!out.contains("ListenAddress"));
        assert!(out.contains("PermitRootLogin no\n"));
        let d = render(
            &SshSettings::default(),
            &RenderCtx {
                listen_addrs: vec![],
                host_keys: vec![],
            },
        );
        assert!(d.contains("Port 22\n") && d.contains("PasswordAuthentication no\n"));
    }

    #[tokio::test]
    async fn invalid_input_is_refused_and_stores_nothing() {
        let s = testutil::store().await;
        for bad in [
            SshInput {
                port: Some(0),
                ..Default::default()
            },
            SshInput {
                listen: Some("eth0\nPermitEmptyPasswords yes".into()),
                ..Default::default()
            },
            SshInput {
                root_login: Some("forced-commands-only".into()),
                ..Default::default()
            },
            SshInput {
                trusted_user_ca_keys: Some("ssh-ed25519-cert-v01@openssh.com AAAA x".into()),
                ..Default::default()
            },
            SshInput {
                trusted_user_ca_keys: Some("not a key".into()),
                ..Default::default()
            },
            SshInput {
                host_certificate: Some(CA.into()),
                ..Default::default()
            },
            SshInput {
                authorized_principals: Some(BTreeMap::from([(
                    "root".to_string(),
                    vec!["a b".to_string()],
                )])),
                ..Default::default()
            },
            SshInput {
                authorized_principals: Some(BTreeMap::from([(
                    "../x".to_string(),
                    vec!["a".to_string()],
                )])),
                ..Default::default()
            },
        ] {
            let e = save_settings(&s, &bad).await.unwrap_err().to_string();
            assert!(e.contains("Invalid") || e.contains("invalid"), "{e}");
        }
        assert!(s.load_system_config(K_PORT).await.unwrap().is_none());
        assert_eq!(configured_port(&s).await, 22);
    }

    #[tokio::test]
    async fn listen_that_resolves_to_nothing_is_an_error_not_all_addresses() {
        let t = testutil::env(&[SSHD_BIN]);
        let s = testutil::store().await;
        save_settings(
            &s,
            &SshInput {
                listen: Some("@opt7".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = SshApplier::new(t.env.clone());
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("resolves to no address"), "{e}");
        assert!(!t.env.path(DROPIN).exists());
        assert!(t.services.log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn snapshot_restore_roundtrip_and_port_helper() {
        let s = testutil::store().await;
        let snap = snapshot(&s).await.unwrap();
        save_settings(
            &s,
            &SshInput {
                port: Some(2200),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(configured_port(&s).await, 2200);
        restore(&s, &snap).await.unwrap();
        assert_eq!(configured_port(&s).await, 22);
    }
}
