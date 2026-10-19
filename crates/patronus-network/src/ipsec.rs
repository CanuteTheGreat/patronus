//! IPsec (lane F): IKEv2 site-to-site tunnels with pre-shared keys,
//! configured through strongSwan's swanctl (VICI), the modern interface
//! (the old module generated a legacy ipsec.conf and was never reachable).
//!
//! - The store's `ipsec_tunnels` become `/etc/swanctl/conf.d/patronus.conf`
//!   (0600, marked as Patronus-owned), which the stock `swanctl.conf`
//!   includes (`include conf.d/*.conf`). Nothing else under /etc/swanctl is
//!   touched.
//! - charon is started through the distro's own service (Gentoo: OpenRC
//!   `ipsec`, systemd `strongswan`; elsewhere `strongswan-swanctl` where
//!   that exists) via [`crate::lan::ServiceControl`], then `swanctl --load-all`
//!   loads the connections and secrets and unloads deleted ones, without
//!   restarting charon (other tunnels stay up). With no tunnel left the
//!   service is stopped again, but only while our file is the managed one.
//! - Live SAs (`swanctl --list-sas`) are read as root in [`IpsecApplier`]'s
//!   status, so the unprivileged web UI sees them through `patronus applyd`.
//! - Firewall: IKE/ESP and the tunnel's traffic are allowed and exempt from
//!   outbound NAT by `patronus_firewall::vpn_rules`.

use crate::lan::{self, check_description, db_err, invalid, now, LanEnv, ManagedFile};
use crate::vpn::{check_host, check_networks, split_list};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

pub const SWANCTL_CONF: &str = "/etc/swanctl/conf.d/patronus.conf";
pub const SWANCTL_BIN: &str = "/usr/sbin/swanctl";
/// Prefix of every connection name Patronus loads into charon.
pub const CONN_PREFIX: &str = "patronus-";

pub const DEFAULT_IKE: &str = "aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048";
pub const DEFAULT_ESP: &str = "aes256gcm16-ecp384,aes256-sha256-modp2048";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpsecTunnel {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub local_address: Option<String>,
    pub remote_address: String,
    pub local_id: Option<String>,
    pub remote_id: Option<String>,
    #[serde(skip_serializing, default)]
    pub psk: String,
    pub local_ts: String,
    pub remote_ts: String,
    pub ike_proposals: String,
    pub esp_proposals: String,
    pub start_action: String,
    pub dpd_delay: u32,
    pub description: Option<String>,
}

pub async fn list_tunnels(store: &ConfigStore) -> Result<Vec<IpsecTunnel>> {
    let rows = sqlx::query(
        "SELECT id, name, enabled, local_address, remote_address, local_id, remote_id, psk,
                local_ts, remote_ts, ike_proposals, esp_proposals, start_action, dpd_delay,
                description FROM ipsec_tunnels ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read ipsec_tunnels"))?;
    Ok(rows
        .iter()
        .map(|r| IpsecTunnel {
            id: r.get(0),
            name: r.get(1),
            enabled: r.get::<i64, _>(2) != 0,
            local_address: r.get(3),
            remote_address: r.get(4),
            local_id: r.get(5),
            remote_id: r.get(6),
            psk: r.get(7),
            local_ts: r.get(8),
            remote_ts: r.get(9),
            ike_proposals: r.get(10),
            esp_proposals: r.get(11),
            start_action: r.get(12),
            dpd_delay: r.get::<i64, _>(13) as u32,
            description: r.get(14),
        })
        .collect())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default)]
    pub remote_address: Option<String>,
    #[serde(default)]
    pub local_id: Option<String>,
    #[serde(default)]
    pub remote_id: Option<String>,
    /// Empty on create = generate one (shown once in the API answer).
    #[serde(default)]
    pub psk: Option<String>,
    #[serde(default)]
    pub local_ts: Option<String>,
    #[serde(default)]
    pub remote_ts: Option<String>,
    #[serde(default)]
    pub ike_proposals: Option<String>,
    #[serde(default)]
    pub esp_proposals: Option<String>,
    #[serde(default)]
    pub start_action: Option<String>,
    #[serde(default)]
    pub dpd_delay: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

fn opt(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

/// Connection names become swanctl section names.
pub fn check_tunnel_name(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 32
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid(format!(
            "tunnel name {s:?}: 1-32 letters, digits, '-' or '_'"
        )));
    }
    Ok(s.to_string())
}

/// Pre-shared keys go into a quoted swanctl string: printable ASCII
/// without quotes or backslashes, 16-128 characters.
pub fn check_psk(s: &str) -> Result<String> {
    if !(16..=128).contains(&s.len())
        || !s
            .chars()
            .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\')
    {
        return Err(invalid(
            "pre-shared key: 16-128 printable characters without quotes or backslashes",
        ));
    }
    Ok(s.to_string())
}

/// A random 40-character pre-shared key.
pub fn generate_psk() -> String {
    use rand::Rng;
    const CS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    (0..40)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
}

/// IKE identities: an address, a FQDN or `user@fqdn` (no spaces/quotes).
fn check_identity(what: &str, s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 255
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':'))
    {
        return Err(invalid(format!(
            "{what} {s:?}: an address, host name or user@domain"
        )));
    }
    Ok(s.to_string())
}

/// strongSwan proposal lists: comma-separated `alg-alg-...` keywords.
fn check_proposals(what: &str, s: &str) -> Result<String> {
    let v = split_list(s);
    if v.is_empty()
        || !v.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    {
        return Err(invalid(format!("{what}: e.g. {DEFAULT_IKE}")));
    }
    Ok(v.join(","))
}

/// Create (`id` = None) or edit a tunnel. Returns (id, generated psk).
pub async fn save_tunnel(
    store: &ConfigStore,
    id: Option<i64>,
    t: &TunnelInput,
) -> Result<(i64, Option<String>)> {
    let all = list_tunnels(store).await?;
    let cur = match id {
        Some(id) => Some(
            all.iter()
                .find(|x| x.id == id)
                .cloned()
                .ok_or_else(|| Error::Config(format!("no IPsec tunnel {id}")))?,
        ),
        None => None,
    };
    let name = match (opt(&t.name), &cur) {
        (Some(n), _) => check_tunnel_name(n)?,
        (None, Some(c)) => c.name.clone(),
        (None, None) => return Err(invalid("tunnel: a name is required")),
    };
    if all.iter().any(|x| x.name == name && Some(x.id) != id) {
        return Err(invalid(format!("tunnel: {name} already exists")));
    }
    let local_address = match (&t.local_address, &cur) {
        (Some(a), _) if a.trim().is_empty() => None,
        (Some(a), _) => Some(check_host("local address", a)?),
        (None, Some(c)) => c.local_address.clone(),
        (None, None) => None,
    };
    let remote_address = match (opt(&t.remote_address), &cur) {
        (Some("%any"), _) => "%any".to_string(),
        (Some(a), _) => check_host("remote gateway", a)?,
        (None, Some(c)) => c.remote_address.clone(),
        (None, None) => {
            return Err(invalid(
                "remote gateway: required (or %any to only respond)",
            ))
        }
    };
    let local_id = match (&t.local_id, &cur) {
        (Some(a), _) if a.trim().is_empty() => None,
        (Some(a), _) => Some(check_identity("local identity", a)?),
        (None, Some(c)) => c.local_id.clone(),
        (None, None) => None,
    };
    let remote_id = match (&t.remote_id, &cur) {
        (Some(a), _) if a.trim().is_empty() => None,
        (Some(a), _) => Some(check_identity("remote identity", a)?),
        (None, Some(c)) => c.remote_id.clone(),
        (None, None) => None,
    };
    if remote_address == "%any" && remote_id.is_none() {
        return Err(invalid(
            "remote identity: required when the remote gateway is %any",
        ));
    }
    let mut generated = None;
    let psk = match (opt(&t.psk), &cur) {
        (Some(p), _) => check_psk(p)?,
        (None, Some(c)) => c.psk.clone(),
        (None, None) => {
            let p = generate_psk();
            generated = Some(p.clone());
            p
        }
    };
    let local_ts = match (&t.local_ts, &cur) {
        (Some(v), _) => check_networks("local networks", v, false)?,
        (None, Some(c)) => c.local_ts.clone(),
        (None, None) => return Err(invalid("local networks: required")),
    };
    let remote_ts = match (&t.remote_ts, &cur) {
        (Some(v), _) => check_networks("remote networks", v, false)?,
        (None, Some(c)) => c.remote_ts.clone(),
        (None, None) => return Err(invalid("remote networks: required")),
    };
    let ike_proposals = match (opt(&t.ike_proposals), &cur) {
        (Some(v), _) => check_proposals("IKE proposals", v)?,
        (None, Some(c)) => c.ike_proposals.clone(),
        (None, None) => DEFAULT_IKE.into(),
    };
    let esp_proposals = match (opt(&t.esp_proposals), &cur) {
        (Some(v), _) => check_proposals("ESP proposals", v)?,
        (None, Some(c)) => c.esp_proposals.clone(),
        (None, None) => DEFAULT_ESP.into(),
    };
    let start_action = match (opt(&t.start_action), &cur) {
        (Some(v @ ("start" | "trap" | "none")), _) => v.to_string(),
        (Some(v), _) => return Err(invalid(format!("start action {v:?}: start, trap or none"))),
        (None, Some(c)) => c.start_action.clone(),
        (None, None) => "start".into(),
    };
    if remote_address == "%any" && start_action != "none" {
        return Err(invalid(
            "start action: a tunnel to %any can only respond (start action none)",
        ));
    }
    let dpd_delay = match (t.dpd_delay, &cur) {
        (Some(d), _) if d > 3600 => return Err(invalid("DPD delay: 0-3600 seconds")),
        (Some(d), _) => d,
        (None, Some(c)) => c.dpd_delay,
        (None, None) => 30,
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
        "UPDATE ipsec_tunnels SET name=?, enabled=?, local_address=?, remote_address=?, local_id=?,
            remote_id=?, psk=?, local_ts=?, remote_ts=?, ike_proposals=?, esp_proposals=?,
            start_action=?, dpd_delay=?, description=?, updated_at=? WHERE id=?"
    } else {
        "INSERT INTO ipsec_tunnels (name, enabled, local_address, remote_address, local_id,
            remote_id, psk, local_ts, remote_ts, ike_proposals, esp_proposals, start_action,
            dpd_delay, description, updated_at, id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    };
    let r = sqlx::query(sql)
        .bind(&name)
        .bind(enabled as i64)
        .bind(&local_address)
        .bind(&remote_address)
        .bind(&local_id)
        .bind(&remote_id)
        .bind(&psk)
        .bind(&local_ts)
        .bind(&remote_ts)
        .bind(&ike_proposals)
        .bind(&esp_proposals)
        .bind(&start_action)
        .bind(dpd_delay as i64)
        .bind(&description)
        .bind(now())
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("save IPsec tunnel"))?;
    Ok((id.unwrap_or_else(|| r.last_insert_rowid()), generated))
}

pub async fn delete_tunnel(store: &ConfigStore, id: i64) -> Result<bool> {
    let r = sqlx::query("DELETE FROM ipsec_tunnels WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db_err("delete IPsec tunnel"))?;
    Ok(r.rows_affected() > 0)
}

/// `/etc/swanctl/conf.d/patronus.conf` for the enabled tunnels.
pub fn render(tunnels: &[&IpsecTunnel], redact: bool) -> String {
    let mut c = lan::header("#", "IPsec tunnels, strongSwan swanctl");
    c.push_str("connections {\n");
    for t in tunnels {
        let local_addrs = t.local_address.as_deref().unwrap_or("%any");
        c.push_str(&format!(
            "    {CONN_PREFIX}{name} {{\n        version = 2\n        local_addrs = {local_addrs}\n        \
             remote_addrs = {remote}\n        proposals = {ike}\n        dpd_delay = {dpd}s\n",
            name = t.name,
            remote = t.remote_address,
            ike = t.ike_proposals,
            dpd = t.dpd_delay,
        ));
        c.push_str("        local {\n            auth = psk\n");
        if let Some(id) = t.local_id.as_ref().or(t.local_address.as_ref()) {
            c.push_str(&format!("            id = {id}\n"));
        }
        c.push_str("        }\n        remote {\n            auth = psk\n");
        let remote_id = t
            .remote_id
            .clone()
            .or_else(|| (t.remote_address != "%any").then(|| t.remote_address.clone()));
        if let Some(id) = &remote_id {
            c.push_str(&format!("            id = {id}\n"));
        }
        let (dpd_action, close_action) = match t.start_action.as_str() {
            "start" => ("restart", "start"),
            "trap" => ("trap", "trap"),
            _ => ("clear", "none"),
        };
        c.push_str(&format!(
            "        }}\n        children {{\n            {name} {{\n                local_ts = {lts}\n                \
             remote_ts = {rts}\n                esp_proposals = {esp}\n                start_action = {sa}\n                \
             dpd_action = {dpd_action}\n                close_action = {close_action}\n            }}\n        }}\n    }}\n",
            name = t.name,
            lts = split_list(&t.local_ts).join(","),
            rts = split_list(&t.remote_ts).join(","),
            esp = t.esp_proposals,
            sa = t.start_action,
        ));
    }
    c.push_str("}\n\nsecrets {\n");
    for t in tunnels {
        c.push_str(&format!("    ike-{CONN_PREFIX}{} {{\n", t.name));
        let mut n = 1;
        if let Some(id) = t.local_id.as_ref().or(t.local_address.as_ref()) {
            c.push_str(&format!("        id-{n} = {id}\n"));
            n += 1;
        }
        let remote_id = t
            .remote_id
            .clone()
            .or_else(|| (t.remote_address != "%any").then(|| t.remote_address.clone()));
        if let Some(id) = &remote_id {
            c.push_str(&format!("        id-{n} = {id}\n"));
        }
        let secret = if redact { "(hidden)" } else { t.psk.as_str() };
        c.push_str(&format!("        secret = \"{secret}\"\n    }}\n"));
    }
    c.push_str("}\n");
    c
}

/// The distro service that runs charon: Gentoo's OpenRC script is `ipsec`
/// (starter + charon), its systemd unit `strongswan` (charon-systemd);
/// other distros use `strongswan` / `strongswan-swanctl`.
pub fn service_name(env: &LanEnv) -> &'static str {
    let systemd =
        patronus_core::ServiceManager::detect_init_system() == patronus_core::InitSystem::Systemd;
    let unit_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ];
    let found = |n: &str| {
        if systemd {
            unit_dirs
                .iter()
                .any(|d| env.path(&format!("{d}/{n}.service")).exists())
        } else {
            env.path(&format!("/etc/init.d/{n}")).exists()
        }
    };
    let candidates: &[&'static str] = if systemd {
        &["strongswan", "strongswan-swanctl"]
    } else {
        &["ipsec", "strongswan", "strongswan-swanctl"]
    };
    candidates
        .iter()
        .copied()
        .find(|n| found(n))
        .unwrap_or("strongswan")
}

/// Runs `swanctl` (a seam for tests).
pub trait Swanctl: Send + Sync {
    fn run(&self, args: &[&str]) -> Result<String>;
}

pub struct SystemSwanctl;

impl Swanctl for SystemSwanctl {
    fn run(&self, args: &[&str]) -> Result<String> {
        let o = std::process::Command::new("swanctl")
            .args(args)
            .output()
            .map_err(|e| Error::Service(format!("swanctl: {e}")))?;
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        if o.status.success() {
            Ok(out)
        } else {
            Err(Error::Service(format!(
                "`swanctl {}` failed: {}{}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim(),
                if out.trim().is_empty() {
                    String::new()
                } else {
                    format!(" ({})", out.trim())
                }
            )))
        }
    }
}

#[derive(Clone)]
pub struct IpsecApplier {
    env: LanEnv,
    swanctl: std::sync::Arc<dyn Swanctl>,
}

impl Default for IpsecApplier {
    fn default() -> Self {
        Self::new(LanEnv::system(), std::sync::Arc::new(SystemSwanctl))
    }
}

impl IpsecApplier {
    pub fn new(env: LanEnv, swanctl: std::sync::Arc<dyn Swanctl>) -> Self {
        Self { env, swanctl }
    }

    /// charon answers on its VICI socket. (The distro service's own
    /// status is not used: Gentoo's OpenRC `ipsec` script reports
    /// `ipsec statusall` output instead of started/stopped.)
    fn charon_up(&self) -> bool {
        self.swanctl.run(&["--stats"]).is_ok()
    }

    fn wait_up(&self, secs: u64) -> bool {
        for _ in 0..secs * 4 {
            if self.charon_up() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        self.charon_up()
    }

    /// `swanctl --load-all`, retried while charon's VICI socket comes up
    /// (a start queued at boot).
    fn load_all(&self) -> Result<String> {
        let mut last = None;
        for i in 0..60 {
            match self.swanctl.run(&["--load-all", "--noprompt"]) {
                Ok(o) => return Ok(o),
                Err(e) => last = Some(e),
            }
            if i < 59 {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        Err(last.unwrap_or_else(|| Error::Service("swanctl --load-all failed".into())))
    }
}

#[async_trait]
impl Applier for IpsecApplier {
    fn name(&self) -> &'static str {
        "ipsec"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let all = list_tunnels(store).await?;
        let on: Vec<&IpsecTunnel> = all.iter().filter(|t| t.enabled).collect();
        let managed = lan::is_managed(&self.env, SWANCTL_CONF);
        if on.is_empty() && !managed {
            rep.applied("no IPsec tunnels configured (strongSwan untouched)");
            return Ok(rep);
        }
        if !on.is_empty() && !self.env.has_binary(SWANCTL_BIN) {
            return Err(Error::Service(
                "IPsec needs strongSwan but /usr/sbin/swanctl is not installed \
                 (emerge net-vpn/strongswan, USE=ipsec)"
                    .into(),
            ));
        }
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: SWANCTL_CONF,
                content: render(&on, false),
                mode: 0o600,
                group: None,
                check: None,
            },
        )?;
        if changed {
            rep.applied(format!("wrote {SWANCTL_CONF}"));
        }
        let svc = service_name(&self.env);
        let up = self.charon_up();
        if !on.is_empty() {
            // start charon if needed; never restart a running one (that
            // would drop every SA): new/changed/deleted connections are
            // (un)loaded with swanctl --load-all
            if !up {
                if let Err(e) = self.env.services.restart(svc) {
                    if !self.wait_up(10) {
                        return Err(e);
                    }
                }
                rep.applied(format!("{svc} started"));
            }
            self.load_all().map_err(|e| {
                Error::Service(format!("loading the IPsec configuration into charon: {e}"))
            })?;
            rep.applied(format!(
                "{} IPsec tunnel(s) loaded (swanctl --load-all)",
                on.len()
            ));
        } else if up {
            // our last tunnel is gone: unload it; stop charon unless it
            // still carries connections Patronus does not manage
            self.load_all()
                .map_err(|e| Error::Service(format!("unloading the IPsec configuration: {e}")))?;
            let others = self.swanctl.run(&["--list-conns"]).unwrap_or_default();
            if others.trim().is_empty() {
                self.env.services.stop(svc)?;
                rep.applied(format!("{svc} stopped (no IPsec tunnel left)"));
            } else {
                rep.applied("IPsec tunnels unloaded; charon keeps running for other connections");
            }
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let all = list_tunnels(store).await?;
        let on: Vec<&IpsecTunnel> = all.iter().filter(|t| t.enabled).collect();
        if on.is_empty() {
            return Ok("# no IPsec tunnels\n".into());
        }
        Ok(format!("## {SWANCTL_CONF}\n{}", render(&on, true)))
    }

    /// `{"installed", "running", "sas": <swanctl --list-sas text>, "error"}`
    async fn status(&self, _store: &ConfigStore) -> Result<Value> {
        let installed = self.env.has_binary(SWANCTL_BIN);
        if !installed {
            return Ok(json!({"installed": false, "running": false, "sas": ""}));
        }
        let me = self.clone();
        Ok(
            tokio::task::spawn_blocking(move || match me.swanctl.run(&["--list-sas"]) {
                Ok(out) => json!({"installed": true, "running": true, "sas": out}),
                Err(e) => {
                    json!({"installed": true, "running": false, "sas": "", "error": e.to_string()})
                }
            })
            .await
            .unwrap_or(Value::Null),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;
    use std::sync::Mutex;

    /// charon is "up" while the recorded service runs.
    #[derive(Default)]
    struct FakeSwanctl {
        calls: Mutex<Vec<String>>,
        services: Option<std::sync::Arc<crate::lan::RecordingServices>>,
    }
    impl Swanctl for FakeSwanctl {
        fn run(&self, args: &[&str]) -> Result<String> {
            self.calls.lock().unwrap().push(args.join(" "));
            let up = self
                .services
                .as_ref()
                .is_some_and(|s| s.is_running("strongswan"));
            if !up {
                return Err(Error::Service(
                    "connecting to 'unix:///run/charon.vici' failed".into(),
                ));
            }
            Ok(String::new())
        }
    }

    fn input(name: &str) -> TunnelInput {
        TunnelInput {
            name: Some(name.into()),
            local_address: Some("203.0.113.2".into()),
            remote_address: Some("198.51.100.2".into()),
            psk: Some("correct-horse-battery-staple".into()),
            local_ts: Some("192.168.50.0/24".into()),
            remote_ts: Some("10.2.0.0/16, fd00:2::/64".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn tunnels_become_a_swanctl_file_charon_loads() {
        let t = testutil::env(&[SWANCTL_BIN]);
        let s = testutil::store().await;
        let sw = std::sync::Arc::new(FakeSwanctl {
            services: Some(t.services.clone()),
            ..Default::default()
        });
        let a = IpsecApplier::new(t.env.clone(), sw.clone());
        // nothing configured: strongSwan is not touched at all
        a.apply(&s).await.unwrap();
        assert!(!t.env.path(SWANCTL_CONF).exists());
        assert!(t.services.log.lock().unwrap().is_empty());

        let (id, generated) = save_tunnel(&s, None, &input("site-b")).await.unwrap();
        assert!(generated.is_none(), "the given PSK is kept");
        a.apply(&s).await.unwrap();
        let c = read(&t, SWANCTL_CONF);
        for want in [
            "patronus-site-b {",
            "version = 2",
            "local_addrs = 203.0.113.2",
            "remote_addrs = 198.51.100.2",
            "auth = psk",
            "id = 203.0.113.2",
            "id = 198.51.100.2",
            "local_ts = 192.168.50.0/24",
            "remote_ts = 10.2.0.0/16,fd00:2::/64",
            "start_action = start",
            "dpd_action = restart",
            "ike-patronus-site-b {",
            "secret = \"correct-horse-battery-staple\"",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(t.env.path(SWANCTL_CONF))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(t.services.is_running("strongswan"), "charon started");
        assert!(sw
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("--load-all")));
        // the dry-run render never shows the key
        let r = a.render(&s).await.unwrap();
        assert!(
            !r.contains("correct-horse") && r.contains("(hidden)"),
            "{r}"
        );

        // an edit reloads without restarting charon
        let restarts = || {
            t.services
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.starts_with("restart"))
                .count()
        };
        let before = restarts();
        save_tunnel(
            &s,
            Some(id),
            &TunnelInput {
                remote_ts: Some("10.3.0.0/16".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(read(&t, SWANCTL_CONF).contains("remote_ts = 10.3.0.0/16"));
        assert_eq!(restarts(), before, "other SAs survive an edit");

        // last tunnel deleted: connections unloaded, charon stopped
        delete_tunnel(&s, id).await.unwrap();
        a.apply(&s).await.unwrap();
        assert!(!read(&t, SWANCTL_CONF).contains("patronus-site-b"));
        assert!(!t.services.is_running("strongswan"));
    }

    #[tokio::test]
    async fn bad_input_is_refused_and_psk_is_generated_when_empty() {
        let s = testutil::store().await;
        let mut i = input("x");
        i.psk = None;
        let (_, psk) = save_tunnel(&s, None, &i).await.unwrap();
        let psk = psk.expect("generated");
        assert_eq!(psk.len(), 40);
        assert!(check_psk(&psk).is_ok());
        assert!(
            save_tunnel(&s, None, &input("x")).await.is_err(),
            "duplicate name"
        );
        for (f, v) in [
            ("name", "bad name"),
            ("psk", "short"),
            ("psk", "has \"quote\" in it......"),
            ("remote", "bad host!"),
            ("lts", "10.0.0.0/99"),
            ("start", "always"),
            ("ike", "aes256;rm"),
        ] {
            let mut i = input("y");
            match f {
                "name" => i.name = Some(v.into()),
                "psk" => i.psk = Some(v.into()),
                "remote" => i.remote_address = Some(v.into()),
                "lts" => i.local_ts = Some(v.into()),
                "start" => i.start_action = Some(v.into()),
                _ => i.ike_proposals = Some(v.into()),
            }
            let e = save_tunnel(&s, None, &i).await.unwrap_err().to_string();
            assert!(
                e.starts_with("Invalid") || e.contains("Invalid"),
                "{f}: {e}"
            );
        }
        // a responder-only tunnel needs the peer's identity
        let mut i = input("roam");
        i.remote_address = Some("%any".into());
        assert!(save_tunnel(&s, None, &i).await.is_err());
        i.remote_id = Some("branch.example.org".into());
        i.start_action = Some("none".into());
        save_tunnel(&s, None, &i).await.unwrap();
        let all = list_tunnels(&s).await.unwrap();
        let roam: Vec<&IpsecTunnel> = all.iter().filter(|t| t.name == "roam").collect();
        let c = render(&roam, false);
        assert!(
            c.contains("remote_addrs = %any") && c.contains("id = branch.example.org"),
            "{c}"
        );
        assert!(
            c.contains("start_action = none") && c.contains("close_action = none"),
            "{c}"
        );
        // the API never serializes the key
        assert!(!serde_json::to_string(&all).unwrap().contains(&psk));
    }

    #[tokio::test]
    async fn missing_strongswan_is_reported_not_faked() {
        let t = testutil::env(&[]);
        let s = testutil::store().await;
        save_tunnel(&s, None, &input("a")).await.unwrap();
        let a = IpsecApplier::new(t.env.clone(), std::sync::Arc::new(FakeSwanctl::default()));
        let e = a.apply(&s).await.unwrap_err().to_string();
        assert!(e.contains("net-vpn/strongswan"), "{e}");
        assert_eq!(a.status(&s).await.unwrap()["installed"], false);
    }
}
