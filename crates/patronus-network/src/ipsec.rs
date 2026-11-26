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
/// charon drop-in written while a route-based tunnel exists: its wildcard
/// selectors (0.0.0.0/0) must not become routes towards the peer; the
/// XFRM interface and the routing table (static, OSPF) decide instead.
pub const CHARON_ROUTES_CONF: &str = "/etc/strongswan.d/patronus-routes.conf";
/// Pending connect / disconnect requests of the status page.
pub const REQUEST_ACTIONS: &[&str] = &["connect", "disconnect"];

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
    /// `policy` (traffic selectors, the default) or `route` (an XFRM
    /// interface carries the traffic; routes/OSPF decide what enters it).
    pub mode: String,
    /// XFRM interface id shared by the SA and the `xfrm<id>` interface
    /// (route mode; allocated on save when not given).
    pub if_id: Option<u32>,
    /// Address (CIDR) of this router on the XFRM interface.
    pub tunnel_address: Option<String>,
    pub mtu: Option<u32>,
    /// Device the XFRM interface is attached to (empty = `DEFAULT_XFRM_DEV`).
    pub xfrm_dev: Option<String>,
}

impl IpsecTunnel {
    pub fn is_route(&self) -> bool {
        self.mode == "route"
    }
    /// Kernel name of the tunnel's XFRM interface (route mode).
    pub fn xfrm_name(&self) -> Option<String> {
        self.if_id
            .filter(|_| self.is_route())
            .map(|i| format!("{XFRM_PREFIX}{i}"))
    }
}

/// Prefix of the XFRM interfaces Patronus creates (`xfrm<if_id>`); an
/// interface with this prefix that no route-mode tunnel owns is removed.
pub const XFRM_PREFIX: &str = "xfrm";
/// Device an XFRM interface hangs off when the tunnel names none (any
/// device works, the SA is bound by `if_id`; `lo` always exists).
pub const DEFAULT_XFRM_DEV: &str = "lo";
pub const WILDCARD_TS: &str = "0.0.0.0/0, ::/0";

pub async fn list_tunnels(store: &ConfigStore) -> Result<Vec<IpsecTunnel>> {
    let rows = sqlx::query(
        "SELECT id, name, enabled, local_address, remote_address, local_id, remote_id, psk,
                local_ts, remote_ts, ike_proposals, esp_proposals, start_action, dpd_delay,
                description, mode, if_id, tunnel_address, mtu, xfrm_dev
                FROM ipsec_tunnels ORDER BY name",
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
            mode: r.get(15),
            if_id: r.get::<Option<i64>, _>(16).map(|v| v as u32),
            tunnel_address: r.get(17),
            mtu: r.get::<Option<i64>, _>(18).map(|v| v as u32),
            xfrm_dev: r.get(19),
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
    /// `policy` or `route`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Route mode: XFRM interface id (empty = allocate the next free one).
    #[serde(default)]
    pub if_id: Option<u32>,
    /// Route mode: this router's address on the tunnel, CIDR (empty = none).
    #[serde(default)]
    pub tunnel_address: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub xfrm_dev: Option<String>,
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

/// Content of [`CHARON_ROUTES_CONF`].
pub fn render_charon_routes(on: bool) -> String {
    if !on {
        return lan::header("#", "strongSwan route installation");
    }
    let mut c = lan::header("#", "strongSwan route installation");
    // `charon` (starter) and `charon-systemd` read their own section
    c.push_str(
        "# route-based IPsec: traffic is steered by routes into the XFRM interfaces\n\
         charon {\n    install_routes = no\n}\ncharon-systemd {\n    install_routes = no\n}\n",
    );
    c
}

/// Install (`on`) or remove [`CHARON_ROUTES_CONF`]; whether it changed.
fn sync_charon_routes(env: &LanEnv, on: bool) -> Result<bool> {
    if !on {
        if lan::is_managed(env, CHARON_ROUTES_CONF) {
            std::fs::remove_file(env.path(CHARON_ROUTES_CONF))
                .map_err(|e| Error::Config(format!("remove {CHARON_ROUTES_CONF}: {e}")))?;
            return Ok(true);
        }
        return Ok(false);
    }
    lan::install(
        env,
        &ManagedFile {
            path: CHARON_ROUTES_CONF,
            content: render_charon_routes(true),
            mode: 0o644,
            group: None,
            check: None,
        },
    )
}

/// Queue a connect / disconnect of the tunnel `name` for the next apply
/// (the unprivileged web UI cannot talk to charon; applyd can).
pub async fn request_action(store: &ConfigStore, name: &str, action: &str) -> Result<()> {
    if !REQUEST_ACTIONS.contains(&action) {
        return Err(invalid(format!("action {action:?}: connect or disconnect")));
    }
    let t = list_tunnels(store)
        .await?
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| Error::Config(format!("no IPsec tunnel {name}")))?;
    if !t.enabled {
        return Err(invalid(format!("tunnel {name} is disabled")));
    }
    if action == "connect" && t.remote_address == "%any" {
        return Err(invalid(format!(
            "tunnel {name} only responds (remote gateway %any): the peer connects"
        )));
    }
    sqlx::query("INSERT INTO ipsec_requests (tunnel, action, requested_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(action)
        .bind(now())
        .execute(store.pool()?)
        .await
        .map_err(db_err("queue IPsec request"))?;
    Ok(())
}

/// Address with prefix for the XFRM interface (`169.254.10.1/30`).
fn check_ifaddr(s: &str) -> Result<String> {
    let s = s.trim();
    let ok = s.split_once('/').is_some_and(|(a, p)| {
        a.parse::<std::net::IpAddr>().is_ok_and(|ip| {
            p.parse::<u8>()
                .is_ok_and(|p| p <= if ip.is_ipv4() { 32 } else { 128 })
        })
    });
    if !ok {
        return Err(invalid(format!(
            "tunnel address {s:?}: an address with prefix, e.g. 169.254.10.1/30"
        )));
    }
    Ok(s.to_string())
}

/// A kernel device name (`eth0`, `br-lan.10`).
fn check_dev(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty()
        || s.len() > 15
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(invalid(format!("device {s:?}: a kernel interface name")));
    }
    Ok(s.to_string())
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
    let mode = match (opt(&t.mode), &cur) {
        (Some(m @ ("policy" | "route")), _) => m.to_string(),
        (Some(m), _) => return Err(invalid(format!("mode {m:?}: policy or route"))),
        (None, Some(c)) => c.mode.clone(),
        (None, None) => "policy".into(),
    };
    let route = mode == "route";
    // a route-based tunnel carries everything its XFRM interface is given:
    // wildcard selectors unless the user narrows them
    let local_ts = match (&t.local_ts, &cur) {
        (Some(v), _) if route && v.trim().is_empty() => WILDCARD_TS.into(),
        (Some(v), _) => check_networks("local networks", v, false)?,
        (None, Some(c)) => c.local_ts.clone(),
        (None, None) if route => WILDCARD_TS.into(),
        (None, None) => return Err(invalid("local networks: required")),
    };
    let remote_ts = match (&t.remote_ts, &cur) {
        (Some(v), _) if route && v.trim().is_empty() => WILDCARD_TS.into(),
        (Some(v), _) => check_networks("remote networks", v, false)?,
        (None, Some(c)) => c.remote_ts.clone(),
        (None, None) if route => WILDCARD_TS.into(),
        (None, None) => return Err(invalid("remote networks: required")),
    };
    let if_id = if !route {
        None
    } else {
        let wanted = t.if_id.or(cur.as_ref().and_then(|c| c.if_id));
        match wanted {
            Some(0) => return Err(invalid("interface id: 1 or more")),
            Some(i) if i > 0x7fff_ffff => return Err(invalid("interface id: too large")),
            Some(i) => {
                if all
                    .iter()
                    .any(|x| x.if_id == Some(i) && Some(x.id) != id && x.is_route())
                {
                    return Err(invalid(format!(
                        "interface id {i} is used by another tunnel"
                    )));
                }
                Some(i)
            }
            None => (1u32..).find(|i| !all.iter().any(|x| x.if_id == Some(*i) && x.is_route())),
        }
    };
    let tunnel_address = match (&t.tunnel_address, &cur) {
        _ if !route => None,
        (Some(a), _) if a.trim().is_empty() => None,
        (Some(a), _) => Some(check_ifaddr(a)?),
        (None, Some(c)) => c.tunnel_address.clone(),
        (None, None) => None,
    };
    let mtu = match (t.mtu, &cur) {
        _ if !route => None,
        (Some(0), _) => None,
        (Some(m), _) if !(576..=9000).contains(&m) => {
            return Err(invalid("MTU: 576-9000 (0 = default)"))
        }
        (Some(m), _) => Some(m),
        (None, Some(c)) => c.mtu,
        (None, None) => None,
    };
    let xfrm_dev = match (&t.xfrm_dev, &cur) {
        _ if !route => None,
        (Some(d), _) if d.trim().is_empty() => None,
        (Some(d), _) => Some(check_dev(d)?),
        (None, Some(c)) => c.xfrm_dev.clone(),
        (None, None) => None,
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
            start_action=?, dpd_delay=?, description=?, mode=?, if_id=?, tunnel_address=?,
            mtu=?, xfrm_dev=?, updated_at=? WHERE id=?"
    } else {
        "INSERT INTO ipsec_tunnels (name, enabled, local_address, remote_address, local_id,
            remote_id, psk, local_ts, remote_ts, ike_proposals, esp_proposals, start_action,
            dpd_delay, description, mode, if_id, tunnel_address, mtu, xfrm_dev, updated_at, id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
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
        .bind(&mode)
        .bind(if_id.map(|v| v as i64))
        .bind(&tunnel_address)
        .bind(mtu.map(|v| v as i64))
        .bind(&xfrm_dev)
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
    render_with(tunnels, &crate::ipsec_rw::RwConfig::default(), redact)
}

/// [`render`] plus the road-warrior profiles' connections, pools and EAP
/// secrets (one `connections`, `pools` and `secrets` section each).
pub fn render_with(
    tunnels: &[&IpsecTunnel],
    rw: &crate::ipsec_rw::RwConfig,
    redact: bool,
) -> String {
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
             dpd_action = {dpd_action}\n                close_action = {close_action}\n{ifid}            }}\n        }}\n    }}\n",
            name = t.name,
            lts = split_list(&t.local_ts).join(","),
            rts = split_list(&t.remote_ts).join(","),
            esp = t.esp_proposals,
            sa = t.start_action,
            ifid = match t.if_id.filter(|_| t.is_route()) {
                Some(i) => format!(
                    "                if_id_in = {i}\n                if_id_out = {i}\n"
                ),
                None => String::new(),
            },
        ));
    }
    c.push_str(&rw.connections);
    c.push_str("}\n\n");
    if !rw.pools.is_empty() {
        c.push_str(&format!("pools {{\n{}}}\n\n", rw.pools));
    }
    c.push_str("secrets {\n");
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
    c.push_str(&rw.secrets);
    c.push_str("}\n");
    c
}

/// Write the road-warrior certificates and keys under /etc/swanctl and
/// remove the ones of profiles/users that are gone. Returns whether
/// anything changed.
fn install_rw_files(env: &LanEnv, rw: &crate::ipsec_rw::RwConfig) -> Result<bool> {
    use crate::ipsec_rw::{PRIVATE_DIR, RW_PREFIX, X509CA_DIR, X509_DIR};
    use std::os::unix::fs::PermissionsExt;
    let mut changed = false;
    for (dir, name, content, mode) in &rw.files {
        let d = env.path(dir);
        std::fs::create_dir_all(&d)
            .map_err(|e| Error::Config(format!("create {}: {e}", d.display())))?;
        let path = d.join(name);
        if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
            std::fs::write(&path, content)
                .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;
            changed = true;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(*mode))
            .map_err(|e| Error::Config(format!("chmod {}: {e}", path.display())))?;
    }
    for dir in [X509_DIR, X509CA_DIR, PRIVATE_DIR] {
        let d = env.path(dir);
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(RW_PREFIX)
                && !rw
                    .files
                    .iter()
                    .any(|(fd, fname, _, _)| *fd == dir && *fname == n)
            {
                let _ = std::fs::remove_file(e.path());
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// A secret given inline (`psk: ...`) or by file (`psk_file: /etc/patronus/secrets/x`,
/// read when the resource is applied, so the repository need not hold it).
pub fn secret_from(v: &Value, inline: &str, file: &str) -> Result<Option<String>> {
    if let Some(s) = v
        .get(inline)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(s.to_string()));
    }
    if let Some(f) = v
        .get(file)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        if !f.starts_with('/') {
            return Err(invalid(format!("{file}: an absolute path")));
        }
        let t =
            std::fs::read_to_string(f).map_err(|e| Error::Config(format!("{file} {f}: {e}")))?;
        return Ok(Some(t.trim().to_string()));
    }
    Ok(None)
}

/// `kind: IpsecTunnel` from a repository: the fields of the VPN page's
/// tunnel form (`local_address, remote_address, local_id, remote_id, psk |
/// psk_file, local_ts, remote_ts, ike_proposals, esp_proposals,
/// start_action, dpd_delay, enabled, description`). A new tunnel needs a PSK.
pub async fn gitops_upsert_tunnel(store: &ConfigStore, name: &str, spec: &Value) -> Result<()> {
    let mut input: TunnelInput = serde_json::from_value(spec.clone())
        .map_err(|e| invalid(format!("IPsec tunnel {name}: {e}")))?;
    input.name = Some(name.to_string());
    input.psk = secret_from(spec, "psk", "psk_file")?;
    let cur = list_tunnels(store)
        .await?
        .into_iter()
        .find(|t| t.name == name);
    if cur.is_none() && input.psk.is_none() {
        return Err(invalid(format!(
            "IPsec tunnel {name}: a new tunnel needs psk or psk_file"
        )));
    }
    save_tunnel(store, cur.map(|t| t.id), &input).await?;
    Ok(())
}

pub async fn gitops_delete_tunnel(store: &ConfigStore, name: &str) -> Result<()> {
    if let Some(t) = list_tunnels(store)
        .await?
        .into_iter()
        .find(|t| t.name == name)
    {
        delete_tunnel(store, t.id).await?;
    }
    Ok(())
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
    /// `ip` (XFRM interfaces, kernel policies); a recorder in tests.
    cmd: std::sync::Arc<dyn crate::linkstate::Cmd>,
}

impl Default for IpsecApplier {
    fn default() -> Self {
        Self::new(LanEnv::system(), std::sync::Arc::new(SystemSwanctl))
    }
}

impl IpsecApplier {
    pub fn new(env: LanEnv, swanctl: std::sync::Arc<dyn Swanctl>) -> Self {
        Self {
            env,
            swanctl,
            cmd: std::sync::Arc::new(crate::linkstate::SystemCmd),
        }
    }

    pub fn with_cmd(mut self, cmd: std::sync::Arc<dyn crate::linkstate::Cmd>) -> Self {
        self.cmd = cmd;
        self
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

    /// Carry out the queued connect / disconnect requests (then forget
    /// them; a request older than an hour was never meant for now).
    async fn run_requests(&self, store: &ConfigStore, rep: &mut ApplyReport) -> Result<()> {
        let pool = store.pool()?;
        let rows =
            sqlx::query("SELECT id, tunnel, action, requested_at FROM ipsec_requests ORDER BY id")
                .fetch_all(pool)
                .await
                .map_err(db_err("read IPsec requests"))?;
        let cutoff = now() - 3600;
        for r in rows {
            let (id, tunnel, action, at): (i64, String, String, i64) =
                (r.get(0), r.get(1), r.get(2), r.get(3));
            let ike = format!("{CONN_PREFIX}{tunnel}");
            if at >= cutoff {
                let me = self.swanctl.clone();
                let (t2, a2, i2) = (tunnel.clone(), action.clone(), ike.clone());
                let res = tokio::task::spawn_blocking(move || match a2.as_str() {
                    "connect" => me.run(&[
                        "--initiate",
                        "--child",
                        &t2,
                        "--ike",
                        &i2,
                        "--timeout",
                        "20",
                    ]),
                    _ => me.run(&["--terminate", "--ike", &i2]),
                })
                .await
                .map_err(|e| Error::Service(format!("swanctl task: {e}")))?;
                match res {
                    Ok(_) => rep.applied(format!("IPsec tunnel {tunnel}: {action} done")),
                    Err(e) => rep.warn(format!("IPsec tunnel {tunnel}: {action} failed: {e}")),
                }
            }
            sqlx::query("DELETE FROM ipsec_requests WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await
                .map_err(db_err("clear IPsec request"))?;
        }
        Ok(())
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

    fn resource_kinds(&self) -> &'static [patronus_config::ResourceKind] {
        &[
            patronus_config::ResourceKind::IpsecTunnel,
            patronus_config::ResourceKind::IpsecRoadWarrior,
        ]
    }

    async fn upsert_resource(
        &self,
        store: &ConfigStore,
        config: &patronus_config::DeclarativeConfig,
    ) -> Result<()> {
        let v = patronus_config::declarative::spec_value(config)?;
        match config.kind {
            patronus_config::ResourceKind::IpsecTunnel => {
                gitops_upsert_tunnel(store, &config.metadata.name, v).await
            }
            patronus_config::ResourceKind::IpsecRoadWarrior => {
                crate::ipsec_rw::gitops_upsert_profile(store, &config.metadata.name, v).await
            }
            _ => Err(invalid("resource kind for the IPsec applier")),
        }
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        kind: &patronus_config::ResourceKind,
        name: &str,
    ) -> Result<()> {
        match kind {
            patronus_config::ResourceKind::IpsecTunnel => gitops_delete_tunnel(store, name).await,
            patronus_config::ResourceKind::IpsecRoadWarrior => {
                crate::ipsec_rw::gitops_delete_profile(store, name).await
            }
            _ => Err(invalid("resource kind for the IPsec applier")),
        }
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let all = list_tunnels(store).await?;
        let on: Vec<&IpsecTunnel> = all.iter().filter(|t| t.enabled).collect();
        let managed = lan::is_managed(&self.env, SWANCTL_CONF);
        let rw_on = crate::ipsec_rw::list_profiles(store)
            .await?
            .iter()
            .any(|p| p.enabled);
        if on.is_empty() && !rw_on && !managed {
            rep.applied("no IPsec tunnels configured (strongSwan untouched)");
            return Ok(rep);
        }
        if (!on.is_empty() || rw_on) && !self.env.has_binary(SWANCTL_BIN) {
            return Err(Error::Service(
                "IPsec needs strongSwan but /usr/sbin/swanctl is not installed \
                 (emerge net-vpn/strongswan, USE=ipsec)"
                    .into(),
            ));
        }
        if rw_on {
            // CA, server and client certificates (openssl) before charon needs them
            crate::ipsec_rw::ensure_pki(store).await?;
        }
        let rw = crate::ipsec_rw::build_config(store, false).await?;
        let files_changed = install_rw_files(&self.env, &rw)?;
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: SWANCTL_CONF,
                content: render_with(&on, &rw, false),
                mode: 0o600,
                group: None,
                check: None,
            },
        )?;
        if changed || files_changed {
            rep.applied(format!("wrote {SWANCTL_CONF}"));
        }
        // route-based tunnels: the XFRM interfaces exist before charon installs
        // the SAs that name their if_id; a wildcard selector must not make
        // charon install a default route towards the peer (charon.install_routes)
        let route_tunnels: Vec<&IpsecTunnel> =
            on.iter().copied().filter(|t| t.is_route()).collect();
        let settings_changed = sync_charon_routes(&self.env, !route_tunnels.is_empty())?;
        let want: Vec<crate::ipsec_xfrm::XfrmWant> = route_tunnels
            .iter()
            .filter_map(|t| {
                Some(crate::ipsec_xfrm::XfrmWant {
                    name: t.xfrm_name()?,
                    if_id: t.if_id?,
                    dev: t
                        .xfrm_dev
                        .clone()
                        .unwrap_or_else(|| DEFAULT_XFRM_DEV.to_string()),
                    addr: t.tunnel_address.clone(),
                    mtu: t.mtu,
                })
            })
            .collect();
        if self.env.root == std::path::Path::new("/") || !want.is_empty() {
            for n in
                crate::ipsec_xfrm::sync_interfaces(self.cmd.as_ref(), XFRM_PREFIX, &want).await?
            {
                rep.applied(n);
            }
        }
        let svc = service_name(&self.env);
        let up = self.charon_up();
        let have = !on.is_empty() || !rw.is_empty();
        if have {
            // start charon if needed; never restart a running one (that
            // would drop every SA): new/changed/deleted connections are
            // (un)loaded with swanctl --load-all
            if up && settings_changed {
                // charon reads install_routes only at start
                self.env.services.restart(svc)?;
                self.wait_up(10);
                rep.applied(format!(
                    "{svc} restarted (route installation setting changed)"
                ));
            } else if !up {
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
                "{} IPsec tunnel(s) and {} road-warrior profile(s) loaded (swanctl --load-all)",
                on.len(),
                rw.connections.matches("version = 2").count()
            ));
            self.run_requests(store, &mut rep).await?;
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
        let rw = crate::ipsec_rw::build_config(store, true).await?;
        if on.is_empty() && rw.is_empty() {
            return Ok("# no IPsec tunnels\n".into());
        }
        Ok(format!(
            "## {SWANCTL_CONF}\n{}",
            render_with(&on, &rw, true)
        ))
    }

    /// `{"installed", "running", "sas": <swanctl --list-sas text>, "error",
    /// "policies": [kernel SPs], "interfaces": [XFRM interfaces]}`
    async fn status(&self, _store: &ConfigStore) -> Result<Value> {
        let installed = self.env.has_binary(SWANCTL_BIN);
        if !installed {
            return Ok(json!({"installed": false, "running": false, "sas": ""}));
        }
        let me = self.clone();
        let mut st = tokio::task::spawn_blocking(move || match me.swanctl.run(&["--list-sas"]) {
            Ok(out) => json!({"installed": true, "running": true, "sas": out}),
            Err(e) => {
                json!({"installed": true, "running": false, "sas": "", "error": e.to_string()})
            }
        })
        .await
        .unwrap_or(Value::Null);
        // kernel side: security policies and the XFRM interfaces (best effort)
        if st["running"] == true {
            let pol = self
                .cmd
                .run("ip", &crate::linkstate::argv(&["xfrm", "policy"]))
                .await
                .map(|t| crate::ipsec_xfrm::parse_policies(&t))
                .unwrap_or_default();
            st["policies"] = json!(pol);
        }
        let ifs = crate::ipsec_xfrm::list_interfaces(self.cmd.as_ref())
            .await
            .unwrap_or_default();
        st["interfaces"] = json!(ifs);
        Ok(st)
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
    async fn tunnels_from_a_repository_are_created_updated_and_deleted() {
        let s = testutil::store().await;
        let psk_file = std::env::temp_dir().join(format!("pa-psk-{}", std::process::id()));
        std::fs::write(&psk_file, "psk-from-a-file-0123456789\n").unwrap();
        let spec = serde_json::json!({
            "remote_address": "198.51.100.2",
            "psk_file": psk_file.to_str().unwrap(),
            "local_ts": "192.168.50.0/24",
            "remote_ts": "10.2.0.0/16",
            "description": "site b",
        });
        gitops_upsert_tunnel(&s, "site-b", &spec).await.unwrap();
        let t = list_tunnels(&s).await.unwrap();
        assert_eq!(
            (t[0].name.as_str(), t[0].remote_ts.as_str()),
            ("site-b", "10.2.0.0/16")
        );
        assert_eq!(
            t[0].psk, "psk-from-a-file-0123456789",
            "read from the file, trimmed"
        );
        // an edit keeps the PSK when none is given
        let spec2 = serde_json::json!({ "remote_address": "198.51.100.2", "local_ts": "192.168.50.0/24", "remote_ts": "10.3.0.0/16" });
        gitops_upsert_tunnel(&s, "site-b", &spec2).await.unwrap();
        let t = list_tunnels(&s).await.unwrap();
        assert_eq!(
            (t.len(), t[0].remote_ts.as_str(), t[0].psk.as_str()),
            (1, "10.3.0.0/16", "psk-from-a-file-0123456789")
        );
        // a new tunnel needs a key
        assert!(gitops_upsert_tunnel(&s, "other", &spec2).await.is_err());
        assert!(
            gitops_upsert_tunnel(&s, "x", &serde_json::json!({ "psk_file": "relative/path" }))
                .await
                .is_err()
        );
        gitops_delete_tunnel(&s, "site-b").await.unwrap();
        gitops_delete_tunnel(&s, "site-b").await.unwrap();
        assert!(list_tunnels(&s).await.unwrap().is_empty());
        let _ = std::fs::remove_file(&psk_file);
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

    /// `ip` stand-in: no XFRM interface exists yet; records every call.
    #[derive(Default)]
    struct FakeIp {
        calls: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl crate::linkstate::Cmd for FakeIp {
        async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{prog} {}", args.join(" ")));
            Ok(if args.first().map(String::as_str) == Some("-j") {
                "[]".into()
            } else {
                String::new()
            })
        }
    }

    fn route_input(name: &str) -> TunnelInput {
        TunnelInput {
            name: Some(name.into()),
            local_address: Some("203.0.113.2".into()),
            remote_address: Some("198.51.100.2".into()),
            psk: Some("correct-horse-battery-staple".into()),
            mode: Some("route".into()),
            tunnel_address: Some("169.254.10.1/30".into()),
            mtu: Some(1400),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_route_based_tunnel_gets_an_xfrm_interface_and_if_ids() {
        let t = testutil::env(&[SWANCTL_BIN]);
        let s = testutil::store().await;
        let sw = std::sync::Arc::new(FakeSwanctl {
            services: Some(t.services.clone()),
            ..Default::default()
        });
        let ip = std::sync::Arc::new(FakeIp::default());
        let a = IpsecApplier::new(t.env.clone(), sw.clone()).with_cmd(ip.clone());
        let (id, _) = save_tunnel(&s, None, &route_input("hub")).await.unwrap();
        let all = list_tunnels(&s).await.unwrap();
        assert_eq!(all[0].if_id, Some(1), "the first free interface id");
        assert_eq!(all[0].xfrm_name().as_deref(), Some("xfrm1"));
        assert_eq!(
            all[0].local_ts, WILDCARD_TS,
            "route mode defaults to wildcard selectors"
        );
        // a second tunnel gets the next id; a taken id is refused
        let (_, _) = save_tunnel(&s, None, &route_input("spoke")).await.unwrap();
        let mut dup = route_input("third");
        dup.if_id = Some(1);
        assert!(save_tunnel(&s, None, &dup).await.is_err());
        delete_tunnel(&s, id + 1).await.unwrap();

        a.apply(&s).await.unwrap();
        let c = read(&t, SWANCTL_CONF);
        assert!(
            c.contains("if_id_in = 1") && c.contains("if_id_out = 1"),
            "{c}"
        );
        assert!(c.contains("local_ts = 0.0.0.0/0,::/0"), "{c}");
        let calls = ip.calls.lock().unwrap().clone();
        assert!(
            calls.contains(&"ip link add xfrm1 type xfrm dev lo if_id 1".to_string()),
            "{calls:?}"
        );
        assert!(calls.contains(&"ip addr replace 169.254.10.1/30 dev xfrm1".to_string()));
        assert!(calls.contains(&"ip link set dev xfrm1 mtu 1400".to_string()));
        assert!(
            read(&t, CHARON_ROUTES_CONF).contains("install_routes = no"),
            "wildcard selectors must not install routes"
        );
        // policy-mode tunnels never carry an if_id
        assert!(!render(
            &[&IpsecTunnel {
                mode: "policy".into(),
                ..all[0].clone()
            }],
            false
        )
        .contains("if_id_in"));

        // back to policy mode: no interface wanted, the drop-in goes away
        save_tunnel(
            &s,
            Some(id),
            &TunnelInput {
                mode: Some("policy".into()),
                local_ts: Some("192.168.50.0/24".into()),
                remote_ts: Some("10.2.0.0/16".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(!t.env.path(CHARON_ROUTES_CONF).exists());
        assert!(!read(&t, SWANCTL_CONF).contains("if_id_in"));
    }

    #[tokio::test]
    async fn bad_route_settings_are_refused() {
        let s = testutil::store().await;
        for (f, v) in [
            ("mode", "vti"),
            ("addr", "10.0.0.1"),
            ("mtu", "100"),
            ("dev", "bad dev"),
            ("id", "0"),
        ] {
            let mut i = route_input("r");
            match f {
                "mode" => i.mode = Some(v.into()),
                "addr" => i.tunnel_address = Some(v.into()),
                "mtu" => i.mtu = Some(v.parse().unwrap()),
                "dev" => i.xfrm_dev = Some(v.into()),
                _ => i.if_id = Some(v.parse().unwrap()),
            }
            assert!(save_tunnel(&s, None, &i).await.is_err(), "{f}={v}");
        }
    }

    #[tokio::test]
    async fn connect_and_disconnect_requests_reach_swanctl_once() {
        let t = testutil::env(&[SWANCTL_BIN]);
        let s = testutil::store().await;
        let sw = std::sync::Arc::new(FakeSwanctl {
            services: Some(t.services.clone()),
            ..Default::default()
        });
        let a = IpsecApplier::new(t.env.clone(), sw.clone())
            .with_cmd(std::sync::Arc::new(FakeIp::default()));
        save_tunnel(&s, None, &input("site-b")).await.unwrap();
        assert!(request_action(&s, "nope", "connect").await.is_err());
        assert!(request_action(&s, "site-b", "reboot").await.is_err());
        request_action(&s, "site-b", "disconnect").await.unwrap();
        request_action(&s, "site-b", "connect").await.unwrap();
        a.apply(&s).await.unwrap();
        let calls = sw.calls.lock().unwrap().clone();
        let term = calls
            .iter()
            .position(|c| c == "--terminate --ike patronus-site-b");
        let init = calls
            .iter()
            .position(|c| c.starts_with("--initiate --child site-b --ike patronus-site-b"));
        assert!(term.is_some() && init.is_some() && term < init, "{calls:?}");
        // handled requests are gone: the next apply does not repeat them
        let n = calls.len();
        a.apply(&s).await.unwrap();
        let again = sw
            .calls
            .lock()
            .unwrap()
            .iter()
            .skip(n)
            .filter(|c| c.starts_with("--initiate") || c.starts_with("--terminate"))
            .count();
        assert_eq!(again, 0);
    }
}
