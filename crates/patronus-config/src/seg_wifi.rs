//! Per-device Wi-Fi credentials (docs/design/device-segmentation.md, section 5):
//! the Wi-Fi networks Patronus' access point serves and one passphrase per
//! device, bound to the device's MAC.
//!
//! - WPA2: hostapd's `wpa_psk_file` holds `keyid=dev-<id> <mac> <passphrase>`;
//!   adding or removing a line is applied live (`reload_wpa_psk`).
//! - WPA3-SAE: `sae_password=<pw>|mac=<mac>|id=dev-<id>` lines live in
//!   hostapd.conf, which stock hostapd reads only at start (a restart).
//! - Enrolment: a device created without a MAC is `pending`; its passphrase
//!   sits in the PSK file with the wildcard MAC `00:00:00:00:00:00`. The first
//!   join makes hostapd report `AP-STA-CONNECTED <mac> keyid=dev-<id>`
//!   ([`bind_pending`]) and the entry becomes MAC-bound. Unused pending
//!   credentials expire after 24 h.
//! - Unknown devices: per network `reject` (not in the list = cannot
//!   associate) or `enrol` (a shared secret that grants nothing: such a
//!   station gets an address but no nft binding, i.e. quarantine).
//!
//! Passphrases are generated here (100 bits), shown once, and never listed by
//! the API; revealing one again is an audited admin action.

use crate::seg::{self, db, invalid, now, unique, Device, DeviceInput};
use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::Ipv4Addr;

pub const SECURITIES: &[&str] = &["wpa2", "wpa2_wpa3", "wpa3"];
/// Pending credentials stop working after this long.
pub const PENDING_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Network {
    pub id: i64,
    pub name: String,
    pub ifname: String,
    pub ssid: String,
    pub band: String,
    pub channel: i64,
    pub country: String,
    pub security: String,
    pub segment: String,
    pub unknown_policy: String,
    pub has_enrol_secret: bool,
    pub enabled: bool,
    /// SAE entries live in hostapd.conf: changing them restarts hostapd
    pub restart_on_credential_change: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkInput {
    pub name: String,
    pub ifname: String,
    pub ssid: String,
    #[serde(default)]
    pub band: Option<String>,
    #[serde(default)]
    pub channel: Option<i64>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub segment: Option<String>,
    #[serde(default)]
    pub unknown_policy: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Credential {
    pub id: i64,
    pub device_id: i64,
    pub device: String,
    pub network_id: i64,
    pub network: String,
    pub kind: String,
    pub state: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub expires_at: Option<i64>,
}

/// What creating a device with a Wi-Fi credential returns: the only time the
/// passphrase is shown without an explicit, audited reveal.
#[derive(Debug, Clone, Serialize)]
pub struct Issued {
    pub device: Device,
    pub credential_id: i64,
    pub network: String,
    pub ssid: String,
    pub secret: String,
    /// `WIFI:T:WPA;S:<ssid>;P:<secret>;;` for a QR code
    pub qr: String,
    pub security: String,
}

/// Everything the access-point renderer needs for one network (with secrets).
#[derive(Debug, Clone, PartialEq)]
pub struct ApNet {
    pub network: Network,
    pub enrol_secret: Option<String>,
    /// resolved from `network.segment` by the caller
    pub creds: Vec<ApCred>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApCred {
    pub keyid: String,
    /// `None` while pending (wildcard entry)
    pub mac: Option<String>,
    pub kind: String,
    pub secret: String,
}

pub fn keyid_of(device_id: i64) -> String {
    format!("dev-{device_id}")
}

/// `dev-<id>` -> id
pub fn parse_keyid(k: &str) -> Option<i64> {
    k.strip_prefix("dev-")?.parse().ok().filter(|n| *n > 0)
}

// ---------------------------------------------------------------------------
// validation and secrets
// ---------------------------------------------------------------------------

/// WPA2 passphrase: 8..63 printable ASCII without spaces, or 64 hex digits.
pub fn check_psk(p: &str) -> Result<()> {
    let ok_chars = p.bytes().all(|b| b.is_ascii_graphic());
    let hex64 = p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit());
    if (8..=63).contains(&p.len()) && ok_chars || hex64 {
        Ok(())
    } else {
        Err(invalid(
            "WPA2 passphrase: 8-63 printable ASCII characters without spaces (or 64 hex digits)",
        ))
    }
}

/// SAE password: 8..80 printable ASCII; `|` separates hostapd's options in
/// `sae_password=pw|mac=..|id=..` and would corrupt the line, so it is refused.
pub fn check_sae(p: &str) -> Result<()> {
    if (8..=80).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_graphic() && b != b'|') {
        Ok(())
    } else {
        Err(invalid(
            "SAE password: 8-80 printable ASCII characters without '|' or spaces",
        ))
    }
}

/// A fresh passphrase: 20 symbols of a 32-letter alphabet (100 bits) in four
/// groups, `xxxxx-xxxxx-xxxxx-xxxxx`.
pub fn generate_passphrase() -> String {
    const A: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789"; // 31 symbols without look-alikes
    let mut out = String::with_capacity(23);
    let mut n = 0;
    while n < 20 {
        for b in uuid::Uuid::new_v4().as_bytes() {
            // rejection sampling keeps the symbols uniform
            if (*b as usize) < 248 && n < 20 {
                if n > 0 && n % 5 == 0 {
                    out.push('-');
                }
                out.push(A[*b as usize % A.len()] as char);
                n += 1;
            }
        }
    }
    out
}

/// The text a phone's camera turns into a "join this network" prompt.
pub fn wifi_uri(ssid: &str, secret: &str, security: &str) -> String {
    let esc = |s: &str| {
        s.replace('\\', "\\\\")
            .replace(';', "\\;")
            .replace(',', "\\,")
            .replace(':', "\\:")
            .replace('"', "\\\"")
    };
    let t = if security == "wpa3" { "SAE" } else { "WPA" };
    format!("WIFI:T:{t};S:{};P:{};;", esc(ssid), esc(secret))
}

fn check_ssid(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 32
        || !s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        || s.starts_with(' ')
        || s.ends_with(' ')
    {
        return Err(invalid(
            "SSID: 1-32 printable ASCII characters, no leading or trailing space",
        ));
    }
    Ok(())
}

fn check_channel(band: &str, ch: i64) -> Result<()> {
    let ok = match band {
        "2g" => (1..=13).contains(&ch),
        "5g" => matches!(
            ch,
            36 | 40
                | 44
                | 48
                | 52
                | 56
                | 60
                | 64
                | 100
                | 104
                | 108
                | 112
                | 116
                | 120
                | 124
                | 128
                | 132
                | 136
                | 140
                | 144
                | 149
                | 153
                | 157
                | 161
                | 165
        ),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("channel {ch} for band {band}")))
    }
}

fn network_row(r: &sqlx::sqlite::SqliteRow) -> Network {
    let security: String = r.get("security");
    Network {
        id: r.get("id"),
        name: r.get("name"),
        ifname: r.get("ifname"),
        ssid: r.get("ssid"),
        band: r.get("band"),
        channel: r.get("channel"),
        country: r.get("country"),
        restart_on_credential_change: security != "wpa2",
        security,
        segment: r.get("segment"),
        unknown_policy: r.get("unknown_policy"),
        has_enrol_secret: r.get::<Option<String>, _>("enrol_secret").is_some(),
        enabled: r.get::<i64, _>("enabled") != 0,
    }
}

// ---------------------------------------------------------------------------
// networks
// ---------------------------------------------------------------------------

pub async fn list_networks(store: &ConfigStore) -> Result<Vec<Network>> {
    let rows = sqlx::query("SELECT * FROM seg_wifi_networks ORDER BY name")
        .fetch_all(store.pool()?)
        .await
        .map_err(db("list Wi-Fi networks"))?;
    Ok(rows.iter().map(network_row).collect())
}

pub async fn get_network(store: &ConfigStore, id: i64) -> Result<Option<Network>> {
    let r = sqlx::query("SELECT * FROM seg_wifi_networks WHERE id = ?")
        .bind(id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read Wi-Fi network"))?;
    Ok(r.as_ref().map(network_row))
}

pub async fn network_by_name(store: &ConfigStore, name: &str) -> Result<Option<Network>> {
    let r = sqlx::query("SELECT * FROM seg_wifi_networks WHERE name = ?")
        .bind(name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read Wi-Fi network"))?;
    Ok(r.as_ref().map(network_row))
}

struct Checked {
    band: String,
    channel: i64,
    country: String,
    security: String,
    segment: String,
    policy: String,
}

fn check_network(i: &NetworkInput) -> Result<Checked> {
    if !seg::is_name(&i.name) {
        return Err(invalid(format!(
            "network name {:?}: use a-z 0-9 _ - (max 32)",
            i.name
        )));
    }
    if !seg::is_ifname(&i.ifname) {
        return Err(invalid(format!("interface {:?}", i.ifname)));
    }
    check_ssid(&i.ssid)?;
    let band = i.band.clone().unwrap_or_else(|| "2g".into());
    let channel = i.channel.unwrap_or(if band == "5g" { 36 } else { 6 });
    check_channel(&band, channel)?;
    let country = i.country.clone().unwrap_or_else(|| "US".into());
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid(format!(
            "country code {country:?}: two capital letters"
        )));
    }
    let security = i.security.clone().unwrap_or_else(|| "wpa2".into());
    if !SECURITIES.contains(&security.as_str()) {
        return Err(invalid(format!(
            "security {security:?}: wpa2, wpa2_wpa3 or wpa3"
        )));
    }
    let segment = seg::check_segment(i.segment.as_deref().unwrap_or("@lan"))?;
    let policy = i.unknown_policy.clone().unwrap_or_else(|| "reject".into());
    if policy != "reject" && policy != "enrol" {
        return Err(invalid("unknown device policy: reject or enrol"));
    }
    Ok(Checked {
        band,
        channel,
        country,
        security,
        segment,
        policy,
    })
}

pub async fn create_network(store: &ConfigStore, i: &NetworkInput) -> Result<i64> {
    let c = check_network(i)?;
    let enrol = (c.policy == "enrol").then(generate_passphrase);
    let r = sqlx::query(
        "INSERT INTO seg_wifi_networks (name, ifname, ssid, band, channel, country, security, segment, unknown_policy, enrol_secret, enabled, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&i.name)
    .bind(&i.ifname)
    .bind(&i.ssid)
    .bind(&c.band)
    .bind(c.channel)
    .bind(&c.country)
    .bind(&c.security)
    .bind(&c.segment)
    .bind(&c.policy)
    .bind(enrol)
    .bind(i.enabled.unwrap_or(true) as i64)
    .bind(now())
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("Wi-Fi network {} or interface {}", i.name, i.ifname)))?;
    Ok(r.last_insert_rowid())
}

pub async fn update_network(store: &ConfigStore, id: i64, i: &NetworkInput) -> Result<()> {
    let c = check_network(i)?;
    let old = get_network(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no Wi-Fi network {id}")))?;
    // moving to WPA3-only strands pending (MAC-less) devices: SAE entries need a MAC
    if c.security == "wpa3" && old.security != "wpa3" {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM seg_wifi_creds WHERE network_id = ? AND state = 'pending'",
        )
        .bind(id)
        .fetch_one(store.pool()?)
        .await
        .map_err(db("count pending"))?;
        if n > 0 {
            return Err(invalid(
                "security: devices still waiting for their first join cannot use a WPA3-only network (SAE needs the MAC); wait for them or revoke them first",
            ));
        }
    }
    let keep_secret: Option<String> =
        sqlx::query_scalar("SELECT enrol_secret FROM seg_wifi_networks WHERE id = ?")
            .bind(id)
            .fetch_one(store.pool()?)
            .await
            .map_err(db("read enrol secret"))?;
    let enrol = if c.policy == "enrol" {
        Some(keep_secret.unwrap_or_else(generate_passphrase))
    } else {
        None
    };
    sqlx::query(
        "UPDATE seg_wifi_networks SET name=?, ifname=?, ssid=?, band=?, channel=?, country=?, security=?, segment=?, unknown_policy=?, enrol_secret=?, enabled=?, updated_at=? WHERE id=?",
    )
    .bind(&i.name)
    .bind(&i.ifname)
    .bind(&i.ssid)
    .bind(&c.band)
    .bind(c.channel)
    .bind(&c.country)
    .bind(&c.security)
    .bind(&c.segment)
    .bind(&c.policy)
    .bind(enrol)
    .bind(i.enabled.unwrap_or(old.enabled) as i64)
    .bind(now())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &format!("Wi-Fi network {} or interface {}", i.name, i.ifname)))?;
    Ok(())
}

pub async fn delete_network(store: &ConfigStore, id: i64) -> Result<()> {
    let r = sqlx::query("DELETE FROM seg_wifi_networks WHERE id = ?")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("delete Wi-Fi network"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no Wi-Fi network {id}")));
    }
    Ok(())
}

/// New shared enrolment secret for `unknown_policy=enrol` (the old one stops working).
pub async fn rotate_enrol_secret(store: &ConfigStore, id: i64) -> Result<String> {
    let n = get_network(store, id)
        .await?
        .ok_or_else(|| Error::Config(format!("no Wi-Fi network {id}")))?;
    if n.unknown_policy != "enrol" {
        return Err(invalid(
            "rotate: this network does not use an enrolment secret",
        ));
    }
    let s = generate_passphrase();
    sqlx::query("UPDATE seg_wifi_networks SET enrol_secret = ? WHERE id = ?")
        .bind(&s)
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("rotate enrol secret"))?;
    Ok(s)
}

/// The enrolment secret (admin reveal; the caller audits it).
pub async fn enrol_secret(store: &ConfigStore, id: i64) -> Result<String> {
    let s: Option<Option<String>> =
        sqlx::query_scalar("SELECT enrol_secret FROM seg_wifi_networks WHERE id = ?")
            .bind(id)
            .fetch_optional(store.pool()?)
            .await
            .map_err(db("read enrol secret"))?;
    s.flatten()
        .ok_or_else(|| Error::Config(format!("no enrolment secret for network {id}")))
}

// ---------------------------------------------------------------------------
// credentials
// ---------------------------------------------------------------------------

fn kind_for(security: &str) -> &'static str {
    match security {
        "wpa3" => "sae",
        "wpa2_wpa3" => "psk+sae",
        _ => "psk",
    }
}

pub async fn list_credentials(store: &ConfigStore) -> Result<Vec<Credential>> {
    let rows = sqlx::query(
        "SELECT c.id, c.device_id, d.name, c.network_id, n.name, c.kind, c.state, c.created_at, c.revoked_at, c.expires_at
         FROM seg_wifi_creds c JOIN seg_devices d ON d.id = c.device_id JOIN seg_wifi_networks n ON n.id = c.network_id
         ORDER BY d.name, c.id",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("list Wi-Fi credentials"))?;
    Ok(rows
        .iter()
        .map(|r| Credential {
            id: r.get(0),
            device_id: r.get(1),
            device: r.get(2),
            network_id: r.get(3),
            network: r.get(4),
            kind: r.get(5),
            state: r.get(6),
            created_at: r.get(7),
            revoked_at: r.get(8),
            expires_at: r.get(9),
        })
        .collect())
}

async fn insert_credential(
    store: &ConfigStore,
    device: i64,
    net: &Network,
    state: &str,
    expires: Option<i64>,
) -> Result<(i64, String)> {
    let kind = kind_for(&net.security);
    for _ in 0..8 {
        let secret = generate_passphrase();
        let r = sqlx::query(
            "INSERT INTO seg_wifi_creds (device_id, network_id, kind, secret, state, created_at, expires_at)
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(device)
        .bind(net.id)
        .bind(kind)
        .bind(&secret)
        .bind(state)
        .bind(now())
        .bind(expires)
        .execute(store.pool()?)
        .await;
        match r {
            Ok(r) => return Ok((r.last_insert_rowid(), secret)),
            Err(e) if e.to_string().contains("UNIQUE") => continue,
            Err(e) => return Err(Error::Config(format!("store Wi-Fi credential: {e}"))),
        }
    }
    Err(Error::Config(
        "could not generate a unique passphrase".into(),
    ))
}

/// Create a Wi-Fi device on `network` with its own passphrase. Without a MAC
/// it is pending (WPA2 / transition networks only: SAE entries are bound to a
/// MAC) and its passphrase works from any MAC until the first join.
pub async fn create_wifi_device(
    store: &ConfigStore,
    i: &DeviceInput,
    network: &str,
) -> Result<Issued> {
    let net = network_by_name(store, network)
        .await?
        .ok_or_else(|| invalid(format!("Wi-Fi network {network:?}: no such network")))?;
    let has_mac = i.mac.as_deref().is_some_and(|m| !m.trim().is_empty());
    if !has_mac && net.security == "wpa3" {
        return Err(invalid(
            "device: a WPA3-only network needs the device's MAC address (SAE passwords are bound to it)",
        ));
    }
    let mut inp = i.clone();
    inp.kind = Some("wifi".into());
    inp.segment = Some(net.segment.clone());
    let d = seg::create_device(store, &inp).await?;
    let (state, exp) = if d.state == "active" {
        ("active", None)
    } else {
        ("pending", Some(now() + PENDING_TTL_SECS))
    };
    let (cid, secret) = match insert_credential(store, d.id, &net, state, exp).await {
        Ok(v) => v,
        Err(e) => {
            let _ = seg::delete_device(store, d.id).await;
            return Err(e);
        }
    };
    Ok(Issued {
        device: d,
        credential_id: cid,
        network: net.name.clone(),
        ssid: net.ssid.clone(),
        qr: wifi_uri(&net.ssid, &secret, &net.security),
        security: net.security.clone(),
        secret,
    })
}

/// New passphrase for a device. `grace_secs > 0` keeps the old one working
/// for that long (no-downtime rotation); 0 revokes it at once.
pub async fn rotate(store: &ConfigStore, device_id: i64, grace_secs: i64) -> Result<Issued> {
    let d = seg::get_device(store, device_id)
        .await?
        .ok_or_else(|| Error::Config(format!("no device {device_id}")))?;
    if d.state == "revoked" {
        return Err(invalid("rotate: the device is revoked"));
    }
    let row = sqlx::query(
        "SELECT network_id FROM seg_wifi_creds WHERE device_id = ? AND state != 'revoked' ORDER BY id DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("read credential"))?
    .ok_or_else(|| invalid(format!("rotate: {} has no Wi-Fi credential", d.name)))?;
    let net = get_network(store, row.get(0))
        .await?
        .ok_or_else(|| Error::Config("network vanished".into()))?;
    let (state, exp) = if d.state == "active" {
        ("active", None)
    } else {
        ("pending", Some(now() + PENDING_TTL_SECS))
    };
    let old: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM seg_wifi_creds WHERE device_id = ? AND state != 'revoked'",
    )
    .bind(device_id)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("read credentials"))?;
    let (cid, secret) = insert_credential(store, device_id, &net, state, exp).await?;
    for o in old {
        if grace_secs > 0 {
            sqlx::query("UPDATE seg_wifi_creds SET expires_at = ? WHERE id = ?")
                .bind(now() + grace_secs)
                .bind(o)
                .execute(store.pool()?)
                .await
                .map_err(db("set grace period"))?;
        } else {
            sqlx::query("UPDATE seg_wifi_creds SET state='revoked', revoked_at=? WHERE id=?")
                .bind(now())
                .bind(o)
                .execute(store.pool()?)
                .await
                .map_err(db("revoke old credential"))?;
        }
    }
    Ok(Issued {
        device: d,
        credential_id: cid,
        network: net.name.clone(),
        ssid: net.ssid.clone(),
        qr: wifi_uri(&net.ssid, &secret, &net.security),
        security: net.security.clone(),
        secret,
    })
}

/// Admin reveal of a stored passphrase: (secret, ssid, security). The caller writes the audit row.
pub async fn reveal(store: &ConfigStore, cred_id: i64) -> Result<(String, String, String)> {
    let r = sqlx::query(
        "SELECT c.secret, n.ssid, n.security, c.state FROM seg_wifi_creds c JOIN seg_wifi_networks n ON n.id = c.network_id WHERE c.id = ?",
    )
    .bind(cred_id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("read credential"))?
    .ok_or_else(|| Error::Config(format!("no credential {cred_id}")))?;
    if r.get::<String, _>(3) == "revoked" {
        return Err(invalid("reveal: the credential is revoked"));
    }
    Ok((r.get(0), r.get(1), r.get(2)))
}

pub async fn revoke_credential(store: &ConfigStore, cred_id: i64) -> Result<()> {
    let r = sqlx::query(
        "UPDATE seg_wifi_creds SET state='revoked', revoked_at=? WHERE id=? AND state != 'revoked'",
    )
    .bind(now())
    .bind(cred_id)
    .execute(store.pool()?)
    .await
    .map_err(db("revoke credential"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("no active credential {cred_id}")));
    }
    Ok(())
}

/// hostapd reported `AP-STA-CONNECTED <mac> keyid=<keyid>`: learn the MAC of a
/// pending device. `Ok(None)` when the key id is not a Patronus device (the
/// shared enrolment key, a manual entry).
pub async fn bind_pending(
    store: &ConfigStore,
    keyid: &str,
    mac: &str,
    ip_hint: Option<Ipv4Addr>,
) -> Result<Option<Device>> {
    let Some(id) = parse_keyid(keyid) else {
        return Ok(None);
    };
    let Some(d) = seg::get_device(store, id).await? else {
        return Ok(None);
    };
    if d.kind != "wifi" {
        return Ok(None);
    }
    let bound = seg::activate_pending(store, id, mac, ip_hint).await?;
    sqlx::query("UPDATE seg_wifi_creds SET state='active', expires_at=NULL WHERE device_id=? AND state='pending'")
        .bind(id)
        .execute(store.pool()?)
        .await
        .map_err(db("activate credentials"))?;
    Ok(Some(bound))
}

/// Revoke pending credentials (and their MAC-less devices) that were never used.
pub async fn expire_pending(store: &ConfigStore, at: i64) -> Result<usize> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT device_id FROM seg_wifi_creds WHERE state='pending' AND expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(at)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("find expired credentials"))?;
    for id in &ids {
        seg::revoke_device(store, *id).await?;
    }
    Ok(ids.len())
}

/// Everything hostapd needs, per enabled network: who may join with what.
/// Revoked and expired credentials are not included; that omission IS the revocation.
pub async fn ap_config(store: &ConfigStore, at: i64) -> Result<Vec<ApNet>> {
    let mut out = Vec::new();
    for n in list_networks(store)
        .await?
        .into_iter()
        .filter(|n| n.enabled)
    {
        let enrol = if n.unknown_policy == "enrol" {
            enrol_secret(store, n.id).await.ok()
        } else {
            None
        };
        let rows = sqlx::query(
            "SELECT c.kind, c.secret, d.id, d.mac, d.state, c.state, c.expires_at
             FROM seg_wifi_creds c JOIN seg_devices d ON d.id = c.device_id
             WHERE c.network_id = ? AND c.state != 'revoked' AND d.state != 'revoked' ORDER BY c.id",
        )
        .bind(n.id)
        .fetch_all(store.pool()?)
        .await
        .map_err(db("read Wi-Fi credentials"))?;
        let mut creds = Vec::new();
        for r in rows {
            let exp: Option<i64> = r.get(6);
            if exp.is_some_and(|e| e <= at) {
                continue;
            }
            let state: String = r.get(5);
            let mac: Option<String> = r.get(3);
            if state == "pending" && mac.is_some() {
                continue; // inconsistent row: never widen
            }
            creds.push(ApCred {
                keyid: keyid_of(r.get(2)),
                mac,
                kind: r.get(0),
                secret: r.get(1),
            });
        }
        out.push(ApNet {
            network: n,
            enrol_secret: enrol,
            creds,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lab() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO interfaces (name, enabled, role, updated_at) VALUES ('br0',1,'lan',0)",
        )
        .execute(s.pool().unwrap())
        .await
        .unwrap();
        sqlx::query("INSERT INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        s
    }

    fn net(name: &str, ifname: &str, security: &str) -> NetworkInput {
        NetworkInput {
            name: name.into(),
            ifname: ifname.into(),
            ssid: "HomeNet".into(),
            security: Some(security.into()),
            ..Default::default()
        }
    }

    fn dev(name: &str, mac: Option<&str>) -> DeviceInput {
        DeviceInput {
            name: name.into(),
            mac: mac.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn passphrases_are_long_unique_and_valid_for_both_wpa_modes() {
        let a = generate_passphrase();
        let b = generate_passphrase();
        assert_ne!(a, b);
        assert_eq!(a.len(), 23, "{a}");
        assert_eq!(a.matches('-').count(), 3);
        check_psk(&a).unwrap();
        check_sae(&a).unwrap();
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'));
        assert!(check_psk("short").is_err() && check_psk("has space 123").is_err());
        assert!(check_sae("abc|mac=00:00:00:00:00:00").is_err());
        assert!(check_psk(&"a".repeat(64)).is_ok(), "64 hex digits");
        assert!(check_psk(&"g".repeat(64)).is_err());
    }

    #[test]
    fn qr_text_escapes_special_characters() {
        assert_eq!(
            wifi_uri("Home", "abc-def", "wpa2"),
            "WIFI:T:WPA;S:Home;P:abc-def;;"
        );
        assert_eq!(
            wifi_uri("a;b:c", "p,w", "wpa3"),
            r"WIFI:T:SAE;S:a\;b\:c;P:p\,w;;"
        );
    }

    #[test]
    fn keyids_round_trip() {
        assert_eq!(parse_keyid(&keyid_of(42)), Some(42));
        for bad in ["", "enrol", "dev-", "dev-0", "dev--3", "dev-x", "laptop"] {
            assert_eq!(parse_keyid(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn networks_validate_and_enrol_secret_exists_only_for_enrol() {
        let s = lab().await;
        let id = create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        let n = get_network(&s, id).await.unwrap().unwrap();
        assert!(!n.has_enrol_secret && !n.restart_on_credential_change);
        let mut e = net("guests", "wlan1", "wpa2_wpa3");
        e.unknown_policy = Some("enrol".into());
        let eid = create_network(&s, &e).await.unwrap();
        let en = get_network(&s, eid).await.unwrap().unwrap();
        assert!(en.has_enrol_secret && en.restart_on_credential_change);
        let secret = enrol_secret(&s, eid).await.unwrap();
        assert_ne!(rotate_enrol_secret(&s, eid).await.unwrap(), secret);
        assert!(rotate_enrol_secret(&s, id).await.is_err());
        // hostile and out-of-range input
        for bad in [
            NetworkInput {
                ssid: "bad\nssid".into(),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                ssid: "".into(),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                ssid: "a".repeat(33),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                ifname: "wlan0; reboot".into(),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                channel: Some(14),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                band: Some("6g".into()),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                band: Some("5g".into()),
                channel: Some(6),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                country: Some("usa".into()),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                security: Some("open".into()),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                unknown_policy: Some("allow".into()),
                ..net("x1", "wlan2", "wpa2")
            },
            NetworkInput {
                segment: Some("@lan\"".into()),
                ..net("x1", "wlan2", "wpa2")
            },
            net("Bad Name", "wlan2", "wpa2"),
            net("dup-if", "wlan0", "wpa2"),
        ] {
            assert!(create_network(&s, &bad).await.is_err(), "{bad:?}");
        }
        assert_eq!(list_networks(&s).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_pending_device_is_enrolled_by_its_first_join() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        let i = create_wifi_device(&s, &dev("phone", None), "home")
            .await
            .unwrap();
        assert_eq!(i.device.state, "pending");
        assert!(i.device.mac.is_none() && i.device.ip4.is_none());
        assert_eq!(i.device.kind, "wifi");
        check_psk(&i.secret).unwrap();
        assert!(i.qr.starts_with("WIFI:T:WPA;S:HomeNet;P:"));
        // hostapd gets a wildcard entry
        let ap = ap_config(&s, now()).await.unwrap();
        assert_eq!(ap[0].creds.len(), 1);
        assert_eq!(
            (ap[0].creds[0].mac.clone(), ap[0].creds[0].keyid.as_str()),
            (None, "dev-1")
        );
        // the first join reports the MAC
        let d = bind_pending(&s, "dev-1", "02:AA:00:00:00:21", None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (d.state.as_str(), d.mac.as_deref()),
            ("active", Some("02:aa:00:00:00:21"))
        );
        assert_eq!(d.ip4.as_deref(), Some("192.168.50.2"));
        let ap = ap_config(&s, now()).await.unwrap();
        assert_eq!(
            ap[0].creds[0].mac.as_deref(),
            Some("02:aa:00:00:00:21"),
            "now MAC-bound"
        );
        // the same event again is a no-op; a different MAC is refused
        assert!(bind_pending(&s, "dev-1", "02:aa:00:00:00:21", None)
            .await
            .unwrap()
            .is_some());
        assert!(bind_pending(&s, "dev-1", "02:aa:00:00:00:22", None)
            .await
            .is_err());
        // the shared enrolment key and unknown ids are not devices
        assert!(bind_pending(&s, "enrol", "02:aa:00:00:00:30", None)
            .await
            .unwrap()
            .is_none());
        assert!(bind_pending(&s, "dev-77", "02:aa:00:00:00:30", None)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn the_lease_address_is_kept_when_it_is_free() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        create_wifi_device(&s, &dev("phone", None), "home")
            .await
            .unwrap();
        let d = bind_pending(
            &s,
            "dev-1",
            "02:aa:00:00:00:21",
            Some("192.168.50.120".parse().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(d.ip4.as_deref(), Some("192.168.50.120"));
        // outside the subnet or the router's own: ignored
        create_wifi_device(&s, &dev("tab", None), "home")
            .await
            .unwrap();
        let d = bind_pending(
            &s,
            "dev-2",
            "02:aa:00:00:00:22",
            Some("192.168.50.1".parse().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(d.ip4.as_deref(), Some("192.168.50.1"));
    }

    #[tokio::test]
    async fn revoking_a_device_removes_its_credential_from_the_ap_config() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        let a = create_wifi_device(&s, &dev("laptop", Some("02:aa:00:00:00:11")), "home")
            .await
            .unwrap();
        let b = create_wifi_device(&s, &dev("phone", Some("02:aa:00:00:00:12")), "home")
            .await
            .unwrap();
        assert_eq!(a.device.state, "active");
        assert_eq!(ap_config(&s, now()).await.unwrap()[0].creds.len(), 2);
        seg::revoke_device(&s, b.device.id).await.unwrap();
        let ap = ap_config(&s, now()).await.unwrap();
        assert_eq!(ap[0].creds.len(), 1, "revocation = omission");
        assert_eq!(ap[0].creds[0].keyid, keyid_of(a.device.id));
        assert!(
            reveal(&s, b.credential_id).await.is_err(),
            "a revoked credential cannot be revealed"
        );
        let all = list_credentials(&s).await.unwrap();
        assert!(all
            .iter()
            .any(|c| c.device == "phone" && c.state == "revoked"));
        // the listing never carries a secret
        assert!(!serde_json::to_string(&all).unwrap().contains(&a.secret));
        // the secret is available to an explicit reveal only
        assert_eq!(reveal(&s, a.credential_id).await.unwrap().0, a.secret);
    }

    #[tokio::test]
    async fn rotation_can_keep_the_old_passphrase_for_a_grace_period() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        let a = create_wifi_device(&s, &dev("laptop", Some("02:aa:00:00:00:11")), "home")
            .await
            .unwrap();
        let r = rotate(&s, a.device.id, 3600).await.unwrap();
        assert_ne!(r.secret, a.secret);
        let ap = ap_config(&s, now()).await.unwrap();
        assert_eq!(ap[0].creds.len(), 2, "both work during the grace period");
        // after the grace period the old one is gone
        assert_eq!(ap_config(&s, now() + 7200).await.unwrap()[0].creds.len(), 1);
        // immediate rotation revokes
        let r2 = rotate(&s, a.device.id, 0).await.unwrap();
        let ap = ap_config(&s, now() + 7200).await.unwrap();
        assert_eq!(ap[0].creds.len(), 1);
        assert_eq!(ap[0].creds[0].secret, r2.secret);
    }

    #[tokio::test]
    async fn unused_pending_credentials_expire() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        let i = create_wifi_device(&s, &dev("phone", None), "home")
            .await
            .unwrap();
        assert_eq!(expire_pending(&s, now() + 60).await.unwrap(), 0);
        assert_eq!(
            ap_config(&s, now() + PENDING_TTL_SECS + 1).await.unwrap()[0]
                .creds
                .len(),
            0,
            "expired = not rendered even before the sweep"
        );
        assert_eq!(
            expire_pending(&s, now() + PENDING_TTL_SECS + 1)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            seg::get_device(&s, i.device.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "revoked"
        );
    }

    #[tokio::test]
    async fn wpa3_only_needs_a_mac_and_cannot_strand_pending_devices() {
        let s = lab().await;
        let id = create_network(&s, &net("sae", "wlan0", "wpa3"))
            .await
            .unwrap();
        assert!(create_wifi_device(&s, &dev("phone", None), "sae")
            .await
            .is_err());
        let ok = create_wifi_device(&s, &dev("laptop", Some("02:aa:00:00:00:11")), "sae")
            .await
            .unwrap();
        assert_eq!(list_credentials(&s).await.unwrap()[0].kind, "sae");
        assert!(wifi_uri("x", &ok.secret, "wpa3").contains("T:SAE"));
        // a WPA2 network with a pending device cannot be switched to WPA3-only
        let wid = create_network(&s, &net("home", "wlan1", "wpa2_wpa3"))
            .await
            .unwrap();
        create_wifi_device(&s, &dev("tab", None), "home")
            .await
            .unwrap();
        let mut up = net("home", "wlan1", "wpa3");
        up.enabled = Some(true);
        assert!(update_network(&s, wid, &up).await.is_err());
        let _ = id;
    }

    #[tokio::test]
    async fn bad_device_input_does_not_leave_a_half_made_device() {
        let s = lab().await;
        create_network(&s, &net("home", "wlan0", "wpa2"))
            .await
            .unwrap();
        assert!(create_wifi_device(&s, &dev("bad name", None), "home")
            .await
            .is_err());
        assert!(create_wifi_device(&s, &dev("x", None), "nope")
            .await
            .is_err());
        assert!(seg::list_devices(&s).await.unwrap().is_empty());
        assert!(list_credentials(&s).await.unwrap().is_empty());
    }
}
