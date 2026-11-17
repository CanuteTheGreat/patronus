//! Wi-Fi client uplink (USE=wifi-client): wpa_supplicant joins an upstream access point on a wireless
//! device (the backup uplink of a router, e.g. behind mwan3-style failover). Everything the store holds
//! is the `wifi_clients` table (migration 0270).
//!
//! Layering: this module only associates the device. The device becomes an uplink like any other by the
//! normal interface settings (role wan/optN, IPv4 mode DHCP, metric) and by gateway groups (failover
//! tiers, monitor IPs), so dhcpcd/udhcpc, routes and the gateway monitor need no Wi-Fi special cases.
//!
//! One wpa_supplicant per device runs through [`crate::supervise`] (systemd template unit
//! `patronus-wpa@<dev>`, OpenRC `patronus-wpa.<dev>`, or detached directly in containers); its config is
//! rendered into the net state dir with mode 0600 (it holds the passphrase).

use crate::supervise::{which, DaemonSpec, Supervisor};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::path::{Path, PathBuf};

pub const SERVICE: &str = "patronus-wpa";
pub const DEFAULT_CTRL_DIR: &str = "/run/wpa_supplicant";

fn invalid(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Wi-Fi uplink: {m}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    Open,
    Wpa2,
    Wpa3,
    Wpa2Wpa3,
}

impl Security {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "open" => Ok(Self::Open),
            "" | "wpa2" => Ok(Self::Wpa2),
            "wpa3" => Ok(Self::Wpa3),
            "wpa2-wpa3" => Ok(Self::Wpa2Wpa3),
            o => Err(invalid(format!(
                "security {o:?} (open, wpa2, wpa3 or wpa2-wpa3)"
            ))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wpa2 => "wpa2",
            Self::Wpa3 => "wpa3",
            Self::Wpa2Wpa3 => "wpa2-wpa3",
        }
    }
}

/// A stored uplink. `psk` is the secret: `Serialize` for the API goes through [`WifiClient::public`].
#[derive(Debug, Clone, PartialEq)]
pub struct WifiClient {
    pub id: i64,
    pub device: String,
    pub enabled: bool,
    pub ssid: String,
    pub security: Security,
    pub psk: Option<String>,
    pub bssid: Option<String>,
    pub description: Option<String>,
}

impl WifiClient {
    /// API view: the passphrase is never part of it (only whether one is set).
    pub fn public(&self) -> Value {
        json!({
            "id": self.id,
            "device": self.device,
            "enabled": self.enabled,
            "ssid": self.ssid,
            "security": self.security.as_str(),
            "has_psk": self.psk.as_deref().is_some_and(|p| !p.is_empty()),
            "bssid": self.bssid,
            "description": self.description,
        })
    }
}

/// What a create/update carries. `psk` None or empty on an update keeps the stored passphrase.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WifiClientInput {
    pub device: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    pub ssid: String,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub psk: Option<String>,
    #[serde(default)]
    pub bssid: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn check_psk(p: &str) -> Result<()> {
    if p.len() == 64 {
        return if p.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(invalid(
                "a 64-character key must be hexadecimal (or use a passphrase of 8-63 characters)",
            ))
        };
    }
    if !(8..=63).contains(&p.len()) || !p.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(invalid(
            "passphrase must be 8-63 printable ASCII characters (or 64 hex digits)",
        ));
    }
    Ok(())
}

impl WifiClientInput {
    /// Validate; `stored` is the existing row (an empty passphrase keeps its secret).
    pub fn validated(&self, stored: Option<&WifiClient>) -> Result<WifiClient> {
        if !crate::netconf::is_valid_ifname(&self.device) {
            return Err(invalid(format!(
                "device {:?} is not an interface name",
                self.device
            )));
        }
        let ssid = self.ssid.as_str();
        if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(|c| c.is_control()) {
            return Err(invalid(
                "SSID must be 1-32 bytes without control characters",
            ));
        }
        let security = Security::parse(self.security.as_deref().unwrap_or("wpa2"))?;
        let given = self.psk.as_deref().filter(|p| !p.is_empty());
        let psk = if security == Security::Open {
            None
        } else {
            let p = given
                .map(str::to_string)
                .or_else(|| stored.and_then(|s| s.psk.clone()).filter(|p| !p.is_empty()))
                .ok_or_else(|| invalid("a passphrase is required unless the network is open"))?;
            check_psk(&p)?;
            Some(p)
        };
        let bssid = match self
            .bssid
            .as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty())
        {
            Some(b) => Some(
                crate::netconf::normalize_mac(b).map_err(|_| invalid(format!("BSSID {b:?}")))?,
            ),
            None => None,
        };
        let description = self
            .description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        if description
            .as_deref()
            .is_some_and(|d| d.len() > 200 || d.chars().any(|c| c.is_control()))
        {
            return Err(invalid("description (at most 200 characters, one line)"));
        }
        Ok(WifiClient {
            id: stored.map(|s| s.id).unwrap_or(0),
            device: self.device.clone(),
            enabled: self.enabled.unwrap_or(true),
            ssid: ssid.to_string(),
            security,
            psk,
            bssid,
            description,
        })
    }
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

fn row(r: &sqlx::sqlite::SqliteRow) -> Result<WifiClient> {
    Ok(WifiClient {
        id: r.get(0),
        device: r.get(1),
        enabled: r.get::<i64, _>(2) != 0,
        ssid: r.get(3),
        security: Security::parse(&r.get::<String, _>(4))?,
        psk: r.get::<Option<String>, _>(5).filter(|p| !p.is_empty()),
        bssid: r.get::<Option<String>, _>(6).filter(|p| !p.is_empty()),
        description: r.get::<Option<String>, _>(7).filter(|p| !p.is_empty()),
    })
}

const COLS: &str = "id, device, enabled, ssid, security, psk, bssid, description";

pub async fn list(store: &ConfigStore) -> Result<Vec<WifiClient>> {
    let rows = sqlx::query(&format!("SELECT {COLS} FROM wifi_clients ORDER BY device"))
        .fetch_all(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("wifi_clients: {e}")))?;
    rows.iter().map(row).collect()
}

pub async fn get(store: &ConfigStore, device: &str) -> Result<Option<WifiClient>> {
    Ok(list(store).await?.into_iter().find(|c| c.device == device))
}

/// Create or update (keyed by device) from validated input.
pub async fn save(store: &ConfigStore, input: &WifiClientInput) -> Result<WifiClient> {
    let stored = get(store, &input.device).await?;
    let c = input.validated(stored.as_ref())?;
    sqlx::query(
        "INSERT INTO wifi_clients (device, enabled, ssid, security, psk, bssid, description, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device) DO UPDATE SET enabled = excluded.enabled, ssid = excluded.ssid,
            security = excluded.security, psk = excluded.psk, bssid = excluded.bssid,
            description = excluded.description, updated_at = excluded.updated_at",
    )
    .bind(&c.device)
    .bind(c.enabled as i64)
    .bind(&c.ssid)
    .bind(c.security.as_str())
    .bind(c.psk.clone())
    .bind(c.bssid.clone())
    .bind(c.description.clone())
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("wifi_clients: {e}")))?;
    get(store, &c.device)
        .await?
        .ok_or_else(|| invalid("row vanished after save"))
}

pub async fn delete(store: &ConfigStore, device: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM wifi_clients WHERE device = ?")
        .bind(device)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("wifi_clients: {e}")))?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// wpa_supplicant.conf for one uplink. The SSID is written as hex (no quoting problems), the
/// passphrase quoted (wpa_supplicant takes everything between the first and last quote).
pub fn render_wpa_supplicant(c: &WifiClient, ctrl_dir: &Path) -> Result<String> {
    let mut o = String::new();
    o.push_str("# generated by Patronus (Wi-Fi uplink); do not edit\n");
    o.push_str(&format!("ctrl_interface={}\n", ctrl_dir.display()));
    o.push_str("update_config=0\nap_scan=1\nnetwork={\n");
    o.push_str(&format!("\tssid={}\n\tscan_ssid=1\n", hex(&c.ssid)));
    if let Some(b) = &c.bssid {
        o.push_str(&format!("\tbssid={b}\n"));
    }
    let key = |o: &mut String| -> Result<()> {
        let p = c.psk.as_deref().ok_or_else(|| invalid("no passphrase"))?;
        check_psk(p)?;
        if p.len() == 64 {
            o.push_str(&format!("\tpsk={p}\n"));
        } else {
            o.push_str(&format!("\tpsk=\"{p}\"\n"));
        }
        Ok(())
    };
    match c.security {
        Security::Open => o.push_str("\tkey_mgmt=NONE\n"),
        Security::Wpa2 => {
            o.push_str("\tkey_mgmt=WPA-PSK\n\tproto=RSN\n\tieee80211w=0\n");
            key(&mut o)?;
        }
        Security::Wpa3 => {
            o.push_str("\tkey_mgmt=SAE\n\tproto=RSN\n\tieee80211w=2\n");
            // SAE takes the passphrase as `psk`/`sae_password`; a raw 64-digit PSK cannot be used
            let p = c.psk.as_deref().ok_or_else(|| invalid("no passphrase"))?;
            check_psk(p)?;
            if p.len() == 64 {
                return Err(invalid("WPA3 needs a passphrase, not a 64-digit key"));
            }
            o.push_str(&format!("\tsae_password=\"{p}\"\n"));
        }
        Security::Wpa2Wpa3 => {
            o.push_str("\tkey_mgmt=WPA-PSK SAE\n\tproto=RSN\n\tieee80211w=1\n");
            let p = c.psk.as_deref().ok_or_else(|| invalid("no passphrase"))?;
            check_psk(p)?;
            if p.len() == 64 {
                return Err(invalid("WPA2/WPA3 needs a passphrase, not a 64-digit key"));
            }
            o.push_str(&format!("\tpsk=\"{p}\"\n\tsae_password=\"{p}\"\n"));
        }
    }
    o.push_str("}\n");
    Ok(o)
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

/// Applier `wifi-client` (boot phase `services`): one wpa_supplicant per enabled uplink.
#[derive(Clone)]
pub struct WifiClientApplier {
    sup: Supervisor,
    ctrl_dir: PathBuf,
    sysfs: PathBuf,
    wpa: Option<PathBuf>,
}

impl Default for WifiClientApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            ctrl_dir: PathBuf::from(
                std::env::var("PATRONUS_WPA_CTRL").unwrap_or_else(|_| DEFAULT_CTRL_DIR.into()),
            ),
            sysfs: PathBuf::from("/sys"),
            wpa: None,
        }
    }
}

impl WifiClientApplier {
    pub fn with_parts(sup: Supervisor, ctrl_dir: PathBuf, sysfs: PathBuf, wpa: PathBuf) -> Self {
        Self {
            sup,
            ctrl_dir,
            sysfs,
            wpa: Some(wpa),
        }
    }
    fn wpa_bin(&self) -> Option<PathBuf> {
        self.wpa.clone().or_else(|| which("wpa_supplicant"))
    }
    fn conf_path(&self, dev: &str) -> PathBuf {
        self.sup
            .paths
            .state_dir
            .join("wpa")
            .join(format!("{dev}.conf"))
    }
    fn spec(&self, wpa: &Path, c: &WifiClient) -> Result<DaemonSpec> {
        let conf = self.conf_path(&c.device);
        Ok(DaemonSpec {
            service: SERVICE,
            instance: c.device.clone(),
            argv: vec![
                wpa.to_string_lossy().into(),
                "-i".into(),
                c.device.clone(),
                "-D".into(),
                "nl80211".into(),
                "-c".into(),
                conf.to_string_lossy().into(),
            ],
            files: vec![(conf, render_wpa_supplicant(c, &self.ctrl_dir)?, 0o600)],
        })
    }
}

#[async_trait]
impl Applier for WifiClientApplier {
    fn name(&self) -> &'static str {
        "wifi-client"
    }
    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let all = list(store).await?;
        let wanted: Vec<&WifiClient> = all.iter().filter(|c| c.enabled).collect();
        for inst in self.sup.instances(SERVICE) {
            if !wanted.iter().any(|c| c.device == inst) {
                self.sup.stop(SERVICE, &inst).await?;
                let _ = std::fs::remove_file(self.conf_path(&inst));
                rep.applied(format!("Wi-Fi uplink {inst} stopped"));
            }
        }
        if wanted.is_empty() {
            if rep.applied.is_empty() {
                rep.applied("no Wi-Fi uplinks configured (wpa_supplicant untouched)".to_string());
            }
            return Ok(rep);
        }
        let Some(wpa) = self.wpa_bin() else {
            return Err(invalid(
                "wpa_supplicant is not installed (emerge net-wireless/wpa_supplicant, USE=wifi-client)",
            ));
        };
        for c in wanted {
            if !self.sysfs.join("class/net").join(&c.device).exists() {
                rep.warn(format!(
                    "Wi-Fi uplink {}: no such device (is the wireless driver loaded?), not started",
                    c.device
                ));
                continue;
            }
            let spec = self.spec(&wpa, c)?;
            if self.sup.ensure(&spec).await? {
                rep.applied(format!(
                    "Wi-Fi uplink {}: wpa_supplicant started (SSID {:?}, {})",
                    c.device,
                    c.ssid,
                    c.security.as_str()
                ));
            } else {
                rep.applied(format!("Wi-Fi uplink {}: already running", c.device));
            }
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut o = String::new();
        for c in list(store).await?.iter().filter(|c| c.enabled) {
            // dry-run output never shows the secret
            let mut shown = c.clone();
            if shown.psk.is_some() {
                shown.psk = Some("********".to_string());
            }
            o.push_str(&format!(
                "# {} (wpa_supplicant -i {} -D nl80211)\n{}\n",
                c.device,
                c.device,
                render_wpa_supplicant(&shown, &self.ctrl_dir)
                    .unwrap_or_else(|e| format!("# {e}\n"))
            ));
        }
        Ok(o)
    }
}

/// Is a wpa_supplicant binary installed (for the UI)?
pub fn available() -> bool {
    which("wpa_supplicant").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(dev: &str) -> WifiClientInput {
        WifiClientInput {
            device: dev.into(),
            ssid: "Backup Net".into(),
            psk: Some("correct horse".into()),
            ..Default::default()
        }
    }

    #[test]
    fn wpa2_config_hides_nothing_it_needs_and_escapes_nothing_unsafe() {
        let c = input("wlan0").validated(None).unwrap();
        let t = render_wpa_supplicant(&c, Path::new("/run/wpa_supplicant")).unwrap();
        assert!(t.contains("ctrl_interface=/run/wpa_supplicant\n"));
        assert!(t.contains(&format!("ssid={}\n", hex("Backup Net"))));
        assert!(t.contains("key_mgmt=WPA-PSK\n"));
        assert!(t.contains("psk=\"correct horse\"\n"));
        assert!(!t.contains("bssid="));
    }

    #[test]
    fn security_modes_and_bssid() {
        let mut i = input("wlan0");
        i.bssid = Some("AA-BB-CC-DD-EE-FF".into());
        i.security = Some("wpa3".into());
        let t = render_wpa_supplicant(&i.validated(None).unwrap(), Path::new("/r")).unwrap();
        assert!(t.contains("bssid=aa:bb:cc:dd:ee:ff"));
        assert!(
            t.contains("key_mgmt=SAE") && t.contains("ieee80211w=2") && t.contains("sae_password=")
        );
        i.security = Some("wpa2-wpa3".into());
        let t = render_wpa_supplicant(&i.validated(None).unwrap(), Path::new("/r")).unwrap();
        assert!(t.contains("key_mgmt=WPA-PSK SAE") && t.contains("ieee80211w=1"));
        i.security = Some("open".into());
        i.psk = None;
        let c = i.validated(None).unwrap();
        assert!(c.psk.is_none());
        assert!(render_wpa_supplicant(&c, Path::new("/r"))
            .unwrap()
            .contains("key_mgmt=NONE"));
        // a 64-digit key is a raw PSK (unquoted) for WPA2 only
        let mut k = input("wlan0");
        k.psk = Some("a".repeat(64));
        let t = render_wpa_supplicant(&k.validated(None).unwrap(), Path::new("/r")).unwrap();
        assert!(t.contains(&format!("psk={}\n", "a".repeat(64))));
        k.security = Some("wpa3".into());
        assert!(render_wpa_supplicant(&k.validated(None).unwrap(), Path::new("/r")).is_err());
    }

    #[test]
    fn bad_input_is_refused() {
        for bad in [
            WifiClientInput {
                device: "bad dev".into(),
                ..input("x")
            },
            WifiClientInput {
                ssid: String::new(),
                ..input("wlan0")
            },
            WifiClientInput {
                ssid: "x".repeat(33),
                ..input("wlan0")
            },
            WifiClientInput {
                ssid: "a\nb".into(),
                ..input("wlan0")
            },
            WifiClientInput {
                security: Some("wep".into()),
                ..input("wlan0")
            },
            WifiClientInput {
                psk: Some("short".into()),
                ..input("wlan0")
            },
            WifiClientInput {
                psk: Some("line\nbreak 12".into()),
                ..input("wlan0")
            },
            WifiClientInput {
                psk: None,
                ..input("wlan0")
            },
            WifiClientInput {
                bssid: Some("nope".into()),
                ..input("wlan0")
            },
        ] {
            assert!(bad.validated(None).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn store_round_trip_keeps_the_secret_and_the_api_view_never_has_it() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let c = save(&s, &input("wlan0")).await.unwrap();
        assert_eq!(c.psk.as_deref(), Some("correct horse"));
        // an update without a passphrase keeps the stored one
        let mut upd = input("wlan0");
        upd.psk = None;
        upd.ssid = "Renamed".into();
        let c2 = save(&s, &upd).await.unwrap();
        assert_eq!(c2.id, c.id);
        assert_eq!(c2.ssid, "Renamed");
        assert_eq!(c2.psk.as_deref(), Some("correct horse"));
        let api = c2.public().to_string();
        assert!(!api.contains("correct horse") && api.contains("\"has_psk\":true"));
        assert_eq!(list(&s).await.unwrap().len(), 1);
        assert!(delete(&s, "wlan0").await.unwrap());
        assert!(!delete(&s, "wlan0").await.unwrap());
        assert!(list(&s).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn applier_writes_a_0600_config_per_enabled_device_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join("sys");
        std::fs::create_dir_all(sys.join("class/net/wlan0")).unwrap();
        let sup = Supervisor::new(
            crate::supervise::InitMode::Systemd,
            crate::supervise::NetPaths::under(dir.path()),
        );
        let fake = dir.path().join("wpa_supplicant");
        std::fs::write(&fake, "").unwrap();
        let a = WifiClientApplier::with_parts(sup.clone(), dir.path().join("ctrl"), sys, fake);
        let s = ConfigStore::open_in_memory().await.unwrap();
        // nothing configured: untouched
        let r = a.apply(&s).await.unwrap();
        assert!(r.applied.iter().any(|l| l.contains("no Wi-Fi uplinks")));
        save(&s, &input("wlan0")).await.unwrap();
        let mut off = input("wlan1");
        off.enabled = Some(false);
        save(&s, &off).await.unwrap();
        let mut absent = input("wlan9");
        absent.ssid = "other".into();
        save(&s, &absent).await.unwrap();
        // systemd mode needs systemctl; the config and env file are written before the unit starts
        let _ = a.apply(&s).await;
        let conf = a.conf_path("wlan0");
        assert_eq!(
            std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_to_string(&conf)
            .unwrap()
            .contains("psk=\"correct horse\""));
        assert!(
            !a.conf_path("wlan1").exists(),
            "a disabled uplink has no config"
        );
        assert!(
            !a.conf_path("wlan9").exists(),
            "a missing device is skipped"
        );
        let env =
            std::fs::read_to_string(dir.path().join("net/svc/patronus-wpa.wlan0.env")).unwrap();
        assert!(
            env.contains("-i wlan0") && env.contains("-D nl80211"),
            "{env}"
        );
        // the dry-run text never shows the passphrase
        let shown = a.render(&s).await.unwrap();
        assert!(shown.contains("wlan0") && !shown.contains("correct horse"));
    }
}
