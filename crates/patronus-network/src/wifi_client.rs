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

/// The other Wi-Fi supplicant a Gentoo image may start at boot. iwd takes every wireless device it sees
/// (it even deletes and re-creates their netdevs), so it and wpa_supplicant must never run on the same radio.
pub const IWD_SERVICE: &str = "iwd";
/// Unit files that mean "the iwd service is installed" (OpenRC script, systemd unit in either prefix).
const IWD_UNITS: [&str; 3] = [
    "etc/init.d/iwd",
    "usr/lib/systemd/system/iwd.service",
    "lib/systemd/system/iwd.service",
];
/// Marker in the wpa state dir: Patronus stopped (and disabled) iwd for a Wi-Fi uplink, so removing the last
/// uplink gives the radio back to it.
const IWD_MARKER: &str = "iwd-released-by-patronus";

/// Applier `wifi-client` (boot phase `services`): one wpa_supplicant per enabled uplink.
#[derive(Clone)]
pub struct WifiClientApplier {
    sup: Supervisor,
    ctrl_dir: PathBuf,
    sysfs: PathBuf,
    wpa: Option<PathBuf>,
    /// Filesystem root for the iwd unit check (tests point it at a temp dir).
    root: PathBuf,
    /// /proc, for an iwd that runs without the init system (started by hand, containers).
    proc_dir: PathBuf,
    services: std::sync::Arc<dyn crate::lan::ServiceControl>,
    /// `iw`, to give a radio its device again (None = from $PATH).
    iw: Option<PathBuf>,
    /// Run the interfaces phase again after a device was re-created (off in unit tests).
    reapply_interfaces: bool,
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
            root: PathBuf::from("/"),
            proc_dir: PathBuf::from("/proc"),
            services: std::sync::Arc::new(crate::lan::SystemServices),
            iw: None,
            reapply_interfaces: true,
        }
    }
}

impl WifiClientApplier {
    /// Tests: explicit paths. iwd is looked for under `sysfs`'s parent (nothing there unless the test puts
    /// it there, see [`Self::with_iwd_env`]), and services are only recorded.
    pub fn with_parts(sup: Supervisor, ctrl_dir: PathBuf, sysfs: PathBuf, wpa: PathBuf) -> Self {
        let base = sysfs
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| sysfs.clone());
        Self {
            sup,
            ctrl_dir,
            sysfs,
            wpa: Some(wpa),
            root: base.clone(),
            proc_dir: base,
            services: std::sync::Arc::new(crate::lan::RecordingServices::default()),
            iw: None,
            reapply_interfaces: false,
        }
    }
    /// Tests: the `iw` to run.
    pub fn with_iw(mut self, iw: PathBuf) -> Self {
        self.iw = Some(iw);
        self
    }
    /// Tests: where iwd's unit files and processes are looked for, and the init system that stops it.
    pub fn with_iwd_env(
        mut self,
        root: PathBuf,
        proc_dir: PathBuf,
        services: std::sync::Arc<dyn crate::lan::ServiceControl>,
    ) -> Self {
        self.root = root;
        self.proc_dir = proc_dir;
        self.services = services;
        self
    }
    fn iwd_installed(&self) -> bool {
        IWD_UNITS.iter().any(|u| self.root.join(u).exists())
    }
    fn iwd_marker(&self) -> PathBuf {
        self.sup.paths.state_dir.join("wpa").join(IWD_MARKER)
    }
    /// Live `iwd` processes (not zombies), whoever started them.
    fn iwd_pids(&self) -> Vec<i32> {
        let Ok(rd) = std::fs::read_dir(&self.proc_dir) else {
            return Vec::new();
        };
        rd.filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
            .filter(|pid| {
                let d = self.proc_dir.join(pid.to_string());
                let comm = std::fs::read_to_string(d.join("comm")).unwrap_or_default();
                let zombie = std::fs::read_to_string(d.join("stat"))
                    .ok()
                    .and_then(|s| {
                        s.rsplit_once(')')
                            .map(|(_, r)| r.trim_start().starts_with('Z'))
                    })
                    .unwrap_or(false);
                comm.trim() == "iwd" && !zombie
            })
            .collect()
    }

    /// Never two supplicants on one radio: before wpa_supplicant takes `devices`, stop iwd (and keep it from
    /// starting at boot). Returns false when iwd is still running afterwards (the caller then starts nothing).
    async fn keep_iwd_off(&self, rep: &mut ApplyReport, devices: &[&str]) -> bool {
        let list = devices.join(", ");
        let installed = self.iwd_installed();
        let mut did = Vec::new();
        // the devices as they are while iwd may own them (iwd names its own `wlan<phy number>`, which can be the
        // uplink's name): the kernel deletes iwd's devices only after iwd is gone
        let ifindex = |d: &str| {
            std::fs::read_to_string(self.sysfs.join("class/net").join(d).join("ifindex"))
                .ok()
                .map(|s| s.trim().to_string())
        };
        let before: Vec<(&str, Option<String>)> =
            devices.iter().map(|d| (*d, ifindex(d))).collect();
        if installed {
            if self.services.is_running(IWD_SERVICE) {
                match self.services.stop(IWD_SERVICE) {
                    Ok(()) => did.push("stopped"),
                    Err(e) => rep.warn(format!("Wi-Fi uplink {list}: could not stop iwd: {e}")),
                }
            }
            if self.services.is_enabled(IWD_SERVICE) {
                match self.services.disable(IWD_SERVICE) {
                    Ok(()) => did.push("disabled at boot"),
                    Err(e) => rep.warn(format!(
                        "Wi-Fi uplink {list}: could not disable iwd at boot: {e}"
                    )),
                }
            }
        }
        // an iwd outside the init system (started by hand): it holds the radio just the same
        let stray = self.iwd_pids();
        if !stray.is_empty() {
            for pid in &stray {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(*pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }
            for _ in 0..30 {
                if self.iwd_pids().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            did.push("ended (it ran outside the init system)");
        }
        if !self.iwd_pids().is_empty() {
            rep.warn(format!(
                "Wi-Fi uplink {list}: iwd is still running and would fight wpa_supplicant over the radio; \
                 not started (stop iwd: rc-service iwd stop / systemctl stop iwd)"
            ));
            return false;
        }
        if did
            .iter()
            .any(|d| d.starts_with("stopped") || d.starts_with("ended"))
        {
            // wait (bounded) until the devices iwd owned are gone, so a device of the same name is not used just
            // before the kernel removes it; a device iwd did not own stays, and the wait ends at the bound
            for _ in 0..30 {
                if before
                    .iter()
                    .all(|(d, idx)| idx.is_none() || ifindex(d) != *idx)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        if !did.is_empty() {
            let _ = std::fs::create_dir_all(self.iwd_marker().parent().unwrap_or(Path::new("/")));
            let _ = std::fs::write(
                self.iwd_marker(),
                if installed { "service\n" } else { "process\n" },
            );
            rep.applied(format!(
                "iwd {}: Patronus runs wpa_supplicant on {list} (two supplicants on one radio fight over it)",
                did.join(", ")
            ));
        }
        true
    }

    /// The last uplink is gone: give the radio back to iwd if Patronus took it away (and no Patronus access
    /// point uses a radio now).
    fn give_back_iwd(&self, rep: &mut ApplyReport) {
        let marker = self.iwd_marker();
        let Ok(how) = std::fs::read_to_string(&marker) else {
            return;
        };
        if !self.sup.instances("patronus-hostapd").is_empty() {
            return;
        }
        if how.trim() == "service" && self.iwd_installed() {
            if let Err(e) = self
                .services
                .enable(IWD_SERVICE)
                .and_then(|_| self.services.restart(IWD_SERVICE))
            {
                rep.warn(format!("could not start iwd again: {e}"));
                return;
            }
            rep.applied("no Wi-Fi uplink left: iwd enabled and started again".to_string());
        }
        let _ = std::fs::remove_file(marker);
    }

    /// Radios (phys) in this network namespace that have no network device at all.
    fn free_phys(&self) -> Vec<String> {
        let names = |d: PathBuf| -> Vec<String> {
            std::fs::read_dir(d)
                .map(|r| {
                    r.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default()
        };
        let used: Vec<String> = names(self.sysfs.join("class/net"))
            .into_iter()
            .filter_map(|n| {
                std::fs::read_link(self.sysfs.join("class/net").join(n).join("phy80211"))
                    .ok()
                    .and_then(|l| l.file_name().map(|f| f.to_string_lossy().to_string()))
            })
            .collect();
        let mut free: Vec<String> = names(self.sysfs.join("class/ieee80211"))
            .into_iter()
            .filter(|p| !used.contains(p))
            .collect();
        free.sort();
        free
    }

    /// An uplink whose device is gone while its radio is free gets the device back: iwd deletes the kernel's
    /// device when it takes a radio and removes its own when it stops, so after iwd the radio has none. The radio
    /// is the one named like the device (`wlanN` = `phyN`, the kernel's and iwd's naming) or the only free one.
    /// Returns the devices created.
    async fn recreate_missing(&self, rep: &mut ApplyReport, wanted: &[&WifiClient]) -> Vec<String> {
        let missing: Vec<&str> = wanted
            .iter()
            .map(|c| c.device.as_str())
            .filter(|d| !self.sysfs.join("class/net").join(d).exists())
            .collect();
        if missing.is_empty() {
            return Vec::new();
        }
        // the kernel deletes the devices iwd owned shortly AFTER iwd exits (they belong to its netlink socket)
        let mut free = self.free_phys();
        for _ in 0..30 {
            if !free.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            free = self.free_phys();
        }
        if free.is_empty() {
            return Vec::new();
        }
        let Some(iw) = self.iw.clone().or_else(|| which("iw")) else {
            rep.warn(format!(
                "Wi-Fi uplink {}: the device is gone and a radio is free, but iw is not installed to re-create it",
                missing.join(", ")
            ));
            return Vec::new();
        };
        let mut made = Vec::new();
        for dev in missing {
            let by_name = dev
                .strip_prefix("wlan")
                .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .map(|n| format!("phy{n}"))
                .filter(|p| free.contains(p));
            let Some(phy) = by_name.or_else(|| (free.len() == 1).then(|| free[0].clone())) else {
                rep.warn(format!(
                    "Wi-Fi uplink {dev}: no such device, and several radios are free ({}): cannot tell which one \
                     it is (name the device wlanN after its radio phyN)",
                    free.join(", ")
                ));
                continue;
            };
            let out = tokio::process::Command::new(&iw)
                .args([
                    "phy",
                    phy.as_str(),
                    "interface",
                    "add",
                    dev,
                    "type",
                    "managed",
                ])
                .output()
                .await;
            match out {
                Ok(o) if o.status.success() && self.sysfs.join("class/net").join(dev).exists() => {
                    free.retain(|p| p != &phy);
                    rep.applied(format!(
                        "Wi-Fi uplink {dev}: device created on radio {phy} (it had none: iwd removes the \
                         devices of the radios it managed when it stops)"
                    ));
                    made.push(dev.to_string());
                }
                Ok(o) => rep.warn(format!(
                    "Wi-Fi uplink {dev}: could not create the device on radio {phy}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                )),
                Err(e) => rep.warn(format!("Wi-Fi uplink {dev}: could not run iw: {e}")),
            }
        }
        made
    }

    /// Ask the running wpa_supplicant (control socket, through wpa_cli) how the uplink is doing.
    async fn query(&self, c: &WifiClient) -> Value {
        let cli = self
            .wpa_bin()
            .and_then(|w| w.parent().map(|d| d.join("wpa_cli")))
            .filter(|p| p.exists())
            .or_else(|| which("wpa_cli"));
        let Some(cli) = cli else {
            return json!({ "connected": false, "wpa_state": "UNKNOWN",
                           "problem": "wpa_cli is not installed (it comes with wpa_supplicant)" });
        };
        let run = |cmd: &'static str| {
            let cli = cli.clone();
            let ctrl = self.ctrl_dir.clone();
            let dev = c.device.clone();
            async move {
                let o = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    tokio::process::Command::new(cli)
                        .arg("-p")
                        .arg(ctrl)
                        .arg("-i")
                        .arg(dev)
                        .arg(cmd)
                        .output(),
                )
                .await
                .ok()?
                .ok()?;
                o.status
                    .success()
                    .then(|| String::from_utf8_lossy(&o.stdout).to_string())
            }
        };
        let Some(st) = run("status").await else {
            return json!({ "connected": false, "wpa_state": "UNKNOWN",
                           "problem": "wpa_supplicant does not answer on its control socket" });
        };
        let nets = run("list_networks").await.unwrap_or_default();
        let scan = run("scan_results").await.unwrap_or_default();
        summarize(&c.ssid, &st, &nets, &scan)
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
            self.give_back_iwd(&mut rep);
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
        // iwd first: while it runs it owns the radio (and it removes the device when it stops)
        let all: Vec<&str> = wanted.iter().map(|c| c.device.as_str()).collect();
        if !self.keep_iwd_off(&mut rep, &all).await {
            return Ok(rep);
        }
        let recreated = self.recreate_missing(&mut rep, &wanted).await;
        let present: Vec<&WifiClient> = wanted
            .into_iter()
            .filter(|c| {
                let ok = self.sysfs.join("class/net").join(&c.device).exists();
                if !ok {
                    rep.warn(format!(
                        "Wi-Fi uplink {}: no such device (is the wireless driver loaded?), not started",
                        c.device
                    ));
                }
                ok
            })
            .collect();
        if present.is_empty() {
            return Ok(rep);
        }
        for c in present {
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
        if !recreated.is_empty() && self.reapply_interfaces {
            // the device is new: its DHCP client (if the interfaces phase started one for the old device) is
            // bound to a vanished interface, so it starts again for the new one
            for d in &recreated {
                let _ = self.sup.stop(crate::dhcp_client::SERVICE, d).await;
            }
            match crate::InterfacesApplier::default().apply(store).await {
                Ok(_) => rep.applied(format!(
                    "interface settings applied again for {}",
                    recreated.join(", ")
                )),
                Err(e) => rep.warn(format!(
                    "interface settings for {}: {e}",
                    recreated.join(", ")
                )),
            }
        }
        Ok(rep)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let mut out = Vec::new();
        for c in list(store).await? {
            let mut v = c.public();
            let running = c.enabled && self.sup.is_running(SERVICE, &c.device);
            let live = if !c.enabled {
                json!({ "connected": false, "wpa_state": "DISABLED", "problem": Value::Null })
            } else if !running {
                let why = if !self.sysfs.join("class/net").join(&c.device).exists() {
                    format!("no device {} (is the wireless driver loaded?)", c.device)
                } else if self.wpa_bin().is_none() {
                    "wpa_supplicant is not installed (emerge net-wireless/wpa_supplicant)"
                        .to_string()
                } else {
                    "wpa_supplicant is not running (see the apply log)".to_string()
                };
                json!({ "connected": false, "wpa_state": "STOPPED", "problem": why })
            } else {
                self.query(&c).await
            };
            v["running"] = json!(running);
            if let (Some(o), Some(l)) = (v.as_object_mut(), live.as_object()) {
                for (k, x) in l {
                    o.insert(k.clone(), x.clone());
                }
            }
            out.push(v);
        }
        Ok(json!({
            "available": self.wpa_bin().is_some(),
            "iwd_running": !self.iwd_pids().is_empty(),
            "uplinks": out,
        }))
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

/// Turn `wpa_cli status` / `list_networks` / `scan_results` into the uplink's state and, when it is not
/// connected, one sentence saying why (shown on the API and the page).
pub fn summarize(ssid: &str, status: &str, networks: &str, scan: &str) -> Value {
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(str::to_string)
    };
    let state = field("wpa_state").unwrap_or_else(|| "UNKNOWN".to_string());
    let connected = state == "COMPLETED";
    let temp_disabled = networks
        .lines()
        .skip(1)
        .any(|l| l.contains("[TEMP-DISABLED]"));
    // scan_results: bssid / frequency / signal level / flags / ssid (tab separated, header first)
    let seen: Vec<(String, String)> = scan
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 5 && f[4] == ssid).then(|| (f[2].to_string(), f[3].to_string()))
        })
        .collect();
    let problem: Option<String> = if connected {
        None
    } else if temp_disabled && !seen.is_empty() {
        Some(format!(
            "authentication with {ssid:?} keeps failing (the access point rejects the key exchange): \
             most likely a wrong passphrase; wpa_supplicant retries with growing pauses"
        ))
    } else if temp_disabled {
        Some(format!(
            "connecting to {ssid:?} keeps failing; wpa_supplicant retries with growing pauses"
        ))
    } else {
        match state.as_str() {
            "INTERFACE_DISABLED" => {
                Some("the wireless device is down or blocked (rfkill)".to_string())
            }
            "SCANNING" | "DISCONNECTED" | "INACTIVE" if seen.is_empty() && !scan.is_empty() => {
                Some(format!(
                    "no access point named {ssid:?} in range (last scan)"
                ))
            }
            "SCANNING" | "DISCONNECTED" | "INACTIVE" => Some(format!("looking for {ssid:?}")),
            s => Some(format!("connecting to {ssid:?} ({})", s.to_lowercase())),
        }
    };
    json!({
        "connected": connected,
        "wpa_state": state,
        "ap_bssid": field("bssid"),
        "freq": field("freq").and_then(|f| f.parse::<u32>().ok()),
        "ip_address": field("ip_address"),
        "key_mgmt": field("key_mgmt"),
        "signal": seen.first().and_then(|(s, _)| s.parse::<i32>().ok()),
        "problem": problem,
    })
}

/// Is a wpa_supplicant binary installed (for the UI)?
pub fn available() -> bool {
    which("wpa_supplicant").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::ServiceControl;
    use std::sync::Arc;

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

    #[test]
    fn status_explains_why_the_uplink_is_not_connected() {
        let hdr = "bssid / frequency / signal level / flags / ssid\n";
        let scan = format!("{hdr}02:00:00:00:00:00\t2412\t-30\t[WPA2-PSK-CCMP][ESS]\tupstream\n");
        let nets_bad = "network id / ssid / bssid / flags\n0\tupstream\tany\t[TEMP-DISABLED]\n";
        let nets_ok = "network id / ssid / bssid / flags\n0\tupstream\tany\t[CURRENT]\n";
        // connected: the details, no problem
        let v = summarize(
            "upstream",
            "bssid=02:00:00:00:00:00\nfreq=2412\nssid=upstream\nkey_mgmt=WPA2-PSK\nwpa_state=COMPLETED\nip_address=10.42.0.120\n",
            nets_ok,
            &scan,
        );
        assert_eq!(v["connected"], true);
        assert_eq!(v["freq"], 2412);
        assert_eq!(v["ip_address"], "10.42.0.120");
        assert_eq!(v["signal"], -30);
        assert!(v["problem"].is_null());
        // the AP is there but the network is temporarily disabled: a wrong passphrase
        let v = summarize("upstream", "wpa_state=DISCONNECTED\n", nets_bad, &scan);
        assert_eq!(v["connected"], false);
        let p = v["problem"].as_str().unwrap();
        assert!(p.contains("wrong passphrase"), "{p}");
        // not in range
        let v = summarize("elsewhere", "wpa_state=SCANNING\n", nets_ok, &scan);
        assert!(v["problem"].as_str().unwrap().contains("in range"), "{v}");
        // in progress / radio off
        let v = summarize("upstream", "wpa_state=4WAY_HANDSHAKE\n", nets_ok, &scan);
        assert!(v["problem"].as_str().unwrap().contains("4way_handshake"));
        let v = summarize("upstream", "wpa_state=INTERFACE_DISABLED\n", nets_ok, "");
        assert!(v["problem"].as_str().unwrap().contains("rfkill"));
    }

    fn iwd_env(dir: &Path, unit: bool) -> (WifiClientApplier, Arc<crate::lan::RecordingServices>) {
        let sys = dir.join("sys");
        std::fs::create_dir_all(sys.join("class/net/wlan0")).unwrap();
        std::fs::create_dir_all(dir.join("proc")).unwrap();
        let root = dir.join("root");
        if unit {
            std::fs::create_dir_all(root.join("etc/init.d")).unwrap();
            std::fs::write(root.join("etc/init.d/iwd"), "").unwrap();
        }
        let sup = Supervisor::new(
            crate::supervise::InitMode::Systemd,
            crate::supervise::NetPaths::under(dir),
        );
        let fake = dir.join("wpa_supplicant");
        std::fs::write(&fake, "").unwrap();
        let svc = Arc::new(crate::lan::RecordingServices::default());
        let a = WifiClientApplier::with_parts(sup, dir.join("ctrl"), sys, fake).with_iwd_env(
            root,
            dir.join("proc"),
            svc.clone(),
        );
        (a, svc)
    }

    #[tokio::test]
    async fn iwd_is_stopped_and_disabled_for_an_uplink_and_gets_the_radio_back_after() {
        let dir = tempfile::tempdir().unwrap();
        let (a, svc) = iwd_env(dir.path(), true);
        svc.running.lock().unwrap().insert("iwd".into());
        svc.enabled.lock().unwrap().insert("iwd".into());
        let s = ConfigStore::open_in_memory().await.unwrap();
        // no uplink: iwd is left alone
        a.apply(&s).await.unwrap();
        assert!(svc.is_running("iwd") && svc.is_enabled("iwd"));
        save(&s, &input("wlan0")).await.unwrap();
        // systemd mode needs systemctl for the wpa unit; iwd is dealt with before that
        let r = a.apply(&s).await;
        assert!(!svc.is_running("iwd"), "iwd still running");
        assert!(!svc.is_enabled("iwd"), "iwd still enabled at boot");
        assert!(svc.log.lock().unwrap().contains(&"stop iwd".to_string()));
        if let Ok(r) = &r {
            assert!(
                r.applied
                    .iter()
                    .any(|l| l.contains("iwd stopped, disabled at boot")),
                "{r:?}"
            );
        }
        assert!(a.iwd_marker().exists());
        // the uplink is removed: iwd comes back, the marker goes
        delete(&s, "wlan0").await.unwrap();
        let r = a.apply(&s).await.unwrap();
        assert!(svc.is_running("iwd") && svc.is_enabled("iwd"), "{r:?}");
        assert!(r
            .applied
            .iter()
            .any(|l| l.contains("iwd enabled and started again")));
        assert!(!a.iwd_marker().exists());
        // without the marker (iwd was never ours to stop) nothing happens to it
        svc.running.lock().unwrap().remove("iwd");
        a.apply(&s).await.unwrap();
        assert!(!svc.is_running("iwd"));
    }

    #[tokio::test]
    async fn a_device_iwd_took_away_is_created_again_on_its_free_radio() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (a, _svc) = iwd_env(dir.path(), false);
        let sys = dir.path().join("sys");
        // after iwd: radios phy3 and phy4, no wlan0 any more; wlan9 still sits on phy4
        std::fs::remove_dir_all(sys.join("class/net/wlan0")).unwrap();
        for p in ["phy3", "phy4"] {
            std::fs::create_dir_all(sys.join("class/ieee80211").join(p)).unwrap();
        }
        std::fs::create_dir_all(sys.join("class/net/wlan9")).unwrap();
        std::os::unix::fs::symlink("../../ieee80211/phy4", sys.join("class/net/wlan9/phy80211"))
            .unwrap();
        // a fake iw that "creates" the device: iw phy P interface add DEV type managed
        let iw = dir.path().join("iw");
        std::fs::write(
            &iw,
            format!(
                "#!/bin/sh\necho \"$@\" >> {0}/iw.log\nmkdir -p {1}/class/net/$5\n",
                dir.path().display(),
                sys.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&iw, std::fs::Permissions::from_mode(0o755)).unwrap();
        let a = a.with_iw(iw);
        assert_eq!(a.free_phys(), vec!["phy3".to_string()]);
        let s = ConfigStore::open_in_memory().await.unwrap();
        save(&s, &input("wlan0")).await.unwrap();
        let mut rep = ApplyReport::default();
        let c = get(&s, "wlan0").await.unwrap().unwrap();
        let made = a.recreate_missing(&mut rep, &[&c]).await;
        assert_eq!(made, vec!["wlan0".to_string()], "{rep:?}");
        let log = std::fs::read_to_string(dir.path().join("iw.log")).unwrap();
        assert_eq!(log.trim(), "phy phy3 interface add wlan0 type managed");
        assert!(rep
            .applied
            .iter()
            .any(|l| l.contains("created on radio phy3")));
        // the device exists now: nothing more to do
        let mut rep = ApplyReport::default();
        assert!(a.recreate_missing(&mut rep, &[&c]).await.is_empty());
        // two free radios and a name that matches neither: refused with a reason
        std::fs::create_dir_all(sys.join("class/ieee80211/phy5")).unwrap();
        save(
            &s,
            &WifiClientInput {
                device: "wlx1".into(),
                ..input("wlx1")
            },
        )
        .await
        .unwrap();
        let c2 = get(&s, "wlx1").await.unwrap().unwrap();
        std::fs::remove_dir_all(sys.join("class/net/wlan0")).unwrap();
        let mut rep = ApplyReport::default();
        assert!(a.recreate_missing(&mut rep, &[&c2]).await.is_empty());
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("several radios are free")),
            "{rep:?}"
        );
        // ... but wlanN goes to phyN
        save(&s, &input("wlan5")).await.unwrap();
        let c3 = get(&s, "wlan5").await.unwrap().unwrap();
        let mut rep = ApplyReport::default();
        assert_eq!(
            a.recreate_missing(&mut rep, &[&c3]).await,
            vec!["wlan5".to_string()]
        );
    }

    #[tokio::test]
    async fn no_iwd_installed_means_no_service_calls() {
        let dir = tempfile::tempdir().unwrap();
        let (a, svc) = iwd_env(dir.path(), false);
        let s = ConfigStore::open_in_memory().await.unwrap();
        save(&s, &input("wlan0")).await.unwrap();
        let _ = a.apply(&s).await;
        assert!(svc.log.lock().unwrap().is_empty());
        assert!(!a.iwd_marker().exists());
        // the status of a configured uplink whose daemon is not running says why
        let st = a.status(&s).await.unwrap();
        let u = &st["uplinks"][0];
        assert_eq!(u["device"], "wlan0");
        assert_eq!(u["connected"], false);
        assert!(u["problem"].as_str().is_some(), "{st}");
        assert!(!st.to_string().contains("correct horse"));
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
