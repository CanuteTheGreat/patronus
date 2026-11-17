//! Access-point Wi-Fi of the router-tier images (`/etc/patronus/ap.env`).
//!
//! On the router-tier access points (GL-AX1800) the radios are driven by
//! `/usr/libexec/patronus/ap`: it renders one hostapd config per radio from
//! the shell variables in `/etc/patronus/ap.env` (sourced through the board's
//! `board.sh`) and starts one hostapd per radio at boot. That file is the
//! ONE source of truth for the live Wi-Fi: the web UI's Wi-Fi page reads and
//! writes it here, and applies it through the same `ap stop` / `ap start`
//! the boot uses, so a setting made in the UI is exactly what the next boot
//! (and a sysupgrade, which keeps `/etc` on the settings volume) brings up.
//!
//! - [`parse`] / [`render`] keep every line this module does not manage
//!   (address settings `AP_ADDR`/`AP_GW`/`AP_DNS`, test switches, comments).
//! - Keys (passphrases) never leave through [`WifiConfig`]: networks report
//!   `has_key`; [`reveal_key`] is a separate, admin-only call.
//! - [`apply`] writes the file atomically (0600, previous copy kept as
//!   `ap.env.prev`), restarts the access points and checks that every
//!   expected BSS comes up; if one does not, it restores the previous file,
//!   restarts again and returns the error.
//! - On a unit without radios (QEMU, a board whose Wi-Fi is not up yet) the
//!   settings are saved and the result says the radios were not restarted.
//!
//! Paths can be redirected for tests: `PATRONUS_AP_ENV`, `PATRONUS_AP_SCRIPT`,
//! `PATRONUS_AP_RUN` (hostapd control dir), `PATRONUS_AP_SYSFS`
//! (`/sys/class/ieee80211`), `PATRONUS_AP_NET` (`/sys/class/net`).

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Where the access-point backend lives.
#[derive(Debug, Clone)]
pub struct Paths {
    pub env: PathBuf,
    pub script: PathBuf,
    pub run: PathBuf,
    pub sysfs: PathBuf,
    pub net: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
        Paths {
            env: p("PATRONUS_AP_ENV", "/etc/patronus/ap.env"),
            script: p("PATRONUS_AP_SCRIPT", "/usr/libexec/patronus/ap"),
            run: p("PATRONUS_AP_RUN", "/run/hostapd"),
            sysfs: p("PATRONUS_AP_SYSFS", "/sys/class/ieee80211"),
            net: p("PATRONUS_AP_NET", "/sys/class/net"),
        }
    }
}

impl Paths {
    /// This unit's Wi-Fi is the `ap` backend (router-tier access point).
    pub fn present(&self) -> bool {
        self.script.is_file()
    }
    /// Radios the kernel has registered right now.
    pub fn radios(&self) -> usize {
        std::fs::read_dir(&self.sysfs)
            .map(|d| d.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }
}

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid Wi-Fi settings: {}", m.into()))
}

// ---------------------------------------------------------------------------
// ap.env: a small subset of POSIX shell assignments
// ---------------------------------------------------------------------------

/// One parsed ap.env: assignments in file order plus the lines that are not
/// plain assignments (kept verbatim).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnvFile {
    /// leading comment block (kept at the top)
    pub header: Vec<String>,
    pub vars: Vec<(String, String)>,
    /// lines that are neither comments nor assignments (kept at the end)
    pub other: Vec<String>,
}

impl EnvFile {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.vars
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
}

fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && c.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Parse one line of `NAME=value NAME2='v' ...  # comment`. `None` when the
/// line is anything else (a command, an unterminated quote).
fn parse_assignments(line: &str) -> Option<Vec<(String, String)>> {
    let b: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    loop {
        while i < b.len() && (b[i] == ' ' || b[i] == '\t') {
            i += 1;
        }
        if i >= b.len() || b[i] == '#' {
            break;
        }
        let start = i;
        while i < b.len() && b[i] != '=' && b[i] != ' ' && b[i] != '\t' {
            i += 1;
        }
        if i >= b.len() || b[i] != '=' {
            return None;
        }
        let name: String = b[start..i].iter().collect();
        if !is_name(&name) {
            return None;
        }
        i += 1;
        let mut val = String::new();
        while i < b.len() && b[i] != ' ' && b[i] != '\t' {
            match b[i] {
                '\'' => {
                    i += 1;
                    while i < b.len() && b[i] != '\'' {
                        val.push(b[i]);
                        i += 1;
                    }
                    if i >= b.len() {
                        return None;
                    }
                    i += 1;
                }
                '"' => {
                    i += 1;
                    while i < b.len() && b[i] != '"' {
                        if b[i] == '\\'
                            && i + 1 < b.len()
                            && matches!(b[i + 1], '"' | '\\' | '$' | '`')
                        {
                            i += 1;
                        } else if b[i] == '$' || b[i] == '`' {
                            return None; // expansions are not data
                        }
                        val.push(b[i]);
                        i += 1;
                    }
                    if i >= b.len() {
                        return None;
                    }
                    i += 1;
                }
                '\\' if i + 1 < b.len() => {
                    val.push(b[i + 1]);
                    i += 2;
                }
                '$' | '`' | ';' | '|' | '&' | '(' | ')' | '<' | '>' => return None,
                c => {
                    val.push(c);
                    i += 1;
                }
            }
        }
        out.push((name, val));
    }
    Some(out)
}

pub fn parse(text: &str) -> EnvFile {
    let mut f = EnvFile::default();
    let mut in_header = true;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            if in_header && t.starts_with('#') {
                f.header.push(line.to_string());
            }
            continue;
        }
        in_header = false;
        match parse_assignments(line) {
            Some(v) => f.vars.extend(v),
            None => f.other.push(line.to_string()),
        }
    }
    f
}

/// Shell-quote a value so `. ap.env` gives back exactly `v`.
pub fn quote(v: &str) -> String {
    if !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.,:/+@%-".contains(c))
    {
        v.to_string()
    } else {
        format!("'{}'", v.replace('\'', "'\\''"))
    }
}

// ---------------------------------------------------------------------------
// typed view
// ---------------------------------------------------------------------------

/// Settings this module manages; every other variable is kept as found.
const MANAGED: &[&str] = &[
    "AP_COUNTRY",
    "AP_CHAN24",
    "AP_CHAN5",
    "AP_HT5",
    "AP_HE",
    "AP_SSIDS",
    "AP_TXPOWER24",
    "AP_TXPOWER5",
    "AP_NAMES",
];
const NET_PREFIXES: &[&str] = &[
    "SSID_", "KEY_", "SEC_", "HIDE_", "BANDS_", "ISOLATE_", "GUEST_", "DENY_",
];
/// Settings the `ap` script applies to running radios without restarting them (transmit power, MAC block lists).
const LIVE_VARS: &[&str] = &["AP_TXPOWER24", "AP_TXPOWER5", "AP_DENY", "AP_NAMES"];
const LIVE_PREFIXES: &[&str] = &["DENY_"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Network {
    pub id: String,
    pub ssid: String,
    pub enabled: bool,
    /// wpa2 | wpa3 | wpa2+3
    pub security: String,
    pub hidden: bool,
    /// both | 24 | 5
    pub bands: String,
    /// clients of this network cannot reach each other
    pub isolate: bool,
    /// guest network: clients reach the internet through the gateway, never the LAN or this unit
    #[serde(default)]
    pub guest: bool,
    /// MACs refused on this network only (the global list is `WifiConfig::blocked`)
    #[serde(default)]
    pub blocked: Vec<String>,
    pub has_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WifiConfig {
    pub country: String,
    /// "auto" or a 2.4 GHz channel number
    pub chan24: String,
    /// "auto" or a 5 GHz channel number
    pub chan5: String,
    /// 5 GHz channel width in MHz: 20 | 40 | 80
    pub width5: u32,
    /// 802.11ax (Wi-Fi 6) on both radios
    pub wifi6: bool,
    /// transmit power per radio: "auto" or dBm
    #[serde(default = "auto")]
    pub txpower24: String,
    #[serde(default = "auto")]
    pub txpower5: String,
    /// where client names come from: "dhcp" (DHCP requests seen on the LAN + reverse DNS at this unit's DNS server),
    /// an IPv4 address of a DNS server to ask instead, or "off"
    #[serde(default = "dhcp")]
    pub names: String,
    /// MACs refused on every network of this unit
    #[serde(default)]
    pub blocked: Vec<String>,
    pub networks: Vec<Network>,
}

fn auto() -> String {
    "auto".into()
}
fn dhcp() -> String {
    "dhcp".into()
}

/// A MAC list value (`AP_DENY` / `DENY_<id>`): space-separated, lower case, only valid MACs.
pub fn mac_list(v: &str) -> Vec<String> {
    v.split_whitespace()
        .map(str::to_ascii_lowercase)
        .filter(|m| valid_mac(m))
        .collect()
}

/// The typed settings of a parsed file (defaults as `board.sh` sets them).
pub fn view(f: &EnvFile) -> WifiConfig {
    let enabled: Vec<String> = f
        .get("AP_SSIDS")
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    // every network that has an SSID_<id>: the enabled ones first, in AP_SSIDS order
    let mut ids: Vec<String> = enabled.clone();
    for (k, _) in &f.vars {
        if let Some(id) = k.strip_prefix("SSID_") {
            if !ids.iter().any(|i| i == id) {
                ids.push(id.to_string());
            }
        }
    }
    let networks = ids
        .into_iter()
        .filter(|id| f.get(&format!("SSID_{id}")).is_some())
        .map(|id| {
            let g = |p: &str| f.get(&format!("{p}{id}")).unwrap_or("").to_string();
            Network {
                enabled: enabled.contains(&id),
                ssid: g("SSID_"),
                security: match g("SEC_").as_str() {
                    "wpa3" => "wpa3".into(),
                    "wpa2+3" => "wpa2+3".into(),
                    _ => "wpa2".into(),
                },
                hidden: g("HIDE_") == "1",
                bands: match g("BANDS_").as_str() {
                    "24" => "24".into(),
                    "5" => "5".into(),
                    _ => "both".into(),
                },
                isolate: g("ISOLATE_") == "1",
                guest: g("GUEST_") == "1",
                blocked: mac_list(&g("DENY_")),
                has_key: !g("KEY_").is_empty(),
                id,
            }
        })
        .collect();
    let chan = |k: &str| match f.get(k).unwrap_or("auto") {
        "" | "0" | "auto" => "auto".to_string(),
        c => c.to_string(),
    };
    let txp = |k: &str| match f.get(k).unwrap_or("auto") {
        "" | "auto" => "auto".to_string(),
        c => c.to_string(),
    };
    WifiConfig {
        country: f.get("AP_COUNTRY").unwrap_or("00").to_string(),
        chan24: chan("AP_CHAN24"),
        chan5: chan("AP_CHAN5"),
        width5: f.get("AP_HT5").and_then(|w| w.parse().ok()).unwrap_or(80),
        wifi6: !matches!(f.get("AP_HE").unwrap_or("1"), "0" | "no" | "off"),
        txpower24: txp("AP_TXPOWER24"),
        txpower5: txp("AP_TXPOWER5"),
        names: match f.get("AP_NAMES").unwrap_or("") {
            "" | "dhcp" => "dhcp".to_string(),
            v => v.to_string(),
        },
        blocked: mac_list(f.get("AP_DENY").unwrap_or("")),
        networks,
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkInput {
    /// existing network id; absent = a new network
    #[serde(default)]
    pub id: Option<String>,
    pub ssid: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub bands: Option<String>,
    #[serde(default)]
    pub isolate: bool,
    /// guest network (internet only: no LAN, no access to this unit)
    #[serde(default)]
    pub guest: bool,
    /// new passphrase; absent or empty = keep the current one
    #[serde(default)]
    pub key: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WifiInput {
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub chan24: Option<String>,
    #[serde(default)]
    pub chan5: Option<String>,
    #[serde(default)]
    pub width5: Option<u32>,
    #[serde(default)]
    pub wifi6: Option<bool>,
    /// "auto" or dBm (1..=30), per radio; applied live
    #[serde(default)]
    pub txpower24: Option<String>,
    #[serde(default)]
    pub txpower5: Option<String>,
    /// client names: "dhcp", "off" or the IPv4 address of a DNS server
    #[serde(default)]
    pub names: Option<String>,
    /// the full list of networks (a network left out is deleted); absent =
    /// networks unchanged
    #[serde(default)]
    pub networks: Option<Vec<NetworkInput>>,
}

/// A 5 GHz channel on the 20 MHz raster (the `ap` script's `valid5`).
pub fn valid5(c: u32) -> bool {
    ((36..=144).contains(&c) && (c - 36).is_multiple_of(4))
        || ((149..=177).contains(&c) && (c - 149).is_multiple_of(4))
}

fn check_chan(v: &str, band: &str) -> Result<String> {
    let v = v.trim().to_ascii_lowercase();
    if v == "auto" || v == "0" || v.is_empty() {
        return Ok("auto".into());
    }
    let n: u32 = v
        .parse()
        .map_err(|_| invalid(format!("{band} channel {v:?} is not a number or auto")))?;
    let ok = if band == "2.4 GHz" {
        (1..=13).contains(&n)
    } else {
        valid5(n)
    };
    if ok {
        Ok(n.to_string())
    } else {
        Err(invalid(format!("{n} is not a {band} channel")))
    }
}

fn check_ssid(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 32 {
        return Err(invalid("a network name (SSID) has 1 to 32 bytes"));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(invalid("the network name contains a control character"));
    }
    Ok(())
}

fn check_key(k: &str, sec: &str) -> Result<()> {
    let hex64 = k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit());
    if hex64 && sec == "wpa2" {
        return Ok(());
    }
    if k.len() < 8 || k.len() > 63 {
        return Err(invalid("a Wi-Fi password has 8 to 63 characters"));
    }
    if !k.chars().all(|c| (' '..='~').contains(&c)) {
        return Err(invalid(
            "a Wi-Fi password uses printable ASCII characters only",
        ));
    }
    Ok(())
}

/// A transmit power setting: "auto" or whole dBm 1..=30 (the regulatory limit still applies on top).
fn check_txpower(v: &str) -> Result<String> {
    let v = v.trim().to_ascii_lowercase();
    let v = v.trim_end_matches("dbm").trim();
    if v.is_empty() || v == "auto" {
        return Ok("auto".into());
    }
    match v.parse::<u32>() {
        Ok(n) if (1..=30).contains(&n) => Ok(n.to_string()),
        _ => Err(invalid(format!(
            "transmit power {v:?}: auto or 1 to 30 dBm"
        ))),
    }
}

/// Where client names come from: dhcp | off | an IPv4 DNS server.
fn check_names(v: &str) -> Result<String> {
    let v = v.trim();
    match v {
        "" | "dhcp" => Ok("dhcp".into()),
        "off" => Ok("off".into()),
        ip if ip.parse::<std::net::Ipv4Addr>().is_ok() => Ok(ip.to_string()),
        _ => Err(invalid(format!(
            "client names {v:?}: dhcp, off or the IPv4 address of a DNS server"
        ))),
    }
}

/// A free network id derived from the SSID: `[a-z][a-z0-9]{0,9}` (the BSS
/// interfaces are named `wl24-<id>` / `wl5-<id>`, 15 characters at most).
pub fn new_id(ssid: &str, taken: &[String]) -> String {
    let mut base: String = ssid
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    while base.starts_with(|c: char| c.is_ascii_digit()) {
        base.remove(0);
    }
    base.truncate(8);
    if base.is_empty() {
        base = "net".into();
    }
    if !taken.contains(&base) {
        return base;
    }
    (2..100)
        .map(|n| format!("{base}{n}"))
        .find(|c| !taken.contains(c))
        .unwrap_or_else(|| "netx".into())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 10
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Most networks a radio carries (BSSIDs and the ath11k firmware's limit).
pub const MAX_PER_BAND: usize = 4;

/// Apply `input` to the parsed file: validate everything first, change
/// nothing on error. Returns the new file.
pub fn update(f: &EnvFile, input: &WifiInput) -> Result<EnvFile> {
    let cur = view(f);
    let mut set: Vec<(String, String)> = Vec::new();
    if let Some(c) = &input.country {
        let c = c.trim().to_ascii_uppercase();
        if !(c.len() == 2 && c.chars().all(|ch| ch.is_ascii_uppercase()) || c == "00") {
            return Err(invalid("country is a two-letter code (e.g. US, DE)"));
        }
        set.push(("AP_COUNTRY".into(), c));
    }
    if let Some(c) = &input.chan24 {
        set.push(("AP_CHAN24".into(), check_chan(c, "2.4 GHz")?));
    }
    if let Some(c) = &input.chan5 {
        set.push(("AP_CHAN5".into(), check_chan(c, "5 GHz")?));
    }
    if let Some(w) = input.width5 {
        if !matches!(w, 20 | 40 | 80) {
            return Err(invalid("5 GHz channel width is 20, 40 or 80 MHz"));
        }
        set.push(("AP_HT5".into(), w.to_string()));
    }
    if let Some(he) = input.wifi6 {
        set.push(("AP_HE".into(), if he { "1" } else { "0" }.into()));
    }
    for (k, v) in [
        ("AP_TXPOWER24", &input.txpower24),
        ("AP_TXPOWER5", &input.txpower5),
    ] {
        if let Some(v) = v {
            set.push((k.into(), check_txpower(v)?));
        }
    }
    if let Some(n) = &input.names {
        set.push(("AP_NAMES".into(), check_names(n)?));
    }

    let mut out = EnvFile {
        header: f.header.clone(),
        other: f.other.clone(),
        vars: Vec::new(),
    };
    // keep everything this module does not manage, in file order
    let net_ids: Vec<String> = cur.networks.iter().map(|n| n.id.clone()).collect();
    let is_net_var = |k: &str| {
        NET_PREFIXES.iter().any(|p| {
            k.strip_prefix(p)
                .is_some_and(|id| net_ids.iter().any(|n| n == id))
        })
    };
    let replace_nets = input.networks.is_some();
    for (k, v) in &f.vars {
        if MANAGED.contains(&k.as_str()) || (replace_nets && is_net_var(k)) {
            continue;
        }
        if !replace_nets && k == "AP_SSIDS" {
            continue;
        }
        out.vars.push((k.clone(), v.clone()));
    }
    // managed radio settings: the new value, else the current one
    for k in [
        "AP_COUNTRY",
        "AP_CHAN24",
        "AP_CHAN5",
        "AP_HT5",
        "AP_HE",
        "AP_TXPOWER24",
        "AP_TXPOWER5",
        "AP_NAMES",
    ] {
        if let Some((_, v)) = set.iter().find(|(n, _)| n == k) {
            out.vars.push((k.into(), v.clone()));
        } else if let Some(v) = f.get(k) {
            out.vars.push((k.into(), v.to_string()));
        }
    }
    match &input.networks {
        None => {
            out.vars.push((
                "AP_SSIDS".into(),
                f.get("AP_SSIDS").unwrap_or("").to_string(),
            ));
        }
        Some(list) => {
            let mut taken: Vec<String> = Vec::new();
            let mut enabled: Vec<String> = Vec::new();
            let mut per_band = [0usize; 2];
            let mut net_vars: Vec<(String, String)> = Vec::new();
            for n in list {
                let ssid = n.ssid.as_str();
                check_ssid(ssid)?;
                let sec = n.security.as_deref().unwrap_or("wpa2");
                if !matches!(sec, "wpa2" | "wpa3" | "wpa2+3") {
                    return Err(invalid(format!("security {sec:?}: wpa2, wpa3 or wpa2+3")));
                }
                let bands = n.bands.as_deref().unwrap_or("both");
                if !matches!(bands, "both" | "24" | "5") {
                    return Err(invalid(format!("bands {bands:?}: both, 24 or 5")));
                }
                let id = match &n.id {
                    Some(id) => {
                        if !net_ids.contains(id) {
                            return Err(invalid(format!("no network with id {id:?}")));
                        }
                        id.clone()
                    }
                    None => {
                        let mut all = net_ids.clone();
                        all.extend(taken.iter().cloned());
                        new_id(ssid, &all)
                    }
                };
                if !valid_id(&id) {
                    return Err(invalid(format!("network id {id:?}")));
                }
                if taken.contains(&id) {
                    return Err(invalid(format!("network {id:?} listed twice")));
                }
                taken.push(id.clone());
                let key = match n.key.as_deref().filter(|k| !k.is_empty()) {
                    Some(k) => {
                        check_key(k, sec)?;
                        k.to_string()
                    }
                    None => match f.get(&format!("KEY_{id}")).filter(|k| !k.is_empty()) {
                        Some(k) if n.id.is_some() => {
                            // a kept hex PSK cannot become a WPA3 password
                            check_key(k, sec)?;
                            k.to_string()
                        }
                        _ => {
                            return Err(invalid(format!(
                                "network {ssid:?} needs a password (8 to 63 characters)"
                            )))
                        }
                    },
                };
                if n.enabled {
                    if bands != "5" {
                        per_band[0] += 1;
                    }
                    if bands != "24" {
                        per_band[1] += 1;
                    }
                    enabled.push(id.clone());
                }
                net_vars.push((format!("SSID_{id}"), ssid.to_string()));
                net_vars.push((format!("KEY_{id}"), key));
                net_vars.push((format!("SEC_{id}"), sec.to_string()));
                if n.hidden {
                    net_vars.push((format!("HIDE_{id}"), "1".into()));
                }
                if bands != "both" {
                    net_vars.push((format!("BANDS_{id}"), bands.to_string()));
                }
                if n.isolate {
                    net_vars.push((format!("ISOLATE_{id}"), "1".into()));
                }
                if n.guest {
                    net_vars.push((format!("GUEST_{id}"), "1".into()));
                }
                // the network's own block list is edited through block()/unblock(), never dropped by a page save
                if n.id.is_some() {
                    if let Some(d) = f
                        .get(&format!("DENY_{id}"))
                        .filter(|d| !d.trim().is_empty())
                    {
                        net_vars.push((format!("DENY_{id}"), d.to_string()));
                    }
                }
            }
            if per_band.iter().any(|&c| c > MAX_PER_BAND) {
                return Err(invalid(format!(
                    "at most {MAX_PER_BAND} networks per band are enabled at a time"
                )));
            }
            let mut seen = std::collections::HashSet::new();
            for n in list.iter().filter(|n| n.enabled) {
                if !seen.insert(n.ssid.as_str()) {
                    return Err(invalid(format!(
                        "two enabled networks are both named {:?}",
                        n.ssid
                    )));
                }
            }
            out.vars.push(("AP_SSIDS".into(), enabled.join(" ")));
            out.vars.extend(net_vars);
        }
    }
    Ok(out)
}

/// The file text: header, then one line per network, then the rest.
pub fn render(f: &EnvFile) -> String {
    let mut s = String::new();
    for h in &f.header {
        s.push_str(h);
        s.push('\n');
    }
    if f.header.is_empty() {
        s.push_str("# Wi-Fi of this access point (written by Patronus; the web UI's Wi-Fi page edits it)\n");
    }
    // network variables grouped per network on one line, like the hand-written files
    let mut ids: Vec<String> = Vec::new();
    for (k, _) in &f.vars {
        if let Some(id) = k.strip_prefix("SSID_") {
            ids.push(id.to_string());
        }
    }
    fn net_of<'a>(k: &'a str, ids: &[String]) -> Option<&'a str> {
        NET_PREFIXES
            .iter()
            .find_map(|p| k.strip_prefix(p))
            .filter(|id| ids.iter().any(|i| i == id))
    }
    let mut done = std::collections::HashSet::new();
    for (k, v) in &f.vars {
        if let Some(id) = net_of(k, &ids) {
            if done.insert(id.to_string()) {
                let line: Vec<String> = f
                    .vars
                    .iter()
                    .filter(|(k2, _)| net_of(k2, &ids) == Some(id))
                    .map(|(k2, v2)| format!("{k2}={}", quote(v2)))
                    .collect();
                s.push_str(&line.join(" "));
                s.push('\n');
            }
            continue;
        }
        s.push_str(&format!("{k}={}\n", quote(v)));
    }
    for o in &f.other {
        s.push_str(o);
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// live system
// ---------------------------------------------------------------------------

fn read_env(p: &Paths) -> Result<EnvFile> {
    match std::fs::read_to_string(&p.env) {
        Ok(t) => Ok(parse(&t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnvFile::default()),
        Err(e) => Err(Error::Config(format!("{}: {e}", p.env.display()))),
    }
}

fn write_env(p: &Paths, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = p.env.with_extension("env.new");
    let mut fh = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| Error::Config(format!("{}: {e}", tmp.display())))?;
    fh.write_all(text.as_bytes())
        .and_then(|_| fh.sync_all())
        .map_err(|e| Error::Config(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &p.env).map_err(|e| Error::Config(format!("{}: {e}", p.env.display())))
}

/// The BSS interfaces the rendered configs define (`interface=` / `bss=`).
pub fn bss_interfaces(run: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for b in ["ap5.conf", "ap24.conf"] {
        if let Ok(t) = std::fs::read_to_string(run.join(b)) {
            for l in t.lines() {
                if let Some(i) = l
                    .strip_prefix("interface=")
                    .or_else(|| l.strip_prefix("bss="))
                {
                    v.push(i.to_string());
                }
            }
        }
    }
    v
}

fn hostapd_cli(run: &Path, ifname: &str, args: &[&str]) -> Option<String> {
    let o = Command::new("hostapd_cli")
        .arg("-p")
        .arg(run)
        .arg("-i")
        .arg(ifname)
        .args(args)
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn kv(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Expected BSS interfaces for a file: `wl5-<id>` / `wl24-<id>` per enabled
/// network and band.
pub fn expected_interfaces(f: &EnvFile) -> Vec<String> {
    let c = view(f);
    let mut v = Vec::new();
    for n in c.networks.iter().filter(|n| n.enabled && n.has_key) {
        if n.bands != "24" {
            v.push(format!("wl5-{}", n.id));
        }
        if n.bands != "5" {
            v.push(format!("wl24-{}", n.id));
        }
    }
    v
}

fn run_script(p: &Paths, arg: &str) -> Result<String> {
    // Under systemd, start hostapd in its own transient scope: started from
    // the web UI's service it would otherwise belong to that unit's cgroup
    // and die with the next restart of the web UI.
    let systemd = Path::new("/run/systemd/system").is_dir()
        && Path::new("/usr/bin/systemd-run").exists()
        && arg == "start";
    let mut cmd = if systemd {
        let mut c = Command::new("/usr/bin/systemd-run");
        c.args(["--scope", "--quiet", "--collect", "--"])
            .arg(&p.script);
        c
    } else {
        Command::new(&p.script)
    };
    let o = cmd
        .arg(arg)
        .output()
        .map_err(|e| Error::Service(format!("{}: {e}", p.script.display())))?;
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    Ok(s)
}

fn restart(p: &Paths) -> Result<String> {
    run_script(p, "stop")?;
    run_script(p, "start")
}

/// Wait until every expected BSS answers; the ones that did not, with their state.
fn wait_up(p: &Paths, want: &[String], within: Duration) -> Vec<String> {
    let t0 = Instant::now();
    loop {
        let bad: Vec<String> = want
            .iter()
            .filter_map(|i| {
                let st = hostapd_cli(&p.run, i, &["status"])
                    .map(|t| {
                        kv(&t)
                            .into_iter()
                            .find(|(k, _)| k == "state")
                            .map(|(_, v)| v)
                            .unwrap_or_default()
                    })
                    .unwrap_or_else(|| "not running".into());
                // DFS: the channel availability check runs (up to 10 min), the BSS follows
                (!matches!(st.as_str(), "ENABLED" | "DFS")).then(|| format!("{i}: {st}"))
            })
            .collect();
        if bad.is_empty() || t0.elapsed() >= within {
            return bad;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// GET: settings (no keys), radios and BSS states.
pub fn get(p: &Paths) -> Result<Value> {
    if !p.present() {
        return Ok(json!({ "backend": false }));
    }
    let f = read_env(p)?;
    Ok(json!({
        "backend": true,
        "config": view(&f),
        "radios": radios(p),
        "radio_count": p.radios(),
        "guard": guard_status(),
        "guest_filter": guest_filter_status(p),
    }))
}

/// Live radio state from hostapd (first BSS of each config).
pub fn radios(p: &Paths) -> Vec<Value> {
    let mut out = Vec::new();
    for (band, file) in [("5", "ap5.conf"), ("24", "ap24.conf")] {
        let Ok(t) = std::fs::read_to_string(p.run.join(file)) else {
            out.push(json!({ "band": band, "state": "off" }));
            continue;
        };
        let first = t
            .lines()
            .find_map(|l| l.strip_prefix("interface="))
            .unwrap_or("")
            .to_string();
        let st = hostapd_cli(&p.run, &first, &["status"])
            .map(|s| kv(&s))
            .unwrap_or_default();
        let g = |k: &str| {
            st.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let bss: Vec<Value> = st
            .iter()
            .filter(|(k, _)| k.starts_with("bss["))
            .map(|(k, iface)| {
                let n = &k[4..k.len() - 1];
                json!({
                    "interface": iface,
                    "ssid": g(&format!("ssid[{n}]")),
                    "bssid": g(&format!("bssid[{n}]")),
                    "clients": g(&format!("num_sta[{n}]")).parse::<u32>().unwrap_or(0),
                })
            })
            .collect();
        let txpower = (!first.is_empty())
            .then(|| {
                Command::new("iw")
                    .args(["dev", &first, "info"])
                    .output()
                    .ok()
            })
            .flatten()
            .and_then(|o| parse_txpower(&String::from_utf8_lossy(&o.stdout)));
        out.push(json!({
            "band": band,
            "state": if st.is_empty() { "not running".to_string() } else { g("state") },
            "channel": g("channel"),
            "freq": g("freq"),
            "wifi6": g("ieee80211ax") == "1",
            "txpower_dbm": txpower,
            "bss": bss,
        }));
    }
    out
}

/// PUT: validate, write, restart, verify (rolls back on failure).
pub fn apply(p: &Paths, input: &WifiInput) -> Result<Value> {
    if !p.present() {
        return Err(Error::Config(
            "Invalid: this unit has no access-point Wi-Fi backend".into(),
        ));
    }
    let old_text = std::fs::read_to_string(&p.env).unwrap_or_default();
    let old = parse(&old_text);
    let new = update(&old, input)?;
    let text = render(&new);
    commit(p, &old_text, &new, &text)
}

/// Write `text` (parsed as `new`) over `old_text`, restart the radios and verify every network; roll back on failure.
fn commit(p: &Paths, old_text: &str, new: &EnvFile, text: &str) -> Result<Value> {
    let old = parse(old_text);
    if text == old_text {
        return Ok(json!({ "changed": false, "restarted": false }));
    }
    if !old_text.is_empty() {
        let prev = p.env.with_extension("env.prev");
        let _ = std::fs::write(&prev, old_text);
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o600));
    }
    write_env(p, text)?;
    if p.radios() == 0 {
        return Ok(json!({
            "changed": true,
            "restarted": false,
            "note": "saved; this unit has no Wi-Fi radio up right now, the settings apply when the radios start"
        }));
    }
    if !restart_needed(&old, new) {
        // transmit power, block lists, client names: applied to the running radios, nobody is disconnected
        let mut out = String::new();
        for a in ["txpower", "acl"] {
            out.push_str(&run_script(p, a)?);
        }
        return Ok(
            json!({ "changed": true, "restarted": false, "live": true, "output": out.trim() }),
        );
    }
    let log = restart(p)?;
    let want = expected_interfaces(new);
    let bad = wait_up(p, &want, Duration::from_secs(40));
    if bad.is_empty() {
        return Ok(json!({ "changed": true, "restarted": true, "interfaces": want }));
    }
    // roll back to the file that worked
    let detail = format!("{}; {}", bad.join(", "), log.trim());
    let _ = write_env(p, old_text);
    let _ = restart(p);
    let back = wait_up(p, &expected_interfaces(&old), Duration::from_secs(40));
    Err(Error::Service(format!(
        "Wi-Fi did not come up with the new settings ({detail}); the previous settings were restored{}",
        if back.is_empty() {
            String::new()
        } else {
            format!(" but these are not up either: {}", back.join(", "))
        }
    )))
}

/// The access-point file as it is (for a configuration backup), or None on a unit without the backend.
pub fn export_text(p: &Paths) -> Result<Option<String>> {
    if !p.present() {
        return Ok(None);
    }
    match std::fs::read_to_string(&p.env) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Config(format!("{}: {e}", p.env.display()))),
    }
}

/// Put a backed-up access-point file back (configuration restore): checked like a page save (every network needs a
/// valid name and, unless open, a valid password), then written, the radios restarted and verified, rolled back on
/// failure.
pub fn restore_text(p: &Paths, text: &str) -> Result<Value> {
    if !p.present() {
        return Err(Error::Config(
            "Invalid: this unit has no access-point Wi-Fi backend".into(),
        ));
    }
    let new = parse(text);
    let cfg = view(&new);
    if cfg.networks.is_empty() {
        return Err(invalid(
            "the backup's access-point settings define no Wi-Fi network",
        ));
    }
    for n in &cfg.networks {
        check_ssid(&n.ssid)?;
        if let Some(k) = new.get(&format!("KEY_{}", n.id)) {
            check_key(k, &n.security)?;
        }
    }
    let old_text = std::fs::read_to_string(&p.env).unwrap_or_default();
    commit(p, &old_text, &new, text)
}

/// Does going from `old` to `new` need the radios restarted? Not when only live settings changed (transmit power,
/// block lists, client names) and comments.
pub fn restart_needed(old: &EnvFile, new: &EnvFile) -> bool {
    let live = |k: &str| LIVE_VARS.contains(&k) || LIVE_PREFIXES.iter().any(|p| k.starts_with(p));
    let rest = |f: &EnvFile| {
        let mut v: Vec<(String, String)> = f
            .vars
            .iter()
            .filter(|(k, _)| !live(k))
            .map(|(k, _)| (k.clone(), f.get(k).unwrap_or("").to_string()))
            .collect();
        v.sort();
        v.dedup();
        (v, f.other.clone())
    };
    rest(old) != rest(new)
}

/// Add (`block = true`) or remove a MAC on one network's block list (`network` = its id) or on the unit's list
/// (`network` = None / "all"). Applied to the running radios through hostapd's deny list: a blocked client still
/// connected is disconnected, nobody else is.
pub fn set_block(p: &Paths, mac: &str, network: Option<&str>, block: bool) -> Result<Value> {
    let mac = mac.trim().to_ascii_lowercase();
    if !valid_mac(&mac) {
        return Err(invalid(format!("MAC address {mac:?}")));
    }
    if !p.present() {
        return Err(Error::Config(
            "Invalid: this unit has no access-point Wi-Fi backend".into(),
        ));
    }
    let old_text = std::fs::read_to_string(&p.env).unwrap_or_default();
    let f = parse(&old_text);
    let key = match network.filter(|n| !n.is_empty() && *n != "all") {
        Some(id) => {
            if f.get(&format!("SSID_{id}")).is_none() {
                return Err(Error::Config(format!("no such network {id:?}")));
            }
            format!("DENY_{id}")
        }
        None => "AP_DENY".to_string(),
    };
    let mut list = mac_list(f.get(&key).unwrap_or(""));
    if block {
        if !list.contains(&mac) {
            list.push(mac.clone());
        }
    } else {
        list.retain(|m| *m != mac);
    }
    if list.len() > 256 {
        return Err(invalid("at most 256 blocked devices per list"));
    }
    let mut new = f.clone();
    new.vars.retain(|(k, _)| *k != key);
    if !list.is_empty() {
        new.vars.push((key, list.join(" ")));
    }
    let text = render(&new);
    commit(p, &old_text, &new, &text)
}

fn guard_script() -> PathBuf {
    PathBuf::from(
        std::env::var("PATRONUS_AP_GUARD")
            .unwrap_or_else(|_| "/usr/libexec/patronus/wifi-guard".into()),
    )
}

/// `wifi-guard status` (firmware crash containment, docs 12.6d) as JSON: mode normal | safe-mode, the reason and
/// hold time of safe mode, firmware crashes this boot. `None` when the unit has no guard.
pub fn parse_guard_status(text: &str) -> Value {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("").trim();
    let mut v = json!({ "mode": "unknown" });
    if first == "normal" {
        v["mode"] = json!("normal");
    } else if let Some(rest) = first.strip_prefix("safe-mode") {
        v["mode"] = json!("safe-mode");
        let rest = rest.trim();
        if let Some(i) = rest.find("reason=") {
            let r = &rest[i + 7..];
            let (reason, tail) = match r.rfind(" hold=") {
                Some(h) => (&r[..h], &r[h + 6..]),
                None => (r, ""),
            };
            v["reason"] = json!(reason.trim());
            if let Ok(h) = tail.trim().parse::<u64>() {
                v["hold_s"] = json!(h);
            }
        }
    }
    for l in lines {
        for (k, val) in kv(&l.replace(' ', "\n")) {
            if let Ok(n) = val.parse::<u64>() {
                match k.as_str() {
                    "crashes-this-boot" => v["crashes_this_boot"] = json!(n),
                    "boot" => v["boot"] = json!(n),
                    _ => {}
                }
            }
        }
    }
    v
}

pub fn guard_status() -> Option<Value> {
    let g = guard_script();
    if !g.is_file() {
        return None;
    }
    let o = Command::new(&g).arg("status").output().ok()?;
    Some(parse_guard_status(&String::from_utf8_lossy(&o.stdout)))
}

/// `ap-guest status`: whether this unit can keep guest networks off the LAN, and why not.
pub fn guest_filter_status(p: &Paths) -> Value {
    let s = p.script.with_file_name("ap-guest");
    if !s.is_file() {
        return json!({ "available": false, "reason": "this firmware has no guest network filter (ap-guest)" });
    }
    let out = Command::new(&s)
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let kvs = kv(&out);
    let g = |k: &str| {
        kvs.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    json!({
        "available": g("available") == "yes",
        "active": g("active") == "yes",
        "ports": g("ports"),
        "reason": g("reason"),
    })
}

/// Transmit power a wireless interface uses right now (`iw dev <if> info`: "txpower 20.00 dBm").
pub fn parse_txpower(info: &str) -> Option<f64> {
    info.lines().find_map(|l| {
        l.trim()
            .strip_prefix("txpower ")
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    })
}

/// The passphrase of one network (admin-only in the web UI).
pub fn reveal_key(p: &Paths, id: &str) -> Result<String> {
    let f = read_env(p)?;
    f.get(&format!("SSID_{id}"))
        .and_then(|_| f.get(&format!("KEY_{id}")))
        .map(str::to_string)
        .ok_or_else(|| Error::Config(format!("no such network {id:?}")))
}

/// Parse `iw dev <if> station dump`.
pub fn parse_station_dump(ifname: &str, text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur: Option<serde_json::Map<String, Value>> = None;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("Station ") {
            if let Some(c) = cur.take() {
                out.push(Value::Object(c));
            }
            let mac = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let mut m = serde_json::Map::new();
            m.insert("mac".into(), json!(mac));
            m.insert("interface".into(), json!(ifname));
            m.insert(
                "band".into(),
                json!(if ifname.starts_with("wl24") {
                    "2.4 GHz"
                } else {
                    "5 GHz"
                }),
            );
            cur = Some(m);
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let Some((k, v)) = l.trim().split_once(':') else {
            continue;
        };
        let v = v.trim();
        let num = |s: &str| {
            s.split_whitespace()
                .next()
                .and_then(|n| n.parse::<i64>().ok())
        };
        match k.trim() {
            "signal" => {
                if let Some(n) = num(v) {
                    m.insert("signal_dbm".into(), json!(n));
                }
            }
            "tx bitrate" => {
                m.insert("tx_rate".into(), json!(v));
            }
            "rx bitrate" => {
                m.insert("rx_rate".into(), json!(v));
            }
            "connected time" => {
                if let Some(n) = num(v) {
                    m.insert("connected_s".into(), json!(n));
                }
            }
            "inactive time" => {
                if let Some(n) = num(v) {
                    m.insert("inactive_ms".into(), json!(n));
                }
            }
            "rx bytes" => {
                if let Some(n) = num(v) {
                    m.insert("rx_bytes".into(), json!(n));
                }
            }
            "tx bytes" => {
                if let Some(n) = num(v) {
                    m.insert("tx_bytes".into(), json!(n));
                }
            }
            _ => {}
        }
    }
    if let Some(c) = cur {
        out.push(Value::Object(c));
    }
    out
}

/// IPv4 neighbours by MAC (`/proc/net/arp`), to name a client's address.
fn arp_table() -> std::collections::HashMap<String, String> {
    std::fs::read_to_string("/proc/net/arp")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.len() >= 4 && c[3] != "00:00:00:00:00:00")
                .then(|| (c[3].to_ascii_lowercase(), c[0].to_string()))
        })
        .collect()
}

/// Connected clients of every BSS, with the network name.
pub fn clients(p: &Paths) -> Result<Value> {
    let f = read_env(p)?;
    let names = view(&f);
    let arp = arp_table();
    let mut all = Vec::new();
    for i in bss_interfaces(&p.run) {
        let Ok(o) = Command::new("iw")
            .args(["dev", &i, "station", "dump"])
            .output()
        else {
            continue;
        };
        let ssid = i
            .split_once('-')
            .and_then(|(_, id)| names.networks.iter().find(|n| n.id == id))
            .map(|n| n.ssid.clone())
            .unwrap_or_default();
        for mut c in parse_station_dump(&i, &String::from_utf8_lossy(&o.stdout)) {
            if let Some(m) = c.as_object_mut() {
                m.insert("ssid".into(), json!(ssid));
                if let Some(ip) = m
                    .get("mac")
                    .and_then(Value::as_str)
                    .and_then(|mac| arp.get(mac))
                {
                    m.insert("ipv4".into(), json!(ip));
                }
            }
            all.push(c);
        }
    }
    crate::apnames::annotate(
        &mut all,
        &names.names,
        &crate::apnames::names_file(),
        &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
    );
    Ok(json!({ "clients": all }))
}

fn valid_mac(m: &str) -> bool {
    let p: Vec<&str> = m.split(':').collect();
    p.len() == 6
        && p.iter()
            .all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Disconnect a client from one BSS (it may join again; this is not a block).
pub fn kick(p: &Paths, ifname: &str, mac: &str) -> Result<Value> {
    if !valid_mac(mac) {
        return Err(Error::Config(format!("Invalid MAC address {mac:?}")));
    }
    if !bss_interfaces(&p.run).iter().any(|i| i == ifname) {
        return Err(Error::Config(format!(
            "Invalid interface {ifname:?}: not one of this unit's networks"
        )));
    }
    match hostapd_cli(&p.run, ifname, &["deauthenticate", mac]) {
        Some(o) if o.trim().ends_with("OK") || o.trim().is_empty() => Ok(json!({ "ok": true })),
        Some(o) => Err(Error::Service(format!("hostapd: {}", o.trim()))),
        None => Err(Error::Service(format!(
            "hostapd on {ifname} did not answer"
        ))),
    }
}

// ---------------------------------------------------------------------------
// uplink of an access point
// ---------------------------------------------------------------------------

/// Default IPv4 gateway from `/proc/net/route` (device, address).
pub fn default_gateway(route: &str) -> Option<(String, String)> {
    route.lines().skip(1).find_map(|l| {
        let c: Vec<&str> = l.split_whitespace().collect();
        if c.len() > 2 && c[1] == "00000000" {
            let g = u32::from_str_radix(c[2], 16).ok()?;
            let b = g.to_le_bytes();
            Some((
                c[0].to_string(),
                format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
            ))
        } else {
            None
        }
    })
}

/// Bridge, address, gateway, DNS and the wired ports of an access point.
pub fn uplink(p: &Paths, bridge: &str) -> Value {
    let rd = |f: PathBuf| {
        std::fs::read_to_string(f)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let addrs: Vec<String> = Command::new("ip")
        .args(["addr", "show", "dev", bridge])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    let rest = t
                        .strip_prefix("inet ")
                        .or_else(|| t.strip_prefix("inet6 "))?;
                    let a = rest.split_whitespace().next()?;
                    (!a.starts_with("fe80:")).then(|| a.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    let gw = default_gateway(&std::fs::read_to_string("/proc/net/route").unwrap_or_default());
    let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default();
    let gw_reachable = gw.as_ref().is_some_and(|(_, g)| {
        arp.lines().any(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            c.len() >= 4 && c[0] == g && c[2] == "0x2"
        })
    });
    let dns: Vec<String> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string()))
        .collect();
    let mut ports = Vec::new();
    if let Ok(d) = std::fs::read_dir(&p.net) {
        let mut names: Vec<String> = d
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for n in names {
            let dir = p.net.join(&n);
            let master = std::fs::read_link(dir.join("master"))
                .ok()
                .and_then(|m| m.file_name().map(|s| s.to_string_lossy().into_owned()));
            if master.as_deref() != Some(bridge) || n.starts_with("wl") {
                continue;
            }
            let carrier = rd(dir.join("carrier")) == "1";
            let speed: i64 = rd(dir.join("speed")).parse().unwrap_or(-1);
            ports.push(json!({
                "name": n,
                "link": carrier,
                "speed_mbps": if carrier && speed > 0 { json!(speed) } else { Value::Null },
                "duplex": if carrier { json!(rd(dir.join("duplex"))) } else { Value::Null },
            }));
        }
    }
    let dhcp = Path::new(&format!("/run/udhcpc-{bridge}.pid")).exists();
    json!({
        "bridge": bridge,
        "addresses": addrs,
        "addressing": if dhcp { "dhcp" } else { "static" },
        "gateway": gw.map(|(_, g)| g),
        "gateway_reachable": gw_reachable,
        "dns": dns,
        "ports": ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoting_like_sh() {
        let f = parse("A='x y' B=\"q \\\"z\\\" \\$\" C=plain D= E='it'\\''s' # tail\n");
        assert_eq!(f.get("A"), Some("x y"));
        assert_eq!(f.get("B"), Some("q \"z\" $"));
        assert_eq!(f.get("C"), Some("plain"));
        assert_eq!(f.get("D"), Some(""));
        assert_eq!(f.get("E"), Some("it's"));
    }

    #[test]
    fn expansions_and_commands_are_kept_verbatim_not_parsed() {
        let f = parse("X=$(id)\nY=\"$HOME\"\n. /etc/foo\nZ=1\n");
        assert_eq!(f.get("X"), None);
        assert_eq!(f.get("Y"), None);
        assert_eq!(f.get("Z"), Some("1"));
        assert_eq!(f.other.len(), 3);
        assert!(render(&f).contains(". /etc/foo\n"));
    }

    #[test]
    fn quote_round_trips_every_printable_value() {
        for v in [
            "",
            "plain",
            "a b",
            "it's",
            "x\"y",
            "$HOME",
            "`id`",
            "a\\b",
            "Platform 9 3/4",
            "';rm -rf /;'",
        ] {
            let f = parse(&format!("K={}\n", quote(v)));
            assert_eq!(f.get("K"), Some(v), "value {v:?} quoted as {}", quote(v));
        }
    }

    fn sample() -> EnvFile {
        parse("# Unit header\nAP_COUNTRY=US\nAP_CHAN24=auto\nAP_CHAN5=149\nAP_HT5=80\nAP_SSIDS=\"p hs\"\nSSID_p='Plat 9' KEY_p=secretpw1 SEC_p=wpa2\nSSID_hs='Hogs' KEY_hs=secretpw2 SEC_hs=wpa2\nAP_ADDR=\nSSID_old=Old KEY_old=oldpass12\n")
    }

    #[test]
    fn view_reads_networks_without_keys() {
        let c = view(&sample());
        assert_eq!(c.country, "US");
        assert_eq!(c.chan24, "auto");
        assert_eq!(c.chan5, "149");
        assert!(c.wifi6, "Wi-Fi 6 is on unless AP_HE=0");
        let ids: Vec<_> = c
            .networks
            .iter()
            .map(|n| (n.id.as_str(), n.enabled))
            .collect();
        assert_eq!(ids, vec![("p", true), ("hs", true), ("old", false)]);
        let js = serde_json::to_string(&c).unwrap();
        assert!(
            !js.contains("secretpw"),
            "keys must not be in the view: {js}"
        );
    }

    #[test]
    fn radio_change_keeps_networks_keys_and_unmanaged_lines() {
        let f = sample();
        let n = update(
            &f,
            &WifiInput {
                chan5: Some("36".into()),
                width5: Some(40),
                ..Default::default()
            },
        )
        .unwrap();
        let t = render(&n);
        let back = parse(&t);
        assert_eq!(back.get("AP_CHAN5"), Some("36"));
        assert_eq!(back.get("AP_HT5"), Some("40"));
        assert_eq!(back.get("KEY_p"), Some("secretpw1"));
        assert_eq!(back.get("AP_SSIDS"), Some("p hs"));
        assert_eq!(back.get("AP_ADDR"), Some(""));
        assert_eq!(back.get("SSID_old"), Some("Old"));
        assert!(t.starts_with("# Unit header\n"));
        assert_eq!(view(&back).networks, view(&f).networks);
    }

    #[test]
    fn untouched_settings_render_identically() {
        let f = sample();
        let once = render(&update(&f, &WifiInput::default()).unwrap());
        let twice = render(&update(&parse(&once), &WifiInput::default()).unwrap());
        assert_eq!(once, twice);
        assert_eq!(view(&parse(&once)), view(&f));
    }

    fn nets(f: &EnvFile) -> Vec<NetworkInput> {
        view(f)
            .networks
            .into_iter()
            .map(|n| NetworkInput {
                id: Some(n.id),
                ssid: n.ssid,
                enabled: n.enabled,
                security: Some(n.security),
                hidden: n.hidden,
                bands: Some(n.bands),
                isolate: n.isolate,
                guest: n.guest,
                key: None,
            })
            .collect()
    }

    #[test]
    fn password_change_rename_hide_and_add() {
        let f = sample();
        let mut l = nets(&f);
        l[0].key = Some("n3w pass'word".into());
        l[1].ssid = "Hogs 2".into();
        l[1].hidden = true;
        l[1].bands = Some("5".into());
        l.push(NetworkInput {
            ssid: "Guest!".into(),
            enabled: true,
            key: Some("guestpass".into()),
            isolate: true,
            ..Default::default()
        });
        let n = update(
            &f,
            &WifiInput {
                networks: Some(l),
                ..Default::default()
            },
        )
        .unwrap();
        let back = parse(&render(&n));
        assert_eq!(back.get("KEY_p"), Some("n3w pass'word"));
        assert_eq!(
            back.get("KEY_hs"),
            Some("secretpw2"),
            "an empty key keeps the old one"
        );
        assert_eq!(back.get("SSID_hs"), Some("Hogs 2"));
        assert_eq!(back.get("HIDE_hs"), Some("1"));
        assert_eq!(back.get("BANDS_hs"), Some("5"));
        assert_eq!(back.get("AP_SSIDS"), Some("p hs guest"));
        assert_eq!(back.get("ISOLATE_guest"), Some("1"));
        assert_eq!(
            expected_interfaces(&back),
            vec!["wl5-p", "wl24-p", "wl5-hs", "wl5-guest", "wl24-guest"]
        );
    }

    #[test]
    fn delete_and_disable() {
        let f = sample();
        let mut l = nets(&f);
        l.retain(|n| n.id.as_deref() != Some("old"));
        l[1].enabled = false;
        let back = parse(&render(
            &update(
                &f,
                &WifiInput {
                    networks: Some(l),
                    ..Default::default()
                },
            )
            .unwrap(),
        ));
        assert_eq!(back.get("SSID_old"), None);
        assert_eq!(back.get("KEY_old"), None);
        assert_eq!(back.get("AP_SSIDS"), Some("p"));
        assert_eq!(
            back.get("SSID_hs"),
            Some("Hogs"),
            "a disabled network keeps its settings"
        );
    }

    #[test]
    fn refuses_bad_input_and_changes_nothing() {
        let f = sample();
        let bad = |i: WifiInput| update(&f, &i).unwrap_err().to_string();
        assert!(bad(WifiInput {
            chan5: Some("150".into()),
            ..Default::default()
        })
        .contains("not a 5 GHz channel"));
        assert!(bad(WifiInput {
            chan24: Some("36".into()),
            ..Default::default()
        })
        .contains("2.4 GHz"));
        assert!(bad(WifiInput {
            width5: Some(160),
            ..Default::default()
        })
        .contains("20, 40 or 80"));
        assert!(bad(WifiInput {
            country: Some("USA".into()),
            ..Default::default()
        })
        .contains("two-letter"));
        let mut l = nets(&f);
        l[0].key = Some("short".into());
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("8 to 63"));
        let mut l = nets(&f);
        l.push(NetworkInput {
            ssid: "New".into(),
            enabled: true,
            ..Default::default()
        });
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("needs a password"));
        let mut l = nets(&f);
        l[0].ssid = "x".repeat(33);
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("1 to 32"));
        let mut l = nets(&f);
        l[1].ssid = "Plat 9".into();
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("both named"));
        let mut l = nets(&f);
        for i in 0..4 {
            l.push(NetworkInput {
                ssid: format!("N{i}"),
                enabled: true,
                key: Some("password1".into()),
                ..Default::default()
            });
        }
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("at most 4"));
        let mut l = nets(&f);
        l[0].id = Some("nope".into());
        assert!(bad(WifiInput {
            networks: Some(l),
            ..Default::default()
        })
        .contains("no network"));
    }

    #[test]
    fn new_ids_fit_interface_names() {
        assert_eq!(new_id("Platform 9 3/4", &[]), "platform");
        assert_eq!(new_id("platform", &["platform".into()]), "platform2");
        assert_eq!(new_id("123 ☃", &[]), "net");
        for id in [new_id("Some Very Long Network Name", &[]), new_id("x", &[])] {
            assert!(valid_id(&id) && format!("wl24-{id}").len() <= 15, "{id}");
        }
    }

    #[test]
    fn guest_block_lists_txpower_and_live_changes() {
        let f = sample();
        let mut l = nets(&f);
        l[1].guest = true;
        let n = update(
            &f,
            &WifiInput {
                networks: Some(l),
                txpower5: Some("17 dBm".into()),
                names: Some("192.0.2.1".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let back = parse(&render(&n));
        assert_eq!(back.get("GUEST_hs"), Some("1"));
        assert_eq!(back.get("AP_TXPOWER5"), Some("17"));
        let v = view(&back);
        assert!(v.networks[1].guest && !v.networks[0].guest);
        assert_eq!((v.txpower5.as_str(), v.txpower24.as_str()), ("17", "auto"));
        assert_eq!(v.names, "192.0.2.1");
        assert!(
            restart_needed(&f, &back),
            "a guest network needs the radios restarted"
        );
        // transmit power and block lists alone are live changes
        let t = update(
            &back,
            &WifiInput {
                txpower24: Some("10".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!restart_needed(&back, &t));
        let mut d = back.clone();
        d.vars.push(("AP_DENY".into(), "aa:bb:cc:dd:ee:ff".into()));
        d.vars
            .push(("DENY_p".into(), "02:00:00:00:00:01 junk".into()));
        assert!(!restart_needed(&back, &d));
        let v = view(&d);
        assert_eq!(v.blocked, vec!["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(
            v.networks[0].blocked,
            vec!["02:00:00:00:00:01"],
            "invalid entries are dropped"
        );
        // a page save keeps a network's block list; deleting the network drops it
        let kept = update(
            &d,
            &WifiInput {
                networks: Some(nets(&d)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(kept.get("DENY_p"), Some("02:00:00:00:00:01 junk"));
        assert_eq!(kept.get("AP_DENY"), Some("aa:bb:cc:dd:ee:ff"));
        let mut l = nets(&d);
        l.remove(0);
        let gone = update(
            &d,
            &WifiInput {
                networks: Some(l),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(gone.get("DENY_p"), None);
        for bad in ["0", "31", "max"] {
            assert!(
                update(
                    &f,
                    &WifiInput {
                        txpower24: Some(bad.into()),
                        ..Default::default()
                    }
                )
                .is_err(),
                "{bad}"
            );
        }
        assert!(update(
            &f,
            &WifiInput {
                names: Some("router.lan".into()),
                ..Default::default()
            }
        )
        .is_err());
    }

    #[test]
    fn block_and_unblock_without_radios() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join("ap.env");
        let script = d.path().join("ap");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&env, render(&sample())).unwrap();
        let p = Paths {
            env: env.clone(),
            script,
            run: d.path().join("run"),
            sysfs: d.path().join("nosys"),
            net: d.path().join("net"),
        };
        set_block(&p, "AA:BB:CC:DD:EE:01", None, true).unwrap();
        set_block(&p, "aa:bb:cc:dd:ee:02", Some("hs"), true).unwrap();
        set_block(&p, "aa:bb:cc:dd:ee:02", Some("hs"), true).unwrap();
        let v = view(&parse(&std::fs::read_to_string(&env).unwrap()));
        assert_eq!(v.blocked, vec!["aa:bb:cc:dd:ee:01"]);
        assert_eq!(v.networks[1].blocked, vec!["aa:bb:cc:dd:ee:02"]);
        assert!(set_block(&p, "nope", None, true).is_err());
        assert!(set_block(&p, "aa:bb:cc:dd:ee:03", Some("zz"), true).is_err());
        set_block(&p, "aa:bb:cc:dd:ee:01", Some("all"), false).unwrap();
        let t = std::fs::read_to_string(&env).unwrap();
        assert!(!t.contains("AP_DENY"), "{t}");
        assert!(t.contains("KEY_p=secretpw1"));
    }

    #[test]
    fn guard_status_lines() {
        let n = parse_guard_status("normal\ncrashes-this-boot=0 boot=12\n");
        assert_eq!(n["mode"], "normal");
        assert_eq!(n["crashes_this_boot"], 0);
        assert_eq!(n["boot"], 12);
        let s = parse_guard_status("safe-mode boot=7 up=31 reason=3 firmware crashes within 600 s hold=7200\ncrashes-this-boot=3 boot=7\n");
        assert_eq!(s["mode"], "safe-mode");
        assert_eq!(s["reason"], "3 firmware crashes within 600 s");
        assert_eq!(s["hold_s"], 7200);
        assert_eq!(s["crashes_this_boot"], 3);
        assert_eq!(parse_guard_status("")["mode"], "unknown");
        assert_eq!(
            parse_txpower("Interface wl5-p\n\tchannel 36 (5180 MHz)\n\ttxpower 23.00 dBm\n"),
            Some(23.0)
        );
    }

    #[test]
    fn station_dump_parsing() {
        let t = "Station 86:04:c3:a6:16:43 (on wl5-p)\n\tinactive time:\t120 ms\n\trx bytes:\t1234\n\ttx bytes:\t5678\n\tsignal:  \t-52 [-55, -54] dBm\n\ttx bitrate:\t1200.9 MBit/s 80MHz HE-MCS 11 HE-NSS 2\n\trx bitrate:\t864.8 MBit/s 80MHz HE-MCS 8 HE-NSS 2\n\tconnected time:\t3600 seconds\nStation e2:49:97:6f:df:99 (on wl5-p)\n\tsignal:  \t-70 dBm\n";
        let v = parse_station_dump("wl5-p", t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0]["mac"], "86:04:c3:a6:16:43");
        assert_eq!(v[0]["signal_dbm"], -52);
        assert_eq!(v[0]["connected_s"], 3600);
        assert_eq!(v[0]["band"], "5 GHz");
        assert!(v[0]["tx_rate"].as_str().unwrap().starts_with("1200.9"));
        assert_eq!(v[1]["signal_dbm"], -70);
    }

    #[test]
    fn gateway_from_proc_route() {
        let r = "Iface\tDestination\tGateway \tFlags\nbr-lan\t000200C0\t00000000\t0001\nbr-lan\t00000000\t010200C0\t0003\n";
        assert_eq!(
            default_gateway(r),
            Some(("br-lan".to_string(), "192.0.2.1".to_string()))
        );
        assert_eq!(default_gateway("Iface\n"), None);
    }

    #[test]
    fn backup_export_and_restore_of_the_access_point_file() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join("ap.env");
        let script = d.path().join("ap");
        let p = Paths {
            env: env.clone(),
            script: script.clone(),
            run: d.path().join("run"),
            sysfs: d.path().join("nosys"),
            net: d.path().join("net"),
        };
        // no backend: nothing exported, restore refused
        assert_eq!(export_text(&p).unwrap(), None);
        assert!(restore_text(&p, "AP_SSIDS=x\n").is_err());
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        let orig = render(&sample()) + "# kept comment\nAP_ADDR=dhcp\n";
        std::fs::write(&env, &orig).unwrap();
        let saved = export_text(&p).unwrap().unwrap();
        assert_eq!(saved, orig);
        // a later change through the page, then the backup goes back verbatim (unmanaged lines too)
        apply(
            &p,
            &WifiInput {
                chan24: Some("6".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(std::fs::read_to_string(&env).unwrap(), orig);
        let r = restore_text(&p, &saved).unwrap();
        assert_eq!(r["changed"], true);
        assert_eq!(std::fs::read_to_string(&env).unwrap(), orig);
        // a broken backup is refused and leaves the file alone
        let e = restore_text(&p, "# nothing here\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("Invalid Wi-Fi settings"), "{e}");
        let bad = saved.replace("Plat 9", &"X".repeat(40));
        assert_ne!(bad, saved);
        assert!(restore_text(&p, &bad).is_err());
        assert_eq!(std::fs::read_to_string(&env).unwrap(), orig);
    }

    #[test]
    fn apply_writes_atomically_and_keeps_previous_without_radios() {
        let d = tempfile::tempdir().unwrap();
        let env = d.path().join("ap.env");
        let script = d.path().join("ap");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(&env, render(&sample())).unwrap();
        let p = Paths {
            env: env.clone(),
            script,
            run: d.path().join("run"),
            sysfs: d.path().join("nosys"),
            net: d.path().join("net"),
        };
        let r = apply(
            &p,
            &WifiInput {
                chan24: Some("6".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r["restarted"], false);
        assert_eq!(
            parse(&std::fs::read_to_string(&env).unwrap()).get("AP_CHAN24"),
            Some("6")
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&env).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_to_string(d.path().join("ap.env.prev"))
            .unwrap()
            .contains("AP_CHAN24=auto"));
        let again = apply(
            &p,
            &WifiInput {
                chan24: Some("6".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(again["changed"], false);
        assert_eq!(reveal_key(&p, "p").unwrap(), "secretpw1");
        assert!(reveal_key(&p, "zz").is_err());
        let g = get(&p).unwrap();
        assert_eq!(g["backend"], true);
        assert!(!g.to_string().contains("secretpw"));
    }
}
