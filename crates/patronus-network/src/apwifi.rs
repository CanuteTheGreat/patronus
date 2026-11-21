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
    "AP_HT24",
    "AP_HT5",
    "AP_DFS",
    "AP_UNII4",
    "AP_CHANLIST24",
    "AP_CHANLIST5",
    "AP_ACS_SCANS",
    "AP_COORD24",
    "AP_COORD5",
    "AP_COORD_PEERS",
    "AP_COORD_MIN_SIGNAL",
    "AP_COORD_DELAY",
    "AP_COORD_INTERVAL",
    "AP_COORD_QUIET",
    "AP_COORD_SCAN_SECS",
    "AP_STEER",
    "AP_STEER_SIGNAL",
    "AP_STEER_AFTER",
    "AP_STEER_IDLE",
    "AP_STEER_BLOCK",
    "AP_STEER_RETRY",
    "AP_STEER_MAX",
    "AP_STEER_INTERVAL",
    "AP_STEER_EXEMPT",
    "AP_AUTHFAIL_MAX",
    "AP_AUTHFAIL_WINDOW",
    "AP_AUTHFAIL_HOLD",
    "AP_AUTHFAIL_HOLD_MAX",
    "AP_XBSS_MAX",
    "AP_XBSS_WINDOW",
    "AP_XBSS_HOLD",
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
const LIVE_VARS: &[&str] = &[
    "AP_TXPOWER24",
    "AP_TXPOWER5",
    "AP_DENY",
    "AP_NAMES",
    "AP_COORD24",
    "AP_COORD5",
    "AP_COORD_PEERS",
    "AP_COORD_MIN_SIGNAL",
    "AP_COORD_DELAY",
    "AP_COORD_INTERVAL",
    "AP_COORD_QUIET",
    "AP_COORD_SCAN_SECS",
    "AP_STEER",
    "AP_STEER_SIGNAL",
    "AP_STEER_AFTER",
    "AP_STEER_IDLE",
    "AP_STEER_BLOCK",
    "AP_STEER_RETRY",
    "AP_STEER_MAX",
    "AP_STEER_INTERVAL",
    "AP_STEER_EXEMPT",
];
const LIVE_PREFIXES: &[&str] = &["DENY_"];
/// The channel-choice switches (docs 12.19) and the airtime switches (queue limit, fairness: docs 12.20); with
/// [`TUNING`] they are managed and live (`ap airtime` applies the airtime ones to the running radios).
const CHAN_SWITCHES: &[&str] = &[
    "AP_CHAN_SMART24",
    "AP_CHAN_SMART5",
    "AP_CHAN_RECHECK24",
    "AP_CHAN_RECHECK5",
    "AP_CHAN_TIME",
    "AP_CHAN_CSA",
    "AP_AQL",
    "AP_ATF",
];
fn chan_keys() -> impl Iterator<Item = &'static str> {
    CHAN_SWITCHES
        .iter()
        .copied()
        .chain(TUNING.iter().map(|e| e.1))
}
fn is_chan_key(k: &str) -> bool {
    chan_keys().any(|c| c == k)
}
fn is_managed(k: &str) -> bool {
    MANAGED.contains(&k) || is_chan_key(k)
}

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
    /// 2.4 GHz channel width in MHz: 20 | 40
    #[serde(default = "w20")]
    pub width24: u32,
    /// automatic channel choice (ACS) may pick a 5 GHz DFS channel (52-144; a 1-10 min radar check at each start)
    #[serde(default)]
    pub dfs: bool,
    /// automatic channel choice may pick the 5.9 GHz channels 169-177 (U-NII-4; many clients cannot use them)
    #[serde(default)]
    pub unii4: bool,
    /// channels ACS may pick per band (empty = every channel the country allows)
    #[serde(default = "default_chanlist24")]
    pub chanlist24: Vec<u32>,
    #[serde(default)]
    pub chanlist5: Vec<u32>,
    /// ACS survey rounds (1-20)
    #[serde(default = "default_acs_scans")]
    pub acs_scans: u32,
    /// channel coordination between this network's access points (docs 12.17): ACS keeps off the channels other
    /// units use, per band (default on)
    #[serde(default = "yes")]
    pub coord24: bool,
    #[serde(default = "yes")]
    pub coord5: bool,
    /// MACs of other units (any of their BSSIDs) whose channels are avoided even when they do not broadcast one of
    /// this unit's SSIDs (hidden networks)
    #[serde(default)]
    pub coord_peers: Vec<String>,
    /// access points weaker than this (dBm) are ignored
    #[serde(default = "default_coord_min_signal")]
    pub coord_min_signal: i32,
    /// seconds after a radio start before the first re-check against the other units
    #[serde(default = "default_coord_delay")]
    pub coord_delay: u32,
    /// seconds between later re-checks (0 = only the first)
    #[serde(default = "default_coord_interval")]
    pub coord_interval: u32,
    /// hours "H-H" in which a re-check may restart a radio that still has stations ("" = any time)
    #[serde(default = "default_coord_quiet")]
    pub coord_quiet: String,
    /// longest a channel scan may take, seconds
    #[serde(default = "default_coord_scan_secs")]
    pub coord_scan_secs: u32,
    /// steering of weak stations to a closer access point of this network (docs 12.18): "auto" (only when another
    /// access point of this network is known), "on" or "off"
    #[serde(default = "auto")]
    pub steer: String,
    /// a station at or below this average signal (dBm) is weak
    #[serde(default = "default_steer_signal")]
    pub steer_signal: i32,
    /// seconds a station stays weak (and on this unit) before it is moved
    #[serde(default = "default_steer_after")]
    pub steer_after: u32,
    /// a station moving less than this many kbit/s counts as idle (only idle stations are moved)
    #[serde(default = "default_steer_idle")]
    pub steer_idle: u32,
    /// seconds a moved station is refused on this unit (0 = never refuse: steering does nothing)
    #[serde(default = "default_steer_block")]
    pub steer_block: u32,
    /// a station that comes back just as weak, or bounces back from another unit, is left alone this many seconds
    #[serde(default = "default_steer_retry")]
    pub steer_retry: u32,
    /// most stations moved per round
    #[serde(default = "default_steer_max")]
    pub steer_max: u32,
    /// seconds between rounds
    #[serde(default = "default_steer_interval")]
    pub steer_interval: u32,
    /// MACs never moved
    #[serde(default)]
    pub steer_exempt: Vec<String>,
    /// channel choice by measurement (docs 12.19): the channel each radio starts on is the best-scoring candidate of
    /// comparable airtime samples + neighbours heard, per band
    #[serde(default = "yes")]
    pub chan_smart24: bool,
    #[serde(default = "yes")]
    pub chan_smart5: bool,
    /// nightly re-check of the running radio's channel, per band (moves only when clearly and repeatedly better)
    #[serde(default = "yes")]
    pub chan_recheck24: bool,
    #[serde(default = "yes")]
    pub chan_recheck5: bool,
    /// local time "HH:MM" of the nightly re-check ("" = no nightly re-check)
    #[serde(default = "default_chan_time")]
    pub chan_time: String,
    /// how a running radio moves: "auto" (channel switch announcement when the driver supports it; clients follow
    /// without disconnecting) or "off" (restart the radio)
    #[serde(default = "auto")]
    pub chan_csa: String,
    /// airtime queue limit (docs 12.20): each station may have only a few milliseconds of airtime queued in the
    /// radio's hardware (the rest waits in the per-station fair queue), so one busy or slow station no longer delays
    /// everything else on that radio; the limits per band are `aql_low*` / `aql_high*` in [`TUNING`]. Live.
    #[serde(default = "yes")]
    pub aql: bool,
    /// airtime fairness: every station gets an equal share of the radio's airtime (a slow station can no longer take
    /// most of it). Live.
    #[serde(default = "yes")]
    pub atf: bool,
    /// the numbers of [`TUNING`] (channel choice, steering back-off, airtime queue limits), by field name
    #[serde(flatten)]
    pub tuning: std::collections::BTreeMap<String, i64>,
    // limits for misbehaving stations in the image's hostapd (docs 12.6d, 12.18); a radio restart applies them
    /// unacknowledged authentication responses within authfail_window before hostapd ignores the station (0 = off)
    #[serde(default = "default_authfail_max")]
    pub authfail_max: u32,
    /// seconds over which authfail_max is counted
    #[serde(default = "default_authfail_window")]
    pub authfail_window: u32,
    /// seconds such a station is ignored the first time (doubles each further time)
    #[serde(default = "default_authfail_hold")]
    pub authfail_hold: u32,
    /// longest such hold, seconds
    #[serde(default = "default_authfail_hold_max")]
    pub authfail_hold_max: u32,
    /// hops between this radio's networks within xbss_window before a station is refused on the new one (0 = off)
    #[serde(default = "default_xbss_max")]
    pub xbss_max: u32,
    /// seconds over which xbss_max is counted
    #[serde(default = "default_xbss_window")]
    pub xbss_window: u32,
    /// seconds a hopping station is refused
    #[serde(default = "default_xbss_hold")]
    pub xbss_hold: u32,
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

/// Defaults of the channel coordination (board.sh `AP_COORD_*`).
pub const DEFAULT_COORD_MIN_SIGNAL: i32 = -90;
pub const DEFAULT_COORD_DELAY: u32 = 120;
pub const DEFAULT_COORD_INTERVAL: u32 = 3600;
pub const DEFAULT_COORD_QUIET: &str = "1-5";
pub const DEFAULT_COORD_SCAN_SECS: u32 = 25;
fn default_coord_min_signal() -> i32 {
    DEFAULT_COORD_MIN_SIGNAL
}
fn default_coord_delay() -> u32 {
    DEFAULT_COORD_DELAY
}
fn default_coord_interval() -> u32 {
    DEFAULT_COORD_INTERVAL
}
fn default_coord_quiet() -> String {
    DEFAULT_COORD_QUIET.into()
}
fn default_coord_scan_secs() -> u32 {
    DEFAULT_COORD_SCAN_SECS
}
/// Steering and station-limit settings (board.sh `AP_STEER_*`, `AP_AUTHFAIL_*`, `AP_XBSS_*`).
pub const DEFAULT_STEER_SIGNAL: i32 = -65;
pub const DEFAULT_CHAN_TIME: &str = "03:30";
fn default_chan_time() -> String {
    DEFAULT_CHAN_TIME.into()
}
/// Channel choice by measurement (`ap-chan`, docs 12.19) and the steering back-off: (field, ap.env key, default, min,
/// max, what the error says). Every one is live (re-read by ap-chan / ap-steer, no radio restart).
pub const TUNING: &[(&str, &str, i64, i64, i64, &str)] = &[
    (
        "chan_hyst",
        "AP_CHAN_HYST",
        20,
        0,
        90,
        "channel move: at least 0 to 90 % better",
    ),
    (
        "chan_min_gain",
        "AP_CHAN_MIN_GAIN",
        10,
        0,
        100,
        "channel move: at least 0 to 100 points better",
    ),
    (
        "chan_confirm",
        "AP_CHAN_CONFIRM",
        3,
        1,
        10,
        "channel move: 1 to 10 agreeing samples",
    ),
    (
        "chan_confirm_gap",
        "AP_CHAN_CONFIRM_GAP",
        300,
        0,
        3600,
        "channel samples: 0 to 3600 seconds apart",
    ),
    (
        "chan_rounds",
        "AP_CHAN_ROUNDS",
        4,
        1,
        20,
        "channel measurement: 1 to 20 scan rounds",
    ),
    (
        "chan_dwell",
        "AP_CHAN_DWELL",
        105,
        20,
        500,
        "channel measurement: 20 to 500 ms per channel",
    ),
    (
        "chan_sample_secs",
        "AP_CHAN_SAMPLE_SECS",
        30,
        0,
        600,
        "channel sample: 0 to 600 seconds",
    ),
    (
        "chan_bss_cost",
        "AP_CHAN_BSS_COST",
        2,
        0,
        20,
        "points per neighbouring access point: 0 to 20",
    ),
    (
        "chan_min_signal",
        "AP_CHAN_MIN_SIGNAL",
        -90,
        -100,
        -30,
        "neighbours counted from -100 to -30 dBm",
    ),
    (
        "chan_csa_count",
        "AP_CHAN_CSA_COUNT",
        10,
        1,
        50,
        "channel switch announced 1 to 50 beacons ahead",
    ),
    (
        "chan_wait",
        "AP_CHAN_WAIT",
        90,
        0,
        600,
        "wait for the units that pick first: 0 to 600 seconds",
    ),
    (
        "chan_jitter",
        "AP_CHAN_JITTER",
        30,
        0,
        300,
        "random extra wait: 0 to 300 seconds",
    ),
    (
        "chan_sync_wait",
        "AP_CHAN_SYNC_WAIT",
        90,
        0,
        600,
        "wait for a started radio before recording its running channel: 0 to 600 seconds",
    ),
    (
        "chan_stagger",
        "AP_CHAN_STAGGER",
        1800,
        0,
        21600,
        "nightly re-check offset per unit: 0 to 21600 seconds",
    ),
    (
        "chan_history",
        "AP_CHAN_HISTORY",
        200,
        10,
        5000,
        "channel history: 10 to 5000 entries",
    ),
    (
        "chan_forget",
        "AP_CHAN_FORGET",
        604800,
        3600,
        31536000,
        "forget a unit not heard for 3600 to 31536000 seconds",
    ),
    (
        "steer_retry_max",
        "AP_STEER_RETRY_MAX",
        604800,
        0,
        2592000,
        "steering: longest hold 0 to 2592000 seconds",
    ),
    // airtime queue limit per band (docs 12.20, `ap airtime`): microseconds of airtime one station may have queued in
    // the radio's hardware, LOW while the radio is busy and HIGH otherwise. 5 GHz keeps mac80211's 5000 / 12000; 2.4 GHz
    // uses 2500 / 5000: its lower rates and busier channels turn the same budget into more queueing delay, and the
    // measured sweep (docs 12.20) gave lower loaded delay at the same throughput
    (
        "aql_low24",
        "AP_AQL_LOW24",
        2500,
        100,
        50000,
        "2.4 GHz airtime queue limit (busy radio): 100 to 50000 microseconds",
    ),
    (
        "aql_high24",
        "AP_AQL_HIGH24",
        5000,
        100,
        50000,
        "2.4 GHz airtime queue limit: 100 to 50000 microseconds",
    ),
    (
        "aql_low5",
        "AP_AQL_LOW5",
        5000,
        100,
        50000,
        "5 GHz airtime queue limit (busy radio): 100 to 50000 microseconds",
    ),
    (
        "aql_high5",
        "AP_AQL_HIGH5",
        12000,
        100,
        50000,
        "5 GHz airtime queue limit: 100 to 50000 microseconds",
    ),
];
/// A [`TUNING`] number from the file: out of range or not a number = its default.
fn tuning_number(f: &EnvFile, key: &str) -> i64 {
    match TUNING.iter().find(|e| e.1 == key) {
        Some(e) => f
            .get(key)
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|n| (e.3..=e.4).contains(n))
            .unwrap_or(e.2),
        None => 0,
    }
}
/// `AP_CHAN_TIME`: "" or "HH:MM" (00:00-23:59).
pub fn valid_hhmm(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    match v.split_once(':') {
        Some((h, m)) => {
            h.len() == 2
                && m.len() == 2
                && h.parse::<u32>().is_ok_and(|n| n < 24)
                && m.parse::<u32>().is_ok_and(|n| n < 60)
        }
        None => false,
    }
}
fn on_off(v: Option<&str>) -> bool {
    !matches!(v.unwrap_or("1"), "0" | "no" | "off" | "false")
}
pub const STEER_SIGNAL_RANGE: std::ops::RangeInclusive<i32> = -90..=-40;
fn default_steer_signal() -> i32 {
    DEFAULT_STEER_SIGNAL
}
/// (field, ap.env key, default, min, max, what the error says)
pub const STATION_NUMBERS: &[(&str, &str, u32, u32, u32, &str)] = &[
    (
        "steer_after",
        "AP_STEER_AFTER",
        600,
        30,
        86400,
        "steering: seconds weak before a move: 30 to 86400",
    ),
    (
        "steer_idle",
        "AP_STEER_IDLE",
        64,
        0,
        1000000,
        "steering: idle below (kbit/s): 0 to 1000000",
    ),
    (
        "steer_block",
        "AP_STEER_BLOCK",
        30,
        0,
        3600,
        "steering: refuse a moved station for 0 to 3600 seconds",
    ),
    (
        "steer_retry",
        "AP_STEER_RETRY",
        21600,
        0,
        604800,
        "steering: leave a station alone for 0 to 604800 seconds",
    ),
    (
        "steer_max",
        "AP_STEER_MAX",
        2,
        0,
        64,
        "steering: stations moved per round: 0 to 64",
    ),
    (
        "steer_interval",
        "AP_STEER_INTERVAL",
        30,
        10,
        3600,
        "steering: round every 10 to 3600 seconds",
    ),
    (
        "authfail_max",
        "AP_AUTHFAIL_MAX",
        10,
        0,
        86400,
        "unacknowledged authentications before a hold: 0 (off) to 86400",
    ),
    (
        "authfail_window",
        "AP_AUTHFAIL_WINDOW",
        60,
        0,
        86400,
        "authentication count window: 0 to 86400 seconds",
    ),
    (
        "authfail_hold",
        "AP_AUTHFAIL_HOLD",
        60,
        0,
        86400,
        "first authentication hold: 0 to 86400 seconds",
    ),
    (
        "authfail_hold_max",
        "AP_AUTHFAIL_HOLD_MAX",
        3600,
        0,
        86400,
        "longest authentication hold: 0 to 86400 seconds",
    ),
    (
        "xbss_max",
        "AP_XBSS_MAX",
        6,
        0,
        86400,
        "network hops before a hold: 0 (off) to 86400",
    ),
    (
        "xbss_window",
        "AP_XBSS_WINDOW",
        60,
        0,
        86400,
        "network hop window: 0 to 86400 seconds",
    ),
    (
        "xbss_hold",
        "AP_XBSS_HOLD",
        30,
        0,
        86400,
        "network hop hold: 0 to 86400 seconds",
    ),
];
fn station_default(field: &str) -> u32 {
    STATION_NUMBERS
        .iter()
        .find(|e| e.0 == field)
        .map(|e| e.2)
        .unwrap_or(0)
}
fn default_steer_after() -> u32 {
    station_default("steer_after")
}
fn default_steer_idle() -> u32 {
    station_default("steer_idle")
}
fn default_steer_block() -> u32 {
    station_default("steer_block")
}
fn default_steer_retry() -> u32 {
    station_default("steer_retry")
}
fn default_steer_max() -> u32 {
    station_default("steer_max")
}
fn default_steer_interval() -> u32 {
    station_default("steer_interval")
}
fn default_authfail_max() -> u32 {
    station_default("authfail_max")
}
fn default_authfail_window() -> u32 {
    station_default("authfail_window")
}
fn default_authfail_hold() -> u32 {
    station_default("authfail_hold")
}
fn default_authfail_hold_max() -> u32 {
    station_default("authfail_hold_max")
}
fn default_xbss_max() -> u32 {
    station_default("xbss_max")
}
fn default_xbss_window() -> u32 {
    station_default("xbss_window")
}
fn default_xbss_hold() -> u32 {
    station_default("xbss_hold")
}
/// `AP_STEER` as the typed view shows it: auto | on | off.
pub fn steer_mode(v: &str) -> &'static str {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "on" | "yes" | "true" => "on",
        "0" | "off" | "no" | "false" => "off",
        _ => "auto",
    }
}
/// A number setting of [`STATION_NUMBERS`] from the file: out of range or not a number = its default.
fn station_number(f: &EnvFile, key: &str) -> u32 {
    match STATION_NUMBERS.iter().find(|e| e.1 == key) {
        Some(e) => f
            .get(key)
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|n| (e.3..=e.4).contains(n))
            .unwrap_or(e.2),
        None => 0,
    }
}
/// `AP_COORD_QUIET`: "" or "H-H" with hours 0-23.
pub fn valid_quiet(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    match v.split_once('-') {
        Some((a, b)) => [a, b]
            .iter()
            .all(|h| !h.is_empty() && h.len() <= 2 && h.parse::<u32>().is_ok_and(|n| n < 24)),
        None => false,
    }
}
fn auto() -> String {
    "auto".into()
}
fn w20() -> u32 {
    20
}
/// ACS on 2.4 GHz picks among the three non-overlapping channels unless told otherwise (board.sh `AP_CHANLIST24`).
pub const DEFAULT_CHANLIST24: [u32; 3] = [1, 6, 11];
pub const DEFAULT_ACS_SCANS: u32 = 5;
fn default_chanlist24() -> Vec<u32> {
    DEFAULT_CHANLIST24.to_vec()
}
fn default_acs_scans() -> u32 {
    DEFAULT_ACS_SCANS
}
/// A channel list value (`AP_CHANLIST24` / `AP_CHANLIST5`): the valid channels of the band, in order, no duplicates.
pub fn chan_list(v: &str, band5: bool) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for c in v.split_whitespace().filter_map(|c| c.parse::<u32>().ok()) {
        let ok = if band5 {
            valid5(c)
        } else {
            (1..=13).contains(&c)
        };
        if ok && !out.contains(&c) {
            out.push(c);
        }
    }
    out
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
        width24: match f.get("AP_HT24") {
            Some("40") => 40,
            _ => 20,
        },
        dfs: matches!(f.get("AP_DFS").unwrap_or("0"), "1" | "yes" | "on"),
        unii4: matches!(f.get("AP_UNII4").unwrap_or("0"), "1" | "yes" | "on"),
        chanlist24: match f.get("AP_CHANLIST24") {
            None => default_chanlist24(),
            Some(v) => chan_list(v, false),
        },
        chanlist5: chan_list(f.get("AP_CHANLIST5").unwrap_or(""), true),
        acs_scans: f
            .get("AP_ACS_SCANS")
            .and_then(|v| v.parse().ok())
            .filter(|n| (1..=20).contains(n))
            .unwrap_or(DEFAULT_ACS_SCANS),
        coord24: !matches!(f.get("AP_COORD24").unwrap_or("1"), "0" | "no" | "off"),
        coord5: !matches!(f.get("AP_COORD5").unwrap_or("1"), "0" | "no" | "off"),
        coord_peers: mac_list(f.get("AP_COORD_PEERS").unwrap_or("")),
        coord_min_signal: f
            .get("AP_COORD_MIN_SIGNAL")
            .and_then(|v| v.parse().ok())
            .filter(|n| (-100..=-30).contains(n))
            .unwrap_or(DEFAULT_COORD_MIN_SIGNAL),
        coord_delay: f
            .get("AP_COORD_DELAY")
            .and_then(|v| v.parse().ok())
            .filter(|n| *n <= 3600)
            .unwrap_or(DEFAULT_COORD_DELAY),
        coord_interval: f
            .get("AP_COORD_INTERVAL")
            .and_then(|v| v.parse().ok())
            .filter(|n| *n == 0 || (60..=86400).contains(n))
            .unwrap_or(DEFAULT_COORD_INTERVAL),
        coord_quiet: match f.get("AP_COORD_QUIET") {
            None => DEFAULT_COORD_QUIET.to_string(),
            Some(v) if valid_quiet(v) => v.to_string(),
            Some(_) => DEFAULT_COORD_QUIET.to_string(),
        },
        coord_scan_secs: f
            .get("AP_COORD_SCAN_SECS")
            .and_then(|v| v.parse().ok())
            .filter(|n| (5..=120).contains(n))
            .unwrap_or(DEFAULT_COORD_SCAN_SECS),
        steer: steer_mode(f.get("AP_STEER").unwrap_or("auto")).to_string(),
        steer_signal: f
            .get("AP_STEER_SIGNAL")
            .and_then(|v| v.trim().parse().ok())
            .filter(|n| STEER_SIGNAL_RANGE.contains(n))
            .unwrap_or(DEFAULT_STEER_SIGNAL),
        steer_after: station_number(f, "AP_STEER_AFTER"),
        steer_idle: station_number(f, "AP_STEER_IDLE"),
        steer_block: station_number(f, "AP_STEER_BLOCK"),
        steer_retry: station_number(f, "AP_STEER_RETRY"),
        steer_max: station_number(f, "AP_STEER_MAX"),
        steer_interval: station_number(f, "AP_STEER_INTERVAL"),
        steer_exempt: mac_list(f.get("AP_STEER_EXEMPT").unwrap_or("")),
        chan_smart24: on_off(f.get("AP_CHAN_SMART24")),
        chan_smart5: on_off(f.get("AP_CHAN_SMART5")),
        chan_recheck24: on_off(f.get("AP_CHAN_RECHECK24")),
        chan_recheck5: on_off(f.get("AP_CHAN_RECHECK5")),
        chan_time: match f.get("AP_CHAN_TIME") {
            None => DEFAULT_CHAN_TIME.to_string(),
            Some(v) if valid_hhmm(v.trim()) => v.trim().to_string(),
            Some(_) => DEFAULT_CHAN_TIME.to_string(),
        },
        chan_csa: match f.get("AP_CHAN_CSA").unwrap_or("auto") {
            "off" | "0" | "no" => "off".into(),
            _ => "auto".into(),
        },
        aql: on_off(f.get("AP_AQL")),
        atf: on_off(f.get("AP_ATF")),
        tuning: TUNING
            .iter()
            .map(|e| (e.0.to_string(), tuning_number(f, e.1)))
            .collect(),
        authfail_max: station_number(f, "AP_AUTHFAIL_MAX"),
        authfail_window: station_number(f, "AP_AUTHFAIL_WINDOW"),
        authfail_hold: station_number(f, "AP_AUTHFAIL_HOLD"),
        authfail_hold_max: station_number(f, "AP_AUTHFAIL_HOLD_MAX"),
        xbss_max: station_number(f, "AP_XBSS_MAX"),
        xbss_window: station_number(f, "AP_XBSS_WINDOW"),
        xbss_hold: station_number(f, "AP_XBSS_HOLD"),
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
    /// 2.4 GHz width: 20 | 40
    #[serde(default)]
    pub width24: Option<u32>,
    /// ACS may pick 5 GHz DFS channels
    #[serde(default)]
    pub dfs: Option<bool>,
    /// ACS may pick the 5.9 GHz channels 169-177
    #[serde(default)]
    pub unii4: Option<bool>,
    /// channels ACS may pick (empty list = all the country allows)
    #[serde(default)]
    pub chanlist24: Option<Vec<u32>>,
    #[serde(default)]
    pub chanlist5: Option<Vec<u32>>,
    /// ACS survey rounds (1-20)
    #[serde(default)]
    pub acs_scans: Option<u32>,
    /// channel coordination between this network's access points (docs 12.17)
    #[serde(default)]
    pub coord24: Option<bool>,
    #[serde(default)]
    pub coord5: Option<bool>,
    #[serde(default)]
    pub coord_peers: Option<Vec<String>>,
    #[serde(default)]
    pub coord_min_signal: Option<i32>,
    #[serde(default)]
    pub coord_delay: Option<u32>,
    #[serde(default)]
    pub coord_interval: Option<u32>,
    #[serde(default)]
    pub coord_quiet: Option<String>,
    #[serde(default)]
    pub coord_scan_secs: Option<u32>,
    /// steering (docs 12.18): "auto", "on" or "off"
    #[serde(default)]
    pub steer: Option<String>,
    #[serde(default)]
    pub steer_signal: Option<i32>,
    #[serde(default)]
    pub steer_after: Option<u32>,
    #[serde(default)]
    pub steer_idle: Option<u32>,
    #[serde(default)]
    pub steer_block: Option<u32>,
    #[serde(default)]
    pub steer_retry: Option<u32>,
    #[serde(default)]
    pub steer_max: Option<u32>,
    #[serde(default)]
    pub steer_interval: Option<u32>,
    #[serde(default)]
    pub steer_exempt: Option<Vec<String>>,
    /// channel choice by measurement (docs 12.19)
    #[serde(default)]
    pub chan_smart24: Option<bool>,
    #[serde(default)]
    pub chan_smart5: Option<bool>,
    #[serde(default)]
    pub chan_recheck24: Option<bool>,
    #[serde(default)]
    pub chan_recheck5: Option<bool>,
    #[serde(default)]
    pub chan_time: Option<String>,
    #[serde(default)]
    pub chan_csa: Option<String>,
    /// airtime queue limit / airtime fairness (docs 12.20)
    #[serde(default)]
    pub aql: Option<bool>,
    #[serde(default)]
    pub atf: Option<bool>,
    /// [`TUNING`] numbers by field name (any other key here is not a setting and is ignored, as before)
    #[serde(flatten)]
    pub tuning: std::collections::BTreeMap<String, Value>,
    /// station limits of the image's hostapd (docs 12.18)
    #[serde(default)]
    pub authfail_max: Option<u32>,
    #[serde(default)]
    pub authfail_window: Option<u32>,
    #[serde(default)]
    pub authfail_hold: Option<u32>,
    #[serde(default)]
    pub authfail_hold_max: Option<u32>,
    #[serde(default)]
    pub xbss_max: Option<u32>,
    #[serde(default)]
    pub xbss_window: Option<u32>,
    #[serde(default)]
    pub xbss_hold: Option<u32>,
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
    if let Some(w) = input.width24 {
        if !matches!(w, 20 | 40) {
            return Err(invalid("2.4 GHz channel width is 20 or 40 MHz"));
        }
        set.push(("AP_HT24".into(), w.to_string()));
    }
    if let Some(d) = input.dfs {
        set.push(("AP_DFS".into(), if d { "1" } else { "0" }.into()));
    }
    if let Some(d) = input.unii4 {
        set.push(("AP_UNII4".into(), if d { "1" } else { "0" }.into()));
    }
    for (k, band5, list) in [
        ("AP_CHANLIST24", false, &input.chanlist24),
        ("AP_CHANLIST5", true, &input.chanlist5),
    ] {
        if let Some(list) = list {
            let mut out: Vec<String> = Vec::new();
            for &c in list {
                let ok = if band5 {
                    valid5(c)
                } else {
                    (1..=13).contains(&c)
                };
                if !ok {
                    return Err(invalid(format!(
                        "{c} is not a {} channel (automatic channel list)",
                        if band5 { "5 GHz" } else { "2.4 GHz" }
                    )));
                }
                if !out.contains(&c.to_string()) {
                    out.push(c.to_string());
                }
            }
            set.push((k.into(), out.join(" ")));
        }
    }
    if let Some(n) = input.acs_scans {
        if !(1..=20).contains(&n) {
            return Err(invalid("automatic channel survey rounds: 1 to 20"));
        }
        set.push(("AP_ACS_SCANS".into(), n.to_string()));
    }
    for (k, v) in [("AP_COORD24", input.coord24), ("AP_COORD5", input.coord5)] {
        if let Some(d) = v {
            set.push((k.into(), if d { "1" } else { "0" }.into()));
        }
    }
    if let Some(list) = &input.coord_peers {
        let mut out: Vec<String> = Vec::new();
        for m in list {
            let m = m.trim().to_ascii_lowercase();
            if !valid_mac(&m) {
                return Err(invalid(format!(
                    "{m:?} is not a MAC address (channel coordination peers)"
                )));
            }
            if !out.contains(&m) {
                out.push(m);
            }
        }
        if out.len() > 16 {
            return Err(invalid("at most 16 channel coordination peers"));
        }
        set.push(("AP_COORD_PEERS".into(), out.join(" ")));
    }
    if let Some(n) = input.coord_min_signal {
        if !(-100..=-30).contains(&n) {
            return Err(invalid(
                "weakest access point to coordinate with: -100 to -30 dBm",
            ));
        }
        set.push(("AP_COORD_MIN_SIGNAL".into(), n.to_string()));
    }
    if let Some(n) = input.coord_delay {
        if n > 3600 {
            return Err(invalid(
                "first channel re-check: 0 to 3600 seconds after start",
            ));
        }
        set.push(("AP_COORD_DELAY".into(), n.to_string()));
    }
    if let Some(n) = input.coord_interval {
        if n != 0 && !(60..=86400).contains(&n) {
            return Err(invalid(
                "channel re-check interval: 0 (never) or 60 to 86400 seconds",
            ));
        }
        set.push(("AP_COORD_INTERVAL".into(), n.to_string()));
    }
    if let Some(q) = &input.coord_quiet {
        let q = q.trim();
        if !valid_quiet(q) {
            return Err(invalid(
                "quiet hours for channel moves: empty (any time) or hours like 1-5",
            ));
        }
        set.push(("AP_COORD_QUIET".into(), q.to_string()));
    }
    if let Some(n) = input.coord_scan_secs {
        if !(5..=120).contains(&n) {
            return Err(invalid("channel scan time: 5 to 120 seconds"));
        }
        set.push(("AP_COORD_SCAN_SECS".into(), n.to_string()));
    }
    if let Some(m) = &input.steer {
        let v = match m.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => "auto",
            "on" | "1" | "yes" | "true" => "1",
            "off" | "0" | "no" | "false" => "0",
            _ => return Err(invalid("steering: auto, on or off")),
        };
        set.push(("AP_STEER".into(), v.into()));
    }
    if let Some(n) = input.steer_signal {
        if !STEER_SIGNAL_RANGE.contains(&n) {
            return Err(invalid("weak signal for steering: -90 to -40 dBm"));
        }
        set.push(("AP_STEER_SIGNAL".into(), n.to_string()));
    }
    for (field, v) in [
        ("steer_after", input.steer_after),
        ("steer_idle", input.steer_idle),
        ("steer_block", input.steer_block),
        ("steer_retry", input.steer_retry),
        ("steer_max", input.steer_max),
        ("steer_interval", input.steer_interval),
        ("authfail_max", input.authfail_max),
        ("authfail_window", input.authfail_window),
        ("authfail_hold", input.authfail_hold),
        ("authfail_hold_max", input.authfail_hold_max),
        ("xbss_max", input.xbss_max),
        ("xbss_window", input.xbss_window),
        ("xbss_hold", input.xbss_hold),
    ] {
        if let (Some(n), Some(e)) = (v, STATION_NUMBERS.iter().find(|e| e.0 == field)) {
            if !(e.3..=e.4).contains(&n) {
                return Err(invalid(e.5));
            }
            set.push((e.1.into(), n.to_string()));
        }
    }
    if let Some(list) = &input.steer_exempt {
        let mut out: Vec<String> = Vec::new();
        for m in list {
            let m = m.trim().to_ascii_lowercase();
            if !valid_mac(&m) {
                return Err(invalid(format!(
                    "{m:?} is not a MAC address (stations never moved)"
                )));
            }
            if !out.contains(&m) {
                out.push(m);
            }
        }
        if out.len() > 256 {
            return Err(invalid("at most 256 stations exempt from steering"));
        }
        set.push(("AP_STEER_EXEMPT".into(), out.join(" ")));
    }
    for (k, v) in [
        ("AP_CHAN_SMART24", input.chan_smart24),
        ("AP_CHAN_SMART5", input.chan_smart5),
        ("AP_CHAN_RECHECK24", input.chan_recheck24),
        ("AP_CHAN_RECHECK5", input.chan_recheck5),
        ("AP_AQL", input.aql),
        ("AP_ATF", input.atf),
    ] {
        if let Some(b) = v {
            set.push((k.into(), if b { "1" } else { "0" }.into()));
        }
    }
    if let Some(t) = &input.chan_time {
        let t = t.trim();
        if !valid_hhmm(t) {
            return Err(invalid(
                "nightly channel re-check: a time like 03:30, or empty for none",
            ));
        }
        set.push(("AP_CHAN_TIME".into(), t.to_string()));
    }
    if let Some(c) = &input.chan_csa {
        let v = match c.trim().to_ascii_lowercase().as_str() {
            "auto" | "" | "on" => "auto",
            "off" => "off",
            _ => return Err(invalid("channel switch announcement: auto or off")),
        };
        set.push(("AP_CHAN_CSA".into(), v.into()));
    }
    for e in TUNING {
        if let Some(v) = input.tuning.get(e.0) {
            let n = v
                .as_i64()
                .filter(|n| (e.3..=e.4).contains(n))
                .ok_or_else(|| invalid(e.5))?;
            set.push((e.1.into(), n.to_string()));
        }
    }
    // the steering hold doubles up to its maximum: a maximum below the first hold is a mistake
    {
        let num = |k: &str| {
            set.iter()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.parse::<i64>().ok())
        };
        let retry =
            num("AP_STEER_RETRY").unwrap_or_else(|| station_number(f, "AP_STEER_RETRY") as i64);
        let max =
            num("AP_STEER_RETRY_MAX").unwrap_or_else(|| tuning_number(f, "AP_STEER_RETRY_MAX"));
        if max < retry {
            return Err(invalid(
                "steering: the longest hold must be at least the first one (leave a device alone for)",
            ));
        }
    }
    // airtime queue limit: the busy-radio limit can't be above the normal one
    for (lo, hi, band) in [
        ("AP_AQL_LOW24", "AP_AQL_HIGH24", "2.4 GHz"),
        ("AP_AQL_LOW5", "AP_AQL_HIGH5", "5 GHz"),
    ] {
        let num = |k: &str| {
            set.iter()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.parse::<i64>().ok())
                .unwrap_or_else(|| tuning_number(f, k))
        };
        if num(lo) > num(hi) {
            return Err(invalid(format!(
                "{band} airtime queue limit: the busy-radio limit must not be above the normal one"
            )));
        }
    }
    // the authentication hold doubles up to its maximum: a maximum below the first hold is a mistake
    {
        let num = |k: &str| {
            set.iter()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.parse::<u32>().ok())
                .unwrap_or_else(|| station_number(f, k))
        };
        if num("AP_AUTHFAIL_HOLD_MAX") < num("AP_AUTHFAIL_HOLD") {
            return Err(invalid(
                "longest authentication hold must be at least the first hold",
            ));
        }
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
        if is_managed(k) || (replace_nets && is_net_var(k)) {
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
        "AP_HT24",
        "AP_HT5",
        "AP_DFS",
        "AP_UNII4",
        "AP_CHANLIST24",
        "AP_CHANLIST5",
        "AP_ACS_SCANS",
        "AP_COORD24",
        "AP_COORD5",
        "AP_COORD_PEERS",
        "AP_COORD_MIN_SIGNAL",
        "AP_COORD_DELAY",
        "AP_COORD_INTERVAL",
        "AP_COORD_QUIET",
        "AP_COORD_SCAN_SECS",
        "AP_STEER",
        "AP_STEER_SIGNAL",
        "AP_STEER_AFTER",
        "AP_STEER_IDLE",
        "AP_STEER_BLOCK",
        "AP_STEER_RETRY",
        "AP_STEER_MAX",
        "AP_STEER_INTERVAL",
        "AP_STEER_EXEMPT",
        "AP_AUTHFAIL_MAX",
        "AP_AUTHFAIL_WINDOW",
        "AP_AUTHFAIL_HOLD",
        "AP_AUTHFAIL_HOLD_MAX",
        "AP_XBSS_MAX",
        "AP_XBSS_WINDOW",
        "AP_XBSS_HOLD",
        "AP_HE",
        "AP_TXPOWER24",
        "AP_TXPOWER5",
        "AP_NAMES",
    ]
    .into_iter()
    .chain(chan_keys())
    {
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
        "channels": channel_status(p),
        "channel_history": channel_history(50),
        "airtime": airtime_status(p),
    }))
}

/// Does the Wi-Fi driver take the airtime settings (docs 12.20)? mac80211 applies the airtime queue limit only for
/// drivers that advertise it (`iw phy` lists "[ AQL ]"); `supported` is null while no radio is registered.
fn airtime_status(p: &Paths) -> Value {
    let phys: Vec<String> = std::fs::read_dir(&p.sysfs)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    if phys.is_empty() {
        return json!({ "supported": Value::Null });
    }
    let supported = phys.iter().all(|phy| {
        Command::new("iw")
            .args(["phy", phy, "info"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("[ AQL ]"))
            .unwrap_or(false)
    });
    json!({ "supported": supported })
}

/// The channel state directory of ap-chan (history, the units heard): `PATRONUS_AP_CHAN_DB`.
fn chan_db() -> PathBuf {
    PathBuf::from(
        std::env::var("PATRONUS_AP_CHAN_DB").unwrap_or_else(|_| "/var/lib/patronus/ap-chan".into()),
    )
}

/// Why each radio is on its channel (ap-chan's last choice, per band): chosen and current channel, the scores of every
/// candidate, whether the driver can move by channel switch announcement. Bands ap-chan has not measured are absent.
pub fn channel_status(p: &Paths) -> Value {
    let mut out = serde_json::Map::new();
    for band in ["5", "24"] {
        if let Some(v) = std::fs::read_to_string(p.run.join(format!("chan-status-{band}")))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(t.trim()).ok())
        {
            out.insert(band.into(), with_primary(v));
        }
    }
    Value::Object(out)
}

/// hostapd's ACS picks the primary channel itself inside the 40/80 MHz block ap-chan pins, so the measured `chosen`
/// primary and the running `current` one can differ (both inside `block`). Adds `primary` (what runs: `current`, else
/// `chosen` before the radio's first sync) and `primary_differs` for API consumers and the Wi-Fi page.
fn with_primary(mut v: Value) -> Value {
    let num = |k: &str| v.get(k).and_then(Value::as_u64);
    let (chosen, current) = (num("chosen"), num("current"));
    let primary = current.or(chosen);
    let differs = matches!((chosen, current), (Some(a), Some(b)) if a != b);
    if let Some(o) = v.as_object_mut() {
        o.insert("primary".into(), primary.map_or(Value::Null, Value::from));
        o.insert("primary_differs".into(), Value::Bool(differs));
        o.entry("block").or_insert_with(|| Value::Array(vec![]));
    }
    v
}

/// The last `n` entries of ap-chan's history (newest last): every start, nightly sample, stay and move with its reason.
pub fn channel_history(n: usize) -> Vec<Value> {
    parse_history(
        &std::fs::read_to_string(chan_db().join("history")).unwrap_or_default(),
        n,
    )
}
pub fn parse_history(text: &str, n: usize) -> Vec<Value> {
    let v: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(Value::is_object)
        .collect();
    let skip = v.len().saturating_sub(n);
    v.into_iter().skip(skip).collect()
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
        let (width, centre) = live_width(&st);
        out.push(json!({
            "band": band,
            "state": if st.is_empty() { "not running".to_string() } else { g("state") },
            "channel": g("channel"),
            "freq": g("freq"),
            "width_mhz": width,
            "centre_channel": centre,
            "wifi6": g("ieee80211ax") == "1",
            "txpower_dbm": txpower,
            "bss": bss,
        }));
    }
    out
}

/// Width (MHz) and centre channel a radio is really using, from `hostapd_cli status`: 80 MHz when the VHT/HE
/// operating width says so, 40 with a secondary channel, else 20. With channel "auto" this is what ACS picked.
pub fn live_width(st: &[(String, String)]) -> (Option<u32>, Option<u32>) {
    let g = |k: &str| st.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let ch: Option<u32> = g("channel").and_then(|c| c.parse().ok());
    let Some(ch) = ch.filter(|&c| c > 0) else {
        return (None, None);
    };
    let seg0: Option<u32> = g("vht_oper_centr_freq_seg0_idx")
        .or_else(|| g("he_oper_centr_freq_seg0_idx"))
        .and_then(|c| c.parse().ok())
        .filter(|&c| c > 0);
    let chw = g("vht_oper_chwidth")
        .or_else(|| g("he_oper_chwidth"))
        .and_then(|c| c.parse::<u32>().ok());
    let sec: i32 = g("secondary_channel")
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    match (chw, seg0) {
        (Some(1), Some(c)) => (Some(80), Some(c)),
        (Some(2), Some(c)) => (Some(160), Some(c)),
        _ if sec != 0 => (Some(40), Some((ch as i32 + 2 * sec) as u32)),
        _ => (Some(20), Some(ch)),
    }
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
    if text == old_text || (!old_text.is_empty() && same_settings(&old, new)) {
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
        for a in ["txpower", "acl", "airtime"] {
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

/// Declarative document of this unit's access-point Wi-Fi (`patronus ap-wifi export`): the typed settings in the
/// shape `apply`/`plan` take ([`WifiInput`]), passphrases left out (an import keeps the stored passphrase of every
/// network it names by `id`).
pub const DOC_API: &str = "patronus.ap-wifi/v1";

pub fn export_doc(f: &EnvFile) -> Value {
    let c = view(f);
    let mut v = serde_json::to_value(&c).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("apiVersion".into(), json!(DOC_API));
        // per-network block lists and the global one are edited live (Block/Unblock), not through this document
        o.remove("blocked");
        if let Some(nets) = o.get_mut("networks").and_then(Value::as_array_mut) {
            for n in nets {
                if let Some(n) = n.as_object_mut() {
                    n.remove("has_key");
                    n.remove("blocked");
                }
            }
        }
    }
    v
}

/// Parse a declarative document (YAML or JSON) into the settings change it describes.
pub fn parse_doc(v: &Value) -> Result<WifiInput> {
    match v.get("apiVersion").and_then(Value::as_str) {
        Some(DOC_API) | None => {}
        Some(other) => return Err(invalid(format!("apiVersion {other:?}: expected {DOC_API}"))),
    }
    serde_json::from_value(v.clone()).map_err(|e| invalid(format!("document: {e}")))
}

/// What applying `input` would change, without writing anything: every changed setting (passphrases shown as
/// "(changed)"), and whether the radios restart.
pub fn plan(f: &EnvFile, input: &WifiInput) -> Result<Value> {
    let new = update(f, input)?;
    let (a, b) = (view(f), view(&new));
    let (ja, jb) = (
        serde_json::to_value(&a).unwrap_or(Value::Null),
        serde_json::to_value(&b).unwrap_or(Value::Null),
    );
    let mut changes = Vec::new();
    if let (Some(oa), Some(ob)) = (ja.as_object(), jb.as_object()) {
        for (k, vb) in ob {
            if k == "networks" {
                continue;
            }
            let va = oa.get(k).cloned().unwrap_or(Value::Null);
            if &va != vb {
                changes.push(json!({ "setting": k, "from": va, "to": vb }));
            }
        }
    }
    let net = |c: &WifiConfig, id: &str| {
        c.networks
            .iter()
            .find(|n| n.id == id)
            .map(|n| serde_json::to_value(n).unwrap_or(Value::Null))
    };
    let mut ids: Vec<String> = a
        .networks
        .iter()
        .chain(b.networks.iter())
        .map(|n| n.id.clone())
        .collect();
    ids.dedup();
    let mut seen = std::collections::HashSet::new();
    for id in ids.into_iter().filter(|i| seen.insert(i.clone())) {
        match (net(&a, &id), net(&b, &id)) {
            (Some(_), None) => changes.push(
                json!({ "setting": format!("networks.{id}"), "from": "present", "to": "removed" }),
            ),
            (None, Some(n)) => {
                changes.push(json!({ "setting": format!("networks.{id}"), "from": null, "to": n }))
            }
            (Some(na), Some(nb)) => {
                if let (Some(oa), Some(ob)) = (na.as_object(), nb.as_object()) {
                    for (k, vb) in ob.iter().filter(|(k, _)| k.as_str() != "has_key") {
                        let va = oa.get(k).cloned().unwrap_or(Value::Null);
                        if &va != vb {
                            changes.push(json!({ "setting": format!("networks.{id}.{k}"), "from": va, "to": vb }));
                        }
                    }
                }
                if f.get(&format!("KEY_{id}")) != new.get(&format!("KEY_{id}")) {
                    changes.push(json!({ "setting": format!("networks.{id}.key"), "from": "(set)", "to": "(changed)" }));
                }
            }
            (None, None) => {}
        }
    }
    Ok(json!({
        "changes": changes,
        "restart": !changes.is_empty() && restart_needed(f, &new),
    }))
}

/// [`plan`] against this unit's file.
pub fn plan_unit(p: &Paths, input: &WifiInput) -> Result<Value> {
    if !p.present() {
        return Err(Error::Config(
            "Invalid: this unit has no access-point Wi-Fi backend".into(),
        ));
    }
    plan(&read_env(p)?, input)
}

/// [`export_doc`] of this unit's file.
pub fn export_unit(p: &Paths) -> Result<Value> {
    if !p.present() {
        return Err(Error::Config(
            "Invalid: this unit has no access-point Wi-Fi backend".into(),
        ));
    }
    Ok(export_doc(&read_env(p)?))
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
    radio_state(old) != radio_state(new)
}

/// Everything a radio restart depends on, compared by meaning, not by spelling: the typed settings without the live
/// ones (transmit power, client names, block lists), every network's passphrase, the unmanaged non-live variables and
/// the non-assignment lines. A setting written out at its default (`AP_HT24=20`) equals the setting left out.
type RadioState = (
    Value,
    Vec<(String, String)>,
    Vec<(String, String)>,
    Vec<String>,
);
fn radio_state(f: &EnvFile) -> RadioState {
    let c = view(f);
    let mut v = serde_json::to_value(&c).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        // live settings: transmit power, names, block lists, and the channel coordination (ap-coord re-reads ap.env
        // at every check, the channel list is planned at the next radio start anyway)
        for k in [
            "txpower24",
            "txpower5",
            "names",
            "blocked",
            "coord24",
            "coord5",
            "coord_peers",
            "coord_min_signal",
            "coord_delay",
            "coord_interval",
            "coord_quiet",
            "coord_scan_secs",
            "steer",
            "steer_signal",
            "steer_after",
            "steer_idle",
            "steer_block",
            "steer_retry",
            "steer_max",
            "steer_interval",
            "steer_exempt",
            "chan_smart24",
            "chan_smart5",
            "chan_recheck24",
            "chan_recheck5",
            "chan_time",
            "chan_csa",
            "aql",
            "atf",
        ] {
            o.remove(k);
        }
        // channel choice tuning and the steering back-off (ap-chan / ap-steer re-read them)
        for e in TUNING {
            o.remove(e.0);
        }
        if let Some(nets) = o.get_mut("networks").and_then(Value::as_array_mut) {
            for n in nets.iter_mut().filter_map(Value::as_object_mut) {
                n.remove("blocked");
            }
        }
    }
    let ids: Vec<String> = c.networks.iter().map(|n| n.id.clone()).collect();
    let mut keys: Vec<(String, String)> = ids
        .iter()
        .map(|id| {
            (
                id.clone(),
                f.get(&format!("KEY_{id}")).unwrap_or("").to_string(),
            )
        })
        .collect();
    keys.sort();
    let live = |k: &str| {
        LIVE_VARS.contains(&k) || is_chan_key(k) || LIVE_PREFIXES.iter().any(|p| k.starts_with(p))
    };
    let net_var = |k: &str| {
        NET_PREFIXES.iter().any(|p| {
            k.strip_prefix(p)
                .is_some_and(|id| ids.iter().any(|n| n == id))
        })
    };
    let mut rest: Vec<(String, String)> = f
        .vars
        .iter()
        .filter(|(k, _)| !live(k) && !is_managed(k) && !net_var(k))
        .map(|(k, _)| (k.clone(), f.get(k).unwrap_or("").to_string()))
        .collect();
    rest.sort();
    rest.dedup();
    (v, keys, rest, f.other.clone())
}

/// Same settings in meaning (radio state and the live settings): nothing to write or apply.
pub fn same_settings(old: &EnvFile, new: &EnvFile) -> bool {
    // every typed setting, live ones included (transmit power, names, block lists, channel coordination, steering):
    // comparing only some of them once made a change of the others report "nothing changed" and never reach ap.env
    radio_state(old) == radio_state(new) && view(old) == view(new)
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
    fn channel_plan_defaults_to_auto_everywhere() {
        // a file without any channel setting (and an empty one) = ACS on both radios, 1/6/11 on 2.4 GHz, no DFS
        for f in [parse(""), parse("AP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n")] {
            let c = view(&f);
            assert_eq!((c.chan24.as_str(), c.chan5.as_str()), ("auto", "auto"));
            assert_eq!((c.width24, c.width5), (20, 80));
            assert!(!c.dfs);
            assert!(!c.unii4);
            assert_eq!(c.chanlist24, vec![1, 6, 11]);
            assert!(c.chanlist5.is_empty());
            assert_eq!(c.acs_scans, 5);
        }
        // "0" and "" are auto too (what the `ap` script treats as ACS)
        let c = view(&parse("AP_CHAN24=0\nAP_CHAN5=\n"));
        assert_eq!((c.chan24.as_str(), c.chan5.as_str()), ("auto", "auto"));
    }

    #[test]
    fn channel_coordination_defaults_round_trip_validate_and_stay_live() {
        // on by default per band, nothing listed, the documented timings (board.sh)
        let c = view(&parse("AP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n"));
        assert!(c.coord24 && c.coord5);
        assert!(c.coord_peers.is_empty());
        assert_eq!(
            (
                c.coord_min_signal,
                c.coord_delay,
                c.coord_interval,
                c.coord_scan_secs
            ),
            (-90, 120, 3600, 25)
        );
        assert_eq!(c.coord_quiet, "1-5");
        let f = sample();
        let n = update(
            &f,
            &WifiInput {
                coord5: Some(false),
                coord_peers: Some(vec!["AA:BB:CC:DD:EE:FF".into(), "aa:bb:cc:dd:ee:ff".into()]),
                coord_min_signal: Some(-75),
                coord_delay: Some(30),
                coord_interval: Some(0),
                coord_quiet: Some("".into()),
                coord_scan_secs: Some(10),
                ..Default::default()
            },
        )
        .unwrap();
        let back = parse(&render(&n));
        assert_eq!(back.get("AP_COORD5"), Some("0"));
        assert_eq!(back.get("AP_COORD_PEERS"), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(back.get("AP_COORD_MIN_SIGNAL"), Some("-75"));
        assert_eq!(back.get("AP_COORD_QUIET"), Some(""));
        let v = view(&back);
        assert!(!v.coord5 && v.coord24);
        assert_eq!(v.coord_peers, vec!["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(
            (v.coord_delay, v.coord_interval, v.coord_scan_secs),
            (30, 0, 10)
        );
        assert_eq!(v.coord_quiet, "");
        // the declarative document carries them (export -> plan -> apply)
        let d = export_doc(&back);
        assert_eq!(d["coord5"], false);
        assert_eq!(d["coord_peers"], json!(["aa:bb:cc:dd:ee:ff"]));
        assert_eq!(d["coord_quiet"], "");
        // none of them restarts the radios: ap-coord re-reads ap.env
        assert!(!restart_needed(&f, &n));
        for bad in [
            WifiInput {
                coord_peers: Some(vec!["nope".into()]),
                ..Default::default()
            },
            WifiInput {
                coord_min_signal: Some(-10),
                ..Default::default()
            },
            WifiInput {
                coord_min_signal: Some(-120),
                ..Default::default()
            },
            WifiInput {
                coord_delay: Some(4000),
                ..Default::default()
            },
            WifiInput {
                coord_interval: Some(30),
                ..Default::default()
            },
            WifiInput {
                coord_quiet: Some("25-3".into()),
                ..Default::default()
            },
            WifiInput {
                coord_quiet: Some("night".into()),
                ..Default::default()
            },
            WifiInput {
                coord_scan_secs: Some(2),
                ..Default::default()
            },
        ] {
            assert!(update(&f, &bad).is_err(), "{bad:?}");
        }
        assert!(
            valid_quiet("")
                && valid_quiet("1-5")
                && valid_quiet("22-6")
                && !valid_quiet("5")
                && !valid_quiet("1-24")
        );
    }

    #[test]
    fn steering_and_station_limits_default_round_trip_validate() {
        // defaults as board.sh sets them
        let c = view(&parse("AP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n"));
        assert_eq!((c.steer.as_str(), c.steer_signal), ("auto", -65));
        assert_eq!(
            (
                c.steer_after,
                c.steer_idle,
                c.steer_block,
                c.steer_retry,
                c.steer_max,
                c.steer_interval
            ),
            (600, 64, 30, 21600, 2, 30)
        );
        assert!(c.steer_exempt.is_empty());
        assert_eq!(
            (
                c.authfail_max,
                c.authfail_window,
                c.authfail_hold,
                c.authfail_hold_max
            ),
            (10, 60, 60, 3600)
        );
        assert_eq!((c.xbss_max, c.xbss_window, c.xbss_hold), (6, 60, 30));
        // the image's board.sh carries the same defaults (no second, drifting copy)
        let board = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ci/embedded-aarch64/ax1800/overlay/etc/patronus/board.sh");
        if let Ok(t) = std::fs::read_to_string(&board) {
            let b = parse(&t);
            for e in STATION_NUMBERS {
                assert_eq!(
                    b.get(e.1).and_then(|v| v.parse::<u32>().ok()),
                    Some(e.2),
                    "board.sh {}",
                    e.1
                );
            }
            assert_eq!(b.get("AP_STEER_SIGNAL"), Some("-65"));
            assert_eq!(b.get("AP_STEER"), Some("auto"));
        }
        // out-of-range values in the file fall back to the default
        let c = view(&parse(
            "AP_STEER=1\nAP_STEER_SIGNAL=-20\nAP_STEER_AFTER=5\nAP_XBSS_HOLD=x\nAP_STEER_EXEMPT='AA:BB:CC:DD:EE:FF bad'\n",
        ));
        assert_eq!(
            (c.steer.as_str(), c.steer_signal, c.steer_after, c.xbss_hold),
            ("on", -65, 600, 30)
        );
        assert_eq!(c.steer_exempt, vec!["aa:bb:cc:dd:ee:ff"]);

        let f = sample();
        let n = update(
            &f,
            &WifiInput {
                steer: Some("off".into()),
                steer_signal: Some(-72),
                steer_after: Some(300),
                steer_idle: Some(0),
                steer_block: Some(45),
                steer_retry: Some(3600),
                steer_max: Some(1),
                steer_interval: Some(60),
                steer_exempt: Some(vec!["AA:BB:CC:DD:EE:01".into(), "aa:bb:cc:dd:ee:01".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        let back = parse(&render(&n));
        assert_eq!(back.get("AP_STEER"), Some("0"));
        assert_eq!(back.get("AP_STEER_SIGNAL"), Some("-72"));
        assert_eq!(back.get("AP_STEER_EXEMPT"), Some("aa:bb:cc:dd:ee:01"));
        let v = view(&back);
        assert_eq!(v.steer, "off");
        assert_eq!(
            (
                v.steer_after,
                v.steer_idle,
                v.steer_block,
                v.steer_retry,
                v.steer_max,
                v.steer_interval
            ),
            (300, 0, 45, 3600, 1, 60)
        );
        // export -> plan -> apply carries them
        let d = export_doc(&back);
        assert_eq!(d["steer"], "off");
        assert_eq!(d["steer_exempt"], json!(["aa:bb:cc:dd:ee:01"]));
        assert_eq!(d["steer_retry"], 3600);
        let again = parse_doc(&d).unwrap();
        assert_eq!(again.steer_signal, Some(-72));
        // steering is live: ap-steer re-reads ap.env every round, no radio restart
        assert!(!restart_needed(&f, &n));
        // ... but it IS a change: apply writes it (a live-only change must not look like "nothing changed")
        assert!(!same_settings(&f, &n));
        for live_only in [
            WifiInput {
                steer_max: Some(5),
                ..Default::default()
            },
            WifiInput {
                coord_min_signal: Some(-70),
                ..Default::default()
            },
            WifiInput {
                coord_quiet: Some("".into()),
                ..Default::default()
            },
        ] {
            let n = update(&f, &live_only).unwrap();
            assert!(
                !same_settings(&f, &n) && !restart_needed(&f, &n),
                "{live_only:?}"
            );
        }
        let pl = plan(
            &f,
            &WifiInput {
                steer_max: Some(5),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(pl["restart"], false);
        assert_eq!(pl["changes"][0]["setting"], "steer_max");

        // the hostapd limits are rendered into the radio config: a change restarts the radios
        let n2 = update(
            &f,
            &WifiInput {
                authfail_max: Some(0),
                authfail_hold: Some(120),
                authfail_hold_max: Some(7200),
                xbss_max: Some(4),
                xbss_window: Some(30),
                xbss_hold: Some(90),
                authfail_window: Some(30),
                ..Default::default()
            },
        )
        .unwrap();
        let b2 = parse(&render(&n2));
        assert_eq!(b2.get("AP_AUTHFAIL_MAX"), Some("0"));
        assert_eq!(b2.get("AP_AUTHFAIL_HOLD_MAX"), Some("7200"));
        assert_eq!(b2.get("AP_XBSS_HOLD"), Some("90"));
        assert_eq!(view(&b2).xbss_window, 30);
        assert!(restart_needed(&f, &n2));
        assert_eq!(export_doc(&b2)["authfail_hold"], 120);

        for bad in [
            WifiInput {
                steer: Some("sometimes".into()),
                ..Default::default()
            },
            WifiInput {
                steer_signal: Some(-30),
                ..Default::default()
            },
            WifiInput {
                steer_signal: Some(-95),
                ..Default::default()
            },
            WifiInput {
                steer_after: Some(10),
                ..Default::default()
            },
            WifiInput {
                steer_block: Some(4000),
                ..Default::default()
            },
            WifiInput {
                steer_interval: Some(5),
                ..Default::default()
            },
            WifiInput {
                steer_max: Some(100),
                ..Default::default()
            },
            WifiInput {
                steer_exempt: Some(vec!["nope".into()]),
                ..Default::default()
            },
            WifiInput {
                xbss_hold: Some(86401),
                ..Default::default()
            },
            WifiInput {
                authfail_window: Some(100000),
                ..Default::default()
            },
            // a longest hold below the first hold
            WifiInput {
                authfail_hold_max: Some(30),
                ..Default::default()
            },
            WifiInput {
                authfail_hold: Some(7200),
                ..Default::default()
            },
        ] {
            assert!(update(&f, &bad).is_err(), "{bad:?}");
        }
        // ... but raising both together is fine
        assert!(update(
            &f,
            &WifiInput {
                authfail_hold: Some(7200),
                authfail_hold_max: Some(14400),
                ..Default::default()
            }
        )
        .is_ok());
    }

    #[test]
    fn airtime_settings_default_on_validate_and_stay_live() {
        // defaults: queue limit + fairness on, halved limits on 2.4 GHz, mac80211's on 5 GHz (board.sh parity: TUNING above)
        let c = view(&parse("AP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n"));
        assert!(c.aql && c.atf);
        assert_eq!(
            (
                c.tuning["aql_low24"],
                c.tuning["aql_high24"],
                c.tuning["aql_low5"],
                c.tuning["aql_high5"]
            ),
            (2500, 5000, 5000, 12000)
        );
        let board = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ci/embedded-aarch64/ax1800/overlay/etc/patronus/board.sh");
        if let Ok(t) = std::fs::read_to_string(&board) {
            let b = parse(&t);
            assert_eq!((b.get("AP_AQL"), b.get("AP_ATF")), (Some("on"), Some("on")));
        }
        let f = sample();
        let mut t = std::collections::BTreeMap::new();
        t.insert("aql_low24".to_string(), json!(1500));
        t.insert("aql_high24".to_string(), json!(4000));
        let n = update(
            &f,
            &WifiInput {
                atf: Some(false),
                tuning: t,
                ..Default::default()
            },
        )
        .unwrap();
        let v = view(&n);
        assert!(v.aql && !v.atf);
        assert_eq!(
            (v.tuning["aql_low24"], v.tuning["aql_high24"]),
            (1500, 4000)
        );
        assert_eq!(n.get("AP_ATF"), Some("0"));
        assert_eq!(n.get("AP_AQL_LOW24"), Some("1500"));
        // live: written and applied by `ap airtime`, never a radio restart; and it IS a change
        assert!(!restart_needed(&f, &n));
        assert!(!same_settings(&f, &n));
        assert_eq!(view(&parse(&render(&n))), v);
        // a busy-radio limit above the normal one, or out of range, is refused
        for (lo, hi) in [(9000, 4000), (50, 4000), (5000, 60000)] {
            let mut t = std::collections::BTreeMap::new();
            t.insert("aql_low24".to_string(), json!(lo));
            t.insert("aql_high24".to_string(), json!(hi));
            assert!(
                update(
                    &f,
                    &WifiInput {
                        tuning: t,
                        ..Default::default()
                    }
                )
                .is_err(),
                "{lo}/{hi}"
            );
        }
        // export -> plan of the same document changes nothing
        let doc = export_doc(&n);
        let again = parse_doc(&doc).unwrap();
        assert_eq!(plan(&n, &again).unwrap()["changes"], json!([]));
    }

    #[test]
    fn channel_choice_and_steer_backoff_defaults_round_trip_validate_and_stay_live() {
        let c = view(&parse("AP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n"));
        assert!(c.chan_smart5 && c.chan_smart24 && c.chan_recheck5 && c.chan_recheck24);
        assert_eq!(
            (c.chan_time.as_str(), c.chan_csa.as_str()),
            ("03:30", "auto")
        );
        for e in TUNING {
            assert_eq!(c.tuning.get(e.0), Some(&e.2), "{} default", e.0);
        }
        // flat in the API document (no nested object), so plan lists each one
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["chan_hyst"], 20);
        assert_eq!(j["steer_retry_max"], 604800);
        // board.sh carries the same defaults
        let board = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ci/embedded-aarch64/ax1800/overlay/etc/patronus/board.sh");
        if let Ok(t) = std::fs::read_to_string(&board) {
            let b = parse(&t);
            for e in TUNING {
                assert_eq!(
                    b.get(e.1).and_then(|v| v.parse::<i64>().ok()),
                    Some(e.2),
                    "board.sh {}",
                    e.1
                );
            }
            for k in [
                "AP_CHAN_SMART24",
                "AP_CHAN_SMART5",
                "AP_CHAN_RECHECK24",
                "AP_CHAN_RECHECK5",
            ] {
                assert_eq!(b.get(k), Some("1"), "board.sh {k}");
            }
            assert_eq!(b.get("AP_CHAN_TIME"), Some(DEFAULT_CHAN_TIME));
            assert_eq!(b.get("AP_CHAN_CSA"), Some("auto"));
        }
        // out of range in the file = default
        let c = view(&parse(
            "AP_CHAN_HYST=95\nAP_CHAN_TIME=25:00\nAP_CHAN_CSA=bogus\nAP_CHAN_SMART5=0\n",
        ));
        assert_eq!(c.tuning["chan_hyst"], 20);
        assert_eq!(
            (c.chan_time.as_str(), c.chan_csa.as_str()),
            ("03:30", "auto")
        );
        assert!(!c.chan_smart5);

        let f = sample();
        let mut t = std::collections::BTreeMap::new();
        t.insert("chan_hyst".to_string(), json!(30));
        t.insert("chan_min_signal".to_string(), json!(-85));
        t.insert("steer_retry_max".to_string(), json!(86400));
        t.insert("apiVersion".to_string(), json!(DOC_API)); // not a setting: ignored
        let input = WifiInput {
            chan_smart24: Some(false),
            chan_recheck5: Some(false),
            chan_time: Some("02:15".into()),
            chan_csa: Some("off".into()),
            tuning: t,
            ..Default::default()
        };
        let n = update(&f, &input).unwrap();
        let v = view(&n);
        assert!(!v.chan_smart24 && v.chan_smart5 && !v.chan_recheck5);
        assert_eq!(
            (v.chan_time.as_str(), v.chan_csa.as_str()),
            ("02:15", "off")
        );
        assert_eq!(
            (
                v.tuning["chan_hyst"],
                v.tuning["chan_min_signal"],
                v.tuning["steer_retry_max"]
            ),
            (30, -85, 86400)
        );
        assert_eq!(n.get("AP_CHAN_TIME"), Some("02:15"));
        // all live: written, never a radio restart
        assert!(!restart_needed(&f, &n));
        assert!(!same_settings(&f, &n));
        // the file round-trips through render/parse
        assert_eq!(view(&parse(&render(&n))), v);
        // export -> plan of the same document changes nothing
        let doc = export_doc(&n);
        let again = parse_doc(&doc).unwrap();
        let p = plan(&n, &again).unwrap();
        assert_eq!(p["changes"], json!([]), "{p}");
        // the plan of a change names the setting
        let mut t = std::collections::BTreeMap::new();
        t.insert("chan_confirm".to_string(), json!(5));
        let p = plan(
            &n,
            &WifiInput {
                tuning: t,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p["changes"][0]["setting"], "chan_confirm");
        assert_eq!(p["restart"], false);

        // refused, nothing written
        for (k, bad) in [
            ("chan_hyst", json!(95)),
            ("chan_dwell", json!(5)),
            ("chan_min_signal", json!(-20)),
            ("chan_confirm", json!("three")),
            ("steer_retry_max", json!(60)), // below steer_retry (21600)
        ] {
            let mut t = std::collections::BTreeMap::new();
            t.insert(k.to_string(), bad.clone());
            let r = update(
                &f,
                &WifiInput {
                    tuning: t,
                    ..Default::default()
                },
            );
            assert!(r.is_err(), "{k}={bad} accepted");
        }
        for (time, csa) in [("3:30", "auto"), ("03:30", "maybe")] {
            let r = update(
                &f,
                &WifiInput {
                    chan_time: Some(time.into()),
                    chan_csa: Some(csa.into()),
                    ..Default::default()
                },
            );
            assert!(r.is_err(), "{time} {csa} accepted");
        }
        // no nightly re-check: empty time
        let n = update(
            &f,
            &WifiInput {
                chan_time: Some(String::new()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(view(&n).chan_time, "");
    }

    #[test]
    fn channel_history_keeps_the_newest_valid_lines() {
        let t = "{\"t\":1,\"event\":\"start\",\"band\":\"5\",\"channel\":36}\nnot json\n[1]\n{\"t\":2,\"event\":\"move\",\"band\":\"24\",\"channel\":6}\n{\"t\":3,\"event\":\"stay\",\"band\":\"5\",\"channel\":36}\n";
        let h = parse_history(t, 2);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0]["t"], 2);
        assert_eq!(h[1]["event"], "stay");
        assert_eq!(parse_history(t, 50).len(), 3);
        assert!(parse_history("", 5).is_empty());
    }

    #[test]
    fn channel_status_reads_each_measured_band() {
        let d = std::env::temp_dir().join(format!("apchan-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        std::fs::write(
            d.join("chan-status-5"),
            "{\"band\":\"5\",\"chosen\":36,\"current\":36,\"csa\":true,\"reason\":\"channel 36: 12% busy\",\"candidates\":[{\"channel\":36,\"score\":20.0,\"busy\":12.0,\"neighbours\":4}]}\n",
        )
        .unwrap();
        std::fs::write(d.join("chan-status-24"), "garbage").unwrap();
        let p = Paths {
            env: d.join("ap.env"),
            script: d.join("ap"),
            run: d.clone(),
            sysfs: d.join("sys"),
            net: d.join("net"),
        };
        let s = channel_status(&p);
        assert_eq!(s["5"]["chosen"], 36);
        assert_eq!(s["5"]["candidates"][0]["busy"], 12.0);
        // an older status without `block`: primary = current, nothing differs
        assert_eq!(s["5"]["primary"], 36);
        assert_eq!(s["5"]["primary_differs"], false);
        assert_eq!(s["5"]["block"], json!([]));
        assert!(s.get("24").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn channel_status_reports_the_running_primary_inside_the_pinned_block() {
        // measured 48, hostapd's ACS runs 36: the same 80 MHz block (seen on hardware 2026-11-18)
        let d = std::env::temp_dir().join(format!("apchan-blk-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        std::fs::write(
            d.join("chan-status-5"),
            "{\"band\":\"5\",\"chosen\":48,\"current\":36,\"block\":[36,40,44,48],\"width\":80,\"csa\":true,\"reason\":\"r\",\"candidates\":[]}\n",
        )
        .unwrap();
        std::fs::write(
            d.join("chan-status-24"),
            "{\"band\":\"24\",\"chosen\":1,\"current\":null,\"block\":[1],\"candidates\":[]}\n",
        )
        .unwrap();
        let p = Paths {
            env: d.join("ap.env"),
            script: d.join("ap"),
            run: d.clone(),
            sysfs: d.join("sys"),
            net: d.join("net"),
        };
        let s = channel_status(&p);
        assert_eq!(s["5"]["chosen"], 48);
        assert_eq!(s["5"]["primary"], 36);
        assert_eq!(s["5"]["primary_differs"], true);
        assert_eq!(s["5"]["block"], json!([36, 40, 44, 48]));
        // before the radio's first sync the measured channel is all there is
        assert_eq!(s["24"]["primary"], 1);
        assert_eq!(s["24"]["primary_differs"], false);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn channel_plan_settings_round_trip_and_validate() {
        let f = sample();
        let n = update(
            &f,
            &WifiInput {
                chan24: Some("auto".into()),
                chan5: Some("auto".into()),
                width24: Some(40),
                width5: Some(80),
                dfs: Some(true),
                unii4: Some(true),
                chanlist24: Some(vec![]),
                chanlist5: Some(vec![36, 40, 44, 48, 36, 149]),
                acs_scans: Some(3),
                ..Default::default()
            },
        )
        .unwrap();
        let back = parse(&render(&n));
        assert_eq!(back.get("AP_CHAN24"), Some("auto"));
        assert_eq!(back.get("AP_CHAN5"), Some("auto"));
        assert_eq!(back.get("AP_HT24"), Some("40"));
        assert_eq!(back.get("AP_DFS"), Some("1"));
        assert_eq!(back.get("AP_UNII4"), Some("1"));
        assert_eq!(
            back.get("AP_CHANLIST24"),
            Some(""),
            "empty list = all channels"
        );
        assert_eq!(back.get("AP_CHANLIST5"), Some("36 40 44 48 149"));
        assert_eq!(back.get("AP_ACS_SCANS"), Some("3"));
        let c = view(&back);
        assert_eq!(c.width24, 40);
        assert!(c.dfs);
        assert!(c.unii4);
        assert!(c.chanlist24.is_empty());
        assert_eq!(c.chanlist5, vec![36, 40, 44, 48, 149]);
        assert_eq!(c.acs_scans, 3);
        assert_eq!(back.get("KEY_p"), Some("secretpw1"), "networks untouched");
        // a pinned channel goes back to auto (what the house units needed)
        let pinned = parse("AP_CHAN24=1\nAP_CHAN5=36\nAP_SSIDS=p\nSSID_p=P KEY_p=secretpw1\n");
        let a = update(
            &pinned,
            &WifiInput {
                chan24: Some("auto".into()),
                chan5: Some("auto".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(view(&a).chan24, "auto");
        assert_eq!(view(&a).chan5, "auto");
        // refused, nothing changed
        for bad in [
            WifiInput {
                width24: Some(80),
                ..Default::default()
            },
            WifiInput {
                chanlist24: Some(vec![14]),
                ..Default::default()
            },
            WifiInput {
                chanlist5: Some(vec![150]),
                ..Default::default()
            },
            WifiInput {
                acs_scans: Some(0),
                ..Default::default()
            },
            WifiInput {
                acs_scans: Some(21),
                ..Default::default()
            },
            WifiInput {
                chan24: Some("14".into()),
                ..Default::default()
            },
            WifiInput {
                chan5: Some("150".into()),
                ..Default::default()
            },
        ] {
            let e = update(&f, &bad).unwrap_err().to_string();
            assert!(e.contains("Invalid Wi-Fi settings"), "{e}");
        }
        // channel plan changes restart the radios (ACS runs at hostapd start)
        assert!(restart_needed(&f, &n));
    }

    #[test]
    fn declarative_export_plan_apply_round_trip() {
        let f = parse("AP_COUNTRY=US\nAP_CHAN24=1\nAP_CHAN5=36\nAP_SSIDS=p\nSSID_p=P KEY_p=secretpw1 DENY_p=02:00:00:00:00:01\nAP_DENY=02:00:00:00:00:02\n");
        let doc = export_doc(&f);
        let text = serde_json::to_string(&doc).unwrap();
        assert!(
            !text.contains("secretpw1"),
            "no passphrase in the export: {text}"
        );
        assert_eq!(doc["apiVersion"], DOC_API);
        assert_eq!(doc["chan24"], "1");
        // the export applied as it is changes nothing (keys and block lists kept)
        let same = parse_doc(&doc).unwrap();
        let p = plan(&f, &same).unwrap();
        assert_eq!(p["changes"], json!([]), "{p}");
        assert_eq!(p["restart"], false);
        let n = update(&f, &same).unwrap();
        assert_eq!(n.get("KEY_p"), Some("secretpw1"));
        assert_eq!(n.get("DENY_p"), Some("02:00:00:00:00:01"));
        assert_eq!(n.get("AP_DENY"), Some("02:00:00:00:00:02"));
        // edit the document: channels to auto, a new password
        let mut d2 = doc.clone();
        d2["chan24"] = json!("auto");
        d2["chan5"] = json!("auto");
        d2["networks"][0]["key"] = json!("newsecret9");
        let p = plan(&f, &parse_doc(&d2).unwrap()).unwrap();
        let ch: Vec<String> = p["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["setting"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ch, vec!["chan24", "chan5", "networks.p.key"]);
        // spelling out a default is not a change, and not a restart
        let mut d3 = doc.clone();
        d3["width24"] = json!(20);
        d3["acs_scans"] = json!(5);
        let p3 = plan(&f, &parse_doc(&d3).unwrap()).unwrap();
        assert_eq!(p3["changes"], json!([]), "{p3}");
        assert!(same_settings(
            &f,
            &update(&f, &parse_doc(&d3).unwrap()).unwrap()
        ));
        assert_eq!(p["restart"], true);
        let ptext = p.to_string();
        assert!(
            !ptext.contains("secretpw1") && !ptext.contains("newsecret9"),
            "plan hides passphrases: {ptext}"
        );
        // a wrong apiVersion or a bad value is refused
        assert!(parse_doc(&json!({"apiVersion": "x/v9"})).is_err());
        assert!(plan(&f, &parse_doc(&json!({"chan5": "150"})).unwrap()).is_err());
    }

    #[test]
    fn live_width_from_hostapd_status() {
        let st = |t: &str| kv(t);
        // .10's 5 GHz radio after hostapd's HT40 coexistence swap: primary 40, secondary below, 80 MHz centre 42
        assert_eq!(
            live_width(&st("state=ENABLED\nchannel=40\nsecondary_channel=-1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=42\n")),
            (Some(80), Some(42))
        );
        assert_eq!(
            live_width(&st("channel=149\nsecondary_channel=1\nvht_oper_chwidth=0\nvht_oper_centr_freq_seg0_idx=151\n")),
            (Some(40), Some(151))
        );
        assert_eq!(
            live_width(&st("channel=6\nsecondary_channel=0\n")),
            (Some(20), Some(6))
        );
        assert_eq!(
            live_width(&st("channel=1\nsecondary_channel=1\n")),
            (Some(40), Some(3))
        );
        // ACS still surveying: no channel yet
        assert_eq!(live_width(&st("state=ACS\nchannel=0\n")), (None, None));
        assert_eq!(live_width(&[]), (None, None));
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
