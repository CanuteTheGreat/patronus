//! Automatic Wi-Fi channel choice for the standard tier (docs/WIFI-AUTO-CHANNEL.md): measure every
//! candidate channel the same way, score it, pick the quietest at radio start and re-check nightly, moving a
//! running radio by channel switch announcement (CSA) so stations follow without disconnecting.
//!
//! Same rules as the router tier's `ap-chan` (embedded-routers.md 12.19), written in Rust:
//! - Why not hostapd's ACS: it measures once and only busy time. A running radio's survey of its OWN channel
//!   accumulates for hours and includes its own traffic, while every other channel is only seen in short
//!   scans, so comparing survey numbers across channels is meaningless.
//! - Every candidate gets the SAME sample: `rounds` scans of `dwell` ms (on a running radio `scan ap-force`,
//!   falling back to a temporary managed interface of the same phy). The channel in use is measured over the
//!   same window from its own survey counters with this radio's own airtime (station byte counters over their
//!   bit rates) taken out.
//! - Score (lower is better, airtime percent): the block's busy % (the primary channel counted twice, the
//!   block's other 20 MHz channels once) + `bss_cost` points per other access point heard on the block (at most
//!   10, weaker than `min_signal` ignored, our own radios never count) + on 2.4 GHz up to 10 points per
//!   neighbour 1-4 channels away, by overlap and by how far above the -82 dBm clear-channel threshold it is.
//!   Equal best scores keep the channel in use.
//! - A move needs `confirm` samples `confirm_gap` s apart to name the same better channel, at least
//!   `hysteresis` % and `min_gain` points below the current one.
//!
//! All IO goes through [`Iw`] (`iw`, `hostapd_cli`, sysfs), so the scoring and decisions are unit-tested with
//! canned `iw` output and the whole path is proven on mac80211_hwsim (ci/netlab/lane-s-wifi-chan-hwsim.sh).

use patronus_config::seg_wifi_chan::{block_of, centre_of, ht40_plus, ChanSettings};
use patronus_core::{Error, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

fn err(m: impl std::fmt::Display) -> Error {
    Error::Network(format!("Wi-Fi channel: {m}"))
}

/// Channel number -> centre frequency (MHz) of a band (`2g` / `5g` / `6g`).
pub fn c2f(band: &str, ch: i64) -> i64 {
    if band == "6g" {
        5950 + ch * 5
    } else if band == "2g" {
        if ch == 14 {
            2484
        } else {
            2407 + ch * 5
        }
    } else {
        5000 + ch * 5
    }
}

pub fn f2c(f: i64) -> i64 {
    if f >= 5955 {
        (f - 5950) / 5
    } else if f >= 5000 {
        (f - 5000) / 5
    } else if f == 2484 {
        14
    } else {
        (f - 2407) / 5
    }
}

/// The band of a frequency (MHz).
pub fn band_of(f: i64) -> Option<&'static str> {
    match f {
        2400..=2499 => Some("2g"),
        4900..=5924 => Some("5g"),
        5925..=7125 => Some("6g"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// parsing `iw` output
// ---------------------------------------------------------------------------

/// One access point heard in a scan.
#[derive(Debug, Clone, PartialEq)]
pub struct Bss {
    pub bssid: String,
    pub freq: i64,
    pub signal: f64,
    /// operating width in MHz (20 when the beacon says nothing else)
    pub width: i64,
    /// 80 MHz: the centre channel; 0 otherwise
    pub center: i64,
    /// 40 MHz: +1 secondary above, -1 below, 0 none
    pub secondary: i8,
    /// milliseconds since its last beacon was heard (the kernel keeps a BSS about 30 s after the last one)
    pub age_ms: u64,
}

impl Bss {
    pub fn primary(&self) -> i64 {
        f2c(self.freq)
    }
}

/// `iw dev X scan` text -> the strongest sighting of every BSSID.
pub fn parse_scan(text: &str) -> Vec<Bss> {
    let mut all: Vec<Bss> = Vec::new();
    let mut cur: Option<Bss> = None;
    let mut vht_width = 0i64;
    let flush = |cur: &mut Option<Bss>, all: &mut Vec<Bss>, vht: i64| {
        if let Some(mut b) = cur.take() {
            if vht == 1 && b.center > 0 {
                b.width = 80;
            } else {
                b.center = 0;
                if b.secondary != 0 {
                    b.width = 40;
                }
            }
            all.push(b);
        }
    };
    for l in text.lines() {
        let t = l.trim();
        if let Some(rest) = t.strip_prefix("BSS ") {
            flush(&mut cur, &mut all, vht_width);
            vht_width = 0;
            let mac = rest
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if mac.len() == 17 {
                cur = Some(Bss {
                    bssid: mac,
                    freq: 0,
                    signal: -100.0,
                    width: 20,
                    center: 0,
                    secondary: 0,
                    age_ms: 0,
                });
            }
            continue;
        }
        let Some(b) = cur.as_mut() else { continue };
        if let Some(v) = t.strip_prefix("freq:") {
            b.freq = v.trim().parse::<f64>().unwrap_or(0.0) as i64;
        } else if let Some(v) = t.strip_prefix("last seen:") {
            b.age_ms = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
        } else if let Some(v) = t.strip_prefix("signal:") {
            b.signal = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(-100.0);
        } else if let Some(v) = t.strip_prefix("* secondary channel offset:") {
            b.secondary = match v.trim() {
                "above" => 1,
                "below" => -1,
                _ => 0,
            };
        } else if let Some(v) = t.strip_prefix("* channel width:") {
            vht_width = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
        } else if let Some(v) = t.strip_prefix("* center freq segment 1:") {
            b.center = v.trim().parse().unwrap_or(0);
        }
    }
    flush(&mut cur, &mut all, vht_width);
    let mut best: BTreeMap<String, Bss> = BTreeMap::new();
    for b in all {
        if b.freq == 0 {
            continue;
        }
        match best.get(&b.bssid) {
            Some(o) if o.signal >= b.signal => {}
            _ => {
                best.insert(b.bssid.clone(), b);
            }
        }
    }
    best.into_values().collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Survey {
    pub freq: i64,
    pub active: u64,
    pub busy: u64,
    pub in_use: bool,
}

/// `iw dev X survey dump` text.
pub fn parse_survey(text: &str) -> Vec<Survey> {
    let mut out: Vec<Survey> = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if let Some(v) = t.strip_prefix("frequency:") {
            out.push(Survey {
                freq: v
                    .split_whitespace()
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(0),
                active: 0,
                busy: 0,
                in_use: v.contains("[in use]"),
            });
        } else if let Some(s) = out.last_mut() {
            let num = |v: &str| v.split_whitespace().next().and_then(|x| x.parse().ok());
            if let Some(v) = t.strip_prefix("channel active time:") {
                s.active = num(v).unwrap_or(0);
            } else if let Some(v) = t.strip_prefix("channel busy time:") {
                s.busy = num(v).unwrap_or(0);
            }
        }
    }
    out
}

/// What the radio's regulatory domain allows, per 20 MHz channel, from `iw phy X info`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PhyChannels {
    /// channel -> usable for an access point (not disabled, not "no IR")
    pub usable: BTreeMap<i64, bool>,
    pub csa: bool,
}

pub fn parse_phy(text: &str, band: &str) -> PhyChannels {
    let mut p = PhyChannels::default();
    for l in text.lines() {
        let t = l.trim();
        if let Some(rest) = t.strip_prefix("* ") {
            // "* 2412.0 MHz [1] (20.0 dBm) (no IR)" (iw 6 prints decimals; older iw does not)
            if let Some((f, tail)) = rest.split_once(" MHz [") {
                if let (Ok(f), Some((ch, tail))) = (f.trim().parse::<f64>(), tail.split_once(']')) {
                    if let Ok(ch) = ch.trim().parse::<i64>() {
                        // 6 GHz numbers repeat 2.4 GHz ones: keep the asked band only
                        if band_of(f.round() as i64) == Some(band) {
                            p.usable
                                .insert(ch, !(tail.contains("disabled") || tail.contains("no IR")));
                        }
                    }
                }
            }
        }
        if t == "* channel_switch" {
            p.csa = true;
        }
    }
    p
}

// ---------------------------------------------------------------------------
// IO
// ---------------------------------------------------------------------------

/// The radio tools (a fake in tests).
pub trait Iw: Send + Sync {
    /// `iw dev IF scan [ap-force] freq F... duration D` text
    fn scan(&self, ifname: &str, freqs: &[i64], dwell: i64, ap_force: bool) -> Result<String>;
    fn survey(&self, ifname: &str) -> Result<String>;
    fn stations(&self, ifname: &str) -> Result<String>;
    fn phy_info(&self, ifname: &str) -> Result<String>;
    /// the interface's MAC (= the BSSID of its first BSS)
    fn mac_of(&self, ifname: &str) -> Option<String>;
    fn hostapd_status(&self, ifname: &str) -> Result<String>;
    fn chan_switch(&self, ifname: &str, count: i64, freq: i64, args: &[String]) -> Result<String>;
    fn pause(&self, secs: u64);
    /// Set the regulatory domain (`iw reg set CC`) before the radio's channels are read: under the world
    /// domain most 5 GHz and every 6 GHz channel is "no IR". Fakes keep the default (nothing to set).
    fn reg_set(&self, _country: &str) -> Result<()> {
        Ok(())
    }
}

/// The real tools: `iw`, `hostapd_cli`, sysfs.
#[derive(Debug, Clone)]
pub struct IwTools {
    pub ctrl_dir: PathBuf,
}

fn run(cmd: &mut Command, what: &str) -> Result<String> {
    let o = cmd.output().map_err(|e| err(format!("{what}: {e}")))?;
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    if o.status.success() {
        Ok(out)
    } else {
        Err(err(format!(
            "{what}: {}{}",
            out.trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        )))
    }
}

fn safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

impl IwTools {
    fn phy(&self, ifname: &str) -> Option<String> {
        std::fs::read_to_string(format!("/sys/class/net/{ifname}/phy80211/name"))
            .ok()
            .map(|s| s.trim().to_string())
    }
    fn scan_cmd(&self, ifname: &str, freqs: &[i64], dwell: i64, ap_force: bool) -> Result<String> {
        let mut c = Command::new("iw");
        c.args(["dev", ifname, "scan"]);
        if ap_force {
            c.arg("ap-force");
        }
        c.arg("freq");
        for f in freqs {
            c.arg(f.to_string());
        }
        c.args(["duration", &dwell.to_string()]);
        run(&mut c, "iw scan").or_else(|first| {
            // a driver that cannot set the dwell scans with its own: still a comparable sample of every channel
            let mut c = Command::new("iw");
            c.args(["dev", ifname, "scan"]);
            if ap_force {
                c.arg("ap-force");
            }
            c.arg("freq");
            for f in freqs {
                c.arg(f.to_string());
            }
            run(&mut c, "iw scan").map_err(|e| err(format!("{first}; without a dwell: {e}")))
        })
    }
}

impl Iw for IwTools {
    fn scan(&self, ifname: &str, freqs: &[i64], dwell: i64, ap_force: bool) -> Result<String> {
        if !safe(ifname) {
            return Err(err("bad interface name"));
        }
        if !ap_force {
            let _ = Command::new("ip")
                .args(["link", "set", ifname, "up"])
                .status();
            return self.scan_cmd(ifname, freqs, dwell, false);
        }
        match self.scan_cmd(ifname, freqs, dwell, true) {
            Ok(t) => Ok(t),
            Err(first) => {
                // a driver without AP scans: a temporary managed interface of the same phy does the same off-channel
                let Some(phy) = self.phy(ifname) else {
                    return Err(first);
                };
                let tmp = format!("pchan{}", std::process::id() % 10000);
                run(
                    Command::new("iw").args([
                        "phy",
                        &phy,
                        "interface",
                        "add",
                        &tmp,
                        "type",
                        "managed",
                    ]),
                    "iw interface add",
                )
                .map_err(|e| err(format!("{first}; and {e}")))?;
                let _ = Command::new("ip")
                    .args(["link", "set", &tmp, "up"])
                    .status();
                let r = self.scan_cmd(&tmp, freqs, dwell, false);
                let _ = Command::new("iw").args(["dev", &tmp, "del"]).status();
                r
            }
        }
    }
    fn survey(&self, ifname: &str) -> Result<String> {
        if !safe(ifname) {
            return Err(err("bad interface name"));
        }
        run(
            Command::new("iw").args(["dev", ifname, "survey", "dump"]),
            "iw survey",
        )
    }
    fn stations(&self, ifname: &str) -> Result<String> {
        if !safe(ifname) {
            return Err(err("bad interface name"));
        }
        run(
            Command::new("iw").args(["dev", ifname, "station", "dump"]),
            "iw station dump",
        )
    }
    fn phy_info(&self, ifname: &str) -> Result<String> {
        let phy = self
            .phy(ifname)
            .ok_or_else(|| err(format!("{ifname} has no phy")))?;
        run(
            Command::new("iw").args(["phy", &phy, "info"]),
            "iw phy info",
        )
    }
    fn mac_of(&self, ifname: &str) -> Option<String> {
        if !safe(ifname) {
            return None;
        }
        std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
    }
    fn hostapd_status(&self, ifname: &str) -> Result<String> {
        if !safe(ifname) {
            return Err(err("bad interface name"));
        }
        run(
            Command::new("hostapd_cli")
                .arg("-p")
                .arg(&self.ctrl_dir)
                .args(["-i", ifname, "status"]),
            "hostapd_cli status",
        )
    }
    fn chan_switch(&self, ifname: &str, count: i64, freq: i64, args: &[String]) -> Result<String> {
        if !safe(ifname)
            || args.iter().any(|a| {
                !a.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'-' | b'_'))
            })
        {
            return Err(err("bad channel switch arguments"));
        }
        let o = run(
            Command::new("hostapd_cli")
                .arg("-p")
                .arg(&self.ctrl_dir)
                .args([
                    "-i",
                    ifname,
                    "chan_switch",
                    &count.to_string(),
                    &freq.to_string(),
                ])
                .args(args),
            "hostapd_cli chan_switch",
        )?;
        if o.contains("FAIL") {
            return Err(err(format!("chan_switch refused: {}", o.trim())));
        }
        Ok(o)
    }
    fn reg_set(&self, country: &str) -> Result<()> {
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(err(format!("bad country code {country:?}")));
        }
        let have = |c: &str| {
            Command::new("iw")
                .args(["reg", "get"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("country {c}:")))
                .unwrap_or(false)
        };
        if have(country) {
            return Ok(());
        }
        run(
            Command::new("iw").args(["reg", "set", country]),
            "iw reg set",
        )?;
        // the kernel applies it asynchronously (regulatory.db lookup)
        for _ in 0..20 {
            if have(country) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }
    fn pause(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

// ---------------------------------------------------------------------------
// measuring
// ---------------------------------------------------------------------------

/// How a measurement is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// the radio is not serving: plain scans
    Idle,
    /// the radio serves clients: AP scans, own channel from survey counters minus own airtime
    Running,
}

/// The measured channel in use (a running radio only), over the sample window.
#[derive(Debug, Clone, PartialEq)]
pub struct Home {
    pub channel: i64,
    pub active: u64,
    pub busy: u64,
    /// this radio's own airtime in that window (ms)
    pub own_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Measurement {
    /// 20 MHz channel -> (active ms, busy ms) summed over the rounds
    pub samples: BTreeMap<i64, (u64, u64)>,
    pub home: Option<Home>,
    pub bss: Vec<Bss>,
}

/// station dump -> mac -> (tx bytes, rx bytes, tx rate Mbit/s, rx rate Mbit/s)
fn station_counters(text: &str) -> BTreeMap<String, (u64, u64, f64, f64)> {
    let mut m: BTreeMap<String, (u64, u64, f64, f64)> = BTreeMap::new();
    let mut mac = String::new();
    for l in text.lines() {
        let t = l.trim();
        if let Some(r) = t.strip_prefix("Station ") {
            mac = r
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            m.entry(mac.clone()).or_default();
            continue;
        }
        let Some(e) = m.get_mut(&mac) else { continue };
        let first = |v: &str| {
            v.split_whitespace()
                .next()
                .map(str::to_string)
                .unwrap_or_default()
        };
        if let Some(v) = t.strip_prefix("rx bytes:") {
            e.1 = first(v).parse().unwrap_or(0);
        } else if let Some(v) = t.strip_prefix("tx bytes:") {
            e.0 = first(v).parse().unwrap_or(0);
        } else if let Some(v) = t.strip_prefix("tx bitrate:") {
            e.2 = first(v).parse().unwrap_or(0.0);
        } else if let Some(v) = t.strip_prefix("rx bitrate:") {
            e.3 = first(v).parse().unwrap_or(0.0);
        }
    }
    m
}

/// Airtime (ms) the stations' traffic between two station dumps took, from bytes and bit rates.
pub fn own_airtime_ms(before: &str, after: &str) -> u64 {
    let b = station_counters(before);
    let a = station_counters(after);
    let mut ms = 0.0;
    for (mac, (tx1, rx1, txr, rxr)) in &a {
        let Some((tx0, rx0, _, _)) = b.get(mac) else {
            continue;
        };
        let dt = tx1.saturating_sub(*tx0) as f64;
        let dr = rx1.saturating_sub(*rx0) as f64;
        if dt > 0.0 && *txr > 0.0 {
            ms += dt * 8.0 / (txr * 1000.0);
        }
        if dr > 0.0 && *rxr > 0.0 {
            ms += dr * 8.0 / (rxr * 1000.0);
        }
    }
    ms as u64
}

/// Measure every channel in `visit` (20 MHz channels of `band`) the same way.
pub fn measure(
    iw: &dyn Iw,
    ifname: &str,
    band: &str,
    mode: Mode,
    visit: &[i64],
    s: &ChanSettings,
) -> Result<Measurement> {
    let freqs: Vec<i64> = visit.iter().map(|c| c2f(band, *c)).collect();
    let mut m = Measurement::default();
    let running = mode == Mode::Running;
    let home0 = if running {
        parse_survey(&iw.survey(ifname).unwrap_or_default())
            .into_iter()
            .find(|e| e.in_use)
    } else {
        None
    };
    let own0 = if running {
        iw.stations(ifname).unwrap_or_default()
    } else {
        String::new()
    };
    let started = std::time::Instant::now();
    let mut heard: Vec<Bss> = Vec::new();
    for _ in 0..s.rounds {
        let t = iw.scan(ifname, &freqs, s.dwell, running)?;
        // an access point whose last beacon is older than this measurement has gone: the kernel only forgets
        // it after about 30 s, and it must not cost the channel it used to be on
        let limit = started.elapsed().as_millis() as u64 + 1000;
        // a multi-band radio hears (and surveys) its other bands too: only this band's channels count
        heard.extend(
            parse_scan(&t)
                .into_iter()
                .filter(|b| b.age_ms <= limit && band_of(b.freq) == Some(band)),
        );
        // each dwell replaces the channel's survey entry: add up what this round measured off our own channel
        for e in parse_survey(&iw.survey(ifname).unwrap_or_default()) {
            if e.in_use
                || e.active == 0
                || band_of(e.freq) != Some(band)
                || home0.as_ref().is_some_and(|h| h.freq == e.freq)
            {
                continue;
            }
            let c = m.samples.entry(f2c(e.freq)).or_default();
            c.0 += e.active;
            c.1 += e.busy;
        }
    }
    if let Some(h0) = home0 {
        let h1 = parse_survey(&iw.survey(ifname).unwrap_or_default())
            .into_iter()
            .find(|e| e.freq == h0.freq);
        if let Some(h1) = h1 {
            let own1 = iw.stations(ifname).unwrap_or_default();
            m.home = Some(Home {
                channel: f2c(h0.freq),
                active: h1.active.saturating_sub(h0.active),
                busy: h1.busy.saturating_sub(h0.busy),
                own_ms: own_airtime_ms(&own0, &own1),
            });
        }
    }
    // the strongest sighting of every BSSID over the rounds
    heard.sort_by(|a, b| {
        a.bssid.cmp(&b.bssid).then(
            b.signal
                .partial_cmp(&a.signal)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    heard.dedup_by(|b, a| a.bssid == b.bssid);
    m.bss = heard;
    Ok(m)
}

// ---------------------------------------------------------------------------
// scoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Cand {
    pub channel: i64,
    pub score: f64,
    pub busy: f64,
    pub neighbours: i64,
}

fn covers5(b: &Bss, x: i64) -> bool {
    let p = b.primary();
    let (lo, hi) = if b.width == 80 && b.center > 0 {
        (b.center - 6, b.center + 6)
    } else if b.width == 40 && b.secondary > 0 {
        (p, p + 4)
    } else if b.width == 40 && b.secondary < 0 {
        (p - 4, p)
    } else {
        (p, p)
    };
    x >= lo && x <= hi
}

fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Score every candidate (primary channels) at `width`; best first, a tie goes to the channel in use `cur`.
pub fn score(
    band: &str,
    width: i64,
    cands: &[i64],
    m: &Measurement,
    s: &ChanSettings,
    own: &[String],
    cur: i64,
) -> Vec<Cand> {
    // busy percent per 20 MHz channel
    let mut bz: BTreeMap<i64, f64> = BTreeMap::new();
    for (c, (a, b)) in &m.samples {
        if *a > 0 {
            bz.insert(*c, 100.0 * *b as f64 / *a as f64);
        }
    }
    if let Some(h) = &m.home {
        if h.active > 0 {
            let v = 100.0 * (h.busy as f64 - h.own_ms as f64) / h.active as f64;
            bz.insert(h.channel, v.max(0.0));
        }
    }
    let nb: Vec<&Bss> = m
        .bss
        .iter()
        .filter(|b| {
            !own.iter().any(|o| o.eq_ignore_ascii_case(&b.bssid)) && b.signal >= s.min_signal as f64
        })
        .collect();
    let mut out: Vec<Cand> = Vec::new();
    for &c in cands {
        let block = block_of(band, c, width);
        let (mut sum, mut wt) = (0.0, 0.0);
        for x in &block {
            if let Some(v) = bz.get(x) {
                let f = if *x == c { 2.0 } else { 1.0 };
                sum += f * v;
                wt += f;
            }
        }
        let busy = if wt > 0.0 { sum / wt } else { 0.0 };
        let (mut co, mut adj) = (0i64, 0.0f64);
        for b in &nb {
            if band != "2g" {
                if block.iter().any(|x| covers5(b, *x)) {
                    co += 1;
                }
            } else {
                let d = (b.primary() - c).abs();
                if d == 0 {
                    co += 1;
                } else if d <= 4 {
                    let sg = ((b.signal + 82.0) / 20.0).clamp(0.0, 1.0);
                    adj += (5 - d) as f64 / 5.0 * sg * 10.0;
                }
            }
        }
        let cc = co.min(10);
        out.push(Cand {
            channel: c,
            score: r1(busy + s.bss_cost as f64 * cc as f64 + adj),
            busy: r1(busy),
            neighbours: co,
        });
    }
    out.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.channel.cmp(&b.channel))
    });
    // equal best scores: the channel in use first (nothing to gain by moving)
    if let Some(best) = out.first().map(|c| c.score) {
        if let Some(i) = out.iter().position(|c| c.channel == cur && c.score == best) {
            let c = out.remove(i);
            out.insert(0, c);
        }
    }
    out
}

/// Is `best` clearly better than `cur`: at least `hyst` percent and `gain` points lower.
pub fn clearly_better(cur: f64, best: f64, hyst: i64, gain: i64) -> bool {
    cur - best >= gain as f64 && best <= cur * (100 - hyst) as f64 / 100.0
}

/// One sentence: what the chosen channel looks like and the next best.
pub fn why(c: &[Cand], chosen: i64) -> String {
    let Some(me) = c.iter().find(|x| x.channel == chosen) else {
        return format!("channel {chosen}");
    };
    let mut s = format!(
        "channel {}: {:.0}% busy, {} other access point{} (score {})",
        me.channel,
        me.busy,
        me.neighbours,
        if me.neighbours == 1 { "" } else { "s" },
        me.score
    );
    if let Some(n) = c.iter().find(|x| x.channel != chosen) {
        s.push_str(&format!(
            "; next best {}: {:.0}% busy, {} (score {})",
            n.channel, n.busy, n.neighbours, n.score
        ));
    }
    s
}

/// The candidates that can carry an access point here: disabled / no-IR channels of the regulatory domain
/// drop out, and at 40/80 MHz so does a block with such a channel in it. With no regulatory information
/// (an empty `phy`) everything stays.
pub fn usable(band: &str, width: i64, cands: &[i64], phy: &PhyChannels) -> Vec<i64> {
    if phy.usable.is_empty() {
        return cands.to_vec();
    }
    cands
        .iter()
        .copied()
        .filter(|c| {
            block_of(band, *c, width)
                .iter()
                .all(|x| phy.usable.get(x).copied().unwrap_or(false))
        })
        .collect()
}

/// The 20 MHz channels a measurement has to visit: every channel of the band on 2.4 GHz (neighbours between the
/// candidates count), the candidates' blocks on 5 GHz.
pub fn visit(band: &str, width: i64, cands: &[i64], phy: &PhyChannels) -> Vec<i64> {
    let mut v: Vec<i64> = if band == "2g" {
        patronus_config::seg_wifi_chan::band_channels("2g")
            .into_iter()
            .filter(|c| phy.usable.is_empty() || phy.usable.get(c).copied().unwrap_or(false))
            .collect()
    } else {
        cands
            .iter()
            .flat_map(|c| block_of(band, *c, width))
            .collect()
    };
    v.sort_unstable();
    v.dedup();
    v
}

// ---------------------------------------------------------------------------
// moving
// ---------------------------------------------------------------------------

fn rank(std: &str) -> usize {
    match std {
        "ac" => 1,
        "ax" => 2,
        "be" => 3,
        _ => 0,
    }
}

/// `*_oper_chwidth` value of a width (0 = 20/40, 1 = 80, 2 = 160, 9 = 320).
fn oper_chwidth(width: i64) -> i64 {
    match width {
        80 => 1,
        160 => 2,
        320 => 9,
        _ => 0,
    }
}

/// hostapd.conf lines of the channel at a width for a generation (`std` = the EFFECTIVE `n`/`ac`/`ax`/`be`).
/// Empty for plain 20 MHz Wi-Fi 4 (unchanged from fixed-channel configs).
pub fn conf_lines(band: &str, ch: i64, width: i64, std: &str) -> String {
    let mut o = String::new();
    let r = rank(std);
    if band == "6g" {
        // 6 GHz: no HT/VHT elements; the operating class names the width
        if let Some(oc) = patronus_config::seg_wifi_chan::op_class_6g(width) {
            o.push_str(&format!("op_class={oc}\n"));
        }
    } else if width >= 40 {
        let plus = if band == "2g" { ch <= 7 } else { ht40_plus(ch) };
        o.push_str(&format!(
            "ht_capab=[HT40{}]\n",
            if plus { '+' } else { '-' }
        ));
        if band == "5g" && width >= 80 && r >= 1 {
            let center = centre_of(band, ch, width).unwrap_or(ch);
            if width == 160 {
                o.push_str("vht_capab=[VHT160]\n");
            }
            o.push_str(&format!(
                "ieee80211ac=1\nvht_oper_chwidth={}\nvht_oper_centr_freq_seg0_idx={center}\n",
                oper_chwidth(width)
            ));
        }
    }
    if r >= 2 {
        o.push_str("ieee80211ax=1\n");
        if band != "2g" && (band == "6g" || width >= 80) {
            // HE has no 320 MHz: it describes the 160 MHz half that holds the primary channel
            let hw = width.min(160);
            let center = centre_of(band, ch, hw).unwrap_or(ch);
            o.push_str(&format!(
                "he_oper_chwidth={}\nhe_oper_centr_freq_seg0_idx={center}\n",
                oper_chwidth(hw)
            ));
        }
    }
    if r >= 3 {
        o.push_str("ieee80211be=1\n");
        if band != "2g" && (band == "6g" || width >= 80) {
            let center = centre_of(band, ch, width).unwrap_or(ch);
            o.push_str(&format!(
                "eht_oper_chwidth={}\neht_oper_centr_freq_seg0_idx={center}\n",
                oper_chwidth(width)
            ));
        }
    }
    o
}

/// `hostapd_cli chan_switch COUNT FREQ ARGS` for a primary channel at a width (Wi-Fi 4/5).
pub fn csa_args(band: &str, ch: i64, width: i64) -> (i64, Vec<String>) {
    csa_args_std(band, ch, width, "ac")
}

/// `hostapd_cli chan_switch COUNT FREQ ARGS` for a primary channel at a width and generation.
pub fn csa_args_std(band: &str, ch: i64, width: i64, std: &str) -> (i64, Vec<String>) {
    let f = c2f(band, ch);
    let mut a: Vec<String> = Vec::new();
    if band == "6g" {
        if width >= 40 {
            let ctr = centre_of(band, ch, width).unwrap_or(ch);
            a.push(format!("center_freq1={}", c2f(band, ctr)));
        }
        a.push(format!("bandwidth={width}"));
    } else {
        if width >= 40 {
            let plus = if band == "2g" { ch <= 7 } else { ht40_plus(ch) };
            let so = if plus { 1 } else { -1 };
            let cf = if band == "2g" {
                f + so * 10
            } else {
                c2f(band, centre_of(band, ch, width).unwrap_or(ch))
            };
            a.push(format!("sec_channel_offset={so}"));
            a.push(format!("center_freq1={cf}"));
        }
        a.push(format!("bandwidth={width}"));
        a.push("ht".into());
        if band == "5g" && width >= 80 {
            a.push("vht".into());
        }
    }
    if rank(std) >= 2 {
        a.push("he".into());
    }
    if rank(std) >= 3 {
        a.push("eht".into());
    }
    (f, a)
}

/// The channel hostapd reports (`channel=N` of `status`).
pub fn status_channel(text: &str) -> Option<i64> {
    text.lines()
        .find_map(|l| l.strip_prefix("channel="))
        .and_then(|v| v.trim().parse().ok())
}

/// Announce a switch to `ch` and wait until hostapd is on it. `Ok(true)` = on the new channel.
pub fn switch_by_csa(
    iw: &dyn Iw,
    ifname: &str,
    band: &str,
    ch: i64,
    width: i64,
    count: i64,
) -> Result<bool> {
    switch_by_csa_std(iw, ifname, band, ch, width, count, "ac")
}

/// [`switch_by_csa`] for a generation (`he`/`eht` are named in the announcement).
pub fn switch_by_csa_std(
    iw: &dyn Iw,
    ifname: &str,
    band: &str,
    ch: i64,
    width: i64,
    count: i64,
    std: &str,
) -> Result<bool> {
    let (f, args) = csa_args_std(band, ch, width, std);
    iw.chan_switch(ifname, count, f, &args)?;
    // the announcement counts beacons (~102 ms each); then hostapd is on the new channel
    for _ in 0..(count / 5 + 6) {
        iw.pause(1);
        if iw
            .hostapd_status(ifname)
            .ok()
            .as_deref()
            .and_then(status_channel)
            == Some(ch)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `HH:MM` of the nightly re-check reached (within the hour after it) and not yet run on `today`?
pub fn due(now_minute: u32, today: i64, time: &str, last_day: Option<i64>) -> bool {
    let Some((h, m)) = time.split_once(':') else {
        return false;
    };
    let (Ok(h), Ok(m)) = (h.parse::<u32>(), m.parse::<u32>()) else {
        return false;
    };
    if h > 23 || m > 59 || last_day == Some(today) {
        return false;
    }
    let at = h * 60 + m;
    (now_minute + 1440 - at) % 1440 < 60
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn bss(mac: &str, freq: i64, sig: f64) -> String {
        format!("BSS {mac}(on wlan0)\n\tfreq: {freq}.0\n\tsignal: {sig:.2} dBm\n\tSSID: n\n")
    }

    fn meas(busy: &[(i64, u64)], bss_list: Vec<Bss>) -> Measurement {
        Measurement {
            samples: busy.iter().map(|(c, b)| (*c, (1000, *b))).collect(),
            home: None,
            bss: bss_list,
        }
    }

    fn nb(mac: &str, ch: i64, sig: f64) -> Bss {
        Bss {
            bssid: mac.into(),
            freq: c2f("2g", ch),
            signal: sig,
            width: 20,
            center: 0,
            secondary: 0,
            age_ms: 0,
        }
    }

    #[test]
    fn scan_parse_keeps_strongest_and_width() {
        let t = format!(
            "{}{}BSS aa:aa:aa:aa:aa:03(on wlan0)\n\tfreq: 5180\n\tsignal: -60.00 dBm\n\tHT operation:\n\t\t * primary channel: 36\n\t\t * secondary channel offset: above\n\t\t * STA channel width: any\n\tVHT operation:\n\t\t * channel width: 1 (80 MHz)\n\t\t * center freq segment 1: 42\n",
            bss("aa:aa:aa:aa:aa:01", 2437, -70.0),
            bss("AA:AA:AA:AA:AA:01", 2437, -50.0)
        );
        let v = parse_scan(&t);
        assert_eq!(v.len(), 2);
        let a = v.iter().find(|b| b.bssid.ends_with(":01")).unwrap();
        assert_eq!(a.signal, -50.0);
        let c = v.iter().find(|b| b.bssid.ends_with(":03")).unwrap();
        assert_eq!((c.width, c.center, c.primary()), (80, 42, 36));
        assert!(covers5(c, 48) && !covers5(c, 52));
    }

    #[test]
    fn a_vanished_access_point_is_not_a_neighbour() {
        // heard in this scan (last seen 40 ms ago) and kept by the kernel from 28 s ago
        let t = "BSS aa:00:00:00:00:01(on wlan0)\n\tlast seen: 40 ms ago\n\tfreq: 2412.0\n\tsignal: -50.00 dBm\nBSS aa:00:00:00:00:02(on wlan0)\n\tlast seen: 28000 ms ago\n\tfreq: 2437.0\n\tsignal: -50.00 dBm\n";
        let iw = fake(t);
        let s = ChanSettings {
            rounds: 2,
            ..Default::default()
        };
        let m = measure(&iw, "wlan0", "2g", Mode::Idle, &[1, 6, 11], &s).unwrap();
        assert_eq!(m.bss.len(), 1, "{:?}", m.bss);
        assert_eq!(m.bss[0].primary(), 1);
        assert_eq!(
            parse_scan(t).len(),
            2,
            "parsing keeps both; the measurement judges their age"
        );
    }

    #[test]
    fn survey_and_phy_parse() {
        let s = parse_survey("Survey data from wlan0\n\tfrequency:\t\t\t2412 MHz [in use]\n\tchannel active time:\t\t1000 ms\n\tchannel busy time:\t\t 250 ms\nSurvey data from wlan0\n\tfrequency:\t\t\t2437 MHz\n\tchannel active time:\t\t100 ms\n\tchannel busy time:\t\t 10 ms\n");
        assert_eq!(s.len(), 2);
        assert!(s[0].in_use && s[0].busy == 250 && s[1].active == 100);
        let p = parse_phy("\t\t\t* 2412 MHz [1] (20.0 dBm)\n\t\t\t* 2467 MHz [12] (disabled)\n\t\t\t* 5260 MHz [52] (23.0 dBm) (no IR, radar detection)\n\t\t\t* channel_switch\n", "2g");
        assert!(p.csa && p.usable[&1] && !p.usable[&12] && !p.usable.contains_key(&52));
        let p5 = parse_phy(
            "\t\t\t* 5260 MHz [52] (23.0 dBm) (no IR, radar detection)\n",
            "5g",
        );
        assert!(!p5.usable[&52]);
        // iw 6 prints decimals; 6 GHz channel numbers repeat 2.4 GHz ones: each band keeps its own
        let t = "\t\t\t* 2412.0 MHz [1] (20.0 dBm) (no IR)\n\t\t\t* 5955.0 MHz [1] (23.0 dBm)\n\t\t\t* 6135.0 MHz [37] (23.0 dBm)\n";
        assert!(!parse_phy(t, "2g").usable[&1]);
        let p6 = parse_phy(t, "6g");
        assert!(p6.usable[&1] && p6.usable[&37] && p6.usable.len() == 2);
        assert_eq!(usable("2g", 20, &[1, 6, 12], &p), vec![1]);
        assert_eq!(
            usable("2g", 20, &[1, 6], &PhyChannels::default()),
            vec![1, 6]
        );
    }

    #[test]
    fn quiet_channel_wins_and_neighbours_cost() {
        let s = ChanSettings::default();
        let m = meas(
            &[(1, 300), (6, 100), (11, 100)],
            vec![
                nb("a1", 6, -50.0),
                nb("a2", 6, -60.0),
                nb("a3", 6, -88.0),
                nb("a4", 1, -50.0),
            ],
        );
        let c = score("2g", 20, &[1, 6, 11], &m, &s, &[], 0);
        assert_eq!(c[0].channel, 11, "{c:?}");
        assert_eq!(c[0].neighbours, 0);
        let six = c.iter().find(|x| x.channel == 6).unwrap();
        assert_eq!(six.neighbours, 3);
        // 10% busy + 3 x 2 points + the adjacent neighbour on channel 1 (5 away: no overlap)
        assert!((six.score - 16.0).abs() < 0.11, "{six:?}");
        // own radios never count, and weak ones are ignored
        let own = vec!["a1".to_string(), "A2".to_string()];
        let c2 = score("2g", 20, &[1, 6, 11], &m, &s, &own, 0);
        assert_eq!(c2.iter().find(|x| x.channel == 6).unwrap().neighbours, 1);
        let mut weak = s.clone();
        weak.min_signal = -55;
        let c3 = score("2g", 20, &[6], &m, &weak, &[], 0);
        assert_eq!(c3[0].neighbours, 1);
    }

    #[test]
    fn overlap_on_2g_hurts_channels_near_a_strong_neighbour() {
        let s = ChanSettings::default();
        let m = meas(&[(1, 0), (6, 0), (11, 0)], vec![nb("n", 3, -55.0)]);
        let c = score("2g", 20, &[1, 6, 11], &m, &s, &[], 0);
        // a strong neighbour on 3 hurts 1 and 6, not 11
        assert_eq!(c[0].channel, 11);
        let one = c.iter().find(|x| x.channel == 1).unwrap().score;
        let six = c.iter().find(|x| x.channel == 6).unwrap().score;
        assert!(one > 5.0 && six > 3.0 && one > six, "{c:?}");
    }

    #[test]
    fn own_airtime_is_taken_out_of_the_channel_in_use() {
        let s = ChanSettings::default();
        let mut m = meas(&[(1, 100), (11, 100)], vec![]);
        // channel 6 (ours): 40% busy, 30 points of it our own traffic
        m.home = Some(Home {
            channel: 6,
            active: 1000,
            busy: 400,
            own_ms: 300,
        });
        let c = score("2g", 20, &[1, 6, 11], &m, &s, &[], 6);
        let six = c.iter().find(|x| x.channel == 6).unwrap();
        assert!((six.busy - 10.0).abs() < 0.11, "{six:?}");
        // equal best scores keep the channel in use first
        assert_eq!(c[0].channel, 6, "{c:?}");
        let c = score("2g", 20, &[1, 6, 11], &m, &s, &[], 11);
        assert_eq!(c[0].channel, 11);
        // more own traffic than busy time cannot go negative
        m.home = Some(Home {
            channel: 6,
            active: 1000,
            busy: 100,
            own_ms: 900,
        });
        let c = score("2g", 20, &[6], &m, &s, &[], 6);
        assert_eq!(c[0].busy, 0.0);
    }

    #[test]
    fn five_ghz_blocks_and_neighbour_width() {
        let s = ChanSettings::default();
        let mut wide = nb("w", 1, -50.0);
        wide.freq = 5180;
        wide.width = 80;
        wide.center = 42;
        let m = Measurement {
            samples: [
                (36, (1000, 0)),
                (40, (1000, 0)),
                (44, (1000, 0)),
                (48, (1000, 0)),
                (149, (1000, 0)),
                (153, (1000, 0)),
                (157, (1000, 0)),
                (161, (1000, 0)),
            ]
            .into_iter()
            .collect(),
            home: None,
            bss: vec![wide],
        };
        let c = score("5g", 80, &[36, 149], &m, &s, &[], 0);
        assert_eq!(c[0].channel, 149);
        assert_eq!(c.iter().find(|x| x.channel == 36).unwrap().neighbours, 1);
        let c = score("5g", 20, &[40, 52, 149], &m, &s, &[], 0);
        assert_eq!(c.iter().find(|x| x.channel == 40).unwrap().neighbours, 1);
        assert_eq!(c.iter().find(|x| x.channel == 52).unwrap().neighbours, 0);
    }

    #[test]
    fn hysteresis_rules() {
        assert!(clearly_better(40.0, 20.0, 20, 10));
        assert!(
            !clearly_better(40.0, 35.0, 20, 10),
            "needs 20% and 10 points"
        );
        assert!(!clearly_better(12.0, 4.0, 20, 10), "8 points is not enough");
        assert!(clearly_better(40.0, 30.0, 20, 10));
        assert!(!clearly_better(50.0, 41.0, 20, 5), "18% < 20%");
        assert!(clearly_better(30.0, 30.0 - 6.0, 20, 0));
    }

    #[test]
    fn nightly_window_runs_once_a_day() {
        assert!(due(3 * 60 + 30, 100, "03:30", None));
        assert!(due(4 * 60 + 29, 100, "03:30", Some(99)));
        assert!(!due(4 * 60 + 30, 100, "03:30", None));
        assert!(!due(3 * 60 + 29, 100, "03:30", None));
        assert!(!due(3 * 60 + 40, 100, "03:30", Some(100)));
        assert!(due(10, 5, "23:30", None), "window crossing midnight");
        for bad in ["", "3:3x", "24:00", "03:60", "0330"] {
            assert!(!due(0, 1, bad, None), "{bad:?}");
        }
    }

    #[test]
    fn switch_arguments_and_conf_lines() {
        assert_eq!(
            csa_args("2g", 6, 20),
            (2437, vec!["bandwidth=20".to_string(), "ht".to_string()])
        );
        let (f, a) = csa_args("5g", 36, 80);
        assert_eq!(f, 5180);
        assert_eq!(
            a,
            [
                "sec_channel_offset=1",
                "center_freq1=5210",
                "bandwidth=80",
                "ht",
                "vht"
            ]
        );
        let (_, a) = csa_args("5g", 40, 40);
        assert_eq!(
            a,
            [
                "sec_channel_offset=-1",
                "center_freq1=5190",
                "bandwidth=40",
                "ht"
            ]
        );
        let (_, a) = csa_args("2g", 11, 40);
        assert_eq!(
            a,
            [
                "sec_channel_offset=-1",
                "center_freq1=2452",
                "bandwidth=40",
                "ht"
            ]
        );
        assert_eq!(conf_lines("2g", 6, 20, "n"), "");
        assert_eq!(conf_lines("2g", 1, 40, "n"), "ht_capab=[HT40+]\n");
        let c = conf_lines("5g", 149, 80, "ac");
        assert!(
            c.contains("[HT40+]")
                && c.contains("vht_oper_centr_freq_seg0_idx=155")
                && c.contains("ieee80211ac=1"),
            "{c}"
        );
        assert!(conf_lines("5g", 40, 40, "n").contains("[HT40-]"));
    }

    #[test]
    fn six_ghz_frequencies() {
        assert_eq!(c2f("6g", 1), 5955);
        assert_eq!(c2f("6g", 37), 6135);
        assert_eq!(c2f("6g", 233), 7115);
        assert_eq!(f2c(6135), 37);
        assert_eq!(f2c(5825), 165);
        assert_eq!(band_of(6135), Some("6g"));
        assert_eq!(band_of(5180), Some("5g"));
        assert_eq!(band_of(2412), Some("2g"));
    }

    #[test]
    fn wifi6_and_wifi7_conf_lines() {
        // Wi-Fi 6 on 2.4 GHz: HE on, no centre lines (HT40 only)
        let c = conf_lines("2g", 6, 20, "ax");
        assert_eq!(c, "ieee80211ax=1\n");
        // 5 GHz 80 MHz Wi-Fi 6: VHT and HE both describe the block
        let c = conf_lines("5g", 36, 80, "ax");
        for l in [
            "ht_capab=[HT40+]",
            "ieee80211ac=1",
            "vht_oper_chwidth=1",
            "vht_oper_centr_freq_seg0_idx=42",
            "ieee80211ax=1",
            "he_oper_chwidth=1",
            "he_oper_centr_freq_seg0_idx=42",
        ] {
            assert!(c.lines().any(|x| x == l), "{l} missing in\n{c}");
        }
        assert!(!c.contains("eht"), "{c}");
        // 160 MHz needs the VHT160 capability named
        let c = conf_lines("5g", 36, 160, "ax");
        for l in [
            "vht_capab=[VHT160]",
            "vht_oper_chwidth=2",
            "vht_oper_centr_freq_seg0_idx=50",
            "he_oper_chwidth=2",
            "he_oper_centr_freq_seg0_idx=50",
        ] {
            assert!(c.lines().any(|x| x == l), "{l} missing in\n{c}");
        }
        // Wi-Fi 5 at 160 MHz: no HE
        assert!(!conf_lines("5g", 100, 160, "ac").contains("ieee80211ax"));
        // Wi-Fi 7 on 5 GHz
        let c = conf_lines("5g", 36, 80, "be");
        assert!(
            c.contains("ieee80211be=1\neht_oper_chwidth=1\neht_oper_centr_freq_seg0_idx=42\n"),
            "{c}"
        );
        // 6 GHz: operating class, no HT/VHT, HE centre always
        let c = conf_lines("6g", 37, 160, "ax");
        assert_eq!(
            c,
            "op_class=134\nieee80211ax=1\nhe_oper_chwidth=2\nhe_oper_centr_freq_seg0_idx=47\n"
        );
        let c = conf_lines("6g", 5, 20, "ax");
        assert_eq!(
            c,
            "op_class=131\nieee80211ax=1\nhe_oper_chwidth=0\nhe_oper_centr_freq_seg0_idx=5\n"
        );
        // 320 MHz: HE describes the 160 MHz half that holds the primary, EHT the whole block
        let c = conf_lines("6g", 37, 320, "be");
        assert_eq!(c, "op_class=137\nieee80211ax=1\nhe_oper_chwidth=2\nhe_oper_centr_freq_seg0_idx=47\nieee80211be=1\neht_oper_chwidth=9\neht_oper_centr_freq_seg0_idx=31\n");
    }

    #[test]
    fn channel_switch_names_he_and_eht() {
        let (_, a) = csa_args_std("5g", 36, 80, "ax");
        assert_eq!(
            a,
            [
                "sec_channel_offset=1",
                "center_freq1=5210",
                "bandwidth=80",
                "ht",
                "vht",
                "he"
            ]
        );
        let (f, a) = csa_args_std("6g", 37, 160, "be");
        assert_eq!(f, 6135);
        assert_eq!(a, ["center_freq1=6185", "bandwidth=160", "he", "eht"]);
        let (_, a) = csa_args_std("6g", 37, 320, "be");
        assert_eq!(a, ["center_freq1=6105", "bandwidth=320", "he", "eht"]);
        // the old signature is the Wi-Fi 4/5 behaviour
        assert_eq!(csa_args("5g", 36, 80), csa_args_std("5g", 36, 80, "ac"));
    }

    #[test]
    fn airtime_from_station_counters() {
        let t = |tx: u64, rx: u64| {
            format!("Station AA:BB:CC:DD:EE:01 (on wlan0)\n\trx bytes:\t{rx}\n\ttx bytes:\t{tx}\n\ttx bitrate:\t10.0 MBit/s\n\trx bitrate:\t20.0 MBit/s\n")
        };
        // 1.25 MB sent at 10 Mbit/s = 1000 ms, 2.5 MB received at 20 Mbit/s = 1000 ms
        assert_eq!(own_airtime_ms(&t(0, 0), &t(1_250_000, 2_500_000)), 2000);
        assert_eq!(
            own_airtime_ms("", &t(1_250_000, 0)),
            0,
            "a station not seen before has no baseline"
        );
    }

    /// A radio with scripted scans: the first scan text for every round, one survey text.
    struct Fake {
        scan: String,
        survey: Mutex<Vec<String>>,
        status: Mutex<String>,
        switches: Mutex<Vec<(i64, i64, Vec<String>)>>,
        fail_switch: bool,
    }
    impl Iw for Fake {
        fn scan(&self, _: &str, _: &[i64], _: i64, _: bool) -> Result<String> {
            Ok(self.scan.clone())
        }
        fn survey(&self, _: &str) -> Result<String> {
            let mut v = self.survey.lock().unwrap();
            Ok(if v.len() > 1 {
                v.remove(0)
            } else {
                v[0].clone()
            })
        }
        fn stations(&self, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn phy_info(&self, _: &str) -> Result<String> {
            Ok(String::new())
        }
        fn mac_of(&self, _: &str) -> Option<String> {
            None
        }
        fn hostapd_status(&self, _: &str) -> Result<String> {
            Ok(self.status.lock().unwrap().clone())
        }
        fn chan_switch(&self, _: &str, count: i64, freq: i64, args: &[String]) -> Result<String> {
            if self.fail_switch {
                return Err(err("refused"));
            }
            self.switches
                .lock()
                .unwrap()
                .push((count, freq, args.to_vec()));
            *self.status.lock().unwrap() = format!("state=ENABLED\nchannel={}\n", f2c(freq));
            Ok("OK".into())
        }
        fn pause(&self, _: u64) {}
    }

    fn fake(scan: &str) -> Fake {
        Fake {
            scan: scan.into(),
            survey: Mutex::new(vec![
                "Survey data from w\n\tfrequency:\t2412 MHz\n\tchannel active time:\t100 ms\n\tchannel busy time:\t80 ms\nSurvey data from w\n\tfrequency:\t2437 MHz\n\tchannel active time:\t100 ms\n\tchannel busy time:\t5 ms\nSurvey data from w\n\tfrequency:\t2462 MHz\n\tchannel active time:\t100 ms\n\tchannel busy time:\t50 ms\n".into(),
            ]),
            status: Mutex::new("channel=1\n".into()),
            switches: Mutex::new(vec![]),
            fail_switch: false,
        }
    }

    #[test]
    fn idle_measurement_sums_rounds_and_picks_the_quiet_channel() {
        let iw = fake(&bss("aa:00:00:00:00:01", 2412, -50.0));
        let s = ChanSettings {
            rounds: 3,
            ..Default::default()
        };
        let m = measure(&iw, "wlan0", "2g", Mode::Idle, &[1, 6, 11], &s).unwrap();
        assert_eq!(m.samples[&1], (300, 240));
        assert_eq!(m.bss.len(), 1);
        let c = score("2g", 20, &[1, 6, 11], &m, &s, &[], 0);
        assert_eq!(c[0].channel, 6);
        assert!(why(&c, 6).contains("channel 6: 5% busy, 0 other access points"));
    }

    #[test]
    fn csa_waits_for_the_new_channel_and_reports_refusal() {
        let iw = fake("");
        assert!(switch_by_csa(&iw, "wlan0", "2g", 6, 20, 10).unwrap());
        assert_eq!(iw.switches.lock().unwrap()[0].1, 2437);
        let mut bad = fake("");
        bad.fail_switch = true;
        assert!(switch_by_csa(&bad, "wlan0", "2g", 6, 20, 10).is_err());
        // hostapd that never reports the channel: not on it
        let stuck = fake("");
        *stuck.status.lock().unwrap() = "channel=1\n".into();
        struct NoMove(Fake);
        impl Iw for NoMove {
            fn scan(&self, a: &str, b: &[i64], c: i64, d: bool) -> Result<String> {
                self.0.scan(a, b, c, d)
            }
            fn survey(&self, a: &str) -> Result<String> {
                self.0.survey(a)
            }
            fn stations(&self, a: &str) -> Result<String> {
                self.0.stations(a)
            }
            fn phy_info(&self, a: &str) -> Result<String> {
                self.0.phy_info(a)
            }
            fn mac_of(&self, a: &str) -> Option<String> {
                self.0.mac_of(a)
            }
            fn hostapd_status(&self, a: &str) -> Result<String> {
                self.0.hostapd_status(a)
            }
            fn chan_switch(&self, _: &str, _: i64, _: i64, _: &[String]) -> Result<String> {
                Ok("OK".into())
            }
            fn pause(&self, _: u64) {}
        }
        assert!(!switch_by_csa(&NoMove(stuck), "wlan0", "2g", 6, 20, 10).unwrap());
    }
}
