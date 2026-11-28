//! Wi-Fi radios of this machine (`/sys/class/ieee80211` + `iw phy info`): which
//! radios can run an access point, on which bands, and with which 802.11
//! generations and channel widths. Shared by the per-device Wi-Fi networks
//! (USE=wifi-ap) and the guest network (USE=guest).
//!
//! Everything here is read from the radio itself, so the UI and the hostapd
//! renderer never offer or claim more than the card does: a card that `iw`
//! reports without an AP HE capability on 6 GHz is not offered 6 GHz.

use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct Radio {
    pub phy: String,
    pub ifaces: Vec<String>,
    /// supports AP mode
    pub ap: bool,
    /// `2g` / `5g` / `6g`
    pub bands: Vec<String>,
    /// what the radio can do as an access point, per band
    pub caps: RadioCaps,
    /// one-line labels for the UI: "Wi-Fi 6E", "160 MHz", ...
    pub supports: Vec<String>,
}

/// One 20 MHz channel of a band, as the regulatory domain in force allows it.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct ChanInfo {
    pub channel: i64,
    pub freq: i64,
    /// an access point may transmit here (not disabled, not "no IR")
    pub usable: bool,
    /// radar detection (DFS) required: the AP waits out the channel availability check first
    pub radar: bool,
}

/// Access-point capabilities of one band of a radio.
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub struct BandCaps {
    pub band: String,
    pub channels: Vec<ChanInfo>,
    pub ht40: bool,
    pub vht: bool,
    pub vht160: bool,
    /// HE (Wi-Fi 6) with the AP interface type
    pub he: bool,
    pub he40: bool,
    pub he80: bool,
    pub he160: bool,
    /// EHT (Wi-Fi 7) with the AP interface type
    pub eht: bool,
    pub eht320: bool,
}

/// Access-point capabilities of one radio.
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub struct RadioCaps {
    pub ap: bool,
    pub bands: Vec<BandCaps>,
    /// the driver can send unsolicited broadcast probe responses (6 GHz discovery)
    pub unsol_probe: bool,
    /// the driver can send FILS discovery frames (6 GHz discovery)
    pub fils_discovery: bool,
    /// channel switch announcement
    pub csa: bool,
}

fn band_of_freq(mhz: f64) -> Option<&'static str> {
    if (2400.0..2500.0).contains(&mhz) {
        Some("2g")
    } else if (4900.0..5925.0).contains(&mhz) {
        Some("5g")
    } else if (5925.0..7125.0).contains(&mhz) {
        Some("6g")
    } else {
        None
    }
}

fn flush(cur: &mut BandCaps, c: &mut RadioCaps) {
    let b = std::mem::take(cur);
    if !b.band.is_empty() && !c.bands.iter().any(|x| x.band == b.band) {
        c.bands.push(b);
    }
}

/// Parse `iw phy <phy> info`.
pub fn parse_caps(text: &str) -> RadioCaps {
    let mut c = RadioCaps::default();
    let mut cur = BandCaps::default();
    let mut in_band = false;
    let mut in_modes = false;
    let mut in_freqs = false;
    // inside an "HE Iftypes:" / "EHT Iftypes:" block that includes AP
    let (mut he_ap, mut eht_ap) = (false, false);
    for l in text.lines() {
        let t = l.trim();
        let depth = l.len() - l.trim_start_matches('\t').len();
        if depth == 1 && t.starts_with("Band ") && t.ends_with(':') {
            flush(&mut cur, &mut c);
            in_band = true;
            in_freqs = false;
            he_ap = false;
            eht_ap = false;
            continue;
        }
        if depth == 1 && in_band {
            flush(&mut cur, &mut c);
            in_band = false;
            in_freqs = false;
        }
        if t.starts_with("Supported interface modes") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if let Some(m) = t.strip_prefix("* ") {
                if m.trim() == "AP" {
                    c.ap = true;
                }
                continue;
            }
            in_modes = false;
        }
        if t == "* channel_switch" {
            c.csa = true;
        }
        if t.contains("[ UNSOL_BCAST_PROBE_RESP ]") {
            c.unsol_probe = true;
        }
        if t.contains("[ FILS_DISCOVERY ]") {
            c.fils_discovery = true;
        }
        if !in_band {
            continue;
        }
        if let Some(v) = t.strip_prefix("HE Iftypes:") {
            he_ap = v.split(',').any(|x| x.trim() == "AP");
            eht_ap = false;
            cur.he |= he_ap;
            continue;
        }
        if let Some(v) = t.strip_prefix("EHT Iftypes:") {
            eht_ap = v.split(',').any(|x| x.trim() == "AP");
            he_ap = false;
            cur.eht |= eht_ap;
            continue;
        }
        if t == "HT20/HT40" {
            cur.ht40 = true;
        }
        if t.starts_with("VHT Capabilities") {
            cur.vht = true;
        }
        if t.starts_with("Supported Channel Width:") && t.contains("160 MHz") {
            cur.vht160 = true;
        }
        if he_ap {
            match t {
                "HE40/2.4GHz" => cur.he40 = true,
                "HE40/HE80/5GHz" => {
                    cur.he40 = true;
                    cur.he80 = true
                }
                "HE160/5GHz" => cur.he160 = true,
                _ => {}
            }
        }
        if eht_ap && t == "320MHz in 6GHz Supported" {
            cur.eht320 = true;
        }
        if t == "Frequencies:" {
            in_freqs = true;
            he_ap = false;
            eht_ap = false;
            continue;
        }
        if in_freqs {
            // "* 2412.0 MHz [1] (20.0 dBm) (no IR, radar detection)" or "* 5180 MHz [36] (disabled)"
            let Some(rest) = t.strip_prefix("* ") else {
                in_freqs = false;
                continue;
            };
            let Some((f, tail)) = rest.split_once(" MHz [") else {
                continue;
            };
            let Some((ch, flags)) = tail.split_once(']') else {
                continue;
            };
            let (Ok(f), Ok(ch)) = (f.trim().parse::<f64>(), ch.trim().parse::<i64>()) else {
                continue;
            };
            if let Some(b) = band_of_freq(f) {
                if cur.band.is_empty() {
                    cur.band = b.to_string();
                }
                if cur.band == b {
                    cur.channels.push(ChanInfo {
                        channel: ch,
                        freq: f.round() as i64,
                        usable: !(flags.contains("disabled") || flags.contains("no IR")),
                        radar: flags.contains("radar detection"),
                    });
                }
            }
        }
    }
    if in_band {
        flush(&mut cur, &mut c);
    }
    c
}

/// The generations as config tokens, oldest first.
pub const STANDARDS: &[&str] = &["n", "ac", "ax", "be"];

/// Position of a generation token in [`STANDARDS`] (unknown = 0).
pub fn std_rank(s: &str) -> usize {
    STANDARDS.iter().position(|x| *x == s).unwrap_or(0)
}

impl RadioCaps {
    pub fn band(&self, b: &str) -> Option<&BandCaps> {
        self.bands.iter().find(|x| x.band == b)
    }
    /// Can this radio run an access point on `band` at all (AP mode, the band, one usable channel; 6 GHz
    /// also needs HE)?
    pub fn ap_band(&self, b: &str) -> bool {
        self.ap
            && self
                .band(b)
                .is_some_and(|x| x.channels.iter().any(|c| c.usable) && (b != "6g" || x.he))
    }
    /// The newest generation the radio offers as an AP on `band` (`n`, `ac`, `ax`, `be`).
    pub fn max_standard(&self, b: &str) -> &'static str {
        let Some(x) = self.band(b) else { return "n" };
        if x.eht {
            "be"
        } else if x.he {
            "ax"
        } else if x.vht && b == "5g" {
            "ac"
        } else {
            "n"
        }
    }
    /// The widest channel (MHz) the radio carries on `band` with generation `std` (0 = none: 6 GHz
    /// without HE).
    pub fn max_width(&self, b: &str, std: &str) -> i64 {
        let Some(x) = self.band(b) else { return 20 };
        let he = matches!(std, "ax" | "be") && x.he;
        let eht = std == "be" && x.eht;
        if b == "6g" && !he {
            return 0; // nothing below HE exists on 6 GHz
        }
        let mut w = 20;
        if x.ht40 || (he && x.he40) {
            w = 40;
        }
        if b != "2g" {
            if (x.vht && std != "n") || (he && x.he80) {
                w = 80;
            }
            if (x.vht160 && std != "n") || (he && x.he160) {
                w = 160;
            }
            if b == "6g" && eht && x.eht320 {
                w = 320;
            }
        }
        w
    }
    /// Is the 20 MHz channel usable for an AP? `None` = the radio does not list it.
    pub fn usable(&self, b: &str, ch: i64) -> Option<bool> {
        self.band(b)?
            .channels
            .iter()
            .find(|c| c.channel == ch)
            .map(|c| c.usable)
    }
    /// One-line labels: generation (with 6E), bands, widest channel, WPA3, and why 6 GHz is unavailable.
    pub fn supports(&self) -> Vec<String> {
        if !self.ap {
            return vec!["no access point mode".into()];
        }
        let bands: Vec<&str> = ["2g", "5g", "6g"]
            .into_iter()
            .filter(|b| self.band(b).is_some())
            .collect();
        let best = bands
            .iter()
            .map(|b| self.max_standard(b))
            .max_by_key(|s| std_rank(s))
            .unwrap_or("n");
        let six = self.band("6g").is_some_and(|x| x.he);
        let mut o = vec![match (best, six) {
            ("be", _) => "Wi-Fi 7",
            ("ax", true) => "Wi-Fi 6E",
            ("ax", false) => "Wi-Fi 6",
            ("ac", _) => "Wi-Fi 5",
            _ => "Wi-Fi 4",
        }
        .to_string()];
        o.push(
            bands
                .iter()
                .map(|b| match *b {
                    "2g" => "2.4",
                    "5g" => "5",
                    _ => "6",
                })
                .collect::<Vec<_>>()
                .join(" / ")
                + " GHz",
        );
        let w = bands
            .iter()
            .map(|b| self.max_width(b, self.max_standard(b)))
            .max()
            .unwrap_or(20);
        o.push(format!("{w} MHz"));
        o.push("WPA3".into());
        if six && !self.ap_band("6g") {
            o.push("6 GHz blocked by the regulatory domain".into());
        }
        o
    }
}

/// What the installed hostapd was built with (its configuration keywords are in the binary).
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub struct HostapdCaps {
    pub installed: bool,
    pub version: String,
    /// CONFIG_IEEE80211AX
    pub ax: bool,
    /// CONFIG_IEEE80211BE
    pub be: bool,
    /// AP MLD (multi-link) support
    pub mld: bool,
}

impl HostapdCaps {
    /// Assume a full build (tests, fakes): nothing is cut by hostapd.
    pub fn full() -> Self {
        Self {
            installed: true,
            version: String::new(),
            ax: true,
            be: true,
            mld: true,
        }
    }
}

/// Look for configuration keywords in hostapd's binary (no hostapd option lists its build options).
pub fn hostapd_caps_of(bin: &[u8], version: &str) -> HostapdCaps {
    let has = |k: &[u8]| bin.windows(k.len()).any(|w| w == k);
    HostapdCaps {
        installed: !bin.is_empty(),
        version: version.to_string(),
        ax: has(b"he_oper_chwidth"),
        be: has(b"eht_oper_chwidth"),
        mld: has(b"mld_ap"),
    }
}

/// Probe the installed hostapd (its binary only: nothing is executed, so a wrapper or a stuck binary
/// cannot hang an apply). The version is the `hostapd vX.Y` banner compiled into it.
pub fn hostapd_caps(bin: &Path) -> HostapdCaps {
    let Ok(b) = std::fs::read(bin) else {
        return HostapdCaps::default();
    };
    hostapd_caps_of(&b, &banner_version(&b))
}

/// `2.12` from the `hostapd v2.12` banner in a binary (empty when absent).
pub fn banner_version(bin: &[u8]) -> String {
    let k = b"hostapd v";
    let Some(i) = bin.windows(k.len()).position(|w| w == k) else {
        return String::new();
    };
    bin[i + k.len()..]
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == b'.' || **c == b'-')
        .map(|c| *c as char)
        .collect()
}

/// `iw phy <phy> info` -> (AP mode supported, bands).
pub fn parse_iw_phy(text: &str) -> (bool, Vec<String>) {
    let c = parse_caps(text);
    (c.ap, c.bands.iter().map(|b| b.band.clone()).collect())
}

/// Wi-Fi radios of this machine (empty where there is no `/sys/class/ieee80211`).
pub fn radios() -> Vec<Radio> {
    let Ok(rd) = std::fs::read_dir("/sys/class/ieee80211") else {
        return Vec::new();
    };
    let mut phys: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    phys.sort_by_key(|p| {
        p.trim_start_matches("phy")
            .parse::<u32>()
            .unwrap_or(u32::MAX)
    });
    let mut out = Vec::new();
    for phy in phys {
        let mut ifaces: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                let on_phy = std::fs::read_link(e.path().join("phy80211"))
                    .ok()
                    .and_then(|p| p.file_name().map(|f| f.to_string_lossy() == phy.as_str()))
                    .unwrap_or(false);
                if on_phy {
                    ifaces.push(n);
                }
            }
        }
        ifaces.sort();
        let caps = Command::new("iw")
            .args(["phy", &phy, "info"])
            .output()
            .map(|o| parse_caps(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        out.push(Radio {
            phy,
            ifaces,
            ap: caps.ap,
            bands: caps.bands.iter().map(|b| b.band.clone()).collect(),
            supports: caps.supports(),
            caps,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORLD: &str = include_str!("testdata/iw-phy-hwsim-world.txt");
    const DE: &str = include_str!("testdata/iw-phy-hwsim-de.txt");
    const WIFI5: &str = include_str!("testdata/iw-phy-wifi5.txt");

    #[test]
    fn a_wifi7_radio_reports_every_band_generation_and_width() {
        let c = parse_caps(DE);
        assert!(c.ap && c.csa);
        assert_eq!(
            c.bands.iter().map(|b| b.band.as_str()).collect::<Vec<_>>(),
            ["2g", "5g", "6g"]
        );
        for b in ["2g", "5g", "6g"] {
            assert_eq!(c.max_standard(b), "be", "{b}");
        }
        assert_eq!(c.max_width("2g", "be"), 40);
        assert_eq!(c.max_width("5g", "ax"), 160);
        assert_eq!(c.max_width("6g", "ax"), 160);
        assert_eq!(c.max_width("6g", "be"), 320);
        assert_eq!(c.max_width("5g", "n"), 40);
        assert_eq!(c.max_width("6g", "n"), 0);
        // band-aware: 6 GHz channel 1 is not 2.4 GHz channel 1
        assert_eq!(c.band("6g").unwrap().channels[0].freq, 5955);
        assert_eq!(c.band("2g").unwrap().channels[0].freq, 2412);
        assert_eq!(c.usable("6g", 37), Some(true));
        assert_eq!(c.usable("6g", 229), Some(false), "DE ends LPI at 6425 MHz");
        assert_eq!(c.usable("5g", 52), Some(true));
        assert!(
            c.band("5g")
                .unwrap()
                .channels
                .iter()
                .find(|x| x.channel == 52)
                .unwrap()
                .radar
        );
        // hwsim has neither discovery feature: the renderer must not ask for one
        assert!(!c.unsol_probe && !c.fils_discovery);
        assert!(c.ap_band("6g"));
        assert_eq!(
            c.supports(),
            ["Wi-Fi 7", "2.4 / 5 / 6 GHz", "320 MHz", "WPA3"]
        );
    }

    #[test]
    fn the_world_domain_blocks_6ghz_and_says_so() {
        let c = parse_caps(WORLD);
        assert_eq!(c.usable("6g", 37), Some(false));
        assert_eq!(c.usable("5g", 36), Some(false), "no IR before a country is set");
        assert!(!c.ap_band("6g"));
        assert!(
            c.supports().iter().any(|s| s.contains("6 GHz blocked")),
            "{:?}",
            c.supports()
        );
    }

    #[test]
    fn a_wifi5_card_is_offered_wifi5_only() {
        let c = parse_caps(WIFI5);
        assert_eq!(c.max_standard("5g"), "ac");
        assert_eq!(c.max_standard("2g"), "n");
        assert!(c.band("6g").is_none() && !c.ap_band("6g"));
        assert_eq!(c.max_width("5g", "ac"), 160, "hwsim's VHT160");
        assert_eq!(c.max_width("5g", "n"), 40);
        assert_eq!(c.supports()[0], "Wi-Fi 5");
    }

    #[test]
    fn hostapd_build_options_are_read_from_the_binary() {
        let h = hostapd_caps_of(b"..ieee80211ax\0he_oper_chwidth\0..", "2.10");
        assert!(h.installed && h.ax && !h.be && !h.mld);
        let h = hostapd_caps_of(b"he_oper_chwidth\0eht_oper_chwidth\0mld_ap\0", "2.12");
        assert!(h.be && h.mld);
        assert!(!hostapd_caps_of(b"", "").installed);
        assert_eq!(banner_version(b"\0hostapd v2.12\nUser space"), "2.12");
        assert_eq!(banner_version(b"#!/bin/sh\nsleep 300\n"), "");
    }

    #[test]
    fn old_iw_output_without_decimals_still_parses() {
        let t = "Wiphy phy0\n\tBand 1:\n\t\tCapabilities: 0x1\n\t\t\tHT20/HT40\n\t\tFrequencies:\n\t\t\t* 2412 MHz [1] (20.0 dBm)\n\t\t\t* 2467 MHz [12] (disabled)\n\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n";
        let c = parse_caps(t);
        assert!(c.ap);
        assert_eq!(c.usable("2g", 1), Some(true));
        assert_eq!(c.usable("2g", 12), Some(false));
        assert_eq!(parse_iw_phy(t), (true, vec!["2g".to_string()]));
    }
}
