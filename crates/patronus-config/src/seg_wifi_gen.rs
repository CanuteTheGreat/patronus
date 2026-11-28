//! Wi-Fi generation settings of one access point network (docs/WIFI-MODERN.md): which 802.11 generation the
//! radio runs (Wi-Fi 4 `n`, 5 `ac`, 6/6E `ax`, 7 `be`, or `auto` = the newest the radio AND the installed
//! hostapd support), BSS colouring, 6 GHz discovery frames and Wi-Fi 7 multi-link (MLO).
//!
//! Configuration only: what the radio can really do is probed at apply time (`patronus_network::radio`) and
//! the effective plan (asked for vs. what runs, and why) is reported in the status, never assumed here.
//! The rules that depend on the band and the security are checked here, so a 6 GHz network with WPA2 is
//! refused with an explanation when it is saved, not when hostapd fails at night.

use crate::seg::invalid;
use crate::seg_wifi_chan::{band_channels, band_widths, centre_of};
use patronus_core::Result;
use serde::{Deserialize, Serialize};

/// Documented defaults (the migration's column defaults are the same values; a test compares them).
pub const DEFAULT_STANDARD: &str = "auto";
pub const DEFAULT_BSS_COLOR: i64 = 0;
pub const DEFAULT_DISCOVERY: &str = "auto";
pub const DEFAULT_DISCOVERY_INTERVAL: i64 = 20;
pub const DEFAULT_MLO_LINKS: &str = "";

/// Generations, oldest first (the order `auto` climbs).
pub const STANDARDS: &[&str] = &["n", "ac", "ax", "be"];

/// Wi-Fi generation of one network.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GenSettings {
    /// `auto` (newest the radio + hostapd support), `n` (Wi-Fi 4), `ac` (Wi-Fi 5, 5 GHz), `ax` (Wi-Fi 6/6E),
    /// `be` (Wi-Fi 7)
    pub standard: String,
    /// HE BSS colour 1-63; 0 = derived from the network name (stable, differs between our own networks)
    pub bss_color: i64,
    /// 6 GHz discovery frames: `auto` (unsolicited probe responses when the driver can send them, else FILS
    /// discovery, else none), `probe`, `fils`, `off`
    pub discovery: String,
    /// time units (1.024 ms) between two discovery frames, 1-20 (802.11ax caps it at 20)
    pub discovery_interval: i64,
    /// Wi-Fi 7 multi-link: extra links of the same radio, `band/channel/width` comma separated
    /// (e.g. `6g/37/320,2g/6/20`); empty = one link
    pub mlo_links: String,
}

impl Default for GenSettings {
    fn default() -> Self {
        Self {
            standard: DEFAULT_STANDARD.into(),
            bss_color: DEFAULT_BSS_COLOR,
            discovery: DEFAULT_DISCOVERY.into(),
            discovery_interval: DEFAULT_DISCOVERY_INTERVAL,
            mlo_links: DEFAULT_MLO_LINKS.into(),
        }
    }
}

/// The same as optional API/UI input (absent = keep).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GenInput {
    #[serde(default)]
    pub standard: Option<String>,
    #[serde(default)]
    pub bss_color: Option<i64>,
    #[serde(default)]
    pub discovery: Option<String>,
    #[serde(default)]
    pub discovery_interval: Option<i64>,
    #[serde(default)]
    pub mlo_links: Option<String>,
}

/// One extra link of a multi-link access point.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Link {
    pub band: String,
    pub channel: i64,
    pub width: i64,
}

/// Human name of a band.
pub fn band_name(band: &str) -> &'static str {
    match band {
        "2g" => "2.4 GHz",
        "5g" => "5 GHz",
        "6g" => "6 GHz",
        _ => "?",
    }
}

/// Can `ch` at `width` be configured on `band` (fixed channel, not auto)?
pub fn channel_fits(band: &str, ch: i64, width: i64) -> bool {
    if !band_channels(band).contains(&ch) || !band_widths(band).contains(&width) {
        return false;
    }
    match (band, width) {
        (_, 20) => true,
        ("2g", 40) => true,
        ("5g", 40) => ch != 165,
        _ => centre_of(band, ch, width).is_some(),
    }
}

/// Parse `mlo_links` (`band/channel/width,...`).
pub fn parse_links(s: &str) -> Result<Vec<Link>> {
    let mut out: Vec<Link> = Vec::new();
    for t in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let p: Vec<&str> = t.split('/').map(str::trim).collect();
        let bad = || invalid(format!("multi-link link {t:?}: band/channel/width, e.g. 6g/37/320"));
        if p.len() != 3 {
            return Err(bad());
        }
        let band = p[0].to_string();
        if !["2g", "5g", "6g"].contains(&band.as_str()) {
            return Err(bad());
        }
        let channel: i64 = p[1].parse().map_err(|_| bad())?;
        let width: i64 = p[2].parse().map_err(|_| bad())?;
        if !channel_fits(&band, channel, width) {
            return Err(invalid(format!(
                "multi-link link {t:?}: channel {channel} cannot carry {width} MHz on {}",
                band_name(&band)
            )));
        }
        if out.iter().any(|l| l.band == band) {
            return Err(invalid(format!("multi-link: two links on {}", band_name(&band))));
        }
        out.push(Link { band, channel, width });
    }
    if out.len() > 2 {
        return Err(invalid("multi-link: at most two extra links (one per other band)"));
    }
    Ok(out)
}

impl GenSettings {
    pub fn merged(&self, i: &GenInput) -> GenSettings {
        let mut g = self.clone();
        if let Some(v) = &i.standard {
            g.standard = v.trim().to_string();
        }
        if let Some(v) = i.bss_color {
            g.bss_color = v;
        }
        if let Some(v) = &i.discovery {
            g.discovery = v.trim().to_string();
        }
        if let Some(v) = i.discovery_interval {
            g.discovery_interval = v;
        }
        if let Some(v) = &i.mlo_links {
            g.mlo_links = v
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(",");
        }
        g
    }

    /// Validate against the network's band, channel width and security.
    pub fn validate(&self, band: &str, width: i64, security: &str) -> Result<()> {
        if self.standard != "auto" && !STANDARDS.contains(&self.standard.as_str()) {
            return Err(invalid(format!(
                "standard {:?}: auto, n (Wi-Fi 4), ac (Wi-Fi 5), ax (Wi-Fi 6/6E) or be (Wi-Fi 7)",
                self.standard
            )));
        }
        match (band, self.standard.as_str()) {
            ("2g", "ac") => {
                return Err(invalid(
                    "standard ac (Wi-Fi 5) exists on 5 GHz only: use n, ax or be on 2.4 GHz",
                ))
            }
            ("6g", "n" | "ac") => {
                return Err(invalid(
                    "6 GHz carries Wi-Fi 6E (ax) and Wi-Fi 7 (be) only: Wi-Fi 4/5 devices cannot use it",
                ))
            }
            _ => {}
        }
        if width == 160 && self.standard == "n" {
            return Err(invalid("160 MHz needs Wi-Fi 5 or newer (standard ac, ax, be or auto)"));
        }
        if width == 320 && !matches!(self.standard.as_str(), "auto" | "be") {
            return Err(invalid("320 MHz is Wi-Fi 7 only (standard be or auto)"));
        }
        if band == "6g" && security != "wpa3" {
            return Err(invalid(SIX_GHZ_SECURITY));
        }
        if !(0..=63).contains(&self.bss_color) {
            return Err(invalid(format!(
                "BSS colour {}: 1 to 63, or 0 = automatic",
                self.bss_color
            )));
        }
        if !["auto", "probe", "fils", "off"].contains(&self.discovery.as_str()) {
            return Err(invalid("6 GHz discovery: auto, probe, fils or off"));
        }
        if !(1..=20).contains(&self.discovery_interval) {
            return Err(invalid(format!(
                "discovery interval {}: 1 to 20 time units",
                self.discovery_interval
            )));
        }
        let links = parse_links(&self.mlo_links)?;
        if !links.is_empty() {
            if links.iter().any(|l| l.band == band) {
                return Err(invalid(format!(
                    "multi-link: the network itself is already on {}; extra links go on the other bands",
                    band_name(band)
                )));
            }
            if !matches!(self.standard.as_str(), "auto" | "be") {
                return Err(invalid("multi-link (MLO) is Wi-Fi 7: standard be or auto"));
            }
            if security != "wpa3" {
                return Err(invalid(
                    "multi-link (MLO) needs WPA3 (SAE): Wi-Fi 7 multi-link devices and every 6 GHz link require it",
                ));
            }
        }
        Ok(())
    }

    pub fn links(&self) -> Vec<Link> {
        parse_links(&self.mlo_links).unwrap_or_default()
    }
}

/// Why a WPA2 network cannot go on 6 GHz, and what per-device credentials become there.
pub const SIX_GHZ_SECURITY: &str = "6 GHz allows WPA3 (SAE) only: WPA2 and the WPA2/WPA3 transition mode are not permitted there (802.11ax 6 GHz rules, Wi-Fi Alliance Wi-Fi 6E). Choose security wpa3. Per-device credentials keep working as WPA3-SAE passwords bound to each device's MAC; changing them restarts the access point, and a device without a known MAC joins through the enrolment secret first.";

#[cfg(test)]
mod tests {
    use super::*;

    fn g(f: impl FnOnce(&mut GenSettings)) -> GenSettings {
        let mut x = GenSettings::default();
        f(&mut x);
        x
    }

    #[test]
    fn defaults_are_valid_on_every_band() {
        for b in ["2g", "5g"] {
            GenSettings::default().validate(b, 20, "wpa2").unwrap();
        }
        GenSettings::default().validate("6g", 20, "wpa3").unwrap();
    }

    #[test]
    fn six_ghz_is_wpa3_only_and_says_why() {
        for sec in ["wpa2", "wpa2_wpa3"] {
            let e = GenSettings::default().validate("6g", 80, sec).unwrap_err().to_string();
            assert!(e.contains("WPA3") && e.contains("Per-device"), "{e}");
        }
        assert!(g(|x| x.standard = "ac".into()).validate("6g", 80, "wpa3").is_err());
        assert!(g(|x| x.standard = "n".into()).validate("6g", 20, "wpa3").is_err());
        assert!(g(|x| x.standard = "ax".into()).validate("6g", 160, "wpa3").is_ok());
    }

    #[test]
    fn standards_and_widths_must_fit_each_other() {
        assert!(g(|x| x.standard = "ac".into()).validate("2g", 20, "wpa2").is_err());
        assert!(g(|x| x.standard = "wifi9".into()).validate("5g", 20, "wpa2").is_err());
        assert!(g(|x| x.standard = "n".into()).validate("5g", 160, "wpa2").is_err());
        assert!(g(|x| x.standard = "ac".into()).validate("5g", 160, "wpa2").is_ok());
        assert!(g(|x| x.standard = "ax".into()).validate("6g", 320, "wpa3").is_err());
        assert!(g(|x| x.standard = "be".into()).validate("6g", 320, "wpa3").is_ok());
        assert!(g(|x| x.bss_color = 64).validate("5g", 20, "wpa2").is_err());
        assert!(g(|x| x.bss_color = 63).validate("5g", 20, "wpa2").is_ok());
        assert!(g(|x| x.discovery = "beacon".into()).validate("6g", 20, "wpa3").is_err());
        assert!(g(|x| x.discovery_interval = 21).validate("6g", 20, "wpa3").is_err());
        assert!(g(|x| x.discovery_interval = 0).validate("6g", 20, "wpa3").is_err());
    }

    #[test]
    fn multi_link_rules() {
        let l = |s: &str| g(|x| x.mlo_links = s.into());
        assert_eq!(
            parse_links("6g/37/320, 2g/6/20").unwrap(),
            vec![
                Link { band: "6g".into(), channel: 37, width: 320 },
                Link { band: "2g".into(), channel: 6, width: 20 }
            ]
        );
        l("6g/37/320").validate("5g", 80, "wpa3").unwrap();
        // WPA3 only, Wi-Fi 7 only, other bands only, sane links only
        assert!(l("6g/37/320").validate("5g", 80, "wpa2").unwrap_err().to_string().contains("WPA3"));
        let ax = GenSettings { standard: "ax".into(), ..l("6g/37/160") };
        assert!(ax.validate("5g", 80, "wpa3").is_err());
        assert!(l("5g/36/80").validate("5g", 80, "wpa3").is_err());
        for bad in ["6g/37", "6g/36/20", "6g/229/160", "5g/165/40", "7g/1/20", "6g/37/320,6g/5/20", "x"] {
            assert!(parse_links(bad).is_err(), "{bad}");
        }
        assert!(parse_links("").unwrap().is_empty());
    }

    #[test]
    fn merge_keeps_absent_values_and_normalises_links() {
        let d = GenSettings::default();
        assert_eq!(d.merged(&GenInput::default()), d);
        let m = d.merged(&GenInput {
            standard: Some("be".into()),
            mlo_links: Some(" 6g/37/320 , ".into()),
            ..Default::default()
        });
        assert_eq!((m.standard.as_str(), m.mlo_links.as_str()), ("be", "6g/37/320"));
    }
}
