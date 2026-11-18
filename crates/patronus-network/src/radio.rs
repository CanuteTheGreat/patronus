//! Wi-Fi radios of this machine (`/sys/class/ieee80211` + `iw phy info`): which
//! radios can run an access point and on which bands. Shared by the per-device
//! Wi-Fi networks (USE=wifi-ap) and the guest network (USE=guest).

use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct Radio {
    pub phy: String,
    pub ifaces: Vec<String>,
    /// supports AP mode
    pub ap: bool,
    /// `2g` / `5g`
    pub bands: Vec<String>,
}

/// `iw phy <phy> info` -> (AP mode supported, bands).
pub fn parse_iw_phy(text: &str) -> (bool, Vec<String>) {
    let mut ap = false;
    let mut in_modes = false;
    let mut bands = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("Supported interface modes") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if let Some(m) = t.strip_prefix("* ") {
                if m.trim() == "AP" {
                    ap = true;
                }
                continue;
            }
            in_modes = false;
        }
        // "* 2412.0 MHz [1] (20.0 dBm)" inside the Frequencies list
        if let Some(f) = t.strip_prefix("* ") {
            if let Some(mhz) = f
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
            {
                let b = if (2400.0..2500.0).contains(&mhz) {
                    "2g"
                } else if (5000.0..5900.0).contains(&mhz) {
                    "5g"
                } else {
                    continue;
                };
                if !bands.contains(&b.to_string()) {
                    bands.push(b.to_string());
                }
            }
        }
    }
    (ap, bands)
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
        let (ap, bands) = Command::new("iw")
            .args(["phy", &phy, "info"])
            .output()
            .map(|o| parse_iw_phy(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or((false, Vec::new()));
        out.push(Radio {
            phy,
            ifaces,
            ap,
            bands,
        });
    }
    out
}

