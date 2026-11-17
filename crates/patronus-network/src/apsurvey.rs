//! Channel survey of an access point's radios (read only): how busy each channel is (`iw dev <if> survey dump`),
//! which other networks are around (`iw dev <if> scan dump`, or a fresh `scan ap-force` when asked) and the least
//! crowded channel to suggest. A survey never restarts a radio; a fresh scan takes the radio off its channel for a
//! few tens of milliseconds at a time (clients stay connected, traffic pauses briefly).

use crate::apwifi::Paths;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::process::Command;

/// Channel number of a frequency (2.4 GHz 1..14, 5 GHz).
pub fn channel(freq: u32) -> Option<u32> {
    match freq {
        2484 => Some(14),
        2412..=2472 => Some((freq - 2407) / 5),
        5160..=5885 => Some((freq - 5000) / 5),
        _ => None,
    }
}

/// One entry of `iw dev <if> survey dump`.
pub fn parse_survey(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur: Option<serde_json::Map<String, Value>> = None;
    let num = |s: &str| {
        s.split_whitespace()
            .next()
            .and_then(|n| n.parse::<i64>().ok())
    };
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with("Survey data from") {
            if let Some(c) = cur.take() {
                out.push(Value::Object(c));
            }
            cur = Some(serde_json::Map::new());
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let Some((k, v)) = t.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "frequency" => {
                if let Some(f) = num(v) {
                    m.insert("freq".into(), json!(f));
                    if let Some(c) = channel(f as u32) {
                        m.insert("channel".into(), json!(c));
                    }
                    m.insert("in_use".into(), json!(v.contains("[in use]")));
                }
            }
            "noise" => {
                if let Some(n) = num(v) {
                    m.insert("noise_dbm".into(), json!(n));
                }
            }
            "channel active time" => {
                if let Some(n) = num(v) {
                    m.insert("active_ms".into(), json!(n));
                }
            }
            "channel busy time" => {
                if let Some(n) = num(v) {
                    m.insert("busy_ms".into(), json!(n));
                }
            }
            _ => {}
        }
    }
    if let Some(c) = cur {
        out.push(Value::Object(c));
    }
    for e in out.iter_mut() {
        if let (Some(a), Some(b)) = (e["active_ms"].as_i64(), e["busy_ms"].as_i64()) {
            if a > 0 {
                e["busy_pct"] = json!(((b * 100) / a).min(100));
            }
        }
    }
    out.retain(|e| e.get("freq").is_some());
    out
}

/// Networks in `iw dev <if> scan [dump]` output.
pub fn parse_scan(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur: Option<serde_json::Map<String, Value>> = None;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("BSS ") {
            if let Some(c) = cur.take() {
                out.push(Value::Object(c));
            }
            let bssid: String = rest
                .chars()
                .take(17)
                .collect::<String>()
                .to_ascii_lowercase();
            let mut m = serde_json::Map::new();
            m.insert("bssid".into(), json!(bssid));
            cur = Some(m);
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let t = l.trim();
        if let Some(v) = t.strip_prefix("freq:") {
            if let Some(f) = v
                .trim()
                .split('.')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
            {
                m.insert("freq".into(), json!(f));
                if let Some(c) = channel(f) {
                    m.insert("channel".into(), json!(c));
                }
            }
        } else if let Some(v) = t.strip_prefix("signal:") {
            if let Some(s) = v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<f64>().ok())
            {
                m.insert("signal_dbm".into(), json!(s.round() as i64));
            }
        } else if let Some(v) = t.strip_prefix("SSID:") {
            if !m.contains_key("ssid") {
                m.insert("ssid".into(), json!(v.trim()));
            }
        }
    }
    if let Some(c) = cur {
        out.push(Value::Object(c));
    }
    out.retain(|e| e.get("freq").is_some());
    out
}

/// 5 GHz channels without a radar check (DFS) in most regulatory domains.
const NON_DFS5: &[u32] = &[36, 40, 44, 48, 149, 153, 157, 161, 165];

/// 80 MHz block a 5 GHz channel belongs to (first channel of the block).
fn block80(c: u32) -> u32 {
    if c >= 149 {
        149 + ((c - 149) / 16) * 16
    } else {
        36 + ((c - 36) / 16) * 16
    }
}

/// The least crowded channel of a band: per candidate, busy % of that channel (when surveyed) plus 10 points per
/// neighbouring network that overlaps it (2.4 GHz: within 4 channels; 5 GHz: same 80 MHz block), stronger ones
/// (above -70 dBm) counting double. 2.4 GHz candidates are 1, 6 and 11; 5 GHz candidates the non-DFS channels.
pub fn suggest(band: &str, survey: &[Value], scan: &[Value]) -> Option<Value> {
    let cands: Vec<u32> = if band == "24" {
        vec![1, 6, 11]
    } else {
        NON_DFS5.to_vec()
    };
    let busy: BTreeMap<u32, i64> = survey
        .iter()
        .filter_map(|s| Some((s["channel"].as_u64()? as u32, s["busy_pct"].as_i64()?)))
        .collect();
    let mut best: Option<(i64, u32, i64, usize)> = None;
    for c in cands {
        let neigh: Vec<&Value> = scan
            .iter()
            .filter(|n| {
                let Some(nc) = n["channel"].as_u64().map(|x| x as u32) else {
                    return false;
                };
                if band == "24" {
                    nc <= 14 && nc.abs_diff(c) < 5
                } else {
                    nc > 14 && block80(nc) == block80(c)
                }
            })
            .collect();
        let weight: i64 = neigh
            .iter()
            .map(|n| {
                if n["signal_dbm"].as_i64().unwrap_or(-90) > -70 {
                    20
                } else {
                    10
                }
            })
            .sum();
        let b = busy.get(&c).copied().unwrap_or(0);
        let score = b + weight;
        if best.is_none_or(|(s, ..)| score < s) {
            best = Some((score, c, b, neigh.len()));
        }
    }
    best.map(|(score, c, b, n)| {
        json!({
            "channel": c,
            "score": score,
            "busy_pct": b,
            "neighbours": n,
            "reason": format!("{n} neighbouring network(s) overlap it, {b}% busy when surveyed"),
        })
    })
}

fn iw(args: &[&str]) -> String {
    Command::new("iw")
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Survey every running radio. `fresh` = start a new scan (`scan ap-force`) instead of reading the last results.
pub fn survey(p: &Paths, fresh: bool) -> Value {
    let mut radios = Vec::new();
    let own: Vec<String> = crate::apwifi::bss_interfaces(&p.run)
        .iter()
        .filter_map(|i| {
            std::fs::read_to_string(p.net.join(i).join("address"))
                .ok()
                .map(|s| s.trim().to_ascii_lowercase())
        })
        .collect();
    for (band, file) in [("5", "ap5.conf"), ("24", "ap24.conf")] {
        let Ok(t) = std::fs::read_to_string(p.run.join(file)) else {
            continue;
        };
        let Some(first) = t.lines().find_map(|l| l.strip_prefix("interface=")) else {
            continue;
        };
        let sv = parse_survey(&iw(&["dev", first, "survey", "dump"]));
        let raw = if fresh {
            iw(&["dev", first, "scan", "ap-force"])
        } else {
            iw(&["dev", first, "scan", "dump"])
        };
        let mut scan = parse_scan(&raw);
        scan.retain(|n| !own.iter().any(|o| Some(o.as_str()) == n["bssid"].as_str()));
        scan.retain(|n| {
            let c = n["channel"].as_u64().unwrap_or(0);
            if band == "24" {
                c <= 14
            } else {
                c > 14
            }
        });
        let current = sv
            .iter()
            .find(|s| s["in_use"] == true)
            .and_then(|s| s["channel"].as_u64());
        radios.push(json!({
            "band": band,
            "interface": first,
            "current_channel": current,
            "channels": sv,
            "neighbours": scan,
            "suggestion": suggest(band, &sv, &scan),
        }));
    }
    json!({
        "radios": radios,
        "fresh": fresh,
        "note": if radios.is_empty() { "no Wi-Fi radio is broadcasting right now: nothing to survey" } else { "" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SURVEY: &str = "Survey data from wl24-p\n\tfrequency:\t\t\t2412 MHz\n\tnoise:\t\t\t\t-95 dBm\n\tchannel active time:\t\t1000 ms\n\tchannel busy time:\t\t600 ms\nSurvey data from wl24-p\n\tfrequency:\t\t\t2437 MHz [in use]\n\tnoise:\t\t\t\t-96 dBm\n\tchannel active time:\t\t2000 ms\n\tchannel busy time:\t\t200 ms\nSurvey data from wl24-p\n\tfrequency:\t\t\t2462 MHz\n\tchannel active time:\t\t1000 ms\n\tchannel busy time:\t\t100 ms\n";
    const SCAN: &str = "BSS 94:83:c4:00:00:01(on wl24-p)\n\tfreq: 2412.0\n\tsignal: -48.00 dBm\n\tSSID: Neighbour A\nBSS 94:83:c4:00:00:02(on wl24-p) -- associated\n\tfreq: 2417\n\tsignal: -80.00 dBm\n\tSSID: Neighbour B\nBSS aa:aa:aa:00:00:03(on wl24-p)\n\tfreq: 2462\n\tsignal: -85.00 dBm\n\tSSID: \nBSS aa:aa:aa:00:00:04(on wl5-p)\n\tfreq: 5180\n\tsignal: -60.00 dBm\n\tSSID: Five\n";

    #[test]
    fn survey_and_scan_parse() {
        let s = parse_survey(SURVEY);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0]["channel"], 1);
        assert_eq!(s[0]["busy_pct"], 60);
        assert_eq!(s[1]["in_use"], true);
        assert_eq!(s[1]["busy_pct"], 10);
        assert_eq!(s[0]["noise_dbm"], -95);
        let n = parse_scan(SCAN);
        assert_eq!(n.len(), 4);
        assert_eq!(n[0]["bssid"], "94:83:c4:00:00:01");
        assert_eq!(n[0]["channel"], 1);
        assert_eq!(n[0]["signal_dbm"], -48);
        assert_eq!(n[2]["ssid"], "");
        assert_eq!(n[3]["channel"], 36);
        assert_eq!(channel(2484), Some(14));
        assert_eq!(channel(5745), Some(149));
        assert_eq!(channel(900), None);
    }

    #[test]
    fn suggestion_prefers_the_quiet_channel() {
        let s = parse_survey(SURVEY);
        let n = parse_scan(SCAN);
        let g = suggest("24", &s, &n).unwrap();
        // 1: 60 % + two neighbours; 6: 10 % + none in range (2417 is 5 channels away from 6? no: ch 2 -> |2-6| = 4)
        // 11: 10 % + one weak neighbour -> 6 wins with 10 + 10 = 20 vs 11's 10 + 10 = 20 -> first best kept (6)
        assert_eq!(g["channel"], 6, "{g}");
        let five = suggest("5", &[], &n).unwrap();
        assert_ne!(
            five["channel"], 36,
            "36 shares its 80 MHz block with a -60 dBm neighbour: {five}"
        );
        assert!(NON_DFS5.contains(&(five["channel"].as_u64().unwrap() as u32)));
        assert_eq!(suggest("24", &[], &[]).unwrap()["channel"], 1);
    }
}
