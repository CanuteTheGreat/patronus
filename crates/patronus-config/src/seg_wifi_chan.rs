//! Automatic Wi-Fi channel choice, settings and measured state (docs/WIFI-AUTO-CHANNEL.md).
//!
//! `seg_wifi_networks.channel = 0` is "auto": `patronus-network::wifichan` measures every candidate
//! channel the same way, picks the quietest at start, and re-checks nightly. This module holds what is
//! configuration (the typed [`ChanSettings`] columns, validated here, defaults documented here) and the
//! measured side (the channel a radio is on and why, plus its history; both in tables that are NOT
//! configuration: a rollback or a restore never rewinds them).

use crate::seg::{db, invalid, now};
use crate::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Documented defaults (the migration's column defaults are the same numbers; a test compares them).
pub const DEFAULT_WIDTH: i64 = 20;
pub const DEFAULT_RECHECK: bool = true;
pub const DEFAULT_TIME: &str = "03:30";
pub const DEFAULT_HYST: i64 = 20;
pub const DEFAULT_MIN_GAIN: i64 = 10;
pub const DEFAULT_CONFIRM: i64 = 3;
pub const DEFAULT_CONFIRM_GAP: i64 = 300;
pub const DEFAULT_CSA: &str = "auto";
pub const DEFAULT_CSA_COUNT: i64 = 10;
pub const DEFAULT_ROUNDS: i64 = 3;
pub const DEFAULT_DWELL: i64 = 105;
pub const DEFAULT_BSS_COST: i64 = 2;
pub const DEFAULT_MIN_SIGNAL: i64 = -90;
pub const DEFAULT_HISTORY: i64 = 200;

/// The tuning of the automatic channel choice of one network.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChanSettings {
    /// candidate channels, comma separated; empty = the band's default list (see [`default_candidates`])
    pub chanlist: String,
    /// channel width in MHz: 20, 40, 80/160 (5 and 6 GHz), 320 (6 GHz only)
    pub width: i64,
    /// nightly re-check of an automatic channel
    pub recheck: bool,
    /// `HH:MM` local time of the nightly re-check; empty = never
    pub recheck_time: String,
    /// a move needs the other channel's score at least this many percent lower
    pub hysteresis: i64,
    /// ... and at least this many points lower
    pub min_gain: i64,
    /// samples (that all name the same better channel) needed before a move
    pub confirm: i64,
    /// seconds between those samples
    pub confirm_gap: i64,
    /// `auto` = channel switch announcement when the driver can, `off` = always restart onto the new channel
    pub csa: String,
    /// beacons the switch is announced for
    pub csa_count: i64,
    /// scans of each candidate channel per sample
    pub rounds: i64,
    /// milliseconds of each scan
    pub dwell: i64,
    /// score points for every other access point heard on the channel
    pub bss_cost: i64,
    /// dBm: weaker neighbours are ignored
    pub min_signal: i64,
    /// history entries kept
    pub history: i64,
}

impl Default for ChanSettings {
    fn default() -> Self {
        Self {
            chanlist: String::new(),
            width: DEFAULT_WIDTH,
            recheck: DEFAULT_RECHECK,
            recheck_time: DEFAULT_TIME.into(),
            hysteresis: DEFAULT_HYST,
            min_gain: DEFAULT_MIN_GAIN,
            confirm: DEFAULT_CONFIRM,
            confirm_gap: DEFAULT_CONFIRM_GAP,
            csa: DEFAULT_CSA.into(),
            csa_count: DEFAULT_CSA_COUNT,
            rounds: DEFAULT_ROUNDS,
            dwell: DEFAULT_DWELL,
            bss_cost: DEFAULT_BSS_COST,
            min_signal: DEFAULT_MIN_SIGNAL,
            history: DEFAULT_HISTORY,
        }
    }
}

/// The same settings as optional API/UI input (absent = keep the old value, or the default for a new network).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChanInput {
    #[serde(default)]
    pub chanlist: Option<String>,
    #[serde(default)]
    pub width: Option<i64>,
    #[serde(default)]
    pub recheck: Option<bool>,
    #[serde(default)]
    pub recheck_time: Option<String>,
    #[serde(default)]
    pub hysteresis: Option<i64>,
    #[serde(default)]
    pub min_gain: Option<i64>,
    #[serde(default)]
    pub confirm: Option<i64>,
    #[serde(default)]
    pub confirm_gap: Option<i64>,
    #[serde(default)]
    pub csa: Option<String>,
    #[serde(default)]
    pub csa_count: Option<i64>,
    #[serde(default)]
    pub rounds: Option<i64>,
    #[serde(default)]
    pub dwell: Option<i64>,
    #[serde(default)]
    pub bss_cost: Option<i64>,
    #[serde(default)]
    pub min_signal: Option<i64>,
    #[serde(default)]
    pub history: Option<i64>,
}

fn range(name: &str, v: i64, lo: i64, hi: i64) -> Result<i64> {
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        Err(invalid(format!("{name} {v}: {lo} to {hi}")))
    }
}

/// Every 20 MHz channel Patronus will configure on a band.
pub fn band_channels(band: &str) -> Vec<i64> {
    match band {
        "2g" => (1..=13).collect(),
        "5g" => (36..=64)
            .step_by(4)
            .chain((100..=144).step_by(4))
            .chain((149..=165).step_by(4))
            .collect(),
        // 6 GHz (U-NII-5..8): 20 MHz channels 1, 5, ... 233
        "6g" => (1..=233).step_by(4).collect(),
        _ => Vec::new(),
    }
}

/// First channel of the 80 MHz block that holds `c` (5 GHz), `None` for 165.
pub fn block80_start(c: i64) -> Option<i64> {
    [36, 52, 100, 116, 132, 149]
        .into_iter()
        .find(|b| c >= *b && c <= *b + 12)
}

/// The 20 MHz channels covered by a primary channel at a width (2.4 GHz 40 MHz = the primary and its
/// pair above or below; 5 GHz 40/80 = the aligned block).
pub fn block_of(band: &str, c: i64, width: i64) -> Vec<i64> {
    match (band, width) {
        ("5g", 160) => match [36, 100].into_iter().find(|b| c >= *b && c <= *b + 28) {
            Some(b) => (0..8).map(|i| b + i * 4).collect(),
            None => Vec::new(),
        },
        ("6g", 20) => vec![c],
        ("6g", 40 | 80 | 160 | 320) => block6(c, width),
        ("5g", 80) => match block80_start(c) {
            Some(b) => (0..4).map(|i| b + i * 4).collect(),
            None => vec![c],
        },
        ("5g", 40) => {
            let lower = ht40_plus(c);
            if lower {
                vec![c, c + 4]
            } else {
                vec![c - 4, c]
            }
        }
        ("2g", 40) => {
            if c <= 7 {
                vec![c, c + 4]
            } else {
                vec![c - 4, c]
            }
        }
        _ => vec![c],
    }
}

/// 6 GHz block of a primary channel: aligned groups of `width / 20` channels; 320 MHz uses the 320-1
/// channelization (centres 31, 95, 159) and 320-2 (centre 191) for the channels above 189. Empty when the
/// block would run past channel 233.
fn block6(c: i64, width: i64) -> Vec<i64> {
    if !(1..=233).contains(&c) || (c - 1) % 4 != 0 {
        return Vec::new();
    }
    let n = width / 20;
    let start = if width == 320 {
        match c {
            1..=189 => (c - 1) / 64 * 64 + 1,
            193..=221 => 161,
            _ => return Vec::new(),
        }
    } else {
        (c - 1) / (4 * n) * (4 * n) + 1
    };
    let v: Vec<i64> = (0..n).map(|i| start + i * 4).collect();
    if *v.last().unwrap_or(&999) > 233 {
        return Vec::new();
    }
    v
}

/// Centre channel index of a primary channel's block at a width (`*_oper_centr_freq_seg0_idx`), `None` when the
/// channel cannot carry that width.
pub fn centre_of(band: &str, c: i64, width: i64) -> Option<i64> {
    let b = block_of(band, c, width);
    if b.is_empty() || (width >= 40 && b.len() as i64 != width / 20) {
        return None;
    }
    Some((b[0] + b[b.len() - 1]) / 2)
}

/// 6 GHz global operating class of a channel width (802.11 Annex E: 131-134, 137).
pub fn op_class_6g(width: i64) -> Option<i64> {
    match width {
        20 => Some(131),
        40 => Some(132),
        80 => Some(133),
        160 => Some(134),
        320 => Some(137),
        _ => None,
    }
}

/// 6 GHz preferred scanning channel (5, 21, 37, ... 229): clients look for access points here first.
pub fn is_psc(c: i64) -> bool {
    (5..=229).contains(&c) && (c - 5) % 16 == 0
}

/// Channel widths a band can carry (MHz).
pub fn band_widths(band: &str) -> &'static [i64] {
    match band {
        "2g" => &[20, 40],
        "5g" => &[20, 40, 80, 160],
        "6g" => &[20, 40, 80, 160, 320],
        _ => &[],
    }
}

/// 5 GHz: is `c` the lower channel of its 40 MHz pair (secondary above = HT40+)?
pub fn ht40_plus(c: i64) -> bool {
    matches!(
        c,
        36 | 44 | 52 | 60 | 100 | 108 | 116 | 124 | 132 | 140 | 149 | 157
    )
}

/// The channels tried when `chanlist` is empty: 2.4 GHz 1/6/11 (1/6 at 40 MHz), 5 GHz the non-radar
/// channels (the owner's list can add radar channels; hostapd then waits out the channel availability
/// check). At 80 MHz one primary per block; 165 cannot carry 40/80.
pub fn default_candidates(band: &str, width: i64) -> Vec<i64> {
    match (band, width) {
        ("2g", 40) => vec![1, 6, 11],
        ("2g", _) => vec![1, 6, 11],
        ("5g", 80) => vec![36, 149],
        ("5g", 40) => vec![36, 44, 149, 157],
        ("5g", 160) => vec![36],
        ("5g", _) => vec![36, 40, 44, 48, 149, 153, 157, 161, 165],
        // 6 GHz: the preferred scanning channels, one per block at the width
        ("6g", w) => {
            let mut seen: Vec<i64> = Vec::new();
            let mut out = Vec::new();
            for c in band_channels("6g").into_iter().filter(|c| is_psc(*c)) {
                if let Some(ctr) = centre_of("6g", c, w) {
                    if !seen.contains(&ctr) {
                        seen.push(ctr);
                        out.push(c);
                    }
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// Parse a channel list (`1,6,11`; spaces allowed); each must be a real channel of the band and, at 40/80
/// MHz, one that can carry that width.
pub fn parse_chanlist(band: &str, width: i64, s: &str) -> Result<Vec<i64>> {
    let all = band_channels(band);
    let mut out: Vec<i64> = Vec::new();
    for t in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let c: i64 = t
            .parse()
            .map_err(|_| invalid(format!("channel list {s:?}: {t:?} is not a channel")))?;
        if !all.contains(&c) {
            return Err(invalid(format!(
                "channel list: {c} is not a {band} channel"
            )));
        }
        if band == "5g" && width >= 40 && c == 165 {
            return Err(invalid("channel list: 165 cannot carry 40 or 80 MHz"));
        }
        if band == "5g" && width == 80 && block80_start(c).is_none() {
            return Err(invalid(format!("channel list: {c} is in no 80 MHz block")));
        }
        if (band == "6g" || width == 160) && centre_of(band, c, width).is_none() {
            return Err(invalid(format!(
                "channel list: {c} is in no {width} MHz block"
            )));
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    if out.len() > 30 {
        return Err(invalid("channel list: at most 30 channels"));
    }
    Ok(out)
}

impl ChanSettings {
    /// Old settings + input, validated for `band`.
    pub fn merged(&self, band: &str, i: &ChanInput) -> Result<ChanSettings> {
        let mut c = self.clone();
        if let Some(v) = &i.chanlist {
            c.chanlist = v
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join(",");
        }
        if let Some(v) = i.width {
            c.width = v;
        }
        if let Some(v) = i.recheck {
            c.recheck = v;
        }
        if let Some(v) = &i.recheck_time {
            c.recheck_time = v.trim().to_string();
        }
        if let Some(v) = i.hysteresis {
            c.hysteresis = v;
        }
        if let Some(v) = i.min_gain {
            c.min_gain = v;
        }
        if let Some(v) = i.confirm {
            c.confirm = v;
        }
        if let Some(v) = i.confirm_gap {
            c.confirm_gap = v;
        }
        if let Some(v) = &i.csa {
            c.csa = v.clone();
        }
        if let Some(v) = i.csa_count {
            c.csa_count = v;
        }
        if let Some(v) = i.rounds {
            c.rounds = v;
        }
        if let Some(v) = i.dwell {
            c.dwell = v;
        }
        if let Some(v) = i.bss_cost {
            c.bss_cost = v;
        }
        if let Some(v) = i.min_signal {
            c.min_signal = v;
        }
        if let Some(v) = i.history {
            c.history = v;
        }
        c.validate(band)?;
        Ok(c)
    }

    pub fn validate(&self, band: &str) -> Result<()> {
        if !band_widths(band).contains(&self.width) {
            return Err(invalid(format!(
                "width {} MHz for band {band}: 20 or 40 (80 and 160 on 5 and 6 GHz, 320 on 6 GHz only)",
                self.width
            )));
        }
        parse_chanlist(band, self.width, &self.chanlist)?;
        if !self.recheck_time.is_empty() {
            let ok = self.recheck_time.split_once(':').is_some_and(|(h, m)| {
                h.len() == 2
                    && m.len() == 2
                    && h.parse::<u32>().is_ok_and(|h| h < 24)
                    && m.parse::<u32>().is_ok_and(|m| m < 60)
            });
            if !ok {
                return Err(invalid(format!(
                    "re-check time {:?}: HH:MM or empty",
                    self.recheck_time
                )));
            }
        }
        if self.csa != "auto" && self.csa != "off" {
            return Err(invalid("channel switch: auto or off"));
        }
        range("hysteresis", self.hysteresis, 0, 90)?;
        range("minimum gain", self.min_gain, 0, 100)?;
        range("confirm samples", self.confirm, 1, 10)?;
        range("confirm gap (s)", self.confirm_gap, 0, 3600)?;
        range("switch count (beacons)", self.csa_count, 1, 50)?;
        range("scan rounds", self.rounds, 1, 20)?;
        range("scan dwell (ms)", self.dwell, 20, 500)?;
        range("neighbour cost", self.bss_cost, 0, 20)?;
        range("minimum signal (dBm)", self.min_signal, -100, -30)?;
        range("history entries", self.history, 10, 5000)?;
        Ok(())
    }

    /// The candidate channels (`chanlist`, or the band default for the width).
    pub fn candidates(&self, band: &str) -> Vec<i64> {
        match parse_chanlist(band, self.width, &self.chanlist) {
            Ok(v) if !v.is_empty() => v,
            _ => default_candidates(band, self.width),
        }
    }
}

// ---------------------------------------------------------------------------
// measured state and history
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChanState {
    pub network_id: i64,
    pub channel: i64,
    pub width: i64,
    pub since: i64,
    pub reason: String,
    /// JSON array of `{channel, score, busy, neighbours}` of the last decision
    pub candidates: serde_json::Value,
    pub csa_capable: Option<bool>,
    pub last_check: Option<i64>,
    pub last_day: Option<i64>,
    pub requested_at: Option<i64>,
}

pub async fn get_state(store: &ConfigStore, network_id: i64) -> Result<Option<ChanState>> {
    let r = sqlx::query("SELECT * FROM seg_wifi_chan_state WHERE network_id = ?")
        .bind(network_id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read channel state"))?;
    Ok(r.map(|r| ChanState {
        network_id: r.get("network_id"),
        channel: r.get("channel"),
        width: r.get("width"),
        since: r.get("since"),
        reason: r.get("reason"),
        candidates: serde_json::from_str(&r.get::<String, _>("candidates"))
            .unwrap_or(serde_json::Value::Array(vec![])),
        csa_capable: r.get::<Option<i64>, _>("csa_capable").map(|v| v != 0),
        last_check: r.get("last_check"),
        last_day: r.get("last_day"),
        requested_at: r.get("requested_at"),
    }))
}

/// Record the channel a radio is on (keeps the check bookkeeping of an existing row).
pub async fn set_channel(
    store: &ConfigStore,
    network_id: i64,
    channel: i64,
    width: i64,
    reason: &str,
    candidates: &serde_json::Value,
    csa_capable: Option<bool>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO seg_wifi_chan_state (network_id, channel, width, since, reason, candidates, csa_capable)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(network_id) DO UPDATE SET channel=excluded.channel, width=excluded.width, since=excluded.since,
           reason=excluded.reason, candidates=excluded.candidates,
           csa_capable=COALESCE(excluded.csa_capable, seg_wifi_chan_state.csa_capable)",
    )
    .bind(network_id)
    .bind(channel)
    .bind(width)
    .bind(now())
    .bind(reason)
    .bind(candidates.to_string())
    .bind(csa_capable.map(|b| b as i64))
    .execute(store.pool()?)
    .await
    .map_err(db("write channel state"))?;
    Ok(())
}

/// Update the last decision's numbers and reason without changing the channel (a re-check that stayed).
pub async fn set_decision(
    store: &ConfigStore,
    network_id: i64,
    reason: &str,
    candidates: &serde_json::Value,
    csa_capable: Option<bool>,
) -> Result<()> {
    sqlx::query(
        "UPDATE seg_wifi_chan_state SET reason=?, candidates=?, csa_capable=COALESCE(?, csa_capable) WHERE network_id=?",
    )
    .bind(reason)
    .bind(candidates.to_string())
    .bind(csa_capable.map(|b| b as i64))
    .bind(network_id)
    .execute(store.pool()?)
    .await
    .map_err(db("write channel state"))?;
    Ok(())
}

/// Drop the state and history of networks that no longer exist (the tables carry no foreign key, so a
/// rollback that re-creates network rows keeps them; the applier prunes after a delete has stuck).
pub async fn prune_orphans(store: &ConfigStore) -> Result<()> {
    for t in ["seg_wifi_chan_state", "seg_wifi_chan_history"] {
        sqlx::query(&format!(
            "DELETE FROM {t} WHERE network_id NOT IN (SELECT id FROM seg_wifi_networks)"
        ))
        .execute(store.pool()?)
        .await
        .map_err(db("prune channel state"))?;
    }
    Ok(())
}

pub async fn clear_state(store: &ConfigStore, network_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM seg_wifi_chan_state WHERE network_id = ?")
        .bind(network_id)
        .execute(store.pool()?)
        .await
        .map_err(db("clear channel state"))?;
    Ok(())
}

/// A check has run: the nightly one of `day` (days since the epoch of the local date), or a requested one (`None`).
pub async fn mark_checked(store: &ConfigStore, network_id: i64, day: Option<i64>) -> Result<()> {
    sqlx::query(
        "UPDATE seg_wifi_chan_state SET last_check=?, last_day=COALESCE(?, last_day), requested_at=NULL WHERE network_id=?",
    )
    .bind(now())
    .bind(day)
    .bind(network_id)
    .execute(store.pool()?)
    .await
    .map_err(db("write channel check"))?;
    Ok(())
}

/// "Re-check now" from the API/UI: the channel service picks it up within seconds.
pub async fn request_recheck(store: &ConfigStore, network_id: i64) -> Result<()> {
    let n = sqlx::query("UPDATE seg_wifi_chan_state SET requested_at=? WHERE network_id=?")
        .bind(now())
        .bind(network_id)
        .execute(store.pool()?)
        .await
        .map_err(db("request re-check"))?
        .rows_affected();
    if n == 0 {
        return Err(Error::Config(format!(
            "Invalid request: network {network_id} has no automatic channel yet (fixed channel, disabled or not started)"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChanEvent {
    pub id: i64,
    pub at: i64,
    pub event: String,
    pub channel: Option<i64>,
    pub score: Option<f64>,
    pub busy: Option<f64>,
    pub neighbours: Option<i64>,
    pub best: Option<i64>,
    pub best_score: Option<f64>,
    pub reason: String,
}

/// Append a history entry and keep the newest `keep`.
pub async fn add_history(
    store: &ConfigStore,
    network_id: i64,
    keep: i64,
    e: &ChanEvent,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO seg_wifi_chan_history (network_id, at, event, channel, score, busy, neighbours, best, best_score, reason)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(network_id)
    .bind(if e.at > 0 { e.at } else { now() })
    .bind(&e.event)
    .bind(e.channel)
    .bind(e.score)
    .bind(e.busy)
    .bind(e.neighbours)
    .bind(e.best)
    .bind(e.best_score)
    .bind(&e.reason)
    .execute(store.pool()?)
    .await
    .map_err(db("write channel history"))?;
    sqlx::query(
        "DELETE FROM seg_wifi_chan_history WHERE network_id = ? AND id NOT IN
           (SELECT id FROM seg_wifi_chan_history WHERE network_id = ? ORDER BY id DESC LIMIT ?)",
    )
    .bind(network_id)
    .bind(network_id)
    .bind(keep.clamp(10, 5000))
    .execute(store.pool()?)
    .await
    .map_err(db("trim channel history"))?;
    Ok(())
}

/// Newest first.
pub async fn history(store: &ConfigStore, network_id: i64, limit: i64) -> Result<Vec<ChanEvent>> {
    let rows = sqlx::query(
        "SELECT * FROM seg_wifi_chan_history WHERE network_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(network_id)
    .bind(limit)
    .fetch_all(store.pool()?)
    .await
    .map_err(db("read channel history"))?;
    Ok(rows
        .iter()
        .map(|r| ChanEvent {
            id: r.get("id"),
            at: r.get("at"),
            event: r.get("event"),
            channel: r.get("channel"),
            score: r.get("score"),
            busy: r.get("busy"),
            neighbours: r.get("neighbours"),
            best: r.get("best"),
            best_score: r.get("best_score"),
            reason: r.get("reason"),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_on_both_bands() {
        for b in ["2g", "5g"] {
            ChanSettings::default().validate(b).unwrap();
        }
    }

    #[test]
    fn width_and_list_rules() {
        let d = ChanSettings::default();
        let i = |f: &dyn Fn(&mut ChanInput)| {
            let mut x = ChanInput::default();
            f(&mut x);
            x
        };
        assert!(d.merged("2g", &i(&|x| x.width = Some(80))).is_err());
        assert!(d.merged("5g", &i(&|x| x.width = Some(80))).is_ok());
        assert!(d.merged("5g", &i(&|x| x.width = Some(60))).is_err());
        assert!(d
            .merged("2g", &i(&|x| x.chanlist = Some("1, 6,11".into())))
            .is_ok());
        assert!(d
            .merged("2g", &i(&|x| x.chanlist = Some("1,14".into())))
            .is_err());
        assert!(d
            .merged("2g", &i(&|x| x.chanlist = Some("36".into())))
            .is_err());
        assert!(d
            .merged("2g", &i(&|x| x.chanlist = Some("x".into())))
            .is_err());
        assert!(d
            .merged(
                "5g",
                &i(&|x| {
                    x.width = Some(40);
                    x.chanlist = Some("36,165".into())
                })
            )
            .is_err());
        assert!(d
            .merged("5g", &i(&|x| x.recheck_time = Some("25:00".into())))
            .is_err());
        assert!(d
            .merged("5g", &i(&|x| x.recheck_time = Some("3:30".into())))
            .is_err());
        assert!(d
            .merged("5g", &i(&|x| x.recheck_time = Some(String::new())))
            .is_ok());
        assert!(d.merged("5g", &i(&|x| x.csa = Some("on".into()))).is_err());
        for (f, bad) in [
            (0, i(&|x| x.hysteresis = Some(91))),
            (1, i(&|x| x.min_gain = Some(-1))),
            (2, i(&|x| x.confirm = Some(0))),
            (3, i(&|x| x.confirm_gap = Some(3601))),
            (4, i(&|x| x.csa_count = Some(51))),
            (5, i(&|x| x.rounds = Some(0))),
            (6, i(&|x| x.dwell = Some(19))),
            (7, i(&|x| x.bss_cost = Some(21))),
            (8, i(&|x| x.min_signal = Some(-29))),
            (9, i(&|x| x.history = Some(9))),
        ] {
            assert!(d.merged("5g", &bad).is_err(), "case {f}");
        }
        // absent input keeps the old values
        let kept = d.merged("5g", &ChanInput::default()).unwrap();
        assert_eq!(kept, d);
    }

    #[test]
    fn blocks_and_candidates() {
        assert_eq!(block_of("5g", 36, 80), vec![36, 40, 44, 48]);
        assert_eq!(block_of("5g", 157, 80), vec![149, 153, 157, 161]);
        assert_eq!(block_of("5g", 44, 40), vec![44, 48]);
        assert_eq!(block_of("5g", 48, 40), vec![44, 48]);
        assert_eq!(block_of("2g", 1, 40), vec![1, 5]);
        assert_eq!(block_of("2g", 11, 40), vec![7, 11]);
        assert_eq!(block_of("2g", 6, 20), vec![6]);
        assert_eq!(ChanSettings::default().candidates("2g"), vec![1, 6, 11]);
        let s = ChanSettings {
            chanlist: "6,11".into(),
            ..Default::default()
        };
        assert_eq!(s.candidates("2g"), vec![6, 11]);
        assert!(!default_candidates("5g", 20)
            .iter()
            .any(|c| (52..=144).contains(c)));
    }

    #[test]
    fn six_ghz_channels_blocks_centres_and_operating_classes() {
        let all = band_channels("6g");
        assert_eq!((all[0], *all.last().unwrap(), all.len()), (1, 233, 59));
        // 20/40/80/160 MHz blocks are aligned groups of 1/2/4/8 channels
        assert_eq!(block_of("6g", 37, 40), vec![33, 37]);
        assert_eq!(block_of("6g", 37, 80), vec![33, 37, 41, 45]);
        assert_eq!(
            block_of("6g", 37, 160),
            (0..8).map(|i| 33 + i * 4).collect::<Vec<_>>()
        );
        // 320 MHz: 320-1 (centres 31/95/159) where it exists, 320-2 (191) above
        assert_eq!(block_of("6g", 37, 320).first(), Some(&1));
        assert_eq!(
            block_of("6g", 197, 320),
            (0..16).map(|i| 161 + i * 4).collect::<Vec<_>>()
        );
        assert!(
            block_of("6g", 229, 320).is_empty(),
            "no 320 MHz block above 221"
        );
        assert_eq!(centre_of("6g", 37, 20), Some(37));
        assert_eq!(centre_of("6g", 37, 40), Some(35));
        assert_eq!(centre_of("6g", 37, 80), Some(39));
        assert_eq!(centre_of("6g", 37, 160), Some(47));
        assert_eq!(centre_of("6g", 37, 320), Some(31));
        assert_eq!(centre_of("6g", 197, 320), Some(191));
        assert_eq!(centre_of("5g", 36, 80), Some(42));
        assert_eq!(centre_of("5g", 36, 160), Some(50));
        assert_eq!(centre_of("5g", 112, 160), Some(114));
        assert_eq!(
            centre_of("5g", 149, 160),
            None,
            "149-161 is the last 5 GHz 80 MHz block"
        );
        assert_eq!(
            block_of("5g", 60, 160),
            (0..8).map(|i| 36 + i * 4).collect::<Vec<_>>()
        );
        assert_eq!(op_class_6g(20), Some(131));
        assert_eq!(op_class_6g(40), Some(132));
        assert_eq!(op_class_6g(80), Some(133));
        assert_eq!(op_class_6g(160), Some(134));
        assert_eq!(op_class_6g(320), Some(137));
        assert_eq!(op_class_6g(60), None);
        // preferred scanning channels: every 16th from 5
        assert!(is_psc(5) && is_psc(37) && is_psc(229) && !is_psc(1) && !is_psc(33));
        assert_eq!(default_candidates("6g", 20)[..3], [5, 21, 37]);
        // one PSC per block at 160 MHz (8 blocks below 225; 229 is alone)
        assert_eq!(
            default_candidates("6g", 160),
            vec![5, 37, 69, 101, 133, 165, 197]
        );
        assert_eq!(default_candidates("6g", 320), vec![5, 69, 133, 197]);
    }

    #[test]
    fn widths_per_band() {
        let d = ChanSettings::default();
        let w = |b: &str, v: i64| {
            d.merged(
                b,
                &ChanInput {
                    width: Some(v),
                    ..Default::default()
                },
            )
        };
        assert!(w("5g", 160).is_ok());
        assert!(w("6g", 160).is_ok() && w("6g", 320).is_ok() && w("6g", 80).is_ok());
        assert!(w("5g", 320).is_err() && w("2g", 160).is_err());
        let e = w("5g", 320).unwrap_err().to_string();
        assert!(e.contains("320") && e.contains("6 GHz"), "{e}");
        // 6 GHz channel list: channels 1..233 step 4; at 160 MHz only channels inside a block
        let l = |b: &str, width: i64, s: &str| {
            d.merged(
                b,
                &ChanInput {
                    width: Some(width),
                    chanlist: Some(s.into()),
                    ..Default::default()
                },
            )
        };
        assert!(l("6g", 20, "5,37,229").is_ok());
        assert!(l("6g", 20, "3").is_err() && l("6g", 20, "237").is_err());
        assert!(l("6g", 160, "229").is_err());
        assert!(l("6g", 320, "225").is_err());
        assert!(l("5g", 160, "149").is_err() && l("5g", 160, "36,100").is_ok());
        ChanSettings::default().validate("6g").unwrap();
    }
}
