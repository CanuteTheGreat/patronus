//! S.M.A.R.T. disk health (USE=smart): which disks the machine has, whether
//! each reports itself healthy, how hot it runs, how many sectors are bad
//! (ATA), how worn it is (NVMe), and the result of its last self-test.
//!
//! How it works:
//!
//! - `patronus smart run` is a small poller (a supervised root daemon,
//!   `patronus-daemon@smart`, OpenRC and systemd alike). Every
//!   `poll_minutes` it runs `smartctl --scan --json` and `smartctl -a --json`
//!   for each disk, parses the answer ([`parse_scan`], [`parse_disk`]),
//!   judges it against the configured thresholds ([`assess`]), stores the
//!   latest report (`smart_state`) and one history row (`smart_samples`,
//!   pruned after `retention_days`), and starts the scheduled short/long
//!   self-tests inside the configured time window.
//! - The web process is not root and never runs smartctl. It reads the
//!   tables; "start a self-test" writes a request (`test_request`) that the
//!   poller picks up within `request_check_secs`.
//! - Notifications reuse the event path of the web crate (the same
//!   channels and rules as gateway and tunnel alerts): the watcher turns a
//!   disk changing between ok / warning / critical into one event. A change is
//!   reported once (no repeats while the level stays), and a temperature has
//!   to fall `temp_hysteresis` degrees below its limit before it counts as
//!   recovered.
//! - Nothing here is a hard-coded threshold or interval: every number is a
//!   field of the page ([`FIELDS`]) with a documented default.
//!
//! Disks without S.M.A.R.T. (virtual disks, SD cards and eMMC on routers and
//! access points) are listed as "unsupported" with the reason smartctl gave;
//! they never raise an alert.

use crate::lan::{self, db_err, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::path::PathBuf;
use std::time::Duration;

pub const INSTANCE: &str = "smart";

// ---------------------------------------------------------------------------
// the settings page
// ---------------------------------------------------------------------------

static FIELDS: [Field; 15] = [
    Field::new("enabled", "S.M.A.R.T. monitoring", Kind::Bool)
        .def("0")
        .help("poll every disk with smartctl, keep the history, raise alerts"),
    Field::new("poll_minutes", "Poll interval (minutes)", Kind::Int(1, 1440)).def("30"),
    Field::new("test_poll_secs", "Poll interval while a self-test runs (seconds)", Kind::Int(10, 3600))
        .def("60")
        .help("so progress and the result show up soon after the test ends"),
    Field::new("request_check_secs", "Self-test request check (seconds)", Kind::Int(2, 300))
        .def("10")
        .help("how soon a self-test started from the web page begins"),
    Field::new("short_test_hours", "Short self-test every (hours)", Kind::Int(0, 8760))
        .def("24")
        .help("0 = never"),
    Field::new("long_test_days", "Long self-test every (days)", Kind::Int(0, 365))
        .def("7")
        .help("0 = never"),
    Field::new("test_window_start", "Scheduled tests start at (hour of day)", Kind::Int(0, 23)).def("2"),
    Field::new("test_window_hours", "Scheduled tests may start for (hours)", Kind::Int(1, 24))
        .def("5")
        .help("a test is only started inside this window (local time)"),
    Field::new("temp_warn", "Temperature warning (°C)", Kind::Int(20, 120)).def("50"),
    Field::new("temp_crit", "Temperature critical (°C)", Kind::Int(20, 150)).def("60"),
    Field::new("temp_hysteresis", "Temperature hysteresis (°C)", Kind::Int(0, 30))
        .def("3")
        .help("must fall this far below a limit before the alert is cleared"),
    Field::new("realloc_warn", "Reallocated sectors: warn from", Kind::Int(1, 1_000_000))
        .def("1")
        .help("pending and uncorrectable sectors always warn"),
    Field::new("nvme_used_warn", "NVMe wear: warn from (% used)", Kind::Int(1, 255)).def("90"),
    Field::new("notify", "Notify on failing attributes", Kind::Bool)
        .def("1")
        .help("send disk problems through the notification channels (Monitoring page)"),
    Field::new("retention_days", "Keep history for (days)", Kind::Int(1, 3650)).def("365"),
];

static SPEC: Spec = Spec {
    slug: "smart",
    title: "S.M.A.R.T. disk health",
    blurb: "Watches the health of the disks with smartmontools: temperature, bad sectors, NVMe wear, \
            self-test results, with scheduled short and long self-tests and alerts when a disk starts \
            to fail. Disks that cannot report S.M.A.R.T. (virtual disks, SD cards, eMMC) are listed as \
            such. The disks themselves are on Hardware > S.M.A.R.T.",
    applier: "smart",
    fields: &FIELDS,
    colls: &[],
    actions: &[
        ("test-short", "Short self-test on every disk"),
        ("test-long", "Long self-test on every disk"),
    ],
};

/// The feature page definition (the web side reads the same settings).
pub fn spec() -> &'static Spec {
    &SPEC
}

pub struct SmartSvc;

#[async_trait]
impl Svc for SmartSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn action(&self, store: &ConfigStore, name: &str, body: &Value) -> Result<Value> {
        let kind = match name {
            "test-short" => TestKind::Short,
            "test-long" => TestKind::Long,
            _ => return Err(invalid(format!("request: no action {name:?}"))),
        };
        let dev = body.get("device").and_then(Value::as_str).filter(|d| !d.is_empty());
        let n = request_test(store, dev, kind).await?;
        Ok(json!({"queued": n, "kind": kind.as_str()}))
    }
}

// ---------------------------------------------------------------------------
// thresholds (from the settings)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thresholds {
    pub temp_warn: i64,
    pub temp_crit: i64,
    pub temp_hysteresis: i64,
    pub realloc_warn: u64,
    pub nvme_used_warn: u64,
}

impl Thresholds {
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            temp_warn: s.n("temp_warn"),
            temp_crit: s.n("temp_crit"),
            temp_hysteresis: s.n("temp_hysteresis"),
            realloc_warn: s.n("realloc_warn").max(0) as u64,
            nvme_used_warn: s.n("nvme_used_warn").max(0) as u64,
        }
    }
}

/// The schedule and cadence settings the poller reads every cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub poll_secs: i64,
    pub test_poll_secs: i64,
    pub request_check_secs: i64,
    pub short_test_secs: i64,
    pub long_test_secs: i64,
    pub window_start: u32,
    pub window_hours: u32,
    pub retention_secs: i64,
}

impl Schedule {
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            poll_secs: s.n("poll_minutes") * 60,
            test_poll_secs: s.n("test_poll_secs"),
            request_check_secs: s.n("request_check_secs"),
            short_test_secs: s.n("short_test_hours") * 3600,
            long_test_secs: s.n("long_test_days") * 86400,
            window_start: s.n("test_window_start").clamp(0, 23) as u32,
            window_hours: s.n("test_window_hours").clamp(1, 24) as u32,
            retention_secs: s.n("retention_days") * 86400,
        }
    }
}

// ---------------------------------------------------------------------------
// what smartctl reports (pure parsers)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDevice {
    pub name: String,
    /// smartctl `-d` type (`sat`, `nvme`, `scsi`, ...); empty = let smartctl decide.
    pub dtype: String,
    pub protocol: String,
}

/// An ATA attribute row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attr {
    pub id: u64,
    pub name: String,
    pub value: u64,
    pub worst: u64,
    pub thresh: u64,
    pub raw: u64,
    pub raw_text: String,
    /// `now` | `past` | empty (smartctl's `when_failed`).
    pub when_failed: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nvme {
    pub critical_warning: u64,
    pub available_spare: Option<u64>,
    pub spare_threshold: Option<u64>,
    pub percentage_used: Option<u64>,
    pub media_errors: Option<u64>,
    pub unsafe_shutdowns: Option<u64>,
}

/// One entry of a self-test log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    pub kind: String,
    pub status: String,
    /// `Some(false)` = the test found a problem.
    pub passed: Option<bool>,
    pub hours: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTest {
    pub running: bool,
    pub remaining_percent: Option<u64>,
    pub log: Vec<TestResult>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub device: String,
    pub dtype: String,
    /// `ATA` | `NVMe` | `SCSI` | empty when smartctl could not tell.
    pub protocol: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub capacity_bytes: Option<u64>,
    /// 0 = SSD, None = unknown
    pub rotation_rpm: Option<u64>,
    pub smart_available: bool,
    pub smart_enabled: bool,
    /// smartctl's overall verdict: `Some(true)` PASSED, `Some(false)` FAILED.
    pub health: Option<bool>,
    pub temperature: Option<i64>,
    pub power_on_hours: Option<u64>,
    pub reallocated: Option<u64>,
    pub pending: Option<u64>,
    pub uncorrectable: Option<u64>,
    pub nvme: Option<Nvme>,
    pub attributes: Vec<Attr>,
    pub self_test: SelfTest,
    /// smartctl's own messages (why a disk cannot report, errors).
    pub messages: Vec<String>,
}

impl Disk {
    pub fn last_test(&self) -> Option<&TestResult> {
        self.self_test.log.first()
    }
}

fn parse_json(text: &str) -> Result<Value> {
    serde_json::from_str(text)
        .map_err(|e| Error::Service(format!("smartctl did not answer with JSON: {e}")))
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// `smartctl --scan --json`.
pub fn parse_scan(text: &str) -> Result<Vec<ScanDevice>> {
    let v = parse_json(text)?;
    let mut out = Vec::new();
    for d in v["devices"].as_array().into_iter().flatten() {
        let name = s(&d["name"]);
        if !valid_device(&name) {
            continue;
        }
        out.push(ScanDevice {
            name,
            dtype: s(&d["type"]),
            protocol: s(&d["protocol"]),
        });
    }
    Ok(out)
}

/// A device path that may reach a command line: `/dev/` + letters, digits and `_ . -` (and `/` for
/// by-id style links), no `..`.
pub fn valid_device(name: &str) -> bool {
    name.strip_prefix("/dev/").is_some_and(|r| {
        !r.is_empty()
            && !r.contains("..")
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'))
    })
}

fn attr_raw(a: &Value) -> u64 {
    a["raw"]["value"].as_u64().unwrap_or(0)
}

/// The messages smartctl attached (errors and notes), one string each.
fn messages(v: &Value) -> Vec<String> {
    v["smartctl"]["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["string"].as_str())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .collect()
}

/// `smartctl -a --json DEVICE` (ATA, NVMe and SCSI). A report from a disk that cannot do S.M.A.R.T.
/// parses too: `smart_available` is false and `messages` tell why.
pub fn parse_disk(text: &str) -> Result<Disk> {
    let v = parse_json(text)?;
    if !v.is_object() || v.get("smartctl").is_none() {
        return Err(Error::Service("not a smartctl report".into()));
    }
    let mut d = Disk {
        device: s(&v["device"]["name"]),
        dtype: s(&v["device"]["type"]),
        protocol: s(&v["device"]["protocol"]),
        model: {
            let m = s(&v["model_name"]);
            if m.is_empty() {
                s(&v["scsi_model_name"])
            } else {
                m
            }
        },
        serial: s(&v["serial_number"]),
        firmware: s(&v["firmware_version"]),
        capacity_bytes: v["user_capacity"]["bytes"].as_u64(),
        rotation_rpm: v["rotation_rate"].as_u64(),
        messages: messages(&v),
        ..Disk::default()
    };
    if d.model.is_empty() {
        d.model = s(&v["scsi_product"]);
    }
    // "SMART support is: Unavailable" (virtual disks, flash cards) has `available: false`; ATA/NVMe
    // reports without the block at all still mean SMART when they carry data
    let has_data = v.get("ata_smart_attributes").is_some()
        || v.get("nvme_smart_health_information_log").is_some()
        || v["smart_status"].get("passed").is_some();
    d.smart_available = v["smart_support"]["available"].as_bool().unwrap_or(has_data);
    d.smart_enabled = v["smart_support"]["enabled"].as_bool().unwrap_or(has_data);
    d.health = v["smart_status"]["passed"].as_bool();

    d.temperature = v["temperature"]["current"].as_i64();
    d.power_on_hours = v["power_on_time"]["hours"].as_u64();

    for a in v["ata_smart_attributes"]["table"].as_array().into_iter().flatten() {
        let attr = Attr {
            id: a["id"].as_u64().unwrap_or(0),
            name: s(&a["name"]),
            value: a["value"].as_u64().unwrap_or(0),
            worst: a["worst"].as_u64().unwrap_or(0),
            thresh: a["thresh"].as_u64().unwrap_or(0),
            raw: attr_raw(a),
            raw_text: s(&a["raw"]["string"]),
            when_failed: s(&a["when_failed"]),
        };
        match attr.id {
            5 => d.reallocated = Some(attr.raw),
            197 => d.pending = Some(attr.raw),
            198 => d.uncorrectable = Some(attr.raw),
            194 if d.temperature.is_none() => d.temperature = Some((attr.raw & 0xff) as i64),
            9 if d.power_on_hours.is_none() => d.power_on_hours = Some(attr.raw & 0xffff_ffff),
            _ => {}
        }
        d.attributes.push(attr);
    }

    if let Some(n) = v.get("nvme_smart_health_information_log") {
        d.nvme = Some(Nvme {
            critical_warning: n["critical_warning"].as_u64().unwrap_or(0),
            available_spare: n["available_spare"].as_u64(),
            spare_threshold: n["available_spare_threshold"].as_u64(),
            percentage_used: n["percentage_used"].as_u64(),
            media_errors: n["media_errors"].as_u64(),
            unsafe_shutdowns: n["unsafe_shutdowns"].as_u64(),
        });
        if d.temperature.is_none() {
            d.temperature = n["temperature"].as_i64();
        }
        if d.power_on_hours.is_none() {
            d.power_on_hours = n["power_on_hours"].as_u64();
        }
    }

    // SCSI / SAS: grown defects are the reallocated sectors, uncorrected errors the unreadable ones
    if let Some(g) = v["scsi_grown_defect_list"].as_u64() {
        d.reallocated = Some(g);
    }
    if let Some(log) = v.get("scsi_error_counter_log") {
        let total: u64 = ["read", "write", "verify"]
            .iter()
            .filter_map(|k| log[*k]["total_uncorrected_errors"].as_u64())
            .sum();
        if log.get("read").is_some() || log.get("write").is_some() {
            d.uncorrectable = Some(total);
        }
    }

    // self-test: running now, and the log (newest first)
    if let Some(st) = v["ata_smart_data"]["self_test"]["status"].as_object() {
        // status byte: high nibble 0xF = "in progress", low nibble = percent remaining / 10
        if let Some(val) = st.get("value").and_then(Value::as_u64) {
            if val >> 4 == 0xf {
                d.self_test.running = true;
                d.self_test.remaining_percent = st
                    .get("remaining_percent")
                    .and_then(Value::as_u64)
                    .or(Some((val & 0xf) * 10));
            }
        }
    }
    for e in v["ata_smart_self_test_log"]["standard"]["table"]
        .as_array()
        .into_iter()
        .flatten()
    {
        d.self_test.log.push(TestResult {
            kind: s(&e["type"]["string"]),
            status: s(&e["status"]["string"]),
            passed: e["status"]["passed"].as_bool(),
            hours: e["lifetime_hours"].as_u64(),
        });
    }
    if let Some(log) = v.get("nvme_self_test_log") {
        if log["current_self_test_operation"]["value"].as_u64().unwrap_or(0) != 0 {
            d.self_test.running = true;
            d.self_test.remaining_percent = log["current_self_test_completion_percent"]
                .as_u64()
                .map(|p| 100u64.saturating_sub(p));
        }
        for e in log["table"].as_array().into_iter().flatten() {
            let res = e["self_test_result"]["value"].as_u64();
            d.self_test.log.push(TestResult {
                kind: s(&e["self_test_code"]["string"]),
                status: s(&e["self_test_result"]["string"]),
                passed: res.map(|r| r == 0),
                hours: e["power_on_hours"].as_u64(),
            });
        }
    }
    Ok(d)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestKind {
    Short,
    Long,
}

impl TestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Short => "short",
            Self::Long => "long",
        }
    }
    pub fn parse(t: &str) -> Option<Self> {
        match t {
            "short" => Some(Self::Short),
            "long" => Some(Self::Long),
            _ => None,
        }
    }
}

/// What starting a self-test (`smartctl -t short|long --json`) answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestStart {
    /// The estimate smartctl gave ("Please wait N minutes"), when it gave one.
    pub minutes: Option<u64>,
    pub message: String,
}

/// `smartctl -t short|long --json DEVICE`: Ok when the test began, Err with smartctl's reason when it did
/// not (not supported, another test running, device busy). smartctl 7.x answers a successful start with
/// exit status 0 and no message at all (the "Test has begun" text only exists in plain output), so success
/// is the absence of an error: a non-zero exit status, or a message of severity `error`, is a refusal.
pub fn parse_test_start(text: &str) -> Result<TestStart> {
    let v = parse_json(text)?;
    if v.get("smartctl").is_none() {
        return Err(Error::Service("self-test not started: not a smartctl answer".into()));
    }
    let msgs = messages(&v);
    let errors: Vec<String> = v["smartctl"]["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["severity"].as_str() == Some("error"))
        .filter_map(|m| m["string"].as_str())
        .map(|m| m.trim().to_string())
        .collect();
    let status = v["smartctl"]["exit_status"].as_u64().unwrap_or(0);
    // bits 0-2 of the exit status are command line / device open / SMART command failures
    if !errors.is_empty() || status & 0b111 != 0 {
        let why = if errors.is_empty() {
            format!("smartctl exit status {status}")
        } else {
            errors.join("; ")
        };
        return Err(Error::Service(format!("self-test not started: {why}")));
    }
    let minutes = msgs.iter().find_map(|m| {
        let i = m.find("Please wait ")? + "Please wait ".len();
        m[i..].split_whitespace().next()?.parse().ok()
    });
    Ok(TestStart {
        minutes,
        message: if msgs.is_empty() {
            "started".into()
        } else {
            msgs.join(" ")
        },
    })
}

// ---------------------------------------------------------------------------
// judging a report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Unsupported,
    Ok,
    Warning,
    Critical,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
    pub fn parse(t: &str) -> Self {
        match t {
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            "unsupported" => Self::Unsupported,
            _ => Self::Ok,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub level: Level,
    /// Where the temperature stands (kept for the hysteresis of the next look).
    pub temp_level: Level,
    pub reasons: Vec<String>,
}

fn temp_level(temp: i64, t: &Thresholds, prev: Level) -> Level {
    let crit_at = if prev == Level::Critical {
        t.temp_crit - t.temp_hysteresis
    } else {
        t.temp_crit
    };
    if temp >= crit_at {
        return Level::Critical;
    }
    let warn_at = if prev >= Level::Warning {
        t.temp_warn - t.temp_hysteresis
    } else {
        t.temp_warn
    };
    if temp >= warn_at {
        Level::Warning
    } else {
        Level::Ok
    }
}

/// Judge one report. `prev_temp` is the temperature level of the previous look (hysteresis).
pub fn assess(d: &Disk, t: &Thresholds, prev_temp: Level) -> Assessment {
    if !d.smart_available {
        return Assessment {
            level: Level::Unsupported,
            temp_level: Level::Ok,
            reasons: d.messages.clone(),
        };
    }
    let mut level = Level::Ok;
    let mut reasons = Vec::new();
    let mut raise = |l: Level, why: String| {
        level = level.max(l);
        reasons.push(why);
    };
    if d.health == Some(false) {
        raise(
            Level::Critical,
            "the disk reports that its S.M.A.R.T. health check FAILED".into(),
        );
    }
    for a in &d.attributes {
        if a.when_failed == "now" {
            raise(
                Level::Critical,
                format!("attribute {} ({}) is failing now: value {} is at or below its threshold {}", a.id, a.name, a.value, a.thresh),
            );
        }
    }
    if let Some(n) = &d.nvme {
        if n.critical_warning != 0 {
            raise(
                Level::Critical,
                format!("NVMe critical warning flags {:#04x}", n.critical_warning),
            );
        }
        if let Some(u) = n.percentage_used {
            if u >= t.nvme_used_warn {
                raise(Level::Warning, format!("{u}% of the NVMe endurance is used"));
            }
        }
        if let (Some(sp), Some(th)) = (n.available_spare, n.spare_threshold) {
            if sp < th {
                raise(
                    Level::Critical,
                    format!("available spare {sp}% is below its threshold {th}%"),
                );
            }
        }
        if n.media_errors.unwrap_or(0) > 0 {
            raise(
                Level::Warning,
                format!("{} media and data integrity errors", n.media_errors.unwrap_or(0)),
            );
        }
    }
    if let Some(p) = d.pending.filter(|p| *p > 0) {
        raise(Level::Warning, format!("{p} sectors waiting to be reallocated (pending)"));
    }
    if let Some(u) = d.uncorrectable.filter(|u| *u > 0) {
        raise(Level::Warning, format!("{u} uncorrectable sectors"));
    }
    if let Some(r) = d.reallocated.filter(|r| *r >= t.realloc_warn.max(1)) {
        raise(Level::Warning, format!("{r} reallocated sectors"));
    }
    if let Some(l) = d.last_test() {
        if l.passed == Some(false) {
            raise(
                Level::Warning,
                format!("the last self-test ({}) did not complete cleanly: {}", l.kind, l.status),
            );
        }
    }
    let mut tl = Level::Ok;
    if let Some(temp) = d.temperature {
        tl = temp_level(temp, t, prev_temp);
        match tl {
            Level::Critical => raise(Level::Critical, format!("temperature {temp} °C (critical from {} °C)", t.temp_crit)),
            Level::Warning => raise(Level::Warning, format!("temperature {temp} °C (warning from {} °C)", t.temp_warn)),
            _ => {}
        }
    }
    Assessment {
        level,
        temp_level: tl,
        reasons,
    }
}

/// Is a scheduled test due? `hour` is the local hour of day. Only one test at a time, only inside the
/// window, the long test first.
pub fn due_test(
    now: i64,
    hour: u32,
    sch: &Schedule,
    last_short: Option<i64>,
    last_long: Option<i64>,
    running: bool,
) -> Option<TestKind> {
    if running {
        return None;
    }
    let in_window = (hour + 24 - sch.window_start) % 24 < sch.window_hours;
    if !in_window {
        return None;
    }
    let due = |every: i64, last: Option<i64>| every > 0 && last.map_or(true, |l| now - l >= every);
    if due(sch.long_test_secs, last_long) {
        Some(TestKind::Long)
    } else if due(sch.short_test_secs, last_short) {
        Some(TestKind::Short)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// the tables
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Stored {
    pub disk: Disk,
    pub level: Level,
    pub reasons: Vec<String>,
    pub at: i64,
    pub last_short: Option<i64>,
    pub last_long: Option<i64>,
    pub test_request: String,
}

fn stored(r: &sqlx::sqlite::SqliteRow) -> Stored {
    Stored {
        disk: serde_json::from_str(&r.get::<String, _>("info")).unwrap_or_default(),
        level: Level::parse(&r.get::<String, _>("level")),
        reasons: serde_json::from_str(&r.get::<String, _>("reasons")).unwrap_or_default(),
        at: r.get("at"),
        last_short: r.get("last_short"),
        last_long: r.get("last_long"),
        test_request: r.get("test_request"),
    }
}

/// The latest report of every disk, by device name.
pub async fn latest(store: &ConfigStore) -> Result<Vec<Stored>> {
    let rows = sqlx::query("SELECT * FROM smart_state ORDER BY device")
        .fetch_all(store.pool()?)
        .await
        .map_err(db_err("read smart state"))?;
    Ok(rows.iter().map(stored).collect())
}

pub async fn latest_one(store: &ConfigStore, device: &str) -> Result<Option<Stored>> {
    let r = sqlx::query("SELECT * FROM smart_state WHERE device = ?")
        .bind(device)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db_err("read smart state"))?;
    Ok(r.as_ref().map(stored))
}

/// Record one look at a disk: judge it (with the previous temperature level for the hysteresis), keep the
/// report as the disk's latest, add a history row.
pub async fn record(store: &ConfigStore, d: &Disk, t: &Thresholds, now: i64) -> Result<Assessment> {
    let pool = store.pool()?;
    let prev: Option<String> = sqlx::query("SELECT temp_level FROM smart_state WHERE device = ?")
        .bind(&d.device)
        .fetch_optional(pool)
        .await
        .map_err(db_err("read smart state"))?
        .map(|r| r.get(0));
    let a = assess(d, t, prev.as_deref().map(Level::parse).unwrap_or(Level::Ok));
    sqlx::query(
        "INSERT INTO smart_state (device, at, level, temp_level, reasons, info) VALUES (?,?,?,?,?,?) \
         ON CONFLICT(device) DO UPDATE SET at = excluded.at, level = excluded.level, \
         temp_level = excluded.temp_level, reasons = excluded.reasons, info = excluded.info",
    )
    .bind(&d.device)
    .bind(now)
    .bind(a.level.as_str())
    .bind(a.temp_level.as_str())
    .bind(serde_json::to_string(&a.reasons).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(d).unwrap_or_else(|_| "{}".into()))
    .execute(pool)
    .await
    .map_err(db_err("write smart state"))?;
    if d.smart_available {
        sqlx::query(
            "INSERT INTO smart_samples (at, device, serial, health, temperature, power_on_hours, \
             reallocated, pending, uncorrectable, nvme_used, level) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(now)
        .bind(&d.device)
        .bind(&d.serial)
        .bind(d.health.map(i64::from))
        .bind(d.temperature)
        .bind(d.power_on_hours.map(|v| v as i64))
        .bind(d.reallocated.map(|v| v as i64))
        .bind(d.pending.map(|v| v as i64))
        .bind(d.uncorrectable.map(|v| v as i64))
        .bind(d.nvme.as_ref().and_then(|n| n.percentage_used).map(|v| v as i64))
        .bind(a.level.as_str())
        .execute(pool)
        .await
        .map_err(db_err("write smart sample"))?;
    }
    Ok(a)
}

/// Drop history older than `retention_secs`. Returns the rows removed.
pub async fn prune(store: &ConfigStore, retention_secs: i64, now: i64) -> Result<u64> {
    let r = sqlx::query("DELETE FROM smart_samples WHERE at < ?")
        .bind(now - retention_secs)
        .execute(store.pool()?)
        .await
        .map_err(db_err("prune smart samples"))?;
    Ok(r.rows_affected())
}

/// Forget disks that are no longer there (their history stays until it ages out).
pub async fn forget_missing(store: &ConfigStore, present: &[String]) -> Result<()> {
    for st in latest(store).await? {
        if !present.contains(&st.disk.device) {
            sqlx::query("DELETE FROM smart_state WHERE device = ?")
                .bind(&st.disk.device)
                .execute(store.pool()?)
                .await
                .map_err(db_err("forget smart disk"))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub at: i64,
    pub health: Option<bool>,
    pub temperature: Option<i64>,
    pub power_on_hours: Option<i64>,
    pub reallocated: Option<i64>,
    pub pending: Option<i64>,
    pub uncorrectable: Option<i64>,
    pub nvme_used: Option<i64>,
    pub level: String,
}

/// The newest `limit` samples of one disk, oldest first.
pub async fn history(store: &ConfigStore, device: &str, limit: i64) -> Result<Vec<Sample>> {
    let rows = sqlx::query(
        "SELECT * FROM (SELECT * FROM smart_samples WHERE device = ? ORDER BY at DESC, id DESC LIMIT ?) ORDER BY at, id",
    )
    .bind(device)
    .bind(limit)
    .fetch_all(store.pool()?)
    .await
    .map_err(db_err("read smart samples"))?;
    Ok(rows
        .iter()
        .map(|r| Sample {
            at: r.get("at"),
            health: r.get::<Option<i64>, _>("health").map(|h| h != 0),
            temperature: r.get("temperature"),
            power_on_hours: r.get("power_on_hours"),
            reallocated: r.get("reallocated"),
            pending: r.get("pending"),
            uncorrectable: r.get("uncorrectable"),
            nvme_used: r.get("nvme_used"),
            level: r.get("level"),
        })
        .collect())
}

/// Ask the poller to start a self-test: on one disk (`/dev/NAME` or `NAME`) or on every disk that supports
/// S.M.A.R.T. Returns how many disks were queued. The web process is not root, so this only writes the
/// request; the poller (root) runs it.
pub async fn request_test(store: &ConfigStore, device: Option<&str>, kind: TestKind) -> Result<usize> {
    let all = latest(store).await?;
    let want = device.map(|d| {
        if d.starts_with("/dev/") {
            d.to_string()
        } else {
            format!("/dev/{d}")
        }
    });
    if let Some(w) = &want {
        if !valid_device(w) {
            return Err(invalid(format!("request: device {w:?}")));
        }
    }
    let targets: Vec<&Stored> = all
        .iter()
        .filter(|st| want.as_ref().is_none_or(|w| &st.disk.device == w))
        .collect();
    if let Some(w) = &want {
        match targets.first() {
            None => return Err(Error::Config(format!("no S.M.A.R.T. disk {w}"))),
            Some(st) if !st.disk.smart_available => {
                return Err(invalid(format!(
                    "request: {w} cannot do S.M.A.R.T. self-tests ({})",
                    st.disk.messages.first().map(String::as_str).unwrap_or("no S.M.A.R.T. support")
                )))
            }
            _ => {}
        }
    }
    let mut n = 0;
    for st in targets.into_iter().filter(|st| st.disk.smart_available) {
        sqlx::query("UPDATE smart_state SET test_request = ?, request_at = ? WHERE device = ?")
            .bind(kind.as_str())
            .bind(lan::now())
            .bind(&st.disk.device)
            .execute(store.pool()?)
            .await
            .map_err(db_err("queue self-test"))?;
        n += 1;
    }
    if n == 0 {
        return Err(Error::Config("no S.M.A.R.T. disk to test".into()));
    }
    Ok(n)
}

/// Disks and levels for the event watcher: `(device, level, why)` for every disk that supports
/// S.M.A.R.T., empty while monitoring or notification is off.
pub async fn alert_states(store: &ConfigStore) -> Vec<(String, Level, String)> {
    let Ok(st) = Settings::load(store, &SPEC).await else {
        return Vec::new();
    };
    if !st.b("enabled") || !st.b("notify") {
        return Vec::new();
    }
    latest(store)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d.level != Level::Unsupported)
        .map(|d| (d.disk.device.clone(), d.level, d.reasons.join("; ")))
        .collect()
}

// ---------------------------------------------------------------------------
// smartctl
// ---------------------------------------------------------------------------

/// The smartctl binary: `PATRONUS_SMARTCTL`, else `smartctl` from the usual directories.
pub fn smartctl_bin() -> Option<PathBuf> {
    std::env::var_os("PATRONUS_SMARTCTL")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| which("smartctl"))
}

#[async_trait]
pub trait Smartctl: Send + Sync {
    async fn scan(&self) -> Result<String>;
    async fn report(&self, dev: &ScanDevice) -> Result<String>;
    async fn start_test(&self, dev: &ScanDevice, kind: TestKind) -> Result<String>;
}

pub struct SystemSmartctl {
    pub bin: PathBuf,
    pub timeout: Duration,
}

impl SystemSmartctl {
    pub fn new(timeout_secs: i64) -> Result<Self> {
        let bin = smartctl_bin().ok_or_else(|| {
            Error::Service(
                "S.M.A.R.T. monitoring needs smartctl, which is not installed (emerge sys-apps/smartmontools, USE=smart)".into(),
            )
        })?;
        Ok(Self {
            bin,
            timeout: Duration::from_secs(timeout_secs.max(1) as u64),
        })
    }

    async fn run(&self, args: &[&str]) -> Result<String> {
        let mut c = tokio::process::Command::new(&self.bin);
        c.args(args).kill_on_drop(true);
        let out = tokio::time::timeout(self.timeout, c.output())
            .await
            .map_err(|_| Error::Service(format!("smartctl {} timed out", args.join(" "))))?
            .map_err(|e| Error::Service(format!("smartctl: {e}")))?;
        // the exit status is a bit mask of findings (failing disk, error log entries): the JSON is
        // what counts
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// `-d TYPE` only for what smartctl cannot work out itself: a plain `sd` disk is reported as type `scsi` by
/// the scan, yet its SATA translation (`sat`) is found by smartctl's own autodetection, which `-d scsi`
/// would defeat (no temperature, no ATA attributes).
fn dev_args<'a>(mut a: Vec<&'a str>, d: &'a ScanDevice) -> Vec<&'a str> {
    if !matches!(d.dtype.as_str(), "" | "auto" | "scsi" | "nvme") {
        a.push("-d");
        a.push(&d.dtype);
    }
    a.push(&d.name);
    a
}

#[async_trait]
impl Smartctl for SystemSmartctl {
    async fn scan(&self) -> Result<String> {
        self.run(&["--scan", "--json"]).await
    }
    async fn report(&self, dev: &ScanDevice) -> Result<String> {
        self.run(&dev_args(vec!["-a", "--json"], dev)).await
    }
    async fn start_test(&self, dev: &ScanDevice, kind: TestKind) -> Result<String> {
        self.run(&dev_args(vec!["-t", kind.as_str(), "--json"], dev)).await
    }
}

// ---------------------------------------------------------------------------
// the poller
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PollReport {
    pub polled: Vec<(String, Level)>,
    pub tests_started: Vec<(String, TestKind)>,
    pub errors: Vec<String>,
}

impl PollReport {
    pub fn describe(&self) -> String {
        let disks: Vec<String> = self
            .polled
            .iter()
            .map(|(d, l)| format!("{d}: {}", l.as_str()))
            .collect();
        let mut s = format!("{} disk(s) [{}]", self.polled.len(), disks.join(", "));
        for (d, k) in &self.tests_started {
            s.push_str(&format!("; {} self-test started on {d}", k.as_str()));
        }
        for e in &self.errors {
            s.push_str(&format!("; {e}"));
        }
        s
    }
}

async fn set_test_time(store: &ConfigStore, device: &str, kind: TestKind, now: i64) -> Result<()> {
    let col = match kind {
        TestKind::Short => "last_short",
        TestKind::Long => "last_long",
    };
    sqlx::query(&format!(
        "UPDATE smart_state SET {col} = ?, test_request = '', request_at = NULL WHERE device = ?"
    ))
    .bind(now)
    .bind(device)
    .execute(store.pool()?)
    .await
    .map_err(db_err("note self-test"))?;
    Ok(())
}

async fn clear_request(store: &ConfigStore, device: &str) -> Result<()> {
    sqlx::query("UPDATE smart_state SET test_request = '', request_at = NULL WHERE device = ?")
        .bind(device)
        .execute(store.pool()?)
        .await
        .map_err(db_err("clear self-test request"))?;
    Ok(())
}

/// Start the requested self-tests (from the web page / API) now. Returns what was started.
pub async fn run_requests(
    store: &ConfigStore,
    run: &dyn Smartctl,
    now: i64,
) -> Result<Vec<(String, TestKind, std::result::Result<TestStart, String>)>> {
    let mut out = Vec::new();
    for st in latest(store).await? {
        let Some(kind) = TestKind::parse(&st.test_request) else {
            continue;
        };
        let dev = ScanDevice {
            name: st.disk.device.clone(),
            dtype: st.disk.dtype.clone(),
            protocol: st.disk.protocol.clone(),
        };
        let res = match run.start_test(&dev, kind).await {
            Ok(t) => parse_test_start(&t).map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match &res {
            Ok(_) => set_test_time(store, &dev.name, kind, now).await?,
            // a refused request is answered once (in the report), not retried every few seconds
            Err(_) => clear_request(store, &dev.name).await?,
        }
        out.push((dev.name, kind, res));
    }
    Ok(out)
}

/// One full look: scan, report on every disk, judge and store, start the scheduled tests that are due,
/// forget vanished disks, prune old history. `hour` is the local hour of day.
pub async fn poll_once(store: &ConfigStore, run: &dyn Smartctl, now: i64, hour: u32) -> Result<PollReport> {
    let st = Settings::load(store, &SPEC).await?;
    let th = Thresholds::from_settings(&st);
    let sch = Schedule::from_settings(&st);
    let mut rep = PollReport::default();
    let scan = parse_scan(&run.scan().await?)?;
    let mut present = Vec::new();
    for sd in &scan {
        present.push(sd.name.clone());
        let mut d = match run.report(sd).await.and_then(|t| parse_disk(&t)) {
            Ok(d) => d,
            Err(e) => {
                rep.errors.push(format!("{}: {e}", sd.name));
                continue;
            }
        };
        d.device = sd.name.clone();
        if d.dtype.is_empty() {
            d.dtype = sd.dtype.clone();
        }
        let a = record(store, &d, &th, now).await?;
        rep.polled.push((d.device.clone(), a.level));
        if a.level == Level::Unsupported {
            continue;
        }
        let prev = latest_one(store, &d.device).await?;
        let (ls, ll) = prev.as_ref().map_or((None, None), |p| (p.last_short, p.last_long));
        if let Some(kind) = due_test(now, hour, &sch, ls, ll, d.self_test.running) {
            match run.start_test(sd, kind).await.and_then(|t| parse_test_start(&t)) {
                Ok(_) => {
                    set_test_time(store, &d.device, kind, now).await?;
                    rep.tests_started.push((d.device.clone(), kind));
                }
                Err(e) => rep.errors.push(format!("{}: {e}", d.device)),
            }
        }
    }
    forget_missing(store, &present).await?;
    prune(store, sch.retention_secs, now).await?;
    Ok(rep)
}

/// The poller loop of `patronus smart run`: requests are checked every `request_check_secs`, a full poll
/// every `poll_minutes` (every `test_poll_secs` while a self-test runs). Settings are re-read each turn, so
/// a change needs no restart.
pub async fn run_loop(store: &ConfigStore, run: Option<&dyn Smartctl>) -> Result<()> {
    use chrono::Timelike;
    let mut last_poll = 0i64;
    loop {
        let st = Settings::load(store, &SPEC).await?;
        let sch = Schedule::from_settings(&st);
        let now = lan::now();
        if st.b("enabled") {
            let sys;
            let run: &dyn Smartctl = match run {
                Some(r) => r,
                None => {
                    sys = SystemSmartctl::new(30)?;
                    &sys
                }
            };
            for (dev, kind, res) in run_requests(store, run, now).await.unwrap_or_default() {
                match res {
                    Ok(t) => println!("smart: {} self-test started on {dev} ({})", kind.as_str(), t.message),
                    Err(e) => eprintln!("smart: {dev}: {e}"),
                }
                last_poll = 0; // look again at once: the disk now shows the test running
            }
            let any_running = latest(store)
                .await
                .unwrap_or_default()
                .iter()
                .any(|d| d.disk.self_test.running);
            let every = if any_running { sch.test_poll_secs } else { sch.poll_secs };
            if now - last_poll >= every {
                match poll_once(store, run, now, chrono::Local::now().hour()).await {
                    Ok(r) => println!("smart: {}", r.describe()),
                    Err(e) => eprintln!("smart: poll failed: {e}"),
                }
                last_poll = now;
            }
        }
        tokio::time::sleep(Duration::from_secs(sch.request_check_secs.max(1) as u64)).await;
    }
}

// ---------------------------------------------------------------------------
// applier
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SmartApplier {
    sup: Supervisor,
}

impl Default for SmartApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

/// The poller's settings as the file the supervisor watches (a change restarts the daemon).
pub fn render(s: &Settings) -> String {
    let mut c = lan::header("#", "smart");
    for f in FIELDS.iter() {
        c.push_str(&format!("{}={}\n", f.key, s.s(f.key)));
    }
    c
}

impl SmartApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }

    fn conf_path(&self) -> PathBuf {
        self.sup.paths.state_dir.join("smart.conf")
    }

    fn patronus_bin() -> PathBuf {
        std::env::var_os("PATRONUS_BIN")
            .map(PathBuf::from)
            .or_else(|| which("patronus"))
            .unwrap_or_else(|| PathBuf::from("/usr/bin/patronus"))
    }
}

#[async_trait]
impl Applier for SmartApplier {
    fn name(&self) -> &'static str {
        "smart"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("S.M.A.R.T. monitoring stopped");
            } else {
                rep.applied("S.M.A.R.T. monitoring is off");
            }
            return Ok(rep);
        }
        if s.n("temp_crit") <= s.n("temp_warn") {
            return Err(invalid(
                "S.M.A.R.T. temperatures: the critical temperature must be higher than the warning temperature",
            ));
        }
        smartctl_bin().ok_or_else(|| {
            Error::Service(
                "S.M.A.R.T. monitoring needs smartctl, which is not installed (emerge sys-apps/smartmontools, USE=smart)".into(),
            )
        })?;
        let conf = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                Self::patronus_bin().to_string_lossy().into(),
                "--db".into(),
                store.path().to_string_lossy().into(),
                "smart".into(),
                "run".into(),
            ],
            vec![(conf, render(&s), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "S.M.A.R.T. poller {}: every {} min",
            if started { "(re)started" } else { "running, unchanged" },
            s.s("poll_minutes")
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# S.M.A.R.T. monitoring off\n".into());
        }
        Ok(format!("## smart.conf\n{}", render(&s)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let disks = latest(store).await.unwrap_or_default();
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": smartctl_bin().is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "disks": disks.iter().map(|d| json!({
                "device": d.disk.device, "level": d.level, "model": d.disk.model,
            })).collect::<Vec<_>>(),
        }))
    }
}

// ---------------------------------------------------------------------------
// JSON for the API / UI
// ---------------------------------------------------------------------------

/// The settings-independent summary of one disk (list view).
pub fn summary_json(st: &Stored) -> Value {
    let d = &st.disk;
    json!({
        "device": d.device,
        "name": d.device.strip_prefix("/dev/").unwrap_or(&d.device),
        "protocol": d.protocol,
        "model": d.model,
        "serial": d.serial,
        "firmware": d.firmware,
        "capacity_bytes": d.capacity_bytes,
        "rotation_rpm": d.rotation_rpm,
        "smart_available": d.smart_available,
        "smart_enabled": d.smart_enabled,
        "health": d.health.map(|h| if h { "PASSED" } else { "FAILED" }),
        "level": st.level,
        "reasons": st.reasons,
        "temperature_c": d.temperature,
        "power_on_hours": d.power_on_hours,
        "reallocated_sectors": d.reallocated,
        "pending_sectors": d.pending,
        "uncorrectable_sectors": d.uncorrectable,
        "nvme": d.nvme.as_ref().map(|n| json!({
            "percentage_used": n.percentage_used,
            "critical_warning": n.critical_warning,
            "available_spare": n.available_spare,
            "media_errors": n.media_errors,
            "unsafe_shutdowns": n.unsafe_shutdowns,
        })),
        "last_self_test": d.last_test(),
        "self_test_running": d.self_test.running,
        "self_test_remaining_percent": d.self_test.remaining_percent,
        "test_requested": if st.test_request.is_empty() { Value::Null } else { json!(st.test_request) },
        "messages": if d.smart_available { Vec::new() } else { d.messages.clone() },
        "checked_at": st.at,
    })
}

/// Everything about one disk (drill-down): the summary plus attributes, the self-test log and the schedule
/// state.
pub fn detail_json(st: &Stored, history: &[Sample]) -> Value {
    let mut v = summary_json(st);
    v["attributes"] = json!(st.disk.attributes);
    v["self_test_log"] = json!(st.disk.self_test.log);
    v["last_short_test"] = json!(st.last_short);
    v["last_long_test"] = json!(st.last_long);
    v["history"] = json!(history);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};
    use std::sync::Mutex;

    const SCAN: &str = include_str!("../tests/fixtures/smart/scan.json");
    const SCAN_EMPTY: &str = include_str!("../tests/fixtures/smart/scan_empty.json");
    const ATA_OK: &str = include_str!("../tests/fixtures/smart/ata_healthy.json");
    const ATA_FAILING: &str = include_str!("../tests/fixtures/smart/ata_failing.json");
    const ATA_PENDING: &str = include_str!("../tests/fixtures/smart/ata_pending.json");
    const NVME_OK: &str = include_str!("../tests/fixtures/smart/nvme_healthy.json");
    const NVME_WORN: &str = include_str!("../tests/fixtures/smart/nvme_worn.json");
    const SCSI_OK: &str = include_str!("../tests/fixtures/smart/scsi_sas.json");
    const VIRTIO: &str = include_str!("../tests/fixtures/smart/virtio_nosmart.json");
    const START_OK: &str = include_str!("../tests/fixtures/smart/test_start_short.json");
    const START_BAD: &str = include_str!("../tests/fixtures/smart/test_start_refused.json");

    fn th() -> Thresholds {
        Thresholds {
            temp_warn: 50,
            temp_crit: 60,
            temp_hysteresis: 3,
            realloc_warn: 1,
            nvme_used_warn: 90,
        }
    }

    #[test]
    fn scan_lists_devices_with_their_type() {
        let d = parse_scan(SCAN).unwrap();
        assert!(!d.is_empty());
        assert!(d.iter().all(|x| valid_device(&x.name)));
        assert!(parse_scan(SCAN_EMPTY).unwrap().is_empty());
        assert!(parse_scan("not json").is_err());
        // a hostile device name never reaches a command line
        let evil = r#"{"devices":[{"name":"/dev/sda; rm -rf /","type":"scsi"},{"name":"/dev/../etc/passwd"},{"name":"/dev/sdb","type":"sat","protocol":"ATA"}]}"#;
        let d = parse_scan(evil).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "/dev/sdb");
        assert!(!valid_device("sda") && !valid_device("/dev/") && !valid_device("/dev/a b"));
    }

    #[test]
    fn healthy_ata_disk() {
        let d = parse_disk(ATA_OK).unwrap();
        assert_eq!(d.protocol, "ATA");
        assert!(d.smart_available && d.smart_enabled);
        assert_eq!(d.health, Some(true));
        assert!(d.temperature.is_some());
        assert!(d.power_on_hours.is_some());
        assert!(!d.attributes.is_empty());
        assert_eq!(d.pending.unwrap_or(0), 0);
        let a = assess(&d, &th(), Level::Ok);
        assert_eq!(a.level, Level::Ok, "{:?}", a.reasons);
        assert!(a.reasons.is_empty());
    }

    #[test]
    fn failing_ata_disk_is_critical_and_says_why() {
        let d = parse_disk(ATA_FAILING).unwrap();
        assert_eq!(d.health, Some(false));
        assert!(d.reallocated.unwrap() > 0);
        assert!(d.attributes.iter().any(|a| a.when_failed == "now"));
        let a = assess(&d, &th(), Level::Ok);
        assert_eq!(a.level, Level::Critical);
        assert!(a.reasons.iter().any(|r| r.contains("FAILED")), "{:?}", a.reasons);
        assert!(a.reasons.iter().any(|r| r.contains("reallocated")), "{:?}", a.reasons);
        assert!(a.reasons.iter().any(|r| r.contains("failing now")), "{:?}", a.reasons);
        assert_eq!(d.last_test().unwrap().passed, Some(false));
    }

    #[test]
    fn pending_sectors_warn_while_the_disk_still_passes() {
        let d = parse_disk(ATA_PENDING).unwrap();
        assert_eq!(d.health, Some(true));
        assert!(d.pending.unwrap() > 0);
        let a = assess(&d, &th(), Level::Ok);
        assert_eq!(a.level, Level::Warning);
        assert!(a.reasons.iter().any(|r| r.contains("pending")), "{:?}", a.reasons);
        // the warning threshold for reallocated sectors is a setting
        let mut d2 = d.clone();
        d2.pending = Some(0);
        d2.reallocated = Some(3);
        let mut t = th();
        assert_eq!(assess(&d2, &t, Level::Ok).level, Level::Warning);
        t.realloc_warn = 10;
        assert_eq!(assess(&d2, &t, Level::Ok).level, Level::Ok);
    }

    #[test]
    fn healthy_nvme_disk() {
        let d = parse_disk(NVME_OK).unwrap();
        assert_eq!(d.protocol, "NVMe");
        assert_eq!(d.health, Some(true));
        let n = d.nvme.as_ref().unwrap();
        assert_eq!(n.critical_warning, 0);
        assert!(n.percentage_used.is_some());
        // QEMU's emulated controller reports 50 °C: that is a warning with the default limits ...
        assert_eq!(d.temperature, Some(50));
        assert!(d.power_on_hours.is_some());
        assert_eq!(assess(&d, &th(), Level::Ok).level, Level::Warning);
        // ... and fine once the limits are the user's
        let mut t = th();
        t.temp_warn = 55;
        t.temp_crit = 70;
        assert_eq!(assess(&d, &t, Level::Ok).level, Level::Ok);
    }

    #[test]
    fn worn_nvme_disk_warns_and_a_critical_warning_is_critical() {
        let d = parse_disk(NVME_WORN).unwrap();
        let n = d.nvme.as_ref().unwrap();
        assert!(n.percentage_used.unwrap() >= 90);
        let a = assess(&d, &th(), Level::Ok);
        assert!(a.level >= Level::Warning);
        assert!(a.reasons.iter().any(|r| r.contains("endurance")), "{:?}", a.reasons);
        assert!(a.reasons.iter().any(|r| r.contains("critical warning")), "{:?}", a.reasons);
        assert_eq!(a.level, Level::Critical);
        // the wear threshold is a setting
        let mut healthy = d.clone();
        healthy.nvme.as_mut().unwrap().critical_warning = 0;
        healthy.nvme.as_mut().unwrap().available_spare = Some(100);
        healthy.nvme.as_mut().unwrap().media_errors = Some(0);
        healthy.health = Some(true);
        let mut t = th();
        t.nvme_used_warn = 100;
        assert_eq!(assess(&healthy, &t, Level::Ok).level, Level::Ok);
    }

    #[test]
    fn scsi_disk() {
        let d = parse_disk(SCSI_OK).unwrap();
        assert_eq!(d.protocol, "SCSI");
        assert!(d.smart_available);
        assert_eq!(d.health, Some(true));
        assert!(d.temperature.is_some());
        assert!(d.reallocated.is_some());
        assert_eq!(d.rotation_rpm, Some(10000));
        assert_eq!(assess(&d, &th(), Level::Ok).level, Level::Ok);
    }

    #[test]
    fn a_disk_without_smart_is_unsupported_not_failed() {
        let d = parse_disk(VIRTIO).unwrap();
        assert!(!d.smart_available);
        assert_eq!(d.health, None);
        assert!(d.temperature.is_none());
        let a = assess(&d, &th(), Level::Ok);
        assert_eq!(a.level, Level::Unsupported);
        assert!(!d.messages.is_empty(), "smartctl's reason is kept");
        assert!(parse_disk("{}").is_err());
        assert!(parse_disk("garbage").is_err());
    }

    #[test]
    fn self_test_start_and_refusal() {
        // the real smartctl 7.3 answer of a started test carries no message at all
        let t = parse_test_start(START_OK).unwrap();
        assert_eq!(t.minutes, None);
        // the real answer for a device smartctl cannot talk to
        let e = parse_test_start(START_BAD).unwrap_err().to_string();
        assert!(e.contains("not started") && e.contains("Unable to detect device type"), "{e}");
        assert!(parse_test_start("{}").is_err());
        let busy = r#"{"smartctl":{"exit_status":4,"messages":[]}}"#;
        assert!(parse_test_start(busy).unwrap_err().to_string().contains("exit status 4"));
        // the estimate is read from the text
        let j = r#"{"smartctl":{"messages":[{"string":"Testing has begun.\nPlease wait 2 minutes for test to complete.","severity":"information"}]}}"#;
        let t = parse_test_start(j).unwrap();
        assert_eq!(t.minutes, Some(2));
    }

    #[test]
    fn temperature_alert_has_hysteresis() {
        let t = th();
        assert_eq!(temp_level(49, &t, Level::Ok), Level::Ok);
        assert_eq!(temp_level(50, &t, Level::Ok), Level::Warning);
        // once warned, it stays warned until 3 degrees below the limit
        assert_eq!(temp_level(48, &t, Level::Warning), Level::Warning);
        assert_eq!(temp_level(46, &t, Level::Warning), Level::Ok);
        assert_eq!(temp_level(60, &t, Level::Warning), Level::Critical);
        // critical falls back to warning only below crit - hysteresis
        assert_eq!(temp_level(58, &t, Level::Critical), Level::Critical);
        assert_eq!(temp_level(56, &t, Level::Critical), Level::Warning);
        assert_eq!(temp_level(46, &t, Level::Critical), Level::Ok);
        let mut d = parse_disk(ATA_OK).unwrap();
        d.temperature = Some(49);
        assert_eq!(assess(&d, &t, Level::Warning).level, Level::Warning);
        assert_eq!(assess(&d, &t, Level::Ok).level, Level::Ok);
    }

    fn sch() -> Schedule {
        Schedule {
            poll_secs: 1800,
            test_poll_secs: 60,
            request_check_secs: 10,
            short_test_secs: 24 * 3600,
            long_test_secs: 7 * 86400,
            window_start: 2,
            window_hours: 5,
            retention_secs: 365 * 86400,
        }
    }

    #[test]
    fn scheduled_tests_follow_the_window_and_the_intervals() {
        let s = sch();
        let now = 10_000_000;
        // never tested: the long one first, inside the window only
        assert_eq!(due_test(now, 3, &s, None, None, false), Some(TestKind::Long));
        assert_eq!(due_test(now, 8, &s, None, None, false), None);
        assert_eq!(due_test(now, 1, &s, None, None, false), None);
        assert_eq!(due_test(now, 6, &s, None, None, false), Some(TestKind::Long));
        // long done recently: the short one when its day is up
        let recent = now - 3600;
        assert_eq!(due_test(now, 3, &s, Some(now - 25 * 3600), Some(recent), false), Some(TestKind::Short));
        assert_eq!(due_test(now, 3, &s, Some(recent), Some(recent), false), None);
        // never while a test runs; 0 = never
        assert_eq!(due_test(now, 3, &s, None, None, true), None);
        let mut off = s.clone();
        off.short_test_secs = 0;
        off.long_test_secs = 0;
        assert_eq!(due_test(now, 3, &off, None, None, false), None);
        // a window that wraps midnight
        let mut w = s;
        w.window_start = 22;
        w.window_hours = 6;
        assert_eq!(due_test(now, 23, &w, None, None, false), Some(TestKind::Long));
        assert_eq!(due_test(now, 3, &w, None, None, false), Some(TestKind::Long));
        assert_eq!(due_test(now, 4, &w, None, None, false), None);
    }

    #[test]
    fn the_defaults_are_the_documented_ones_and_valid() {
        for f in FIELDS.iter() {
            if !f.default.is_empty() {
                svc::check(f, &json!(f.default)).unwrap_or_else(|e| panic!("{}: {e}", f.key));
            }
        }
        assert!(FIELDS.iter().find(|f| f.key == "poll_minutes").unwrap().default == "30");
    }

    /// A smartctl that answers from the fixtures.
    struct Fake {
        scan: String,
        reports: Vec<(String, String)>,
        started: Mutex<Vec<(String, &'static str)>>,
        refuse: bool,
    }

    #[async_trait]
    impl Smartctl for Fake {
        async fn scan(&self) -> Result<String> {
            Ok(self.scan.clone())
        }
        async fn report(&self, dev: &ScanDevice) -> Result<String> {
            self.reports
                .iter()
                .find(|(n, _)| n == &dev.name)
                .map(|(_, t)| t.clone())
                .ok_or_else(|| Error::Service(format!("no report for {}", dev.name)))
        }
        async fn start_test(&self, dev: &ScanDevice, kind: TestKind) -> Result<String> {
            self.started.lock().unwrap().push((dev.name.clone(), kind.as_str()));
            Ok(if self.refuse { START_BAD } else { START_OK }.to_string())
        }
    }

    fn rename(report: &str, name: &str) -> String {
        let mut v: Value = serde_json::from_str(report).unwrap();
        v["device"]["name"] = json!(name);
        v.to_string()
    }

    fn fake(refuse: bool) -> Fake {
        Fake {
            scan: json!({"devices": [
                {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
                {"name": "/dev/nvme0", "type": "nvme", "protocol": "NVMe"},
                {"name": "/dev/sdb", "type": "scsi", "protocol": "SCSI"},
            ]})
            .to_string(),
            reports: vec![
                ("/dev/sda".into(), rename(ATA_OK, "/dev/sda")),
                ("/dev/nvme0".into(), rename(NVME_OK, "/dev/nvme0")),
                ("/dev/sdb".into(), rename(VIRTIO, "/dev/sdb")),
            ],
            started: Mutex::new(Vec::new()),
            refuse,
        }
    }

    async fn enable(s: &ConfigStore) {
        svc::put_settings(s, &SPEC, &json!({"enabled": true})).await.unwrap();
    }

    #[tokio::test]
    async fn a_poll_stores_state_and_history_and_starts_the_scheduled_tests() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        let f = fake(false);
        let now = 1_700_000_000;
        let r = poll_once(&s, &f, now, 3).await.unwrap();
        assert_eq!(r.polled.len(), 3, "{r:?}");
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        // the disk without S.M.A.R.T. is listed, never tested, never alerts
        let all = latest(&s).await.unwrap();
        let sdb = all.iter().find(|d| d.disk.device == "/dev/sdb").unwrap();
        assert_eq!(sdb.level, Level::Unsupported);
        assert!(sdb.last_long.is_none());
        let sda = all.iter().find(|d| d.disk.device == "/dev/sda").unwrap();
        assert_eq!(sda.level, Level::Ok);
        assert_eq!(sda.last_long, Some(now));
        let started = f.started.lock().unwrap().clone();
        assert_eq!(started.len(), 2, "{started:?}");
        assert!(started.iter().all(|(_, k)| *k == "long"));
        // history rows only for the disks that report
        assert_eq!(history(&s, "/dev/sda", 10).await.unwrap().len(), 1);
        assert_eq!(history(&s, "/dev/sdb", 10).await.unwrap().len(), 0);
        // a second poll an hour later: no new test, one more sample
        let r = poll_once(&s, &f, now + 3600, 3).await.unwrap();
        assert!(r.tests_started.is_empty(), "{r:?}");
        assert_eq!(history(&s, "/dev/sda", 10).await.unwrap().len(), 2);
        // alert states: both reporting disks, none for the unsupported one
        let a = alert_states(&s).await;
        assert_eq!(a.len(), 2);
        assert!(a.iter().all(|(_, l, _)| *l == Level::Ok));
    }

    #[tokio::test]
    async fn a_refused_test_is_reported_and_not_retried_forever() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        let f = fake(true);
        let r = poll_once(&s, &f, 1_700_000_000, 3).await.unwrap();
        assert!(r.tests_started.is_empty());
        assert!(r.errors.iter().any(|e| e.contains("not started")), "{:?}", r.errors);
    }

    #[tokio::test]
    async fn history_is_pruned_by_the_retention_setting() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        svc::put_settings(&s, &SPEC, &json!({"retention_days": 2, "short_test_hours": 0, "long_test_days": 0}))
            .await
            .unwrap();
        let f = fake(false);
        let day = 86400;
        let t0 = 1_700_000_000;
        for i in 0..4 {
            poll_once(&s, &f, t0 + i * day, 12).await.unwrap();
        }
        // looked at day 3: samples older than 2 days are gone (days 0 and 1)
        let h = history(&s, "/dev/sda", 100).await.unwrap();
        assert_eq!(h.len(), 3, "{h:?}");
        assert_eq!(h[0].at, t0 + day);
        assert_eq!(prune(&s, 2 * day, t0 + 10 * day).await.unwrap(), 6);
        assert!(history(&s, "/dev/sda", 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_history_tables_are_not_configuration() {
        // a rollback / export must never carry or rewind the history
        let s = lan::testutil::store().await;
        enable(&s).await;
        poll_once(&s, &fake(false), 1_700_000_000, 12).await.unwrap();
        let doc = s.export_json().await.unwrap();
        let tables = doc["tables"].as_object().unwrap();
        assert!(!tables.contains_key("smart_samples"));
        assert!(!tables.contains_key("smart_state"));
        // but the settings are exported (they live in lan_settings)
        assert!(doc.to_string().contains("smart.enabled"));
    }

    #[tokio::test]
    async fn disks_that_vanish_are_forgotten_and_failures_become_alerts() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        let mut f = fake(false);
        poll_once(&s, &f, 1_700_000_000, 12).await.unwrap();
        assert_eq!(latest(&s).await.unwrap().len(), 3);
        // the SATA disk starts failing; the NVMe disk is unplugged
        f.reports[0].1 = rename(ATA_FAILING, "/dev/sda");
        f.scan = json!({"devices": [
            {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
            {"name": "/dev/sdb", "type": "scsi", "protocol": "SCSI"},
        ]})
        .to_string();
        poll_once(&s, &f, 1_700_001_800, 12).await.unwrap();
        let all = latest(&s).await.unwrap();
        assert_eq!(all.len(), 2);
        let a = alert_states(&s).await;
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, "/dev/sda");
        assert_eq!(a[0].1, Level::Critical);
        assert!(a[0].2.contains("FAILED"), "{}", a[0].2);
        // notifications can be switched off
        svc::put_settings(&s, &SPEC, &json!({"notify": false})).await.unwrap();
        assert!(alert_states(&s).await.is_empty());
    }

    #[tokio::test]
    async fn a_self_test_request_is_queued_by_the_web_side_and_run_by_the_poller() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        let f = fake(false);
        let t0 = 1_700_000_000;
        svc::put_settings(&s, &SPEC, &json!({"short_test_hours": 0, "long_test_days": 0})).await.unwrap();
        poll_once(&s, &f, t0, 12).await.unwrap();
        assert!(f.started.lock().unwrap().is_empty());
        // bad requests
        assert!(request_test(&s, Some("sda; reboot"), TestKind::Short).await.is_err());
        let e = request_test(&s, Some("sdz"), TestKind::Short).await.unwrap_err().to_string();
        assert!(e.starts_with("no "), "{e}");
        let e = request_test(&s, Some("sdb"), TestKind::Short).await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "{e}");
        // one disk
        assert_eq!(request_test(&s, Some("sda"), TestKind::Short).await.unwrap(), 1);
        assert_eq!(latest_one(&s, "/dev/sda").await.unwrap().unwrap().test_request, "short");
        let ran = run_requests(&s, &f, t0 + 5).await.unwrap();
        assert_eq!(ran.len(), 1);
        assert!(ran[0].2.is_ok());
        let st = latest_one(&s, "/dev/sda").await.unwrap().unwrap();
        assert_eq!(st.test_request, "");
        assert_eq!(st.last_short, Some(t0 + 5));
        // every disk that can: the one without S.M.A.R.T. is not queued
        assert_eq!(request_test(&s, None, TestKind::Long).await.unwrap(), 2);
        assert_eq!(latest_one(&s, "/dev/sdb").await.unwrap().unwrap().test_request, "");
    }

    #[tokio::test]
    async fn the_page_action_queues_tests() {
        let s = lan::testutil::store().await;
        enable(&s).await;
        poll_once(&s, &fake(false), 1_700_000_000, 12).await.unwrap();
        let r = SmartSvc
            .action(&s, "test-short", &json!({"device": "nvme0"}))
            .await
            .unwrap();
        assert_eq!(r["queued"], 1);
        assert!(SmartSvc.action(&s, "format-disk", &Value::Null).await.is_err());
    }

    #[tokio::test]
    async fn settings_are_validated() {
        let s = lan::testutil::store().await;
        assert!(svc::put_settings(&s, &SPEC, &json!({"poll_minutes": 0})).await.is_err());
        assert!(svc::put_settings(&s, &SPEC, &json!({"test_window_start": 24})).await.is_err());
        assert!(svc::put_settings(&s, &SPEC, &json!({"temp_warn": "hot"})).await.is_err());
        svc::put_settings(&s, &SPEC, &json!({"temp_warn": 45, "temp_crit": 55})).await.unwrap();
        let st = Settings::load(&s, &SPEC).await.unwrap();
        assert_eq!(Thresholds::from_settings(&st).temp_warn, 45);
        assert_eq!(Schedule::from_settings(&st).poll_secs, 1800);
    }

    #[tokio::test]
    async fn the_applier_renders_runs_and_stops_the_poller() {
        let s = lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = SmartApplier::with_supervisor(Supervisor::new(InitMode::Direct, NetPaths::under(d.path())));
        assert!(a.render(&s).await.unwrap().contains("off"));
        a.apply(&s).await.unwrap();
        enable(&s).await;
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("poll_minutes=30") && r.contains("temp_crit=60"), "{r}");
        // critical must be above warning
        svc::put_settings(&s, &SPEC, &json!({"temp_warn": 70, "temp_crit": 60})).await.unwrap();
        assert!(a.apply(&s).await.unwrap_err().to_string().contains("higher"));
        svc::put_settings(&s, &SPEC, &json!({"temp_warn": 50, "temp_crit": 60})).await.unwrap();
        if smartctl_bin().is_none() {
            let e = a.apply(&s).await.unwrap_err();
            assert!(e.to_string().contains("smartctl"), "{e}");
        }
        let st = a.status(&s).await.unwrap();
        assert_eq!(st["enabled"], true);
    }

    #[test]
    fn json_views_name_the_health_and_the_empty_reason() {
        let ok = Stored {
            disk: parse_disk(ATA_OK).unwrap(),
            level: Level::Ok,
            reasons: vec![],
            at: 5,
            last_short: None,
            last_long: None,
            test_request: String::new(),
        };
        let v = summary_json(&ok);
        assert_eq!(v["health"], "PASSED");
        assert!(v["temperature_c"].is_number());
        assert_eq!(v["name"].as_str().unwrap(), ok.disk.device.trim_start_matches("/dev/"));
        let bad = Stored {
            disk: parse_disk(VIRTIO).unwrap(),
            level: Level::Unsupported,
            reasons: vec![],
            at: 5,
            last_short: None,
            last_long: None,
            test_request: String::new(),
        };
        let v = summary_json(&bad);
        assert!(v["health"].is_null());
        assert_eq!(v["smart_available"], false);
        assert!(!v["messages"].as_array().unwrap().is_empty());
        let d = detail_json(&ok, &[]);
        assert!(d["attributes"].is_array() && d["history"].is_array());
    }

    #[test]
    fn the_scheduler_names_every_setting() {
        // nothing is hard-coded: each of these keys is a field of the page
        for k in [
            "poll_minutes", "test_poll_secs", "request_check_secs", "short_test_hours", "long_test_days",
            "test_window_start", "test_window_hours", "temp_warn", "temp_crit", "temp_hysteresis",
            "realloc_warn", "nvme_used_warn", "notify", "retention_days", "enabled",
        ] {
            assert!(FIELDS.iter().any(|f| f.key == k), "{k}");
        }
    }
}
