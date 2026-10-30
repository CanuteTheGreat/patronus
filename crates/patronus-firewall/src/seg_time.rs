//! Parental time limits for managed devices (design 8, `seg_time_*` tables).
//!
//! A *time policy* (attached to a group, or to one device which then wins)
//! has any number of weekly windows (the device is only online inside one;
//! no window = always) and an optional daily quota of *active* minutes. A
//! minute counts as used when the device moved more than
//! `active_bytes_per_min` bytes in it (conntrack byte counters), so an idle
//! phone does not burn the quota. The "day" rolls over at `reset_hour`.
//!
//! Enforcement: table `inet patronus_time` (own table so it survives every
//! firewall re-apply, and because the "time's up" redirect needs a NAT hook).
//! Device addresses are *elements of sets*, toggled with one atomic `nft -f`
//! (no full reload, other devices see no blip):
//!
//! - `blocked_v4`: forwarded traffic of the device is rejected/dropped (both
//!   directions); to the router only ICMP, DNS, DHCP and the time's-up page
//!   are allowed (so DNS/DHCP keep working and the admin UI does not);
//! - `blocked_hard_v4`: same, but nothing at all (policy `allow_dns = 0`);
//! - `blocked_mac`: the device's MAC, to cut IPv6 as well;
//! - `warn_v4` (timeout 2 min): one-shot grace warning, plain HTTP of the
//!   device is redirected to the time's-up page so the phone's own
//!   captive-portal check shows "N minutes left";
//! - blocked devices get the same HTTP redirect ("time's up").
//!
//! The decision is a pure function of (policy, usage, clock), see
//! [`decide`]; the clock is `schedule::now()` so `PATRONUS_FAKE_TIME_FILE`
//! drives it in netlab. [`TimeTicker`] adds the accounting; `patronus apply`
//! (via [`SegTimeApplier`]) recomputes the sets at boot.

use crate::schedule::{self, Schedule};
use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime, Timelike};
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use serde::Serialize;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::Ipv4Addr;

pub const TABLE_NAME: &str = "patronus_time";
/// Plain-HTTP port of the "time's up" page (`patronus-captiveportal` timeup).
pub const PORTAL_PORT: u16 = 8081;
/// A one-shot grace warning redirects HTTP for this long.
pub const WARN_SECONDS: u32 = 120;

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct TimePolicy {
    pub id: i64,
    pub name: String,
    pub daily_limit_minutes: Option<i64>,
    pub reset_hour: u32,
    pub active_bytes_per_min: u64,
    pub allow_dns: bool,
    pub grace_minutes: i64,
    pub windows: Vec<Schedule>,
}

/// One managed device with the policy that applies to it.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub device_id: i64,
    pub name: String,
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub policy: TimePolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub used: i64,
    pub bonus: i64,
    pub paused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    None,
    Paused,
    Window,
    Quota,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::None => "",
            Reason::Paused => "paused",
            Reason::Window => "window",
            Reason::Quota => "quota",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub blocked: bool,
    pub reason: Reason,
    /// quota minutes left today (None = no quota)
    pub remaining: Option<i64>,
    /// minutes until the current window ends (None = no windows / not in one)
    pub window_ends_in: Option<i64>,
    /// inside the grace period before a cut
    pub warn: bool,
    /// when access comes back (`HH:MM`, with a weekday if not today)
    pub resume_at: String,
}

impl Decision {
    /// Minutes until the device is cut: the sooner of the quota and the window end.
    pub fn minutes_left(&self) -> Option<i64> {
        match (self.remaining, self.window_ends_in) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// The "day" a minute belongs to: it rolls over at `reset_hour`, not midnight.
pub fn usage_day(at: NaiveDateTime, reset_hour: u32) -> String {
    (at - Duration::hours(i64::from(reset_hour.min(23))))
        .format("%Y-%m-%d")
        .to_string()
}

fn in_window(windows: &[Schedule], at: NaiveDateTime) -> bool {
    windows.is_empty() || windows.iter().any(|w| w.is_active_at(at))
}

/// Minutes from `at` until the "in a window" state flips (looks ahead a week).
fn minutes_until_flip(windows: &[Schedule], at: NaiveDateTime) -> Option<i64> {
    if windows.is_empty() {
        return None;
    }
    let now_in = in_window(windows, at);
    (1..=7 * 24 * 60).find(|m| in_window(windows, at + Duration::minutes(*m)) != now_in)
}

fn fmt_resume(at: NaiveDateTime, when: NaiveDateTime) -> String {
    if when.date() == at.date() {
        when.format("%H:%M").to_string()
    } else {
        when.format("%a %H:%M").to_string()
    }
}

/// Decide for one device at `at`. Priority of reasons: paused, outside the
/// windows, quota used up.
pub fn decide(p: &TimePolicy, u: &Usage, at: NaiveDateTime) -> Decision {
    let at = at.with_second(0).unwrap_or(at);
    let remaining = p.daily_limit_minutes.map(|l| (l + u.bonus - u.used).max(0));
    let inside = in_window(&p.windows, at);
    let flip = minutes_until_flip(&p.windows, at);
    let window_ends_in = if inside { flip } else { None };
    let (reason, resume_at) = if u.paused {
        (Reason::Paused, String::new())
    } else if !inside {
        let when = flip.map(|m| at + Duration::minutes(m));
        (
            Reason::Window,
            when.map(|w| fmt_resume(at, w)).unwrap_or_default(),
        )
    } else if remaining == Some(0) {
        // the next day starts at reset_hour:00
        let reset = at
            .date()
            .and_hms_opt(p.reset_hour.min(23), 0, 0)
            .unwrap_or(at);
        let next = if reset > at {
            reset
        } else {
            reset + Duration::days(1)
        };
        (Reason::Quota, fmt_resume(at, next))
    } else {
        (Reason::None, String::new())
    };
    let blocked = reason != Reason::None;
    let g = p.grace_minutes;
    let warn = !blocked
        && g > 0
        && (remaining.is_some_and(|r| r <= g) || window_ends_in.is_some_and(|m| m <= g));
    Decision {
        blocked,
        reason,
        remaining,
        window_ends_in,
        warn,
        resume_at,
    }
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

/// Is `s` a lower-case `aa:bb:cc:dd:ee:ff`?
pub fn valid_mac(s: &str) -> bool {
    let p: Vec<&str> = s.split(':').collect();
    p.len() == 6
        && p.iter()
            .all(|b| b.len() == 2 && b.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Active devices that have a time policy (their own, else their group's).
pub async fn load_targets(store: &ConfigStore) -> Result<Vec<Target>> {
    let pool = store.pool()?;
    let mut windows: HashMap<i64, Vec<Schedule>> = HashMap::new();
    for r in
        sqlx::query(r#"SELECT policy_id, days, start, "end" FROM seg_time_windows ORDER BY id"#)
            .fetch_all(pool)
            .await
            .map_err(db("load time windows"))?
    {
        let w = Schedule {
            name: "w".into(),
            days: r
                .get::<String, _>(1)
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            start: r.get(2),
            end: r.get(3),
            description: None,
        };
        // a stored window that no longer validates must not widen access
        // (it would never match, so the device would be blocked: fail closed)
        windows
            .entry(r.get(0))
            .or_default()
            .push(w.validated().unwrap_or(Schedule {
                name: "w".into(),
                days: vec!["mon".into()],
                start: "00:00".into(),
                end: "00:01".into(),
                description: Some("invalid window".into()),
            }));
    }
    let rows = sqlx::query(
        "SELECT d.id, d.name, d.ip4, d.mac, p.id, p.name, p.daily_limit_minutes, p.reset_hour,
                p.active_bytes_per_min, p.allow_dns, p.grace_minutes
         FROM seg_devices d
         JOIN seg_groups g ON g.id = d.group_id
         JOIN seg_time_policies p ON p.id = COALESCE(d.time_policy_id, g.time_policy_id)
         WHERE d.state = 'active' AND d.ip4 IS NOT NULL
         ORDER BY d.id",
    )
    .fetch_all(pool)
    .await
    .map_err(db("load time targets"))?;
    let mut out = Vec::new();
    for r in rows {
        let Ok(ip) = r.get::<String, _>(2).trim().parse::<Ipv4Addr>() else {
            continue;
        };
        let pid: i64 = r.get(4);
        out.push(Target {
            device_id: r.get(0),
            name: r.get(1),
            ip,
            mac: r
                .get::<Option<String>, _>(3)
                .map(|m| m.to_ascii_lowercase())
                .filter(|m| valid_mac(m)),
            policy: TimePolicy {
                id: pid,
                name: r.get(5),
                daily_limit_minutes: r.get(6),
                reset_hour: r.get::<i64, _>(7).clamp(0, 23) as u32,
                active_bytes_per_min: r.get::<i64, _>(8).max(0) as u64,
                allow_dns: r.get::<i64, _>(9) != 0,
                grace_minutes: r.get::<i64, _>(10).max(0),
                windows: windows.get(&pid).cloned().unwrap_or_default(),
            },
        });
    }
    Ok(out)
}

pub async fn load_usage(store: &ConfigStore, day: &str, device_id: i64) -> Result<Usage> {
    let r = sqlx::query(
        "SELECT used_minutes, bonus_minutes, paused FROM seg_time_usage WHERE day = ? AND device_id = ?",
    )
    .bind(day)
    .bind(device_id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("load time usage"))?;
    Ok(r.map(|r| Usage {
        used: r.get(0),
        bonus: r.get(1),
        paused: r.get::<i64, _>(2) != 0,
    })
    .unwrap_or_default())
}

async fn ensure_row(store: &ConfigStore, day: &str, device_id: i64) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO seg_time_usage (day, device_id) VALUES (?, ?)")
        .bind(day)
        .bind(device_id)
        .execute(store.pool()?)
        .await
        .map_err(db("create usage row"))?;
    Ok(())
}

pub async fn add_used(store: &ConfigStore, day: &str, device_id: i64, minutes: i64) -> Result<()> {
    ensure_row(store, day, device_id).await?;
    sqlx::query(
        "UPDATE seg_time_usage SET used_minutes = used_minutes + ? WHERE day = ? AND device_id = ?",
    )
    .bind(minutes)
    .bind(day)
    .bind(device_id)
    .execute(store.pool()?)
    .await
    .map_err(db("add used minutes"))?;
    Ok(())
}

/// Parent action "+N minutes today".
pub async fn add_bonus(store: &ConfigStore, day: &str, device_id: i64, minutes: i64) -> Result<()> {
    if !(1..=24 * 60).contains(&minutes) {
        return Err(invalid("bonus: minutes must be 1..1440"));
    }
    ensure_row(store, day, device_id).await?;
    sqlx::query("UPDATE seg_time_usage SET bonus_minutes = bonus_minutes + ? WHERE day = ? AND device_id = ?")
        .bind(minutes)
        .bind(day)
        .bind(device_id)
        .execute(store.pool()?)
        .await
        .map_err(db("add bonus minutes"))?;
    Ok(())
}

/// Parent actions "Pause internet now" / "Resume". A pause outlives the day
/// roll-over: it is kept on every day row, so it is stored as the *latest* row
/// and carried by [`load_usage_carry`].
pub async fn set_paused(
    store: &ConfigStore,
    day: &str,
    device_id: i64,
    paused: bool,
) -> Result<()> {
    ensure_row(store, day, device_id).await?;
    sqlx::query("UPDATE seg_time_usage SET paused = ? WHERE day = ? AND device_id = ?")
        .bind(i64::from(paused))
        .bind(day)
        .bind(device_id)
        .execute(store.pool()?)
        .await
        .map_err(db("set pause"))?;
    if !paused {
        // resuming clears an older pause too
        sqlx::query("UPDATE seg_time_usage SET paused = 0 WHERE device_id = ?")
            .bind(device_id)
            .execute(store.pool()?)
            .await
            .map_err(db("clear pause"))?;
    }
    Ok(())
}

/// Usage for `day`, where a pause from an earlier day still holds (a parent
/// who paused the tablet at night does not expect it to wake up at 06:00).
pub async fn load_usage_carry(store: &ConfigStore, day: &str, device_id: i64) -> Result<Usage> {
    let mut u = load_usage(store, day, device_id).await?;
    if !u.paused {
        let r = sqlx::query(
            "SELECT 1 FROM seg_time_usage WHERE device_id = ? AND paused = 1 AND day < ? LIMIT 1",
        )
        .bind(device_id)
        .bind(day)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("load carried pause"))?;
        u.paused = r.is_some();
    }
    Ok(u)
}

/// Drop usage rows older than `keep_days`.
pub async fn prune_usage(store: &ConfigStore, now: NaiveDateTime, keep_days: i64) -> Result<()> {
    let cut = (now - Duration::days(keep_days))
        .format("%Y-%m-%d")
        .to_string();
    sqlx::query("DELETE FROM seg_time_usage WHERE day < ? AND paused = 0")
        .bind(cut)
        .execute(store.pool()?)
        .await
        .map_err(db("prune usage"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// policies (CRUD for the API)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyOut {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub daily_limit_minutes: Option<i64>,
    pub reset_hour: i64,
    pub active_bytes_per_min: i64,
    pub allow_dns: bool,
    pub grace_minutes: i64,
    pub windows: Vec<WindowIo>,
    /// groups and devices that use the policy
    pub groups: Vec<String>,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct WindowIo {
    pub days: Vec<String>,
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PolicyIn {
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// `Some(None)` is spelled `0` in the API: no quota
    #[serde(default)]
    pub daily_limit_minutes: Option<i64>,
    #[serde(default)]
    pub reset_hour: Option<i64>,
    #[serde(default)]
    pub active_bytes_per_min: Option<i64>,
    #[serde(default)]
    pub allow_dns: Option<bool>,
    #[serde(default)]
    pub grace_minutes: Option<i64>,
    /// replaces all windows when present
    #[serde(default)]
    pub windows: Option<Vec<WindowIo>>,
}

fn invalid(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid {m}"))
}

fn check_policy_in(i: &PolicyIn, creating: bool) -> Result<Option<Vec<WindowIo>>> {
    if creating && i.name.is_none() {
        return Err(invalid("policy: a name is required"));
    }
    if let Some(n) = &i.name {
        if !(1..=32).contains(&n.len())
            || !n
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(invalid(format!(
                "policy name {n:?} (a-z, 0-9, - and _, at most 32)"
            )));
        }
    }
    if let Some(l) = i.daily_limit_minutes {
        if !(0..=1440).contains(&l) {
            return Err(invalid("daily limit: 1..1440 minutes (0 = no quota)"));
        }
    }
    if let Some(h) = i.reset_hour {
        if !(0..=23).contains(&h) {
            return Err(invalid("reset hour: 0..23"));
        }
    }
    if let Some(b) = i.active_bytes_per_min {
        if !(0..=100_000_000).contains(&b) {
            return Err(invalid("active bytes per minute: 0..100000000"));
        }
    }
    if let Some(g) = i.grace_minutes {
        if !(0..=120).contains(&g) {
            return Err(invalid("grace period: 0..120 minutes"));
        }
    }
    if let Some(d) = &i.description {
        if d.len() > 200 || d.chars().any(|c| c.is_control()) {
            return Err(invalid("description"));
        }
    }
    let Some(ws) = &i.windows else {
        return Ok(None);
    };
    if ws.len() > 28 {
        return Err(invalid("windows: at most 28"));
    }
    let mut out = Vec::new();
    for w in ws {
        let v = Schedule {
            name: "w".into(),
            days: w.days.clone(),
            start: w.start.clone(),
            end: w.end.clone(),
            description: None,
        }
        .validated()?;
        out.push(WindowIo {
            days: v.days,
            start: v.start,
            end: v.end,
        });
    }
    Ok(Some(out))
}

fn unique(e: sqlx::Error, name: &str) -> Error {
    if e.to_string().contains("UNIQUE") {
        invalid(format!("request: policy {name:?} already exists"))
    } else {
        Error::Config(format!("store: {e}"))
    }
}

async fn replace_windows(store: &ConfigStore, id: i64, ws: &[WindowIo]) -> Result<()> {
    let pool = store.pool()?;
    sqlx::query("DELETE FROM seg_time_windows WHERE policy_id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db("clear windows"))?;
    for w in ws {
        sqlx::query(
            r#"INSERT INTO seg_time_windows (policy_id, days, start, "end") VALUES (?,?,?,?)"#,
        )
        .bind(id)
        .bind(w.days.join(","))
        .bind(&w.start)
        .bind(&w.end)
        .execute(pool)
        .await
        .map_err(db("add window"))?;
    }
    Ok(())
}

pub async fn create_policy(store: &ConfigStore, i: &PolicyIn) -> Result<i64> {
    let ws = check_policy_in(i, true)?;
    let name = i.name.clone().unwrap_or_default();
    let r = sqlx::query(
        "INSERT INTO seg_time_policies (name, description, daily_limit_minutes, reset_hour,
            active_bytes_per_min, allow_dns, grace_minutes, updated_at) VALUES (?,?,?,?,?,?,?,?)",
    )
    .bind(&name)
    .bind(&i.description)
    .bind(i.daily_limit_minutes.filter(|l| *l > 0))
    .bind(i.reset_hour.unwrap_or(6))
    .bind(i.active_bytes_per_min.unwrap_or(20000))
    .bind(i64::from(i.allow_dns.unwrap_or(true)))
    .bind(i.grace_minutes.unwrap_or(5))
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &name))?;
    let id = r.last_insert_rowid();
    replace_windows(store, id, &ws.unwrap_or_default()).await?;
    Ok(id)
}

pub async fn update_policy(store: &ConfigStore, id: i64, i: &PolicyIn) -> Result<()> {
    let ws = check_policy_in(i, false)?;
    let cur = sqlx::query(
        "SELECT name, description, daily_limit_minutes, reset_hour, active_bytes_per_min, allow_dns, grace_minutes
         FROM seg_time_policies WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(store.pool()?)
    .await
    .map_err(db("load policy"))?
    .ok_or_else(|| Error::Config(format!("time policy {id} not found")))?;
    let name = i.name.clone().unwrap_or_else(|| cur.get(0));
    let limit: Option<i64> = match i.daily_limit_minutes {
        Some(l) => Some(l).filter(|l| *l > 0),
        None => cur.get(2),
    };
    sqlx::query(
        "UPDATE seg_time_policies SET name=?, description=?, daily_limit_minutes=?, reset_hour=?,
            active_bytes_per_min=?, allow_dns=?, grace_minutes=?, updated_at=? WHERE id=?",
    )
    .bind(&name)
    .bind(i.description.clone().or_else(|| cur.get(1)))
    .bind(limit)
    .bind(i.reset_hour.unwrap_or_else(|| cur.get(3)))
    .bind(i.active_bytes_per_min.unwrap_or_else(|| cur.get(4)))
    .bind(i64::from(
        i.allow_dns.unwrap_or_else(|| cur.get::<i64, _>(5) != 0),
    ))
    .bind(i.grace_minutes.unwrap_or_else(|| cur.get(6)))
    .bind(chrono::Utc::now().timestamp())
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(|e| unique(e, &name))?;
    if let Some(ws) = ws {
        replace_windows(store, id, &ws).await?;
    }
    Ok(())
}

/// Deleting a policy detaches it from every group and device (they are
/// unlimited again).
pub async fn delete_policy(store: &ConfigStore, id: i64) -> Result<()> {
    let pool = store.pool()?;
    for sql in [
        "UPDATE seg_groups SET time_policy_id = NULL WHERE time_policy_id = ?",
        "UPDATE seg_devices SET time_policy_id = NULL WHERE time_policy_id = ?",
        "DELETE FROM seg_time_windows WHERE policy_id = ?",
    ] {
        sqlx::query(sql)
            .bind(id)
            .execute(pool)
            .await
            .map_err(db("detach time policy"))?;
    }
    let r = sqlx::query("DELETE FROM seg_time_policies WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map_err(db("delete time policy"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("time policy {id} not found")));
    }
    Ok(())
}

pub async fn list_policies(store: &ConfigStore) -> Result<Vec<PolicyOut>> {
    let pool = store.pool()?;
    let rows = sqlx::query(
        "SELECT id, name, description, daily_limit_minutes, reset_hour, active_bytes_per_min, allow_dns, grace_minutes
         FROM seg_time_policies ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .map_err(db("list time policies"))?;
    let mut out = Vec::new();
    for r in rows {
        let id: i64 = r.get(0);
        let windows = sqlx::query(
            r#"SELECT days, start, "end" FROM seg_time_windows WHERE policy_id = ? ORDER BY id"#,
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .map_err(db("list windows"))?
        .iter()
        .map(|w| WindowIo {
            days: w
                .get::<String, _>(0)
                .split(',')
                .filter(|d| !d.is_empty())
                .map(String::from)
                .collect(),
            start: w.get(1),
            end: w.get(2),
        })
        .collect();
        let groups: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM seg_groups WHERE time_policy_id = ? ORDER BY name",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .map_err(db("policy groups"))?;
        let devices: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM seg_devices WHERE time_policy_id = ? ORDER BY name",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .map_err(db("policy devices"))?;
        out.push(PolicyOut {
            id,
            name: r.get(1),
            description: r.get(2),
            daily_limit_minutes: r.get(3),
            reset_hour: r.get(4),
            active_bytes_per_min: r.get(5),
            allow_dns: r.get::<i64, _>(6) != 0,
            grace_minutes: r.get(7),
            windows,
            groups,
            devices,
        });
    }
    Ok(out)
}

/// Attach a time policy to a group or device (`None` = unlimited).
pub async fn assign(
    store: &ConfigStore,
    kind: &str,
    id: i64,
    policy_id: Option<i64>,
) -> Result<()> {
    let table = match kind {
        "group" => "seg_groups",
        "device" => "seg_devices",
        k => return Err(invalid(format!("assign target {k:?} (group or device)"))),
    };
    if let Some(p) = policy_id {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM seg_time_policies WHERE id = ?")
            .bind(p)
            .fetch_one(store.pool()?)
            .await
            .map_err(db("check policy"))?;
        if n == 0 {
            return Err(Error::Config(format!("time policy {p} not found")));
        }
    }
    let r = sqlx::query(&format!(
        "UPDATE {table} SET time_policy_id = ? WHERE id = ?"
    ))
    .bind(policy_id)
    .bind(id)
    .execute(store.pool()?)
    .await
    .map_err(db("assign time policy"))?;
    if r.rows_affected() == 0 {
        return Err(Error::Config(format!("{kind} {id} not found")));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsageRow {
    pub device_id: i64,
    pub device: String,
    pub ip: String,
    pub policy: String,
    pub state: &'static str,
    pub reason: &'static str,
    pub used_minutes: i64,
    pub bonus_minutes: i64,
    pub limit_minutes: Option<i64>,
    pub remaining_minutes: Option<i64>,
    pub window_ends_in: Option<i64>,
    pub resume_at: String,
    pub paused: bool,
}

/// Live per-device view for the UI (computed now, not read from the ticker).
pub async fn usage_overview(store: &ConfigStore, at: NaiveDateTime) -> Result<Vec<UsageRow>> {
    Ok(evaluate_all(store, at)
        .await?
        .into_iter()
        .map(|(t, u, d)| UsageRow {
            device_id: t.device_id,
            device: t.name,
            ip: t.ip.to_string(),
            policy: t.policy.name,
            state: if d.blocked {
                "blocked"
            } else if d.warn {
                "warn"
            } else {
                "ok"
            },
            reason: d.reason.as_str(),
            used_minutes: u.used,
            bonus_minutes: u.bonus,
            limit_minutes: t.policy.daily_limit_minutes.map(|l| l + u.bonus),
            remaining_minutes: d.remaining,
            window_ends_in: d.window_ends_in,
            resume_at: d.resume_at,
            paused: u.paused,
        })
        .collect())
}

/// Re-evaluate and push the sets to the kernel now (after a policy change or
/// a parent action), without accounting.
pub async fn refresh(store: &ConfigStore) -> Result<()> {
    let at = schedule::now();
    let ds = evaluate_all(store, at).await?;
    let port = portal_port(store).await;
    if ds.is_empty() && !table_exists() {
        return Ok(());
    }
    run_nft(&render_script(&sets_from(&ds), &[], port))?;
    write_state(store, &ds, chrono::Utc::now().timestamp()).await
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

/// The desired kernel state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sets {
    pub blocked: BTreeSet<Ipv4Addr>,
    pub blocked_hard: BTreeSet<Ipv4Addr>,
    pub macs: BTreeSet<String>,
}

fn elems<T: std::fmt::Display>(it: impl Iterator<Item = T>) -> String {
    it.map(|x| x.to_string()).collect::<Vec<_>>().join(", ")
}

/// The whole table as one idempotent script (every `add` is a no-op when the
/// object exists; chains and sets are flushed and refilled in the same
/// transaction). `warn_new` are one-shot grace warnings.
pub fn render_script(sets: &Sets, warn_new: &[Ipv4Addr], port: u16) -> String {
    let t = format!("inet {TABLE_NAME}");
    let mut s = String::new();
    s.push_str(&format!("add table {t}\n"));
    s.push_str(&format!("add set {t} blocked_v4 {{ type ipv4_addr; }}\n"));
    s.push_str(&format!(
        "add set {t} blocked_hard_v4 {{ type ipv4_addr; }}\n"
    ));
    s.push_str(&format!("add set {t} blocked_mac {{ type ether_addr; }}\n"));
    s.push_str(&format!(
        "add set {t} warn_v4 {{ type ipv4_addr; flags timeout; }}\n"
    ));
    s.push_str(&format!(
        "add chain {t} forward {{ type filter hook forward priority -11; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain {t} input {{ type filter hook input priority -11; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain {t} prerouting {{ type nat hook prerouting priority -101; policy accept; }}\n"
    ));
    for c in ["forward", "input", "prerouting"] {
        s.push_str(&format!("flush chain {t} {c}\n"));
    }
    for set in ["blocked_v4", "blocked_hard_v4", "blocked_mac"] {
        s.push_str(&format!("flush set {t} {set}\n"));
    }
    if !sets.blocked.is_empty() {
        s.push_str(&format!(
            "add element {t} blocked_v4 {{ {} }}\n",
            elems(sets.blocked.iter())
        ));
    }
    if !sets.blocked_hard.is_empty() {
        s.push_str(&format!(
            "add element {t} blocked_hard_v4 {{ {} }}\n",
            elems(sets.blocked_hard.iter())
        ));
    }
    if !sets.macs.is_empty() {
        s.push_str(&format!(
            "add element {t} blocked_mac {{ {} }}\n",
            elems(sets.macs.iter())
        ));
    }
    if !warn_new.is_empty() {
        s.push_str(&format!(
            "add element {t} warn_v4 {{ {} }}\n",
            warn_new
                .iter()
                .map(|ip| format!("{ip} timeout {WARN_SECONDS}s"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    // forward: nothing leaves or reaches a blocked device (TCP is reset so
    // apps fail fast instead of hanging); IPv6 is cut by MAC
    for set in ["blocked_v4", "blocked_hard_v4"] {
        s.push_str(&format!(
            "add rule {t} forward ip saddr @{set} meta l4proto tcp counter reject with tcp reset comment \"time limit\"\n"
        ));
        s.push_str(&format!(
            "add rule {t} forward ip saddr @{set} counter drop comment \"time limit\"\n"
        ));
        s.push_str(&format!(
            "add rule {t} forward ip daddr @{set} counter drop comment \"time limit (inbound)\"\n"
        ));
    }
    s.push_str(&format!(
        "add rule {t} forward meta nfproto ipv6 ether saddr @blocked_mac counter drop comment \"time limit (IPv6)\"\n"
    ));
    // input: a blocked device may still reach ICMP, DNS, DHCP and the page
    s.push_str(&format!(
        "add rule {t} input ip saddr @blocked_hard_v4 counter drop comment \"time limit (hard)\"\n"
    ));
    s.push_str(&format!(
        "add rule {t} input ip saddr @blocked_v4 meta l4proto icmp return\n"
    ));
    s.push_str(&format!(
        "add rule {t} input ip saddr @blocked_v4 udp dport {{ 53, 67 }} return\n"
    ));
    s.push_str(&format!(
        "add rule {t} input ip saddr @blocked_v4 tcp dport {{ 53, {port} }} return\n"
    ));
    s.push_str(&format!(
        "add rule {t} input ip saddr @blocked_v4 counter drop comment \"time limit\"\n"
    ));
    s.push_str(&format!(
        "add rule {t} input meta nfproto ipv6 ether saddr @blocked_mac meta l4proto != icmpv6 counter drop comment \"time limit (IPv6)\"\n"
    ));
    // the \"time's up\" / grace page: plain HTTP of these devices is redirected
    for set in ["blocked_v4", "warn_v4"] {
        s.push_str(&format!(
            "add rule {t} prerouting ip saddr @{set} tcp dport 80 counter redirect to :{port}\n"
        ));
    }
    s
}

/// Run an nft script; the error carries nft's message.
pub fn run_nft(script: &str) -> Result<()> {
    crate::nftables::execute_nft_script(script).map(|_| ())
}

fn table_exists() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", TABLE_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Elements of `blocked_v4`/`blocked_hard_v4` as the kernel has them now
/// (for status pages and tests).
pub fn live_sets() -> Result<BTreeMap<String, Vec<String>>> {
    let out = crate::nftables::execute_nft_command(&["-j", "list", "table", "inet", TABLE_NAME])?;
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|e| Error::Firewall(format!("nft json: {e}")))?;
    let mut m = BTreeMap::new();
    for item in v["nftables"].as_array().into_iter().flatten() {
        if let Some(set) = item.get("set") {
            let name = set["name"].as_str().unwrap_or("").to_string();
            let el: Vec<String> = set["elem"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| match e {
                    serde_json::Value::String(s) => s.clone(),
                    o => o["elem"]["val"].as_str().unwrap_or("").to_string(),
                })
                .collect();
            m.insert(name, el);
        }
    }
    Ok(m)
}

/// Decisions for every target now (pure given the store and the clock).
pub async fn evaluate_all(
    store: &ConfigStore,
    at: NaiveDateTime,
) -> Result<Vec<(Target, Usage, Decision)>> {
    let mut out = Vec::new();
    for t in load_targets(store).await? {
        let day = usage_day(at, t.policy.reset_hour);
        let u = load_usage_carry(store, &day, t.device_id).await?;
        let d = decide(&t.policy, &u, at);
        out.push((t, u, d));
    }
    Ok(out)
}

pub fn sets_from(decisions: &[(Target, Usage, Decision)]) -> Sets {
    let mut s = Sets::default();
    for (t, _, d) in decisions {
        if !d.blocked {
            continue;
        }
        if t.policy.allow_dns {
            s.blocked.insert(t.ip);
        } else {
            s.blocked_hard.insert(t.ip);
        }
        if let Some(m) = &t.mac {
            s.macs.insert(m.clone());
        }
    }
    s
}

/// The time's-up page port (`seg.time_portal_port` in `lan_settings`).
pub async fn portal_port(store: &ConfigStore) -> u16 {
    let Ok(pool) = store.pool() else {
        return PORTAL_PORT;
    };
    sqlx::query("SELECT value FROM lan_settings WHERE key = 'seg.time_portal_port'")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.get::<String, _>(0).trim().parse::<u16>().ok())
        .filter(|p| *p >= 1024)
        .unwrap_or(PORTAL_PORT)
}

async fn write_state(
    store: &ConfigStore,
    ds: &[(Target, Usage, Decision)],
    now_ts: i64,
) -> Result<()> {
    let pool = store.pool()?;
    sqlx::query("DELETE FROM seg_time_state")
        .execute(pool)
        .await
        .map_err(db("clear time state"))?;
    for (t, u, d) in ds {
        let state = if d.blocked {
            "blocked"
        } else if d.warn {
            "warn"
        } else {
            "ok"
        };
        sqlx::query(
            "INSERT INTO seg_time_state (device_id, ip, state, reason, used_minutes, limit_minutes,
                 remaining_minutes, resume_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(t.device_id)
        .bind(t.ip.to_string())
        .bind(state)
        .bind(d.reason.as_str())
        .bind(u.used)
        .bind(t.policy.daily_limit_minutes.map(|l| l + u.bonus))
        .bind(d.minutes_left())
        .bind(&d.resume_at)
        .bind(now_ts)
        .execute(pool)
        .await
        .map_err(db("write time state"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// conntrack accounting
// ---------------------------------------------------------------------------

/// `(flow key, bytes)` of one conntrack line for a device address: both
/// directions are summed; the key is the original tuple.
pub fn flow_bytes(line: &str, ip: &str) -> Option<(String, u64)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let get = |k: &str| -> Vec<&str> {
        words
            .iter()
            .filter_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .collect()
    };
    let src = get("src");
    let dst = get("dst");
    let (s0, d0) = (src.first()?, dst.first()?);
    if *s0 != ip && *d0 != ip {
        return None;
    }
    let bytes: u64 = get("bytes")
        .iter()
        .filter_map(|b| b.parse::<u64>().ok())
        .sum();
    let key = format!(
        "{}|{}>{}|{}>{}",
        words.get(2).copied().unwrap_or(""),
        s0,
        d0,
        get("sport").first().copied().unwrap_or(""),
        get("dport").first().copied().unwrap_or("")
    );
    Some((key, bytes))
}

/// Accounting state of the minute ticker.
#[derive(Default)]
pub struct TimeTicker {
    /// last byte count of each flow (per device) to turn counters into deltas
    last: HashMap<(i64, String), u64>,
    /// bytes moved in the current clock minute
    minute_bytes: HashMap<i64, u64>,
    minute: Option<NaiveDateTime>,
    /// what `seg_time_state` holds now (rewritten only when it changes: the
    /// router's flash must not take a write per second)
    written: Option<Vec<StateKey>>,
    /// the kernel state we last wrote
    loaded: Option<(Sets, u16)>,
    loaded_at: Option<NaiveDateTime>,
    /// devices that were blocked at some tick of the current minute: that
    /// minute does not count (the time's-up page, DNS and retries of a
    /// blocked device must not burn tomorrow's quota)
    blocked_minute: BTreeSet<i64>,
    /// devices already warned in their current grace period
    warned: BTreeSet<i64>,
    pub last_error: Option<String>,
}

type StateKey = (i64, String, &'static str, String, i64, Option<i64>, String);

fn state_keys(ds: &[(Target, Usage, Decision)]) -> Vec<StateKey> {
    ds.iter()
        .map(|(t, u, d)| {
            (
                t.device_id,
                t.ip.to_string(),
                if d.blocked {
                    "blocked"
                } else if d.warn {
                    "warn"
                } else {
                    "ok"
                },
                format!("{}|{}", d.reason.as_str(), d.resume_at),
                u.used,
                d.minutes_left(),
                format!("{:?}", t.policy.daily_limit_minutes.map(|l| l + u.bonus)),
            )
        })
        .collect()
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub blocked: usize,
    pub warned: usize,
    pub counted: Vec<i64>,
    pub changed: bool,
}

impl TimeTicker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add this poll's byte deltas (conntrack text) to the current minute.
    pub fn account(&mut self, targets: &[Target], conntrack: &str) {
        let mut seen: BTreeSet<(i64, String)> = BTreeSet::new();
        for line in conntrack.lines() {
            for t in targets {
                if let Some((key, bytes)) = flow_bytes(line, &t.ip.to_string()) {
                    let k = (t.device_id, key);
                    let prev = self.last.get(&k).copied();
                    // a flow first seen mid-minute contributes only what we
                    // see after this poll, unless it is brand new (small)
                    let delta = match prev {
                        Some(p) => bytes.saturating_sub(p),
                        None => bytes,
                    };
                    *self.minute_bytes.entry(t.device_id).or_default() += delta;
                    self.last.insert(k.clone(), bytes);
                    seen.insert(k);
                }
            }
        }
        self.last.retain(|k, _| seen.contains(k));
    }

    /// Close the previous minute if the clock moved on: devices above the
    /// threshold used one minute.
    async fn close_minute(
        &mut self,
        store: &ConfigStore,
        targets: &[Target],
        at: NaiveDateTime,
    ) -> Result<Vec<i64>> {
        let cur = at.with_second(0).unwrap_or(at);
        let mut counted = Vec::new();
        if let Some(prev) = self.minute {
            if prev != cur {
                for t in targets {
                    let b = self.minute_bytes.get(&t.device_id).copied().unwrap_or(0);
                    if b >= t.policy.active_bytes_per_min
                        && t.policy.daily_limit_minutes.is_some()
                        && !self.blocked_minute.contains(&t.device_id)
                    {
                        let day = usage_day(prev, t.policy.reset_hour);
                        add_used(store, &day, t.device_id, 1).await?;
                        counted.push(t.device_id);
                    }
                }
                self.minute_bytes.clear();
                self.blocked_minute.clear();
            }
        }
        self.minute = Some(cur);
        Ok(counted)
    }

    /// One tick: account, decide, reconcile the kernel. `conntrack` is the
    /// text of `/proc/net/nf_conntrack`; `apply_nft = false` skips the kernel
    /// (unit tests and `--dry-run`).
    pub async fn tick(
        &mut self,
        store: &ConfigStore,
        at: NaiveDateTime,
        conntrack: &str,
        apply_nft: bool,
    ) -> Result<TickReport> {
        let targets = load_targets(store).await?;
        // close the previous minute first: a poll in the new minute belongs to it
        let counted = self.close_minute(store, &targets, at).await?;
        self.account(&targets, conntrack);
        let ds = evaluate_all(store, at).await?;
        let sets = sets_from(&ds);
        let port = portal_port(store).await;
        for (t, _, d) in &ds {
            if d.blocked {
                self.blocked_minute.insert(t.device_id);
            }
        }
        // one-shot grace warnings
        let warn_now: BTreeSet<i64> = ds
            .iter()
            .filter(|(_, _, d)| d.warn)
            .map(|(t, _, _)| t.device_id)
            .collect();
        let warn_new: Vec<Ipv4Addr> = ds
            .iter()
            .filter(|(t, _, d)| d.warn && !self.warned.contains(&t.device_id))
            .map(|(t, _, _)| t.ip)
            .collect();
        self.warned.retain(|id| warn_now.contains(id));
        self.warned.extend(warn_now.iter().copied());
        let want = (sets.clone(), port);
        let stale = self
            .loaded_at
            .map(|l| at - l >= Duration::minutes(1) || at < l)
            .unwrap_or(true);
        let changed = self.loaded.as_ref() != Some(&want);
        if apply_nft && ds.is_empty() && self.loaded.is_none() && !table_exists() {
            // no policy in use and no table: nothing to enforce or clean up
            return Ok(TickReport {
                counted,
                ..TickReport::default()
            });
        }
        let mut report = TickReport {
            blocked: sets.blocked.len() + sets.blocked_hard.len(),
            warned: warn_new.len(),
            counted,
            changed,
        };
        let keys = state_keys(&ds);
        if self.written.as_ref() != Some(&keys) {
            write_state(store, &ds, chrono::Utc::now().timestamp()).await?;
            self.written = Some(keys);
        }
        if apply_nft && (changed || !warn_new.is_empty() || stale) {
            // self-heal: someone deleted the table -> recreate it
            let script = render_script(&sets, &warn_new, port);
            match run_nft(&script) {
                Ok(()) => {
                    self.loaded = Some(want);
                    self.loaded_at = Some(at);
                    self.last_error = None;
                }
                Err(e) => {
                    self.last_error = Some(e.to_string());
                    report.changed = false;
                    return Err(e);
                }
            }
        } else if !apply_nft {
            self.loaded = Some(want);
        }
        Ok(report)
    }

    /// Is the table still in the kernel? (the ticker recreates it when not)
    pub fn table_present() -> bool {
        table_exists()
    }
}

// ---------------------------------------------------------------------------
// applier (boot: `patronus apply`)
// ---------------------------------------------------------------------------

/// Loads the time-limit table at boot / on demand from the stored state,
/// before the first forwarded packet is allowed (fail closed).
#[derive(Default)]
pub struct SegTimeApplier;

#[async_trait]
impl Applier for SegTimeApplier {
    fn name(&self) -> &'static str {
        "segtime"
    }

    fn phase(&self) -> Phase {
        Phase::Firewall
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let ds = evaluate_all(store, schedule::now()).await?;
        let sets = sets_from(&ds);
        let port = portal_port(store).await;
        if ds.is_empty() && !table_exists() {
            rep.applied("time limits: no policy in use".to_string());
            return Ok(rep);
        }
        run_nft(&render_script(&sets, &[], port))?;
        write_state(store, &ds, chrono::Utc::now().timestamp()).await?;
        rep.applied(format!(
            "time limits: {} device(s) with a policy, {} blocked now",
            ds.len(),
            sets.blocked.len() + sets.blocked_hard.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let ds = evaluate_all(store, schedule::now()).await?;
        Ok(render_script(
            &sets_from(&ds),
            &[],
            portal_port(store).await,
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<serde_json::Value> {
        let ds = evaluate_all(store, schedule::now()).await?;
        Ok(serde_json::json!({
            "devices": ds.len(),
            "blocked": ds.iter().filter(|(_, _, d)| d.blocked).count(),
            "table_loaded": table_exists(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap()
    }

    fn win(days: &[&str], s: &str, e: &str) -> Schedule {
        Schedule {
            name: "w".into(),
            days: days.iter().map(|d| d.to_string()).collect(),
            start: s.into(),
            end: e.into(),
            description: None,
        }
        .validated()
        .unwrap()
    }

    fn pol(limit: Option<i64>, windows: Vec<Schedule>) -> TimePolicy {
        TimePolicy {
            id: 1,
            name: "kids".into(),
            daily_limit_minutes: limit,
            reset_hour: 6,
            active_bytes_per_min: 20000,
            allow_dns: true,
            grace_minutes: 5,
            windows,
        }
    }

    #[test]
    fn day_rolls_over_at_reset_hour_not_midnight() {
        assert_eq!(usage_day(at("2026-10-12 05:59"), 6), "2026-10-11");
        assert_eq!(usage_day(at("2026-10-12 06:00"), 6), "2026-10-12");
        assert_eq!(usage_day(at("2026-10-12 00:30"), 0), "2026-10-12");
    }

    #[test]
    fn window_edges_and_midnight_wrap() {
        // school nights: mon-thu 16:00-20:00; fri/sat 16:00-23:00; 2026-10-12 is a Monday
        let p = pol(
            None,
            vec![
                win(&["mon", "tue", "wed", "thu"], "16:00", "20:00"),
                win(&["fri", "sat"], "16:00", "02:00"),
            ],
        );
        let u = Usage::default();
        assert!(decide(&p, &u, at("2026-10-12 15:59")).blocked);
        assert!(!decide(&p, &u, at("2026-10-12 16:00")).blocked);
        assert!(!decide(&p, &u, at("2026-10-12 19:59")).blocked);
        let d = decide(&p, &u, at("2026-10-12 20:00"));
        assert!(d.blocked && d.reason == Reason::Window);
        assert_eq!(d.resume_at, "Tue 16:00");
        // friday window wraps: Saturday 01:30 is still inside, 02:00 is not
        assert!(!decide(&p, &u, at("2026-10-17 01:30")).blocked);
        assert!(decide(&p, &u, at("2026-10-17 02:00")).blocked);
    }

    #[test]
    fn no_window_means_always_and_no_quota_means_unlimited() {
        let p = pol(None, vec![]);
        let d = decide(&p, &Usage::default(), at("2026-10-12 03:00"));
        assert!(!d.blocked && !d.warn && d.remaining.is_none());
    }

    #[test]
    fn quota_bonus_pause_and_priority() {
        let p = pol(Some(120), vec![win(&["mon"], "08:00", "22:00")]);
        let mut u = Usage {
            used: 100,
            bonus: 0,
            paused: false,
        };
        let d = decide(&p, &u, at("2026-10-12 10:00"));
        assert!(!d.blocked);
        assert_eq!(d.remaining, Some(20));
        u.used = 120;
        let d = decide(&p, &u, at("2026-10-12 10:00"));
        assert!(d.blocked && d.reason == Reason::Quota);
        assert_eq!(d.resume_at, "Tue 06:00");
        // +30 minutes today
        u.bonus = 30;
        let d = decide(&p, &u, at("2026-10-12 10:00"));
        assert!(!d.blocked);
        assert_eq!(d.remaining, Some(30));
        // pause beats everything, even inside the window with quota left
        u.paused = true;
        assert_eq!(
            decide(&p, &u, at("2026-10-12 10:00")).reason,
            Reason::Paused
        );
        // outside the window beats the quota reason
        u.paused = false;
        u.used = 500;
        assert_eq!(
            decide(&p, &u, at("2026-10-12 23:00")).reason,
            Reason::Window
        );
    }

    #[test]
    fn grace_warning_before_quota_and_window_end() {
        let p = pol(Some(120), vec![win(&["mon"], "08:00", "22:00")]);
        let u = Usage {
            used: 114,
            ..Usage::default()
        };
        let d = decide(&p, &u, at("2026-10-12 10:00"));
        assert!(!d.blocked && !d.warn); // 6 left > 5 grace
        let u = Usage {
            used: 115,
            ..Usage::default()
        };
        assert!(decide(&p, &u, at("2026-10-12 10:00")).warn); // exactly 5 left
                                                              // window ends 22:00: warn from 21:55
        let u = Usage::default();
        assert!(!decide(&p, &u, at("2026-10-12 21:54")).warn);
        let d = decide(&p, &u, at("2026-10-12 21:55"));
        assert!(d.warn && d.window_ends_in == Some(5));
        // grace 0 turns the warning off
        let mut p0 = p.clone();
        p0.grace_minutes = 0;
        assert!(!decide(&p0, &u, at("2026-10-12 21:59")).warn);
        // a blocked device is not "warned"
        assert!(!decide(&p, &u, at("2026-10-12 22:00")).warn);
    }

    #[test]
    fn minutes_left_is_the_sooner_of_quota_and_window() {
        let p = pol(Some(120), vec![win(&["mon"], "08:00", "22:00")]);
        let u = Usage {
            used: 100,
            ..Usage::default()
        };
        // 20 quota minutes left, 60 until the window ends
        assert_eq!(
            decide(&p, &u, at("2026-10-12 21:00")).minutes_left(),
            Some(20)
        );
        // 20 quota minutes left, 5 until the window ends
        assert_eq!(
            decide(&p, &u, at("2026-10-12 21:55")).minutes_left(),
            Some(5)
        );
        assert_eq!(
            decide(&pol(None, vec![]), &u, at("2026-10-12 21:55")).minutes_left(),
            None
        );
    }

    #[test]
    fn dst_day_keeps_minute_accounting() {
        // 2026-11-01 (US fall back) has a 25 h day in local time; the usage day
        // key is a calendar date so a repeated 01:xx hour stays on the same day
        assert_eq!(usage_day(at("2026-11-01 01:30"), 6), "2026-10-31");
        assert_eq!(usage_day(at("2026-11-01 07:00"), 6), "2026-11-01");
    }

    #[test]
    fn nft_script_has_sets_chains_and_redirect() {
        let mut s = Sets::default();
        s.blocked.insert("172.31.77.12".parse().unwrap());
        s.blocked_hard.insert("172.31.77.13".parse().unwrap());
        s.macs.insert("02:aa:00:00:00:12".into());
        let t = render_script(&s, &["172.31.77.14".parse().unwrap()], 8081);
        assert!(t.contains("add element inet patronus_time blocked_v4 { 172.31.77.12 }"));
        assert!(t.contains("add element inet patronus_time blocked_hard_v4 { 172.31.77.13 }"));
        assert!(t.contains("blocked_mac { 02:aa:00:00:00:12 }"));
        assert!(t.contains("warn_v4 { 172.31.77.14 timeout 120s }"));
        assert!(t.contains("ip saddr @blocked_v4 tcp dport 80 counter redirect to :8081"));
        assert!(t.contains("ip saddr @warn_v4 tcp dport 80 counter redirect to :8081"));
        assert!(t.contains("input ip saddr @blocked_v4 udp dport { 53, 67 } return"));
        assert!(t.contains("tcp dport { 53, 8081 } return"));
        // forward chain is refilled in the same transaction as the sets
        assert!(
            t.find("flush chain inet patronus_time forward").unwrap()
                < t.find("add rule inet patronus_time forward").unwrap()
        );
        // nothing blocked: no empty `add element` (nft syntax error)
        let e = render_script(&Sets::default(), &[], 8081);
        assert!(!e.contains("add element"));
    }

    #[test]
    fn conntrack_bytes_are_summed_per_flow_and_deltas_are_counted_once() {
        let line = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.2.3.4 sport=40000 dport=443 packets=10 bytes=1000 src=1.2.3.4 dst=10.0.0.5 sport=443 dport=40000 packets=12 bytes=9000 [ASSURED] mark=0 use=1";
        let other = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.9 dst=1.2.3.4 sport=1 dport=443 packets=1 bytes=99999 src=1.2.3.4 dst=10.0.0.9 sport=443 dport=1 packets=1 bytes=1 [ASSURED]";
        let (k, b) = flow_bytes(line, "10.0.0.5").unwrap();
        assert_eq!(b, 10_000);
        assert!(k.contains("10.0.0.5>1.2.3.4"));
        assert!(flow_bytes(other, "10.0.0.5").is_none());
        // a different device whose address is a prefix must not match
        assert!(flow_bytes(line, "10.0.0.50").is_none());
        let policy = pol(Some(60), vec![]);
        let tg = vec![Target {
            device_id: 7,
            name: "tab".into(),
            ip: "10.0.0.5".parse().unwrap(),
            mac: None,
            policy,
        }];
        let mut tk = TimeTicker::new();
        tk.account(&tg, line);
        assert_eq!(tk.minute_bytes[&7], 10_000);
        tk.account(&tg, line); // same counters again: no new bytes
        assert_eq!(tk.minute_bytes[&7], 10_000);
        let grown = line.replace("bytes=1000 ", "bytes=3000 ");
        tk.account(&tg, &grown);
        assert_eq!(tk.minute_bytes[&7], 12_000);
        // the flow ends; its entry is forgotten (a new flow starts from 0)
        tk.account(&tg, "");
        assert!(tk.last.is_empty());
    }

    #[test]
    fn mac_validation_rejects_injection() {
        assert!(valid_mac("02:aa:00:00:00:12"));
        assert!(!valid_mac("02:aa:00:00:00:12; flush ruleset"));
        assert!(!valid_mac("02:aa:00:00:00"));
        assert!(!valid_mac("zz:aa:00:00:00:12"));
    }

    async fn fixture() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let q = |sql: &'static str| {
            let pool = s.pool().unwrap().clone();
            async move { sqlx::query(sql).execute(&pool).await.unwrap() }
        };
        q("INSERT INTO seg_time_policies (id, name, daily_limit_minutes, reset_hour, active_bytes_per_min, allow_dns, grace_minutes)
           VALUES (1, 'kids', 3, 6, 1000, 1, 1), (2, 'strict', NULL, 6, 1000, 0, 0)").await;
        q(
            r#"INSERT INTO seg_time_windows (policy_id, days, start, "end")
           VALUES (2, 'mon,tue,wed,thu,fri,sat,sun', '16:00', '20:00')"#,
        )
        .await;
        q("INSERT INTO seg_groups (id, name, time_policy_id) VALUES (11, 'kids', 1), (12, 'family', NULL)").await;
        q("INSERT INTO seg_devices (id, name, mac, group_id, kind, segment, ip4, state, created_at)
           VALUES (1, 'tablet', '02:AA:00:00:00:01', 11, 'wifi', '@lan', '10.0.0.11', 'active', 0),
                  (2, 'laptop', '02:aa:00:00:00:02', 12, 'wired', '@lan', '10.0.0.12', 'active', 0),
                  (3, 'switch', NULL, 12, 'wired', '@lan', '10.0.0.13', 'active', 0),
                  (4, 'old-tab', '02:aa:00:00:00:04', 11, 'wifi', '@lan', '10.0.0.14', 'revoked', 0)").await;
        // switch has its own (device) policy that overrides the group's (none)
        q("UPDATE seg_devices SET time_policy_id = 2 WHERE id = 3").await;
        s
    }

    fn flow(ip: &str, bytes: u64) -> String {
        format!("ipv4 2 tcp 6 100 ESTABLISHED src={ip} dst=1.1.1.1 sport=5000 dport=443 packets=9 bytes={bytes} src=1.1.1.1 dst={ip} sport=443 dport=5000 packets=9 bytes=0 [ASSURED]\n")
    }

    #[tokio::test]
    async fn targets_follow_device_over_group_and_skip_revoked() {
        let s = fixture().await;
        let t = load_targets(&s).await.unwrap();
        let names: Vec<_> = t
            .iter()
            .map(|x| (x.name.as_str(), x.policy.name.as_str()))
            .collect();
        // laptop has no policy; the revoked tablet is not enforced (the seg table drops it)
        assert_eq!(names, vec![("tablet", "kids"), ("switch", "strict")]);
        assert_eq!(t[0].mac.as_deref(), Some("02:aa:00:00:00:01")); // lower-cased
        assert_eq!(t[1].mac, None);
        assert_eq!(t[1].policy.windows.len(), 1);
        assert!(!t[1].policy.allow_dns);
    }

    #[tokio::test]
    async fn quota_is_consumed_by_active_minutes_only_and_cuts_at_the_limit() {
        let s = fixture().await;
        let mut tk = TimeTicker::new();
        let mut bytes = 0u64;
        // 2026-10-12 is a Monday; the quota is 3 active minutes, threshold 1000 B/min
        for (i, m) in ["10:00", "10:01", "10:02", "10:03", "10:04"]
            .iter()
            .enumerate()
        {
            // the tablet moves 5000 B in minutes 10:00-10:02, nothing after
            if i < 3 {
                bytes += 5000;
            }
            let r = tk
                .tick(
                    &s,
                    at(&format!("2026-10-12 {m}")),
                    &flow("10.0.0.11", bytes),
                    false,
                )
                .await
                .unwrap();
            // an idle minute (10:03) is closed when the clock moves to 10:04
            let _ = r;
        }
        let u = load_usage(&s, "2026-10-12", 1).await.unwrap();
        assert_eq!(u.used, 3, "three active minutes counted, idle ones not");
        let ds = evaluate_all(&s, at("2026-10-12 10:05")).await.unwrap();
        let (t, _, d) = &ds[0];
        assert_eq!(t.name, "tablet");
        assert!(d.blocked && d.reason == Reason::Quota);
        assert!(sets_from(&ds)
            .blocked
            .contains(&"10.0.0.11".parse::<Ipv4Addr>().unwrap()));
        // the state table feeds the time's-up page
        let st: (String, String, i64) = sqlx::query_as(
            "SELECT state, reason, used_minutes FROM seg_time_state WHERE device_id = 1",
        )
        .fetch_one(s.pool().unwrap())
        .await
        .unwrap();
        assert_eq!(st, ("blocked".into(), "quota".into(), 3));
        // next day (after 06:00) the quota is fresh
        let ds = evaluate_all(&s, at("2026-10-13 06:00")).await.unwrap();
        assert!(!ds[0].2.blocked);
        // parent: +10 minutes today lifts the block
        add_bonus(&s, "2026-10-12", 1, 10).await.unwrap();
        let ds = evaluate_all(&s, at("2026-10-12 10:06")).await.unwrap();
        assert!(!ds[0].2.blocked);
        assert!(add_bonus(&s, "2026-10-12", 1, 0).await.is_err());
    }

    #[tokio::test]
    async fn traffic_of_a_blocked_device_does_not_burn_quota() {
        let s = fixture().await;
        let mut tk = TimeTicker::new();
        // pause the tablet: it is blocked all minute, but its retries move bytes
        set_paused(&s, "2026-10-12", 1, true).await.unwrap();
        let mut bytes = 0u64;
        for m in ["10:00", "10:01", "10:02"] {
            bytes += 50_000;
            tk.tick(
                &s,
                at(&format!("2026-10-12 {m}")),
                &flow("10.0.0.11", bytes),
                false,
            )
            .await
            .unwrap();
        }
        assert_eq!(load_usage(&s, "2026-10-12", 1).await.unwrap().used, 0);
        // resumed: the same traffic now counts
        set_paused(&s, "2026-10-12", 1, false).await.unwrap();
        for m in ["10:03", "10:04"] {
            bytes += 50_000;
            tk.tick(
                &s,
                at(&format!("2026-10-12 {m}")),
                &flow("10.0.0.11", bytes),
                false,
            )
            .await
            .unwrap();
        }
        assert_eq!(load_usage(&s, "2026-10-12", 1).await.unwrap().used, 1);
    }

    #[tokio::test]
    async fn grace_warning_is_one_shot_and_pause_survives_midnight() {
        let s = fixture().await;
        let mut tk = TimeTicker::new();
        add_used(&s, "2026-10-12", 1, 2).await.unwrap(); // 1 of 3 left, grace 1
        let r = tk
            .tick(&s, at("2026-10-12 10:00"), "", false)
            .await
            .unwrap();
        assert_eq!(r.warned, 1);
        let r = tk
            .tick(&s, at("2026-10-12 10:00"), "", false)
            .await
            .unwrap();
        assert_eq!(r.warned, 0, "warned once per grace period");
        // pause carries over to the next usage day
        set_paused(&s, "2026-10-12", 1, true).await.unwrap();
        let ds = evaluate_all(&s, at("2026-10-14 10:00")).await.unwrap();
        assert_eq!(ds[0].2.reason, Reason::Paused);
        set_paused(&s, "2026-10-14", 1, false).await.unwrap();
        let ds = evaluate_all(&s, at("2026-10-14 10:00")).await.unwrap();
        assert!(!ds[0].2.blocked);
    }

    #[tokio::test]
    async fn window_cuts_and_restores_and_hard_policy_uses_the_hard_set() {
        let s = fixture().await;
        let out = evaluate_all(&s, at("2026-10-12 15:00")).await.unwrap();
        let sets = sets_from(&out);
        // "switch": strict policy (windows 16-20, allow_dns = 0) -> hard set, no MAC (none stored)
        assert!(sets
            .blocked_hard
            .contains(&"10.0.0.13".parse::<Ipv4Addr>().unwrap()));
        assert!(sets.macs.is_empty());
        let out = evaluate_all(&s, at("2026-10-12 16:00")).await.unwrap();
        assert!(sets_from(&out).blocked_hard.is_empty());
        let out = evaluate_all(&s, at("2026-10-12 20:00")).await.unwrap();
        assert_eq!(sets_from(&out).blocked_hard.len(), 1);
    }
}
