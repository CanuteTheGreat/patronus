//! Firewall schedules (time-based rules).
//!
//! A schedule is a set of weekdays plus a daily time window in local time
//! (`end < start` wraps past midnight: `22:00-06:00`). A filter rule that
//! names a schedule is only rendered into nftables while the schedule is
//! active; patronus-web re-applies the firewall when a schedule starts or
//! ends ([`scheduled_rule_states`] is checked every few seconds), and every
//! `patronus apply` evaluates the schedules again, so a reboot inside or
//! outside a window comes up in the right state.
//!
//! Clock: local time, unless `PATRONUS_FAKE_TIME_FILE` names a file that
//! holds `YYYY-MM-DD HH:MM` -- a test hook used by the netlab CI to toggle a
//! schedule at a mocked time (the kernel clock cannot be faked per network
//! namespace).
//!
//! Table: `firewall_schedules` (lane B migration 0100).

use chrono::{Datelike, NaiveDateTime, NaiveTime, Timelike, Weekday};
use patronus_config::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// Environment variable naming the fake-clock file (tests only).
pub const FAKE_TIME_ENV: &str = "PATRONUS_FAKE_TIME_FILE";

/// A stored schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    pub name: String,
    /// `mon` .. `sun`
    pub days: Vec<String>,
    /// `HH:MM`
    pub start: String,
    /// `HH:MM` (exclusive; `end <= start` wraps past midnight)
    pub end: String,
    #[serde(default)]
    pub description: Option<String>,
}

const DAYS: [(&str, Weekday); 7] = [
    ("mon", Weekday::Mon),
    ("tue", Weekday::Tue),
    ("wed", Weekday::Wed),
    ("thu", Weekday::Thu),
    ("fri", Weekday::Fri),
    ("sat", Weekday::Sat),
    ("sun", Weekday::Sun),
];

fn parse_day(d: &str) -> Option<Weekday> {
    // chrono accepts "mon"/"monday" in any case
    d.trim().parse::<Weekday>().ok()
}

fn parse_hm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}

impl Schedule {
    /// Validate and normalise (days `mon`..`sun` in week order, `HH:MM`).
    pub fn validated(mut self) -> Result<Self> {
        if !crate::nftables::is_valid_alias_name(&self.name) {
            return Err(Error::Config(format!(
                "Invalid schedule name {:?} (a letter, then letters, digits or _, at most 31)",
                self.name
            )));
        }
        let mut days = Vec::new();
        for d in &self.days {
            let w = parse_day(d)
                .ok_or_else(|| Error::Config(format!("Invalid schedule day {d:?} (mon..sun)")))?;
            if !days.contains(&w) {
                days.push(w);
            }
        }
        if days.is_empty() {
            return Err(Error::Config(
                "Invalid schedule: pick at least one day".into(),
            ));
        }
        days.sort_by_key(|w| w.num_days_from_monday());
        self.days = days
            .iter()
            .map(|w| DAYS[w.num_days_from_monday() as usize].0.to_string())
            .collect();
        let (s, e) = (
            parse_hm(&self.start).ok_or_else(|| {
                Error::Config(format!("Invalid schedule start {:?} (HH:MM)", self.start))
            })?,
            parse_hm(&self.end).ok_or_else(|| {
                Error::Config(format!("Invalid schedule end {:?} (HH:MM)", self.end))
            })?,
        );
        self.start = s.format("%H:%M").to_string();
        self.end = e.format("%H:%M").to_string();
        Ok(self)
    }

    /// Is the schedule active at `at` (local time)? A window that wraps
    /// past midnight belongs to the day it starts on.
    pub fn is_active_at(&self, at: NaiveDateTime) -> bool {
        let (Some(s), Some(e)) = (parse_hm(&self.start), parse_hm(&self.end)) else {
            return false;
        };
        let days: Vec<Weekday> = self.days.iter().filter_map(|d| parse_day(d)).collect();
        let t = NaiveTime::from_hms_opt(at.hour(), at.minute(), 0).expect("valid time");
        let today = at.weekday();
        if s < e {
            days.contains(&today) && t >= s && t < e
        } else {
            // wraps: [s, 24:00) on a scheduled day, [00:00, e) the day after
            (days.contains(&today) && t >= s) || (days.contains(&today.pred()) && t < e)
        }
    }
}

/// "Now" for schedule evaluation: local time, or the fake clock.
pub fn now() -> NaiveDateTime {
    if let Some(p) = std::env::var_os(FAKE_TIME_ENV) {
        match std::fs::read_to_string(&p) {
            Ok(t) => match NaiveDateTime::parse_from_str(t.trim(), "%Y-%m-%d %H:%M") {
                Ok(dt) => return dt,
                Err(e) => tracing::warn!("{FAKE_TIME_ENV}: {t:?}: {e}; using the real clock"),
            },
            Err(e) => tracing::warn!("{FAKE_TIME_ENV}: {e}; using the real clock"),
        }
    }
    chrono::Local::now().naive_local()
}

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// All schedules, by name.
pub async fn load_schedules(store: &ConfigStore) -> Result<Vec<Schedule>> {
    let rows = sqlx::query(
        "SELECT name, days, start_time, end_time, description FROM firewall_schedules
         ORDER BY name",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(db("load schedules"))?;
    Ok(rows
        .iter()
        .map(|r| Schedule {
            name: r.get(0),
            days: r
                .get::<String, _>(1)
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            start: r.get(2),
            end: r.get(3),
            description: r.get(4),
        })
        .collect())
}

/// Insert or replace a schedule (validated).
pub async fn save_schedule(store: &ConfigStore, s: &Schedule) -> Result<()> {
    let s = s.clone().validated()?;
    sqlx::query(
        "INSERT INTO firewall_schedules (name, days, start_time, end_time, description, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET days = excluded.days, start_time = excluded.start_time,
             end_time = excluded.end_time, description = excluded.description,
             updated_at = excluded.updated_at",
    )
    .bind(&s.name)
    .bind(s.days.join(","))
    .bind(&s.start)
    .bind(&s.end)
    .bind(&s.description)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save schedule"))?;
    Ok(())
}

/// Delete a schedule. Refused while a rule uses it.
pub async fn delete_schedule(store: &ConfigStore, name: &str) -> Result<()> {
    let users: Vec<String> = store
        .load_firewall_rules()
        .await?
        .into_iter()
        .filter(|r| r.schedule.as_deref() == Some(name))
        .map(|r| format!("{:?}", r.name))
        .collect();
    if !users.is_empty() {
        return Err(Error::Config(format!(
            "Invalid request: schedule {name} is used by rule {}",
            users.join(", ")
        )));
    }
    sqlx::query("DELETE FROM firewall_schedules WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete schedule"))?;
    Ok(())
}

/// Which scheduled rules are active right now: `(rule id, active)` for
/// every rule with a schedule. A change in this list means the firewall
/// must be re-applied.
pub async fn scheduled_rule_states(
    store: &ConfigStore,
    at: NaiveDateTime,
) -> Result<Vec<(u64, bool)>> {
    let schedules = load_schedules(store).await?;
    Ok(store
        .load_firewall_rules()
        .await?
        .into_iter()
        .filter_map(|r| {
            let name = r.schedule.as_ref()?;
            let active = schedules
                .iter()
                .find(|s| &s.name == name)
                .map(|s| s.is_active_at(at));
            Some((r.id.unwrap_or(0), active.unwrap_or(false)))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap()
    }

    fn sched(days: &[&str], start: &str, end: &str) -> Schedule {
        Schedule {
            name: "s".into(),
            days: days.iter().map(|s| s.to_string()).collect(),
            start: start.into(),
            end: end.into(),
            description: None,
        }
        .validated()
        .unwrap()
    }

    #[test]
    fn day_window_and_midnight_wrap() {
        // 2026-10-12 is a Monday
        let work = sched(&["Mon", "tuesday", "fri"], "9:00", "17:30");
        assert_eq!(work.days, vec!["mon", "tue", "fri"]);
        assert_eq!(work.start, "09:00");
        assert!(work.is_active_at(at("2026-10-12 09:00")));
        assert!(work.is_active_at(at("2026-10-12 17:29")));
        assert!(!work.is_active_at(at("2026-10-12 17:30")));
        assert!(!work.is_active_at(at("2026-10-14 10:00"))); // Wednesday
        let night = sched(&["fri"], "22:00", "06:00");
        assert!(night.is_active_at(at("2026-10-16 23:00"))); // Fri
        assert!(night.is_active_at(at("2026-10-17 05:59"))); // Sat early
        assert!(!night.is_active_at(at("2026-10-17 06:00")));
        assert!(!night.is_active_at(at("2026-10-16 05:00"))); // Fri early (Thu not scheduled)
    }

    #[test]
    fn invalid_schedules_are_rejected() {
        let mk = |d: &[&str], s: &str, e: &str| Schedule {
            name: "s".into(),
            days: d.iter().map(|x| x.to_string()).collect(),
            start: s.into(),
            end: e.into(),
            description: None,
        };
        assert!(mk(&[], "09:00", "10:00").validated().is_err());
        assert!(mk(&["funday"], "09:00", "10:00").validated().is_err());
        assert!(mk(&["mon"], "25:00", "10:00").validated().is_err());
        assert!(mk(&["mon"], "09:00", "x").validated().is_err());
        let mut bad = mk(&["mon"], "09:00", "10:00");
        bad.name = "a b".into();
        assert!(bad.validated().is_err());
    }

    #[test]
    fn fake_clock_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("now");
        std::fs::write(&f, "2026-10-12 08:15\n").unwrap();
        std::env::set_var(FAKE_TIME_ENV, &f);
        assert_eq!(now(), at("2026-10-12 08:15"));
        std::env::remove_var(FAKE_TIME_ENV);
    }
}
