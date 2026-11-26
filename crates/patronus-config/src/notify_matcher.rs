//! Notification matchers (lane H, docs/NOTIFY-MATCHERS.md).
//!
//! A matcher is a small tree that decides whether a notification channel
//! (`event_hooks`) gets an event. Groups `all` / `any` / `not` hold child
//! matchers; the leaves test the event kind, a minimum severity, a glob on the
//! event subject (interface / gateway / tunnel name) and a calendar window
//! (weekdays plus a daily start/end time in the box's local time zone; a window
//! that ends before it starts runs past midnight and belongs to the day it
//! starts on). A channel names one matcher (`event_hooks.matcher`); matchers
//! live in `notify_matchers` (migration 0795) and are GitOps resources
//! (`kind: NotifyMatcher`).
//!
//! The evaluator here is pure: it gets the event and a local wall-clock time.
//! The web side supplies the clock (`PATRONUS_FAKE_TIME_FILE` aware) and the
//! delivery. Size limits are typed settings (`notify.matcher_max_*` in
//! `system_config`), see [`Limits`].
//!
//! ```yaml
//! - apiVersion: patronus.firewall/v1
//!   kind: NotifyMatcher
//!   metadata: { name: night-wan }
//!   spec:
//!     description: WAN trouble at night
//!     tree:
//!       op: all
//!       items:
//!         - { op: kind, kinds: [gateway_down, uplink_sla_breach] }
//!         - { op: calendar, days: [mon, tue, wed, thu, fri], start: "22:00", end: "06:00" }
//!         - op: not
//!           items: [ { op: subject, glob: "guest*" } ]
//! ```

use crate::applier::{Applier, ApplyReport, Phase};
use crate::declarative::{spec_value, DeclarativeConfig, ResourceKind};
use crate::store::ConfigStore;
use async_trait::async_trait;
use chrono::{Datelike, NaiveDateTime, NaiveTime, Timelike, Weekday};
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};

pub const SEVERITIES: &[&str] = &["info", "warning", "critical"];
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// Rank of a severity name (unknown = lowest).
pub fn severity_rank(s: &str) -> u8 {
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(0) as u8
}

/// One node of a matcher tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Matcher {
    /// Every child matches (no children: matches everything).
    All {
        #[serde(default)]
        items: Vec<Matcher>,
    },
    /// At least one child matches (needs a child).
    Any {
        #[serde(default)]
        items: Vec<Matcher>,
    },
    /// The single child does not match.
    Not {
        #[serde(default)]
        items: Vec<Matcher>,
    },
    /// The event kind is one of `kinds`.
    Kind { kinds: Vec<String> },
    /// The event severity is at least `min`.
    Severity { min: String },
    /// The event subject matches a glob (`*` any run, `?` one character).
    Subject { glob: String },
    /// Local time falls inside the window on one of the days.
    Calendar {
        days: Vec<String>,
        start: String,
        end: String,
    },
}

/// What a matcher is asked about.
#[derive(Debug, Clone)]
pub struct EventCtx<'a> {
    pub kind: &'a str,
    pub severity: &'a str,
    pub subject: &'a str,
    /// Local wall-clock time in the box's time zone.
    pub local: NaiveDateTime,
}

/// Size limits (typed settings, see [`Limits::load`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_items: usize,
    pub max_glob_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_nodes: 64,
            max_items: 32,
            max_glob_len: 64,
        }
    }
}

impl Limits {
    /// Read `notify.matcher_max_depth|nodes|items|glob_len` (defaults when unset).
    pub async fn load(store: &ConfigStore) -> Limits {
        let mut l = Limits::default();
        for (key, slot) in [
            ("notify.matcher_max_depth", &mut l.max_depth),
            ("notify.matcher_max_nodes", &mut l.max_nodes),
            ("notify.matcher_max_items", &mut l.max_items),
            ("notify.matcher_max_glob_len", &mut l.max_glob_len),
        ] {
            if let Ok(Some(v)) = store.load_system_config(key).await {
                if let Ok(n) = v.trim().parse::<usize>() {
                    if n >= 1 {
                        *slot = n;
                    }
                }
            }
        }
        l
    }
}

fn invalid(m: impl std::fmt::Display) -> Error {
    Error::Config(format!("Invalid matcher: {m}"))
}

fn parse_hm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}

fn parse_day(d: &str) -> Option<Weekday> {
    d.trim().parse::<Weekday>().ok()
}

/// `*` / `?` glob, case-sensitive, whole-string.
pub fn glob_match(glob: &str, text: &str) -> bool {
    let (g, t): (Vec<char>, Vec<char>) = (glob.chars().collect(), text.chars().collect());
    let (mut gi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if gi < g.len() && (g[gi] == '?' || g[gi] == t[ti]) {
            gi += 1;
            ti += 1;
        } else if gi < g.len() && g[gi] == '*' {
            star = Some(gi);
            mark = ti;
            gi += 1;
        } else if let Some(s) = star {
            gi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while gi < g.len() && g[gi] == '*' {
        gi += 1;
    }
    gi == g.len()
}

/// Is `at` inside the calendar window? `end <= start` runs past midnight and
/// belongs to the day it starts on; `start == end` means the whole day.
pub fn calendar_active(days: &[String], start: &str, end: &str, at: NaiveDateTime) -> bool {
    let (Some(s), Some(e)) = (parse_hm(start), parse_hm(end)) else {
        return false;
    };
    let days: Vec<Weekday> = days.iter().filter_map(|d| parse_day(d)).collect();
    let t = NaiveTime::from_hms_opt(at.hour(), at.minute(), 0).expect("valid time");
    let today = at.weekday();
    if s == e {
        days.contains(&today)
    } else if s < e {
        days.contains(&today) && t >= s && t < e
    } else {
        (days.contains(&today) && t >= s) || (days.contains(&today.pred()) && t < e)
    }
}

impl Matcher {
    /// Does the event match?
    pub fn matches(&self, c: &EventCtx<'_>) -> bool {
        match self {
            Matcher::All { items } => items.iter().all(|m| m.matches(c)),
            Matcher::Any { items } => items.iter().any(|m| m.matches(c)),
            Matcher::Not { items } => !items.first().is_some_and(|m| m.matches(c)),
            Matcher::Kind { kinds } => kinds.iter().any(|k| k == c.kind),
            Matcher::Severity { min } => severity_rank(c.severity) >= severity_rank(min),
            Matcher::Subject { glob } => glob_match(glob, c.subject),
            Matcher::Calendar { days, start, end } => calendar_active(days, start, end, c.local),
        }
    }

    /// Number of nodes in the tree.
    pub fn nodes(&self) -> usize {
        1 + match self {
            Matcher::All { items } | Matcher::Any { items } | Matcher::Not { items } => {
                items.iter().map(Matcher::nodes).sum()
            }
            _ => 0,
        }
    }

    /// Depth of the tree (a lone leaf is 1).
    pub fn depth(&self) -> usize {
        1 + match self {
            Matcher::All { items } | Matcher::Any { items } | Matcher::Not { items } => {
                items.iter().map(Matcher::depth).max().unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// Check the tree and return it normalised (days `mon`..`sun` in week
    /// order, `HH:MM`, trimmed names). `known_kinds`: the event kinds the box
    /// can raise (empty slice = do not check).
    pub fn validated(mut self, lim: &Limits, known_kinds: &[&str]) -> Result<Matcher> {
        if self.depth() > lim.max_depth {
            return Err(invalid(format!(
                "nested deeper than {} levels",
                lim.max_depth
            )));
        }
        if self.nodes() > lim.max_nodes {
            return Err(invalid(format!("more than {} nodes", lim.max_nodes)));
        }
        self.normalise(lim, known_kinds)?;
        Ok(self)
    }

    fn normalise(&mut self, lim: &Limits, known: &[&str]) -> Result<()> {
        match self {
            Matcher::Any { items } if items.is_empty() => {
                return Err(invalid("an 'any' group needs at least one item"));
            }
            Matcher::Not { items } if items.len() != 1 => {
                return Err(invalid("a 'not' group takes exactly one item"));
            }
            _ => {}
        }
        match self {
            Matcher::All { items } | Matcher::Any { items } | Matcher::Not { items } => {
                if items.len() > lim.max_items {
                    return Err(invalid(format!(
                        "more than {} items in a group",
                        lim.max_items
                    )));
                }
                for m in items.iter_mut() {
                    m.normalise(lim, known)?;
                }
            }
            Matcher::Kind { kinds } => {
                let mut out: Vec<String> = Vec::new();
                for k in kinds.iter() {
                    let k = k.trim();
                    if k.is_empty()
                        || !k
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        return Err(invalid(format!("event kind {k:?}")));
                    }
                    if !known.is_empty() && !known.contains(&k) {
                        return Err(invalid(format!("unknown event kind {k:?}")));
                    }
                    if !out.iter().any(|x| x == k) {
                        out.push(k.to_string());
                    }
                }
                if out.is_empty() {
                    return Err(invalid("a kind leaf needs at least one event kind"));
                }
                if out.len() > lim.max_items {
                    return Err(invalid(format!("more than {} kinds", lim.max_items)));
                }
                *kinds = out;
            }
            Matcher::Severity { min } => {
                let m = min.trim().to_ascii_lowercase();
                if !SEVERITIES.contains(&m.as_str()) {
                    return Err(invalid(format!(
                        "severity {min:?} (info, warning or critical)"
                    )));
                }
                *min = m;
            }
            Matcher::Subject { glob } => {
                let g = glob.trim();
                if g.is_empty()
                    || g.chars().count() > lim.max_glob_len
                    || g.chars().any(char::is_control)
                {
                    return Err(invalid(format!(
                        "subject glob (1-{} printable characters)",
                        lim.max_glob_len
                    )));
                }
                *glob = g.to_string();
            }
            Matcher::Calendar { days, start, end } => {
                let mut ds: Vec<Weekday> = Vec::new();
                for d in days.iter() {
                    let w = parse_day(d)
                        .ok_or_else(|| invalid(format!("calendar day {d:?} (mon..sun)")))?;
                    if !ds.contains(&w) {
                        ds.push(w);
                    }
                }
                if ds.is_empty() {
                    return Err(invalid("a calendar leaf needs at least one day"));
                }
                ds.sort_by_key(|w| w.num_days_from_monday());
                *days = ds
                    .iter()
                    .map(|w| DAYS[w.num_days_from_monday() as usize].to_string())
                    .collect();
                let s = parse_hm(start)
                    .ok_or_else(|| invalid(format!("calendar start {start:?} (HH:MM)")))?;
                let e = parse_hm(end)
                    .ok_or_else(|| invalid(format!("calendar end {end:?} (HH:MM)")))?;
                *start = s.format("%H:%M").to_string();
                *end = e.format("%H:%M").to_string();
            }
        }
        Ok(())
    }

    /// The matcher a channel had before matchers existed: the listed kinds
    /// (none = all kinds) and a minimum severity (`info` = no floor).
    pub fn legacy(kinds_csv: &str, min_severity: &str) -> Matcher {
        let mut items = Vec::new();
        if !kinds_csv.is_empty() {
            items.push(Matcher::Kind {
                kinds: kinds_csv.split(',').map(String::from).collect(),
            });
        }
        if !min_severity.is_empty() && min_severity != "info" {
            items.push(Matcher::Severity {
                min: min_severity.to_string(),
            });
        }
        Matcher::All { items }
    }
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

/// A stored matcher.
#[derive(Debug, Clone, Serialize)]
pub struct StoredMatcher {
    pub name: String,
    pub description: String,
    pub tree: Matcher,
    /// Channels using it.
    pub used_by: Vec<String>,
}

fn db(what: &'static str) -> impl Fn(sqlx::Error) -> Error {
    move |e| Error::Config(format!("{what}: {e}"))
}

/// Matcher names: 1-64 letters, digits, `-`, `_`, `.` or spaces.
pub fn check_name(n: &str) -> Result<()> {
    let ok = !n.is_empty()
        && n.chars().count() <= 64
        && n.trim() == n
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '));
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "Invalid matcher name {n:?}: 1-64 letters, digits, '-', '_', '.' or spaces"
        )))
    }
}

/// All matchers by name, with the channels that use each.
pub async fn list(store: &ConfigStore) -> Result<Vec<StoredMatcher>> {
    let pool = store.pool()?;
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT name, description, tree FROM notify_matchers ORDER BY name")
            .fetch_all(pool)
            .await
            .map_err(db("read notify_matchers"))?;
    let uses: Vec<(String, String)> =
        sqlx::query_as("SELECT matcher, name FROM event_hooks WHERE matcher <> '' ORDER BY name")
            .fetch_all(pool)
            .await
            .map_err(db("read event_hooks"))?;
    let mut out = Vec::new();
    for (name, description, tree) in rows {
        let tree: Matcher = serde_json::from_str(&tree)
            .map_err(|e| Error::Config(format!("matcher {name}: stored tree unreadable: {e}")))?;
        let used_by = uses
            .iter()
            .filter(|(m, _)| *m == name)
            .map(|(_, h)| h.clone())
            .collect();
        out.push(StoredMatcher {
            name,
            description,
            tree,
            used_by,
        });
    }
    Ok(out)
}

/// One matcher's tree (None when it does not exist).
pub async fn get_tree(store: &ConfigStore, name: &str) -> Result<Option<Matcher>> {
    let t: Option<String> = sqlx::query_scalar("SELECT tree FROM notify_matchers WHERE name = ?")
        .bind(name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(db("read notify_matchers"))?;
    t.map(|t| {
        serde_json::from_str(&t)
            .map_err(|e| Error::Config(format!("matcher {name}: stored tree unreadable: {e}")))
    })
    .transpose()
}

/// Create or replace a matcher (validated).
pub async fn upsert(
    store: &ConfigStore,
    name: &str,
    description: &str,
    tree: Matcher,
    known_kinds: &[&str],
) -> Result<Matcher> {
    check_name(name)?;
    let lim = Limits::load(store).await;
    let tree = tree.validated(&lim, known_kinds)?;
    let json = serde_json::to_string(&tree).expect("matcher serializes");
    sqlx::query(
        "INSERT INTO notify_matchers (name, description, tree, updated_at) VALUES (?,?,?,?)
         ON CONFLICT(name) DO UPDATE SET description = excluded.description,
             tree = excluded.tree, updated_at = excluded.updated_at",
    )
    .bind(name)
    .bind(description.trim())
    .bind(json)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(db("save notify_matchers"))?;
    Ok(tree)
}

/// Delete a matcher; refused while a channel uses it.
pub async fn delete(store: &ConfigStore, name: &str) -> Result<bool> {
    let users: Vec<String> =
        sqlx::query_scalar("SELECT name FROM event_hooks WHERE matcher = ? ORDER BY name")
            .bind(name)
            .fetch_all(store.pool()?)
            .await
            .map_err(db("read event_hooks"))?;
    if !users.is_empty() {
        return Err(Error::Config(format!(
            "Invalid delete: matcher {name} is used by channel(s) {}",
            users.join(", ")
        )));
    }
    let r = sqlx::query("DELETE FROM notify_matchers WHERE name = ?")
        .bind(name)
        .execute(store.pool()?)
        .await
        .map_err(db("delete notify_matchers"))?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------------------
// GitOps
// ---------------------------------------------------------------------------

/// Applier for `kind: NotifyMatcher`: the rows are read by patronus-web when
/// an event fires, so applying is just writing them.
pub struct NotifyMatcherApplier;

#[derive(Debug, Deserialize)]
struct Spec {
    #[serde(default)]
    description: String,
    tree: Matcher,
}

#[async_trait]
impl Applier for NotifyMatcherApplier {
    fn name(&self) -> &'static str {
        "notify-matchers"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notify_matchers")
            .fetch_one(store.pool()?)
            .await
            .map_err(db("count notify_matchers"))?;
        rep.applied(format!(
            "{n} notification matcher(s); patronus-web evaluates them when an event fires"
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(list(store)
            .await?
            .iter()
            .map(|m| {
                format!(
                    "{} {}\n",
                    m.name,
                    serde_json::to_string(&m.tree).unwrap_or_default()
                )
            })
            .collect())
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::NotifyMatcher]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let v = spec_value(config)?;
        let name = &config.metadata.name;
        let s: Spec =
            serde_json::from_value(v.clone()).map_err(|e| invalid(format!("{name}: {e}")))?;
        upsert(store, name, &s.description, s.tree, &[])
            .await
            .map(|_| ())
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        kind: &ResourceKind,
        name: &str,
    ) -> Result<()> {
        if *kind != ResourceKind::NotifyMatcher {
            return Err(invalid("resource kind for the notify-matchers applier"));
        }
        delete(store, name).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn at(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap()
    }

    fn ctx<'a>(kind: &'a str, sev: &'a str, subj: &'a str, local: NaiveDateTime) -> EventCtx<'a> {
        EventCtx {
            kind,
            severity: sev,
            subject: subj,
            local,
        }
    }

    fn parse(j: &str) -> Matcher {
        serde_json::from_str(j).unwrap()
    }

    #[test]
    fn globs() {
        assert!(glob_match("wan*", "wan"));
        assert!(glob_match("wan*", "wan2"));
        assert!(glob_match("*", ""));
        assert!(glob_match("w?n", "wan"));
        assert!(!glob_match("w?n", "wn"));
        assert!(glob_match("*lte*", "my-lte-1"));
        assert!(!glob_match("wan", "wan2"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn nested_all_any_not() {
        let m = parse(
            r#"{"op":"all","items":[
                {"op":"any","items":[{"op":"kind","kinds":["gateway_down"]},{"op":"kind","kinds":["tunnel_down"]}]},
                {"op":"not","items":[{"op":"subject","glob":"guest*"}]},
                {"op":"severity","min":"warning"}]}"#,
        );
        let t = at(2026, 11, 25, 12, 0);
        assert!(m.matches(&ctx("gateway_down", "critical", "wan", t)));
        assert!(m.matches(&ctx("tunnel_down", "warning", "office", t)));
        assert!(!m.matches(&ctx("tunnel_down", "info", "office", t)));
        assert!(!m.matches(&ctx("tunnel_down", "warning", "guest-vpn", t)));
        assert!(!m.matches(&ctx("config_changed", "critical", "x", t)));
        // not of an any, and double negation
        let n = parse(
            r#"{"op":"not","items":[{"op":"not","items":[{"op":"kind","kinds":["test"]}]}]}"#,
        );
        assert!(n.matches(&ctx("test", "info", "", t)));
        assert!(!n.matches(&ctx("tunnel_up", "info", "", t)));
        // empty all matches everything
        assert!(parse(r#"{"op":"all"}"#).matches(&ctx("x", "info", "", t)));
    }

    #[test]
    fn calendar_edges() {
        let d = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let wk = d(&["mon", "tue", "wed", "thu", "fri"]);
        // 2026-11-23 is a Monday
        assert!(calendar_active(
            &wk,
            "09:00",
            "17:00",
            at(2026, 11, 23, 9, 0)
        ));
        assert!(calendar_active(
            &wk,
            "09:00",
            "17:00",
            at(2026, 11, 23, 16, 59)
        ));
        assert!(!calendar_active(
            &wk,
            "09:00",
            "17:00",
            at(2026, 11, 23, 17, 0)
        ));
        assert!(!calendar_active(
            &wk,
            "09:00",
            "17:00",
            at(2026, 11, 23, 8, 59)
        ));
        assert!(!calendar_active(
            &wk,
            "09:00",
            "17:00",
            at(2026, 11, 28, 10, 0)
        )); // Saturday
            // across midnight: Friday 22:00 -> Saturday 06:00 belongs to Friday
        assert!(calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 27, 23, 30)
        ));
        assert!(calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 28, 5, 59)
        ));
        assert!(!calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 28, 6, 0)
        ));
        assert!(!calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 28, 23, 0)
        )); // Saturday night
            // Sunday early morning is Saturday's night: not scheduled
        assert!(!calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 29, 3, 0)
        ));
        // Monday 03:00 is Sunday's tail: not scheduled either
        assert!(!calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 23, 3, 0)
        ));
        // Tuesday 03:00 is Monday's tail
        assert!(calendar_active(
            &wk,
            "22:00",
            "06:00",
            at(2026, 11, 24, 3, 0)
        ));
        // start == end = the whole day
        assert!(calendar_active(
            &d(&["sat"]),
            "00:00",
            "00:00",
            at(2026, 11, 28, 13, 0)
        ));
        assert!(!calendar_active(
            &d(&["sat"]),
            "00:00",
            "00:00",
            at(2026, 11, 29, 13, 0)
        ));
        // 23:59 / 00:00 boundaries
        assert!(calendar_active(
            &wk,
            "00:00",
            "23:59",
            at(2026, 11, 23, 23, 58)
        ));
        assert!(!calendar_active(
            &wk,
            "00:00",
            "23:59",
            at(2026, 11, 23, 23, 59)
        ));
    }

    /// A DST change moves the wall clock: the window is in local time, so on
    /// the spring-forward day 01:30-03:30 covers 1h less real time, and the
    /// skipped 02:xx wall times never occur.
    #[test]
    fn calendar_across_dst_change() {
        // US spring forward 2026-03-08: 02:00 PST -> 03:00 PDT
        let local = |utc: i64| {
            let off = if utc < 1772964000 { -8 } else { -7 }; // 10:00 UTC
            chrono::DateTime::from_timestamp(utc + off * 3600, 0)
                .unwrap()
                .naive_utc()
        };
        let days = vec!["sun".to_string()];
        // 2026-03-08 09:30 UTC = 01:30 PST (inside), 09:59 UTC = 01:59 PST (inside)
        let base = 1772962200; // 2026-03-08 09:30:00 UTC
        assert!(calendar_active(&days, "01:30", "03:30", local(base)));
        assert!(calendar_active(
            &days,
            "01:30",
            "03:30",
            local(base + 29 * 60)
        ));
        // 10:00 UTC = 03:00 PDT: wall clock jumped, still inside (no 02:xx)
        assert_eq!(local(base + 30 * 60).hour(), 3);
        assert!(calendar_active(
            &days,
            "01:30",
            "03:30",
            local(base + 30 * 60)
        ));
        // 10:30 UTC = 03:30 PDT: window over after only 1 real hour
        assert!(!calendar_active(
            &days,
            "01:30",
            "03:30",
            local(base + 60 * 60)
        ));
        // fall back 2026-11-01: 01:30 happens twice and matches both times
        let fall = |utc: i64| {
            let off = if utc < 1793523600 { -7 } else { -8 }; // 09:00 UTC
            chrono::DateTime::from_timestamp(utc + off * 3600, 0)
                .unwrap()
                .naive_utc()
        };
        let sun = vec!["sun".to_string()];
        let t1 = 1793521800; // 08:30 UTC = 01:30 PDT
        let t2 = t1 + 3600; // 09:30 UTC = 01:30 PST
        assert_eq!(fall(t1).format("%H:%M").to_string(), "01:30");
        assert_eq!(fall(t2).format("%H:%M").to_string(), "01:30");
        assert!(calendar_active(&sun, "01:00", "02:00", fall(t1)));
        assert!(calendar_active(&sun, "01:00", "02:00", fall(t2)));
        assert!(!calendar_active(&sun, "01:00", "02:00", fall(t2 + 1800)));
    }

    #[test]
    fn validation_and_limits() {
        let lim = Limits::default();
        let ok =
            parse(r#"{"op":"calendar","days":["fri","MON","mon"],"start":"7:05","end":"18:00"}"#)
                .validated(&lim, &[])
                .unwrap();
        assert_eq!(
            ok,
            Matcher::Calendar {
                days: vec!["mon".into(), "fri".into()],
                start: "07:05".into(),
                end: "18:00".into()
            }
        );
        for bad in [
            r#"{"op":"any","items":[]}"#,
            r#"{"op":"not","items":[]}"#,
            r#"{"op":"not","items":[{"op":"kind","kinds":["a"]},{"op":"kind","kinds":["b"]}]}"#,
            r#"{"op":"kind","kinds":[]}"#,
            r#"{"op":"kind","kinds":["Bad Kind"]}"#,
            r#"{"op":"severity","min":"loud"}"#,
            r#"{"op":"subject","glob":""}"#,
            r#"{"op":"calendar","days":[],"start":"09:00","end":"10:00"}"#,
            r#"{"op":"calendar","days":["mon"],"start":"25:00","end":"10:00"}"#,
            r#"{"op":"calendar","days":["funday"],"start":"09:00","end":"10:00"}"#,
        ] {
            assert!(parse(bad).validated(&lim, &[]).is_err(), "{bad}");
        }
        assert!(parse(r#"{"op":"kind","kinds":["nope"]}"#)
            .validated(&lim, &["test"])
            .is_err());
        // depth and size limits
        let mut m = Matcher::Kind {
            kinds: vec!["test".into()],
        };
        for _ in 0..8 {
            m = Matcher::All { items: vec![m] };
        }
        assert_eq!(m.depth(), 9);
        assert!(m.clone().validated(&lim, &[]).is_err());
        assert!(m
            .validated(
                &Limits {
                    max_depth: 9,
                    ..lim
                },
                &[]
            )
            .is_ok());
        let wide = Matcher::All {
            items: (0..40)
                .map(|_| Matcher::Kind {
                    kinds: vec!["test".into()],
                })
                .collect(),
        };
        assert!(wide.clone().validated(&lim, &[]).is_err()); // > 32 items
        assert!(wide
            .validated(
                &Limits {
                    max_items: 64,
                    max_nodes: 64,
                    ..lim
                },
                &[]
            )
            .is_ok());
    }

    #[test]
    fn legacy_equivalence() {
        let t = at(2026, 11, 25, 12, 0);
        let sevs = ["info", "warning", "critical"];
        for kinds in ["", "gateway_down", "gateway_down,tunnel_up"] {
            for min in sevs {
                let m = Matcher::legacy(kinds, min);
                for k in ["gateway_down", "tunnel_up", "test"] {
                    for s in sevs {
                        let want = (kinds.is_empty() || kinds.split(',').any(|x| x == k))
                            && severity_rank(s) >= severity_rank(min);
                        assert_eq!(m.matches(&ctx(k, s, "x", t)), want, "{kinds}/{min}/{k}/{s}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn store_roundtrip_and_gitops() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let a = NotifyMatcherApplier;
        let docs = crate::declarative::ConfigParser::parse_yaml(
            "- apiVersion: patronus.firewall/v1\n  kind: NotifyMatcher\n  metadata: { name: night-wan }\n  spec:\n    description: d\n    tree: { op: all, items: [ { op: kind, kinds: [gateway_down] }, { op: calendar, days: [mon], start: \"22:00\", end: \"06:00\" } ] }\n",
        )
        .unwrap();
        a.upsert_resource(&s, &docs[0]).await.unwrap();
        let l = list(&s).await.unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].name, "night-wan");
        assert_eq!(l[0].tree.nodes(), 3);
        // a channel using it blocks deletion
        sqlx::query("INSERT INTO event_hooks (name, url, secret, kinds, enabled, created_at, matcher) VALUES ('h','http://x','','',1,0,'night-wan')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        assert!(a
            .delete_resource(&s, &ResourceKind::NotifyMatcher, "night-wan")
            .await
            .is_err());
        sqlx::query("DELETE FROM event_hooks")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        a.delete_resource(&s, &ResourceKind::NotifyMatcher, "night-wan")
            .await
            .unwrap();
        assert!(list(&s).await.unwrap().is_empty());
        // export / import carries them
        upsert(&s, "m1", "", Matcher::legacy("test", "warning"), &[])
            .await
            .unwrap();
        let doc = s.export_json().await.unwrap();
        let s2 = ConfigStore::open_in_memory().await.unwrap();
        s2.import_json(&doc).await.unwrap();
        assert_eq!(list(&s2).await.unwrap().len(), 1);
        // limits come from system_config
        s.save_system_config("notify.matcher_max_depth", "1")
            .await
            .unwrap();
        assert!(
            upsert(&s, "deep", "", Matcher::legacy("test", "warning"), &[])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn migration_converts_existing_channels() {
        // 0795 runs on a store that already has channels: open at 0740, add rows, migrate.
        let s = ConfigStore::open_in_memory().await.unwrap();
        // the in-memory store is fully migrated; re-run the conversion statement on new rows
        sqlx::query("INSERT INTO event_hooks (name, url, secret, kinds, enabled, created_at, min_severity) VALUES ('a','http://x','','gateway_down,tunnel_up',1,0,'warning'),('b','http://x','','',1,0,'info'),('c','http://x','','test',1,0,'info'),('d','http://x','','',1,0,'critical')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let sql = include_str!("../migrations/0795_h_notify_matchers.sql");
        let convert: String = sql
            .split(';')
            .filter(|st| {
                st.contains("INSERT INTO notify_matchers") || st.contains("UPDATE event_hooks")
            })
            .map(|st| format!("{st};"))
            .collect();
        sqlx::raw_sql(&convert)
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        let t = at(2026, 11, 25, 12, 0);
        for (name, kinds, min) in [
            ("a", "gateway_down,tunnel_up", "warning"),
            ("b", "", "info"),
            ("c", "test", "info"),
            ("d", "", "critical"),
        ] {
            let m = get_tree(&s, &format!("auto-{name}"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(m, Matcher::legacy(kinds, min), "{name}");
            for k in ["gateway_down", "tunnel_up", "test", "config_changed"] {
                for sv in ["info", "warning", "critical"] {
                    let want = (kinds.is_empty() || kinds.split(',').any(|x| x == k))
                        && severity_rank(sv) >= severity_rank(min);
                    assert_eq!(m.matches(&ctx(k, sv, "", t)), want);
                }
            }
            let used: String = sqlx::query_scalar("SELECT matcher FROM event_hooks WHERE name = ?")
                .bind(name)
                .fetch_one(s.pool().unwrap())
                .await
                .unwrap();
            assert_eq!(used, format!("auto-{name}"));
        }
    }
}
