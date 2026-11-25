//! Line parsers of the system log viewer: one syslog / journald record -> [`Entry`].
//!
//! The priority is READ from the record, never guessed from words:
//! - journald JSON (`PRIORITY`, `_BOOT_ID`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `_TRANSPORT`);
//! - busybox syslogd: `Nov 25 12:00:00 host daemon.warn ident[pid]: text`;
//! - rsyslog / syslog-ng with the Patronus file template (the same shape, ISO timestamp):
//!   `2026-11-25T12:00:00.123456-08:00 host daemon.warning ident[pid]: text`;
//! - sysklogd / RFC 5424 (`<PRI>1 2026-11-25T12:00:00Z host app pid msgid - text`) and any
//!   line carrying a leading `<PRI>`;
//! - the traditional file format (`Nov 25 12:00:00 host ident: text`) has NO priority:
//!   the entry shows as "unknown" and a priority filter leaves it out.

use chrono::{DateTime, Datelike, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;

pub const LEVEL_NAMES: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "security", "console", "solaris-cron", "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
];

/// Facility names by number (RFC 5424), for `<PRI>` values and journald `SYSLOG_FACILITY`.
pub fn facility_name(n: u8) -> &'static str {
    const BY_NUM: [&str; 24] = [
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
        "authpriv", "ftp", "ntp", "security", "console", "solaris-cron", "local0", "local1",
        "local2", "local3", "local4", "local5", "local6", "local7",
    ];
    BY_NUM.get(n as usize).copied().unwrap_or("user")
}

/// A priority word or number -> 0..=7.
pub fn parse_priority(s: &str) -> Option<u8> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<u8>() {
        return (n <= 7).then_some(n);
    }
    Some(match s.as_str() {
        "emerg" | "panic" | "emergency" => 0,
        "alert" => 1,
        "crit" | "critical" => 2,
        "err" | "error" => 3,
        "warn" | "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    /// Milliseconds since the Unix epoch.
    pub ts: i64,
    pub host: String,
    pub facility: Option<String>,
    /// 0 (emerg) .. 7 (debug); `None` = the record carries none.
    pub priority: Option<u8>,
    pub ident: String,
    pub pid: Option<u32>,
    /// journald: the systemd unit; files: filled from the unit map on demand.
    pub unit: Option<String>,
    pub message: String,
    pub kernel: bool,
    /// journald `_BOOT_ID`.
    pub boot_id: Option<String>,
    /// The record is a boot marker (files): the viewer draws a separator before it.
    #[serde(skip)]
    pub boot_marker: bool,
}

impl Entry {
    pub fn level(&self) -> &'static str {
        self.priority.map(|p| LEVEL_NAMES[p as usize]).unwrap_or("unknown")
    }
}

/// What the parser needs besides the line: the clock (for the year a BSD timestamp lacks).
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub now: DateTime<Utc>,
}

impl Ctx {
    pub fn now() -> Self {
        Ctx { now: Utc::now() }
    }
}

fn month(s: &str) -> Option<u32> {
    Some(match s {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// `Nov 25 12:00:00` (day may be space padded) -> (epoch ms, rest of the line).
fn bsd_time<'a>(line: &'a str, ctx: &Ctx) -> Option<(i64, &'a str)> {
    let mut it = line.splitn(2, ' ');
    let mon = month(it.next()?)?;
    let rest = it.next()?.trim_start();
    let mut it = rest.splitn(3, ' ');
    let day: u32 = it.next()?.parse().ok()?;
    let hms = it.next()?;
    let tail = it.next().unwrap_or("");
    let t = NaiveTime::parse_from_str(hms, "%H:%M:%S").ok()?;
    let now_local = ctx.now.with_timezone(&Local);
    let mk = |year: i32| -> Option<DateTime<Local>> {
        let d = NaiveDate::from_ymd_opt(year, mon, day)?;
        Local.from_local_datetime(&NaiveDateTime::new(d, t)).earliest()
    };
    let mut dt = mk(now_local.year())?;
    // a December line read in January is last year's, a line from the future is too
    if dt.with_timezone(&Utc) > ctx.now + chrono::Duration::days(1) {
        dt = mk(now_local.year() - 1)?;
    }
    Some((dt.timestamp_millis(), tail))
}

/// `2026-11-25T12:00:00.123456-08:00 ` -> (epoch ms, rest).
fn iso_time<'a>(line: &'a str) -> Option<(i64, &'a str)> {
    let (tok, rest) = line.split_once(' ').unwrap_or((line, ""));
    if tok.len() < 19 || tok.as_bytes().get(4) != Some(&b'-') || tok.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(tok) {
        return Some((d.timestamp_millis(), rest));
    }
    // no zone (rare): the box's local time
    let n = NaiveDateTime::parse_from_str(tok, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    let d = Local.from_local_datetime(&n).earliest()?;
    Some((d.timestamp_millis(), rest))
}

/// `facility.level` (busybox, rsyslog and syslog-ng with the Patronus template).
fn fac_level(tok: &str) -> Option<(String, u8)> {
    let (f, l) = tok.split_once('.')?;
    let f = f.to_ascii_lowercase();
    if !FACILITIES.contains(&f.as_str()) {
        return None;
    }
    Some((f, parse_priority(l)?))
}

/// `ident[pid]: text` / `ident: text`; a first token with spaces before its colon is no tag.
fn split_tag(rest: &str) -> (String, Option<u32>, String) {
    if let Some(i) = rest.find(':') {
        let head = &rest[..i];
        if !head.is_empty() && !head.contains(' ') {
            let text = rest[i + 1..].strip_prefix(' ').unwrap_or(&rest[i + 1..]);
            if let Some(b) = head.find('[') {
                if head.ends_with(']') {
                    let pid = head[b + 1..head.len() - 1].parse().ok();
                    return (head[..b].to_string(), pid, text.to_string());
                }
            }
            return (head.to_string(), None, text.to_string());
        }
    }
    (String::new(), None, rest.to_string())
}

fn is_kernel(facility: &Option<String>, ident: &str) -> bool {
    facility.as_deref() == Some("kern") || ident == "kernel"
}

/// One line of a syslog file. `None` = not a record start (blank, or a continuation line).
pub fn parse_file_line(line: &str, ctx: &Ctx, markers: &[String]) -> Option<Entry> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    let mut rest = line;
    let mut pri: Option<(Option<String>, u8)> = None;
    if let Some(r) = rest.strip_prefix('<') {
        if let Some((n, after)) = r.split_once('>') {
            if let Ok(n) = n.parse::<u16>() {
                if n < 192 {
                    pri = Some((Some(facility_name((n >> 3) as u8).to_string()), (n & 7) as u8));
                    rest = after;
                }
            }
        }
    }
    // RFC 5424: `1 TIMESTAMP HOST APP PROCID MSGID SD MSG`
    if pri.is_some() {
        if let Some(r) = rest.strip_prefix("1 ") {
            let mut f = r.splitn(7, ' ');
            let (ts, host, app, procid, _msgid, sd) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            let msg = f.next().unwrap_or("");
            let (ms, _) = iso_time(&format!("{ts} "))?;
            // structured data is skipped (`-` or one bracketed block without spaces in values)
            let msg = if sd == "-" { msg.to_string() } else { format!("{sd} {msg}").trim().to_string() };
            let ident = if app == "-" { String::new() } else { app.to_string() };
            let (fac, p) = pri.clone().unwrap();
            return Some(finish(ms, host, fac, Some(p), ident, procid.parse().ok(), msg, ctx, markers));
        }
    }
    let (ms, after_ts) = if let Some(x) = iso_time(rest) {
        x
    } else {
        bsd_time(rest, ctx)?
    };
    let (host, after_host) = after_ts.split_once(' ').unwrap_or((after_ts, ""));
    let mut body = after_host;
    let mut fac = None;
    let mut prio = None;
    if let Some((tok, r)) = body.split_once(' ') {
        if let Some((f, p)) = fac_level(tok) {
            fac = Some(f);
            prio = Some(p);
            body = r;
        }
    }
    if let Some((f, p)) = pri {
        fac = fac.or(f);
        prio = prio.or(Some(p));
    }
    let (ident, pid, text) = split_tag(body);
    Some(finish(ms, host, fac, prio, ident, pid, text, ctx, markers))
}

#[allow(clippy::too_many_arguments)]
fn finish(
    ts: i64,
    host: &str,
    facility: Option<String>,
    priority: Option<u8>,
    ident: String,
    pid: Option<u32>,
    message: String,
    _ctx: &Ctx,
    markers: &[String],
) -> Entry {
    let kernel = is_kernel(&facility, &ident);
    // the marker may be the tag (`patronus-boot: boot <id>`) or text in the message (`Linux version ...`)
    let whole = format!("{ident}: {message}");
    let boot_marker = markers.iter().any(|m| whole.contains(m.as_str()));
    Entry {
        ts,
        host: host.to_string(),
        facility,
        priority,
        ident,
        pid,
        unit: None,
        message,
        kernel,
        boot_id: None,
        boot_marker,
    }
}

/// `patronus-boot: boot <uuid>` -> the boot id of a boot-record line.
pub fn boot_id_of(message: &str) -> Option<String> {
    let rest = message.split("boot ").nth(1)?;
    let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit() || *c == '-').collect();
    (id.len() >= 8).then_some(id)
}

fn jstr(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => {
            // binary / non-UTF-8 fields come as byte arrays
            let b: Vec<u8> = a.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            Some(String::from_utf8_lossy(&b).into_owned())
        }
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// One `journalctl -o json` object. Returns the entry and its `__CURSOR`.
pub fn parse_journal(v: &Value) -> Option<(Entry, String)> {
    let micros: i64 = jstr(v, "__REALTIME_TIMESTAMP")?.parse().ok()?;
    let priority = jstr(v, "PRIORITY").and_then(|p| p.parse::<u8>().ok()).filter(|p| *p <= 7);
    let ident = jstr(v, "SYSLOG_IDENTIFIER").or_else(|| jstr(v, "_COMM")).unwrap_or_default();
    let transport = jstr(v, "_TRANSPORT").unwrap_or_default();
    let facility = jstr(v, "SYSLOG_FACILITY")
        .and_then(|f| f.parse::<u8>().ok())
        .map(|f| facility_name(f).to_string());
    let kernel = transport == "kernel";
    Some((
        Entry {
            ts: micros / 1000,
            host: jstr(v, "_HOSTNAME").unwrap_or_default(),
            facility,
            priority,
            ident,
            pid: jstr(v, "SYSLOG_PID").or_else(|| jstr(v, "_PID")).and_then(|p| p.parse().ok()),
            unit: jstr(v, "_SYSTEMD_UNIT").or_else(|| jstr(v, "UNIT")),
            message: jstr(v, "MESSAGE").unwrap_or_default(),
            kernel,
            boot_id: jstr(v, "_BOOT_ID"),
            boot_marker: false,
        },
        jstr(v, "__CURSOR").unwrap_or_default(),
    ))
}

/// `*` matches any run of characters; case-insensitive; no `*` = exact match.
pub fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Ctx {
        Ctx {
            now: Utc.with_ymd_and_hms(2026, 11, 25, 20, 0, 0).unwrap(),
        }
    }
    fn markers() -> Vec<String> {
        vec!["Linux version ".into(), "patronus-boot:".into()]
    }

    #[test]
    fn busybox_line_has_facility_and_priority() {
        let e = parse_file_line("Nov 25 12:00:01 ap daemon.warn test-ident[42]: link flapping", &ctx(), &markers()).unwrap();
        assert_eq!(e.priority, Some(4));
        assert_eq!(e.level(), "warning");
        assert_eq!(e.facility.as_deref(), Some("daemon"));
        assert_eq!(e.ident, "test-ident");
        assert_eq!(e.pid, Some(42));
        assert_eq!(e.message, "link flapping");
        assert_eq!(e.host, "ap");
        assert!(!e.kernel);
    }

    #[test]
    fn busybox_kernel_and_err_levels() {
        let e = parse_file_line("Nov  5 03:04:05 ap kern.err kernel: [  12.3] ath11k: failed", &ctx(), &markers()).unwrap();
        assert!(e.kernel);
        assert_eq!(e.priority, Some(3));
        assert_eq!(e.ident, "kernel");
        assert_eq!(e.message, "[  12.3] ath11k: failed");
    }

    #[test]
    fn rsyslog_and_syslog_ng_template_lines_use_iso_time() {
        let a = parse_file_line("2026-11-25T12:00:00.123456-08:00 gw daemon.warning dhcpd[7]: no free leases", &ctx(), &markers()).unwrap();
        assert_eq!(a.priority, Some(4));
        assert_eq!(a.ts, Utc.with_ymd_and_hms(2026, 11, 25, 20, 0, 0).unwrap().timestamp_millis() + 123);
        assert_eq!(a.ident, "dhcpd");
        let b = parse_file_line("2026-11-25T20:00:01+00:00 gw auth.notice sshd[9]: Accepted key", &ctx(), &markers()).unwrap();
        assert_eq!(b.priority, Some(5));
        assert_eq!(b.facility.as_deref(), Some("auth"));
    }

    #[test]
    fn rfc5424_and_pri_prefix() {
        let a = parse_file_line("<27>1 2026-11-25T20:00:00Z gw unbound 311 - - resolver error", &ctx(), &markers()).unwrap();
        assert_eq!(a.priority, Some(3));
        assert_eq!(a.facility.as_deref(), Some("daemon"));
        assert_eq!(a.ident, "unbound");
        assert_eq!(a.pid, Some(311));
        assert_eq!(a.message, "resolver error");
        let b = parse_file_line("<12>Nov 25 12:00:00 gw kernel: oops", &ctx(), &markers()).unwrap();
        assert_eq!(b.priority, Some(4));
        assert_eq!(b.facility.as_deref(), Some("user"));
        assert!(b.kernel);
    }

    #[test]
    fn traditional_line_has_no_priority_and_is_never_guessed() {
        let e = parse_file_line("Nov 25 12:00:00 gw sshd[1]: error: could not open file", &ctx(), &markers()).unwrap();
        assert_eq!(e.priority, None);
        assert_eq!(e.level(), "unknown");
        assert_eq!(e.ident, "sshd");
    }

    #[test]
    fn continuation_and_blank_lines_are_not_records() {
        assert!(parse_file_line("   at frame 3", &ctx(), &markers()).is_none());
        assert!(parse_file_line("", &ctx(), &markers()).is_none());
    }

    #[test]
    fn december_line_in_january_is_last_year() {
        let c = Ctx { now: Utc.with_ymd_and_hms(2027, 1, 2, 12, 0, 0).unwrap() };
        let e = parse_file_line("Dec 31 23:59:59 gw daemon.info x: y", &c, &markers()).unwrap();
        let d = DateTime::<Utc>::from_timestamp_millis(e.ts).unwrap().with_timezone(&Local);
        assert_eq!(d.year(), 2026);
    }

    #[test]
    fn boot_marker_detection_and_id() {
        let e = parse_file_line("Nov 25 12:00:00 gw kern.notice kernel: [    0.000000] Linux version 6.12.118 (x)", &ctx(), &markers()).unwrap();
        assert!(e.boot_marker);
        let b = parse_file_line("Nov 25 12:00:02 gw daemon.notice patronus-boot: boot 3f2a9c1e-1111-4222-8333-444455556666", &ctx(), &markers()).unwrap();
        assert!(b.boot_marker);
        assert_eq!(boot_id_of(&b.message).unwrap(), "3f2a9c1e-1111-4222-8333-444455556666");
        let n = parse_file_line("Nov 25 12:00:03 gw daemon.info x: Linux versions are fine", &ctx(), &markers()).unwrap();
        assert!(!n.boot_marker);
    }

    #[test]
    fn journald_json_record() {
        let v = json!({
            "__CURSOR": "s=abc;i=1", "__REALTIME_TIMESTAMP": "1764100800123456",
            "PRIORITY": "3", "_BOOT_ID": "b007", "_SYSTEMD_UNIT": "unbound.service",
            "SYSLOG_IDENTIFIER": "unbound", "_TRANSPORT": "journal", "_HOSTNAME": "gw",
            "_PID": "311", "SYSLOG_FACILITY": "3", "MESSAGE": "boom"
        });
        let (e, cur) = parse_journal(&v).unwrap();
        assert_eq!(cur, "s=abc;i=1");
        assert_eq!(e.ts, 1764100800123);
        assert_eq!(e.priority, Some(3));
        assert_eq!(e.unit.as_deref(), Some("unbound.service"));
        assert_eq!(e.boot_id.as_deref(), Some("b007"));
        assert_eq!(e.facility.as_deref(), Some("daemon"));
        assert!(!e.kernel);
        let k = json!({"__REALTIME_TIMESTAMP": "1", "_TRANSPORT": "kernel", "MESSAGE": [104, 105], "PRIORITY": "6"});
        let (e, _) = parse_journal(&k).unwrap();
        assert!(e.kernel);
        assert_eq!(e.message, "hi");
    }

    #[test]
    fn wildcard_matching() {
        assert!(glob_match("patronus-*", "patronus-web"));
        assert!(glob_match("*web", "Patronus-Web"));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("patronus", "patronus-web"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("a*b", "a"));
    }

    #[test]
    fn priority_words() {
        assert_eq!(parse_priority("err"), Some(3));
        assert_eq!(parse_priority("Warning"), Some(4));
        assert_eq!(parse_priority("7"), Some(7));
        assert_eq!(parse_priority("9"), None);
        assert_eq!(parse_priority("loud"), None);
    }
}
