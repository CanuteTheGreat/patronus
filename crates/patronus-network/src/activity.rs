//! System activity: the busiest processes, load, CPU and memory totals and a
//! per-daemon rollup, read from `/proc` only (no `top`/`ps` dependency, so it
//! works the same on the busybox-based embedded tier).
//!
//! Everything here is pure over a `/proc` root directory so the unit tests run
//! on fixture trees. CPU percentages need two samples: [`take`] reads one raw
//! sample, [`compute`] turns two of them into a [`Snapshot`]. The web layer
//! keeps the latest snapshot in a cache refreshed by a background task, so a
//! request never waits for the sampling interval.
//!
//! Command lines are redacted ([`redact_cmdline`]) before they leave this
//! module: secrets passed as options, `NAME=value` words, bearer tokens and
//! the password part of a URL never reach the API.

use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Longest command line kept (characters), after redaction.
pub const MAX_COMMAND_CHARS: usize = 400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    /// utime + stime in clock ticks.
    pub cpu_ticks: u64,
    pub threads: u64,
    pub start_ticks: u64,
    pub rss_pages: i64,
}

/// Parse Linux /proc/PID/stat, including names containing spaces or ')'.
pub fn parse_stat(input: &str) -> Option<ProcessStat> {
    let open = input.find('(')?;
    let close = input.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid = input[..open].trim().parse().ok()?;
    let fields: Vec<&str> = input[close + 1..].split_whitespace().collect();
    Some(ProcessStat {
        pid,
        comm: input[open + 1..close].to_owned(),
        state: fields.first()?.chars().next()?,
        cpu_ticks: fields
            .get(11)?
            .parse::<u64>()
            .ok()?
            .checked_add(fields.get(12)?.parse().ok()?)?,
        threads: fields.get(17)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
        rss_pages: fields.get(21)?.parse().ok()?,
    })
}

/// UID and resident memory (in bytes) from Linux /proc/PID/status.
pub fn parse_status(input: &str) -> Option<(u32, u64)> {
    let mut uid = None;
    let mut rss = None;
    for line in input.lines() {
        if let Some(v) = line.strip_prefix("Uid:") {
            uid = v.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(v) = line.strip_prefix("VmRSS:") {
            let mut words = v.split_whitespace();
            let size = words.next()?.parse::<u64>().ok()?;
            if words.next()? != "kB" {
                return None;
            }
            rss = size.checked_mul(1024);
        }
    }
    Some((uid?, rss.unwrap_or(0)))
}

// ---------------------------------------------------------------------------
// command-line redaction
// ---------------------------------------------------------------------------

/// Words that make an option name or a `NAME=value` word secret.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api-key",
    "credential",
    "private-key",
    "privkey",
    "psk",
    "bearer",
    "authorization",
    "auth-key",
    "cookie",
    "session-key",
];

const REDACTED: &str = "<redacted>";

fn is_secret_name(name: &str) -> bool {
    let n = name
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    SECRET_WORDS.iter().any(|w| n.contains(w))
}

/// `scheme://user:pass@host` -> `scheme://user:<redacted>@host`.
fn redact_url_userinfo(word: &str) -> String {
    let Some(scheme_end) = word.find("://") else {
        return word.to_string();
    };
    let rest = &word[scheme_end + 3..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    match auth.rfind('@') {
        Some(at) if auth[..at].contains(':') => {
            let user = auth[..at].split(':').next().unwrap_or("");
            format!(
                "{}{}:{}@{}{}",
                &word[..scheme_end + 3],
                user,
                REDACTED,
                &auth[at + 1..],
                &rest[auth_end..]
            )
        }
        _ => word.to_string(),
    }
}

/// One whitespace-free word: `--opt=value`, `NAME=value`, URL userinfo.
/// Returns the redacted word and whether the NEXT word is a secret value
/// (`--password hunter2`).
fn redact_word(word: &str) -> (String, bool) {
    if let Some((k, _)) = word.split_once('=') {
        if is_secret_name(k) {
            return (format!("{k}={REDACTED}"), false);
        }
    } else if word.starts_with('-') && is_secret_name(word) {
        return (word.to_string(), true);
    }
    (redact_url_userinfo(word), false)
}

/// Redact one argument. A shell script argument (`sh -c "..."`) holds several
/// words, so every space-separated piece is checked.
fn redact_arg(arg: &str, hide_next: &mut bool) -> String {
    if *hide_next {
        *hide_next = false;
        return REDACTED.to_string();
    }
    if !arg.contains(char::is_whitespace) {
        let (w, hide) = redact_word(arg);
        *hide_next = hide;
        return w;
    }
    let mut out = String::with_capacity(arg.len());
    let mut hide = false;
    for (i, piece) in arg.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if piece.is_empty() {
            continue;
        }
        if hide {
            out.push_str(REDACTED);
            hide = false;
            continue;
        }
        // `Authorization: Bearer abc` / `Bearer abc` inside one argument
        if piece.eq_ignore_ascii_case("bearer") || piece.eq_ignore_ascii_case("basic") {
            out.push_str(piece);
            hide = true;
            continue;
        }
        let (w, h) = redact_word(piece);
        out.push_str(&w);
        hide = h;
    }
    out
}

/// Redact common secret forms before a command line can leave the backend.
/// The program name and non-secret arguments remain useful for diagnostics.
/// Input is the raw NUL-separated `/proc/PID/cmdline`.
pub fn redact_cmdline(input: &[u8]) -> String {
    let mut hide_next = false;
    let mut result: Vec<String> = Vec::new();
    for raw in input.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let arg = String::from_utf8_lossy(raw);
        result.push(redact_arg(&arg, &mut hide_next));
    }
    let mut s: String = result
        .join(" ")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if s.chars().count() > MAX_COMMAND_CHARS {
        s = s.chars().take(MAX_COMMAND_CHARS).collect::<String>() + "...";
    }
    s
}

// ---------------------------------------------------------------------------
// system-wide files
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

pub fn parse_loadavg(input: &str) -> Option<LoadAvg> {
    let mut w = input.split_whitespace();
    Some(LoadAvg {
        one: w.next()?.parse().ok()?,
        five: w.next()?.parse().ok()?,
        fifteen: w.next()?.parse().ok()?,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

/// /proc/meminfo (values in kB) -> bytes. `MemAvailable` falls back to
/// free + buffers + cached on kernels without it.
pub fn parse_meminfo(input: &str) -> Memory {
    let mut m = HashMap::new();
    for line in input.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if let Some(n) = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
            {
                m.insert(k.trim().to_string(), n.saturating_mul(1024));
            }
        }
    }
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    let available = m
        .get("MemAvailable")
        .copied()
        .unwrap_or_else(|| g("MemFree") + g("Buffers") + g("Cached"));
    Memory {
        total: g("MemTotal"),
        available,
        swap_total: g("SwapTotal"),
        swap_free: g("SwapFree"),
    }
}

/// Counters of /proc/stat: (busy+idle total, idle) of the `cpu` line and the
/// number of `cpuN` lines.
pub fn parse_cpu_stat(input: &str) -> Option<(u64, u64, usize)> {
    let mut total = None;
    let mut cpus = 0usize;
    for line in input.lines() {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("cpu") => {
                let v: Vec<u64> = w.filter_map(|s| s.parse().ok()).collect();
                if v.len() >= 4 {
                    // user nice system idle iowait irq softirq steal
                    let all: u64 = v.iter().take(8).sum();
                    let idle = v[3] + v.get(4).copied().unwrap_or(0);
                    total = Some((all, idle));
                }
            }
            Some(n) if n.starts_with("cpu") && n[3..].chars().all(|c| c.is_ascii_digit()) => {
                cpus += 1
            }
            _ => {}
        }
    }
    total.map(|(a, i)| (a, i, cpus.max(1)))
}

/// /etc/passwd -> uid -> name.
pub fn parse_passwd(input: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for line in input.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() > 2 {
            if let Ok(uid) = f[2].parse() {
                m.entry(uid).or_insert_with(|| f[0].to_string());
            }
        }
    }
    m
}

// ---------------------------------------------------------------------------
// sampling
// ---------------------------------------------------------------------------

/// One process as read at one instant.
#[derive(Debug, Clone)]
pub struct RawProc {
    pub stat: ProcessStat,
    pub uid: u32,
    pub rss_bytes: u64,
    /// Redacted command line (kernel threads: empty).
    pub command: String,
    /// argv[0] basename, for the daemon rollup (kernel threads: empty).
    pub exe: String,
}

/// One sample of the whole system.
#[derive(Debug, Clone)]
pub struct RawSample {
    pub procs: Vec<RawProc>,
    pub cpu_total: u64,
    pub cpu_idle: u64,
    pub cpus: usize,
    pub load: LoadAvg,
    pub mem: Memory,
    pub uptime_secs: f64,
    pub users: HashMap<u32, String>,
}

/// Sampling constants of the host: clock ticks per second and page size.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    pub hz: u64,
    pub page: u64,
}

impl Host {
    pub fn detect() -> Self {
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        Host {
            hz: if hz > 0 { hz as u64 } else { 100 },
            page: if page > 0 { page as u64 } else { 4096 },
        }
    }
}

fn exe_name(cmdline: &[u8]) -> String {
    let first = cmdline.split(|b| *b == 0).next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(first);
    let word = s.split_whitespace().next().unwrap_or("");
    word.rsplit('/').next().unwrap_or("").to_string()
}

/// Read one sample from `root` (`/proc`); `etc_passwd` is the passwd file.
/// A process that vanishes or cannot be read is skipped, never an error.
pub fn take(root: &Path, etc_passwd: &Path, host: Host) -> std::io::Result<RawSample> {
    let stat = std::fs::read_to_string(root.join("stat"))?;
    let (cpu_total, cpu_idle, cpus) = parse_cpu_stat(&stat).unwrap_or((0, 0, 1));
    let mut procs = Vec::new();
    for entry in std::fs::read_dir(root)?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let dir = entry.path();
        let Some(st) = std::fs::read_to_string(dir.join("stat"))
            .ok()
            .and_then(|s| parse_stat(&s))
        else {
            continue;
        };
        if st.pid != pid {
            continue;
        }
        let (uid, rss_status) = std::fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|s| parse_status(&s))
            .unwrap_or((0, 0));
        let rss_bytes = if rss_status > 0 {
            rss_status
        } else {
            (st.rss_pages.max(0) as u64).saturating_mul(host.page)
        };
        let raw = std::fs::read(dir.join("cmdline")).unwrap_or_default();
        procs.push(RawProc {
            exe: exe_name(&raw),
            command: redact_cmdline(&raw),
            uid,
            rss_bytes,
            stat: st,
        });
    }
    Ok(RawSample {
        procs,
        cpu_total,
        cpu_idle,
        cpus,
        load: parse_loadavg(&std::fs::read_to_string(root.join("loadavg")).unwrap_or_default())
            .unwrap_or_default(),
        mem: parse_meminfo(&std::fs::read_to_string(root.join("meminfo")).unwrap_or_default()),
        uptime_secs: std::fs::read_to_string(root.join("uptime"))
            .ok()
            .and_then(|s| s.split_whitespace().next().and_then(|w| w.parse().ok()))
            .unwrap_or(0.0),
        users: parse_passwd(&std::fs::read_to_string(etc_passwd).unwrap_or_default()),
    })
}

// ---------------------------------------------------------------------------
// the answer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub user: String,
    /// Kernel name of the process (`comm`).
    pub name: String,
    /// Redacted command line.
    pub command: String,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub threads: u64,
    pub state: String,
    pub daemon: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonRow {
    pub name: String,
    pub description: String,
    pub processes: usize,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub threads: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snapshot {
    /// Unix seconds the second sample was taken.
    pub taken_at: i64,
    /// Seconds between the two samples the percentages come from.
    pub interval_secs: f64,
    pub cpus: usize,
    /// Busy share of all CPUs, 0..100.
    pub cpu_percent: f64,
    pub load: LoadAvg,
    pub memory: Memory,
    pub uptime_secs: f64,
    pub process_count: usize,
    pub processes: Vec<ProcessRow>,
    pub daemons: Vec<DaemonRow>,
}

/// Process names (argv[0] basenames or `comm`) that belong to a managed
/// service although they are not called like it.
const DAEMON_ALIASES: &[(&str, &str)] = &[
    ("charon", "strongswan"),
    ("charon-systemd", "strongswan"),
    ("starter", "ipsec"),
];

/// The managed service a process belongs to, by its program name. `known`
/// is `(service, description)` (`services::KNOWN_SERVICES`).
pub fn daemon_of<'a>(p: &RawProc, known: &'a [(&'a str, &'a str)]) -> Option<&'a str> {
    let by = |n: &str| known.iter().find(|(k, _)| *k == n).map(|(k, _)| *k);
    for cand in [p.exe.as_str(), p.stat.comm.as_str()] {
        if cand.is_empty() {
            continue;
        }
        if let Some(k) = by(cand) {
            return Some(k);
        }
        if let Some((_, svc)) = DAEMON_ALIASES.iter().find(|(a, _)| *a == cand) {
            if let Some(k) = by(svc) {
                return Some(k);
            }
        }
    }
    // comm is cut at 15 characters by the kernel
    let comm = p.stat.comm.as_str();
    if comm.len() == 15 {
        if let Some((k, _)) = known.iter().find(|(k, _)| k.starts_with(comm)) {
            return Some(k);
        }
    }
    None
}

fn cmp_f64(a: f64, b: f64) -> std::cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
}

/// Turn two samples into the answer. `a` is the earlier one. Returns `None`
/// when the counters went backwards (a counter reset).
pub fn compute(
    a: &RawSample,
    b: &RawSample,
    host: Host,
    known: &[(&str, &str)],
    taken_at: i64,
) -> Option<Snapshot> {
    let dtotal = b.cpu_total.checked_sub(a.cpu_total)?;
    let didle = b.cpu_idle.saturating_sub(a.cpu_idle);
    if dtotal == 0 {
        return None;
    }
    let cpus = b.cpus.max(1);
    // ticks one CPU runs in the window
    let per_cpu = dtotal as f64 / cpus as f64;
    let prev: HashMap<(u32, u64), u64> = a
        .procs
        .iter()
        .map(|p| ((p.stat.pid, p.stat.start_ticks), p.stat.cpu_ticks))
        .collect();
    let mut rows = Vec::with_capacity(b.procs.len());
    for p in &b.procs {
        let cpu = match prev.get(&(p.stat.pid, p.stat.start_ticks)) {
            // a process new in this window has no baseline yet
            None => 0.0,
            Some(old) => p.stat.cpu_ticks.saturating_sub(*old) as f64 / per_cpu * 100.0,
        };
        rows.push(ProcessRow {
            pid: p.stat.pid,
            user: b
                .users
                .get(&p.uid)
                .cloned()
                .unwrap_or_else(|| p.uid.to_string()),
            name: p.stat.comm.clone(),
            command: if p.command.is_empty() {
                format!("[{}]", p.stat.comm)
            } else {
                p.command.clone()
            },
            cpu_percent: (cpu * 10.0).round() / 10.0,
            rss_bytes: p.rss_bytes,
            threads: p.stat.threads,
            state: p.stat.state.to_string(),
            daemon: daemon_of(p, known).map(str::to_string),
        });
    }
    let mut daemons: Vec<DaemonRow> = Vec::new();
    for r in &rows {
        let Some(d) = &r.daemon else { continue };
        if let Some(row) = daemons.iter_mut().find(|x| &x.name == d) {
            row.processes += 1;
            row.cpu_percent += r.cpu_percent;
            row.rss_bytes += r.rss_bytes;
            row.threads += r.threads;
        } else {
            daemons.push(DaemonRow {
                name: d.clone(),
                description: known
                    .iter()
                    .find(|(k, _)| k == d)
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default(),
                processes: 1,
                cpu_percent: r.cpu_percent,
                rss_bytes: r.rss_bytes,
                threads: r.threads,
            });
        }
    }
    for d in &mut daemons {
        d.cpu_percent = (d.cpu_percent * 10.0).round() / 10.0;
    }
    daemons.sort_by(|x, y| {
        cmp_f64(y.cpu_percent, x.cpu_percent).then(y.rss_bytes.cmp(&x.rss_bytes))
    });
    rows.sort_by(|x, y| {
        cmp_f64(y.cpu_percent, x.cpu_percent)
            .then(y.rss_bytes.cmp(&x.rss_bytes))
            .then(x.pid.cmp(&y.pid))
    });
    Some(Snapshot {
        taken_at,
        interval_secs: (per_cpu / host.hz as f64 * 100.0).round() / 100.0,
        cpus,
        cpu_percent: ((1.0 - didle as f64 / dtotal as f64) * 1000.0).round() / 10.0,
        load: b.load,
        memory: b.mem,
        uptime_secs: b.uptime_secs,
        process_count: rows.len(),
        processes: rows,
        daemons,
    })
}

/// Sort keys the API accepts.
pub const SORT_KEYS: &[&str] = &["cpu", "memory", "pid", "name", "user", "threads"];

/// Sort rows in place by `key`. Returns false (rows untouched) for an
/// unknown key.
pub fn sort_rows(rows: &mut [ProcessRow], key: &str, descending: bool) -> bool {
    if !SORT_KEYS.contains(&key) {
        return false;
    }
    let f = |a: &ProcessRow, b: &ProcessRow| {
        match key {
            "cpu" => cmp_f64(a.cpu_percent, b.cpu_percent),
            "memory" => a.rss_bytes.cmp(&b.rss_bytes),
            "pid" => a.pid.cmp(&b.pid),
            "name" => a.name.cmp(&b.name),
            "user" => a.user.cmp(&b.user),
            _ => a.threads.cmp(&b.threads),
        }
        .then(a.pid.cmp(&b.pid))
    };
    rows.sort_by(|a, b| if descending { f(b, a) } else { f(a, b) });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_process_names_with_parentheses() {
        let s = "42 (a ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 3 18 1234 20 321 22";
        let p = parse_stat(s).unwrap();
        assert_eq!((p.pid, p.comm.as_str(), p.state), (42, "a ) name", 'S'));
        assert_eq!(
            (p.cpu_ticks, p.threads, p.start_ticks, p.rss_pages),
            (23, 3, 1234, 321)
        );
        assert!(parse_stat("42 (bad) S 1").is_none());
    }

    #[test]
    fn status_parses_uid_and_memory() {
        assert_eq!(
            parse_status("Name:\tx\nUid:\t1000 1000 1000 1000\nVmRSS:\t12 kB\n"),
            Some((1000, 12288))
        );
        assert_eq!(parse_status("Uid: 0 0 0 0\n"), Some((0, 0)));
        assert_eq!(parse_status("Uid: 0\nVmRSS: 2 MB\n"), None);
    }

    fn red(args: &[&str]) -> String {
        redact_cmdline(args.join("\0").as_bytes())
    }

    #[test]
    fn redacts_both_common_option_forms() {
        let r = red(&[
            "prog",
            "--password=hunter2",
            "--api-token",
            "abc",
            "--port",
            "80",
        ]);
        assert_eq!(r, "prog --password=<redacted> --api-token <redacted> --port 80");
        assert!(!r.contains("hunter2") && !r.contains("abc"));
    }

    #[test]
    fn redacts_names_urls_scripts_and_bearer_words() {
        let r = red(&["app", "DB_PASSWORD=s3cr3t", "--client_secret=zzz"]);
        assert_eq!(r, "app DB_PASSWORD=<redacted> --client_secret=<redacted>");
        let r = red(&[
            "curl",
            "https://user:pw123@example.test:8443/x?a=1",
            "-H",
            "Authorization: Bearer tok123",
        ]);
        assert!(!r.contains("pw123") && !r.contains("tok123"), "{r}");
        assert!(
            r.contains("https://user:<redacted>@example.test:8443/x?a=1"),
            "{r}"
        );
        let r = red(&[
            "sh",
            "-c",
            "export API_TOKEN=abc && run --password hunter2 --verbose",
        ]);
        assert!(!r.contains("abc") && !r.contains("hunter2"), "{r}");
        assert!(r.contains("--verbose"), "{r}");
        // harmless options stay readable
        let r = red(&["sshd", "-D", "-f", "/etc/ssh/sshd_config", "--key-file", "/etc/k"]);
        assert_eq!(r, "sshd -D -f /etc/ssh/sshd_config --key-file /etc/k");
        // control characters and very long lines
        assert_eq!(redact_cmdline(b"a\x1b[31mb\0"), "a [31mb");
        let long = "x".repeat(2000);
        assert!(redact_cmdline(long.as_bytes()).chars().count() <= MAX_COMMAND_CHARS + 3);
    }

    #[test]
    fn system_files_parse() {
        assert_eq!(parse_loadavg("0.52 0.30 0.10 1/200 999\n").unwrap().five, 0.30);
        assert!(parse_loadavg("x").is_none());
        let m = parse_meminfo(
            "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 10 kB\nCached: 40 kB\nSwapTotal: 8 kB\nSwapFree: 4 kB\n",
        );
        assert_eq!((m.total, m.available, m.swap_free), (1_024_000, 153_600, 4096));
        let m = parse_meminfo("MemTotal: 10 kB\nMemAvailable: 7 kB\n");
        assert_eq!(m.available, 7168);
        let (all, idle, cpus) = parse_cpu_stat(
            "cpu  10 0 10 70 10 0 0 0 0 0\ncpu0 5 0 5 35 5 0 0 0\ncpu1 5 0 5 35 5 0 0 0\nintr 1\n",
        )
        .unwrap();
        assert_eq!((all, idle, cpus), (100, 80, 2));
        assert_eq!(
            parse_passwd("root:x:0:0::/root:/bin/sh\nfoo:x:100:100::/:/bin/false\n")[&100],
            "foo"
        );
    }

    const KNOWN: &[(&str, &str)] = &[
        ("patronus-web", "Web interface"),
        ("dnsmasq", "DHCP / DNS"),
        ("strongswan", "IPsec"),
        ("patronus-firewall", "Boot-time apply"),
    ];

    #[allow(clippy::too_many_arguments)]
    fn write_proc(
        root: &Path,
        pid: u32,
        comm: &str,
        state: char,
        ticks: (u64, u64),
        threads: u64,
        uid: u32,
        rss_kb: u64,
        cmd: &[&str],
    ) {
        let d = root.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("stat"),
            format!(
                "{pid} ({comm}) {state} 1 1 1 0 -1 0 0 0 0 0 {} {} 0 0 20 0 {threads} 0 {}00 1 {}\n",
                ticks.0,
                ticks.1,
                pid,
                rss_kb / 4
            ),
        )
        .unwrap();
        fs::write(
            d.join("status"),
            format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nVmRSS:\t{rss_kb} kB\n"),
        )
        .unwrap();
        fs::write(d.join("cmdline"), cmd.join("\0")).unwrap();
    }

    fn fixture(dir: &Path, cpu: &str, procs: &[(u32, &str, (u64, u64))]) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("stat"), cpu).unwrap();
        fs::write(dir.join("loadavg"), "1.50 1.00 0.50 2/100 1\n").unwrap();
        fs::write(dir.join("meminfo"), "MemTotal: 2048 kB\nMemAvailable: 1024 kB\n").unwrap();
        fs::write(dir.join("uptime"), "1234.5 99.0\n").unwrap();
        fs::write(dir.join("not-a-pid"), "x").unwrap();
        for (pid, comm, t) in procs {
            match *pid {
                1 => write_proc(dir, 1, "init", 'S', *t, 1, 0, 400, &["/sbin/init"]),
                10 => write_proc(
                    dir,
                    10,
                    comm,
                    'S',
                    *t,
                    4,
                    0,
                    4000,
                    &["/usr/bin/patronus-web", "--password=hunter2"],
                ),
                11 => write_proc(dir, 11, comm, 'R', *t, 1, 100, 800, &["/usr/sbin/dnsmasq", "-k"]),
                12 => write_proc(dir, 12, comm, 'S', *t, 1, 100, 600, &["dnsmasq", "--child"]),
                13 => write_proc(dir, 13, comm, 'I', *t, 1, 0, 0, &[]),
                _ => write_proc(dir, *pid, comm, 'S', *t, 1, 7, 100, &[comm]),
            }
        }
        fs::write(
            dir.join("passwd"),
            "root:x:0:0::/root:/bin/sh\ndnsmasq:x:100:100::/:/bin/false\n",
        )
        .unwrap();
    }

    #[test]
    fn two_samples_make_percentages_rollup_and_sorting() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        let host = Host { hz: 100, page: 4096 };
        fixture(
            &a,
            "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 50 0 50 350 50 0 0 0\ncpu1 50 0 50 350 50 0 0 0\n",
            &[
                (1, "init", (0, 0)),
                (10, "patronus-web", (10, 10)),
                (11, "dnsmasq", (5, 5)),
                (12, "dnsmasq", (0, 0)),
                (13, "kworker/0:1", (0, 0)),
            ],
        );
        // 200 ticks pass on 2 CPUs (100 per CPU = 1 s); 100 of them busy
        fixture(
            &b,
            "cpu  150 0 150 800 100 0 0 0 0 0\ncpu0 75 0 75 400 50 0 0 0\ncpu1 75 0 75 400 50 0 0 0\n",
            &[
                (1, "init", (0, 0)),
                (10, "patronus-web", (40, 10)),
                (11, "dnsmasq", (10, 5)),
                (12, "dnsmasq", (20, 0)),
                (13, "kworker/0:1", (0, 0)),
                (20, "newproc", (50, 0)),
            ],
        );
        let ra = take(&a, &a.join("passwd"), host).unwrap();
        let rb = take(&b, &b.join("passwd"), host).unwrap();
        assert_eq!(ra.procs.len(), 5);
        assert_eq!(rb.cpus, 2);
        let s = compute(&ra, &rb, host, KNOWN, 1000).unwrap();
        assert_eq!(s.interval_secs, 1.0);
        assert_eq!(s.cpu_percent, 50.0);
        assert_eq!(s.load.one, 1.5);
        assert_eq!(s.memory.total, 2_097_152);
        assert_eq!(s.process_count, 6);
        let web = s.processes.iter().find(|p| p.pid == 10).unwrap();
        assert_eq!(web.cpu_percent, 30.0);
        assert_eq!(s.processes[0].pid, 10, "busiest first");
        assert_eq!(web.command, "/usr/bin/patronus-web --password=<redacted>");
        assert_eq!(web.daemon.as_deref(), Some("patronus-web"));
        assert_eq!(
            s.processes.iter().find(|p| p.pid == 11).unwrap().user,
            "dnsmasq"
        );
        let k = s.processes.iter().find(|p| p.pid == 13).unwrap();
        assert_eq!(k.command, "[kworker/0:1]", "kernel thread has no command line");
        assert_eq!(
            s.processes.iter().find(|p| p.pid == 20).unwrap().cpu_percent,
            0.0,
            "new process: no baseline yet"
        );
        let dns = s.daemons.iter().find(|d| d.name == "dnsmasq").unwrap();
        assert_eq!(
            (dns.processes, dns.threads, dns.rss_bytes),
            (2, 2, 1_433_600)
        );
        assert_eq!(dns.cpu_percent, 25.0);
        assert!(s.daemons.iter().all(|d| d.name != "init"));
        assert_eq!(s.daemons[0].name, "patronus-web", "daemons sort by CPU");
        // counters that went backwards give no answer instead of garbage
        assert!(compute(&rb, &ra, host, KNOWN, 1).is_none());
    }

    #[test]
    fn rows_sort_by_every_key_and_refuse_unknown_keys() {
        let row = |pid, user: &str, name: &str, cpu, rss, th| ProcessRow {
            pid,
            user: user.into(),
            name: name.into(),
            command: String::new(),
            cpu_percent: cpu,
            rss_bytes: rss,
            threads: th,
            state: "S".into(),
            daemon: None,
        };
        let mut v = vec![
            row(2, "b", "y", 5.0, 10, 3),
            row(1, "a", "z", 9.0, 5, 1),
            row(3, "c", "x", 1.0, 99, 2),
        ];
        let order = |v: &[ProcessRow]| v.iter().map(|r| r.pid).collect::<Vec<_>>();
        assert!(sort_rows(&mut v, "cpu", true));
        assert_eq!(order(&v), [1, 2, 3]);
        assert!(sort_rows(&mut v, "memory", true));
        assert_eq!(order(&v), [3, 2, 1]);
        assert!(sort_rows(&mut v, "pid", false));
        assert_eq!(order(&v), [1, 2, 3]);
        assert!(sort_rows(&mut v, "name", false));
        assert_eq!(order(&v), [3, 2, 1]);
        assert!(sort_rows(&mut v, "user", true));
        assert_eq!(order(&v), [3, 2, 1]);
        assert!(sort_rows(&mut v, "threads", true));
        assert_eq!(order(&v), [2, 3, 1]);
        assert!(!sort_rows(&mut v, "rm -rf", true));
    }

    #[test]
    fn the_live_proc_tree_can_be_read() {
        if Path::new("/proc/self/stat").exists() {
            let s = take(Path::new("/proc"), Path::new("/etc/passwd"), Host::detect()).unwrap();
            assert!(s.procs.iter().any(|p| p.stat.pid == std::process::id()));
            assert!(s.mem.total > 0);
        }
    }
}
