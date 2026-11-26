//! Parsing helpers for a future non-blocking /proc activity sampler.
//!
//! The input is supplied by the caller so these parsers can be tested without
//! depending on the host's process table. A caller must treat disappearing or
//! inaccessible processes as normal and must not expose raw command lines.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub cpu_ticks: u64,
    pub threads: u64,
    pub start_ticks: u64,
    pub rss_pages: i64,
}

/// Parse Linux /proc/PID/stat, including names containing spaces or ')'.
pub fn parse_stat(input: &str) -> Option<ProcessStat> {
    let open = input.find('(')?;
    let close = input.rfind(')')?;
    if close <= open { return None; }
    let pid = input[..open].trim().parse().ok()?;
    let fields: Vec<&str> = input[close + 1..].split_whitespace().collect();
    Some(ProcessStat {
        pid,
        comm: input[open + 1..close].to_owned(),
        state: fields.first()?.chars().next()?,
        cpu_ticks: fields.get(11)?.parse::<u64>().ok()?.checked_add(fields.get(12)?.parse().ok()?)?,
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
            if words.next()? != "kB" { return None; }
            rss = size.checked_mul(1024);
        }
    }
    Some((uid?, rss.unwrap_or(0)))
}

/// Redact common option forms before a command line can leave the backend.
/// The program name and non-secret arguments remain useful for diagnostics.
pub fn redact_cmdline(input: &[u8]) -> String {
    let mut hide_next = false;
    let mut result = Vec::new();
    for raw in input.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let arg = String::from_utf8_lossy(raw);
        if hide_next {
            result.push("<redacted>".to_string());
            hide_next = false;
            continue;
        }
        let (key, value) = arg.split_once('=').map_or((arg.as_ref(), None), |(k,v)| (k, Some(v)));
        let lower = key.to_ascii_lowercase();
        let secret = lower.starts_with('-') && ["password", "passwd", "secret", "token", "api-key", "apikey", "credential", "private-key"].iter().any(|word| lower.contains(word));
        if secret {
            if value.is_some() { result.push(format!("{key}=<redacted>")); }
            else { result.push(arg.to_string()); hide_next = true; }
        } else { result.push(arg.to_string()); }
    }
    result.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_names_with_parentheses() {
        let s = "42 (a ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 3 18 1234 20 321 22";
        let p = parse_stat(s).unwrap();
        assert_eq!((p.pid, p.comm.as_str(), p.state), (42, "a ) name", 'S'));
        assert_eq!((p.cpu_ticks, p.threads, p.start_ticks, p.rss_pages), (23, 3, 1234, 321));
        assert!(parse_stat("42 (bad) S 1").is_none());
    }

    #[test]
    fn status_parses_uid_and_memory() {
        assert_eq!(parse_status("Name:\tx\nUid:\t1000 1000 1000 1000\nVmRSS:\t12 kB\n"), Some((1000, 12288)));
        assert_eq!(parse_status("Uid: 0 0 0 0\n"), Some((0, 0)));
        assert_eq!(parse_status("Uid: 0\nVmRSS: 2 MB\n"), None);
    }

    #[test]
    fn redacts_both_common_option_forms() {
        let command = b"prog\0--password=hunter2\0--api-token\0abc\0--port\080\0";
        let result = redact_cmdline(command);
        assert_eq!(result, "prog --password=<redacted> --api-token <redacted> --port 80");
        assert!(!result.contains("hunter2") && !result.contains("abc"));
    }
}
