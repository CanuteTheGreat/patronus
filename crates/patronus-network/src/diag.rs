//! Diagnostics for the web UI's Diagnostics page (pfSense/OPNsense
//! "Diagnostics", OpenWrt LuCI "Network > Diagnostics"): ping, traceroute,
//! DNS lookup, the ARP/NDP neighbour table, the routing tables and the
//! listening sockets, run on the router itself.
//!
//! Every request arrives as JSON from the web UI and is turned into a fixed
//! argument vector from validated fields only: a target is an IP address or
//! a DNS name (letters, digits, `.`, `-`, never starting with `-`), counts
//! are bounded numbers, an interface is a device name. Nothing is ever passed
//! through a shell. Each tool runs with a hard time limit.
//!
//! The DNS lookup is a small built-in stub resolver (one UDP query, the
//! answer section decoded), so it works the same on every tier without
//! bind-tools/drill, and it can ask a chosen server (the router's own
//! resolver, an upstream, or any other) for any common record type.
//!
//! Called through `sysops::handle("diag", ..)`, i.e. as root via applyd when
//! the web UI runs unprivileged (ping/traceroute need raw sockets; `ss -p`
//! needs root to name the owning process).

use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid diagnostics request: {}", m.into()))
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for d in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        dirs.push(PathBuf::from(d));
    }
    dirs.into_iter().map(|d| d.join(bin)).find(|p| p.is_file())
}

/// An IP address or a DNS name. Returned unchanged when valid.
pub fn valid_target(s: &str) -> Result<String> {
    let s = s.trim();
    if s.parse::<IpAddr>().is_ok() {
        return Ok(s.to_string());
    }
    let ok_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.is_empty() || name.len() > 253 || !name.split('.').all(ok_label) {
        return Err(invalid(
            "target must be an IP address or a host name (letters, digits, '.', '-')",
        ));
    }
    Ok(s.to_string())
}

fn valid_iface(s: &str) -> Result<String> {
    if s.is_empty()
        || s.len() > 15
        || s.starts_with('-')
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
    {
        return Err(invalid(
            "interface must be a device name (letters, digits . _ -)",
        ));
    }
    Ok(s.to_string())
}

fn num(params: &Value, key: &str, def: u64, min: u64, max: u64) -> Result<u64> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(def),
        Some(Value::String(s)) if s.is_empty() => Ok(def),
        Some(v) => {
            let n = v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()));
            match n {
                Some(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(invalid(format!(
                    "{key} must be a number from {min} to {max}"
                ))),
            }
        }
    }
}

fn str_param<'a>(params: &'a Value, key: &str) -> &'a str {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// `4`, `6` or `None` (automatic).
fn family(params: &Value) -> Result<Option<u8>> {
    match str_param(params, "family") {
        "" | "auto" | "any" => match params.get("family").and_then(Value::as_u64) {
            Some(4) => Ok(Some(4)),
            Some(6) => Ok(Some(6)),
            None => Ok(None),
            Some(_) => Err(invalid("family must be 4, 6 or auto")),
        },
        "4" | "ipv4" | "inet" => Ok(Some(4)),
        "6" | "ipv6" | "inet6" => Ok(Some(6)),
        _ => Err(invalid("family must be 4, 6 or auto")),
    }
}

/// Validated ping request: argv for `ping` and the overall time limit.
#[derive(Debug, PartialEq)]
pub struct ToolSpec {
    pub argv: Vec<String>,
    pub seconds: u64,
}

/// `ping -n -c COUNT -W 2 [-4|-6] [-I IFACE] [-s SIZE] TARGET`
/// (iputils and busybox both accept these).
pub fn ping_spec(params: &Value) -> Result<ToolSpec> {
    let target = valid_target(str_param(params, "target"))?;
    let count = num(params, "count", 3, 1, 10)?;
    let size = num(params, "size", 56, 1, 1472)?;
    let mut argv: Vec<String> = vec!["-n".into(), "-c".into(), count.to_string()];
    argv.extend(["-W".into(), "2".into()]);
    match family(params)? {
        Some(4) => argv.push("-4".into()),
        Some(6) => argv.push("-6".into()),
        _ => {}
    }
    let src = str_param(params, "interface");
    if !src.is_empty() {
        argv.extend(["-I".into(), valid_iface(src)?]);
    }
    if size != 56 {
        argv.extend(["-s".into(), size.to_string()]);
    }
    argv.push(target);
    Ok(ToolSpec {
        argv,
        seconds: count + 4,
    })
}

/// `traceroute -n -q 1 -w 2 -m HOPS [-4|-6] [-i IFACE] TARGET`
/// (net-analyzer/traceroute and busybox).
pub fn traceroute_spec(params: &Value) -> Result<ToolSpec> {
    let target = valid_target(str_param(params, "target"))?;
    let hops = num(params, "max_hops", 15, 1, 30)?;
    let mut argv: Vec<String> = vec![
        "-n".into(),
        "-q".into(),
        "1".into(),
        "-w".into(),
        "2".into(),
    ];
    argv.extend(["-m".into(), hops.to_string()]);
    match family(params)? {
        Some(4) => argv.push("-4".into()),
        Some(6) => argv.push("-6".into()),
        _ => {}
    }
    let src = str_param(params, "interface");
    if !src.is_empty() {
        argv.extend(["-i".into(), valid_iface(src)?]);
    }
    argv.push(target);
    Ok(ToolSpec {
        argv,
        seconds: hops * 2 + 5,
    })
}

/// Run `bin argv..` under `timeout`; stdout+stderr lines and the exit code.
fn run_tool(bin: &str, spec: &ToolSpec) -> Result<Value> {
    // the real tool, else the busybox applet (embedded tiers link the
    // applets they ship; a Gentoo install may only have busybox itself)
    let (path, applet) = match which(bin) {
        Some(p) => (p, None),
        None => (
            which("busybox")
                .ok_or_else(|| Error::Service(format!("{bin} is not installed on this system")))?,
            Some(bin),
        ),
    };
    let started = Instant::now();
    let out = std::process::Command::new("timeout")
        .args(["-s", "INT", &spec.seconds.to_string()])
        .arg(&path)
        .args(applet)
        .args(&spec.argv)
        .output()
        .map_err(|e| Error::Service(format!("cannot run {bin}: {e}")))?;
    let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    lines.extend(
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string),
    );
    let code = out.status.code().unwrap_or(-1);
    Ok(json!({
        "command": format!("{bin} {}", spec.argv.join(" ")),
        "exit_code": code,
        "timed_out": code == 124,
        "ms": started.elapsed().as_millis() as u64,
        "output": lines,
    }))
}

/// Parse ping's summary: (transmitted, received).
pub fn ping_summary(lines: &[String]) -> Option<(u64, u64)> {
    for l in lines {
        if l.contains("transmitted") {
            let nums: Vec<u64> = l
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 2 {
                return Some((nums[0], nums[1]));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// DNS lookup (built-in stub resolver)
// ---------------------------------------------------------------------------

pub const QTYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("CAA", 257),
];

fn qtype_name(t: u16) -> String {
    QTYPES
        .iter()
        .find(|(_, n)| *n == t)
        .map(|(s, _)| s.to_string())
        .unwrap_or_else(|| format!("TYPE{t}"))
}

/// The reverse-lookup name of an address (`4.3.2.1.in-addr.arpa`, nibbles
/// for IPv6).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// A standard query with RD set, EDNS0 (1232-byte UDP payload).
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00]); // RD
    b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // 1 question, 1 additional (OPT)
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(invalid("name has an empty or too long label"));
            }
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
    }
    b.push(0);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&[0, 1]); // IN
                                  // OPT pseudo-record: root name, type 41, payload 1232, no flags
    b.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    Ok(b)
}

fn read_name(msg: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let bad = || Error::Service("malformed DNS answer (name)".into());
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos).ok_or_else(bad)? as usize;
        if len & 0xc0 == 0xc0 {
            let lo = *msg.get(pos + 1).ok_or_else(bad)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return Err(bad());
            }
            pos = ((len & 0x3f) << 8) | lo;
            continue;
        }
        if len == 0 {
            let next = end.unwrap_or(pos + 1);
            let name = if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            };
            return Ok((name, next));
        }
        let l = msg.get(pos + 1..pos + 1 + len).ok_or_else(bad)?;
        labels.push(String::from_utf8_lossy(l).into_owned());
        pos += 1 + len;
    }
}

fn be16(m: &[u8], p: usize) -> Result<u16> {
    m.get(p..p + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| Error::Service("malformed DNS answer (short)".into()))
}
fn be32(m: &[u8], p: usize) -> Result<u32> {
    m.get(p..p + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| Error::Service("malformed DNS answer (short)".into()))
}

fn rdata_text(msg: &[u8], rtype: u16, start: usize, len: usize) -> Result<String> {
    let rd = msg
        .get(start..start + len)
        .ok_or_else(|| Error::Service("malformed DNS answer (rdata)".into()))?;
    Ok(match rtype {
        1 if len == 4 => format!("{}.{}.{}.{}", rd[0], rd[1], rd[2], rd[3]),
        28 if len == 16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(rd);
            std::net::Ipv6Addr::from(a).to_string()
        }
        2 | 5 | 12 => read_name(msg, start)?.0,
        15 => format!("{} {}", be16(msg, start)?, read_name(msg, start + 2)?.0),
        33 => format!(
            "{} {} {} {}",
            be16(msg, start)?,
            be16(msg, start + 2)?,
            be16(msg, start + 4)?,
            read_name(msg, start + 6)?.0
        ),
        6 => {
            let (mname, p) = read_name(msg, start)?;
            let (rname, p) = read_name(msg, p)?;
            format!(
                "{mname} {rname} {} {} {} {} {}",
                be32(msg, p)?,
                be32(msg, p + 4)?,
                be32(msg, p + 8)?,
                be32(msg, p + 12)?,
                be32(msg, p + 16)?
            )
        }
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rd.len() {
                let l = rd[i] as usize;
                let s = rd.get(i + 1..i + 1 + l).unwrap_or(&[]);
                parts.push(format!("\"{}\"", String::from_utf8_lossy(s)));
                i += 1 + l;
            }
            parts.join(" ")
        }
        257 if len >= 2 => {
            let tl = rd[1] as usize;
            let tag = String::from_utf8_lossy(rd.get(2..2 + tl).unwrap_or(&[]));
            let val = String::from_utf8_lossy(rd.get(2 + tl..).unwrap_or(&[]));
            format!("{} {tag} \"{val}\"", rd[0])
        }
        _ => rd.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    })
}

/// Decoded answer: rcode name, flags and the answer/authority records.
pub fn parse_response(id: u16, msg: &[u8]) -> Result<Value> {
    if msg.len() < 12 {
        return Err(Error::Service("DNS answer too short".into()));
    }
    if be16(msg, 0)? != id {
        return Err(Error::Service("DNS answer for another query".into()));
    }
    let flags = be16(msg, 2)?;
    let rcode = flags & 0x0f;
    let rcode_name = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    };
    let qd = be16(msg, 4)? as usize;
    let an = be16(msg, 6)? as usize;
    let ns = be16(msg, 8)? as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let (_, p) = read_name(msg, pos)?;
        pos = p + 4;
    }
    let mut sections = [Vec::new(), Vec::new()];
    for (i, count) in [an, ns].into_iter().enumerate() {
        for _ in 0..count {
            let (name, p) = read_name(msg, pos)?;
            let rtype = be16(msg, p)?;
            let ttl = be32(msg, p + 4)?;
            let rdlen = be16(msg, p + 8)? as usize;
            let data = rdata_text(msg, rtype, p + 10, rdlen)?;
            sections[i].push(json!({
                "name": name, "type": qtype_name(rtype), "ttl": ttl, "data": data,
            }));
            pos = p + 10 + rdlen;
        }
    }
    let [answers, authority] = sections;
    Ok(json!({
        "rcode": rcode_name,
        "authoritative": flags & 0x0400 != 0,
        "truncated": flags & 0x0200 != 0,
        "recursion_available": flags & 0x0080 != 0,
        "authenticated_data": flags & 0x0020 != 0,
        "answers": answers,
        "authority": authority,
    }))
}

/// The first `nameserver` of a resolv.conf text.
pub fn first_nameserver(resolv: &str) -> Option<IpAddr> {
    resolv.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next() == Some("nameserver"))
            .then(|| it.next().and_then(|a| a.split('%').next()?.parse().ok()))
            .flatten()
    })
}

fn dns_lookup(params: &Value) -> Result<Value> {
    let raw = str_param(params, "name");
    let mut qtype_s = str_param(params, "type").to_ascii_uppercase();
    if qtype_s.is_empty() {
        qtype_s = "A".into();
    }
    let qtype = QTYPES
        .iter()
        .find(|(n, _)| *n == qtype_s)
        .map(|(_, t)| *t)
        .ok_or_else(|| {
            invalid(format!(
                "type must be one of {}",
                QTYPES
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
    let (name, qtype) = match raw.parse::<IpAddr>() {
        // an address is always looked up as its PTR name
        Ok(ip) => (reverse_name(ip), 12),
        Err(_) => (valid_target(raw)?, qtype),
    };
    let server: IpAddr = match str_param(params, "server") {
        "" => first_nameserver(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
            .unwrap_or(IpAddr::from([127, 0, 0, 1])),
        s => s
            .parse()
            .map_err(|_| invalid("server must be an IPv4 or IPv6 address"))?,
    };
    let id: u16 =
        (std::process::id() as u16) ^ (chrono::Utc::now().timestamp_subsec_nanos() as u16);
    let q = encode_query(id, &name, qtype)?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).map_err(|e| Error::Service(format!("dns: {e}")))?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let started = Instant::now();
    let mut buf = vec![0u8; 4096];
    let mut last_err = String::new();
    for _attempt in 0..2 {
        if let Err(e) = sock.send_to(&q, SocketAddr::new(server, 53)) {
            last_err = e.to_string();
            continue;
        }
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from.ip() == server => {
                    if let Ok(mut v) = parse_response(id, &buf[..n]) {
                        v["server"] = json!(server.to_string());
                        v["name"] = json!(name);
                        v["type"] = json!(qtype_name(qtype));
                        v["ms"] = json!(started.elapsed().as_millis() as u64);
                        return Ok(v);
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    last_err = e.to_string();
                    break;
                }
            }
        }
    }
    Err(Error::Service(format!(
        "no answer from {server} for {name} ({}): {last_err}",
        qtype_name(qtype)
    )))
}

// ---------------------------------------------------------------------------
// tables
// ---------------------------------------------------------------------------

/// Parse `ip neigh show` text (iproute2 and busybox print the same layout):
/// `ADDR dev DEV [lladdr MAC] [router] STATE`.
pub fn parse_neighbors(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(addr) = f.first() else { continue };
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        let after = |k: &str| {
            f.iter()
                .position(|x| *x == k)
                .and_then(|i| f.get(i + 1))
                .copied()
        };
        let state = f
            .last()
            .filter(|s| s.chars().all(|c| c.is_ascii_uppercase()))
            .copied()
            .unwrap_or("");
        out.push(json!({
            "address": ip.to_string(),
            "family": if ip.is_ipv4() { "inet" } else { "inet6" },
            "device": after("dev").unwrap_or(""),
            "mac": after("lladdr").unwrap_or(""),
            "router": f.contains(&"router"),
            "state": state,
        }));
    }
    out
}

fn ip_lines(args: &[&str]) -> Result<String> {
    let ip = which("ip").ok_or_else(|| Error::Service("ip is not installed".into()))?;
    let out = std::process::Command::new(ip)
        .args(args)
        .output()
        .map_err(|e| Error::Service(format!("cannot run ip: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn neighbors() -> Result<Value> {
    let mut text = ip_lines(&["-4", "neigh", "show"])?;
    text.push_str(&ip_lines(&["-6", "neigh", "show"])?);
    Ok(json!({ "neighbors": parse_neighbors(&text) }))
}

fn routes() -> Result<Value> {
    let keep = |t: String| -> Vec<String> {
        t.lines()
            .filter(|l| !l.contains("table local") && !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    };
    Ok(json!({
        "ipv4": keep(ip_lines(&["-4", "route", "show", "table", "all"])?),
        "ipv6": keep(ip_lines(&["-6", "route", "show", "table", "all"])?),
        "rules4": keep(ip_lines(&["-4", "rule", "show"])?),
        "rules6": keep(ip_lines(&["-6", "rule", "show"])?),
    }))
}

fn sockets() -> Result<Value> {
    let (bin, args): (&str, &[&str]) = if which("ss").is_some() {
        ("ss", &["-H", "-tulpn"])
    } else {
        ("netstat", &["-tulpn"])
    };
    let path =
        which(bin).ok_or_else(|| Error::Service("neither ss nor netstat is installed".into()))?;
    let out = std::process::Command::new(path)
        .args(args)
        .output()
        .map_err(|e| Error::Service(format!("cannot run {bin}: {e}")))?;
    let lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    Ok(json!({ "command": format!("{bin} {}", args.join(" ")), "sockets": lines }))
}

/// Default connect timeout of the TCP port test (seconds); the web layer
/// replaces it with the typed `diag.tcp_timeout_secs` setting.
pub const DEFAULT_TCP_TIMEOUT_SECS: u64 = 3;
/// Port tests allowed per minute (all callers together): a port scanner
/// through this page is not what it is for. The web layer passes the typed
/// `diag.tcp_tests_per_minute` setting as `rate_limit`.
pub const DEFAULT_TCP_TESTS_PER_MINUTE: usize = 30;

/// Sliding one-minute window of recent test start times.
fn tcp_rate_ok(now: Instant, recent: &mut Vec<Instant>, limit: usize) -> bool {
    recent.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
    if recent.len() >= limit {
        return false;
    }
    recent.push(now);
    true
}

static TCP_RECENT: std::sync::Mutex<Vec<Instant>> = std::sync::Mutex::new(Vec::new());

/// What a failed `connect` means for the port.
fn tcp_state(kind: std::io::ErrorKind, raw: Option<i32>) -> &'static str {
    use std::io::ErrorKind as K;
    match kind {
        K::ConnectionRefused => "closed",
        K::TimedOut | K::WouldBlock => "filtered",
        _ => match raw {
            // ENETDOWN, ENETUNREACH, EHOSTUNREACH: nothing was tried on the wire
            Some(100) | Some(101) | Some(113) => "unreachable",
            _ => "error",
        },
    }
}

/// TCP connect test: `host`, `port`, optional `interface` (device to send
/// through) and `source` (local address), `family`, `timeout` seconds.
/// Reports `open`, `closed` (refused), `filtered` (no answer in time),
/// `unreachable` or `error`, with the resolved address and the latency.
pub fn tcp_test(params: &Value) -> Result<Value> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::ToSocketAddrs;
    let host = valid_target(str_param(params, "host"))?;
    let port = num(params, "port", 0, 1, 65535)? as u16;
    let timeout = num(params, "timeout", DEFAULT_TCP_TIMEOUT_SECS, 1, 30)?;
    let limit = num(
        params,
        "rate_limit",
        DEFAULT_TCP_TESTS_PER_MINUTE as u64,
        1,
        600,
    )? as usize;
    let fam = family(params)?;
    let iface = match str_param(params, "interface") {
        "" => None,
        i => Some(valid_iface(i)?),
    };
    let source: Option<IpAddr> = match str_param(params, "source") {
        "" => None,
        s => Some(
            s.parse()
                .map_err(|_| invalid("source must be an IP address of this router"))?,
        ),
    };
    let wanted = |a: &SocketAddr| match (fam, source) {
        (Some(4), _) if !a.is_ipv4() => false,
        (Some(6), _) if !a.is_ipv6() => false,
        (_, Some(s)) if s.is_ipv4() != a.is_ipv4() => false,
        _ => true,
    };
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| invalid(format!("cannot resolve {host}: {e}")))?
        .find(wanted)
        .ok_or_else(|| invalid(format!("{host} has no address of the requested IP version")))?;
    {
        let mut recent = TCP_RECENT.lock().unwrap_or_else(|e| e.into_inner());
        if !tcp_rate_ok(Instant::now(), &mut recent, limit) {
            return Err(invalid(
                "too many port tests in the last minute, wait a moment",
            ));
        }
    }
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| Error::Config(format!("socket: {e}")))?;
    #[cfg(target_os = "linux")]
    if let Some(i) = &iface {
        sock.bind_device(Some(i.as_bytes()))
            .map_err(|e| invalid(format!("interface {i}: {e}")))?;
    }
    if let Some(s) = source {
        sock.bind(&SockAddr::from(SocketAddr::new(s, 0)))
            .map_err(|e| invalid(format!("source {s}: {e}")))?;
    }
    let start = Instant::now();
    let res = sock.connect_timeout(&SockAddr::from(addr), Duration::from_secs(timeout));
    let ms = start.elapsed().as_millis() as u64;
    let (state, error) = match res {
        Ok(()) => ("open", String::new()),
        Err(e) => (tcp_state(e.kind(), e.raw_os_error()), e.to_string()),
    };
    Ok(json!({
        "tool": "tcp", "host": host, "port": port, "resolved": addr.ip().to_string(),
        "state": state, "ms": ms, "timeout": timeout, "error": error,
        "interface": iface.unwrap_or_default(),
        "source": source.map(|s| s.to_string()).unwrap_or_default(),
    }))
}

/// Entry point: `params.tool` = ping | traceroute | dns | tcp | neighbors |
/// routes | sockets.
pub fn handle(params: &Value) -> Result<Value> {
    match str_param(params, "tool") {
        "ping" => {
            let spec = ping_spec(params)?;
            let mut v = run_tool("ping", &spec)?;
            let lines: Vec<String> = v["output"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some((tx, rx)) = ping_summary(&lines) {
                v["transmitted"] = json!(tx);
                v["received"] = json!(rx);
            }
            Ok(v)
        }
        "traceroute" => run_tool("traceroute", &traceroute_spec(params)?),
        "dns" => dns_lookup(params),
        "neighbors" => neighbors(),
        "routes" => routes(),
        "sockets" => sockets(),
        "tcp" => tcp_test(params),
        other => Err(invalid(format!(
            "unknown tool {other:?}: ping, traceroute, dns, tcp, neighbors, routes or sockets"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_addresses_or_host_names_only() {
        for ok in [
            "192.0.2.1",
            "2001:db8::1",
            "example.com",
            "www.example.test.",
            "a-b.c_d.example",
        ] {
            assert!(valid_target(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-c 1000",
            "example.com; rm -rf /",
            "$(id)",
            "a b",
            "--help",
            "x..y",
            "-example.com",
            "ex`a`mple",
            &"a".repeat(64),
            "a|b",
        ] {
            assert!(valid_target(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ping_argv_is_built_from_validated_fields() {
        let s =
            ping_spec(&json!({"target":"198.51.100.10","count":2,"family":"4","interface":"eth1"}))
                .unwrap();
        assert_eq!(
            s.argv,
            [
                "-n",
                "-c",
                "2",
                "-W",
                "2",
                "-4",
                "-I",
                "eth1",
                "198.51.100.10"
            ]
        );
        assert_eq!(s.seconds, 6);
        assert!(ping_spec(&json!({"target":"x","count":11})).is_err());
        assert!(ping_spec(&json!({"target":"x","interface":"-f"})).is_err());
        assert!(ping_spec(&json!({"target":"x","family":"7"})).is_err());
        // numbers typed into a form arrive as strings
        let s = ping_spec(&json!({"target":"x","count":"4","size":"1400"})).unwrap();
        assert_eq!(s.argv, ["-n", "-c", "4", "-W", "2", "-s", "1400", "x"]);
    }

    #[test]
    fn traceroute_argv_is_bounded() {
        let s = traceroute_spec(&json!({"target":"2001:db8::1","max_hops":5,"family":6})).unwrap();
        assert_eq!(
            s.argv,
            ["-n", "-q", "1", "-w", "2", "-m", "5", "-6", "2001:db8::1"]
        );
        assert!(traceroute_spec(&json!({"target":"x","max_hops":31})).is_err());
        assert!(traceroute_spec(&json!({"target":"x y"})).is_err());
    }

    #[test]
    fn ping_summary_reads_iputils_and_busybox() {
        let iputils = vec![
            "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms".to_string(),
        ];
        assert_eq!(ping_summary(&iputils), Some((3, 2)));
        let bb = vec!["3 packets transmitted, 3 packets received, 0% packet loss".to_string()];
        assert_eq!(ping_summary(&bb), Some((3, 3)));
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.0.2.10".parse().unwrap()),
            "10.2.0.192.in-addr.arpa"
        );
        let r = reverse_name("2001:db8::1".parse().unwrap());
        assert!(
            r.starts_with("1.0.0.0.") && r.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa"),
            "{r}"
        );
    }

    #[test]
    fn query_encoding_and_answer_decoding_round_trip() {
        let q = encode_query(0x1234, "www.example.test", 1).unwrap();
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[12], 3);
        assert_eq!(&q[13..16], b"www");
        // answer = the query (minus OPT) + 2 answers using compression
        let mut a = q[..q.len() - 11].to_vec();
        a[2] = 0x81; // QR RD
        a[3] = 0x80; // RA, NOERROR
        a[7] = 2; // ancount
        a[11] = 0; // arcount
                   // A 198.51.100.10, ttl 300, name -> pointer to offset 12
        a.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 198, 51, 100, 10]);
        // CNAME -> "web" + pointer to "example.test" (offset 16)
        a.extend_from_slice(&[
            0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'w', b'e', b'b', 0xc0, 16,
        ]);
        let v = parse_response(0x1234, &a).unwrap();
        assert_eq!(v["rcode"], "NOERROR");
        assert_eq!(v["recursion_available"], true);
        assert_eq!(v["answers"][0]["data"], "198.51.100.10");
        assert_eq!(v["answers"][0]["name"], "www.example.test");
        assert_eq!(v["answers"][0]["ttl"], 300);
        assert_eq!(v["answers"][1]["type"], "CNAME");
        assert_eq!(v["answers"][1]["data"], "web.example.test");
        // wrong id, short message and pointer loops are errors, not panics
        assert!(parse_response(1, &a).is_err());
        assert!(parse_response(0x1234, &a[..10]).is_err());
        let mut lp = a.clone();
        let n = lp.len();
        lp[n - 2] = 0xc0;
        lp[n - 1] = (n - 2) as u8;
        let _ = parse_response(0x1234, &lp);
    }

    #[test]
    fn nxdomain_mx_txt_decode() {
        let q = encode_query(7, "example.test", 15).unwrap();
        let mut a = q[..q.len() - 11].to_vec();
        a[2] = 0x81;
        a[3] = 0x83; // NXDOMAIN
        a[11] = 0;
        let v = parse_response(7, &a).unwrap();
        assert_eq!(v["rcode"], "NXDOMAIN");
        assert_eq!(v["answers"].as_array().unwrap().len(), 0);
        let mut m = q[..q.len() - 11].to_vec();
        m[2] = 0x81;
        m[7] = 2;
        m[11] = 0;
        m.extend_from_slice(&[0xc0, 12, 0, 15, 0, 1, 0, 0, 0, 1, 0, 4, 0, 10, 0xc0, 12]);
        m.extend_from_slice(&[
            0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1, 0, 6, 5, b'v', b'=', b's', b'p', b'f',
        ]);
        let v = parse_response(7, &m).unwrap();
        assert_eq!(v["answers"][0]["data"], "10 example.test");
        assert_eq!(v["answers"][1]["data"], "\"v=spf\"");
    }

    #[test]
    fn neighbour_table_parsing() {
        let t = "192.0.2.10 dev eth1 lladdr 02:00:00:00:00:0a REACHABLE\n\
                 192.0.2.11 dev eth1  FAILED\n\
                 fe80::1 dev eth0 lladdr 02:00:00:00:00:01 router STALE\n\
                 garbage line\n";
        let n = parse_neighbors(t);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0]["mac"], "02:00:00:00:00:0a");
        assert_eq!(n[0]["state"], "REACHABLE");
        assert_eq!(n[1]["mac"], "");
        assert_eq!(n[2]["family"], "inet6");
        assert_eq!(n[2]["router"], true);
        assert_eq!(n[2]["device"], "eth0");
    }

    #[test]
    fn resolv_conf_first_nameserver() {
        let r = "# x\nsearch example.test\nnameserver fe80::1%eth0\nnameserver 192.0.2.53\n";
        assert_eq!(first_nameserver(r), Some("fe80::1".parse().unwrap()));
        assert_eq!(first_nameserver("search x\n"), None);
    }

    #[test]
    fn unknown_tool_is_invalid() {
        let e = handle(&json!({"tool":"rm"})).unwrap_err().to_string();
        assert!(e.contains("Invalid"), "{e}");
        let e = handle(&json!({"tool":"dns","name":"x","type":"ANY"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("Invalid"), "{e}");
    }

    #[test]
    fn tcp_test_reports_open_closed_and_validates() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let v = tcp_test(&json!({"host":"127.0.0.1","port":port,"rate_limit":600})).unwrap();
        assert_eq!(v["state"], "open", "{v}");
        assert_eq!(v["resolved"], "127.0.0.1");
        drop(l);
        let v = tcp_test(&json!({"host":"127.0.0.1","port":port,"rate_limit":600})).unwrap();
        assert_eq!(v["state"], "closed", "{v}");
        for bad in [
            json!({"host":"127.0.0.1"}),
            json!({"host":"127.0.0.1","port":0}),
            json!({"host":"127.0.0.1","port":70000}),
            json!({"host":"a;b","port":80}),
            json!({"host":"-x","port":80}),
            json!({"host":"127.0.0.1","port":80,"timeout":0}),
            json!({"host":"127.0.0.1","port":80,"timeout":31}),
            json!({"host":"127.0.0.1","port":80,"interface":"-x"}),
            json!({"host":"127.0.0.1","port":80,"source":"not-an-ip"}),
            json!({"host":"127.0.0.1","port":80,"family":"6"}),
        ] {
            let e = tcp_test(&bad).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{bad}: {e}");
        }
    }

    #[test]
    fn tcp_failures_are_classified_and_rate_is_limited() {
        use std::io::ErrorKind as K;
        assert_eq!(tcp_state(K::ConnectionRefused, Some(111)), "closed");
        assert_eq!(tcp_state(K::TimedOut, Some(110)), "filtered");
        assert_eq!(tcp_state(K::Other, Some(113)), "unreachable");
        assert_eq!(tcp_state(K::Other, None), "error");
        let t0 = Instant::now();
        let mut r = Vec::new();
        assert!(tcp_rate_ok(t0, &mut r, 2));
        assert!(tcp_rate_ok(t0, &mut r, 2));
        assert!(!tcp_rate_ok(t0, &mut r, 2));
        assert!(tcp_rate_ok(t0 + Duration::from_secs(61), &mut r, 2));
    }
}
