//! Firewall log viewer backend (lane B): an NFLOG collector, a bounded
//! history in the config store (`firewall_log`) and the search behind
//! `GET /api/firewall/logs`.
//!
//! Rules with the Log flag, threat-feed drops and (optionally) the default
//! deny log to NFLOG group [`patronus_firewall::feeds::NFLOG_GROUP`] with the
//! prefix `patronus[<rule id>] <action>: `. NFLOG works in every network
//! namespace (the kernel ring buffer only gets init-namespace packets), needs
//! no syslog daemon, and carries the interface indexes and the packet
//! header, which is all the viewer shows. The collector reads the group
//! through a raw netfilter netlink socket (it needs CAP_NET_ADMIN, like the
//! rest of the firewall), parses the headers, attributes each line to its
//! rule and appends batches to the store; the newest [`KEEP_LINES`] lines are
//! kept.

use super::firewall::FirewallManager;
use patronus_config::ConfigStore;
use patronus_firewall::feeds::NFLOG_GROUP;
use serde::Serialize;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Lines kept in the store.
pub const KEEP_LINES: i64 = 20_000;
/// Most lines written per second; the rest are counted as dropped.
const MAX_PER_SEC: usize = 400;

/// One parsed NFLOG packet.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Packet {
    pub ts: i64,
    pub prefix: String,
    pub hook: u8,
    pub iface_in: String,
    pub iface_out: String,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub length: Option<u32>,
}

/// Where a logged line came from, from its prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub rule_id: Option<i64>,
    /// `feed:<id>` for threat feeds, `default deny` for the policy log,
    /// otherwise empty (the caller fills in the rule's name).
    pub label: String,
    pub action: String,
}

/// `patronus[12] drop: ` / `patronus[ti:spamhaus_drop] drop: ` /
/// `patronus[default] drop: ` / `patronus accept: `.
pub fn attribute(prefix: &str) -> Option<Attribution> {
    let rest = prefix.strip_prefix("patronus")?;
    let (tag, tail) = match rest.strip_prefix('[') {
        Some(r) => {
            let (t, tail) = r.split_once(']')?;
            (Some(t), tail)
        }
        None => (None, rest),
    };
    let action = tail
        .trim()
        .trim_end_matches(':')
        .trim()
        .to_ascii_lowercase();
    Some(match tag {
        Some(t) if t.starts_with("ti:") => Attribution {
            rule_id: None,
            label: format!("feed:{}", &t[3..]),
            action,
        },
        Some("default") => Attribution {
            rule_id: None,
            label: "default deny".into(),
            action,
        },
        Some(t) => Attribution {
            rule_id: t.parse().ok(),
            label: String::new(),
            action,
        },
        None => Attribution {
            rule_id: None,
            label: String::new(),
            action,
        },
    })
}

fn chain_of(hook: u8) -> &'static str {
    match hook {
        0 => "prerouting",
        1 => "input",
        2 => "forward",
        3 => "output",
        4 => "postrouting",
        _ => "",
    }
}

/// Parse the IP header (and ports) of an NFLOG payload.
pub fn parse_ip(payload: &[u8], p: &mut Packet) {
    let proto_name = |n: u8| match n {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        58 => "ICMPV6".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        n => n.to_string(),
    };
    let ports = |b: &[u8], p: &mut Packet| {
        if b.len() >= 4 {
            p.sport = Some(u16::from_be_bytes([b[0], b[1]]));
            p.dport = Some(u16::from_be_bytes([b[2], b[3]]));
        }
    };
    match payload.first().map(|b| b >> 4) {
        Some(4) if payload.len() >= 20 => {
            let ihl = ((payload[0] & 0x0f) as usize) * 4;
            let proto = payload[9];
            p.proto = proto_name(proto);
            p.src = std::net::Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15])
                .to_string();
            p.dst = std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19])
                .to_string();
            p.length = Some(u16::from_be_bytes([payload[2], payload[3]]) as u32);
            // not a first fragment: no ports
            let frag = u16::from_be_bytes([payload[6], payload[7]]) & 0x1fff;
            if matches!(proto, 6 | 17) && frag == 0 && payload.len() >= ihl {
                ports(&payload[ihl..], p);
            }
        }
        Some(6) if payload.len() >= 40 => {
            let mut next = payload[6];
            let mut off = 40usize;
            // walk hop-by-hop, routing and destination option headers
            while matches!(next, 0 | 43 | 60) && payload.len() >= off + 8 {
                let l = (payload[off + 1] as usize + 1) * 8;
                next = payload[off];
                off += l;
            }
            p.proto = proto_name(next);
            let a: [u8; 16] = payload[8..24].try_into().unwrap_or([0; 16]);
            let b: [u8; 16] = payload[24..40].try_into().unwrap_or([0; 16]);
            p.src = std::net::Ipv6Addr::from(a).to_string();
            p.dst = std::net::Ipv6Addr::from(b).to_string();
            p.length = Some(u16::from_be_bytes([payload[4], payload[5]]) as u32 + 40);
            if matches!(next, 6 | 17) && payload.len() >= off {
                ports(&payload[off..], p);
            }
        }
        _ => {}
    }
}

/// Parse one `NFULNL_MSG_PACKET` message body (the attributes after the
/// nfgenmsg header).
pub fn parse_packet_attrs(mut b: &[u8], ifname: &dyn Fn(u32) -> String) -> Packet {
    let mut p = Packet {
        ts: chrono::Utc::now().timestamp(),
        ..Default::default()
    };
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            break;
        }
        let v = &b[4..len];
        let be32 = |v: &[u8]| {
            v.get(..4)
                .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
        };
        match ty {
            1 if v.len() >= 3 => p.hook = v[2],
            3 if v.len() >= 8 => {
                let secs = u64::from_be_bytes(v[..8].try_into().unwrap_or([0; 8]));
                if secs > 1_000_000_000 {
                    p.ts = secs as i64;
                }
            }
            4 => p.iface_in = be32(v).filter(|i| *i != 0).map(ifname).unwrap_or_default(),
            5 => p.iface_out = be32(v).filter(|i| *i != 0).map(ifname).unwrap_or_default(),
            9 => parse_ip(v, &mut p),
            10 => {
                p.prefix = String::from_utf8_lossy(v)
                    .trim_end_matches('\0')
                    .to_string()
            }
            _ => {}
        }
        b = &b[((len + 3) & !3).min(b.len())..];
    }
    p
}

// ---------------------------------------------------------------------
// collector status
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Default)]
pub struct CollectorStatus {
    pub running: bool,
    pub error: Option<String>,
    pub received: u64,
    pub dropped: u64,
}

fn status() -> &'static Mutex<CollectorStatus> {
    static S: OnceLock<Mutex<CollectorStatus>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(CollectorStatus::default()))
}

pub fn collector_status() -> CollectorStatus {
    status().lock().map(|s| s.clone()).unwrap_or_default()
}

// ---------------------------------------------------------------------
// NFLOG socket
// ---------------------------------------------------------------------

mod nflog {
    use super::*;

    const NETLINK_NETFILTER: i32 = 12;
    const NFNL_SUBSYS_ULOG: u16 = 4;
    const NFULNL_MSG_PACKET: u16 = 0;
    const NFULNL_MSG_CONFIG: u16 = 1;
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;

    pub struct Socket {
        fd: i32,
    }

    fn attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
        let len = (4 + data.len()) as u16;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(data);
        buf.resize((buf.len() + 3) & !3, 0);
    }

    fn config_msg(group: u16, seq: u32, attrs: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        let total = 16 + 4 + attrs.len();
        m.extend_from_slice(&(total as u32).to_ne_bytes());
        m.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG).to_ne_bytes());
        m.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid
        m.push(0); // AF_UNSPEC
        m.push(0); // version
        m.extend_from_slice(&group.to_be_bytes());
        m.extend_from_slice(attrs);
        m
    }

    impl Socket {
        /// Bind NFLOG `group` with a copy range of `range` bytes.
        pub fn open(group: u16, range: u32) -> Result<Socket, String> {
            // SAFETY: plain syscalls on a socket we own; every buffer
            // passed is a live slice/struct of the stated length.
            unsafe {
                let fd = libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    NETLINK_NETFILTER,
                );
                if fd < 0 {
                    return Err(format!(
                        "netlink socket: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                let s = Socket { fd };
                let mut sa: libc::sockaddr_nl = std::mem::zeroed();
                sa.nl_family = libc::AF_NETLINK as u16;
                if libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as u32,
                ) < 0
                {
                    return Err(format!("netlink bind: {}", std::io::Error::last_os_error()));
                }
                let tv = libc::timeval {
                    tv_sec: 1,
                    tv_usec: 0,
                };
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                );
                let sz: i32 = 1 << 20;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &sz as *const _ as *const libc::c_void,
                    4,
                );
                // bind the group
                let mut a = Vec::new();
                attr(&mut a, 1, &[1, 0, 0, 0]); // NFULA_CFG_CMD: NFULNL_CFG_CMD_BIND
                s.send(&config_msg(group, 1, &a))?;
                s.expect_ack("bind NFLOG group (is nfnetlink_log available and are you root?)")?;
                // copy the packet header, deliver each packet at once
                let mut a = Vec::new();
                let mut mode = Vec::new();
                mode.extend_from_slice(&range.to_be_bytes());
                mode.push(2); // NFULNL_COPY_PACKET
                mode.push(0);
                attr(&mut a, 2, &mode); // NFULA_CFG_MODE
                attr(&mut a, 3, &10u32.to_be_bytes()); // timeout, 1/100 s
                attr(&mut a, 4, &1u32.to_be_bytes()); // queue threshold
                s.send(&config_msg(group, 2, &a))?;
                s.expect_ack("configure NFLOG group")?;
                Ok(s)
            }
        }

        fn send(&self, m: &[u8]) -> Result<(), String> {
            // SAFETY: `m` is a live slice.
            let n = unsafe { libc::send(self.fd, m.as_ptr() as *const libc::c_void, m.len(), 0) };
            if n < 0 {
                Err(format!("netlink send: {}", std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }

        fn expect_ack(&self, what: &str) -> Result<(), String> {
            let mut buf = vec![0u8; 8192];
            // SAFETY: `buf` is a live buffer of the stated length.
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 20 {
                return Err(format!("{what}: no answer from the kernel"));
            }
            let ty = u16::from_ne_bytes([buf[4], buf[5]]);
            if ty == NLMSG_ERROR {
                let e = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if e != 0 {
                    return Err(format!("{what}: {}", std::io::Error::from_raw_os_error(-e)));
                }
            }
            Ok(())
        }

        /// Wait up to a second for messages; returns the packets read.
        pub fn read(&self, ifname: &dyn Fn(u32) -> String) -> Result<Vec<Packet>, String> {
            let mut buf = vec![0u8; 65536];
            // SAFETY: `buf` is a live buffer of the stated length.
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                return match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(vec![]),
                    _ if e.raw_os_error() == Some(libc::ENOBUFS) => Ok(vec![]),
                    _ => Err(format!("netlink recv: {e}")),
                };
            }
            let b = &buf[..n as usize];
            let mut out = Vec::new();
            let mut off = 0;
            while off + 16 <= b.len() {
                let len = u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
                let ty = u16::from_ne_bytes([b[off + 4], b[off + 5]]);
                if len < 16 || off + len > b.len() {
                    break;
                }
                if ty == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET && len >= 20 {
                    out.push(parse_packet_attrs(&b[off + 20..off + len], ifname));
                }
                off += (len + 3) & !3;
            }
            Ok(out)
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            // SAFETY: closing the fd we opened.
            unsafe { libc::close(self.fd) };
        }
    }

    pub fn if_name(idx: u32) -> String {
        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `buf` is IF_NAMESIZE bytes as required.
        let p = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr()) };
        if p.is_null() {
            return idx.to_string();
        }
        // SAFETY: if_indextoname wrote a NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}

// ---------------------------------------------------------------------
// store
// ---------------------------------------------------------------------

/// One stored line.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LogEntry {
    pub id: i64,
    pub ts: i64,
    pub rule_id: Option<i64>,
    pub rule: String,
    pub action: String,
    pub chain: String,
    pub iface_in: String,
    pub iface_out: String,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub sport: Option<i64>,
    pub dport: Option<i64>,
    pub length: Option<i64>,
    pub prefix: String,
}

/// Filters of the log search.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct LogQuery {
    pub rule: Option<String>,
    pub action: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub proto: Option<String>,
    pub port: Option<u16>,
    pub iface: Option<String>,
    pub q: Option<String>,
    pub minutes: Option<i64>,
    pub since_id: Option<i64>,
    pub limit: Option<i64>,
}

fn nz(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn like(s: &str) -> String {
    let e = s
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{e}%")
}

enum Bind {
    S(String),
    I(i64),
}

/// Search the stored log, newest first. Returns the lines and the id of
/// the newest stored line (the cursor for live polling).
pub async fn search(store: &ConfigStore, q: &LogQuery) -> anyhow::Result<(Vec<LogEntry>, i64)> {
    let mut sql = String::from(
        "SELECT id, ts, rule_id, rule, action, chain, iface_in, iface_out, proto, src, dst,
                sport, dport, length, prefix FROM firewall_log WHERE 1=1",
    );
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(r) = nz(&q.rule) {
        match r.parse::<i64>() {
            Ok(n) => {
                sql.push_str(" AND (rule_id = ? OR rule LIKE ? ESCAPE '\\')");
                binds.push(Bind::I(n));
                binds.push(Bind::S(like(r)));
            }
            Err(_) => {
                sql.push_str(" AND rule LIKE ? ESCAPE '\\'");
                binds.push(Bind::S(like(r)));
            }
        }
    }
    if let Some(a) = nz(&q.action) {
        sql.push_str(" AND action = ?");
        binds.push(Bind::S(a.to_ascii_lowercase()));
    }
    for (col, v) in [("src", nz(&q.src)), ("dst", nz(&q.dst))] {
        if let Some(s) = v {
            sql.push_str(&format!(" AND {col} LIKE ? ESCAPE '\\'"));
            binds.push(Bind::S(format!("{}%", like(s).trim_matches('%'))));
        }
    }
    if let Some(p) = nz(&q.proto) {
        sql.push_str(" AND proto = ?");
        binds.push(Bind::S(p.to_ascii_uppercase()));
    }
    if let Some(p) = q.port {
        sql.push_str(" AND (sport = ? OR dport = ?)");
        binds.push(Bind::I(p as i64));
        binds.push(Bind::I(p as i64));
    }
    if let Some(i) = nz(&q.iface) {
        sql.push_str(" AND (iface_in = ? OR iface_out = ?)");
        binds.push(Bind::S(i.to_string()));
        binds.push(Bind::S(i.to_string()));
    }
    if let Some(t) = nz(&q.q) {
        let cols = ["rule", "prefix", "src", "dst", "proto", "chain", "action"];
        let parts: Vec<String> = cols
            .iter()
            .map(|c| format!("{c} LIKE ? ESCAPE '\\'"))
            .collect();
        sql.push_str(&format!(" AND ({})", parts.join(" OR ")));
        for _ in cols {
            binds.push(Bind::S(like(t)));
        }
    }
    if let Some(m) = q.minutes.filter(|m| *m > 0) {
        sql.push_str(" AND ts >= ?");
        binds.push(Bind::I(chrono::Utc::now().timestamp() - m * 60));
    }
    if let Some(s) = q.since_id {
        sql.push_str(" AND id > ?");
        binds.push(Bind::I(s));
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    binds.push(Bind::I(q.limit.unwrap_or(200).clamp(1, 2000)));
    let mut query = sqlx::query(&sql);
    for b in binds {
        query = match b {
            Bind::S(s) => query.bind(s),
            Bind::I(i) => query.bind(i),
        };
    }
    let rows = query.fetch_all(store.pool()?).await?;
    let entries: Vec<LogEntry> = rows
        .iter()
        .map(|r| LogEntry {
            id: r.get(0),
            ts: r.get(1),
            rule_id: r.get(2),
            rule: r.get(3),
            action: r.get(4),
            chain: r.get(5),
            iface_in: r.get(6),
            iface_out: r.get(7),
            proto: r.get(8),
            src: r.get(9),
            dst: r.get(10),
            sport: r.get(11),
            dport: r.get(12),
            length: r.get(13),
            prefix: r.get(14),
        })
        .collect();
    let last: i64 = sqlx::query("SELECT COALESCE(MAX(id), 0) FROM firewall_log")
        .fetch_one(store.pool()?)
        .await?
        .get(0);
    Ok((entries, last))
}

/// Append parsed packets, attributing each to its rule.
pub async fn store_packets(
    store: &ConfigStore,
    packets: &[Packet],
    names: &HashMap<i64, String>,
) -> anyhow::Result<usize> {
    let mut n = 0;
    let mut tx = store.pool()?.begin().await?;
    for p in packets {
        let Some(at) = attribute(&p.prefix) else {
            continue;
        };
        let rule = if !at.label.is_empty() {
            at.label.clone()
        } else if let Some(id) = at.rule_id {
            names
                .get(&id)
                .cloned()
                .unwrap_or_else(|| format!("rule {id} (deleted)"))
        } else {
            String::from("unnamed rule")
        };
        sqlx::query(
            "INSERT INTO firewall_log (ts, rule_id, rule, action, chain, iface_in, iface_out,
                 proto, src, dst, sport, dport, length, prefix)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(p.ts)
        .bind(at.rule_id)
        .bind(rule)
        .bind(&at.action)
        .bind(chain_of(p.hook))
        .bind(&p.iface_in)
        .bind(&p.iface_out)
        .bind(&p.proto)
        .bind(&p.src)
        .bind(&p.dst)
        .bind(p.sport.map(i64::from))
        .bind(p.dport.map(i64::from))
        .bind(p.length.map(i64::from))
        .bind(&p.prefix)
        .execute(&mut *tx)
        .await?;
        n += 1;
    }
    tx.commit().await?;
    Ok(n)
}

/// Delete everything older than the newest [`KEEP_LINES`] lines.
pub async fn prune(store: &ConfigStore) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM firewall_log WHERE id <= (SELECT MAX(id) FROM firewall_log) - ?")
        .bind(KEEP_LINES)
        .execute(store.pool()?)
        .await?;
    Ok(())
}

pub async fn clear(store: &ConfigStore) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM firewall_log")
        .execute(store.pool()?)
        .await?;
    Ok(())
}

async fn rule_names(store: &ConfigStore) -> HashMap<i64, String> {
    store
        .load_firewall_rules()
        .await
        .map(|v| {
            v.into_iter()
                .filter_map(|r| r.id.map(|i| (i as i64, r.name)))
                .collect()
        })
        .unwrap_or_default()
}

/// Start the collector: a blocking reader thread feeding a writer task.
/// `PATRONUS_FWLOG=0` turns it off.
pub fn spawn_collector(fw: Arc<FirewallManager>) {
    if std::env::var("PATRONUS_FWLOG")
        .map(|v| v == "0")
        .unwrap_or(false)
    {
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Packet>(4096);
    std::thread::Builder::new()
        .name("fwlog-nflog".into())
        .spawn(move || loop {
            match nflog::Socket::open(NFLOG_GROUP, 128) {
                Err(e) => {
                    if let Ok(mut s) = status().lock() {
                        s.running = false;
                        s.error = Some(e);
                    }
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
                Ok(sock) => {
                    if let Ok(mut s) = status().lock() {
                        s.running = true;
                        s.error = None;
                    }
                    loop {
                        match sock.read(&nflog::if_name) {
                            Ok(v) => {
                                for p in v {
                                    if tx.try_send(p).is_err() {
                                        if let Ok(mut s) = status().lock() {
                                            s.dropped += 1;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                if let Ok(mut s) = status().lock() {
                                    s.running = false;
                                    s.error = Some(e);
                                }
                                break;
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
            }
        })
        .ok();
    tokio::spawn(async move {
        let mut names = rule_names(&fw.store).await;
        let mut ticks = 0u32;
        let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            t.tick().await;
            let mut batch = Vec::new();
            while let Ok(p) = rx.try_recv() {
                batch.push(p);
            }
            ticks += 1;
            if ticks >= 30 {
                ticks = 0;
                names = rule_names(&fw.store).await;
                let _ = prune(&fw.store).await;
            }
            if batch.is_empty() {
                continue;
            }
            if let Ok(mut s) = status().lock() {
                s.received += batch.len() as u64;
            }
            if batch.len() > MAX_PER_SEC {
                if let Ok(mut s) = status().lock() {
                    s.dropped += (batch.len() - MAX_PER_SEC) as u64;
                }
                batch.truncate(MAX_PER_SEC);
            }
            if batch.iter().any(|p| {
                attribute(&p.prefix)
                    .and_then(|a| a.rule_id)
                    .map(|id| !names.contains_key(&id))
                    .unwrap_or(false)
            }) {
                names = rule_names(&fw.store).await;
            }
            if let Err(e) = store_packets(&fw.store, &batch, &names).await {
                tracing::warn!("firewall log: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_attributed() {
        let a = attribute("patronus[12] drop: ").unwrap();
        assert_eq!(
            (a.rule_id, a.action.as_str(), a.label.as_str()),
            (Some(12), "drop", "")
        );
        let a = attribute("patronus[ti:spamhaus_drop] drop: ").unwrap();
        assert_eq!(a.label, "feed:spamhaus_drop");
        assert_eq!(
            attribute("patronus[default] drop: ").unwrap().label,
            "default deny"
        );
        assert_eq!(attribute("patronus accept: ").unwrap().action, "accept");
        assert!(attribute("[GeoIP-CN] x").is_none());
        assert!(attribute("kernel: whatever").is_none());
    }

    fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(data);
        v.resize((v.len() + 3) & !3, 0);
        v
    }

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 60, 0, 0, 0x40, 0, 64, 6, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    #[test]
    fn nflog_attributes_parse_into_a_packet() {
        let mut body = Vec::new();
        body.extend(attr(1, &[0x08, 0x00, 2, 0])); // hook 2 = forward
        body.extend(attr(4, &3u32.to_be_bytes()));
        body.extend(attr(5, &4u32.to_be_bytes()));
        body.extend(attr(
            9,
            &ipv4_tcp([192, 0, 2, 7], [198, 51, 100, 9], 40000, 443),
        ));
        body.extend(attr(10, b"patronus[7] reject: \0"));
        let p = parse_packet_attrs(&body, &|i| format!("if{i}"));
        assert_eq!(p.hook, 2);
        assert_eq!((p.iface_in.as_str(), p.iface_out.as_str()), ("if3", "if4"));
        assert_eq!(
            (p.proto.as_str(), p.src.as_str(), p.dst.as_str()),
            ("TCP", "192.0.2.7", "198.51.100.9")
        );
        assert_eq!(
            (p.sport, p.dport, p.length),
            (Some(40000), Some(443), Some(60))
        );
        assert_eq!(p.prefix, "patronus[7] reject: ");
    }

    #[test]
    fn ipv6_udp_header_parses() {
        let mut pk = vec![0x60, 0, 0, 0, 0, 20, 17, 64];
        pk.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        pk.extend_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        pk.extend_from_slice(&5353u16.to_be_bytes());
        pk.extend_from_slice(&53u16.to_be_bytes());
        pk.extend_from_slice(&[0; 12]);
        let mut p = Packet::default();
        parse_ip(&pk, &mut p);
        assert_eq!(
            (p.proto.as_str(), p.src.as_str(), p.dst.as_str()),
            ("UDP", "2001:db8::1", "2001:db8::2")
        );
        assert_eq!(
            (p.sport, p.dport, p.length),
            (Some(5353), Some(53), Some(60))
        );
        // truncated garbage never panics
        for n in 0..45 {
            let mut p = Packet::default();
            parse_ip(&pk[..n.min(pk.len())], &mut p);
            let _ = parse_packet_attrs(&pk[..n.min(pk.len())], &|i| i.to_string());
        }
    }

    #[tokio::test]
    async fn store_search_filters_and_pruning() {
        let s = ConfigStore::open_in_memory().await.unwrap();
        let mk = |prefix: &str, src: &str, dport: u16, hook: u8| Packet {
            ts: chrono::Utc::now().timestamp(),
            prefix: prefix.into(),
            hook,
            iface_in: "eth0".into(),
            proto: "TCP".into(),
            src: src.into(),
            dst: "10.0.0.5".into(),
            sport: Some(1234),
            dport: Some(dport),
            length: Some(60),
            ..Default::default()
        };
        let mut names = HashMap::new();
        names.insert(3, "block ssh".to_string());
        let n = store_packets(
            &s,
            &[
                mk("patronus[3] drop: ", "203.0.113.9", 22, 1),
                mk("patronus[3] drop: ", "203.0.113.10", 22, 1),
                mk("patronus[ti:spamhaus_drop] drop: ", "1.10.16.4", 80, 2),
                mk("patronus[99] accept: ", "198.51.100.1", 443, 2),
                mk("not ours", "9.9.9.9", 1, 1),
            ],
            &names,
        )
        .await
        .unwrap();
        assert_eq!(n, 4);
        let q = |f: &dyn Fn(&mut LogQuery)| {
            let mut q = LogQuery::default();
            f(&mut q);
            q
        };
        let all = search(&s, &LogQuery::default()).await.unwrap();
        assert_eq!(all.0.len(), 4);
        assert_eq!(all.0[0].rule, "rule 99 (deleted)", "newest first");
        let r = search(&s, &q(&|q| q.rule = Some("3".into())))
            .await
            .unwrap()
            .0;
        assert_eq!(r.len(), 2);
        assert!(r
            .iter()
            .all(|e| e.rule == "block ssh" && e.chain == "input" && e.action == "drop"));
        let r = search(&s, &q(&|q| q.rule = Some("feed".into())))
            .await
            .unwrap()
            .0;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule, "feed:spamhaus_drop");
        let r = search(&s, &q(&|q| q.src = Some("203.0.113.".into())))
            .await
            .unwrap()
            .0;
        assert_eq!(r.len(), 2);
        let r = search(&s, &q(&|q| q.port = Some(443))).await.unwrap().0;
        assert_eq!((r.len(), r[0].dport), (1, Some(443)));
        let r = search(&s, &q(&|q| q.action = Some("ACCEPT".into())))
            .await
            .unwrap()
            .0;
        assert_eq!(r.len(), 1);
        let r = search(&s, &q(&|q| q.q = Some("spamhaus".into())))
            .await
            .unwrap()
            .0;
        assert_eq!(r.len(), 1);
        let r = search(
            &s,
            &q(&|q| {
                q.q = Some("ssh".into());
                q.proto = Some("tcp".into());
                q.iface = Some("eth0".into());
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(r.len(), 2, "text + proto + iface combine");
        // a % or _ in a filter is literal, and quotes cannot break the query
        assert!(search(&s, &q(&|q| q.q = Some("%".into())))
            .await
            .unwrap()
            .0
            .is_empty());
        assert!(search(&s, &q(&|q| q.src = Some("' OR 1=1 --".into())))
            .await
            .unwrap()
            .0
            .is_empty());
        // live poll: only what is newer than the cursor
        let last = all.1;
        store_packets(
            &s,
            &[mk("patronus[3] drop: ", "203.0.113.77", 22, 1)],
            &names,
        )
        .await
        .unwrap();
        let r = search(&s, &q(&|q| q.since_id = Some(last)))
            .await
            .unwrap()
            .0;
        assert_eq!((r.len(), r[0].src.as_str()), (1, "203.0.113.77"));
        prune(&s).await.unwrap();
        clear(&s).await.unwrap();
        assert!(search(&s, &LogQuery::default()).await.unwrap().0.is_empty());
    }
}
