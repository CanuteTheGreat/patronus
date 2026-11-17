//! Names of Wi-Fi clients on an access point.
//!
//! An access point hands out no addresses: the main router has the DHCP leases. Two lease sources that need nothing
//! configured on the router:
//!
//! - **DHCP snoop** ([`spawn_snoop`], run by `patronus applyd` on access points): a client that joins sends a
//!   broadcast DHCPDISCOVER/DHCPREQUEST, which crosses the AP's bridge. Its client MAC (`chaddr`), the address it asks
//!   for (option 50 / `ciaddr`) and its host name (option 12) are recorded in [`NAMES_FILE`] (one line per MAC, at
//!   most [`MAX_ENTRIES`], the newest kept). The socket only reads; nothing is answered or changed.
//! - **Reverse DNS** ([`ptr_lookup`]) at the router's DNS server for clients whose address is known but whose
//!   request was not seen (joined before the AP started): routers that register DHCP names in DNS (dnsmasq/OpenWrt,
//!   pfSense/OPNsense with DHCP registration, most home routers) answer the PTR query with the lease's name.
//!
//! A name that neither source knows stays empty: nothing is guessed.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Where the snoop keeps what it saw: `mac ipv4|- unix-time hostname|-` per line.
pub const NAMES_FILE: &str = "/run/patronus/dhcp-names";
pub const MAX_ENTRIES: usize = 512;

pub fn names_file() -> PathBuf {
    PathBuf::from(std::env::var("PATRONUS_DHCP_NAMES").unwrap_or_else(|_| NAMES_FILE.into()))
}

/// What one DHCP client message says about its sender.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub mac: String,
    pub ip: Option<Ipv4Addr>,
    pub hostname: Option<String>,
}

/// A host name as a client may send it: letters, digits, `-`, `_` and `.`, 1..=63 characters; anything else is
/// dropped (never shown).
pub fn clean_name(raw: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim_end_matches('\0').trim().trim_end_matches('.');
    (!s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    .then(|| s.to_string())
}

/// Parse a BOOTP/DHCP message (the UDP payload) sent BY a client (op 1, Ethernet). `None` for anything else.
pub fn parse_dhcp(p: &[u8]) -> Option<Seen> {
    if p.len() < 240 || p[0] != 1 || p[1] != 1 || p[2] != 6 || p[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let mac = p[28..34]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let ciaddr = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let mut ip = (!ciaddr.is_unspecified()).then_some(ciaddr);
    let mut hostname = None;
    let mut msg_type = 0u8;
    let mut i = 240;
    while i < p.len() {
        let code = p[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = *p.get(i + 1)? as usize;
        let v = p.get(i + 2..i + 2 + len)?;
        match code {
            12 => hostname = clean_name(v),
            50 if len == 4 => ip = Some(Ipv4Addr::new(v[0], v[1], v[2], v[3])),
            53 if len == 1 => msg_type = v[0],
            _ => {}
        }
        i += 2 + len;
    }
    // DISCOVER (1), REQUEST (3), INFORM (8); a RELEASE/DECLINE says the address is gone
    if !matches!(msg_type, 1 | 3 | 8) {
        return None;
    }
    Some(Seen { mac, ip, hostname })
}

/// Parse an IPv4 packet (from an `AF_PACKET`/`SOCK_DGRAM` socket: no Ethernet header) carrying UDP 68 -> 67.
pub fn parse_ipv4_dhcp(pkt: &[u8]) -> Option<Seen> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let udp = pkt.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let (sport, dport) = (
        u16::from_be_bytes([udp[0], udp[1]]),
        u16::from_be_bytes([udp[2], udp[3]]),
    );
    if sport != 68 || dport != 67 {
        return None;
    }
    parse_dhcp(&udp[8..])
}

/// One line of the names file.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub ip: Option<Ipv4Addr>,
    pub at: u64,
    pub hostname: Option<String>,
}

pub fn read_names(path: &Path) -> HashMap<String, Entry> {
    parse_names(&std::fs::read_to_string(path).unwrap_or_default())
}

pub fn parse_names(text: &str) -> HashMap<String, Entry> {
    text.lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.len() == 4).then(|| {
                (
                    c[0].to_string(),
                    Entry {
                        ip: c[1].parse().ok(),
                        at: c[2].parse().unwrap_or(0),
                        hostname: (c[3] != "-").then(|| c[3].to_string()),
                    },
                )
            })
        })
        .collect()
}

pub fn render_names(m: &HashMap<String, Entry>) -> String {
    let mut v: Vec<(&String, &Entry)> = m.iter().collect();
    v.sort_by(|a, b| b.1.at.cmp(&a.1.at).then(a.0.cmp(b.0)));
    v.truncate(MAX_ENTRIES);
    v.iter()
        .map(|(mac, e)| {
            format!(
                "{mac} {} {} {}\n",
                e.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
                e.at,
                e.hostname.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

/// Merge one sighting; returns whether anything changed. A request without a name keeps the name seen before.
pub fn merge(m: &mut HashMap<String, Entry>, s: Seen, now: u64) -> bool {
    let e = m.entry(s.mac).or_insert(Entry {
        ip: None,
        at: 0,
        hostname: None,
    });
    let before = e.clone();
    if s.ip.is_some() {
        e.ip = s.ip;
    }
    if s.hostname.is_some() {
        e.hostname = s.hostname;
    }
    e.at = now;
    // the time alone changing is not worth a write more than once a minute
    before.ip != e.ip || before.hostname != e.hostname || now >= before.at + 60
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_atomic(path: &Path, text: &str) {
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = path.with_extension("new");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Watch DHCP client messages crossing `bridge` (read only) and keep [`names_file`] current. Runs in its own thread
/// for the life of the process; errors (no bridge yet, no permission) are retried every 30 s.
pub fn spawn_snoop(bridge: String) {
    std::thread::Builder::new()
        .name("dhcp-snoop".into())
        .spawn(move || loop {
            if let Err(e) = snoop(&bridge, &names_file()) {
                tracing::debug!("dhcp snoop on {bridge}: {e}");
            }
            std::thread::sleep(Duration::from_secs(30));
        })
        .ok();
}

fn snoop(bridge: &str, path: &Path) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let ifindex = unsafe {
        let c = std::ffi::CString::new(bridge).map_err(std::io::Error::other)?;
        libc::if_nametoindex(c.as_ptr())
    };
    if ifindex == 0 {
        return Err(std::io::Error::other("no such interface"));
    }
    let proto = (libc::ETH_P_IP as u16).to_be();
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto as i32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto;
    sll.sll_ifindex = ifindex as i32;
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut map = read_names(path);
    let mut buf = vec![0u8; 2048];
    loop {
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if let Some(s) = parse_ipv4_dhcp(&buf[..n as usize]) {
            if merge(&mut map, s, now()) {
                if map.len() > MAX_ENTRIES {
                    map = parse_names(&render_names(&map));
                }
                write_atomic(path, &render_names(&map));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// reverse DNS
// ---------------------------------------------------------------------------

/// A PTR query for `ip` with message id `id`.
pub fn ptr_query(id: u16, ip: Ipv4Addr) -> Vec<u8> {
    let o = ip.octets();
    let name = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 12, 0, 1]); // PTR, IN
    q
}

fn read_name(msg: &[u8], mut i: usize, depth: u8) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    loop {
        let l = *msg.get(i)? as usize;
        if l == 0 {
            i += 1;
            break;
        }
        if l & 0xc0 == 0xc0 {
            let off = ((l & 0x3f) << 8) | *msg.get(i + 1)? as usize;
            let (rest, _) = read_name(msg, off, depth + 1)?;
            if !rest.is_empty() {
                labels.push(rest);
            }
            end = Some(i + 2);
            break;
        }
        labels.push(String::from_utf8_lossy(msg.get(i + 1..i + 1 + l)?).into_owned());
        i += 1 + l;
    }
    Some((labels.join("."), end.unwrap_or(i)))
}

/// The PTR answer of a DNS response: (message id, name).
pub fn parse_ptr_answer(msg: &[u8]) -> Option<(u16, String)> {
    if msg.len() < 12 || msg[2] & 0x80 == 0 || msg[3] & 0x0f != 0 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut i = 12;
    for _ in 0..qd {
        let (_, j) = read_name(msg, i, 0)?;
        i = j + 4;
    }
    for _ in 0..an {
        let (_, j) = read_name(msg, i, 0)?;
        let typ = u16::from_be_bytes([*msg.get(j)?, *msg.get(j + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(j + 8)?, *msg.get(j + 9)?]) as usize;
        let rd = j + 10;
        if typ == 12 {
            let (name, _) = read_name(msg, rd, 0)?;
            return clean_name(name.as_bytes()).map(|n| (id, n));
        }
        i = rd + rdlen;
    }
    None
}

/// Ask `server` for the PTR names of `ips`, all queries at once, waiting at most `within` in total.
pub fn ptr_lookup(
    server: SocketAddr,
    ips: &[Ipv4Addr],
    within: Duration,
) -> HashMap<Ipv4Addr, String> {
    let mut out = HashMap::new();
    if ips.is_empty() {
        return out;
    }
    let Ok(sock) = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }) else {
        return out;
    };
    let base: u16 = (now() as u16).wrapping_mul(7919);
    let mut ids = HashMap::new();
    for (n, ip) in ips.iter().take(256).enumerate() {
        let id = base.wrapping_add(n as u16);
        ids.insert(id, *ip);
        let _ = sock.send_to(&ptr_query(id, *ip), server);
    }
    let t0 = Instant::now();
    let mut buf = [0u8; 1500];
    while out.len() < ids.len() {
        let left = within.saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        let _ = sock.set_read_timeout(Some(left.max(Duration::from_millis(1))));
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == server.ip() => {
                if let Some((id, name)) = parse_ptr_answer(&buf[..n]) {
                    if let Some(ip) = ids.get(&id) {
                        out.insert(*ip, name);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
}

/// The first IPv4 nameserver of a resolv.conf.
pub fn first_nameserver(resolv: &str) -> Option<Ipv4Addr> {
    resolv.lines().find_map(|l| {
        l.trim()
            .strip_prefix("nameserver")
            .and_then(|r| r.trim().parse().ok())
    })
}

/// Fill `hostname` (and `ipv4` when the snoop saw it) into client rows (`mac`, optional `ipv4`), per the unit's
/// `AP_NAMES` setting: "dhcp" (default) = snoop + PTR at this unit's own DNS server, an IPv4 = snoop + PTR at that
/// server, "off" = nothing.
pub fn annotate(clients: &mut [Value], setting: &str, names: &Path, resolv: &str) {
    if setting == "off" {
        return;
    }
    let seen = read_names(names);
    for c in clients.iter_mut() {
        let Some(mac) = c.get("mac").and_then(Value::as_str).map(str::to_string) else {
            continue;
        };
        if let Some(e) = seen.get(&mac) {
            if c.get("ipv4").is_none() {
                if let Some(ip) = e.ip {
                    c["ipv4"] = json!(ip.to_string());
                }
            }
            if let Some(h) = &e.hostname {
                c["hostname"] = json!(h);
                c["hostname_source"] = json!("dhcp");
            }
        }
    }
    let server = setting
        .parse::<Ipv4Addr>()
        .ok()
        .or_else(|| first_nameserver(resolv));
    let Some(server) = server else { return };
    let want: Vec<Ipv4Addr> = clients
        .iter()
        .filter(|c| c.get("hostname").is_none())
        .filter_map(|c| c.get("ipv4").and_then(Value::as_str)?.parse().ok())
        .collect();
    let got = ptr_lookup(
        SocketAddr::from((server, 53)),
        &want,
        Duration::from_millis(800),
    );
    for c in clients.iter_mut() {
        let ip: Option<Ipv4Addr> = c
            .get("ipv4")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok());
        if c.get("hostname").is_none() {
            if let Some(n) = ip.and_then(|ip| got.get(&ip)) {
                c["hostname"] = json!(n);
                c["hostname_source"] = json!("dns");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dhcp_request(mac: [u8; 6], host: Option<&str>, req: Option<[u8; 4]>, msg: u8) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1;
        p[1] = 1;
        p[2] = 6;
        p[28..34].copy_from_slice(&mac);
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        p.extend_from_slice(&[53, 1, msg]);
        if let Some(h) = host {
            p.push(12);
            p.push(h.len() as u8);
            p.extend_from_slice(h.as_bytes());
        }
        if let Some(r) = req {
            p.extend_from_slice(&[50, 4]);
            p.extend_from_slice(&r);
        }
        p.push(255);
        p
    }

    fn ip_udp(payload: &[u8], sport: u16, dport: u16) -> Vec<u8> {
        let mut v = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
        ];
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn dhcp_requests_name_their_sender() {
        let p = dhcp_request(
            [0x86, 4, 0xc3, 0xa6, 0x16, 0x43],
            Some("Galaxy-S23"),
            Some([192, 0, 2, 44]),
            3,
        );
        let s = parse_ipv4_dhcp(&ip_udp(&p, 68, 67)).unwrap();
        assert_eq!(s.mac, "86:04:c3:a6:16:43");
        assert_eq!(s.ip, Some(Ipv4Addr::new(192, 0, 2, 44)));
        assert_eq!(s.hostname.as_deref(), Some("Galaxy-S23"));
        // server replies, other ports, releases and junk are ignored
        assert!(parse_ipv4_dhcp(&ip_udp(&p, 67, 68)).is_none());
        assert!(parse_ipv4_dhcp(&ip_udp(&p, 68, 53)).is_none());
        let rel = dhcp_request([1, 2, 3, 4, 5, 6], Some("x"), None, 7);
        assert!(parse_ipv4_dhcp(&ip_udp(&rel, 68, 67)).is_none());
        assert!(parse_ipv4_dhcp(&[0x45, 0, 1]).is_none());
        assert!(parse_dhcp(&p[..100]).is_none());
        // a name with shell or markup characters is dropped, the address kept
        let bad = dhcp_request([1, 2, 3, 4, 5, 6], Some("<b>x;rm"), Some([10, 0, 0, 9]), 1);
        let s = parse_dhcp(&bad).unwrap();
        assert_eq!(s.hostname, None);
        assert_eq!(s.ip, Some(Ipv4Addr::new(10, 0, 0, 9)));
        // truncated option list does not panic
        let mut t = dhcp_request([1, 2, 3, 4, 5, 6], Some("abc"), None, 3);
        t.truncate(t.len() - 3);
        let _ = parse_dhcp(&t);
    }

    #[test]
    fn names_file_round_trip_and_merge() {
        let mut m = HashMap::new();
        assert!(merge(
            &mut m,
            Seen {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 5)),
                hostname: Some("laptop".into())
            },
            1000
        ));
        // a renewal without option 12 keeps the name; same data within a minute is not a change
        assert!(!merge(
            &mut m,
            Seen {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 5)),
                hostname: None
            },
            1010
        ));
        assert_eq!(m["aa:bb:cc:dd:ee:ff"].hostname.as_deref(), Some("laptop"));
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("names");
        std::fs::write(&f, render_names(&m)).unwrap();
        let back = read_names(&f);
        assert_eq!(back, m);
        for i in 0..(MAX_ENTRIES + 10) {
            m.insert(
                format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256),
                Entry {
                    ip: None,
                    at: i as u64,
                    hostname: None,
                },
            );
        }
        assert_eq!(render_names(&m).lines().count(), MAX_ENTRIES);
    }

    fn ptr_reply(id: u16, ip: Ipv4Addr, name: &str) -> Vec<u8> {
        let q = ptr_query(id, ip);
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 60]);
        let mut rd = Vec::new();
        for l in name.split('.') {
            rd.push(l.len() as u8);
            rd.extend_from_slice(l.as_bytes());
        }
        rd.push(0);
        r.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        r.extend_from_slice(&rd);
        r
    }

    #[test]
    fn ptr_answers_are_parsed_and_looked_up() {
        let ip = Ipv4Addr::new(192, 0, 2, 7);
        assert_eq!(
            parse_ptr_answer(&ptr_reply(77, ip, "printer.lan")),
            Some((77, "printer.lan".into()))
        );
        let mut nx = ptr_query(5, ip);
        nx[2] = 0x81;
        nx[3] = 0x83; // NXDOMAIN
        assert_eq!(parse_ptr_answer(&nx), None);
        // a fake DNS server on localhost answers one of two queries; the other stays unnamed
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut b = [0u8; 512];
            for _ in 0..2 {
                let (n, from) = srv.recv_from(&mut b).unwrap();
                let id = u16::from_be_bytes([b[0], b[1]]);
                if b[..n].windows(4).any(|w| w == b"\x017\x012") {
                    srv.send_to(&ptr_reply(id, ip, "printer.lan"), from)
                        .unwrap();
                }
            }
        });
        let got = ptr_lookup(
            addr,
            &[ip, Ipv4Addr::new(192, 0, 2, 8)],
            Duration::from_millis(500),
        );
        t.join().unwrap();
        assert_eq!(got.get(&ip).map(String::as_str), Some("printer.lan"));
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn annotate_uses_the_snoop_then_stays_blank() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("names");
        std::fs::write(
            &f,
            "aa:bb:cc:dd:ee:01 192.0.2.10 100 phone-1\naa:bb:cc:dd:ee:02 - 100 -\n",
        )
        .unwrap();
        let mut c = vec![
            json!({"mac": "aa:bb:cc:dd:ee:01"}),
            json!({"mac": "aa:bb:cc:dd:ee:02"}),
            json!({"mac": "aa:bb:cc:dd:ee:03"}),
        ];
        // no DNS server in resolv.conf: snoop only
        annotate(&mut c, "dhcp", &f, "");
        assert_eq!(c[0]["hostname"], "phone-1");
        assert_eq!(c[0]["ipv4"], "192.0.2.10");
        assert!(c[1].get("hostname").is_none() && c[2].get("hostname").is_none());
        let mut off = vec![json!({"mac": "aa:bb:cc:dd:ee:01"})];
        annotate(&mut off, "off", &f, "");
        assert!(off[0].get("hostname").is_none());
        assert_eq!(
            first_nameserver("# x\nnameserver fd00::1\nnameserver 192.0.2.1\n"),
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
    }
}
