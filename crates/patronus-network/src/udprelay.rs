//! UDP broadcast relay (USE=udp-relay): carry IPv4 UDP broadcasts (NetBIOS
//! name service, SSDP/UPnP discovery over broadcast, game and printer
//! discovery, Wake-on-LAN magic packets, licence-server lookups) from one LAN
//! segment to others, like pfSense's udpbroadcastrelay package and the
//! OPNsense plugin of the same purpose.
//!
//! A broadcast never leaves its own segment. One *rule* (a table row) says:
//! "on interface X, UDP broadcasts to these ports are repeated on interfaces
//! Y, Z". Several rules can name the same interface with different ports and
//! targets, so every interface has its own multi-port relay list.
//!
//! There is no external daemon: the relay is `patronus udp-relay run`, run by
//! the supervisor (`patronus-daemon@udp-relay`, OpenRC and systemd) from a
//! generated JSON file, and its engine is in this module ([`engine`]). It
//! listens with an `AF_PACKET` socket per source interface (so it sees the
//! broadcast whether or not a local socket wants it, and never needs a
//! firewall hole: packet sockets read before netfilter) and sends with a raw
//! IPv4 socket bound to the target device. Per rule the relayed datagram
//! keeps its UDP source port and, if `spoof` is set (the default), its
//! original source address, so replies go straight back to the sender; with
//! it off the target interface's own address is the source. Relayed packets
//! carry a fixed IP identification marker and a TTL of 1: a relay never
//! relays a relayed packet (no loops, not even between two routers), and the
//! datagram is never routed on.
//!
//! The firewall needs nothing for reception; the relayed copy leaves through
//! the OUTPUT hook. A per-source packet rate limit (`rate_limit`, 0 = off)
//! bounds a broadcast storm.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const INSTANCE: &str = "udp-relay";

static FIELDS: [Field; 2] = [
    Field::new("enabled", "UDP broadcast relay", Kind::Bool).def("0"),
    Field::new("rate_limit", "Rate limit (packets/s per interface)", Kind::Int(0, 1_000_000))
        .def("200")
        .help("broadcasts above this rate on one source interface are dropped (a storm guard); 0 = no limit"),
];

static RULE_FIELDS: [Field; 6] = [
    Field::new("iface", "Listen on", Kind::Iface)
        .req()
        .help("device or @lan / @optN where the broadcast starts"),
    Field::new("ports", "UDP ports", Kind::Ports)
        .req()
        .help("destination ports, e.g. 137,138,1900 or 5000-5010 (not 67/68: use the DHCP relay)"),
    Field::new("targets", "Repeat on", Kind::Ifaces)
        .req()
        .help("one or more devices or @lan / @optN, comma separated"),
    Field::new("spoof", "Keep original source address", Kind::Bool)
        .def("1")
        .help("replies then go straight to the sender; off = use the target interface's own address"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "udp-relay",
    title: "UDP broadcast relay",
    blurb: "Repeat UDP broadcasts (NetBIOS 137/138, SSDP 1900, game and printer discovery, \
            Wake-on-LAN, ...) from one LAN segment to others. Each rule names the interface \
            the broadcast starts on, the UDP ports and the interfaces to repeat it on. \
            Discovery only: reaching the service still needs a firewall rule between the \
            segments.",
    applier: "udp-relay",
    fields: &FIELDS,
    colls: &[Coll {
        key: "rules",
        title: "Relay rules",
        table: "udp_relay_rules",
        fields: &RULE_FIELDS,
        unique: None,
    }],
    actions: &[],
};

pub struct UdpRelaySvc;

#[async_trait]
impl Svc for UdpRelaySvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

pub use crate::svc::{check_ports, fmt_ports, parse_ports, REFUSED_PORTS};

/// One resolved rule as the engine sees it (devices, not roles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleConf {
    pub id: i64,
    pub src: String,
    pub ports: Vec<(u16, u16)>,
    pub dst: Vec<String>,
    pub spoof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayConf {
    pub rate_limit: u64,
    pub rules: Vec<RuleConf>,
}

/// The relay's JSON file for the daemon.
pub fn render(c: &RelayConf) -> String {
    let mut s = serde_json::to_string_pretty(c).unwrap_or_default();
    s.push('\n');
    s
}

/// Rules resolved to devices (deduplicated targets, the source never a target).
pub async fn load(store: &ConfigStore) -> Result<RelayConf> {
    let s = Settings::load(store, &SPEC).await?;
    let mut conf = RelayConf {
        rate_limit: s.n("rate_limit").max(0) as u64,
        rules: Vec::new(),
    };
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        let id = r["id"].as_i64().unwrap_or(0);
        let ports = parse_ports(r["ports"].as_str().unwrap_or(""))
            .map_err(|e| invalid(format!("UDP relay rule {id}: {e}")))?;
        let mut dst: Vec<String> = Vec::new();
        for t in r["targets"].as_str().unwrap_or("").split(',') {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            for d in lan::resolve_iface(store, t).await? {
                if !dst.contains(&d) {
                    dst.push(d);
                }
            }
        }
        let srcs = lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await?;
        for src in srcs {
            let d: Vec<String> = dst.iter().filter(|x| **x != src).cloned().collect();
            if d.is_empty() {
                return Err(invalid(format!(
                    "UDP relay rule {id}: no target interface besides {src} (a broadcast is repeated on OTHER segments)"
                )));
            }
            conf.rules.push(RuleConf {
                id,
                src,
                ports: ports.clone(),
                dst: d,
                spoof: lan::flag(r["spoof"].as_str().unwrap_or("")),
            });
        }
    }
    Ok(conf)
}

#[derive(Clone)]
pub struct UdpRelayApplier {
    sup: Supervisor,
    bin: Option<std::path::PathBuf>,
}

impl Default for UdpRelayApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            bin: None,
        }
    }
}

impl UdpRelayApplier {
    pub fn with(sup: Supervisor, bin: Option<std::path::PathBuf>) -> Self {
        Self { sup, bin }
    }
    fn patronus(&self) -> Option<std::path::PathBuf> {
        self.bin.clone().or_else(|| which("patronus"))
    }
    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("udp-relay.json")
    }
    pub fn stats_path(&self) -> std::path::PathBuf {
        self.sup.paths.run_dir.join("udp-relay.stats")
    }
}

#[async_trait]
impl Applier for UdpRelayApplier {
    fn name(&self) -> &'static str {
        "udp-relay"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("UDP broadcast relay stopped");
            } else {
                rep.applied("UDP broadcast relay is off");
            }
            return Ok(rep);
        }
        let conf = load(store).await?;
        if conf.rules.is_empty() {
            return Err(invalid(
                "UDP broadcast relay: add at least one enabled rule (interface, ports, targets)",
            ));
        }
        let bin = self.patronus().ok_or_else(|| {
            Error::Service("the UDP broadcast relay needs the `patronus` binary on the PATH".into())
        })?;
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        let cp = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "udp-relay".into(),
                "run".into(),
                "--conf".into(),
                cp.to_string_lossy().into(),
                "--stats".into(),
                self.stats_path().to_string_lossy().into(),
            ],
            vec![(cp, render(&conf), 0o644)],
        )
        .await?;
        rep.applied(format!(
            "UDP broadcast relay {} ({} rule(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged,"
            },
            conf.rules.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# UDP broadcast relay off\n".into());
        }
        Ok(format!("## udp-relay.json\n{}", render(&load(store).await?)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let stats: Value = std::fs::read_to_string(self.stats_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null);
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": self.patronus().is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "rules": load(store).await.map(|c| c.rules.len()).unwrap_or(0),
            "stats": stats,
        }))
    }
}

/// The packet logic without sockets: parse a received IPv4 datagram and
/// build the copy for a target interface. Kept pure so it is unit-tested.
pub mod packet {
    use std::net::Ipv4Addr;

    /// IP identification of every relayed copy: the loop guard.
    pub const MARKER_ID: u16 = 0x7552;
    pub const PROTO_UDP: u8 = 17;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Udp<'a> {
        pub src: Ipv4Addr,
        pub dst: Ipv4Addr,
        pub id: u16,
        pub sport: u16,
        pub dport: u16,
        pub payload: &'a [u8],
    }

    /// Parse an IPv4 + UDP datagram (no link header). Fragments, other
    /// protocols and truncated packets give `None`.
    pub fn parse(p: &[u8]) -> Option<Udp<'_>> {
        if p.len() < 28 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0x0f) as usize * 4;
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        if ihl < 20 || total < ihl + 8 || total > p.len() || p[9] != PROTO_UDP {
            return None;
        }
        let frag = u16::from_be_bytes([p[6], p[7]]);
        if frag & 0x3fff != 0 {
            return None; // more-fragments or a non-zero offset
        }
        let u = &p[ihl..total];
        let ulen = u16::from_be_bytes([u[4], u[5]]) as usize;
        if ulen < 8 || ulen > u.len() {
            return None;
        }
        Some(Udp {
            src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
            dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
            id: u16::from_be_bytes([p[4], p[5]]),
            sport: u16::from_be_bytes([u[0], u[1]]),
            dport: u16::from_be_bytes([u[2], u[3]]),
            payload: &u[8..ulen],
        })
    }

    fn sum(mut acc: u32, data: &[u8]) -> u32 {
        let mut it = data.chunks_exact(2);
        for c in &mut it {
            acc += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [b] = it.remainder() {
            acc += (*b as u32) << 8;
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    /// IPv4 header checksum over a 20-byte header whose checksum field is 0.
    pub fn ip_checksum(h: &[u8]) -> u16 {
        fold(sum(0, h))
    }

    /// The datagram to send: marker id, TTL 1, `src:sport` -> `dst:dport`,
    /// the payload unchanged, valid IP and UDP checksums.
    pub fn build(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let ulen = 8 + payload.len();
        let total = 20 + ulen;
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0]);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&MARKER_ID.to_be_bytes());
        p.extend_from_slice(&[0, 0, 1, PROTO_UDP, 0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        let c = ip_checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&(ulen as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        // UDP checksum over the pseudo header + datagram
        let mut acc = 0u32;
        acc = sum(acc, &src.octets());
        acc = sum(acc, &dst.octets());
        acc += PROTO_UDP as u32 + ulen as u32;
        acc = sum(acc, &p[20..]);
        let mut c = fold(acc);
        if c == 0 {
            c = 0xffff;
        }
        p[26..28].copy_from_slice(&c.to_be_bytes());
        p
    }

    /// Does `ports` contain `p`?
    pub fn port_matches(ports: &[(u16, u16)], p: u16) -> bool {
        ports.iter().any(|&(a, b)| (a..=b).contains(&p))
    }
}

/// The runtime: what `patronus udp-relay run` executes.
pub mod engine {
    use super::packet::{self, MARKER_ID};
    use super::{RelayConf, RuleConf};
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Per-rule counters (id of the rule row + source device).
    #[derive(Default)]
    pub struct Counters {
        pub relayed: AtomicU64,
        pub sent_copies: AtomicU64,
        pub rate_dropped: AtomicU64,
        pub send_errors: AtomicU64,
    }

    /// IPv4 addresses of a device: (address, netmask).
    pub fn dev_addrs(dev: &str) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        let mut out = Vec::new();
        if let Ok(it) = nix::ifaddrs::getifaddrs() {
            for a in it {
                if a.interface_name != dev {
                    continue;
                }
                if let (Some(ad), Some(m)) = (a.address, a.netmask) {
                    if let (Some(ad), Some(m)) = (ad.as_sockaddr_in(), m.as_sockaddr_in()) {
                        out.push((Ipv4Addr::from(ad.ip()), Ipv4Addr::from(m.ip())));
                    }
                }
            }
        }
        out
    }

    pub fn directed_broadcast(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(addr) | !u32::from(mask))
    }

    fn all_local_addrs() -> Vec<Ipv4Addr> {
        let mut v = Vec::new();
        if let Ok(it) = nix::ifaddrs::getifaddrs() {
            for a in it {
                if let Some(ad) = a.address.as_ref().and_then(|a| a.as_sockaddr_in()) {
                    v.push(Ipv4Addr::from(ad.ip()));
                }
            }
        }
        v
    }

    fn ifindex(dev: &str) -> Option<i32> {
        let c = CString::new(dev).ok()?;
        let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (i != 0).then_some(i as i32)
    }

    fn packet_socket(idx: i32) -> std::io::Result<OwnedFd> {
        let proto = (libc::ETH_P_IP as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, proto) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = idx;
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
        Ok(fd)
    }

    fn raw_send_socket(dev: &str) -> std::io::Result<OwnedFd> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let one: libc::c_int = 1;
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                &one as *const _ as *const libc::c_void,
                4,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                dev.as_ptr() as *const libc::c_void,
                dev.len() as u32,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn send_to(fd: &OwnedFd, pkt: &[u8], dst: Ipv4Addr) -> std::io::Result<()> {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_addr.s_addr = u32::from(dst).to_be();
        let r = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Is `dst` a broadcast for the segment `addrs` belong to?
    pub fn is_broadcast_for(dst: Ipv4Addr, addrs: &[(Ipv4Addr, Ipv4Addr)]) -> bool {
        dst == Ipv4Addr::BROADCAST
            || addrs.iter().any(|&(a, m)| directed_broadcast(a, m) == dst)
    }

    struct Bucket {
        rate: u64,
        tokens: f64,
        last: Instant,
    }

    impl Bucket {
        fn allow(&mut self) -> bool {
            if self.rate == 0 {
                return true;
            }
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * self.rate as f64).min(self.rate as f64);
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                true
            } else {
                false
            }
        }
    }

    /// Relay loop for one source device (returns only when `stop` is set).
    fn run_source(
        src: String,
        rules: Vec<(RuleConf, Arc<Counters>)>,
        rate: u64,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut senders: BTreeMap<String, OwnedFd> = BTreeMap::new();
        let mut bucket = Bucket {
            rate,
            tokens: rate as f64,
            last: Instant::now(),
        };
        let mut buf = vec![0u8; 65536];
        while !stop.load(Ordering::Relaxed) {
            // (re)open the packet socket: the device may appear later or be recreated
            let Some(idx) = ifindex(&src) else {
                std::thread::sleep(Duration::from_secs(2));
                continue;
            };
            let fd = match packet_socket(idx) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("udp-relay: {src}: packet socket: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            let mut last_check = Instant::now();
            let mut locals = all_local_addrs();
            let mut src_addrs = dev_addrs(&src);
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let mut pfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let pr = unsafe { libc::poll(&mut pfd, 1, 1000) };
                if last_check.elapsed() > Duration::from_secs(2) {
                    last_check = Instant::now();
                    if ifindex(&src) != Some(idx) {
                        break; // device gone or recreated
                    }
                    locals = all_local_addrs();
                    src_addrs = dev_addrs(&src);
                }
                if pr <= 0 {
                    continue;
                }
                let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                let mut sl = std::mem::size_of::<libc::sockaddr_ll>() as u32;
                let n = unsafe {
                    libc::recvfrom(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                        &mut sll as *mut _ as *mut libc::sockaddr,
                        &mut sl,
                    )
                };
                if n < 0 {
                    break;
                }
                if sll.sll_pkttype != libc::PACKET_BROADCAST {
                    continue;
                }
                let Some(u) = packet::parse(&buf[..n as usize]) else {
                    continue;
                };
                if u.id == MARKER_ID || locals.contains(&u.src) {
                    continue; // already relayed, or our own
                }
                if !is_broadcast_for(u.dst, &src_addrs) {
                    continue;
                }
                let hits: Vec<&(RuleConf, Arc<Counters>)> = rules
                    .iter()
                    .filter(|(r, _)| packet::port_matches(&r.ports, u.dport))
                    .collect();
                if hits.is_empty() {
                    continue;
                }
                if !bucket.allow() {
                    for (_, c) in &hits {
                        c.rate_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
                let mut done: Vec<(&str, bool)> = Vec::new();
                for (r, c) in hits {
                    c.relayed.fetch_add(1, Ordering::Relaxed);
                    for d in &r.dst {
                        // one copy per target device per received packet
                        if done.iter().any(|(x, s)| *x == d && *s == r.spoof) {
                            continue;
                        }
                        done.push((d, r.spoof));
                        let addrs = dev_addrs(d);
                        let Some(&(own, mask)) = addrs.first() else {
                            c.send_errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let to = if u.dst == Ipv4Addr::BROADCAST {
                            Ipv4Addr::BROADCAST
                        } else {
                            directed_broadcast(own, mask)
                        };
                        let from = if r.spoof { u.src } else { own };
                        let pkt = packet::build(from, to, u.sport, u.dport, u.payload);
                        if !senders.contains_key(d) {
                            match raw_send_socket(d) {
                                Ok(s) => {
                                    senders.insert(d.clone(), s);
                                }
                                Err(e) => {
                                    eprintln!("udp-relay: {d}: raw socket: {e}");
                                    c.send_errors.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            }
                        }
                        match send_to(&senders[d], &pkt, to) {
                            Ok(()) => {
                                c.sent_copies.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("udp-relay: {src} -> {d}: {e}");
                                c.send_errors.fetch_add(1, Ordering::Relaxed);
                                senders.remove(d); // device may have been recreated
                            }
                        }
                    }
                }
            }
        }
    }

    /// Run until SIGTERM/SIGINT. Blocks.
    pub fn run(conf_path: &std::path::Path, stats_path: Option<&std::path::Path>) -> anyhow::Result<()> {
        let conf: RelayConf = serde_json::from_str(&std::fs::read_to_string(conf_path)?)?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        for sig in [signal_hook_flag::TERM, signal_hook_flag::INT] {
            signal_hook_flag::register(sig, stop.clone());
        }
        let mut by_src: BTreeMap<String, Vec<(RuleConf, Arc<Counters>)>> = BTreeMap::new();
        let mut all: Vec<(String, i64, Arc<Counters>)> = Vec::new();
        for r in &conf.rules {
            let c = Arc::new(Counters::default());
            all.push((r.src.clone(), r.id, c.clone()));
            by_src.entry(r.src.clone()).or_default().push((r.clone(), c));
        }
        let mut threads = Vec::new();
        for (src, rules) in by_src {
            let stop = stop.clone();
            let rate = conf.rate_limit;
            threads.push(std::thread::spawn(move || run_source(src, rules, rate, stop)));
        }
        eprintln!("udp-relay: {} rule(s) on {} interface(s)", conf.rules.len(), threads.len());
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        while !stop.load(Ordering::Relaxed) {
            if let Some(p) = stats_path {
                let rules: Vec<serde_json::Value> = all
                    .iter()
                    .map(|(s, id, c)| {
                        serde_json::json!({
                            "id": id, "iface": s,
                            "relayed": c.relayed.load(Ordering::Relaxed),
                            "copies": c.sent_copies.load(Ordering::Relaxed),
                            "rate_dropped": c.rate_dropped.load(Ordering::Relaxed),
                            "errors": c.send_errors.load(Ordering::Relaxed),
                        })
                    })
                    .collect();
                let body = serde_json::json!({"started": started, "rules": rules}).to_string();
                let _ = crate::supervise::write_atomic(p, &body, 0o644);
            }
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        for t in threads {
            let _ = t.join();
        }
        Ok(())
    }

    /// Minimal signal -> flag glue (no extra dependency).
    mod signal_hook_flag {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, OnceLock};
        pub const TERM: i32 = libc::SIGTERM;
        pub const INT: i32 = libc::SIGINT;
        static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
        extern "C" fn handler(_: i32) {
            if let Some(f) = FLAG.get() {
                f.store(true, Ordering::Relaxed);
            }
        }
        pub fn register(sig: i32, f: Arc<AtomicBool>) {
            let _ = FLAG.set(f);
            unsafe {
                libc::signal(sig, handler as extern "C" fn(i32) as libc::sighandler_t);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::packet::*;
    use super::*;
    use crate::supervise::{InitMode, NetPaths};
    use std::net::Ipv4Addr;

    #[test]
    fn ports_parse_normalise_and_refuse_dhcp() {
        assert_eq!(parse_ports("137, 138,5000-5010").unwrap(), vec![(137, 137), (138, 138), (5000, 5010)]);
        assert_eq!(check_ports("1900 , 137").unwrap(), "1900,137");
        assert_eq!(check_ports("5000-5010").unwrap(), "5000-5010");
        for bad in ["", "0", "70000", "a", "10-5", "137,", "67", "60-70", "68", "1;2", "-5"] {
            assert!(parse_ports(bad).is_err(), "{bad:?} must be refused");
        }
        let many = (1000..1040).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
        assert!(parse_ports(&many).is_err(), "more than 32 entries");
    }

    #[test]
    fn built_packet_round_trips_with_valid_checksums() {
        let src = Ipv4Addr::new(10, 1, 0, 5);
        let dst = Ipv4Addr::new(10, 2, 0, 255);
        let p = build(src, dst, 137, 138, b"hello broadcast");
        let u = parse(&p).unwrap();
        assert_eq!((u.src, u.dst, u.sport, u.dport), (src, dst, 137, 138));
        assert_eq!(u.payload, b"hello broadcast");
        assert_eq!(u.id, MARKER_ID, "relayed copies carry the loop marker");
        assert_eq!(p[8], 1, "ttl 1: never routed on");
        // a header with its checksum filled in sums to zero
        let mut h = p[..20].to_vec();
        let c = u16::from_be_bytes([h[10], h[11]]);
        h[10] = 0;
        h[11] = 0;
        assert_eq!(ip_checksum(&h), c);
        // known-good UDP checksum: recompute by an independent summation
        let mut acc: u32 = 0;
        let mut words = Vec::new();
        words.extend_from_slice(&src.octets());
        words.extend_from_slice(&dst.octets());
        words.extend_from_slice(&[0, 17]);
        words.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        words.extend_from_slice(&p[20..]);
        if words.len() % 2 == 1 {
            words.push(0);
        }
        for c in words.chunks(2) {
            acc += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        assert_eq!(acc, 0xffff, "UDP checksum verifies (odd payload length included)");
    }

    #[test]
    fn parse_rejects_fragments_other_protocols_and_garbage() {
        let mut p = build(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::BROADCAST, 1, 2, b"x");
        assert!(parse(&p).is_some());
        let mut f = p.clone();
        f[6] = 0x20; // more fragments
        assert!(parse(&f).is_none());
        let mut f = p.clone();
        f[7] = 1; // offset
        assert!(parse(&f).is_none());
        p[9] = 6;
        assert!(parse(&p).is_none(), "TCP");
        assert!(parse(&[0x45, 0, 0]).is_none());
        let mut t = build(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::BROADCAST, 1, 2, b"abcdef");
        t.truncate(30);
        assert!(parse(&t).is_none(), "truncated");
        assert!(port_matches(&[(137, 138), (5000, 5010)], 5005));
        assert!(!port_matches(&[(137, 138)], 139));
    }

    #[test]
    fn broadcast_detection_uses_the_segment_address() {
        use engine::{directed_broadcast, is_broadcast_for};
        let a = Ipv4Addr::new(192, 168, 7, 1);
        let m = Ipv4Addr::new(255, 255, 255, 0);
        assert_eq!(directed_broadcast(a, m), Ipv4Addr::new(192, 168, 7, 255));
        assert!(is_broadcast_for(Ipv4Addr::BROADCAST, &[(a, m)]));
        assert!(is_broadcast_for(Ipv4Addr::new(192, 168, 7, 255), &[(a, m)]));
        assert!(!is_broadcast_for(Ipv4Addr::new(192, 168, 8, 255), &[(a, m)]));
    }

    #[tokio::test]
    async fn rules_are_validated_resolved_and_rendered() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = UdpRelayApplier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            Some("/bin/true".into()),
        );
        assert!(a.apply(&s).await.is_ok(), "off: nothing to do");
        svc::put_settings(&s, &SPEC, &json!({"enabled": true})).await.unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least one"), "{e}");
        let c = &SPEC.colls[0];
        for bad in [
            json!({"iface": "eth1", "ports": "67", "targets": "eth2"}),
            json!({"iface": "eth1", "ports": "abc", "targets": "eth2"}),
            json!({"iface": "eth1", "ports": "137", "targets": "eth2;x"}),
            json!({"iface": "eth1", "ports": "137"}),
            json!({"iface": "lan;x", "ports": "137", "targets": "eth2"}),
        ] {
            assert!(svc::save_row(&s, c, None, &bad).await.is_err(), "{bad}");
        }
        // same source twice with different ports/targets is allowed (multi-port per interface)
        svc::save_row(&s, c, None, &json!({"iface": "eth1", "ports": "137,138", "targets": "eth2, eth3"}))
            .await
            .unwrap();
        svc::save_row(&s, c, None, &json!({"iface": "eth1", "ports": "1900", "targets": "eth2", "spoof": false}))
            .await
            .unwrap();
        // a rule whose only target is its own source is refused at apply
        svc::save_row(&s, c, None, &json!({"iface": "eth4", "ports": "9", "targets": "eth4"}))
            .await
            .unwrap();
        let e = a.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("other") || e.to_string().contains("besides"), "{e}");
        let rows = svc::raw_rows(&s, c).await.unwrap();
        svc::delete_row(&s, c, rows[2]["id"].as_i64().unwrap()).await.unwrap();
        let conf = load(&s).await.unwrap();
        assert_eq!(conf.rate_limit, 200);
        assert_eq!(conf.rules.len(), 2);
        assert_eq!(conf.rules[0].ports, vec![(137, 137), (138, 138)]);
        assert_eq!(conf.rules[0].dst, vec!["eth2", "eth3"]);
        assert!(conf.rules[0].spoof && !conf.rules[1].spoof);
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("\"src\": \"eth1\"") && r.contains("eth3"), "{r}");
        let back: RelayConf = serde_json::from_str(r.trim_start_matches("## udp-relay.json\n")).unwrap();
        assert_eq!(back, conf);
        // disabled rules do not reach the daemon
        svc::save_row(&s, c, Some(rows[1]["id"].as_i64().unwrap()), &json!({"enabled": false}))
            .await
            .unwrap();
        assert_eq!(load(&s).await.unwrap().rules.len(), 1);
    }
}
