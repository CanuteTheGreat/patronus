//! DHCPv6 relay agent (USE=dhcp6-relay, RFC 8415 section 19): carry the DHCPv6
//! messages of clients on a LAN segment to a DHCPv6 server on another network
//! and the answers back, like ISC `dhcrelay -6`, pfSense/OPNsense "DHCPv6
//! Relay" and OpenWrt's odhcpd relay mode.
//!
//! Clients multicast to `ff02::1:2` and never reach a server that is not on
//! their own link. One *rule* (a table row) says: "messages received on
//! interface X are relayed to server S" (S a unicast address anywhere the
//! router can route to, or the all-servers multicast group `ff02::1:2`, or
//! a link-local address, then on a named upstream interface). Several rules
//! may name the same interface (several servers get every message) and one
//! server may serve several interfaces.
//!
//! There is no external daemon: the relay is `patronus dhcp6-relay run`, run
//! by the supervisor (`patronus-daemon@dhcp6-relay`, OpenRC and systemd) from
//! a generated JSON file; the engine is in [`engine`]. Per client-facing
//! interface a UDP socket bound to that device listens on `[::]:547` and has
//! joined `ff02::1:2`; one unbound socket on `[::]:547` talks to the servers
//! (they answer to port 547 of the relay) and receives their Relay-reply.
//!
//! What the relay puts into the Relay-forward message (RFC 8415 19.1):
//! hop-count 0 (or the received hop-count + 1 when it relays another relay's
//! Relay-forward, which is dropped at the hop limit), the first global address
//! of the client-facing interface as link-address (`::` when it relays a
//! Relay-forward, or the interface has none), the client's address as
//! peer-address, an Interface-Id option (the device name; off in settings)
//! and the client's message as Relay Message option. A Relay-reply is
//! unwrapped and sent to the client (port 546), or, if the unwrapped message
//! is itself a Relay-reply, to the downstream relay (port 547) at its
//! peer-address. The interface of the answer comes from the Interface-Id, or
//! from the link-address.
//!
//! Firewall (`patronus-firewall/src/svc_rules.rs`): udp/547 is accepted on each
//! client-facing interface, and the Relay-reply of each server (udp 547 -> 547
//! from its address; from the upstream interface when the rule names one, and
//! from any host there for the all-servers group, since conntrack cannot match
//! the answer to a multicast). A per-interface rate limit bounds a storm.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::Ipv6Addr;

pub const INSTANCE: &str = "dhcp6-relay";

static FIELDS: [Field; 4] = [
    Field::new("enabled", "DHCPv6 relay", Kind::Bool).def("0"),
    Field::new("hop_limit", "Hop limit", Kind::Int(1, 32))
        .def("32")
        .help("a Relay-forward that already passed this many relays is dropped (loop guard, RFC 8415: 32)"),
    Field::new("interface_id", "Send the interface name (Interface-Id option)", Kind::Bool)
        .def("1")
        .help("lets the server and this relay tell the client-facing interface apart; off = the link-address alone decides"),
    Field::new("rate_limit", "Rate limit (messages/s per interface)", Kind::Int(0, 1_000_000))
        .def("500")
        .help("client messages above this rate on one interface are dropped (a storm guard); 0 = no limit"),
];

static RULE_FIELDS: [Field; 5] = [
    Field::new("iface", "Clients are on", Kind::Iface)
        .req()
        .help("device or @lan / @optN the clients are connected to"),
    Field::new("server", "DHCPv6 server", Kind::Ipv6)
        .req()
        .help("the server's unicast address, or ff02::1:2 (all servers on the upstream link); a link-local address needs the upstream interface"),
    Field::new("upstream", "Upstream interface", Kind::Iface)
        .help("device or @wan / @optN toward the server; needed for ff02::1:2 and link-local servers, optional otherwise"),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
    Field::new("description", "Description", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "dhcp6-relay",
    title: "DHCPv6 relay",
    blurb: "Relay DHCPv6 requests of the clients on a LAN segment to a DHCPv6 server on \
            another network (RFC 8415 relay agent) and the answers back. Each rule names \
            the interface the clients are on and the server's address. Do not run a DHCPv6 \
            server on the same interface: the relay owns UDP port 547 there.",
    applier: "dhcp6-relay",
    fields: &FIELDS,
    colls: &[Coll {
        key: "rules",
        title: "Relay rules",
        table: "dhcp6_relay_rules",
        fields: &RULE_FIELDS,
        unique: None,
    }],
    actions: &[],
};

pub struct Dhcp6RelaySvc;

#[async_trait]
impl Svc for Dhcp6RelaySvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// All DHCP servers and relay agents multicast group (RFC 8415 7.1).
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// One resolved rule as the engine sees it (devices, not roles).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleConf {
    pub id: i64,
    pub iface: String,
    pub server: Ipv6Addr,
    /// Device toward the server (required for multicast and link-local servers).
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayConf {
    pub hop_limit: u8,
    pub interface_id: bool,
    pub rate_limit: u64,
    pub rules: Vec<RuleConf>,
}

/// The relay's JSON file for the daemon.
pub fn render(c: &RelayConf) -> String {
    let mut s = serde_json::to_string_pretty(c).unwrap_or_default();
    s.push('\n');
    s
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// Is `server` something a relay may send to? Unspecified, loopback and
/// non-all-servers multicast are not.
pub fn check_server(server: &Ipv6Addr, upstream: bool) -> std::result::Result<(), String> {
    if server.is_unspecified() || server.is_loopback() {
        return Err("the server address cannot be :: or ::1".into());
    }
    if server.is_multicast() {
        if *server != ALL_SERVERS {
            return Err("the only multicast address a relay may use is ff02::1:2".into());
        }
        if !upstream {
            return Err("ff02::1:2 needs the upstream interface".into());
        }
    } else if is_link_local(server) && !upstream {
        return Err("a link-local server address needs the upstream interface".into());
    }
    Ok(())
}

/// Rules resolved to devices.
pub async fn load(store: &ConfigStore) -> Result<RelayConf> {
    let s = Settings::load(store, &SPEC).await?;
    let mut conf = RelayConf {
        hop_limit: s.n("hop_limit").clamp(1, 32) as u8,
        interface_id: s.b("interface_id"),
        rate_limit: s.n("rate_limit").max(0) as u64,
        rules: Vec::new(),
    };
    for r in svc::raw_rows(store, &SPEC.colls[0]).await? {
        if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
            continue;
        }
        let id = r["id"].as_i64().unwrap_or(0);
        let server: Ipv6Addr = r["server"]
            .as_str()
            .unwrap_or("")
            .parse()
            .map_err(|_| invalid(format!("DHCPv6 relay rule {id}: server is not an IPv6 address")))?;
        let up_spec = r["upstream"].as_str().unwrap_or("").trim();
        let ups: Vec<String> = if up_spec.is_empty() {
            Vec::new()
        } else {
            lan::resolve_iface(store, up_spec).await?
        };
        check_server(&server, !ups.is_empty())
            .map_err(|e| invalid(format!("DHCPv6 relay rule {id}: {e}")))?;
        let srcs = lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await?;
        for src in srcs {
            if ups.is_empty() {
                conf.rules.push(RuleConf {
                    id,
                    iface: src,
                    server,
                    upstream: None,
                });
                continue;
            }
            for up in &ups {
                if *up == src {
                    return Err(invalid(format!(
                        "DHCPv6 relay rule {id}: the upstream interface {up} is the clients' interface"
                    )));
                }
                conf.rules.push(RuleConf {
                    id,
                    iface: src.clone(),
                    server,
                    upstream: Some(up.clone()),
                });
            }
        }
    }
    // a client-facing interface cannot also be the way to a server: the
    // relay would see its own relayed copy as client traffic
    for a in &conf.rules {
        for b in &conf.rules {
            if b.upstream.as_deref() == Some(a.iface.as_str()) {
                return Err(invalid(format!(
                    "DHCPv6 relay: {} is both a client interface (rule {}) and an upstream interface (rule {})",
                    a.iface, a.id, b.id
                )));
            }
        }
    }
    Ok(conf)
}

#[derive(Clone)]
pub struct Dhcp6RelayApplier {
    sup: Supervisor,
    bin: Option<std::path::PathBuf>,
}

impl Default for Dhcp6RelayApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            bin: None,
        }
    }
}

impl Dhcp6RelayApplier {
    pub fn with(sup: Supervisor, bin: Option<std::path::PathBuf>) -> Self {
        Self { sup, bin }
    }
    fn patronus(&self) -> Option<std::path::PathBuf> {
        self.bin.clone().or_else(|| which("patronus"))
    }
    fn conf_path(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("dhcp6-relay.json")
    }
    pub fn stats_path(&self) -> std::path::PathBuf {
        self.sup.paths.run_dir.join("dhcp6-relay.stats")
    }
}

#[async_trait]
impl Applier for Dhcp6RelayApplier {
    fn name(&self) -> &'static str {
        "dhcp6-relay"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            if self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await? {
                rep.applied("DHCPv6 relay stopped");
            } else {
                rep.applied("DHCPv6 relay is off");
            }
            return Ok(rep);
        }
        let conf = load(store).await?;
        if conf.rules.is_empty() {
            return Err(invalid(
                "DHCPv6 relay: add at least one enabled rule (clients' interface and server)",
            ));
        }
        let bin = self.patronus().ok_or_else(|| {
            Error::Service("the DHCPv6 relay needs the `patronus` binary on the PATH".into())
        })?;
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        let cp = self.conf_path();
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "dhcp6-relay".into(),
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
            "DHCPv6 relay {} ({} rule(s))",
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
            return Ok("# DHCPv6 relay off\n".into());
        }
        Ok(format!(
            "## dhcp6-relay.json\n{}",
            render(&load(store).await?)
        ))
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

/// The message logic without sockets (RFC 8415 section 9 and 19), unit-tested.
pub mod packet {
    use std::net::Ipv6Addr;

    pub const RELAY_FORW: u8 = 12;
    pub const RELAY_REPL: u8 = 13;
    pub const OPT_RELAY_MSG: u16 = 9;
    pub const OPT_INTERFACE_ID: u16 = 18;

    /// Message types a client (or a downstream relay) sends toward a server:
    /// Solicit, Request, Confirm, Renew, Rebind, Release, Decline,
    /// Information-request, Relay-forward.
    pub fn is_for_server(t: u8) -> bool {
        matches!(t, 1 | 3 | 4 | 5 | 6 | 8 | 9 | 11 | RELAY_FORW)
    }

    /// Build a Relay-forward around `inner`.
    pub fn build_forw(
        hop: u8,
        link: Ipv6Addr,
        peer: Ipv6Addr,
        interface_id: Option<&[u8]>,
        inner: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(34 + inner.len() + 24);
        v.push(RELAY_FORW);
        v.push(hop);
        v.extend_from_slice(&link.octets());
        v.extend_from_slice(&peer.octets());
        if let Some(id) = interface_id {
            v.extend_from_slice(&OPT_INTERFACE_ID.to_be_bytes());
            v.extend_from_slice(&(id.len() as u16).to_be_bytes());
            v.extend_from_slice(id);
        }
        v.extend_from_slice(&OPT_RELAY_MSG.to_be_bytes());
        v.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        v.extend_from_slice(inner);
        v
    }

    /// A parsed Relay-reply.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Repl<'a> {
        pub hop: u8,
        pub link: Ipv6Addr,
        pub peer: Ipv6Addr,
        pub interface_id: Option<&'a [u8]>,
        pub msg: &'a [u8],
    }

    fn addr(b: &[u8]) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o.copy_from_slice(&b[..16]);
        Ipv6Addr::from(o)
    }

    pub fn parse_repl(b: &[u8]) -> Option<Repl<'_>> {
        if b.len() < 34 || b[0] != RELAY_REPL {
            return None;
        }
        let mut r = Repl {
            hop: b[1],
            link: addr(&b[2..18]),
            peer: addr(&b[18..34]),
            interface_id: None,
            msg: &[],
        };
        let mut have_msg = false;
        let mut i = 34;
        while i + 4 <= b.len() {
            let code = u16::from_be_bytes([b[i], b[i + 1]]);
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            i += 4;
            if i + len > b.len() {
                return None; // truncated option
            }
            let body = &b[i..i + len];
            match code {
                OPT_RELAY_MSG if !have_msg => {
                    r.msg = body;
                    have_msg = true;
                }
                OPT_INTERFACE_ID if r.interface_id.is_none() => r.interface_id = Some(body),
                _ => {}
            }
            i += len;
        }
        if i != b.len() || !have_msg || r.msg.is_empty() {
            return None;
        }
        Some(r)
    }

    /// What to relay for one received message: `Some((hop, link_is_zero))`, or
    /// `None` when the message must be dropped (not for a server, too short,
    /// hop limit reached).
    pub fn forward_plan(msg: &[u8], hop_limit: u8) -> Option<(u8, bool)> {
        let t = *msg.first()?;
        if !is_for_server(t) {
            return None;
        }
        if t == RELAY_FORW {
            if msg.len() < 34 {
                return None;
            }
            let hop = msg[1].checked_add(1)?;
            if hop > hop_limit {
                return None;
            }
            return Some((hop, true));
        }
        if msg.len() < 4 {
            return None; // type + transaction id
        }
        Some((0, false))
    }

    /// Does `addr` lie in the same /64 as `link`?
    pub fn same_64(a: &Ipv6Addr, b: &Ipv6Addr) -> bool {
        a.octets()[..8] == b.octets()[..8]
    }
}

pub mod engine {
    use super::packet;
    use super::{RelayConf, RuleConf};
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const PORT: u16 = 547;
    const CLIENT_PORT: u16 = 546;

    #[derive(Default)]
    pub struct Counters {
        pub forwarded: AtomicU64,
        pub replies: AtomicU64,
        pub dropped: AtomicU64,
        pub rate_dropped: AtomicU64,
        pub errors: AtomicU64,
    }

    pub fn ifindex(dev: &str) -> Option<u32> {
        let c = CString::new(dev).ok()?;
        let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (i != 0).then_some(i)
    }

    /// IPv6 addresses of a device.
    pub fn dev_addrs(dev: &str) -> Vec<Ipv6Addr> {
        let mut out = Vec::new();
        if let Ok(it) = nix::ifaddrs::getifaddrs() {
            for a in it {
                if a.interface_name != dev {
                    continue;
                }
                if let Some(sin6) = a.address.as_ref().and_then(|a| a.as_sockaddr_in6()) {
                    out.push(sin6.ip());
                }
            }
        }
        out
    }

    fn all_local_addrs() -> Vec<Ipv6Addr> {
        let mut v = Vec::new();
        if let Ok(it) = nix::ifaddrs::getifaddrs() {
            for a in it {
                if let Some(sin6) = a.address.as_ref().and_then(|a| a.as_sockaddr_in6()) {
                    v.push(sin6.ip());
                }
            }
        }
        v
    }

    /// link-address for a message received on `dev`: its first global address.
    pub fn link_address(dev: &str) -> Ipv6Addr {
        dev_addrs(dev)
            .into_iter()
            .find(|a| {
                !a.is_unspecified()
                    && !a.is_loopback()
                    && !a.is_multicast()
                    && (a.segments()[0] & 0xffc0) != 0xfe80
            })
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    fn base_socket() -> std::io::Result<socket2::Socket> {
        let s = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        s.set_only_v6(true)?;
        s.set_reuse_address(true)?;
        Ok(s)
    }

    /// Client-facing socket: bound to the device, in the all-servers group.
    fn client_socket(dev: &str, idx: u32) -> std::io::Result<UdpSocket> {
        let s = base_socket()?;
        s.bind_device(Some(dev.as_bytes()))?;
        s.set_multicast_loop_v6(false)?;
        s.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0)).into())?;
        s.join_multicast_v6(&super::ALL_SERVERS, idx)?;
        Ok(s.into())
    }

    /// Server-facing socket: not bound to a device, source port 547.
    fn server_socket() -> std::io::Result<UdpSocket> {
        let s = base_socket()?;
        s.set_multicast_loop_v6(false)?;
        s.set_multicast_hops_v6(1)?;
        s.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0)).into())?;
        Ok(s.into())
    }

    fn wait_readable(fd: i32, ms: i32) -> bool {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut p, 1, ms) > 0 }
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

    type Clients = Arc<Mutex<BTreeMap<String, Arc<UdpSocket>>>>;

    struct Shared {
        conf: RelayConf,
        server: UdpSocket,
        /// serialises set-multicast-if + send on the one server socket
        send_lock: Mutex<()>,
        clients: Clients,
        stop: Arc<AtomicBool>,
        counters: BTreeMap<(String, i64), Arc<Counters>>,
        unmatched: AtomicU64,
        /// peer-address -> client-facing device it was last relayed from: the
        /// way back for an answer that carries neither Interface-Id nor a link-address
        peers: Mutex<BTreeMap<Ipv6Addr, (String, Instant)>>,
    }

    fn remember_peer(sh: &Shared, peer: Ipv6Addr, dev: &str) {
        let mut m = sh.peers.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= 4096 {
            let old = Duration::from_secs(3600);
            m.retain(|_, (_, t)| t.elapsed() < old);
            if m.len() >= 4096 {
                m.clear();
            }
        }
        m.insert(peer, (dev.to_string(), Instant::now()));
    }

    fn is_ll(a: &Ipv6Addr) -> bool {
        (a.segments()[0] & 0xffc0) == 0xfe80
    }

    fn send_server(sh: &Shared, pkt: &[u8], r: &RuleConf) -> std::io::Result<()> {
        let need = r.server.is_multicast() || is_ll(&r.server);
        let scope = match &r.upstream {
            Some(up) if need => ifindex(up).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, format!("{up}: no such device"))
            })?,
            _ => 0,
        };
        let to = SocketAddrV6::new(r.server, PORT, 0, scope);
        let _g = sh.send_lock.lock().unwrap_or_else(|e| e.into_inner());
        if r.server.is_multicast() {
            let sock = socket2::SockRef::from(&sh.server);
            sock.set_multicast_if_v6(scope)?;
        }
        // a link-local server is reached through the scope id (the upstream
        // device); a global one by routing, `upstream` then only widens the firewall rule
        sh.server.send_to(pkt, to).map(|_| ())
    }

    /// Relay loop for one client-facing device.
    fn run_clients(dev: String, rules: Vec<RuleConf>, sh: Arc<Shared>) {
        let mut bucket = Bucket {
            rate: sh.conf.rate_limit,
            tokens: sh.conf.rate_limit as f64,
            last: Instant::now(),
        };
        let mut buf = vec![0u8; 65536];
        while !sh.stop.load(Ordering::Relaxed) {
            let Some(idx) = ifindex(&dev) else {
                std::thread::sleep(Duration::from_secs(2));
                continue;
            };
            let sock = match client_socket(&dev, idx) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!("dhcp6-relay: {dev}: socket: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            sh.clients
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(dev.clone(), sock.clone());
            let mut last_check = Instant::now();
            let mut locals = all_local_addrs();
            loop {
                if sh.stop.load(Ordering::Relaxed) {
                    return;
                }
                let ready = wait_readable(sock.as_raw_fd(), 1000);
                if last_check.elapsed() > Duration::from_secs(2) {
                    last_check = Instant::now();
                    if ifindex(&dev) != Some(idx) {
                        break; // device gone or recreated: new socket + group join
                    }
                    locals = all_local_addrs();
                }
                if !ready {
                    continue;
                }
                let (n, from) = match sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                };
                let SocketAddr::V6(from) = from else { continue };
                let msg = &buf[..n];
                let ctr: Vec<&Arc<Counters>> = rules
                    .iter()
                    .filter_map(|r| sh.counters.get(&(dev.clone(), r.id)))
                    .collect();
                if locals.contains(from.ip()) {
                    continue; // our own transmission
                }
                if !bucket.allow() {
                    for c in &ctr {
                        c.rate_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
                let Some((hop, link_zero)) = packet::forward_plan(msg, sh.conf.hop_limit) else {
                    for c in &ctr {
                        c.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                };
                remember_peer(&sh, *from.ip(), &dev);
                let link = if link_zero {
                    Ipv6Addr::UNSPECIFIED
                } else {
                    link_address(&dev)
                };
                let iid = sh.conf.interface_id.then(|| dev.as_bytes().to_vec());
                let pkt = packet::build_forw(hop, link, *from.ip(), iid.as_deref(), msg);
                for r in &rules {
                    let c = sh.counters.get(&(dev.clone(), r.id)).cloned().unwrap_or_default();
                    match send_server(&sh, &pkt, r) {
                        Ok(()) => {
                            c.forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("dhcp6-relay: {dev} -> {}: {e}", r.server);
                            c.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// Which client-facing device does a Relay-reply belong to?
    pub fn pick_device<'a>(
        devs: &'a [String],
        rep: &packet::Repl<'_>,
        addrs_of: &dyn Fn(&str) -> Vec<Ipv6Addr>,
        peer_dev: Option<&str>,
    ) -> Option<&'a String> {
        if let Some(id) = rep.interface_id {
            return devs.iter().find(|d| d.as_bytes() == id);
        }
        if rep.link.is_unspecified() {
            // a relayed Relay-forward has link-address ::; the peer is the downstream relay
            return peer_dev.and_then(|p| devs.iter().find(|d| d.as_str() == p));
        }
        devs.iter()
            .find(|d| addrs_of(d).iter().any(|a| packet::same_64(a, &rep.link)))
    }

    /// Server side: Relay-reply in, message to the client (or downstream relay) out.
    fn run_server(sh: Arc<Shared>) {
        let devs: Vec<String> = {
            let mut v: Vec<String> = sh.conf.rules.iter().map(|r| r.iface.clone()).collect();
            v.sort();
            v.dedup();
            v
        };
        let multicast_rule = sh.conf.rules.iter().any(|r| r.server.is_multicast());
        let servers: Vec<Ipv6Addr> = sh.conf.rules.iter().map(|r| r.server).collect();
        let mut buf = vec![0u8; 65536];
        while !sh.stop.load(Ordering::Relaxed) {
            if !wait_readable(sh.server.as_raw_fd(), 500) {
                continue;
            }
            let (n, from) = match sh.server.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let SocketAddr::V6(from) = from else { continue };
            // only a configured server may answer (any host on the upstream
            // link when a rule uses the all-servers group)
            if !multicast_rule && !servers.contains(from.ip()) {
                continue;
            }
            let Some(rep) = packet::parse_repl(&buf[..n]) else {
                continue;
            };
            let remembered = sh
                .peers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&rep.peer)
                .map(|(d, _)| d.clone());
            let Some(dev) = pick_device(&devs, &rep, &dev_addrs, remembered.as_deref()) else {
                sh.unmatched.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let sock = sh
                .clients
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(dev)
                .cloned();
            let Some(sock) = sock else { continue };
            let Some(idx) = ifindex(dev) else { continue };
            let port = if rep.msg[0] == packet::RELAY_REPL {
                PORT
            } else {
                CLIENT_PORT
            };
            let scope = if rep.peer.segments()[0] & 0xffc0 == 0xfe80 {
                idx
            } else {
                0
            };
            let to = SocketAddrV6::new(rep.peer, port, 0, scope);
            let ok = sock.send_to(rep.msg, to).is_ok();
            for r in sh.conf.rules.iter().filter(|r| &r.iface == dev) {
                if let Some(c) = sh.counters.get(&(dev.clone(), r.id)) {
                    if ok {
                        c.replies.fetch_add(1, Ordering::Relaxed);
                    } else {
                        c.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Run until SIGTERM/SIGINT. Blocks.
    pub fn run(
        conf_path: &std::path::Path,
        stats_path: Option<&std::path::Path>,
    ) -> anyhow::Result<()> {
        let conf: RelayConf = serde_json::from_str(&std::fs::read_to_string(conf_path)?)?;
        let stop = Arc::new(AtomicBool::new(false));
        for sig in [flag::TERM, flag::INT] {
            flag::register(sig, stop.clone());
        }
        let mut counters = BTreeMap::new();
        let mut by_dev: BTreeMap<String, Vec<RuleConf>> = BTreeMap::new();
        for r in &conf.rules {
            counters.insert((r.iface.clone(), r.id), Arc::new(Counters::default()));
            by_dev.entry(r.iface.clone()).or_default().push(r.clone());
        }
        let sh = Arc::new(Shared {
            server: server_socket()?,
            conf: conf.clone(),
            send_lock: Mutex::new(()),
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            stop: stop.clone(),
            counters,
            unmatched: AtomicU64::new(0),
            peers: Mutex::new(BTreeMap::new()),
        });
        let mut threads = Vec::new();
        {
            let sh = sh.clone();
            threads.push(std::thread::spawn(move || run_server(sh)));
        }
        let ndev = by_dev.len();
        for (dev, rules) in by_dev {
            let sh = sh.clone();
            threads.push(std::thread::spawn(move || run_clients(dev, rules, sh)));
        }
        eprintln!(
            "dhcp6-relay: {} rule(s) on {} interface(s)",
            conf.rules.len(),
            ndev
        );
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        while !stop.load(Ordering::Relaxed) {
            if let Some(p) = stats_path {
                let rules: Vec<serde_json::Value> = sh
                    .counters
                    .iter()
                    .map(|((iface, id), c)| {
                        serde_json::json!({
                            "id": id, "iface": iface,
                            "forwarded": c.forwarded.load(Ordering::Relaxed),
                            "replies": c.replies.load(Ordering::Relaxed),
                            "dropped": c.dropped.load(Ordering::Relaxed),
                            "rate_dropped": c.rate_dropped.load(Ordering::Relaxed),
                            "errors": c.errors.load(Ordering::Relaxed),
                        })
                    })
                    .collect();
                let body = serde_json::json!({
                    "started": started,
                    "unmatched_replies": sh.unmatched.load(Ordering::Relaxed),
                    "rules": rules,
                })
                .to_string();
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
    mod flag {
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

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn forward_wraps_the_client_message_per_rfc8415() {
        let solicit = [1u8, 0xab, 0xcd, 0xef, 0, 1, 0, 2, 0, 0];
        let p = build_forw(0, a("2001:db8:50::1"), a("fe80::1234"), Some(b"rtr-lan"), &solicit);
        assert_eq!(p[0], RELAY_FORW);
        assert_eq!(p[1], 0, "hop-count");
        assert_eq!(&p[2..18], &a("2001:db8:50::1").octets());
        assert_eq!(&p[18..34], &a("fe80::1234").octets());
        // Interface-Id first, then the Relay Message option holding the client's bytes
        assert_eq!(&p[34..38], &[0, 18, 0, 7]);
        assert_eq!(&p[38..45], b"rtr-lan");
        assert_eq!(&p[45..49], &[0, 9, 0, 10]);
        assert_eq!(&p[49..], &solicit);
        // without an interface id there is only the relay message
        let q = build_forw(3, Ipv6Addr::UNSPECIFIED, a("fe80::1"), None, &solicit);
        assert_eq!(q[1], 3);
        assert_eq!(&q[34..38], &[0, 9, 0, 10]);
    }

    #[test]
    fn reply_is_parsed_and_garbage_refused() {
        let adv = [2u8, 1, 2, 3, 0, 1, 0, 0];
        let mut r = vec![RELAY_REPL, 0];
        r.extend_from_slice(&a("2001:db8:50::1").octets());
        r.extend_from_slice(&a("fe80::77").octets());
        r.extend_from_slice(&[0, 18, 0, 3]);
        r.extend_from_slice(b"eth");
        r.extend_from_slice(&[0, 9, 0, adv.len() as u8]);
        r.extend_from_slice(&adv);
        let p = parse_repl(&r).unwrap();
        assert_eq!(p.peer, a("fe80::77"));
        assert_eq!(p.link, a("2001:db8:50::1"));
        assert_eq!(p.interface_id, Some(&b"eth"[..]));
        assert_eq!(p.msg, &adv);
        // not a Relay-reply, too short, truncated option, no relay message, trailing byte
        let mut not = r.clone();
        not[0] = RELAY_FORW;
        assert!(parse_repl(&not).is_none());
        assert!(parse_repl(&r[..20]).is_none());
        assert!(parse_repl(&r[..r.len() - 1]).is_none());
        let mut nomsg = vec![RELAY_REPL, 0];
        nomsg.extend_from_slice(&[0u8; 32]);
        nomsg.extend_from_slice(&[0, 18, 0, 1, b'x']);
        assert!(parse_repl(&nomsg).is_none());
        let mut tail = r.clone();
        tail.push(0);
        assert!(parse_repl(&tail).is_none(), "3 trailing bytes cannot be an option");
    }

    #[test]
    fn forward_plan_hop_count_and_message_types() {
        // client messages start at hop 0 with the interface link-address
        assert_eq!(forward_plan(&[1, 0, 0, 1, 0, 1, 0, 0], 32), Some((0, false)));
        for t in [1u8, 3, 4, 5, 6, 8, 9, 11] {
            assert!(forward_plan(&[t, 0, 0, 1], 32).is_some(), "type {t}");
        }
        // server messages never come from clients
        for t in [2u8, 7, 10, 13, 0, 14, 255] {
            assert!(forward_plan(&[t, 0, 0, 1, 0, 0], 32).is_none(), "type {t}");
        }
        assert!(forward_plan(&[1, 0], 32).is_none(), "too short");
        assert!(forward_plan(&[], 32).is_none());
        // another relay's Relay-forward: hop + 1, link-address zero
        let mut f = vec![RELAY_FORW, 4];
        f.extend_from_slice(&[0u8; 32]);
        assert_eq!(forward_plan(&f, 32), Some((5, true)));
        f[1] = 31;
        assert_eq!(forward_plan(&f, 32), Some((32, true)));
        f[1] = 32;
        assert_eq!(forward_plan(&f, 32), None, "hop limit reached: dropped");
        f[1] = 255;
        assert_eq!(forward_plan(&f, 32), None, "overflow is a drop, not a wrap");
        f[1] = 2;
        assert_eq!(forward_plan(&f, 3), Some((3, true)));
        assert_eq!(forward_plan(&f, 2), None);
        assert!(forward_plan(&[RELAY_FORW, 0, 0], 32).is_none(), "truncated relay-forward");
    }

    #[test]
    fn answer_goes_to_the_interface_named_by_interface_id_or_link_address() {
        let devs = vec!["rtr-lan".to_string(), "rtr-guest".to_string()];
        let addrs = |d: &str| -> Vec<Ipv6Addr> {
            match d {
                "rtr-lan" => vec![a("fe80::1"), a("2001:db8:50::1")],
                _ => vec![a("2001:db8:70::1")],
            }
        };
        let mk = |link: &str, id: Option<&'static [u8]>| Repl {
            hop: 0,
            link: a(link),
            peer: a("fe80::2"),
            interface_id: id,
            msg: &[2, 0, 0, 0],
        };
        let pick = |r: &Repl<'_>| engine::pick_device(&devs, r, &addrs, None).cloned();
        assert_eq!(pick(&mk("::", Some(b"rtr-guest"))).as_deref(), Some("rtr-guest"));
        // the Interface-Id wins over a (wrong) link-address
        assert_eq!(
            pick(&mk("2001:db8:50::1", Some(b"rtr-guest"))).as_deref(),
            Some("rtr-guest")
        );
        assert_eq!(pick(&mk("2001:db8:50::1", Some(b"nope"))), None);
        assert_eq!(pick(&mk("2001:db8:70::1", None)).as_deref(), Some("rtr-guest"));
        assert_eq!(pick(&mk("2001:db8:50::ffff", None)).as_deref(), Some("rtr-lan"));
        assert_eq!(pick(&mk("::", None)), None);
        // a relayed Relay-forward has link-address :: and no Interface-Id: the
        // device the downstream relay was heard on is the way back
        let r = mk("::", None);
        assert_eq!(
            engine::pick_device(&devs, &r, &addrs, Some("rtr-guest")).map(String::as_str),
            Some("rtr-guest")
        );
        assert_eq!(engine::pick_device(&devs, &r, &addrs, Some("gone")), None);
        assert_eq!(pick(&mk("2001:db8:99::1", None)), None);
    }

    #[test]
    fn server_addresses_are_checked() {
        assert!(check_server(&a("2001:db8::53"), false).is_ok());
        assert!(check_server(&a("fd00::53"), true).is_ok());
        assert!(check_server(&a("fe80::53"), true).is_ok());
        assert!(check_server(&a("fe80::53"), false).is_err());
        assert!(check_server(&ALL_SERVERS, true).is_ok());
        assert!(check_server(&ALL_SERVERS, false).is_err());
        assert!(check_server(&a("ff02::1"), true).is_err());
        assert!(check_server(&a("ff05::1:3"), true).is_err());
        assert!(check_server(&a("::"), true).is_err());
        assert!(check_server(&a("::1"), true).is_err());
    }

    #[tokio::test]
    async fn rules_are_validated_resolved_and_rendered() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let ap = Dhcp6RelayApplier::with(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            Some("/bin/true".into()),
        );
        assert!(ap.apply(&s).await.is_ok(), "off: nothing to do");
        svc::put_settings(&s, &SPEC, &json!({"enabled": true}))
            .await
            .unwrap();
        let e = ap.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("at least one"), "{e}");
        let c = &SPEC.colls[0];
        for bad in [
            json!({"iface": "eth1", "server": "not-an-address"}),
            json!({"iface": "eth1", "server": "192.0.2.1"}),
            json!({"iface": "eth1"}),
            json!({"server": "2001:db8::1"}),
            json!({"iface": "lan;x", "server": "2001:db8::1"}),
            json!({"iface": "eth1", "server": "2001:db8::1", "upstream": "x;y"}),
        ] {
            assert!(svc::save_row(&s, c, None, &bad).await.is_err(), "{bad}");
        }
        // the checks that need the pair of fields happen when the config is built
        svc::save_row(&s, c, None, &json!({"iface": "eth1", "server": "ff02::1:2"}))
            .await
            .unwrap();
        let e = ap.apply(&s).await.unwrap_err();
        assert!(e.to_string().contains("upstream"), "{e}");
        let rows = svc::raw_rows(&s, c).await.unwrap();
        svc::delete_row(&s, c, rows[0]["id"].as_i64().unwrap())
            .await
            .unwrap();
        svc::save_row(&s, c, None, &json!({"iface": "eth1", "server": "2001:db8:1::53"}))
            .await
            .unwrap();
        svc::save_row(
            &s,
            c,
            None,
            &json!({"iface": "eth1", "server": "FF02::1:2", "upstream": "eth0"}),
        )
        .await
        .unwrap();
        svc::save_row(
            &s,
            c,
            None,
            &json!({"iface": "eth2", "server": "2001:db8:1::53", "description": "guests"}),
        )
        .await
        .unwrap();
        let conf = load(&s).await.unwrap();
        assert_eq!((conf.hop_limit, conf.interface_id, conf.rate_limit), (32, true, 500));
        assert_eq!(conf.rules.len(), 3);
        assert_eq!(conf.rules[0].upstream, None);
        assert_eq!(conf.rules[1].server, ALL_SERVERS);
        assert_eq!(conf.rules[1].upstream.as_deref(), Some("eth0"));
        let r = ap.render(&s).await.unwrap();
        assert!(r.contains("ff02::1:2") && r.contains("eth2"), "{r}");
        let back: RelayConf =
            serde_json::from_str(r.trim_start_matches("## dhcp6-relay.json\n")).unwrap();
        assert_eq!(back, conf);
        // a client interface that is also an upstream interface would see its own copies
        svc::save_row(
            &s,
            c,
            None,
            &json!({"iface": "eth0", "server": "2001:db8:1::54", "upstream": "eth2"}),
        )
        .await
        .unwrap();
        let e = load(&s).await.unwrap_err();
        assert!(e.to_string().contains("both a client interface"), "{e}");
        // upstream == clients' interface
        let rows = svc::raw_rows(&s, c).await.unwrap();
        svc::delete_row(&s, c, rows[3]["id"].as_i64().unwrap())
            .await
            .unwrap();
        svc::save_row(
            &s,
            c,
            None,
            &json!({"iface": "eth5", "server": "fe80::1", "upstream": "eth5"}),
        )
        .await
        .unwrap();
        let e = load(&s).await.unwrap_err();
        assert!(e.to_string().contains("clients' interface"), "{e}");
    }

    #[tokio::test]
    async fn settings_are_bounded_and_disabled_rules_do_not_reach_the_daemon() {
        let s = crate::lan::testutil::store().await;
        for bad in [
            json!({"hop_limit": 0}),
            json!({"hop_limit": 33}),
            json!({"rate_limit": -1}),
            json!({"interface_id": "maybe"}),
        ] {
            assert!(svc::put_settings(&s, &SPEC, &bad).await.is_err(), "{bad}");
        }
        svc::put_settings(&s, &SPEC, &json!({"hop_limit": 8, "interface_id": false}))
            .await
            .unwrap();
        let c = &SPEC.colls[0];
        let id = svc::save_row(&s, c, None, &json!({"iface": "eth1", "server": "2001:db8::1"}))
            .await
            .unwrap();
        let conf = load(&s).await.unwrap();
        assert_eq!((conf.hop_limit, conf.interface_id), (8, false));
        assert_eq!(conf.rules.len(), 1);
        svc::save_row(&s, c, Some(id), &json!({"enabled": false}))
            .await
            .unwrap();
        assert!(load(&s).await.unwrap().rules.is_empty());
    }
}
