//! Extra uplink probes (device segmentation, part d).
//!
//! The gateway monitor pings each gateway. An ISP that answers ping but has
//! broken DNS (or a dead HTTP path) looks healthy that way, so a gateway can
//! also carry TCP / HTTP / DNS probes (`ins_uplink_probes`). Each probe is
//! sent through the gateway's own device (`SO_BINDTODEVICE` / `curl
//! --interface`), like the ping is. A probe marked `critical` counts as a lost
//! sample for the gateway while it fails, which feeds the normal failover
//! (loss / down triggers of the gateway groups); other probes only mark the
//! uplink *degraded* in the history and raise an event.
//!
//! A probe fails only after [`FAIL_AFTER`] consecutive failures and recovers
//! on the first success, so one lost UDP packet does not flap a WAN.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Consecutive failures before a probe counts as failed.
pub const FAIL_AFTER: u32 = 2;
/// Seconds between two rounds of extra probes.
pub const EVERY_SECS: u64 = 5;
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Tcp,
    Http,
    Dns,
}

impl ProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeKind::Tcp => "tcp",
            ProbeKind::Http => "http",
            ProbeKind::Dns => "dns",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "tcp" => Ok(ProbeKind::Tcp),
            "http" => Ok(ProbeKind::Http),
            "dns" => Ok(ProbeKind::Dns),
            o => Err(invalid(format!("probe kind {o:?} (tcp, http or dns)"))),
        }
    }
}

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid request: {}", m.into()))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeSpec {
    pub id: i64,
    pub gateway: String,
    pub kind: ProbeKind,
    /// tcp: IP address; dns: resolver IP; http: URL.
    pub target: String,
    pub port: Option<u16>,
    /// dns: the name to resolve.
    pub name: String,
    pub critical: bool,
    pub enabled: bool,
}

/// Validate user input; returns the normalised `(target, port, name)`.
pub fn validate(
    kind: ProbeKind,
    target: &str,
    port: Option<u16>,
    name: &str,
) -> Result<(String, Option<u16>, String)> {
    let target = target.trim();
    let name = name.trim().trim_end_matches('.');
    match kind {
        ProbeKind::Tcp => {
            let ip: IpAddr = target
                .parse()
                .map_err(|_| invalid("tcp probe: the target must be an IP address"))?;
            match port {
                Some(p) if p > 0 => Ok((ip.to_string(), Some(p), String::new())),
                _ => Err(invalid("tcp probe: a port (1-65535) is required")),
            }
        }
        ProbeKind::Dns => {
            let ip: IpAddr = target
                .parse()
                .map_err(|_| invalid("dns probe: the target must be the resolver's IP address"))?;
            if !valid_hostname(name) {
                return Err(invalid(
                    "dns probe: give the name to resolve (e.g. example.com)",
                ));
            }
            Ok((
                ip.to_string(),
                Some(port.filter(|p| *p > 0).unwrap_or(53)),
                name.to_string(),
            ))
        }
        ProbeKind::Http => {
            let rest = target
                .strip_prefix("http://")
                .or_else(|| target.strip_prefix("https://"))
                .ok_or_else(|| {
                    invalid("http probe: the URL must start with http:// or https://")
                })?;
            if rest.is_empty()
                || target.len() > 512
                || !target.bytes().all(|b| {
                    b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'`' | b'{' | b'}')
                })
            {
                return Err(invalid(
                    "http probe: the URL has characters that are not allowed",
                ));
            }
            Ok((target.to_string(), None, String::new()))
        }
    }
}

fn valid_hostname(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
        })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: i64,
    pub kind: ProbeKind,
    pub target: String,
    pub critical: bool,
    /// After hysteresis: false once [`FAIL_AFTER`] probes in a row failed.
    pub ok: bool,
    /// Did the latest single probe succeed?
    pub last_ok: bool,
    pub rtt_ms: Option<f64>,
    pub fails: u32,
    pub error: Option<String>,
}

/// Runs one probe through `dev` (empty = no device binding).
#[async_trait::async_trait]
pub trait ExtraProber: Send + Sync {
    /// `Ok(rtt_ms)` on success, `Err(reason)` otherwise.
    async fn run(&self, dev: &str, spec: &ProbeSpec) -> std::result::Result<f64, String>;
}

/// The real probes (sockets bound to the gateway's device, curl for HTTP).
pub struct SysExtraProber;

#[async_trait::async_trait]
impl ExtraProber for SysExtraProber {
    async fn run(&self, dev: &str, spec: &ProbeSpec) -> std::result::Result<f64, String> {
        match spec.kind {
            ProbeKind::Tcp => {
                let ip: IpAddr = spec.target.parse().map_err(|_| "bad address".to_string())?;
                tcp_connect(dev, SocketAddr::new(ip, spec.port.unwrap_or(0))).await
            }
            ProbeKind::Dns => {
                let ip: IpAddr = spec.target.parse().map_err(|_| "bad address".to_string())?;
                dns_query(
                    dev,
                    SocketAddr::new(ip, spec.port.unwrap_or(53)),
                    &spec.name,
                )
                .await
            }
            ProbeKind::Http => http_head(dev, &spec.target).await,
        }
    }
}

pub async fn tcp_connect(dev: &str, addr: SocketAddr) -> std::result::Result<f64, String> {
    let sock = if addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()
    } else {
        tokio::net::TcpSocket::new_v4()
    }
    .map_err(|e| format!("socket: {e}"))?;
    if !dev.is_empty() {
        sock.bind_device(Some(dev.as_bytes()))
            .map_err(|e| format!("bind to {dev}: {e}"))?;
    }
    let t = Instant::now();
    match tokio::time::timeout(TIMEOUT, sock.connect(addr)).await {
        Ok(Ok(_)) => Ok(t.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) => Err(format!("connect {addr}: {e}")),
        Err(_) => Err(format!("connect {addr}: timed out")),
    }
}

/// A DNS "A" query for `name`.
pub fn dns_query_packet(id: u16, name: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(32 + name.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for l in name.trim_end_matches('.').split('.') {
        p.push(l.len() as u8);
        p.extend_from_slice(l.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 1, 0, 1]); // A IN
    p
}

/// Does `resp` answer the query `id` with NOERROR and at least one record?
pub fn dns_response_ok(resp: &[u8], id: u16) -> std::result::Result<(), String> {
    if resp.len() < 12 {
        return Err("short DNS reply".into());
    }
    if resp[..2] != id.to_be_bytes() {
        return Err("DNS reply for another query".into());
    }
    if resp[2] & 0x80 == 0 {
        return Err("not a DNS response".into());
    }
    match resp[3] & 0x0f {
        0 => {}
        2 => return Err("SERVFAIL".into()),
        3 => return Err("NXDOMAIN".into()),
        5 => return Err("REFUSED".into()),
        r => return Err(format!("DNS rcode {r}")),
    }
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    if an == 0 {
        return Err("DNS reply without an answer".into());
    }
    Ok(())
}

pub async fn dns_query(
    dev: &str,
    server: SocketAddr,
    name: &str,
) -> std::result::Result<f64, String> {
    use socket2::{Domain, Protocol, Socket, Type};
    let dom = if server.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let s =
        Socket::new(dom, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| format!("socket: {e}"))?;
    if !dev.is_empty() {
        s.bind_device(Some(dev.as_bytes()))
            .map_err(|e| format!("bind to {dev}: {e}"))?;
    }
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    let local: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    s.bind(&local.into()).map_err(|e| format!("bind: {e}"))?;
    let sock = tokio::net::UdpSocket::from_std(s.into()).map_err(|e| e.to_string())?;
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7)
        & 0xffff) as u16;
    let t = Instant::now();
    sock.send_to(&dns_query_packet(id, name), server)
        .await
        .map_err(|e| format!("send to {server}: {e}"))?;
    let mut buf = [0u8; 1500];
    let r = tokio::time::timeout(TIMEOUT, async {
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if from.ip() == server.ip() {
                return Ok::<usize, std::io::Error>(n);
            }
        }
    })
    .await;
    match r {
        Ok(Ok(n)) => dns_response_ok(&buf[..n], id).map(|_| t.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) => Err(format!("receive: {e}")),
        Err(_) => Err(format!("no DNS reply from {server}")),
    }
}

/// HEAD request with curl through the device; any answer below 500 proves
/// the path (a 404 from a CDN still crossed the uplink).
pub async fn http_head(dev: &str, url: &str) -> std::result::Result<f64, String> {
    if url.starts_with('-') {
        return Err("bad URL".into());
    }
    let mut c = tokio::process::Command::new("curl");
    c.args([
        "-sS",
        "-I",
        "-o",
        "/dev/null",
        "-m",
        "4",
        "--connect-timeout",
        "3",
    ])
    .args(["-w", "%{http_code} %{time_total}"]);
    if !dev.is_empty() {
        c.args(["--interface", dev]);
    }
    c.args(["--", url]).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(6), c.output())
        .await
        .map_err(|_| "curl timed out".to_string())?
        .map_err(|e| format!("cannot run curl: {e}"))?;
    parse_curl_result(
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    )
}

/// `"<code> <seconds>"` of curl's `-w` output.
pub fn parse_curl_result(
    success: bool,
    stdout: &str,
    stderr: &str,
) -> std::result::Result<f64, String> {
    if !success {
        let e = stderr.trim();
        return Err(if e.is_empty() {
            "curl failed".into()
        } else {
            e.lines().last().unwrap_or(e).to_string()
        });
    }
    let mut it = stdout.split_whitespace();
    let code: u32 = it
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or("no HTTP status")?;
    let secs: f64 = it.next().and_then(|c| c.parse().ok()).unwrap_or(0.0);
    if (100..500).contains(&code) {
        Ok(secs * 1000.0)
    } else {
        Err(format!("HTTP {code}"))
    }
}

/// Failure hysteresis: the result a probe shows after one more attempt.
pub fn next_result(
    spec: &ProbeSpec,
    prev: Option<&ProbeResult>,
    attempt: std::result::Result<f64, String>,
) -> ProbeResult {
    let fails_before = prev.map(|p| p.fails).unwrap_or(0);
    let (last_ok, rtt, err, fails) = match attempt {
        Ok(rtt) => (true, Some((rtt * 1000.0).round() / 1000.0), None, 0),
        Err(e) => (false, None, Some(e), fails_before.saturating_add(1)),
    };
    ProbeResult {
        id: spec.id,
        kind: spec.kind,
        target: match spec.kind {
            ProbeKind::Tcp => format!("{}:{}", spec.target, spec.port.unwrap_or(0)),
            ProbeKind::Dns => format!("{} @{}", spec.name, spec.target),
            ProbeKind::Http => spec.target.clone(),
        },
        critical: spec.critical,
        ok: fails < FAIL_AFTER,
        last_ok,
        rtt_ms: rtt,
        fails,
        error: err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: ProbeKind, critical: bool) -> ProbeSpec {
        ProbeSpec {
            id: 1,
            gateway: "WAN".into(),
            kind,
            target: "192.0.2.1".into(),
            port: Some(443),
            name: "example.com".into(),
            critical,
            enabled: true,
        }
    }

    #[test]
    fn validation_normalises_and_rejects() {
        assert_eq!(
            validate(ProbeKind::Tcp, " 1.1.1.1 ", Some(443), "").unwrap(),
            ("1.1.1.1".into(), Some(443), String::new())
        );
        assert!(validate(ProbeKind::Tcp, "one.one.one.one", Some(443), "").is_err());
        assert!(validate(ProbeKind::Tcp, "1.1.1.1", None, "").is_err());
        assert!(validate(ProbeKind::Tcp, "1.1.1.1", Some(0), "").is_err());
        assert_eq!(
            validate(ProbeKind::Dns, "9.9.9.9", None, "Example.com.").unwrap(),
            ("9.9.9.9".into(), Some(53), "Example.com".into())
        );
        assert!(validate(ProbeKind::Dns, "9.9.9.9", None, "").is_err());
        assert!(validate(ProbeKind::Dns, "9.9.9.9", None, "bad name.com").is_err());
        assert!(validate(ProbeKind::Dns, "9.9.9.9", None, "-x.com").is_err());
        assert!(validate(ProbeKind::Dns, "dns.google", None, "a.com").is_err());
        assert!(validate(ProbeKind::Http, "https://example.com/", None, "").is_ok());
        assert!(validate(ProbeKind::Http, "ftp://example.com/", None, "").is_err());
        assert!(validate(ProbeKind::Http, "http://", None, "").is_err());
        assert!(validate(ProbeKind::Http, "http://a b/", None, "").is_err());
        assert!(validate(ProbeKind::Http, "http://a/\"x", None, "").is_err());
        assert!(ProbeKind::parse("icmp").is_err());
        assert_eq!(ProbeKind::parse(" dns ").unwrap().as_str(), "dns");
    }

    #[test]
    fn dns_packet_layout_and_response_checks() {
        let q = dns_query_packet(0xabcd, "www.example.com.");
        assert_eq!(&q[..2], &[0xab, 0xcd]);
        assert_eq!(&q[4..6], &[0, 1], "one question");
        assert_eq!(q[12], 3);
        assert_eq!(&q[13..16], b"www");
        assert_eq!(&q[q.len() - 5..], &[0, 0, 1, 0, 1], "root label, A, IN");
        let mut r = q.clone();
        r[2] = 0x81; // QR + RD
        r[3] = 0x80; // RA, NOERROR
        r[7] = 1; // one answer
        assert!(dns_response_ok(&r, 0xabcd).is_ok());
        assert!(dns_response_ok(&r, 0xabce).unwrap_err().contains("another"));
        r[7] = 0;
        assert!(dns_response_ok(&r, 0xabcd)
            .unwrap_err()
            .contains("without an answer"));
        r[7] = 1;
        r[3] = 0x83;
        assert_eq!(dns_response_ok(&r, 0xabcd).unwrap_err(), "NXDOMAIN");
        r[3] = 0x82;
        assert_eq!(dns_response_ok(&r, 0xabcd).unwrap_err(), "SERVFAIL");
        r[3] = 0x85;
        assert_eq!(dns_response_ok(&r, 0xabcd).unwrap_err(), "REFUSED");
        r[3] = 0x84;
        assert!(dns_response_ok(&r, 0xabcd).unwrap_err().contains("rcode 4"));
        r[2] = 0x01;
        r[3] = 0x80;
        assert!(dns_response_ok(&r, 0xabcd)
            .unwrap_err()
            .contains("not a DNS response"));
        assert!(dns_response_ok(&[0; 5], 1).is_err());
    }

    #[test]
    fn curl_result_parsing() {
        assert!((parse_curl_result(true, "200 0.0421", "").unwrap() - 42.1).abs() < 1e-6);
        assert!(
            parse_curl_result(true, "404 0.01", "").is_ok(),
            "any answer below 500 proves the path"
        );
        assert_eq!(
            parse_curl_result(true, "503 0.01", "").unwrap_err(),
            "HTTP 503"
        );
        assert_eq!(
            parse_curl_result(true, "000 0.0", "").unwrap_err(),
            "HTTP 0"
        );
        assert_eq!(
            parse_curl_result(false, "", "curl: (7) Failed to connect\n").unwrap_err(),
            "curl: (7) Failed to connect"
        );
        assert_eq!(parse_curl_result(false, "", "").unwrap_err(), "curl failed");
        assert!(parse_curl_result(true, "", "").is_err());
    }

    #[test]
    fn hysteresis_fails_after_two_and_recovers_at_once() {
        let s = spec(ProbeKind::Tcp, true);
        let a = next_result(&s, None, Err("refused".into()));
        assert!(
            a.ok && !a.last_ok && a.fails == 1,
            "one failure is not enough"
        );
        let b = next_result(&s, Some(&a), Err("refused".into()));
        assert!(!b.ok && b.fails == 2 && b.error.as_deref() == Some("refused"));
        assert!(b.critical);
        let c = next_result(&s, Some(&b), Ok(12.3456));
        assert!(c.ok && c.last_ok && c.fails == 0 && c.rtt_ms == Some(12.346));
        assert_eq!(c.target, "192.0.2.1:443");
        assert_eq!(
            next_result(&spec(ProbeKind::Dns, false), None, Ok(1.0)).target,
            "example.com @192.0.2.1"
        );
        assert_eq!(
            next_result(&spec(ProbeKind::Http, false), None, Ok(1.0)).target,
            "192.0.2.1"
        );
    }

    #[tokio::test]
    async fn tcp_probe_against_a_local_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let rtt = tcp_connect("", addr).await.unwrap();
        assert!((0.0..3000.0).contains(&rtt));
        drop(l);
        assert!(tcp_connect("", addr).await.unwrap_err().contains("connect"));
    }

    #[tokio::test]
    async fn dns_probe_against_a_local_responder() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = srv.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for answer in [true, false] {
                let (n, from) = srv.recv_from(&mut buf).await.unwrap();
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                r[3] = if answer { 0x80 } else { 0x83 };
                r[7] = u8::from(answer);
                srv.send_to(&r, from).await.unwrap();
            }
        });
        assert!(dns_query("", addr, "example.com").await.is_ok());
        assert_eq!(
            dns_query("", addr, "nope.example.com").await.unwrap_err(),
            "NXDOMAIN"
        );
        h.await.unwrap();
        // nothing listens any more: the ICMP unreachable or the timeout both fail
        assert!(dns_query("", addr, "example.com").await.is_err());
    }

    #[tokio::test]
    async fn sys_prober_dispatches_by_kind() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let mut s = spec(ProbeKind::Tcp, false);
        s.target = "127.0.0.1".into();
        s.port = Some(port);
        assert!(SysExtraProber.run("", &s).await.is_ok());
        s.target = "nonsense".into();
        assert_eq!(SysExtraProber.run("", &s).await.unwrap_err(), "bad address");
        s.kind = ProbeKind::Dns;
        assert_eq!(SysExtraProber.run("", &s).await.unwrap_err(), "bad address");
        assert!(http_head("", "-oops").await.is_err());
    }
}
