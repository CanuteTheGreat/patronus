//! RADIUS client for the captive portal: PAP authentication (RFC 2865, with a
//! Message-Authenticator, RFC 3579 / the 2024 BlastRADIUS hardening) and
//! accounting start / interim / stop (RFC 2866).
//!
//! Every reply is checked against its Response Authenticator, so a forged
//! Access-Accept from someone without the shared secret is refused.

use md5::{Digest, Md5};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

pub const ACCESS_REQUEST: u8 = 1;
pub const ACCESS_ACCEPT: u8 = 2;
pub const ACCESS_REJECT: u8 = 3;
pub const ACCOUNTING_REQUEST: u8 = 4;
pub const ACCOUNTING_RESPONSE: u8 = 5;

const USER_NAME: u8 = 1;
const USER_PASSWORD: u8 = 2;
const NAS_IP_ADDRESS: u8 = 4;
const SERVICE_TYPE: u8 = 6;
const FRAMED_IP_ADDRESS: u8 = 8;
const REPLY_MESSAGE: u8 = 18;
const VENDOR_SPECIFIC: u8 = 26;
const SESSION_TIMEOUT: u8 = 27;
const IDLE_TIMEOUT: u8 = 28;
const CALLED_STATION_ID: u8 = 30;
const CALLING_STATION_ID: u8 = 31;
const NAS_IDENTIFIER: u8 = 32;
const ACCT_STATUS_TYPE: u8 = 40;
const ACCT_SESSION_ID: u8 = 44;
const ACCT_SESSION_TIME: u8 = 46;
const ACCT_TERMINATE_CAUSE: u8 = 49;
const EVENT_TIMESTAMP: u8 = 55;
const NAS_PORT_TYPE: u8 = 61;
const MESSAGE_AUTHENTICATOR: u8 = 80;
/// WISPr vendor id and its bandwidth attributes (bit/s).
const WISPR: u32 = 14122;
const WISPR_BW_UP: u8 = 7;
const WISPR_BW_DOWN: u8 = 8;

pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-MD5 (RFC 2104) for the Message-Authenticator.
pub fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..16].copy_from_slice(&md5(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = md5(&[&ipad, msg]);
    md5(&[&opad, &inner])
}

/// RFC 2865 5.2: c(i) = p(i) xor MD5(secret + c(i-1)), c(0) = authenticator.
pub fn hide_password(password: &[u8], secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    let mut p = password.to_vec();
    let pad = (16 - p.len() % 16) % 16;
    p.resize(p.len() + if p.is_empty() { 16 } else { pad }, 0);
    let mut out = Vec::with_capacity(p.len());
    let mut prev = authenticator.to_vec();
    for blk in p.chunks(16) {
        let key = md5(&[secret, &prev]);
        let c: Vec<u8> = blk.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
        out.extend_from_slice(&c);
        prev = c;
    }
    out
}

fn attr(out: &mut Vec<u8>, t: u8, v: &[u8]) {
    let v = &v[..v.len().min(253)];
    out.push(t);
    out.push((v.len() + 2) as u8);
    out.extend_from_slice(v);
}

fn attr_u32(out: &mut Vec<u8>, t: u8, v: u32) {
    attr(out, t, &v.to_be_bytes());
}

fn random16() -> [u8; 16] {
    use std::io::Read;
    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        // never reached on Linux; still unpredictable enough for an id
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = md5(&[&t.to_le_bytes()]);
    }
    b
}

/// `aa:bb:cc:dd:ee:ff` -> `AA-BB-CC-DD-EE-FF` (RFC 3580 Calling-Station-Id).
pub fn station_id(mac: &str) -> String {
    mac.to_ascii_uppercase().replace(':', "-")
}

#[derive(Debug, Clone)]
pub struct Server {
    pub addr: SocketAddr,
    pub secret: String,
    pub nas_id: String,
    pub timeout: Duration,
}

/// What an Access-Accept says about the session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grant {
    pub session_timeout: Option<u32>,
    pub idle_timeout: Option<u32>,
    pub up_bps: Option<u32>,
    pub down_bps: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Accept(Grant),
    Reject(String),
}

/// Who is logging in (for the request attributes).
#[derive(Debug, Clone)]
pub struct Client {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub nas_ip: Ipv4Addr,
}

fn finish(code: u8, id: u8, auth: &[u8; 16], attrs: &[u8]) -> Vec<u8> {
    let len = (20 + attrs.len()) as u16;
    let mut p = vec![code, id];
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(auth);
    p.extend_from_slice(attrs);
    p
}

/// Build an Access-Request (PAP) with a Message-Authenticator.
pub fn access_request(
    id: u8,
    auth: &[u8; 16],
    srv: &Server,
    user: &str,
    password: &str,
    c: &Client,
) -> Vec<u8> {
    let mut a = Vec::new();
    // Message-Authenticator first (BlastRADIUS: servers may require it, placed first)
    attr(&mut a, MESSAGE_AUTHENTICATOR, &[0u8; 16]);
    attr(&mut a, USER_NAME, user.as_bytes());
    attr(
        &mut a,
        USER_PASSWORD,
        &hide_password(password.as_bytes(), srv.secret.as_bytes(), auth),
    );
    attr_u32(&mut a, SERVICE_TYPE, 1); // Login
    attr(&mut a, NAS_IDENTIFIER, srv.nas_id.as_bytes());
    attr(&mut a, NAS_IP_ADDRESS, &c.nas_ip.octets());
    attr(&mut a, FRAMED_IP_ADDRESS, &c.ip.octets());
    attr(&mut a, CALLING_STATION_ID, station_id(&c.mac).as_bytes());
    attr(&mut a, CALLED_STATION_ID, srv.nas_id.as_bytes());
    attr_u32(&mut a, NAS_PORT_TYPE, 19); // Wireless-802.11 (also used by wired hotspots)
    let mut p = finish(ACCESS_REQUEST, id, auth, &a);
    let mac = hmac_md5(srv.secret.as_bytes(), &p);
    p[22..38].copy_from_slice(&mac);
    p
}

/// Check a reply to the request with `id` / `req_auth`; returns (code, attributes).
pub fn check_reply(p: &[u8], id: u8, req_auth: &[u8; 16], secret: &str) -> Option<(u8, Vec<u8>)> {
    if p.len() < 20 || p[1] != id {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if len < 20 || len > p.len() {
        return None;
    }
    let p = &p[..len];
    let want = md5(&[&p[..4], req_auth, &p[20..], secret.as_bytes()]);
    if want[..] != p[4..20] {
        return None;
    }
    Some((p[0], p[20..].to_vec()))
}

fn parse_attrs(a: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= a.len() {
        let (t, l) = (a[i], usize::from(a[i + 1]));
        if l < 2 || i + l > a.len() {
            break;
        }
        out.push((t, a[i + 2..i + l].to_vec()));
        i += l;
    }
    out
}

fn u32_of(v: &[u8]) -> Option<u32> {
    (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

pub fn grant_of(attrs: &[u8]) -> Grant {
    let mut g = Grant::default();
    for (t, v) in parse_attrs(attrs) {
        match t {
            SESSION_TIMEOUT => g.session_timeout = u32_of(&v),
            IDLE_TIMEOUT => g.idle_timeout = u32_of(&v),
            VENDOR_SPECIFIC if v.len() >= 6 => {
                let vendor = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                if vendor != WISPR {
                    continue;
                }
                for (vt, vv) in parse_attrs(&v[4..]) {
                    match vt {
                        WISPR_BW_UP => g.up_bps = u32_of(&vv),
                        WISPR_BW_DOWN => g.down_bps = u32_of(&vv),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    g
}

fn reply_message(attrs: &[u8]) -> String {
    parse_attrs(attrs)
        .into_iter()
        .find(|(t, _)| *t == REPLY_MESSAGE)
        .map(|(_, v)| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default()
}

/// Send `pkt` and wait for a valid reply (3 tries).
async fn exchange(
    srv: &Server,
    pkt: &[u8],
    id: u8,
    req_auth: &[u8; 16],
) -> Result<(u8, Vec<u8>), String> {
    let bind: SocketAddr = if srv.addr.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    } else {
        "[::]:0"
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("RADIUS socket: {e}"))?;
    sock.connect(srv.addr)
        .await
        .map_err(|e| format!("RADIUS {}: {e}", srv.addr))?;
    let mut buf = vec![0u8; 4096];
    for _ in 0..3 {
        sock.send(pkt)
            .await
            .map_err(|e| format!("RADIUS send to {}: {e}", srv.addr))?;
        let deadline = tokio::time::Instant::now() + srv.timeout;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    if let Some(r) = check_reply(&buf[..n], id, req_auth, &srv.secret) {
                        return Ok(r);
                    }
                    // a stray or forged answer: keep waiting for the real one
                }
                Ok(Err(e)) => return Err(format!("RADIUS {}: {e}", srv.addr)),
                Err(_) => break,
            }
        }
    }
    Err(format!("RADIUS server {} did not answer", srv.addr))
}

/// PAP login.
pub async fn authenticate(
    srv: &Server,
    user: &str,
    password: &str,
    c: &Client,
) -> Result<AuthOutcome, String> {
    let auth = random16();
    let id = auth[0];
    let pkt = access_request(id, &auth, srv, user, password, c);
    let (code, attrs) = exchange(srv, &pkt, id, &auth).await?;
    match code {
        ACCESS_ACCEPT => Ok(AuthOutcome::Accept(grant_of(&attrs))),
        ACCESS_REJECT => Ok(AuthOutcome::Reject(reply_message(&attrs))),
        other => Err(format!("RADIUS server answered with code {other}")),
    }
}

/// Accounting record kinds (Acct-Status-Type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acct {
    Start,
    Stop,
    Interim,
}

/// RFC 2866 Acct-Terminate-Cause values the portal uses.
pub mod cause {
    pub const USER_REQUEST: u32 = 1;
    pub const IDLE_TIMEOUT: u32 = 4;
    pub const SESSION_TIMEOUT: u32 = 5;
    pub const ADMIN_RESET: u32 = 6;
    pub const NAS_REQUEST: u32 = 10;
}

#[derive(Debug, Clone)]
pub struct AcctRecord {
    pub kind: Acct,
    pub session_id: String,
    pub user: String,
    pub client: Client,
    pub session_time: u32,
    pub terminate_cause: Option<u32>,
    pub timestamp: u32,
}

pub fn accounting_request(id: u8, srv: &Server, r: &AcctRecord) -> (Vec<u8>, [u8; 16]) {
    let mut a = Vec::new();
    attr_u32(
        &mut a,
        ACCT_STATUS_TYPE,
        match r.kind {
            Acct::Start => 1,
            Acct::Stop => 2,
            Acct::Interim => 3,
        },
    );
    attr(&mut a, ACCT_SESSION_ID, r.session_id.as_bytes());
    if !r.user.is_empty() {
        attr(&mut a, USER_NAME, r.user.as_bytes());
    }
    attr(&mut a, NAS_IDENTIFIER, srv.nas_id.as_bytes());
    attr(&mut a, NAS_IP_ADDRESS, &r.client.nas_ip.octets());
    attr(&mut a, FRAMED_IP_ADDRESS, &r.client.ip.octets());
    attr(
        &mut a,
        CALLING_STATION_ID,
        station_id(&r.client.mac).as_bytes(),
    );
    attr_u32(&mut a, NAS_PORT_TYPE, 19);
    attr_u32(&mut a, EVENT_TIMESTAMP, r.timestamp);
    if r.kind != Acct::Start {
        attr_u32(&mut a, ACCT_SESSION_TIME, r.session_time);
    }
    if let (Acct::Stop, Some(c)) = (r.kind, r.terminate_cause) {
        attr_u32(&mut a, ACCT_TERMINATE_CAUSE, c);
    }
    // Request Authenticator = MD5(Code+ID+Length+16 zero octets+Attributes+Secret)
    let unsigned = finish(ACCOUNTING_REQUEST, id, &[0u8; 16], &a);
    let ra = md5(&[&unsigned, srv.secret.as_bytes()]);
    (finish(ACCOUNTING_REQUEST, id, &ra, &a), ra)
}

pub async fn account(srv: &Server, r: &AcctRecord) -> Result<(), String> {
    let id = random16()[0];
    let (pkt, ra) = accounting_request(id, srv, r);
    let (code, _) = exchange(srv, &pkt, id, &ra).await?;
    if code == ACCOUNTING_RESPONSE {
        Ok(())
    } else {
        Err(format!("RADIUS accounting answered with code {code}"))
    }
}

#[cfg(test)]
pub(crate) mod testserver {
    //! An independent RADIUS server for tests: decodes PAP its own way,
    //! checks the Message-Authenticator and the accounting authenticator, and
    //! signs its replies.
    use super::*;
    use std::sync::{Arc, Mutex};

    pub struct Fake {
        pub addr: SocketAddr,
        /// ("auth", user, password) / ("acct", status, session id)
        pub seen: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    pub async fn start(
        secret: &'static str,
        accounts: Vec<(&'static str, &'static str)>,
        grant: Vec<u8>,
    ) -> Fake {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let p = buf[..n].to_vec();
                let (code, id) = (p[0], p[1]);
                let req_auth: [u8; 16] = p[4..20].try_into().unwrap();
                let attrs = parse_attrs(&p[20..]);
                let resp_code = match code {
                    ACCESS_REQUEST => {
                        // Message-Authenticator over the packet with the attribute zeroed
                        let mut z = p.clone();
                        let pos = 20 + {
                            let mut i = 0;
                            let mut at = None;
                            while i + 2 <= z.len() - 20 {
                                if z[20 + i] == MESSAGE_AUTHENTICATOR {
                                    at = Some(i);
                                    break;
                                }
                                i += usize::from(z[21 + i]);
                            }
                            at.expect("Message-Authenticator present")
                        };
                        let got: [u8; 16] = z[pos + 2..pos + 18].try_into().unwrap();
                        z[pos + 2..pos + 18].copy_from_slice(&[0u8; 16]);
                        assert_eq!(
                            hmac_md5(secret.as_bytes(), &z),
                            got,
                            "Message-Authenticator"
                        );
                        let user = attrs
                            .iter()
                            .find(|(t, _)| *t == USER_NAME)
                            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                            .unwrap_or_default();
                        let hidden = attrs
                            .iter()
                            .find(|(t, _)| *t == USER_PASSWORD)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                        let mut plain = Vec::new();
                        let mut prev = req_auth.to_vec();
                        for blk in hidden.chunks(16) {
                            let key = md5(&[secret.as_bytes(), &prev]);
                            plain.extend(blk.iter().zip(key.iter()).map(|(a, b)| a ^ b));
                            prev = blk.to_vec();
                        }
                        while plain.last() == Some(&0) {
                            plain.pop();
                        }
                        let pw = String::from_utf8_lossy(&plain).into_owned();
                        seen2
                            .lock()
                            .unwrap()
                            .push(("auth".into(), user.clone(), pw.clone()));
                        if accounts.iter().any(|(u, w)| *u == user && *w == pw) {
                            ACCESS_ACCEPT
                        } else {
                            ACCESS_REJECT
                        }
                    }
                    ACCOUNTING_REQUEST => {
                        let mut z = p.clone();
                        z[4..20].copy_from_slice(&[0u8; 16]);
                        assert_eq!(
                            md5(&[&z, secret.as_bytes()]),
                            req_auth,
                            "accounting authenticator"
                        );
                        let st = attrs
                            .iter()
                            .find(|(t, _)| *t == ACCT_STATUS_TYPE)
                            .and_then(|(_, v)| u32_of(v))
                            .unwrap_or(0);
                        let sid = attrs
                            .iter()
                            .find(|(t, _)| *t == ACCT_SESSION_ID)
                            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                            .unwrap_or_default();
                        seen2
                            .lock()
                            .unwrap()
                            .push(("acct".into(), st.to_string(), sid));
                        ACCOUNTING_RESPONSE
                    }
                    _ => continue,
                };
                let body = if resp_code == ACCESS_ACCEPT {
                    grant.clone()
                } else {
                    Vec::new()
                };
                let mut resp = vec![resp_code, id, 0, 0];
                resp.extend_from_slice(&[0u8; 16]);
                resp.extend_from_slice(&body);
                let l = resp.len() as u16;
                resp[2..4].copy_from_slice(&l.to_be_bytes());
                let ra = md5(&[&resp[..4], &req_auth, &body, secret.as_bytes()]);
                resp[4..20].copy_from_slice(&ra);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        Fake { addr, seen }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(addr: SocketAddr) -> Server {
        Server {
            addr,
            secret: "testing123".into(),
            nas_id: "patronus".into(),
            timeout: Duration::from_millis(500),
        }
    }

    fn client() -> Client {
        Client {
            ip: "10.0.0.5".parse().unwrap(),
            mac: "02:00:00:00:00:05".into(),
            nas_ip: "10.0.0.1".parse().unwrap(),
        }
    }

    #[test]
    fn hmac_md5_matches_rfc_2104_vector() {
        // RFC 2104 test 2: key "Jefe", data "what do ya want for nothing?"
        let h = hmac_md5(b"Jefe", b"what do ya want for nothing?");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "750c783e6ab0b503eaa86e310a5db738");
    }

    #[test]
    fn password_is_hidden_in_16_byte_blocks() {
        let ra = [7u8; 16];
        assert_eq!(hide_password(b"short", b"s", &ra).len(), 16);
        assert_eq!(hide_password(b"exactly-16-bytes", b"s", &ra).len(), 16);
        assert_eq!(hide_password(b"seventeen-bytes!!", b"s", &ra).len(), 32);
        assert_eq!(station_id("02:ab:00:00:00:05"), "02-AB-00-00-00-05");
    }

    #[test]
    fn grants_read_session_idle_and_wispr_bandwidth() {
        let mut a = Vec::new();
        attr_u32(&mut a, SESSION_TIMEOUT, 600);
        attr_u32(&mut a, IDLE_TIMEOUT, 60);
        let mut vsa = WISPR.to_be_bytes().to_vec();
        attr_u32(&mut vsa, WISPR_BW_DOWN, 2_000_000);
        attr_u32(&mut vsa, WISPR_BW_UP, 500_000);
        attr(&mut a, VENDOR_SPECIFIC, &vsa);
        let g = grant_of(&a);
        assert_eq!(
            g,
            Grant {
                session_timeout: Some(600),
                idle_timeout: Some(60),
                up_bps: Some(500_000),
                down_bps: Some(2_000_000)
            }
        );
    }

    #[test]
    fn forged_reply_without_the_secret_is_refused() {
        let req = [1u8; 16];
        let mut resp = vec![ACCESS_ACCEPT, 9, 0, 20];
        resp.extend_from_slice(&md5(&[&[ACCESS_ACCEPT, 9, 0, 20], &req, b"wrong"]));
        assert!(check_reply(&resp, 9, &req, "right").is_none());
        let mut ok = vec![ACCESS_ACCEPT, 9, 0, 20];
        ok.extend_from_slice(&md5(&[&[ACCESS_ACCEPT, 9, 0, 20], &req, b"right"]));
        assert_eq!(
            check_reply(&ok, 9, &req, "right").map(|r| r.0),
            Some(ACCESS_ACCEPT)
        );
        assert!(check_reply(&ok, 8, &req, "right").is_none(), "other id");
    }

    #[tokio::test]
    async fn login_and_accounting_against_an_independent_server() {
        let mut grant = Vec::new();
        attr_u32(&mut grant, SESSION_TIMEOUT, 120);
        let f = testserver::start("testing123", vec![("alice", "a-long-secret-pass")], grant).await;
        let s = srv(f.addr);
        assert_eq!(
            authenticate(&s, "alice", "a-long-secret-pass", &client())
                .await
                .unwrap(),
            AuthOutcome::Accept(Grant {
                session_timeout: Some(120),
                ..Default::default()
            })
        );
        assert!(matches!(
            authenticate(&s, "alice", "nope", &client()).await.unwrap(),
            AuthOutcome::Reject(_)
        ));
        let rec = |kind| AcctRecord {
            kind,
            session_id: "abc123".into(),
            user: "alice".into(),
            client: client(),
            session_time: 42,
            terminate_cause: Some(cause::USER_REQUEST),
            timestamp: 1_700_000_000,
        };
        account(&s, &rec(Acct::Start)).await.unwrap();
        account(&s, &rec(Acct::Stop)).await.unwrap();
        let seen = f.seen.lock().unwrap().clone();
        assert_eq!(
            seen[0],
            ("auth".into(), "alice".into(), "a-long-secret-pass".into())
        );
        assert_eq!(seen[2], ("acct".into(), "1".into(), "abc123".into()));
        assert_eq!(seen[3], ("acct".into(), "2".into(), "abc123".into()));
    }

    #[tokio::test]
    async fn silent_server_is_an_error_not_a_login() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut s = srv(sock.local_addr().unwrap());
        s.timeout = Duration::from_millis(50);
        assert!(authenticate(&s, "a", "b", &client()).await.is_err());
    }
}
