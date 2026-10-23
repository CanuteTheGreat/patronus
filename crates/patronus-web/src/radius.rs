//! RADIUS client (RFC 2865, PAP) for the web UI login (lane H): a person
//! whose account lives on a RADIUS server logs in to Patronus with those
//! credentials.
//!
//! Only what a login needs: Access-Request with User-Name, the hidden
//! User-Password and NAS-Identifier; the answer (Access-Accept / -Reject) is
//! accepted only when its Response Authenticator verifies against the shared
//! secret, so a forged or replayed UDP packet cannot log anyone in.
//! Access-Challenge (OTP/2FA prompts) is not supported and counts as a
//! refusal.

use md5::{Digest, Md5};
use rand::RngCore;
use sqlx::Row;
use std::time::Duration;
use tokio::net::UdpSocket;

pub const ACCESS_REQUEST: u8 = 1;
pub const ACCESS_ACCEPT: u8 = 2;
pub const ACCESS_REJECT: u8 = 3;
const ATTR_USER_NAME: u8 = 1;
const ATTR_USER_PASSWORD: u8 = 2;
const ATTR_NAS_IDENTIFIER: u8 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    Reject,
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 2865 section 5.2: pad to a multiple of 16, XOR each block with
/// MD5(secret + previous ciphertext block (the request authenticator for the
/// first)).
pub fn hide_password(password: &[u8], secret: &[u8], authenticator: &[u8; 16]) -> Vec<u8> {
    let mut p = password.to_vec();
    if p.is_empty() || !p.len().is_multiple_of(16) {
        p.resize(p.len().div_ceil(16).max(1) * 16, 0);
    }
    let mut out = Vec::with_capacity(p.len());
    let mut prev: Vec<u8> = authenticator.to_vec();
    for block in p.chunks(16) {
        let key = md5(&[secret, &prev]);
        let c: Vec<u8> = block.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
        prev = c.clone();
        out.extend(c);
    }
    out
}

/// An Access-Request packet.
pub fn build_request(
    id: u8,
    authenticator: &[u8; 16],
    user: &str,
    password: &str,
    secret: &str,
    nas_id: &str,
) -> Result<Vec<u8>, String> {
    if user.is_empty() || user.len() > 253 {
        return Err("user name: 1-253 bytes".into());
    }
    if password.len() > 128 {
        return Err("password: at most 128 bytes".into());
    }
    let hidden = hide_password(password.as_bytes(), secret.as_bytes(), authenticator);
    let mut attrs = Vec::new();
    for (t, v) in [
        (ATTR_USER_NAME, user.as_bytes()),
        (ATTR_USER_PASSWORD, hidden.as_slice()),
        (ATTR_NAS_IDENTIFIER, nas_id.as_bytes()),
    ] {
        attrs.push(t);
        attrs.push((v.len() + 2) as u8);
        attrs.extend_from_slice(v);
    }
    let len = 20 + attrs.len();
    let mut pkt = vec![ACCESS_REQUEST, id, (len >> 8) as u8, len as u8];
    pkt.extend_from_slice(authenticator);
    pkt.extend(attrs);
    Ok(pkt)
}

/// Check a response to the request with `id`/`req_auth`: code, id, length
/// and the Response Authenticator.
pub fn check_response(
    resp: &[u8],
    id: u8,
    req_auth: &[u8; 16],
    secret: &str,
) -> Result<Outcome, String> {
    if resp.len() < 20 {
        return Err("short RADIUS packet".into());
    }
    let len = usize::from(resp[2]) << 8 | usize::from(resp[3]);
    if len < 20 || len > resp.len() {
        return Err("bad RADIUS length".into());
    }
    let resp = &resp[..len];
    if resp[1] != id {
        return Err("answer to a different request".into());
    }
    let want = md5(&[&resp[..4], req_auth, &resp[20..], secret.as_bytes()]);
    // constant-time compare
    let diff = want
        .iter()
        .zip(&resp[4..20])
        .fold(0u8, |d, (a, b)| d | (a ^ b));
    if diff != 0 {
        return Err("the response authenticator does not verify (wrong shared secret?)".into());
    }
    match resp[0] {
        ACCESS_ACCEPT => Ok(Outcome::Accept),
        ACCESS_REJECT => Ok(Outcome::Reject),
        other => Ok({
            tracing::warn!("RADIUS answered code {other} (challenge?): treated as a refusal");
            Outcome::Reject
        }),
    }
}

/// Ask one RADIUS server (`host:port`) whether `user`/`password` is valid.
pub async fn authenticate(
    addr: &str,
    secret: &str,
    user: &str,
    password: &str,
    timeout: Duration,
    retries: u32,
) -> Result<Outcome, String> {
    let mut rng = rand::rngs::OsRng;
    let mut auth = [0u8; 16];
    rng.fill_bytes(&mut auth);
    let mut id = [0u8; 1];
    rng.fill_bytes(&mut id);
    let id = id[0];
    let pkt = build_request(id, &auth, user, password, secret, "patronus")?;
    let target = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("resolving {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr} does not resolve"))?;
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("udp socket: {e}"))?;
    sock.connect(target)
        .await
        .map_err(|e| format!("connect {target}: {e}"))?;
    let mut last = format!("no answer from {addr}");
    for _ in 0..=retries {
        sock.send(&pkt).await.map_err(|e| format!("send: {e}"))?;
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => match check_response(&buf[..n], id, &auth, secret) {
                Ok(o) => return Ok(o),
                // a bad answer is not retried into success: forged or misconfigured
                Err(e) => return Err(e),
            },
            Ok(Err(e)) => last = format!("receive: {e}"),
            Err(_) => last = format!("no answer from {addr} within {timeout:?}"),
        }
    }
    Err(last)
}

// ---------------------------------------------------------------------------
// configured servers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuthServer {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: u16,
    #[serde(skip)]
    pub secret: String,
    pub default_role: String,
    pub timeout_secs: u32,
    pub enabled: bool,
    /// LDAP only (empty for RADIUS)
    pub base_dn: String,
    pub bind_dn: String,
    pub user_filter: String,
    pub tls: String,
    pub operator_group: String,
}

pub async fn servers(store: &patronus_config::ConfigStore) -> anyhow::Result<Vec<AuthServer>> {
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = sqlx::query(
        "SELECT id, name, kind, host, port, secret, default_role, timeout_secs, enabled,
                base_dn, bind_dn, user_filter, tls, operator_group
         FROM auth_servers ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| AuthServer {
            id: r.get(0),
            name: r.get(1),
            kind: r.get(2),
            host: r.get(3),
            port: r.get::<i64, _>(4) as u16,
            secret: r.get(5),
            default_role: r.get(6),
            timeout_secs: r.get::<i64, _>(7) as u32,
            enabled: r.get::<i64, _>(8) != 0,
            base_dn: r.get(9),
            bind_dn: r.get(10),
            user_filter: r.get(11),
            tls: r.get(12),
            operator_group: r.get(13),
        })
        .collect())
}

pub async fn add_server(
    store: &patronus_config::ConfigStore,
    name: &str,
    host: &str,
    port: Option<u16>,
    secret: &str,
    default_role: Option<&str>,
    timeout_secs: Option<u32>,
) -> anyhow::Result<i64> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        anyhow::bail!(
            "Invalid server name {name:?}: 1-40 letters, digits, '-', '_', '.' or spaces"
        );
    }
    let host = host.trim();
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
    {
        anyhow::bail!("Invalid server address {host:?}: a host name or IP address");
    }
    if secret.is_empty() || secret.len() > 128 || secret.chars().any(|c| c.is_control()) {
        anyhow::bail!("Invalid shared secret: 1-128 printable characters");
    }
    let role = default_role.unwrap_or("readonly");
    if !matches!(role, "readonly" | "operator") {
        anyhow::bail!(
            "Invalid default role {role:?}: readonly or operator (admins are promoted by hand)"
        );
    }
    let timeout = timeout_secs.unwrap_or(5);
    if !(1..=30).contains(&timeout) {
        anyhow::bail!("Invalid timeout: 1-30 seconds");
    }
    let port = port.unwrap_or(1812);
    if port == 0 {
        anyhow::bail!("Invalid port: 1-65535");
    }
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let r = sqlx::query(
        "INSERT INTO auth_servers (name, kind, host, port, secret, default_role, timeout_secs, enabled, created_at)
         VALUES (?, 'radius', ?, ?, ?, ?, ?, 1, ?)",
    )
    .bind(name)
    .bind(host)
    .bind(i64::from(port))
    .bind(secret)
    .bind(role)
    .bind(i64::from(timeout))
    .bind(chrono::Utc::now().timestamp())
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow::anyhow!("Invalid server name: {name} already exists")
        } else {
            anyhow::anyhow!("saving the server: {e}")
        }
    })?;
    Ok(r.last_insert_rowid())
}

/// The settings of an LDAP server (what `add_ldap_server` validates).
#[derive(Debug, Default, Clone)]
pub struct LdapInput {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_filter: Option<String>,
    pub tls: Option<String>,
    pub operator_group: String,
    pub default_role: Option<String>,
    pub timeout_secs: Option<u32>,
}

fn plain_dn(x: &str) -> bool {
    x.len() <= 512 && !x.chars().any(|c| c.is_control())
}

pub async fn add_ldap_server(
    store: &patronus_config::ConfigStore,
    i: &LdapInput,
) -> anyhow::Result<i64> {
    let name = i.name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        anyhow::bail!("Invalid server name {name:?}: 1-40 letters, digits, '-', '_', '.' or spaces");
    }
    let host = i.host.trim();
    if host.is_empty()
        || host.len() > 253
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
    {
        anyhow::bail!("Invalid server address {host:?}: a host name or IP address");
    }
    let tls = i.tls.as_deref().unwrap_or("none");
    if !matches!(tls, "none" | "starttls" | "ldaps") {
        anyhow::bail!("Invalid tls {tls:?}: none, starttls or ldaps");
    }
    let port = i.port.unwrap_or(if tls == "ldaps" { 636 } else { 389 });
    if port == 0 {
        anyhow::bail!("Invalid port: 1-65535");
    }
    if i.base_dn.trim().is_empty() || !plain_dn(&i.base_dn) {
        anyhow::bail!("Invalid base DN: the entry the user search starts at");
    }
    if !plain_dn(&i.bind_dn) || !plain_dn(&i.operator_group) {
        anyhow::bail!("Invalid DN: printable characters only");
    }
    if i.bind_dn.is_empty() != i.bind_password.is_empty() {
        anyhow::bail!("Invalid search account: give both the bind DN and its password, or neither (anonymous search)");
    }
    if i.bind_password.len() > 128 || i.bind_password.chars().any(|c| c.is_control()) {
        anyhow::bail!("Invalid password: at most 128 printable characters");
    }
    let filter = i.user_filter.as_deref().unwrap_or("(uid={u})");
    #[cfg(feature = "ldap")]
    if !crate::ldap::check_filter(filter) {
        anyhow::bail!("Invalid user filter {filter:?}: parenthesised and containing {{u}}, e.g. (uid={{u}})");
    }
    #[cfg(not(feature = "ldap"))]
    anyhow::bail!("Invalid server kind: this build has no LDAP support (USE=ldap)");
    let role = i.default_role.as_deref().unwrap_or("readonly");
    if !matches!(role, "readonly" | "operator") {
        anyhow::bail!("Invalid default role {role:?}: readonly or operator (admins are promoted by hand)");
    }
    let timeout = i.timeout_secs.unwrap_or(5);
    if !(1..=30).contains(&timeout) {
        anyhow::bail!("Invalid timeout: 1-30 seconds");
    }
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    let r = sqlx::query(
        "INSERT INTO auth_servers (name, kind, host, port, secret, default_role, timeout_secs, enabled, created_at,
                                   base_dn, bind_dn, user_filter, tls, operator_group)
         VALUES (?, 'ldap', ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(host)
    .bind(i64::from(port))
    .bind(&i.bind_password)
    .bind(role)
    .bind(i64::from(timeout))
    .bind(chrono::Utc::now().timestamp())
    .bind(i.base_dn.trim())
    .bind(&i.bind_dn)
    .bind(filter.trim())
    .bind(tls)
    .bind(&i.operator_group)
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow::anyhow!("Invalid server name: {name} already exists")
        } else {
            anyhow::anyhow!("saving the server: {e}")
        }
    })?;
    Ok(r.last_insert_rowid())
}

pub async fn delete_server(store: &patronus_config::ConfigStore, id: i64) -> anyhow::Result<bool> {
    let pool = store.pool().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(sqlx::query("DELETE FROM auth_servers WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        > 0)
}

/// Try the enabled servers in order: the first one that accepts wins and
/// gives its default role; a server that rejects ends the attempt (a
/// reject is an answer); one that cannot be reached is skipped.
pub async fn check_login(
    store: &patronus_config::ConfigStore,
    user: &str,
    password: &str,
) -> Option<AuthServer> {
    if password.is_empty() {
        return None;
    }
    let list = servers(store).await.ok()?;
    for s in list.into_iter().filter(|s| s.enabled && s.kind == "radius") {
        let addr = if s.host.contains(':') {
            format!("[{}]:{}", s.host, s.port)
        } else {
            format!("{}:{}", s.host, s.port)
        };
        match authenticate(
            &addr,
            &s.secret,
            user,
            password,
            Duration::from_secs(u64::from(s.timeout_secs)),
            1,
        )
        .await
        {
            Ok(Outcome::Accept) => return Some(s),
            Ok(Outcome::Reject) => return None,
            Err(e) => tracing::warn!("RADIUS server {} ({addr}): {e}", s.name),
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod testserver {
    //! An independent RFC 2865 server for tests: decodes the hidden password
    //! its own way and answers with a correct Response Authenticator.
    use super::*;

    pub struct Server {
        pub addr: std::net::SocketAddr,
        pub seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    /// Accepts `(user, password)` pairs in `accounts`; `secret` is shared.
    pub async fn start(
        secret: &'static str,
        accounts: Vec<(&'static str, &'static str)>,
    ) -> Server {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let p = &buf[..n];
                if p.len() < 20 || p[0] != ACCESS_REQUEST {
                    continue;
                }
                let (id, auth) = (p[1], <[u8; 16]>::try_from(&p[4..20]).unwrap());
                let (mut user, mut hidden) = (String::new(), Vec::new());
                let mut i = 20;
                while i + 2 <= p.len() {
                    let (t, l) = (p[i], usize::from(p[i + 1]));
                    if l < 2 || i + l > p.len() {
                        break;
                    }
                    match t {
                        1 => user = String::from_utf8_lossy(&p[i + 2..i + l]).into_owned(),
                        2 => hidden = p[i + 2..i + l].to_vec(),
                        _ => {}
                    }
                    i += l;
                }
                // un-hide (RFC 2865 5.2), the receiving side
                let mut plain = Vec::new();
                let mut prev = auth.to_vec();
                for blk in hidden.chunks(16) {
                    let key = md5(&[secret.as_bytes(), &prev]);
                    plain.extend(blk.iter().zip(key.iter()).map(|(a, b)| a ^ b));
                    prev = blk.to_vec();
                }
                while plain.last() == Some(&0) {
                    plain.pop();
                }
                let pw = String::from_utf8_lossy(&plain).into_owned();
                seen2.lock().unwrap().push((user.clone(), pw.clone()));
                let code = if accounts.iter().any(|(u, w)| *u == user && *w == pw) {
                    ACCESS_ACCEPT
                } else {
                    ACCESS_REJECT
                };
                let mut resp = vec![code, id, 0, 20];
                resp.extend_from_slice(&[0u8; 16]);
                let ra = md5(&[&resp[..4], &auth, secret.as_bytes()]);
                resp[4..20].copy_from_slice(&ra);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        Server { addr, seen }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hiding_matches_rfc_2865_section_5_2() {
        // one block: c = p xor MD5(secret + RA)
        let ra = [7u8; 16];
        let h = hide_password(b"arctangent", b"xyzzy5461", &ra);
        assert_eq!(h.len(), 16);
        let key = md5(&[b"xyzzy5461", &ra]);
        let mut want = b"arctangent".to_vec();
        want.resize(16, 0);
        for (w, k) in want.iter_mut().zip(key) {
            *w ^= k;
        }
        assert_eq!(h, want);
        // two blocks chain on the first ciphertext block
        let long = b"0123456789abcdefXYZ";
        let h2 = hide_password(long, b"s", &ra);
        assert_eq!(h2.len(), 32);
        assert_eq!(&h2[..16], &hide_password(&long[..16], b"s", &ra)[..]);
        let k2 = md5(&[b"s", &h2[..16]]);
        let mut p2 = long[16..].to_vec();
        p2.resize(16, 0);
        for (w, k) in p2.iter_mut().zip(k2) {
            *w ^= k;
        }
        assert_eq!(&h2[16..], &p2[..]);
        // an empty password is one padded block, not nothing
        assert_eq!(hide_password(b"", b"s", &ra).len(), 16);
    }

    #[test]
    fn requests_are_well_formed_and_responses_must_verify() {
        let ra = [3u8; 16];
        let pkt = build_request(9, &ra, "alice", "pw", "secret", "patronus").unwrap();
        assert_eq!(pkt[0], ACCESS_REQUEST);
        assert_eq!(pkt[1], 9);
        assert_eq!(usize::from(pkt[2]) << 8 | usize::from(pkt[3]), pkt.len());
        assert_eq!(&pkt[4..20], &ra);
        assert!(build_request(1, &ra, "", "pw", "s", "n").is_err());
        assert!(build_request(1, &ra, "u", &"x".repeat(129), "s", "n").is_err());

        let mk = |code: u8, id: u8, secret: &str| {
            let mut r = vec![code, id, 0, 20];
            r.extend_from_slice(&[0u8; 16]);
            let a = md5(&[&r[..4], &ra, secret.as_bytes()]);
            r[4..20].copy_from_slice(&a);
            r
        };
        assert_eq!(
            check_response(&mk(ACCESS_ACCEPT, 9, "secret"), 9, &ra, "secret"),
            Ok(Outcome::Accept)
        );
        assert_eq!(
            check_response(&mk(ACCESS_REJECT, 9, "secret"), 9, &ra, "secret"),
            Ok(Outcome::Reject)
        );
        // wrong secret, wrong id, truncated, tampered code: never an accept
        assert!(check_response(&mk(ACCESS_ACCEPT, 9, "other"), 9, &ra, "secret").is_err());
        assert!(check_response(&mk(ACCESS_ACCEPT, 8, "secret"), 9, &ra, "secret").is_err());
        assert!(check_response(&mk(ACCESS_ACCEPT, 9, "secret")[..10], 9, &ra, "secret").is_err());
        let mut forged = mk(ACCESS_REJECT, 9, "secret");
        forged[0] = ACCESS_ACCEPT;
        assert!(
            check_response(&forged, 9, &ra, "secret").is_err(),
            "flipping reject to accept must not verify"
        );
        // a challenge is a refusal
        assert_eq!(
            check_response(&mk(11, 9, "secret"), 9, &ra, "secret"),
            Ok(Outcome::Reject)
        );
    }

    #[tokio::test]
    async fn a_real_udp_exchange_accepts_rejects_and_survives_a_dead_server() {
        let srv =
            testserver::start("s3cret", vec![("alice", "correct horse battery staple")]).await;
        let addr = srv.addr.to_string();
        let t = Duration::from_secs(2);
        assert_eq!(
            authenticate(
                &addr,
                "s3cret",
                "alice",
                "correct horse battery staple",
                t,
                0
            )
            .await,
            Ok(Outcome::Accept)
        );
        assert_eq!(
            authenticate(&addr, "s3cret", "alice", "wrong", t, 0).await,
            Ok(Outcome::Reject)
        );
        assert_eq!(
            authenticate(&addr, "s3cret", "mallory", "x", t, 0).await,
            Ok(Outcome::Reject)
        );
        // the server saw the password exactly as typed (hidden on the wire)
        assert!(srv
            .seen
            .lock()
            .unwrap()
            .contains(&("alice".into(), "correct horse battery staple".into())));
        // a shared-secret mismatch is an error, not an accept
        assert!(authenticate(
            &addr,
            "wrong-secret",
            "alice",
            "correct horse battery staple",
            t,
            0
        )
        .await
        .is_err());
        // nobody listening: an error after the timeout
        let dead = authenticate("127.0.0.1:9", "s", "u", "p", Duration::from_millis(200), 1).await;
        assert!(dead.is_err(), "{dead:?}");
        // passwords longer than one block
        let long = "a-very-long-passphrase-that-needs-three-blocks-of-sixteen!";
        let srv2 = testserver::start(
            "k",
            vec![(
                "bob",
                "a-very-long-passphrase-that-needs-three-blocks-of-sixteen!",
            )],
        )
        .await;
        assert_eq!(
            authenticate(&srv2.addr.to_string(), "k", "bob", long, t, 0).await,
            Ok(Outcome::Accept)
        );
    }
}
