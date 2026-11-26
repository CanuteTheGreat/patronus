//! Portal sessions: who may sign in, what the kernel lets through for them,
//! and when they are signed out again.
//!
//! A session is one row of `cp_sessions` plus kernel state: the client's
//! MAC + IPv4 address in the zone's `auth` set (element timeout = hard
//! timeout), its MAC in `amac` (IPv6), in `seen` (idle timeout, refreshed by
//! its traffic), optional `tc` classes for per-client bandwidth, and RADIUS
//! accounting start/interim/stop when the zone logs in through RADIUS.
//! [`Portal::tick`] ends sessions on hard timeout (the kernel already dropped
//! the element), idle timeout (the client fell out of `seen`), an
//! administrator's disconnect (`cp_sessions.disconnect_req`, set by the web UI
//! or CLI) or a zone that was switched off or deleted.

use crate::radius;
use patronus_config::ConfigStore;
use patronus_network::captive::{self, Globals, Zone};
use patronus_network::lan::{self, IfAddr};
use serde::Serialize;
use sqlx::Row;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// System commands the portal runs (a recorder in tests).
pub trait Sys: Send + Sync {
    /// Run a program; Err carries stderr.
    fn run(&self, argv: &[&str]) -> Result<String, String>;
    fn nft(&self, script: &str) -> Result<(), String>;
    /// MAC of an IPv4 neighbour (the client that is talking to us).
    fn neigh_mac(&self, ip: Ipv4Addr) -> Option<String>;
    fn addrs(&self) -> Vec<IfAddr>;
}

pub struct LiveSys;

impl Sys for LiveSys {
    fn run(&self, argv: &[&str]) -> Result<String, String> {
        let Some((prog, args)) = argv.split_first() else {
            return Err("empty command".into());
        };
        let out = std::process::Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{}: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn nft(&self, script: &str) -> Result<(), String> {
        use std::io::Write;
        let mut child = std::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("nft: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("nft: no stdin")?
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft: {e}"))?;
        let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    fn neigh_mac(&self, ip: Ipv4Addr) -> Option<String> {
        let t = std::fs::read_to_string("/proc/net/arp").ok()?;
        parse_arp(&t, ip)
    }

    fn addrs(&self) -> Vec<IfAddr> {
        use patronus_network::lan::AddrSource;
        lan::LiveAddrs.addrs().unwrap_or_default()
    }
}

/// `/proc/net/arp`: `IP HWtype Flags HWaddress Mask Device`; complete entries only.
pub fn parse_arp(t: &str, ip: Ipv4Addr) -> Option<String> {
    t.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 4 && f[0] == ip.to_string() && f[2] != "0x0" && f[3] != "00:00:00:00:00:00" {
            lan::check_mac(f[3]).ok()
        } else {
            None
        }
    })
}

/// The client a request came from, in its zone.
#[derive(Debug, Clone)]
pub struct ClientCtx {
    pub zone: Zone,
    pub dev: String,
    pub router: Ipv4Addr,
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// One row of `cp_sessions`.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: i64,
    pub sid: String,
    pub zone: String,
    pub ip: String,
    pub mac: String,
    pub dev: String,
    pub username: String,
    pub method: String,
    pub voucher: Option<String>,
    pub started: i64,
    pub expires: i64,
    pub idle_secs: i64,
    pub download_kbit: i64,
    pub upload_kbit: i64,
    pub ended: Option<i64>,
    pub end_reason: Option<String>,
}

const COLS: &str = "id, sid, zone, ip, mac, dev, username, method, voucher, started, expires, \
                    idle_secs, download_kbit, upload_kbit, ended, end_reason";

fn session_of(r: &sqlx::sqlite::SqliteRow) -> Session {
    Session {
        id: r.get(0),
        sid: r.get(1),
        zone: r.get(2),
        ip: r.get(3),
        mac: r.get(4),
        dev: r.get(5),
        username: r.get(6),
        method: r.get(7),
        voucher: r.get(8),
        started: r.get(9),
        expires: r.get(10),
        idle_secs: r.get(11),
        download_kbit: r.get(12),
        upload_kbit: r.get(13),
        ended: r.get(14),
        end_reason: r.get(15),
    }
}

/// What the client typed on the splash page.
#[derive(Debug, Clone, Default)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub voucher: String,
    pub terms: bool,
}

/// Why a login was refused (the page shows the zone's error text; the reason
/// goes to the log and the audit trail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Terms,
    Credentials,
    VoucherExpired,
    TooManyDevices,
    Unavailable(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Terms => write!(f, "terms not accepted"),
            Refused::Credentials => write!(f, "wrong credentials"),
            Refused::VoucherExpired => write!(f, "voucher used up"),
            Refused::TooManyDevices => write!(f, "too many devices for this account"),
            Refused::Unavailable(s) => write!(f, "login unavailable: {s}"),
        }
    }
}

pub fn now() -> i64 {
    lan::now()
}

fn random_hex(n: usize) -> String {
    use std::io::Read;
    let mut b = vec![0u8; n];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `tc` class / filter priority of a session (unique per live session id).
pub fn tc_minor(id: i64) -> u32 {
    (id.rem_euclid(0xfff0) as u32) + 0x10
}

/// The HTB root handle the portal owns on a zone device.
pub const TC_ROOT: &str = "1cf:";

pub struct Portal {
    pub store: Arc<ConfigStore>,
    pub sys: Arc<dyn Sys>,
}

impl Portal {
    pub fn new(store: Arc<ConfigStore>, sys: Arc<dyn Sys>) -> Self {
        Self { store, sys }
    }

    pub async fn globals(&self) -> Globals {
        match Globals::load(&self.store).await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("captive portal settings: {e}");
                Globals {
                    http_port: 8002,
                    https_port: 8003,
                    hostname: String::new(),
                    tls_cert: String::new(),
                    tls_key: String::new(),
                    retention_days: 30,
                    interim_secs: 300,
                    code_len: 10,
                    poll_secs: 2,
                }
            }
        }
    }

    /// The enabled zone `ip` is a client of (by the subnets of the zone's devices).
    pub async fn client(&self, ip: Ipv4Addr) -> Option<ClientCtx> {
        let zones = captive::zones(&self.store).await.ok()?;
        let addrs = self.sys.addrs();
        for z in zones.into_iter().filter(|z| z.enabled) {
            let devs = lan::resolve_iface(&self.store, &z.interface)
                .await
                .unwrap_or_default();
            for a in addrs.iter().filter(|a| devs.contains(&a.ifname)) {
                let IpAddr::V4(router) = a.addr else { continue };
                if a.network().is_some_and(|n| n.contains(IpAddr::V4(ip))) {
                    let mac = self.sys.neigh_mac(ip).unwrap_or_default();
                    return Some(ClientCtx {
                        zone: z,
                        dev: a.ifname.clone(),
                        router,
                        ip,
                        mac,
                    });
                }
            }
        }
        None
    }

    /// The client's active session, if it is signed in.
    pub async fn active(&self, c: &ClientCtx) -> Option<Session> {
        let r = sqlx::query(&format!(
            "SELECT {COLS} FROM cp_sessions WHERE ended IS NULL AND zone = ? AND ip = ? AND mac = ? \
             AND (expires = 0 OR expires > ?) ORDER BY id DESC LIMIT 1"
        ))
        .bind(&c.zone.name)
        .bind(c.ip.to_string())
        .bind(&c.mac)
        .bind(now())
        .fetch_optional(self.store.pool().ok()?)
        .await
        .ok()??;
        Some(session_of(&r))
    }

    pub async fn sessions(&self, include_ended: i64) -> Vec<Session> {
        let Ok(pool) = self.store.pool() else {
            return Vec::new();
        };
        let mut v: Vec<Session> = sqlx::query(&format!(
            "SELECT {COLS} FROM cp_sessions WHERE ended IS NULL ORDER BY id"
        ))
        .fetch_all(pool)
        .await
        .map(|rows| rows.iter().map(session_of).collect())
        .unwrap_or_default();
        if include_ended > 0 {
            let ended: Vec<Session> = sqlx::query(&format!(
                "SELECT {COLS} FROM cp_sessions WHERE ended IS NOT NULL ORDER BY ended DESC LIMIT ?"
            ))
            .bind(include_ended)
            .fetch_all(pool)
            .await
            .map(|rows| rows.iter().map(session_of).collect())
            .unwrap_or_default();
            v.extend(ended);
        }
        v
    }

    async fn count_active(&self, zone: &str, col: &str, val: &str) -> i64 {
        let Ok(pool) = self.store.pool() else {
            return 0;
        };
        sqlx::query(&format!(
            "SELECT count(*) FROM cp_sessions WHERE ended IS NULL AND zone = ? AND {col} = ?"
        ))
        .bind(zone)
        .bind(val)
        .fetch_one(pool)
        .await
        .map(|r| r.get::<i64, _>(0))
        .unwrap_or(0)
    }

    fn radius_server(z: &Zone, acct: bool) -> Result<radius::Server, String> {
        use std::net::ToSocketAddrs;
        let port = if acct {
            z.radius.acct_port
        } else {
            z.radius.port
        };
        let addr: SocketAddr = (z.radius.server.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("RADIUS server {}: {e}", z.radius.server))?
            .next()
            .ok_or_else(|| format!("RADIUS server {} has no address", z.radius.server))?;
        Ok(radius::Server {
            addr,
            secret: z.radius.secret.clone(),
            nas_id: z.radius.nas_id.clone(),
            timeout: Duration::from_secs(z.radius.timeout_secs),
        })
    }

    /// Check the form against the zone's backend; on success start the session.
    pub async fn login(&self, c: &ClientCtx, f: &LoginForm) -> Result<Session, Refused> {
        if let Some(s) = self.active(c).await {
            return Ok(s);
        }
        if c.mac.is_empty() {
            return Err(Refused::Unavailable(format!(
                "no MAC address known for {} (not on the zone's link?)",
                c.ip
            )));
        }
        let z = &c.zone;
        let t = now();
        if z.terms_required && !f.terms {
            return Err(Refused::Terms);
        }
        let mut hard = z.hard_minutes * 60;
        let (mut dl, mut ul) = (z.download_kbit, z.upload_kbit);
        let mut username = String::new();
        let mut voucher = None;
        let pool = self
            .store
            .pool()
            .map_err(|e| Refused::Unavailable(e.to_string()))?;
        match z.auth.as_str() {
            "none" => {}
            "local" => {
                let r =
                    sqlx::query("SELECT password, zone, enabled FROM cp_users WHERE username = ?")
                        .bind(f.username.trim())
                        .fetch_optional(pool)
                        .await
                        .map_err(|e| Refused::Unavailable(e.to_string()))?;
                // an unknown user costs the same argon2 work as a wrong password
                let (hash, zone_ok, enabled) = match &r {
                    Some(r) => {
                        let zn: Option<String> = r.get(1);
                        let zn = zn.unwrap_or_default();
                        (
                            r.get::<String, _>(0),
                            zn.is_empty() || zn == z.name,
                            r.get::<Option<i64>, _>(2).unwrap_or(1) != 0,
                        )
                    }
                    None => (DECOY.to_string(), false, false),
                };
                let pw = f.password.clone();
                let ok = tokio::task::spawn_blocking(move || captive::verify_password(&pw, &hash))
                    .await
                    .unwrap_or(false);
                if !(ok && zone_ok && enabled && r.is_some()) {
                    return Err(Refused::Credentials);
                }
                username = f.username.trim().to_string();
            }
            "voucher" => {
                let code: String = f
                    .voucher
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
                    .to_ascii_uppercase();
                let r = sqlx::query(
                    "SELECT r.minutes FROM cp_vouchers v JOIN cp_voucher_rolls r ON r.id = v.roll_id \
                     WHERE v.code = ? AND r.zone = ?",
                )
                .bind(&code)
                .bind(&z.name)
                .fetch_optional(pool)
                .await
                .map_err(|e| Refused::Unavailable(e.to_string()))?;
                let Some(r) = r else {
                    return Err(Refused::Credentials);
                };
                let minutes: i64 = r.get(0);
                let used = sqlx::query("SELECT expires FROM cp_voucher_use WHERE code = ?")
                    .bind(&code)
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| Refused::Unavailable(e.to_string()))?;
                let exp = match used {
                    Some(u) => u.get::<i64, _>(0),
                    None => {
                        let exp = t + minutes * 60;
                        sqlx::query(
                            "INSERT OR IGNORE INTO cp_voucher_use (code, first_used, expires) VALUES (?, ?, ?)",
                        )
                        .bind(&code)
                        .bind(t)
                        .bind(exp)
                        .execute(pool)
                        .await
                        .map_err(|e| Refused::Unavailable(e.to_string()))?;
                        exp
                    }
                };
                if exp <= t {
                    return Err(Refused::VoucherExpired);
                }
                let left = exp - t;
                hard = if hard > 0 { hard.min(left) } else { left };
                voucher = Some(code);
            }
            "radius" => {
                let srv = Self::radius_server(z, false).map_err(Refused::Unavailable)?;
                let who = radius::Client {
                    ip: c.ip,
                    mac: c.mac.clone(),
                    nas_ip: c.router,
                };
                match radius::authenticate(&srv, f.username.trim(), &f.password, &who).await {
                    Ok(radius::AuthOutcome::Accept(g)) => {
                        if let Some(st) = g.session_timeout.filter(|s| *s > 0) {
                            hard = i64::from(st);
                        }
                        if let Some(d) = g.down_bps.filter(|b| *b > 0) {
                            dl = i64::from(d / 1000).max(1);
                        }
                        if let Some(u) = g.up_bps.filter(|b| *b > 0) {
                            ul = i64::from(u / 1000).max(1);
                        }
                        username = f.username.trim().to_string();
                    }
                    Ok(radius::AuthOutcome::Reject(_)) => return Err(Refused::Credentials),
                    Err(e) => return Err(Refused::Unavailable(e)),
                }
            }
            other => return Err(Refused::Unavailable(format!("unknown login {other:?}"))),
        }
        if z.max_sessions > 0 {
            let n = match (&voucher, username.is_empty()) {
                (Some(v), _) => self.count_active(&z.name, "voucher", v).await,
                (None, false) => self.count_active(&z.name, "username", &username).await,
                _ => 0,
            };
            if n >= z.max_sessions {
                return Err(Refused::TooManyDevices);
            }
        }
        // a client that signs in again (new IP after a DHCP change, or a
        // different account) replaces its old session
        let old: Vec<i64> = sqlx::query(
            "SELECT id FROM cp_sessions WHERE ended IS NULL AND zone = ? AND (mac = ? OR ip = ?)",
        )
        .bind(&z.name)
        .bind(&c.mac)
        .bind(c.ip.to_string())
        .fetch_all(pool)
        .await
        .map(|rows| rows.iter().map(|r| r.get(0)).collect())
        .unwrap_or_default();
        for id in old {
            self.end(id, "replaced", radius::cause::USER_REQUEST).await;
        }
        let expires = if hard > 0 { t + hard } else { 0 };
        let idle = z.idle_minutes * 60;
        let sid = random_hex(8);
        let method = z.auth.clone();
        let r = sqlx::query(
            "INSERT INTO cp_sessions (sid, zone, ip, mac, dev, username, method, voucher, started, \
             expires, idle_secs, download_kbit, upload_kbit, last_interim) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&sid)
        .bind(&z.name)
        .bind(c.ip.to_string())
        .bind(&c.mac)
        .bind(&c.dev)
        .bind(&username)
        .bind(&method)
        .bind(&voucher)
        .bind(t)
        .bind(expires)
        .bind(idle)
        .bind(dl)
        .bind(ul)
        .bind(t)
        .execute(pool)
        .await
        .map_err(|e| Refused::Unavailable(e.to_string()))?;
        let id = r.last_insert_rowid();
        let s = Session {
            id,
            sid,
            zone: z.name.clone(),
            ip: c.ip.to_string(),
            mac: c.mac.clone(),
            dev: c.dev.clone(),
            username,
            method,
            voucher,
            started: t,
            expires,
            idle_secs: idle,
            download_kbit: dl,
            upload_kbit: ul,
            ended: None,
            end_reason: None,
        };
        if let Err(e) = self.admit(z, &s, t) {
            tracing::error!("captive portal: letting {} through failed: {e}", s.ip);
            let _ =
                sqlx::query("UPDATE cp_sessions SET ended = ?, end_reason = 'error' WHERE id = ?")
                    .bind(t)
                    .bind(id)
                    .execute(pool)
                    .await;
            return Err(Refused::Unavailable(e));
        }
        self.shape(&s);
        // web connections the portal redirected (TCP 80 to anywhere) keep their
        // NAT to the portal while tracked: forget them so the next packet goes
        // out. Never all of the client's flows: the HTTPS connection this login
        // came in on would lose its NAT and the answer with it.
        let _ = self
            .sys
            .run(&["conntrack", "-D", "-s", &s.ip, "-p", "tcp", "--dport", "80"]);
        let _ = self
            .store
            .audit(
                "portal",
                "captive_login",
                &z.name,
                Some(&s.sid),
                &serde_json::json!({"ip": s.ip, "mac": s.mac, "method": s.method, "user": s.username}),
            )
            .await;
        tracing::info!(
            "captive portal {}: {} ({}) signed in via {}{}",
            z.name,
            s.ip,
            s.mac,
            s.method,
            if s.username.is_empty() {
                String::new()
            } else {
                format!(" as {}", s.username)
            }
        );
        self.account(z, &s, radius::Acct::Start, None, t);
        Ok(s)
    }

    /// Put the client's elements into the zone's sets.
    fn admit(&self, z: &Zone, s: &Session, t: i64) -> Result<(), String> {
        let to = captive::remaining(s.expires, t)
            .map(|r| format!(" timeout {r}s"))
            .unwrap_or_default();
        let tbl = format!("inet {}", captive::TABLE);
        let mut script = format!(
            "add element {tbl} {} {{ {} . {}{to} }}\nadd element {tbl} {} {{ {}{to} }}\n",
            z.set("auth"),
            s.mac,
            s.ip,
            z.set("amac"),
            s.mac
        );
        if z.idle_minutes > 0 {
            script.push_str(&format!(
                "add element {tbl} {} {{ {} . {} }}\n",
                z.set("seen"),
                s.mac,
                s.ip
            ));
        }
        self.sys.nft(&script)
    }

    /// Per-client bandwidth: an HTB class (download, on the zone device's
    /// egress) and an ingress policer (upload), both matched on the client address.
    fn shape(&self, s: &Session) {
        if s.dev.is_empty() || (s.download_kbit <= 0 && s.upload_kbit <= 0) {
            return;
        }
        let dev = s.dev.as_str();
        let m = tc_minor(s.id);
        let prio = m.to_string();
        let class = format!("{TC_ROOT}{m:x}");
        let dst = format!("{}/32", s.ip);
        if s.download_kbit > 0 {
            let has_root = self
                .sys
                .run(&["tc", "qdisc", "show", "dev", dev])
                .map(|o| o.contains("htb 1cf:"))
                .unwrap_or(false);
            if !has_root {
                let _ = self.sys.run(&[
                    "tc", "qdisc", "replace", "dev", dev, "root", "handle", TC_ROOT, "htb",
                    "default", "1",
                ]);
                let _ = self.sys.run(&[
                    "tc", "class", "replace", "dev", dev, "parent", TC_ROOT, "classid", "1cf:1",
                    "htb", "rate", "10gbit",
                ]);
            }
            let rate = format!("{}kbit", s.download_kbit);
            let _ = self.sys.run(&[
                "tc", "class", "replace", "dev", dev, "parent", TC_ROOT, "classid", &class, "htb",
                "rate", &rate, "ceil", &rate,
            ]);
            let _ = self.sys.run(&[
                "tc", "filter", "del", "dev", dev, "parent", TC_ROOT, "prio", &prio,
            ]);
            if let Err(e) = self.sys.run(&[
                "tc", "filter", "add", "dev", dev, "parent", TC_ROOT, "protocol", "ip", "prio",
                &prio, "u32", "match", "ip", "dst", &dst, "flowid", &class,
            ]) {
                tracing::warn!("captive portal: download limit for {}: {e}", s.ip);
            }
        }
        if s.upload_kbit > 0 {
            let _ = self.sys.run(&[
                "tc", "qdisc", "add", "dev", dev, "handle", "ffff:", "ingress",
            ]);
            let rate = format!("{}kbit", s.upload_kbit);
            // the burst must hold a 64 KB GSO packet or TCP crawls
            let burst = format!("{}b", (s.upload_kbit * 1000 / 8 / 10).max(70_000));
            let _ = self.sys.run(&[
                "tc", "filter", "del", "dev", dev, "parent", "ffff:", "prio", &prio,
            ]);
            if let Err(e) = self.sys.run(&[
                "tc", "filter", "add", "dev", dev, "parent", "ffff:", "protocol", "ip", "prio",
                &prio, "u32", "match", "ip", "src", &dst, "police", "rate", &rate, "burst", &burst,
                "drop", "flowid", ":1",
            ]) {
                tracing::warn!("captive portal: upload limit for {}: {e}", s.ip);
            }
        }
    }

    fn unshape(&self, s: &Session) {
        if s.dev.is_empty() || (s.download_kbit <= 0 && s.upload_kbit <= 0) {
            return;
        }
        let dev = s.dev.as_str();
        let m = tc_minor(s.id);
        let prio = m.to_string();
        let class = format!("{TC_ROOT}{m:x}");
        if s.download_kbit > 0 {
            let _ = self.sys.run(&[
                "tc", "filter", "del", "dev", dev, "parent", TC_ROOT, "prio", &prio,
            ]);
            let _ = self
                .sys
                .run(&["tc", "class", "del", "dev", dev, "classid", &class]);
        }
        if s.upload_kbit > 0 {
            let _ = self.sys.run(&[
                "tc", "filter", "del", "dev", dev, "parent", "ffff:", "prio", &prio,
            ]);
        }
    }

    fn account(&self, z: &Zone, s: &Session, kind: radius::Acct, cause: Option<u32>, t: i64) {
        if z.auth != "radius" || !z.radius.accounting {
            return;
        }
        let srv = match Self::radius_server(z, true) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("captive portal accounting: {e}");
                return;
            }
        };
        let rec = radius::AcctRecord {
            kind,
            session_id: s.sid.clone(),
            user: s.username.clone(),
            client: radius::Client {
                ip: s.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
                mac: s.mac.clone(),
                nas_ip: Ipv4Addr::UNSPECIFIED,
            },
            session_time: u32::try_from((t - s.started).max(0)).unwrap_or(u32::MAX),
            terminate_cause: cause,
            timestamp: u32::try_from(t).unwrap_or(0),
        };
        let nas = self
            .sys
            .addrs()
            .into_iter()
            .find(|a| a.ifname == s.dev && a.addr.is_ipv4())
            .and_then(|a| match a.addr {
                IpAddr::V4(v) => Some(v),
                _ => None,
            });
        let mut rec = rec;
        if let Some(n) = nas {
            rec.client.nas_ip = n;
        }
        tokio::spawn(async move {
            if let Err(e) = radius::account(&srv, &rec).await {
                tracing::warn!(
                    "captive portal accounting ({:?} {}): {e}",
                    rec.kind,
                    rec.session_id
                );
            }
        });
    }

    async fn zone_named(&self, name: &str) -> Option<Zone> {
        captive::zones(&self.store)
            .await
            .ok()?
            .into_iter()
            .find(|z| z.name == name)
    }

    /// End session `id` (idempotent): kernel elements, tc, conntrack, accounting stop.
    pub async fn end(&self, id: i64, reason: &str, cause: u32) -> bool {
        let Ok(pool) = self.store.pool() else {
            return false;
        };
        let Ok(Some(r)) = sqlx::query(&format!(
            "SELECT {COLS} FROM cp_sessions WHERE id = ? AND ended IS NULL"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await
        else {
            return false;
        };
        let s = session_of(&r);
        let t = now();
        let done = sqlx::query(
            "UPDATE cp_sessions SET ended = ?, end_reason = ? WHERE id = ? AND ended IS NULL",
        )
        .bind(t)
        .bind(reason)
        .bind(id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() > 0)
        .unwrap_or(false);
        if !done {
            return false;
        }
        let zone = self.zone_named(&s.zone).await;
        if let Some(z) = &zone {
            let tbl = format!("inet {}", captive::TABLE);
            // one element per command: a missing element (the kernel already
            // expired it) must not keep the others in place
            let _ = self.sys.nft(&format!(
                "delete element {tbl} {} {{ {} . {} }}\n",
                z.set("auth"),
                s.mac,
                s.ip
            ));
            let _ = self.sys.nft(&format!(
                "delete element {tbl} {} {{ {} . {} }}\n",
                z.set("seen"),
                s.mac,
                s.ip
            ));
            if self.count_active(&s.zone, "mac", &s.mac).await == 0 {
                let _ = self.sys.nft(&format!(
                    "delete element {tbl} {} {{ {} }}\n",
                    z.set("amac"),
                    s.mac
                ));
            }
        }
        self.unshape(&s);
        // no conntrack flush: the zone's forward chain checks every packet
        // (not only new connections), so the client's open connections stop
        // at once, and its logout request still gets its answer
        let _ = self
            .store
            .audit(
                "portal",
                "captive_logout",
                &s.zone,
                Some(&s.sid),
                &serde_json::json!({"ip": s.ip, "mac": s.mac, "reason": reason}),
            )
            .await;
        tracing::info!(
            "captive portal {}: {} ({}) signed out: {reason}",
            s.zone,
            s.ip,
            s.mac
        );
        if let Some(z) = &zone {
            self.account(z, &s, radius::Acct::Stop, Some(cause), t);
        }
        true
    }

    /// Members of a zone's idle-tracking set (`mac . ip` strings); None if the
    /// set cannot be read (table not loaded).
    fn seen(&self, z: &Zone) -> Option<HashSet<String>> {
        let out = self
            .sys
            .run(&[
                "nft",
                "-j",
                "list",
                "set",
                "inet",
                captive::TABLE,
                &z.set("seen"),
            ])
            .ok()?;
        Some(parse_concat_elems(&out))
    }

    /// One pass: disconnect requests, hard and idle timeouts, zones that are
    /// gone, interim accounting, retention.
    pub async fn tick(&self, g: &Globals) {
        let Ok(pool) = self.store.pool() else { return };
        let t = now();
        let active: Vec<Session> = sqlx::query(&format!(
            "SELECT {COLS}, disconnect_req, last_interim FROM cp_sessions WHERE ended IS NULL ORDER BY id"
        ))
        .fetch_all(pool)
        .await
        .map(|rows| {
            rows.iter()
                .map(|r| {
                    let mut s = session_of(r);
                    if r.get::<i64, _>(16) != 0 {
                        s.end_reason = Some("admin".into());
                    }
                    s.ended = Some(r.get::<i64, _>(17));
                    s
                })
                .collect()
        })
        .unwrap_or_default();
        if active.is_empty() {
            self.prune(g, t).await;
            return;
        }
        let zones = captive::zones(&self.store).await.unwrap_or_default();
        let mut seen_cache: std::collections::HashMap<String, Option<HashSet<String>>> =
            std::collections::HashMap::new();
        for s in active {
            let last_interim = s.ended.unwrap_or(0);
            let z = zones.iter().find(|z| z.name == s.zone && z.enabled);
            if s.end_reason.as_deref() == Some("admin") {
                self.end(
                    s.id,
                    "disconnected by an administrator",
                    radius::cause::ADMIN_RESET,
                )
                .await;
                continue;
            }
            let Some(z) = z else {
                self.end(s.id, "zone switched off", radius::cause::NAS_REQUEST)
                    .await;
                continue;
            };
            if s.expires > 0 && s.expires <= t {
                self.end(s.id, "hard timeout", radius::cause::SESSION_TIMEOUT)
                    .await;
                continue;
            }
            if z.idle_minutes > 0 && t - s.started >= 5 {
                let seen = seen_cache
                    .entry(z.name.clone())
                    .or_insert_with(|| self.seen(z));
                if let Some(seen) = seen {
                    if !seen.contains(&format!("{} . {}", s.mac, s.ip)) {
                        self.end(s.id, "idle timeout", radius::cause::IDLE_TIMEOUT)
                            .await;
                        continue;
                    }
                }
            }
            if g.interim_secs > 0 && z.auth == "radius" && t - last_interim >= g.interim_secs {
                let _ = sqlx::query("UPDATE cp_sessions SET last_interim = ? WHERE id = ?")
                    .bind(t)
                    .bind(s.id)
                    .execute(pool)
                    .await;
                let mut s2 = s.clone();
                s2.ended = None;
                self.account(z, &s2, radius::Acct::Interim, None, t);
            }
        }
        self.prune(g, t).await;
    }

    async fn prune(&self, g: &Globals, t: i64) {
        // cheap enough to run every pass: two indexed deletes
        let Ok(pool) = self.store.pool() else { return };
        let cutoff = t - g.retention_days * 86400;
        let _ = sqlx::query("DELETE FROM cp_sessions WHERE ended IS NOT NULL AND ended < ?")
            .bind(cutoff)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM cp_voucher_use WHERE expires < ?")
            .bind(cutoff)
            .execute(pool)
            .await;
    }

    /// After a restart: put the bandwidth classes of live sessions back (the
    /// kernel lost them on a reboot; the nft elements come back with the applier).
    pub async fn restore(&self) {
        for s in self.sessions(0).await {
            self.shape(&s);
        }
    }
}

/// Elements of `nft -j list set` for an `ether_addr . ipv4_addr` set, as `mac . ip`.
pub fn parse_concat_elems(json: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
    fn walk(v: &serde_json::Value, out: &mut HashSet<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(serde_json::Value::Array(parts)) = m.get("concat") {
                    let p: Vec<String> = parts
                        .iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect();
                    if p.len() == 2 {
                        out.insert(format!("{} . {}", p[0].to_ascii_lowercase(), p[1]));
                    }
                    return;
                }
                for x in m.values() {
                    walk(x, out);
                }
            }
            serde_json::Value::Array(a) => {
                for x in a {
                    walk(x, out);
                }
            }
            _ => {}
        }
    }
    walk(&v, &mut out);
    out
}

/// A fixed argon2 hash (same cost as real ones) checked for unknown users.
const DECOY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$VKrBy3sP0e2sNfeD9ZBbaQOz2hO+pVPwRjvW3HDQ5r0";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Rec {
        cmds: Mutex<Vec<String>>,
        seen_json: Mutex<String>,
    }

    impl Sys for Rec {
        fn run(&self, argv: &[&str]) -> Result<String, String> {
            self.cmds.lock().unwrap().push(argv.join(" "));
            if argv.first() == Some(&"nft") && argv.get(1) == Some(&"-j") {
                return Ok(self.seen_json.lock().unwrap().clone());
            }
            Ok(String::new())
        }
        fn nft(&self, script: &str) -> Result<(), String> {
            self.cmds
                .lock()
                .unwrap()
                .push(format!("nft: {}", script.trim()));
            Ok(())
        }
        fn neigh_mac(&self, ip: Ipv4Addr) -> Option<String> {
            Some(format!("02:00:00:00:00:{:02x}", ip.octets()[3]))
        }
        fn addrs(&self) -> Vec<IfAddr> {
            vec![IfAddr {
                ifname: "eth1".into(),
                addr: "10.1.0.1".parse().unwrap(),
                prefix: 24,
            }]
        }
    }

    async fn setup(auth: &str, extra: &str) -> (Portal, Arc<Rec>) {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        store.set_interface_role("eth1", Some("lan")).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO cp_zones (name, enabled, interface, auth, idle_minutes, hard_minutes, \
             download_kbit, upload_kbit, terms_required{}, updated_at) VALUES ('lobby', 1, '@lan', ?, 10, 60, 2000, 500, 1{}, 0)",
            if extra.is_empty() { "" } else { ", max_sessions" },
            if extra.is_empty() { "" } else { ", 1" }
        ))
        .bind(auth)
        .execute(store.pool().unwrap())
        .await
        .unwrap();
        let rec = Arc::new(Rec::default());
        (Portal::new(store, rec.clone()), rec)
    }

    #[tokio::test]
    async fn click_through_needs_the_terms_then_admits_and_shapes() {
        let (p, rec) = setup("none", "").await;
        let c = p
            .client("10.1.0.20".parse().unwrap())
            .await
            .expect("zone by subnet");
        assert_eq!(c.mac, "02:00:00:00:00:14");
        assert!(p.client("192.0.2.1".parse().unwrap()).await.is_none());
        assert_eq!(
            p.login(&c, &LoginForm::default()).await.unwrap_err(),
            Refused::Terms
        );
        let s = p
            .login(
                &c,
                &LoginForm {
                    terms: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(s.expires > now() + 3500 && s.expires <= now() + 3600);
        let cmds = rec.cmds.lock().unwrap().join("\n");
        assert!(
            cmds.contains(
                "add element inet patronus_portal z1_auth { 02:00:00:00:00:14 . 10.1.0.20 timeout"
            ),
            "{cmds}"
        );
        assert!(cmds.contains("z1_seen { 02:00:00:00:00:14 . 10.1.0.20 }"));
        assert!(cmds.contains("htb rate 2000kbit ceil 2000kbit"));
        assert!(cmds.contains("match ip src 10.1.0.20/32 police rate 500kbit burst 70000b"));
        // signing in again is the same session
        assert_eq!(p.login(&c, &LoginForm::default()).await.unwrap().id, s.id);
        assert!(p.end(s.id, "test", 1).await);
        assert!(!p.end(s.id, "test", 1).await, "idempotent");
        let cmds = rec.cmds.lock().unwrap().join("\n");
        assert!(cmds.contains(
            "delete element inet patronus_portal z1_auth { 02:00:00:00:00:14 . 10.1.0.20 }"
        ));
        assert!(cmds.contains("conntrack -D -s 10.1.0.20 -p tcp --dport 80"));
        assert!(p.active(&c).await.is_none());
    }

    #[tokio::test]
    async fn local_users_and_vouchers() {
        let (p, _rec) = setup("local", "").await;
        let h = captive::hash_password("correct horse").unwrap();
        sqlx::query("INSERT INTO cp_users (username, password, zone, enabled, updated_at) VALUES ('ann', ?, '', 1, 0)")
            .bind(&h)
            .execute(p.store.pool().unwrap())
            .await
            .unwrap();
        let c = p.client("10.1.0.21".parse().unwrap()).await.unwrap();
        let f = |u: &str, pw: &str| LoginForm {
            username: u.into(),
            password: pw.into(),
            terms: true,
            ..Default::default()
        };
        assert_eq!(
            p.login(&c, &f("ann", "wrong")).await.unwrap_err(),
            Refused::Credentials
        );
        assert_eq!(
            p.login(&c, &f("bob", "correct horse")).await.unwrap_err(),
            Refused::Credentials
        );
        assert_eq!(
            p.login(&c, &f("ann", "correct horse"))
                .await
                .unwrap()
                .username,
            "ann"
        );

        let (p, _rec) = setup("voucher", "").await;
        let pool = p.store.pool().unwrap();
        sqlx::query("INSERT INTO cp_voucher_rolls (id, name, zone, count, minutes, updated_at) VALUES (1, 'r1', 'lobby', 1, 30, 0)").execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO cp_vouchers (roll_id, code, updated_at) VALUES (1, 'ABCD2345', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        let c = p.client("10.1.0.22".parse().unwrap()).await.unwrap();
        let v = |code: &str| LoginForm {
            voucher: code.into(),
            terms: true,
            ..Default::default()
        };
        assert_eq!(
            p.login(&c, &v("nope")).await.unwrap_err(),
            Refused::Credentials
        );
        let s = p.login(&c, &v("abcd-2345")).await.unwrap();
        assert!(
            s.expires <= now() + 1800,
            "the voucher's 30 minutes cap the zone's hour"
        );
        sqlx::query("UPDATE cp_voucher_use SET expires = 1")
            .execute(pool)
            .await
            .unwrap();
        p.end(s.id, "t", 1).await;
        assert_eq!(
            p.login(&c, &v("ABCD2345")).await.unwrap_err(),
            Refused::VoucherExpired
        );
    }

    #[tokio::test]
    async fn tick_ends_admin_hard_and_idle_sessions() {
        let (p, rec) = setup("none", "").await;
        let pool = p.store.pool().unwrap();
        let yes = LoginForm {
            terms: true,
            ..Default::default()
        };
        let mut ids = Vec::new();
        for ip in ["10.1.0.30", "10.1.0.31", "10.1.0.32", "10.1.0.33"] {
            let c = p.client(ip.parse().unwrap()).await.unwrap();
            ids.push(p.login(&c, &yes).await.unwrap().id);
        }
        sqlx::query("UPDATE cp_sessions SET started = started - 60")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE cp_sessions SET disconnect_req = 1 WHERE id = ?")
            .bind(ids[0])
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE cp_sessions SET expires = 5 WHERE id = ?")
            .bind(ids[1])
            .execute(pool)
            .await
            .unwrap();
        // .32 and .33 are in the seen set, .31 too; .30 is gone but admin wins
        *rec.seen_json.lock().unwrap() = r#"{"nftables":[{"set":{"elem":[{"elem":{"val":{"concat":["02:00:00:00:00:1f","10.1.0.31"]},"timeout":600}},{"concat":["02:00:00:00:00:20","10.1.0.32"]}]}}]}"#.into();
        p.tick(&p.globals().await).await;
        let reasons: Vec<(i64, Option<String>)> =
            sqlx::query("SELECT id, end_reason FROM cp_sessions ORDER BY id")
                .fetch_all(pool)
                .await
                .unwrap()
                .iter()
                .map(|r| (r.get(0), r.get(1)))
                .collect();
        assert_eq!(
            reasons[0].1.as_deref(),
            Some("disconnected by an administrator")
        );
        assert_eq!(reasons[1].1.as_deref(), Some("hard timeout"));
        assert_eq!(reasons[2].1, None, "active and seen");
        assert_eq!(reasons[3].1.as_deref(), Some("idle timeout"));
        // switching the zone off ends the rest
        sqlx::query("UPDATE cp_zones SET enabled = 0")
            .execute(pool)
            .await
            .unwrap();
        p.tick(&p.globals().await).await;
        assert!(p.sessions(0).await.is_empty());
    }

    #[tokio::test]
    async fn max_sessions_per_voucher() {
        let (p, _rec) = setup("voucher", "max").await;
        let pool = p.store.pool().unwrap();
        sqlx::query("INSERT INTO cp_voucher_rolls (id, name, zone, count, minutes, updated_at) VALUES (1, 'r1', 'lobby', 1, 30, 0)").execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO cp_vouchers (roll_id, code, updated_at) VALUES (1, 'ZZZZ2222', 0)",
        )
        .execute(pool)
        .await
        .unwrap();
        let v = LoginForm {
            voucher: "ZZZZ2222".into(),
            terms: true,
            ..Default::default()
        };
        let a = p.client("10.1.0.40".parse().unwrap()).await.unwrap();
        let b = p.client("10.1.0.41".parse().unwrap()).await.unwrap();
        p.login(&a, &v).await.unwrap();
        assert_eq!(p.login(&b, &v).await.unwrap_err(), Refused::TooManyDevices);
    }

    #[test]
    fn arp_and_tc_helpers() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 10.1.0.5         0x1         0x2         02:AA:00:00:00:05     *        eth1\n\
                 10.1.0.6         0x1         0x0         00:00:00:00:00:00     *        eth1\n";
        assert_eq!(
            parse_arp(t, "10.1.0.5".parse().unwrap()).as_deref(),
            Some("02:aa:00:00:00:05")
        );
        assert_eq!(parse_arp(t, "10.1.0.6".parse().unwrap()), None);
        assert_eq!(tc_minor(1), 0x11);
        assert_eq!(tc_minor(0xfff0), 0x10);
        assert!(!captive::verify_password("x", DECOY));
    }
}
