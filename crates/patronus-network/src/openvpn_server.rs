//! OpenVPN server with client profile export (USE=openvpn).
//!
//! Remote-access VPN: `openvpn` runs through the supervisor with a generated
//! server config (tun device `pat-ovpn`, tls-crypt, AES-256-GCM, EC P-256
//! certificates). The PKI is created on first use and kept in the config
//! store (backups include it). Each client row is a certificate; its
//! `.ovpn` profile (CA, certificate, key and tls-crypt key inline) is
//! exported on request. Disabling or deleting a client takes effect at once:
//! its client-config-dir entry says `disable`, which OpenVPN enforces at
//! connect time, and the daemon restarts so current sessions end.

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

pub const INSTANCE: &str = "openvpn-server";
pub const DEV: &str = "pat-ovpn";

static FIELDS: [Field; 7] = [
    Field::new("enabled", "OpenVPN server", Kind::Bool).def("0"),
    Field::new("interface", "Listen on", Kind::Iface)
        .def("@wan")
        .help("the server port is opened on this interface"),
    Field::new("proto", "Protocol", Kind::Select(&["udp", "tcp"])).def("udp"),
    Field::new("port", "Port", Kind::Int(1, 65535)).def("1194"),
    Field::new("tunnel_net", "Client address pool", Kind::Cidr4).def("10.8.0.0/24"),
    Field::new("public_host", "Address clients connect to", Kind::Host)
        .help("DNS name or IP written into the client profiles (your WAN address or dynamic DNS name)"),
    Field::new("lan_route", "Network behind this firewall", Kind::Cidr4)
        .help("optional: pushed to clients so they reach it (e.g. 192.168.1.0/24); clients may then reach the LAN"),
];

static CLIENT_FIELDS: [Field; 2] = [
    Field::new("name", "Client name", Kind::Token).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: "openvpn",
    title: "OpenVPN server",
    blurb: "Remote-access VPN for laptops and phones. Add a client, then download its .ovpn profile \
            (certificate and keys inline) and import it into any OpenVPN client. Disabling a client \
            ends its session and blocks it.",
    applier: "openvpn",
    fields: &FIELDS,
    colls: &[Coll {
        key: "clients",
        title: "Clients",
        table: "openvpn_clients",
        fields: &CLIENT_FIELDS,
        unique: Some("name"),
    }],
    actions: &[],
};

pub struct OpenVpnSvc;

#[async_trait]
impl Svc for OpenVpnSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

// ---- PKI ------------------------------------------------------------------

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd
        .output()
        .map_err(|e| Error::Service(format!("OpenVPN PKI ({what}): {e}")))?;
    if !out.status.success() {
        return Err(Error::Service(format!(
            "OpenVPN PKI ({what}): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// A key + certificate signed by the CA in `dir` (EKU `serverAuth` or `clientAuth`).
fn issue(dir: &Path, cn: &str, eku: &str) -> Result<(String, String)> {
    let (key, csr, crt, ext) = (
        dir.join(format!("{cn}.key")),
        dir.join(format!("{cn}.csr")),
        dir.join(format!("{cn}.crt")),
        dir.join(format!("{cn}.ext")),
    );
    run(
        Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key),
        "key",
    )?;
    run(
        Command::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", &format!("/CN={cn}"), "-out"])
            .arg(&csr),
        "request",
    )?;
    std::fs::write(&ext, format!("basicConstraints=CA:FALSE\nextendedKeyUsage={eku}\nkeyUsage=digitalSignature,keyAgreement\n"))
        .map_err(|e| Error::Service(format!("{}: {e}", ext.display())))?;
    run(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "3650", "-in"])
            .arg(&csr)
            .args(["-CA"])
            .arg(dir.join("ca.crt"))
            .args(["-CAkey"])
            .arg(dir.join("ca.key"))
            .args(["-CAcreateserial", "-extfile"])
            .arg(&ext)
            .args(["-out"])
            .arg(&crt),
        "sign",
    )?;
    let rd = |p: &Path| {
        std::fs::read_to_string(p).map_err(|e| Error::Service(format!("{}: {e}", p.display())))
    };
    Ok((rd(&crt)?, rd(&key)?))
}

async fn pki_get(store: &ConfigStore, name: &str) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT pem FROM openvpn_pki WHERE name = ?")
        .bind(name)
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read PKI: {e}")))
}

async fn pki_put(store: &ConfigStore, name: &str, pem: &str) -> Result<()> {
    sqlx::query("INSERT OR REPLACE INTO openvpn_pki (name, pem) VALUES (?, ?)")
        .bind(name)
        .bind(pem)
        .execute(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("store PKI: {e}")))?;
    Ok(())
}

async fn client_names(store: &ConfigStore) -> Result<Vec<(String, bool)>> {
    Ok(svc::raw_rows(store, &SPEC.colls[0])
        .await?
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or("").to_string(),
                lan::flag(r["enabled"].as_str().unwrap_or("")),
            )
        })
        .collect())
}

/// Create whatever PKI material is missing: CA, server certificate,
/// tls-crypt key and one certificate per client.
pub async fn ensure_pki(store: &ConfigStore) -> Result<()> {
    if which("openssl").is_none() || which("openvpn").is_none() {
        return Err(Error::Service(
            "the OpenVPN server needs openssl and openvpn (emerge net-vpn/openvpn, USE=openvpn)"
                .into(),
        ));
    }
    let clients = client_names(store).await?;
    let missing_client = {
        let mut m = false;
        for (n, _) in &clients {
            if pki_get(store, &format!("client:{n}:crt")).await?.is_none() {
                m = true;
            }
        }
        m
    };
    let need_base = pki_get(store, "ca.crt").await?.is_none()
        || pki_get(store, "server.crt").await?.is_none()
        || pki_get(store, "tls-crypt.key").await?.is_none();
    if !need_base && !missing_client {
        return Ok(());
    }
    let tmp = std::env::temp_dir().join(format!(".patronus-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .map_err(|e| Error::Service(format!("{}: {e}", tmp.display())))?;
    }
    let res = async {
        // bring the existing CA back to disk (or make one)
        if let (Some(crt), Some(key)) = (
            pki_get(store, "ca.crt").await?,
            pki_get(store, "ca.key").await?,
        ) {
            std::fs::write(tmp.join("ca.crt"), crt).ok();
            std::fs::write(tmp.join("ca.key"), key).ok();
        } else {
            run(
                Command::new("openssl")
                    .args([
                        "ecparam",
                        "-name",
                        "prime256v1",
                        "-genkey",
                        "-noout",
                        "-out",
                    ])
                    .arg(tmp.join("ca.key")),
                "CA key",
            )?;
            run(
                Command::new("openssl")
                    .args(["req", "-new", "-x509", "-days", "3650", "-key"])
                    .arg(tmp.join("ca.key"))
                    .args(["-subj", "/CN=Patronus VPN CA", "-out"])
                    .arg(tmp.join("ca.crt")),
                "CA certificate",
            )?;
            for f in ["ca.crt", "ca.key"] {
                pki_put(
                    store,
                    f,
                    &std::fs::read_to_string(tmp.join(f)).unwrap_or_default(),
                )
                .await?;
            }
        }
        if pki_get(store, "server.crt").await?.is_none() {
            let (crt, key) = issue(&tmp, "server", "serverAuth")?;
            pki_put(store, "server.crt", &crt).await?;
            pki_put(store, "server.key", &key).await?;
        }
        if pki_get(store, "tls-crypt.key").await?.is_none() {
            let p = tmp.join("tc.key");
            run(
                Command::new("openvpn").args(["--genkey", "secret"]).arg(&p),
                "tls-crypt key",
            )?;
            pki_put(
                store,
                "tls-crypt.key",
                &std::fs::read_to_string(&p).unwrap_or_default(),
            )
            .await?;
        }
        for (n, _) in &clients {
            if pki_get(store, &format!("client:{n}:crt")).await?.is_none() {
                let (crt, key) = issue(&tmp, n, "clientAuth")?;
                pki_put(store, &format!("client:{n}:crt"), &crt).await?;
                pki_put(store, &format!("client:{n}:key"), &key).await?;
            }
        }
        Ok::<(), Error>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// The `.ovpn` profile of client `name`: everything inline.
pub async fn export_profile(store: &ConfigStore, name: &str) -> Result<String> {
    let s = Settings::load(store, &SPEC).await?;
    let known = client_names(store).await?;
    if !known.iter().any(|(n, _)| n == name) {
        return Err(Error::Config(format!("no such OpenVPN client {name:?}")));
    }
    let host = s.s("public_host");
    if host.is_empty() {
        return Err(invalid(
            "OpenVPN: set \"Address clients connect to\" before exporting a profile",
        ));
    }
    ensure_pki(store).await?;
    let get = |k: String| async move { pki_get(store, &k).await.map(|v| v.unwrap_or_default()) };
    let (ca, crt, key, tc) = (
        get("ca.crt".into()).await?,
        get(format!("client:{name}:crt")).await?,
        get(format!("client:{name}:key")).await?,
        get("tls-crypt.key".into()).await?,
    );
    Ok(render_profile(&s, &host, &ca, &crt, &key, &tc))
}

pub fn render_profile(
    s: &Settings,
    host: &str,
    ca: &str,
    crt: &str,
    key: &str,
    tc: &str,
) -> String {
    let crt = crt
        .split("-----END CERTIFICATE-----")
        .next()
        .map(|c| format!("{c}-----END CERTIFICATE-----\n"))
        .unwrap_or_default();
    format!(
        "# OpenVPN profile generated by Patronus\nclient\ndev tun\nproto {}\nremote {host} {}\nresolv-retry infinite\nnobind\n\
         persist-key\npersist-tun\nremote-cert-tls server\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\nverb 3\n\
         <ca>\n{}</ca>\n<cert>\n{crt}</cert>\n<key>\n{}</key>\n<tls-crypt>\n{}</tls-crypt>\n",
        s.s("proto"),
        s.s("port"),
        ca.trim_end().to_string() + "\n",
        key.trim_end().to_string() + "\n",
        tc.trim_end().to_string() + "\n",
    )
}

// ---- server config ---------------------------------------------------------

pub fn pool(cidr: &str) -> Result<(String, String)> {
    let (ip, len) = cidr
        .split_once('/')
        .ok_or_else(|| invalid("OpenVPN: the client pool is a CIDR like 10.8.0.0/24"))?;
    let len: u32 = len
        .parse()
        .map_err(|_| invalid("OpenVPN: bad pool prefix"))?;
    let ip: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| invalid("OpenVPN: the client pool must be IPv4"))?;
    if !(8..=29).contains(&len) {
        return Err(invalid("OpenVPN: the client pool prefix is 8 to 29"));
    }
    let mask = u32::MAX << (32 - len);
    let net = std::net::Ipv4Addr::from(u32::from(ip) & mask);
    Ok((net.to_string(), std::net::Ipv4Addr::from(mask).to_string()))
}

fn route_line(cidr: &str) -> Option<String> {
    let (n, m) = pool(cidr).ok().or_else(|| {
        // pool() limits the prefix for client pools; routes may be /32../0
        let (ip, len) = cidr.split_once('/')?;
        let len: u32 = len.parse().ok()?;
        let ip: std::net::Ipv4Addr = ip.parse().ok()?;
        let mask = if len == 0 {
            0
        } else {
            u32::MAX << (32 - len.min(32))
        };
        Some((
            std::net::Ipv4Addr::from(u32::from(ip) & mask).to_string(),
            std::net::Ipv4Addr::from(mask).to_string(),
        ))
    })?;
    Some(format!("push \"route {n} {m}\"\n"))
}

pub fn render_server(s: &Settings, dir: &str, ccd: &str) -> Result<String> {
    let (net, mask) = pool(&s.s("tunnel_net"))?;
    let mut c = lan::header("#", "openvpn server");
    c.push_str(&format!(
        "dev {DEV}\ndev-type tun\nproto {}\nport {}\nserver {net} {mask}\ntopology subnet\n\
         ca {dir}/ca.crt\ncert {dir}/server.crt\nkey {dir}/server.key\ndh none\ntls-crypt {dir}/tls-crypt.key\n\
         remote-cert-tls client\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\ndata-ciphers-fallback AES-256-GCM\n\
         keepalive 10 60\npersist-key\npersist-tun\nclient-config-dir {ccd}\nstatus {dir}/status.log 5\nverb 3\n",
        s.s("proto"),
        s.s("port")
    ));
    if let Some(r) = Some(s.s("lan_route"))
        .filter(|r| !r.is_empty())
        .and_then(|r| route_line(&r))
    {
        c.push_str(&r);
    }
    Ok(c)
}

#[derive(Clone)]
pub struct OpenVpnApplier {
    sup: Supervisor,
}

impl Default for OpenVpnApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
        }
    }
}

impl OpenVpnApplier {
    pub fn with_supervisor(sup: Supervisor) -> Self {
        Self { sup }
    }
}

#[async_trait]
impl Applier for OpenVpnApplier {
    fn name(&self) -> &'static str {
        "openvpn"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            rep.applied(if was {
                "OpenVPN server stopped"
            } else {
                "OpenVPN server is off"
            });
            return Ok(rep);
        }
        pool(&s.s("tunnel_net"))?;
        ensure_pki(store).await?;
        let bin =
            which("openvpn").ok_or_else(|| Error::Service("openvpn is not installed".into()))?;
        let dir = self.sup.paths.state_dir.join("openvpn");
        let ccd = dir.join("ccd");
        std::fs::create_dir_all(&ccd)
            .map_err(|e| Error::Service(format!("{}: {e}", ccd.display())))?;
        let mut files: Vec<(std::path::PathBuf, String, u32)> = Vec::new();
        for (name, secret) in [
            ("ca.crt", false),
            ("server.crt", false),
            ("server.key", true),
            ("tls-crypt.key", true),
        ] {
            let pem = pki_get(store, name).await?.unwrap_or_default();
            files.push((dir.join(name), pem, if secret { 0o600 } else { 0o644 }));
        }
        let clients = client_names(store).await?;
        // clients that were deleted stay blocked (their certificate is still valid)
        let mut known: Vec<String> = clients.iter().map(|(n, _)| n.clone()).collect();
        for e in std::fs::read_dir(&ccd).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if !known.contains(&n) {
                files.push((ccd.join(&n), "disable\n".into(), 0o644));
                known.push(n);
            }
        }
        for (n, on) in &clients {
            files.push((
                ccd.join(n),
                if *on {
                    "# enabled\n".into()
                } else {
                    "disable\n".into()
                },
                0o644,
            ));
        }
        let conf = dir.join("server.conf");
        files.push((
            conf.clone(),
            render_server(&s, &dir.to_string_lossy(), &ccd.to_string_lossy())?,
            0o644,
        ));
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "--config".into(),
                conf.to_string_lossy().into(),
            ],
            files,
        )
        .await?;
        rep.applied(format!(
            "openvpn {} on {}/{} ({} client(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            s.s("proto"),
            s.s("port"),
            clients.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# OpenVPN server off\n".into());
        }
        render_server(&s, "<state>/openvpn", "<state>/openvpn/ccd")
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let status = self.sup.paths.state_dir.join("openvpn/status.log");
        let connected: Vec<String> = std::fs::read_to_string(status)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                l.strip_prefix("CLIENT_LIST,")
                    .map(|r| r.split(',').next().unwrap_or("").to_string())
            })
            .filter(|n| !n.is_empty() && n != "Common Name")
            .collect();
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("openvpn").is_some() && which("openssl").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "connected_clients": connected,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let mut m = serde_json::Map::new();
        for (k, v) in pairs {
            m.insert((*k).into(), json!(v));
        }
        Settings(m)
    }

    #[test]
    fn pool_and_server_config() {
        assert_eq!(
            pool("10.8.0.7/24").unwrap(),
            ("10.8.0.0".into(), "255.255.255.0".into())
        );
        assert!(pool("10.8.0.0/31").is_err() && pool("nope").is_err());
        let s = settings(&[
            ("proto", "tcp"),
            ("port", "443"),
            ("tunnel_net", "10.9.0.0/24"),
            ("lan_route", "192.168.1.0/24"),
        ]);
        let c = render_server(&s, "/d", "/d/ccd").unwrap();
        assert!(
            c.contains("dev pat-ovpn\n")
                && c.contains("proto tcp\nport 443\nserver 10.9.0.0 255.255.255.0\n")
        );
        assert!(c.contains("tls-crypt /d/tls-crypt.key") && c.contains("client-config-dir /d/ccd"));
        assert!(c.contains("push \"route 192.168.1.0 255.255.255.0\""));
    }

    #[test]
    fn profile_has_everything_inline() {
        let s = settings(&[("proto", "udp"), ("port", "1194")]);
        let p = render_profile(
            &s,
            "vpn.example.net",
            "CA\n",
            "CRT\n-----END CERTIFICATE-----\nextra",
            "KEY\n",
            "TC\n",
        );
        assert!(p.contains("remote vpn.example.net 1194\n"));
        for tag in [
            "<ca>\nCA\n</ca>",
            "<key>\nKEY\n</key>",
            "<tls-crypt>\nTC\n</tls-crypt>",
        ] {
            assert!(p.contains(tag), "{tag}");
        }
        assert!(
            p.contains("<cert>\nCRT\n-----END CERTIFICATE-----\n</cert>") && !p.contains("extra")
        );
    }
}
