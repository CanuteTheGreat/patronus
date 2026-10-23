//! NAT64 / DNS64 (USE=nat64): lets IPv6-only clients reach IPv4-only servers.
//!
//! - NAT64: `tayga` (userspace stateless-ish translator on a TUN device
//!   `nat64`). Patronus creates the device, brings it up, routes the NAT64
//!   prefix (default `64:ff9b::/96`) and the IPv4 translation pool into it and
//!   runs tayga through the supervisor (`patronus-daemon@tayga`). The firewall
//!   forwards the clients' traffic to the prefix, forwards the translated
//!   IPv4 out of the WAN and masquerades the pool
//!   (`patronus_firewall::svc_rules`).
//! - DNS64: Unbound synthesizes AAAA records from A records inside the NAT64
//!   prefix (`dns64` module; the DNS applier reads `nat64.dns64`).
//!
//! Only /96 prefixes are accepted (the form every DNS64 client expects).

use crate::lan::{self, invalid};
use crate::supervise::{which, Supervisor};
use crate::svc::{self, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const DEV: &str = "nat64";
pub const INSTANCE: &str = "tayga";
/// The router's own addresses on the TUN device (outside every pool).
const DEV_V4: &str = "169.254.64.1";
const DEV_V6: &str = "fd64:6464::1";
const TAYGA_V6: &str = "fd64:6464::2";

static FIELDS: [Field; 6] = [
    Field::new("enabled", "NAT64", Kind::Bool).def("0"),
    Field::new("prefix", "NAT64 prefix", Kind::Cidr6)
        .def("64:ff9b::/96")
        .help("IPv6 addresses inside it map to IPv4 (must be a /96). The well-known 64:ff9b::/96 only translates public IPv4 addresses; use a /96 of your own IPv6 space to reach private ones"),
    Field::new("pool", "IPv4 translation pool", Kind::Cidr4)
        .def("192.168.255.0/24")
        .help("private addresses the translator uses; masqueraded to the WAN address"),
    Field::new("clients", "IPv6-only clients on", Kind::Iface)
        .def("@lan")
        .help("interface whose clients may use the NAT64 gateway"),
    Field::new("dns64", "DNS64 in Unbound", Kind::Bool)
        .def("1")
        .help("synthesize AAAA records for IPv4-only names (needs the Unbound resolver)"),
    Field::new("description", "Note", Kind::Text),
];

static SPEC: Spec = Spec {
    slug: "nat64",
    title: "NAT64 / DNS64",
    blurb: "Let IPv6-only clients reach IPv4-only servers. tayga translates packets sent to the \
            NAT64 prefix; Unbound's DNS64 answers AAAA queries for IPv4-only names with addresses \
            in that prefix.",
    applier: "nat64",
    fields: &FIELDS,
    colls: &[],
    actions: &[],
};

pub struct Nat64Svc;

#[async_trait]
impl Svc for Nat64Svc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        // refuse bad prefixes before they are stored
        if let Some(p) = body.get("prefix").and_then(Value::as_str) {
            if !p.trim().is_empty() {
                check_prefix(p)?;
            }
        }
        svc::put_settings(store, &SPEC, body).await
    }
}

pub fn check_prefix(p: &str) -> Result<()> {
    let n: ipnetwork::IpNetwork = p
        .trim()
        .parse()
        .map_err(|_| invalid(format!("NAT64 prefix {p:?}")))?;
    if n.is_ipv6() && n.prefix() == 96 {
        Ok(())
    } else {
        Err(invalid(format!("NAT64 prefix {p:?} (an IPv6 /96)")))
    }
}

/// First usable address of an IPv4 pool.
pub fn tayga_v4(pool: &str) -> Result<String> {
    let n: ipnetwork::Ipv4Network = pool
        .parse()
        .map_err(|_| invalid(format!("NAT64 pool {pool:?}")))?;
    if n.prefix() > 28 {
        return Err(invalid(format!("NAT64 pool {pool:?} (at least a /28)")));
    }
    Ok(std::net::Ipv4Addr::from(u32::from(n.network()) + 1).to_string())
}

pub fn render(prefix: &str, pool: &str, data_dir: &str) -> Result<String> {
    check_prefix(prefix)?;
    let mut c = lan::header("#", "tayga NAT64");
    c.push_str(&format!(
        "tun-device {DEV}\nipv4-addr {}\nipv6-addr {TAYGA_V6}\nprefix {prefix}\ndynamic-pool {pool}\ndata-dir {data_dir}\n",
        tayga_v4(pool)?
    ));
    Ok(c)
}

fn ip(args: &[&str]) -> Result<String> {
    let o = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| Error::Network(format!("ip: {e}")))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(Error::Network(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        )))
    }
}

fn dev_exists() -> bool {
    std::path::Path::new(&format!("/sys/class/net/{DEV}")).exists()
}

#[derive(Clone)]
pub struct Nat64Applier {
    sup: Supervisor,
    /// Touch the kernel (devices, routes, sysctls). False in unit tests.
    live: bool,
}

impl Default for Nat64Applier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            live: true,
        }
    }
}

impl Nat64Applier {
    pub fn with_supervisor(sup: Supervisor, live: bool) -> Self {
        Self { sup, live }
    }

    fn data_dir(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("tayga")
    }

    fn conf(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("tayga.conf")
    }

    fn teardown(&self) {
        if self.live && dev_exists() {
            let _ = ip(&["link", "del", DEV]);
        }
    }
}

fn write_sysctl(path: &str, v: &str) {
    let _ = std::fs::write(path, v);
}

#[async_trait]
impl Applier for Nat64Applier {
    fn name(&self) -> &'static str {
        "nat64"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            if was || (self.live && dev_exists() && self.conf().exists()) {
                self.teardown();
                rep.applied("NAT64 stopped and its device removed");
            } else {
                rep.applied("NAT64 is off");
            }
            return Ok(rep);
        }
        let (prefix, pool) = (s.s("prefix"), s.s("pool"));
        let data = self.data_dir();
        let conf_text = render(&prefix, &pool, &data.to_string_lossy())?;
        let bin = which("tayga").ok_or_else(|| {
            Error::Service(
                "NAT64 needs tayga, which is not installed (emerge net-proxy/tayga, USE=nat64)"
                    .into(),
            )
        })?;
        if s.b("dns64") {
            let dns = lan::setting_or(store, "dns.mode", "auto").await?;
            if dns == "forwarder" {
                rep.warn("DNS64 needs the Unbound resolver; the DNS page is set to the dnsmasq forwarder");
            }
        }
        let conf = self.conf();
        std::fs::create_dir_all(&data)
            .map_err(|e| Error::Service(format!("{}: {e}", data.display())))?;
        let changed = crate::supervise::write_atomic(&conf, &conf_text, 0o644)?;
        if self.live {
            if changed && dev_exists() {
                // address/prefix changed: rebuild the device cleanly
                let _ = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await;
                self.teardown();
            }
            if !dev_exists() {
                let o = std::process::Command::new(&bin)
                    .args(["-c", &conf.to_string_lossy(), "--mktun"])
                    .output()
                    .map_err(|e| Error::Service(format!("tayga --mktun: {e}")))?;
                if !o.status.success() {
                    return Err(Error::Service(format!(
                        "tayga --mktun failed (is /dev/net/tun available?): {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    )));
                }
            }
            ip(&["link", "set", DEV, "up"])?;
            ip(&["addr", "replace", &format!("{DEV_V4}/32"), "dev", DEV])?;
            ip(&[
                "-6",
                "addr",
                "replace",
                &format!("{DEV_V6}/128"),
                "dev",
                DEV,
            ])?;
            ip(&["route", "replace", &pool, "dev", DEV])?;
            ip(&["-6", "route", "replace", &prefix, "dev", DEV])?;
            // the box forwards IPv6 now: keep router advertisements on the WAN
            for w in lan::resolve_iface(store, "@wan").await? {
                write_sysctl(&format!("/proc/sys/net/ipv6/conf/{w}/accept_ra"), "2");
            }
            write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
            write_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
            rep.applied(format!(
                "device {DEV} up, {prefix} and {pool} routed into it"
            ));
        }
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            vec![
                bin.to_string_lossy().into(),
                "-c".into(),
                conf.to_string_lossy().into(),
                "--nodetach".into(),
            ],
            vec![],
        )
        .await?;
        rep.applied(format!(
            "tayga {} (prefix {prefix}, pool {pool})",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            }
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = Settings::load(store, &SPEC).await?;
        if !s.b("enabled") {
            return Ok("# NAT64 off\n".into());
        }
        Ok(format!(
            "## tayga.conf\n{}",
            render(
                &s.s("prefix"),
                &s.s("pool"),
                &self.data_dir().to_string_lossy()
            )?
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "installed": which("tayga").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "device": dev_exists(),
            "prefix": s.s("prefix"),
            "pool": s.s("pool"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn config_for_the_default_prefix_and_pool() {
        let c = render(
            "64:ff9b::/96",
            "192.168.255.0/24",
            "/var/lib/patronus/net/tayga",
        )
        .unwrap();
        for want in [
            "tun-device nat64",
            "ipv4-addr 192.168.255.1",
            "prefix 64:ff9b::/96",
            "dynamic-pool 192.168.255.0/24",
            "data-dir /var/lib/patronus/net/tayga",
        ] {
            assert!(c.contains(want), "missing {want}: {c}");
        }
        assert!(render("64:ff9b::/64", "192.168.255.0/24", "/x").is_err());
        assert!(render("64:ff9b::/96", "192.168.255.0/30", "/x").is_err());
    }

    #[tokio::test]
    async fn settings_are_validated_and_apply_needs_tayga() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = Nat64Applier::with_supervisor(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            false,
        );
        a.apply(&s).await.unwrap();
        for bad in [
            json!({"prefix": "10.0.0.0/8"}),
            json!({"pool": "fd00::/64"}),
            json!({"clients": "lan;x"}),
        ] {
            assert!(Nat64Svc.put(&s, &bad).await.is_err(), "{bad}");
        }
        assert!(Nat64Svc
            .put(&s, &json!({"prefix": "2001:db8::/64"}))
            .await
            .is_err());
        Nat64Svc.put(&s, &json!({"enabled": true})).await.unwrap();
        if which("tayga").is_none() {
            let e = a.apply(&s).await.unwrap_err();
            assert!(e.to_string().contains("tayga"), "{e}");
        }
        assert!(a.render(&s).await.unwrap().contains("prefix 64:ff9b::/96"));
        // DNS64 is switched on for the resolver
        #[cfg(feature = "dns")]
        {
            let dns = crate::dns::settings(&s).await.unwrap();
            assert_eq!(dns.dns64_prefix.as_deref(), Some("64:ff9b::/96"));
            Nat64Svc.put(&s, &json!({"dns64": false})).await.unwrap();
            assert_eq!(crate::dns::settings(&s).await.unwrap().dns64_prefix, None);
        }
    }
}
