//! NTP server (lane D): chrony serving time to the LAN.
//!
//! With `ntp.enabled=1` Patronus owns `/etc/chrony/chrony.conf` (the file
//! Gentoo's `chronyd` OpenRC script and systemd unit read; the old module
//! wrote it but was never compiled, and installed its own systemd unit):
//! upstream servers from `ntp.servers`, `allow` lines for the subnets of
//! `ntp.interfaces` (default `@lan`), and `local stratum 10` so clients
//! keep getting time while the upstreams are unreachable. Turning the
//! server off keeps chrony as a client with the same upstreams (the box
//! still needs a correct clock) and drops the `allow` lines. Patronus never
//! touches a chrony.conf it has not written unless the server is enabled.

use crate::lan::{self, invalid, LanEnv, ManagedFile};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const CHRONY_CONF: &str = "/etc/chrony/chrony.conf";
pub const CHRONYD_BIN: &str = "/usr/sbin/chronyd";
pub const SERVICE: &str = "chronyd";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NtpSettings {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NtpInput {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub servers: Option<String>,
    #[serde(default)]
    pub interfaces: Option<String>,
}

fn split(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

fn check_server(s: &str) -> Result<String> {
    if s.parse::<std::net::IpAddr>().is_ok() || lan::valid_dns_name(s, false) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(invalid(format!("NTP server {s:?}")))
    }
}

pub async fn settings(store: &ConfigStore) -> Result<NtpSettings> {
    Ok(NtpSettings {
        enabled: lan::flag(&lan::setting_or(store, "ntp.enabled", "0").await?),
        servers: split(&lan::setting_or(store, "ntp.servers", "pool.ntp.org").await?),
        interfaces: split(&lan::setting_or(store, "ntp.interfaces", "@lan").await?),
    })
}

pub async fn save_settings(store: &ConfigStore, i: &NtpInput) -> Result<()> {
    let mut kv = Vec::new();
    if let Some(e) = i.enabled {
        kv.push(("ntp.enabled", if e { "1" } else { "0" }.to_string()));
    }
    if let Some(s) = &i.servers {
        let v = split(s)
            .iter()
            .map(|x| check_server(x))
            .collect::<Result<Vec<_>>>()?;
        if v.is_empty() {
            return Err(invalid("NTP servers: at least one upstream server"));
        }
        kv.push(("ntp.servers", v.join(",")));
    }
    if let Some(s) = &i.interfaces {
        let v = split(s)
            .iter()
            .map(|x| lan::check_iface_spec(x))
            .collect::<Result<Vec<_>>>()?;
        kv.push(("ntp.interfaces", v.join(",")));
    }
    for (k, v) in kv {
        lan::set_setting(store, k, &v).await?;
    }
    Ok(())
}

/// `/etc/chrony/chrony.conf`.
pub fn render(s: &NtpSettings, allow: &[String]) -> String {
    let mut c = lan::header("#", "chrony: NTP client and LAN time server");
    for sv in &s.servers {
        let kind = if sv.starts_with("pool.") || sv.contains(".pool.") {
            "pool"
        } else {
            "server"
        };
        c.push_str(&format!("{kind} {sv} iburst\n"));
    }
    c.push_str("driftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\n");
    if s.enabled {
        for n in allow {
            c.push_str(&format!("allow {n}\n"));
        }
        c.push_str(
            "# keep serving the LAN while the upstreams are unreachable\nlocal stratum 10\n",
        );
    }
    c
}

#[derive(Clone, Default)]
pub struct NtpApplier {
    env: LanEnv,
}

impl NtpApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    async fn allow(
        &self,
        store: &ConfigStore,
        s: &NtpSettings,
        rep: &mut ApplyReport,
    ) -> Result<Vec<String>> {
        let addrs = self.env.addrs()?;
        let mut nets = Vec::new();
        for spec in &s.interfaces {
            let devs = lan::resolve_iface(store, spec).await?;
            if devs.is_empty() {
                rep.warn(format!(
                    "NTP on {spec}: interface role is not assigned, skipped"
                ));
            }
            for a in addrs.iter().filter(|a| devs.contains(&a.ifname)) {
                if a.addr.is_ipv4() || a.is_global_v6() {
                    if let Some(n) = a.network() {
                        nets.push(n.to_string());
                    }
                }
            }
        }
        nets.sort();
        nets.dedup();
        Ok(nets)
    }
}

#[async_trait]
impl Applier for NtpApplier {
    fn name(&self) -> &'static str {
        "ntp"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        let managed = lan::is_managed(&self.env, CHRONY_CONF);
        if !s.enabled && !managed {
            rep.applied("NTP server disabled (chrony config untouched)");
            return Ok(rep);
        }
        if !self.env.has_binary(CHRONYD_BIN) {
            return Err(Error::Service(
                "the NTP server needs chrony but /usr/sbin/chronyd is not installed \
                 (emerge net-misc/chrony, USE=ntp)"
                    .into(),
            ));
        }
        let allow = self.allow(store, &s, &mut rep).await?;
        if s.enabled && allow.is_empty() {
            rep.warn("NTP server enabled but no served interface has an address");
        }
        let changed = lan::install(
            &self.env,
            &ManagedFile {
                path: CHRONY_CONF,
                content: render(&s, &allow),
                mode: 0o644,
                group: None,
                check: Some(vec![CHRONYD_BIN, "-p", "-f", "{}"]),
            },
        )?;
        if changed {
            rep.applied(format!("wrote {CHRONY_CONF}"));
        }
        lan::reconcile(&self.env, SERVICE, true, changed, CHRONY_CONF, &mut rep)?;
        rep.applied(format!(
            "NTP server {} ({} subnet(s))",
            if s.enabled { "on" } else { "off, client only" },
            allow.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        if !s.enabled {
            return Ok("# NTP server disabled\n".into());
        }
        let allow = self.allow(store, &s, &mut rep).await?;
        Ok(format!(
            "## {CHRONY_CONF} (chronyd)\n{}",
            render(&s, &allow)
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        Ok(json!({
            "enabled": s.enabled,
            "available": self.env.has_binary(CHRONYD_BIN),
            "running": self.env.services.is_running(SERVICE),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil::{self, read};
    use crate::lan::ServiceControl;

    #[tokio::test]
    async fn serves_lan_subnets_and_leaves_foreign_config_alone() {
        let t = testutil::env(&[CHRONYD_BIN]);
        let s = testutil::store().await;
        std::fs::create_dir_all(t.env.path("/etc/chrony")).unwrap();
        std::fs::write(t.env.path(CHRONY_CONF), "server my.own.server\n").unwrap();
        let a = NtpApplier::new(t.env.clone());
        a.apply(&s).await.unwrap();
        assert_eq!(read(&t, CHRONY_CONF), "server my.own.server\n");
        save_settings(
            &s,
            &NtpInput {
                enabled: Some(true),
                servers: Some("0.pool.ntp.org, 192.0.2.123".into()),
                interfaces: None,
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        for want in [
            "pool 0.pool.ntp.org iburst",
            "server 192.0.2.123 iburst",
            "allow 192.168.50.0/24",
            "allow fd00:50::/64",
            "local stratum 10",
        ] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(!c.contains("203.0.113"), "never serve the WAN");
        assert!(t.services.is_running(SERVICE));
        save_settings(
            &s,
            &NtpInput {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        let c = read(&t, CHRONY_CONF);
        assert!(!c.contains("allow ") && c.contains("pool 0.pool.ntp.org"));
        assert!(save_settings(
            &s,
            &NtpInput {
                servers: Some("bad_host".into()),
                ..Default::default()
            }
        )
        .await
        .is_err());
    }
}
