//! General setup: host name, DNS domain and time zone, set from the System
//! page / `PUT /api/system/general` and re-applied at every boot.
//!
//! Store: `lan_settings` keys `general.hostname`, `general.domain`,
//! `general.timezone`. A key that was never set is never touched, so a box
//! that was configured by hand keeps its own values until the owner changes
//! them here.
//!
//! Applying (as root, through `patronus applyd` when the web UI is
//! unprivileged):
//! - host name: the running kernel (`/proc/sys/kernel/hostname`), `/etc/hostname`
//!   (systemd, Debian) and `/etc/conf.d/hostname` (OpenRC, only when
//!   `/etc/conf.d` exists), plus a `127.0.1.1 fqdn short` line in a marked
//!   block of `/etc/hosts` (the rest of that file is left alone);
//! - domain: the same `/etc/hosts` block (the FQDN);
//! - time zone: `/etc/localtime` symlink to `/usr/share/zoneinfo/<zone>`
//!   (replaced atomically) and `/etc/timezone`.

use crate::lan::{self, invalid, LanEnv};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

const K_HOST: &str = "general.hostname";
const K_DOMAIN: &str = "general.domain";
const K_TZ: &str = "general.timezone";
const HOSTS_BEGIN: &str = "# BEGIN patronus general";
const HOSTS_END: &str = "# END patronus general";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GeneralSettings {
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub timezone: Option<String>,
}

/// Fields of `PUT /api/system/general`; absent = unchanged, empty domain =
/// clear it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeneralInput {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
}

pub fn check_hostname(s: &str) -> Result<String> {
    let t = s.trim().to_ascii_lowercase();
    if t.contains('.') || !lan::valid_dns_name(&t, false) {
        return Err(invalid(format!(
            "host name {s:?}: one label of letters, digits and '-' (up to 63), no dots; \
             put the domain in the DNS domain field"
        )));
    }
    Ok(t)
}

pub fn check_timezone(s: &str) -> Result<String> {
    let t = s.trim();
    let ok = !t.is_empty()
        && t.len() <= 64
        && !t.starts_with('/')
        && !t.ends_with('/')
        && t.split('/').all(|p| p != ".." && p != "." && !p.is_empty())
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'/'));
    if ok {
        Ok(t.to_string())
    } else {
        Err(invalid(format!(
            "time zone {s:?}: a zoneinfo name such as Europe/Berlin or UTC"
        )))
    }
}

pub async fn settings(store: &ConfigStore) -> Result<GeneralSettings> {
    let get = |v: Option<String>| v.filter(|x| !x.trim().is_empty());
    Ok(GeneralSettings {
        hostname: get(lan::get_setting(store, K_HOST).await?),
        domain: get(lan::get_setting(store, K_DOMAIN).await?),
        timezone: get(lan::get_setting(store, K_TZ).await?),
    })
}

pub async fn save_settings(store: &ConfigStore, i: &GeneralInput) -> Result<()> {
    let mut kv = Vec::new();
    if let Some(h) = &i.hostname {
        kv.push((K_HOST, check_hostname(h)?));
    }
    if let Some(d) = &i.domain {
        let d = d.trim().trim_end_matches('.');
        kv.push((
            K_DOMAIN,
            if d.is_empty() {
                String::new()
            } else {
                lan::check_dns_name("DNS domain", d)?
            },
        ));
    }
    if let Some(t) = &i.timezone {
        kv.push((K_TZ, check_timezone(t)?));
    }
    for (k, v) in kv {
        lan::set_setting(store, k, &v).await?;
    }
    Ok(())
}

/// `/etc/hosts` with the Patronus block replaced (or appended).
pub fn render_hosts(old: &str, host: &str, domain: Option<&str>) -> String {
    let mut out = String::new();
    let mut skip = false;
    for l in old.lines() {
        if l.trim() == HOSTS_BEGIN {
            skip = true;
        } else if l.trim() == HOSTS_END {
            skip = false;
        } else if !skip {
            out.push_str(l);
            out.push('\n');
        }
    }
    let names = match domain {
        Some(d) => format!("{host}.{d} {host}"),
        None => host.to_string(),
    };
    out.push_str(&format!("{HOSTS_BEGIN}\n127.0.1.1 {names}\n{HOSTS_END}\n"));
    out
}

pub(crate) fn write_atomic(path: &Path, content: &str, mode: u32) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(false);
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)
            .map_err(|e| Error::Config(format!("create {}: {e}", d.display())))?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.patronus-new",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f")
    ));
    std::fs::write(&tmp, content)
        .map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    match std::fs::rename(&tmp, path) {
        Ok(()) => {}
        // A bind-mounted file (/etc/hostname and /etc/hosts in a container)
        // cannot be replaced by rename: write it in place instead.
        Err(e) if e.raw_os_error() == Some(16) => {
            let _ = std::fs::remove_file(&tmp);
            std::fs::write(path, content)
                .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Config(format!("install {}: {e}", path.display())));
        }
    }
    Ok(true)
}

#[derive(Clone, Default)]
pub struct GeneralApplier {
    env: LanEnv,
}

impl GeneralApplier {
    pub fn new(env: LanEnv) -> Self {
        Self { env }
    }

    fn live(&self) -> bool {
        self.env.root == Path::new("/")
    }

    fn apply_hostname(
        &self,
        host: &str,
        domain: Option<&str>,
        rep: &mut ApplyReport,
    ) -> Result<()> {
        let mut changed =
            write_atomic(&self.env.path("/etc/hostname"), &format!("{host}\n"), 0o644)?;
        if self.env.path("/etc/conf.d").is_dir() {
            changed |= write_atomic(
                &self.env.path("/etc/conf.d/hostname"),
                &format!("hostname=\"{host}\"\n"),
                0o644,
            )?;
        }
        let hosts = self.env.path("/etc/hosts");
        let old = std::fs::read_to_string(&hosts).unwrap_or_default();
        changed |= write_atomic(&hosts, &render_hosts(&old, host, domain), 0o644)?;
        if self.live() {
            let cur = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            if cur.trim() != host {
                std::fs::write("/proc/sys/kernel/hostname", host)
                    .map_err(|e| Error::Config(format!("set the running host name: {e}")))?;
                changed = true;
            }
        }
        if changed {
            rep.applied(format!("host name {host}"));
        }
        Ok(())
    }

    fn apply_timezone(&self, tz: &str, rep: &mut ApplyReport) -> Result<()> {
        let zone = self.env.path(&format!("/usr/share/zoneinfo/{tz}"));
        if !zone.is_file() {
            return Err(invalid(format!(
                "time zone {tz:?}: not found in /usr/share/zoneinfo"
            )));
        }
        let link = self.env.path("/etc/localtime");
        let target = format!("/usr/share/zoneinfo/{tz}");
        let mut changed = std::fs::read_link(&link).ok().as_deref() != Some(Path::new(&target));
        if changed {
            let tmp = link.with_file_name(".localtime.patronus-new");
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(&target, &tmp)
                .map_err(|e| Error::Config(format!("link /etc/localtime: {e}")))?;
            std::fs::rename(&tmp, &link)
                .map_err(|e| Error::Config(format!("install /etc/localtime: {e}")))?;
        }
        changed |= write_atomic(&self.env.path("/etc/timezone"), &format!("{tz}\n"), 0o644)?;
        if changed {
            rep.applied(format!("time zone {tz}"));
        }
        Ok(())
    }
}

#[async_trait]
impl Applier for GeneralApplier {
    fn name(&self) -> &'static str {
        "general"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let s = settings(store).await?;
        if s.hostname.is_none() && s.domain.is_none() && s.timezone.is_none() {
            rep.applied("general setup not configured (host name, domain, time zone untouched)");
            return Ok(rep);
        }
        if let Some(tz) = &s.timezone {
            self.apply_timezone(tz, &mut rep)?;
        }
        // The domain alone still needs a host name for the hosts line.
        let host = match &s.hostname {
            Some(h) => Some(h.clone()),
            None if s.domain.is_some() => std::fs::read_to_string(self.env.path("/etc/hostname"))
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty()),
            None => None,
        };
        if let Some(h) = host {
            self.apply_hostname(&h, s.domain.as_deref(), &mut rep)?;
        }
        if rep.applied.is_empty() {
            rep.applied("general setup already in effect");
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let s = settings(store).await?;
        Ok(format!(
            "## general setup\nhostname={}\ndomain={}\ntimezone={}\n",
            s.hostname.as_deref().unwrap_or("(unmanaged)"),
            s.domain.as_deref().unwrap_or("(none)"),
            s.timezone.as_deref().unwrap_or("(unmanaged)")
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = settings(store).await?;
        Ok(json!({ "settings": s }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::testutil;

    #[test]
    fn names_are_validated() {
        assert_eq!(check_hostname(" Gate-1 ").unwrap(), "gate-1");
        for bad in ["a.b", "", "-x", "x_y", "a b", "x\ny"] {
            assert!(check_hostname(bad).is_err(), "{bad:?}");
        }
        assert!(check_timezone("Europe/Berlin").is_ok());
        assert!(check_timezone("Etc/GMT+5").is_ok());
        for bad in ["../etc/passwd", "/etc/passwd", "a//b", "", "x y", "a/./b"] {
            assert!(check_timezone(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hosts_block_is_replaced_not_duplicated() {
        let a = render_hosts("127.0.0.1 localhost\n", "gw", Some("lan.example"));
        assert!(a.starts_with("127.0.0.1 localhost\n"));
        assert!(a.contains("127.0.1.1 gw.lan.example gw\n"));
        let b = render_hosts(&a, "gw2", None);
        assert_eq!(b.matches(HOSTS_BEGIN).count(), 1);
        assert!(b.contains("127.0.1.1 gw2\n") && !b.contains("gw.lan.example"));
        assert!(b.contains("127.0.0.1 localhost"));
    }

    #[tokio::test]
    async fn applies_host_domain_and_zone_and_leaves_unset_alone() {
        let t = testutil::env(&[]);
        let s = testutil::store().await;
        let zi = t.env.path("/usr/share/zoneinfo/Europe");
        std::fs::create_dir_all(&zi).unwrap();
        std::fs::write(zi.join("Berlin"), "TZif").unwrap();
        std::fs::create_dir_all(t.env.path("/etc")).unwrap();
        std::fs::write(t.env.path("/etc/hostname"), "old\n").unwrap();
        let a = GeneralApplier::new(t.env.clone());
        // nothing stored: nothing touched
        a.apply(&s).await.unwrap();
        assert_eq!(testutil::read(&t, "/etc/hostname"), "old\n");
        save_settings(
            &s,
            &GeneralInput {
                hostname: Some("Edge1".into()),
                domain: Some("corp.example.".into()),
                timezone: Some("Europe/Berlin".into()),
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert_eq!(testutil::read(&t, "/etc/hostname"), "edge1\n");
        assert_eq!(testutil::read(&t, "/etc/timezone"), "Europe/Berlin\n");
        assert_eq!(
            std::fs::read_link(t.env.path("/etc/localtime")).unwrap(),
            Path::new("/usr/share/zoneinfo/Europe/Berlin")
        );
        assert!(testutil::read(&t, "/etc/hosts").contains("127.0.1.1 edge1.corp.example edge1"));
        // idempotent
        let r = a.apply(&s).await.unwrap();
        assert!(
            r.applied.iter().all(|x| x.contains("already")),
            "{:?}",
            r.applied
        );
        // clearing the domain
        save_settings(
            &s,
            &GeneralInput {
                domain: Some("".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        a.apply(&s).await.unwrap();
        assert!(testutil::read(&t, "/etc/hosts").contains("127.0.1.1 edge1\n"));
        // unknown zone is refused, nothing half-applied
        save_settings(
            &s,
            &GeneralInput {
                timezone: Some("Mars/Base".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(a.apply(&s).await.is_err());
    }
}
