//! Kernel sysctl [`Applier`] (boot phase [`Phase::Sysctl`], applied first).
//!
//! Writes every row of the store's `sysctls` table to `/proc/sys`, then
//! reads it back to verify. The default rows (seeded on first boot by
//! `patronus_config::defaults`) turn on IPv4 and IPv6 forwarding -- before
//! this, no shipped code path ever enabled forwarding, so a fresh box did
//! not route at all.
//!
//! Derived settings: with IPv6 forwarding on, the kernel ignores router
//! advertisements unless `accept_ra=2`, which would silently break SLAAC /
//! default-route learning on the WAN. So for every WAN interface the
//! applier also sets `net.ipv6.conf.<wan>.accept_ra=2` (unless the store
//! sets that key explicitly).
//!
//! A per-interface key for a device that does not exist yet is skipped
//! with a warning (it is applied on the next run once the device exists).

use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::{is_valid_sysctl_key, ConfigStore};
use patronus_core::{Error, Result};
use std::path::PathBuf;

/// Sysctl applier.
#[derive(Debug, Clone)]
pub struct SysctlApplier {
    proc_root: PathBuf,
}

impl Default for SysctlApplier {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc/sys"),
        }
    }
}

impl SysctlApplier {
    /// An applier writing under `root` instead of `/proc/sys` (tests).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: root.into(),
        }
    }

    /// `/proc/sys/...` path for a sysctl(8) key (`/` inside a component
    /// stands for a literal `.`, e.g. a VLAN device `eth0.100`).
    pub fn key_path(&self, key: &str) -> Result<PathBuf> {
        if !is_valid_sysctl_key(key) {
            return Err(Error::Config(format!("Invalid sysctl key {key:?}")));
        }
        let mut p = self.proc_root.clone();
        for c in key.split('.') {
            p.push(c.replace('/', "."));
        }
        Ok(p)
    }

    /// Everything to write, in order: stored keys, then derived ones.
    pub async fn desired(&self, store: &ConfigStore) -> Result<Vec<(String, String)>> {
        let mut v = store.load_sysctls().await?;
        let v6_forwarding = v
            .iter()
            .any(|(k, val)| k == "net.ipv6.conf.all.forwarding" && val.trim() == "1");
        if v6_forwarding {
            for wan in store.interfaces_with_role("wan").await? {
                let key = format!("net.ipv6.conf.{}.accept_ra", wan.replace('.', "/"));
                if !v.iter().any(|(k, _)| *k == key) {
                    v.push((key, "2".into()));
                }
            }
        }
        Ok(v)
    }
}

/// Keys whose target depends on a device existing (`...conf.<dev>...`,
/// `...neigh.<dev>...`), other than the `all`/`default` pseudo-devices.
fn device_of(key: &str) -> Option<&str> {
    let parts: Vec<&str> = key.split('.').collect();
    match parts.as_slice() {
        ["net", _, "conf" | "neigh", dev, ..] if *dev != "all" && *dev != "default" => Some(dev),
        _ => None,
    }
}

#[async_trait]
impl Applier for SysctlApplier {
    fn name(&self) -> &'static str {
        "sysctl"
    }

    fn phase(&self) -> Phase {
        Phase::Sysctl
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut report = ApplyReport::default();
        let mut errors = Vec::new();
        for (key, value) in self.desired(store).await? {
            let path = match self.key_path(&key) {
                Ok(p) => p,
                Err(e) => {
                    errors.push(e.to_string());
                    continue;
                }
            };
            if !path.exists() {
                if let Some(dev) = device_of(&key) {
                    report.warn(format!(
                        "sysctl {key} skipped: interface {} does not exist yet",
                        dev.replace('/', ".")
                    ));
                } else {
                    errors.push(format!("sysctl {key}: {} does not exist", path.display()));
                }
                continue;
            }
            if let Err(e) = std::fs::write(&path, format!("{value}\n")) {
                errors.push(format!("sysctl {key}={value}: {e}"));
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(now) if now.split_whitespace().eq(value.split_whitespace()) => {
                    report.applied(format!("{key} = {value}"));
                }
                Ok(now) => errors.push(format!(
                    "sysctl {key}: wrote {value:?} but the kernel reports {:?}",
                    now.trim()
                )),
                Err(e) => errors.push(format!("sysctl {key}: read back failed: {e}")),
            }
        }
        if errors.is_empty() {
            Ok(report)
        } else {
            Err(Error::Config(errors.join("; ")))
        }
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        Ok(self
            .desired(store)
            .await?
            .into_iter()
            .map(|(k, v)| format!("{k} = {v}\n"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::store::RuleOrigin;

    fn fake_proc() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for p in [
            "net/ipv4/ip_forward",
            "net/ipv6/conf/all/forwarding",
            "net/ipv6/conf/eth0/accept_ra",
            "net/ipv6/conf/eth0.100/accept_ra",
        ] {
            let f = d.path().join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "0\n").unwrap();
        }
        d
    }

    #[tokio::test]
    async fn writes_verifies_and_derives_wan_accept_ra() {
        let proc = fake_proc();
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_sysctl("net.ipv4.ip_forward", "1", RuleOrigin::Default)
            .await
            .unwrap();
        s.set_sysctl("net.ipv6.conf.all.forwarding", "1", RuleOrigin::Default)
            .await
            .unwrap();
        s.set_interface_role("eth0", Some("wan")).await.unwrap();
        s.set_interface_role("ghost9", Some("wan")).await.unwrap();
        let a = SysctlApplier::with_root(proc.path());
        let r = a.apply(&s).await.unwrap();
        let read = |p: &str| std::fs::read_to_string(proc.path().join(p)).unwrap();
        assert_eq!(read("net/ipv4/ip_forward"), "1\n");
        assert_eq!(read("net/ipv6/conf/all/forwarding"), "1\n");
        assert_eq!(read("net/ipv6/conf/eth0/accept_ra"), "2\n");
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings); // ghost9 missing
        assert!(r.warnings[0].contains("ghost9"));
    }

    #[tokio::test]
    async fn vlan_device_keys_and_missing_global_keys() {
        let proc = fake_proc();
        let s = ConfigStore::open_in_memory().await.unwrap();
        s.set_sysctl("net.ipv6.conf.eth0/100.accept_ra", "1", RuleOrigin::User)
            .await
            .unwrap();
        let a = SysctlApplier::with_root(proc.path());
        a.apply(&s).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(proc.path().join("net/ipv6/conf/eth0.100/accept_ra")).unwrap(),
            "1\n"
        );
        s.set_sysctl("net.ipv4.does_not_exist", "1", RuleOrigin::User)
            .await
            .unwrap();
        assert!(
            a.apply(&s).await.is_err(),
            "a missing non-device key is an error"
        );
    }
}
