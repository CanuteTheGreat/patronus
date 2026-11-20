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
    /// `/sys` (queue masks for packet steering).
    sys_root: PathBuf,
}

/// `system_config` key: spread receive/transmit processing over all CPUs.
pub const PACKET_STEERING_KEY: &str = "system.packet_steering";

/// Hex CPU mask in the kernel's `rps_cpus` format (32-bit groups, comma
/// separated, most significant first) for the given CPU numbers.
pub fn cpu_mask(cpus: &[usize]) -> String {
    let top = cpus.iter().copied().max().unwrap_or(0);
    let words = top / 32 + 1;
    let mut w = vec![0u32; words];
    for &c in cpus {
        w[c / 32] |= 1 << (c % 32);
    }
    let mut it = w.iter().rev();
    let first = format!("{:x}", it.next().unwrap());
    std::iter::once(first)
        .chain(it.map(|x| format!("{x:08x}")))
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse a cpulist like `0-3,8,10-11`.
pub fn parse_cpulist(s: &str) -> Vec<usize> {
    let mut v = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                    v.extend(a..=b.min(a + 4096));
                }
            }
            None => v.extend(part.parse::<usize>()),
        }
    }
    v
}

impl Default for SysctlApplier {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc/sys"),
            sys_root: PathBuf::from("/sys"),
        }
    }
}

impl SysctlApplier {
    /// An applier writing under `root` instead of `/proc/sys` (tests).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        let proc_root: PathBuf = root.into();
        Self {
            sys_root: proc_root.join("__sys"),
            proc_root,
        }
    }

    /// Packet steering (OpenWrt `packet_steering`): every receive queue of
    /// every real interface may be processed on all CPUs (`rps_cpus`), and
    /// transmit queue N is bound to CPU N mod ncpu (`xps_cpus`). `off`
    /// writes zeros back (kernel default), but only when the setting is
    /// explicitly `0`, so hand-tuned queues are left alone by default.
    async fn packet_steering(&self, store: &ConfigStore, report: &mut ApplyReport) {
        let want = match store.load_system_config(PACKET_STEERING_KEY).await {
            Ok(Some(v)) => v.trim().to_string(),
            _ => return,
        };
        let on = match want.as_str() {
            "1" => true,
            "0" => false,
            _ => return,
        };
        let mut cpus = std::fs::read_to_string(self.sys_root.join("devices/system/cpu/online"))
            .map(|s| parse_cpulist(&s))
            .unwrap_or_default();
        if cpus.is_empty() {
            cpus = (0..std::thread::available_parallelism().map_or(1, |n| n.get())).collect();
        }
        let all = cpu_mask(&cpus);
        let Ok(rd) = std::fs::read_dir(self.sys_root.join("class/net")) else {
            return;
        };
        let mut n = 0;
        let mut no_xps = 0;
        let mut devs: Vec<_> = rd.flatten().collect();
        devs.sort_by_key(|d| d.file_name());
        for d in devs {
            let name = d.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let Ok(q) = std::fs::read_dir(d.path().join("queues")) else {
                continue;
            };
            let mut qs: Vec<_> = q.flatten().collect();
            qs.sort_by_key(|d| d.file_name());
            for q in qs {
                let qn = q.file_name().to_string_lossy().to_string();
                let (file, val) = if let Some(i) = qn.strip_prefix("tx-") {
                    let i: usize = i.parse().unwrap_or(0);
                    ("xps_cpus", cpu_mask(&[cpus[i % cpus.len()]]))
                } else if qn.starts_with("rx-") {
                    ("rps_cpus", all.clone())
                } else {
                    continue;
                };
                let path = q.path().join(file);
                if !path.exists() {
                    continue;
                }
                let val = if on { val } else { "0".to_string() };
                match std::fs::write(&path, format!("{val}\n")) {
                    Ok(()) => n += 1,
                    Err(e) if xps_unsupported(file, &e) => no_xps += 1,
                    Err(e) => report.warn(format!("packet steering: {name}/{qn}/{file}: {e}")),
                }
            }
        }
        let skipped = if no_xps > 0 {
            format!(", {no_xps} transmit queue(s) of single-queue devices without XPS left alone")
        } else {
            String::new()
        };
        report.applied(format!(
            "packet steering {} ({n} queue file(s){skipped}, {} CPU(s))",
            if on { "on" } else { "off" },
            cpus.len()
        ));
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
        // Per-flow byte/packet counters in the connection-tracking table: the
        // Traffic insights page (top hosts/services) reads them. Skipped with a
        // warning where nf_conntrack is not loaded yet.
        if !v.iter().any(|(k, _)| k == CONNTRACK_ACCT) {
            v.push((CONNTRACK_ACCT.into(), "1".into()));
        }
        Ok(v)
    }
}

pub const CONNTRACK_ACCT: &str = "net.netfilter.nf_conntrack_acct";

/// The kernel lists `queues/tx-N/xps_cpus` on every device but refuses a
/// write with ENOENT when the device is not multiqueue (e.g. a single-queue
/// virtio NIC): transmit steering does not apply there, which is not an error.
fn xps_unsupported(file: &str, e: &std::io::Error) -> bool {
    file == "xps_cpus" && e.kind() == std::io::ErrorKind::NotFound
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
                if key == CONNTRACK_ACCT {
                    report.warn(format!(
                        "sysctl {key} skipped: connection tracking is not loaded (Traffic insights show no byte counts)"
                    ));
                } else if let Some(dev) = device_of(&key) {
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
        self.packet_steering(store, &mut report).await;
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
            "net/netfilter/nf_conntrack_acct",
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
        // conntrack accounting (Traffic insights) is switched on
        assert_eq!(read("net/netfilter/nf_conntrack_acct"), "1\n");
    }

    #[tokio::test]
    async fn missing_conntrack_is_a_warning_not_an_error() {
        let proc = fake_proc();
        std::fs::remove_file(proc.path().join("net/netfilter/nf_conntrack_acct")).unwrap();
        let s = ConfigStore::open_in_memory().await.unwrap();
        let r = SysctlApplier::with_root(proc.path())
            .apply(&s)
            .await
            .unwrap();
        assert!(
            r.warnings.iter().any(|w| w.contains("nf_conntrack_acct")),
            "{:?}",
            r.warnings
        );
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

    #[test]
    fn cpu_masks() {
        assert_eq!(cpu_mask(&[0, 1, 2, 3]), "f");
        assert_eq!(cpu_mask(&[2]), "4");
        assert_eq!(cpu_mask(&(0..24).collect::<Vec<_>>()), "ffffff");
        assert_eq!(cpu_mask(&(0..36).collect::<Vec<_>>()), "f,ffffffff");
        assert_eq!(cpu_mask(&[32]), "1,00000000");
        assert_eq!(parse_cpulist("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpulist("0\n"), vec![0]);
    }

    #[tokio::test]
    async fn packet_steering_spreads_queues_over_all_cpus() {
        let proc = fake_proc();
        let sys = proc.path().join("__sys");
        std::fs::create_dir_all(sys.join("devices/system/cpu")).unwrap();
        std::fs::write(sys.join("devices/system/cpu/online"), "0-3\n").unwrap();
        for dev in ["eth0", "lo"] {
            for q in [
                "rx-0/rps_cpus",
                "rx-1/rps_cpus",
                "tx-0/xps_cpus",
                "tx-1/xps_cpus",
            ] {
                let f = sys.join("class/net").join(dev).join("queues").join(q);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "0\n").unwrap();
            }
        }
        let rd = |p: &str| std::fs::read_to_string(sys.join("class/net").join(p)).unwrap();
        let s = ConfigStore::open_in_memory().await.unwrap();
        let a = SysctlApplier::with_root(proc.path());
        // unset: nothing touched
        a.apply(&s).await.unwrap();
        assert_eq!(rd("eth0/queues/rx-0/rps_cpus"), "0\n");
        s.save_system_config(PACKET_STEERING_KEY, "1")
            .await
            .unwrap();
        let r = a.apply(&s).await.unwrap();
        assert!(
            r.applied.iter().any(|l| l.contains("packet steering on")),
            "{r:?}"
        );
        assert_eq!(rd("eth0/queues/rx-0/rps_cpus"), "f\n");
        assert_eq!(rd("eth0/queues/rx-1/rps_cpus"), "f\n");
        assert_eq!(rd("eth0/queues/tx-0/xps_cpus"), "1\n");
        assert_eq!(rd("eth0/queues/tx-1/xps_cpus"), "2\n");
        assert_eq!(rd("lo/queues/rx-0/rps_cpus"), "0\n", "lo is left alone");
        s.save_system_config(PACKET_STEERING_KEY, "0")
            .await
            .unwrap();
        a.apply(&s).await.unwrap();
        assert_eq!(rd("eth0/queues/rx-0/rps_cpus"), "0\n");
        assert_eq!(rd("eth0/queues/tx-1/xps_cpus"), "0\n");
    }

    #[test]
    fn xps_enoent_on_a_single_queue_device_is_not_a_warning() {
        let enoent = std::io::Error::from_raw_os_error(2);
        assert!(xps_unsupported("xps_cpus", &enoent));
        assert!(!xps_unsupported("rps_cpus", &enoent), "rps has no such case");
        let eacces = std::io::Error::from_raw_os_error(13);
        assert!(!xps_unsupported("xps_cpus", &eacces), "other errors still warn");
    }
}
