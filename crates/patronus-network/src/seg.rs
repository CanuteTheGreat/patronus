//! Layer-2 side of device segmentation (USE=segmentation): what has to be true
//! of the kernel for the nft rules in `patronus-firewall/src/seg_rules.rs` to
//! mean something.
//!
//! Devices on one segment must not reach each other without the router:
//! - every port of a bridge that carries an enforced segment is switched to
//!   `bridge link ... isolated on`, so frames from a port reach only the
//!   (non-isolated) bridge device itself, i.e. the router;
//! - the segment's interface gets `proxy_arp=1` and `proxy_arp_pvlan=1` so the
//!   router answers ARP for a device that sits on the same interface and then
//!   routes the traffic through the forward hook (where the seg table
//!   decides), and `send_redirects=0` so it never tells hosts to go direct.
//!
//! Wired devices behind an *unmanaged* switch share one bridge port: the
//! switch forwards between them without the router, which no setting here can
//! prevent. The UI and the docs say so; group such devices together.
//!
//! The applier is full-state: what an earlier apply switched on and the store
//! no longer asks for is switched back off (state file), nothing else is
//! touched. It never touches the Wi-Fi AP's own isolation (`ap_isolate=1` in
//! hostapd.conf).

use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::seg;
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

pub const STATE_FILE: &str = "/var/lib/patronus/seg-l2.json";

/// What the applier does to the kernel (a fake in tests).
pub trait L2Ops: Send + Sync {
    fn is_bridge(&self, dev: &str) -> bool;
    fn bridge_ports(&self, bridge: &str) -> Vec<String>;
    /// Write `net/ipv4/conf/<dev>/<key>`.
    fn set_conf(&self, dev: &str, key: &str, val: &str) -> Result<()>;
    fn set_isolated(&self, port: &str, on: bool) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct SystemL2 {
    /// `/proc/sys` and `/sys/class/net` roots (tests point them at a tempdir)
    pub proc_sys: Option<PathBuf>,
    pub sys_net: Option<PathBuf>,
}

impl SystemL2 {
    fn proc_sys(&self) -> PathBuf {
        self.proc_sys.clone().unwrap_or_else(|| "/proc/sys".into())
    }
    fn sys_net(&self) -> PathBuf {
        self.sys_net
            .clone()
            .unwrap_or_else(|| "/sys/class/net".into())
    }
}

impl L2Ops for SystemL2 {
    fn is_bridge(&self, dev: &str) -> bool {
        self.sys_net().join(dev).join("bridge").exists()
    }
    fn bridge_ports(&self, bridge: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.sys_net().join(bridge).join("brif"))
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
    fn set_conf(&self, dev: &str, key: &str, val: &str) -> Result<()> {
        if !seg::is_ifname(dev) || !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return Err(Error::Config(format!("Invalid sysctl {dev}/{key}")));
        }
        let p = self.proc_sys().join("net/ipv4/conf").join(dev).join(key);
        std::fs::write(&p, val).map_err(|e| Error::Config(format!("write {}: {e}", p.display())))
    }
    fn set_isolated(&self, port: &str, on: bool) -> Result<()> {
        if !seg::is_ifname(port) {
            return Err(Error::Config(format!("Invalid port {port:?}")));
        }
        let out = Command::new("bridge")
            .args([
                "link",
                "set",
                "dev",
                port,
                "isolated",
                if on { "on" } else { "off" },
            ])
            .output()
            .map_err(|e| Error::Config(format!("bridge: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Error::Config(format!(
                "bridge link set dev {port} isolated: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
}

#[derive(Clone)]
pub struct SegApplier {
    ops: Arc<dyn L2Ops>,
    state: PathBuf,
}

impl Default for SegApplier {
    fn default() -> Self {
        Self::new(Arc::new(SystemL2::default()), PathBuf::from(STATE_FILE))
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct Managed {
    /// interfaces whose proxy-ARP settings we switched on
    ifaces: BTreeSet<String>,
    /// bridge ports we isolated
    ports: BTreeSet<String>,
}

impl SegApplier {
    pub fn new(ops: Arc<dyn L2Ops>, state: PathBuf) -> Self {
        Self { ops, state }
    }

    fn load(&self) -> Managed {
        std::fs::read_to_string(&self.state)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, m: &Managed) -> Result<()> {
        if let Some(d) = self.state.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let tmp = self.state.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string(m).unwrap_or_default())
            .and_then(|_| std::fs::rename(&tmp, &self.state))
            .map_err(|e| Error::Config(format!("write {}: {e}", self.state.display())))
    }

    /// Interfaces of every enabled segment.
    async fn wanted(&self, store: &ConfigStore) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for s in seg::list_segments(store)
            .await?
            .into_iter()
            .filter(|s| s.enabled)
        {
            for i in seg::resolve_segment(store, &s.segment).await? {
                if seg::is_ifname(&i) && !out.contains(&i) {
                    out.push(i);
                }
            }
        }
        Ok(out)
    }

    fn plan(&self, wanted: &[String]) -> Managed {
        let mut m = Managed::default();
        for i in wanted {
            m.ifaces.insert(i.clone());
            if self.ops.is_bridge(i) {
                m.ports.extend(self.ops.bridge_ports(i));
            }
        }
        m
    }
}

#[async_trait]
impl Applier for SegApplier {
    fn name(&self) -> &'static str {
        "segmentation"
    }
    fn phase(&self) -> Phase {
        Phase::Interfaces
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let want = self.plan(&self.wanted(store).await?);
        let had = self.load();
        for i in &want.ifaces {
            let mut conf = vec![("send_redirects", "0")];
            if self.ops.is_bridge(i) {
                conf.push(("proxy_arp", "1"));
                conf.push(("proxy_arp_pvlan", "1"));
            }
            for (k, v) in conf {
                if let Err(e) = self.ops.set_conf(i, k, v) {
                    rep.warn(format!("segmentation: {i}: {k}: {e}"));
                }
            }
        }
        for p in &want.ports {
            match self.ops.set_isolated(p, true) {
                Ok(()) => {}
                Err(e) => rep.warn(format!("segmentation: port {p} not isolated: {e}")),
            }
        }
        // switch off what an earlier apply enabled and the store no longer asks for
        for p in had.ports.difference(&want.ports) {
            let _ = self.ops.set_isolated(p, false);
        }
        for i in had.ifaces.difference(&want.ifaces) {
            for (k, v) in [("proxy_arp", "0"), ("proxy_arp_pvlan", "0")] {
                let _ = self.ops.set_conf(i, k, v);
            }
        }
        self.save(&want)?;
        if want.ifaces.is_empty() {
            rep.applied("device segmentation off: no L2 settings".to_string());
        } else {
            rep.applied(format!(
                "segment L2: proxy ARP on {}, {} isolated bridge port(s)",
                want.ifaces.iter().cloned().collect::<Vec<_>>().join(", "),
                want.ports.len()
            ));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let want = self.plan(&self.wanted(store).await?);
        let mut o = String::from("# device segmentation: layer-2 settings\n");
        for i in &want.ifaces {
            o.push_str(&format!("net.ipv4.conf.{i}.send_redirects = 0\n"));
            if self.ops.is_bridge(i) {
                o.push_str(&format!(
                    "net.ipv4.conf.{i}.proxy_arp = 1\nnet.ipv4.conf.{i}.proxy_arp_pvlan = 1\n"
                ));
            }
        }
        for p in &want.ports {
            o.push_str(&format!("bridge link set dev {p} isolated on\n"));
        }
        Ok(o)
    }

    async fn status(&self, _store: &ConfigStore) -> Result<serde_json::Value> {
        let m = self.load();
        Ok(serde_json::json!({
            "proxy_arp_interfaces": m.ifaces,
            "isolated_ports": m.ports,
            "wired_note": "devices behind an unmanaged switch share one port and cannot be isolated from each other",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        log: Mutex<Vec<String>>,
    }
    impl L2Ops for Fake {
        fn is_bridge(&self, dev: &str) -> bool {
            dev.starts_with("br")
        }
        fn bridge_ports(&self, b: &str) -> Vec<String> {
            vec![format!("{b}-p1"), format!("{b}-p2")]
        }
        fn set_conf(&self, dev: &str, key: &str, val: &str) -> Result<()> {
            self.log
                .lock()
                .unwrap()
                .push(format!("conf {dev} {key}={val}"));
            Ok(())
        }
        fn set_isolated(&self, port: &str, on: bool) -> Result<()> {
            self.log.lock().unwrap().push(format!("iso {port} {on}"));
            Ok(())
        }
    }

    async fn store() -> ConfigStore {
        let s = ConfigStore::open_in_memory().await.unwrap();
        sqlx::query("INSERT INTO interfaces (name, enabled, role, updated_at) VALUES ('br0',1,'lan',0), ('eth9',1,'opt1',0)")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        s
    }

    #[tokio::test]
    async fn nothing_enabled_touches_nothing() {
        let s = store().await;
        let f = Arc::new(Fake::default());
        let d = tempfile::tempdir().unwrap();
        let a = SegApplier::new(f.clone(), d.path().join("st.json"));
        let r = a.apply(&s).await.unwrap();
        assert!(f.log.lock().unwrap().is_empty(), "upgrade: no change");
        assert!(r.applied[0].contains("off"));
    }

    #[tokio::test]
    async fn enabled_bridge_gets_proxy_arp_and_isolated_ports_then_is_undone() {
        let s = store().await;
        let f = Arc::new(Fake::default());
        let d = tempfile::tempdir().unwrap();
        let a = SegApplier::new(f.clone(), d.path().join("st.json"));
        seg::set_segment_enabled(&s, "@lan", true).await.unwrap();
        seg::set_segment_enabled(&s, "eth9", true).await.unwrap();
        a.apply(&s).await.unwrap();
        let l = f.log.lock().unwrap().clone();
        assert!(l.contains(&"conf br0 proxy_arp=1".to_string()), "{l:?}");
        assert!(l.contains(&"conf br0 proxy_arp_pvlan=1".to_string()));
        assert!(l.contains(&"conf br0 send_redirects=0".to_string()));
        assert!(
            l.contains(&"iso br0-p1 true".to_string())
                && l.contains(&"iso br0-p2 true".to_string())
        );
        assert!(l.contains(&"conf eth9 send_redirects=0".to_string()));
        assert!(
            !l.iter().any(|x| x.contains("eth9 proxy_arp")),
            "a plain NIC is not a bridge: {l:?}"
        );
        f.log.lock().unwrap().clear();
        let rendered = a.render(&s).await.unwrap();
        assert!(rendered.contains("bridge link set dev br0-p1 isolated on"));
        // switch the bridge's segment off: what we enabled is undone, and only that
        seg::set_segment_enabled(&s, "@lan", false).await.unwrap();
        a.apply(&s).await.unwrap();
        let l = f.log.lock().unwrap().clone();
        assert!(l.contains(&"iso br0-p1 false".to_string()), "{l:?}");
        assert!(l.contains(&"conf br0 proxy_arp=0".to_string()));
        assert!(!l
            .iter()
            .any(|x| x.contains("eth9") && x.contains("=0") && x.contains("proxy")));
        // idempotent second run
        f.log.lock().unwrap().clear();
        a.apply(&s).await.unwrap();
        assert!(
            !f.log.lock().unwrap().iter().any(|x| x.contains("br0-p1")),
            "{:?}",
            f.log.lock().unwrap()
        );
    }

    #[test]
    fn system_l2_rejects_hostile_names() {
        let s = SystemL2::default();
        assert!(s.set_conf("../../etc", "proxy_arp", "1").is_err());
        assert!(s.set_conf("br0", "../x", "1").is_err());
        assert!(s.set_isolated("x; reboot", true).is_err());
    }

    #[test]
    fn system_l2_reads_sysfs_layout() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("sys/br0/bridge")).unwrap();
        std::fs::create_dir_all(d.path().join("sys/br0/brif/eth1")).unwrap();
        std::fs::create_dir_all(d.path().join("sys/br0/brif/eth0")).unwrap();
        std::fs::create_dir_all(d.path().join("sys/eth5")).unwrap();
        std::fs::create_dir_all(d.path().join("proc/net/ipv4/conf/br0")).unwrap();
        let s = SystemL2 {
            proc_sys: Some(d.path().join("proc")),
            sys_net: Some(d.path().join("sys")),
        };
        assert!(s.is_bridge("br0") && !s.is_bridge("eth5"));
        assert_eq!(s.bridge_ports("br0"), vec!["eth0", "eth1"]);
        s.set_conf("br0", "proxy_arp", "1").unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("proc/net/ipv4/conf/br0/proxy_arp")).unwrap(),
            "1"
        );
    }
}
