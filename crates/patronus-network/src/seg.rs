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
use std::net::Ipv4Addr;
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
    /// Broadcast a gratuitous ARP reply claiming `ip` at the bridge's own MAC.
    /// Hosts that learned each other's real MAC before the ports were
    /// isolated would otherwise keep sending frames the bridge now drops
    /// until their ARP cache entry expires (up to about a minute).
    fn announce(&self, _bridge: &str, _ip: Ipv4Addr) -> Result<()> {
        Ok(())
    }
}

/// An Ethernet + ARP frame: gratuitous reply, `ip` is at `mac`.
pub fn garp_frame(mac: [u8; 6], ip: Ipv4Addr) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    f[18] = 6;
    f[19] = 4;
    f[20..22].copy_from_slice(&2u16.to_be_bytes()); // reply
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&ip.octets());
    f[32..38].copy_from_slice(&[0xff; 6]);
    f[38..42].copy_from_slice(&ip.octets());
    f
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let mut it = s.trim().split(':');
    for b in &mut m {
        *b = u8::from_str_radix(it.next()?, 16).ok()?;
    }
    it.next().is_none().then_some(m)
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
    fn announce(&self, bridge: &str, ip: Ipv4Addr) -> Result<()> {
        if !seg::is_ifname(bridge) {
            return Err(Error::Config(format!("Invalid bridge {bridge:?}")));
        }
        let mac = std::fs::read_to_string(self.sys_net().join(bridge).join("address"))
            .ok()
            .and_then(|m| parse_mac(&m))
            .ok_or_else(|| Error::Config(format!("no MAC address for {bridge}")))?;
        send_frame(bridge, &garp_frame(mac, ip))
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

/// Send one raw Ethernet frame out of `ifname` (AF_PACKET).
fn send_frame(ifname: &str, frame: &[u8]) -> Result<()> {
    use std::ffi::CString;
    let name = CString::new(ifname).map_err(|_| Error::Config("bad interface name".into()))?;
    let err = |what: &str| Error::Config(format!("{what}: {}", std::io::Error::last_os_error()));
    // SAFETY: plain libc socket calls on a socket we own and close; the sockaddr is fully initialised.
    unsafe {
        let idx = libc::if_nametoindex(name.as_ptr());
        if idx == 0 {
            return Err(err("if_nametoindex"));
        }
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ARP as u16).to_be() as i32,
        );
        if fd < 0 {
            return Err(err("socket(AF_PACKET)"));
        }
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_ifindex = idx as i32;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);
        let r = libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
        let e = if r < 0 { Some(err("sendto")) } else { None };
        libc::close(fd);
        match e {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct SegApplier {
    ops: Arc<dyn L2Ops>,
    state: PathBuf,
    /// repeat the announcements after these delays (hosts may miss the first)
    repeat: Vec<std::time::Duration>,
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
        Self {
            ops,
            state,
            repeat: vec![
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(4),
            ],
        }
    }

    /// No repeated announcements (tests).
    pub fn without_repeats(mut self) -> Self {
        self.repeat.clear();
        self
    }

    /// (bridge, address) of every active device on an enforced bridge segment.
    async fn announce_targets(&self, store: &ConfigStore) -> Result<Vec<(String, Ipv4Addr)>> {
        let mut out = Vec::new();
        let devices = seg::list_devices(store).await?;
        for s in seg::list_segments(store)
            .await?
            .into_iter()
            .filter(|s| s.enabled)
        {
            let bridges: Vec<String> = seg::resolve_segment(store, &s.segment)
                .await?
                .into_iter()
                .filter(|i| self.ops.is_bridge(i))
                .collect();
            for d in devices
                .iter()
                .filter(|d| d.segment == s.segment && d.state == "active")
            {
                let Some(ip) = d.ip4.as_deref().and_then(|a| a.parse::<Ipv4Addr>().ok()) else {
                    continue;
                };
                for b in &bridges {
                    out.push((b.clone(), ip));
                }
            }
        }
        Ok(out)
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
        let targets = self.announce_targets(store).await?;
        let mut sent = 0;
        for (b, ip) in &targets {
            match self.ops.announce(b, *ip) {
                Ok(()) => sent += 1,
                Err(e) => rep.warn(format!(
                    "segmentation: ARP announcement for {ip} on {b}: {e}"
                )),
            }
        }
        if !targets.is_empty() && !self.repeat.is_empty() {
            let (ops, delays) = (self.ops.clone(), self.repeat.clone());
            std::thread::spawn(move || {
                for d in delays {
                    std::thread::sleep(d);
                    for (b, ip) in &targets {
                        let _ = ops.announce(b, *ip);
                    }
                }
            });
        }
        if sent > 0 {
            rep.applied(format!(
                "announced {sent} device address(es) at the router's MAC (gratuitous ARP)"
            ));
        }
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
        fn announce(&self, bridge: &str, ip: Ipv4Addr) -> Result<()> {
            self.log.lock().unwrap().push(format!("garp {bridge} {ip}"));
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
        let a = SegApplier::new(f.clone(), d.path().join("st.json")).without_repeats();
        let r = a.apply(&s).await.unwrap();
        assert!(f.log.lock().unwrap().is_empty(), "upgrade: no change");
        assert!(r.applied[0].contains("off"));
    }

    #[tokio::test]
    async fn enabled_bridge_gets_proxy_arp_and_isolated_ports_then_is_undone() {
        let s = store().await;
        let f = Arc::new(Fake::default());
        let d = tempfile::tempdir().unwrap();
        let a = SegApplier::new(f.clone(), d.path().join("st.json")).without_repeats();
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
    fn gratuitous_arp_frame_is_a_broadcast_reply_for_the_device_address() {
        let f = garp_frame([2, 0, 0, 0, 0, 1], "192.168.50.12".parse().unwrap());
        assert_eq!(&f[0..6], &[0xff; 6], "broadcast");
        assert_eq!(&f[6..12], &[2, 0, 0, 0, 0, 1], "from the bridge's MAC");
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[20..22], &[0, 2], "ARP reply");
        assert_eq!(
            &f[22..28],
            &[2, 0, 0, 0, 0, 1],
            "sender hardware = the router"
        );
        assert_eq!(
            &f[28..32],
            &[192, 168, 50, 12],
            "sender protocol = the device"
        );
        assert_eq!(
            &f[38..42],
            &[192, 168, 50, 12],
            "gratuitous: target = sender"
        );
        assert_eq!(
            parse_mac("02:aa:00:00:00:10\n"),
            Some([2, 0xaa, 0, 0, 0, 0x10])
        );
        assert_eq!(parse_mac("02:aa:00:00:00"), None);
        assert_eq!(parse_mac("02:aa:00:00:00:10:11"), None);
    }

    #[tokio::test]
    async fn enabling_announces_every_active_device_so_cached_peers_relearn() {
        let s = store().await;
        sqlx::query("INSERT INTO interface_addresses (interface_name, address, prefix_len, family) VALUES ('br0','192.168.50.1',24,'ipv4')")
            .execute(s.pool().unwrap())
            .await
            .unwrap();
        for (name, mac) in [("a", "02:aa:00:00:00:11"), ("b", "02:aa:00:00:00:12")] {
            seg::create_device(
                &s,
                &seg::DeviceInput {
                    name: name.into(),
                    mac: Some(mac.into()),
                    segment: Some("@lan".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let revoked = seg::create_device(
            &s,
            &seg::DeviceInput {
                name: "gone".into(),
                mac: Some("02:aa:00:00:00:13".into()),
                segment: Some("@lan".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        seg::revoke_device(&s, revoked.id).await.unwrap();
        let f = Arc::new(Fake::default());
        let d = tempfile::tempdir().unwrap();
        let a = SegApplier::new(f.clone(), d.path().join("st.json")).without_repeats();
        a.apply(&s).await.unwrap();
        assert!(
            !f.log.lock().unwrap().iter().any(|x| x.starts_with("garp")),
            "off: silent"
        );
        seg::set_segment_enabled(&s, "@lan", true).await.unwrap();
        let r = a.apply(&s).await.unwrap();
        let l = f.log.lock().unwrap().clone();
        assert!(
            l.contains(&"garp br0 192.168.50.2".to_string())
                && l.contains(&"garp br0 192.168.50.3".to_string()),
            "{l:?}"
        );
        assert_eq!(
            l.iter().filter(|x| x.starts_with("garp")).count(),
            2,
            "not the revoked device: {l:?}"
        );
        assert!(
            r.applied.iter().any(|x| x.contains("gratuitous ARP")),
            "{r:?}"
        );
        // a plain NIC cannot be isolated: no announcements for it
        seg::set_segment_enabled(&s, "@lan", false).await.unwrap();
        seg::set_segment_enabled(&s, "eth9", true).await.unwrap();
        f.log.lock().unwrap().clear();
        a.apply(&s).await.unwrap();
        assert!(!f.log.lock().unwrap().iter().any(|x| x.starts_with("garp")));
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
