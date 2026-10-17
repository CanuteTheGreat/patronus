//! Interfaces & L2 state (lane C): a thin adapter over the config store +
//! the interfaces applier (`patronus_network::InterfacesApplier`, through
//! the root apply broker when patronus-web runs unprivileged).
//!
//! Every change: load -> edit -> validate ("Invalid ..." -> 400) ->
//! anti-lockout check (409 unless forced) -> config revision -> write the
//! store -> apply -> on failure restore lane C's tables and re-apply. Role
//! changes also re-run the firewall applier, because `@wan`/`@lan`/`@mgmt`
//! in rules resolve to whatever device carries the role.
//!
//! The old fixture list (eth0/eth1/wg0 with made-up counters and a fake
//! "1 Gbps") and the in-memory up/down toggles are gone: the page shows
//! the kernel's devices and the stored configuration, or an honest empty
//! state.

use patronus_config::{Applier, ApplyReport, ConfigStore};
use patronus_network::linkstate::{Cmd, KernelState, SystemCmd};
use patronus_network::netconf::{
    self, BondConfig, BridgeConfig, IfaceConfig, NetConfig, PppoeConfig, V4Mode, V6Mode, VlanConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Prefix of errors that mean "this change would cut off the admin" (409).
pub const LOCKOUT: &str = "Lockout risk";

/// Body of `PUT /api/interfaces/:name`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct InterfaceUpdate {
    /// `wan`, `lan`, `optN`, or "" / null for none.
    pub role: Option<String>,
    pub enabled: Option<bool>,
    pub ipv4_mode: String,
    /// CIDR strings (static mode).
    pub ipv4: Vec<String>,
    pub gateway4: Option<String>,
    pub ipv6_mode: String,
    pub ipv6: Vec<String>,
    pub gateway6: Option<String>,
    pub mtu: Option<u32>,
    pub mac: Option<String>,
    pub description: Option<String>,
    /// Apply even if it may cut off the current management session.
    pub force: bool,
}

/// Body for VLAN / bond / bridge / PPPoE create-or-replace.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct VlanBody {
    pub name: Option<String>,
    pub parent: String,
    pub vlan_id: u16,
    pub protocol: Option<String>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    pub force: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct BondBody {
    pub name: String,
    pub mode: Option<String>,
    pub miimon: Option<u32>,
    pub lacp_rate: Option<String>,
    pub xmit_hash_policy: Option<String>,
    pub primary: Option<String>,
    pub members: Vec<String>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    pub force: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct BridgeBody {
    pub name: String,
    pub stp: bool,
    pub members: Vec<String>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    pub force: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct PppoeBody {
    pub name: String,
    pub parent: String,
    pub username: String,
    /// Empty when editing = keep the stored password.
    pub password: String,
    pub service_name: Option<String>,
    pub mtu: Option<u32>,
    pub default_route: Option<bool>,
    pub use_peer_dns: Option<bool>,
    pub ipv6: bool,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    pub force: bool,
}

fn opt(s: &Option<String>) -> Option<String> {
    s.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_nets(
    v: &[String],
    v6: bool,
) -> anyhow::Result<Vec<patronus_network::ipnetwork::IpNetwork>> {
    v.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            let n: patronus_network::ipnetwork::IpNetwork = s.parse().map_err(|_| {
                anyhow::anyhow!("Invalid address {s:?} (use CIDR, e.g. 192.168.1.1/24)")
            })?;
            if n.is_ipv6() != v6 || !s.contains('/') {
                anyhow::bail!(
                    "Invalid {} address {s:?} (CIDR with prefix length)",
                    if v6 { "IPv6" } else { "IPv4" }
                );
            }
            Ok(n)
        })
        .collect()
}

fn parse_ip(s: &Option<String>) -> anyhow::Result<Option<IpAddr>> {
    opt(s)
        .map(|s| {
            s.parse()
                .map_err(|_| anyhow::anyhow!("Invalid gateway address {s:?}"))
        })
        .transpose()
}

/// Devices that get the anti-lockout rule (`@mgmt` in the firewall): the
/// LAN interfaces, else the WAN ones, else every interface (None).
pub fn mgmt_set(cfg: &NetConfig) -> Option<BTreeSet<String>> {
    let with = |r: &str| -> BTreeSet<String> {
        cfg.interfaces
            .iter()
            .filter(|i| i.enabled && i.role.as_deref() == Some(r))
            .map(|i| i.name.clone())
            .collect()
    };
    let lan = with("lan");
    if !lan.is_empty() {
        return Some(lan);
    }
    let wan = with("wan");
    if !wan.is_empty() {
        return Some(wan);
    }
    None
}

/// Would `after` cut off an admin connected through `dev` (server address
/// `src`)? Returns the reason.
pub fn lockout_reason(
    before: &NetConfig,
    after: &NetConfig,
    dev: &str,
    src: Option<IpAddr>,
) -> Option<String> {
    let was_mgmt = mgmt_set(before).is_none_or(|s| s.contains(dev));
    let is_mgmt = mgmt_set(after).is_none_or(|s| s.contains(dev));
    if was_mgmt && !is_mgmt {
        return Some(format!(
            "{LOCKOUT}: you are connected through {dev}, and after this change the anti-lockout \
             rule (SSH + web UI) would no longer cover {dev}"
        ));
    }
    if before.virtual_names().contains(dev) && !after.virtual_names().contains(dev) {
        return Some(format!(
            "{LOCKOUT}: you are connected through {dev}, which this change deletes"
        ));
    }
    if after.master_of(dev).is_some() && before.master_of(dev).is_none() {
        return Some(format!(
            "{LOCKOUT}: you are connected through {dev}, which this change makes a bond/bridge member"
        ));
    }
    let (b, a) = (before.iface(dev), after.iface(dev));
    if a.is_some_and(|a| !a.enabled) && b.is_none_or(|b| b.enabled) {
        return Some(format!(
            "{LOCKOUT}: you are connected through {dev}, which this change disables"
        ));
    }
    if let (Some(src), Some(a)) = (src, a) {
        if b != Some(a) {
            let v6 = src.is_ipv6();
            let (mode_dhcp_now, keeps) = if v6 {
                (
                    a.ipv6_mode == V6Mode::Dhcp6 || a.ipv6_mode == V6Mode::Slaac,
                    match a.ipv6_mode {
                        V6Mode::Unmanaged => true,
                        V6Mode::Static => a.ipv6.iter().any(|n| n.ip() == src),
                        V6Mode::None => false,
                        V6Mode::Slaac | V6Mode::Dhcp6 => {
                            b.is_some_and(|b| b.ipv6_mode == a.ipv6_mode)
                        }
                    },
                )
            } else {
                (
                    a.ipv4_mode == V4Mode::Dhcp,
                    match a.ipv4_mode {
                        V4Mode::Unmanaged => true,
                        V4Mode::Static => a.ipv4.iter().any(|n| n.ip() == src),
                        V4Mode::None => false,
                        V4Mode::Dhcp => b.is_some_and(|b| b.ipv4_mode == V4Mode::Dhcp),
                    },
                )
            };
            if !keeps {
                return Some(format!(
                    "{LOCKOUT}: you are connected to {src} on {dev}, and after this change {dev} \
                     {}",
                    if mode_dhcp_now {
                        "gets its address from DHCP/RA, which may differ"
                    } else {
                        "no longer has that address"
                    }
                ));
            }
        }
    }
    None
}

/// Interfaces management operations.
pub struct InterfacesManager {
    store: Arc<ConfigStore>,
    applier: Arc<dyn Applier>,
    firewall: Arc<dyn Applier>,
    cmd: Arc<dyn Cmd>,
    edit: Mutex<()>,
}

impl InterfacesManager {
    pub fn new(
        store: Arc<ConfigStore>,
        applier: Arc<dyn Applier>,
        firewall: Arc<dyn Applier>,
        cmd: Arc<dyn Cmd>,
    ) -> Self {
        Self {
            store,
            applier,
            firewall,
            cmd,
            edit: Mutex::new(()),
        }
    }

    /// The shipped wiring: real `ip`, the interfaces applier (via the root
    /// broker when unprivileged).
    pub fn system(store: Arc<ConfigStore>, firewall: Arc<dyn Applier>) -> Self {
        let local: Arc<dyn Applier> = Arc::new(patronus_network::InterfacesApplier::default());
        Self::new(
            store,
            patronus_network::applyd::RemoteApplier::wrap(local),
            firewall,
            Arc::new(SystemCmd),
        )
    }

    fn e(e: patronus_core::Error) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    async fn kernel(&self) -> KernelState {
        match KernelState::read(self.cmd.as_ref()).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("reading interfaces from the kernel: {e}");
                KernelState::default()
            }
        }
    }

    /// Interface the client at `ip` is connected through, and our address.
    async fn client_path(&self, ip: Option<IpAddr>) -> Option<(String, Option<IpAddr>)> {
        let ip = ip?;
        if ip.is_loopback() {
            return None;
        }
        let ip = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        match KernelState::route_get(self.cmd.as_ref(), ip).await {
            Ok((dev, src)) if dev != "lo" => Some((dev, src.and_then(|s| s.parse().ok()))),
            _ => None,
        }
    }

    /// Re-apply interfaces from the store.
    pub async fn apply(&self) -> anyhow::Result<ApplyReport> {
        let _g = self.edit.lock().await;
        self.applier
            .apply(&self.store)
            .await
            .map_err(|e| anyhow::anyhow!("failed to apply interfaces: {e}"))
    }

    /// Validate, guard, store, apply (undo on failure).
    async fn mutate(
        &self,
        what: String,
        client: Option<IpAddr>,
        force: bool,
        edit: impl FnOnce(&mut NetConfig) -> anyhow::Result<()>,
    ) -> anyhow::Result<ApplyReport> {
        let _g = self.edit.lock().await;
        let before = NetConfig::load(&self.store).await.map_err(Self::e)?;
        let mut after = before.clone();
        edit(&mut after)?;
        let kernel = self.kernel().await;
        let mut existing = kernel.names();
        // a NIC that vanished is still a valid reference for rows that
        // already used it; only new references must exist
        for i in &before.interfaces {
            existing.push(i.name.clone());
        }
        after.validate(&existing).map_err(Self::e)?;
        if !force {
            if let Some((dev, src)) = self.client_path(client).await {
                if let Some(r) = lockout_reason(&before, &after, &dev, src) {
                    anyhow::bail!("{r}. Re-submit with \"apply anyway\" if you are sure.");
                }
            }
        }
        let roles_changed = before
            .interfaces
            .iter()
            .map(|i| (&i.name, &i.role, i.enabled))
            .collect::<Vec<_>>()
            != after
                .interfaces
                .iter()
                .map(|i| (&i.name, &i.role, i.enabled))
                .collect::<Vec<_>>();
        let snap = netconf::snapshot_tables(&self.store)
            .await
            .map_err(Self::e)?;
        self.store
            .snapshot("web", &format!("before {what}"))
            .await
            .map_err(Self::e)?;
        after.save(&self.store).await.map_err(Self::e)?;
        let mut result = self.applier.apply(&self.store).await;
        if result.is_ok() && roles_changed {
            if let Err(e) = self.firewall.apply(&self.store).await {
                result = Err(patronus_core::Error::Firewall(format!(
                    "firewall re-apply after the role change failed: {e}"
                )));
            }
        }
        match result {
            Ok(rep) => {
                let _ = self
                    .store
                    .audit(
                        "web",
                        "update",
                        "interfaces",
                        Some(&what),
                        &json!({"applied": rep.applied}),
                    )
                    .await;
                Ok(rep)
            }
            Err(e) => {
                if let Err(re) = netconf::restore_tables(&self.store, &snap).await {
                    tracing::error!("restoring interfaces config after a failed apply: {re}");
                }
                if let Err(e2) = self.applier.apply(&self.store).await {
                    tracing::error!("re-applying the previous interfaces config: {e2}");
                }
                // The re-apply leaves rows the previous config did not
                // manage alone, so addresses the failed attempt already put
                // on such an interface would stay: take them off again.
                let now = self.kernel().await;
                for (dev, net) in leftover_addrs(&kernel, &now, &after) {
                    let a = ["addr", "del", &net, "dev", &dev].map(str::to_string);
                    if let Err(e3) = self.cmd.run("ip", &a).await {
                        tracing::error!("removing {net} from {dev} after a failed apply: {e3}");
                    }
                }
                if roles_changed {
                    let _ = self.firewall.apply(&self.store).await;
                }
                Err(anyhow::anyhow!("failed to apply interfaces ({what}): {e}"))
            }
        }
    }

    /// Everything the Interfaces page shows.
    pub async fn overview(&self, client: Option<IpAddr>) -> anyhow::Result<Value> {
        let cfg = NetConfig::load(&self.store).await.map_err(Self::e)?;
        let k = self.kernel().await;
        let virt = cfg.virtual_names();
        let mut devices = Vec::new();
        for l in k.links.values() {
            if l.name == "lo" {
                continue;
            }
            devices.push(json!({
                "name": l.name,
                "kind": l.kind.clone().unwrap_or_else(|| "ethernet".into()),
                "up": l.up,
                "operstate": l.operstate,
                "mac": l.mac,
                "mtu": l.mtu,
                "master": l.master,
                "parent": l.link,
                "rx_bytes": l.rx_bytes,
                "tx_bytes": l.tx_bytes,
                "patronus_created": l.managed(),
                "addresses": l.addrs.iter().filter(|a| a.scope != "host").map(|a| json!({
                    "address": a.net.to_string(),
                    "dynamic": a.dynamic,
                    "scope": a.scope,
                })).collect::<Vec<_>>(),
                "config": cfg.iface(&l.name),
                "member_of": cfg.master_of(&l.name),
            }));
        }
        // configured but not (yet) present: missing NICs, pending PPPoE
        let present: BTreeSet<&String> = k.links.keys().collect();
        let mut missing = Vec::new();
        for n in cfg
            .interfaces
            .iter()
            .map(|i| i.name.clone())
            .chain(virt.iter().cloned())
        {
            if !present.contains(&n) && !missing.contains(&n) {
                missing.push(n);
            }
        }
        let roles: Vec<Value> = cfg
            .interfaces
            .iter()
            .filter_map(|i| {
                i.role
                    .as_ref()
                    .map(|r| json!({"role": r, "interface": i.name, "enabled": i.enabled}))
            })
            .collect();
        let client_dev = self.client_path(client).await;
        let sup = patronus_network::supervise::Supervisor::detect();
        let daemons: Vec<Value> = [
            patronus_network::dhcp_client::SERVICE,
            patronus_network::PPPOE_SERVICE,
        ]
        .iter()
        .flat_map(|svc| {
            let sup = &sup;
            sup.instances(svc).into_iter().map(
                move |i| json!({"service": svc, "instance": i, "running": sup.is_running(svc, &i)}),
            )
        })
        .collect();
        let dhcp_override = self
            .store
            .load_system_config(patronus_network::dhcp_client::CLIENT_KEY)
            .await
            .map_err(Self::e)?;
        Ok(json!({
            "features": patronus_network::interface_features(),
            "dhcp_client_override": dhcp_override,
            "devices": devices,
            "missing": missing,
            "roles": roles,
            "mgmt": mgmt_set(&cfg),
            "client_interface": client_dev.map(|(d, s)| json!({"interface": d, "address": s})),
            "vlans": cfg.vlans,
            "bonds": cfg.bonds,
            "bridges": cfg.bridges,
            "pppoe": cfg.pppoe.iter().map(PppoeConfig::redacted).collect::<Vec<_>>(),
            "daemons": daemons,
        }))
    }

    /// Kernel interfaces in the legacy template shape (dashboard, network
    /// page, `/api/network/interfaces`).
    pub async fn list_template(&self) -> anyhow::Result<Vec<crate::templates::InterfaceInfo>> {
        let k = self.kernel().await;
        Ok(k.links
            .values()
            .filter(|l| l.name != "lo")
            .map(|l| {
                let addrs: Vec<String> = l
                    .addrs
                    .iter()
                    .filter(|a| a.scope != "host")
                    .map(|a| a.net.to_string())
                    .collect();
                crate::templates::InterfaceInfo {
                    name: l.name.clone(),
                    state: if l.up { "UP".into() } else { "DOWN".into() },
                    ip_address: addrs
                        .first()
                        .map(|a| a.split('/').next().unwrap_or(a).to_string()),
                    ip_display: if addrs.is_empty() {
                        "none".into()
                    } else {
                        addrs.join(", ")
                    },
                    ip_addresses: addrs,
                    mac_address: l.mac.clone().unwrap_or_else(|| "N/A".into()),
                    mac_display: l.mac.clone().unwrap_or_else(|| "N/A".into()),
                    rx_bytes: l.rx_bytes,
                    tx_bytes: l.tx_bytes,
                    mtu: l.mtu,
                    enabled: l.up,
                    interface_type: l.kind.clone().unwrap_or_else(|| "ethernet".into()),
                    speed_display: std::fs::read_to_string(format!(
                        "/sys/class/net/{}/speed",
                        l.name
                    ))
                    .ok()
                    .and_then(|s| s.trim().parse::<i64>().ok())
                    .filter(|s| *s > 0)
                    .map(|s| {
                        if s >= 1000 {
                            format!("{} Gbps", s / 1000)
                        } else {
                            format!("{s} Mbps")
                        }
                    })
                    .unwrap_or_else(|| "n/a".into()),
                }
            })
            .collect())
    }

    /// Assign a role and configure addressing/MTU/MAC of one interface.
    pub async fn update_interface(
        &self,
        name: &str,
        u: InterfaceUpdate,
        client: Option<IpAddr>,
    ) -> anyhow::Result<ApplyReport> {
        if !netconf::is_valid_ifname(name) {
            anyhow::bail!("Invalid interface name {name:?}");
        }
        let ipv4_mode = V4Mode::parse(&u.ipv4_mode).map_err(Self::e)?;
        let ipv6_mode = V6Mode::parse(&u.ipv6_mode).map_err(Self::e)?;
        let ipv4 = parse_nets(&u.ipv4, false)?;
        let ipv6 = parse_nets(&u.ipv6, true)?;
        let gateway4 = parse_ip(&u.gateway4)?;
        let gateway6 = parse_ip(&u.gateway6)?;
        let mac = opt(&u.mac)
            .map(|m| netconf::normalize_mac(&m))
            .transpose()
            .map_err(Self::e)?;
        let role = opt(&u.role)
            .map(|r| r.to_ascii_lowercase())
            .filter(|r| r != "none");
        let name = name.to_string();
        self.mutate(format!("interface {name}"), client, u.force, move |c| {
            let i: &mut IfaceConfig = c.iface_mut(&name);
            i.role = role;
            if let Some(e) = u.enabled {
                i.enabled = e;
            }
            i.ipv4_mode = ipv4_mode;
            i.ipv4 = if ipv4_mode == V4Mode::Static {
                ipv4
            } else {
                Vec::new()
            };
            i.gateway4 = if ipv4_mode == V4Mode::Static {
                gateway4
            } else {
                None
            };
            i.ipv6_mode = ipv6_mode;
            i.ipv6 = if ipv6_mode == V6Mode::Static {
                ipv6
            } else {
                Vec::new()
            };
            i.gateway6 = if ipv6_mode == V6Mode::Static {
                gateway6
            } else {
                None
            };
            i.mtu = u.mtu.filter(|m| *m > 0);
            i.mac = mac;
            i.description = opt(&u.description);
            Ok(())
        })
        .await
    }

    /// Administratively enable/disable an interface (persisted).
    pub async fn set_enabled(
        &self,
        name: &str,
        enabled: bool,
        client: Option<IpAddr>,
        force: bool,
    ) -> anyhow::Result<ApplyReport> {
        let name = name.to_string();
        let k = self.kernel().await;
        let cfg = NetConfig::load(&self.store).await.map_err(Self::e)?;
        if k.get(&name).is_none() && cfg.iface(&name).is_none() {
            anyhow::bail!("Invalid interface {name:?}: no such interface");
        }
        self.mutate(
            format!("{} {name}", if enabled { "enable" } else { "disable" }),
            client,
            force,
            move |c| {
                c.iface_mut(&name).enabled = enabled;
                Ok(())
            },
        )
        .await
    }

    pub async fn upsert_vlan(
        &self,
        b: VlanBody,
        client: Option<IpAddr>,
    ) -> anyhow::Result<ApplyReport> {
        if !cfg!(feature = "vlan") {
            anyhow::bail!("Invalid request: this build has no VLAN support (USE=vlan)");
        }
        let protocol = b
            .protocol
            .clone()
            .map(|p| p.to_ascii_lowercase())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "802.1q".into());
        let name = opt(&b.name).unwrap_or_else(|| format!("{}.{}", b.parent, b.vlan_id));
        let v = VlanConfig {
            name: name.clone(),
            parent: b.parent.trim().to_string(),
            vlan_id: b.vlan_id,
            protocol,
            enabled: b.enabled.unwrap_or(true),
            description: opt(&b.description),
        };
        self.mutate(format!("VLAN {name}"), client, b.force, move |c| {
            c.vlans.retain(|x| x.name != v.name);
            c.vlans.push(v);
            Ok(())
        })
        .await
    }

    pub async fn upsert_bond(
        &self,
        b: BondBody,
        client: Option<IpAddr>,
    ) -> anyhow::Result<ApplyReport> {
        let name = b.name.trim().to_string();
        let bond = BondConfig {
            name: name.clone(),
            mode: opt(&b.mode).unwrap_or_else(|| "active-backup".into()),
            miimon: b.miimon.unwrap_or(100),
            lacp_rate: opt(&b.lacp_rate),
            xmit_hash_policy: opt(&b.xmit_hash_policy),
            primary: opt(&b.primary),
            members: b
                .members
                .iter()
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect(),
            enabled: b.enabled.unwrap_or(true),
            description: opt(&b.description),
        };
        if bond.members.is_empty() {
            anyhow::bail!("Invalid bond {name:?}: at least one member port is required");
        }
        self.mutate(format!("bond {name}"), client, b.force, move |c| {
            c.bonds.retain(|x| x.name != bond.name);
            c.bonds.push(bond);
            Ok(())
        })
        .await
    }

    pub async fn upsert_bridge(
        &self,
        b: BridgeBody,
        client: Option<IpAddr>,
    ) -> anyhow::Result<ApplyReport> {
        let name = b.name.trim().to_string();
        let br = BridgeConfig {
            name: name.clone(),
            stp: b.stp,
            members: b
                .members
                .iter()
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty())
                .collect(),
            enabled: b.enabled.unwrap_or(true),
            description: opt(&b.description),
        };
        self.mutate(format!("bridge {name}"), client, b.force, move |c| {
            c.bridges.retain(|x| x.name != br.name);
            c.bridges.push(br);
            Ok(())
        })
        .await
    }

    pub async fn upsert_pppoe(
        &self,
        b: PppoeBody,
        client: Option<IpAddr>,
    ) -> anyhow::Result<ApplyReport> {
        if !cfg!(feature = "pppoe") {
            anyhow::bail!("Invalid request: this build has no PPPoE support (USE=pppoe)");
        }
        let name = b.name.trim().to_string();
        let mut p = PppoeConfig {
            name: name.clone(),
            parent: b.parent.trim().to_string(),
            username: b.username.trim().to_string(),
            password: b.password.clone(),
            service_name: opt(&b.service_name),
            mtu: b.mtu.unwrap_or(1492),
            default_route: b.default_route.unwrap_or(true),
            use_peer_dns: b.use_peer_dns.unwrap_or(true),
            ipv6: b.ipv6,
            enabled: b.enabled.unwrap_or(true),
            description: opt(&b.description),
        };
        self.mutate(format!("PPPoE {name}"), client, b.force, move |c| {
            if p.password.is_empty() {
                p.password = c
                    .pppoe
                    .iter()
                    .find(|x| x.name == p.name)
                    .map(|x| x.password.clone())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Invalid PPPoE {}: password is required", p.name)
                    })?;
            }
            c.pppoe.retain(|x| x.name != p.name);
            c.pppoe.push(p);
            Ok(())
        })
        .await
    }

    /// Delete a VLAN / bond / bridge / PPPoE link (refused while it carries
    /// a role or other devices sit on it).
    pub async fn delete_virtual(
        &self,
        kind: &str,
        name: &str,
        client: Option<IpAddr>,
        force: bool,
    ) -> anyhow::Result<ApplyReport> {
        let (kind, name) = (kind.to_string(), name.to_string());
        self.mutate(format!("delete {kind} {name}"), client, force, move |c| {
            let found = match kind.as_str() {
                "vlans" => c.vlans.iter().any(|x| x.name == name),
                "bonds" => c.bonds.iter().any(|x| x.name == name),
                "bridges" => c.bridges.iter().any(|x| x.name == name),
                "pppoe" => c.pppoe.iter().any(|x| x.name == name),
                _ => false,
            };
            if !found {
                anyhow::bail!("Invalid request: no {kind} named {name:?}");
            }
            if let Some(r) = c.iface(&name).and_then(|i| i.role.clone()) {
                anyhow::bail!(
                    "Invalid request: {name} is assigned as {}; assign that role elsewhere first",
                    r.to_uppercase()
                );
            }
            let users: Vec<String> = c
                .users_of(&name)
                .into_iter()
                .filter(|u| {
                    !(kind == "bonds" && u == &format!("bond {name}"))
                        && !(kind == "bridges" && u == &format!("bridge {name}"))
                })
                .collect();
            if !users.is_empty() {
                anyhow::bail!("Invalid request: {name} is used by {}", users.join(", "));
            }
            match kind.as_str() {
                "vlans" => c.vlans.retain(|x| x.name != name),
                "bonds" => c.bonds.retain(|x| x.name != name),
                "bridges" => c.bridges.retain(|x| x.name != name),
                _ => c.pppoe.retain(|x| x.name != name),
            }
            c.interfaces.retain(|i| i.name != name);
            Ok(())
        })
        .await
    }

    /// Choose the DHCP client (`dhcpcd`, `udhcpc`, or "" for the build default).
    pub async fn set_dhcp_client(&self, client: &str) -> anyhow::Result<ApplyReport> {
        let c = client.trim();
        if !c.is_empty() && c != "dhcpcd" && c != "udhcpc" {
            anyhow::bail!("Invalid DHCP client {c:?} (dhcpcd or udhcpc)");
        }
        {
            let _g = self.edit.lock().await;
            self.store
                .save_system_config(patronus_network::dhcp_client::CLIENT_KEY, c)
                .await
                .map_err(Self::e)?;
        }
        self.apply().await
    }
}

/// Static addresses the rejected config (`wanted`) asked for that are on
/// the kernel now but were not before the attempt (`before`): what a
/// half-applied change left behind. DHCP/SLAAC (finite lifetime) and
/// link-local addresses are never touched.
fn leftover_addrs(
    before: &KernelState,
    now: &KernelState,
    wanted: &NetConfig,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for i in &wanted.interfaces {
        let Some(link) = now.get(&i.name) else {
            continue;
        };
        let had = before.get(&i.name);
        for a in &link.addrs {
            let asked = i.ipv4.contains(&a.net) || i.ipv6.contains(&a.net);
            let existed = had.is_some_and(|h| h.addrs.iter().any(|o| o.net == a.net));
            if asked && !existed && !a.dynamic && a.scope == "global" {
                out.push((i.name.clone(), a.net.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::Phase;
    use std::sync::Mutex as StdMutex;

    /// Fake kernel: `ip -j` answers from fixed JSON, records mutations.
    struct FakeIp {
        log: StdMutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl Cmd for FakeIp {
        async fn run(&self, _p: &str, a: &[String]) -> patronus_core::Result<String> {
            let line = a.join(" ");
            if line == "-j -d -s link show" {
                return Ok(r#"[{"ifindex":2,"ifname":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:01"},
                    {"ifindex":3,"ifname":"eth1","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:02"},
                    {"ifindex":4,"ifname":"eth2","flags":[],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"52:54:00:00:00:03"}]"#.into());
            }
            if line.starts_with("-j route get") {
                return Ok(
                    r#"[{"dst":"192.168.1.50","dev":"eth1","prefsrc":"192.168.1.1"}]"#.into(),
                );
            }
            if line.starts_with("-j") {
                return Ok("[]".into());
            }
            self.log.lock().unwrap().push(line);
            Ok(String::new())
        }
    }

    struct Rec {
        name: &'static str,
        n: StdMutex<u32>,
        fail: StdMutex<bool>,
    }
    #[async_trait::async_trait]
    impl Applier for Rec {
        fn name(&self) -> &'static str {
            self.name
        }
        fn phase(&self) -> Phase {
            Phase::Interfaces
        }
        async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
            *self.n.lock().unwrap() += 1;
            if *self.fail.lock().unwrap() {
                return Err(patronus_core::Error::Network("ip: boom".into()));
            }
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
            Ok(String::new())
        }
    }

    async fn mgr() -> (InterfacesManager, Arc<Rec>, Arc<Rec>, Arc<ConfigStore>) {
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        store.set_interface_role("eth0", Some("wan")).await.unwrap();
        store.set_interface_role("eth1", Some("lan")).await.unwrap();
        let ifa = Arc::new(Rec {
            name: "interfaces",
            n: StdMutex::new(0),
            fail: StdMutex::new(false),
        });
        let fw = Arc::new(Rec {
            name: "firewall",
            n: StdMutex::new(0),
            fail: StdMutex::new(false),
        });
        let m = InterfacesManager::new(
            store.clone(),
            ifa.clone(),
            fw.clone(),
            Arc::new(FakeIp {
                log: StdMutex::new(vec![]),
            }),
        );
        (m, ifa, fw, store)
    }

    fn admin() -> Option<IpAddr> {
        Some("192.168.1.50".parse().unwrap())
    }

    fn static_lan(addr: &str) -> InterfaceUpdate {
        InterfaceUpdate {
            role: Some("lan".into()),
            ipv4_mode: "static".into(),
            ipv4: vec![addr.into()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn changes_are_stored_applied_and_role_changes_reapply_the_firewall() {
        let (m, ifa, fw, store) = mgr().await;
        m.update_interface("eth1", static_lan("192.168.1.1/24"), admin())
            .await
            .unwrap();
        assert_eq!(*ifa.n.lock().unwrap(), 1);
        assert_eq!(
            *fw.n.lock().unwrap(),
            0,
            "role unchanged: no firewall apply"
        );
        let c = NetConfig::load(&store).await.unwrap();
        assert_eq!(
            c.iface("eth1").unwrap().ipv4[0].to_string(),
            "192.168.1.1/24"
        );
        m.update_interface(
            "eth2",
            InterfaceUpdate {
                role: Some("opt1".into()),
                ipv4_mode: "dhcp".into(),
                ..Default::default()
            },
            admin(),
        )
        .await
        .unwrap();
        assert_eq!(*fw.n.lock().unwrap(), 1);
        assert_eq!(
            store.interfaces_with_role("opt1").await.unwrap(),
            vec!["eth2"]
        );
        assert!(
            !store.list_revisions().await.unwrap().is_empty(),
            "config history recorded"
        );
    }

    #[tokio::test]
    async fn invalid_input_is_rejected_before_anything_is_written() {
        let (m, ifa, _, store) = mgr().await;
        for (u, needle) in [
            (static_lan("192.168.1.1"), "CIDR"),
            (static_lan("fd00::1/64"), "IPv4"),
            (
                InterfaceUpdate {
                    ipv4_mode: "bogus".into(),
                    ..Default::default()
                },
                "IPv4 mode",
            ),
            (
                InterfaceUpdate {
                    mac: Some("zz".into()),
                    ..Default::default()
                },
                "MAC",
            ),
            (
                InterfaceUpdate {
                    role: Some("dmz".into()),
                    ..Default::default()
                },
                "role",
            ),
        ] {
            let e = m
                .update_interface("eth2", u, None)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("Invalid") && e.contains(needle), "{needle}: {e}");
        }
        assert_eq!(*ifa.n.lock().unwrap(), 0);
        assert!(NetConfig::load(&store)
            .await
            .unwrap()
            .iface("eth2")
            .is_none());
        let e = m
            .upsert_bond(
                BondBody {
                    name: "bond0".into(),
                    members: vec!["eth9".into()],
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Invalid") && e.contains("eth9"), "{e}");
    }

    #[tokio::test]
    async fn changes_that_would_cut_off_the_admin_are_refused_unless_forced() {
        let (m, ifa, _, store) = mgr().await;
        m.update_interface("eth1", static_lan("192.168.1.1/24"), admin())
            .await
            .unwrap();
        let n = *ifa.n.lock().unwrap();
        // moving LAN (and with it anti-lockout) off the admin's interface
        let mut moved = static_lan("192.168.1.1/24");
        moved.role = Some("opt1".into());
        let e = m
            .update_interface("eth1", moved.clone(), admin())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.starts_with(LOCKOUT) && e.contains("anti-lockout"), "{e}");
        // ... changing the address the admin is connected to
        let e = m
            .update_interface("eth1", static_lan("192.168.1.2/24"), admin())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no longer has that address"), "{e}");
        // ... disabling it, or enslaving it into a bridge
        assert!(m
            .set_enabled("eth1", false, admin(), false)
            .await
            .unwrap_err()
            .to_string()
            .starts_with(LOCKOUT));
        assert_eq!(*ifa.n.lock().unwrap(), n, "nothing applied");
        assert_eq!(
            store.interfaces_with_role("lan").await.unwrap(),
            vec!["eth1"]
        );
        // adding an address keeps the admin's one: fine
        let mut u = static_lan("192.168.1.1/24");
        u.ipv4.push("192.168.2.1/24".into());
        m.update_interface("eth1", u, admin()).await.unwrap();
        // the same change from the console (no client) or forced goes through
        m.update_interface("eth1", static_lan("192.168.1.2/24"), None)
            .await
            .unwrap();
        moved.force = true;
        m.update_interface("eth1", moved, admin()).await.unwrap();
        assert!(store.interfaces_with_role("lan").await.unwrap().is_empty());
    }

    #[test]
    fn a_half_applied_change_leaves_only_the_addresses_it_added_for_cleanup() {
        let links = r#"[{"ifindex":4,"ifname":"eth2","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:03"}]"#;
        let addr = |extra: &str| {
            format!(
                r#"[{{"ifname":"eth2","addr_info":[
                    {{"family":"inet","local":"10.0.0.7","prefixlen":24,"scope":"global","valid_life_time":4294967295}},
                    {{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link","valid_life_time":4294967295}}{extra}]}}]"#
            )
        };
        let before = KernelState::parse(links, &addr("")).unwrap();
        let now = KernelState::parse(
            links,
            &addr(
                r#",{"family":"inet","local":"10.9.9.1","prefixlen":24,"scope":"global","valid_life_time":4294967295},
                   {"family":"inet","local":"10.8.8.8","prefixlen":24,"scope":"global","valid_life_time":4294967295},
                   {"family":"inet6","local":"fd00:9::1","prefixlen":64,"scope":"global","valid_life_time":4294967295},
                   {"family":"inet","local":"203.0.113.5","prefixlen":24,"scope":"global","valid_life_time":600}"#,
            ),
        )
        .unwrap();
        let mut wanted = NetConfig::default();
        let mut i = IfaceConfig::new("eth2");
        i.ipv4_mode = V4Mode::Static;
        i.ipv4 = vec![
            "10.9.9.1/24".parse().unwrap(),
            "10.0.0.7/24".parse().unwrap(),
        ];
        i.ipv6_mode = V6Mode::Static;
        i.ipv6 = vec!["fd00:9::1/64".parse().unwrap()];
        wanted.interfaces.push(i);
        // added by the attempt -> removed; already there before (10.0.0.7),
        // not asked for (10.8.8.8), DHCP (finite lifetime), link-local -> kept
        assert_eq!(
            leftover_addrs(&before, &now, &wanted),
            vec![
                ("eth2".to_string(), "10.9.9.1/24".to_string()),
                ("eth2".to_string(), "fd00:9::1/64".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn a_failed_apply_restores_the_previous_config_and_reapplies_it() {
        let (m, ifa, _, store) = mgr().await;
        m.update_interface("eth1", static_lan("192.168.1.1/24"), None)
            .await
            .unwrap();
        *ifa.fail.lock().unwrap() = true;
        let e = m
            .update_interface("eth1", static_lan("192.168.5.1/24"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("boom"), "{e}");
        let c = NetConfig::load(&store).await.unwrap();
        assert_eq!(
            c.iface("eth1").unwrap().ipv4[0].to_string(),
            "192.168.1.1/24"
        );
        assert_eq!(
            *ifa.n.lock().unwrap(),
            3,
            "apply, failed apply, re-apply of the old config"
        );
    }

    #[tokio::test]
    async fn virtual_devices_cannot_be_deleted_while_in_use() {
        let (m, _, _, _) = mgr().await;
        m.upsert_bridge(
            BridgeBody {
                name: "br0".into(),
                members: vec!["eth2".into()],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        m.update_interface(
            "br0",
            InterfaceUpdate {
                role: Some("opt1".into()),
                ipv4_mode: "static".into(),
                ipv4: vec!["10.1.0.1/24".into()],
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        let e = m
            .delete_virtual("bridges", "br0", None, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("assigned as OPT1"), "{e}");
        m.update_interface("br0", InterfaceUpdate::default(), None)
            .await
            .unwrap();
        m.delete_virtual("bridges", "br0", None, false)
            .await
            .unwrap();
        let e = m
            .delete_virtual("bridges", "br0", None, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no bridges named"), "{e}");
    }

    #[test]
    fn mgmt_follows_lan_then_wan_then_any() {
        let mut c = NetConfig::default();
        assert_eq!(mgmt_set(&c), None);
        c.iface_mut("eth0").role = Some("wan".into());
        assert_eq!(
            mgmt_set(&c).unwrap().into_iter().collect::<Vec<_>>(),
            vec!["eth0"]
        );
        c.iface_mut("eth1").role = Some("lan".into());
        assert_eq!(
            mgmt_set(&c).unwrap().into_iter().collect::<Vec<_>>(),
            vec!["eth1"]
        );
    }
}
