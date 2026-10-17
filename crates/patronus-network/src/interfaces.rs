//! Network interfaces: listing (rtnetlink) and the interfaces [`Applier`]
//! (lane C): store -> kernel for roles, static/DHCP/PPPoE addressing,
//! IPv6, MTU/MAC, VLANs, bonds and bridges. See [`InterfacesApplier`].

use futures::TryStreamExt;
use patronus_core::{
    types::{Interface, IpNetwork},
    Error, Result,
};
use rtnetlink::{new_connection, Handle};
use std::net::IpAddr;

/// Manages network interfaces
pub struct InterfaceManager {
    handle: Handle,
}

impl InterfaceManager {
    /// Create a new interface manager
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()
            .map_err(|e| Error::Network(format!("Failed to create netlink connection: {}", e)))?;

        // Spawn the connection in the background
        tokio::spawn(connection);

        Ok(Self { handle })
    }

    /// List all network interfaces
    pub async fn list(&self) -> Result<Vec<Interface>> {
        let mut links = self.handle.link().get().execute();
        let mut interfaces = Vec::new();

        while let Some(msg) = links
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get interfaces: {}", e)))?
        {
            use netlink_packet_route::link::LinkAttribute;

            let name = msg
                .attributes
                .iter()
                .find_map(|attr| {
                    if let LinkAttribute::IfName(name) = attr {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| format!("interface{}", msg.header.index));

            // Extract MAC address
            let mac_address = msg.attributes.iter().find_map(|attr| {
                if let LinkAttribute::Address(addr) = attr {
                    Some(
                        addr.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":"),
                    )
                } else {
                    None
                }
            });

            // Get IP addresses for this interface
            let ip_addresses = self.get_interface_ips(msg.header.index).await?;

            // Extract MTU from attributes if available
            let mtu = msg
                .attributes
                .iter()
                .find_map(|attr| {
                    if let LinkAttribute::Mtu(mtu) = attr {
                        Some(*mtu)
                    } else {
                        None
                    }
                })
                .unwrap_or(1500); // Default MTU

            // Check if interface is up by looking for IFF_UP flag
            let enabled = msg
                .header
                .flags
                .iter()
                .any(|flag| matches!(flag, netlink_packet_route::link::LinkFlag::Up));

            let interface = Interface {
                name,
                mac_address,
                ip_addresses,
                mtu,
                enabled,
                index: msg.header.index,
            };

            interfaces.push(interface);
        }

        Ok(interfaces)
    }

    /// Get IP addresses for a specific interface
    async fn get_interface_ips(&self, index: u32) -> Result<Vec<IpAddr>> {
        let mut addresses = self.handle.address().get().execute();
        let mut ips = Vec::new();

        while let Some(msg) = addresses
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get addresses: {}", e)))?
        {
            // Check if this address belongs to our interface
            if msg.header.index != index {
                continue;
            }

            use netlink_packet_route::address::AddressAttribute;

            // Extract the address
            for attr in &msg.attributes {
                if let AddressAttribute::Address(addr) = attr {
                    ips.push(*addr);
                }
            }
        }

        Ok(ips)
    }

    /// Get a specific interface by name
    pub async fn get_by_name(&self, name: &str) -> Result<Option<Interface>> {
        let interfaces = self.list().await?;
        Ok(interfaces.into_iter().find(|iface| iface.name == name))
    }

    /// Get a specific interface by index
    pub async fn get_by_index(&self, index: u32) -> Result<Option<Interface>> {
        let interfaces = self.list().await?;
        Ok(interfaces.into_iter().find(|iface| iface.index == index))
    }

    /// Enable a network interface (bring it up)
    pub async fn enable(&self, name: &str) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .up()
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to enable interface {}: {}", name, e)))?;

        tracing::info!("Enabled interface: {}", name);
        Ok(())
    }

    /// Disable a network interface (bring it down)
    pub async fn disable(&self, name: &str) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .down()
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to disable interface {}: {}", name, e)))?;

        tracing::info!("Disabled interface: {}", name);
        Ok(())
    }

    /// Set MTU for an interface
    pub async fn set_mtu(&self, name: &str, mtu: u32) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .link()
            .set(interface.index)
            .mtu(mtu)
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to set MTU for {}: {}", name, e)))?;

        tracing::info!("Set MTU for {} to {}", name, mtu);
        Ok(())
    }

    /// Add an IP address to an interface
    pub async fn add_ip(&self, name: &str, ip: IpNetwork) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .address()
            .add(interface.index, ip.addr, ip.prefix_len)
            .execute()
            .await
            .map_err(|e| Error::Network(format!("Failed to add IP {} to {}: {}", ip, name, e)))?;

        tracing::info!("Added IP {} to interface {}", ip.to_string(), name);
        Ok(())
    }

    /// Remove an IP address from an interface
    pub async fn remove_ip(&self, name: &str, ip: IpNetwork) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        self.handle
            .address()
            .del(
                self.handle
                    .address()
                    .add(interface.index, ip.addr, ip.prefix_len)
                    .message_mut()
                    .clone(),
            )
            .execute()
            .await
            .map_err(|e| {
                Error::Network(format!("Failed to remove IP {} from {}: {}", ip, name, e))
            })?;

        tracing::info!("Removed IP {} from interface {}", ip.to_string(), name);
        Ok(())
    }

    /// Flush all IP addresses from an interface
    pub async fn flush_ips(&self, name: &str) -> Result<()> {
        let interface = self
            .get_by_name(name)
            .await?
            .ok_or_else(|| Error::Network(format!("Interface not found: {}", name)))?;

        // Get all addresses for this interface
        let mut addresses = self.handle.address().get().execute();

        while let Some(msg) = addresses
            .try_next()
            .await
            .map_err(|e| Error::Network(format!("Failed to get addresses: {}", e)))?
        {
            if msg.header.index != interface.index {
                continue;
            }

            // Delete this address
            self.handle
                .address()
                .del(msg)
                .execute()
                .await
                .map_err(|e| Error::Network(format!("Failed to delete address: {}", e)))?;
        }

        tracing::info!("Flushed all IPs from interface: {}", name);
        Ok(())
    }
}

// =====================================================================
// Interfaces applier (lane C, boot phase `interfaces`)
// =====================================================================

use crate::dhcp_client;
use crate::linkstate::{argv, Cmd, KLink, KernelState, SystemCmd, MANAGED_ALIAS};
use crate::netconf::{IfaceConfig, NetConfig, V4Mode, V6Mode};
use crate::supervise::{DaemonSpec, NetPaths, Supervisor};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::declarative::{DeclarativeConfig, ResourceKind, ResourceSpec};
use patronus_config::store::ConfigStore;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

/// Route protocol number Patronus tags the default routes of static
/// interface gateways with, so it only ever removes its own routes.
pub const ROUTE_PROTO: &str = "250";

/// One step of an interfaces apply.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// `ip <args>`
    Ip(Vec<String>),
    /// Write `/proc/sys/<path>`.
    Sysctl { path: String, value: String },
    /// Keep a daemon (DHCP client, pppd) running with this exact config.
    Ensure(DaemonSpec),
    /// Stop a daemon Patronus started.
    Stop {
        service: &'static str,
        instance: String,
    },
}

impl Op {
    pub fn describe(&self) -> String {
        match self {
            Op::Ip(a) => format!("ip {}", a.join(" ")),
            Op::Sysctl { path, value } => format!("{} = {value}", path.replace('/', ".")),
            Op::Ensure(s) => format!("run {}", s.describe()),
            Op::Stop { service, instance } => format!("stop {service}[{instance}]"),
        }
    }
}

/// What an apply would do.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub ops: Vec<Op>,
    pub warnings: Vec<String>,
}

/// Resolved DHCP client: (client, argv prefix, fallback warning).
pub type DhcpChoice =
    std::result::Result<(dhcp_client::Client, Vec<String>, Option<String>), String>;

/// Everything [`plan`] looks at.
pub struct PlanInput<'a> {
    pub cfg: &'a NetConfig,
    pub kernel: &'a KernelState,
    /// (service, instance) Patronus manages (has started) now.
    pub managed: &'a BTreeSet<(String, String)>,
    /// (service, instance) currently running.
    pub running: &'a BTreeSet<(String, String)>,
    /// DHCP client for IPv4-only use and for DHCPv6 use.
    pub dhcp_v4: &'a DhcpChoice,
    pub dhcp_v6: &'a DhcpChoice,
    /// Current value of a `/proc/sys` path (`net/ipv6/conf/eth0/accept_ra`).
    pub sysctl: &'a dyn Fn(&str) -> Option<String>,
    pub paths: &'a NetPaths,
}

struct Planner<'a> {
    inp: &'a PlanInput<'a>,
    plan: Plan,
    deleted: BTreeSet<String>,
    created: BTreeSet<String>,
    /// names configured but blocked by a foreign kernel device
    skip: BTreeSet<String>,
    upped: BTreeSet<String>,
    disabled: BTreeSet<String>,
}

fn ip(a: &[&str]) -> Op {
    Op::Ip(argv(a))
}

impl<'a> Planner<'a> {
    fn present(&self, n: &str) -> bool {
        self.created.contains(n) || (self.inp.kernel.get(n).is_some() && !self.deleted.contains(n))
    }

    /// Kernel view of a device that still exists unchanged (None if it
    /// was just created or is gone).
    fn klink(&self, n: &str) -> Option<&'a KLink> {
        if self.created.contains(n) || self.deleted.contains(n) {
            None
        } else {
            self.inp.kernel.get(n)
        }
    }

    fn warn(&mut self, w: String) {
        if !self.plan.warnings.contains(&w) {
            self.plan.warnings.push(w);
        }
    }

    fn push(&mut self, op: Op) {
        self.plan.ops.push(op);
    }

    fn up(&mut self, n: &str) {
        if self.disabled.contains(n) || self.upped.contains(n) {
            return;
        }
        let is_up = self.klink(n).map(|k| k.up).unwrap_or(false);
        if !is_up {
            self.push(ip(&["link", "set", "dev", n, "up"]));
        }
        self.upped.insert(n.to_string());
    }

    /// Delete a managed device; VLANs stacked on it disappear with it.
    fn delete(&mut self, n: &str) {
        if self.deleted.contains(n) {
            return;
        }
        self.push(ip(&["link", "del", "dev", n]));
        self.mark_deleted(n);
    }

    fn mark_deleted(&mut self, n: &str) {
        self.deleted.insert(n.to_string());
        let children: Vec<String> = self
            .inp
            .kernel
            .links
            .values()
            .filter(|l| l.kind.as_deref() == Some("vlan") && l.link.as_deref() == Some(n))
            .map(|l| l.name.clone())
            .collect();
        for c in children {
            if !self.deleted.contains(&c) {
                self.mark_deleted(&c);
            }
        }
    }

    fn create(&mut self, args: Vec<String>, n: &str) {
        self.push(Op::Ip(args));
        self.push(ip(&["link", "set", "dev", n, "alias", MANAGED_ALIAS]));
        self.created.insert(n.to_string());
    }

    /// Enslave `m` to `master` unless it already is.
    fn enslave(&mut self, m: &str, master: &str, bond: bool) {
        if !self.present(m) {
            self.warn(format!("{master}: member {m} does not exist; skipped"));
            return;
        }
        let cur = self.klink(m).and_then(|k| k.master.clone());
        let master_fresh = self.created.contains(master);
        if cur.as_deref() == Some(master) && !master_fresh {
            self.up(m);
            return;
        }
        if let Some(o) = cur {
            if !self.deleted.contains(&o) {
                self.push(ip(&["link", "set", "dev", m, "nomaster"]));
            }
        }
        if bond {
            // the bonding driver only enslaves a port that is down
            self.push(ip(&["link", "set", "dev", m, "down"]));
            self.upped.remove(m);
        }
        self.push(ip(&["link", "set", "dev", m, "master", master]));
        if bond {
            self.push(ip(&["link", "set", "dev", m, "up"]));
            self.upped.insert(m.to_string());
        } else {
            self.up(m);
        }
    }

    /// Release ports a managed master has that are no longer configured.
    fn release_extra(&mut self, master: &str, members: &[String]) {
        if self.created.contains(master) {
            return;
        }
        let extra: Vec<String> = self
            .inp
            .kernel
            .links
            .values()
            .filter(|l| l.master.as_deref() == Some(master) && !members.contains(&l.name))
            .map(|l| l.name.clone())
            .collect();
        for e in extra {
            if !self.deleted.contains(&e) {
                self.push(ip(&["link", "set", "dev", &e, "nomaster"]));
            }
        }
    }

    fn sysctl(&mut self, dev: &str, key: &str, value: &str) {
        let path = format!("net/ipv6/conf/{dev}/{key}");
        let fresh = !self.inp.kernel.links.contains_key(dev) || self.created.contains(dev);
        if fresh || (self.inp.sysctl)(&path).as_deref().map(str::trim) != Some(value) {
            self.push(Op::Sysctl {
                path,
                value: value.to_string(),
            });
        }
    }

    /// Default route via a static gateway (tagged ROUTE_PROTO); removes
    /// stale Patronus gateway routes on this device.
    fn gateway(&mut self, dev: &str, v6: bool, gw: Option<std::net::IpAddr>, metric: u32) {
        let fam = if v6 { "-6" } else { "-4" };
        let mine: Vec<_> = self
            .inp
            .kernel
            .default_routes
            .iter()
            .filter(|r| r.v6 == v6 && r.dev == dev && r.protocol == ROUTE_PROTO)
            .cloned()
            .collect();
        let want = gw.map(|g| g.to_string());
        let mut have_it = false;
        for r in &mine {
            if want.is_some()
                && r.gateway == want
                && r.metric == metric
                && self.klink(dev).is_some()
            {
                have_it = true;
            } else if self.klink(dev).is_some() {
                let mut a = vec!["route", "del", "default"];
                if let Some(g) = &r.gateway {
                    a.extend(["via", g]);
                }
                let m = r.metric.to_string();
                a.extend(["dev", dev, "metric", &m, "proto", ROUTE_PROTO]);
                let mut full = vec![fam];
                full.extend(a);
                self.push(ip(&full));
            }
        }
        if let (Some(g), false) = (want, have_it) {
            let m = metric.to_string();
            self.push(ip(&[
                fam,
                "route",
                "replace",
                "default",
                "via",
                &g,
                "dev",
                dev,
                "metric",
                &m,
                "proto",
                ROUTE_PROTO,
            ]));
        }
    }

    fn addr_diff(
        &mut self,
        dev: &str,
        want: &[ipnetwork::IpNetwork],
        v6: bool,
        keep_dynamic: bool,
    ) {
        let have: Vec<(ipnetwork::IpNetwork, bool)> = self
            .klink(dev)
            .map(|k| {
                if v6 {
                    k.v6_global().map(|a| (a.net, a.dynamic)).collect()
                } else {
                    k.v4()
                        .filter(|a| a.scope != "host")
                        .map(|a| (a.net, a.dynamic))
                        .collect()
                }
            })
            .unwrap_or_default();
        for (a, dynamic) in &have {
            if !want.contains(a) && !(keep_dynamic && *dynamic) {
                self.push(ip(&["addr", "del", &a.to_string(), "dev", dev]));
            }
        }
        for a in want {
            if !have.iter().any(|(h, _)| h == a) {
                self.push(ip(&["addr", "add", &a.to_string(), "dev", dev]));
            }
        }
    }

    fn address(&mut self, i: &IfaceConfig, is_ppp: bool) {
        let dev = i.name.as_str();
        let metric = dhcp_client::metric_for_role(i.role.as_deref());
        let dhcp_running = self
            .inp
            .running
            .contains(&(dhcp_client::SERVICE.to_string(), dev.to_string()));
        if !is_ppp {
            match i.ipv4_mode {
                V4Mode::Unmanaged => {}
                V4Mode::Static => {
                    self.addr_diff(dev, &i.ipv4, false, false);
                    self.gateway(dev, false, i.gateway4, metric);
                }
                V4Mode::Dhcp => {
                    if !dhcp_running {
                        // take over from static config: drop permanent addrs
                        self.addr_diff(dev, &[], false, true);
                    }
                    self.gateway(dev, false, None, metric);
                }
                V4Mode::None => {
                    self.addr_diff(dev, &[], false, false);
                    self.gateway(dev, false, None, metric);
                }
            }
        }
        match i.ipv6_mode {
            V6Mode::Unmanaged => {}
            V6Mode::Static => {
                self.sysctl(dev, "accept_ra", "0");
                self.sysctl(dev, "autoconf", "0");
                self.addr_diff(dev, &i.ipv6, true, false);
                self.gateway(dev, true, i.gateway6, metric);
            }
            V6Mode::Slaac => {
                // forwarding is on, so RAs are only honoured with accept_ra=2
                self.sysctl(dev, "accept_ra", "2");
                self.sysctl(dev, "autoconf", "1");
                self.addr_diff(dev, &[], true, true);
                self.gateway(dev, true, None, metric);
            }
            V6Mode::Dhcp6 => {
                if !dhcp_running {
                    self.addr_diff(dev, &[], true, true);
                }
                self.gateway(dev, true, None, metric);
            }
            V6Mode::None => {
                self.sysctl(dev, "accept_ra", "0");
                self.sysctl(dev, "autoconf", "0");
                self.addr_diff(dev, &[], true, false);
                self.gateway(dev, true, None, metric);
            }
        }
        let v4 = !is_ppp && i.ipv4_mode == V4Mode::Dhcp;
        let v6 = i.ipv6_mode == V6Mode::Dhcp6;
        if v4 || v6 {
            let choice = if v6 {
                self.inp.dhcp_v6
            } else {
                self.inp.dhcp_v4
            };
            match choice {
                Ok((client, prefix, fallback)) => {
                    if let Some(w) = fallback {
                        self.warn(w.clone());
                    }
                    match dhcp_client::spec(
                        dev,
                        v4,
                        v6,
                        i.role.as_deref(),
                        *client,
                        prefix,
                        self.inp.paths,
                    ) {
                        Ok(s) => self.push(Op::Ensure(s)),
                        Err(e) => self.warn(format!("{dev}: DHCP client not started: {e}")),
                    }
                }
                Err(e) => self.warn(format!("{dev}: DHCP client not started: {e}")),
            }
        }
    }

    fn run(mut self) -> Plan {
        let inp = self.inp;
        let mut cfg = inp.cfg.clone();
        if !cfg!(feature = "vlan") && !cfg.vlans.is_empty() {
            self.warn(format!(
                "VLANs {} are configured but this build has no VLAN support (USE=vlan); skipped",
                cfg.vlans
                    .iter()
                    .map(|v| v.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            cfg.vlans.clear();
        }
        if !cfg!(feature = "pppoe") && !cfg.pppoe.is_empty() {
            self.warn(format!(
                "PPPoE links {} are configured but this build has no PPPoE support (USE=pppoe); skipped",
                cfg.pppoe.iter().map(|v| v.name.as_str()).collect::<Vec<_>>().join(", ")
            ));
            cfg.pppoe.clear();
        }
        cfg.vlans.retain(|v| v.enabled);
        cfg.bonds.retain(|v| v.enabled);
        cfg.bridges.retain(|v| v.enabled);
        cfg.pppoe.retain(|v| v.enabled);
        for i in &cfg.interfaces {
            if !i.enabled {
                self.disabled.insert(i.name.clone());
            }
        }

        // foreign devices squatting on a configured name are never touched
        for n in cfg.virtual_names() {
            if let Some(k) = inp.kernel.get(&n) {
                let is_ppp = cfg.pppoe.iter().any(|p| p.name == n);
                if !k.managed() && !(is_ppp && k.kind.as_deref() == Some("ppp")) {
                    self.warn(format!(
                        "{n} already exists and was not created by Patronus; leaving it alone"
                    ));
                    self.skip.insert(n);
                }
            }
        }

        // 1. stop daemons that are no longer wanted
        let want_dhcp: BTreeSet<String> = cfg
            .interfaces
            .iter()
            .filter(|i| i.enabled && (i.ipv4_mode == V4Mode::Dhcp || i.ipv6_mode == V6Mode::Dhcp6))
            .filter(|i| i.ipv6_mode == V6Mode::Dhcp6 || !cfg.pppoe.iter().any(|p| p.name == i.name))
            .map(|i| i.name.clone())
            .collect();
        let want_ppp: BTreeSet<String> = cfg
            .pppoe
            .iter()
            .filter(|p| !self.skip.contains(&p.name))
            .map(|p| p.name.clone())
            .collect();
        for (svc, inst) in inp.managed {
            let stop = (svc == dhcp_client::SERVICE && !want_dhcp.contains(inst))
                || (svc == crate::PPPOE_SERVICE && !want_ppp.contains(inst));
            if stop {
                let service = if svc == dhcp_client::SERVICE {
                    dhcp_client::SERVICE
                } else {
                    crate::PPPOE_SERVICE
                };
                self.push(Op::Stop {
                    service,
                    instance: inst.clone(),
                });
            }
        }

        // 2. delete stale / mismatched Patronus devices
        let kernel_links: Vec<&KLink> = inp.kernel.links.values().collect();
        for k in kernel_links {
            if !k.managed() {
                continue;
            }
            let keep = match k.kind.as_deref() {
                Some("vlan") => cfg
                    .vlans
                    .iter()
                    .any(|v| v.name == k.name && !vlan_mismatch(v, k)),
                Some("bond") => cfg
                    .bonds
                    .iter()
                    .any(|b| b.name == k.name && !crate::bond::needs_recreate(b, k)),
                Some("bridge") => cfg.bridges.iter().any(|b| b.name == k.name),
                _ => true,
            };
            if !keep {
                self.delete(&k.name.clone());
            }
        }

        // 3. bonds
        for b in cfg.bonds.clone() {
            if self.skip.contains(&b.name) {
                continue;
            }
            if !self.present(&b.name) {
                self.create(crate::bond::create_args(&b), &b.name);
            }
            for m in &b.members {
                self.enslave(m, &b.name, true);
            }
            self.release_extra(&b.name, &b.members);
            if let Some(p) = &b.primary {
                let cur = self.klink(&b.name).and_then(|k| k.bond_primary.clone());
                if cur.as_deref() != Some(p.as_str()) && self.present(p) {
                    self.push(ip(&[
                        "link", "set", "dev", &b.name, "type", "bond", "primary", p,
                    ]));
                }
            }
        }

        // 4. VLANs, parents first (QinQ)
        let vlans = cfg.vlans.clone();
        let ordered = vlan_order(&vlans);
        for v in &ordered {
            if self.skip.contains(&v.name) || self.present(&v.name) {
                continue;
            }
            if !self.present(&v.parent) {
                self.warn(format!(
                    "VLAN {}: parent {} does not exist; skipped",
                    v.name, v.parent
                ));
                continue;
            }
            self.up(&v.parent.clone());
            self.create(vlan_create_args(v), &v.name);
        }

        // 5. bridges
        for b in cfg.bridges.clone() {
            if self.skip.contains(&b.name) {
                continue;
            }
            if !self.present(&b.name) {
                self.create(crate::bridge::create_args(&b), &b.name);
            } else if self.klink(&b.name).and_then(|k| k.bridge_stp) != Some(b.stp) {
                self.push(Op::Ip(crate::bridge::stp_args(&b)));
            }
            for m in &b.members {
                self.enslave(m, &b.name, false);
            }
            self.release_extra(&b.name, &b.members);
        }

        // 6. link settings (lower devices first) + 7. addressing
        let virt = cfg.virtual_names();
        let mut order: Vec<String> = cfg
            .interfaces
            .iter()
            .filter(|i| !virt.contains(&i.name))
            .map(|i| i.name.clone())
            .collect();
        order.extend(cfg.bonds.iter().map(|b| b.name.clone()));
        order.extend(ordered.iter().map(|v| v.name.clone()));
        order.extend(cfg.bridges.iter().map(|b| b.name.clone()));
        order.extend(cfg.pppoe.iter().map(|p| p.name.clone()));
        let mut seen = BTreeSet::new();
        for name in order {
            if !seen.insert(name.clone()) || self.skip.contains(&name) {
                continue;
            }
            let row = cfg.iface(&name).cloned();
            let is_ppp = cfg.pppoe.iter().any(|p| p.name == name);
            let is_virtual = virt.contains(&name) && !is_ppp;
            let managed = row.as_ref().is_some_and(|r| r.is_managed());
            if !managed && !is_virtual {
                continue;
            }
            if !self.present(&name) {
                if !is_ppp {
                    self.warn(format!(
                        "interface {name} does not exist; its settings are not applied"
                    ));
                }
                continue;
            }
            let enabled = row.as_ref().map(|r| r.enabled).unwrap_or(true);
            if !enabled {
                if self.klink(&name).map(|k| k.up).unwrap_or(true) {
                    self.push(ip(&["link", "set", "dev", &name, "down"]));
                }
                continue;
            }
            if let Some(r) = &row {
                if let Some(mac) = &r.mac {
                    let mac = crate::netconf::normalize_mac(mac).unwrap_or_else(|_| mac.clone());
                    if self.klink(&name).and_then(|k| k.mac.clone()).as_deref()
                        != Some(mac.as_str())
                    {
                        if self.klink(&name).map(|k| k.up).unwrap_or(false) {
                            self.push(ip(&["link", "set", "dev", &name, "down"]));
                        }
                        self.push(ip(&["link", "set", "dev", &name, "address", &mac]));
                        self.upped.remove(&name);
                        self.push(ip(&["link", "set", "dev", &name, "up"]));
                        self.upped.insert(name.clone());
                    }
                }
                if let Some(mtu) = r.mtu {
                    if self.klink(&name).map(|k| k.mtu) != Some(mtu) {
                        self.push(ip(&["link", "set", "dev", &name, "mtu", &mtu.to_string()]));
                    }
                }
            }
            self.up(&name);
            if let Some(r) = &row {
                if r.is_managed() {
                    self.address(r, is_ppp);
                }
            }
        }

        // 8. PPPoE links
        for p in cfg.pppoe.clone() {
            if self.skip.contains(&p.name) {
                continue;
            }
            if !self.present(&p.parent) {
                self.warn(format!(
                    "PPPoE {}: parent {} does not exist; not started",
                    p.name, p.parent
                ));
                continue;
            }
            self.up(&p.parent.clone());
            match pppoe_spec(&p, inp.paths) {
                Ok(s) => self.push(Op::Ensure(s)),
                Err(e) => self.warn(format!("PPPoE {}: not started: {e}", p.name)),
            }
        }
        self.plan
    }
}

#[cfg(feature = "vlan")]
fn vlan_mismatch(v: &crate::netconf::VlanConfig, k: &KLink) -> bool {
    crate::vlan::needs_recreate(v, k)
}
#[cfg(not(feature = "vlan"))]
fn vlan_mismatch(_v: &crate::netconf::VlanConfig, _k: &KLink) -> bool {
    true
}
#[cfg(feature = "vlan")]
fn vlan_order(v: &[crate::netconf::VlanConfig]) -> Vec<crate::netconf::VlanConfig> {
    crate::vlan::topo_order(v).into_iter().cloned().collect()
}
#[cfg(not(feature = "vlan"))]
fn vlan_order(v: &[crate::netconf::VlanConfig]) -> Vec<crate::netconf::VlanConfig> {
    v.to_vec()
}
#[cfg(feature = "vlan")]
fn vlan_create_args(v: &crate::netconf::VlanConfig) -> Vec<String> {
    crate::vlan::create_args(v)
}
#[cfg(not(feature = "vlan"))]
fn vlan_create_args(_v: &crate::netconf::VlanConfig) -> Vec<String> {
    unreachable!("VLANs are dropped from the plan without the vlan feature")
}
#[cfg(feature = "pppoe")]
fn pppoe_spec(p: &crate::netconf::PppoeConfig, paths: &NetPaths) -> Result<DaemonSpec> {
    crate::pppoe::spec(p, paths)
}
#[cfg(not(feature = "pppoe"))]
fn pppoe_spec(_p: &crate::netconf::PppoeConfig, _paths: &NetPaths) -> Result<DaemonSpec> {
    Err(Error::Network(
        "PPPoE support is not compiled in (USE=pppoe)".into(),
    ))
}

/// Compute the steps that bring the kernel in line with the store.
pub fn plan(inp: &PlanInput) -> Plan {
    Planner {
        inp,
        plan: Plan::default(),
        deleted: BTreeSet::new(),
        created: BTreeSet::new(),
        skip: BTreeSet::new(),
        upped: BTreeSet::new(),
        disabled: BTreeSet::new(),
    }
    .run()
}

/// The interfaces applier: roles, static/DHCP/PPPoE addressing, IPv6,
/// MTU/MAC, VLANs (802.1Q/QinQ), bonds and bridges.
#[derive(Clone)]
pub struct InterfacesApplier {
    cmd: Arc<dyn Cmd>,
    sup: Supervisor,
    proc_root: PathBuf,
}

impl Default for InterfacesApplier {
    fn default() -> Self {
        Self {
            cmd: Arc::new(SystemCmd),
            sup: Supervisor::detect(),
            proc_root: PathBuf::from("/proc/sys"),
        }
    }
}

impl InterfacesApplier {
    pub fn new(cmd: Arc<dyn Cmd>, sup: Supervisor, proc_root: PathBuf) -> Self {
        Self {
            cmd,
            sup,
            proc_root,
        }
    }

    pub fn supervisor(&self) -> &Supervisor {
        &self.sup
    }

    /// Store config + kernel state -> plan.
    pub async fn compute(&self, store: &ConfigStore) -> Result<(NetConfig, KernelState, Plan)> {
        let cfg = NetConfig::load(store).await?;
        let kernel = KernelState::read(self.cmd.as_ref()).await?;
        // structural checks only: a NIC missing at boot is a warning, not a
        // reason to leave every other interface unconfigured
        let mut names = kernel.names();
        for i in &cfg.interfaces {
            names.push(i.name.clone());
        }
        for b in &cfg.bonds {
            names.extend(b.members.iter().cloned());
        }
        for b in &cfg.bridges {
            names.extend(b.members.iter().cloned());
        }
        for v in &cfg.vlans {
            names.push(v.parent.clone());
        }
        for p in &cfg.pppoe {
            names.push(p.parent.clone());
        }
        cfg.validate(&names)?;
        let mut managed = BTreeSet::new();
        let mut running = BTreeSet::new();
        for svc in [dhcp_client::SERVICE, crate::PPPOE_SERVICE] {
            for inst in self.sup.instances(svc) {
                if self.sup.is_running(svc, &inst) {
                    running.insert((svc.to_string(), inst.clone()));
                }
                managed.insert((svc.to_string(), inst));
            }
        }
        let over = store.load_system_config(dhcp_client::CLIENT_KEY).await?;
        let to_choice = |r: Result<(dhcp_client::Client, Vec<String>, Option<String>)>| {
            r.map_err(|e| e.to_string())
        };
        let dhcp_v4 = to_choice(dhcp_client::choose(over.as_deref(), false));
        let dhcp_v6 = to_choice(dhcp_client::choose(over.as_deref(), true));
        let root = self.proc_root.clone();
        let sysctl = move |p: &str| std::fs::read_to_string(root.join(p)).ok();
        let paths = self.sup.paths.clone();
        let p = plan(&PlanInput {
            cfg: &cfg,
            kernel: &kernel,
            managed: &managed,
            running: &running,
            dhcp_v4: &dhcp_v4,
            dhcp_v6: &dhcp_v6,
            sysctl: &sysctl,
            paths: &paths,
        });
        Ok((cfg, kernel, p))
    }

    async fn execute(&self, plan: &Plan, report: &mut ApplyReport) -> Vec<String> {
        let mut errors = Vec::new();
        for op in &plan.ops {
            let r: Result<bool> = match op {
                Op::Ip(a) => self.cmd.run("ip", a).await.map(|_| true),
                Op::Sysctl { path, value } => {
                    let p = self.proc_root.join(path);
                    std::fs::write(&p, format!("{value}\n"))
                        .map(|_| true)
                        .map_err(|e| Error::Network(format!("{}: {e}", p.display())))
                }
                Op::Ensure(s) => self.sup.ensure(s).await,
                Op::Stop { service, instance } => self.sup.stop(service, instance).await,
            };
            match r {
                Ok(true) => report.applied(op.describe()),
                Ok(false) => {}
                Err(e) if already_gone(op, &e.to_string()) => {}
                Err(e) => errors.push(format!("{}: {e}", op.describe())),
            }
        }
        errors
    }
}

/// A delete whose target vanished between planning and executing (a DHCP
/// client releasing its lease on stop, a VLAN removed with its parent) has
/// reached the desired state.
fn already_gone(op: &Op, err: &str) -> bool {
    let Op::Ip(a) = op else { return false };
    let is_del = a
        .windows(2)
        .any(|w| (w[0] == "addr" || w[0] == "route" || w[0] == "link") && w[1] == "del");
    is_del
        && [
            "Cannot assign requested address",
            // iproute2 >= 6: "Error: ipv4: Address not found."
            "Address not found",
            "No such process",
            "Cannot find device",
            "No such device",
        ]
        .iter()
        .any(|m| err.contains(m))
}

#[async_trait]
impl Applier for InterfacesApplier {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    fn phase(&self) -> Phase {
        Phase::Interfaces
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let (_, _, plan) = self.compute(store).await?;
        let mut report = ApplyReport::default();
        for w in &plan.warnings {
            report.warn(w.clone());
        }
        let errors = self.execute(&plan, &mut report).await;
        if errors.is_empty() {
            Ok(report)
        } else {
            Err(Error::Network(errors.join("; ")))
        }
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let (_, _, mut plan) = self.compute(store).await?;
        plan.ops
            .retain(|op| !matches!(op, Op::Ensure(spec) if self.sup.up_to_date(spec)));
        let mut s = String::new();
        if plan.ops.is_empty() {
            s.push_str("# interfaces already match the store\n");
        }
        for op in &plan.ops {
            s.push_str(&op.describe());
            s.push('\n');
        }
        for w in &plan.warnings {
            s.push_str(&format!("# warning: {w}\n"));
        }
        Ok(s)
    }

    fn resource_kinds(&self) -> &'static [ResourceKind] {
        &[ResourceKind::Interface]
    }

    async fn upsert_resource(&self, store: &ConfigStore, config: &DeclarativeConfig) -> Result<()> {
        let ResourceSpec::Interface(spec) = &config.spec else {
            return Err(Error::Config(format!(
                "Invalid interface resource {}",
                config.metadata.name
            )));
        };
        let mut cfg = NetConfig::load(store).await?;
        let i = cfg.iface_mut(&spec.device);
        i.enabled = spec.enabled;
        i.mtu = spec.mtu;
        i.ipv4.clear();
        if let Some(a) = &spec.ip_address {
            i.ipv4_mode = V4Mode::Static;
            i.ipv4 = vec![a
                .parse()
                .map_err(|_| Error::Config(format!("Invalid IPv4 address {a:?}")))?];
        } else if spec.dhcp == Some(true) {
            i.ipv4_mode = V4Mode::Dhcp;
        }
        i.description = config.metadata.description.clone();
        let names = KernelState::read(self.cmd.as_ref())
            .await
            .map(|k| k.names())
            .unwrap_or_default();
        let mut all = names;
        all.push(spec.device.clone());
        cfg.validate(&all)?;
        cfg.save(store).await
    }

    async fn delete_resource(
        &self,
        store: &ConfigStore,
        _kind: &ResourceKind,
        name: &str,
    ) -> Result<()> {
        let mut cfg = NetConfig::load(store).await?;
        if let Some(i) = cfg.interfaces.iter_mut().find(|i| i.name == name) {
            let role = i.role.clone();
            *i = IfaceConfig::new(name);
            i.role = role;
        }
        cfg.save(store).await
    }
}

#[cfg(test)]
mod applier_tests {
    use super::*;

    #[test]
    fn deletes_whose_target_already_vanished_count_as_done() {
        let del = ip(&["addr", "del", "203.0.113.9/24", "dev", "wan0"]);
        let add = ip(&["addr", "add", "203.0.113.9/24", "dev", "wan0"]);
        // a DHCP client releasing its lease on stop removes the address first
        assert!(already_gone(&del, "Error: ipv4: Address not found."));
        assert!(already_gone(
            &del,
            "RTNETLINK answers: Cannot assign requested address"
        ));
        assert!(!already_gone(&add, "Error: ipv4: Address not found."));
        assert!(!already_gone(&del, "Operation not permitted"));
    }
    use crate::linkstate::KernelState;
    use crate::netconf::BridgeConfig;
    #[cfg(feature = "vlan")]
    use crate::netconf::{BondConfig, VlanConfig};

    const LINKS: &str = r#"[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback"},
 {"ifindex":2,"ifname":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"52:54:00:00:00:10"},
 {"ifindex":3,"ifname":"eth1","flags":[],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"52:54:00:00:00:11"},
 {"ifindex":4,"ifname":"eth2","flags":[],"mtu":1500,"operstate":"DOWN","link_type":"ether","address":"52:54:00:00:00:12"},
 {"ifindex":9,"ifname":"old0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","ifalias":"patronus","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}},
 {"ifindex":10,"ifname":"foreign0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}}}
]"#;
    const ADDRS: &str = r#"[
 {"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","local":"10.0.0.5","prefixlen":24,"scope":"global","valid_life_time":4294967295}]}
]"#;

    fn run(cfg: &NetConfig, k: &KernelState, running: &[(&str, &str)]) -> Plan {
        let managed: BTreeSet<(String, String)> = running
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let v4: DhcpChoice = Ok((dhcp_client::Client::Udhcpc, vec!["udhcpc".into()], None));
        let v6: DhcpChoice = Err("DHCPv6 needs dhcpcd".into());
        let sysctl = |_: &str| Some("1\n".to_string());
        let paths = NetPaths::under(std::path::Path::new("/tmp/x"));
        plan(&PlanInput {
            cfg,
            kernel: k,
            managed: &managed,
            running: &managed,
            dhcp_v4: &v4,
            dhcp_v6: &v6,
            sysctl: &sysctl,
            paths: &paths,
        })
    }

    fn lines(p: &Plan) -> Vec<String> {
        p.ops.iter().map(|o| o.describe()).collect()
    }

    #[test]
    fn unmanaged_rows_and_foreign_devices_are_left_alone() {
        let k = KernelState::parse(LINKS, ADDRS).unwrap();
        let mut c = NetConfig::default();
        c.iface_mut("eth0").role = Some("wan".into());
        c.bridges.push(BridgeConfig {
            name: "foreign0".into(),
            stp: false,
            members: vec![],
            enabled: true,
            description: None,
        });
        let p = run(&c, &k, &[]);
        // the stale Patronus bridge goes, nothing else is touched
        assert_eq!(lines(&p), vec!["ip link del dev old0"]);
        assert!(
            p.warnings.iter().any(|w| w.contains("foreign0")),
            "{:?}",
            p.warnings
        );
    }

    #[cfg(feature = "vlan")]
    #[test]
    fn builds_bond_vlan_bridge_static_and_dhcp_in_dependency_order() {
        let k = KernelState::parse(LINKS, ADDRS).unwrap();
        let mut c = NetConfig::default();
        let w = c.iface_mut("eth0");
        w.role = Some("wan".into());
        w.ipv4_mode = V4Mode::Dhcp;
        w.mtu = Some(1400);
        c.bonds.push(BondConfig {
            name: "bond0".into(),
            mode: "active-backup".into(),
            miimon: 100,
            lacp_rate: None,
            xmit_hash_policy: None,
            primary: Some("eth1".into()),
            members: vec!["eth1".into(), "eth2".into()],
            enabled: true,
            description: None,
        });
        c.vlans.push(VlanConfig {
            name: "bond0.10".into(),
            parent: "bond0".into(),
            vlan_id: 10,
            protocol: "802.1q".into(),
            enabled: true,
            description: None,
        });
        c.bridges.push(BridgeConfig {
            name: "br0".into(),
            stp: false,
            members: vec!["bond0.10".into()],
            enabled: true,
            description: None,
        });
        let l = c.iface_mut("br0");
        l.role = Some("lan".into());
        l.ipv4_mode = V4Mode::Static;
        l.ipv4 = vec!["192.168.7.1/24".parse().unwrap()];
        l.gateway4 = None;
        l.ipv6_mode = V6Mode::Static;
        l.ipv6 = vec!["fd00:7::1/64".parse().unwrap()];
        let p = run(&c, &k, &[]);
        let ls = lines(&p);
        let pos = |s: &str| {
            ls.iter()
                .position(|l| l == s)
                .unwrap_or_else(|| panic!("{s:?} not in {ls:#?}"))
        };
        assert!(
            pos("ip link add name bond0 type bond mode active-backup miimon 100")
                < pos("ip link set dev eth1 master bond0")
        );
        assert!(pos("ip link set dev eth1 down") < pos("ip link set dev eth1 master bond0"));
        assert!(
            pos("ip link set dev eth2 master bond0")
                < pos("ip link set dev bond0 type bond primary eth1")
        );
        assert!(
            pos("ip link set dev bond0 alias patronus")
                < pos("ip link add link bond0 name bond0.10 type vlan id 10 protocol 802.1Q")
        );
        assert!(
            pos("ip link add link bond0 name bond0.10 type vlan id 10 protocol 802.1Q")
                < pos("ip link set dev bond0.10 master br0")
        );
        assert!(pos("ip link set dev eth0 mtu 1400") > 0);
        // eth0 switches static -> dhcp: its permanent address goes first
        assert!(
            pos("ip addr del 10.0.0.5/24 dev eth0")
                < pos(&ls
                    .iter()
                    .find(|l| l.starts_with("run patronus-dhcpc[eth0]"))
                    .unwrap()
                    .clone())
        );
        pos("ip addr add 192.168.7.1/24 dev br0");
        pos("ip addr add fd00:7::1/64 dev br0");
        pos("net.ipv6.conf.br0.accept_ra = 0");
        pos("ip link set dev br0 up");
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }

    #[cfg(feature = "vlan")]
    #[test]
    fn a_matching_kernel_needs_nothing_and_dhcp6_without_dhcpcd_warns() {
        let links = r#"[
 {"ifindex":2,"ifname":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether"},
 {"ifindex":3,"ifname":"eth0.5","link":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","ifalias":"patronus","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":5}}}
]"#;
        let addrs = r#"[{"ifname":"eth0.5","addr_info":[{"family":"inet","local":"10.5.0.1","prefixlen":24,"scope":"global","valid_life_time":4294967295}]}]"#;
        let mut k = KernelState::parse(links, addrs).unwrap();
        k.default_routes.push(crate::linkstate::KRoute {
            v6: false,
            dev: "eth0.5".into(),
            gateway: Some("10.5.0.254".into()),
            metric: 300,
            protocol: ROUTE_PROTO.into(),
        });
        let mut c = NetConfig::default();
        c.vlans.push(VlanConfig {
            name: "eth0.5".into(),
            parent: "eth0".into(),
            vlan_id: 5,
            protocol: "802.1q".into(),
            enabled: true,
            description: None,
        });
        let i = c.iface_mut("eth0.5");
        i.role = Some("lan".into());
        i.ipv4_mode = V4Mode::Static;
        i.ipv4 = vec!["10.5.0.1/24".parse().unwrap()];
        i.gateway4 = Some("10.5.0.254".parse().unwrap());
        let p = run(&c, &k, &[]);
        assert!(p.ops.is_empty(), "{:#?}", lines(&p));
        // gateway removed -> only our route is deleted
        c.iface_mut("eth0.5").gateway4 = None;
        assert_eq!(
            lines(&run(&c, &k, &[])),
            vec!["ip -4 route del default via 10.5.0.254 dev eth0.5 metric 300 proto 250"]
        );
        c.iface_mut("eth0").ipv6_mode = V6Mode::Dhcp6;
        let p = run(&c, &k, &[("patronus-dhcpc", "ethX")]);
        assert!(lines(&p).contains(&"stop patronus-dhcpc[ethX]".to_string()));
        assert!(
            p.warnings.iter().any(|w| w.contains("dhcpcd")),
            "{:?}",
            p.warnings
        );
    }

    #[cfg(feature = "vlan")]
    #[test]
    fn changing_a_vlan_id_recreates_it_and_disabled_interfaces_go_down() {
        let links = r#"[
 {"ifindex":2,"ifname":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether"},
 {"ifindex":3,"ifname":"v","link":"eth0","flags":["UP"],"mtu":1500,"operstate":"UP","link_type":"ether","ifalias":"patronus","linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":5}}}
]"#;
        let k = KernelState::parse(links, "[]").unwrap();
        let mut c = NetConfig::default();
        c.vlans.push(VlanConfig {
            name: "v".into(),
            parent: "eth0".into(),
            vlan_id: 6,
            protocol: "802.1q".into(),
            enabled: true,
            description: None,
        });
        c.iface_mut("eth0").enabled = false;
        let ls = lines(&run(&c, &k, &[]));
        assert_eq!(ls[0], "ip link del dev v");
        assert!(
            ls.contains(&"ip link set dev eth0 down".to_string()),
            "{ls:#?}"
        );
        assert!(
            ls.contains(&"ip link add link eth0 name v type vlan id 6 protocol 802.1Q".to_string())
        );
    }
}
