//! Device segmentation state (lane s): groups, devices, links, one-way service
//! rules and the per-segment isolation switch, over `patronus_config::seg`
//! and the `segmentation` (L2), `dhcp` (reservations) and `firewall`
//! (nft table `inet patronus_seg`) appliers.
//!
//! Same contract as every LAN page: validate -> snapshot -> write the store ->
//! run the appliers -> on failure restore the tables and re-apply the previous
//! state. Turning isolation on for a segment adopts the devices already on it
//! into the built-in `home` group first, so day one behaves exactly as before.

use super::LanManager;
use patronus_config::seg::{self, Discovered};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// Appliers a segmentation change must run, in order: L2 settings, DHCP
/// reservations, the firewall (which renders the nft table: a revoked device
/// is cut here first, established connections included), then the Wi-Fi
/// access point (PSK entries leave / join live; a revoked station is
/// deauthenticated). Appliers a build does not have are skipped.
pub(super) const APPLIERS: &[&str] = &["segmentation", "dhcp", "firewall", "wifi"];

/// `ip -4 neigh show` lines -> (ip, device, mac) of entries that resolved.
pub fn parse_neigh(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(ip) = f.first() else { continue };
        let (mut dev, mut mac) = (None, None);
        let mut i = 1;
        while i + 1 < f.len() {
            match f[i] {
                "dev" => dev = Some(f[i + 1]),
                "lladdr" => mac = Some(f[i + 1]),
                _ => {}
            }
            i += 1;
        }
        let state = f.last().copied().unwrap_or("");
        if matches!(state, "FAILED" | "INCOMPLETE") {
            continue;
        }
        if let (Some(d), Some(m)) = (dev, mac) {
            out.push((ip.to_string(), d.to_string(), m.to_ascii_lowercase()));
        }
    }
    out
}

impl LanManager {
    /// Hosts currently on the network: DHCP leases and the neighbour table.
    async fn seg_seen(&self) -> Vec<Discovered> {
        let mut found: Vec<Discovered> = Vec::new();
        #[cfg(feature = "dhcp")]
        if let Ok(ls) =
            patronus_network::dhcp::leases(&self.store, &patronus_network::lan::LanEnv::system())
                .await
        {
            for l in ls {
                if l.family == "ipv4" && l.state == "active" {
                    found.push(Discovered {
                        mac: l.mac.to_ascii_lowercase(),
                        ip: l.ip,
                        hostname: l.hostname,
                    });
                }
            }
        }
        if let Ok(o) = std::process::Command::new("ip")
            .args(["-4", "neigh", "show"])
            .output()
        {
            for (ip, _dev, mac) in parse_neigh(&String::from_utf8_lossy(&o.stdout)) {
                if !found.iter().any(|f| f.mac == mac) {
                    found.push(Discovered {
                        mac,
                        ip,
                        hostname: None,
                    });
                }
            }
        }
        found
    }

    /// Segments the UI offers: every role that carries a LAN-side interface
    /// (everything but WAN) plus anything already recorded.
    async fn seg_candidates(&self) -> anyhow::Result<Vec<String>> {
        let mut v: BTreeSet<String> = BTreeSet::new();
        for (_, role) in self.store.interface_roles().await.map_err(e)? {
            if role != "wan" && !role.starts_with("wan") {
                v.insert(format!("@{role}"));
            }
        }
        for s in seg::list_segments(&self.store).await.map_err(e)? {
            v.insert(s.segment);
        }
        Ok(v.into_iter().collect())
    }

    pub async fn seg_overview(&self) -> anyhow::Result<Value> {
        let s = &*self.store;
        let recorded = seg::list_segments(s).await.map_err(e)?;
        let mut segments = Vec::new();
        for name in self.seg_candidates().await? {
            let rec = recorded.iter().find(|r| r.segment == name);
            let ifaces = seg::resolve_segment(s, &name).await.map_err(e)?;
            let (nets, _) = seg::segment_v4(s, &name).await.map_err(e)?;
            segments.push(json!({
                "segment": name,
                "enabled": rec.map(|r| r.enabled).unwrap_or(false),
                "adopted_at": rec.and_then(|r| r.adopted_at),
                "interfaces": ifaces,
                "subnets": nets.iter().map(|n| n.cidr()).collect::<Vec<_>>(),
            }));
        }
        let rules = patronus_firewall::seg_rules::seg_rules(s)
            .await
            .map_err(e)?;
        Ok(json!({
            "segments": segments,
            "groups": seg::list_groups(s).await.map_err(e)?,
            "devices": seg::list_devices(s).await.map_err(e)?,
            "links": seg::list_links(s).await.map_err(e)?,
            "services": seg::list_services(s).await.map_err(e)?,
            "enforced": rules.active,
            "enforced_devices": rules.devices,
            "warnings": rules.warnings,
            "l2": self.status("segmentation").await?,
            "notes": {
                "opt_in": "Nothing is isolated until you switch a segment on; switching on adopts every device now on it into the group 'home' (which may talk to itself and the internet), so day one behaves as before.",
                "wired": "Wired devices behind an unmanaged switch share one switch port: the switch forwards between them without the router, so they cannot be isolated from each other. Put them in one group, or connect them to ports of this router / a managed switch with port isolation.",
                "ipv6": "IPv6 between devices of a segment is denied while isolation is on; an unknown MAC forwards no IPv6. Per-address IPv6 binding is not done yet.",
            },
        }))
    }

    /// Hosts on the network that are not devices yet.
    pub async fn seg_discovered(&self) -> anyhow::Result<Value> {
        let s = &*self.store;
        let known: BTreeSet<String> = seg::list_devices(s)
            .await
            .map_err(e)?
            .into_iter()
            .filter_map(|d| d.mac)
            .collect();
        let mut out = Vec::new();
        let cands = self.seg_candidates().await?;
        for f in self.seg_seen().await {
            if known.contains(&f.mac) {
                continue;
            }
            let Ok(ip) = f.ip.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            for c in &cands {
                let (nets, own) = seg::segment_v4(s, c).await.map_err(e)?;
                if !own.contains(&ip) && nets.iter().any(|n| n.contains(ip)) {
                    out.push(
                        json!({"mac": f.mac, "ip": f.ip, "hostname": f.hostname, "segment": c}),
                    );
                    break;
                }
            }
        }
        Ok(json!(out))
    }

    pub async fn seg_preview(&self) -> anyhow::Result<Value> {
        let r = patronus_firewall::seg_rules::seg_rules(&self.store)
            .await
            .map_err(e)?;
        Ok(
            json!({"script": r.script, "warnings": r.warnings, "active": r.active, "devices": r.devices}),
        )
    }

    pub async fn seg_group_save(&self, id: Option<i64>, i: seg::GroupInput) -> anyhow::Result<i64> {
        let _g = self.edit.lock().await;
        let what = format!("segmentation group {}", i.name);
        let snap = self.begin(&what).await?;
        let id = match id {
            Some(id) => {
                seg::update_group(&self.store, id, &i).await.map_err(e)?;
                id
            }
            None => seg::create_group(&self.store, &i).await.map_err(e)?,
        };
        self.commit(&what, snap, APPLIERS).await?;
        Ok(id)
    }

    pub async fn seg_group_delete(&self, id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("delete segmentation group {id}");
        let snap = self.begin(&what).await?;
        seg::delete_group(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    pub async fn seg_device_create(&self, i: seg::DeviceInput) -> anyhow::Result<seg::Device> {
        let _g = self.edit.lock().await;
        let what = format!("segmentation device {}", i.name);
        let snap = self.begin(&what).await?;
        let d = seg::create_device(&self.store, &i).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(d)
    }

    pub async fn seg_device_update(
        &self,
        id: i64,
        name: Option<String>,
        group: Option<String>,
        note: Option<String>,
    ) -> anyhow::Result<seg::Device> {
        let _g = self.edit.lock().await;
        let what = format!("change segmentation device {id}");
        let snap = self.begin(&what).await?;
        let d = seg::update_device(
            &self.store,
            id,
            name.as_deref(),
            group.as_deref(),
            note.as_deref(),
        )
        .await
        .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(d)
    }

    /// Revoke: the nft table is re-rendered and loaded in one transaction, so
    /// the device is cut at once, established connections included.
    pub async fn seg_device_revoke(&self, id: i64) -> anyhow::Result<seg::Device> {
        let _g = self.edit.lock().await;
        let what = format!("revoke segmentation device {id}");
        let snap = self.begin(&what).await?;
        let d = seg::revoke_device(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(d)
    }

    pub async fn seg_device_delete(&self, id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("delete segmentation device {id}");
        let snap = self.begin(&what).await?;
        seg::delete_device(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    pub async fn seg_link_add(&self, a: &str, b: &str) -> anyhow::Result<i64> {
        let _g = self.edit.lock().await;
        let what = format!("link groups {a} and {b}");
        let snap = self.begin(&what).await?;
        let id = seg::add_link(&self.store, a, b).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(id)
    }

    pub async fn seg_link_delete(&self, id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("delete group link {id}");
        let snap = self.begin(&what).await?;
        seg::delete_link(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    pub async fn seg_service_add(&self, i: seg::ServiceInput) -> anyhow::Result<i64> {
        let _g = self.edit.lock().await;
        let what = format!("segmentation service {}", i.name);
        let snap = self.begin(&what).await?;
        let id = seg::add_service(&self.store, &i).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(id)
    }

    pub async fn seg_service_delete(&self, id: i64) -> anyhow::Result<()> {
        let _g = self.edit.lock().await;
        let what = format!("delete segmentation service {id}");
        let snap = self.begin(&what).await?;
        seg::delete_service(&self.store, id).await.map_err(e)?;
        self.commit(&what, snap, APPLIERS).await
    }

    /// Switch isolation on or off for one segment. Switching on adopts what is
    /// on the segment into `home` first (the admin's own machine included),
    /// unless `adopt` is false.
    pub async fn seg_segment_set(
        &self,
        segment: &str,
        enabled: bool,
        adopt: bool,
    ) -> anyhow::Result<Value> {
        let segment = seg::check_segment(segment).map_err(e)?;
        let seen = if enabled && adopt {
            self.seg_seen().await
        } else {
            Vec::new()
        };
        let _g = self.edit.lock().await;
        let what = format!(
            "segmentation {} on {segment}",
            if enabled { "on" } else { "off" }
        );
        let snap = self.begin(&what).await?;
        let mut report = None;
        if enabled && adopt {
            report = Some(
                seg::adopt(&self.store, &segment, &seen, None)
                    .await
                    .map_err(e)?,
            );
        }
        seg::set_segment_enabled(&self.store, &segment, enabled)
            .await
            .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(json!({"segment": segment, "enabled": enabled, "adoption": report}))
    }

    /// Approve one discovered host into `group`.
    pub async fn seg_adopt_host(
        &self,
        mac: &str,
        name: Option<String>,
        group: Option<String>,
        segment: Option<String>,
    ) -> anyhow::Result<seg::Device> {
        let mac = seg::norm_mac(mac).map_err(e)?;
        let found = self
            .seg_seen()
            .await
            .into_iter()
            .find(|f| f.mac == mac)
            .ok_or_else(|| anyhow::anyhow!("no host with MAC {mac} is on the network right now"))?;
        let segment = match segment {
            Some(s) => s,
            None => {
                let ip: std::net::Ipv4Addr = found
                    .ip
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid address {}", found.ip))?;
                let mut hit = None;
                for c in self.seg_candidates().await? {
                    let (nets, _) = seg::segment_v4(&self.store, &c).await.map_err(e)?;
                    if nets.iter().any(|n| n.contains(ip)) {
                        hit = Some(c);
                        break;
                    }
                }
                hit.ok_or_else(|| anyhow::anyhow!("Invalid host: {ip} is on no known segment"))?
            }
        };
        let _g = self.edit.lock().await;
        let what = format!("adopt {mac} into segmentation");
        let snap = self.begin(&what).await?;
        let d = seg::adopt_host(
            &self.store,
            &segment,
            &found,
            name.as_deref(),
            group.as_deref().unwrap_or(seg::GROUP_HOME),
        )
        .await
        .map_err(e)?;
        self.commit(&what, snap, APPLIERS).await?;
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_neighbour_table() {
        let t = "192.168.1.20 dev br0 lladdr AA:BB:CC:00:00:01 REACHABLE\n\
                 192.168.1.21 dev br0  FAILED\n\
                 192.168.1.22 dev br0 lladdr aa:bb:cc:00:00:02 STALE\n\
                 192.168.1.23 dev br0 INCOMPLETE\n\
                 garbage\n";
        let v = parse_neigh(t);
        assert_eq!(
            v,
            vec![
                (
                    "192.168.1.20".into(),
                    "br0".into(),
                    "aa:bb:cc:00:00:01".into()
                ),
                (
                    "192.168.1.22".into(),
                    "br0".into(),
                    "aa:bb:cc:00:00:02".into()
                ),
            ]
        );
    }
}
