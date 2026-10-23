//! VRF segmentation (USE=vrf): separate routing tables per tenant/zone.
//!
//! Each VRF is a kernel `vrf` device named `vrf-<name>` bound to a routing
//! table (100-4000); its member interfaces are enslaved to it, so their
//! connected and learned routes live in that table only and traffic arriving on
//! a member is routed with that table. The applier reconciles the kernel with
//! the store (creates, re-binds, enslaves, releases and removes stale
//! `vrf-*` devices) at every apply and at boot. Inter-VRF traffic is
//! whatever the firewall rules and routes you add allow.

use crate::lan::{self, invalid};
use crate::svc::{self, Coll, Field, Kind, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

pub const PREFIX: &str = "vrf-";

static VRF_FIELDS: [Field; 2] = [
    Field::new("name", "Name", Kind::Token)
        .req()
        .help("1-11 letters/digits/-/_; the device is vrf-<name>"),
    Field::new("table_id", "Routing table", Kind::Int(100, 4000)).req(),
];
static MEMBER_FIELDS: [Field; 2] = [
    Field::new("vrf", "VRF", Kind::Token).req(),
    Field::new("interface", "Interface", Kind::Iface)
        .req()
        .help("an interface can be in one VRF"),
];

static SPEC: Spec = Spec {
    slug: "vrf",
    title: "VRF (segmentation)",
    blurb:
        "Virtual routing and forwarding: give a group of interfaces a routing table of their own. \
            Member interfaces are enslaved to the VRF device; routes stay inside it.",
    applier: "vrf",
    fields: &[],
    colls: &[
        Coll {
            key: "vrfs",
            title: "VRFs",
            table: "vrf_instances",
            fields: &VRF_FIELDS,
            unique: Some("name"),
        },
        Coll {
            key: "members",
            title: "Members",
            table: "vrf_members",
            fields: &MEMBER_FIELDS,
            unique: None,
        },
    ],
    actions: &[],
};

pub struct VrfSvc;

#[async_trait]
impl Svc for VrfSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }
}

/// A desired VRF: kernel device -> (table, member devices).
pub type Plan = BTreeMap<String, (u32, Vec<String>)>;

pub fn plan(vrfs: &[(String, u32)], members: &[(String, Vec<String>)]) -> Result<Plan> {
    let mut out = Plan::new();
    let mut tables = BTreeSet::new();
    for (n, t) in vrfs {
        if n.is_empty()
            || n.len() > 11
            || !n
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(invalid(format!(
                "VRF name {n:?}: 1-11 letters, digits, - or _"
            )));
        }
        if !tables.insert(*t) {
            return Err(invalid(format!(
                "VRF {n}: routing table {t} is used by another VRF"
            )));
        }
        if matches!(*t, 253..=255) {
            return Err(invalid(format!("VRF {n}: routing table {t} is reserved")));
        }
        out.insert(format!("{PREFIX}{n}"), (*t, Vec::new()));
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (v, devs) in members {
        let key = format!("{PREFIX}{v}");
        let Some(e) = out.get_mut(&key) else {
            return Err(invalid(format!(
                "VRF member refers to the unknown VRF {v:?}"
            )));
        };
        for d in devs {
            if let Some(o) = seen.insert(d.clone(), v.clone()) {
                if o != *v {
                    return Err(invalid(format!("interface {d} is in two VRFs ({o}, {v})")));
                }
            }
            if !e.1.contains(d) {
                e.1.push(d.clone());
            }
        }
    }
    Ok(out)
}

fn ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| Error::Network(format!("ip {}: {e}", args.join(" "))))?;
    if !out.status.success() {
        return Err(Error::Network(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn names(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|n| n.split('@').next().unwrap_or(n).to_string())
        .collect()
}

fn current_table(dev: &str) -> Option<u32> {
    let d = ip(&["-d", "link", "show", dev]).ok()?;
    let w: Vec<&str> = d.split_whitespace().collect();
    w.iter()
        .position(|x| *x == "table")
        .and_then(|i| w.get(i + 1))
        .and_then(|t| t.parse().ok())
}

/// Sockets bound to no device (the web UI, SSH, DNS, DHCP) only answer
/// traffic that arrives on a VRF-enslaved interface when the l3mdev accept
/// sysctls are on; without them the management UI vanishes from a LAN the
/// moment that LAN joins a VRF.
fn allow_unbound_listeners(rep: &mut ApplyReport) {
    for k in ["tcp_l3mdev_accept", "udp_l3mdev_accept"] {
        let p = format!("/proc/sys/net/ipv4/{k}");
        if std::fs::read_to_string(&p).map(|v| v.trim() == "1").unwrap_or(true) {
            continue;
        }
        match std::fs::write(&p, "1") {
            Ok(()) => rep.applied(format!("net.ipv4.{k}=1 (listeners answer inside VRFs)")),
            Err(e) => rep.warn(format!("net.ipv4.{k}: {e}")),
        }
    }
}

/// Reconcile the kernel with `want`.
pub fn reconcile(want: &Plan, rep: &mut ApplyReport) -> Result<()> {
    if want.values().any(|(_, m)| !m.is_empty()) {
        allow_unbound_listeners(rep);
    }
    let have: Vec<String> = names(&ip(&["-br", "link", "show", "type", "vrf"]).unwrap_or_default())
        .into_iter()
        .filter(|n| n.starts_with(PREFIX))
        .collect();
    for v in &have {
        if !want.contains_key(v) {
            for s in names(&ip(&["-br", "link", "show", "master", v]).unwrap_or_default()) {
                ip(&["link", "set", "dev", &s, "nomaster"])?;
            }
            ip(&["link", "del", v])?;
            rep.applied(format!("removed {v}"));
        }
    }
    for (v, (table, members)) in want {
        let mut exists = have.contains(v);
        if exists && current_table(v) != Some(*table) {
            for s in names(&ip(&["-br", "link", "show", "master", v]).unwrap_or_default()) {
                ip(&["link", "set", "dev", &s, "nomaster"])?;
            }
            ip(&["link", "del", v])?;
            exists = false;
        }
        if !exists {
            ip(&["link", "add", v, "type", "vrf", "table", &table.to_string()])?;
            rep.applied(format!("created {v} (table {table})"));
        }
        ip(&["link", "set", "dev", v, "up"])?;
        let slaves = names(&ip(&["-br", "link", "show", "master", v]).unwrap_or_default());
        for s in &slaves {
            if !members.contains(s) {
                ip(&["link", "set", "dev", s, "nomaster"])?;
                rep.applied(format!("released {s} from {v}"));
            }
        }
        for m in members {
            if !slaves.contains(m) {
                if ip(&["link", "show", m]).is_err() {
                    rep.warn(format!("{v}: member {m} does not exist; skipped"));
                    continue;
                }
                ip(&["link", "set", "dev", m, "master", v])?;
                ip(&["link", "set", "dev", m, "up"]).ok();
                rep.applied(format!("{m} joined {v}"));
            }
        }
    }
    Ok(())
}

async fn load(store: &ConfigStore) -> Result<Plan> {
    let vrfs: Vec<(String, u32)> = svc::raw_rows(store, &SPEC.colls[0])
        .await?
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or("").to_string(),
                r["table_id"]
                    .as_str()
                    .and_then(|t| t.parse().ok())
                    .or_else(|| r["table_id"].as_i64().map(|i| i as u32))
                    .unwrap_or(0),
            )
        })
        .collect();
    let mut members = Vec::new();
    for r in svc::raw_rows(store, &SPEC.colls[1]).await? {
        let devs = lan::resolve_iface(store, r["interface"].as_str().unwrap_or("")).await?;
        members.push((r["vrf"].as_str().unwrap_or("").to_string(), devs));
    }
    plan(&vrfs, &members)
}

#[derive(Default, Clone)]
pub struct VrfApplier;

#[async_trait]
impl Applier for VrfApplier {
    fn name(&self) -> &'static str {
        "vrf"
    }

    fn phase(&self) -> Phase {
        // after the interfaces exist, before routes and services use them
        Phase::Interfaces
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let mut rep = ApplyReport::default();
        let want = load(store).await?;
        reconcile(&want, &mut rep)?;
        if rep.applied.is_empty() {
            rep.applied(format!("{} VRF(s), unchanged", want.len()));
        }
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let want = load(store).await?;
        let mut s = String::new();
        for (v, (t, m)) in want {
            s.push_str(&format!("ip link add {v} type vrf table {t}\n"));
            for d in m {
                s.push_str(&format!("ip link set dev {d} master {v}\n"));
            }
        }
        Ok(s)
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let want = load(store).await.unwrap_or_default();
        let have = names(&ip(&["-br", "link", "show", "type", "vrf"]).unwrap_or_default());
        Ok(json!({
            "configured": want.len(),
            "present": have.into_iter().filter(|n| n.starts_with(PREFIX)).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_are_checked() {
        let v = vec![("red".to_string(), 100u32), ("blue".to_string(), 200)];
        let p = plan(
            &v,
            &[
                ("red".into(), vec!["eth1".into()]),
                ("blue".into(), vec!["eth2".into()]),
            ],
        )
        .unwrap();
        assert_eq!(p["vrf-red"], (100, vec!["eth1".to_string()]));
        assert!(
            plan(&[("a".into(), 100), ("b".into(), 100)], &[]).is_err(),
            "shared table"
        );
        assert!(
            plan(
                &v,
                &[
                    ("red".into(), vec!["eth1".into()]),
                    ("blue".into(), vec!["eth1".into()])
                ]
            )
            .is_err(),
            "two VRFs"
        );
        assert!(
            plan(&v, &[("green".into(), vec![])]).is_err(),
            "unknown vrf"
        );
        assert!(plan(&[("this-name-is-too-long".into(), 100)], &[]).is_err());
        assert!(plan(&[("x".into(), 254)], &[]).is_err());
        assert_eq!(
            names("vrf-red UP 1.2.3.4\nrtr-lan@if5 UP"),
            vec!["vrf-red", "rtr-lan"]
        );
    }
}
