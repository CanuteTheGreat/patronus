//! Network map & discovery (lane w, USE=netmap; docs/design/network-map.md).
//!
//! - `collect`: one discovery round. Merges DHCP leases, the kernel neighbour table, an optional
//!   probe (`map.probe`: ARP refresh of known addresses, or an opt-in `nmap -sn` sweep of LAN-side
//!   subnets) and LLDP neighbours (`lldpctl -f json`, when installed) into `map_devices`.
//! - `graph`: the `infra-map/v1` JSON the shared map component (ui-map/map.js) draws.
//! - `advisor`: flat-network findings + isolation plans; applying a plan is
//!   `LanManager::map_advisor_apply` (device segmentation engine, one snapshot, undo on failure).

use patronus_config::netmap::{self, MapDevice, Observation};
use patronus_config::seg;
use patronus_config::ConfigStore;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Mutex;

fn e(e: patronus_core::Error) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

/// One `ip -4 neigh show` entry with its NUD state.
#[derive(Debug, Clone, PartialEq)]
pub struct Neigh {
    pub ip: String,
    pub dev: String,
    pub mac: Option<String>,
    pub state: String,
}

pub fn parse_neigh_states(text: &str) -> Vec<Neigh> {
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(ip) = f.first() else { continue };
        if ip.parse::<Ipv4Addr>().is_err() {
            continue;
        }
        let (mut dev, mut mac) = (None, None);
        for w in f.windows(2) {
            match w[0] {
                "dev" => dev = Some(w[1].to_string()),
                "lladdr" => mac = Some(w[1].to_ascii_lowercase()),
                _ => {}
            }
        }
        let state = f.last().copied().unwrap_or("").to_string();
        if let Some(dev) = dev {
            out.push(Neigh {
                ip: ip.to_string(),
                dev,
                mac,
                state,
            });
        }
    }
    out
}

/// Confirmed reachable by the kernel. Unconfirmed states (STALE, DELAY, PROBE) only count when no
/// probe runs; with a probe, the echo answer decides.
fn neigh_up(state: &str, probe: &str) -> bool {
    matches!(state, "REACHABLE" | "PERMANENT")
        || (matches!(state, "STALE" | "DELAY" | "PROBE") && probe == "off")
}

fn read_neigh() -> Vec<Neigh> {
    std::process::Command::new("ip")
        .args(["-4", "neigh", "show"])
        .output()
        .map(|o| parse_neigh_states(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// `nmap -sn -oG -` output -> addresses that are up.
pub fn parse_nmap_up(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.starts_with("Host: ") && l.contains("Status: Up"))
        .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
        .collect()
}

/// An LLDP neighbour heard on one of the router's ports.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LldpNeighbor {
    pub iface: String,
    pub chassis: String,
    pub port: String,
    pub descr: String,
    pub mgmt_ip: Option<String>,
}

/// `lldpctl -f json` (lldpd 1.x): `lldp.interface` is an object keyed by port, or a list of such
/// objects when several neighbours are known.
pub fn parse_lldp(text: &str) -> Vec<LldpNeighbor> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut items: Vec<(String, Value)> = Vec::new();
    match &v["lldp"]["interface"] {
        Value::Object(m) => items.extend(m.iter().map(|(k, x)| (k.clone(), x.clone()))),
        Value::Array(a) => {
            for o in a {
                if let Value::Object(m) = o {
                    items.extend(m.iter().map(|(k, x)| (k.clone(), x.clone())));
                }
            }
        }
        _ => {}
    }
    let s = |x: &Value| -> String {
        match x {
            Value::String(s) => s.clone(),
            Value::Object(o) => o
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        }
    };
    let mut out = Vec::new();
    for (iface, x) in items {
        let Value::Object(m) = &x["chassis"] else {
            continue;
        };
        // named form {"<name>": {id, descr, mgmt-ip}} or flat form {id, name, descr, mgmt-ip}
        let named = m.len() == 1
            && !matches!(
                m.keys().next().map(String::as_str),
                Some("id" | "name" | "descr" | "mgmt-ip")
            )
            && m.values().next().map(Value::is_object).unwrap_or(false);
        let (chassis, cx) = if named {
            let (k, c) = m.iter().next().expect("one entry");
            (k.clone(), c.clone())
        } else {
            (s(&x["chassis"]["name"]), x["chassis"].clone())
        };
        let mgmt = match &cx["mgmt-ip"] {
            Value::Array(a) => a.first().map(s),
            v => Some(s(v)).filter(|x| !x.is_empty()),
        };
        out.push(LldpNeighbor {
            iface,
            chassis: if chassis.is_empty() {
                s(&cx["id"])
            } else {
                chassis
            },
            port: {
                let p = s(&x["port"]["id"]);
                if p.is_empty() {
                    s(&x["port"]["descr"])
                } else {
                    p
                }
            },
            descr: s(&cx["descr"]),
            mgmt_ip: mgmt,
        });
    }
    out
}

static LLDP: Mutex<Vec<LldpNeighbor>> = Mutex::new(Vec::new());
static ROUND: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn have(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// One LAN-side segment: (segment token, interfaces, subnets, the router's own addresses).
pub type SegInfo = (String, Vec<String>, Vec<seg::Subnet>, Vec<Ipv4Addr>);

pub async fn segments(store: &ConfigStore) -> anyhow::Result<Vec<SegInfo>> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (_, role) in store.interface_roles().await.map_err(e)? {
        if !role.starts_with("wan") {
            names.insert(format!("@{role}"));
        }
    }
    let mut out = Vec::new();
    for n in names {
        let ifs = seg::resolve_segment(store, &n).await.map_err(e)?;
        let (nets, own) = seg::segment_v4(store, &n).await.map_err(e)?;
        out.push((n, ifs, nets, own));
    }
    Ok(out)
}

fn segment_of(ip: &str, segs: &[SegInfo]) -> Option<String> {
    let ip: Ipv4Addr = ip.parse().ok()?;
    segs.iter()
        .find(|(_, _, nets, own)| !own.contains(&ip) && nets.iter().any(|n| n.contains(ip)))
        .map(|(s, ..)| s.clone())
}

fn own_ip(ip: &str, segs: &[SegInfo]) -> bool {
    ip.parse::<Ipv4Addr>()
        .map(|a| segs.iter().any(|(_, _, _, own)| own.contains(&a)))
        .unwrap_or(false)
}

/// One discovery round. Returns how many sightings were recorded.
pub async fn collect(store: &ConfigStore) -> anyhow::Result<usize> {
    let _round = ROUND
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let s = netmap::load_settings(store).await.map_err(e)?;
    let probe = s.get("probe").to_string();
    let segs = segments(store).await?;
    let lan_ifs: BTreeSet<String> = segs.iter().flat_map(|(_, i, _, _)| i.clone()).collect();
    let mut obs: Vec<Observation> = Vec::new();
    #[cfg(feature = "dhcp")]
    if let Ok(ls) =
        patronus_network::dhcp::leases(store, &patronus_network::lan::LanEnv::system()).await
    {
        for l in ls
            .into_iter()
            .filter(|l| l.family == "ipv4" && l.state == "active")
        {
            obs.push(Observation {
                mac: l.mac.to_ascii_lowercase(),
                segment: segment_of(&l.ip, &segs),
                ip: Some(l.ip),
                hostname: l.hostname.filter(|h| !h.is_empty() && h != "*"),
                source: "lease",
                ..Default::default()
            });
        }
    }
    // probe every address the router already knows (seen before, leased, or in the neighbour table
    // without a confirmed state), then read the neighbour table again so the answers count this round
    let first = read_neigh();
    let confirmed: BTreeSet<String> = first
        .iter()
        .filter(|n| matches!(n.state.as_str(), "REACHABLE" | "PERMANENT"))
        .map(|n| n.ip.clone())
        .collect();
    let in_neigh: Vec<String> = first
        .into_iter()
        .filter(|n| n.mac.is_some())
        .map(|n| n.ip)
        .collect();
    let known: Vec<String> = netmap::list_devices(store, &s, chrono::Utc::now().timestamp())
        .await
        .map_err(e)?
        .into_iter()
        .filter_map(|d| d.ip)
        .chain(obs.iter().filter_map(|o| o.ip.clone()))
        .chain(in_neigh)
        .filter(|ip| !confirmed.contains(ip))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|ip| segment_of(ip, &segs).is_some())
        .take(s.num("probe_max").max(1) as usize)
        .collect();
    let mut probe_up: BTreeSet<String> = BTreeSet::new();
    match probe.as_str() {
        "ping" if !known.is_empty() && have("ping") => {
            // one ICMP echo per known address, all at once (1 s timeout): an answer is "up".
            let mut set = tokio::task::JoinSet::new();
            for ip in known.clone() {
                set.spawn(async move {
                    let ok = tokio::process::Command::new("ping")
                        .args(["-c1", "-W1", "-n", "-q", &ip])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await
                        .map(|s| s.success())
                        .unwrap_or(false);
                    (ip, ok)
                });
            }
            while let Some(r) = set.join_next().await {
                if let Ok((ip, true)) = r {
                    probe_up.insert(ip);
                }
            }
        }
        "nmap" if have("nmap") => {
            for (_, _, nets, _) in &segs {
                for n in nets.iter().filter(|n| n.prefix >= 16) {
                    let out = tokio::process::Command::new("nmap")
                        .args(["-sn", "-n", "-oG", "-", &n.cidr()])
                        .output()
                        .await;
                    if let Ok(o) = out {
                        probe_up.extend(parse_nmap_up(&String::from_utf8_lossy(&o.stdout)));
                    }
                }
            }
        }
        _ => {}
    }
    for n in read_neigh() {
        let Some(mac) = n.mac.clone() else { continue };
        if !lan_ifs.is_empty() && !lan_ifs.contains(&n.dev) {
            continue;
        }
        if own_ip(&n.ip, &segs) || mac == "00:00:00:00:00:00" {
            continue;
        }
        let up = neigh_up(&n.state, &probe) || probe_up.contains(&n.ip);
        obs.push(Observation {
            mac,
            segment: segment_of(&n.ip, &segs),
            ip: Some(n.ip.clone()),
            iface: Some(n.dev.clone()),
            source: if probe_up.contains(&n.ip) {
                "probe"
            } else {
                "neigh"
            },
            up,
            neigh_state: Some(n.state.clone()),
            ..Default::default()
        });
    }
    if s.get("lldp") == "auto" && have("lldpctl") {
        if let Ok(o) = tokio::process::Command::new("lldpctl")
            .args(["-f", "json"])
            .output()
            .await
        {
            let v = parse_lldp(&String::from_utf8_lossy(&o.stdout));
            if let Ok(mut g) = LLDP.lock() {
                *g = v;
            }
        }
    }
    let at = chrono::Utc::now().timestamp();
    let n = netmap::observe(store, &obs, at).await.map_err(e)?;
    netmap::prune(store, s.num("retention_days"), at)
        .await
        .map_err(e)?;
    Ok(n)
}

/// Background discovery: a round every `map.discovery_interval_secs` (re-read each round).
pub fn spawn(store: std::sync::Arc<ConfigStore>) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = collect(&store).await {
                tracing::warn!("network map discovery: {err}");
            }
            let secs = match netmap::load_settings(&store).await {
                Ok(s) => s.num("discovery_interval_secs").clamp(10, 3600) as u64,
                Err(_) => 60,
            };
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        }
    });
}

fn label_of(segment: &str) -> String {
    segment.trim_start_matches('@').to_ascii_uppercase()
}

async fn seg_state(
    store: &ConfigStore,
) -> anyhow::Result<(BTreeSet<String>, BTreeMap<String, String>)> {
    let on: BTreeSet<String> = seg::list_segments(store)
        .await
        .map_err(e)?
        .into_iter()
        .filter(|s| s.enabled)
        .map(|s| s.segment)
        .collect();
    let group_of: BTreeMap<String, String> = seg::list_devices(store)
        .await
        .map_err(e)?
        .into_iter()
        .filter(|d| d.state == "active")
        .filter_map(|d| d.mac.map(|m| (m, d.group)))
        .collect();
    Ok((on, group_of))
}

/// Findings + one plan per flagged segment.
pub async fn advisor(store: &ConfigStore) -> anyhow::Result<Value> {
    let s = netmap::load_settings(store).await.map_err(e)?;
    let devs = netmap::list_devices(store, &s, chrono::Utc::now().timestamp())
        .await
        .map_err(e)?;
    let (on, group_of) = seg_state(store).await?;
    let views: Vec<netmap::SegView> = segments(store)
        .await?
        .into_iter()
        .map(|(sg, ..)| netmap::SegView {
            label: label_of(&sg),
            isolated: on.contains(&sg),
            segment: sg,
        })
        .collect();
    let findings = netmap::advise(&views, &devs, &s, &group_of);
    let existing: BTreeSet<String> = seg::list_groups(store)
        .await
        .map_err(e)?
        .into_iter()
        .map(|g| g.name)
        .collect();
    let plans: Vec<netmap::Plan> = findings
        .iter()
        .map(|f| netmap::plan(&f.segment, on.contains(&f.segment), &devs, &s, &existing))
        .collect();
    Ok(json!({
        "findings": findings,
        "plans": plans,
        "segmentation_built": cfg!(feature = "segmentation"),
    }))
}

fn host_name() -> String {
    crate::state::host::hostname()
}

/// The `infra-map/v1` graph. `full` = MACs and per-device details (signed-in users and
/// `detail: full` share keys).
pub async fn graph(store: &ConfigStore, full: bool) -> anyhow::Result<Value> {
    let s = netmap::load_settings(store).await.map_err(e)?;
    let at = chrono::Utc::now().timestamp();
    let devs = netmap::list_devices(store, &s, at).await.map_err(e)?;
    let segs = segments(store).await?;
    let roles = store.interface_roles().await.map_err(e)?;
    let mut groups = Vec::new();
    let mut nodes = vec![
        json!({"id": "router", "label": host_name(), "kind": "router", "status": "up", "href": "/"}),
    ];
    let mut edges = Vec::new();
    let wans: Vec<String> = roles
        .iter()
        .filter(|(_, r)| r.starts_with("wan"))
        .map(|(i, _)| i.clone())
        .collect();
    if !wans.is_empty() {
        nodes.push(
            json!({"id": "internet", "label": "Internet", "kind": "internet", "status": "up"}),
        );
        edges.push(
            json!({"from": "router", "to": "internet", "kind": "wan", "label": wans.join(", ")}),
        );
    }
    for (sg, ifs, nets, _) in &segs {
        let gid = format!("seg:{sg}");
        groups.push(json!({
            "id": gid, "label": label_of(sg), "kind": "segment",
            "sub": nets.iter().map(|n| n.cidr()).collect::<Vec<_>>().join(", "),
        }));
        edges.push(json!({"from": "router", "to": gid, "kind": "link", "label": ifs.join(", ")}));
    }
    let lldp = LLDP.lock().map(|g| g.clone()).unwrap_or_default();
    for n in &lldp {
        let sg = segs
            .iter()
            .find(|(_, ifs, ..)| ifs.contains(&n.iface))
            .map(|(s, ..)| format!("seg:{s}"));
        let id = format!("lldp:{}", n.chassis);
        nodes.push(json!({
            "id": id, "label": n.chassis, "kind": "switch", "class": "infra", "group": sg,
            "status": "up", "ip": n.mgmt_ip,
            "meta": if full { json!({"router port": n.iface, "their port": n.port, "description": n.descr}) } else { json!({}) },
        }));
        if sg.is_none() {
            edges.push(json!({"from": "router", "to": id, "kind": "lldp", "label": format!("{} <-> {}", n.iface, n.port)}));
        }
    }
    let known: BTreeSet<String> = segs.iter().map(|(s, ..)| s.clone()).collect();
    for d in &devs {
        let group = d
            .segment
            .as_ref()
            .filter(|s| known.contains(*s))
            .map(|s| format!("seg:{s}"));
        let mut meta = serde_json::Map::new();
        if full {
            meta.insert("hostname".into(), json!(d.hostname));
            meta.insert("seen by".into(), json!(d.sources));
            meta.insert("neighbour state".into(), json!(d.neigh_state));
            meta.insert("class from".into(), json!(d.class_source));
            meta.insert("first seen".into(), json!(fmt_time(d.first_seen)));
            meta.insert("last seen".into(), json!(fmt_time(d.last_seen)));
            if d.private_mac {
                meta.insert("MAC".into(), json!("private (randomised) address"));
            }
            if let Some(n) = &d.note {
                meta.insert("note".into(), json!(n));
            }
        }
        nodes.push(json!({
            "id": format!("dev:{}", d.mac), "label": d.name, "kind": "device", "class": d.class,
            "group": group, "status": d.status, "ip": d.ip,
            "mac": if full { Some(&d.mac) } else { None },
            "href": format!("/map#dev:{}", d.mac), "meta": meta,
        }));
    }
    let adv = advisor(store).await?;
    let findings: Vec<Value> = adv["findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|f| {
            json!({
                "id": f["id"], "severity": f["severity"], "title": f["title"], "detail": f["detail"],
                "nodes": f["untrusted"].as_array().map(|a| a.iter().filter_map(|m| m.as_str()).map(|m| format!("dev:{m}")).collect::<Vec<_>>()),
                "action": {"label": "Review the fix", "href": "/map#advisor"},
            })
        })
        .collect();
    let up = devs.iter().filter(|d| d.status == "up").count();
    let mut g = json!({
        "schema": "infra-map/v1",
        "source": {"product": "patronus", "name": host_name(), "generated_at": at},
        "refresh_secs": s.num("refresh_secs"),
        "groups": groups,
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
        "counts": {"devices": devs.len(), "up": up, "down": devs.len() - up, "segments": segs.len(), "findings": findings.len()},
    });
    if !full {
        anonymize(&mut g);
    }
    Ok(g)
}

/// A basic share must not carry MAC addresses anywhere: device ids (`dev:<mac>`) become `n<i>`, a name that
/// is only the MAC becomes "device <i>", edges and findings follow the new ids.
pub fn anonymize(g: &mut Value) {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    if let Some(ns) = g["nodes"].as_array_mut() {
        for (i, n) in ns.iter_mut().enumerate() {
            let id = n["id"].as_str().unwrap_or("").to_string();
            if id.starts_with("dev:") || id.starts_with("lldp:") {
                let new = format!("n{i}");
                if n["label"]
                    .as_str()
                    .map(|l| seg::norm_mac(l).is_ok())
                    .unwrap_or(false)
                {
                    n["label"] = json!(format!("device {i}"));
                }
                n["id"] = json!(new.clone());
                map.insert(id, new);
            }
            if let Some(o) = n.as_object_mut() {
                o.remove("mac");
                o.remove("href");
            }
        }
    }
    let re = |v: &mut Value| {
        if let Some(new) = v.as_str().and_then(|x| map.get(x)) {
            *v = json!(new);
        }
    };
    if let Some(es) = g["edges"].as_array_mut() {
        for e in es {
            re(&mut e["from"]);
            re(&mut e["to"]);
        }
    }
    if let Some(fs) = g["findings"].as_array_mut() {
        for f in fs {
            if let Some(ns) = f["nodes"].as_array_mut() {
                for n in ns.iter_mut() {
                    re(n);
                }
            }
        }
    }
}

/// Flat stats for dashboard widgets (Homepage `customapi`).
pub async fn stats(store: &ConfigStore) -> anyhow::Result<Value> {
    let s = netmap::load_settings(store).await.map_err(e)?;
    let devs = netmap::list_devices(store, &s, chrono::Utc::now().timestamp())
        .await
        .map_err(e)?;
    let up = devs.iter().filter(|d| d.status == "up").count();
    let segs = segments(store).await?.len();
    let findings = advisor(store).await?["findings"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    for d in &devs {
        *by_class.entry(d.class.clone()).or_default() += 1;
    }
    Ok(json!({
        "devices": devs.len(), "up": up, "down": devs.len() - up, "segments": segs,
        "findings": findings, "classes": by_class,
    }))
}

fn fmt_time(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

pub fn devices_json(devs: &[MapDevice]) -> Value {
    json!(devs)
}

#[cfg(feature = "segmentation")]
impl super::LanManager {
    /// Apply (or with `dry_run` only show) the advisor's isolation plan for `segment` through the
    /// device-segmentation engine, in one snapshot: on any failure the store and the live state go back.
    pub async fn map_advisor_apply(&self, segment: &str, dry_run: bool) -> anyhow::Result<Value> {
        let segment = seg::check_segment(segment).map_err(e)?;
        let store = &*self.store;
        let s = netmap::load_settings(store).await.map_err(e)?;
        let devs = netmap::list_devices(store, &s, chrono::Utc::now().timestamp())
            .await
            .map_err(e)?;
        let (on, _) = seg_state(store).await?;
        let existing: BTreeSet<String> = seg::list_groups(store)
            .await
            .map_err(e)?
            .into_iter()
            .map(|g| g.name)
            .collect();
        let plan = netmap::plan(&segment, on.contains(&segment), &devs, &s, &existing);
        if plan.moves.is_empty() {
            return Err(anyhow::anyhow!(
                "Invalid request: nothing on {segment} needs to move"
            ));
        }
        if dry_run {
            return Ok(json!({"plan": plan, "applied": false}));
        }
        let seen = self.seg_seen().await;
        let _g = self.edit.lock().await;
        let what = format!("segmentation advisor on {segment}");
        let snap = self.begin(&what).await?;
        let mut skipped: Vec<String> = Vec::new();
        let r: anyhow::Result<()> = async {
            if plan.enable_isolation {
                seg::adopt(store, &segment, &seen, None).await.map_err(e)?;
                seg::set_segment_enabled(store, &segment, true)
                    .await
                    .map_err(e)?;
            }
            for g in plan.groups.iter().filter(|g| !g.exists) {
                seg::create_group(
                    store,
                    &seg::GroupInput {
                        name: g.name.clone(),
                        description: Some(format!("{} devices (segmentation advisor)", g.class)),
                        intra: g.intra,
                        internet: g.internet.clone(),
                        quarantine: false,
                    },
                )
                .await
                .map_err(e)?;
            }
            for m in &plan.moves {
                match seg::device_by_mac(store, &m.mac).await.map_err(e)? {
                    Some(d) => {
                        seg::update_device(store, d.id, None, Some(&m.group), None)
                            .await
                            .map_err(e)?;
                    }
                    None => {
                        let ip = devs
                            .iter()
                            .find(|d| d.mac == m.mac)
                            .and_then(|d| d.ip.clone());
                        match ip {
                            Some(ip) => {
                                let f = seg::Discovered {
                                    mac: m.mac.clone(),
                                    ip,
                                    hostname: devs
                                        .iter()
                                        .find(|d| d.mac == m.mac)
                                        .and_then(|d| d.hostname.clone()),
                                };
                                seg::adopt_host(store, &segment, &f, None, &m.group)
                                    .await
                                    .map_err(e)?;
                            }
                            None => skipped.push(m.mac.clone()),
                        }
                    }
                }
            }
            let have: BTreeSet<String> = seg::list_services(store)
                .await
                .map_err(e)?
                .into_iter()
                .map(|x| x.name)
                .collect();
            for sv in plan.services.iter().filter(|x| !have.contains(&x.name)) {
                seg::add_service(
                    store,
                    &seg::ServiceInput {
                        name: sv.name.clone(),
                        src: format!("group:{}", sv.src),
                        dst: format!("group:{}", sv.dst),
                        proto: sv.proto.clone(),
                        ports: sv.ports.clone(),
                        schedule: None,
                        enabled: true,
                    },
                )
                .await
                .map_err(e)?;
            }
            let links: BTreeSet<(String, String)> = seg::list_links(store)
                .await
                .map_err(e)?
                .into_iter()
                .map(|l| (l.a, l.b))
                .collect();
            for (a, b) in &plan.links {
                if !links.contains(&(a.clone(), b.clone()))
                    && !links.contains(&(b.clone(), a.clone()))
                {
                    seg::add_link(store, a, b).await.map_err(e)?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(err) = r {
            if let Err(re) = patronus_network::lan::restore_tables(store, &snap).await {
                tracing::error!("could not undo {what}: {re}");
            }
            return Err(err);
        }
        self.commit(&what, snap, super::segmentation::APPLIERS)
            .await?;
        Ok(json!({"plan": plan, "applied": true, "skipped": skipped}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbour_states_and_nmap() {
        let t = "192.168.1.20 dev br0 lladdr AA:BB:CC:00:00:01 REACHABLE\n\
                 192.168.1.21 dev br0 FAILED\n\
                 192.168.1.22 dev br0 lladdr aa:bb:cc:00:00:02 STALE\n\
                 fe80::1 dev br0 lladdr aa:bb:cc:00:00:03 router STALE\n";
        let v = parse_neigh_states(t);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].mac.as_deref(), Some("aa:bb:cc:00:00:01"));
        assert_eq!(v[1].mac, None);
        assert_eq!(v[1].state, "FAILED");
        assert!(
            neigh_up("REACHABLE", "ping")
                && !neigh_up("STALE", "ping")
                && !neigh_up("DELAY", "ping")
                && neigh_up("STALE", "off")
        );
        assert!(!neigh_up("FAILED", "off"));
        let g = "# Nmap 7.95 scan\nHost: 192.168.1.20 ()\tStatus: Up\nHost: 192.168.1.30 ()\tStatus: Down\n";
        assert_eq!(parse_nmap_up(g), vec!["192.168.1.20".to_string()]);
    }

    #[test]
    fn basic_shares_carry_no_mac_anywhere() {
        let mut g = json!({"nodes": [{"id": "router", "label": "gw"},
            {"id": "dev:aa:bb:cc:00:00:01", "label": "aa:bb:cc:00:00:01", "mac": "aa:bb:cc:00:00:01", "href": "/map#dev:aa:bb:cc:00:00:01"},
            {"id": "dev:aa:bb:cc:00:00:02", "label": "printer"}],
            "edges": [{"from": "router", "to": "dev:aa:bb:cc:00:00:02"}],
            "findings": [{"nodes": ["dev:aa:bb:cc:00:00:01"]}]});
        anonymize(&mut g);
        let t = g.to_string();
        assert!(!t.contains("aa:bb:cc"), "{t}");
        assert_eq!(g["nodes"][1]["label"], "device 1");
        assert_eq!(g["nodes"][2]["label"], "printer");
        assert_eq!(g["edges"][0]["to"], "n2");
        assert_eq!(g["findings"][0]["nodes"][0], "n1");
        assert_eq!(g["nodes"][0]["id"], "router");
    }

    #[test]
    fn lldp_json_single_and_list() {
        let one = r#"{"lldp":{"interface":{"eth1":{"chassis":{"core-sw":{"id":{"type":"mac","value":"00:11:22:33:44:55"},
            "descr":"8-port switch","mgmt-ip":"192.168.1.2"}},"port":{"id":{"type":"ifname","value":"gi0/3"},"descr":"port 3"}}}}}"#;
        let v = parse_lldp(one);
        assert_eq!(v.len(), 1);
        assert_eq!(
            (
                v[0].iface.as_str(),
                v[0].chassis.as_str(),
                v[0].port.as_str()
            ),
            ("eth1", "core-sw", "gi0/3")
        );
        assert_eq!(v[0].mgmt_ip.as_deref(), Some("192.168.1.2"));
        let list = r#"{"lldp":{"interface":[{"eth1":{"chassis":{"a":{"mgmt-ip":["10.0.0.2","fe80::1"]}},"port":{"descr":"p1"}}},
            {"eth2":{"chassis":{"b":{}},"port":{"id":{"value":"7"}}}}]}}"#;
        let v = parse_lldp(list);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mgmt_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(v[0].port, "p1");
        assert_eq!((v[1].chassis.as_str(), v[1].port.as_str()), ("b", "7"));
        assert!(parse_lldp("not json").is_empty());
    }
}
