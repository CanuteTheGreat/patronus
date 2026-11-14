//! `patronus import-uci <dir|tar.gz> [--dry-run] [--map UCI=DEVICE]...`
//!
//! Reads an OpenWrt UCI configuration (a `sysupgrade -b` tarball or a directory
//! holding `etc/config/*`) offline and writes Patronus store resources
//! (docs/embedded-routers.md section 7).
//!
//! Mapping (anything not listed ends up in the `unmapped` report, never dropped):
//!
//! | UCI | Patronus |
//! |---|---|
//! | `network` interface (static / dhcp / dhcpv6) | NetConfig interface (role from the firewall zones) |
//! | `dhcp` `dhcp` + `host` | DHCP pool on the LAN device + static leases (`dhcp-server`) |
//! | `firewall` `rule` ACCEPT / `redirect` | firewall rules / port forwards; stock OpenWrt rules are `covered by default` |
//! | `firewall` zone `masq` | recorded (outbound NAT is a default) |
//! | `wireless` `wifi-iface` | AP -> Wi-Fi network (`wifi-ap`), STA -> parked setting, order and `disabled` kept |
//!
//! Secrets (`key`) go only into the store and are printed as `key: (set)`.
//! The physical device names differ on Patronus: `--map lan=br-lan` maps a UCI
//! interface (or `wifi-iface` section) to the Patronus device.

use anyhow::{bail, Context, Result};
use patronus_core::types::{
    ChainType, FirewallAction, FirewallRule, IpVersion, NatRule, NatType, PortSpec, Protocol,
};
use patronus_network::ipnetwork::IpNetwork;
use patronus_network::netconf::{NetConfig, V4Mode, V6Mode};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// UCI parser
// ---------------------------------------------------------------------------

/// One `config <kind> [name]` block. Options keep one value, lists many.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Section {
    pub kind: String,
    /// `None` for an anonymous section.
    pub name: Option<String>,
    /// Position among the sections of the same kind (`@kind[index]`).
    pub index: usize,
    opts: Vec<(String, Vec<String>)>,
}

impl Section {
    /// `lan` or `@rule[3]`.
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("@{}[{}]", self.kind, self.index))
    }

    /// The (last) value of an option / list.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.opts
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.last())
            .map(String::as_str)
    }

    /// Every value of a list, each also split on whitespace (UCI accepts
    /// `option proto 'tcp udp'` as well as `list proto 'tcp'`).
    pub fn words(&self, key: &str) -> Vec<String> {
        self.opts
            .iter()
            .filter(|(k, _)| k == key)
            .flat_map(|(_, v)| v.iter())
            .flat_map(|v| v.split_whitespace().map(str::to_string))
            .collect()
    }

    pub fn flag(&self, key: &str) -> Option<bool> {
        self.get(key).map(|v| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "1" | "on" | "true" | "yes" | "enabled"
            )
        })
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.opts.iter().map(|(k, _)| k.as_str())
    }

    /// Option names that are not in `known`, in file order.
    fn leftover(&self, known: &[&str]) -> Vec<String> {
        self.keys()
            .filter(|k| !known.contains(k))
            .map(str::to_string)
            .collect()
    }

    fn set(&mut self, key: &str, val: String, list: bool) {
        if let Some((_, v)) = self.opts.iter_mut().find(|(k, _)| k == key) {
            if list {
                v.push(val);
            } else {
                *v = vec![val];
            }
        } else {
            self.opts.push((key.to_string(), vec![val]));
        }
    }
}

fn tokenize(line: &str, no: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false; // a quoted (possibly empty) piece is in `cur`
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                has = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => bail!("line {no}: unterminated single quote"),
                    }
                }
            }
            '"' => {
                has = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => cur.push(e),
                            Some(e) => {
                                cur.push('\\');
                                cur.push(e);
                            }
                            None => bail!("line {no}: unterminated double quote"),
                        },
                        Some(ch) => cur.push(ch),
                        None => bail!("line {no}: unterminated double quote"),
                    }
                }
            }
            '#' if !has && cur.is_empty() => break,
            c if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

/// Parse one UCI file (`config` / `option` / `list` lines).
pub fn parse_uci(text: &str) -> Result<Vec<Section>> {
    let mut secs: Vec<Section> = Vec::new();
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let no = i + 1;
        let w = tokenize(line, no)?;
        let Some(cmd) = w.first() else { continue };
        match cmd.as_str() {
            "package" => {}
            "config" => {
                let kind = w
                    .get(1)
                    .with_context(|| format!("line {no}: config without a type"))?
                    .clone();
                let n = per_kind.entry(kind.clone()).or_insert(0);
                secs.push(Section {
                    kind,
                    name: w.get(2).cloned(),
                    index: *n,
                    opts: vec![],
                });
                *n += 1;
            }
            "option" | "list" => {
                let (Some(k), Some(v)) = (w.get(1), w.get(2)) else {
                    bail!("line {no}: {cmd} needs a name and a value");
                };
                let Some(sec) = secs.last_mut() else {
                    bail!("line {no}: {cmd} before the first config");
                };
                sec.set(k, v.clone(), cmd == "list");
            }
            other => bail!("line {no}: unknown keyword {other:?}"),
        }
    }
    Ok(secs)
}

/// All parsed files of `etc/config`, by file name.
pub type Files = BTreeMap<String, Vec<Section>>;

fn config_dir(root: &Path) -> Result<PathBuf> {
    for c in [
        root.join("etc/config"),
        root.join("config"),
        root.to_path_buf(),
    ] {
        if c.join("network").is_file() {
            return Ok(c);
        }
    }
    bail!(
        "{}: no etc/config/network (not a UCI backup or config directory)",
        root.display()
    )
}

/// Read every file of the config directory under `root`.
pub fn load_dir(root: &Path) -> Result<Files> {
    let dir = config_dir(root)?;
    let mut files = Files::new();
    for e in std::fs::read_dir(&dir)? {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(e.path())
            .with_context(|| format!("read {}", e.path().display()))?;
        files.insert(
            name.clone(),
            parse_uci(&text).with_context(|| format!("etc/config/{name}"))?,
        );
    }
    Ok(files)
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `etc/config/<file>` member names of a tarball listing (`./etc/config/x` too).
fn config_members(listing: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|l| {
            let p = l.strip_prefix("./").unwrap_or(l);
            p.strip_prefix("etc/config/")
                .is_some_and(|f| !f.is_empty() && !f.contains('/'))
        })
        .map(str::to_string)
        .collect()
}

/// Load a directory, or a `.tar.gz` (extracted with `tar xzf`, only the
/// `etc/config/*` members: the backup also holds passwords and host keys).
pub fn load_input(input: &Path) -> Result<Files> {
    if input.is_dir() {
        return load_dir(input);
    }
    let list = std::process::Command::new("tar")
        .arg("tzf")
        .arg(input)
        .output()
        .context("run tar (needed to read a tarball)")?;
    if !list.status.success() {
        bail!(
            "tar tzf {}: {}",
            input.display(),
            String::from_utf8_lossy(&list.stderr).trim()
        );
    }
    let members = config_members(&String::from_utf8_lossy(&list.stdout));
    if members.is_empty() {
        bail!("{}: no etc/config/* in the archive", input.display());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = Scratch(std::env::temp_dir().join(format!(
        "patronus-import-uci-{}-{nanos}",
        std::process::id()
    )));
    std::fs::create_dir_all(&tmp.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o700))?;
    }
    let st = std::process::Command::new("tar")
        .arg("xzf")
        .arg(input)
        .arg("-C")
        .arg(&tmp.0)
        .args(&members)
        .status()
        .context("run tar")?;
    if !st.success() {
        bail!("tar xzf {} failed", input.display());
    }
    load_dir(&tmp.0)
}

// ---------------------------------------------------------------------------
// the plan (pure: UCI in, store writes out)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct IfacePlan {
    pub uci: String,
    pub device: String,
    pub role: Option<String>,
    pub enabled: bool,
    pub v4: V4Mode,
    pub addrs: Vec<IpNetwork>,
    pub gateway4: Option<IpAddr>,
    pub v6: V6Mode,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoolPlan {
    pub uci: String,
    pub device: String,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub lease_time: Option<u32>,
    pub router: Ipv4Addr,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticPlan {
    pub device: String,
    pub name: Option<String>,
    pub mac: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WifiPlan {
    pub section: String,
    pub mode: String,
    pub ssid: String,
    pub encryption: String,
    /// Never printed: the report says `key: (set)`.
    pub key: Option<String>,
    pub disabled: bool,
    pub radio: String,
    pub network: String,
    pub band: Option<String>,
    pub channel: Option<i64>,
    pub country: Option<String>,
    /// Patronus device (`--map <section>=<device>`), needed for an AP.
    pub device: Option<String>,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub ifaces: Vec<IfacePlan>,
    pub pools: Vec<PoolPlan>,
    pub statics: Vec<StaticPlan>,
    pub fw_rules: Vec<FirewallRule>,
    pub nat_rules: Vec<NatRule>,
    pub wifi: Vec<WifiPlan>,
    pub covered: Vec<String>,
    pub notes: Vec<String>,
    pub unmapped: Vec<String>,
}

const STOCK_RULES: &[&str] = &[
    "Allow-DHCP-Renew",
    "Allow-Ping",
    "Allow-IGMP",
    "Allow-DHCPv6",
    "Allow-MLD",
    "Allow-ICMPv6-Input",
    "Allow-ICMPv6-Forward",
    "Allow-IPSec-ESP",
    "Allow-ISAKMP",
];

const HANDLED_FILES: &[&str] = &["network", "wireless", "firewall", "dhcp", "system"];

/// Parse repeated `--map UCI=DEVICE`.
pub fn parse_maps(maps: &[String]) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for s in maps {
        let Some((k, v)) = s.split_once('=') else {
            bail!("--map {s:?}: use UCI=DEVICE (for example lan=br-lan)");
        };
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() || !patronus_network::netconf::is_valid_ifname(v) {
            bail!("--map {s:?}: UCI name and a valid Patronus device name expected");
        }
        m.insert(k.to_string(), v.to_string());
    }
    Ok(m)
}

fn sections<'a>(files: &'a Files, file: &str, kind: &'a str) -> impl Iterator<Item = &'a Section> {
    files
        .get(file)
        .into_iter()
        .flatten()
        .filter(move |s| s.kind == kind)
}

fn unmapped_opts(plan: &mut Plan, file: &str, s: &Section, known: &[&str]) {
    let left = s.leftover(known);
    if !left.is_empty() {
        plan.unmapped.push(format!(
            "{file}: {} '{}': option(s) not imported: {}",
            s.kind,
            s.label(),
            left.join(", ")
        ));
    }
}

fn v4_netmask_prefix(mask: &str) -> Option<u8> {
    let m: Ipv4Addr = mask.parse().ok()?;
    let bits = u32::from(m);
    (bits.leading_ones() + bits.trailing_zeros() == 32).then(|| bits.leading_ones() as u8)
}

fn parse_addr(a: &str, netmask: Option<&str>) -> Option<IpNetwork> {
    if a.contains('/') {
        return a.parse().ok();
    }
    let ip: IpAddr = a.parse().ok()?;
    let prefix = match ip {
        IpAddr::V4(_) => netmask.and_then(v4_netmask_prefix).unwrap_or(24),
        IpAddr::V6(_) => 64,
    };
    IpNetwork::new(ip, prefix).ok()
}

/// `12h`, `30m`, `3600`, `1w` -> seconds. `infinite` -> None.
fn parse_duration(s: &str) -> Option<u32> {
    let s = s.trim();
    let (num, mul) = match s.chars().last()? {
        'w' => (&s[..s.len() - 1], 604_800),
        'd' => (&s[..s.len() - 1], 86_400),
        'h' => (&s[..s.len() - 1], 3_600),
        'm' => (&s[..s.len() - 1], 60),
        's' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    num.parse::<u32>().ok()?.checked_mul(mul)
}

fn parse_dports(spec: &str) -> Option<PortSpec> {
    let parts: Vec<&str> = spec.split_whitespace().collect();
    let one = |p: &str| p.parse::<u16>().ok().filter(|n| *n != 0);
    if parts.len() == 1 {
        let p = parts[0];
        if let Some((a, b)) = p.split_once(['-', ':']) {
            let (a, b) = (one(a)?, one(b)?);
            return (a <= b).then_some(PortSpec::Range(a, b));
        }
        return one(p).map(PortSpec::Single);
    }
    parts
        .iter()
        .map(|p| one(p))
        .collect::<Option<Vec<_>>>()
        .map(PortSpec::Multiple)
}

fn protocols(s: &Section) -> Result<Vec<Option<Protocol>>, String> {
    let mut out = Vec::new();
    let words = s.words("proto");
    if words.is_empty() {
        return Ok(vec![None]);
    }
    for w in words {
        match w.to_ascii_lowercase().as_str() {
            "tcp" => out.push(Some(Protocol::Tcp)),
            "udp" => out.push(Some(Protocol::Udp)),
            "tcpudp" => {
                out.push(Some(Protocol::Tcp));
                out.push(Some(Protocol::Udp));
            }
            "icmp" => out.push(Some(Protocol::Icmp)),
            "all" | "any" => out.push(None),
            other => return Err(format!("protocol {other:?}")),
        }
    }
    Ok(out)
}

struct Zone {
    name: String,
    networks: Vec<String>,
}

/// Zone `lan` / `wan` are the Patronus roles; other zone names have none.
fn role_of_zone(z: &str) -> Option<&'static str> {
    match z {
        "lan" => Some("lan"),
        "wan" => Some("wan"),
        _ => None,
    }
}

/// Build the plan from the parsed UCI files.
pub fn build_plan(files: &Files, maps: &BTreeMap<String, String>) -> Plan {
    let mut plan = Plan::default();
    let zones: Vec<Zone> = sections(files, "firewall", "zone")
        .map(|z| Zone {
            name: z.get("name").unwrap_or("").to_string(),
            networks: z.words("network"),
        })
        .collect();
    let role_of = |iface: &str| -> Option<String> {
        zones
            .iter()
            .find(|z| z.networks.iter().any(|n| n == iface))
            .and_then(|z| role_of_zone(&z.name))
            .map(str::to_string)
    };
    network_plan(&mut plan, files, maps, &role_of);
    dhcp_plan(&mut plan, files);
    firewall_plan(&mut plan, files);
    wireless_plan(&mut plan, files, maps);
    system_plan(&mut plan, files);
    for (name, secs) in files {
        if !HANDLED_FILES.contains(&name.as_str()) {
            plan.unmapped.push(format!(
                "{name}: file not imported ({} section(s))",
                secs.len()
            ));
        }
    }
    plan
}

fn network_plan(
    plan: &mut Plan,
    files: &Files,
    maps: &BTreeMap<String, String>,
    role_of: &dyn Fn(&str) -> Option<String>,
) {
    const KNOWN: &[&str] = &[
        "proto", "device", "ifname", "ipaddr", "netmask", "gateway", "mtu", "auto",
    ];
    let mut dev_of_uci_device: BTreeMap<String, String> = BTreeMap::new();
    let mut v6_pending: Vec<(&Section, String)> = Vec::new();
    for s in sections(files, "network", "interface") {
        let name = s.label();
        let proto = s.get("proto").unwrap_or("none");
        if name == "loopback" {
            plan.covered
                .push("network: interface 'loopback' (the kernel's lo)".into());
            continue;
        }
        let uci_dev = s
            .get("device")
            .or(s.get("ifname"))
            .unwrap_or("")
            .to_string();
        match proto {
            "static" | "dhcp" => {}
            "dhcpv6" => {
                v6_pending.push((s, uci_dev));
                continue;
            }
            other => {
                plan.unmapped.push(format!(
                    "network: interface '{name}' proto '{other}' (not supported by the importer)"
                ));
                continue;
            }
        }
        let Some(dev) = maps.get(&name) else {
            plan.unmapped.push(format!(
                "network: interface '{name}' (UCI device '{uci_dev}', proto {proto}): no --map {name}=<patronus device>"
            ));
            continue;
        };
        if !uci_dev.is_empty() {
            dev_of_uci_device.insert(uci_dev, dev.clone());
        }
        let mut ip = IfacePlan {
            uci: name.clone(),
            device: dev.clone(),
            role: role_of(&name),
            enabled: s.flag("auto").unwrap_or(true),
            v4: V4Mode::Dhcp,
            addrs: vec![],
            gateway4: None,
            v6: V6Mode::Unmanaged,
            mtu: s.get("mtu").and_then(|m| m.parse().ok()),
        };
        if proto == "static" {
            ip.v4 = V4Mode::Static;
            let nm = s.get("netmask");
            for a in s.words("ipaddr") {
                match parse_addr(&a, nm) {
                    Some(n) if n.is_ipv4() => ip.addrs.push(n),
                    _ => plan.unmapped.push(format!(
                        "network: interface '{name}' ipaddr '{a}' (not an IPv4 address)"
                    )),
                }
            }
            ip.gateway4 = s.get("gateway").and_then(|g| g.parse().ok());
        }
        if ip.role.is_none() {
            plan.notes.push(format!(
                "network: interface '{name}' is in no lan/wan firewall zone: no role set"
            ));
        }
        unmapped_opts(plan, "network", s, KNOWN);
        plan.ifaces.push(ip);
    }
    // dhcpv6 rides on the device of an already mapped interface (wan6 + wan)
    for (s, uci_dev) in v6_pending {
        let name = s.label();
        let dev = maps
            .get(&name)
            .or_else(|| dev_of_uci_device.get(&uci_dev))
            .cloned();
        match dev.and_then(|d| plan.ifaces.iter_mut().find(|i| i.device == d)) {
            Some(i) => {
                i.v6 = V6Mode::Dhcp6;
                plan.notes.push(format!(
                    "network: interface '{name}' (dhcpv6) -> IPv6 dhcp6 on {}",
                    i.device
                ));
                unmapped_opts(plan, "network", s, KNOWN);
            }
            None => plan.unmapped.push(format!(
                "network: interface '{name}' proto 'dhcpv6': no mapped interface on UCI device '{uci_dev}'"
            )),
        }
    }
    for s in files.get("network").into_iter().flatten() {
        if s.kind == "interface" {
            continue;
        }
        let detail = match s.kind.as_str() {
            "device" => format!(
                " ({} {})",
                s.get("type").unwrap_or("device"),
                s.get("name").unwrap_or("")
            ),
            _ => String::new(),
        };
        plan.unmapped.push(format!(
            "network: {} '{}'{detail} (bridges, switch, routes and globals are not imported)",
            s.kind,
            s.label()
        ));
    }
}

fn dhcp_plan(plan: &mut Plan, files: &Files) {
    const KNOWN: &[&str] = &[
        "interface",
        "start",
        "limit",
        "leasetime",
        "ignore",
        "dhcpv4",
    ];
    let domain = sections(files, "dhcp", "dnsmasq")
        .next()
        .and_then(|d| d.get("domain"))
        .map(str::to_string);
    for s in sections(files, "dhcp", "dhcp") {
        let name = s.label();
        let uci_if = s.get("interface").unwrap_or(&name).to_string();
        if s.flag("ignore") == Some(true) {
            plan.notes.push(format!(
                "dhcp: '{name}' ignore '1' -> no pool on '{uci_if}'"
            ));
            continue;
        }
        let Some(i) = plan.ifaces.iter().find(|i| i.uci == uci_if) else {
            plan.unmapped.push(format!(
                "dhcp: '{name}' on UCI interface '{uci_if}' (interface not mapped)"
            ));
            continue;
        };
        let Some(IpNetwork::V4(net)) = i.addrs.first().cloned() else {
            plan.unmapped.push(format!(
                "dhcp: '{name}' on '{uci_if}' (no static IPv4 address to derive the range from)"
            ));
            continue;
        };
        let start: u32 = s.get("start").and_then(|v| v.parse().ok()).unwrap_or(100);
        let limit: u32 = s.get("limit").and_then(|v| v.parse().ok()).unwrap_or(150);
        let base = u32::from(net.network());
        let (first, last) = (
            base.wrapping_add(start),
            base.wrapping_add(start.saturating_add(limit.max(1) - 1)),
        );
        let (first, last) = (Ipv4Addr::from(first), Ipv4Addr::from(last));
        if limit == 0 || !net.contains(first) || !net.contains(last) {
            plan.unmapped.push(format!(
                "dhcp: '{name}' start {start} limit {limit} does not fit {net}"
            ));
            continue;
        }
        let lease_time = match s.get("leasetime") {
            None => None,
            Some(l) => {
                let t = parse_duration(l);
                if t.is_none() {
                    plan.unmapped.push(format!(
                        "dhcp: '{name}' leasetime '{l}' (default lease time used)"
                    ));
                }
                t
            }
        };
        plan.pools.push(PoolPlan {
            uci: uci_if,
            device: i.device.clone(),
            start: first,
            end: last,
            lease_time,
            router: net.ip(),
            domain: domain.clone(),
        });
        let left: Vec<String> = s
            .leftover(KNOWN)
            .into_iter()
            .filter(|k| !k.starts_with("ra") && k != "dhcpv6")
            .collect();
        if !left.is_empty() {
            plan.unmapped.push(format!(
                "dhcp: dhcp '{name}': option(s) not imported: {}",
                left.join(", ")
            ));
        }
        let v6: Vec<String> = s
            .keys()
            .filter(|k| k.starts_with("ra") || *k == "dhcpv6")
            .map(str::to_string)
            .collect();
        if !v6.is_empty() {
            plan.unmapped.push(format!(
                "dhcp: dhcp '{name}': IPv6 RA/DHCPv6 option(s) not imported: {}",
                v6.join(", ")
            ));
        }
    }
    for s in sections(files, "dhcp", "host") {
        let (mac, ip) = (
            s.words("mac"),
            s.get("ip").and_then(|i| i.parse::<Ipv4Addr>().ok()),
        );
        let (Some(mac), Some(ip)) = (mac.first(), ip) else {
            plan.unmapped.push(format!(
                "dhcp: host '{}' (needs an IPv4 ip and a mac)",
                s.label()
            ));
            continue;
        };
        let Some(pool) = plan.pools.iter().find(|p| {
            plan.ifaces
                .iter()
                .find(|i| i.uci == p.uci)
                .is_some_and(|i| i.addrs.iter().any(|a| a.contains(IpAddr::V4(ip))))
        }) else {
            plan.unmapped.push(format!(
                "dhcp: host '{}' {ip} (no imported pool covers it)",
                s.label()
            ));
            continue;
        };
        plan.statics.push(StaticPlan {
            device: pool.device.clone(),
            name: s.get("name").map(str::to_string),
            mac: mac.clone(),
            ip,
        });
        unmapped_opts(plan, "dhcp", s, &["name", "mac", "ip"]);
    }
    for s in files.get("dhcp").into_iter().flatten() {
        match s.kind.as_str() {
            "dhcp" | "host" => {}
            "dnsmasq" => {
                let left = s.leftover(&["domain"]);
                plan.unmapped.push(format!(
                    "dhcp: dnsmasq '{}': {} option(s) not imported ({}); domain is used for the DHCP pool",
                    s.label(),
                    left.len(),
                    left.join(", ")
                ));
            }
            _ => plan
                .unmapped
                .push(format!("dhcp: {} '{}' (not imported)", s.kind, s.label())),
        }
    }
}

fn zone_iface(zone: Option<&str>) -> Result<Option<String>, String> {
    match zone {
        None | Some("*") => Ok(None),
        Some(z) => role_of_zone(z)
            .map(|r| Some(format!("@{r}")))
            .ok_or_else(|| format!("zone '{z}' (only the lan and wan zones map to roles)")),
    }
}

fn firewall_plan(plan: &mut Plan, files: &Files) {
    for s in files.get("firewall").into_iter().flatten() {
        match s.kind.as_str() {
            "defaults" => {
                plan.notes.push(
                    "firewall: defaults input/output/forward: Patronus ships its own default policy (not imported)"
                        .into(),
                );
                let left = s.leftover(&["input", "output", "forward"]);
                if !left.is_empty() {
                    plan.unmapped.push(format!(
                        "firewall: defaults: option(s) not imported: {}",
                        left.join(", ")
                    ));
                }
            }
            "zone" => {
                let name = s.get("name").unwrap_or("");
                if role_of_zone(name).is_none() {
                    plan.unmapped.push(format!(
                        "firewall: zone '{name}' (only lan and wan zones map to roles)"
                    ));
                    continue;
                }
                if s.flag("masq") == Some(true) {
                    if name == "wan" {
                        plan.notes.push(
                            "firewall: wan zone masq '1' -> outbound NAT (default masquerade rule already exists, recorded)"
                                .into(),
                        );
                    } else {
                        plan.unmapped.push(format!(
                            "firewall: zone '{name}' masq '1' (only the wan zone is NATed)"
                        ));
                    }
                }
                unmapped_opts(
                    plan,
                    "firewall",
                    s,
                    &["name", "network", "masq", "input", "output", "forward"],
                );
            }
            "forwarding" => {
                let (src, dest) = (s.get("src").unwrap_or("?"), s.get("dest").unwrap_or("?"));
                if src == "lan" && dest == "wan" {
                    plan.covered.push(
                        "firewall: forwarding lan -> wan (default 'Allow LAN to any')".into(),
                    );
                } else {
                    plan.unmapped
                        .push(format!("firewall: forwarding {src} -> {dest}"));
                }
            }
            "rule" => rule_plan(plan, s),
            "redirect" => redirect_plan(plan, s),
            _ => plan.unmapped.push(format!(
                "firewall: {} '{}' (not imported)",
                s.kind,
                s.label()
            )),
        }
    }
}

fn rule_plan(plan: &mut Plan, s: &Section) {
    let name = s.get("name").unwrap_or(&s.label()).to_string();
    let is_stock = STOCK_RULES.contains(&name.as_str())
        && s.get("src") == Some("wan")
        && s.get("target")
            .unwrap_or("ACCEPT")
            .eq_ignore_ascii_case("ACCEPT");
    if is_stock {
        plan.covered.push(format!(
            "firewall: rule '{name}' (stock OpenWrt rule, covered by default)"
        ));
        return;
    }
    let skip = |plan: &mut Plan, why: String| {
        plan.unmapped
            .push(format!("firewall: rule '{name}': {why}"));
    };
    let left = s.leftover(&[
        "name",
        "src",
        "dest",
        "proto",
        "src_ip",
        "dest_ip",
        "dest_port",
        "src_port",
        "target",
        "family",
        "enabled",
    ]);
    if !left.is_empty() {
        return skip(plan, format!("option(s) not imported: {}", left.join(", ")));
    }
    if !s
        .get("target")
        .unwrap_or("ACCEPT")
        .eq_ignore_ascii_case("ACCEPT")
    {
        return skip(
            plan,
            format!(
                "target {} (only ACCEPT rules are imported)",
                s.get("target").unwrap_or("")
            ),
        );
    }
    let protos = match protocols(s) {
        Ok(p) => p,
        Err(e) => return skip(plan, e),
    };
    let iface_in = match zone_iface(s.get("src")) {
        Ok(v) => v,
        Err(e) => return skip(plan, e),
    };
    let iface_out = match zone_iface(s.get("dest")) {
        Ok(v) => v,
        Err(e) => return skip(plan, e),
    };
    let dport = match s.get("dest_port").map(parse_dports) {
        Some(None) => return skip(plan, "dest_port (unsupported syntax)".into()),
        Some(Some(p)) => Some(p),
        None => None,
    };
    let sport = match s.get("src_port").map(parse_dports) {
        Some(None) => return skip(plan, "src_port (unsupported syntax)".into()),
        Some(Some(p)) => Some(p),
        None => None,
    };
    if (dport.is_some() || sport.is_some())
        && !protos
            .iter()
            .all(|p| matches!(p, Some(Protocol::Tcp | Protocol::Udp)))
    {
        return skip(plan, "a port needs protocol tcp or udp".into());
    }
    let sources: Vec<Option<String>> = match s.words("src_ip") {
        v if v.is_empty() => vec![None],
        v => v.into_iter().map(Some).collect(),
    };
    let dests: Vec<Option<String>> = match s.words("dest_ip") {
        v if v.is_empty() => vec![None],
        v => v.into_iter().map(Some).collect(),
    };
    let version = match s.get("family") {
        Some("ipv4") => Some(IpVersion::V4),
        Some("ipv6") => Some(IpVersion::V6),
        _ => None,
    };
    let chain = if iface_out.is_some() || s.get("dest").is_some() {
        ChainType::Forward
    } else {
        ChainType::Input
    };
    let many = protos.len() * sources.len() * dests.len() > 1;
    let mut n = 0;
    for p in &protos {
        for src in &sources {
            for dst in &dests {
                n += 1;
                let mut r = FirewallRule::new(
                    if many {
                        format!("{name} #{n}")
                    } else {
                        name.clone()
                    },
                    chain.clone(),
                    FirewallAction::Accept,
                );
                r.enabled = s.flag("enabled").unwrap_or(true);
                r.protocol = p.clone();
                r.source = src.clone();
                r.destination = dst.clone();
                r.dport = dport.clone();
                r.sport = sport.clone();
                r.interface_in = iface_in.clone();
                r.interface_out = iface_out.clone();
                r.ip_version = version;
                r.comment = Some("imported from OpenWrt UCI".into());
                plan.fw_rules.push(r);
            }
        }
    }
}

fn redirect_plan(plan: &mut Plan, s: &Section) {
    let name = s.get("name").unwrap_or(&s.label()).to_string();
    let skip = |plan: &mut Plan, why: String| {
        plan.unmapped
            .push(format!("firewall: redirect '{name}': {why}"));
    };
    let left = s.leftover(&[
        "name",
        "src",
        "dest",
        "proto",
        "src_dport",
        "src_dip",
        "src_ip",
        "dest_ip",
        "dest_port",
        "target",
        "enabled",
        "reflection",
    ]);
    if !left.is_empty() {
        return skip(plan, format!("option(s) not imported: {}", left.join(", ")));
    }
    if !s
        .get("target")
        .unwrap_or("DNAT")
        .eq_ignore_ascii_case("DNAT")
    {
        return skip(plan, "target is not DNAT".into());
    }
    let Some(to) = s.get("dest_ip").and_then(|a| a.parse::<IpAddr>().ok()) else {
        return skip(
            plan,
            "no dest_ip (a port forward needs an internal address)".into(),
        );
    };
    let iface_in = match zone_iface(s.get("src").or(Some("wan"))) {
        Ok(v) => v,
        Err(e) => return skip(plan, e),
    };
    let dport = match s.get("src_dport").map(parse_dports) {
        Some(None) => return skip(plan, "src_dport (unsupported syntax)".into()),
        Some(p) => p,
        None => None,
    };
    let to_port = match s.get("dest_port").map(|p| p.parse::<u16>()) {
        Some(Ok(p)) => Some(p),
        Some(Err(_)) => return skip(plan, "dest_port (a single port is supported)".into()),
        None => None,
    };
    if to_port.is_some() && dport.is_none() {
        return skip(plan, "a target port needs src_dport".into());
    }
    let protos = match protocols(s) {
        Ok(p) if s.get("proto").is_some() => p,
        Ok(_) => vec![Some(Protocol::Tcp), Some(Protocol::Udp)],
        Err(e) => return skip(plan, e),
    };
    let many = protos.len() > 1;
    for p in protos {
        if dport.is_some() && !matches!(p, Some(Protocol::Tcp | Protocol::Udp)) {
            return skip(plan, "a port needs protocol tcp or udp".into());
        }
        let label = p.as_ref().map(|p| p.to_string()).unwrap_or_default();
        let mut r = NatRule::new(
            if many {
                format!("{name} ({label})")
            } else {
                name.clone()
            },
            NatType::Dnat {
                to_address: to,
                to_port,
            },
        );
        r.enabled = s.flag("enabled").unwrap_or(true);
        r.protocol = p;
        r.dport = dport.clone();
        r.interface_in = iface_in.clone();
        r.source = s.get("src_ip").map(str::to_string);
        r.destination = s.get("src_dip").map(str::to_string);
        r.reflection = s.flag("reflection").unwrap_or(true);
        r.comment = Some("imported from OpenWrt UCI".into());
        plan.nat_rules.push(r);
    }
}

fn wireless_plan(plan: &mut Plan, files: &Files, maps: &BTreeMap<String, String>) {
    let radios: BTreeMap<String, &Section> = sections(files, "wireless", "wifi-device")
        .map(|d| (d.label(), d))
        .collect();
    for d in radios.values() {
        unmapped_opts(plan, "wireless", d, &["band", "channel", "country"]);
    }
    for s in sections(files, "wireless", "wifi-iface") {
        let section = s.label();
        let radio = s.get("device").unwrap_or("").to_string();
        let dev = radios.get(&radio);
        let mode = s.get("mode").unwrap_or("ap").to_string();
        plan.wifi.push(WifiPlan {
            section: section.clone(),
            mode: mode.clone(),
            ssid: s.get("ssid").unwrap_or("").to_string(),
            encryption: s.get("encryption").unwrap_or("none").to_string(),
            key: s.get("key").map(str::to_string),
            disabled: s.flag("disabled").unwrap_or(false),
            radio,
            network: s.get("network").unwrap_or("").to_string(),
            band: dev.and_then(|d| d.get("band")).map(str::to_string),
            channel: dev
                .and_then(|d| d.get("channel"))
                .and_then(|c| c.parse().ok()),
            country: dev.and_then(|d| d.get("country")).map(str::to_string),
            device: maps.get(&section).cloned(),
        });
        unmapped_opts(
            plan,
            "wireless",
            s,
            &[
                "device",
                "mode",
                "ssid",
                "encryption",
                "key",
                "disabled",
                "network",
            ],
        );
    }
    for s in files.get("wireless").into_iter().flatten() {
        if s.kind != "wifi-device" && s.kind != "wifi-iface" {
            plan.unmapped.push(format!(
                "wireless: {} '{}' (not imported)",
                s.kind,
                s.label()
            ));
        }
    }
}

/// `psk2`, `psk2+ccmp`, `sae`, ... -> the wifi-ap `security` value.
fn wifi_security(enc: &str) -> Option<&'static str> {
    let base = enc.split('+').next().unwrap_or("");
    match base {
        "psk2" | "psk-mixed" | "psk" => Some("wpa2"),
        "sae-mixed" => Some("wpa2_wpa3"),
        "sae" => Some("wpa3"),
        _ => None,
    }
}

impl WifiPlan {
    /// Why this AP cannot become a Wi-Fi network (None = it can).
    pub fn ap_blocker(&self) -> Option<String> {
        if self.mode != "ap" {
            return Some(format!("mode '{}' is not an access point", self.mode));
        }
        if wifi_security(&self.encryption).is_none() {
            return Some(format!(
                "encryption '{}' has no equivalent (Patronus APs are WPA2/WPA3)",
                self.encryption
            ));
        }
        if self.key.is_none() {
            return Some("no key".into());
        }
        if self.device.is_none() {
            return Some(format!("no --map {}=<ap device>", self.section));
        }
        if !cfg!(feature = "wifi-ap") {
            return Some("built without the wifi-ap feature".into());
        }
        None
    }
}

fn system_plan(plan: &mut Plan, files: &Files) {
    for s in files.get("system").into_iter().flatten() {
        let mut kept = Vec::new();
        for k in ["hostname", "timezone", "zonename"] {
            if let Some(v) = s.get(k) {
                kept.push(format!("{k} '{v}'"));
            }
        }
        // the store has no hostname/timezone/ntp setting to write them to
        let left = s.leftover(&["hostname", "timezone", "zonename"]);
        plan.unmapped.push(format!(
            "system: {} '{}': {}{}",
            s.kind,
            s.label(),
            if kept.is_empty() {
                "-".to_string()
            } else {
                kept.join(", ")
            },
            if left.is_empty() {
                String::new()
            } else {
                format!("; also {}", left.join(", "))
            }
        ));
    }
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

fn describe_rule(r: &FirewallRule) -> String {
    format!(
        "{} {} {}{}{} in {} out {} from {} to {}  \"{}\"",
        r.chain,
        r.action,
        r.protocol
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".into()),
        r.dport
            .as_ref()
            .map(|p| format!("/{p}"))
            .unwrap_or_default(),
        r.ip_version.map(|v| format!(" {v}")).unwrap_or_default(),
        r.interface_in.as_deref().unwrap_or("any"),
        r.interface_out.as_deref().unwrap_or("any"),
        r.source.as_deref().unwrap_or("any"),
        r.destination.as_deref().unwrap_or("any"),
        r.name
    )
}

/// The report. Contains no secret: keys print as `key: (set)`.
pub fn render(plan: &Plan, dry_run: bool) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "patronus import-uci{}",
        if dry_run {
            " (dry run, nothing is written)"
        } else {
            ""
        }
    );
    let verb = if dry_run { "would write" } else { "write" };
    let _ = writeln!(o, "\nnetwork ({verb}):");
    for i in &plan.ifaces {
        let _ = writeln!(
            o,
            "  {} -> {}: role {}, {}{}{}{}{}",
            i.uci,
            i.device,
            i.role.as_deref().unwrap_or("-"),
            i.v4.as_str(),
            i.addrs.iter().map(|a| format!(" {a}")).collect::<String>(),
            i.gateway4.map(|g| format!(" gw {g}")).unwrap_or_default(),
            if i.v6 == V6Mode::Unmanaged {
                String::new()
            } else {
                format!(", ipv6 {}", i.v6.as_str())
            },
            if i.enabled { "" } else { ", disabled" }
        );
    }
    let _ = writeln!(o, "\ndhcp ({verb}):");
    for p in &plan.pools {
        let _ = writeln!(
            o,
            "  pool on {}: {}-{} lease {}s router {}{}",
            p.device,
            p.start,
            p.end,
            p.lease_time.unwrap_or(86400),
            p.router,
            p.domain
                .as_ref()
                .map(|d| format!(" domain {d}"))
                .unwrap_or_default()
        );
    }
    for s in &plan.statics {
        let _ = writeln!(
            o,
            "  static lease on {}: {} {} {}",
            s.device,
            s.mac,
            s.ip,
            s.name.as_deref().unwrap_or("")
        );
    }
    let _ = writeln!(o, "\nfirewall ({verb}):");
    for r in &plan.fw_rules {
        let _ = writeln!(o, "  rule {}", describe_rule(r));
    }
    for n in &plan.nat_rules {
        if let NatType::Dnat {
            to_address,
            to_port,
        } = &n.nat_type
        {
            let _ = writeln!(
                o,
                "  port forward {} {} {} -> {}{}  \"{}\"",
                n.interface_in.as_deref().unwrap_or("any"),
                n.protocol
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "any".into()),
                n.dport
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "any".into()),
                to_address,
                to_port.map(|p| format!(":{p}")).unwrap_or_default(),
                n.name
            );
        }
    }
    let _ = writeln!(o, "\nwireless (order kept):");
    for (n, w) in plan.wifi.iter().enumerate() {
        let _ = writeln!(
            o,
            "  {}. {} {} ssid '{}' radio {} encryption {} key: {} {}",
            n + 1,
            w.mode,
            w.section,
            w.ssid,
            w.radio,
            w.encryption,
            if w.key.is_some() { "(set)" } else { "(none)" },
            if w.disabled { "disabled" } else { "enabled" },
        );
        let how = match w.mode.as_str() {
            "ap" => match w.ap_blocker() {
                None => format!("-> Wi-Fi network on {}", w.device.as_deref().unwrap_or("")),
                Some(b) => format!("-> reported only: {b}"),
            },
            "sta" => "-> parked as setting import.uci.wifi_sta (no client resource yet)".into(),
            m => format!("-> reported only: mode '{m}'"),
        };
        let _ = writeln!(o, "     {how}");
    }
    let _ = writeln!(o, "\ncovered by default:");
    for c in &plan.covered {
        let _ = writeln!(o, "  {c}");
    }
    let _ = writeln!(o, "\nrecorded:");
    for c in &plan.notes {
        let _ = writeln!(o, "  {c}");
    }
    let _ = writeln!(o, "\nunmapped ({}):", plan.unmapped.len());
    for c in &plan.unmapped {
        let _ = writeln!(o, "  {c}");
    }
    o
}

// ---------------------------------------------------------------------------
// store writes
// ---------------------------------------------------------------------------

const STA_SETTING: &str = "import.uci.wifi_sta";

/// Write the plan into the store. Returns one line per thing written/skipped.
pub async fn apply(
    store: &patronus_config::store::ConfigStore,
    plan: &Plan,
) -> Result<Vec<String>> {
    use patronus_network::lan::set_setting;
    let e = |x: patronus_core::Error| anyhow::anyhow!("{x}");
    let mut out = Vec::new();

    // validate before the first write
    #[cfg(feature = "dhcp-server")]
    let pools: Vec<_> = plan
        .pools
        .iter()
        .map(|p| {
            patronus_network::dhcp::PoolInput {
                interface: p.device.clone(),
                enabled: true,
                range_start: p.start.to_string(),
                range_end: p.end.to_string(),
                lease_time: p.lease_time,
                gateway: Some(p.router.to_string()),
                dns_servers: Some(p.router.to_string()),
                domain: p.domain.clone(),
                description: Some("imported from OpenWrt UCI".into()),
                ..Default::default()
            }
            .validate()
            .map_err(|x| anyhow::anyhow!("dhcp pool on {}: {x}", p.device))
        })
        .collect::<Result<_>>()?;

    if !plan.ifaces.is_empty() {
        let mut cfg = NetConfig::load(store).await.map_err(e)?;
        for p in &plan.ifaces {
            let i = cfg.iface_mut(&p.device);
            i.role = p.role.clone().or(i.role.take());
            i.enabled = p.enabled;
            i.ipv4_mode = p.v4;
            i.ipv4 = p.addrs.clone();
            i.gateway4 = p.gateway4;
            if p.v6 != V6Mode::Unmanaged {
                i.ipv6_mode = p.v6;
            }
            if p.mtu.is_some() {
                i.mtu = p.mtu;
            }
            i.description = Some(format!("imported from UCI interface {}", p.uci));
        }
        cfg.save(store).await.map_err(e)?;
        out.push(format!("interfaces: {} written", plan.ifaces.len()));
    }

    #[cfg(feature = "dhcp-server")]
    {
        use patronus_network::dhcp;
        let existing = dhcp::list_pools(store).await.map_err(e)?;
        for pool in pools {
            let id = existing
                .iter()
                .find(|x| x.interface == pool.interface)
                .map(|x| x.id);
            let dev = pool.interface.clone();
            dhcp::upsert_pool(store, id, &pool).await.map_err(e)?;
            out.push(format!(
                "dhcp pool on {dev}: {}",
                if id.is_some() { "updated" } else { "created" }
            ));
        }
        let pools = dhcp::list_pools(store).await.map_err(e)?;
        for s in &plan.statics {
            let Some(pool) = pools.iter().find(|p| p.interface == s.device) else {
                out.push(format!("static lease {}: no pool on {}", s.ip, s.device));
                continue;
            };
            if pool.static_mappings.iter().any(|m| m.ip == s.ip) {
                out.push(format!("static lease {}: already present", s.ip));
                continue;
            }
            let m = dhcp::StaticInput {
                mac: s.mac.clone(),
                ip: s.ip.to_string(),
                hostname: s.name.clone(),
                description: Some("imported from OpenWrt UCI".into()),
            }
            .validate(pool);
            match m {
                Ok(m) => {
                    dhcp::add_static(store, &m).await.map_err(e)?;
                    out.push(format!("static lease {}: created", s.ip));
                }
                Err(x) => out.push(format!("static lease {}: skipped ({x})", s.ip)),
            }
        }
    }
    #[cfg(not(feature = "dhcp-server"))]
    if !plan.pools.is_empty() || !plan.statics.is_empty() {
        out.push("dhcp: skipped (built without the dhcp-server feature)".into());
    }

    let have: BTreeSet<String> = store
        .load_firewall_rules()
        .await
        .map_err(e)?
        .into_iter()
        .map(|r| r.name)
        .collect();
    for r in &plan.fw_rules {
        if have.contains(&r.name) {
            out.push(format!("firewall rule '{}': already present", r.name));
        } else {
            store.save_firewall_rule(r).await.map_err(e)?;
            out.push(format!("firewall rule '{}': created", r.name));
        }
    }
    let have: BTreeSet<String> = store
        .load_nat_rules()
        .await
        .map_err(e)?
        .into_iter()
        .map(|r| r.name)
        .collect();
    for r in &plan.nat_rules {
        if have.contains(&r.name) {
            out.push(format!("port forward '{}': already present", r.name));
        } else {
            store.save_nat_rule(r).await.map_err(e)?;
            out.push(format!("port forward '{}': created", r.name));
        }
    }

    // wireless: APs -> Wi-Fi networks (wifi-ap); the shared key is parked in
    // the store (the per-device credential model has no slot for it)
    for w in plan.wifi.iter().filter(|w| w.mode == "ap") {
        if let Some(why) = w.ap_blocker() {
            out.push(format!("wifi {}: reported only ({why})", w.section));
            continue;
        }
        #[cfg(feature = "wifi-ap")]
        {
            use patronus_config::seg_wifi;
            let name = w.section.to_ascii_lowercase();
            if seg_wifi::network_by_name(store, &name)
                .await
                .map_err(e)?
                .is_some()
            {
                out.push(format!("wifi {}: already present", w.section));
                continue;
            }
            let band = match w.band.as_deref() {
                Some("5g") => "5g",
                _ => "2g",
            };
            let id = seg_wifi::create_network(
                store,
                &seg_wifi::NetworkInput {
                    name,
                    ifname: w.device.clone().unwrap_or_default(),
                    ssid: w.ssid.clone(),
                    band: Some(band.into()),
                    channel: w.channel.filter(|c| *c > 0),
                    country: w.country.clone(),
                    security: wifi_security(&w.encryption).map(str::to_string),
                    enabled: Some(!w.disabled),
                    ..Default::default()
                },
            )
            .await
            .map_err(e)?;
            if let Some(k) = &w.key {
                set_setting(store, &format!("import.uci.wifi_ap.{}.key", w.section), k)
                    .await
                    .map_err(e)?;
            }
            out.push(format!(
                "wifi {}: network {id} created, key: (set)",
                w.section
            ));
        }
    }
    let sta: Vec<serde_json::Value> = plan
        .wifi
        .iter()
        .filter(|w| w.mode == "sta")
        .enumerate()
        .map(|(n, w)| {
            serde_json::json!({
                "order": n, "section": w.section, "radio": w.radio, "ssid": w.ssid,
                "encryption": w.encryption, "key": w.key, "disabled": w.disabled,
                "network": w.network,
            })
        })
        .collect();
    if !sta.is_empty() {
        set_setting(
            store,
            STA_SETTING,
            &serde_json::Value::Array(sta.clone()).to_string(),
        )
        .await
        .map_err(e)?;
        out.push(format!(
            "wifi client entries: {} parked in {STA_SETTING}, key: (set)",
            sta.len()
        ));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

pub async fn run(
    db: Option<PathBuf>,
    input: PathBuf,
    dry_run: bool,
    maps: Vec<String>,
) -> Result<()> {
    let maps = parse_maps(&maps)?;
    let files = load_input(&input)?;
    let plan = build_plan(&files, &maps);
    print!("{}", render(&plan, dry_run));
    if dry_run {
        return Ok(());
    }
    let store = super::apply::open_store(db.as_deref()).await?;
    println!("\nstore:");
    for l in apply(&store, &plan).await? {
        println!("  {l}");
    }
    println!("\nreview with `patronus apply --dry-run`, then `patronus apply`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_config::store::ConfigStore;

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/uci-slate")
    }

    fn maps() -> BTreeMap<String, String> {
        parse_maps(&[
            "lan=br-lan".into(),
            "wan=eth1".into(),
            "wwan=wl24-sta".into(),
            "default_radio0=wl50-ap".into(),
        ])
        .unwrap()
    }

    fn fixture_plan() -> Plan {
        build_plan(&load_dir(&fixture_dir()).unwrap(), &maps())
    }

    // ---- parser

    #[test]
    fn parser_quoting_lists_and_anonymous_sections() {
        let s = parse_uci(
            "# comment\npackage x\n\nconfig rule\n\toption name 'Allow SSH'  # trailing\n\toption dq \"a \\\"b\\\" c\"\n\toption bare plain\n\toption empty ''\n\tlist proto 'tcp'\n\tlist proto udp\n\tlist src_ip \"10.0.0.0/8\"\n\nconfig rule 'named'\n\toption name x\n\nconfig other\n",
        )
        .unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].name, None);
        assert_eq!(s[0].label(), "@rule[0]");
        assert_eq!(s[1].label(), "named");
        assert_eq!(s[1].index, 1);
        assert_eq!(s[2].label(), "@other[0]");
        assert_eq!(s[0].get("name"), Some("Allow SSH"));
        assert_eq!(s[0].get("dq"), Some("a \"b\" c"));
        assert_eq!(s[0].get("bare"), Some("plain"));
        assert_eq!(s[0].get("empty"), Some(""));
        assert_eq!(s[0].words("proto"), ["tcp", "udp"]);
        assert_eq!(s[0].words("src_ip"), ["10.0.0.0/8"]);
    }

    #[test]
    fn parser_later_option_replaces_and_hash_inside_quotes_is_data() {
        let s =
            parse_uci("config a 'x'\noption k '1'\noption k '2'\noption h 'a # b'\noption m a#b\n")
                .unwrap();
        assert_eq!(s[0].get("k"), Some("2"));
        assert_eq!(s[0].get("h"), Some("a # b"));
        assert_eq!(s[0].get("m"), Some("a#b"));
    }

    #[test]
    fn parser_rejects_garbage() {
        assert!(parse_uci("option a b\n")
            .unwrap_err()
            .to_string()
            .contains("line 1"));
        assert!(parse_uci("config a\noption k 'open\n")
            .unwrap_err()
            .to_string()
            .contains("unterminated"));
        assert!(parse_uci("config a\nfrob x y\n").is_err());
        assert!(parse_uci("config a\noption onlykey\n").is_err());
    }

    #[test]
    fn small_helpers() {
        assert_eq!(parse_duration("12h"), Some(43200));
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("infinite"), None);
        assert_eq!(v4_netmask_prefix("255.255.255.0"), Some(24));
        assert_eq!(v4_netmask_prefix("255.0.255.0"), None);
        assert_eq!(parse_dports("22"), Some(PortSpec::Single(22)));
        assert_eq!(parse_dports("1000-2000"), Some(PortSpec::Range(1000, 2000)));
        assert_eq!(
            parse_dports("80 443"),
            Some(PortSpec::Multiple(vec![80, 443]))
        );
        assert_eq!(parse_dports("0"), None);
        assert!(parse_maps(&["nodev".into()]).is_err());
        assert_eq!(
            config_members("./etc/shadow\n./etc/config/network\netc/config/dhcp\n./etc/config/\n./etc/config/x/y\n"),
            ["./etc/config/network", "etc/config/dhcp"]
        );
    }

    // ---- mapping of the (sanitized) GL-AR750S config

    #[test]
    fn fixture_network_mapping() {
        let p = fixture_plan();
        let lan = p.ifaces.iter().find(|i| i.uci == "lan").unwrap();
        assert_eq!(lan.device, "br-lan");
        assert_eq!(lan.role.as_deref(), Some("lan"));
        assert_eq!(lan.v4, V4Mode::Static);
        assert_eq!(
            lan.addrs,
            vec!["10.0.66.1/24".parse::<IpNetwork>().unwrap()]
        );
        let wwan = p.ifaces.iter().find(|i| i.uci == "wwan").unwrap();
        assert_eq!(wwan.device, "wl24-sta");
        assert_eq!(wwan.role.as_deref(), Some("wan"));
        assert_eq!(wwan.v4, V4Mode::Dhcp);
        let wan = p.ifaces.iter().find(|i| i.uci == "wan").unwrap();
        assert_eq!(
            (wan.role.as_deref(), wan.v4, wan.v6),
            (Some("wan"), V4Mode::Dhcp, V6Mode::Dhcp6)
        );
        // wan6 rode on wan's device; the etph 'phone' interface and the switch are reported
        assert_eq!(p.ifaces.len(), 3);
        assert!(p
            .unmapped
            .iter()
            .any(|u| u.contains("interface 'phone' proto 'etph'")));
        assert!(p.unmapped.iter().any(|u| u.contains("switch_vlan")));
        assert!(p.unmapped.iter().any(|u| u.contains("ip6assign")));
    }

    #[test]
    fn unmapped_interfaces_go_to_the_report() {
        let p = build_plan(&load_dir(&fixture_dir()).unwrap(), &BTreeMap::new());
        assert!(p.ifaces.is_empty() && p.pools.is_empty());
        assert!(p.unmapped.iter().any(|u| u.contains("no --map lan=")));
        assert!(p
            .unmapped
            .iter()
            .any(|u| u.contains("interface not mapped")));
    }

    #[test]
    fn fixture_dhcp_pool() {
        let p = fixture_plan();
        assert_eq!(p.pools.len(), 1, "wan has ignore '1'");
        let pool = &p.pools[0];
        assert_eq!(pool.device, "br-lan");
        assert_eq!(pool.start, "10.0.66.100".parse::<Ipv4Addr>().unwrap());
        assert_eq!(pool.end, "10.0.66.249".parse::<Ipv4Addr>().unwrap());
        assert_eq!(pool.lease_time, Some(43200));
        assert_eq!(pool.router, "10.0.66.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(pool.domain.as_deref(), Some("lan"));
        assert!(p.notes.iter().any(|n| n.contains("ignore '1'")));
    }

    #[test]
    fn fixture_firewall_mapping() {
        let p = fixture_plan();
        for n in STOCK_RULES {
            assert!(
                p.covered
                    .iter()
                    .any(|c| c.contains(&format!("'{n}'")) && c.contains("covered by default")),
                "{n}"
            );
        }
        assert!(p
            .fw_rules
            .iter()
            .all(|r| !STOCK_RULES.contains(&r.name.as_str())));
        assert_eq!(p.fw_rules.len(), 1);
        let ssh = &p.fw_rules[0];
        assert_eq!(ssh.name, "Allow SSH");
        assert_eq!(ssh.chain, ChainType::Input);
        assert_eq!(ssh.protocol, Some(Protocol::Tcp));
        assert_eq!(ssh.dport, Some(PortSpec::Single(22)));
        assert_eq!(ssh.source.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(ssh.interface_in.as_deref(), Some("@wan"));
        assert!(p
            .covered
            .iter()
            .any(|c| c.contains("forwarding lan -> wan")));
        assert!(p.notes.iter().any(|n| n.contains("masq")));
        assert!(p.unmapped.iter().any(|u| u.contains("include")));
    }

    #[test]
    fn fixture_wireless_order_and_disabled_state() {
        let p = fixture_plan();
        let got: Vec<_> = p
            .wifi
            .iter()
            .map(|w| {
                (
                    w.section.as_str(),
                    w.mode.as_str(),
                    w.ssid.as_str(),
                    w.disabled,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("default_radio0", "ap", "HomeNet", false),
                ("default_radio1", "ap", "OpenWrt", true),
                ("wifinet2", "sta", "UpstreamRepeater", false),
                ("wifinet3", "sta", "PhoneHotspot", false),
                ("wifinet4", "sta", "GuestStation", true),
            ]
        );
        assert!(p.wifi[2..]
            .iter()
            .all(|w| w.key.is_some() && w.encryption == "psk2"));
        // an open AP has no Patronus equivalent
        assert!(p.wifi[0]
            .ap_blocker()
            .unwrap()
            .contains("encryption 'none'"));
    }

    #[test]
    fn fixture_system_is_reported() {
        let p = fixture_plan();
        assert!(p
            .unmapped
            .iter()
            .any(|u| u.contains("hostname 'slate'") && u.contains("timezone 'GMT0'")));
        assert!(p.unmapped.iter().any(|u| u.contains("timeserver")));
    }

    #[test]
    fn report_never_prints_a_key() {
        let p = fixture_plan();
        let r = render(&p, true);
        assert!(r.contains("key: (set)"));
        assert!(!r.contains("fixture-key"), "{r}");
        assert!(r.contains("dry run"));
    }

    #[test]
    fn rules_and_redirects_from_text() {
        let f = Files::from([
            (
                "network".to_string(),
                parse_uci("config interface 'lan'\n\toption device 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.5.1'\n\toption netmask '255.255.255.0'\n").unwrap(),
            ),
            (
                "firewall".to_string(),
                parse_uci(
                    "config zone\n\toption name 'lan'\n\tlist network 'lan'\nconfig zone\n\toption name 'dmz'\nconfig rule\n\toption name 'web'\n\toption src 'wan'\n\toption dest 'lan'\n\toption proto 'tcp udp'\n\toption dest_port '8000-8010'\nconfig rule\n\toption name 'drop-it'\n\toption target 'DROP'\nconfig rule\n\toption name 'ping6'\n\toption proto 'icmp'\n\toption icmp_type 'echo-request'\nconfig redirect\n\toption name 'ssh-in'\n\toption src 'wan'\n\toption src_dport '2222'\n\toption dest_ip '192.168.5.10'\n\toption dest_port '22'\n\toption proto 'tcp'\nconfig redirect\n\toption name 'broken'\n",
                )
                .unwrap(),
            ),
            (
                "dhcp".to_string(),
                parse_uci("config dhcp 'lan'\n\toption interface 'lan'\n\toption start '10'\n\toption limit '20'\nconfig host\n\toption name 'nas'\n\toption mac 'AA:BB:CC:00:11:22'\n\toption ip '192.168.5.5'\n").unwrap(),
            ),
        ]);
        let m = parse_maps(&["lan=br-lan".into()]).unwrap();
        let p = build_plan(&f, &m);
        assert_eq!(p.ifaces[0].addrs[0].to_string(), "192.168.5.1/24");
        assert_eq!(p.pools[0].start.to_string(), "192.168.5.10");
        assert_eq!(p.pools[0].end.to_string(), "192.168.5.29");
        assert_eq!(p.statics.len(), 1);
        let web: Vec<_> = p
            .fw_rules
            .iter()
            .filter(|r| r.name.starts_with("web"))
            .collect();
        assert_eq!(web.len(), 2);
        assert!(
            web.iter()
                .all(|r| r.chain == ChainType::Forward
                    && r.dport == Some(PortSpec::Range(8000, 8010)))
        );
        assert_eq!(p.nat_rules.len(), 1);
        assert_eq!(
            p.nat_rules[0].nat_type,
            NatType::Dnat {
                to_address: "192.168.5.10".parse().unwrap(),
                to_port: Some(22)
            }
        );
        assert_eq!(p.nat_rules[0].dport, Some(PortSpec::Single(2222)));
        let u = p.unmapped.join("\n");
        assert!(u.contains("zone 'dmz'"), "{u}");
        assert!(u.contains("rule 'drop-it': target DROP"), "{u}");
        assert!(
            u.contains("rule 'ping6': option(s) not imported: icmp_type"),
            "{u}"
        );
        assert!(u.contains("redirect 'broken'"), "{u}");
    }

    // ---- store round trip

    #[tokio::test]
    async fn store_round_trip_and_rerun() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let plan = fixture_plan();
        let before = store.load_firewall_rules().await.unwrap().len();
        let out = apply(&store, &plan).await.unwrap();
        assert!(!out.join("\n").contains("fixture-key"));

        let cfg = NetConfig::load(&store).await.unwrap();
        let lan = cfg.iface("br-lan").unwrap();
        assert_eq!(lan.role.as_deref(), Some("lan"));
        assert_eq!(lan.ipv4_mode, V4Mode::Static);
        assert_eq!(lan.ipv4, vec!["10.0.66.1/24".parse::<IpNetwork>().unwrap()]);
        let sta = cfg.iface("wl24-sta").unwrap();
        assert_eq!(
            (sta.role.as_deref(), sta.ipv4_mode),
            (Some("wan"), V4Mode::Dhcp)
        );
        assert_eq!(cfg.iface("eth1").unwrap().ipv6_mode, V6Mode::Dhcp6);

        #[cfg(feature = "dhcp-server")]
        {
            let pools = patronus_network::dhcp::list_pools(&store).await.unwrap();
            assert_eq!(pools.len(), 1);
            assert_eq!(pools[0].interface, "br-lan");
            assert_eq!(pools[0].range_start.to_string(), "10.0.66.100");
            assert_eq!(pools[0].range_end.to_string(), "10.0.66.249");
            assert_eq!(pools[0].lease_time, 43200);
        }
        let rules = store.load_firewall_rules().await.unwrap();
        assert_eq!(rules.len(), before + 1);
        let ssh = rules.iter().find(|r| r.name == "Allow SSH").unwrap();
        assert_eq!(ssh.dport, Some(PortSpec::Single(22)));
        assert_eq!(ssh.interface_in.as_deref(), Some("@wan"));

        // STA entries are parked in order with their disabled flag, key kept in the store
        let parked = patronus_network::lan::get_setting(&store, STA_SETTING)
            .await
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&parked).unwrap();
        let ids: Vec<_> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["ssid"].as_str().unwrap(),
                    e["disabled"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            ids,
            [
                ("UpstreamRepeater", false),
                ("PhoneHotspot", false),
                ("GuestStation", true)
            ]
        );
        assert_eq!(v[0]["key"], "fixture-key-1");

        // second run: nothing is duplicated
        apply(&store, &plan).await.unwrap();
        assert_eq!(store.load_firewall_rules().await.unwrap().len(), before + 1);
        #[cfg(feature = "dhcp-server")]
        assert_eq!(
            patronus_network::dhcp::list_pools(&store)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn store_writes_port_forward_and_static_lease() {
        let f = Files::from([
            ("network".to_string(), parse_uci("config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '192.168.5.1/24'\nconfig interface 'wan'\n\toption proto 'dhcp'\n").unwrap()),
            ("firewall".to_string(), parse_uci("config zone\n\toption name 'lan'\n\tlist network 'lan'\nconfig zone\n\toption name 'wan'\n\tlist network 'wan'\nconfig redirect\n\toption name 'ssh-in'\n\toption src 'wan'\n\toption src_dport '2222'\n\toption dest_ip '192.168.5.10'\n\toption dest_port '22'\n\toption proto 'tcp'\n").unwrap()),
            ("dhcp".to_string(), parse_uci("config dhcp 'lan'\n\toption interface 'lan'\nconfig host\n\toption name 'nas'\n\toption mac 'AA:BB:CC:00:11:22'\n\toption ip '192.168.5.5'\n").unwrap()),
        ]);
        let m = parse_maps(&["lan=br-lan".into(), "wan=eth1".into()]).unwrap();
        let plan = build_plan(&f, &m);
        let store = ConfigStore::open_in_memory().await.unwrap();
        apply(&store, &plan).await.unwrap();
        let nat = store.load_nat_rules().await.unwrap();
        let fwd = nat.iter().find(|n| n.name == "ssh-in").unwrap();
        assert_eq!(fwd.interface_in.as_deref(), Some("@wan"));
        assert_eq!(fwd.dport, Some(PortSpec::Single(2222)));
        #[cfg(feature = "dhcp-server")]
        {
            let pools = patronus_network::dhcp::list_pools(&store).await.unwrap();
            assert_eq!(pools[0].range_start.to_string(), "192.168.5.100");
            assert_eq!(pools[0].static_mappings.len(), 1);
            assert_eq!(pools[0].static_mappings[0].mac, "aa:bb:cc:00:11:22");
        }
    }

    #[cfg(feature = "wifi-ap")]
    #[tokio::test]
    async fn store_writes_a_wpa2_ap() {
        let f = Files::from([
            ("network".to_string(), parse_uci("config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '192.168.5.1/24'\n").unwrap()),
            ("wireless".to_string(), parse_uci("config wifi-device 'radio0'\n\toption band '5g'\n\toption channel '36'\nconfig wifi-iface 'ap0'\n\toption device 'radio0'\n\toption mode 'ap'\n\toption ssid 'HomeNet'\n\toption encryption 'psk2'\n\toption key 'fixture-key-9'\n").unwrap()),
        ]);
        let m = parse_maps(&["ap0=wl50-ap".into()]).unwrap();
        let plan = build_plan(&f, &m);
        let store = ConfigStore::open_in_memory().await.unwrap();
        let out = apply(&store, &plan).await.unwrap();
        assert!(!out.join("\n").contains("fixture-key"));
        let n = patronus_config::seg_wifi::network_by_name(&store, "ap0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                n.ssid.as_str(),
                n.band.as_str(),
                n.channel,
                n.security.as_str()
            ),
            ("HomeNet", "5g", 36, "wpa2")
        );
        assert_eq!(n.ifname, "wl50-ap");
    }

    // ---- tarball

    #[test]
    fn tarball_is_read_with_tar() {
        let tmp = std::env::temp_dir().join(format!("uci-import-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("etc")).unwrap();
        std::fs::create_dir_all(tmp.join("root")).unwrap();
        let cfg = tmp.join("etc/config");
        std::fs::create_dir_all(&cfg).unwrap();
        for f in std::fs::read_dir(fixture_dir().join("etc/config")).unwrap() {
            let f = f.unwrap();
            std::fs::copy(f.path(), cfg.join(f.file_name())).unwrap();
        }
        std::fs::write(tmp.join("etc/shadow"), "root:x:\n").unwrap();
        let tgz = tmp.join("backup.tar.gz");
        let st = std::process::Command::new("tar")
            .args(["czf"])
            .arg(&tgz)
            .args(["-C"])
            .arg(&tmp)
            .args(["./etc/shadow", "./etc/config"])
            .status()
            .unwrap();
        assert!(st.success());
        let files = load_input(&tgz).unwrap();
        let from_dir = load_dir(&fixture_dir()).unwrap();
        assert_eq!(files, from_dir);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
