//! nftables interaction layer

use patronus_core::{
    types::{FirewallAction, FirewallRule, IpVersion, NatRule, NatType, PortSpec, Protocol},
    Error, Result,
};
use std::process::Command;

const TABLE_NAME: &str = "patronus";
const TABLE_FAMILY: &str = "inet";

/// Execute an nftables command
pub fn execute_nft_command(args: &[&str]) -> Result<String> {
    tracing::debug!("Executing nft command: {:?}", args);

    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| Error::Firewall(format!("Failed to execute nft command: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Firewall(format!("nft command failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Execute an nftables command from a script
pub fn execute_nft_script(script: &str) -> Result<String> {
    tracing::debug!("Executing nft script:\n{}", script);

    let output = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(script.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|e| Error::Firewall(format!("Failed to execute nft script: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Firewall(format!("nft script failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Table family/name every Patronus rule lives in.
pub const TABLE: &str = "inet patronus";

/// The base table: chains with their policies plus the rules every
/// ruleset starts with (loopback, established/related, invalid, ICMP).
/// Shared by [`initialize_table`] and the atomic full-ruleset render in
/// [`crate::applier`].
pub fn base_table_script() -> String {
    let t = TABLE;
    format!(
        r#"add table {t}
add chain {t} input {{ type filter hook input priority 0; policy drop; }}
add chain {t} output {{ type filter hook output priority 0; policy accept; }}
add chain {t} forward {{ type filter hook forward priority 0; policy drop; }}
add chain {t} prerouting {{ type nat hook prerouting priority -100; }}
add chain {t} postrouting {{ type nat hook postrouting priority 100; }}
add rule {t} input iifname "lo" accept
add rule {t} input ct state established,related accept
add rule {t} forward ct state established,related accept
add rule {t} input ct state invalid drop
add rule {t} forward ct state invalid drop
add rule {t} input ip protocol icmp accept
add rule {t} input ip6 nexthdr icmpv6 accept
"#
    )
}

/// Initialize the patronus nftables table and chains
pub fn initialize_table() -> Result<()> {
    execute_nft_script(&base_table_script())?;
    tracing::info!("Initialized nftables table: {}", TABLE_NAME);
    Ok(())
}

/// Flush the patronus table
pub fn flush_table() -> Result<()> {
    execute_nft_command(&["flush", "table", TABLE_FAMILY, TABLE_NAME])?;
    tracing::info!("Flushed nftables table: {}", TABLE_NAME);
    Ok(())
}

/// Delete the patronus table
pub fn delete_table() -> Result<()> {
    execute_nft_command(&["delete", "table", TABLE_FAMILY, TABLE_NAME])?;
    tracing::info!("Deleted nftables table: {}", TABLE_NAME);
    Ok(())
}

/// List all nftables rulesets
pub fn list_ruleset() -> Result<String> {
    execute_nft_command(&["list", "ruleset"])
}

/// List the patronus table
pub fn list_table() -> Result<String> {
    execute_nft_command(&["list", "table", TABLE_FAMILY, TABLE_NAME])
}

/// Validate a source/destination address specifier (`ip saddr`/`ip daddr`
/// operand) before it is spliced into an nftables script. This accepts a bare
/// IPv4/IPv6 address, a CIDR network, or the literal `any`/`all` -- nothing
/// else, and in particular no whitespace, `;`, `{`/`}`, or other characters
/// that would let a value break out of its single `ip saddr <value>` operand
/// position.
///
/// `execute_nft_script` feeds its whole argument to `nft -f -`, which parses
/// its own statement grammar directly (no shell involved) -- an unvalidated
/// `source`/`destination` string containing e.g. `0.0.0.0/0; add rule ...`
/// is therefore a real nftables ruleset-injection vector, not just a
/// cosmetic parsing concern (same bug class as the captive-portal
/// `mac_address` injection fixed in 37c832c).
fn is_valid_address_spec(s: &str) -> bool {
    if s.eq_ignore_ascii_case("any") || s.eq_ignore_ascii_case("all") {
        return true;
    }
    match s.split_once('/') {
        Some((addr, prefix)) => {
            addr.parse::<std::net::IpAddr>().is_ok()
                && prefix.len() <= 3
                && !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && prefix.parse::<u8>().is_ok()
        }
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

/// Validate an interface name before it is spliced into an nftables script
/// (`iifname "<value>"`/`oifname "<value>"`). Linux interface names are at
/// most `IFNAMSIZ - 1` (15) bytes and never contain a `"`, so anything
/// outside that is either not a real interface or an attempt to break out of
/// the quoted operand (same injection class as `is_valid_address_spec`).
pub fn is_valid_interface_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// What an alias name refers to while rendering (`$name` in a rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasKind {
    /// Addresses/networks/ranges: sets `alias_<name>_v4` + `alias_<name>_v6`.
    Host,
    /// Ports/port ranges: set `alias_<name>_ports`.
    Port,
}

/// Aliases known to the renderer (name -> kind). Empty = no aliases.
pub type AliasMap = std::collections::BTreeMap<String, AliasKind>;

/// nft set name of a host alias for one address family.
pub fn alias_set_name(alias: &str, family: IpVersion) -> String {
    match family {
        IpVersion::V4 => format!("alias_{alias}_v4"),
        IpVersion::V6 => format!("alias_{alias}_v6"),
    }
}

/// nft set name of a port alias.
pub fn alias_port_set_name(alias: &str) -> String {
    format!("alias_{alias}_ports")
}

/// Alias names: a letter, then letters/digits/underscore, at most 31
/// characters (they become nft set names, so nothing else may get in).
pub fn is_valid_alias_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 31
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One side (source or destination) of a rule.
enum AddrMatch {
    Any,
    Literal(String, IpVersion),
    Alias(String),
}

fn addr_family(s: &str) -> Option<IpVersion> {
    let a = s.split_once('/').map(|(a, _)| a).unwrap_or(s);
    match a.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(_) => Some(IpVersion::V4),
        std::net::IpAddr::V6(_) => Some(IpVersion::V6),
    }
}

fn parse_addr(
    field: &str,
    value: Option<&String>,
    aliases: &AliasMap,
    what: &str,
) -> Result<AddrMatch> {
    let Some(v) = value else {
        return Ok(AddrMatch::Any);
    };
    if let Some(name) = v.strip_prefix('$') {
        return match aliases.get(name) {
            Some(AliasKind::Host) => Ok(AddrMatch::Alias(name.to_string())),
            Some(AliasKind::Port) => Err(Error::Firewall(format!(
                "Invalid {field} for {what}: ${name} is a port alias, not a host alias"
            ))),
            None => Err(Error::Firewall(format!(
                "Invalid {field} for {what}: unknown alias ${name}"
            ))),
        };
    }
    if !is_valid_address_spec(v) {
        return Err(Error::Firewall(format!(
            "Invalid {field} address spec for {what}: {v:?}"
        )));
    }
    if v.eq_ignore_ascii_case("any") || v.eq_ignore_ascii_case("all") {
        return Ok(AddrMatch::Any);
    }
    let fam = addr_family(v).expect("validated address");
    Ok(AddrMatch::Literal(v.clone(), fam))
}

/// The address families a rule must be rendered for: one nft rule per
/// entry (`None` = family-agnostic). IPv6 literals are matched with
/// `ip6 saddr`, not `ip saddr` (which nft rejects / never matches).
fn families(
    matches: &[&AddrMatch],
    forced: Option<IpVersion>,
    what: &str,
) -> Result<Vec<Option<IpVersion>>> {
    let mut lit: Option<IpVersion> = None;
    let mut alias = false;
    for m in matches {
        match m {
            AddrMatch::Literal(_, f) => {
                if lit.is_some_and(|l| l != *f) {
                    return Err(Error::Firewall(format!(
                        "Invalid {what}: source and destination are different address families"
                    )));
                }
                lit = Some(*f);
            }
            AddrMatch::Alias(_) => alias = true,
            AddrMatch::Any => {}
        }
    }
    if let (Some(f), Some(l)) = (forced, lit) {
        if f != l {
            return Err(Error::Firewall(format!(
                "Invalid {what}: an {l} address in a rule restricted to {f}"
            )));
        }
    }
    Ok(match (forced.or(lit), alias) {
        (Some(f), _) => vec![Some(f)],
        (None, true) => vec![Some(IpVersion::V4), Some(IpVersion::V6)],
        (None, false) => vec![None],
    })
}

fn addr_expr(dir: &str, m: &AddrMatch, fam: Option<IpVersion>) -> Option<String> {
    let kw = match fam {
        Some(IpVersion::V6) => "ip6",
        _ => "ip",
    };
    match m {
        AddrMatch::Any => None,
        AddrMatch::Literal(v, _) => Some(format!("{kw} {dir} {v}")),
        AddrMatch::Alias(a) => Some(format!(
            "{kw} {dir} @{}",
            alias_set_name(a, fam.unwrap_or(IpVersion::V4))
        )),
    }
}

fn port_expr(p: &PortSpec, aliases: &AliasMap, what: &str) -> Result<String> {
    match p {
        PortSpec::Alias(name) => match aliases.get(name) {
            Some(AliasKind::Port) => Ok(format!("@{}", alias_port_set_name(name))),
            Some(AliasKind::Host) => Err(Error::Firewall(format!(
                "Invalid {what}: ${name} is a host alias, not a port alias"
            ))),
            None => Err(Error::Firewall(format!(
                "Invalid {what}: unknown port alias ${name}"
            ))),
        },
        PortSpec::Multiple(v) if v.is_empty() => {
            Err(Error::Firewall(format!("Invalid {what}: empty port list")))
        }
        PortSpec::Range(a, b) if a > b => Err(Error::Firewall(format!(
            "Invalid {what}: port range {a}-{b}"
        ))),
        other => Ok(other.to_string()),
    }
}

/// nft expression for the protocol and port matches.
///
/// These used to be emitted as separate words -- a bare `tcp` before the
/// address matches and a bare `dport N` after them -- which nft rejects
/// (`iifname "eth0" tcp ip saddr 10.0.0.0/8 dport 80` -> "syntax error,
/// unexpected ip"), so every rule with a protocol and a source/destination
/// failed to apply. A port match must be written `tcp dport N` and needs
/// tcp or udp; a protocol without ports is `meta l4proto <proto>`.
fn l4_match(
    protocol: Option<&Protocol>,
    sport: Option<&PortSpec>,
    dport: Option<&PortSpec>,
    fam: Option<IpVersion>,
    aliases: &AliasMap,
) -> Result<Vec<String>> {
    let proto = match protocol {
        Some(Protocol::Tcp) => Some("tcp"),
        Some(Protocol::Udp) => Some("udp"),
        Some(Protocol::Icmp) if fam == Some(IpVersion::V6) => Some("ipv6-icmp"),
        Some(Protocol::Icmp) => Some("icmp"),
        Some(Protocol::All) | None => None,
    };
    let mut out = Vec::new();
    if sport.is_some() || dport.is_some() {
        let p = match proto {
            Some(p @ ("tcp" | "udp")) => p,
            _ => {
                return Err(Error::Firewall(
                    "Invalid rule: a port match needs protocol tcp or udp".to_string(),
                ))
            }
        };
        if let Some(s) = sport {
            out.push(format!("{p} sport {}", port_expr(s, aliases, "rule")?));
        }
        if let Some(d) = dport {
            out.push(format!("{p} dport {}", port_expr(d, aliases, "rule")?));
        }
    } else if let Some(p) = proto {
        out.push(format!("meta l4proto {p}"));
    }
    Ok(out)
}

fn iface_expr(kw: &str, v: Option<&String>, what: &str) -> Result<Option<String>> {
    let Some(iface) = v else { return Ok(None) };
    if iface.eq_ignore_ascii_case("any") || iface.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    if !is_valid_interface_name(iface) {
        return Err(Error::Firewall(format!(
            "Invalid interface name {iface:?} ({what})"
        )));
    }
    Ok(Some(format!("{kw} \"{iface}\"")))
}

fn comment_expr(c: &Option<String>) -> Option<String> {
    c.as_ref().map(|c| {
        // nft comments are at most 128 bytes and must not break the quotes
        let clean: String = c
            .chars()
            .filter(|ch| *ch != '"' && *ch != '\\' && !ch.is_control())
            .collect();
        let mut end = clean.len().min(120);
        while !clean.is_char_boundary(end) {
            end -= 1;
        }
        format!("comment \"{}\"", &clean[..end])
    })
}

/// Render a filter rule into nft `add rule` lines (one per address family
/// it covers: an alias reference with no family restriction renders an
/// IPv4 and an IPv6 rule). Every operand is validated first, so nothing
/// unvalidated is spliced into the script (see `is_valid_address_spec`).
pub fn render_filter_rule(rule: &FirewallRule, aliases: &AliasMap) -> Result<Vec<String>> {
    if !rule.enabled {
        return Ok(Vec::new());
    }
    let what = "firewall rule";
    let iin = iface_expr(
        "iifname",
        rule.interface_in.as_ref(),
        "interface_in of firewall rule",
    )?;
    let iout = iface_expr(
        "oifname",
        rule.interface_out.as_ref(),
        "interface_out of firewall rule",
    )?;
    let src = parse_addr("source", rule.source.as_ref(), aliases, what)?;
    let dst = parse_addr("destination", rule.destination.as_ref(), aliases, what)?;
    let mut lines = Vec::new();
    for fam in families(&[&src, &dst], rule.ip_version, what)? {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(iin.clone());
        parts.extend(iout.clone());
        let s = addr_expr("saddr", &src, fam);
        let d = addr_expr("daddr", &dst, fam);
        if let (Some(f), None, None) = (fam, &s, &d) {
            parts.push(format!("meta nfproto {f}"));
        }
        parts.extend(s);
        parts.extend(d);
        parts.extend(l4_match(
            rule.protocol.as_ref(),
            rule.sport.as_ref(),
            rule.dport.as_ref(),
            fam,
            aliases,
        )?);
        if rule.log {
            let tag = match rule.id {
                Some(id) => format!("patronus[{id}] {}: ", rule.action),
                None => format!("patronus {}: ", rule.action),
            };
            parts.push(format!("log prefix \"{tag}\""));
        }
        parts.push(match (&rule.action, &rule.protocol) {
            (FirewallAction::Reject, Some(Protocol::Tcp)) => "reject with tcp reset".to_string(),
            (a, _) => a.to_string(),
        });
        parts.extend(comment_expr(&rule.comment));
        lines.push(format!(
            "add rule {} {} {} {}",
            TABLE_FAMILY,
            TABLE_NAME,
            rule.chain,
            parts.join(" ")
        ));
    }
    Ok(lines)
}

/// Convert a FirewallRule (without aliases) to nftables commands. Returns
/// an error instead of building a script from a `source`/`destination`/
/// `interface_in`/`interface_out` value that doesn't pass validation,
/// rather than silently splicing an unsafe value into the generated nft
/// script.
pub fn rule_to_nft_command(rule: &FirewallRule) -> Result<String> {
    Ok(render_filter_rule(rule, &AliasMap::new())?.join("\n"))
}

/// Add a firewall rule to nftables
pub fn add_rule(rule: &FirewallRule) -> Result<()> {
    let command = rule_to_nft_command(rule)?;
    if command.is_empty() {
        return Ok(()); // Rule is disabled
    }

    execute_nft_script(&command)?;
    tracing::info!("Added firewall rule: {}", rule.name);
    Ok(())
}

/// nft lines a NAT rule renders to, by chain.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NatLines {
    pub prerouting: Vec<String>,
    pub postrouting: Vec<String>,
    /// filter/forward accepts paired with a port forward
    pub forward: Vec<String>,
}

impl NatLines {
    pub fn is_empty(&self) -> bool {
        self.prerouting.is_empty() && self.postrouting.is_empty() && self.forward.is_empty()
    }
}

/// Extra inputs for rendering NAT reflection.
#[derive(Debug, Default, Clone)]
pub struct NatContext {
    /// Addresses configured on the port forward's inbound interface(s)
    /// (the "WAN address" LAN clients use).
    pub inbound_addresses: Vec<std::net::IpAddr>,
}

fn fam_of(a: &std::net::IpAddr) -> IpVersion {
    if a.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    }
}

fn nat_target(a: &std::net::IpAddr, port: Option<u16>) -> String {
    match (a, port) {
        (std::net::IpAddr::V4(v4), Some(p)) => format!("ip to {v4}:{p}"),
        (std::net::IpAddr::V4(v4), None) => format!("ip to {v4}"),
        (std::net::IpAddr::V6(v6), Some(p)) => format!("ip6 to [{v6}]:{p}"),
        (std::net::IpAddr::V6(v6), None) => format!("ip6 to {v6}"),
    }
}

/// Render a NAT rule (interfaces already resolved to device names).
pub fn render_nat_rule(rule: &NatRule, aliases: &AliasMap, ctx: &NatContext) -> Result<NatLines> {
    let mut out = NatLines::default();
    if !rule.enabled {
        return Ok(out);
    }
    let what = "NAT rule";
    let iin = iface_expr(
        "iifname",
        rule.interface_in.as_ref(),
        "interface_in of NAT rule",
    )?;
    let iout = iface_expr(
        "oifname",
        rule.interface_out.as_ref(),
        "interface_out of NAT rule",
    )?;
    let src = parse_addr("source", rule.source.as_ref(), aliases, what)?;
    let dst = parse_addr("destination", rule.destination.as_ref(), aliases, what)?;
    let comment = comment_expr(&rule.comment);
    let line = |chain: &str, parts: Vec<String>| {
        format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} {chain} {}",
            parts.join(" ")
        )
    };
    match &rule.nat_type {
        NatType::Masquerade | NatType::Snat { .. } => {
            let forced = match &rule.nat_type {
                NatType::Snat { to_address } => Some(fam_of(to_address)),
                _ => None,
            };
            for fam in families(&[&src, &dst], forced, what)? {
                let mut p: Vec<String> = Vec::new();
                p.extend(iout.clone());
                let (s, d) = (addr_expr("saddr", &src, fam), addr_expr("daddr", &dst, fam));
                if let (Some(f), None, None) = (fam, &s, &d) {
                    p.push(format!("meta nfproto {f}"));
                }
                p.extend(s);
                p.extend(d);
                p.extend(l4_match(
                    rule.protocol.as_ref(),
                    None,
                    rule.dport.as_ref(),
                    fam,
                    aliases,
                )?);
                p.push(match &rule.nat_type {
                    NatType::Snat { to_address } => {
                        format!("snat {}", nat_target(to_address, None))
                    }
                    _ => "masquerade".to_string(),
                });
                p.extend(comment.clone());
                out.postrouting.push(line("postrouting", p));
            }
        }
        NatType::Dnat {
            to_address,
            to_port,
        } => {
            let fam = fam_of(to_address);
            families(&[&src, &dst], Some(fam), what)?;
            if to_port.is_some() && !matches!(rule.dport, None | Some(PortSpec::Single(_))) {
                return Err(Error::Firewall(
                    "Invalid port forward: a target port needs a single external port (a range or \
                     list is forwarded to the same ports)"
                        .into(),
                ));
            }
            if to_port.is_some() && rule.dport.is_none() {
                return Err(Error::Firewall(
                    "Invalid port forward: a target port needs an external port".into(),
                ));
            }
            if rule.reflection && iin.is_none() {
                return Err(Error::Firewall(
                    "Invalid port forward: NAT reflection needs an inbound interface".into(),
                ));
            }
            let l4 = l4_match(
                rule.protocol.as_ref(),
                None,
                rule.dport.as_ref(),
                Some(fam),
                aliases,
            )?;
            let target = format!("dnat {}", nat_target(to_address, *to_port));
            let mut p: Vec<String> = Vec::new();
            p.extend(iin.clone());
            p.extend(addr_expr("saddr", &src, Some(fam)));
            p.extend(addr_expr("daddr", &dst, Some(fam)));
            p.extend(l4.clone());
            p.push(target.clone());
            p.extend(comment.clone());
            out.prerouting.push(line("prerouting", p));

            // Paired filter rule: let the forwarded traffic through (only
            // what this forward translated: `ct status dnat`).
            let kw = if fam == IpVersion::V6 { "ip6" } else { "ip" };
            let inner_port = match (to_port, &rule.dport) {
                (Some(p), _) => Some(PortSpec::Single(*p)),
                (None, d) => d.clone(),
            };
            let inner_l4 = l4_match(
                rule.protocol.as_ref(),
                None,
                inner_port.as_ref(),
                Some(fam),
                aliases,
            )?;
            let mut f: Vec<String> = Vec::new();
            if !rule.reflection {
                f.extend(iin.clone());
            }
            f.push("ct status dnat".into());
            f.extend(addr_expr("saddr", &src, Some(fam)));
            f.push(format!("{kw} daddr {to_address}"));
            f.extend(inner_l4.clone());
            f.push("accept".into());
            f.extend(comment.clone());
            out.forward.push(line("forward", f));

            if rule.reflection {
                let iface = iin.clone().expect("checked above");
                let neg = iface.replacen("iifname ", "iifname != ", 1);
                let addrs: Vec<String> = match &dst {
                    AddrMatch::Literal(v, _) => vec![v.clone()],
                    _ => ctx
                        .inbound_addresses
                        .iter()
                        .filter(|a| fam_of(a) == fam)
                        .map(|a| a.to_string())
                        .collect(),
                };
                if !addrs.is_empty() {
                    let mut r: Vec<String> = vec![neg.clone()];
                    r.push(format!("{kw} daddr {{ {} }}", addrs.join(", ")));
                    r.extend(l4.clone());
                    r.push(target);
                    r.extend(comment.clone());
                    out.prerouting.push(line("prerouting", r));
                    // replies must come back through the router: source NAT
                    // the hairpinned connection to the router's own address
                    let mut m: Vec<String> = vec![neg];
                    m.push("ct status dnat".into());
                    m.push(format!("{kw} daddr {to_address}"));
                    m.extend(inner_l4);
                    m.push("masquerade".into());
                    m.extend(comment.clone());
                    out.postrouting.push(line("postrouting", m));
                }
            }
        }
        NatType::OneToOne { external, internal } => {
            if fam_of(external) != fam_of(internal) {
                return Err(Error::Firewall(
                    "Invalid 1:1 NAT: external and internal addresses are different families"
                        .into(),
                ));
            }
            let kw = if fam_of(external) == IpVersion::V6 {
                "ip6"
            } else {
                "ip"
            };
            let mut p: Vec<String> = Vec::new();
            p.extend(iin.clone());
            p.push(format!("{kw} daddr {external}"));
            p.push(format!("dnat {}", nat_target(internal, None)));
            p.extend(comment.clone());
            out.prerouting.push(line("prerouting", p));
            let mut q: Vec<String> = Vec::new();
            q.extend(iout.clone());
            q.push(format!("{kw} saddr {internal}"));
            q.push(format!("snat {}", nat_target(external, None)));
            q.extend(comment.clone());
            out.postrouting.push(line("postrouting", q));
        }
    }
    Ok(out)
}

/// Convert a NAT rule (without aliases or reflection context) to nftables
/// commands. Returns an error instead of splicing an unvalidated
/// `source`/`destination`/interface value into the generated nft script
/// (see `is_valid_address_spec`/`is_valid_interface_name`).
pub fn nat_rule_to_nft_command(rule: &NatRule) -> Result<String> {
    let l = render_nat_rule(rule, &AliasMap::new(), &NatContext::default())?;
    Ok(l.prerouting
        .into_iter()
        .chain(l.postrouting)
        .chain(l.forward)
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Add a NAT rule to nftables
pub fn add_nat_rule(rule: &NatRule) -> Result<()> {
    let command = nat_rule_to_nft_command(rule)?;
    if command.is_empty() {
        return Ok(()); // Rule is disabled
    }

    execute_nft_script(&command)?;
    tracing::info!("Added NAT rule: {}", rule.name);
    Ok(())
}

/// Enable IP forwarding
pub fn enable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| Error::Firewall(format!("Failed to enable IPv4 forwarding: {}", e)))?;

    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .map_err(|e| Error::Firewall(format!("Failed to enable IPv6 forwarding: {}", e)))?;

    tracing::info!("Enabled IP forwarding");
    Ok(())
}

/// Disable IP forwarding
pub fn disable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "0")
        .map_err(|e| Error::Firewall(format!("Failed to disable IPv4 forwarding: {}", e)))?;

    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0")
        .map_err(|e| Error::Firewall(format!("Failed to disable IPv6 forwarding: {}", e)))?;

    tracing::info!("Disabled IP forwarding");
    Ok(())
}

#[cfg(test)]
mod qa_regression_tests {
    use super::*;
    use patronus_core::types::{ChainType, FirewallAction, NatRule, NatType};
    use std::net::IpAddr;

    fn base_rule() -> FirewallRule {
        let mut r = FirewallRule::new(
            "test-rule".to_string(),
            ChainType::Input,
            FirewallAction::Accept,
        );
        r.enabled = true;
        r
    }

    #[test]
    fn is_valid_address_spec_accepts_ip_cidr_and_any() {
        assert!(is_valid_address_spec("10.0.0.0/8"));
        assert!(is_valid_address_spec("192.168.1.1"));
        assert!(is_valid_address_spec("::1"));
        assert!(is_valid_address_spec("2001:db8::/32"));
        assert!(is_valid_address_spec("any"));
        assert!(is_valid_address_spec("ANY"));
        assert!(is_valid_address_spec("all"));
    }

    #[test]
    fn is_valid_address_spec_rejects_injection_payloads() {
        // A real payload that would otherwise be spliced straight into
        // `ip saddr <value>` inside a multi-statement nft script fed to
        // `nft -f -`, letting the caller inject an arbitrary extra rule.
        assert!(!is_valid_address_spec(
            "0.0.0.0/0; add rule inet patronus forward accept"
        ));
        assert!(!is_valid_address_spec(""));
        assert!(!is_valid_address_spec("not-an-address"));
        assert!(!is_valid_address_spec("10.0.0.0/999"));
        assert!(!is_valid_address_spec("10.0.0.0/"));
    }

    #[test]
    fn is_valid_interface_name_accepts_real_names_rejects_injection() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("wg0"));
        assert!(is_valid_interface_name("br-lan.100"));
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name(
            "eth0\" }; add rule inet patronus forward accept #"
        ));
        assert!(!is_valid_interface_name(
            "this-name-is-way-too-long-for-ifnamsiz"
        ));
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_source() {
        let mut rule = base_rule();
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        let result = rule_to_nft_command(&rule);
        assert!(
            result.is_err(),
            "a source value containing nft statement syntax must be rejected, not spliced into the script"
        );
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_destination() {
        let mut rule = base_rule();
        rule.destination = Some("10.0.0.1 }; flush ruleset #".to_string());
        assert!(rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn rule_to_nft_command_rejects_injection_in_interface_name() {
        let mut rule = base_rule();
        rule.interface_in = Some("eth0\" }; add rule inet patronus forward accept #".to_string());
        assert!(rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn rule_to_nft_command_omits_match_for_any_interface_instead_of_splicing_literal_any() {
        // Same bug class as the source/destination "any"/"all" fix above:
        // "any" is the UI's own default interface value, but it is not a
        // real interface name -- nft fails outright trying to apply
        // `iifname "any"`/`oifname "any"` ("Could not process rule: No
        // such file or directory"). A rule with the default "Any"
        // interface_in/interface_out must still produce a command nft can
        // actually run, by omitting the match entirely.
        let mut rule = base_rule();
        rule.interface_in = Some("any".to_string());
        rule.interface_out = Some("ALL".to_string());
        let command =
            rule_to_nft_command(&rule).expect("'any'/'all' interface must not be rejected");
        assert!(!command.contains("iifname \"any\""));
        assert!(!command.contains("oifname \"ALL\""));
    }

    /// Regression: protocol + address + port used to render as
    /// `tcp ip saddr X dport 80`, which nft rejects.
    #[test]
    fn protocol_and_ports_render_as_valid_nft_syntax() {
        let mut rule = base_rule();
        rule.interface_in = Some("eth0".to_string());
        rule.source = Some("10.0.0.0/8".to_string());
        rule.protocol = Some(Protocol::Tcp);
        rule.dport = Some(PortSpec::Single(80));
        let c = rule_to_nft_command(&rule).unwrap();
        assert!(
            c.contains("iifname \"eth0\" ip saddr 10.0.0.0/8 tcp dport 80"),
            "{c}"
        );

        rule.dport = Some(PortSpec::Range(8000, 8010));
        rule.protocol = Some(Protocol::Udp);
        assert!(rule_to_nft_command(&rule)
            .unwrap()
            .contains("udp dport 8000-8010"));

        rule.dport = None;
        assert!(rule_to_nft_command(&rule)
            .unwrap()
            .contains("meta l4proto udp"));

        rule.protocol = None;
        rule.dport = Some(PortSpec::Single(80));
        assert!(rule_to_nft_command(&rule).is_err(), "port without tcp/udp");
    }

    #[test]
    fn rule_to_nft_command_accepts_well_formed_rule() {
        let mut rule = base_rule();
        rule.source = Some("10.0.0.0/8".to_string());
        rule.destination = Some("any".to_string());
        rule.interface_in = Some("eth0".to_string());
        let command = rule_to_nft_command(&rule).expect("well-formed rule should be accepted");
        assert!(command.contains("ip saddr 10.0.0.0/8"));
        assert!(command.contains("iifname \"eth0\""));
    }

    #[test]
    fn rule_to_nft_command_omits_match_for_any_destination_instead_of_splicing_literal_any() {
        // "any" is a valid value from `is_valid_address_spec`'s point of
        // view, but it is not a real nftables address -- nft would try to
        // resolve it as a hostname and fail ("Could not resolve hostname:
        // any"). A rule with the UI's default "Any" destination/source must
        // still produce a command nft can actually run.
        let mut rule = base_rule();
        rule.destination = Some("any".to_string());
        rule.source = Some("ALL".to_string());
        let command = rule_to_nft_command(&rule).expect("'any'/'all' must not be rejected");
        assert!(!command.contains("ip daddr any"));
        assert!(!command.contains("ip saddr ALL"));
    }

    #[test]
    fn nat_rule_to_nft_command_rejects_injection_in_source() {
        let mut rule = NatRule::new(
            "test-nat".to_string(),
            NatType::Dnat {
                to_address: "192.168.1.100".parse::<IpAddr>().unwrap(),
                to_port: Some(8080),
            },
        );
        rule.enabled = true;
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        assert!(nat_rule_to_nft_command(&rule).is_err());
    }

    #[test]
    fn nat_rule_to_nft_command_accepts_well_formed_rule() {
        let mut rule = NatRule::new("test-nat".to_string(), NatType::Masquerade);
        rule.enabled = true;
        rule.source = Some("10.0.0.0/8".to_string());
        rule.interface_out = Some("eth0".to_string());
        let command =
            nat_rule_to_nft_command(&rule).expect("well-formed NAT rule should be accepted");
        assert!(command.contains("masquerade"));
        assert!(command.contains("ip saddr 10.0.0.0/8"));
    }

    #[test]
    fn disabled_rule_still_short_circuits_to_empty_command() {
        let mut rule = base_rule();
        rule.enabled = false;
        // Deliberately set an "invalid" value here too -- a disabled rule
        // must never even reach validation/the nft script, matching the
        // pre-existing early-return-on-disabled behavior.
        rule.source = Some("0.0.0.0/0; add rule inet patronus forward accept #".to_string());
        assert_eq!(rule_to_nft_command(&rule).unwrap(), "");
    }
}
