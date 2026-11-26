//! Route-based IPsec (lane F): the kernel side of a tunnel in `route` mode.
//!
//! strongSwan binds the child SA to an XFRM interface with `if_id_in` /
//! `if_id_out`; whatever the routing table (static routes, FRR/OSPF) sends
//! into that interface is encrypted, and what the SA decrypts comes back out
//! of it. This module creates, updates and removes those `xfrm<if_id>`
//! interfaces through `ip` (the [`Cmd`] seam), reads their state for the
//! status page, and parses the kernel's security policies (`ip xfrm policy`).

use crate::linkstate::{argv, Cmd};
use patronus_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// What one route-mode tunnel needs from the kernel.
#[derive(Debug, Clone, PartialEq)]
pub struct XfrmWant {
    pub name: String,
    pub if_id: u32,
    /// Device the interface is attached to.
    pub dev: String,
    /// This router's address on the tunnel (CIDR).
    pub addr: Option<String>,
    pub mtu: Option<u32>,
}

/// An XFRM interface as the kernel reports it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct XfrmIface {
    pub name: String,
    pub if_id: Option<u32>,
    pub up: bool,
    /// IFF_MULTICAST: an XFRM interface is created without it, and OSPF
    /// (hellos to 224.0.0.5) needs it.
    pub multicast: bool,
    pub mtu: Option<u32>,
    pub dev: Option<String>,
    pub addresses: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

fn num(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => match s.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16).ok(),
            None => s.parse().ok(),
        },
        _ => None,
    }
}

/// `ip -j -d -s link show type xfrm` (+ one `ip -j addr show dev X` each).
pub async fn list_interfaces(cmd: &dyn Cmd) -> Result<Vec<XfrmIface>> {
    let out = cmd
        .run(
            "ip",
            &argv(&["-j", "-d", "-s", "link", "show", "type", "xfrm"]),
        )
        .await?;
    let v: Value = serde_json::from_str(out.trim()).unwrap_or(Value::Null);
    let mut res = Vec::new();
    for l in v.as_array().into_iter().flatten() {
        let Some(name) = l["ifname"].as_str() else {
            continue;
        };
        let up = l["flags"]
            .as_array()
            .is_some_and(|f| f.iter().any(|x| x == "UP"));
        let mut i = XfrmIface {
            name: name.to_string(),
            if_id: num(&l["linkinfo"]["info_data"]["if_id"]).map(|v| v as u32),
            up,
            multicast: l["flags"]
                .as_array()
                .is_some_and(|f| f.iter().any(|x| x == "MULTICAST")),
            mtu: l["mtu"].as_u64().map(|v| v as u32),
            dev: l["link"].as_str().map(str::to_string),
            rx_bytes: l["stats64"]["rx"]["bytes"].as_u64().unwrap_or(0),
            tx_bytes: l["stats64"]["tx"]["bytes"].as_u64().unwrap_or(0),
            addresses: Vec::new(),
        };
        i.addresses = addresses(cmd, name).await?;
        res.push(i);
    }
    Ok(res)
}

/// The interface's global addresses as `addr/prefix` (link-local ones are the
/// kernel's, not configuration).
async fn addresses(cmd: &dyn Cmd, dev: &str) -> Result<Vec<String>> {
    let out = cmd
        .run("ip", &argv(&["-j", "addr", "show", "dev", dev]))
        .await?;
    let v: Value = serde_json::from_str(out.trim()).unwrap_or(Value::Null);
    let mut a = Vec::new();
    for e in v.as_array().into_iter().flatten() {
        for ai in e["addr_info"].as_array().into_iter().flatten() {
            if ai["scope"] == "link" {
                continue;
            }
            if let (Some(l), Some(p)) = (ai["local"].as_str(), ai["prefixlen"].as_u64()) {
                a.push(format!("{l}/{p}"));
            }
        }
    }
    Ok(a)
}

/// Make the kernel's `xfrm*` interfaces match `want`: create the missing
/// ones, fix address/MTU/state of existing ones, delete the ones nobody
/// owns any more. Returns a note per change.
pub async fn sync_interfaces(
    cmd: &dyn Cmd,
    prefix: &str,
    want: &[XfrmWant],
) -> Result<Vec<String>> {
    let have = list_interfaces(cmd).await?;
    let mut notes = Vec::new();
    let wanted: BTreeSet<&str> = want.iter().map(|w| w.name.as_str()).collect();
    for h in &have {
        if h.name.starts_with(prefix) && !wanted.contains(h.name.as_str()) {
            cmd.run("ip", &argv(&["link", "del", "dev", &h.name]))
                .await?;
            notes.push(format!("removed XFRM interface {}", h.name));
        }
    }
    for w in want {
        let mut cur = have.iter().find(|h| h.name == w.name).cloned();
        // a different if_id or underlay device cannot be edited in place
        if let Some(c) = &cur {
            if c.if_id != Some(w.if_id) || c.dev.as_deref().is_some_and(|d| d != w.dev) {
                cmd.run("ip", &argv(&["link", "del", "dev", &w.name]))
                    .await?;
                notes.push(format!("recreating XFRM interface {}", w.name));
                cur = None;
            }
        }
        if cur.is_none() {
            cmd.run(
                "ip",
                &argv(&[
                    "link",
                    "add",
                    &w.name,
                    "type",
                    "xfrm",
                    "dev",
                    &w.dev,
                    "if_id",
                    &w.if_id.to_string(),
                ]),
            )
            .await?;
            notes.push(format!(
                "created XFRM interface {} (if_id {})",
                w.name, w.if_id
            ));
        }
        let c = cur.unwrap_or_default();
        if let Some(m) = w.mtu {
            if c.mtu != Some(m) {
                cmd.run(
                    "ip",
                    &argv(&["link", "set", "dev", &w.name, "mtu", &m.to_string()]),
                )
                .await?;
            }
        }
        for a in &c.addresses {
            if Some(a) != w.addr.as_ref() {
                cmd.run("ip", &argv(&["addr", "del", a, "dev", &w.name]))
                    .await?;
            }
        }
        if let Some(a) = &w.addr {
            if !c.addresses.contains(a) {
                cmd.run("ip", &argv(&["addr", "replace", a, "dev", &w.name]))
                    .await?;
                notes.push(format!("{} has {a}", w.name));
            }
        }
        if !c.multicast {
            cmd.run(
                "ip",
                &argv(&["link", "set", "dev", &w.name, "multicast", "on"]),
            )
            .await?;
        }
        if !c.up {
            cmd.run("ip", &argv(&["link", "set", "dev", &w.name, "up"]))
                .await?;
        }
    }
    Ok(notes)
}

/// One kernel security policy (SP) that belongs to an IPsec SA.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct XfrmPolicy {
    pub src: String,
    pub dst: String,
    /// `in`, `out` or `fwd`.
    pub dir: String,
    pub if_id: Option<u32>,
    /// Tunnel endpoints of the policy's template.
    pub peer_src: String,
    pub peer_dst: String,
    pub proto: String,
    pub mode: String,
    pub reqid: Option<u32>,
}

/// Parse `ip xfrm policy`. Socket policies (`dir socket ...`) and the
/// kernel's own default blocks carry no template and are left out.
pub fn parse_policies(text: &str) -> Vec<XfrmPolicy> {
    let mut v: Vec<XfrmPolicy> = Vec::new();
    let mut cur: Option<XfrmPolicy> = None;
    let mut sock = false;
    let flush = |cur: &mut Option<XfrmPolicy>, sock: &mut bool, v: &mut Vec<XfrmPolicy>| {
        if let Some(p) = cur.take() {
            if !*sock && !p.peer_src.is_empty() {
                v.push(p);
            }
        }
        *sock = false;
    };
    for line in text.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        let get = |k: &str| {
            w.iter()
                .position(|x| *x == k)
                .and_then(|i| w.get(i + 1))
                .map(|s| s.to_string())
        };
        if w.first() == Some(&"src") && !line.starts_with(char::is_whitespace) {
            flush(&mut cur, &mut sock, &mut v);
            cur = Some(XfrmPolicy {
                src: get("src").unwrap_or_default(),
                dst: get("dst").unwrap_or_default(),
                ..Default::default()
            });
        } else if let Some(p) = cur.as_mut() {
            if w.first() == Some(&"dir") {
                let d = get("dir").unwrap_or_default();
                sock = d == "socket";
                p.dir = d;
                p.if_id = get("if_id")
                    .and_then(|s| num(&Value::String(s)))
                    .map(|v| v as u32);
            } else if w.first() == Some(&"tmpl") {
                p.peer_src = get("src").unwrap_or_default();
                p.peer_dst = get("dst").unwrap_or_default();
            } else if w.first() == Some(&"proto") {
                p.proto = get("proto").unwrap_or_default();
                p.mode = get("mode").unwrap_or_default();
                p.reqid = get("reqid").and_then(|s| s.parse().ok());
            }
        }
    }
    flush(&mut cur, &mut sock, &mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeCmd {
        links: String,
        addrs: String,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Cmd for FakeCmd {
        async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{prog} {}", args.join(" ")));
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            Ok(match a.as_slice() {
                ["-j", "-d", "-s", "link", "show", "type", "xfrm"] => self.links.clone(),
                ["-j", "addr", "show", "dev", _] => self.addrs.clone(),
                _ => String::new(),
            })
        }
    }

    fn want(id: u32) -> XfrmWant {
        XfrmWant {
            name: format!("xfrm{id}"),
            if_id: id,
            dev: "lo".into(),
            addr: Some("169.254.10.1/30".into()),
            mtu: Some(1400),
        }
    }

    fn changes(c: &FakeCmd) -> Vec<String> {
        c.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|l| !l.contains(" -j "))
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn a_missing_interface_is_created_with_its_if_id_address_and_mtu() {
        let c = FakeCmd {
            links: "[]".into(),
            ..Default::default()
        };
        let n = sync_interfaces(&c, "xfrm", &[want(7)]).await.unwrap();
        assert!(n.iter().any(|x| x.contains("created XFRM interface xfrm7")));
        let ch = changes(&c);
        assert_eq!(ch[0], "ip link add xfrm7 type xfrm dev lo if_id 7");
        assert!(
            ch.contains(&"ip link set dev xfrm7 mtu 1400".to_string()),
            "{ch:?}"
        );
        assert!(ch.contains(&"ip addr replace 169.254.10.1/30 dev xfrm7".to_string()));
        assert!(ch.contains(&"ip link set dev xfrm7 multicast on".to_string()));
        assert!(ch.contains(&"ip link set dev xfrm7 up".to_string()));
    }

    #[tokio::test]
    async fn an_interface_that_already_matches_is_left_alone_and_a_stray_one_goes() {
        let c = FakeCmd {
            links: r#"[
              {"ifname":"xfrm7","flags":["NOARP","UP","LOWER_UP","MULTICAST"],"mtu":1400,"link":"lo",
               "linkinfo":{"info_kind":"xfrm","info_data":{"if_id":7}},
               "stats64":{"rx":{"bytes":1200},"tx":{"bytes":3400}}},
              {"ifname":"xfrm9","flags":["UP"],"mtu":1500,"linkinfo":{"info_data":{"if_id":"0x9"}}}
            ]"#
            .into(),
            addrs: r#"[{"addr_info":[{"family":"inet","local":"169.254.10.1","prefixlen":30,"scope":"global"},
                {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]"#
                .into(),
            ..Default::default()
        };
        sync_interfaces(&c, "xfrm", &[want(7)]).await.unwrap();
        assert_eq!(changes(&c), vec!["ip link del dev xfrm9".to_string()]);
        let l = list_interfaces(&c).await.unwrap();
        assert_eq!(l[0].if_id, Some(7));
        assert_eq!((l[0].rx_bytes, l[0].tx_bytes), (1200, 3400));
        assert_eq!(l[0].addresses, vec!["169.254.10.1/30"]);
        assert_eq!(l[1].if_id, Some(9), "a hex string if_id is understood");
    }

    #[tokio::test]
    async fn a_changed_if_id_recreates_the_interface() {
        let c = FakeCmd {
            links: r#"[{"ifname":"xfrm7","flags":["UP"],"mtu":1400,"link":"lo",
                "linkinfo":{"info_data":{"if_id":99}}}]"#
                .into(),
            addrs: "[]".into(),
            ..Default::default()
        };
        sync_interfaces(&c, "xfrm", &[want(7)]).await.unwrap();
        let ch = changes(&c);
        assert_eq!(ch[0], "ip link del dev xfrm7");
        assert!(ch[1].starts_with("ip link add xfrm7 type xfrm"), "{ch:?}");
    }

    #[test]
    fn kernel_policies_are_parsed_and_socket_policies_skipped() {
        let t = "src 192.168.50.0/24 dst 10.2.0.0/16 \n\tdir out priority 375423 ptype main \n\ttmpl src 203.0.113.2 dst 198.51.100.2\n\t\tproto esp spi 0xc0 reqid 1 mode tunnel\nsrc 0.0.0.0/0 dst 0.0.0.0/0 \n\tdir out priority 400 ptype main if_id 0x7 \n\ttmpl src 203.0.113.2 dst 198.51.100.2\n\t\tproto esp reqid 2 mode tunnel\nsrc 0.0.0.0/0 dst 0.0.0.0/0 \n\tsocket in priority 0 ptype main \n";
        let p = parse_policies(t);
        assert_eq!(p.len(), 2, "{p:?}");
        assert_eq!(p[0].src, "192.168.50.0/24");
        assert_eq!((p[0].dir.as_str(), p[0].if_id), ("out", None));
        assert_eq!(p[0].peer_dst, "198.51.100.2");
        assert_eq!(
            (p[0].proto.as_str(), p[0].mode.as_str(), p[0].reqid),
            ("esp", "tunnel", Some(1))
        );
        assert_eq!(p[1].if_id, Some(7));
    }
}
