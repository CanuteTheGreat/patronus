use super::*;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

/// Answers `ip -j ...` reads from canned JSON and records every call.
#[derive(Default)]
struct FakeCmd {
    links: String,
    addrs: String,
    /// `ip -j -4|-6 route show default` (every protocol)
    defaults4: String,
    defaults6: String,
    /// our routes, by (family flag, proto)
    owned: BTreeMap<(String, String), String>,
    calls: Mutex<Vec<String>>,
    fail_on: Option<String>,
}

#[async_trait]
impl Cmd for FakeCmd {
    async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
        let line = format!("{prog} {}", args.join(" "));
        self.calls.lock().unwrap().push(line.clone());
        if let Some(f) = &self.fail_on {
            if line.contains(f.as_str()) {
                return Err(Error::Network(format!(
                    "`{line}` failed: Nexthop has invalid gateway"
                )));
            }
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(match a.as_slice() {
            ["-j", "-d", "-s", "link", "show"] => self.links.clone(),
            ["-j", "addr", "show"] => self.addrs.clone(),
            ["-j", "-4", "route", "show", "default"] => self.defaults4.clone(),
            ["-j", "-6", "route", "show", "default"] => self.defaults6.clone(),
            ["-j", fam, "route", "show", "table", t, "proto", p] => {
                match self.owned.get(&(fam.to_string(), p.to_string())) {
                    Some(o) => o.clone(),
                    // iproute2 6.x: listing a table nothing created yet fails
                    None if t.parse::<u32>().is_ok() => {
                        return Err(Error::Network(format!(
                            "`{line}` failed: Error: ipv4: FIB table does not exist."
                        )))
                    }
                    None => "[]".into(),
                }
            }
            _ => String::new(),
        })
    }
}

impl FakeCmd {
    fn writes(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.contains(" replace ") || c.contains(" del ") || c.contains(" rule add "))
            .cloned()
            .collect()
    }
}

const LINKS: &str = r#"[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback"},
 {"ifindex":2,"ifname":"wan1","flags":["UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:01"},
 {"ifindex":3,"ifname":"wan2","flags":["UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:02"},
 {"ifindex":4,"ifname":"lan0","flags":["UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:03"},
 {"ifindex":5,"ifname":"ppp0","flags":["UP","LOWER_UP"],"mtu":1492,"operstate":"UNKNOWN","link_type":"ppp"},
 {"ifindex":6,"ifname":"wan3","flags":["UP"],"mtu":1500,"operstate":"LOWERLAYERDOWN","link_type":"ether","address":"02:00:00:00:00:04"}
]"#;

/// wan1 got 198.51.100.1 by DHCP; wan2 has a static interface gateway
/// (proto 250); ppp0 is point to point; an old Patronus default (253)
/// must never be "learned".
const DEFAULTS4: &str = r#"[
 {"dst":"default","gateway":"198.51.100.1","dev":"wan1","protocol":"dhcp","metric":100,"flags":[]},
 {"dst":"default","gateway":"203.0.113.1","dev":"wan2","protocol":250,"metric":201,"flags":[]},
 {"dst":"default","dev":"ppp0","protocol":"boot","scope":"link","flags":[]},
 {"dst":"default","gateway":"192.0.2.99","dev":"wan2","protocol":253,"metric":1,"flags":[]}
]"#;

fn kernel() -> KernelState {
    let mut k = KernelState::parse(LINKS, "[]").unwrap();
    k.default_routes = crate::linkstate::parse_routes(DEFAULTS4, false).unwrap();
    k
}

fn gw(name: &str, iface: &str, addr: Option<&str>) -> Gateway {
    Gateway {
        name: name.into(),
        interface: iface.into(),
        family: Family::Inet,
        address: addr.map(|a| a.parse().unwrap()),
        monitor_ip: None,
        monitor_enabled: true,
        loss_threshold: 20,
        latency_threshold: 500,
        description: None,
    }
}

fn st(state: GwState) -> GwStatus {
    GwStatus {
        state,
        loss_pct: 0,
        rtt_ms: None,
        samples: 10,
        detail: None,
        since: 0,
    }
}

fn resolved_up(dev: &str, addr: &str) -> Resolved {
    Resolved {
        dev: Some(dev.into()),
        address: Some(addr.parse().unwrap()),
        ptp: false,
        link_up: true,
        problem: None,
    }
}

fn window(v: &[Option<f64>]) -> VecDeque<Option<f64>> {
    v.iter().copied().collect()
}

// ---------------------------------------------------------------------------
// monitor evaluation
// ---------------------------------------------------------------------------

#[test]
fn probe_windows_become_online_loss_latency_or_down() {
    let g = gw("A", "@wan", None);
    assert_eq!(evaluate(&window(&[]), &g).0, GwState::Pending);
    assert_eq!(
        evaluate(&window(&[Some(1.0), Some(1.0)]), &g).0,
        GwState::Pending
    );
    let (s, loss, rtt) = evaluate(&window(&[Some(1.0), Some(3.0), Some(2.0)]), &g);
    assert_eq!((s, loss, rtt), (GwState::Online, 0, Some(2.0)));
    // 2 of 10 lost = 20 % = the threshold
    let mut w = vec![Some(1.0); 8];
    w.insert(2, None);
    w.insert(5, None);
    assert_eq!(evaluate(&window(&w), &g).0, GwState::Loss);
    // 1 of 10 lost is below it
    let mut w = vec![Some(1.0); 9];
    w.insert(4, None);
    assert_eq!(evaluate(&window(&w), &g).0, GwState::Online);
    // slow but answering
    assert_eq!(
        evaluate(&window(&[Some(600.0), Some(700.0), Some(450.0)]), &g).0,
        GwState::Latency
    );
    // the last five lost = down, whatever came before
    let w = [
        Some(1.0),
        Some(1.0),
        Some(1.0),
        Some(1.0),
        Some(1.0),
        None,
        None,
        None,
        None,
        None,
    ];
    assert_eq!(evaluate(&window(&w), &g).0, GwState::Down);
    // only four lost in a row: still up (with loss)
    let w = [
        Some(1.0),
        Some(1.0),
        Some(1.0),
        Some(1.0),
        Some(1.0),
        Some(1.0),
        None,
        None,
        None,
        None,
    ];
    assert_eq!(evaluate(&window(&w), &g).0, GwState::Loss);
    // three samples, all lost: down already
    assert_eq!(evaluate(&window(&[None, None, None]), &g).0, GwState::Down);
    // back: a reply after the outage ends "down" at once (loss remains)
    let w = [None, None, None, None, None, Some(1.0)];
    assert_eq!(evaluate(&window(&w), &g).0, GwState::Loss);
}

#[test]
fn trigger_decides_which_states_drop_a_member() {
    use GwState::*;
    for s in [Pending, Online, Unmonitored] {
        for t in [
            Trigger::Down,
            Trigger::Loss,
            Trigger::Latency,
            Trigger::LossLatency,
        ] {
            assert!(usable(s, t), "{s:?} {t:?}");
        }
    }
    for t in [
        Trigger::Down,
        Trigger::Loss,
        Trigger::Latency,
        Trigger::LossLatency,
    ] {
        assert!(!usable(Down, t));
    }
    assert!(usable(Loss, Trigger::Down) && usable(Loss, Trigger::Latency));
    assert!(!usable(Loss, Trigger::Loss) && !usable(Loss, Trigger::LossLatency));
    assert!(usable(Latency, Trigger::Down) && usable(Latency, Trigger::Loss));
    assert!(!usable(Latency, Trigger::Latency) && !usable(Latency, Trigger::LossLatency));
}

#[test]
fn ping_output_round_trip_is_parsed() {
    let out = "PING 198.51.100.1 (198.51.100.1) from 198.51.100.2 wan1: 56(84) bytes of data.\n\
               64 bytes from 198.51.100.1: icmp_seq=1 ttl=64 time=0.043 ms\n";
    assert_eq!(parse_ping_rtt(out), Some(0.043));
    assert_eq!(
        parse_ping_rtt("64 bytes from x: seq=0 ttl=64 time=12 ms"),
        Some(12.0)
    );
    assert_eq!(parse_ping_rtt("1 packets transmitted, 0 received"), None);
}

// ---------------------------------------------------------------------------
// resolution
// ---------------------------------------------------------------------------

#[test]
fn dynamic_gateways_learn_the_interfaces_own_default_route() {
    let k = kernel();
    let r = resolve_one(&gw("A", "@wan", None), Some("wan1"), &k);
    assert_eq!(r.address, Some("198.51.100.1".parse().unwrap()));
    assert!(r.routable() && r.link_up);
    // the static interface gateway (proto 250) counts, our own 253 never
    let r = resolve_one(&gw("B", "@opt1", None), Some("wan2"), &k);
    assert_eq!(r.address, Some("203.0.113.1".parse().unwrap()));
    // PPPoE: routed by device
    let r = resolve_one(&gw("P", "ppp0", None), Some("ppp0"), &k);
    assert!(r.ptp && r.address.is_none() && r.routable());
    // configured address wins
    let r = resolve_one(&gw("S", "lan0", Some("10.0.0.254")), Some("lan0"), &k);
    assert_eq!(r.address, Some("10.0.0.254".parse().unwrap()));
    // nothing learned yet
    let r = resolve_one(&gw("N", "lan0", None), Some("lan0"), &k);
    assert!(!r.routable() && r.problem.unwrap().contains("no IPv4 default route on lan0"));
    // missing device / unassigned role / cable out
    assert!(resolve_one(&gw("X", "eth9", None), Some("eth9"), &k)
        .problem
        .unwrap()
        .contains("does not exist"));
    assert!(resolve_one(&gw("X", "@opt7", None), None, &k)
        .problem
        .unwrap()
        .contains("@opt7 is not assigned"));
    let r = resolve_one(&gw("D", "wan3", Some("192.0.2.1")), Some("wan3"), &k);
    assert!(r.routable() && !r.link_up);
}

// ---------------------------------------------------------------------------
// planning
// ---------------------------------------------------------------------------

fn two_wan_cfg() -> (RoutingConfig, BTreeMap<String, Resolved>) {
    let cfg = RoutingConfig {
        gateways: vec![
            gw("WAN1", "@wan", None),
            gw("WAN2", "@opt1", None),
            gw("WAN3", "@opt2", None),
        ],
        groups: vec![GatewayGroup {
            name: "FAILOVER".into(),
            trigger: Trigger::Down,
            members: vec![
                Member {
                    gateway: "WAN1".into(),
                    tier: 1,
                    weight: 1,
                },
                Member {
                    gateway: "WAN2".into(),
                    tier: 2,
                    weight: 1,
                },
                Member {
                    gateway: "WAN3".into(),
                    tier: 2,
                    weight: 3,
                },
            ],
            description: None,
        }],
        ..Default::default()
    };
    let resolved = BTreeMap::from([
        ("WAN1".to_string(), resolved_up("wan1", "198.51.100.1")),
        ("WAN2".to_string(), resolved_up("wan2", "203.0.113.1")),
        ("WAN3".to_string(), resolved_up("wan3", "192.0.2.1")),
    ]);
    (cfg, resolved)
}

#[test]
fn tiers_fail_over_and_a_tier_load_balances_by_weight() {
    let (cfg, res) = two_wan_cfg();
    let g = &cfg.groups[0];
    let names = |v: Vec<&Member>| v.iter().map(|m| m.gateway.clone()).collect::<Vec<_>>();
    // all up (or not probed yet): tier 1 only
    assert_eq!(names(select_members(g, &res, &BTreeMap::new())), ["WAN1"]);
    // tier 1 down: both tier-2 members
    let s = BTreeMap::from([("WAN1".to_string(), st(GwState::Down))]);
    assert_eq!(names(select_members(g, &res, &s)), ["WAN2", "WAN3"]);
    // packet loss does not count with trigger "down"
    let s = BTreeMap::from([("WAN1".to_string(), st(GwState::Loss))]);
    assert_eq!(names(select_members(g, &res, &s)), ["WAN1"]);
    let mut g2 = g.clone();
    g2.trigger = Trigger::Loss;
    assert_eq!(names(select_members(&g2, &res, &s)), ["WAN2", "WAN3"]);
    // a member whose link dropped is out even before the probes notice
    let mut r2 = res.clone();
    r2.get_mut("WAN1").unwrap().link_up = false;
    assert_eq!(
        names(select_members(g, &r2, &BTreeMap::new())),
        ["WAN2", "WAN3"]
    );
    // everything down
    let s = BTreeMap::from([
        ("WAN1".to_string(), st(GwState::Down)),
        ("WAN2".to_string(), st(GwState::Down)),
        ("WAN3".to_string(), st(GwState::Down)),
    ]);
    assert!(select_members(g, &res, &s).is_empty());
}

#[cfg(feature = "multiwan")]
#[test]
fn the_default_route_follows_the_group() {
    let (mut cfg, res) = two_wan_cfg();
    cfg.default4 = Some("FAILOVER".into());
    let d = desired(&cfg, &res, &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(d.routes.len(), 1);
    assert_eq!(
        d.routes[0].replace_args().join(" "),
        "-4 route replace default table 4250 metric 1 proto 253 via 198.51.100.1 dev wan1"
    );
    let s = BTreeMap::from([("WAN1".to_string(), st(GwState::Down))]);
    let d = desired(&cfg, &res, &s, &BTreeMap::new());
    assert_eq!(
        d.routes[0].replace_args().join(" "),
        "-4 route replace default table 4250 metric 1 proto 253 nexthop via 203.0.113.1 dev wan2 weight 1 \
         nexthop via 192.0.2.1 dev wan3 weight 3"
    );
    assert_eq!(d.default_hops["inet"], ["WAN2", "WAN3"]);
    // all down: no Patronus default; the interfaces' own defaults apply
    let s = BTreeMap::from([
        ("WAN1".to_string(), st(GwState::Down)),
        ("WAN2".to_string(), st(GwState::Down)),
        ("WAN3".to_string(), st(GwState::Down)),
    ]);
    let d = desired(&cfg, &res, &s, &BTreeMap::new());
    assert!(d.routes.is_empty());
    assert!(d.warnings[0].contains("every member of gateway group FAILOVER is down"));
}

#[cfg(not(feature = "multiwan"))]
#[test]
fn without_multiwan_a_group_is_never_used_as_default() {
    let (mut cfg, res) = two_wan_cfg();
    cfg.default4 = Some("FAILOVER".into());
    let d = desired(&cfg, &res, &BTreeMap::new(), &BTreeMap::new());
    assert!(d.routes.is_empty());
    assert!(d.warnings[0].contains("USE=multiwan"));
}

#[test]
fn a_single_default_gateway_and_static_routes_render_as_ip_commands() {
    let (mut cfg, mut res) = two_wan_cfg();
    cfg.groups.clear();
    cfg.default4 = Some("WAN2".into());
    cfg.gateways[0].monitor_ip = Some("9.9.9.9".parse().unwrap());
    cfg.routes = vec![
        StaticRoute {
            id: 1,
            destination: "10.20.0.0/16".parse().unwrap(),
            gateway: Some("192.168.1.2".into()),
            interface: None,
            metric: None,
            description: None,
            enabled: true,
        },
        StaticRoute {
            id: 2,
            destination: "172.16.0.0/12".parse().unwrap(),
            gateway: Some("WAN1".into()),
            interface: None,
            metric: Some(20),
            description: None,
            enabled: true,
        },
        StaticRoute {
            id: 3,
            destination: "10.30.0.0/24".parse().unwrap(),
            gateway: None,
            interface: Some("@opt5".into()),
            metric: None,
            description: None,
            enabled: true,
        },
        StaticRoute {
            id: 4,
            destination: "10.40.0.0/24".parse().unwrap(),
            gateway: None,
            interface: Some("@lan".into()),
            metric: None,
            description: None,
            enabled: true,
        },
        StaticRoute {
            id: 5,
            destination: "10.50.0.0/24".parse().unwrap(),
            gateway: Some("10.0.0.1".into()),
            interface: None,
            metric: None,
            description: None,
            enabled: false,
        },
    ];
    let devs = BTreeMap::from([
        ("@opt5".to_string(), None),
        ("@lan".to_string(), Some("lan0".to_string())),
    ]);
    let d = desired(&cfg, &res, &BTreeMap::new(), &devs);
    let lines: Vec<String> = d
        .routes
        .iter()
        .map(|r| r.replace_args().join(" "))
        .collect();
    assert_eq!(
        lines,
        [
            "-4 route replace default table 4250 metric 1 proto 253 via 203.0.113.1 dev wan2",
            "-4 route replace 9.9.9.9/32 metric 0 proto 252 via 198.51.100.1 dev wan1",
            "-4 route replace 10.20.0.0/16 metric 0 proto 251 via 192.168.1.2",
            "-4 route replace 172.16.0.0/12 metric 20 proto 251 via 198.51.100.1 dev wan1",
            "-4 route replace 10.40.0.0/24 metric 0 proto 251 dev lan0",
        ]
    );
    assert_eq!(d.warnings.len(), 1);
    assert!(d.warnings[0].contains("@opt5 is not assigned"));
    // a dynamic gateway that lost its lease: its routes wait, with a reason
    res.get_mut("WAN1").unwrap().problem = Some("no IPv4 default route on wan1 yet".into());
    let d = desired(&cfg, &res, &BTreeMap::new(), &devs);
    assert!(d
        .warnings
        .iter()
        .any(|w| w.contains("172.16.0.0/12: gateway WAN1 cannot be used now")));
    assert!(!d
        .routes
        .iter()
        .any(|r| r.dst == "172.16.0.0/12" || r.dst == "9.9.9.9/32"));
}

// ---------------------------------------------------------------------------
// kernel diff
// ---------------------------------------------------------------------------

fn kr(dst: &str, metric: u32, proto: &str, hops: &[(&str, Option<&str>, u32)]) -> KRoute {
    KRoute {
        v6: false,
        dst: dst.into(),
        metric,
        proto: proto.into(),
        table: if dst == "default" { DEFAULT_TABLE } else { 254 },
        hops: hops
            .iter()
            .map(|(v, d, w)| Hop {
                via: (!v.is_empty()).then(|| v.to_string()),
                dev: d.map(str::to_string),
                weight: *w,
            })
            .collect(),
    }
}

#[test]
fn the_diff_is_empty_when_the_kernel_already_matches() {
    let want = vec![
        kr("default", 1, "253", &[("198.51.100.1", Some("wan1"), 1)]),
        kr("10.20.0.0/16", 0, "251", &[("192.168.1.2", None, 1)]),
    ];
    // the kernel filled in the device of the second route by itself
    let have = vec![
        kr("default", 1, "253", &[("198.51.100.1", Some("wan1"), 1)]),
        kr(
            "10.20.0.0/16",
            0,
            "251",
            &[("192.168.1.2", Some("lan0"), 1)],
        ),
    ];
    assert!(diff(&want, &have).is_empty());
}

#[test]
fn moved_routes_are_replaced_before_stale_ones_are_deleted() {
    let want = vec![kr(
        "default",
        1,
        "253",
        &[
            ("203.0.113.1", Some("wan2"), 1),
            ("192.0.2.1", Some("wan3"), 3),
        ],
    )];
    let have = vec![
        kr("default", 1, "253", &[("198.51.100.1", Some("wan1"), 1)]),
        kr("10.9.0.0/16", 0, "251", &[("192.168.1.2", Some("lan0"), 1)]),
    ];
    let ops: Vec<String> = diff(&want, &have).iter().map(|o| o.join(" ")).collect();
    assert_eq!(
        ops,
        [
            "-4 route replace default table 4250 metric 1 proto 253 nexthop via 203.0.113.1 dev wan2 weight 1 nexthop via 192.0.2.1 dev wan3 weight 3",
            "-4 route del 10.9.0.0/16 metric 0 proto 251",
        ]
    );
    // weights matter for multipath, order does not
    let have = vec![kr(
        "default",
        1,
        "253",
        &[
            ("192.0.2.1", Some("wan3"), 3),
            ("203.0.113.1", Some("wan2"), 1),
        ],
    )];
    assert!(diff(&want, &have).is_empty());
    let have = vec![kr(
        "default",
        1,
        "253",
        &[
            ("192.0.2.1", Some("wan3"), 1),
            ("203.0.113.1", Some("wan2"), 1),
        ],
    )];
    assert_eq!(diff(&want, &have).len(), 1);
}

#[test]
fn kernel_route_listings_parse_including_split_ipv6_multipath() {
    let v4 = r#"[{"dst":"default","protocol":"253","metric":1,"flags":[],"nexthops":[
        {"gateway":"203.0.113.1","dev":"wan2","weight":1,"flags":[]},
        {"gateway":"192.0.2.1","dev":"wan3","weight":3,"flags":[]}]},
        {"dst":"9.9.9.9","gateway":"198.51.100.1","dev":"wan1","protocol":"252","flags":[]}]"#;
    let r = parse_owned(v4, false, "253", DEFAULT_TABLE).unwrap();
    assert_eq!(r[0].hops.len(), 2);
    assert_eq!(r[0].hops[1].weight, 3);
    assert_eq!(r[1].dst, "9.9.9.9/32");
    assert_eq!(r[1].metric, 0);
    let v6 = r#"[{"dst":"default","gateway":"fe80::1","dev":"wan1","metric":1,"flags":[]},
                 {"dst":"default","gateway":"fe80::2","dev":"wan2","metric":1,"flags":[]},
                 {"dst":"2001:db8::1","gateway":"fe80::1","dev":"wan1","metric":0,"flags":[]}]"#;
    let r = parse_owned(v6, true, "253", DEFAULT_TABLE).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].hops.len(), 2);
    assert_eq!(r[1].dst, "2001:db8::1/128");
    assert!(parse_owned("", false, "251", 254).unwrap().is_empty());
    assert!(parse_owned("nonsense", false, "251", 254).is_err());
}

#[test]
fn policy_rules_follow_the_tables_in_use() {
    let route = |table: u32, v6: bool| KRoute {
        v6,
        dst: "default".into(),
        metric: 1,
        proto: "253".into(),
        table,
        hops: vec![],
    };
    let d = Desired {
        routes: vec![
            route(DEFAULT_TABLE, false),
            route(0x2_0001, false),
            route(0x1_0002, false),
            route(0x1_0003, true),
            kr("10.0.0.0/8", 0, "251", &[("192.0.2.1", None, 1)]),
        ],
        ..Default::default()
    };
    let want = wanted_rules(&d);
    let lines: Vec<String> = rule_ops(&want, &[]).iter().map(|o| o.join(" ")).collect();
    assert_eq!(
        lines,
        [
            "-4 rule add pref 31000 lookup main suppress_prefixlength 0",
            "-4 rule add pref 31100 fwmark 0x10002 lookup 65538",
            "-4 rule add pref 31101 fwmark 0x20001 lookup 131073",
            "-4 rule add pref 31900 lookup 4250",
            "-6 rule add pref 31000 lookup main suppress_prefixlength 0",
            "-6 rule add pref 31100 fwmark 0x10003 lookup 65539",
        ]
    );
    // the kernel's listing of exactly those: nothing to do
    let listing = r#"[{"priority":0,"src":"all","table":"local"},
        {"priority":31000,"src":"all","table":"main","suppress_prefixlen":0},
        {"priority":31100,"src":"all","fwmark":"0x10002","table":"65538"},
        {"priority":31101,"src":"all","fwmark":"0x20001","table":"131073"},
        {"priority":31900,"src":"all","table":"4250"},
        {"priority":32766,"src":"all","table":"main"}]"#;
    let have4 = parse_rules(listing, false).unwrap();
    assert_eq!(have4.len(), 4, "only Patronus' priorities");
    let want4: Vec<KRule> = want.iter().filter(|r| !r.v6).cloned().collect();
    assert!(rule_ops(&want4, &have4).is_empty(), "already right");
    // no default gateway, no gateways: every rule of ours goes, others stay
    let ops: Vec<String> = rule_ops(&[], &have4).iter().map(|o| o.join(" ")).collect();
    assert_eq!(
        ops,
        [
            "-4 rule del pref 31000",
            "-4 rule del pref 31100",
            "-4 rule del pref 31101",
            "-4 rule del pref 31900",
        ]
    );
    // something else squatting on one of our priorities is replaced
    let odd = parse_rules(r#"[{"priority":31900,"src":"all","table":"main"}]"#, false).unwrap();
    let ops: Vec<String> = rule_ops(&want4, &odd).iter().map(|o| o.join(" ")).collect();
    assert_eq!(ops.len(), 5);
    assert_eq!(ops[3], "-4 rule del pref 31900");
    assert_eq!(ops[4], "-4 rule add pref 31900 lookup 4250");
    assert!(parse_rules("", true).unwrap().is_empty());
    assert!(wanted_rules(&Desired::default()).is_empty());
}

#[test]
fn every_gateway_and_group_gets_a_policy_table() {
    let (mut cfg, res) = two_wan_cfg();
    cfg.marks = BTreeMap::from([
        ("WAN1".to_string(), 0x1_0001),
        ("WAN2".to_string(), 0x1_0002),
        ("FAILOVER".to_string(), 0x2_0001),
    ]);
    let s = BTreeMap::from([("WAN1".to_string(), st(GwState::Down))]);
    let d = desired(&cfg, &res, &s, &BTreeMap::new());
    let lines: Vec<String> = d
        .routes
        .iter()
        .map(|r| r.replace_args().join(" "))
        .collect();
    // a single gateway's table keeps it even while it is down (like the
    // default gateway: there is nothing else to send that traffic to)
    assert!(
        lines.contains(
            &"-4 route replace default table 65537 metric 1 proto 253 via 198.51.100.1 dev wan1"
                .to_string()
        ),
        "{lines:?}"
    );
    assert!(
        lines.contains(
            &"-4 route replace default table 65538 metric 1 proto 253 via 203.0.113.1 dev wan2"
                .to_string()
        ),
        "{lines:?}"
    );
    if MULTIWAN {
        // the group's table follows its failover
        assert!(lines.contains(&"-4 route replace default table 131073 metric 1 proto 253 nexthop via 203.0.113.1 dev wan2 weight 1 nexthop via 192.0.2.1 dev wan3 weight 3".to_string()), "{lines:?}");
    }
    // WAN3 has no mark (not stored yet): no table
    assert!(!lines.iter().any(|l| l.contains("table 65539")));
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

async fn store() -> ConfigStore {
    let s = ConfigStore::open_in_memory().await.unwrap();
    s.set_interface_role("wan1", Some("wan")).await.unwrap();
    s.set_interface_role("wan2", Some("opt1")).await.unwrap();
    s.set_interface_role("lan0", Some("lan")).await.unwrap();
    s
}

fn gi(name: &str, iface: &str) -> GatewayInput {
    GatewayInput {
        name: name.into(),
        interface: iface.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn gateways_routes_and_defaults_round_trip_through_the_store() {
    let s = store().await;
    save_gateway(&s, None, &gi("WAN1", "@wan").validated().unwrap())
        .await
        .unwrap();
    let mut g2 = gi("WAN2", "@opt1");
    g2.address = Some("203.0.113.1".into());
    g2.monitor_ip = Some("9.9.9.9".into());
    g2.loss_threshold = Some(40);
    save_gateway(&s, None, &g2.validated().unwrap())
        .await
        .unwrap();
    let cfg = load(&s).await.unwrap();
    let r = RouteInput {
        destination: "10.20.3.4/16".into(),
        gateway: Some("WAN2".into()),
        ..Default::default()
    }
    .validated(&cfg, 0)
    .unwrap();
    assert_eq!(
        r.destination.to_string(),
        "10.20.0.0/16",
        "stored as the network"
    );
    let id = save_route(&s, None, &r).await.unwrap();
    set_default(&s, Family::Inet, Some("WAN1")).await.unwrap();
    let cfg = load(&s).await.unwrap();
    assert_eq!(cfg.gateways.len(), 2);
    let w2 = cfg.gateway("WAN2").unwrap();
    assert_eq!(w2.address, Some("203.0.113.1".parse().unwrap()));
    assert_eq!((w2.loss_threshold, w2.latency_threshold), (40, 500));
    assert_eq!(cfg.routes[0].id, id);
    assert_eq!(cfg.routes[0].gateway.as_deref(), Some("WAN2"));
    assert_eq!(cfg.default4.as_deref(), Some("WAN1"));
    assert_eq!(cfg.default6, None);

    // in use: refused, with what uses it
    let e = delete_gateway(&s, "WAN1").await.unwrap_err().to_string();
    assert!(
        e.contains("Invalid") && e.contains("default IPv4 gateway"),
        "{e}"
    );
    let e = delete_gateway(&s, "WAN2").await.unwrap_err().to_string();
    assert!(e.contains("static route 10.20.0.0/16"), "{e}");
    // names are fixed; families must match the slot
    let e = save_gateway(&s, Some("WAN1"), &gi("WAN9", "@wan").validated().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("cannot be renamed"), "{e}");
    let mut v6 = gi("WAN1", "@wan");
    v6.family = Some("inet6".into());
    let e = save_gateway(&s, Some("WAN1"), &v6.validated().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("family cannot change"), "{e}");
    let e = set_default(&s, Family::Inet6, Some("WAN2"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not an IPv6 gateway"), "{e}");
    let e = set_default(&s, Family::Inet, Some("NOPE"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("no gateway or group NOPE"), "{e}");
    let e = save_gateway(&s, None, &gi("WAN1", "@wan").validated().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("already exists"), "{e}");

    // snapshot -> change -> restore
    let snap = snapshot_tables(&s).await.unwrap();
    set_default(&s, Family::Inet, None).await.unwrap();
    delete_route(&s, id).await.unwrap();
    delete_gateway(&s, "WAN2").await.unwrap();
    assert!(load(&s).await.unwrap().default4.is_none());
    restore_tables(&s, &snap).await.unwrap();
    let back = load(&s).await.unwrap();
    assert_eq!(back, cfg);
    // a store export/import keeps lane E too
    let doc = s.export_json().await.unwrap();
    let s2 = ConfigStore::open_in_memory().await.unwrap();
    s2.import_json(&doc).await.unwrap();
    assert_eq!(load(&s2).await.unwrap(), cfg);
    delete_route(&s, id).await.unwrap();
    assert!(delete_route(&s, id)
        .await
        .unwrap_err()
        .to_string()
        .contains("not found"));
}

#[test]
fn bad_input_is_refused_before_it_reaches_the_store() {
    let cfg = RoutingConfig {
        gateways: vec![gw("WAN1", "@wan", None)],
        ..Default::default()
    };
    let bad = |i: GatewayInput| i.validated().unwrap_err().to_string();
    assert!(bad(gi("1abc", "@wan")).contains("name"));
    assert!(bad(gi("a b", "@wan")).contains("name"));
    assert!(bad(gi("OK", "eth0; rm -rf /")).contains("interface"));
    let mut i = gi("OK", "@wan");
    i.address = Some("2001:db8::1".into());
    i.family = Some("inet".into());
    assert!(bad(i).contains("not an IPv4 address"));
    let mut i = gi("OK", "@wan");
    i.address = Some("2001:db8::1".into());
    assert_eq!(
        i.validated().unwrap().family,
        Family::Inet6,
        "family follows the address"
    );
    let mut i = gi("OK", "@wan");
    i.monitor_ip = Some("127.0.0.1".into());
    assert!(bad(i).contains("monitor IP"));
    let mut i = gi("OK", "@wan");
    i.loss_threshold = Some(0);
    assert!(bad(i).contains("loss threshold"));

    let r = |d: &str, g: Option<&str>, i: Option<&str>| {
        RouteInput {
            destination: d.into(),
            gateway: g.map(str::to_string),
            interface: i.map(str::to_string),
            ..Default::default()
        }
        .validated(&cfg, 0)
    };
    assert!(r("0.0.0.0/0", Some("1.2.3.4"), None)
        .unwrap_err()
        .to_string()
        .contains("Default gateway"));
    assert!(r("10.0.0.0/8", None, None)
        .unwrap_err()
        .to_string()
        .contains("gateway, an interface"));
    assert!(r("10.0.0.0/8", Some("NOPE"), None)
        .unwrap_err()
        .to_string()
        .contains("gateway name"));
    assert!(r("10.0.0.0/8", Some("2001:db8::1"), None)
        .unwrap_err()
        .to_string()
        .contains("IPv4"));
    assert!(r("2001:db8::/32", Some("WAN1"), None)
        .unwrap_err()
        .to_string()
        .contains("IPv4 gateway"));
    assert!(r("not-a-net", Some("1.2.3.4"), None).is_err());
    assert!(r("10.0.0.0/8", None, Some("@lan")).is_ok());

    let g = |m: MembersInput| {
        GroupInput {
            name: "G".into(),
            trigger: None,
            members: m,
            description: None,
        }
        .validated()
    };
    let ok = g(MembersInput::Spec("WAN1:1, WAN2:2:5".into())).unwrap();
    assert_eq!(
        ok.members,
        vec![
            Member {
                gateway: "WAN1".into(),
                tier: 1,
                weight: 1
            },
            Member {
                gateway: "WAN2".into(),
                tier: 2,
                weight: 5
            }
        ]
    );
    assert_eq!(ok.trigger, Trigger::Down);
    assert!(g(MembersInput::Spec("".into())).is_err());
    assert!(g(MembersInput::Spec("WAN1:1, WAN1:2".into()))
        .unwrap_err()
        .to_string()
        .contains("twice"));
    assert!(g(MembersInput::Spec("WAN1:9".into()))
        .unwrap_err()
        .to_string()
        .contains("tier"));
    assert!(g(MembersInput::Spec("WAN1:x".into())).is_err());
    assert!(g(MembersInput::Spec("WAN1:1:1:1".into())).is_err());
}

#[cfg(feature = "multiwan")]
#[tokio::test]
async fn groups_need_existing_gateways_of_one_family() {
    let s = store().await;
    save_gateway(&s, None, &gi("WAN1", "@wan").validated().unwrap())
        .await
        .unwrap();
    let mut v6 = gi("WAN6", "@opt1");
    v6.family = Some("inet6".into());
    save_gateway(&s, None, &v6.validated().unwrap())
        .await
        .unwrap();
    let grp = |spec: &str| {
        GroupInput {
            name: "G".into(),
            trigger: Some("loss".into()),
            members: MembersInput::Spec(spec.into()),
            description: None,
        }
        .validated()
        .unwrap()
    };
    let e = save_group(&s, None, &grp("WAN1:1, NOPE:2"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("Invalid") && e.contains("NOPE"), "{e}");
    let e = save_group(&s, None, &grp("WAN1:1, WAN6:2"))
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("mix IPv4 and IPv6"), "{e}");
    // refused saves leave nothing behind
    assert!(load(&s).await.unwrap().groups.is_empty());
    save_group(&s, None, &grp("WAN1:1")).await.unwrap();
    set_default(&s, Family::Inet, Some("G")).await.unwrap();
    let e = delete_group(&s, "G").await.unwrap_err().to_string();
    assert!(e.contains("default IPv4 gateway"), "{e}");
    let e = delete_gateway(&s, "WAN1").await.unwrap_err().to_string();
    assert!(e.contains("gateway group G"), "{e}");
    let e = save_gateway(&s, None, &gi("G", "@wan").validated().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("already exists"), "{e}");
    set_default(&s, Family::Inet, None).await.unwrap();
    delete_group(&s, "G").await.unwrap();
    delete_gateway(&s, "WAN1").await.unwrap();
}

// ---------------------------------------------------------------------------
// applier + monitor against a fake `ip`
// ---------------------------------------------------------------------------

fn fake() -> FakeCmd {
    FakeCmd {
        links: LINKS.into(),
        addrs: "[]".into(),
        defaults4: DEFAULTS4.into(),
        defaults6: "[]".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn apply_installs_the_routes_and_removes_only_its_own_stale_ones() {
    let s = store().await;
    save_gateway(&s, None, &gi("WAN1", "@wan").validated().unwrap())
        .await
        .unwrap();
    set_default(&s, Family::Inet, Some("WAN1")).await.unwrap();
    let cfg = load(&s).await.unwrap();
    let r = RouteInput {
        destination: "10.20.0.0/16".into(),
        gateway: Some("192.168.1.2".into()),
        interface: Some("@lan".into()),
        ..Default::default()
    }
    .validated(&cfg, 0)
    .unwrap();
    save_route(&s, None, &r).await.unwrap();
    let mut f = fake();
    // a stale static route from an earlier config, plus our current default
    f.owned.insert(
        ("-4".into(), "251".into()),
        r#"[{"dst":"10.99.0.0/16","gateway":"192.168.1.9","dev":"lan0","flags":[]}]"#.into(),
    );
    f.owned.insert(
        ("-4".into(), "253".into()),
        r#"[{"dst":"default","table":"4250","gateway":"198.51.100.1","dev":"wan1","metric":1,"flags":[]}]"#.into(),
    );
    let f = Arc::new(f);
    let a =
        RoutesApplier::new(f.clone(), PathBuf::from("/nonexistent")).with_status(BTreeMap::new());
    let rep = a.apply(&s).await.unwrap();
    assert_eq!(
        f.writes(),
        [
            "ip -4 route replace default table 65537 metric 1 proto 253 via 198.51.100.1 dev wan1",
            "ip -4 route replace 10.20.0.0/16 metric 0 proto 251 via 192.168.1.2 dev lan0",
            "ip -4 route del 10.99.0.0/16 metric 0 proto 251",
            "ip -4 rule add pref 31000 lookup main suppress_prefixlength 0",
            "ip -4 rule add pref 31100 fwmark 0x10001 lookup 65537",
            "ip -4 rule add pref 31900 lookup 4250",
        ],
        "the default route was already right; nothing else is touched"
    );
    assert_eq!(rep.applied.len(), 6);
    // the dry run shows the same plan without running anything
    let out = a.render(&s).await.unwrap();
    assert!(out.contains(
        "ip -4 route replace default table 4250 metric 1 proto 253 via 198.51.100.1 dev wan1"
    ));
    assert!(
        out.contains("ip -4 rule add pref 31000 lookup main suppress_prefixlength 0"),
        "{out}"
    );
    // status for the UI
    let st = a.status(&s).await.unwrap();
    assert_eq!(st["gateways"][0]["resolved_address"], "198.51.100.1");
    assert_eq!(st["gateways"][0]["dev"], "wan1");
    assert_eq!(st["default_via"]["inet"][0], "WAN1");
}

#[tokio::test]
async fn a_failing_route_is_reported_and_the_others_still_apply() {
    let s = store().await;
    let cfg = load(&s).await.unwrap();
    for (d, g) in [
        ("10.1.0.0/16", "10.99.99.99"),
        ("10.2.0.0/16", "192.168.1.2"),
    ] {
        let r = RouteInput {
            destination: d.into(),
            gateway: Some(g.into()),
            ..Default::default()
        }
        .validated(&cfg, 0)
        .unwrap();
        save_route(&s, None, &r).await.unwrap();
    }
    let mut f = fake();
    f.fail_on = Some("via 10.99.99.99".into());
    let f = Arc::new(f);
    let a =
        RoutesApplier::new(f.clone(), PathBuf::from("/nonexistent")).with_status(BTreeMap::new());
    let e = a.apply(&s).await.unwrap_err().to_string();
    assert!(e.contains("Nexthop has invalid gateway"), "{e}");
    assert!(f.writes().iter().any(|w| w.contains("10.2.0.0/16")));
}

#[tokio::test]
async fn load_balancing_turns_on_port_hashing() {
    let s = store().await;
    let dir = std::env::temp_dir().join(format!("patronus-routes-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("net/ipv4")).unwrap();
    std::fs::write(dir.join("net/ipv4/fib_multipath_hash_policy"), "0\n").unwrap();
    std::fs::create_dir_all(dir.join("net/ipv4/conf/wan1")).unwrap();
    std::fs::create_dir_all(dir.join("net/ipv4/conf/wan2")).unwrap();
    std::fs::write(dir.join("net/ipv4/conf/wan1/rp_filter"), "1\n").unwrap();
    std::fs::write(dir.join("net/ipv4/conf/wan2/rp_filter"), "0\n").unwrap();
    let a = RoutesApplier::new(Arc::new(fake()), dir.clone());
    let mut rep = ApplyReport::default();
    let one = Desired {
        routes: vec![kr(
            "default",
            1,
            "253",
            &[("198.51.100.1", Some("wan1"), 1)],
        )],
        ..Default::default()
    };
    a.multipath_hashing(&one, &mut rep);
    assert_eq!(
        std::fs::read_to_string(dir.join("net/ipv4/fib_multipath_hash_policy")).unwrap(),
        "0\n"
    );
    let two = Desired {
        routes: vec![kr(
            "default",
            1,
            "253",
            &[
                ("198.51.100.1", Some("wan1"), 1),
                ("203.0.113.1", Some("wan2"), 1),
            ],
        )],
        ..Default::default()
    };
    a.multipath_hashing(&two, &mut rep);
    assert_eq!(
        std::fs::read_to_string(dir.join("net/ipv4/fib_multipath_hash_policy")).unwrap(),
        "1"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("net/ipv4/conf/wan1/rp_filter")).unwrap(),
        "2",
        "strict -> loose"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("net/ipv4/conf/wan2/rp_filter")).unwrap(),
        "0\n",
        "off stays off"
    );
    assert_eq!(rep.applied.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = s;
}

/// Replies per target; a target missing from the map never answers.
struct FakeProber(Mutex<BTreeMap<IpAddr, f64>>);

#[async_trait]
impl Prober for FakeProber {
    async fn probe(&self, _dev: &str, target: IpAddr) -> Option<f64> {
        self.0.lock().unwrap().get(&target).copied()
    }
}

/// Counts applies.
#[derive(Default)]
struct CountingApplier(Mutex<u32>);

#[async_trait]
impl Applier for CountingApplier {
    fn name(&self) -> &'static str {
        "routes"
    }
    fn phase(&self) -> Phase {
        Phase::Routes
    }
    async fn apply(&self, _s: &ConfigStore) -> Result<ApplyReport> {
        *self.0.lock().unwrap() += 1;
        Ok(ApplyReport::default())
    }
    async fn render(&self, _s: &ConfigStore) -> Result<String> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn the_monitor_marks_a_silent_gateway_down_and_reapplies_on_changes_only() {
    let s = store().await;
    save_gateway(&s, None, &gi("WAN1", "@wan").validated().unwrap())
        .await
        .unwrap();
    let mut g2 = gi("WAN2", "@opt1");
    g2.monitor_ip = Some("9.9.9.9".into());
    save_gateway(&s, None, &g2.validated().unwrap())
        .await
        .unwrap();
    let mut off = gi("OFF", "lan0");
    off.address = Some("192.168.1.254".into());
    off.monitor_enabled = Some(false);
    save_gateway(&s, None, &off.validated().unwrap())
        .await
        .unwrap();
    let prober = Arc::new(FakeProber(Mutex::new(BTreeMap::from([
        ("198.51.100.1".parse().unwrap(), 2.0),
        ("9.9.9.9".parse().unwrap(), 30.0),
    ]))));
    let applier = Arc::new(CountingApplier::default());
    let mut m = Monitor::new(applier.clone(), Arc::new(fake()), prober.clone());
    for _ in 0..3 {
        m.tick(&s).await.unwrap();
    }
    assert_eq!(m.states()["WAN1"].state, GwState::Online);
    assert_eq!(m.states()["WAN2"].state, GwState::Online);
    assert_eq!(
        m.states()["WAN2"].rtt_ms,
        Some(30.0),
        "probed the monitor IP"
    );
    assert_eq!(m.states()["OFF"].state, GwState::Unmonitored);
    // applied when the states first appeared (pending -> online), not on
    // every tick
    let applies = *applier.0.lock().unwrap();
    assert_eq!(applies, 2);
    m.tick(&s).await.unwrap();
    assert_eq!(*applier.0.lock().unwrap(), applies);
    // WAN1 stops answering: down after five lost probes, then one re-apply
    prober
        .0
        .lock()
        .unwrap()
        .remove(&"198.51.100.1".parse().unwrap());
    for _ in 0..4 {
        m.tick(&s).await.unwrap();
    }
    assert_eq!(m.states()["WAN1"].state, GwState::Loss);
    m.tick(&s).await.unwrap();
    assert_eq!(m.states()["WAN1"].state, GwState::Down);
    assert_eq!(m.states()["WAN1"].loss_pct, 55);
    let after_down = *applier.0.lock().unwrap();
    assert!(after_down > applies);
    // back
    prober
        .0
        .lock()
        .unwrap()
        .insert("198.51.100.1".parse().unwrap(), 2.0);
    m.tick(&s).await.unwrap();
    assert_ne!(m.states()["WAN1"].state, GwState::Down);
    assert!(*applier.0.lock().unwrap() > after_down);
}
