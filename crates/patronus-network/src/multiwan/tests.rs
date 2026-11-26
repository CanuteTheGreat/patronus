use super::*;
use crate::routes::{
    desired, GatewayGroup, GroupInput, KillInfo, MembersInput, Member, Resolved, GatewayInput,
};
use patronus_config::store::ConfigStore;
use std::sync::Mutex;

fn gw(name: &str) -> Gateway {
    Gateway {
        name: name.into(),
        interface: "@wan".into(),
        family: Family::Inet,
        address: None,
        monitor_ip: None,
        monitor_ips: vec![],
        monitor_reliability: 1,
        monitor_interval: 1,
        monitor_down: 5,
        monitor_up: 1,
        monitor_enabled: true,
        loss_threshold: 20,
        latency_threshold: 500,
        loss_warn: 0,
        latency_warn: 0,
        dns_servers: vec![],
        failback_delay: 0,
        failback_ramp: 0,
        description: None,
    }
}

fn status(state: GwState) -> GwStatus {
    GwStatus {
        state,
        loss_pct: 0,
        rtt_ms: None,
        samples: 10,
        detail: None,
        since: 0,
        recovered_at: None,
        ramp_secs: 0,
        probes: vec![],
        warning: None,
        killed: None::<KillInfo>,
    }
}

fn group(kill: KillStates, trigger: Trigger) -> GatewayGroup {
    GatewayGroup {
        name: "LB".into(),
        trigger,
        members: vec![
            Member {
                gateway: "A".into(),
                tier: 1,
                weight: 1,
            },
            Member {
                gateway: "B".into(),
                tier: 2,
                weight: 1,
            },
        ],
        sticky_secs: 0,
        kill_states: kill,
        description: None,
    }
}

fn cfg(g: GatewayGroup) -> RoutingConfig {
    let mut c = RoutingConfig {
        gateways: vec![gw("A"), gw("B")],
        groups: vec![g],
        ..Default::default()
    };
    c.marks.insert("A".into(), 0x10001);
    c.marks.insert("B".into(), 0x10002);
    c.marks.insert("LB".into(), 0x20001);
    c
}

fn map(v: &[(&str, GwState)]) -> BTreeMap<String, GwStatus> {
    v.iter().map(|(n, s)| (n.to_string(), status(*s))).collect()
}

#[test]
fn warning_levels_stay_below_down_and_only_warn_while_online() {
    let mut g = gw("A");
    g.loss_warn = 5;
    g.latency_warn = 100;
    assert_eq!(warning_of(&g, GwState::Online, 0, Some(20.0)), None);
    assert_eq!(
        warning_of(&g, GwState::Online, 5, Some(20.0)).as_deref(),
        Some("loss")
    );
    assert_eq!(
        warning_of(&g, GwState::Online, 0, Some(150.0)).as_deref(),
        Some("latency")
    );
    // degraded or down gateways are not "warning": they have their own state
    assert_eq!(warning_of(&g, GwState::Latency, 0, Some(900.0)), None);
    assert_eq!(warning_of(&g, GwState::Down, 100, None), None);
    // 0 = no warning level
    g.loss_warn = 0;
    g.latency_warn = 0;
    assert_eq!(warning_of(&g, GwState::Online, 19, Some(499.0)), None);
}

#[test]
fn kills_follow_the_group_setting_and_the_trigger() {
    let before = map(&[("A", GwState::Online), ("B", GwState::Online)]);
    let a_down = map(&[("A", GwState::Down), ("B", GwState::Online)]);
    let down = |o: Vec<KillOrder>| o.into_iter().map(|k| k.gateway).collect::<Vec<_>>();
    // kill_states = down: the member that left
    let c = cfg(group(KillStates::Down, Trigger::Down));
    assert_eq!(down(plan_kills(&c, &before, &a_down)), vec!["A"]);
    // none: nothing
    let c = cfg(group(KillStates::None, Trigger::Down));
    assert!(plan_kills(&c, &before, &a_down).is_empty());
    // the trigger decides what "left" means: latency does not move a `down` group
    let c = cfg(group(KillStates::Down, Trigger::Down));
    let slow = map(&[("A", GwState::Latency), ("B", GwState::Online)]);
    assert!(plan_kills(&c, &before, &slow).is_empty());
    let c = cfg(group(KillStates::Down, Trigger::Latency));
    assert_eq!(down(plan_kills(&c, &before, &slow)), vec!["A"]);
    // a gateway first seen down was never carrying anything
    assert!(plan_kills(&c, &BTreeMap::new(), &a_down).is_empty());
}

#[test]
fn recovery_kills_the_fallback_flows_only_when_asked_and_without_a_ramp() {
    let c = cfg(group(KillStates::DownRecovery, Trigger::Down));
    let a_down = map(&[("A", GwState::Down), ("B", GwState::Online)]);
    let back = map(&[("A", GwState::Online), ("B", GwState::Online)]);
    let o = plan_kills(&c, &a_down, &back);
    assert_eq!(o.len(), 1);
    assert_eq!(o[0].gateway, "B");
    // plain `down`: the recovery leaves the flows alone
    let c = cfg(group(KillStates::Down, Trigger::Down));
    assert!(plan_kills(&c, &a_down, &back).is_empty());
    // a failback ramp moves new flows gradually: no cut-over
    let c = cfg(group(KillStates::DownRecovery, Trigger::Down));
    let mut ramped = back.clone();
    ramped.get_mut("A").unwrap().ramp_secs = 30;
    assert!(plan_kills(&c, &a_down, &ramped).is_empty());
    // the fallback itself going down on the way: nothing moves to it, its own
    // flows go because it left
    let both = map(&[("A", GwState::Online), ("B", GwState::Down)]);
    let o = plan_kills(&c, &a_down, &both);
    assert_eq!(o.len(), 1);
    assert!(o[0].gateway == "B" && o[0].why.contains("left"), "{o:?}");
}

#[test]
fn conntrack_output_is_counted() {
    assert_eq!(
        parse_deleted("conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted."),
        3
    );
    assert_eq!(
        parse_deleted("conntrack v1.4.7 (conntrack-tools): 1 flow entries have been deleted."),
        1
    );
    assert_eq!(parse_deleted("conntrack: 0 flow entries have been deleted."), 0);
    assert_eq!(parse_deleted("no idea"), 0);
}

fn sticky(is_default: bool) -> StickyGroup {
    StickyGroup {
        group: "LB".into(),
        mark: 0x20001,
        is_default,
        v6: false,
        secs: 1800,
        members: vec![(0x10001, 1), (0x10002, 3)],
        skip_ifaces: vec!["eth1".into(), "eth2".into()],
    }
}

#[test]
fn sticky_script_assigns_by_weight_and_refreshes_the_timeout() {
    let s = render_nft(&[sticky(true)], &[], &Default::default());
    assert!(s.contains("add table inet patronus_wan\n"));
    assert!(s.contains("hook prerouting priority -140"), "{s}");
    assert!(
        s.contains("add map inet patronus_wan st1_4 { type ipv4_addr : mark ; flags timeout ; }"),
        "{s}"
    );
    // known client: stored mark, timeout refreshed; for the default group
    // (unmarked traffic) and for policy-routed traffic (the group's own mark)
    for sel in ["0x20001", "0x0"] {
        assert!(
            s.contains(&format!(
                "iifname != {{ \"eth1\", \"eth2\" }} meta mark {sel} ip saddr @st1_4 meta mark set ip saddr map @st1_4 update @st1_4 {{ ip saddr timeout 1800s : meta mark }}"
            )),
            "{s}"
        );
        // new client: weights 1:3 over numgen 0..3
        assert!(
            s.contains(&format!(
                "meta mark {sel} meta mark set numgen random mod 4 map {{ 0 : 0x10001, 1-3 : 0x10002 }} update @st1_4"
            )),
            "{s}"
        );
    }
    // a group that is not the default never touches unmarked traffic
    let s = render_nft(&[sticky(false)], &[], &Default::default());
    assert!(!s.contains("meta mark 0x0 "), "{s}");
}

#[test]
fn sticky_script_v6_one_member_stale_and_flush() {
    let mut g = sticky(false);
    g.v6 = true;
    g.members = vec![(0x10001, 5)];
    let flush: BTreeSet<String> = ["st1_6".to_string()].into();
    let s = render_nft(&[g], &["st9_4".to_string()], &flush);
    assert!(s.contains("delete map inet patronus_wan st9_4"));
    assert!(s.contains("type ipv6_addr : mark"));
    assert!(s.contains("flush map inet patronus_wan st1_6"));
    assert!(s.contains("ip6 saddr @st1_6"));
    assert!(s.contains("meta mark 0x20001 meta mark set 0x10001 update @st1_6"));
    // the flush comes after the map exists and before the rules use it
    let add = s.find("add map").unwrap();
    let fl = s.find("flush map").unwrap();
    let rule = s.find("add rule").unwrap();
    assert!(add < fl && fl < rule);
}

#[test]
fn live_table_json_gives_maps_and_marks() {
    let j = r#"{"nftables":[{"metainfo":{}},{"map":{"name":"st1_4","elem":[[{"elem":{"val":"10.0.0.5","timeout":1800,"expires":1700}},65538],["10.0.0.6",65537]]}},{"map":{"name":"st2_4"}}]}"#;
    let t = parse_table(j);
    assert_eq!(t["st1_4"], vec![65538, 65537]);
    assert!(t["st2_4"].is_empty());
    assert!(parse_table("nonsense").is_empty());
}

/// Records every call; `list` answers with a canned live table.
struct FakeNft {
    live: Option<String>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl Cmd for FakeNft {
    async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
        let line = format!("{prog} {}", args.join(" "));
        self.calls.lock().unwrap().push(line.clone());
        if line.contains("list table") {
            return self.live.clone().ok_or_else(|| {
                patronus_core::Error::Network("No such file or directory".into())
            });
        }
        Ok(String::new())
    }
}

#[tokio::test]
async fn apply_creates_keeps_flushes_and_removes_the_table() {
    let dir = std::env::temp_dir().join(format!("pw-run-{}", std::process::id()));
    // no table yet and nothing wanted: not a single write
    let n = FakeNft {
        live: None,
        calls: Mutex::new(vec![]),
    };
    assert!(apply_sticky(&n, &[], &dir).await.unwrap().is_empty());
    assert_eq!(n.calls.lock().unwrap().len(), 1);
    // wanted: one `nft -f file`
    let n = FakeNft {
        live: None,
        calls: Mutex::new(vec![]),
    };
    let done = apply_sticky(&n, &[sticky(true)], &dir).await.unwrap();
    assert!(done.iter().any(|l| l.contains("1 group")), "{done:?}");
    assert!(n
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c.starts_with("nft -f ")));
    // clients on a member that is still carrying traffic keep it ...
    let keep = r#"{"nftables":[{"map":{"name":"st1_4","elem":[["10.0.0.6",65537],["10.0.0.7",65538]]}}]}"#;
    let n = FakeNft {
        live: Some(keep.into()),
        calls: Mutex::new(vec![]),
    };
    let done = apply_sticky(&n, &[sticky(true)], &dir).await.unwrap();
    assert!(!done.iter().any(|l| l.contains("dropped")), "{done:?}");
    // ... entries of a member that left are dropped, a stale map is deleted
    let lost = r#"{"nftables":[{"map":{"name":"st1_4","elem":[["10.0.0.6",65539]]}},{"map":{"name":"st7_4"}}]}"#;
    let n = FakeNft {
        live: Some(lost.into()),
        calls: Mutex::new(vec![]),
    };
    let done = apply_sticky(&n, &[sticky(true)], &dir).await.unwrap();
    assert!(done.iter().any(|l| l.contains("dropped")), "{done:?}");
    let script = std::fs::read_to_string(dir.join("wan-sticky.nft")).unwrap();
    assert!(script.contains("flush map inet patronus_wan st1_4"), "{script}");
    assert!(script.contains("delete map inet patronus_wan st7_4"), "{script}");
    // sticky switched off: the table goes
    let n = FakeNft {
        live: Some(keep.into()),
        calls: Mutex::new(vec![]),
    };
    let done = apply_sticky(&n, &[], &dir).await.unwrap();
    assert!(done.iter().any(|l| l.contains("removed")));
    assert!(n
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c == "nft delete table inet patronus_wan"));
}

#[test]
fn gateway_dns_servers_count_while_the_gateway_carries_traffic() {
    let mut c = cfg(group(KillStates::Down, Trigger::Down));
    c.gateways[0].dns_servers = vec!["9.9.9.9".parse().unwrap()];
    c.gateways[1].dns_servers = vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()];
    let all = usable_dns_servers(&c, &BTreeMap::new());
    assert_eq!(all.len(), 2);
    let down = map(&[("A", GwState::Down), ("B", GwState::Online)]);
    assert_eq!(
        usable_dns_servers(&c, &down),
        vec!["1.1.1.1".parse::<IpAddr>().unwrap(), "9.9.9.9".parse().unwrap()]
    );
    let both = map(&[("A", GwState::Down), ("B", GwState::Down)]);
    assert!(usable_dns_servers(&c, &both).is_empty());
    // a slow or lossy uplink still answers DNS
    let slow = map(&[("A", GwState::Latency), ("B", GwState::Loss)]);
    assert_eq!(usable_dns_servers(&c, &slow).len(), 2);
}

fn up(dev: &str, addr: &str) -> Resolved {
    Resolved {
        dev: Some(dev.into()),
        address: Some(addr.parse().unwrap()),
        ptp: false,
        link_up: true,
        problem: None,
    }
}

#[cfg(feature = "multiwan")]
#[test]
fn desired_plans_sticky_for_the_members_that_carry_traffic() {
    let mut g = group(KillStates::Down, Trigger::Down);
    g.sticky_secs = 600;
    g.members[1].tier = 1;
    g.members[1].weight = 2;
    let mut c = cfg(g);
    c.default4 = Some("LB".into());
    c.gateways[0].dns_servers = vec!["9.9.9.9".parse().unwrap()];
    let resolved: BTreeMap<String, Resolved> = [
        ("A".to_string(), up("eth1", "203.0.113.1")),
        ("B".to_string(), up("eth2", "100.64.0.1")),
    ]
    .into();
    let d = desired(&c, &resolved, &BTreeMap::new(), &BTreeMap::new());
    assert_eq!(d.sticky.len(), 1);
    let s = &d.sticky[0];
    assert!(s.is_default && !s.v6 && s.secs == 600);
    assert_eq!(s.members, vec![(0x10001, 1), (0x10002, 2)]);
    assert_eq!(s.skip_ifaces, vec!["eth1", "eth2"]);
    // the DNS server is pinned to its gateway
    assert!(d
        .routes
        .iter()
        .any(|r| r.dst == "9.9.9.9/32" && r.hops[0].dev.as_deref() == Some("eth1")));
    // a member that is down drops out of the assignment
    let st = map(&[("A", GwState::Down), ("B", GwState::Online)]);
    let d = desired(&c, &resolved, &st, &BTreeMap::new());
    assert_eq!(d.sticky[0].members, vec![(0x10002, 2)]);
    // not sticky: nothing planned
    c.groups[0].sticky_secs = 0;
    assert!(desired(&c, &resolved, &BTreeMap::new(), &BTreeMap::new())
        .sticky
        .is_empty());
}

#[test]
fn input_validation_of_the_new_settings() {
    let gi = |f: &dyn Fn(&mut GatewayInput)| {
        let mut i = GatewayInput {
            name: "A".into(),
            interface: "@wan".into(),
            ..Default::default()
        };
        f(&mut i);
        i.validated()
    };
    let g = gi(&|i| {
        i.loss_warn = Some(5);
        i.latency_warn = Some(100);
        i.dns_servers = Some("9.9.9.9, 1.1.1.1 9.9.9.9".into());
    })
    .unwrap();
    assert_eq!((g.loss_warn, g.latency_warn), (5, 100));
    assert_eq!(g.dns_servers.len(), 2);
    // a warning level must sit below the down threshold
    assert!(gi(&|i| i.loss_warn = Some(20)).is_err());
    assert!(gi(&|i| i.latency_warn = Some(500)).is_err());
    assert!(gi(&|i| {
        i.latency_threshold = Some(80);
        i.latency_warn = Some(80)
    })
    .is_err());
    // DNS servers: right family, no junk, at most four
    assert!(gi(&|i| i.dns_servers = Some("2001:db8::1".into())).is_err());
    assert!(gi(&|i| i.dns_servers = Some("not-an-ip".into())).is_err());
    assert!(gi(&|i| i.dns_servers = Some("127.0.0.1".into())).is_err());
    assert!(gi(&|i| i.dns_servers = Some("1.1.1.1 1.0.0.1 9.9.9.9 8.8.8.8 8.8.4.4".into())).is_err());
    let grp = |sticky: Option<u32>, kill: Option<&str>| {
        GroupInput {
            name: "LB".into(),
            trigger: None,
            members: MembersInput::Spec("A:1, B:1".into()),
            sticky_secs: sticky,
            kill_states: kill.map(str::to_string),
            description: None,
        }
        .validated()
    };
    let g = grp(Some(900), Some("down_recovery")).unwrap();
    assert_eq!((g.sticky_secs, g.kill_states), (900, KillStates::DownRecovery));
    assert_eq!(grp(None, None).unwrap().kill_states, KillStates::Down);
    assert_eq!(grp(None, Some("none")).unwrap().kill_states, KillStates::None);
    assert!(grp(Some(8 * 86_400), None).is_err());
    assert!(grp(None, Some("always")).is_err());
}

#[tokio::test]
async fn settings_round_trip_through_the_store() {
    let s = ConfigStore::open_in_memory().await.unwrap();
    let mut i = GatewayInput {
        name: "A".into(),
        interface: "@wan".into(),
        loss_warn: Some(3),
        latency_warn: Some(120),
        dns_servers: Some("9.9.9.9".into()),
        ..Default::default()
    };
    crate::routes::save_gateway(&s, None, &i.validated().unwrap())
        .await
        .unwrap();
    i.name = "B".into();
    crate::routes::save_gateway(&s, None, &i.validated().unwrap())
        .await
        .unwrap();
    let g = GroupInput {
        name: "LB".into(),
        trigger: Some("loss_latency".into()),
        members: MembersInput::Spec("A:1, B:1".into()),
        sticky_secs: Some(300),
        kill_states: Some("down_recovery".into()),
        description: None,
    }
    .validated()
    .unwrap();
    let r = crate::routes::save_group(&s, None, &g).await;
    let c = crate::routes::load(&s).await.unwrap();
    assert_eq!(c.gateway("A").unwrap().loss_warn, 3);
    assert_eq!(c.gateway("A").unwrap().latency_warn, 120);
    assert_eq!(
        c.gateway("A").unwrap().dns_servers,
        vec!["9.9.9.9".parse::<IpAddr>().unwrap()]
    );
    if crate::routes::MULTIWAN {
        r.unwrap();
        let g = c.group("LB").unwrap();
        assert_eq!((g.sticky_secs, g.kill_states), (300, KillStates::DownRecovery));
    }
}

#[cfg(feature = "multiwan")]
#[tokio::test]
async fn gitops_group_documents_carry_the_new_settings() {
    use patronus_config::applier::Applier;
    let s = ConfigStore::open_in_memory().await.unwrap();
    for n in ["A", "B"] {
        crate::routes::save_gateway(
            &s,
            None,
            &GatewayInput {
                name: n.into(),
                interface: "@wan".into(),
                ..Default::default()
            }
            .validated()
            .unwrap(),
        )
        .await
        .unwrap();
    }
    let doc = |extra: &str| {
        let y = format!(
            "- apiVersion: patronus.firewall/v1\n  kind: GatewayGroup\n  metadata: {{ name: LB }}\n  spec:\n    members:\n      - {{ gateway_name: A, tier: 1, weight: 1 }}\n      - {{ gateway_name: B, tier: 1, weight: 1 }}\n{extra}"
        );
        patronus_config::declarative::ConfigParser::parse_yaml(&y)
            .unwrap()
            .remove(0)
    };
    let ap = crate::routes::RoutesApplier::default();
    ap.upsert_resource(
        &s,
        &doc("    sticky_secs: 900\n    kill_states: down_recovery\n    trigger: loss_latency\n"),
    )
    .await
    .unwrap();
    let c = crate::routes::load(&s).await.unwrap();
    let g = c.group("LB").unwrap();
    assert_eq!(g.sticky_secs, 900);
    assert_eq!(g.kill_states, KillStates::DownRecovery);
    assert_eq!(g.trigger, Trigger::LossLatency);
    // the older `sticky: true` means the documented default timeout
    ap.upsert_resource(&s, &doc("    sticky: true\n")).await.unwrap();
    let g = crate::routes::load(&s).await.unwrap().group("LB").cloned().unwrap();
    assert_eq!(g.sticky_secs, patronus_config::declarative::DEFAULT_STICKY_SECS);
    assert_eq!(g.kill_states, KillStates::Down);
    // an unknown kill-states value is refused
    assert!(ap
        .upsert_resource(&s, &doc("    kill_states: sometimes\n"))
        .await
        .is_err());
}
