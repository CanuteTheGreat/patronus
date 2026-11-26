use super::*;
use serde_json::json;

fn rule(expr: Value, comment: &str) -> Value {
    json!({"rule": {"family": "inet", "table": "patronus", "chain": "input", "handle": 5, "comment": comment, "expr": expr}})
}

/// A router with LAN lan0, WAN wan0 (203.0.113.2), sshd + web listening on every address,
/// a default-drop input chain with the anti-lockout rule on the LAN only.
fn base() -> Inputs {
    let nft = json!({"nftables": [
        {"chain": {"family": "inet", "table": "patronus", "name": "input", "policy": "drop"}},
        rule(json!([{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]), ""),
        rule(json!([{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lan0"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [22, 80, 443]}}}, {"accept": null}]), "anti-lockout"),
    ]});
    Inputs {
        facts: json!({
            "listeners": [
                {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"},
                {"proto": "tcp", "addr": "0.0.0.0", "port": 443, "process": "patronus-web"},
                {"proto": "tcp", "addr": "0.0.0.0", "port": 80, "process": "patronus-web"},
                {"proto": "udp", "addr": "0.0.0.0", "port": 53, "process": "unbound"},
            ],
            "system": {"mem_total_mb": 4096, "tcp_syncookies": "1"},
            "ssh": {"sshd": {"port": ["22"], "passwordauthentication": ["yes"], "kbdinteractiveauthentication": ["no"], "permitrootlogin": ["prohibit-password"], "trustedusercakeys": ["none"]}, "authorized_keys": 1},
            "wg": {"peers": []},
            "ipsec": {"proposals": [], "sa_algorithms": []},
            "openvpn": [],
            "dns": {"unbound_running": true, "validator": true, "trust_anchor": true, "permissive": false},
            "ids": {"suricata_running": false},
            "nft": {"main": nft, "guard_table": false},
        }),
        wan_devs: vec!["wan0".into()],
        wan_addrs: vec!["203.0.113.2".parse().unwrap()],
        guard_built: true,
        dnssec_setting: true,
        ssh_port: 22,
        web_ports: vec![443, 80],
        https_port: 443,
        redirect_port: 80,
        totp_built: true,
        admins: vec![("admin".into(), false)],
        ids_built: true,
        settings: Settings::default(),
        now: 1_800_000_000,
        updates: json!({"checked_at": null, "pending": []}),
        ..Default::default()
    }
}

fn st(c: &[Check], id: &str) -> Status {
    c.iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id}"))
        .status
}

#[test]
fn a_default_drop_router_passes_the_wan_checks_and_fails_the_switches() {
    let i = base();
    let c = run_checks(&i);
    assert_eq!(st(&c, "web_wan"), Status::Pass);
    assert_eq!(st(&c, "ssh_wan"), Status::Pass);
    assert_eq!(
        st(&c, "ssh_keys"),
        Status::Fail,
        "sshd -T says passwordauthentication yes"
    );
    assert_eq!(st(&c, "guard"), Status::Fail);
    assert_eq!(st(&c, "threat_feeds"), Status::Fail);
    assert_eq!(st(&c, "dnssec"), Status::Pass);
    assert_eq!(st(&c, "wan_bogons"), Status::Fail);
    assert_eq!(st(&c, "wan_private"), Status::Fail);
    assert_eq!(st(&c, "synflood"), Status::Fail);
    assert_eq!(st(&c, "admin_2fa"), Status::Fail);
    assert_eq!(st(&c, "ids"), Status::Warn, "4 GB RAM, Suricata off");
    assert_eq!(st(&c, "std_ports"), Status::Pass);
    assert_eq!(st(&c, "services"), Status::Pass);
    assert_eq!(st(&c, "wg_psk"), Status::Na);
    assert_eq!(st(&c, "ipsec_weak"), Status::Na);
    assert_eq!(st(&c, "openvpn_tls"), Status::Na);
    let (score, g) = grade(&c);
    assert!(score < 65, "{score}");
    assert!(matches!(g, "D" | "F"));
}

#[test]
fn a_wan_accept_rule_makes_the_web_ui_check_fail_critically() {
    let mut i = base();
    let r = rule(
        json!([{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wan0"}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}}, {"accept": null}]),
        "web from anywhere",
    );
    i.facts["nft"]["main"]["nftables"]
        .as_array_mut()
        .unwrap()
        .push(r);
    i.wan_rules = vec![WanRule {
        id: 7,
        name: "web from anywhere".into(),
        ports: Some(vec![(443, 443)]),
    }];
    let c = run_checks(&i);
    let w = c.iter().find(|c| c.id == "web_wan").unwrap();
    assert_eq!(w.status, Status::Fail);
    assert!(
        w.evidence.contains("port 443 on wan0") && w.evidence.contains("web from anywhere"),
        "{}",
        w.evidence
    );
    assert!(w.in_baseline);
    // everything else passing: still capped at D by the critical failure
    let all_pass: Vec<Check> = c
        .into_iter()
        .map(|mut x| {
            if x.id != "web_wan" {
                x.status = Status::Pass;
            }
            x
        })
        .collect();
    assert_eq!(grade(&all_pass).1, "D");
    // a web UI bound to the LAN address only is not reachable on the WAN, whatever the rule says
    let mut j = i.clone();
    for l in j.facts["listeners"].as_array_mut().unwrap() {
        if l["port"] == 443 || l["port"] == 80 {
            l["addr"] = json!("192.168.50.1");
        }
    }
    assert_eq!(st(&run_checks(&j), "web_wan"), Status::Pass);
}

#[test]
fn plan_turns_on_the_switches_and_disables_the_wan_rule() {
    let mut i = base();
    let r = rule(
        json!([{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wan0"}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}}, {"accept": null}]),
        "web from anywhere",
    );
    i.facts["nft"]["main"]["nftables"]
        .as_array_mut()
        .unwrap()
        .push(r);
    i.wan_rules = vec![WanRule {
        id: 7,
        name: "web from anywhere".into(),
        ports: Some(vec![(443, 443)]),
    }];
    let c = run_checks(&i);
    let lan = SessionPath {
        addr: Some("192.168.50.10".parse().unwrap()),
        dev: Some("lan0".into()),
        over_wan: false,
    };
    let p = plan(&i, &c, &lan);
    let acts: Vec<&Action> = p.changes.iter().map(|c| &c.action).collect();
    assert!(acts.contains(&&Action::Guard));
    assert!(
        acts.contains(&&Action::SshPasswordOff),
        "a key is installed"
    );
    assert!(acts.contains(&&Action::DisableRule { id: 7 }));
    assert!(acts.contains(&&Action::System {
        key: "firewall.synflood_protect".into(),
        value: "1".into()
    }));
    assert!(acts.contains(&&Action::System {
        key: "firewall.wan_block_bogons".into(),
        value: "1".into()
    }));
    assert!(acts.contains(&&Action::System {
        key: "firewall.wan_block_private".into(),
        value: "1".into()
    }));
    assert_eq!(
        acts.iter()
            .filter(|a| matches!(a, Action::Feed { .. }))
            .count(),
        3
    );
    assert!(p.skipped.iter().any(|s| s.check == "admin_2fa"));
    assert!(p.skipped.iter().any(|s| s.check == "ids"));
    // the token names exactly these actions
    assert_eq!(p.token, plan(&i, &c, &lan).token);
    let mut j = i.clone();
    j.synflood = true;
    assert_ne!(p.token, plan(&j, &run_checks(&j), &lan).token);
}

#[test]
fn plan_never_cuts_the_admins_own_wan_session() {
    let mut i = base();
    let r = rule(
        json!([{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wan0"}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}}, {"accept": null}]),
        "web from anywhere",
    );
    i.facts["nft"]["main"]["nftables"]
        .as_array_mut()
        .unwrap()
        .push(r);
    i.wan_rules = vec![WanRule {
        id: 7,
        name: "web from anywhere".into(),
        ports: Some(vec![(443, 443)]),
    }];
    let c = run_checks(&i);
    // connected over the WAN from a documentation (bogon) address
    let wan = SessionPath {
        addr: Some("203.0.113.1".parse().unwrap()),
        dev: Some("wan0".into()),
        over_wan: true,
    };
    let p = plan(&i, &c, &wan);
    assert!(
        !p.changes
            .iter()
            .any(|c| c.action == Action::DisableRule { id: 7 }),
        "{:?}",
        p.changes
    );
    assert!(p
        .skipped
        .iter()
        .any(|s| s.check == "web_wan" && s.reason.contains("over the WAN")));
    assert!(!p.changes.iter().any(|c| c.check == "wan_bogons"));
    assert!(p
        .skipped
        .iter()
        .any(|s| s.check == "wan_bogons" && s.reason.contains("203.0.113.1")));
    // private WAN source: the private-source guard is left alone
    let wp = SessionPath {
        addr: Some("10.1.2.3".parse().unwrap()),
        dev: Some("wan0".into()),
        over_wan: true,
    };
    let p = plan(&i, &c, &wp);
    assert!(!p.changes.iter().any(|c| c.check == "wan_private"));
    assert!(
        p.changes.iter().any(|c| c.check == "wan_bogons"),
        "10.1.2.3 is not a bogon"
    );
}

#[test]
fn ssh_passwords_stay_on_without_a_key_and_a_private_wan_is_na() {
    let mut i = base();
    i.facts["ssh"]["authorized_keys"] = json!(0);
    i.wan_addrs = vec!["10.0.0.2".parse().unwrap()];
    let c = run_checks(&i);
    assert_eq!(st(&c, "wan_private"), Status::Na);
    let p = plan(&i, &c, &SessionPath::default());
    assert!(!p.changes.iter().any(|c| c.action == Action::SshPasswordOff));
    assert!(p
        .skipped
        .iter()
        .any(|s| s.check == "ssh_keys" && s.reason.contains("no SSH key")));
    assert!(p.skipped.iter().any(|s| s.check == "wan_private"));
    // a user CA counts as a way in
    i.facts["ssh"]["sshd"]["trustedusercakeys"] = json!(["/etc/ssh/patronus/trusted_user_ca_keys"]);
    let p = plan(&i, &run_checks(&i), &SessionPath::default());
    assert!(p.changes.iter().any(|c| c.action == Action::SshPasswordOff));
}

#[test]
fn live_state_decides_not_the_switch() {
    let mut i = base();
    i.guard_enabled = true;
    i.synflood = true;
    i.wan_block_bogons = true;
    let c = run_checks(&i);
    assert_eq!(st(&c, "guard"), Status::Warn, "switched on but no table");
    assert_eq!(st(&c, "synflood"), Status::Warn);
    assert_eq!(st(&c, "wan_bogons"), Status::Warn);
    i.facts["nft"]["guard_table"] = json!(true);
    let nft = i.facts["nft"]["main"]["nftables"].as_array_mut().unwrap();
    nft.push(rule(json!([{"drop": null}]), "SYN flood protection"));
    nft.push(rule(json!([{"drop": null}]), "WAN: block bogon sources"));
    let c = run_checks(&i);
    assert_eq!(st(&c, "guard"), Status::Pass);
    assert_eq!(st(&c, "synflood"), Status::Pass);
    assert_eq!(st(&c, "wan_bogons"), Status::Pass);
    // unbound running without the validator
    i.facts["dns"]["validator"] = json!(false);
    assert_eq!(st(&run_checks(&i), "dnssec"), Status::Fail);
    // no live facts at all: unknown, never pass
    let mut u = base();
    u.facts = Value::Null;
    u.facts_error = Some("applyd down".into());
    let c = run_checks(&u);
    assert_eq!(st(&c, "web_wan"), Status::Unknown);
    assert_eq!(st(&c, "ssh_keys"), Status::Unknown);
}

#[test]
fn vpn_checks() {
    let mut i = base();
    i.facts["wg"]["peers"] = json!([
        {"interface": "wg0", "public_key": "AAAAkey1", "preshared_key": false, "latest_handshake": 0},
        {"interface": "wg0", "public_key": "BBBBkey2", "preshared_key": true, "latest_handshake": i.now - 3600},
    ]);
    i.wg_store = vec![
        WgStorePeer {
            id: 1,
            interface: "wg0".into(),
            name: "old-phone".into(),
            public_key: "AAAAkey1".into(),
            enabled: true,
            updated_at: i.now - 200 * 86_400,
        },
        WgStorePeer {
            id: 2,
            interface: "wg0".into(),
            name: "laptop".into(),
            public_key: "BBBBkey2".into(),
            enabled: true,
            updated_at: i.now - 200 * 86_400,
        },
    ];
    // the sampler saw old-phone 100 days ago (the kernel forgot it at a reboot)
    i.wg_seen.insert("AAAAkey1".into(), i.now - 100 * 86_400);
    let c = run_checks(&i);
    let psk = c.iter().find(|c| c.id == "wg_psk").unwrap();
    assert_eq!(psk.status, Status::Warn);
    assert!(psk.evidence.contains("old-phone"));
    let silent = c.iter().find(|c| c.id == "wg_silent").unwrap();
    assert_eq!(silent.status, Status::Warn);
    assert_eq!(silent.detail["silent"][0]["id"], 1);
    assert_eq!(silent.detail["silent"][0]["days"], 100);
    assert!(!silent.evidence.contains("laptop"));
    i.facts["ipsec"]["proposals"] = json!([{"block": "connections.site", "kind": "ike", "proposals": ["aes256-sha256-modp2048"]}]);
    assert_eq!(st(&run_checks(&i), "ipsec_weak"), Status::Pass);
    i.facts["ipsec"]["proposals"] = json!([{"block": "connections.site", "kind": "ike", "proposals": ["aes128-sha1-modp1024"]}]);
    let c = run_checks(&i);
    let ip = c.iter().find(|c| c.id == "ipsec_weak").unwrap();
    assert_eq!(ip.status, Status::Fail);
    assert!(
        ip.evidence.contains("MODP-1024") && ip.evidence.contains("SHA-1"),
        "{}",
        ip.evidence
    );
    i.facts["openvpn"] = json!([{"config": "/etc/openvpn/a.conf", "tls_crypt": false, "tls_auth": true, "weak_cipher": false}]);
    assert_eq!(st(&run_checks(&i), "openvpn_tls"), Status::Warn);
    i.facts["openvpn"] = json!([{"config": "/etc/openvpn/a.conf", "tls_crypt": false, "tls_auth": false, "weak_cipher": false}]);
    assert_eq!(st(&run_checks(&i), "openvpn_tls"), Status::Fail);
    i.facts["openvpn"] = json!([{"config": "/etc/openvpn/a.conf", "tls_crypt": true, "tls_auth": false, "weak_cipher": false}]);
    assert_eq!(st(&run_checks(&i), "openvpn_tls"), Status::Pass);
}

#[test]
fn weak_algorithms_and_cidrs() {
    assert!(weak_algorithms("aes256gcm16-prfsha384-ecp384").is_empty());
    assert!(weak_algorithms("aes256-sha256-modp2048").is_empty());
    assert_eq!(
        weak_algorithms("aes128-sha1-modp1024"),
        vec!["MODP-1024", "SHA-1"]
    );
    assert_eq!(
        weak_algorithms("3des-md5-modp768"),
        vec!["MODP-768", "3DES", "MD5"]
    );
    assert_eq!(
        weak_algorithms("AES_CBC-128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024"),
        vec!["MODP-1024", "SHA-1"]
    );
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(cidr_contains("10.0.0.0/8", &ip("10.200.1.1")));
    assert!(!cidr_contains("10.0.0.0/8", &ip("11.0.0.1")));
    assert!(cidr_contains("fc00::/7", &ip("fd00::1")));
    assert!(!cidr_contains("fc00::/7", &ip("2001:db8::1")));
    assert!(!cidr_contains("10.0.0.0/8", &ip("fd00::1")));
    assert!(is_bogon(&ip("203.0.113.9")) && !is_bogon(&ip("8.8.8.8")));
    assert!(is_private(&ip("100.64.1.1")) && !is_private(&ip("203.0.113.9")));
}

#[test]
fn settings_are_validated() {
    let d = Settings::default();
    assert!(d
        .merged(&SettingsIn {
            wg_silent_days: Some(0),
            ..Default::default()
        })
        .is_err());
    assert!(d
        .merged(&SettingsIn {
            baseline_feeds: Some(vec!["nope".into()]),
            ..Default::default()
        })
        .is_err());
    let s = d
        .merged(&SettingsIn {
            wg_silent_days: Some(30),
            baseline_feeds: Some(vec!["spamhaus_drop".into(), "spamhaus_drop".into()]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(s.wg_silent_days, 30);
    assert_eq!(s.baseline_feeds, vec!["spamhaus_drop"]);
}

#[tokio::test]
async fn sampler_turns_restarting_counters_into_history() {
    let s = ConfigStore::open_in_memory().await.unwrap();
    let nft = |p: u64| json!({"nftables": [{"rule": {"chain": "ti_check", "comment": "threat-intel a", "expr": [{"counter": {"packets": p, "bytes": p * 60}}, {"drop": null}]}}]});
    // a whole hour (1_800_000_000 is a multiple of 3600)
    let t0: i64 = 1_800_000_000;
    assert_eq!(t0 % 3600, 0);
    record_sample(&s, &nft(10), None, t0 + 10, 30)
        .await
        .unwrap();
    record_sample(&s, &nft(15), None, t0 + 70, 30)
        .await
        .unwrap();
    // ruleset reloaded: the counter restarts at 3
    record_sample(&s, &nft(3), None, t0 + 130, 30)
        .await
        .unwrap();
    let h = feed_hits_since(&s, t0).await.unwrap();
    assert_eq!(h.get("a"), Some(&18), "10 + 5 + 3");
    // next hour, then retention drops the first hour
    record_sample(&s, &nft(4), None, t0 + 3700, 30)
        .await
        .unwrap();
    let series = feed_hit_series(&s, t0).await.unwrap();
    assert_eq!(series["a"], vec![(t0, 18), (t0 + 3600, 1)]);
    record_sample(&s, &nft(4), None, t0 + 31 * 86_400, 30)
        .await
        .unwrap();
    assert!(feed_hit_series(&s, 0)
        .await
        .unwrap()
        .get("a")
        .is_none_or(|v| v.iter().all(|(h, _)| *h > t0 + 3600)));
    // WireGuard handshakes are kept (the newest wins)
    let wg = json!({"peers": [{"interface": "wg0", "public_key": "K", "latest_handshake": 500}]});
    record_sample(&s, &json!({}), Some(&wg), t0, 30)
        .await
        .unwrap();
    let wg2 = json!({"peers": [{"interface": "wg0", "public_key": "K", "latest_handshake": 400}]});
    record_sample(&s, &json!({}), Some(&wg2), t0, 30)
        .await
        .unwrap();
    assert_eq!(wg_seen(&s).await.get("K"), Some(&500));
    // measured data never enters a revision
    let rev = s.snapshot("t", "x").await.unwrap();
    let doc = s.revision_json(rev).await.unwrap().unwrap();
    assert!(doc["tables"].get("sec_feed_hits").is_none(), "NON_CONFIG");
    assert_eq!(counter_delta(5, 3), 3);
    assert_eq!(counter_delta(5, 9), 4);
}

#[test]
fn memory_and_dnssec_wording() {
    assert_eq!(human_mb(512), "512 MB");
    assert_eq!(human_mb(31485), "30.7 GB");
    let mut i = base();
    i.facts["dns"]["trust_anchor"] = json!(false);
    let c = run_checks(&i);
    assert_eq!(st(&c, "dnssec"), Status::Fail);
    let p = plan(&i, &c, &SessionPath::default());
    let s = p.skipped.iter().find(|s| s.check == "dnssec").unwrap();
    assert!(s.reason.contains("trust anchor"), "{}", s.reason);
    i.redirect_port = 0;
    i.https_port = 8443;
    let c = run_checks(&i);
    let sp = c.iter().find(|c| c.id == "std_ports").unwrap();
    assert!(sp.evidence.contains("no HTTP redirect"), "{}", sp.evidence);
}
