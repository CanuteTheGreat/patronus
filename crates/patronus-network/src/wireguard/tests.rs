use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// `ip` / `wg` stand-in: fixed kernel state, records every command.
#[derive(Default)]
struct FakeCmd {
    links: String,
    addrs: String,
    routes: BTreeMap<String, String>,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl Cmd for FakeCmd {
    async fn run(&self, prog: &str, args: &[String]) -> Result<String> {
        let line = format!("{prog} {}", args.join(" "));
        self.calls.lock().unwrap().push(line.clone());
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(match a.as_slice() {
            ["-j", "-d", "-s", "link", "show"] => self.links.clone(),
            ["-j", "addr", "show"] => self.addrs.clone(),
            ["-j", _, "route", "show", "default"] => "[]".into(),
            ["-j", fam, "route", "show", "dev", dev, "proto", _] => self
                .routes
                .get(&format!("{fam} {dev}"))
                .cloned()
                .unwrap_or_else(|| "[]".into()),
            _ => String::new(),
        })
    }
}

impl FakeCmd {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn changes(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter(|c| !c.starts_with("ip -j"))
            .collect()
    }
}

const NO_LINKS: &str =
    r#"[{"ifindex":1,"ifname":"lo","flags":["UP"],"mtu":65536,"operstate":"UNKNOWN"}]"#;

async fn store_with_tunnel() -> (ConfigStore, String) {
    let s = ConfigStore::open_in_memory().await.unwrap();
    let n = save_interface(
        &s,
        None,
        &InterfaceInput {
            addresses: Some("10.99.0.1/24, fd00:99::1/64".into()),
            endpoint: Some("vpn.example.net".into()),
            client_dns: Some("10.99.0.1".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (s, n)
}

#[test]
fn generated_keys_are_real_curve25519_pairs() {
    let (private, public) = generate_keypair();
    assert_eq!(public_key(&private).unwrap(), public);
    assert_eq!(B64.decode(&private).unwrap().len(), 32);
    // RFC 7748 test vector (Alice): private -> public
    let alice = B64.encode([
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ]);
    let want = B64.encode([
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ]);
    assert_eq!(public_key(&alice).unwrap(), want);
    assert_ne!(generate_keypair().0, private, "fresh randomness each time");
    assert_eq!(B64.decode(generate_psk()).unwrap().len(), 32);
    assert!(check_key("k", "not base64!").is_err());
    assert!(check_key("k", &B64.encode([1u8; 31])).is_err());
}

#[tokio::test]
async fn tunnels_and_peers_validate_and_pick_free_addresses() {
    let (s, n) = store_with_tunnel().await;
    assert_eq!(n, "wg0");
    let t = &list_interfaces(&s).await.unwrap()[0];
    assert_eq!(t.listen_port, DEFAULT_PORT);
    assert_eq!(public_key(&t.private_key).unwrap(), t.public_key);
    // a second tunnel gets the next name and port
    let n2 = save_interface(&s, None, &InterfaceInput::default())
        .await
        .unwrap();
    assert_eq!(n2, "wg1");
    assert_eq!(list_interfaces(&s).await.unwrap()[1].listen_port, 51821);
    let dup = save_interface(
        &s,
        Some("wg1"),
        &InterfaceInput {
            listen_port: Some(51820),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(dup.to_string().contains("already used by wg0"), "{dup}");
    for bad in ["0wg", "wg 0", "a-very-long-interface-name", "wg0;x"] {
        assert!(check_ifname(bad).is_err(), "{bad}");
    }

    // road warrior: no key given -> Patronus generates the pair, next free IPs
    let id = save_peer(
        &s,
        None,
        &PeerInput {
            name: Some("laptop".into()),
            preshared_key: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let p = list_peers(&s).await.unwrap();
    let laptop = p.iter().find(|x| x.id == id).unwrap();
    assert_eq!(laptop.allowed_ips, "10.99.0.2/32, fd00:99::2/128");
    assert!(laptop.exportable && laptop.has_psk);
    assert_eq!(
        public_key(laptop.private_key.as_ref().unwrap()).unwrap(),
        laptop.public_key
    );
    let id2 = save_peer(
        &s,
        None,
        &PeerInput {
            name: Some("phone".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let phone = list_peers(&s)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == id2)
        .unwrap();
    assert_eq!(phone.allowed_ips, "10.99.0.3/32, fd00:99::3/128");

    // site-to-site: given public key + endpoint, no private key held
    let (_, other_pub) = generate_keypair();
    let site = save_peer(
        &s,
        None,
        &PeerInput {
            name: Some("site-b".into()),
            public_key: Some(other_pub.clone()),
            allowed_ips: Some("10.99.0.10/32, 10.2.0.0/16".into()),
            endpoint: Some("198.51.100.2:51820".into()),
            persistent_keepalive: Some(25),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sp = list_peers(&s)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == site)
        .unwrap();
    assert!(!sp.exportable);
    let iface = &list_interfaces(&s).await.unwrap()[0];
    assert_eq!(client_config(iface, &sp).unwrap(), None);
    for (field, input) in [
        (
            "key",
            PeerInput {
                name: Some("x".into()),
                public_key: Some("short".into()),
                ..Default::default()
            },
        ),
        (
            "same key",
            PeerInput {
                name: Some("x".into()),
                public_key: Some(other_pub.clone()),
                ..Default::default()
            },
        ),
        (
            "own key",
            PeerInput {
                name: Some("x".into()),
                public_key: Some(iface.public_key.clone()),
                ..Default::default()
            },
        ),
        (
            "name",
            PeerInput {
                name: Some("laptop".into()),
                ..Default::default()
            },
        ),
        (
            "ips",
            PeerInput {
                name: Some("x".into()),
                allowed_ips: Some("10.0.0.0/99".into()),
                ..Default::default()
            },
        ),
        (
            "endpoint",
            PeerInput {
                name: Some("x".into()),
                endpoint: Some("no-port".into()),
                ..Default::default()
            },
        ),
    ] {
        let e = save_peer(&s, None, &input).await.unwrap_err().to_string();
        assert!(e.contains("Invalid"), "{field}: {e}");
    }

    // the API view never carries private or pre-shared keys
    let json = serde_json::to_string(&list_peers(&s).await.unwrap()).unwrap();
    assert!(!json.contains(laptop.private_key.as_ref().unwrap()));
    let ijson = serde_json::to_string(&list_interfaces(&s).await.unwrap()).unwrap();
    assert!(!ijson.contains(&iface.private_key));

    // client export: server key, endpoint with the listen port, PSK, DNS
    let cfg = client_config(iface, laptop).unwrap().unwrap();
    for want in [
        format!("PrivateKey = {}", laptop.private_key.as_ref().unwrap()),
        "Address = 10.99.0.2/32, fd00:99::2/128".into(),
        "DNS = 10.99.0.1".into(),
        format!("PublicKey = {}", iface.public_key),
        format!("PresharedKey = {}", laptop.preshared_key.as_ref().unwrap()),
        "AllowedIPs = 0.0.0.0/0, ::/0".into(),
        "Endpoint = vpn.example.net:51820".into(),
    ] {
        assert!(cfg.contains(&want), "missing {want:?} in\n{cfg}");
    }
    // deleting the tunnel deletes its peers
    assert!(delete_interface(&s, "wg0").await.unwrap());
    assert!(list_peers(&s).await.unwrap().is_empty());
}

#[tokio::test]
async fn apply_creates_the_link_syncs_peers_and_routes_remote_networks() {
    let (s, _) = store_with_tunnel().await;
    let (_, other_pub) = generate_keypair();
    save_peer(
        &s,
        None,
        &PeerInput {
            name: Some("site-b".into()),
            public_key: Some(other_pub.clone()),
            allowed_ips: Some("10.99.0.10/32, 10.2.0.0/16, 0.0.0.0/0".into()),
            endpoint: Some("198.51.100.2:51820".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cmd = Arc::new(FakeCmd {
        links: NO_LINKS.into(),
        addrs: "[]".into(),
        ..Default::default()
    });
    let a = WireGuardApplier::new(cmd.clone(), dir.path().to_path_buf());
    let rep = a.apply(&s).await.unwrap();
    let ch = cmd.changes();
    let conf = dir.path().join("wg0.conf");
    let want = [
        "ip link add name wg0 type wireguard".to_string(),
        format!("ip link set dev wg0 alias {WG_ALIAS}"),
        format!("wg syncconf wg0 {}", conf.display()),
        "ip addr add 10.99.0.1/24 dev wg0".into(),
        "ip addr add fd00:99::1/64 dev wg0".into(),
        "ip link set dev wg0 mtu 1420".into(),
        "ip link set dev wg0 up".into(),
        format!("ip route replace 10.2.0.0/16 dev wg0 proto {WG_PROTO}"),
    ];
    assert_eq!(ch, want, "{ch:#?}");
    assert!(
        rep.warnings.iter().any(|w| w.contains("0.0.0.0/0")),
        "a default-route peer is not routed: {:?}",
        rep.warnings
    );
    let c = std::fs::read_to_string(&conf).unwrap();
    assert!(c.contains("ListenPort = 51820") && c.contains(&format!("PublicKey = {other_pub}")));
    assert!(c.contains("Endpoint = 198.51.100.2:51820"));
    assert!(!c.contains("Address"), "setconf format, not wg-quick: {c}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let r = a.render(&s).await.unwrap();
    assert!(r.contains("PrivateKey = (hidden)"), "{r}");
}

#[tokio::test]
async fn apply_is_idempotent_and_removes_only_its_own_stale_state() {
    let (s, _) = store_with_tunnel().await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("wg7.conf"), "old").unwrap();
    // wg0 exists already with the right state, wg7 is a deleted Patronus
    // tunnel, wg9 belongs to someone else (wg-quick), eth0 is a NIC
    let links = format!(
        r#"[{{"ifindex":5,"ifname":"wg0","flags":["UP"],"mtu":1420,"operstate":"UNKNOWN","ifalias":"{WG_ALIAS}","linkinfo":{{"info_kind":"wireguard"}}}},
            {{"ifindex":6,"ifname":"wg7","flags":["UP"],"mtu":1420,"operstate":"UNKNOWN","ifalias":"{WG_ALIAS}","linkinfo":{{"info_kind":"wireguard"}}}},
            {{"ifindex":7,"ifname":"wg9","flags":["UP"],"mtu":1420,"operstate":"UNKNOWN","linkinfo":{{"info_kind":"wireguard"}}}}]"#
    );
    let addrs = r#"[{"ifindex":5,"ifname":"wg0","addr_info":[
        {"family":"inet","local":"10.99.0.1","prefixlen":24,"scope":"global","valid_life_time":4294967295},
        {"family":"inet","local":"10.98.0.1","prefixlen":24,"scope":"global","valid_life_time":4294967295},
        {"family":"inet6","local":"fd00:99::1","prefixlen":64,"scope":"global","valid_life_time":4294967295},
        {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link","valid_life_time":4294967295}]}]"#;
    let mut routes = BTreeMap::new();
    routes.insert(
        "-4 wg0".to_string(),
        r#"[{"dst":"10.5.0.0/16","dev":"wg0","protocol":"249"}]"#.to_string(),
    );
    let cmd = Arc::new(FakeCmd {
        links,
        addrs: addrs.into(),
        routes,
        ..Default::default()
    });
    let a = WireGuardApplier::new(cmd.clone(), dir.path().to_path_buf());
    a.apply(&s).await.unwrap();
    let ch = cmd.changes();
    assert!(ch.contains(&"ip link del dev wg7".to_string()), "{ch:#?}");
    assert!(
        !ch.iter().any(|c| c.contains("wg9")),
        "foreign tunnel untouched: {ch:#?}"
    );
    assert!(!ch.iter().any(|c| c.contains("link add")), "{ch:#?}");
    assert!(
        ch.contains(&"ip addr del 10.98.0.1/24 dev wg0".to_string()),
        "{ch:#?}"
    );
    assert!(!ch.iter().any(|c| c.contains("fe80")), "{ch:#?}");
    assert!(!ch.iter().any(|c| c.starts_with("ip addr add")), "{ch:#?}");
    assert!(
        !ch.iter().any(|c| c.contains("mtu") || c.ends_with(" up")),
        "{ch:#?}"
    );
    assert!(
        ch.contains(&format!(
            "ip route del 10.5.0.0/16 dev wg0 proto {WG_PROTO}"
        )),
        "stale peer route removed: {ch:#?}"
    );
    assert!(!dir.path().join("wg7.conf").exists());

    // disabled -> the link goes away
    save_interface(
        &s,
        Some("wg0"),
        &InterfaceInput {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let cmd2 = Arc::new(FakeCmd {
        links: cmd.links.clone(),
        addrs: addrs.into(),
        ..Default::default()
    });
    WireGuardApplier::new(cmd2.clone(), dir.path().to_path_buf())
        .apply(&s)
        .await
        .unwrap();
    assert!(cmd2.changes().contains(&"ip link del dev wg0".to_string()));
}

#[tokio::test]
async fn a_foreign_device_with_the_same_name_is_left_alone() {
    let (s, _) = store_with_tunnel().await;
    let dir = tempfile::tempdir().unwrap();
    let cmd = Arc::new(FakeCmd {
        links: r#"[{"ifindex":5,"ifname":"wg0","flags":["UP"],"mtu":1500,"operstate":"UP","linkinfo":{"info_kind":"bridge"}}]"#.into(),
        addrs: "[]".into(),
        ..Default::default()
    });
    let rep = WireGuardApplier::new(cmd.clone(), dir.path().to_path_buf())
        .apply(&s)
        .await
        .unwrap();
    assert!(cmd.changes().is_empty(), "{:?}", cmd.changes());
    assert!(rep.warnings[0].contains("not created by Patronus"));
}

#[test]
fn next_free_addresses_skip_used_hosts_but_not_site_networks() {
    let used: Vec<IpNetwork> = vec![
        "10.99.0.2/32".parse().unwrap(),
        "10.0.0.0/8".parse().unwrap(),
    ];
    let v = next_free_addresses("10.99.0.1/24", &used);
    assert_eq!(v, vec!["10.99.0.3/32".parse::<IpNetwork>().unwrap()]);
    assert!(next_free_addresses("", &used).is_empty());
    assert!(next_free_addresses("10.99.0.1/31", &[]).is_empty());
}
