use super::*;
use patronus_config::store::ConfigStore;

// std::env::set_var is process-global; tests that set PATRONUS_LANAUDIT_TARGETS
// must not run at the same time.
// async-aware: the tests that set env vars await while holding it (clippy await_holding_lock)
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ---- nmap XML ----

#[test]
fn nmap_xml_open_ports_and_versions() {
    let xml = r#"<nmaprun><host><address addr="192.168.1.5"/>
      <ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1"/></port>
        <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
        <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
        <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MariaDB" version="10.11" extrainfo="unauthorized"/></port>
      </ports></host></nmaprun>"#;
    let ports = parse_nmap_xml(xml);
    assert_eq!(
        ports.iter().map(|p| p.port).collect::<Vec<_>>(),
        vec![22, 23, 3306]
    );
    let ssh = ports.iter().find(|p| p.port == 22).unwrap();
    assert_eq!(ssh.product, "OpenSSH");
    assert_eq!(ssh.version, "9.2p1");
    let db = ports.iter().find(|p| p.port == 3306).unwrap();
    assert!(
        db.version.contains("unauthorized"),
        "extrainfo merged: {}",
        db.version
    );
    assert!(parse_nmap_xml("not xml").is_empty());
}

#[test]
fn nmap_xml_unescapes() {
    let xml = r#"<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache &amp; mod_ssl"/></port>"#;
    let p = parse_nmap_xml(xml);
    assert_eq!(p[0].product, "Apache & mod_ssl");
}

// ---- finding rules ----

fn host(addr: &str, ports: Vec<(u16, &str, &str)>) -> Host {
    Host {
        address: addr.into(),
        name: String::new(),
        mac: String::new(),
        segment: "@lan".into(),
        ports: ports
            .into_iter()
            .map(|(port, service, product)| Port {
                proto: "tcp".into(),
                port,
                service: service.into(),
                product: product.into(),
                version: String::new(),
            })
            .collect(),
    }
}

fn rules(fs: &[Finding]) -> Vec<&str> {
    fs.iter().map(|f| f.rule.as_str()).collect()
}

#[test]
fn telnet_is_critical() {
    let h = host("10.0.0.2", vec![(23, "telnet", "")]);
    let f = findings_for_host(&h, false, &BTreeSet::new());
    assert_eq!(rules(&f), vec!["telnet"]);
    assert_eq!(f[0].severity, "critical");
}

#[test]
fn ftp_smb_upnp_database() {
    let h = host(
        "10.0.0.3",
        vec![
            (21, "ftp", ""),
            (445, "smb", ""),
            (1900, "upnp", ""),
            (5432, "postgresql", ""),
        ],
    );
    let f = findings_for_host(&h, false, &BTreeSet::new());
    let r = rules(&f);
    assert!(r.contains(&"ftp"));
    assert!(r.contains(&"smb"));
    assert!(r.contains(&"upnp"));
    assert!(r.contains(&"database"));
    // the LAN DB is a warning, telnet-grade is not here
    assert_eq!(
        f.iter().find(|x| x.rule == "database").unwrap().severity,
        "warning"
    );
}

#[test]
fn smbv1_banner_escalates_to_critical() {
    let mut h = host("10.0.0.4", vec![(445, "smb", "Samba smbv1")]);
    h.ports[0].product = "Samba smbv1".into();
    let f = findings_for_host(&h, false, &BTreeSet::new());
    assert_eq!(
        f.iter().find(|x| x.rule == "smb").unwrap().severity,
        "critical"
    );
}

#[test]
fn http_admin_only_without_https() {
    // plain HTTP admin page, no HTTPS -> flagged
    let h = host("10.0.0.5", vec![(80, "http", "login")]);
    let f = findings_for_host(&h, false, &BTreeSet::new());
    assert!(rules(&f).contains(&"http_admin"));
    // same host also on 443 -> not flagged
    let h2 = host(
        "10.0.0.5",
        vec![(80, "http", "login"), (443, "https", "login")],
    );
    let f2 = findings_for_host(&h2, false, &BTreeSet::new());
    assert!(!rules(&f2).contains(&"http_admin"));
}

#[test]
fn default_credentials_signature() {
    let mut h = host("10.0.0.6", vec![(80, "http", "")]);
    h.ports[0].product = "GoAhead-Webs".into();
    let f = findings_for_host(&h, false, &BTreeSet::new());
    let dc = f.iter().find(|x| x.rule == "default_creds").unwrap();
    assert_eq!(dc.severity, "critical");
}

#[test]
fn new_device_and_new_port() {
    let h = host("10.0.0.7", vec![(22, "ssh", ""), (8080, "http", "")]);
    // new device: every port is new but we only raise new_device, not new_port
    let f_new = findings_for_host(&h, true, &BTreeSet::new());
    assert!(rules(&f_new).contains(&"new_device"));
    assert!(!rules(&f_new).contains(&"new_port"));
    // known device, 8080 newly open
    let mut newp = BTreeSet::new();
    newp.insert(8080);
    let f = findings_for_host(&h, false, &newp);
    assert!(rules(&f).contains(&"new_port"));
    assert!(!rules(&f).contains(&"new_device"));
}

// ---- settings ----

#[test]
fn settings_validate() {
    let d = Settings::default();
    assert!(!d.enabled);
    // bad severity
    assert!(d
        .merged(&SettingsIn {
            alert_min_severity: Some("loud".into()),
            ..Default::default()
        })
        .is_err());
    // the WAN may not be a segment
    assert!(d
        .merged(&SettingsIn {
            segments: Some(vec!["@wan".into()]),
            ..Default::default()
        })
        .is_err());
    // good segment
    let s = d
        .merged(&SettingsIn {
            segments: Some(vec!["@lan".into(), "@opt1".into()]),
            interval_hours: Some(6),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(s.segments, vec!["@lan", "@opt1"]);
    assert_eq!(s.interval_hours, 6);
}

#[test]
fn quiet_window_wraps_midnight() {
    let s = Settings {
        quiet_start_min: 23 * 60,
        quiet_end_min: 5 * 60,
        ..Settings::default()
    };
    assert!(s.in_quiet_window(23 * 60 + 30));
    assert!(s.in_quiet_window(2 * 60));
    assert!(!s.in_quiet_window(12 * 60));
    // no window = always
    let s2 = Settings {
        quiet_start_min: 0,
        quiet_end_min: 0,
        ..Settings::default()
    };
    assert!(s2.in_quiet_window(12 * 60));
}

// ---- neighbour parsing / cidr / csv ----

#[test]
fn neigh_json_filters_dead_and_iface() {
    let json = r#"[
      {"dst":"10.0.0.2","dev":"lan0","lladdr":"aa:bb:cc:dd:ee:01","state":["REACHABLE"]},
      {"dst":"10.0.0.3","dev":"lan0","state":["FAILED"]},
      {"dst":"10.0.0.4","dev":"wan0","lladdr":"aa:bb:cc:dd:ee:02","state":["STALE"]}
    ]"#;
    let mut ifs = BTreeSet::new();
    ifs.insert("lan0".to_string());
    let n = parse_neigh_json(json, &ifs);
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].0.to_string(), "10.0.0.2");
}

#[test]
fn ipnet_contains() {
    let n = IpNet {
        addr: "192.168.1.0".parse().unwrap(),
        prefix: 24,
    };
    assert!(n.contains("192.168.1.55".parse().unwrap()));
    assert!(!n.contains("192.168.2.55".parse().unwrap()));
}

#[test]
fn csv_escapes() {
    assert_eq!(csv("plain"), "plain");
    assert_eq!(csv("a,b"), "\"a,b\"");
    assert_eq!(csv("a\"b"), "\"a\"\"b\"");
}

// ---- a full scan, diff and prune, against a fake scanner ----

struct FakeScanner {
    ports: std::collections::HashMap<String, Vec<Port>>,
}

#[async_trait]
impl Scanner for FakeScanner {
    fn name(&self) -> &'static str {
        "fake"
    }
    async fn scan_host(&self, addr: IpAddr) -> Vec<Port> {
        self.ports
            .get(&addr.to_string())
            .cloned()
            .unwrap_or_default()
    }
}

fn p(port: u16, service: &str) -> Port {
    Port {
        proto: "tcp".into(),
        port,
        service: service.into(),
        product: String::new(),
        version: String::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn full_scan_diff_events_and_prune() {
    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("PATRONUS_LANAUDIT_TARGETS", "10.0.0.2,10.0.0.3");
    let store = ConfigStore::open_in_memory().await.unwrap();
    let s = Settings {
        keep_scans: 2,
        ..Settings::default()
    };

    // scan 1: two hosts, .2 has telnet + mysql, .3 has ssh
    let mut m = std::collections::HashMap::new();
    m.insert("10.0.0.2".into(), vec![p(23, "telnet"), p(3306, "mysql")]);
    m.insert("10.0.0.3".into(), vec![p(22, "ssh")]);
    let sc1 = FakeScanner { ports: m };
    let id1 = run_scan_with(&store, "manual", &s, &sc1, None)
        .await
        .unwrap();
    let d1 = scan_detail(&store, id1).await.unwrap();
    assert_eq!(d1["hosts"].as_array().unwrap().len(), 2);
    let r1: Vec<String> = d1["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    assert!(r1.contains(&"telnet".to_string()));
    assert!(r1.contains(&"database".to_string()));
    // first scan: no diff findings
    assert!(!r1.contains(&"new_device".to_string()));
    assert!(!r1.contains(&"new_port".to_string()));

    // scan 2: .2 opens 8080, a new host .4 appears (change the env), .3 same
    std::env::set_var("PATRONUS_LANAUDIT_TARGETS", "10.0.0.2,10.0.0.3,10.0.0.4");
    let mut m2 = std::collections::HashMap::new();
    m2.insert(
        "10.0.0.2".into(),
        vec![p(23, "telnet"), p(3306, "mysql"), p(8080, "http")],
    );
    m2.insert("10.0.0.3".into(), vec![p(22, "ssh")]);
    m2.insert("10.0.0.4".into(), vec![p(23, "telnet")]);
    let sc2 = FakeScanner { ports: m2 };

    // capture events through a sink
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String, String)>::new()));
    let ev2 = events.clone();
    let sink = EventSink {
        record: Box::new(move |kind, subject, sev, _detail| {
            let ev = ev2.clone();
            Box::pin(async move {
                ev.lock().unwrap().push((kind, subject, sev));
            })
        }),
    };
    let id2 = run_scan_with(&store, "manual", &s, &sc2, Some(&sink))
        .await
        .unwrap();
    let d2 = scan_detail(&store, id2).await.unwrap();
    let r2: Vec<String> = d2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_string())
        .collect();
    assert!(r2.contains(&"new_device".to_string()), "4 is new: {r2:?}");
    assert!(
        r2.contains(&"new_port".to_string()),
        "8080 is new on .2: {r2:?}"
    );

    // events: at or above 'warning' (default), one per (rule, source). telnet
    // (critical) on .2 and .4, database(.2), new_port(.2)... but not info-level
    // new_device.
    let evs = events.lock().unwrap().clone();
    assert!(evs
        .iter()
        .any(|(k, s, _)| k == "audit_telnet" && s == "10.0.0.2"));
    assert!(evs
        .iter()
        .any(|(k, _, sev)| k == "audit_new_port" && sev == "warning"));
    // info-only new_device must be filtered out by the default min severity
    assert!(!evs.iter().any(|(k, _, _)| k == "audit_new_device"));

    // CSV export has a row per open port
    let csv = scan_csv(&store, id2).await.unwrap();
    assert!(csv.starts_with("address,name,mac,segment,proto,port,service"));
    assert_eq!(csv.lines().count() - 1, 3 + 1 + 1); // .2 has 3, .3 has 1, .4 has 1

    // scan 3 to trigger prune (keep_scans=2)
    let sc3 = FakeScanner {
        ports: std::collections::HashMap::new(),
    };
    let _id3 = run_scan_with(&store, "manual", &s, &sc3, None)
        .await
        .unwrap();
    let scans = list_scans(&store, 100).await.unwrap();
    assert_eq!(scans.len(), 2, "prune keeps the newest 2");
    // the oldest scan's rows are gone
    assert!(scan_detail(&store, id1).await.is_err());

    std::env::remove_var("PATRONUS_LANAUDIT_TARGETS");
}

#[tokio::test(flavor = "multi_thread")]
async fn pdf_export_is_valid() {
    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("PATRONUS_LANAUDIT_TARGETS", "10.0.0.9");
    let store = ConfigStore::open_in_memory().await.unwrap();
    let s = Settings::default();
    let mut m = std::collections::HashMap::new();
    m.insert("10.0.0.9".into(), vec![p(23, "telnet"), p(80, "http")]);
    let sc = FakeScanner { ports: m };
    let id = run_scan_with(&store, "manual", &s, &sc, None)
        .await
        .unwrap();
    let pdf = scan_pdf(&store, id).await.unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF"));
    assert!(pdf.windows(5).any(|w| w == b"xref\n"));
    std::env::remove_var("PATRONUS_LANAUDIT_TARGETS");
}

#[test]
fn pdf_escapes_parens() {
    let out = render_pdf(&[(true, "a (b) \\c".to_string())]);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a \\(b\\) \\\\c"));
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_round_trip() {
    let store = ConfigStore::open_in_memory().await.unwrap();
    let s = save(
        &store,
        &SettingsIn {
            enabled: Some(true),
            interval_hours: Some(12),
            segments: Some(vec!["@lan".into()]),
            quiet_start_min: Some(60),
            quiet_end_min: Some(300),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(s.enabled);
    let loaded = load(&store).await.unwrap();
    assert_eq!(loaded.interval_hours, 12);
    assert_eq!(loaded.segments, vec!["@lan"]);
    assert_eq!(loaded.quiet_start_min, 60);
}
