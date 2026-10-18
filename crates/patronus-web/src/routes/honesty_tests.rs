//! Regression tests for the "fabricated data shown as real" finding: every
//! page/endpoint that used to return fixtures (WireGuard peers, IPsec
//! tunnel, routes, backups, services, updates, users, alerts, connections,
//! dashboard/status counters) must now answer from the live system or say
//! it cannot -- driven through the real router with a logged-in session.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

/// Literals of the old fixtures. None may appear in any response.
pub(crate) const FIXTURE_MARKERS: &[&str] = &[
    "RZv3iVQPxjKqBVLPEMJJX",
    "cBVRKzyV6FkeN9tYPqJCILdNX",
    "kH5N8GxYJ2V5QfXzJnP9sKLmRt",
    "mobile-device",
    "site-b-gateway",
    "site-to-site-hq",
    "203.0.113.100",
    "192.168.1.254",
    "patronus-backup-2024",
    "15.2 MB",
    "\"0 MB\"",
    "15d 8h",
    "15 days, 8 hours",
    "2024-01-1",
    "System Administrator",
    "Network Operator",
    "Intel Core i7",
    "6.16.12-gentoo",
    "Patronus SD-WAN v2.1.0",
    "vpn.example.com",
    "your-private-key",
    "generate-private-key",
    "High CPU usage detected on eth0",
    "New WireGuard peer connected",
    "192.168.1.100:54321",
    "137.4 GB",
    "Core Components: Operational",
];

/// The fixtures must not come back in the code or templates either
/// (comments and this file excepted).
#[test]
fn no_fixture_literals_in_sources_or_templates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut stack = vec![root.join("src"), root.join("templates")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if !p.ends_with("honesty_tests.rs") {
                files.push(p);
            }
        }
    }
    assert!(files.len() > 20, "scanned {} files", files.len());
    let extra = [
        "Math.random",
        "rand::random",
        "Simulate live logs",
        "sample values",
    ];
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            for m in FIXTURE_MARKERS.iter().chain(extra.iter()) {
                assert!(
                    !line.contains(m),
                    "{}:{}: fixture literal {m:?} is back",
                    f.display(),
                    i + 1
                );
            }
        }
    }
}

struct App {
    app: axum::Router,
    cookie: String,
    dir: std::path::PathBuf,
}

async fn app() -> App {
    let dir = std::env::temp_dir().join(format!("patronus-web-honest-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = std::sync::Arc::new(
        patronus_config::ConfigStore::open(dir.join("config.db"))
            .await
            .unwrap(),
    );
    let state = crate::AppState::new(
        store,
        std::sync::Arc::new(crate::state::firewall::NoopApplier),
    )
    .await
    .unwrap();
    let pw = "Honest-Test-Passw0rd!".to_string();
    state
        .auth
        .user_store
        .provision_admin(Some(pw.clone()), &dir.join("pw"))
        .await
        .unwrap();
    let app = super::build_router(state, std::sync::Arc::new(crate::WsBroadcaster::new()));
    let login = format!(r#"{{"username":"admin","password":"{pw}"}}"#);
    let r = app
        .clone()
        .oneshot(req(Method::POST, "/api/auth/login", None, Some(&login)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    App { app, cookie, dir }
}

fn req(method: Method, uri: &str, cookie: Option<&str>, body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b.body(
        body.map(|s| Body::from(s.to_string()))
            .unwrap_or_else(Body::empty),
    )
    .unwrap()
}

impl App {
    async fn call(&self, m: Method, uri: &str, body: Option<&str>) -> (StatusCode, String) {
        let r = self
            .app
            .clone()
            .oneshot(req(m, uri, Some(&self.cookie), body))
            .await
            .unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 10 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for f in FIXTURE_MARKERS {
            assert!(!text.contains(f), "{uri} answered fixture text {f:?}");
        }
        (status, text)
    }
}

#[tokio::test]
async fn backups_are_real_files_and_create_writes_one() {
    let a = app().await;
    let (s, body) = a.call(Method::GET, "/api/system/backups", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.trim(), "[]", "a new box has no backups");

    let (s, body) = a.call(Method::POST, "/api/system/backups", None).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let b: serde_json::Value = serde_json::from_str(&body).unwrap();
    let name = b["name"].as_str().unwrap().to_string();
    let file = a.dir.join("backups").join(&name);
    let on_disk = std::fs::read(&file).expect("the backup file exists");
    assert_eq!(b["size_bytes"].as_u64().unwrap(), on_disk.len() as u64);
    assert!(on_disk.len() > 100, "a config export is not empty");
    assert_eq!(b["is_valid"], true);

    let (_, list) = a.call(Method::GET, "/api/system/backups", None).await;
    let list: Vec<serde_json::Value> = serde_json::from_str(&list).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], name.as_str());

    let (s, dl) = a
        .call(Method::GET, &format!("/api/system/backups/{name}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(dl.as_bytes(), &on_disk[..]);
    let (s, _) = a
        .call(Method::GET, "/api/system/backups/..%2Fconfig.db", None)
        .await;
    assert_ne!(s, StatusCode::OK, "no path traversal");

    let (_, page) = a.call(Method::GET, "/system", None).await;
    assert!(page.contains(&name), "the System page lists the real file");

    let (s, _) = a
        .call(Method::DELETE, &format!("/api/system/backups/{name}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!file.exists());
}

#[tokio::test]
async fn vpn_reads_the_system_and_refuses_to_fake_writes() {
    let a = app().await;
    let (s, body) = a.call(Method::GET, "/api/vpn/wireguard/peers", None).await;
    let live = std::process::Command::new("wg")
        .args(["show", "all", "dump"])
        .output();
    match live {
        Ok(o) if o.status.success() => {
            assert_eq!(s, StatusCode::OK, "{body}");
            let peers: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
            let kernel_peers = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.split('\t').count() == 9)
                .count();
            assert_eq!(peers.len(), kernel_peers, "exactly the kernel's peers");
        }
        // no wireguard-tools / not permitted: an error, never a list
        _ => assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}"),
    }
    for (m, uri, body) in [
        (
            Method::POST,
            "/api/vpn/wireguard/peers",
            Some(
                r#"{"name":"x","public_key":"k","allowed_ips":"10.0.0.9/32","endpoint":null,"persistent_keepalive":null,"enabled":true}"#,
            ),
        ),
        (Method::DELETE, "/api/vpn/wireguard/peers/1", None),
        (Method::GET, "/api/vpn/wireguard/config/1", None),
        (Method::GET, "/api/vpn/wireguard/qrcode/1", None),
        (Method::GET, "/api/vpn/openvpn/tunnels", None),
    ] {
        let (s, _) = a.call(m.clone(), uri, body).await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED, "{m} {uri}");
    }
    // The counters are derived from the same live read.
    let (s, body) = a.call(Method::GET, "/api/status", None).await;
    assert_eq!(s, StatusCode::OK);
    let st: serde_json::Value = serde_json::from_str(&body).unwrap();
    let snap = crate::state::VpnManager::new().snapshot().await;
    assert_eq!(
        st["vpn_connections"].as_u64().unwrap() as usize,
        snap.active_connections()
    );
    if snap.wg_peers.is_empty() && snap.ipsec_tunnels.is_empty() {
        assert_eq!(st["vpn_connections"], 0, "no tunnels, no connections");
    }
    assert_eq!(
        st["vpn_errors"].as_array().unwrap().len(),
        snap.read_errors().len()
    );
    // The dashboard tile shows the same read failures, never a bare count.
    let (s, dash) = a.call(Method::GET, "/", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        dash.contains("VPN state could not be read"),
        !snap.read_errors().is_empty(),
        "dashboard VPN tile vs read errors {:?}",
        snap.read_errors()
    );
    let (s, page) = a.call(Method::GET, "/vpn", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("WireGuard"));
    // strongSwan installed but charon stopped (every USE=ipsec box that
    // doesn't use IPsec, and the Gentoo CI base image) is a normal state:
    // 200 + empty list, no error text, the page says "not running".
    let (s, body) = a.call(Method::GET, "/api/vpn/ipsec/tunnels", None).await;
    if snap.ipsec_error.is_none() {
        assert_eq!(s, StatusCode::OK, "{body}");
    } else {
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    }
    assert!(!body.contains("usage:"), "{body}");
    if snap.ipsec_not_running {
        assert_eq!(body.trim(), "[]");
        assert!(page.contains("id=\"ipsec-not-running\""));
        assert!(!st.to_string().contains("swanctl"), "{st}");
    }
    eprintln!(
        "ipsec state on this host: not_running={} error={:?}",
        snap.ipsec_not_running, snap.ipsec_error
    );
}

#[tokio::test]
async fn routes_services_updates_and_pages_are_live_or_honest() {
    let a = app().await;
    let (s, body) = a.call(Method::GET, "/api/network/routes", None).await;
    if s == StatusCode::OK {
        let routes: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        let v4 = std::process::Command::new("ip")
            .args(["-json", "-4", "route", "show", "table", "main"])
            .output()
            .unwrap();
        let kernel: Vec<serde_json::Value> = serde_json::from_slice(&v4.stdout).unwrap_or_default();
        let ours = routes
            .iter()
            .filter(|r| !r["destination"].as_str().unwrap().contains(':'))
            .count();
        assert_eq!(ours, kernel.len(), "the kernel's IPv4 routes, no more");
    } else {
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    }

    let (s, body) = a.call(Method::GET, "/api/system/services", None).await;
    assert_eq!(s, StatusCode::OK);
    let services: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    for svc in &services {
        let name = svc["name"].as_str().unwrap();
        assert!(
            crate::state::system::KNOWN_SERVICES
                .iter()
                .any(|(n, _)| *n == name),
            "{name}"
        );
    }
    let (s, _) = a
        .call(
            Method::POST,
            "/api/system/services/definitely-not-ours/stop",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "only Patronus' own services");

    let (s, _) = a.call(Method::GET, "/api/system/updates", None).await;
    assert_eq!(s, StatusCode::NOT_IMPLEMENTED);

    let (s, body) = a.call(Method::GET, "/api/system/users", None).await;
    assert_eq!(s, StatusCode::OK);
    let users: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(users.len(), 1, "only the provisioned admin: {body}");
    assert_eq!(users[0]["username"], "admin");

    let host = crate::state::host::hostname();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    for uri in ["/", "/system", "/monitoring", "/network", "/vpn"] {
        let (s, page) = a.call(Method::GET, uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        if uri == "/" || uri == "/system" {
            assert!(page.contains(&host), "{uri} shows the real hostname");
        }
        if uri == "/system" {
            assert!(page.contains(kernel.trim()), "real kernel release");
            assert!(page.contains(env!("CARGO_PKG_VERSION")));
        }
        assert!(!page.contains("Math.random"), "{uri}");
    }
    let r = a
        .app
        .clone()
        .oneshot(req(Method::GET, "/simple/status", Some(&a.cookie), None))
        .await
        .unwrap();
    assert_eq!(r.headers()[header::LOCATION], "/system");
}

/// Every in-app link in every template leads to a page that exists (the
/// sidebar used to link /ai and /gitops, which never had a route -- the
/// AI and GitOps features are not reachable from a shipped binary yet).
#[tokio::test]
async fn every_template_link_resolves_to_a_page() {
    let a = app().await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut links = std::collections::BTreeSet::new();
    for e in std::fs::read_dir(&root).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        for chunk in text.split("<a ").skip(1) {
            let tag = chunk.split('>').next().unwrap_or("");
            if let Some(rest) = tag.split("href=\"").nth(1) {
                let href = rest.split('"').next().unwrap_or("");
                if href.starts_with('/') && !href.contains('{') {
                    links.insert(href.to_string());
                }
            }
        }
    }
    assert!(links.contains("/firewall") && links.len() >= 8, "{links:?}");
    for href in &links {
        let (s, _) = a.call(Method::GET, href, None).await;
        assert!(
            s.is_success() || s.is_redirection(),
            "template link {href} answers {s}"
        );
    }
    for gone in ["/ai", "/gitops"] {
        assert!(!links.contains(gone), "{gone} has no page");
    }
}

/// No page may reference an asset that 404s (the Firewall page logged a
/// favicon 404 on every load; the login page linked a stylesheet that
/// never existed). /favicon.ico is served without a session, since
/// browsers fetch it on the login page too.
#[tokio::test]
async fn page_assets_and_the_favicon_are_served() {
    let a = app().await;
    for path in ["/favicon.ico", "/favicon.svg"] {
        let r = a
            .app
            .clone()
            .oneshot(req(Method::GET, path, None, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{path} without a session");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "image/svg+xml");
        let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        assert!(body.starts_with(b"<svg"), "{path}");
    }
    let pages = [
        "/",
        "/firewall",
        "/vpn",
        "/network",
        "/interfaces",
        "/monitoring",
        "/system",
        "/login",
    ];
    for page in pages {
        let (s, html) = a.call(Method::GET, page, None).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        assert!(
            html.contains(r#"<link rel="icon" href="/favicon.svg""#),
            "{page} declares the favicon"
        );
        // Every local stylesheet/script/image the page loads must exist.
        for tag in html.split('<').skip(1) {
            let tag = tag.split('>').next().unwrap_or("");
            let attr = if tag.starts_with("link ") {
                "href=\"/"
            } else if tag.starts_with("script ") || tag.starts_with("img ") {
                "src=\"/"
            } else {
                continue;
            };
            let Some(rest) = tag.split(attr).nth(1) else {
                continue;
            };
            let url = format!("/{}", rest.split('"').next().unwrap_or(""));
            let (s, _) = a.call(Method::GET, &url, None).await;
            assert_eq!(s, StatusCode::OK, "{page} loads {url}");
        }
    }
}
