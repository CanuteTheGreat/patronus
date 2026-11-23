//! Alert delivery proofs: a real alert condition is delivered to local
//! sinks (HTTP webhook receiver, ntfy-compatible HTTP sink, SMTP sink)
//! with the documented payload (docs/ALERT-DELIVERY.md), and a failing
//! sink (500 / timeout / refused / SMTP 4xx) is retried with backoff and
//! audited. Nothing here is mocked: the real `Watcher`, the real curl
//! transport and the real store.

use super::telemetry::{self, DeliveryPolicy, Event, HookSpec, Watcher};
use super::AppState;
use patronus_config::ConfigStore;
use serde_json::Value;
use sqlx::Row;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
struct Hit {
    at: Instant,
    /// request line + headers (HTTP), or the SMTP transcript (mail)
    head: String,
    body: String,
}

impl Hit {
    fn header(&self, name: &str) -> Option<String> {
        let want = format!("{}:", name.to_lowercase());
        self.head.lines().find_map(|l| {
            l.to_lowercase()
                .starts_with(&want)
                .then(|| l[want.len()..].trim().to_string())
        })
    }
}

#[derive(Clone)]
enum Mode {
    /// answer each request with the next status (the last one repeats)
    Status(Vec<u16>),
    /// accept and never answer
    Hang,
}

struct Sink {
    addr: SocketAddr,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Sink {
    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
    async fn wait_hits(&self, n: usize) -> Vec<Hit> {
        for _ in 0..200 {
            if self.hits().len() >= n {
                return self.hits();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("sink got {} of {n} requests", self.hits().len());
    }
    fn url(&self) -> String {
        format!("http://{}/hook", self.addr)
    }
}

/// An HTTP receiver (webhook and ntfy alike).
async fn http_sink(mode: Mode) -> Sink {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
    let h2 = hits.clone();
    tokio::spawn(async move {
        let mut n = 0usize;
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (hits, mode) = (h2.clone(), mode.clone());
            let idx = n;
            n += 1;
            tokio::spawn(async move {
                let mut r = BufReader::new(&mut s);
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                }
                let mut body = vec![0u8; len];
                if r.read_exact(&mut body).await.is_err() {
                    return;
                }
                hits.lock().unwrap().push(Hit {
                    at: Instant::now(),
                    head,
                    body: String::from_utf8_lossy(&body).into(),
                });
                let status = match &mode {
                    Mode::Hang => {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        return;
                    }
                    Mode::Status(v) => *v.get(idx).or(v.last()).unwrap_or(&200),
                };
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    Sink { addr, hits }
}

/// A closed port: connections are refused.
async fn refused_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    format!("http://{a}/hook")
}

/// A minimal SMTP server. `reject` answers MAIL FROM with a 451.
async fn smtp_sink(reject: bool) -> Sink {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
    let h2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let hits = h2.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = s.into_split();
                let mut rd = BufReader::new(rd);
                let (mut script, mut data, mut in_data) = (String::new(), String::new(), false);
                let _ = wr.write_all(b"220 sink ESMTP\r\n").await;
                loop {
                    let mut line = String::new();
                    if rd.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    if in_data {
                        if line == ".\r\n" {
                            in_data = false;
                            let _ = wr.write_all(b"250 queued\r\n").await;
                        } else {
                            data.push_str(&line);
                        }
                        continue;
                    }
                    script.push_str(&line);
                    let up = line.to_uppercase();
                    let reply: &[u8] = if up.starts_with("EHLO") || up.starts_with("HELO") {
                        b"250 sink\r\n"
                    } else if up.starts_with("MAIL FROM") {
                        if reject {
                            b"451 try again later\r\n"
                        } else {
                            b"250 ok\r\n"
                        }
                    } else if up.starts_with("RCPT TO") {
                        b"250 ok\r\n"
                    } else if up.starts_with("DATA") {
                        in_data = true;
                        b"354 go\r\n"
                    } else if up.starts_with("QUIT") {
                        let _ = wr.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        b"250 ok\r\n"
                    };
                    let _ = wr.write_all(reply).await;
                }
                if script.to_uppercase().contains("MAIL FROM") {
                    hits.lock().unwrap().push(Hit {
                        at: Instant::now(),
                        head: script,
                        body: data,
                    });
                }
            });
        }
    });
    Sink { addr, hits }
}

async fn store() -> Arc<ConfigStore> {
    Arc::new(ConfigStore::open_in_memory().await.unwrap())
}

fn spec(channel: &str, url: &str, secret: &str, target: &str, sender: &str) -> HookSpec {
    HookSpec {
        name: format!("proof-{channel}"),
        url: url.into(),
        secret: secret.into(),
        channel: channel.into(),
        target: target.into(),
        sender: sender.into(),
        ..Default::default()
    }
}

/// Fast policy for the failure tests, set through the real config keys.
async fn fast_policy(store: &ConfigStore, attempts: u32, backoff_ms: u64) -> DeliveryPolicy {
    for (k, v) in [
        (telemetry::KEY_ATTEMPTS, attempts.to_string()),
        (telemetry::KEY_BACKOFF_MS, backoff_ms.to_string()),
        (telemetry::KEY_BACKOFF_FACTOR, "2".to_string()),
        (telemetry::KEY_HTTP_TIMEOUT_SECS, "1".to_string()),
        (telemetry::KEY_MAIL_TIMEOUT_SECS, "5".to_string()),
    ] {
        store.save_system_config(k, &v).await.unwrap();
    }
    DeliveryPolicy::load(store).await
}

async fn audit_rows(store: &ConfigStore, action: &str) -> Vec<(String, Value)> {
    sqlx::query("SELECT entity_id, details FROM audit_log WHERE action = ? ORDER BY id")
        .bind(action)
        .fetch_all(store.pool().unwrap())
        .await
        .unwrap()
        .into_iter()
        .map(|r| {
            let id: Option<String> = r.get(0);
            let d: String = r.get(1);
            (id.unwrap_or_default(), serde_json::from_str(&d).unwrap())
        })
        .collect()
}

fn test_event() -> Event {
    Event {
        id: 7,
        ts: 1_700_000_000,
        kind: "gateway_down".into(),
        subject: "WAN".into(),
        severity: "critical".into(),
        detail: "gateway WAN: up -> down".into(),
    }
}

#[test]
fn delivery_policy_defaults_keys_and_backoff() {
    let d = DeliveryPolicy::default();
    assert_eq!((d.attempts, d.backoff_ms, d.backoff_factor), (3, 2000, 3));
    assert_eq!((d.http_timeout_secs, d.mail_timeout_secs), (15, 30));
    // 2 s, then 6 s, then 18 s
    assert_eq!(d.wait_before(1), Duration::ZERO);
    assert_eq!(d.wait_before(2), Duration::from_secs(2));
    assert_eq!(d.wait_before(3), Duration::from_secs(6));
    assert_eq!(d.wait_before(4), Duration::from_secs(18));
}

#[tokio::test]
async fn delivery_policy_is_read_from_the_config_keys() {
    let s = store().await;
    assert_eq!(DeliveryPolicy::load(&s).await, DeliveryPolicy::default());
    let p = fast_policy(&s, 5, 10).await;
    assert_eq!(
        (
            p.attempts,
            p.backoff_ms,
            p.backoff_factor,
            p.http_timeout_secs
        ),
        (5, 10, 2, 1)
    );
    // nonsense falls back to the defaults
    s.save_system_config(telemetry::KEY_ATTEMPTS, "zero")
        .await
        .unwrap();
    s.save_system_config(telemetry::KEY_HTTP_TIMEOUT_SECS, "0")
        .await
        .unwrap();
    let p = DeliveryPolicy::load(&s).await;
    assert_eq!(p.attempts, 3);
    assert_eq!(p.http_timeout_secs, 15);
}

/// A real change in the router (a new configuration revision) goes
/// through the real watcher to a webhook, an ntfy topic and a mailbox.
#[tokio::test]
async fn real_alert_reaches_webhook_ntfy_and_mail_sinks() {
    let s = store().await;
    let state = AppState::new(s.clone(), Arc::new(super::firewall::NoopApplier))
        .await
        .unwrap();
    let web = http_sink(Mode::Status(vec![200])).await;
    let ntfy = http_sink(Mode::Status(vec![200])).await;
    let mail = smtp_sink(false).await;
    let ntfy_url = format!("http://{}/patronus-alerts", ntfy.addr);
    telemetry::save_channel(&s, &spec("webhook", &web.url(), "s3cret-key", "", ""))
        .await
        .unwrap();
    telemetry::save_channel(&s, &spec("ntfy", &ntfy_url, "tk_token", "", ""))
        .await
        .unwrap();
    telemetry::save_channel(
        &s,
        &spec(
            "email",
            &format!("smtp://{}", mail.addr),
            "",
            "ops@example.test,noc@example.test",
            "fw@example.test",
        ),
    )
    .await
    .unwrap();

    let mut w = Watcher::new(state.clone());
    assert!(w.tick().await.is_empty(), "first look is the baseline");
    state
        .config_store
        .snapshot("web", "before alert proof")
        .await
        .unwrap();
    let events = w.tick().await;
    let ev = events
        .iter()
        .find(|e| e.kind == "config_changed")
        .expect("the watcher saw the configuration change");
    assert!(ev.id > 0, "the event was recorded");

    // --- webhook: the signed JSON document ---
    let h = &web.wait_hits(1).await[0];
    assert!(h.head.starts_with("POST /hook "), "{}", h.head);
    assert_eq!(
        h.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        h.header("x-patronus-event").as_deref(),
        Some("config_changed")
    );
    let sig = h.header("x-patronus-signature").unwrap();
    assert_eq!(
        sig,
        format!(
            "sha256={}",
            telemetry::hmac_sha256_hex(b"s3cret-key", h.body.as_bytes())
        )
    );
    let v: Value = serde_json::from_str(&h.body).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["detail", "host", "id", "kind", "severity", "subject", "time"]
    );
    assert_eq!(v["kind"], "config_changed");
    assert_eq!(v["id"], ev.id);
    assert_eq!(v["severity"], "info");
    assert_eq!(v["time"], ev.ts);
    assert!(v["detail"]
        .as_str()
        .unwrap()
        .contains("configuration revision"));
    assert!(!v["host"].as_str().unwrap().is_empty());

    // --- ntfy: plain text with Title / Priority / Tags and a bearer token ---
    let h = &ntfy.wait_hits(1).await[0];
    assert!(h.head.starts_with("POST /patronus-alerts "), "{}", h.head);
    assert!(h.header("content-type").unwrap().starts_with("text/plain"));
    assert!(h.header("title").unwrap().contains("INFO: config changed"));
    assert_eq!(h.header("priority").as_deref(), Some("default"));
    assert_eq!(h.header("tags").as_deref(), Some("config_changed"));
    assert_eq!(
        h.header("authorization").as_deref(),
        Some("Bearer tk_token")
    );
    assert!(h.body.contains("configuration revision"), "{}", h.body);

    // --- email: envelope and message ---
    let h = &mail.wait_hits(1).await[0];
    assert!(h.head.contains("MAIL FROM:<fw@example.test>"), "{}", h.head);
    assert!(h.head.contains("RCPT TO:<ops@example.test>"), "{}", h.head);
    assert!(h.head.contains("RCPT TO:<noc@example.test>"), "{}", h.head);
    assert!(h.body.contains("Subject: ["), "{}", h.body);
    assert!(h.body.contains("INFO: config changed"), "{}", h.body);
    assert!(h.body.contains("X-Patronus-Event: config_changed"));
    assert!(h.body.contains("configuration revision"));

    // every hook notes "ok"; nothing was audited as failed
    for _ in 0..100 {
        let hs = telemetry::hooks(&s).await.unwrap();
        if hs.iter().all(|h| h.last_result.as_deref() == Some("ok")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for h in telemetry::hooks(&s).await.unwrap() {
        assert_eq!(h.last_result.as_deref(), Some("ok"), "{}", h.name);
    }
    assert!(audit_rows(&s, "alert_delivery_failed").await.is_empty());
}

/// A gateway going down (critical) maps to ntfy "urgent" and the
/// webhook severity, and a hook's minimum severity filters.
#[tokio::test]
async fn critical_event_priority_and_severity_filter() {
    let s = store().await;
    let ntfy = http_sink(Mode::Status(vec![200])).await;
    let mut sp = spec("ntfy", &ntfy.url(), "", "", "");
    sp.min_severity = "critical".into();
    telemetry::save_channel(&s, &sp).await.unwrap();
    let mut info = test_event();
    info.severity = "info".into();
    info.kind = "gateway_up".into();
    let prev: std::collections::BTreeMap<String, String> =
        [("gateway:WAN".to_string(), "up".to_string())].into();
    let cur: std::collections::BTreeMap<String, String> =
        [("gateway:WAN".to_string(), "down".to_string())].into();
    let mut real = telemetry::diff(&prev, &cur);
    assert_eq!(real[0].kind, "gateway_down");
    let e = &mut real[0];
    e.id = telemetry::record(&s, e).await.unwrap();
    telemetry::deliver(s.clone(), info).await; // below the minimum: not sent
    telemetry::deliver(s.clone(), e.clone()).await;
    let h = &ntfy.wait_hits(1).await[0];
    assert_eq!(h.header("priority").as_deref(), Some("urgent"));
    assert_eq!(h.header("tags").as_deref(), Some("gateway_down"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ntfy.hits().len(), 1, "the info event was filtered");
}

fn gaps(hits: &[Hit]) -> Vec<Duration> {
    hits.windows(2).map(|w| w[1].at - w[0].at).collect()
}

async fn one_hook(s: &ConfigStore, sp: &HookSpec) -> telemetry::Hook {
    telemetry::save_channel(s, sp).await.unwrap();
    telemetry::hooks(s).await.unwrap().remove(0)
}

#[tokio::test]
async fn http_500_is_retried_with_backoff_then_audited() {
    let s = store().await;
    let p = fast_policy(&s, 3, 150).await;
    let sink = http_sink(Mode::Status(vec![500])).await;
    let hook = one_hook(&s, &spec("webhook", &sink.url(), "", "", "")).await;
    let r = telemetry::deliver_hook(&s, "fw1", &hook, &test_event(), &p).await;
    let hits = sink.hits();
    assert_eq!(hits.len(), 3, "three attempts");
    let g = gaps(&hits);
    assert!(
        g[0] >= Duration::from_millis(150),
        "first backoff {:?}",
        g[0]
    );
    assert!(
        g[1] >= Duration::from_millis(300),
        "second backoff {:?}",
        g[1]
    );
    assert!(r.starts_with("attempt 3:"), "{r}");
    let rows = audit_rows(&s, "alert_delivery_failed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, hook.id.to_string());
    assert_eq!(rows[0].1["attempts"], 3);
    assert_eq!(rows[0].1["channel"], "webhook");
    assert_eq!(rows[0].1["event_kind"], "gateway_down");
    assert_eq!(
        telemetry::hooks(&s).await.unwrap()[0]
            .last_result
            .as_deref(),
        Some(r.as_str())
    );
}

#[tokio::test]
async fn a_sink_that_recovers_gets_the_alert_and_nothing_is_audited() {
    let s = store().await;
    let p = fast_policy(&s, 3, 20).await;
    let sink = http_sink(Mode::Status(vec![500, 503, 200])).await;
    let hook = one_hook(&s, &spec("ntfy", &sink.url(), "", "", "")).await;
    let r = telemetry::deliver_hook(&s, "fw1", &hook, &test_event(), &p).await;
    assert_eq!(r, "ok");
    assert_eq!(sink.hits().len(), 3);
    assert!(audit_rows(&s, "alert_delivery_failed").await.is_empty());
}

#[tokio::test]
async fn a_hanging_sink_times_out_per_the_configured_limit_and_is_audited() {
    let s = store().await;
    let p = fast_policy(&s, 2, 20).await; // http timeout 1 s
    let sink = http_sink(Mode::Hang).await;
    let hook = one_hook(&s, &spec("webhook", &sink.url(), "", "", "")).await;
    let t = Instant::now();
    let r = telemetry::deliver_hook(&s, "fw1", &hook, &test_event(), &p).await;
    let took = t.elapsed();
    assert_eq!(sink.hits().len(), 2, "both attempts reached the sink");
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(10),
        "{took:?}"
    );
    assert!(r.starts_with("attempt 2:"), "{r}");
    assert!(
        r.to_lowercase().contains("timed out") || r.contains("28"),
        "{r}"
    );
    assert_eq!(audit_rows(&s, "alert_delivery_failed").await.len(), 1);
}

#[tokio::test]
async fn a_refused_connection_is_retried_and_audited() {
    let s = store().await;
    let p = fast_policy(&s, 3, 50).await;
    let hook = one_hook(&s, &spec("webhook", &refused_url().await, "", "", "")).await;
    let t = Instant::now();
    let r = telemetry::deliver_hook(&s, "fw1", &hook, &test_event(), &p).await;
    assert!(
        t.elapsed() >= Duration::from_millis(150),
        "50 + 100 ms of backoff"
    );
    assert!(r.starts_with("attempt 3:"), "{r}");
    let rows = audit_rows(&s, "alert_delivery_failed").await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].1["error"].as_str().unwrap().contains("attempt 3"));
}

#[tokio::test]
async fn a_rejecting_mail_server_is_retried_and_audited() {
    let s = store().await;
    let p = fast_policy(&s, 2, 20).await;
    let mail = smtp_sink(true).await;
    let hook = one_hook(
        &s,
        &spec(
            "email",
            &format!("smtp://{}", mail.addr),
            "",
            "ops@example.test",
            "fw@example.test",
        ),
    )
    .await;
    let r = telemetry::deliver_hook(&s, "fw1", &hook, &test_event(), &p).await;
    assert_eq!(mail.wait_hits(2).await.len(), 2, "two SMTP sessions");
    assert!(r.starts_with("attempt 2:"), "{r}");
    let rows = audit_rows(&s, "alert_delivery_failed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1["channel"], "email");
}
