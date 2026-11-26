//! Status summary, Prometheus metrics, the event log and outbound
//! webhooks (lane H), for monitoring systems such as Rustinion:
//!
//! - [`summary`]: one JSON document with the facts a collector needs
//!   (gateways, tunnels, conntrack, DHCP leases, services, HA, firewall
//!   rule fingerprint, last configuration change).
//! - [`prometheus`]: the same as OpenMetrics text (`GET /metrics`).
//! - [`Watcher`]: every few seconds compares the live state with the last
//!   look and records an event (`system_events`) for each change:
//!   gateway up/down/degraded, gateway-group failover, tunnel up/down, HA
//!   state change, configuration change. Each event is POSTed to the
//!   enabled webhooks (`event_hooks`), signed with HMAC-SHA256 in
//!   `X-Patronus-Signature: sha256=<hex>`.
//! - Notification channels on the same table (`event_hooks.channel`): besides
//!   the signed JSON webhook, a readable message to ntfy, Telegram, Discord,
//!   Slack or email (SMTP with STARTTLS or implicit TLS), filtered by event
//!   kind and minimum severity, with a "send test" per channel.

use super::{host, AppState};
use patronus_config::ConfigStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use patronus_config::notify_matcher as matcher;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Events kept in the store.
const KEEP_EVENTS: i64 = 2000;

// ---------------------------------------------------------------------------
// events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub detail: String,
}

fn ev(kind: &str, subject: &str, severity: &str, detail: String) -> Event {
    Event {
        id: 0,
        ts: chrono::Utc::now().timestamp(),
        kind: kind.into(),
        subject: subject.into(),
        severity: severity.into(),
        detail,
    }
}

/// What changed between two looks. Keys are `gateway:<name>`,
/// `group:<name>` (active members), `tunnel:<name>`, `ha:state`; values
/// are the state strings. A key that is new is only reported when its
/// state is a problem (a tunnel that never came up is not news; a gateway
/// that appears down is).
pub fn diff(prev: &BTreeMap<String, String>, cur: &BTreeMap<String, String>) -> Vec<Event> {
    let mut out = Vec::new();
    for (k, new) in cur {
        let old = prev.get(k);
        if old == Some(new) {
            continue;
        }
        let Some((class, name)) = k.split_once(':') else {
            continue;
        };
        match class {
            "gateway" => {
                let was = old.map(String::as_str).unwrap_or("");
                let (kind, sev) = match new.as_str() {
                    "down" => ("gateway_down", "critical"),
                    "loss" | "latency" => ("gateway_degraded", "warning"),
                    "online" | "unmonitored" if matches!(was, "down" | "loss" | "latency") => {
                        ("gateway_up", "info")
                    }
                    _ => continue,
                };
                out.push(ev(
                    kind,
                    name,
                    sev,
                    format!(
                        "gateway {name}: {} -> {new}",
                        if was.is_empty() { "unknown" } else { was }
                    ),
                ));
            }
            "group" => {
                if let Some(old) = old {
                    out.push(ev(
                        "group_failover",
                        name,
                        "warning",
                        format!(
                            "gateway group {name}: active {} -> {}",
                            if old.is_empty() { "(none)" } else { old },
                            if new.is_empty() { "(none)" } else { new }
                        ),
                    ));
                }
            }
            "tunnel" => {
                let up = new == "up";
                let was_up = old.is_some_and(|o| o == "up");
                if up || was_up {
                    out.push(ev(
                        if up { "tunnel_up" } else { "tunnel_down" },
                        name,
                        if up { "info" } else { "warning" },
                        format!("tunnel {name} is {new}"),
                    ));
                }
            }
            "ha" => {
                // a state appearing for the first time (HA just came up) is news too
                out.push(ev(
                    "ha_state",
                    name,
                    if new == "MASTER" { "warning" } else { "info" },
                    format!(
                        "HA state {} -> {new}",
                        old.map_or("unknown", String::as_str)
                    ),
                ));
            }
            _ => {}
        }
    }
    // a tunnel / gateway that vanished from the list while up is not
    // reported: the configuration changed (reported as config_changed)
    out
}

pub async fn record(store: &ConfigStore, e: &Event) -> anyhow::Result<i64> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let r = sqlx::query(
        "INSERT INTO system_events (ts, kind, subject, severity, detail) VALUES (?,?,?,?,?)",
    )
    .bind(e.ts)
    .bind(&e.kind)
    .bind(&e.subject)
    .bind(&e.severity)
    .bind(&e.detail)
    .execute(pool)
    .await?;
    let id = r.last_insert_rowid();
    sqlx::query("DELETE FROM system_events WHERE id <= ?")
        .bind(id - KEEP_EVENTS)
        .execute(pool)
        .await?;
    Ok(id)
}

/// Events newer than `after_id`, oldest first (so a collector can resume
/// with the last id it saw), optionally one `kind`.
pub async fn events(
    store: &ConfigStore,
    after_id: i64,
    kind: Option<&str>,
    limit: i64,
) -> anyhow::Result<Vec<Event>> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let rows = sqlx::query(
        "SELECT id, ts, kind, subject, severity, detail FROM system_events
         WHERE id > ? AND (? IS NULL OR kind = ?) ORDER BY id ASC LIMIT ?",
    )
    .bind(after_id)
    .bind(kind)
    .bind(kind)
    .bind(limit.clamp(1, 1000))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Event {
            id: r.get(0),
            ts: r.get(1),
            kind: r.get(2),
            subject: r.get(3),
            severity: r.get(4),
            detail: r.get(5),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// webhooks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Hook {
    pub id: i64,
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub secret: String,
    pub has_secret: bool,
    pub kinds: String,
    pub enabled: bool,
    pub last_attempt_at: Option<i64>,
    pub last_result: Option<String>,
    /// webhook | ntfy | telegram | discord | slack | email
    pub channel: String,
    /// Telegram chat id, or the email recipients (comma separated)
    pub target: String,
    /// email From address
    pub sender: String,
    /// SMTP login (the password is the secret)
    pub username: String,
    /// info | warning | critical: events below it are not sent
    pub min_severity: String,
    /// Name of the notification matcher (`notify_matchers`) that decides which
    /// events this channel gets; empty = the channel's own kinds + min_severity.
    pub matcher: String,
}

/// Notification channel types (`event_hooks.channel`).
pub const CHANNELS: &[&str] = &["webhook", "ntfy", "telegram", "discord", "slack", "email"];
pub const SEVERITIES: &[&str] = &["info", "warning", "critical"];
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// A channel as entered in the UI / API.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HookSpec {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub kinds: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub min_severity: String,
    /// Existing matcher to use; empty = build one from `kinds` + `min_severity`.
    #[serde(default)]
    pub matcher: String,
}

pub async fn hooks(store: &ConfigStore) -> anyhow::Result<Vec<Hook>> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let rows = sqlx::query(
        "SELECT id, name, url, secret, kinds, enabled, last_attempt_at, last_result,
                channel, target, sender, username, min_severity, matcher
         FROM event_hooks ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let secret: String = r.get(3);
            Hook {
                id: r.get(0),
                name: r.get(1),
                url: r.get(2),
                has_secret: !secret.is_empty(),
                secret,
                kinds: r.get(4),
                enabled: r.get::<i64, _>(5) != 0,
                last_attempt_at: r.get(6),
                last_result: r.get(7),
                channel: r.get(8),
                target: r.get(9),
                sender: r.get(10),
                username: r.get(11),
                min_severity: r.get(12),
                matcher: r.get(13),
            }
        })
        .collect())
}

pub const EVENT_KINDS: &[&str] = &[
    "gateway_down",
    "gateway_up",
    "gateway_degraded",
    "uplink_probe_failed",
    "uplink_probe_recovered",
    "uplink_sla_breach",
    "uplink_sla_ok",
    "group_failover",
    "tunnel_up",
    "tunnel_down",
    "ha_state",
    "config_changed",
    "data_cap",
    "test",
];

/// A plain signed JSON webhook (the original API).
pub async fn save_hook(
    store: &ConfigStore,
    name: &str,
    url: &str,
    secret: &str,
    kinds: &str,
) -> anyhow::Result<i64> {
    save_channel(
        store,
        &HookSpec {
            name: name.into(),
            url: url.into(),
            secret: secret.into(),
            kinds: kinds.into(),
            ..Default::default()
        },
    )
    .await
}

fn one_line(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

/// `local@domain` with conservative characters.
pub fn valid_email(a: &str) -> bool {
    let Some((l, d)) = a.split_once('@') else {
        return false;
    };
    !l.is_empty()
        && l.len() <= 64
        && l.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && d.contains('.')
        && d.len() <= 253
        && d.split('.').all(|x| {
            !x.is_empty()
                && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !x.starts_with('-')
        })
}

/// Validate a channel: the checked row values
/// (channel, url, target, sender, username, min_severity, kinds).
#[allow(clippy::type_complexity)]
pub fn check_spec(
    h: &HookSpec,
) -> anyhow::Result<(String, String, String, String, String, String, String)> {
    let name = h.name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
    {
        anyhow::bail!(
            "Invalid webhook name {name:?}: 1-40 letters, digits, '-', '_', '.' or spaces"
        );
    }
    let channel = match h.channel.trim() {
        "" => "webhook",
        c if CHANNELS.contains(&c) => c,
        c => anyhow::bail!("Invalid channel {c:?}: one of {}", CHANNELS.join(", ")),
    };
    let mut url = h.url.trim().to_string();
    if channel == "telegram" && url.is_empty() {
        url = TELEGRAM_API.into();
    }
    let bad_url = url.len() > 500
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\');
    if channel == "email" {
        let rest = url
            .strip_prefix("smtps://")
            .or_else(|| url.strip_prefix("smtp://"));
        let host_ok = rest.is_some_and(|r| {
            let r = r.trim_end_matches('/');
            !r.is_empty()
                && !r.contains('/')
                && !r.contains('@')
                && r.chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c))
        });
        if bad_url || !host_ok {
            anyhow::bail!(
                "Invalid mail server: smtp://host[:port] (STARTTLS when offered) or smtps://host[:port] (TLS)"
            );
        }
    } else if bad_url || !(url.starts_with("http://") || url.starts_with("https://")) {
        anyhow::bail!("Invalid webhook URL: an http:// or https:// address");
    }
    if h.secret.len() > 200 || h.secret.chars().any(|c| c.is_control()) {
        anyhow::bail!("Invalid secret: up to 200 printable characters");
    }
    let target = h.target.trim().to_string();
    let sender = h.sender.trim().to_string();
    let username = h.username.trim().to_string();
    match channel {
        "telegram" => {
            let tok = h.secret.trim();
            if tok.is_empty()
                || !tok
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ":_-".contains(c))
            {
                anyhow::bail!("Invalid Telegram bot token (from @BotFather, put it in the secret)");
            }
            let t = target.strip_prefix('@').unwrap_or(&target);
            let id_ok = !t.is_empty()
                && if target.starts_with('@') {
                    t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                } else {
                    t.strip_prefix('-')
                        .unwrap_or(t)
                        .chars()
                        .all(|c| c.is_ascii_digit())
                };
            if !id_ok || target.len() > 64 {
                anyhow::bail!(
                    "Invalid Telegram chat id: a number (-100... for groups) or @channel"
                );
            }
        }
        "email" => {
            if !valid_email(&sender) {
                anyhow::bail!("Invalid sender address {sender:?}");
            }
            let rcpts: Vec<&str> = target
                .split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .collect();
            if rcpts.is_empty() || rcpts.len() > 10 || !rcpts.iter().all(|r| valid_email(r)) {
                anyhow::bail!("Invalid recipients: 1-10 email addresses, comma separated");
            }
            if !one_line(&username, 100) || username.contains(':') {
                anyhow::bail!("Invalid SMTP user name");
            }
        }
        _ => {
            if !target.is_empty() || !sender.is_empty() || !username.is_empty() {
                anyhow::bail!(
                    "Invalid fields: recipient/sender/user only apply to Telegram or email"
                );
            }
        }
    }
    let min = match h.min_severity.trim() {
        "" => "info",
        m if SEVERITIES.contains(&m) => m,
        m => anyhow::bail!("Invalid minimum severity {m:?}: info, warning or critical"),
    };
    let mut ks = Vec::new();
    for k in h
        .kinds
        .split([',', ' '])
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        if !EVENT_KINDS.contains(&k) {
            anyhow::bail!(
                "Invalid event kind {k:?}: one of {}",
                EVENT_KINDS.join(", ")
            );
        }
        ks.push(k);
    }
    let target = if channel == "email" {
        target
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        target
    };
    Ok((
        channel.to_string(),
        url,
        target,
        sender,
        username,
        min.to_string(),
        ks.join(","),
    ))
}

/// Store a notification channel (any type). Errors starting with
/// "Invalid" are the caller's fault.
pub async fn save_channel(store: &ConfigStore, h: &HookSpec) -> anyhow::Result<i64> {
    let (channel, url, target, sender, username, min, kinds) = check_spec(h)?;
    let name = h.name.trim();
    let wanted = h.matcher.trim();
    if !wanted.is_empty() && matcher::get_tree(store, wanted).await?.is_none() {
        anyhow::bail!("Invalid matcher {wanted:?}: no such notification matcher");
    }
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let r = sqlx::query(
        "INSERT INTO event_hooks (name, url, secret, kinds, enabled, created_at, channel, target, \
         sender, username, min_severity, matcher) VALUES (?,?,?,?,1,?,?,?,?,?,?,?)",
    )
    .bind(name)
    .bind(url)
    .bind(h.secret.trim())
    .bind(&kinds)
    .bind(chrono::Utc::now().timestamp())
    .bind(channel)
    .bind(target)
    .bind(sender)
    .bind(username)
    .bind(&min)
    .bind(wanted)
    .execute(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            anyhow::anyhow!("Invalid webhook name: {name} already exists")
        } else {
            anyhow::anyhow!("saving the webhook: {e}")
        }
    })?;
    let id = r.last_insert_rowid();
    if wanted.is_empty() {
        // the channel's own kinds + minimum severity, as a matcher
        let auto = format!("auto-{name}");
        matcher::upsert(
            store,
            &auto,
            "Built from the channel's event kinds and minimum severity",
            matcher::Matcher::legacy(&kinds, &min),
            EVENT_KINDS,
        )
        .await?;
        sqlx::query("UPDATE event_hooks SET matcher=? WHERE id=?")
            .bind(&auto)
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(id)
}

/// Point a channel at another matcher (`""` = back to its own kinds +
/// minimum severity).
pub async fn set_hook_matcher(
    store: &ConfigStore,
    id: i64,
    name: &str,
) -> anyhow::Result<bool> {
    let name = name.trim();
    if !name.is_empty() && matcher::get_tree(store, name).await?.is_none() {
        anyhow::bail!("Invalid matcher {name:?}: no such notification matcher");
    }
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    Ok(sqlx::query("UPDATE event_hooks SET matcher=? WHERE id=?")
        .bind(name)
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        > 0)
}

pub async fn delete_hook(store: &ConfigStore, id: i64) -> anyhow::Result<bool> {
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let own: Option<(String, String)> =
        sqlx::query_as("SELECT name, matcher FROM event_hooks WHERE id=?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let deleted = delete_hook_row(pool, id).await?;
    if let Some((name, m)) = own {
        // the matcher built for this channel goes with it (a shared one stays)
        if deleted && m == format!("auto-{name}") {
            let _ = matcher::delete(store, &m).await;
        }
    }
    Ok(deleted)
}

async fn delete_hook_row(pool: &sqlx::SqlitePool, id: i64) -> anyhow::Result<bool> {
    Ok(sqlx::query("DELETE FROM event_hooks WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
        > 0)
}

/// HMAC-SHA256 (RFC 2104), hex.
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A double-quoted curl config value: backslash, quote and line breaks
/// escaped (curl's config parser understands \\ \" \n \r \t), so a
/// multi-line message body can never end the value and start an option.
pub fn curl_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// POST `body` to `url` with curl (headers, and so the signature, on
/// stdin rather than in `ps`). Ok on a 2xx answer.
pub async fn post_json(url: &str, headers: &[String], body: &str) -> anyhow::Result<()> {
    post_body(url, "application/json", headers, body).await
}

/// POST with any content type (ntfy takes plain text).
pub async fn post_body(
    url: &str,
    content_type: &str,
    headers: &[String],
    body: &str,
) -> anyhow::Result<()> {
    let mut cfg = format!(
        "url = {}\nrequest = \"POST\"\nsilent\nshow-error\nfail\nmax-time = 15\n\
         user-agent = \"Patronus-Events/1.0\"\nheader = {}\n",
        curl_quote(url),
        curl_quote(&format!("Content-Type: {content_type}"))
    );
    for h in headers {
        cfg.push_str(&format!("header = {}\n", curl_quote(h)));
    }
    cfg.push_str(&format!("data-binary = {}\n", curl_quote(body)));
    run_curl(cfg).await
}

/// Run curl with a config on stdin (secrets never in `ps`).
async fn run_curl(cfg: String) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("curl")
        .args(["-K", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot run curl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(cfg.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim())
    }
}

/// One readable line for chat/push channels, and a subject for email.
pub fn message_text(host: &str, e: &Event) -> (String, String) {
    let sev = e.severity.to_uppercase();
    let subject = if e.subject.is_empty() {
        format!("[{host}] {sev}: {}", e.kind.replace('_', " "))
    } else {
        format!("[{host}] {sev}: {} {}", e.kind.replace('_', " "), e.subject)
    };
    let when = chrono::DateTime::from_timestamp(e.ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default();
    let body = if e.detail.is_empty() {
        format!("{subject}\n{when}")
    } else {
        format!("{subject}\n{}\n{when}", e.detail)
    };
    (subject, body)
}

/// What one delivery sends.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    Http {
        url: String,
        content_type: &'static str,
        headers: Vec<String>,
        body: String,
    },
    Mail {
        url: String,
        from: String,
        rcpts: Vec<String>,
        user: Option<(String, String)>,
        message: String,
    },
}

/// Build the delivery of `e` to `hook` for its channel type.
pub fn request(host: &str, hook: &Hook, e: &Event) -> Request {
    let (subject, text) = message_text(host, e);
    let json_req = |url: &str, body: Value| Request::Http {
        url: url.to_string(),
        content_type: "application/json",
        headers: vec![],
        body: body.to_string(),
    };
    match hook.channel.as_str() {
        "ntfy" => {
            let prio = match e.severity.as_str() {
                "critical" => "urgent",
                "warning" => "high",
                _ => "default",
            };
            let mut headers = vec![
                format!("Title: {}", subject.replace(['\r', '\n'], " ")),
                format!("Priority: {prio}"),
                format!("Tags: {}", e.kind),
            ];
            if hook.has_secret {
                headers.push(format!("Authorization: Bearer {}", hook.secret));
            }
            Request::Http {
                url: hook.url.clone(),
                content_type: "text/plain; charset=utf-8",
                headers,
                body: text,
            }
        }
        "telegram" => json_req(
            &format!(
                "{}/bot{}/sendMessage",
                hook.url.trim_end_matches('/'),
                hook.secret
            ),
            json!({"chat_id": hook.target, "text": text, "disable_web_page_preview": true}),
        ),
        "discord" => json_req(&hook.url, json!({"content": text, "username": "Patronus"})),
        "slack" => json_req(&hook.url, json!({"text": text})),
        "email" => {
            let rcpts: Vec<String> = hook.target.split(',').map(String::from).collect();
            let date = chrono::DateTime::from_timestamp(e.ts, 0)
                .unwrap_or_default()
                .to_rfc2822();
            let message = format!(
                "From: Patronus <{}>\r\nTo: {}\r\nSubject: {}\r\nDate: {date}\r\n\
                 MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Transfer-Encoding: 8bit\r\nX-Patronus-Event: {}\r\n\r\n{}\r\n",
                hook.sender,
                rcpts.join(", "),
                subject.replace(['\r', '\n'], " "),
                e.kind,
                text.replace('\n', "\r\n")
            );
            Request::Mail {
                url: hook.url.clone(),
                from: hook.sender.clone(),
                rcpts,
                user: (!hook.username.is_empty())
                    .then(|| (hook.username.clone(), hook.secret.clone())),
                message,
            }
        }
        _ => {
            let (body, headers) = delivery(host, hook, e);
            Request::Http {
                url: hook.url.clone(),
                content_type: "application/json",
                headers,
                body,
            }
        }
    }
}

/// Send one delivery (one attempt).
pub async fn send(req: &Request) -> anyhow::Result<()> {
    match req {
        Request::Http {
            url,
            content_type,
            headers,
            body,
        } => post_body(url, content_type, headers, body).await,
        Request::Mail {
            url,
            from,
            rcpts,
            user,
            message,
        } => {
            // the message goes through a private temp file (curl reads the
            // config, with the password, from stdin)
            let path = std::env::temp_dir().join(format!(
                "patronus-mail-{}-{}.eml",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                f.write_all(message.as_bytes())?;
            }
            let mut cfg = format!(
                "url = {}\nsilent\nshow-error\nmax-time = 30\nmail-from = {}\nupload-file = {}\n",
                curl_quote(url),
                curl_quote(from),
                curl_quote(&path.to_string_lossy())
            );
            if url.starts_with("smtp://") {
                // STARTTLS whenever the server offers it
                cfg.push_str("ssl\n");
            }
            for r in rcpts {
                cfg.push_str(&format!("mail-rcpt = {}\n", curl_quote(r)));
            }
            if let Some((u, p)) = user {
                cfg.push_str(&format!("user = {}\n", curl_quote(&format!("{u}:{p}"))));
            }
            let r = run_curl(cfg).await;
            let _ = std::fs::remove_file(&path);
            r
        }
    }
}

fn severity_rank(s: &str) -> usize {
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(0)
}

/// The body and headers of one delivery.
pub fn delivery(host: &str, hook: &Hook, e: &Event) -> (String, Vec<String>) {
    let body = json!({
        "id": e.id, "time": e.ts, "kind": e.kind, "subject": e.subject,
        "severity": e.severity, "detail": e.detail, "host": host,
    })
    .to_string();
    let mut headers = vec![format!("X-Patronus-Event: {}", e.kind)];
    if hook.has_secret {
        headers.push(format!(
            "X-Patronus-Signature: sha256={}",
            hmac_sha256_hex(hook.secret.as_bytes(), body.as_bytes())
        ));
    }
    (body, headers)
}

fn wants(hook: &Hook, kind: &str) -> bool {
    hook.enabled && (hook.kinds.is_empty() || hook.kinds.split(',').any(|k| k == kind))
}

/// Does `hook` get `e`? A channel with a matcher follows the matcher (a name
/// that no longer resolves falls back to the channel's own kinds + minimum
/// severity: a lost notification is worse than an extra one); `local` is the
/// box's wall-clock time for calendar leaves.
fn wants_event(
    hook: &Hook,
    e: &Event,
    matchers: &HashMap<String, matcher::Matcher>,
    local: chrono::NaiveDateTime,
) -> bool {
    if !hook.enabled {
        return false;
    }
    match matchers.get(&hook.matcher) {
        Some(m) => m.matches(&matcher::EventCtx {
            kind: &e.kind,
            severity: &e.severity,
            subject: &e.subject,
            local,
        }),
        None => wants(hook, &e.kind) && severity_rank(&e.severity) >= severity_rank(&hook.min_severity),
    }
}

/// Matchers by name.
async fn matcher_map(store: &ConfigStore) -> HashMap<String, matcher::Matcher> {
    matcher::list(store)
        .await
        .map(|l| l.into_iter().map(|m| (m.name, m.tree)).collect())
        .unwrap_or_default()
}

/// One past event judged by a matcher tree.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewRow {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub matched: bool,
}

/// How many past events a preview judges (typed: `notify.preview_events`).
pub const DEFAULT_PREVIEW_EVENTS: i64 = 50;

/// "Would match" preview: the last events of `system_events`, newest first,
/// each judged by `tree` at the box-local time it happened.
pub async fn preview(store: &ConfigStore, tree: &matcher::Matcher) -> anyhow::Result<Vec<PreviewRow>> {
    use chrono::TimeZone;
    let n = store
        .load_system_config("notify.preview_events")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| (1..=1000).contains(n))
        .unwrap_or(DEFAULT_PREVIEW_EVENTS);
    let pool = store.pool().map_err(|x| anyhow::anyhow!("{x}"))?;
    let rows = sqlx::query(
        "SELECT id, ts, kind, subject, severity FROM system_events ORDER BY id DESC LIMIT ?",
    )
    .bind(n)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let ts: i64 = r.get(1);
            let (kind, subject, severity): (String, String, String) = (r.get(2), r.get(3), r.get(4));
            let local = chrono::Local
                .timestamp_opt(ts, 0)
                .single()
                .map(|d| d.naive_local())
                .unwrap_or_default();
            let matched = tree.matches(&matcher::EventCtx {
                kind: &kind,
                severity: &severity,
                subject: &subject,
                local,
            });
            PreviewRow {
                id: r.get(0),
                ts,
                kind,
                subject,
                severity,
                matched,
            }
        })
        .collect())
}

async fn note_result(store: &ConfigStore, id: i64, result: &str) {
    if let Ok(pool) = store.pool() {
        let _ = sqlx::query("UPDATE event_hooks SET last_attempt_at=?, last_result=? WHERE id=?")
            .bind(chrono::Utc::now().timestamp())
            .bind(result)
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// Send a test message to one channel now (one attempt) and note the result.
pub async fn send_test(store: &ConfigStore, id: i64) -> anyhow::Result<Option<String>> {
    let Some(h) = hooks(store).await?.into_iter().find(|h| h.id == id) else {
        return Ok(None);
    };
    let e = ev(
        "test",
        &h.name,
        "info",
        "Test message from Patronus: this notification channel works.".into(),
    );
    let r = send(&request(&host::hostname(), &h, &e)).await;
    let result = match &r {
        Ok(()) => "ok".to_string(),
        Err(err) => format!("test: {err}"),
    };
    note_result(store, id, &result).await;
    r.map(|_| Some(result))
}

/// Send `e` to every hook that wants it (up to 3 tries each, 2 s / 6 s
/// apart), and note the outcome on the hook.
pub async fn deliver(store: Arc<ConfigStore>, e: Event) {
    let Ok(all) = hooks(&store).await else { return };
    let me = host::hostname();
    let matchers = matcher_map(&store).await;
    // the box's local time; PATRONUS_FAKE_TIME_FILE moves it in tests
    let local = patronus_firewall::schedule::now();
    for h in all.into_iter().filter(|h| wants_event(h, &e, &matchers, local)) {
        let (store, e, me) = (store.clone(), e.clone(), me.clone());
        tokio::spawn(async move {
            let req = request(&me, &h, &e);
            let mut result = String::new();
            for (i, wait) in [0u64, 2, 6].iter().enumerate() {
                if *wait > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(*wait)).await;
                }
                match send(&req).await {
                    Ok(()) => {
                        result = "ok".into();
                        break;
                    }
                    Err(err) => {
                        result = format!("attempt {}: {err}", i + 1);
                    }
                }
            }
            note_result(&store, h.id, &result).await;
        });
    }
}

// ---------------------------------------------------------------------------
// live state
// ---------------------------------------------------------------------------

fn conntrack() -> (Option<u64>, Option<u64>) {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    (
        read("/proc/sys/net/netfilter/nf_conntrack_count"),
        read("/proc/sys/net/netfilter/nf_conntrack_max"),
    )
}

/// A fingerprint of the firewall + NAT rule set (changes when a rule is
/// added, edited, reordered or removed), for drift detection. Reads only
/// those two tables: the event watcher calls it every 10 s, and a full
/// configuration export there cost tens of MB per call on small routers.
pub async fn rules_hash(store: &ConfigStore) -> String {
    let Ok(doc) = store
        .export_tables_json(&["firewall_rules", "nat_rules"])
        .await
    else {
        return String::new();
    };
    let mut h = Sha256::new();
    if let Some(t) = doc.get("tables").and_then(Value::as_object) {
        for name in ["firewall_rules", "nat_rules"] {
            if let Some(rows) = t.get(name) {
                // volatile columns do not count
                let s = rows.to_string();
                h.update(name.as_bytes());
                h.update(s.as_bytes());
            }
        }
    }
    h.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn wg_names(store: &ConfigStore) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Ok(pool) = store.pool() {
        if let Ok(rows) = sqlx::query("SELECT public_key, name FROM wg_peers")
            .fetch_all(pool)
            .await
        {
            for r in rows {
                m.insert(r.get::<String, _>(0), r.get::<String, _>(1));
            }
        }
    }
    m
}

/// Everything a collector wants, read live.
pub async fn summary(state: &AppState) -> Value {
    let store = &state.config_store;
    let routing = state.routing.status().await.unwrap_or(Value::Null);
    let vpn = state.vpn.snapshot().await;
    let names = wg_names(store).await;
    let (ct, ct_max) = conntrack();
    let dhcp = state.lan.status("dhcp").await.unwrap_or(Value::Null);
    let leases = dhcp
        .get("leases")
        .and_then(Value::as_array)
        .map(|a| a.len());
    let services: Vec<Value> = state
        .system
        .list_services()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| json!({"name": s.name, "running": s.is_running}))
        .collect();
    let revisions = store.list_revisions().await.unwrap_or_default();
    let last_rev = revisions.first().map(
        |(id, at, user, summary)| json!({"id": id, "at": at, "user": user, "summary": summary}),
    );
    let load = host::load_average();
    let mem = host::memory();
    let gateways: Vec<Value> = routing
        .get("gateways")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            json!({
                "name": g["name"], "interface": g["interface"], "dev": g["dev"],
                "address": g["resolved_address"], "state": g["state"],
                "rtt_ms": g["rtt_ms"], "loss_pct": g["loss_pct"], "since": g["since"],
                "link_up": g["link_up"],
            })
        })
        .collect();
    let groups: Vec<Value> = routing
        .get("groups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            let active: Vec<Value> = g["members"]
                .as_array()
                .map(|m| {
                    m.iter()
                        .filter(|x| x["active"] == true)
                        .map(|x| x["gateway"].clone())
                        .collect()
                })
                .unwrap_or_default();
            json!({"name": g["name"], "active": active})
        })
        .collect();
    let wireguard: Vec<Value> = vpn
        .wg_peers
        .iter()
        .map(|p| {
            json!({
                "interface": p.interface,
                "peer": names.get(&p.public_key).cloned().unwrap_or_else(|| p.public_key.chars().take(8).collect()),
                "public_key": p.public_key,
                "connected": p.connected,
                "handshake_age_secs": p.handshake_age_secs,
                "endpoint": p.endpoint,
            })
        })
        .collect();
    let ipsec: Vec<Value> = vpn
        .ipsec_tunnels
        .iter()
        .map(|t| json!({"name": t.name, "status": t.status, "established": t.status.eq_ignore_ascii_case("ESTABLISHED")}))
        .collect();
    json!({
        "product": "patronus",
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": host::hostname(),
        "time": chrono::Utc::now().timestamp(),
        "uptime_secs": host::uptime_secs(),
        "load": load.map(|l| json!([l.0, l.1, l.2])),
        "memory_used_percent": mem.map(|m| m.0),
        "disk_used_percent": host::disk_percent("/"),
        "firewall": {
            "active_rules": state.firewall.count_active_rules().await.unwrap_or(0),
            "rules_hash": rules_hash(store).await,
        },
        "config": { "last_change": last_rev, "revisions": revisions.len() },
        "gateways": gateways,
        "gateway_groups": groups,
        "default_via": routing.get("default_via").cloned().unwrap_or(Value::Null),
        "vpn": {
            "active_connections": vpn.active_connections(),
            "wireguard": wireguard,
            "ipsec": ipsec,
            "errors": vpn.read_errors(),
        },
        "conntrack": { "count": ct, "max": ct_max },
        "dhcp": { "leases": leases },
        "services": services,
        "ha": ha_summary(state).await,
    })
}

/// HA state for the summary: null while HA is off or not built.
async fn ha_summary(state: &AppState) -> Value {
    match state.lan.status("ha").await {
        Ok(v) if v["enabled"] == true => json!({
            "enabled": true, "state": v["state"], "since": v["since"],
            "maintenance": v["maintenance"], "keepalived": v["keepalived"],
            "conntrackd": v["conntrackd"], "vips": v["vips"],
        }),
        _ => Value::Null,
    }
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_u64().map(|u| u as f64))
}

/// OpenMetrics / Prometheus text for a [`summary`].
pub fn prometheus(s: &Value) -> String {
    let mut o = String::new();
    let mut m = |name: &str, help: &str, kind: &str, rows: Vec<(String, f64)>| {
        if rows.is_empty() {
            return;
        }
        o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, v) in rows {
            if labels.is_empty() {
                o.push_str(&format!("{name} {v}\n"));
            } else {
                o.push_str(&format!("{name}{{{labels}}} {v}\n"));
            }
        }
    };
    m(
        "patronus_info",
        "Patronus build and host",
        "gauge",
        vec![(
            format!(
                "version=\"{}\",hostname=\"{}\"",
                esc(s["version"].as_str().unwrap_or("")),
                esc(s["hostname"].as_str().unwrap_or(""))
            ),
            1.0,
        )],
    );
    m(
        "patronus_uptime_seconds",
        "Host uptime",
        "gauge",
        num(&s["uptime_secs"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_memory_used_percent",
        "Memory in use",
        "gauge",
        num(&s["memory_used_percent"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_disk_used_percent",
        "Root filesystem in use",
        "gauge",
        num(&s["disk_used_percent"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_firewall_active_rules",
        "Enabled firewall rules",
        "gauge",
        num(&s["firewall"]["active_rules"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    let gws = s["gateways"].as_array().cloned().unwrap_or_default();
    let label = |g: &Value| format!("gateway=\"{}\"", esc(g["name"].as_str().unwrap_or("")));
    m(
        "patronus_gateway_up",
        "1 when the gateway is online (or unmonitored), 0 when down, loss or latency",
        "gauge",
        gws.iter()
            .map(|g| {
                let up = matches!(
                    g["state"].as_str(),
                    Some("online" | "unmonitored" | "pending")
                );
                (label(g), if up { 1.0 } else { 0.0 })
            })
            .collect(),
    );
    m(
        "patronus_gateway_rtt_ms",
        "Gateway round-trip time",
        "gauge",
        gws.iter()
            .filter_map(|g| num(&g["rtt_ms"]).map(|v| (label(g), v)))
            .collect(),
    );
    m(
        "patronus_gateway_loss_percent",
        "Gateway packet loss",
        "gauge",
        gws.iter()
            .filter_map(|g| num(&g["loss_pct"]).map(|v| (label(g), v)))
            .collect(),
    );
    let wg = s["vpn"]["wireguard"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let wl = |p: &Value| {
        format!(
            "interface=\"{}\",peer=\"{}\"",
            esc(p["interface"].as_str().unwrap_or("")),
            esc(p["peer"].as_str().unwrap_or(""))
        )
    };
    m(
        "patronus_wireguard_peer_connected",
        "1 when the peer shook hands in the last 180 s",
        "gauge",
        wg.iter()
            .map(|p| (wl(p), if p["connected"] == true { 1.0 } else { 0.0 }))
            .collect(),
    );
    m(
        "patronus_wireguard_handshake_age_seconds",
        "Seconds since the peer's last handshake",
        "gauge",
        wg.iter()
            .filter_map(|p| num(&p["handshake_age_secs"]).map(|v| (wl(p), v)))
            .collect(),
    );
    m(
        "patronus_ipsec_sa_established",
        "1 when the IPsec tunnel's IKE SA is established",
        "gauge",
        s["vpn"]["ipsec"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|t| {
                (
                    format!("tunnel=\"{}\"", esc(t["name"].as_str().unwrap_or(""))),
                    if t["established"] == true { 1.0 } else { 0.0 },
                )
            })
            .collect(),
    );
    m(
        "patronus_conntrack_entries",
        "Tracked connections",
        "gauge",
        num(&s["conntrack"]["count"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_conntrack_max",
        "Connection tracking table size",
        "gauge",
        num(&s["conntrack"]["max"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_dhcp_leases",
        "Active DHCP leases",
        "gauge",
        num(&s["dhcp"]["leases"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_service_up",
        "1 when the service is running",
        "gauge",
        s["services"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|x| {
                (
                    format!("service=\"{}\"", esc(x["name"].as_str().unwrap_or(""))),
                    if x["running"] == true { 1.0 } else { 0.0 },
                )
            })
            .collect(),
    );
    m(
        "patronus_config_revision",
        "Id of the latest configuration revision",
        "gauge",
        num(&s["config"]["last_change"]["id"])
            .map(|v| (String::new(), v))
            .into_iter()
            .collect(),
    );
    m(
        "patronus_ha_master",
        "1 when this node holds the HA virtual addresses",
        "gauge",
        s["ha"]["state"]
            .as_str()
            .map(|st| (String::new(), if st == "MASTER" { 1.0 } else { 0.0 }))
            .into_iter()
            .collect(),
    );
    o
}

// ---------------------------------------------------------------------------
// the watcher
// ---------------------------------------------------------------------------

/// The state strings [`diff`] compares, from a [`summary`].
pub fn state_vector(s: &Value) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for g in s["gateways"].as_array().into_iter().flatten() {
        if let (Some(n), Some(st)) = (g["name"].as_str(), g["state"].as_str()) {
            m.insert(format!("gateway:{n}"), st.to_string());
        }
    }
    for g in s["gateway_groups"].as_array().into_iter().flatten() {
        if let Some(n) = g["name"].as_str() {
            let mut a: Vec<&str> = g["active"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            a.sort_unstable();
            m.insert(format!("group:{n}"), a.join(","));
        }
    }
    for p in s["vpn"]["wireguard"].as_array().into_iter().flatten() {
        let n = format!(
            "{}/{}",
            p["interface"].as_str().unwrap_or(""),
            p["peer"].as_str().unwrap_or("")
        );
        m.insert(
            format!("tunnel:wg {n}"),
            if p["connected"] == true { "up" } else { "down" }.into(),
        );
    }
    for t in s["vpn"]["ipsec"].as_array().into_iter().flatten() {
        if let Some(n) = t["name"].as_str() {
            m.insert(
                format!("tunnel:ipsec {n}"),
                if t["established"] == true {
                    "up"
                } else {
                    "down"
                }
                .into(),
            );
        }
    }
    if let Some(st) = s["ha"]["state"].as_str() {
        m.insert("ha:state".into(), st.to_string());
    }
    m
}

pub struct Watcher {
    state: AppState,
    prev: Option<BTreeMap<String, String>>,
    last_rev: Option<i64>,
}

impl Watcher {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            prev: None,
            last_rev: None,
        }
    }

    /// One look; records and delivers what changed. Returns the events.
    pub async fn tick(&mut self) -> Vec<Event> {
        let store = self.state.config_store.clone();
        let s = summary(&self.state).await;
        let cur = state_vector(&s);
        let mut out = match &self.prev {
            Some(prev) => diff(prev, &cur),
            None => Vec::new(),
        };
        self.prev = Some(cur);
        let rev = s["config"]["last_change"]["id"].as_i64();
        if let (Some(old), Some(new)) = (self.last_rev, rev) {
            if new != old {
                let what = s["config"]["last_change"]["summary"].as_str().unwrap_or("");
                out.push(ev(
                    "config_changed",
                    "config",
                    "info",
                    format!("configuration revision {new}: {what}"),
                ));
            }
        }
        self.last_rev = rev.or(self.last_rev);
        for e in out.iter_mut() {
            match record(&store, e).await {
                Ok(id) => e.id = id,
                Err(err) => tracing::warn!("recording event {}: {err}", e.kind),
            }
            deliver(store.clone(), e.clone()).await;
        }
        out
    }
}

/// Start the watcher: a look every 10 seconds.
pub fn spawn_watcher(state: AppState) {
    tokio::spawn(async move {
        let mut w = Watcher::new(state);
        let mut t = tokio::time::interval(std::time::Duration::from_secs(10));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            w.tick().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(v: &[(&str, &str)]) -> BTreeMap<String, String> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn kinds(v: &[Event]) -> Vec<(&str, &str)> {
        v.iter()
            .map(|e| (e.kind.as_str(), e.subject.as_str()))
            .collect()
    }

    #[test]
    fn gateway_and_tunnel_changes_become_events() {
        let a = m(&[
            ("gateway:WAN", "online"),
            ("gateway:OPT", "online"),
            ("group:FAIL", "WAN"),
            ("tunnel:wg wg0/phone", "up"),
            ("tunnel:ipsec hq", "down"),
            ("ha:state", "BACKUP"),
        ]);
        assert!(diff(&a, &a).is_empty());
        let b = m(&[
            ("gateway:WAN", "down"),
            ("gateway:OPT", "latency"),
            ("group:FAIL", "OPT"),
            ("tunnel:wg wg0/phone", "down"),
            ("tunnel:ipsec hq", "up"),
            ("ha:state", "MASTER"),
        ]);
        let e = diff(&a, &b);
        assert_eq!(
            kinds(&e),
            vec![
                ("gateway_degraded", "OPT"),
                ("gateway_down", "WAN"),
                ("group_failover", "FAIL"),
                ("ha_state", "state"),
                ("tunnel_up", "ipsec hq"),
                ("tunnel_down", "wg wg0/phone"),
            ]
        );
        assert_eq!(
            e.iter()
                .find(|x| x.kind == "gateway_down")
                .unwrap()
                .severity,
            "critical"
        );
        // recovery
        let c = m(&[("gateway:WAN", "online"), ("gateway:OPT", "online")]);
        let e = diff(&b, &c);
        assert_eq!(kinds(&e).iter().filter(|k| k.0 == "gateway_up").count(), 2);
    }

    #[test]
    fn new_keys_only_matter_when_they_are_a_problem() {
        let prev = BTreeMap::new();
        let cur = m(&[
            ("gateway:A", "online"),
            ("gateway:B", "down"),
            ("tunnel:ipsec x", "down"),
            ("tunnel:ipsec y", "up"),
            ("group:G", "A"),
            ("ha:state", "BACKUP"),
        ]);
        assert_eq!(
            kinds(&diff(&prev, &cur)),
            vec![
                ("gateway_down", "B"),
                ("ha_state", "state"),
                ("tunnel_up", "ipsec y")
            ]
        );
        // a pending gateway turning online is not a recovery
        let e = diff(
            &m(&[("gateway:A", "pending")]),
            &m(&[("gateway:A", "online")]),
        );
        assert!(e.is_empty());
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        assert_eq!(
            hmac_sha256_hex(&[0x0b; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // keys longer than the block size are hashed first
        assert_eq!(
            hmac_sha256_hex(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[tokio::test]
    async fn events_and_hooks_are_stored_and_validated() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        let id1 = record(&store, &ev("gateway_down", "WAN", "critical", "x".into()))
            .await
            .unwrap();
        let id2 = record(&store, &ev("tunnel_up", "hq", "info", "y".into()))
            .await
            .unwrap();
        assert!(id2 > id1);
        let all = events(&store, 0, None, 100).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(events(&store, id1, None, 100).await.unwrap().len(), 1);
        assert_eq!(
            events(&store, 0, Some("tunnel_up"), 100).await.unwrap()[0].subject,
            "hq"
        );

        let h = save_hook(
            &store,
            "rustinion",
            "https://rustinion.example/ev",
            "s3cret",
            "gateway_down, tunnel_down",
        )
        .await
        .unwrap();
        let hs = hooks(&store).await.unwrap();
        assert_eq!(hs[0].kinds, "gateway_down,tunnel_down");
        assert!(hs[0].has_secret);
        assert!(!serde_json::to_string(&hs[0]).unwrap().contains("s3cret"));
        assert!(wants(&hs[0], "gateway_down") && !wants(&hs[0], "tunnel_up"));
        let (body, headers) = delivery("fw1", &hs[0], &all[0]);
        let sig = headers
            .iter()
            .find(|h| h.starts_with("X-Patronus-Signature: sha256="))
            .unwrap();
        assert!(sig.ends_with(&hmac_sha256_hex(b"s3cret", body.as_bytes())));
        for (n, u, k) in [
            ("", "https://a", ""),
            ("x", "ftp://a", ""),
            ("x", "https://a b", ""),
            ("x", "https://a", "nonsense"),
        ] {
            let e = save_hook(&store, n, u, "", k).await.unwrap_err();
            assert!(e.to_string().starts_with("Invalid"), "{n} {u} {k}: {e}");
        }
        assert!(delete_hook(&store, h).await.unwrap());
        assert!(!delete_hook(&store, h).await.unwrap());
    }

    fn spec(channel: &str, url: &str, secret: &str, target: &str, sender: &str) -> HookSpec {
        HookSpec {
            name: format!("c-{channel}"),
            channel: channel.into(),
            url: url.into(),
            secret: secret.into(),
            target: target.into(),
            sender: sender.into(),
            ..Default::default()
        }
    }

    #[test]
    fn curl_config_values_cannot_break_out() {
        assert_eq!(curl_quote("a\nb"), "\"a\\nb\"");
        assert_eq!(curl_quote("x\"\\y\r\t"), "\"x\\\"\\\\y\\r\\t\"");
        assert!(!curl_quote("line1\nurl = http://evil").contains('\n'));
    }

    #[test]
    fn channel_validation() {
        for ok in [
            spec("ntfy", "https://ntfy.example/alerts", "", "", ""),
            spec("telegram", "", "123456:ABC-def_1", "-1001234", ""),
            spec("telegram", "", "123456:ABC", "@my_channel", ""),
            spec(
                "discord",
                "https://discord.example/api/webhooks/1/x",
                "",
                "",
                "",
            ),
            spec(
                "slack",
                "https://hooks.slack.example/services/x",
                "",
                "",
                "",
            ),
            spec(
                "email",
                "smtps://mail.example.com:465",
                "pw",
                "a@example.com, b@example.net",
                "fw@example.com",
            ),
            spec(
                "email",
                "smtp://[2001:db8::25]:587",
                "",
                "a@example.com",
                "fw@example.com",
            ),
        ] {
            check_spec(&ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for bad in [
            spec("pager", "https://x.example", "", "", ""),
            spec("telegram", "", "", "123", ""),
            spec("telegram", "", "tok;rm", "123", ""),
            spec("telegram", "", "1:A", "12a", ""),
            spec(
                "email",
                "https://mail.example.com",
                "",
                "a@example.com",
                "fw@example.com",
            ),
            spec(
                "email",
                "smtp://mail.example.com/x",
                "",
                "a@example.com",
                "fw@example.com",
            ),
            spec(
                "email",
                "smtp://u@mail.example.com",
                "",
                "a@example.com",
                "fw@example.com",
            ),
            spec("email", "smtp://mail.example.com", "", "", "fw@example.com"),
            spec(
                "email",
                "smtp://mail.example.com",
                "",
                "a@example.com",
                "not-an-address",
            ),
            spec(
                "email",
                "smtp://mail.example.com",
                "",
                "a@example.com\r\nBcc: x@y.z",
                "fw@example.com",
            ),
            spec("ntfy", "ftp://x", "", "", ""),
            spec("ntfy", "https://x.example", "", "123", ""),
        ] {
            let e = check_spec(&bad).unwrap_err().to_string();
            assert!(e.starts_with("Invalid"), "{bad:?}: {e}");
        }
        let mut s = spec("ntfy", "https://n.example/t", "", "", "");
        s.min_severity = "loud".into();
        assert!(check_spec(&s).is_err());
        assert_eq!(
            check_spec(&spec("telegram", "", "1:A", "5", "")).unwrap().1,
            TELEGRAM_API
        );
    }

    fn hook(
        channel: &str,
        url: &str,
        secret: &str,
        target: &str,
        sender: &str,
        user: &str,
    ) -> Hook {
        Hook {
            id: 1,
            name: "n".into(),
            url: url.into(),
            secret: secret.into(),
            has_secret: !secret.is_empty(),
            kinds: String::new(),
            enabled: true,
            last_attempt_at: None,
            last_result: None,
            channel: channel.into(),
            target: target.into(),
            sender: sender.into(),
            username: user.into(),
            min_severity: "info".into(),
            matcher: String::new(),
        }
    }

    #[test]
    fn channel_requests() {
        let e = Event {
            id: 7,
            ts: 1_700_000_000,
            kind: "gateway_down".into(),
            subject: "WAN".into(),
            severity: "critical".into(),
            detail: "no reply from 192.0.2.1".into(),
        };
        let (subj, text) = message_text("fw1", &e);
        assert_eq!(subj, "[fw1] CRITICAL: gateway down WAN");
        assert!(text.contains("no reply from 192.0.2.1") && text.contains("2023-11-14"));
        match request(
            "fw1",
            &hook("ntfy", "https://n.example/t", "tk", "", "", ""),
            &e,
        ) {
            Request::Http {
                url,
                content_type,
                headers,
                body,
            } => {
                assert_eq!(url, "https://n.example/t");
                assert!(content_type.starts_with("text/plain"));
                assert!(headers.contains(&"Priority: urgent".to_string()));
                assert!(headers.contains(&"Authorization: Bearer tk".to_string()));
                assert_eq!(body, text);
            }
            r => panic!("{r:?}"),
        }
        match request(
            "fw1",
            &hook("telegram", TELEGRAM_API, "1:A", "-100", "", ""),
            &e,
        ) {
            Request::Http { url, body, .. } => {
                assert_eq!(url, "https://api.telegram.org/bot1:A/sendMessage");
                let v: Value = serde_json::from_str(&body).unwrap();
                assert_eq!(v["chat_id"], "-100");
                assert_eq!(v["text"], text);
            }
            r => panic!("{r:?}"),
        }
        match request(
            "fw1",
            &hook("discord", "https://d.example/w", "", "", "", ""),
            &e,
        ) {
            Request::Http { body, .. } => assert!(body.contains("\"content\"")),
            r => panic!("{r:?}"),
        }
        match request(
            "fw1",
            &hook(
                "email",
                "smtp://m.example",
                "pw",
                "a@example.com,b@example.com",
                "fw@example.com",
                "u",
            ),
            &e,
        ) {
            Request::Mail {
                from,
                rcpts,
                user,
                message,
                ..
            } => {
                assert_eq!(from, "fw@example.com");
                assert_eq!(rcpts, vec!["a@example.com", "b@example.com"]);
                assert_eq!(user, Some(("u".into(), "pw".into())));
                assert!(message.contains("Subject: [fw1] CRITICAL: gateway down WAN\r\n"));
                assert!(message.contains("To: a@example.com, b@example.com\r\n"));
                assert!(message.contains("\r\n\r\n[fw1] CRITICAL"));
            }
            r => panic!("{r:?}"),
        }
        // webhook keeps the signed JSON
        match request(
            "fw1",
            &hook("webhook", "https://w.example", "k", "", "", ""),
            &e,
        ) {
            Request::Http { headers, .. } => {
                assert!(headers
                    .iter()
                    .any(|h| h.starts_with("X-Patronus-Signature: sha256=")))
            }
            r => panic!("{r:?}"),
        }
        // severity filter
        let mut h = hook("ntfy", "https://n.example/t", "", "", "", "");
        h.min_severity = "critical".into();
        let none = HashMap::new();
        let t = chrono::NaiveDate::from_ymd_opt(2026, 11, 25)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        assert!(wants_event(&h, &e, &none, t));
        let mut info = e.clone();
        info.severity = "warning".into();
        assert!(!wants_event(&h, &info, &none, t));
    }

    #[tokio::test]
    async fn channels_follow_their_matcher() {
        let store = ConfigStore::open_in_memory().await.unwrap();
        // a plain channel gets an equivalent matcher of its own
        let id = save_hook(&store, "legacy", "https://w.example", "", "gateway_down")
            .await
            .unwrap();
        let hs = hooks(&store).await.unwrap();
        assert_eq!(hs[0].matcher, "auto-legacy");
        let ms = matcher_map(&store).await;
        let t = chrono::NaiveDate::from_ymd_opt(2026, 11, 23) // a Monday
            .unwrap()
            .and_hms_opt(23, 0, 0)
            .unwrap();
        let down = ev("gateway_down", "wan", "critical", String::new());
        let up = ev("gateway_up", "wan", "info", String::new());
        assert!(wants_event(&hs[0], &down, &ms, t));
        assert!(!wants_event(&hs[0], &up, &ms, t));
        // a night-time matcher: WAN problems on weekday nights, never guest*
        let tree: matcher::Matcher = serde_json::from_value(json!({"op":"all","items":[
            {"op":"any","items":[{"op":"kind","kinds":["gateway_down"]},{"op":"kind","kinds":["tunnel_down"]}]},
            {"op":"calendar","days":["mon","tue","wed","thu","fri"],"start":"22:00","end":"06:00"},
            {"op":"not","items":[{"op":"subject","glob":"guest*"}]}]}))
        .unwrap();
        matcher::upsert(&store, "night", "", tree.clone(), EVENT_KINDS).await.unwrap();
        assert!(set_hook_matcher(&store, id, "night").await.unwrap());
        assert!(set_hook_matcher(&store, id, "nope").await.is_err());
        let hs = hooks(&store).await.unwrap();
        let ms = matcher_map(&store).await;
        assert!(wants_event(&hs[0], &down, &ms, t));
        let noon = t.date().and_hms_opt(12, 0, 0).unwrap();
        assert!(!wants_event(&hs[0], &down, &ms, noon));
        let guest = ev("gateway_down", "guest-wan", "critical", String::new());
        assert!(!wants_event(&hs[0], &guest, &ms, t));
        // a shared matcher stays when its channel goes; the auto one goes
        assert!(delete_hook(&store, id).await.unwrap());
        assert!(matcher::get_tree(&store, "night").await.unwrap().is_some());
        assert!(matcher::get_tree(&store, "auto-legacy").await.unwrap().is_none());
        // channel naming a matcher that does not exist is refused
        let mut sp = spec("webhook", "https://w.example", "", "", "");
        sp.name = "x".into();
        sp.matcher = "missing".into();
        assert!(save_channel(&store, &sp).await.unwrap_err().to_string().starts_with("Invalid"));
        // preview judges stored events
        for e in [&down, &up, &guest] {
            record(&store, e).await.unwrap();
        }
        let rows = preview(&store, &tree).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.id > 0));
    }

    #[test]
    fn metrics_are_prometheus_text() {
        let s = json!({
            "version": "1.2.3", "hostname": "fw\"1", "uptime_secs": 99,
            "firewall": {"active_rules": 12},
            "gateways": [{"name": "WAN", "state": "online", "rtt_ms": 4.5, "loss_pct": 0},
                         {"name": "OPT", "state": "down", "rtt_ms": null, "loss_pct": 100}],
            "vpn": {"wireguard": [{"interface": "wg0", "peer": "phone", "connected": true, "handshake_age_secs": 12}],
                    "ipsec": [{"name": "hq", "established": false}]},
            "conntrack": {"count": 321, "max": 262144},
            "dhcp": {"leases": 4},
            "services": [{"name": "unbound", "running": true}],
            "config": {"last_change": {"id": 7}},
            "ha": {"state": "MASTER"},
        });
        let t = prometheus(&s);
        for want in [
            "patronus_info{version=\"1.2.3\",hostname=\"fw\\\"1\"} 1",
            "patronus_gateway_up{gateway=\"WAN\"} 1",
            "patronus_gateway_up{gateway=\"OPT\"} 0",
            "patronus_gateway_rtt_ms{gateway=\"WAN\"} 4.5",
            "patronus_wireguard_peer_connected{interface=\"wg0\",peer=\"phone\"} 1",
            "patronus_wireguard_handshake_age_seconds{interface=\"wg0\",peer=\"phone\"} 12",
            "patronus_ipsec_sa_established{tunnel=\"hq\"} 0",
            "patronus_conntrack_entries 321",
            "patronus_dhcp_leases 4",
            "patronus_service_up{service=\"unbound\"} 1",
            "patronus_config_revision 7",
            "patronus_ha_master 1",
            "# TYPE patronus_uptime_seconds gauge",
        ] {
            assert!(t.contains(want), "missing {want:?} in:\n{t}");
        }
        // no value -> no sample (a null RTT is not 0)
        assert!(!t.contains("patronus_gateway_rtt_ms{gateway=\"OPT\"}"));
    }
}
