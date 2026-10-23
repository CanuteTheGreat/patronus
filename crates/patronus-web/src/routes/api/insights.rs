//! Traffic insights (the built-in alternative to ntopng): who talks, to which
//! services, over which protocols, and how fast each interface moves, all
//! from the kernel's connection-tracking table (per-flow byte counters, switched
//! on by the sysctl applier) and the interface counters. `/insights` page and
//! `GET /api/insights`; the page polls the API and draws the rates itself, so
//! the router keeps no history. Nothing is invented: with accounting off or
//! conntrack unreadable the answer says so.

use crate::state::AppState;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub dport: Option<u16>,
    pub bytes: u64,
    pub packets: u64,
    pub accounted: bool,
}

/// Flows from /proc/net/nf_conntrack (or `conntrack -L -o extended`) text.
pub fn parse_flows(text: &str) -> Vec<Flow> {
    const PROTOS: &[&str] = &[
        "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre", "udplite",
    ];
    let mut out = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(proto) = words.iter().find(|w| PROTOS.contains(w)) else {
            continue;
        };
        let all = |k: &str| -> Vec<&str> {
            words
                .iter()
                .filter_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .collect()
        };
        let (src, dst) = (all("src"), all("dst"));
        let (Some(src), Some(dst)) = (src.first(), dst.first()) else {
            continue;
        };
        let sum = |k: &str| all(k).iter().filter_map(|v| v.parse::<u64>().ok()).sum();
        let accounted = !all("bytes").is_empty();
        out.push(Flow {
            proto: proto.to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            dport: all("dport").first().and_then(|p| p.parse().ok()),
            bytes: sum("bytes"),
            packets: sum("packets"),
            accounted,
        });
    }
    out
}

fn service_name(proto: &str, port: u16) -> &'static str {
    match (proto, port) {
        (_, 22) => "ssh",
        (_, 25) | (_, 587) => "smtp",
        (_, 53) => "dns",
        (_, 80) => "http",
        (_, 123) => "ntp",
        (_, 143) | (_, 993) => "imap",
        (_, 443) => "https",
        (_, 3389) => "rdp",
        (_, 5060) => "sip",
        ("udp", 51820) => "wireguard",
        ("udp", 1194) | ("tcp", 1194) => "openvpn",
        _ => "",
    }
}

/// Top hosts (by originating address), top services (protocol + port of the
/// destination) and per-protocol totals, biggest first.
pub fn aggregate(flows: &[Flow], top: usize) -> Value {
    let accounting = flows.iter().any(|f| f.accounted);
    let mut hosts: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
    let mut services: BTreeMap<(String, Option<u16>), (u64, u64)> = BTreeMap::new();
    let mut protos: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for f in flows {
        let h = hosts.entry(&f.src).or_default();
        h.0 += f.bytes;
        h.1 += f.packets;
        h.2 += 1;
        let s = services.entry((f.proto.clone(), f.dport)).or_default();
        s.0 += f.bytes;
        s.1 += 1;
        let p = protos.entry(&f.proto).or_default();
        p.0 += f.bytes;
        p.1 += 1;
    }
    let by_bytes_then_flows = |a: &(u64, u64), b: &(u64, u64)| b.cmp(a);
    let mut h: Vec<_> = hosts.into_iter().collect();
    h.sort_by(|a, b| {
        (b.1 .0, b.1 .2)
            .cmp(&(a.1 .0, a.1 .2))
            .then_with(|| a.0.cmp(b.0))
    });
    let mut s: Vec<_> = services.into_iter().collect();
    s.sort_by(|a, b| by_bytes_then_flows(&a.1, &b.1).then_with(|| a.0.cmp(&b.0)));
    let mut p: Vec<_> = protos.into_iter().collect();
    p.sort_by(|a, b| by_bytes_then_flows(&a.1, &b.1).then_with(|| a.0.cmp(b.0)));
    json!({
        "flows": flows.len(),
        "accounting": accounting,
        "top_hosts": h.into_iter().take(top).map(|(a, (bytes, packets, n))|
            json!({"host": a, "bytes": bytes, "packets": packets, "flows": n})).collect::<Vec<_>>(),
        "top_services": s.into_iter().take(top).map(|((proto, port), (bytes, n))| json!({
            "proto": proto, "port": port,
            "name": port.map(|p| service_name(&proto, p)).unwrap_or(""),
            "bytes": bytes, "flows": n})).collect::<Vec<_>>(),
        "protocols": p.into_iter().map(|(proto, (bytes, n))|
            json!({"proto": proto, "bytes": bytes, "flows": n})).collect::<Vec<_>>(),
    })
}

fn interface_counters() -> Vec<Value> {
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut v: Vec<(String, u64, u64, String)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            if n == "lo" {
                return None;
            }
            let rd = |f: &str| {
                std::fs::read_to_string(e.path().join("statistics").join(f))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
            };
            let state = std::fs::read_to_string(e.path().join("operstate"))
                .unwrap_or_default()
                .trim()
                .to_string();
            Some((n, rd("rx_bytes")?, rd("tx_bytes")?, state))
        })
        .collect();
    v.sort();
    v.into_iter()
        .map(|(n, rx, tx, st)| json!({"name": n, "rx_bytes": rx, "tx_bytes": tx, "state": st}))
        .collect()
}

fn read_conntrack() -> Result<String, String> {
    match std::fs::read_to_string("/proc/net/nf_conntrack") {
        Ok(t) => Ok(t),
        Err(pe) => match std::process::Command::new("conntrack")
            .args(["-L", "-o", "extended"])
            .output()
        {
            Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
            Ok(o) => Err(format!(
                "connection tracking is unreadable ({pe}; conntrack: {})",
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => Err(format!(
                "connection tracking is unreadable ({pe}; conntrack: {e})"
            )),
        },
    }
}

async fn insights() -> Response {
    let r = tokio::task::spawn_blocking(|| {
        let mut v = match read_conntrack() {
            Ok(t) => aggregate(&parse_flows(&t), 10),
            Err(e) => json!({"flows": 0, "accounting": false, "error": e,
                "top_hosts": [], "top_services": [], "protocols": []}),
        };
        v["interfaces"] = Value::Array(interface_counters());
        v["time"] = json!(chrono::Utc::now().timestamp_millis());
        v
    })
    .await;
    match r {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Template)]
#[template(path = "insights.html")]
struct InsightsTemplate {
    page: &'static str,
}

async fn page(_me: crate::auth::AuthUser) -> Response {
    match (InsightsTemplate { page: "insights" }).render() {
        Ok(h) => Html(h).into_response(),
        Err(e) => {
            tracing::error!("render insights: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to render page").into_response()
        }
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route("/insights", axum::routing::get(insights))
}

pub fn pages() -> axum::Router<AppState> {
    axum::Router::new().route("/insights", axum::routing::get(page))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
ipv4     2 tcp      6 100 ESTABLISHED src=192.168.50.10 dst=198.51.100.10 sport=40000 dport=80 packets=10 bytes=5000 src=198.51.100.10 dst=203.0.113.2 sport=80 dport=40000 packets=8 bytes=95000 [ASSURED] mark=0 use=1
ipv4     2 udp      17 20 src=192.168.50.10 dst=198.51.100.53 sport=5353 dport=53 packets=1 bytes=70 src=198.51.100.53 dst=192.168.50.10 sport=53 dport=5353 packets=1 bytes=120 mark=0 use=1
ipv4     2 tcp      6 100 ESTABLISHED src=192.168.50.20 dst=198.51.100.10 sport=41000 dport=443 packets=2 bytes=300 src=198.51.100.10 dst=203.0.113.2 sport=443 dport=41000 packets=2 bytes=900 mark=0 use=1
";

    #[test]
    fn hosts_services_and_protocols_are_ranked_by_bytes() {
        let f = parse_flows(SAMPLE);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].bytes, 100_000);
        let a = aggregate(&f, 10);
        assert_eq!(a["accounting"], true);
        assert_eq!(a["top_hosts"][0]["host"], "192.168.50.10");
        assert_eq!(a["top_hosts"][0]["bytes"], 100_190);
        assert_eq!(a["top_hosts"][0]["flows"], 2);
        assert_eq!(a["top_services"][0]["port"], 80);
        assert_eq!(a["top_services"][0]["name"], "http");
        assert_eq!(a["protocols"][0]["proto"], "tcp");
        assert_eq!(a["protocols"][1]["proto"], "udp");
        assert_eq!(aggregate(&f, 1)["top_hosts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn without_accounting_the_answer_says_so() {
        let f = parse_flows(
            "ipv4 2 tcp 6 100 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=1 dport=22 src=10.0.0.2 dst=10.0.0.1 sport=22 dport=1 mark=0 use=1",
        );
        let a = aggregate(&f, 5);
        assert_eq!(a["accounting"], false);
        assert_eq!(a["flows"], 1);
        assert_eq!(a["top_services"][0]["name"], "ssh");
        assert!(parse_flows("").is_empty());
    }
}
