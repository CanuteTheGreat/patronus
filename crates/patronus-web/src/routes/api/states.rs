//! Firewall state table: list the kernel's tracked connections and kill
//! them (pfSense "Diagnostics > States" / "Reset states").
//!
//! * `GET /api/firewall/states?q=&proto=&limit=` -- the conntrack table,
//!   newest-agnostic, filtered by a substring over the addresses/ports.
//! * `DELETE /api/firewall/states?src=&dst=&sport=&dport=&proto=` -- kill
//!   the matching states with `conntrack -D`. At least one filter is
//!   required: an empty filter would drop every connection (including the
//!   admin's own session), so it is refused with 400.
//!
//! Addresses and ports are parsed to typed values before they reach the
//! command line, so nothing user-typed is passed through as text.

use crate::state::insight::parse_dir_flows;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

const DEFAULT_LIMIT: usize = 500;
const MAX_LIMIT: usize = 5000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StateEntry {
    pub proto: String,
    pub src: String,
    pub sport: u16,
    pub dst: String,
    pub dport: u16,
    /// Source of the reply tuple (differs from `dst` after a port forward).
    pub reply_src: String,
    /// TCP state (`ESTABLISHED`, `TIME_WAIT`, ...); empty for other protocols.
    pub state: String,
    /// Seconds until the kernel forgets the entry.
    pub timeout: u64,
    pub packets: u64,
    pub bytes: u64,
}

/// Entries of `/proc/net/nf_conntrack` (or `conntrack -L`) text.
pub fn parse_states(text: &str) -> Vec<StateEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(f) = parse_dir_flows(line).into_iter().next() else {
            continue;
        };
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(pi) = words.iter().position(|w| *w == f.proto) else {
            continue;
        };
        // `<proto> <protonum> <timeout> [STATE] src=...`
        let timeout = words
            .get(pi + 2)
            .and_then(|w| w.parse::<u64>().ok())
            .unwrap_or(0);
        let state = words
            .get(pi + 3)
            .filter(|w| !w.contains('=') && !w.starts_with('['))
            .map(|w| w.to_string())
            .unwrap_or_default();
        out.push(StateEntry {
            proto: f.proto.clone(),
            src: f.osrc.to_string(),
            sport: f.sport,
            dst: f.odst.to_string(),
            dport: f.dport,
            reply_src: f.rsrc.to_string(),
            state,
            timeout,
            packets: f.opackets + f.rpackets,
            bytes: f.obytes + f.rbytes,
        });
    }
    out
}

fn read_table() -> Result<String, String> {
    if let Ok(t) = std::fs::read_to_string("/proc/net/nf_conntrack") {
        return Ok(t);
    }
    let o = std::process::Command::new("conntrack")
        .args(["-L", "-o", "extended"])
        .output()
        .map_err(|e| format!("conntrack is not available: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!(
            "conntrack -L failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    pub q: Option<String>,
    pub proto: Option<String>,
    pub limit: Option<usize>,
}

fn matches(e: &StateEntry, q: &str, proto: &str) -> bool {
    if !proto.is_empty() && !e.proto.eq_ignore_ascii_case(proto) {
        return false;
    }
    if q.is_empty() {
        return true;
    }
    let hay = format!(
        "{} {}:{} {}:{} {} {}",
        e.proto, e.src, e.sport, e.dst, e.dport, e.reply_src, e.state
    )
    .to_ascii_lowercase();
    q.split_whitespace()
        .all(|t| hay.contains(&t.to_ascii_lowercase()))
}

/// GET /api/firewall/states
pub async fn list_states(State(_s): State<AppState>, Query(q): Query<ListQuery>) -> Response {
    let table = tokio::task::spawn_blocking(read_table).await;
    let text = match table {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let all = parse_states(&text);
    let total = all.len();
    let needle = q.q.unwrap_or_default();
    let proto = q.proto.unwrap_or_default();
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let hits: Vec<StateEntry> = all
        .into_iter()
        .filter(|e| matches(e, needle.trim(), proto.trim()))
        .collect();
    let matched = hits.len();
    let states: Vec<StateEntry> = hits.into_iter().take(limit).collect();
    Json(serde_json::json!({
        "total": total,
        "matched": matched,
        "shown": states.len(),
        "states": states,
    }))
    .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct KillQuery {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub proto: Option<String>,
}

/// The `conntrack -D` arguments for a kill request, or the reason it is
/// refused.
pub fn kill_args(q: &KillQuery) -> Result<Vec<String>, String> {
    let mut a: Vec<String> = vec!["-D".into()];
    let mut filters = 0;
    if let Some(p) = q.proto.as_deref().filter(|p| !p.is_empty()) {
        let p = p.to_ascii_lowercase();
        if ![
            "tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "gre", "udplite",
        ]
        .contains(&p.as_str())
        {
            return Err(format!("Invalid protocol {p:?}"));
        }
        a.extend(["-p".into(), p]);
        filters += 1;
    }
    for (flag, v) in [("-s", &q.src), ("-d", &q.dst)] {
        if let Some(v) = v.as_deref().filter(|v| !v.is_empty()) {
            let ip: IpAddr = v
                .trim()
                .parse()
                .map_err(|_| format!("Invalid address {v:?}"))?;
            a.extend([flag.into(), ip.to_string()]);
            filters += 1;
        }
    }
    // conntrack only accepts --sport/--dport together with -p.
    if (q.sport.is_some() || q.dport.is_some()) && !a.iter().any(|x| x == "-p") {
        return Err("Invalid request: a port filter needs a protocol (tcp, udp, ...)".into());
    }
    for (flag, v) in [("--sport", q.sport), ("--dport", q.dport)] {
        if let Some(p) = v {
            a.extend([flag.into(), p.to_string()]);
            filters += 1;
        }
    }
    // A protocol alone is too broad a delete only if nothing else is given
    // and it is tcp (the admin's own session); require an address or port.
    let has_addr_or_port = q.src.as_deref().is_some_and(|s| !s.is_empty())
        || q.dst.as_deref().is_some_and(|s| !s.is_empty())
        || q.sport.is_some()
        || q.dport.is_some();
    if filters == 0 || !has_addr_or_port {
        return Err("Invalid request: give a source or destination address or a port (an empty filter would kill every connection)".into());
    }
    // `conntrack -D -s` without -p is fine for IPv4; an IPv6 address needs
    // the family set explicitly.
    let v6 = [&q.src, &q.dst]
        .iter()
        .filter_map(|v| v.as_deref())
        .any(|v| v.trim().parse::<IpAddr>().is_ok_and(|i| i.is_ipv6()));
    if v6 {
        a.extend(["-f".into(), "ipv6".into()]);
    }
    Ok(a)
}

/// Number from conntrack's "N flow entries have been deleted." line.
pub fn deleted_count(stderr: &str) -> u64 {
    stderr
        .lines()
        .find(|l| l.contains("flow entries have been deleted"))
        .and_then(|l| l.split_whitespace().find_map(|w| w.parse::<u64>().ok()))
        .unwrap_or(0)
}

/// DELETE /api/firewall/states
pub async fn kill_states(State(_s): State<AppState>, Query(q): Query<KillQuery>) -> Response {
    let args = match kill_args(&q) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    };
    let run = tokio::task::spawn_blocking(move || {
        std::process::Command::new("conntrack").args(&args).output()
    })
    .await;
    match run {
        Ok(Ok(o)) => {
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            let n = deleted_count(&err);
            // conntrack exits 1 when nothing matched; that is "0 killed".
            if o.status.success() || n == 0 && err.contains("0 flow entries") {
                tracing::info!("killed {n} firewall state(s)");
                Json(serde_json::json!({"deleted": n})).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("conntrack -D failed: {}", err.trim())}))).into_response()
            }
        }
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": format!("conntrack is not available: {e}")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub fn router() -> axum::Router<AppState> {
    axum::Router::new().route(
        "/firewall/states",
        axum::routing::get(list_states).delete(kill_states),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.10 dst=198.51.100.7 sport=40000 dport=443 packets=6 bytes=700 src=198.51.100.7 dst=203.0.113.2 sport=443 dport=40000 packets=5 bytes=900 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 25 src=192.168.50.10 dst=198.51.100.53 sport=5353 dport=53 packets=1 bytes=60 src=198.51.100.53 dst=203.0.113.2 sport=53 dport=5353 packets=1 bytes=120 mark=0 use=2
ipv6     10 icmpv6   58 29 src=fd00:50::10 dst=2001:db8:100::10 type=128 code=0 id=7 src=2001:db8:100::10 dst=fd00:50::10 type=129 code=0 id=7 mark=0 use=1
";

    #[test]
    fn parses_tcp_udp_and_v6() {
        let s = parse_states(SAMPLE);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].proto, "tcp");
        assert_eq!(s[0].state, "ESTABLISHED");
        assert_eq!(s[0].timeout, 431999);
        assert_eq!((s[0].sport, s[0].dport), (40000, 443));
        assert_eq!(s[0].bytes, 1600);
        assert_eq!(s[1].state, "");
        assert_eq!(s[1].timeout, 25);
        assert_eq!(s[2].src, "fd00:50::10");
    }

    #[test]
    fn filter_matches_terms() {
        let s = parse_states(SAMPLE);
        assert!(matches(&s[0], "198.51.100.7 443", ""));
        assert!(!matches(&s[1], "443", ""));
        assert!(matches(&s[1], "", "UDP"));
        assert!(!matches(&s[1], "", "tcp"));
    }

    #[test]
    fn kill_needs_an_address_or_port_and_types_them() {
        assert!(kill_args(&KillQuery::default()).is_err());
        let proto_only = KillQuery {
            proto: Some("tcp".into()),
            ..Default::default()
        };
        assert!(kill_args(&proto_only).is_err());
        let bad = KillQuery {
            src: Some("1.2.3.4; reboot".into()),
            ..Default::default()
        };
        assert!(kill_args(&bad).unwrap_err().starts_with("Invalid address"));
        let ok = KillQuery {
            src: Some("192.168.50.10".into()),
            dport: Some(443),
            proto: Some("TCP".into()),
            ..Default::default()
        };
        assert_eq!(
            kill_args(&ok).unwrap(),
            vec!["-D", "-p", "tcp", "-s", "192.168.50.10", "--dport", "443"]
        );
        let no_proto = KillQuery {
            src: Some("10.0.0.1".into()),
            dport: Some(80),
            ..Default::default()
        };
        assert!(kill_args(&no_proto)
            .unwrap_err()
            .contains("needs a protocol"));
        let v6 = KillQuery {
            dst: Some("fd00:50::10".into()),
            ..Default::default()
        };
        assert!(kill_args(&v6)
            .unwrap()
            .ends_with(&["-f".to_string(), "ipv6".to_string()]));
    }

    #[test]
    fn counts_deleted() {
        assert_eq!(
            deleted_count("conntrack v1.4.8: 3 flow entries have been deleted.\n"),
            3
        );
        assert_eq!(
            deleted_count(
                "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n"
            ),
            0
        );
    }
}
