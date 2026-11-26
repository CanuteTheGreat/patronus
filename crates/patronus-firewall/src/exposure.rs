//! Is a local service reachable through an interface? Read from the LIVE
//! ruleset (`nft -j list table inet patronus`), not from the store: the
//! security overview (docs/SECURITY-OVERVIEW.md) must show what the kernel
//! does, whatever wrote it.
//!
//! The evaluator walks the `input` chain in order the way the kernel would
//! for one new connection (`iifname`, protocol, destination port), following
//! `jump`/`goto` into the table's own chains:
//!
//! - an `accept` whose conditions all hold for that connection = **open**;
//! - an `accept` that also needs a source address / set we cannot decide =
//!   **restricted** (reachable from some addresses only; reported, not open);
//! - a `drop`/`reject` that matches unconditionally = **closed** at that rule;
//! - a rule that only matches established/related traffic never accepts a new
//!   connection and is skipped;
//! - anything the evaluator does not understand on an `accept` rule counts as
//!   **open (conditional)**: a check must never call an unknown rule safe.
//!
//! Then the chain policy decides.

use serde::Serialize;
use serde_json::Value;

/// Name of the main table (`inet patronus`) in nft JSON.
const MAIN_TABLE: &str = "patronus";

/// What one new connection to `proto/port` arriving on `iface` gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Exposure {
    /// Accepted for everybody by the rule with this handle/comment.
    Open {
        handle: Option<u64>,
        comment: String,
    },
    /// Accepted by a rule that also matches on something the evaluator cannot
    /// decide (a source address, a set it cannot read): reachable from some
    /// addresses.
    Restricted {
        handle: Option<u64>,
        comment: String,
    },
    /// Dropped (by a rule or the chain policy).
    Closed,
    /// The table or its input chain is not loaded.
    NoRuleset,
}

impl Exposure {
    pub fn is_open(&self) -> bool {
        matches!(self, Exposure::Open { .. })
    }
}

/// Result of one condition for the connection under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    Yes,
    No,
    /// Depends on the source (address, set membership, ...).
    Maybe,
}

struct Conn<'a> {
    iface: &'a str,
    proto: &'a str,
    port: u16,
}

fn as_set(v: &Value) -> Vec<&Value> {
    match v.get("set").and_then(Value::as_array) {
        Some(a) => a.iter().collect(),
        None => vec![v],
    }
}

fn port_in(right: &Value, port: u16) -> Option<bool> {
    let mut any = false;
    for e in as_set(right) {
        if let Some(n) = e.as_u64() {
            any |= n == port as u64;
            continue;
        }
        let r = e.get("range").and_then(Value::as_array)?;
        let lo = r.first().and_then(Value::as_u64)?;
        let hi = r.get(1).and_then(Value::as_u64)?;
        any |= (lo..=hi).contains(&(port as u64));
    }
    Some(any)
}

fn str_in(right: &Value, s: &str) -> Option<bool> {
    let mut any = false;
    for e in as_set(right) {
        let v = e.as_str()?;
        any |= if let Some(prefix) = v.strip_suffix('*') {
            s.starts_with(prefix)
        } else {
            v == s
        };
    }
    Some(any)
}

fn negate(op: &str, b: bool) -> bool {
    if op == "!=" {
        !b
    } else {
        b
    }
}

fn eval_match(m: &Value, c: &Conn) -> Cond {
    let op = m.get("op").and_then(Value::as_str).unwrap_or("==");
    let left = &m["left"];
    let right = &m["right"];
    let to = |o: Option<bool>| match o {
        Some(b) if negate(op, b) => Cond::Yes,
        Some(_) => Cond::No,
        None => Cond::Maybe,
    };
    if let Some(key) = left.pointer("/meta/key").and_then(Value::as_str) {
        return match key {
            "iifname" | "iif" => to(str_in(right, c.iface)),
            "l4proto" | "protocol" => to(str_in(right, c.proto)),
            // a new connection to the router never has an output interface
            "oifname" | "oif" => Cond::No,
            "nfproto" => Cond::Yes,
            "mark" => Cond::Maybe,
            _ => Cond::Maybe,
        };
    }
    if let Some(p) = left.get("payload") {
        let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("");
        let field = p.get("field").and_then(Value::as_str).unwrap_or("");
        return match (proto, field) {
            ("tcp" | "udp", "dport") => {
                if proto != c.proto {
                    Cond::No
                } else {
                    to(port_in(right, c.port))
                }
            }
            ("tcp" | "udp", _) if proto != c.proto => Cond::No,
            ("ip" | "ip6", "saddr") => Cond::Maybe,
            ("ip" | "ip6", "daddr") => Cond::Maybe,
            ("ip" | "ip6", "protocol" | "nexthdr") => to(str_in(right, c.proto)),
            ("icmp" | "icmpv6", _) => Cond::No,
            _ => Cond::Maybe,
        };
    }
    if let Some(key) = left.pointer("/ct/key").and_then(Value::as_str) {
        if key == "state" {
            let states: Vec<&str> = as_set(right)
                .into_iter()
                .chain(right.as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .collect();
            let has_new = states.contains(&"new");
            let matches_new = match op {
                "!=" => !has_new,
                _ => has_new,
            };
            // `ct state established,related accept` never accepts a new connection
            return if states.is_empty() {
                Cond::Maybe
            } else if matches_new {
                Cond::Yes
            } else {
                Cond::No
            };
        }
        return Cond::Maybe;
    }
    if left.get("fib").is_some() || left.get("socket").is_some() {
        return Cond::Maybe;
    }
    Cond::Maybe
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Accept,
    Drop,
    Return,
    Jump(String),
    Goto(String),
    None,
}

fn rule_parts(rule: &Value, c: &Conn) -> (Cond, Verdict) {
    let mut cond = Cond::Yes;
    let mut verdict = Verdict::None;
    for e in rule["expr"].as_array().into_iter().flatten() {
        if let Some(m) = e.get("match") {
            match eval_match(m, c) {
                Cond::No => cond = Cond::No,
                Cond::Maybe if cond == Cond::Yes => cond = Cond::Maybe,
                _ => {}
            }
        } else if e.get("accept").is_some() {
            verdict = Verdict::Accept;
        } else if e.get("drop").is_some() || e.get("reject").is_some() {
            verdict = Verdict::Drop;
        } else if e.get("return").is_some() {
            verdict = Verdict::Return;
        } else if let Some(t) = e.pointer("/jump/target").and_then(Value::as_str) {
            verdict = Verdict::Jump(t.to_string());
        } else if let Some(t) = e.pointer("/goto/target").and_then(Value::as_str) {
            verdict = Verdict::Goto(t.to_string());
        } else if e.get("limit").is_some() || e.get("meter").is_some() {
            // a rate limit makes the rule match only some packets
            if cond == Cond::Yes {
                cond = Cond::Maybe;
            }
        }
    }
    (cond, verdict)
}

enum Walk {
    Final(Exposure),
    Fallthrough,
}

fn walk(
    rules: &[&Value],
    chains: &std::collections::BTreeMap<String, Vec<&Value>>,
    chain: &str,
    c: &Conn,
    depth: usize,
) -> Walk {
    if depth > 8 {
        return Walk::Fallthrough;
    }
    let empty = Vec::new();
    let list = if chain == "input" {
        rules
    } else {
        chains.get(chain).map(Vec::as_slice).unwrap_or(&empty)
    };
    for r in list {
        let (cond, verdict) = rule_parts(r, c);
        if cond == Cond::No {
            continue;
        }
        let handle = r.get("handle").and_then(Value::as_u64);
        let comment = r
            .get("comment")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        match verdict {
            Verdict::Accept => {
                return Walk::Final(if cond == Cond::Yes {
                    Exposure::Open { handle, comment }
                } else {
                    Exposure::Restricted { handle, comment }
                })
            }
            Verdict::Drop if cond == Cond::Yes => return Walk::Final(Exposure::Closed),
            Verdict::Return if cond == Cond::Yes => return Walk::Fallthrough,
            Verdict::Jump(t) | Verdict::Goto(t) => {
                if let Walk::Final(x) = walk(rules, chains, &t, c, depth + 1) {
                    // a restricted accept deeper down does not end the walk: an
                    // unconditional accept later on may still open it to all
                    if !matches!(x, Exposure::Restricted { .. }) {
                        return Walk::Final(x);
                    }
                }
            }
            _ => {}
        }
    }
    Walk::Fallthrough
}

/// Evaluate `proto` (`tcp`/`udp`) `port` on `iface` against the JSON of
/// `nft -j list table inet patronus` (or the whole ruleset).
pub fn evaluate(nft_json: &Value, iface: &str, proto: &str, port: u16) -> Exposure {
    let mut chains: std::collections::BTreeMap<String, Vec<&Value>> = Default::default();
    let mut policy: Option<String> = None;
    let mut have_input = false;
    for item in nft_json["nftables"].as_array().into_iter().flatten() {
        if let Some(ch) = item.get("chain") {
            if ch["family"] == "inet" && ch["table"] == MAIN_TABLE {
                if ch["name"] == "input" {
                    have_input = true;
                    policy = ch.get("policy").and_then(Value::as_str).map(str::to_string);
                }
                chains
                    .entry(ch["name"].as_str().unwrap_or("").to_string())
                    .or_default();
            }
        }
        if let Some(r) = item.get("rule") {
            if r["family"] == "inet" && r["table"] == MAIN_TABLE {
                chains
                    .entry(r["chain"].as_str().unwrap_or("").to_string())
                    .or_default()
                    .push(r);
            }
        }
    }
    if !have_input {
        return Exposure::NoRuleset;
    }
    let c = Conn { iface, proto, port };
    let input = chains.get("input").cloned().unwrap_or_default();
    let mut restricted = None;
    // a restricted accept is remembered; an unconditional accept/drop later decides
    let mut rest: &[&Value] = &input;
    loop {
        match walk(rest, &chains, "input", &c, 0) {
            Walk::Final(Exposure::Restricted { handle, comment }) => {
                restricted = Some(Exposure::Restricted {
                    handle,
                    comment: comment.clone(),
                });
                let pos = rest
                    .iter()
                    .position(|r| r.get("handle").and_then(Value::as_u64) == handle)
                    .map(|p| p + 1)
                    .unwrap_or(rest.len());
                if pos >= rest.len() {
                    break;
                }
                rest = &rest[pos..];
            }
            Walk::Final(x) => return restricted.filter(|_| x == Exposure::Closed).unwrap_or(x),
            Walk::Fallthrough => break,
        }
    }
    if let Some(r) = restricted {
        return r;
    }
    match policy.as_deref() {
        Some("accept") => Exposure::Open {
            handle: None,
            comment: "input chain policy accept".into(),
        },
        _ => Exposure::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table(rules: Vec<Value>, policy: &str) -> Value {
        let mut items = vec![
            json!({"chain": {"family": "inet", "table": "patronus", "name": "input", "policy": policy}}),
        ];
        items.extend(rules.into_iter().enumerate().map(|(i, mut r)| {
            r["family"] = json!("inet");
            r["table"] = json!("patronus");
            if r.get("chain").is_none() {
                r["chain"] = json!("input");
            }
            r["handle"] = json!(i as u64 + 10);
            json!({ "rule": r })
        }));
        json!({ "nftables": items })
    }
    fn iif(n: Value) -> Value {
        json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": n}})
    }
    fn dport(p: Value) -> Value {
        json!({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": p}})
    }
    fn est() -> Value {
        json!({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}})
    }
    fn accept() -> Value {
        json!({"accept": null})
    }

    #[test]
    fn default_drop_policy_is_closed() {
        let t = table(
            vec![
                json!({"expr": [est(), accept()]}),
                json!({"expr": [iif(json!("lan0")), dport(json!({"set": [22, 443]})), accept()], "comment": "anti-lockout"}),
            ],
            "drop",
        );
        assert_eq!(evaluate(&t, "wan0", "tcp", 443), Exposure::Closed);
        assert!(evaluate(&t, "lan0", "tcp", 443).is_open());
        assert_eq!(evaluate(&t, "lan0", "tcp", 80), Exposure::Closed);
    }

    #[test]
    fn a_wan_accept_opens_and_a_source_restriction_is_restricted() {
        let any = table(
            vec![
                json!({"expr": [iif(json!("wan0")), dport(json!(22)), accept()], "comment": "ssh from anywhere"}),
            ],
            "drop",
        );
        assert!(
            matches!(evaluate(&any, "wan0", "tcp", 22), Exposure::Open { comment, .. } if comment == "ssh from anywhere")
        );
        let src = json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "198.51.100.0", "len": 24}}}});
        let r = table(
            vec![json!({"expr": [iif(json!("wan0")), src, dport(json!(22)), accept()]})],
            "drop",
        );
        assert!(matches!(
            evaluate(&r, "wan0", "tcp", 22),
            Exposure::Restricted { .. }
        ));
    }

    #[test]
    fn ranges_negation_jumps_and_policy_accept() {
        let t = table(
            vec![
                json!({"expr": [{"jump": {"target": "ti_check"}}]}),
                json!({"expr": [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "lan0"}}, dport(json!({"range": [400, 500]})), accept()]}),
                json!({"chain": "ti_check", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@alias_ti_x_v4"}}, {"drop": null}]}),
            ],
            "drop",
        );
        assert!(evaluate(&t, "wan0", "tcp", 443).is_open());
        assert_eq!(evaluate(&t, "lan0", "tcp", 443), Exposure::Closed);
        assert_eq!(evaluate(&t, "wan0", "udp", 443), Exposure::Closed);
        let open = table(vec![], "accept");
        assert!(evaluate(&open, "wan0", "tcp", 22).is_open());
        assert_eq!(
            evaluate(&json!({"nftables": []}), "wan0", "tcp", 22),
            Exposure::NoRuleset
        );
    }

    #[test]
    fn an_unconditional_drop_before_the_accept_closes() {
        let t = table(
            vec![
                json!({"expr": [iif(json!("wan0")), {"drop": null}]}),
                json!({"expr": [dport(json!(22)), accept()]}),
            ],
            "drop",
        );
        assert_eq!(evaluate(&t, "wan0", "tcp", 22), Exposure::Closed);
        assert!(evaluate(&t, "lan0", "tcp", 22).is_open());
    }

    #[test]
    fn rate_limited_and_set_based_rules_are_never_called_safe() {
        let t = table(
            vec![
                json!({"expr": [iif(json!("wan0")), {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "@alias_web_ports"}}, accept()]}),
            ],
            "drop",
        );
        assert!(matches!(
            evaluate(&t, "wan0", "tcp", 443),
            Exposure::Restricted { .. }
        ));
        // a SYN-flood limit + drop is not an unconditional drop
        let s = table(
            vec![
                json!({"expr": [iif(json!("wan0")), {"limit": {"rate": 25}}, {"drop": null}]}),
                json!({"expr": [iif(json!("wan0")), dport(json!(443)), accept()]}),
            ],
            "drop",
        );
        assert!(evaluate(&s, "wan0", "tcp", 443).is_open());
        // a later unconditional accept beats an earlier restricted one
        let src = json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.1"}});
        let both = table(
            vec![
                json!({"expr": [iif(json!("wan0")), src, dport(json!(22)), accept()]}),
                json!({"expr": [dport(json!(22)), accept()], "comment": "all"}),
            ],
            "drop",
        );
        assert!(
            matches!(evaluate(&both, "wan0", "tcp", 22), Exposure::Open { comment, .. } if comment == "all")
        );
    }
}
