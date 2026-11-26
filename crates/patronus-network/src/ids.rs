//! Intrusion detection / prevention (USE=intrusion-detection, `suricata`):
//!
//! - **IDS** mode: Suricata watches the chosen interface passively
//!   (AF_PACKET) and logs alerts to `eve.json`;
//! - **IPS** mode: forwarded traffic of that interface goes through an NFQUEUE
//!   (`patronus_firewall::svc_rules`, `bypass` so the firewall keeps forwarding
//!   if Suricata is down) and rules with action `drop` really drop packets.
//!
//! Rules: the ones you write here (action, protocol, source, destination,
//! port, content pattern, message) become `patronus.rules`; optionally the
//! community/Emerging Threats rules `suricata-update` keeps in
//! `/var/lib/suricata/rules/suricata.rules` are loaded too (fetching them is
//! `suricata-update`'s job, e.g. from cron). The generated config and rules are
//! checked with `suricata -T` before the running instance is replaced; a rule
//! Suricata rejects leaves the previous one running and is reported.
//! The Alerts card of the page reads the last alerts from eve.json.
//!
//! Rule sets (ET Open, abuse.ch, ...) are managed by [`crate::ids_sets`]: typed sources, a nightly
//! download in the product's own task, `suricata -T` before a new set replaces the running one,
//! per-ruleset/category/classtype policy and per-SID overrides, suppress/threshold entries. The
//! alert history (`ids_alerts`, retention) and its browser queries are [`crate::ids_alerts`].

use crate::ids_alerts;
use crate::ids_sets::{self, CurlFetch, Extra, Schedule};
use crate::lan::{self, invalid};
use crate::supervise::{which, write_atomic, Supervisor};
use crate::svc::{self, Coll, Field, Kind, Settings, Spec, Svc};
use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplyReport, Phase};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};

pub const INSTANCE: &str = "suricata";
pub const LOG_DIR: &str = "/var/log/suricata";
pub const DISTRO_RULES: &str = "/var/lib/suricata/rules/suricata.rules";
pub const QUEUE: u16 = 3;

static FIELDS: [Field; 11] = [
    Field::new("enabled", "Intrusion detection", Kind::Bool).def("0"),
    Field::new("mode", "Mode", Kind::Select(&["ids", "ips"]))
        .def("ids")
        .help("ids = alert only; ips = inline, rules with action drop block the packets"),
    Field::new("interface", "Watch interface", Kind::Iface)
        .def("@wan")
        .help("@wan, @lan, @optN or a device name; more interfaces below"),
    Field::new("home_net", "Protected networks (HOME_NET)", Kind::Text)
        .def("192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
        .help("comma-separated networks"),
    Field::new(
        "distro_rules",
        "Also load suricata-update rules",
        Kind::Bool,
    )
    .def("1")
    .help("uses /var/lib/suricata/rules/suricata.rules when it exists"),
    Field::new(
        "update_enabled",
        "Update the rule sets automatically",
        Kind::Bool,
    )
    .def("1")
    .help("downloads the enabled rule sets in the window below; a new one is fetched at once"),
    Field::new(
        "update_hour",
        "Update window starts at (hour, 0-23)",
        Kind::Int(0, 23),
    )
    .def("3")
    .help("local time of this router"),
    Field::new(
        "update_window_hours",
        "Update window length (hours)",
        Kind::Int(1, 24),
    )
    .def("3"),
    Field::new(
        "update_interval_hours",
        "Update at most every (hours)",
        Kind::Int(1, 720),
    )
    .def("24"),
    Field::new(
        "alert_retention_days",
        "Keep alerts for (days)",
        Kind::Int(1, 3650),
    )
    .def("30"),
    Field::new(
        "alert_max_rows",
        "Keep at most this many alerts",
        Kind::Int(1000, 5_000_000),
    )
    .def("200000"),
];

static SOURCE_FIELDS: [Field; 7] = [
    Field::new("key", "Short name", Kind::Token)
        .req()
        .help("letters, digits, - and _ (used in the policy)"),
    Field::new("name", "Name", Kind::Text).req(),
    Field::new("url", "Download URL", Kind::Text).req().help(
        "http:// or https://; {suricata_version} is replaced by the installed Suricata's version",
    ),
    Field::new(
        "format",
        "Format",
        Kind::Select(&["tar.gz", "rules", "rules.gz"]),
    )
    .def("tar.gz"),
    Field::new("licence", "Licence", Kind::Text),
    Field::new("enabled", "Use this rule set", Kind::Bool).def("0"),
    Field::new("max_mb", "Largest download (MB)", Kind::Int(1, 512)).def("64"),
];

static POLICY_FIELDS: [Field; 5] = [
    Field::new("scope", "Applies to", Kind::Select(&["ruleset", "category", "classtype"]))
        .def("ruleset")
        .help("a rule set, a category (the rule file, e.g. emerging-malware) or a classtype"),
    Field::new("target", "Name", Kind::Token).req(),
    Field::new("action", "Action", Kind::Select(&["alert", "drop", "disable"]))
        .def("alert")
        .help("drop only blocks in inline (IPS) mode; most specific policy wins, a SID override beats all"),
    Field::new("note", "Note", Kind::Text),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static OVERRIDE_FIELDS: [Field; 4] = [
    Field::new("sid", "Rule SID", Kind::Int(1, 4_294_967_295)).req(),
    Field::new(
        "action",
        "Action",
        Kind::Select(&["alert", "drop", "disable"]),
    )
    .def("disable"),
    Field::new("note", "Note", Kind::Text),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SUPPRESS_FIELDS: [Field; 8] = [
    Field::new("sid", "Rule SID", Kind::Int(1, 4_294_967_295)).req(),
    Field::new(
        "kind",
        "What",
        Kind::Select(&["suppress", "limit", "threshold", "both"]),
    )
    .def("suppress")
    .help("suppress = no alert; limit = at most count alerts per period; threshold = alert every count-th match"),
    Field::new("track", "Tracked by", Kind::Select(&["none", "by_src", "by_dst"]))
        .def("none")
        .help("limit/threshold need by_src or by_dst; suppress with an address needs one too"),
    Field::new("ip", "Only for address", Kind::Text)
        .help("suppress only: an address or address/prefix of the source (by_src) or destination (by_dst)"),
    Field::new("count", "Count", Kind::Int(1, 100_000)),
    Field::new("seconds", "Period (seconds)", Kind::Int(1, 2_592_000)),
    Field::new("note", "Note", Kind::Text),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static IFACE_FIELDS: [Field; 2] = [
    Field::new("iface", "Interface", Kind::Iface).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static RULE_FIELDS: [Field; 8] = [
    Field::new("action", "Action", Kind::Select(&["alert", "drop"])).def("alert"),
    Field::new(
        "proto",
        "Protocol",
        Kind::Select(&["tcp", "udp", "icmp", "ip"]),
    )
    .def("tcp"),
    Field::new("src", "Source", Kind::Token)
        .def("any")
        .help("any or an address/prefix"),
    Field::new("dst", "Destination", Kind::Token)
        .def("any")
        .help("any or an address/prefix"),
    Field::new("dport", "Destination port", Kind::Token)
        .def("any")
        .help("any or a port number"),
    Field::new("content", "Payload contains", Kind::Token)
        .help("a text pattern in the packet payload (letters, digits, . _ : / @ + -)"),
    Field::new("msg", "Message", Kind::Text).req(),
    Field::new("enabled", "Enabled", Kind::Bool).def("1"),
];

static SPEC: Spec = Spec {
    slug: "ids",
    title: "Intrusion detection (Suricata)",
    blurb: "Watch an interface with Suricata and alert on traffic that matches your rules, or run \
            it inline and drop it. Your rules are checked by Suricata before they replace the \
            running ones.",
    applier: "ids",
    fields: &FIELDS,
    colls: &[
        Coll {
            key: "sources",
            title: "Rule sets (downloaded)",
            table: "ids_sources",
            fields: &SOURCE_FIELDS,
            unique: Some("key"),
        },
        Coll {
            key: "policies",
            title: "Policy per rule set / category / classtype",
            table: "ids_policies",
            fields: &POLICY_FIELDS,
            unique: None,
        },
        Coll {
            key: "overrides",
            title: "Rule overrides (by SID)",
            table: "ids_overrides",
            fields: &OVERRIDE_FIELDS,
            unique: None,
        },
        Coll {
            key: "suppress",
            title: "Suppress and threshold",
            table: "ids_suppress",
            fields: &SUPPRESS_FIELDS,
            unique: None,
        },
        Coll {
            key: "interfaces",
            title: "More interfaces to watch",
            table: "ids_ifaces",
            fields: &IFACE_FIELDS,
            unique: None,
        },
        Coll {
            key: "rules",
            title: "Your own rules",
            table: "ids_rules",
            fields: &RULE_FIELDS,
            unique: None,
        },
    ],
    actions: &[("update", "Update rule sets now")],
};

pub struct IdsSvc;

fn check_net(s: &str) -> bool {
    s == "any" || s.parse::<ipnetwork::IpNetwork>().is_ok() || s.parse::<std::net::IpAddr>().is_ok()
}

/// HOME_NET: comma-separated networks, each parseable.
pub fn check_home_net(s: &str) -> Result<Vec<String>> {
    let v: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect();
    if v.is_empty() || v.iter().any(|n| n.parse::<ipnetwork::IpNetwork>().is_err()) {
        return Err(invalid(format!(
            "protected networks {s:?} (comma-separated address/prefix)"
        )));
    }
    Ok(v)
}

fn check_rule(body: &Value) -> Result<()> {
    for k in ["src", "dst"] {
        if let Some(v) = body.get(k).and_then(Value::as_str) {
            if !v.trim().is_empty() && !check_net(v.trim()) {
                return Err(invalid(format!(
                    "rule {k} {v:?} (any or an address/prefix)"
                )));
            }
        }
    }
    if let Some(v) = body.get("dport").and_then(Value::as_str) {
        let v = v.trim();
        if !v.is_empty() && v != "any" && v.parse::<u16>().is_err() {
            return Err(invalid(format!("rule port {v:?} (any or 1-65535)")));
        }
    }
    Ok(())
}

/// The row as it will be stored: the stored row (when editing) with the request's fields on top.
async fn effective(
    store: &ConfigStore,
    c: &Coll,
    id: Option<i64>,
    body: &Value,
) -> Result<serde_json::Map<String, Value>> {
    let mut m = serde_json::Map::new();
    if let Some(id) = id {
        if let Some(r) = svc::raw_rows(store, c)
            .await?
            .into_iter()
            .find(|r| r["id"].as_i64() == Some(id))
        {
            m = r;
        }
    }
    if let Some(o) = body.as_object() {
        for (k, v) in o {
            m.insert(k.clone(), v.clone());
        }
    }
    Ok(m)
}

fn gs(m: &serde_json::Map<String, Value>, k: &str) -> String {
    match m.get(k) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// An address or address/prefix, or empty.
fn check_ip_or_net(s: &str) -> bool {
    s.is_empty()
        || s.parse::<std::net::IpAddr>().is_ok()
        || s.parse::<ipnetwork::IpNetwork>().is_ok()
}

async fn check_row(store: &ConfigStore, coll: &str, id: Option<i64>, body: &Value) -> Result<()> {
    let c = svc::find_coll(&SPEC, coll)?;
    match coll {
        "rules" => check_rule(body),
        "sources" => {
            let m = effective(store, c, id, body).await?;
            let key = gs(&m, "key");
            if key.is_empty()
                || key.len() > 32
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid(format!(
                    "rule set short name {key:?} (letters, digits, - and _, at most 32)"
                )));
            }
            ids_sets::check_url(&gs(&m, "url"))
        }
        "policies" => {
            let m = effective(store, c, id, body).await?;
            let (scope, target) = (gs(&m, "scope"), gs(&m, "target"));
            let dup = svc::raw_rows(store, c).await?.iter().any(|r| {
                r["id"].as_i64() != id && gs(r, "scope") == scope && gs(r, "target") == target
            });
            if dup {
                return Err(invalid(format!(
                    "request: a policy for {scope} {target:?} already exists (change that one)"
                )));
            }
            Ok(())
        }
        "overrides" => {
            let m = effective(store, c, id, body).await?;
            let sid = gs(&m, "sid");
            let dup = svc::raw_rows(store, c)
                .await?
                .iter()
                .any(|r| r["id"].as_i64() != id && gs(r, "sid") == sid);
            if dup {
                return Err(invalid(format!(
                    "request: rule {sid} already has an override (change that one)"
                )));
            }
            Ok(())
        }
        "suppress" => {
            let m = effective(store, c, id, body).await?;
            let (kind, track, ip) = (gs(&m, "kind"), gs(&m, "track"), gs(&m, "ip"));
            let tracked = track == "by_src" || track == "by_dst";
            if !check_ip_or_net(&ip) {
                return Err(invalid(format!(
                    "suppress address {ip:?} (an address or address/prefix)"
                )));
            }
            if kind == "suppress" {
                if !ip.is_empty() && !tracked {
                    return Err(invalid(
                        "suppress: an address needs \"Tracked by\" by_src or by_dst",
                    ));
                }
            } else {
                if !tracked {
                    return Err(invalid(format!(
                        "{kind}: \"Tracked by\" must be by_src or by_dst"
                    )));
                }
                if !ip.is_empty() {
                    return Err(invalid(format!(
                        "{kind}: an address only works for suppress"
                    )));
                }
                if gs(&m, "count").is_empty() || gs(&m, "seconds").is_empty() {
                    return Err(invalid(format!("{kind}: count and period are required")));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[async_trait]
impl Svc for IdsSvc {
    fn spec(&self) -> &'static Spec {
        &SPEC
    }

    async fn put(&self, store: &ConfigStore, body: &Value) -> Result<()> {
        if let Some(h) = body.get("home_net").and_then(Value::as_str) {
            check_home_net(h)?;
        }
        svc::put_settings(store, &SPEC, body).await
    }

    async fn save_row(
        &self,
        store: &ConfigStore,
        coll: &str,
        id: Option<i64>,
        body: &Value,
    ) -> Result<i64> {
        let c = svc::find_coll(&SPEC, coll)?;
        check_row(store, coll, id, body).await?;
        svc::save_row(store, c, id, body).await
    }

    async fn action(&self, store: &ConfigStore, name: &str, _body: &Value) -> Result<Value> {
        match name {
            "update" => {
                ids_sets::request_update(store).await?;
                Ok(
                    json!({"requested": true, "note": "the rule sets are downloaded and checked now; see the status below"}),
                )
            }
            _ => Err(invalid(format!("request: no action {name:?}"))),
        }
    }

    /// "Update now" is a request the root applier acts on while it applies.
    fn action_applies(&self, name: &str) -> bool {
        name == "update"
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub sid: i64,
    pub action: String,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub dport: String,
    pub content: String,
    pub msg: String,
}

pub async fn rules(store: &ConfigStore) -> Result<Vec<Rule>> {
    Ok(svc::raw_rows(store, svc::find_coll(&SPEC, "rules")?)
        .await?
        .iter()
        .filter(|r| lan::flag(r["enabled"].as_str().unwrap_or("")))
        .map(|r| {
            let g = |k: &str, d: &str| {
                let v = r[k].as_str().unwrap_or("");
                if v.is_empty() {
                    d.to_string()
                } else {
                    v.to_string()
                }
            };
            Rule {
                sid: 1_000_000 + r["id"].as_i64().unwrap_or(0),
                action: g("action", "alert"),
                proto: g("proto", "tcp"),
                src: g("src", "any"),
                dst: g("dst", "any"),
                dport: g("dport", "any"),
                content: g("content", ""),
                msg: g("msg", "Patronus rule"),
            }
        })
        .collect())
}

/// One Suricata rule line (message sanitised: no quote, semicolon, backslash).
pub fn render_rule(r: &Rule) -> String {
    let msg: String = r
        .msg
        .chars()
        .filter(|c| !matches!(c, '"' | ';' | '\\' | '\n' | '\r'))
        .collect();
    let content = if r.content.is_empty() {
        String::new()
    } else {
        format!(" content:\"{}\";", r.content)
    };
    format!(
        "{} {} {} any -> {} {} (msg:\"{}\";{content} sid:{}; rev:1;)\n",
        r.action, r.proto, r.src, r.dst, r.dport, msg, r.sid
    )
}

pub fn render_rules(rs: &[Rule]) -> String {
    let mut c = lan::header("#", "Suricata rules");
    for r in rs {
        c.push_str(&render_rule(r));
    }
    c
}

pub struct YamlInput<'a> {
    pub mode: &'a str,
    pub devices: &'a [String],
    pub home_net: &'a [String],
    pub rules_dir: &'a str,
    pub log_dir: &'a str,
    pub distro_rules: bool,
    pub classification: bool,
}

pub fn render_yaml(i: &YamlInput) -> String {
    let mut c = String::from("%YAML 1.1\n---\n");
    c.push_str(&lan::header("#", "Suricata"));
    c.push_str(&format!(
        "vars:\n  address-groups:\n    HOME_NET: \"[{}]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n    HTTP_SERVERS: \"$HOME_NET\"\n    SMTP_SERVERS: \"$HOME_NET\"\n    SQL_SERVERS: \"$HOME_NET\"\n    DNS_SERVERS: \"$HOME_NET\"\n    TELNET_SERVERS: \"$HOME_NET\"\n    AIM_SERVERS: \"$EXTERNAL_NET\"\n    DC_SERVERS: \"$HOME_NET\"\n    DNP3_SERVER: \"$HOME_NET\"\n    DNP3_CLIENT: \"$HOME_NET\"\n    MODBUS_CLIENT: \"$HOME_NET\"\n    MODBUS_SERVER: \"$HOME_NET\"\n    ENIP_CLIENT: \"$HOME_NET\"\n    ENIP_SERVER: \"$HOME_NET\"\n  port-groups:\n    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n    ORACLE_PORTS: 1521\n    SSH_PORTS: 22\n    DNP3_PORTS: 20000\n    MODBUS_PORTS: 502\n    FILE_DATA_PORTS: \"[$HTTP_PORTS,110,143]\"\n    FTP_PORTS: 21\n    GENEVE_PORTS: 6081\n    VXLAN_PORTS: 4789\n    TEREDO_PORTS: 3544\n",
        i.home_net.join(",")
    ));
    c.push_str(&format!(
        "default-log-dir: {}\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - alert\n",
        i.log_dir
    ));
    c.push_str(
        "logging:\n  default-log-level: notice\n  outputs:\n    - console:\n        enabled: yes\n",
    );
    if i.mode == "ips" {
        c.push_str(&format!("nfq:\n  mode: accept\n  fail-open: yes\n  # queue {QUEUE} is where the firewall sends forwarded traffic\n"));
    } else {
        c.push_str("af-packet:\n");
        for d in i.devices {
            c.push_str(&format!("  - interface: {d}\n    cluster-id: 99\n    cluster-type: cluster_flow\n    defrag: yes\n"));
        }
    }
    c.push_str(&format!(
        "default-rule-path: {}\nthreshold-file: {}/threshold.config\nrule-files:\n  - patronus.rules\n  - sources.rules\n",
        i.rules_dir, i.rules_dir
    ));
    if i.distro_rules {
        c.push_str(&format!("  - {DISTRO_RULES}\n"));
    }
    if i.classification {
        c.push_str("classification-file: /etc/suricata/classification.config\nreference-config-file: /etc/suricata/reference.config\n");
    }
    c.push_str("app-layer:\n  protocols:\n    http:\n      enabled: yes\n    dns:\n      enabled: yes\n    tls:\n      enabled: yes\n");
    c.push_str("host-mode: auto\nrunmode: workers\n");
    c
}

/// The last `n` alerts of an eve.json (newest last).
pub fn recent_alerts(eve: &std::path::Path, n: usize) -> Vec<Value> {
    let mut v: Vec<Value> = svc::tail_lines(eve, 2000)
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|j| j["event_type"] == "alert")
        .map(|j| {
            json!({
                "time": j["timestamp"],
                "signature": j["alert"]["signature"],
                "action": j["alert"]["action"],
                "src": format!("{}:{}", j["src_ip"].as_str().unwrap_or("?"), j["src_port"]),
                "dst": format!("{}:{}", j["dest_ip"].as_str().unwrap_or("?"), j["dest_port"]),
                "proto": j["proto"],
            })
        })
        .collect();
    let skip = v.len().saturating_sub(n);
    v.drain(..skip);
    v
}

/// One run of the applier or of the background task at a time: both write the rule files.
static RUN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
pub struct IdsApplier {
    sup: Supervisor,
    log_dir: std::path::PathBuf,
    /// Run `suricata -T` before replacing the running instance.
    check: bool,
}

impl Default for IdsApplier {
    fn default() -> Self {
        Self {
            sup: Supervisor::detect(),
            log_dir: LOG_DIR.into(),
            check: true,
        }
    }
}

/// Everything the config says about the running IDS.
struct Plan {
    s: Settings,
    devs: Vec<String>,
    home: Vec<String>,
    rules: Vec<Rule>,
}

impl IdsApplier {
    pub fn with_supervisor(sup: Supervisor, log_dir: std::path::PathBuf, check: bool) -> Self {
        Self {
            sup,
            log_dir,
            check,
        }
    }

    fn dir(&self) -> std::path::PathBuf {
        self.sup.paths.state_dir.join("suricata")
    }

    async fn plan(&self, store: &ConfigStore) -> Result<Plan> {
        let s = Settings::load(store, &SPEC).await?;
        let mut devs = lan::resolve_iface(store, &s.s("interface")).await?;
        for r in svc::raw_rows(store, svc::find_coll(&SPEC, "interfaces")?).await? {
            if !lan::flag(r["enabled"].as_str().unwrap_or("")) {
                continue;
            }
            for d in lan::resolve_iface(store, r["iface"].as_str().unwrap_or("")).await? {
                if !devs.contains(&d) {
                    devs.push(d);
                }
            }
        }
        let home = check_home_net(&s.s("home_net"))?;
        Ok(Plan {
            s,
            devs,
            home,
            rules: rules(store).await?,
        })
    }

    fn schedule(s: &Settings) -> Schedule {
        Schedule {
            enabled: s.b("update_enabled"),
            hour: s.n("update_hour"),
            window_hours: s.n("update_window_hours"),
            interval_hours: s.n("update_interval_hours"),
        }
    }

    fn yaml_for(&self, p: &Plan, rules_dir: &std::path::Path) -> String {
        render_yaml(&YamlInput {
            mode: &p.s.s("mode"),
            devices: &p.devs,
            home_net: &p.home,
            rules_dir: &rules_dir.to_string_lossy(),
            log_dir: &self.log_dir.to_string_lossy(),
            distro_rules: p.s.b("distro_rules") && std::path::Path::new(DISTRO_RULES).exists(),
            classification: std::path::Path::new("/etc/suricata/classification.config").exists(),
        })
    }

    /// `suricata -T` on the bundle (`patronus.rules`, `sources.rules`, `threshold.config`) in `dir`.
    fn test_bundle(
        &self,
        bin: &std::path::Path,
        p: &Plan,
        dir: &std::path::Path,
    ) -> std::result::Result<(), String> {
        let cand = dir.join("suricata.yaml.new");
        write_atomic(&cand, &self.yaml_for(p, dir), 0o644).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&self.log_dir).ok();
        let o = std::process::Command::new(bin)
            .args(["-T", "-c"])
            .arg(&cand)
            .arg("-l")
            .arg(&self.log_dir)
            .output()
            .map_err(|e| format!("suricata -T: {e}"))?;
        let _ = std::fs::remove_file(&cand);
        if o.status.success() {
            return Ok(());
        }
        let out = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        let tail: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("rror") || l.contains("ERR"))
            .take(6)
            .collect();
        Err(if tail.is_empty() {
            out.trim().chars().take(400).collect::<String>()
        } else {
            tail.join(" | ")
        })
    }

    /// Download the sources that are due (`force`: all enabled ones), check them against the rest
    /// of the running set and swap them in. Caller holds [`RUN`].
    async fn run_update(
        &self,
        store: &ConfigStore,
        p: &Plan,
        force: bool,
    ) -> Result<Vec<ids_sets::Outcome>> {
        let dir = self.dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Service(format!("{}: {e}", dir.display())))?;
        let bin = which("suricata");
        let thr = ids_sets::render_threshold(store).await?;
        let extra = Extra {
            files: vec![
                ("patronus.rules", render_rules(&p.rules)),
                ("threshold.config", thr),
            ],
        };
        let version = bin.as_deref().and_then(ids_sets::suricata_version);
        let fetch = CurlFetch {
            tmp: dir.join("dl"),
        };
        let check = self.check;
        let mut validate = |cand: &std::path::Path| -> std::result::Result<(), String> {
            match (&bin, check) {
                (Some(b), true) => self.test_bundle(b, p, cand),
                _ => Ok(()),
            }
        };
        ids_sets::update(
            store,
            &dir,
            &fetch,
            &Self::schedule(&p.s),
            force,
            version.as_deref(),
            &extra,
            &mut validate,
        )
        .await
    }

    /// One pass of the background task: collect alerts, apply retention, and download the rule
    /// sets that are due (then re-apply so the daemon runs them).
    pub async fn tick(&self, store: &ConfigStore) {
        if let Err(e) = ids_alerts::ingest(store, &self.log_dir.join("eve.json")).await {
            tracing::warn!("ids alerts: {e}");
        }
        let Ok(p) = self.plan(store).await else {
            return;
        };
        static LAST_PRUNE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        let t = lan::now();
        if t - LAST_PRUNE.load(std::sync::atomic::Ordering::Relaxed) >= 600 {
            LAST_PRUNE.store(t, std::sync::atomic::Ordering::Relaxed);
            if let Err(e) = ids_alerts::prune(
                store,
                p.s.n("alert_retention_days"),
                p.s.n("alert_max_rows"),
            )
            .await
            {
                tracing::warn!("ids alert retention: {e}");
            }
        }
        if !p.s.b("enabled") || !p.s.b("update_enabled") {
            return;
        }
        let changed = {
            let _g = RUN.lock().await;
            match self.run_update(store, &p, false).await {
                Ok(o) => o.iter().any(|x| x.status == "ok"),
                Err(e) => {
                    tracing::warn!("ids rule-set update: {e}");
                    false
                }
            }
        };
        if changed {
            if let Err(e) = self.apply(store).await {
                tracing::warn!("ids apply after the rule-set update: {e}");
            }
        }
    }
}

/// The background task of the root process (applyd, or patronus-web when there is no applyd):
/// every `PATRONUS_IDS_TICK_SECS` (default 60) collect alerts and run due rule-set updates.
pub fn spawn_task(store: std::sync::Arc<ConfigStore>, only_without_applyd: bool) {
    let secs = std::env::var("PATRONUS_IDS_TICK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(60);
    tokio::spawn(async move {
        let a = IdsApplier::default();
        let mut t = tokio::time::interval(std::time::Duration::from_secs(secs));
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            t.tick().await;
            if only_without_applyd && crate::applyd::socket_path().exists() {
                continue;
            }
            a.tick(&store).await;
        }
    });
}

#[async_trait]
impl Applier for IdsApplier {
    fn name(&self) -> &'static str {
        "ids"
    }

    fn phase(&self) -> Phase {
        Phase::Services
    }

    async fn apply(&self, store: &ConfigStore) -> Result<ApplyReport> {
        let _g = RUN.lock().await;
        let mut rep = ApplyReport::default();
        let p = self.plan(store).await?;
        let s = &p.s;
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            rep.applied(if was {
                "intrusion detection stopped"
            } else {
                "intrusion detection is off"
            });
            return Ok(rep);
        }
        if p.devs.is_empty() {
            return Err(invalid(format!(
                "intrusion detection: interface {} is not assigned to any device",
                s.s("interface")
            )));
        }
        let bin = which("suricata").ok_or_else(|| {
            Error::Service(
                "intrusion detection needs suricata, which is not installed (emerge \
                 net-analyzer/suricata, USE=intrusion-detection suricata)"
                    .into(),
            )
        })?;
        let dir = self.dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Service(format!("{}: {e}", dir.display())))?;
        std::fs::create_dir_all(&self.log_dir).ok();
        let ips = s.s("mode") == "ips";

        // "Update now": download and check the rule sets first (refusals are recorded per source
        // and never fail the apply: the running rules stay)
        let (asked, done) = ids_sets::update_request(store).await;
        if asked > done {
            match self.run_update(store, &p, true).await {
                Ok(outs) => {
                    for o in outs {
                        rep.applied(format!("rule set {}: {} ({})", o.key, o.status, o.message));
                    }
                }
                Err(e) => rep.warn(format!("rule-set update: {e}")),
            }
            ids_sets::mark_update_done(store, lan::now()).await;
        }

        // the candidate bundle: checked by Suricata before anything live is touched
        let sets = ids_sets::render_sources(store, &dir, None).await?;
        let thr = ids_sets::render_threshold(store).await?;
        let custom = render_rules(&p.rules);
        if self.check {
            let cand = dir.join("apply-cand");
            let _ = std::fs::remove_dir_all(&cand);
            std::fs::create_dir_all(&cand)
                .map_err(|e| Error::Service(format!("{}: {e}", cand.display())))?;
            for (n, c) in [
                ("patronus.rules", &custom),
                ("sources.rules", &sets.text),
                ("threshold.config", &thr),
            ] {
                std::fs::write(cand.join(n), c)
                    .map_err(|e| Error::Service(format!("{}: {e}", cand.display())))?;
            }
            let verdict = self.test_bundle(&bin, &p, &cand);
            let _ = std::fs::remove_dir_all(&cand);
            if let Err(why) = verdict {
                return Err(invalid(format!(
                    "intrusion detection config (rejected by suricata -T, previous rules kept): {why}"
                )));
            }
        }
        let conf = dir.join("suricata.yaml");
        let yaml = self.yaml_for(&p, &dir);
        let rules_path = dir.join("patronus.rules");
        let sets_path = dir.join("sources.rules");
        let thr_path = dir.join("threshold.config");

        let mut argv: Vec<String> = vec![
            bin.to_string_lossy().into(),
            "-c".into(),
            conf.to_string_lossy().into(),
            "-l".into(),
            self.log_dir.to_string_lossy().into(),
            "--pidfile".into(),
            self.sup
                .paths
                .run_dir
                .join("suricata.pid")
                .to_string_lossy()
                .into(),
        ];
        if ips {
            argv.push("-q".into());
            argv.push(QUEUE.to_string());
        } else {
            argv.push("--af-packet".into());
        }
        std::fs::create_dir_all(&self.sup.paths.run_dir).ok();
        // the supervisor fingerprints the files it is given: a rule, policy or threshold edit
        // changes one of them, so the daemon restarts with the new set
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            argv,
            vec![
                (conf, yaml, 0o644),
                (rules_path, custom, 0o644),
                (sets_path, sets.text.clone(), 0o644),
                (thr_path, thr, 0o644),
            ],
        )
        .await?;
        rep.applied(format!(
            "suricata {} ({} mode on {}, {} custom rule(s), {} rule(s) from {} rule set(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            if ips { "inline IPS" } else { "IDS" },
            p.devs.join(", "),
            p.rules.len(),
            sets.loaded(),
            sets.per_source.len(),
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let p = self.plan(store).await?;
        if !p.s.b("enabled") {
            return Ok("# intrusion detection off\n".into());
        }
        let sets = ids_sets::render_sources(store, &self.dir(), None).await?;
        let st: Vec<String> = sets
            .per_source
            .iter()
            .map(|(k, v)| {
                format!(
                    "# rule set {k}: {} loaded, {} dropping",
                    v.loaded, v.dropping
                )
            })
            .collect();
        Ok(format!(
            "## patronus.rules\n{}\n## sources.rules\n{}\n## threshold.config\n{}",
            render_rules(&p.rules),
            st.join("\n"),
            ids_sets::render_threshold(store).await?
        ))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let rs = rules(store).await?;
        let dir = self.dir();
        let (mut loaded, mut dropping) = (0usize, 0usize);
        if let Ok(t) = std::fs::read_to_string(dir.join("sources.rules")) {
            for l in t.lines() {
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                loaded += 1;
                if l.starts_with("drop ") || l.starts_with("reject") {
                    dropping += 1;
                }
            }
        }
        let sm = ids_alerts::summary(store).await.unwrap_or(Value::Null);
        let last_ok = ids_sets::state(store)
            .await
            .map(|m| m.values().filter_map(|x| x.ok_at).max())
            .unwrap_or(None);
        Ok(json!({
            "enabled": s.b("enabled"),
            "mode": s.s("mode"),
            "installed": which("suricata").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "custom_rules": rs.len(),
            "distro_rules_present": std::path::Path::new(DISTRO_RULES).exists(),
            "rules_loaded": loaded,
            "rules_dropping": dropping,
            "rule_sets": ids_sets::overview(store, &dir).await.unwrap_or(Value::Null),
            "last_rule_update": last_ok,
            "alerts_24h": sm["alerts_24h"],
            "blocked_24h": sm["blocked_24h"],
            "alerts": recent_alerts(&self.log_dir.join("eve.json"), 25),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{InitMode, NetPaths};

    #[test]
    fn rules_are_rendered_with_stable_sids_and_sanitised_messages() {
        let r = render_rule(&Rule {
            sid: 1_000_007,
            action: "drop".into(),
            proto: "tcp".into(),
            src: "any".into(),
            dst: "192.168.50.0/24".into(),
            dport: "80".into(),
            content: "evil-pattern".into(),
            msg: "bad \"thing\"; really\\".into(),
        });
        assert_eq!(
            r,
            "drop tcp any any -> 192.168.50.0/24 80 (msg:\"bad thing really\"; content:\"evil-pattern\"; sid:1000007; rev:1;)\n"
        );
    }

    #[test]
    fn yaml_has_the_mode_specific_capture_section() {
        let devs = vec!["eth0".to_string()];
        let home = vec!["192.168.0.0/16".to_string()];
        let mk = |mode: &str| {
            render_yaml(&YamlInput {
                mode,
                devices: &devs,
                home_net: &home,
                rules_dir: "/r",
                log_dir: "/l",
                distro_rules: false,
                classification: false,
            })
        };
        let ids = mk("ids");
        assert!(ids.contains("af-packet:\n  - interface: eth0") && !ids.contains("nfq:"));
        assert!(
            ids.contains("HOME_NET: \"[192.168.0.0/16]\"") && ids.contains("default-rule-path: /r")
        );
        let ips = mk("ips");
        assert!(ips.contains("nfq:") && !ips.contains("af-packet:"));
    }

    #[test]
    fn alerts_are_read_from_eve_json() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("eve.json");
        std::fs::write(
            &p,
            "{\"event_type\":\"stats\"}\n{\"timestamp\":\"t1\",\"event_type\":\"alert\",\"src_ip\":\"1.1.1.1\",\"src_port\":5,\"dest_ip\":\"2.2.2.2\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"signature\":\"bad\",\"action\":\"allowed\"}}\nnot json\n",
        )
        .unwrap();
        let a = recent_alerts(&p, 10);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["signature"], "bad");
        assert_eq!(a[0]["dst"], "2.2.2.2:80");
    }

    /// By hand (`IDS_YAML_OUT=/x/suricata.yaml IDS_RULES_DIR=/x cargo test ... -- --ignored`): the
    /// generated config for a real rule set, so a real Suricata can be asked to load ET Open with it.
    #[test]
    #[ignore = "writes a config for a manual run against a real rule set"]
    fn dump_yaml_for_a_real_rule_set() {
        let out = std::env::var("IDS_YAML_OUT").expect("IDS_YAML_OUT");
        let dir = std::env::var("IDS_RULES_DIR").expect("IDS_RULES_DIR");
        let y = render_yaml(&YamlInput {
            mode: "ids",
            devices: &["eth0".to_string()],
            home_net: &["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
            rules_dir: &dir,
            log_dir: "/tmp/ids-log",
            distro_rules: false,
            classification: std::path::Path::new("/etc/suricata/classification.config").exists(),
        });
        std::fs::write(out, y).unwrap();
    }

    #[tokio::test]
    async fn rules_are_validated_and_apply_preconditions() {
        let s = crate::lan::testutil::store().await;
        let d = tempfile::tempdir().unwrap();
        let a = IdsApplier::with_supervisor(
            Supervisor::new(InitMode::Direct, NetPaths::under(d.path())),
            d.path().join("log"),
            false,
        );
        a.apply(&s).await.unwrap();
        for bad in [
            json!({"msg": "x", "src": "1.2.3.4; drop"}),
            json!({"msg": "x", "dport": "http"}),
            json!({"msg": "x", "content": "a\"b"}),
            json!({"msg": "x", "proto": "gre"}),
            json!({"src": "any"}),
        ] {
            assert!(
                IdsSvc.save_row(&s, "rules", None, &bad).await.is_err(),
                "{bad}"
            );
        }
        assert!(IdsSvc
            .put(&s, &json!({"home_net": "10.0.0.0/8, nope"}))
            .await
            .is_err());
        IdsSvc
            .save_row(
                &s,
                "rules",
                None,
                &json!({"msg": "http test", "content": "evil", "dport": "80"}),
            )
            .await
            .unwrap();
        IdsSvc.put(&s, &json!({"enabled": true})).await.unwrap();
        if which("suricata").is_none() {
            assert!(a
                .apply(&s)
                .await
                .unwrap_err()
                .to_string()
                .contains("suricata"));
        }
        let r = a.render(&s).await.unwrap();
        assert!(r.contains("alert tcp any any -> any 80 (msg:\"http test\"; content:\"evil\"; sid:1000001; rev:1;)"), "{r}");
    }
}
