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

static FIELDS: [Field; 5] = [
    Field::new("enabled", "Intrusion detection", Kind::Bool).def("0"),
    Field::new("mode", "Mode", Kind::Select(&["ids", "ips"]))
        .def("ids")
        .help("ids = alert only; ips = inline, rules with action drop block the packets"),
    Field::new("interface", "Watch interface", Kind::Iface).def("@wan"),
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
    colls: &[Coll {
        key: "rules",
        title: "Rules",
        table: "ids_rules",
        fields: &RULE_FIELDS,
        unique: None,
    }],
    actions: &[],
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
        check_rule(body)?;
        let c = svc::find_coll(&SPEC, coll)?;
        svc::save_row(store, c, id, body).await
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
    Ok(svc::raw_rows(store, &SPEC.colls[0])
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
        "default-rule-path: {}\nrule-files:\n  - patronus.rules\n",
        i.rules_dir
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

impl IdsApplier {
    pub fn with_supervisor(sup: Supervisor, log_dir: std::path::PathBuf, check: bool) -> Self {
        Self {
            sup,
            log_dir,
            check,
        }
    }

    async fn plan(
        &self,
        store: &ConfigStore,
    ) -> Result<(Settings, Vec<String>, Vec<String>, Vec<Rule>)> {
        let s = Settings::load(store, &SPEC).await?;
        let devs = lan::resolve_iface(store, &s.s("interface")).await?;
        let home = check_home_net(&s.s("home_net"))?;
        Ok((s, devs, home, rules(store).await?))
    }
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
        let mut rep = ApplyReport::default();
        let (s, devs, home, rs) = self.plan(store).await?;
        if !s.b("enabled") {
            let was = self.sup.stop(svc::DAEMON_SERVICE, INSTANCE).await?;
            rep.applied(if was {
                "intrusion detection stopped"
            } else {
                "intrusion detection is off"
            });
            return Ok(rep);
        }
        if devs.is_empty() {
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
        let dir = self.sup.paths.state_dir.join("suricata");
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Service(format!("{}: {e}", dir.display())))?;
        std::fs::create_dir_all(&self.log_dir).ok();
        let rules_path = dir.join("patronus.rules");
        let conf = dir.join("suricata.yaml");
        let ips = s.s("mode") == "ips";
        let yaml = render_yaml(&YamlInput {
            mode: &s.s("mode"),
            devices: &devs,
            home_net: &home,
            rules_dir: &dir.to_string_lossy(),
            log_dir: &self.log_dir.to_string_lossy(),
            distro_rules: s.b("distro_rules") && std::path::Path::new(DISTRO_RULES).exists(),
            classification: std::path::Path::new("/etc/suricata/classification.config").exists(),
        });
        let new_rules = render_rules(&rs);
        let old_rules = std::fs::read_to_string(&rules_path).ok();
        let rules_changed = write_atomic(&rules_path, &new_rules, 0o644)?;
        let cand = dir.join("suricata.yaml.new");
        if self.check {
            write_atomic(&cand, &yaml, 0o644)?;
            let o = std::process::Command::new(&bin)
                .args([
                    "-T",
                    "-c",
                    &cand.to_string_lossy(),
                    "-l",
                    &self.log_dir.to_string_lossy(),
                ])
                .output()
                .map_err(|e| Error::Service(format!("suricata -T: {e}")))?;
            let _ = std::fs::remove_file(&cand);
            if !o.status.success() {
                if let Some(old) = old_rules {
                    let _ = write_atomic(&rules_path, &old, 0o644);
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
                return Err(invalid(format!(
                    "intrusion detection config (rejected by suricata -T, previous rules kept): {}",
                    if tail.is_empty() {
                        out.trim().chars().take(400).collect::<String>()
                    } else {
                        tail.join(" | ")
                    }
                )));
            }
        }
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
        // rules changed but the file content the supervisor fingerprints is the yaml:
        // put the rules in its file list so a rule edit restarts the daemon
        let started = svc::ensure_daemon(
            &self.sup,
            INSTANCE,
            argv,
            vec![(conf, yaml, 0o644), (rules_path, new_rules, 0o644)],
        )
        .await?;
        let _ = rules_changed;
        rep.applied(format!(
            "suricata {} ({} mode on {}, {} custom rule(s))",
            if started {
                "(re)started"
            } else {
                "running, unchanged"
            },
            if ips { "inline IPS" } else { "IDS" },
            devs.join(", "),
            rs.len()
        ));
        Ok(rep)
    }

    async fn render(&self, store: &ConfigStore) -> Result<String> {
        let (s, _devs, _home, rs) = self.plan(store).await?;
        if !s.b("enabled") {
            return Ok("# intrusion detection off\n".into());
        }
        Ok(format!("## patronus.rules\n{}", render_rules(&rs)))
    }

    async fn status(&self, store: &ConfigStore) -> Result<Value> {
        let s = Settings::load(store, &SPEC).await?;
        let rs = rules(store).await?;
        Ok(json!({
            "enabled": s.b("enabled"),
            "mode": s.s("mode"),
            "installed": which("suricata").is_some(),
            "running": self.sup.is_running(svc::DAEMON_SERVICE, INSTANCE),
            "custom_rules": rs.len(),
            "distro_rules_present": std::path::Path::new(DISTRO_RULES).exists(),
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
