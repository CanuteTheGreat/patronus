//! Boot rollback of the router tier (`patronus-guard`, docs/embedded-routers.md 12.14): its state for the System >
//! Firmware page and `/api/system/firmware`, its policy file (`/etc/patronus/boot-guard.conf`, the one source of truth
//! the guard itself reads in the early boot) and the manual rollback / confirm actions. Runs as root (applyd).
//!
//! The policy file holds plain `KEY=value` lines; only the keys below are managed here, every other line is kept.

use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Paths (environment overrides for tests and other boards).
#[derive(Debug, Clone)]
pub struct GuardPaths {
    /// `patronus-guard` (router-tier images only)
    pub tool: PathBuf,
    /// `patronus-flash` (rollback with restart)
    pub flash: PathBuf,
    /// the unit's policy file
    pub conf: PathBuf,
}

impl Default for GuardPaths {
    fn default() -> Self {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
        GuardPaths {
            tool: p("PATRONUS_GUARD", "/usr/sbin/patronus-guard"),
            flash: p("PATRONUS_FLASH", "/usr/sbin/patronus-flash"),
            conf: p("PATRONUS_GUARD_CONF", "/etc/patronus/boot-guard.conf"),
        }
    }
}

/// Managed settings: JSON name, file key, kind.
enum Kind {
    Bool,
    Int(i64, i64),
    Checks,
    Ping,
    Hostapd,
}

const KEYS: &[(&str, &str, Kind)] = &[
    ("enabled", "GUARD_ENABLED", Kind::Bool),
    ("require", "GUARD_REQUIRE", Kind::Bool),
    ("attempts", "GUARD_ATTEMPTS", Kind::Int(1, 9)),
    ("window_s", "GUARD_WINDOW", Kind::Int(60, 3600)),
    ("interval_s", "GUARD_INTERVAL", Kind::Int(2, 60)),
    ("pass_rounds", "GUARD_PASS_ROUNDS", Kind::Int(1, 20)),
    ("checks", "GUARD_CHECKS", Kind::Checks),
    ("net_ping", "GUARD_NET_PING", Kind::Ping),
    ("hostapd", "GUARD_HOSTAPD", Kind::Hostapd),
    ("watchdog", "GUARD_WATCHDOG", Kind::Bool),
    (
        "watchdog_timeout_s",
        "GUARD_WATCHDOG_TIMEOUT",
        Kind::Int(5, 32),
    ),
    ("reboot_grace_s", "GUARD_REBOOT_GRACE", Kind::Int(10, 600)),
];
const CHECKS: &[&str] = &["network", "ssh", "web", "hostapd"];

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid boot rollback setting: {}", m.into()))
}

/// The value written to the file for one setting, validated.
fn file_value(kind: &Kind, name: &str, v: &Value) -> Result<String> {
    match kind {
        Kind::Bool => v
            .as_bool()
            .map(|b| if b { "1" } else { "0" }.to_string())
            .ok_or_else(|| invalid(format!("{name} must be true or false"))),
        Kind::Int(lo, hi) => match v.as_i64() {
            Some(n) if n >= *lo && n <= *hi => Ok(n.to_string()),
            _ => Err(invalid(format!(
                "{name} must be a whole number from {lo} to {hi}"
            ))),
        },
        Kind::Checks => {
            let s = v
                .as_str()
                .ok_or_else(|| invalid("checks must be a space-separated list"))?;
            let mut out: Vec<&str> = Vec::new();
            for c in s.split([' ', ',']).filter(|c| !c.is_empty()) {
                if !CHECKS.contains(&c) {
                    return Err(invalid(format!(
                        "unknown check {c:?} (network, ssh, web, hostapd)"
                    )));
                }
                if !out.contains(&c) {
                    out.push(c);
                }
            }
            Ok(format!("\"{}\"", out.join(" ")))
        }
        Kind::Ping => {
            let s = v.as_str().unwrap_or("").trim();
            if s == "gateway" || s == "none" || s.parse::<std::net::IpAddr>().is_ok() {
                Ok(s.to_string())
            } else {
                Err(invalid("net_ping must be gateway, none or an IP address"))
            }
        }
        Kind::Hostapd => match v.as_str() {
            Some(s @ ("auto" | "require" | "off")) => Ok(s.to_string()),
            _ => Err(invalid("hostapd must be auto, require or off")),
        },
    }
}

/// New file text: `params` applied over `old` (managed keys rewritten in place or appended, other lines kept).
pub fn render_conf(old: &str, params: &Value) -> Result<String> {
    let obj = params
        .as_object()
        .ok_or_else(|| invalid("expected an object of settings"))?;
    for k in obj.keys() {
        if !KEYS.iter().any(|(n, _, _)| n == k) {
            return Err(invalid(format!("unknown setting {k:?}")));
        }
    }
    let mut set: Vec<(&str, String)> = Vec::new();
    for (name, key, kind) in KEYS {
        if let Some(v) = obj.get(*name) {
            set.push((key, file_value(kind, name, v)?));
        }
    }
    // the watchdog is fed every interval: the interval must stay well inside its timeout
    let cur = |key: &str, dflt: i64| -> i64 {
        set.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.parse().unwrap_or(dflt))
            .or_else(|| conf_value(old, key).and_then(|v| v.parse().ok()))
            .unwrap_or(dflt)
    };
    if cur("GUARD_INTERVAL", 5) * 2 > cur("GUARD_WATCHDOG_TIMEOUT", 30) {
        return Err(invalid(
            "interval_s must be at most half of watchdog_timeout_s",
        ));
    }
    if cur("GUARD_WINDOW", 300) < cur("GUARD_INTERVAL", 5) * cur("GUARD_PASS_ROUNDS", 2) {
        return Err(invalid("window_s is shorter than pass_rounds x interval_s"));
    }
    let mut out = String::new();
    let mut done: Vec<&str> = Vec::new();
    for line in old.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        if let Some((k, v)) = set.iter().find(|(k, _)| *k == key) {
            out.push_str(&format!("{k}={v}\n"));
            done.push(k);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    for (k, v) in &set {
        if !done.contains(k) {
            out.push_str(&format!("{k}={v}\n"));
        }
    }
    Ok(out)
}

fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix(&format!("{key}=")))
        .last()
        .map(|v| {
            v.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string()
        })
}

/// State for the UI: `patronus-guard status --json` (reads the bootloader environment), or null without the guard.
pub fn status_in(p: &GuardPaths) -> Value {
    if !p.tool.is_file() {
        return Value::Null;
    }
    match std::process::Command::new(&p.tool)
        .args(["status", "--json"])
        .output()
    {
        Ok(o) => serde_json::from_slice(&o.stdout).unwrap_or_else(
            |e| json!({ "available": true, "error": format!("unreadable status: {e}") }),
        ),
        Err(e) => json!({ "available": true, "error": e.to_string() }),
    }
}

pub fn status() -> Value {
    status_in(&GuardPaths::default())
}

/// Save settings to the policy file (temp file + rename), then return the fresh state.
pub fn set_in(p: &GuardPaths, params: &Value) -> Result<Value> {
    if !p.tool.is_file() {
        return Err(Error::Config(
            "Invalid: this firmware has no boot rollback".into(),
        ));
    }
    let old = std::fs::read_to_string(&p.conf).unwrap_or_default();
    let new = render_conf(&old, params)?;
    let tmp = p.conf.with_extension("conf.new");
    std::fs::write(&tmp, new).map_err(|e| Error::Service(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &p.conf)
        .map_err(|e| Error::Service(format!("{}: {e}", p.conf.display())))?;
    Ok(status_in(p))
}

fn run(tool: &Path, args: &[&str]) -> Result<Value> {
    let o = std::process::Command::new(tool)
        .args(args)
        .output()
        .map_err(|e| Error::Service(format!("{}: {e}", tool.display())))?;
    let mut msg = String::from_utf8_lossy(&o.stdout).into_owned();
    msg.push_str(&String::from_utf8_lossy(&o.stderr));
    if !o.status.success() {
        return Err(Error::Config(format!("Invalid: {}", msg.trim())));
    }
    Ok(json!({ "output": msg.trim() }))
}

/// `rollback`: the previous image is put back by the bootloader at the next restart (the caller restarts).
/// `confirm`: confirm a running trial by hand.
pub fn action_in(p: &GuardPaths, what: &str) -> Result<Value> {
    if !p.tool.is_file() {
        return Err(Error::Config(
            "Invalid: this firmware has no boot rollback".into(),
        ));
    }
    let mut v = match what {
        "rollback" => run(&p.flash, &["rollback"])?,
        "confirm" => run(&p.flash, &["confirm"])?,
        other => {
            return Err(Error::Config(format!(
                "Invalid boot rollback action {other:?}"
            )))
        }
    };
    v["boot_guard"] = status_in(p);
    Ok(v)
}

pub fn set(params: &Value) -> Result<Value> {
    set_in(&GuardPaths::default(), params)
}

pub fn action(what: &str) -> Result<Value> {
    action_in(&GuardPaths::default(), what)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_validated_and_other_lines_kept() {
        let old = "# comment\n#GUARD_ATTEMPTS=2\nGUARD_WINDOW=300\nOTHER=x\n";
        let n = render_conf(
            old,
            &json!({"attempts": 3, "window_s": 240, "checks": "web, ssh web", "net_ping": "10.0.0.1", "watchdog": false}),
        )
        .unwrap();
        assert!(
            n.contains("# comment\n#GUARD_ATTEMPTS=2\nGUARD_WINDOW=240\nOTHER=x\n"),
            "{n}"
        );
        assert!(n.contains("GUARD_ATTEMPTS=3\n") && n.contains("GUARD_CHECKS=\"web ssh\"\n"));
        assert!(n.contains("GUARD_NET_PING=10.0.0.1\n") && n.contains("GUARD_WATCHDOG=0\n"));
        assert_eq!(conf_value(&n, "GUARD_CHECKS").as_deref(), Some("web ssh"));
        for bad in [
            json!({"attempts": 0}),
            json!({"attempts": 10}),
            json!({"checks": "web rm"}),
            json!({"net_ping": "$(reboot)"}),
            json!({"hostapd": "maybe"}),
            json!({"watchdog_timeout_s": 60}),
            json!({"interval_s": 20}),
            json!({"window_s": 60, "interval_s": 10, "pass_rounds": 10}),
            json!({"nope": 1}),
            json!([1]),
        ] {
            let e = render_conf(old, &bad).unwrap_err().to_string();
            assert!(e.contains("Invalid boot rollback setting"), "{bad}: {e}");
        }
    }

    #[test]
    fn status_and_actions_go_through_the_tools() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let tool = d.path().join("patronus-guard");
        let flash = d.path().join("patronus-flash");
        std::fs::write(&tool, "#!/bin/sh\n[ \"$1 $2\" = 'status --json' ] && echo '{\"available\":true,\"state\":\"ok\"}'\n").unwrap();
        std::fs::write(&flash, "#!/bin/sh\ncase $1 in rollback) echo 'restored at the next restart';; confirm) echo 'no trial running';; *) exit 1;; esac\n").unwrap();
        for f in [&tool, &flash] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let p = GuardPaths {
            tool,
            flash,
            conf: d.path().join("boot-guard.conf"),
        };
        assert_eq!(status_in(&p)["state"], "ok");
        let v = set_in(&p, &json!({"attempts": 4})).unwrap();
        assert_eq!(v["state"], "ok");
        assert_eq!(
            std::fs::read_to_string(&p.conf).unwrap(),
            "GUARD_ATTEMPTS=4\n"
        );
        assert!(action_in(&p, "rollback").unwrap()["output"]
            .as_str()
            .unwrap()
            .contains("next restart"));
        assert!(action_in(&p, "reboot").is_err());
        let none = GuardPaths {
            tool: d.path().join("missing"),
            ..p
        };
        assert_eq!(status_in(&none), Value::Null);
        assert!(set_in(&none, &json!({})).is_err());
    }
}
