//! Boot environments of a ZFS-root install (standard tier), for the web UI and the console: list them, activate one for
//! the next boot, take a snapshot, roll back to a snapshot, pin or delete. Everything goes through the installed
//! `horcrux-be` tool (package sys-apps/horcrux-be, the shared installer's boot-environment manager, which also keeps one kernel set per environment in
//! /boot and rewrites the boot menu), so the web UI and the command line can never disagree.
//!
//! Runs as root (through `patronus applyd` when the web UI is unprivileged: sysops actions `be_list` and `be_op`).
//! A box without the tool or without a ZFS root answers `available: false` with the reason.

use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::process::Command;

/// The boot-environment tool of ZFS-root installs (package `sys-apps/horcrux-be`, the shared installer's manager).
pub const DEFAULT_TOOL: &str = "/usr/bin/horcrux-be";

/// The tool to run: `PATRONUS_BE_TOOL` (tests, other layouts) or [`DEFAULT_TOOL`].
pub fn tool() -> String {
    std::env::var("PATRONUS_BE_TOOL")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TOOL.to_string())
}

/// What the web UI may ask for. `rollback` creates a new environment from a snapshot and activates it.
pub const OPS: &[&str] = &[
    "activate",
    "destroy",
    "snapshot",
    "rollback",
    "pin",
    "unpin",
    "destroy-snapshot",
];

/// A boot-environment name (`BE`) or a snapshot (`BE@snap`): the characters the tool accepts, never an option.
pub fn valid_name(n: &str, snapshot: bool) -> bool {
    let ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 64
            && !p.starts_with('-')
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    };
    match n.split_once('@') {
        Some((be, s)) => snapshot && ok(be) && ok(s),
        None => ok(n),
    }
}

/// The argument vector of one operation (without the tool), validated.
pub fn op_argv(op: &str, name: Option<&str>) -> Result<Vec<String>> {
    let bad = |m: String| {
        Err(Error::Config(format!(
            "Invalid boot-environment request: {m}"
        )))
    };
    if !OPS.contains(&op) {
        return bad(format!("unknown operation {op:?} ({})", OPS.join(", ")));
    }
    let name = name.map(str::trim).filter(|n| !n.is_empty());
    let needs_snapshot = matches!(op, "destroy-snapshot");
    let takes_snapshot = matches!(op, "rollback" | "pin" | "unpin" | "destroy-snapshot");
    match name {
        None if matches!(op, "snapshot" | "rollback") => Ok(vec![op.to_string()]),
        None => bad(format!("{op} needs a name")),
        Some(n) => {
            if !valid_name(n, takes_snapshot) || (needs_snapshot && !n.contains('@')) {
                return bad(format!("name {n:?}"));
            }
            if op == "rollback" && !n.contains('@') {
                return bad("rollback needs a snapshot (BE@snapshot)".into());
            }
            Ok(vec![op.to_string(), n.to_string()])
        }
    }
}

fn run(args: &[String]) -> Result<(bool, String, String)> {
    let t = tool();
    let out = Command::new(&t)
        .args(args)
        .output()
        .map_err(|e| Error::Config(format!("{t}: {e}")))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// `horcrux-be list --json`, or `{available: false, reason}`.
pub fn list() -> Value {
    let t = tool();
    if !std::path::Path::new(&t).exists() {
        return json!({"available": false,
            "reason": "this install has no boot environments (they exist on a ZFS root; this system was installed on another file system or the tool is missing)"});
    }
    match run(&["list".into(), "--json".into()]) {
        Ok((true, out, _)) => match serde_json::from_str::<Value>(&out) {
            Ok(mut v) => {
                v["available"] = json!(true);
                v
            }
            Err(e) => {
                json!({"available": false, "reason": format!("unreadable answer from {t}: {e}")})
            }
        },
        Ok((false, _, err)) => json!({"available": false, "reason": err.trim()}),
        Err(e) => json!({"available": false, "reason": e.to_string()}),
    }
}

/// Run one operation; the tool's own message is returned (or the error).
pub fn op(op: &str, name: Option<&str>) -> Result<Value> {
    let argv = op_argv(op, name)?;
    let (ok, out, err) = run(&argv)?;
    if ok {
        Ok(json!({"ok": true, "output": out.trim(), "environments": list()}))
    } else {
        let m = err.trim().trim_start_matches("horcrux-be: ").to_string();
        Err(Error::Config(format!(
            "horcrux-be {} failed: {}",
            argv.join(" "),
            if m.is_empty() {
                out.trim().to_string()
            } else {
                m
            }
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_never_become_options_or_paths() {
        assert!(valid_name("default", false));
        assert!(valid_name("rollback-20261125-101500", false));
        assert!(!valid_name("-rf", false));
        assert!(!valid_name("a/b", false));
        assert!(!valid_name("a b", false));
        assert!(!valid_name("", false));
        assert!(!valid_name("be@pre-upgrade-1", false));
        assert!(valid_name("be@pre-upgrade-20261125-0101", true));
        assert!(!valid_name("be@", true));
        assert!(!valid_name("@snap", true));
    }

    #[test]
    fn each_operation_gets_exactly_its_arguments() {
        assert_eq!(
            op_argv("activate", Some("b1")).unwrap(),
            vec!["activate", "b1"]
        );
        assert_eq!(op_argv("snapshot", None).unwrap(), vec!["snapshot"]);
        assert_eq!(op_argv("rollback", None).unwrap(), vec!["rollback"]);
        assert_eq!(
            op_argv("rollback", Some("b1@pre-upgrade-1")).unwrap(),
            vec!["rollback", "b1@pre-upgrade-1"]
        );
        assert!(op_argv("rollback", Some("b1")).is_err());
        assert!(op_argv("activate", None).is_err());
        assert!(op_argv("destroy-snapshot", Some("b1")).is_err());
        assert!(op_argv("init", Some("x")).is_err());
        assert!(op_argv("activate", Some("--force")).is_err());
        assert!(op_argv("pin", Some("b1@s")).is_ok());
    }

    #[test]
    fn a_missing_tool_is_reported_not_fatal() {
        std::env::set_var("PATRONUS_BE_TOOL", "/nonexistent/horcrux-be");
        let v = list();
        assert_eq!(v["available"], false);
        assert!(v["reason"].as_str().unwrap().contains("ZFS"));
        std::env::remove_var("PATRONUS_BE_TOOL");
    }
}
