//! `patronus config ...` keeps stdout for data only: logging goes to stderr,
//! so a redirected `export` is valid JSON and imports back unchanged.

use std::path::Path;
use std::process::{Command, Output};

fn cli(db: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_patronus-cli"))
        .arg("--db")
        .arg(db)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("run patronus-cli")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "exit {:?}: {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout.clone()).unwrap()
}

#[test]
fn export_stdout_is_pure_json_and_logs_go_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("a.db");
    let out = cli(&db, &["config", "export"]);
    let stdout = ok(&out);
    let doc: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", &stdout[..stdout.len().min(200)]));
    assert!(doc.get("tables").is_some());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Opening config store"),
        "the log line should be on stderr: {stderr}"
    );
}

#[test]
fn revisions_stdout_has_no_log_lines() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("a.db");
    let stdout = ok(&cli(&db, &["config", "revisions"]));
    assert!(!stdout.contains("INFO"), "log line on stdout: {stdout}");
}

#[test]
fn exported_file_imports_back_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.db");
    let b = dir.path().join("b.db");
    let file = dir.path().join("backup.json");
    std::fs::write(&file, ok(&cli(&a, &["config", "export"]))).unwrap();
    // the redirected file must parse (the python one-liner of the QA finding)
    serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&file).unwrap()).unwrap();
    ok(&cli(
        &b,
        &["config", "import", file.to_str().unwrap(), "--no-apply"],
    ));
    let again: serde_json::Value =
        serde_json::from_str(&ok(&cli(&b, &["config", "export"]))).unwrap();
    let first: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(first.get("tables"), again.get("tables"));
}
