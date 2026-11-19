//! `patronus-cli config export` must keep log lines off stdout so a
//! redirected backup is valid JSON.
use std::process::Command;

#[test]
fn config_export_stdout_is_pure_json() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("config.db");
    let out = Command::new(env!("CARGO_BIN_EXE_patronus-cli"))
        .args(["--db", db.to_str().unwrap(), "config", "export"])
        .output()
        .expect("run patronus-cli");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout:?}"));
}
