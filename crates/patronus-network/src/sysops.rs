//! Privileged system operations for the web UI (lane H), run as root by
//! `patronus applyd` (op `system`) or in-process when the caller is root:
//!
//! - `reboot` / `shutdown`: after a short delay, so the HTTP answer gets
//!   out first.
//! - Software updates through **Portage** (Patronus is Gentoo-based):
//!   `update_check` (`emaint sync -a`, then `emerge --pretend --update
//!   --deep --newuse @world`, parsed into a package list), `update_apply`
//!   (`emerge --update ...` for the Patronus package or all of @world) and
//!   `update_status`. Check and apply run as one detached job at a time
//!   (survives an applyd/web restart): a job file in the state directory
//!   records the pid, the log and the exit code file.
//!
//! The job's state lives in `$PATRONUS_UPDATE_DIR` (default
//! `/var/lib/patronus/update`); the web user can read it.

use patronus_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn state_dir() -> PathBuf {
    std::env::var_os("PATRONUS_UPDATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/patronus/update"))
}

/// Is Portage installed (`emerge` on the PATH)?
pub fn has_portage() -> bool {
    which("emerge").is_some()
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
    for d in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        dirs.push(PathBuf::from(d));
    }
    dirs.into_iter().map(|d| d.join(bin)).find(|p| p.is_file())
}

// ---------------------------------------------------------------------------
// parsing `emerge --pretend` output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pending {
    /// `net-firewall/patronus`
    pub atom: String,
    pub version: String,
    /// installed version being replaced (None for a new package)
    pub from: Option<String>,
    /// `N` new, `U` upgrade, `D` downgrade, `R` rebuild
    pub kind: String,
}

/// Split `category/name-1.2.3-r1[:slot][::repo]` into (`category/name`, `1.2.3-r1`).
pub fn split_cpv(s: &str) -> Option<(String, String)> {
    let s = s.split("::").next()?.split(':').next()?;
    let bytes = s.as_bytes();
    for i in (1..bytes.len().saturating_sub(1)).rev() {
        if bytes[i] == b'-' && bytes[i + 1].is_ascii_digit() {
            return Some((s[..i].to_string(), s[i + 1..].to_string()));
        }
    }
    None
}

/// The `[ebuild ...]` lines of `emerge --pretend`.
pub fn parse_pretend(out: &str) -> Vec<Pending> {
    let mut v = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("[ebuild") else {
            continue;
        };
        let Some((flags, rest)) = rest.split_once(']') else {
            continue;
        };
        let kind = ['N', 'U', 'D', 'R']
            .into_iter()
            .find(|c| flags.contains(*c))
            .unwrap_or('R');
        let mut it = rest.split_whitespace();
        let Some((atom, version)) = it.next().and_then(split_cpv) else {
            continue;
        };
        let from = rest
            .split_once('[')
            .and_then(|(_, r)| r.split_once(']'))
            .and_then(|(old, _)| {
                // `[1.1:0::repo]` is a version; `USE="..."` is not in brackets
                let old = old.split("::").next()?.split(':').next()?;
                old.chars().next().filter(|c| c.is_ascii_digit())?;
                Some(old.to_string())
            });
        v.push(Pending {
            atom,
            version,
            from,
            kind: kind.to_string(),
        });
    }
    v
}

// ---------------------------------------------------------------------------
// jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    /// `check` | `apply`
    pub kind: String,
    /// `patronus` | `world`
    pub scope: String,
    pub pid: u32,
    pub started_at: i64,
    pub log: String,
    pub exit_file: String,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn job_file(dir: &Path) -> PathBuf {
    dir.join("job.json")
}

fn pid_alive(pid: u32) -> bool {
    // /proc/<pid>/stat state Z = finished, not yet reaped
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| {
            s.rsplit_once(')')
                .and_then(|(_, r)| r.split_whitespace().next().map(|st| st != "Z"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// The latest job's state: `{state: none|running|ok|failed|interrupted, ...}`.
pub fn job_status(dir: &Path) -> Value {
    let Some(job) = std::fs::read_to_string(job_file(dir))
        .ok()
        .and_then(|s| serde_json::from_str::<Job>(&s).ok())
    else {
        return json!({"state": "none"});
    };
    let read_exit = || {
        std::fs::read_to_string(&job.exit_file)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
    };
    let mut exit = read_exit();
    // look at the pid first, then at the file again: the shell writes the
    // exit code just before it ends
    let alive = exit.is_none() && pid_alive(job.pid);
    if exit.is_none() && !alive {
        exit = read_exit();
    }
    let (state, finished) = match exit {
        Some(0) => ("ok", true),
        Some(_) => ("failed", true),
        None if alive => ("running", false),
        None => ("interrupted", true),
    };
    let tail = std::fs::read_to_string(&job.log)
        .map(|s| {
            let lines: Vec<&str> = s.lines().collect();
            lines[lines.len().saturating_sub(60)..].join("\n")
        })
        .unwrap_or_default();
    json!({
        "state": state, "id": job.id, "kind": job.kind, "scope": job.scope,
        "started_at": job.started_at, "finished": finished, "exit_code": exit,
        "log_tail": tail,
    })
}

/// Start `script` (a shell command line) as a detached job. Refuses while
/// another job runs. The exit status lands in `<dir>/exit-<id>`.
fn spawn_job(dir: &Path, kind: &str, scope: &str, script: &str) -> Result<Value> {
    use std::os::unix::process::CommandExt;
    std::fs::create_dir_all(dir).map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?;
    let cur = job_status(dir);
    if cur["state"] == "running" {
        return Err(Error::Config(format!(
            "an update job ({}) is already running",
            cur["kind"].as_str().unwrap_or("?")
        )));
    }
    // unique even for two jobs in the same second
    static SEQ: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let id = format!(
        "{}",
        now() * 1000 + SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 1000
    );
    let log = dir.join(format!("{kind}-{id}.log"));
    let exit_file = dir.join(format!("exit-{id}"));
    let wrapped = format!(
        "( {script} ) >> '{log}' 2>&1 < /dev/null; echo $? > '{exit}'",
        log = log.display(),
        exit = exit_file.display()
    );
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg(&wrapped)
        .env("LC_ALL", "C")
        .env("EMERGE_DEFAULT_OPTS", "--color=n")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // own session: the job outlives this process
    unsafe {
        cmd.pre_exec(|| {
            let _ = nix::unistd::setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| Error::Service(format!("cannot start the {kind} job: {e}")))?;
    let job = Job {
        id: id.clone(),
        kind: kind.into(),
        scope: scope.into(),
        pid: child.id(),
        started_at: now(),
        log: log.display().to_string(),
        exit_file: exit_file.display().to_string(),
    };
    // reap in the background so the shell does not stay a zombie while we live
    std::thread::spawn(move || {
        let mut c = child;
        let _ = c.wait();
    });
    std::fs::write(
        job_file(dir),
        serde_json::to_string(&job).unwrap_or_default(),
    )
    .map_err(|e| Error::Config(format!("job file: {e}")))?;
    Ok(job_status(dir))
}

/// The package atom Patronus is installed as.
pub const PATRONUS_ATOM: &str = "net-firewall/patronus";

fn check_script(sync: bool) -> String {
    let sync_step = if sync {
        "if command -v emaint >/dev/null 2>&1; then emaint sync -a || exit 1; else emerge --sync || exit 1; fi; "
    } else {
        ""
    };
    format!("{sync_step}emerge --pretend --update --deep --newuse --verbose --columns @world")
}

fn apply_script(scope: &str) -> String {
    match scope {
        "patronus" => format!("emerge --oneshot --update --quiet-build {PATRONUS_ATOM}"),
        _ => "emerge --update --deep --newuse --quiet-build @world".to_string(),
    }
}

/// The result of the last finished check job (what is pending).
pub fn pending_from_last_check(dir: &Path) -> Value {
    // find the newest finished check log
    let mut newest: Option<(i64, PathBuf)> = None;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if let Some(id) = n
                .strip_prefix("check-")
                .and_then(|r| r.strip_suffix(".log"))
                .and_then(|i| i.parse::<i64>().ok())
            {
                if dir.join(format!("exit-{id}")).exists()
                    && std::fs::read_to_string(dir.join(format!("exit-{id}")))
                        .map(|s| s.trim() == "0")
                        .unwrap_or(false)
                    && newest.as_ref().is_none_or(|(t, _)| id > *t)
                {
                    newest = Some((id, e.path()));
                }
            }
        }
    }
    match newest {
        Some((id, p)) => {
            let out = std::fs::read_to_string(p).unwrap_or_default();
            let pending = parse_pretend(&out);
            let patronus = pending.iter().find(|p| p.atom == PATRONUS_ATOM).cloned();
            json!({"checked_at": id / 1000, "pending": pending, "patronus": patronus})
        }
        None => json!({"checked_at": null, "pending": [], "patronus": null}),
    }
}

// ---------------------------------------------------------------------------
// reboot / shutdown
// ---------------------------------------------------------------------------

/// The command that reboots or powers off, for the init system.
pub fn power_argv(action: &str, systemd: bool) -> Option<Vec<&'static str>> {
    match (action, systemd) {
        ("reboot", true) => Some(vec!["systemctl", "reboot"]),
        ("shutdown", true) => Some(vec!["systemctl", "poweroff"]),
        ("reboot", false) => Some(vec!["reboot"]),
        ("shutdown", false) => Some(vec!["poweroff"]),
        _ => None,
    }
}

fn power(action: &str) -> Result<Value> {
    let systemd = Path::new("/run/systemd/system").is_dir();
    let argv = power_argv(action, systemd)
        .ok_or_else(|| Error::Config(format!("Invalid power action {action:?}")))?;
    tracing::warn!("system {action} requested; running {argv:?} in 3 s");
    let a: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let _ = std::process::Command::new(&a[0]).args(&a[1..]).status();
    });
    Ok(json!({"ok": true, "action": action, "in_seconds": 3}))
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// Run one operation as the current (root) user. `params` carries
/// `scope` (`patronus`|`world`) and `sync` (bool) for updates.
pub fn handle(action: &str, params: &Value) -> Result<Value> {
    handle_in(&state_dir(), action, params)
}

pub fn handle_in(dir: &Path, action: &str, params: &Value) -> Result<Value> {
    match action {
        "reboot" | "shutdown" => power(action),
        #[cfg(feature = "plugins")]
        "package_job" => {
            let job = params.get("job").and_then(Value::as_i64).unwrap_or(0);
            let comp = params.get("component").and_then(Value::as_str).unwrap_or("");
            let act = params.get("action").and_then(Value::as_str).unwrap_or("");
            // dir is the broker's state dir for update jobs; package jobs live
            // under the net state dir both processes derive the same way
            let state = crate::supervise::NetPaths::default().state_dir;
            crate::packages::spawn_emerge(&state, job, comp, act)?;
            Ok(json!({"ok": true, "job": job}))
        }
        "update_status" => Ok(json!({
            "portage": has_portage(),
            "job": job_status(dir),
            "last_check": pending_from_last_check(dir),
        })),
        "update_check" | "update_apply" => {
            if !has_portage() {
                return Err(Error::Service(
                    "this system has no Portage (`emerge`): Patronus updates through Portage on Gentoo"
                        .into(),
                ));
            }
            if action == "update_check" {
                let sync = params.get("sync").and_then(Value::as_bool).unwrap_or(true);
                spawn_job(dir, "check", "world", &check_script(sync))
            } else {
                let scope = params
                    .get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or("patronus");
                if !matches!(scope, "patronus" | "world") {
                    return Err(Error::Config(format!(
                        "Invalid update scope {scope:?}: patronus or world"
                    )));
                }
                spawn_job(dir, "apply", scope, &apply_script(scope))
            }
        }
        other => Err(Error::Config(format!("Invalid system action {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRETEND: &str = "\n These are the packages that would be merged, in order:\n\n\
Calculating dependencies... done!\n\
[ebuild     U  ] net-firewall/patronus-0.1.1:0::patronus [0.1.0:0::patronus] USE=\"web* -ipsec\" 0 KiB\n\
[ebuild  N     ] dev-libs/foo-2.3_p1-r2:0/2::gentoo  USE=\"ssl\" 120 KiB\n\
[ebuild   R    ] sys-apps/bar-1.0:0::gentoo  0 KiB\n\
[ebuild     UD ] sys-kernel/gentoo-sources-6.6.1:6.6.1::gentoo [6.7.0:6.7.0::gentoo] 0 KiB\n\
Total: 4 packages (1 upgrade, 1 new, 1 reinstall), Size of downloads: 120 KiB\n";

    #[test]
    fn emerge_pretend_output_is_parsed() {
        let p = parse_pretend(PRETEND);
        assert_eq!(p.len(), 4, "{p:?}");
        assert_eq!(
            p[0],
            Pending {
                atom: "net-firewall/patronus".into(),
                version: "0.1.1".into(),
                from: Some("0.1.0".into()),
                kind: "U".into()
            }
        );
        assert_eq!(p[1].atom, "dev-libs/foo");
        assert_eq!(p[1].version, "2.3_p1-r2");
        assert_eq!(p[1].from, None);
        assert_eq!(p[1].kind, "N");
        assert_eq!(p[2].kind, "R");
        assert_eq!(p[3].kind, "U");
        assert_eq!(p[3].atom, "sys-kernel/gentoo-sources");
        assert!(parse_pretend("nothing to do\n").is_empty());
    }

    #[test]
    fn cpv_splitting() {
        assert_eq!(
            split_cpv("dev-lang/python-3.12.4_p1-r1:3.12::gentoo"),
            Some(("dev-lang/python".into(), "3.12.4_p1-r1".into()))
        );
        assert_eq!(
            split_cpv("x11-libs/gtk+-3.24.1"),
            Some(("x11-libs/gtk+".into(), "3.24.1".into()))
        );
        assert_eq!(split_cpv("garbage"), None);
    }

    #[test]
    fn power_commands_follow_the_init_system() {
        assert_eq!(
            power_argv("reboot", true),
            Some(vec!["systemctl", "reboot"])
        );
        assert_eq!(
            power_argv("shutdown", true),
            Some(vec!["systemctl", "poweroff"])
        );
        assert_eq!(power_argv("reboot", false), Some(vec!["reboot"]));
        assert_eq!(power_argv("shutdown", false), Some(vec!["poweroff"]));
        assert_eq!(power_argv("rm -rf /", false), None);
        assert!(handle("halt-and-catch-fire", &Value::Null).is_err());
    }

    #[test]
    fn a_job_runs_detached_and_reports_its_exit_code() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(job_status(d.path())["state"], "none");
        let st = spawn_job(d.path(), "apply", "patronus", "echo hello; exit 3").unwrap();
        assert!(["running", "failed"].contains(&st["state"].as_str().unwrap()));
        for _ in 0..100 {
            if job_status(d.path())["finished"] == true {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let st = job_status(d.path());
        assert_eq!(st["state"], "failed", "{st}");
        assert_eq!(st["exit_code"], 3);
        assert!(st["log_tail"].as_str().unwrap().contains("hello"));
        // a second job may start once the first finished, and ok = 0
        spawn_job(d.path(), "check", "world", "exit 0").unwrap();
        for _ in 0..100 {
            if job_status(d.path())["finished"] == true {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(job_status(d.path())["state"], "ok");
    }

    #[test]
    fn only_one_job_runs_at_a_time() {
        let d = tempfile::tempdir().unwrap();
        spawn_job(d.path(), "apply", "world", "sleep 2").unwrap();
        let e = spawn_job(d.path(), "check", "world", "true").unwrap_err();
        assert!(e.to_string().contains("already running"), "{e}");
    }

    #[test]
    fn the_last_good_check_lists_what_is_pending() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(pending_from_last_check(d.path())["checked_at"], Value::Null);
        std::fs::write(d.path().join("check-100000.log"), PRETEND).unwrap();
        std::fs::write(d.path().join("exit-100000"), "0\n").unwrap();
        // a failed, newer check is ignored
        std::fs::write(d.path().join("check-200000.log"), "boom").unwrap();
        std::fs::write(d.path().join("exit-200000"), "1\n").unwrap();
        let v = pending_from_last_check(d.path());
        assert_eq!(v["checked_at"], 100);
        assert_eq!(v["pending"].as_array().unwrap().len(), 4);
        assert_eq!(v["patronus"]["version"], "0.1.1");
    }
}
