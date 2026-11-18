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
    // unique even for two jobs in the same second (32-bit: MIPS32 has no 64-bit atomics)
    static SEQ: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    let id = format!(
        "{}",
        now() * 1000 + SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as i64 % 1000
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

/// Shell guard run before every apply. GRUB reads kernels from the separate
/// `boot`-labelled partition; when that partition is not mounted at /boot a
/// kernel update lands in the root file system's empty /boot and the machine
/// keeps booting the old kernel. Mount it (fstab entry, else by label); if that
/// fails, refuse the update instead of installing an unbootable kernel.
const BOOT_GUARD: &str = "\
if blkid -L boot >/dev/null 2>&1 && ! mountpoint -q /boot; then \
echo 'patronus-update: /boot is not mounted (partition labelled boot exists), mounting it'; \
mount /boot 2>/dev/null || mount \"$(blkid -L boot)\" /boot || \
{ echo 'patronus-update: REFUSING to update: cannot mount the boot partition on /boot, a kernel update would never be booted'; exit 1; }; \
fi; \
if [ \"$(awk '/^MemTotal:/{print int($2/1048576)}' /proc/meminfo)\" -lt 3 ]; then \
export MAKEOPTS=-j1 EMERGE_DEFAULT_OPTS=\"$EMERGE_DEFAULT_OPTS --jobs=1\"; fi; ";

fn apply_script(scope: &str) -> String {
    let emerge = match scope {
        "patronus" => format!("emerge --oneshot --update --quiet-build {PATRONUS_ATOM}"),
        _ => "emerge --update --deep --newuse --quiet-build @world".to_string(),
    };
    format!("{BOOT_GUARD}{emerge}")
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
// packet capture (diagnostics)
// ---------------------------------------------------------------------------

/// Validated parameters of one capture.
#[derive(Debug, PartialEq, Eq)]
pub struct CaptureSpec {
    pub iface: String,
    pub count: u32,
    pub seconds: u32,
    /// libpcap filter built from the structured fields (never from free text)
    pub filter: String,
}

fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid capture request: {}", m.into()))
}

/// Check the request and build the pcap filter from its structured fields
/// (`proto`, `host`, `port`): no field is ever passed to tcpdump as free text.
pub fn capture_spec(params: &Value) -> Result<CaptureSpec> {
    let iface = params
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("");
    if iface.is_empty()
        || iface.len() > 15
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        || iface.starts_with('-')
    {
        return Err(invalid(
            "interface must be a device name (letters, digits . _ -)",
        ));
    }
    let num = |key: &str, def: u64, max: u64| -> Result<u32> {
        match params.get(key) {
            None | Some(Value::Null) => Ok(def as u32),
            Some(v) => match v.as_u64() {
                Some(n) if (1..=max).contains(&n) => Ok(n as u32),
                _ => Err(invalid(format!("{key} must be a number from 1 to {max}"))),
            },
        }
    };
    let count = num("count", 50, 500)?;
    let seconds = num("seconds", 10, 30)?;
    let mut parts: Vec<String> = Vec::new();
    let proto = match params.get("proto") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_str() {
            Some("") | Some("any") => None,
            Some(p @ ("tcp" | "udp" | "icmp" | "icmp6" | "arp")) => Some(p),
            _ => return Err(invalid("proto must be tcp, udp, icmp, icmp6, arp or any")),
        },
    };
    if let Some(p) = proto {
        parts.push(p.to_string());
    }
    match params.get("host") {
        None | Some(Value::Null) => {}
        Some(v) => match v.as_str() {
            Some("") => {}
            Some(h) => {
                let ip: std::net::IpAddr = h
                    .parse()
                    .map_err(|_| invalid("host must be an IPv4 or IPv6 address"))?;
                parts.push(format!("host {ip}"));
            }
            None => return Err(invalid("host must be an IPv4 or IPv6 address")),
        },
    }
    match params.get("port") {
        None | Some(Value::Null) => {}
        Some(v) => {
            let port = v
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .ok_or_else(|| invalid("port must be a number from 1 to 65535"))?;
            if !matches!(proto, None | Some("tcp") | Some("udp")) {
                return Err(invalid("a port needs proto tcp, udp or any"));
            }
            parts.push(format!("port {port}"));
        }
    }
    Ok(CaptureSpec {
        iface: iface.to_string(),
        count,
        seconds,
        filter: parts.join(" and "),
    })
}

/// Run tcpdump on one interface (root) until `count` packets or `seconds`
/// pass, and return the decoded one-line summaries.
fn capture(params: &Value) -> Result<Value> {
    let spec = capture_spec(params)?;
    let tcpdump = which("tcpdump")
        .ok_or_else(|| Error::Service("tcpdump is not installed on this system".into()))?;
    let mut cmd = std::process::Command::new("timeout");
    cmd.args(["-s", "INT", &spec.seconds.to_string()])
        .arg(tcpdump)
        .args(["-nn", "-l", "-s", "128", "-c", &spec.count.to_string()])
        .args(["-i", &spec.iface])
        .args(spec.filter.split_whitespace());
    let out = cmd
        .output()
        .map_err(|e| Error::Service(format!("capture: cannot run tcpdump: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let packets: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let code = out.status.code().unwrap_or(-1);
    // 0 = reached -c, 124 = the time limit (tcpdump stops on SIGINT)
    if code != 0 && code != 124 && packets.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().next().unwrap_or("tcpdump failed").to_string();
        return Err(Error::Service(format!(
            "capture on {}: {first}",
            spec.iface
        )));
    }
    Ok(json!({
        "interface": spec.iface,
        "filter": spec.filter,
        "seconds": spec.seconds,
        "count": packets.len(),
        "truncated": packets.len() as u32 >= spec.count,
        "packets": packets,
    }))
}

// ---------------------------------------------------------------------------
// router-tier firmware (patronus-flash)
// ---------------------------------------------------------------------------

/// Paths of the firmware flow (environment overrides for tests and other boards).
#[derive(Debug, Clone)]
pub struct FwPaths {
    /// `patronus-flash` (present on the router-tier images only)
    pub tool: PathBuf,
    /// where the web UI puts an uploaded image: RAM (/tmp is a tmpfs on the router tier), so the settings
    /// volume keeps its room for the staged copy
    pub upload: PathBuf,
    pub data: PathBuf,
    pub release: PathBuf,
}

impl Default for FwPaths {
    fn default() -> Self {
        let p = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
        FwPaths {
            tool: p("PATRONUS_FLASH", "/usr/sbin/patronus-flash"),
            upload: p("PATRONUS_FW_UPLOAD", "/tmp/patronus-firmware.tar"),
            data: p("PATRONUS_DATA", "/data"),
            release: p("PATRONUS_RELEASE_FILE", "/etc/patronus-release"),
        }
    }
}

/// Where the web UI writes an uploaded firmware image.
pub fn firmware_upload_path() -> PathBuf {
    FwPaths::default().upload
}

fn release_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_string())
}

/// What runs now, whether an image is uploaded or staged.
pub fn firmware_status_in(p: &FwPaths) -> Value {
    let rel = std::fs::read_to_string(&p.release).unwrap_or_default();
    let staged = std::fs::read_to_string(p.data.join(".upgrade/patronus-release"))
        .ok()
        .filter(|_| p.data.join(".upgrade/ready").exists())
        .and_then(|t| release_value(&t, "BUILD"));
    json!({
        "available": p.tool.is_file(),
        "build": release_value(&rel, "BUILD"),
        "board": release_value(&rel, "BOARD"),
        "init": release_value(&rel, "INIT"),
        "uploaded": p.upload.is_file(),
        "uploaded_bytes": std::fs::metadata(&p.upload).map(|m| m.len()).ok(),
        "staged": staged,
    })
}

pub fn firmware_status() -> Value {
    firmware_status_in(&FwPaths::default())
}

/// `patronus-flash check|sysupgrade <upload>` or `cancel`: the tool's own guards decide (board, metadata,
/// checksums, UBI sizes); its message is returned either way. A refusal is an "Invalid image" error (HTTP 400).
pub fn firmware_flash_in(p: &FwPaths, op: &str) -> Result<Value> {
    if !p.tool.is_file() {
        return Err(Error::Config(
            "Invalid: firmware images are installed with patronus-flash, which this system does not have".into(),
        ));
    }
    let mut cmd = std::process::Command::new(&p.tool);
    cmd.arg(op);
    if op != "cancel" {
        if !p.upload.is_file() {
            return Err(Error::Config("Invalid: no firmware image uploaded".into()));
        }
        cmd.arg(&p.upload);
    }
    let o = cmd
        .output()
        .map_err(|e| Error::Service(format!("{}: {e}", p.tool.display())))?;
    let mut msg = String::from_utf8_lossy(&o.stdout).into_owned();
    msg.push_str(&String::from_utf8_lossy(&o.stderr));
    let msg = msg.trim().to_string();
    if !o.status.success() {
        return Err(Error::Config(format!("Invalid image: {msg}")));
    }
    if op == "sysupgrade" || op == "cancel" {
        // staged: the tool copied what it needs onto the settings volume; cancel: nothing to keep
        let _ = std::fs::remove_file(&p.upload);
    }
    let mut st = firmware_status_in(p);
    st["output"] = json!(msg);
    Ok(st)
}

fn firmware_flash(op: &str) -> Result<Value> {
    firmware_flash_in(&FwPaths::default(), op)
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
        "capture" => capture(params),
        "diag" => crate::diag::handle(params),
        // access-point Wi-Fi of the router-tier images (/etc/patronus/ap.env, see crate::apwifi)
        "wifi_get" => crate::apwifi::get(&crate::apwifi::Paths::default()),
        "wifi_set" => {
            let input: crate::apwifi::WifiInput = serde_json::from_value(params.clone())
                .map_err(|e| Error::Config(format!("Invalid Wi-Fi settings: {e}")))?;
            crate::apwifi::apply(&crate::apwifi::Paths::default(), &input)
        }
        "wifi_clients" => crate::apwifi::clients(&crate::apwifi::Paths::default()),
        "wifi_kick" => crate::apwifi::kick(
            &crate::apwifi::Paths::default(),
            params
                .get("interface")
                .and_then(Value::as_str)
                .unwrap_or(""),
            params.get("mac").and_then(Value::as_str).unwrap_or(""),
        ),
        "wifi_key" => crate::apwifi::reveal_key(
            &crate::apwifi::Paths::default(),
            params.get("id").and_then(Value::as_str).unwrap_or(""),
        )
        .map(|k| json!({ "key": k })),
        // the access-point file in configuration backups
        "wifi_export" => crate::apwifi::export_text(&crate::apwifi::Paths::default())
            .map(|t| json!({ "ap_env": t })),
        "wifi_restore" => crate::apwifi::restore_text(
            &crate::apwifi::Paths::default(),
            params.get("ap_env").and_then(Value::as_str).unwrap_or(""),
        ),
        "wifi_block" | "wifi_unblock" => crate::apwifi::set_block(
            &crate::apwifi::Paths::default(),
            params.get("mac").and_then(Value::as_str).unwrap_or(""),
            params.get("network").and_then(Value::as_str),
            action == "wifi_block",
        ),
        "wifi_survey" => Ok(crate::apsurvey::survey(
            &crate::apwifi::Paths::default(),
            params
                .get("fresh")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )),
        // device settings of the router tier (crate::apdev)
        "leds_get" => Ok(crate::apdev::leds_get()),
        "leds_set" => {
            crate::apdev::leds_set(params.get("on").and_then(Value::as_bool).unwrap_or(true))
        }
        "restart_schedule_get" => crate::apdev::schedule_get(),
        "restart_schedule_set" => crate::apdev::schedule_set(
            params.get("mode").and_then(Value::as_str).unwrap_or(""),
            params.get("time").and_then(Value::as_str),
            params.get("day").and_then(Value::as_str),
        ),
        "ssh_keys_get" => Ok(crate::apdev::keys_get(&crate::apdev::EtcPaths::default())),
        "ssh_keys_add" => crate::apdev::keys_add(
            &crate::apdev::EtcPaths::default(),
            params.get("user").and_then(Value::as_str).unwrap_or(""),
            params.get("key").and_then(Value::as_str).unwrap_or(""),
        ),
        "ssh_keys_delete" => crate::apdev::keys_delete(
            &crate::apdev::EtcPaths::default(),
            params.get("user").and_then(Value::as_str).unwrap_or(""),
            params
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ),
        "accounts_export" => Ok(crate::apdev::accounts_export(
            &crate::apdev::EtcPaths::default(),
        )),
        "accounts_restore" => {
            crate::apdev::accounts_restore(&crate::apdev::EtcPaths::default(), params)
                .map(|n| json!({ "notes": n }))
        }
        "ap_address_get" => Ok(crate::apdev::address_get(
            &crate::apwifi::Paths::default().env,
        )),
        "ap_address_set" => crate::apdev::address_set(&crate::apwifi::Paths::default().env, params),
        "ap_address_confirm" => {
            crate::apdev::address_confirm(params.get("host").and_then(Value::as_str).unwrap_or(""))
        }
        "firmware_feed_get" => Ok(json!({ "feed": crate::apdev::feed_url() })),
        "firmware_feed_set" => {
            crate::apdev::feed_set(params.get("feed").and_then(Value::as_str).unwrap_or(""))
        }
        "firmware_feed_check" => crate::apdev::feed_check(
            &crate::apdev::FeedPaths::default(),
            &crate::apdev::feed_url(),
        ),
        "firmware_feed_download" => {
            // the image lands where an upload would; then the same patronus-flash check as an upload (never staged)
            let p = FwPaths::default();
            let c = crate::apdev::feed_download(
                &crate::apdev::FeedPaths::default(),
                &crate::apdev::feed_url(),
                &p.upload,
            )?;
            let mut st = match firmware_flash_in(&p, "check") {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_file(&p.upload);
                    return Err(e);
                }
            };
            st["feed"] = c;
            Ok(st)
        }
        // router-tier firmware images through patronus-flash (validate, stage; the box installs at the next start)
        "firmware_status" => {
            let mut v = firmware_status();
            v["boot_guard"] = crate::bootguard::status();
            Ok(v)
        }
        // boot rollback (patronus-guard): policy, manual rollback (the caller restarts), confirm a trial by hand
        "firmware_guard_set" => crate::bootguard::set(params),
        "firmware_rollback" => crate::bootguard::action("rollback"),
        "firmware_confirm" => crate::bootguard::action("confirm"),
        "firmware_check" => firmware_flash("check"),
        "firmware_stage" => firmware_flash("sysupgrade"),
        "firmware_discard" => firmware_flash("cancel"),
        #[cfg(feature = "plugins")]
        "package_job" => {
            let job = params.get("job").and_then(Value::as_i64).unwrap_or(0);
            let comp = params
                .get("component")
                .and_then(Value::as_str)
                .unwrap_or("");
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

    #[test]
    fn firmware_flow_runs_the_flash_tool_and_reports_its_verdict() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let tool = d.path().join("patronus-flash");
        // fake tool: refuses images that contain BAD, stages the rest like the real one (data/.upgrade/{ready,patronus-release})
        std::fs::write(&tool, format!("#!/bin/sh\nD={}\ncase \"$1\" in\n check) grep -q BAD \"$2\" && {{ echo 'patronus-flash: ERROR: image is for another board'; exit 1; }}; echo 'patronus-flash: OK: unit-abc-openrc (openrc)';;\n sysupgrade) mkdir -p $D/.upgrade && echo BUILD=unit-abc-openrc > $D/.upgrade/patronus-release && date > $D/.upgrade/ready; echo staged;;\n cancel) rm -rf $D/.upgrade; echo dropped;;\nesac\n", d.path().join("data").display())).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            d.path().join("rel"),
            "BUILD=unit-old-openrc\nBOARD=x,y\nINIT=openrc\n",
        )
        .unwrap();
        let p = FwPaths {
            tool,
            upload: d.path().join("up.tar"),
            data: d.path().join("data"),
            release: d.path().join("rel"),
        };
        assert_eq!(firmware_status_in(&p)["build"], "unit-old-openrc");
        assert!(firmware_flash_in(&p, "check")
            .unwrap_err()
            .to_string()
            .contains("no firmware image uploaded"));
        std::fs::write(&p.upload, "BAD image").unwrap();
        let e = firmware_flash_in(&p, "check").unwrap_err().to_string();
        assert!(
            e.contains(": Invalid image") && e.contains("another board"),
            "{e}"
        );
        std::fs::write(&p.upload, "good image").unwrap();
        assert!(firmware_flash_in(&p, "check").unwrap()["output"]
            .as_str()
            .unwrap()
            .contains("OK: unit-abc"));
        let st = firmware_flash_in(&p, "sysupgrade").unwrap();
        assert_eq!(st["staged"], "unit-abc-openrc");
        assert_eq!(st["uploaded"], false, "the upload is removed once staged");
        assert_eq!(
            firmware_flash_in(&p, "cancel").unwrap()["staged"],
            Value::Null
        );
        let none = FwPaths {
            tool: d.path().join("missing"),
            ..p
        };
        assert_eq!(firmware_status_in(&none)["available"], false);
        assert!(firmware_flash_in(&none, "check")
            .unwrap_err()
            .to_string()
            .contains("does not have"));
    }

    const PRETEND: &str = "\n These are the packages that would be merged, in order:\n\n\
Calculating dependencies... done!\n\
[ebuild     U  ] net-firewall/patronus-0.1.1:0::patronus [0.1.0:0::patronus] USE=\"web* -ipsec\" 0 KiB\n\
[ebuild  N     ] dev-libs/foo-2.3_p1-r2:0/2::gentoo  USE=\"ssl\" 120 KiB\n\
[ebuild   R    ] sys-apps/bar-1.0:0::gentoo  0 KiB\n\
[ebuild     UD ] sys-kernel/gentoo-sources-6.6.1:6.6.1::gentoo [6.7.0:6.7.0::gentoo] 0 KiB\n\
Total: 4 packages (1 upgrade, 1 new, 1 reinstall), Size of downloads: 120 KiB\n";

    #[test]
    fn capture_filter_is_built_from_validated_fields_only() {
        use serde_json::json;
        let s = capture_spec(&json!({"interface":"rtr-lan"})).unwrap();
        assert_eq!((s.count, s.seconds, s.filter.as_str()), (50, 10, ""));
        let s = capture_spec(
            &json!({"interface":"eth0","proto":"tcp","host":"192.168.50.10","port":443,"count":5,"seconds":3}),
        )
        .unwrap();
        assert_eq!(s.filter, "tcp and host 192.168.50.10 and port 443");
        assert_eq!((s.count, s.seconds), (5, 3));
        assert_eq!(
            capture_spec(&json!({"interface":"any","host":"fe80::1","proto":"icmp6"}))
                .unwrap()
                .filter,
            "icmp6 and host fe80::1"
        );
        for bad in [
            json!({}),
            json!({"interface":"-w /etc/passwd"}),
            json!({"interface":"eth0; id"}),
            json!({"interface":"-i"}),
            json!({"interface":"eth0","host":"1.2.3.4 or port 22"}),
            json!({"interface":"eth0","proto":"tcp or udp"}),
            json!({"interface":"eth0","port":0}),
            json!({"interface":"eth0","port":70000}),
            json!({"interface":"eth0","proto":"icmp","port":80}),
            json!({"interface":"eth0","count":0}),
            json!({"interface":"eth0","count":501}),
            json!({"interface":"eth0","seconds":31}),
        ] {
            let e = capture_spec(&bad).unwrap_err().to_string();
            assert!(e.contains("Invalid"), "{bad}: {e}");
        }
    }

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
    fn apply_refuses_when_the_boot_partition_cannot_be_mounted() {
        // stubbed blkid/mountpoint/mount/emerge: a boot partition exists, /boot is not mounted
        let d = tempfile::tempdir().unwrap();
        let w = |n: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = d.path().join(n);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        w("blkid", "echo /dev/sda2");
        w("mountpoint", "exit 1");
        w("emerge", "echo EMERGE-RAN");
        let run = |mount_rc: i32| {
            w("mount", &format!("exit {mount_rc}"));
            std::process::Command::new("sh")
                .arg("-c")
                .arg(apply_script("world"))
                .env(
                    "PATH",
                    format!("{}:{}", d.path().display(), std::env::var("PATH").unwrap()),
                )
                .output()
                .unwrap()
        };
        let bad = run(1);
        let out = String::from_utf8_lossy(&bad.stdout);
        assert!(!bad.status.success(), "{out}");
        assert!(out.contains("REFUSING") && !out.contains("EMERGE-RAN"), "{out}");
        let ok = run(0);
        assert!(ok.status.success());
        assert!(String::from_utf8_lossy(&ok.stdout).contains("EMERGE-RAN"));
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
