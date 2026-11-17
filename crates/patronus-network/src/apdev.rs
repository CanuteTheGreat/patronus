//! Device settings of the router-tier images (System > Device page): SSH keys, system accounts in backups,
//! scheduled restart, LEDs, the access point's own address (with a rollback timer) and the online firmware check.
//!
//! Settings that the boot needs live in shell-variable files the image's scripts source, edited with the same
//! parser/renderer as the Wi-Fi file (`crate::apwifi::{parse, render}`, every unmanaged line kept):
//! `/etc/patronus/device.env` (`LEDS`, `RESTART`, `RESTART_TIME`, `RESTART_DAY`, `FW_FEED_URL`) and, for the
//! address, `/etc/patronus/ap.env` (`AP_ADDR`, `AP_GW`, `AP_DNS`). The scripts that act on them are in
//! `/usr/libexec/patronus/` (`leds`, `restart-schedule`, `ap-addr`); this module validates, writes and calls them.
//!
//! Paths can be redirected for tests: `PATRONUS_DEVICE_ENV`, `PATRONUS_LIBEXEC`, `PATRONUS_LEDS_SYSFS`,
//! `PATRONUS_ETC` (passwd/shadow/group), `PATRONUS_FW_KEYRING`, `PATRONUS_WGET`, `PATRONUS_GPGV`.

use crate::apwifi::{parse, quote, render, EnvFile};
use base64::Engine;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

fn env_path(k: &str, d: &str) -> PathBuf {
    PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()))
}
fn invalid(m: impl Into<String>) -> Error {
    Error::Config(format!("Invalid: {}", m.into()))
}
pub fn device_env() -> PathBuf {
    env_path("PATRONUS_DEVICE_ENV", "/etc/patronus/device.env")
}
fn libexec(name: &str) -> PathBuf {
    env_path("PATRONUS_LIBEXEC", "/usr/libexec/patronus").join(name)
}

fn read_file(p: &Path) -> EnvFile {
    parse(&std::fs::read_to_string(p).unwrap_or_default())
}

/// Set (or with `None` remove) variables in a shell-variable file, keeping every other line; 0600, atomic.
pub fn set_vars(p: &Path, set: &[(&str, Option<String>)]) -> Result<()> {
    let mut f = read_file(p);
    for (k, v) in set {
        f.vars.retain(|(n, _)| n != k);
        if let Some(v) = v {
            f.vars.push((k.to_string(), v.clone()));
        }
    }
    if f.header.is_empty() {
        f.header.push(
            "# Device settings (written by Patronus; the web UI's Device page edits it)".into(),
        );
    }
    write_atomic(p, &render(&f), 0o600)
}

fn write_atomic(p: &Path, text: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = p.with_extension(format!(
        "{}.new",
        p.extension().and_then(|e| e.to_str()).unwrap_or("x")
    ));
    let mut fh = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| Error::Config(format!("{}: {e}", tmp.display())))?;
    fh.write_all(text.as_bytes())
        .and_then(|_| fh.sync_all())
        .map_err(|e| Error::Config(format!("{}: {e}", tmp.display())))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    std::fs::rename(&tmp, p).map_err(|e| Error::Config(format!("{}: {e}", p.display())))
}

fn run(cmd: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| Error::Service(format!("{}: {e}", cmd.display())))?;
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    if !o.status.success() {
        s.push_str(&String::from_utf8_lossy(&o.stderr));
        return Err(Error::Service(format!(
            "{} {}: {}",
            cmd.display(),
            args.join(" "),
            s.trim()
        )));
    }
    Ok(s)
}

/// `key=value` lines of a script's status output.
pub fn kv_lines(text: &str) -> serde_json::Map<String, Value> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), json!(v.trim())))
        .collect()
}

// ---------------------------------------------------------------------------
// LEDs
// ---------------------------------------------------------------------------

fn leds_sysfs() -> PathBuf {
    env_path("PATRONUS_LEDS_SYSFS", "/sys/class/leds")
}

/// The LEDs the kernel exposes, with their current brightness and trigger.
pub fn leds_list(sysfs: &Path) -> Vec<Value> {
    let mut names: Vec<String> = std::fs::read_dir(sysfs)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let rd = |f: &str| {
                std::fs::read_to_string(sysfs.join(&n).join(f))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            };
            let trig = rd("trigger");
            let current = trig
                .split_whitespace()
                .find(|t| t.starts_with('['))
                .map(|t| t.trim_matches(|c| c == '[' || c == ']').to_string())
                .unwrap_or_default();
            json!({
                "name": n,
                "brightness": rd("brightness").parse::<u32>().unwrap_or(0),
                "max_brightness": rd("max_brightness").parse::<u32>().unwrap_or(1),
                "trigger": current,
            })
        })
        .collect()
}

pub fn leds_get() -> Value {
    let list = leds_list(&leds_sysfs());
    let f = read_file(&device_env());
    let available = !list.is_empty();
    json!({
        "available": available,
        "reason": if available { "" } else { "this device exposes no LEDs to the operating system (/sys/class/leds is empty)" },
        "setting": if f.get("LEDS") == Some("off") { "off" } else { "on" },
        "leds": list,
    })
}

/// LEDS=on|off, applied at once (and at every boot by `board-network` -> `leds apply`).
pub fn leds_set(on: bool) -> Result<Value> {
    if leds_list(&leds_sysfs()).is_empty() {
        return Err(invalid(
            "this device exposes no LEDs to the operating system (/sys/class/leds is empty)",
        ));
    }
    set_vars(
        &device_env(),
        &[("LEDS", Some(if on { "on" } else { "off" }.into()))],
    )?;
    let out = run(&libexec("leds"), &["apply"])?;
    let mut v = leds_get();
    v["output"] = json!(out.trim());
    Ok(v)
}

// ---------------------------------------------------------------------------
// scheduled restart
// ---------------------------------------------------------------------------

pub const DAYS: &[&str] = &["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Validate a schedule: (RESTART, RESTART_TIME, RESTART_DAY).
pub fn check_schedule(
    mode: &str,
    time: Option<&str>,
    day: Option<&str>,
) -> Result<(String, String, String)> {
    let mode = mode.trim().to_ascii_lowercase();
    if !matches!(mode.as_str(), "off" | "daily" | "weekly") {
        return Err(invalid(format!("schedule {mode:?}: off, daily or weekly")));
    }
    let time = time.unwrap_or("04:30").trim().to_string();
    let ok_time = time
        .split_once(':')
        .and_then(|(h, m)| {
            Some((
                h.parse::<u32>().ok()?,
                m.parse::<u32>().ok()?,
                h.len(),
                m.len(),
            ))
        })
        .is_some_and(|(h, m, hl, ml)| h < 24 && m < 60 && (1..=2).contains(&hl) && ml == 2);
    if !ok_time {
        return Err(invalid(format!("time {time:?}: HH:MM, 24-hour")));
    }
    let (h, m) = time.split_once(':').unwrap();
    let time = format!("{:02}:{m}", h.parse::<u32>().unwrap());
    let day = day.unwrap_or("sun").trim().to_ascii_lowercase();
    let day: String = day.chars().take(3).collect();
    if !DAYS.contains(&day.as_str()) {
        return Err(invalid(format!("day {day:?}: sun, mon, ... sat")));
    }
    Ok((mode, time, day))
}

/// Cron line (busybox crond, OpenRC) and systemd OnCalendar of a schedule.
pub fn schedule_specs(mode: &str, time: &str, day: &str) -> Option<(String, String)> {
    let (h, m) = time.split_once(':')?;
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    let dow = DAYS.iter().position(|d| *d == day)?;
    match mode {
        "daily" => Some((format!("{m} {h} * * *"), format!("*-*-* {h:02}:{m:02}:00"))),
        "weekly" => Some((
            format!("{m} {h} * * {dow}"),
            format!(
                "{} *-*-* {h:02}:{m:02}:00",
                ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][dow]
            ),
        )),
        _ => None,
    }
}

pub fn schedule_get() -> Result<Value> {
    let f = read_file(&device_env());
    let st = run(&libexec("restart-schedule"), &["status"]).unwrap_or_default();
    Ok(json!({
        "mode": f.get("RESTART").unwrap_or("off"),
        "time": f.get("RESTART_TIME").unwrap_or("04:30"),
        "day": f.get("RESTART_DAY").unwrap_or("sun"),
        "available": libexec("restart-schedule").is_file(),
        "unit": kv_lines(&st),
    }))
}

pub fn schedule_set(mode: &str, time: Option<&str>, day: Option<&str>) -> Result<Value> {
    let (mode, time, day) = check_schedule(mode, time, day)?;
    if !libexec("restart-schedule").is_file() {
        return Err(invalid(
            "this firmware has no scheduled restart (restart-schedule)",
        ));
    }
    set_vars(
        &device_env(),
        &[
            ("RESTART", Some(mode)),
            ("RESTART_TIME", Some(time)),
            ("RESTART_DAY", Some(day)),
        ],
    )?;
    run(&libexec("restart-schedule"), &["apply"])?;
    schedule_get()
}

// ---------------------------------------------------------------------------
// system accounts and SSH keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EtcPaths {
    pub passwd: PathBuf,
    pub shadow: PathBuf,
    pub group: PathBuf,
    /// prefix for home directories (tests: a temp dir; real: "/")
    pub root: PathBuf,
}

impl Default for EtcPaths {
    fn default() -> Self {
        let etc = env_path("PATRONUS_ETC", "/etc");
        EtcPaths {
            passwd: etc.join("passwd"),
            shadow: etc.join("shadow"),
            group: etc.join("group"),
            root: std::env::var("PATRONUS_ETC")
                .map(|e| PathBuf::from(e).join("root"))
                .unwrap_or_else(|_| PathBuf::from("/")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PwEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub line: String,
}

pub fn parse_passwd(text: &str) -> Vec<PwEntry> {
    text.lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.len() == 7).then(|| PwEntry {
                name: c[0].into(),
                uid: c[2].parse().unwrap_or(u32::MAX),
                gid: c[3].parse().unwrap_or(u32::MAX),
                home: c[5].into(),
                shell: c[6].into(),
                line: l.to_string(),
            })
        })
        .collect()
}

/// Accounts of people (web and/or SSH logins): uid 1000..=65535 except `nobody` (65534). The web UI's own accounts
/// (first-run, Accounts page) are of this kind with the shell /sbin/nologin.
pub fn is_human(e: &PwEntry) -> bool {
    (1000..=65535).contains(&e.uid) && e.uid != 65534
}

/// An account that can log in over SSH (a real shell).
pub fn has_shell(e: &PwEntry) -> bool {
    !e.shell.is_empty() && !e.shell.ends_with("nologin") && !e.shell.ends_with("/false")
}

fn home_of(p: &EtcPaths, e: &PwEntry) -> PathBuf {
    let h = if e.home.is_empty() { "/" } else { &e.home };
    p.root.join(h.trim_start_matches('/'))
}

fn keys_file(p: &EtcPaths, e: &PwEntry) -> PathBuf {
    home_of(p, e).join(".ssh/authorized_keys")
}

/// Key types dropbear accepts.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// A parsed public key line: (type, blob, comment, fingerprint "SHA256:...").
#[derive(Debug, Clone, PartialEq)]
pub struct PubKey {
    pub kind: String,
    pub blob: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
}

/// Parse and check one authorized_keys line: no options, a known type, base64 that decodes to a key blob naming
/// the same type, a sane length.
pub fn parse_key(line: &str) -> Result<PubKey> {
    let line = line.trim();
    if line.contains('\n') || line.contains('\r') {
        return Err(invalid("one key per line"));
    }
    let mut it = line.splitn(3, char::is_whitespace);
    let kind = it.next().unwrap_or("");
    if !KEY_TYPES.contains(&kind) {
        return Err(invalid(format!(
            "key type {kind:?}: one of {} (options before the key are not accepted)",
            KEY_TYPES.join(", ")
        )));
    }
    let b64 = it.next().unwrap_or("").trim();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| invalid("the key data is not valid base64"))?;
    if blob.len() < 4 + kind.len() || blob.len() > 4096 {
        return Err(invalid("the key data has the wrong length"));
    }
    let n = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if blob.get(4..4 + n) != Some(kind.as_bytes()) {
        return Err(invalid("the key data does not match its type"));
    }
    if kind == "ssh-ed25519" && blob.len() != 51 {
        return Err(invalid("an ssh-ed25519 key has 32 bytes"));
    }
    if kind == "ssh-rsa" && blob.len() < 256 {
        return Err(invalid("RSA keys need at least 2048 bits"));
    }
    let comment: String = it
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
    Ok(PubKey {
        kind: kind.into(),
        blob,
        comment,
        fingerprint: format!("SHA256:{fp}"),
    })
}

fn read_keys(f: &Path) -> Vec<(String, Option<PubKey>)> {
    std::fs::read_to_string(f)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| (l.to_string(), parse_key(l).ok()))
        .collect()
}

fn login_users(p: &EtcPaths) -> Vec<PwEntry> {
    parse_passwd(&std::fs::read_to_string(&p.passwd).unwrap_or_default())
        .into_iter()
        .filter(|e| e.uid == 0 && e.name == "root" || is_human(e) && has_shell(e))
        .collect()
}

/// root's (or a user's) shadow password field is usable for a login.
fn has_password(p: &EtcPaths, user: &str) -> bool {
    std::fs::read_to_string(&p.shadow)
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            let c: Vec<&str> = l.split(':').collect();
            (c.len() >= 2 && c[0] == user).then(|| c[1].to_string())
        })
        .is_some_and(|pw| !pw.is_empty() && !pw.starts_with('!') && !pw.starts_with('*'))
}

pub fn keys_get(p: &EtcPaths) -> Value {
    let users: Vec<Value> = login_users(p)
        .iter()
        .map(|u| {
            let keys: Vec<Value> = read_keys(&keys_file(p, u))
                .into_iter()
                .map(|(line, k)| match k {
                    Some(k) => json!({ "type": k.kind, "fingerprint": k.fingerprint, "comment": k.comment }),
                    None => json!({ "type": line.split_whitespace().next().unwrap_or(""), "fingerprint": "", "comment": "(not a key this page manages: options or an unknown type)" }),
                })
                .collect();
            json!({ "user": u.name, "uid": u.uid, "password_login": has_password(p, &u.name), "keys": keys })
        })
        .collect();
    json!({ "users": users })
}

fn find_user(p: &EtcPaths, user: &str) -> Result<PwEntry> {
    login_users(p)
        .into_iter()
        .find(|u| u.name == user)
        .ok_or_else(|| invalid(format!("{user:?} is not a login account on this device")))
}

fn write_keys(p: &EtcPaths, u: &PwEntry, lines: &[String]) -> Result<()> {
    let f = keys_file(p, u);
    let dir = f.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    write_atomic(&f, &text, 0o600)?;
    if nix::unistd::geteuid().is_root() {
        let (uid, gid) = (
            Some(nix::unistd::Uid::from_raw(u.uid)),
            Some(nix::unistd::Gid::from_raw(u.gid)),
        );
        let _ = nix::unistd::chown(&dir, uid, gid);
        let _ = nix::unistd::chown(&f, uid, gid);
    }
    Ok(())
}

pub fn keys_add(p: &EtcPaths, user: &str, line: &str) -> Result<Value> {
    let u = find_user(p, user)?;
    let k = parse_key(line)?;
    let have = read_keys(&keys_file(p, &u));
    if have
        .iter()
        .any(|(_, h)| h.as_ref().is_some_and(|h| h.blob == k.blob))
    {
        return Err(invalid(format!("{user} already has this key")));
    }
    if have.len() >= 64 {
        return Err(invalid("at most 64 keys per account"));
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&k.blob);
    let mut lines: Vec<String> = have.into_iter().map(|(l, _)| l).collect();
    lines.push(
        format!("{} {} {}", k.kind, b64, k.comment)
            .trim_end()
            .to_string(),
    );
    write_keys(p, &u, &lines)?;
    Ok(json!({ "ok": true, "user": user, "fingerprint": k.fingerprint }))
}

/// Remove one key (by fingerprint). Refused when it would leave nobody able to log in over SSH as root: root
/// keeps at least one key unless root has a password.
pub fn keys_delete(p: &EtcPaths, user: &str, fingerprint: &str) -> Result<Value> {
    let u = find_user(p, user)?;
    let have = read_keys(&keys_file(p, &u));
    let keep: Vec<String> = have
        .iter()
        .filter(|(_, k)| k.as_ref().map(|k| k.fingerprint.as_str()) != Some(fingerprint))
        .map(|(l, _)| l.clone())
        .collect();
    if keep.len() == have.len() {
        return Err(invalid(format!("{user} has no key {fingerprint}")));
    }
    if u.uid == 0 && keep.is_empty() && !has_password(p, "root") {
        return Err(invalid(
            "this is root's last SSH key and root has no password: removing it would lock everyone out of the console over SSH (add another key first)",
        ));
    }
    write_keys(p, &u, &keep)?;
    Ok(json!({ "ok": true, "user": user, "fingerprint": fingerprint }))
}

/// Human accounts for a configuration backup: their passwd and shadow lines, the group lines they appear in, their
/// authorized keys; plus root's authorized keys (root's password is not exported).
pub fn accounts_export(p: &EtcPaths) -> Value {
    let pw = parse_passwd(&std::fs::read_to_string(&p.passwd).unwrap_or_default());
    let shadow = std::fs::read_to_string(&p.shadow).unwrap_or_default();
    let group = std::fs::read_to_string(&p.group).unwrap_or_default();
    let accounts: Vec<Value> = pw
        .iter()
        .filter(|e| is_human(e))
        .map(|e| {
            let sh = shadow
                .lines()
                .find(|l| l.split(':').next() == Some(e.name.as_str()))
                .unwrap_or("");
            let groups: Vec<&str> = group
                .lines()
                .filter(|l| {
                    let c: Vec<&str> = l.split(':').collect();
                    c.len() == 4
                        && (c[3].split(',').any(|m| m == e.name)
                            || c[2].parse::<u32>().ok() == Some(e.gid))
                })
                .collect();
            json!({
                "name": e.name,
                "passwd": e.line,
                "shadow": sh,
                "groups": groups,
                "authorized_keys": std::fs::read_to_string(keys_file(p, e)).unwrap_or_default(),
            })
        })
        .collect();
    let root_keys = pw
        .iter()
        .find(|e| e.name == "root")
        .map(|r| std::fs::read_to_string(keys_file(p, r)).unwrap_or_default())
        .unwrap_or_default();
    json!({ "accounts": accounts, "root_authorized_keys": root_keys })
}

fn field_ok(line: &str, n: usize, name: &str) -> bool {
    !line.contains('\n') && line.split(':').count() == n && line.split(':').next() == Some(name)
}

/// Put backed-up accounts back: each account's passwd/shadow lines replace (or add) the lines of the same name,
/// its groups gain it as a member (a missing group line is added), its keys are written; root's keys are merged
/// (never removed). An account whose uid belongs to a different name here is skipped. Returns one note per account.
pub fn accounts_restore(p: &EtcPaths, doc: &Value) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    let mut passwd = std::fs::read_to_string(&p.passwd).unwrap_or_default();
    let mut shadow = std::fs::read_to_string(&p.shadow).unwrap_or_default();
    let mut group = std::fs::read_to_string(&p.group).unwrap_or_default();
    let mut keys: Vec<(PwEntry, String)> = Vec::new();
    for a in doc["accounts"].as_array().cloned().unwrap_or_default() {
        let name = a["name"].as_str().unwrap_or("").to_string();
        let pl = a["passwd"].as_str().unwrap_or("");
        let sl = a["shadow"].as_str().unwrap_or("");
        let Some(e) = parse_passwd(pl).into_iter().next() else {
            notes.push(format!("account {name:?}: no valid passwd line, skipped"));
            continue;
        };
        if e.name != name
            || !is_human(&e)
            || !field_ok(pl, 7, &name)
            || !(sl.is_empty() || field_ok(sl, 9, &name))
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            notes.push(format!("account {name:?}: malformed, skipped"));
            continue;
        }
        let cur = parse_passwd(&passwd);
        if cur.iter().any(|c| c.uid == e.uid && c.name != name) {
            notes.push(format!(
                "account {name}: uid {} belongs to another account here, skipped",
                e.uid
            ));
            continue;
        }
        let replace = |text: &str, line: &str| -> String {
            let mut out: Vec<String> = text
                .lines()
                .filter(|l| l.split(':').next() != Some(name.as_str()))
                .map(str::to_string)
                .collect();
            out.push(line.to_string());
            out.join("\n") + "\n"
        };
        passwd = replace(&passwd, pl);
        if !sl.is_empty() {
            shadow = replace(&shadow, sl);
        }
        for g in a["groups"].as_array().cloned().unwrap_or_default() {
            let Some(gl) = g.as_str() else { continue };
            let gc: Vec<&str> = gl.split(':').collect();
            if gc.len() != 4 || gl.contains('\n') {
                continue;
            }
            let mut found = false;
            let lines: Vec<String> = group
                .lines()
                .map(|l| {
                    let c: Vec<&str> = l.split(':').collect();
                    if c.len() == 4 && c[0] == gc[0] {
                        found = true;
                        let is_primary = c[2].parse::<u32>().ok() == Some(e.gid);
                        let mut m: Vec<&str> = c[3].split(',').filter(|x| !x.is_empty()).collect();
                        if !is_primary && !m.contains(&name.as_str()) {
                            m.push(&name);
                        }
                        format!("{}:{}:{}:{}", c[0], c[1], c[2], m.join(","))
                    } else {
                        l.to_string()
                    }
                })
                .collect();
            group = lines.join("\n") + "\n";
            if !found {
                group.push_str(gl);
                group.push('\n');
            }
        }
        keys.push((e, a["authorized_keys"].as_str().unwrap_or("").to_string()));
        notes.push(format!("system account {name} restored"));
    }
    if keys.is_empty()
        && doc["root_authorized_keys"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    {
        return Ok(notes);
    }
    write_atomic(&p.passwd, &passwd, 0o644)?;
    write_atomic(&p.shadow, &shadow, 0o600)?;
    write_atomic(&p.group, &group, 0o644)?;
    for (e, k) in keys {
        let lines: Vec<String> = k
            .lines()
            .filter(|l| parse_key(l).is_ok())
            .map(str::to_string)
            .collect();
        if !lines.is_empty() {
            write_keys(p, &e, &lines)?;
        }
    }
    let rk = doc["root_authorized_keys"].as_str().unwrap_or("");
    if let Some(root) = parse_passwd(&passwd).into_iter().find(|e| e.name == "root") {
        let have = read_keys(&keys_file(p, &root));
        let mut lines: Vec<String> = have.iter().map(|(l, _)| l.clone()).collect();
        let mut added = 0;
        for l in rk.lines() {
            if let Ok(k) = parse_key(l) {
                if !have
                    .iter()
                    .any(|(_, h)| h.as_ref().is_some_and(|h| h.blob == k.blob))
                {
                    lines.push(l.trim().to_string());
                    added += 1;
                }
            }
        }
        if added > 0 {
            write_keys(p, &root, &lines)?;
            notes.push(format!("{added} SSH key(s) of root restored"));
        }
    }
    Ok(notes)
}

// ---------------------------------------------------------------------------
// the access point's own address (AP_ADDR / AP_GW / AP_DNS) with a rollback timer
// ---------------------------------------------------------------------------

/// Validated address settings: (AP_ADDR, AP_GW, AP_DNS); empty AP_ADDR = DHCP.
pub fn check_address(
    mode: &str,
    addr: &str,
    gw: &str,
    dns: &str,
) -> Result<(String, String, String)> {
    match mode {
        "dhcp" => Ok((String::new(), String::new(), String::new())),
        "static" => {
            let net: ipnetwork::Ipv4Network = addr.trim().parse().map_err(|_| {
                invalid(format!(
                    "address {addr:?}: an IPv4 address with prefix, e.g. 192.0.2.10/24"
                ))
            })?;
            if !(8..=30).contains(&net.prefix()) {
                return Err(invalid("the prefix length is 8 to 30"));
            }
            let ip = net.ip();
            if ip == net.network()
                || ip == net.broadcast()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
            {
                return Err(invalid(format!("{ip} cannot be this unit's address")));
            }
            let gw = gw.trim();
            let g: std::net::Ipv4Addr = gw
                .parse()
                .map_err(|_| invalid(format!("gateway {gw:?}: an IPv4 address")))?;
            if !net.contains(g) || g == ip {
                return Err(invalid(format!(
                    "the gateway {g} must be another address in {}/{}",
                    net.network(),
                    net.prefix()
                )));
            }
            let mut d = Vec::new();
            for s in dns.split([' ', ',']).filter(|s| !s.is_empty()) {
                let a: std::net::IpAddr = s
                    .parse()
                    .map_err(|_| invalid(format!("DNS server {s:?}: an IP address")))?;
                d.push(a.to_string());
            }
            if d.is_empty() {
                d.push(g.to_string());
            }
            if d.len() > 3 {
                return Err(invalid("at most three DNS servers"));
            }
            Ok((format!("{ip}/{}", net.prefix()), g.to_string(), d.join(" ")))
        }
        _ => Err(invalid(format!("addressing {mode:?}: dhcp or static"))),
    }
}

pub fn address_get(ap_env: &Path) -> Value {
    let f = read_file(ap_env);
    let st = run(&libexec("ap-addr"), &["status"]).unwrap_or_default();
    json!({
        "mode": if f.get("AP_ADDR").unwrap_or("").is_empty() { "dhcp" } else { "static" },
        "address": f.get("AP_ADDR").unwrap_or(""),
        "gateway": f.get("AP_GW").unwrap_or(""),
        "dns": f.get("AP_DNS").unwrap_or(""),
        "available": libexec("ap-addr").is_file(),
        "pending": kv_lines(&st),
    })
}

/// Save new address settings and start the trial: `ap-addr trial SECS` (detached) adds the new address next to the
/// current one; unless `address_confirm` runs within SECS seconds, the previous settings come back by themselves.
pub fn address_set(ap_env: &Path, v: &Value) -> Result<Value> {
    if !libexec("ap-addr").is_file() {
        return Err(invalid(
            "this firmware cannot change its address from the web UI (ap-addr)",
        ));
    }
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
    let (a, g, d) = check_address(s("mode"), s("address"), s("gateway"), s("dns"))?;
    let secs = v
        .get("confirm_within")
        .and_then(Value::as_u64)
        .unwrap_or(120);
    if !(30..=600).contains(&secs) {
        return Err(invalid("the confirmation window is 30 to 600 seconds"));
    }
    let old = std::fs::read_to_string(ap_env).unwrap_or_default();
    let f = parse(&old);
    if f.get("AP_ADDR").unwrap_or("") == a
        && f.get("AP_GW").unwrap_or("") == g
        && f.get("AP_DNS").unwrap_or("") == d
    {
        return Ok(json!({ "changed": false }));
    }
    let st = kv_lines(&run(&libexec("ap-addr"), &["status"]).unwrap_or_default());
    if st.get("pending").and_then(Value::as_str) == Some("yes") {
        return Err(invalid(
            "an address change is already waiting for confirmation",
        ));
    }
    write_atomic(&ap_env.with_extension("env.addr-prev"), &old, 0o600)?;
    let opt = |x: String| Some(x);
    set_vars(
        ap_env,
        &[
            ("AP_ADDR", opt(a.clone())),
            ("AP_GW", opt(g.clone())),
            ("AP_DNS", opt(d.clone())),
        ],
    )?;
    // the script detaches the trial itself (its own systemd unit, or setsid) and returns at once, so this request is
    // answered before the bridge changes; a restart during the trial also reverts (the pending marker is on /etc)
    run(&libexec("ap-addr"), &["trial", &secs.to_string()])?;
    Ok(json!({
        "changed": true,
        "mode": if a.is_empty() { "dhcp" } else { "static" },
        "address": a, "gateway": g, "dns": d,
        "confirm_within": secs,
        "note": format!("the new settings run next to the current address for {secs} s: open this page at the new address and confirm, or the previous settings come back by themselves"),
    }))
}

/// Keep the trial settings. `host` = the address the confirming browser used, which must be one of the NEW
/// addresses: a confirmation that only reached the unit over its old address proves nothing about the new one.
pub fn address_confirm(host: &str) -> Result<Value> {
    let st = kv_lines(&run(&libexec("ap-addr"), &["status"]).unwrap_or_default());
    if st.get("pending").and_then(Value::as_str) != Some("yes") {
        return Err(invalid("no address change is waiting for confirmation"));
    }
    let new: Vec<String> = st
        .get("new")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .map(|a| a.split('/').next().unwrap_or("").to_string())
        .collect();
    let host = host
        .trim()
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("");
    let host = if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or("")
    } else {
        host
    };
    if !new.iter().any(|a| a == host) {
        return Err(invalid(format!(
            "confirm from the new address ({}): this page was opened at {host}",
            if new.is_empty() {
                "not up yet".to_string()
            } else {
                new.join(", ")
            }
        )));
    }
    run(&libexec("ap-addr"), &["confirm"])?;
    Ok(json!({ "ok": true, "confirmed": new }))
}

// ---------------------------------------------------------------------------
// online firmware check
// ---------------------------------------------------------------------------

/// Fingerprint of the Errant Solutions release key (keys/release-signing.asc); the feed's metadata must be signed
/// by exactly this key.
pub const RELEASE_KEY_FPR: &str = "5439354939B9C0552A68E9BBE323A6A3AC0A6506";

fn release_fpr() -> String {
    std::env::var("PATRONUS_FW_FPR").unwrap_or_else(|_| RELEASE_KEY_FPR.into())
}

/// The feed directory of this board and init system: `<feed>/<board with , -> _>/<init>/`.
pub fn feed_dir(feed: &str, board: &str, init: &str) -> Result<String> {
    let feed = feed.trim().trim_end_matches('/');
    if !(feed.starts_with("https://") || feed.starts_with("http://"))
        || feed.contains(char::is_whitespace)
    {
        return Err(invalid(format!("feed URL {feed:?}: http(s)://...")));
    }
    let board = board.replace(',', "_");
    if board.is_empty()
        || !board
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        || !matches!(init, "openrc" | "systemd")
    {
        return Err(invalid(format!(
            "this firmware does not name its board/init ({board:?}, {init:?})"
        )));
    }
    Ok(format!("{feed}/{board}/{init}"))
}

/// The primary-key fingerprint of a good signature in gpgv `--status-fd` output.
pub fn validsig_fpr(status: &str) -> Option<String> {
    let good = status.lines().any(|l| l.starts_with("[GNUPG:] GOODSIG "));
    status
        .lines()
        .find_map(|l| l.strip_prefix("[GNUPG:] VALIDSIG "))
        .and_then(|r| r.split_whitespace().last().map(str::to_ascii_uppercase))
        .filter(|_| good)
}

fn fetch(url: &str, to: &Path) -> Result<()> {
    let wget = env_path("PATRONUS_WGET", "wget");
    let o = Command::new(&wget)
        .args(["-q", "-T", "30", "-O"])
        .arg(to)
        .arg(url)
        .output()
        .map_err(|e| Error::Service(format!("wget: {e}")))?;
    if !o.status.success() {
        let _ = std::fs::remove_file(to);
        return Err(Error::Service(format!(
            "could not download {url}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )));
    }
    Ok(())
}

pub struct FeedPaths {
    pub release: PathBuf,
    pub keyring: PathBuf,
    pub work: PathBuf,
}

impl Default for FeedPaths {
    fn default() -> Self {
        FeedPaths {
            release: env_path("PATRONUS_RELEASE_FILE", "/etc/patronus-release"),
            keyring: env_path(
                "PATRONUS_FW_KEYRING",
                "/usr/share/openpgp-keys/errantsolutions.gpg",
            ),
            work: env_path("PATRONUS_FW_WORK", "/tmp/patronus-feed"),
        }
    }
}

fn release_value(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Download and verify the feed's `latest.json` (+ `latest.json.sig`, a detached OpenPGP signature by the release
/// key, checked with gpgv against the keyring built into this firmware). Nothing is installed.
pub fn feed_check(fp: &FeedPaths, feed: &str) -> Result<Value> {
    if feed.trim().is_empty() {
        return Err(invalid(
            "no update feed is configured (System > Firmware > feed URL)",
        ));
    }
    let rel = std::fs::read_to_string(&fp.release).unwrap_or_default();
    let (board, init, build) = (
        release_value(&rel, "BOARD"),
        release_value(&rel, "INIT"),
        release_value(&rel, "BUILD"),
    );
    let dir = feed_dir(feed, &board, &init)?;
    if !fp.keyring.is_file() {
        return Err(Error::Service(format!(
            "this firmware has no release keyring ({}): it cannot verify an update feed, so it does not use one",
            fp.keyring.display()
        )));
    }
    let _ = std::fs::remove_dir_all(&fp.work);
    std::fs::create_dir_all(&fp.work)
        .map_err(|e| Error::Service(format!("{}: {e}", fp.work.display())))?;
    let (j, s) = (fp.work.join("latest.json"), fp.work.join("latest.json.sig"));
    fetch(&format!("{dir}/latest.json"), &j)?;
    fetch(&format!("{dir}/latest.json.sig"), &s)?;
    let gpgv = env_path("PATRONUS_GPGV", "gpgv");
    let gh = fp.work.join("gnupg");
    let _ = std::fs::create_dir_all(&gh);
    let o = Command::new(&gpgv)
        .env("GNUPGHOME", &gh)
        .args(["--status-fd", "1", "--keyring"])
        .arg(&fp.keyring)
        .arg(&s)
        .arg(&j)
        .output()
        .map_err(|e| Error::Service(format!("gpgv: {e}")))?;
    let status = String::from_utf8_lossy(&o.stdout);
    match validsig_fpr(&status) {
        Some(f) if o.status.success() && f == release_fpr() => {}
        Some(f) => {
            return Err(invalid(format!(
                "the feed is signed by key {f}, not by the release key {}: refused",
                release_fpr()
            )))
        }
        None => return Err(invalid("the feed's signature is missing or bad: refused")),
    }
    let meta: Value = serde_json::from_slice(&std::fs::read(&j).unwrap_or_default())
        .map_err(|e| invalid(format!("the feed's latest.json: {e}")))?;
    let l = |k: &str| {
        meta.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (lb, image, sha) = (l("build"), l("image"), l("sha256").to_ascii_lowercase());
    let size = meta.get("size").and_then(Value::as_u64).unwrap_or(0);
    if lb.is_empty()
        || image.is_empty()
        || image.contains('/')
        || image.contains("..")
        || !image.ends_with(".tar")
        || sha.len() != 64
        || !sha.chars().all(|c| c.is_ascii_hexdigit())
        || size == 0
    {
        return Err(invalid(
            "the feed's latest.json lacks build, image, sha256 or size",
        ));
    }
    Ok(json!({
        "current": build,
        "latest": { "build": lb, "version": l("version"), "notes": l("notes"), "date": l("date"),
                    "image": image, "url": format!("{dir}/{image}"), "sha256": sha, "size": size },
        "update_available": lb != build,
        "signed_by": release_fpr(),
    }))
}

/// Download the image the verified feed names into `to` (sha256 and size checked). The caller hands it to the
/// existing firmware check (`patronus-flash check`); installing stays a separate, explicit step.
pub fn feed_download(fp: &FeedPaths, feed: &str, to: &Path) -> Result<Value> {
    let c = feed_check(fp, feed)?;
    let url = c["latest"]["url"].as_str().unwrap_or("").to_string();
    let sha = c["latest"]["sha256"].as_str().unwrap_or("").to_string();
    let size = c["latest"]["size"].as_u64().unwrap_or(0);
    if let Some(dir) = to.parent() {
        if let Ok(st) = nix::sys::statvfs::statvfs(dir) {
            // statvfs field widths differ per target (u32 on 32-bit MIPS, u64 here)
            #[allow(clippy::useless_conversion)]
            let free = u64::from(st.blocks_available()) * u64::from(st.fragment_size());
            if free < size + 4 * 1024 * 1024 {
                return Err(Error::Service(format!(
                    "not enough room in {} for a {} MiB image ({} MiB free)",
                    dir.display(),
                    size / 1048576,
                    free / 1048576
                )));
            }
        }
    }
    let part = to.with_extension("part");
    fetch(&url, &part)?;
    let data =
        std::fs::read(&part).map_err(|e| Error::Service(format!("{}: {e}", part.display())))?;
    let got = hex(&Sha256::digest(&data));
    if data.len() as u64 != size || got != sha {
        let _ = std::fs::remove_file(&part);
        return Err(invalid(format!(
            "the downloaded image does not match the signed feed (size {} vs {size}, sha256 {got} vs {sha}): removed",
            data.len()
        )));
    }
    std::fs::rename(&part, to).map_err(|e| Error::Service(format!("{}: {e}", to.display())))?;
    Ok(c)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn feed_url() -> String {
    read_file(&device_env())
        .get("FW_FEED_URL")
        .unwrap_or("")
        .to_string()
}

pub fn feed_set(url: &str) -> Result<Value> {
    let url = url.trim();
    if !url.is_empty() {
        feed_dir(url, "b", "openrc")?;
    }
    set_vars(
        &device_env(),
        &[("FW_FEED_URL", (!url.is_empty()).then(|| url.to_string()))],
    )?;
    Ok(json!({ "feed": url }))
}

/// For tests and docs: a shell-quoted assignment as the files hold it.
pub fn assignment(k: &str, v: &str) -> String {
    format!("{k}={}", quote(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh user@host";

    #[test]
    fn keys_are_validated() {
        let k = parse_key(ED).unwrap();
        assert_eq!(k.kind, "ssh-ed25519");
        assert_eq!(k.comment, "user@host");
        assert!(
            k.fingerprint.starts_with("SHA256:") && k.fingerprint.len() == 50,
            "{}",
            k.fingerprint
        );
        for bad in [
            "",
            "ssh-dss AAAAB3NzaC1kc3M= x",
            "command=\"id\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh",
            "ssh-ed25519 not-base64!!",
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZC",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMZCoQbywI87vj5xHCZCN3GeRyG77PKWc5YUW/XNmwrh a\nssh-rsa x",
        ] {
            assert!(parse_key(bad).is_err(), "{bad:?}");
        }
    }

    fn etc() -> (tempfile::TempDir, EtcPaths) {
        let d = tempfile::tempdir().unwrap();
        let e = d.path().join("etc");
        std::fs::create_dir_all(&e).unwrap();
        std::fs::write(e.join("passwd"), "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\nchrony:x:980:980::/var/lib/chrony:/sbin/nologin\nalice:x:65535:65535::/home/alice:/bin/sh\nweb:x:65533:65533::/nonexistent:/sbin/nologin\n").unwrap();
        std::fs::write(e.join("shadow"), "root:!:19000:0:99999:7:::\nalice:$6$abc$def:19000:0:99999:7:::\nweb:$6$w$w:19000:0:99999:7:::\n").unwrap();
        std::fs::write(
            e.join("group"),
            "root:x:0:\nalice:x:65535:\npatronus-admin:x:65536:alice\n",
        )
        .unwrap();
        let p = EtcPaths {
            passwd: e.join("passwd"),
            shadow: e.join("shadow"),
            group: e.join("group"),
            root: d.path().join("fs"),
        };
        (d, p)
    }

    #[test]
    fn keys_add_list_delete_with_anti_lockout() {
        let (_d, p) = etc();
        let users: Vec<String> = keys_get(&p)["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["user"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            users,
            vec!["root", "alice"],
            "system and web-only accounts are not listed"
        );
        let fp = keys_add(&p, "root", ED).unwrap()["fingerprint"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(keys_add(&p, "root", ED)
            .unwrap_err()
            .to_string()
            .contains("already"));
        assert!(keys_add(&p, "chrony", ED).is_err());
        let f = p.root.join("root/.ssh/authorized_keys");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(keys_get(&p)["users"][0]["keys"][0]["fingerprint"], fp);
        // root has no password: its last key stays
        let e = keys_delete(&p, "root", &fp).unwrap_err().to_string();
        assert!(e.contains("lock"), "{e}");
        // alice's only key can go (root still has one)
        keys_add(&p, "alice", ED).unwrap();
        keys_delete(&p, "alice", &fp).unwrap();
        assert_eq!(
            keys_get(&p)["users"][1]["keys"].as_array().unwrap().len(),
            0
        );
        assert!(keys_delete(&p, "alice", &fp).is_err());
        // with a root password, root's last key may go
        std::fs::write(&p.shadow, "root:$6$x$y:19000:0:99999:7:::\n").unwrap();
        keys_delete(&p, "root", &fp).unwrap();
    }

    #[test]
    fn accounts_survive_a_backup_and_restore() {
        let (_d, p) = etc();
        keys_add(&p, "alice", ED).unwrap();
        keys_add(&p, "root", ED).unwrap();
        let doc = accounts_export(&p);
        assert_eq!(doc["accounts"].as_array().unwrap().len(), 2, "{doc}");
        assert_eq!(doc["accounts"][0]["name"], "alice");
        assert_eq!(
            doc["accounts"][1]["name"], "web",
            "web-only accounts are backed up too"
        );
        assert!(doc["accounts"][0]["shadow"]
            .as_str()
            .unwrap()
            .starts_with("alice:$6$"));
        assert!(
            !doc.to_string().contains("root:!"),
            "root's password is not exported"
        );
        // the account is lost (as after a factory reset of /etc)
        std::fs::write(&p.passwd, "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        std::fs::write(&p.shadow, "root:!:19000:0:99999:7:::\n").unwrap();
        std::fs::write(&p.group, "root:x:0:\npatronus-admin:x:65536:\n").unwrap();
        std::fs::remove_dir_all(&p.root).unwrap();
        let notes = accounts_restore(&p, &doc).unwrap();
        assert!(
            notes.iter().any(|n| n.contains("alice restored")),
            "{notes:?}"
        );
        let pw = std::fs::read_to_string(&p.passwd).unwrap();
        assert!(pw.contains("alice:x:65535:65535::/home/alice:/bin/sh"));
        assert!(std::fs::read_to_string(&p.shadow)
            .unwrap()
            .contains("alice:$6$abc$def:"));
        let g = std::fs::read_to_string(&p.group).unwrap();
        assert!(g.contains("patronus-admin:x:65536:alice"), "{g}");
        assert!(
            g.contains("alice:x:65535:"),
            "the missing primary group is added: {g}"
        );
        assert_eq!(
            keys_get(&p)["users"][1]["keys"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            keys_get(&p)["users"][0]["keys"].as_array().unwrap().len(),
            1,
            "root's key merged back"
        );
        // idempotent, and a uid clash is skipped
        accounts_restore(&p, &doc).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p.passwd)
                .unwrap()
                .lines()
                .filter(|l| l.starts_with("alice:"))
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(&p.group)
                .unwrap()
                .matches("alice")
                .count(),
            2
        );
        std::fs::write(
            &p.passwd,
            "root:x:0:0:root:/root:/bin/sh\nbob:x:65535:65535::/home/bob:/bin/sh\n",
        )
        .unwrap();
        let n = accounts_restore(&p, &doc).unwrap();
        assert!(n[0].contains("belongs to another"), "{n:?}");
        // malformed lines are never written
        let bad =
            json!({"accounts": [{"name": "eve", "passwd": "eve:x:0:0::/:/bin/sh", "shadow": ""}]});
        assert!(accounts_restore(&p, &bad).unwrap()[0].contains("skipped"));
    }

    #[test]
    fn schedules_and_addresses_are_validated() {
        assert_eq!(
            check_schedule("weekly", Some("4:05"), Some("Monday")).unwrap(),
            ("weekly".into(), "04:05".into(), "mon".into())
        );
        assert!(check_schedule("hourly", None, None).is_err());
        assert!(check_schedule("daily", Some("24:00"), None).is_err());
        assert!(check_schedule("daily", Some("3:5"), None).is_err());
        assert_eq!(
            schedule_specs("weekly", "04:05", "mon").unwrap(),
            ("5 4 * * 1".to_string(), "Mon *-*-* 04:05:00".to_string())
        );
        assert_eq!(
            schedule_specs("daily", "23:30", "sun").unwrap().0,
            "30 23 * * *"
        );
        assert_eq!(schedule_specs("off", "23:30", "sun"), None);
        assert_eq!(
            check_address("static", "192.0.2.10/24", "192.0.2.1", "").unwrap(),
            (
                "192.0.2.10/24".into(),
                "192.0.2.1".into(),
                "192.0.2.1".into()
            )
        );
        assert_eq!(check_address("dhcp", "x", "y", "z").unwrap().0, "");
        for (a, g, d) in [
            ("192.0.2.10", "192.0.2.1", ""),
            ("192.0.2.0/24", "192.0.2.1", ""),
            ("192.0.2.10/24", "198.51.100.1", ""),
            ("192.0.2.10/24", "192.0.2.10", ""),
            ("192.0.2.10/24", "192.0.2.1", "dns.example"),
            ("192.0.2.10/31", "192.0.2.11", ""),
        ] {
            assert!(check_address("static", a, g, d).is_err(), "{a} {g} {d}");
        }
    }

    #[test]
    fn feed_is_verified_before_anything_is_trusted() {
        assert_eq!(
            feed_dir("https://fw.example/patronus/", "glinet,gl-ax1800", "openrc").unwrap(),
            "https://fw.example/patronus/glinet_gl-ax1800/openrc"
        );
        assert!(feed_dir("ftp://x", "b", "openrc").is_err());
        assert!(feed_dir("https://x", "", "openrc").is_err());
        let st = format!("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG E323A6A3AC0A6506 Errant\n[GNUPG:] VALIDSIG AAAA 2026-11-17 1 0 4 0 22 8 01 {RELEASE_KEY_FPR}\n");
        assert_eq!(validsig_fpr(&st).as_deref(), Some(RELEASE_KEY_FPR));
        assert_eq!(validsig_fpr("[GNUPG:] BADSIG x\n"), None);

        // fake wget (copies from a local "server" dir) and gpgv (good signature by the key named in $FAKE_FPR)
        let d = tempfile::tempdir().unwrap();
        let srv = d.path().join("srv/glinet_gl-ax1800/openrc");
        std::fs::create_dir_all(&srv).unwrap();
        let img = b"image bytes";
        let sha = hex(&Sha256::digest(img));
        std::fs::write(srv.join("p-2-sysupgrade.tar"), img).unwrap();
        std::fs::write(
            srv.join("latest.json"),
            json!({"build": "unit-new-openrc", "version": "0.3.0", "image": "p-2-sysupgrade.tar", "sha256": sha, "size": img.len()}).to_string(),
        )
        .unwrap();
        std::fs::write(srv.join("latest.json.sig"), "sig").unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let wget = bin.join("wget");
        std::fs::write(&wget, format!("#!/bin/sh\n# -q -T 30 -O FILE URL\nu=$6; f=${{u#https://fw.test/}}; cp \"{}/$f\" \"$5\"\n", d.path().join("srv").display())).unwrap();
        let gpgv = bin.join("gpgv");
        std::fs::write(&gpgv, "#!/bin/sh\necho \"[GNUPG:] GOODSIG X Errant\"; echo \"[GNUPG:] VALIDSIG Y 2026 1 0 4 0 22 8 01 $(cat \"$(dirname \"$0\")/fpr\")\"\n").unwrap();
        std::fs::write(bin.join("fpr"), RELEASE_KEY_FPR).unwrap();
        use std::os::unix::fs::PermissionsExt;
        for f in [&wget, &gpgv] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("PATRONUS_WGET", &wget);
        std::env::set_var("PATRONUS_GPGV", &gpgv);
        let rel = d.path().join("release");
        std::fs::write(
            &rel,
            "BUILD=unit-old-openrc\nBOARD=glinet,gl-ax1800\nINIT=openrc\n",
        )
        .unwrap();
        let mut fp = FeedPaths {
            release: rel,
            keyring: d.path().join("nokeyring"),
            work: d.path().join("work"),
        };
        assert!(feed_check(&fp, "")
            .unwrap_err()
            .to_string()
            .contains("no update feed"));
        assert!(feed_check(&fp, "https://fw.test")
            .unwrap_err()
            .to_string()
            .contains("no release keyring"));
        fp.keyring = d.path().join("keyring");
        std::fs::write(&fp.keyring, "k").unwrap();
        let c = feed_check(&fp, "https://fw.test").unwrap();
        assert_eq!(c["update_available"], true);
        assert_eq!(c["latest"]["build"], "unit-new-openrc");
        let to = d.path().join("upload.tar");
        feed_download(&fp, "https://fw.test", &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), img);
        // a tampered image is refused and removed
        std::fs::write(srv.join("p-2-sysupgrade.tar"), b"image bytez").unwrap();
        std::fs::remove_file(&to).unwrap();
        assert!(feed_download(&fp, "https://fw.test", &to)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        assert!(!to.exists());
        // signed by another key: refused
        std::fs::write(bin.join("fpr"), "0000000000000000000000000000000000000000").unwrap();
        let e = feed_check(&fp, "https://fw.test").unwrap_err().to_string();
        assert!(e.contains("not by the release key"), "{e}");
        std::env::remove_var("PATRONUS_WGET");
        std::env::remove_var("PATRONUS_GPGV");
    }

    #[test]
    fn device_env_keeps_other_lines() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("device.env");
        std::fs::write(&f, "# mine\nFOO='a b'\nLEDS=on\n").unwrap();
        set_vars(&f, &[("LEDS", Some("off".into())), ("X", None)]).unwrap();
        let t = std::fs::read_to_string(&f).unwrap();
        assert!(
            t.starts_with("# mine\n") && t.contains("FOO='a b'") && t.contains("LEDS=off"),
            "{t}"
        );
        assert_eq!(assignment("A", "x y"), "A='x y'");
        let leds = d.path().join("leds");
        std::fs::create_dir_all(leds.join("green:status")).unwrap();
        std::fs::write(
            leds.join("green:status/trigger"),
            "none [default-on] timer\n",
        )
        .unwrap();
        std::fs::write(leds.join("green:status/brightness"), "1\n").unwrap();
        let l = leds_list(&leds);
        assert_eq!(l[0]["trigger"], "default-on");
        assert_eq!(l[0]["brightness"], 1);
        assert!(leds_list(&d.path().join("none")).is_empty());
    }
}
