//! Keep the installer's system `dhcpcd` away from the interfaces Patronus configures.
//!
//! The installed image runs one system-wide `dhcpcd` (the installer's network stack, in the default runlevel) that manages every wired
//! NIC. Once the interfaces applier takes an interface over (a static address, its own per-interface DHCP client
//! `patronus-dhcpc.<dev>`, a bridge/bond member with no address), two managers fight over it: the system dhcpcd re-adds a DHCP address
//! and a `proto dhcp` route to a LAN port that has a static one, refuses to share the pid/lease files with Patronus' own client, and
//! after a reboot races the boot apply for the WAN default route.
//!
//! The applier therefore keeps a marked block in the system dhcpcd's config:
//!
//! ```text
//! # BEGIN patronus-managed
//! denyinterfaces enp0s1 enp0s2
//! # END patronus-managed
//! ```
//!
//! (a later dhcpcd start, i.e. every boot, ignores those interfaces) and tells a running manager to let go of them with
//! `dhcpcd -x <dev>`; the installer's config sets `persistent`, so the addresses and routes stay put. The rest of the file is never
//! touched, and a box that opted out (`network.system_dhcpcd` = `leave`) keeps the old behaviour.
//!
//! Settings (system_config, set from the Interfaces page / `PUT /api/interfaces/system-dhcpcd`):
//! - [`MODE_KEY`] `network.system_dhcpcd`: `release` (default) or `leave`
//! - [`CONF_KEY`] `network.system_dhcpcd_conf`: the config file to edit (default [`DEFAULT_CONF`])
//! - [`RUN_KEY`] `network.system_dhcpcd_run`: its run directory (default [`DEFAULT_RUN_DIR`])
//!
//! A port Patronus puts in DHCP mode is NOT denied: with the manager running, a second `dhcpcd <port>` cannot run beside it (it hands its
//! command line to the manager and exits), so the manager stays the DHCP client of that port and Patronus only asks it to start
//! (`dhcpcd <port>`). Static, down and member ports are denied.

use patronus_core::{Error, Result};
use std::path::{Path, PathBuf};

pub const MODE_KEY: &str = "network.system_dhcpcd";
pub const CONF_KEY: &str = "network.system_dhcpcd_conf";
pub const RUN_KEY: &str = "network.system_dhcpcd_run";
pub const DEFAULT_CONF: &str = "/etc/dhcpcd.conf";
/// dhcpcd's run directory; `<run dir>/sock` is the control socket of the manager daemon (a per-interface instance has `<iface>.sock`).
pub const DEFAULT_RUN_DIR: &str = "/run/dhcpcd";
pub const BEGIN: &str = "# BEGIN patronus-managed";
pub const END: &str = "# END patronus-managed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Keep the system dhcpcd off the interfaces Patronus configures.
    #[default]
    Release,
    /// Never touch the system dhcpcd.
    Leave,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "release" => Ok(Mode::Release),
            "leave" => Ok(Mode::Leave),
            o => Err(Error::Config(format!(
                "Invalid system dhcpcd mode {o:?} (release or leave)"
            ))),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Release => "release",
            Mode::Leave => "leave",
        }
    }
}

/// The resolved settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub mode: Mode,
    pub conf: PathBuf,
    pub run_dir: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Release,
            conf: PathBuf::from(DEFAULT_CONF),
            run_dir: PathBuf::from(DEFAULT_RUN_DIR),
        }
    }
}

impl Settings {
    pub fn from_values(mode: Option<&str>, conf: Option<&str>, run: Option<&str>) -> Result<Self> {
        let path = |what: &str, v: Option<&str>, default: &str| -> Result<PathBuf> {
            let v = v.map(str::trim).filter(|c| !c.is_empty());
            if let Some(c) = v {
                if !c.starts_with('/') || c.contains('\0') || c.contains("..") {
                    return Err(Error::Config(format!(
                        "Invalid system dhcpcd {what} {c:?}: an absolute path"
                    )));
                }
            }
            Ok(PathBuf::from(v.unwrap_or(default)))
        };
        Ok(Self {
            mode: Mode::parse(mode.unwrap_or(""))?,
            conf: path("config path", conf, DEFAULT_CONF)?,
            run_dir: path("run directory", run, DEFAULT_RUN_DIR)?,
        })
    }
}

/// Is a dhcpcd manager daemon running (its control socket exists in `run_dir`)?
pub fn manager_running(run_dir: &Path) -> bool {
    run_dir.join("sock").exists()
}

/// An interface name that is safe to put on a `denyinterfaces` line (no glob, no whitespace).
fn plain_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 15
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}

/// Does this config line open a per-interface/SSID/profile scope? In dhcpcd.conf everything after such a line belongs to that scope, and
/// `denyinterfaces` is only honoured in the global part, i.e. BEFORE the first one.
fn opens_scope(line: &str) -> bool {
    let t = line.trim_start();
    ["interface", "ssid", "profile", "arping"].iter().any(|k| {
        t.strip_prefix(k)
            .is_some_and(|r| r.starts_with([' ', '\t']))
    })
}

/// `conf` with the Patronus block set to `owned` (sorted, deduplicated); the block is removed when `owned` is empty. Everything outside the
/// block is kept byte for byte. The block goes into the global part of the file (before the first `interface`/`ssid`/`profile`/`arping`
/// line): appended after the installer's `interface enp0s2` / `static ip_address=...` lines it would sit inside that interface's scope and
/// dhcpcd would silently ignore it.
pub fn merge(conf: &str, owned: &[String]) -> String {
    let mut names: Vec<&str> = owned
        .iter()
        .map(String::as_str)
        .filter(|n| plain_name(n))
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut kept: Vec<&str> = Vec::new();
    let mut inside = false;
    let mut dangling = false;
    for line in conf.split_inclusive('\n') {
        let t = line.trim();
        if t == BEGIN {
            inside = true;
            dangling = true;
            continue;
        }
        if inside {
            if t == END {
                inside = false;
                dangling = false;
            }
            continue;
        }
        kept.push(line);
    }
    if dangling {
        // a BEGIN without END: what followed it may not have been ours; keep the text, drop only the marker
        kept = conf
            .split_inclusive('\n')
            .filter(|l| l.trim() != BEGIN)
            .collect();
    }
    if names.is_empty() {
        return kept.concat();
    }
    let block = format!("{BEGIN}\ndenyinterfaces {}\n{END}\n", names.join(" "));
    let at = kept
        .iter()
        .position(|l| opens_scope(l))
        .unwrap_or(kept.len());
    let mut out = String::with_capacity(conf.len() + block.len() + 1);
    for l in &kept[..at] {
        out.push_str(l);
    }
    if at == kept.len() && !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);
    for l in &kept[at..] {
        out.push_str(l);
    }
    out
}

/// Write the block; `Ok(true)` when the file changed. A missing config file means there is no system dhcpcd to keep away: nothing to do.
pub fn write_block(conf: &Path, owned: &[String]) -> std::io::Result<bool> {
    let old = match std::fs::read_to_string(conf) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let new = merge(&old, owned);
    if new == old {
        return Ok(false);
    }
    let tmp = conf.with_extension("patronus-tmp");
    let meta = std::fs::metadata(conf)?;
    std::fs::write(&tmp, new)?;
    std::fs::set_permissions(&tmp, meta.permissions())?;
    std::fs::rename(&tmp, conf)?;
    Ok(true)
}

/// The interfaces named in the Patronus block of `conf` (for status/tests).
pub fn denied(conf: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for l in conf.lines() {
        let t = l.trim();
        if t == BEGIN {
            inside = true;
        } else if t == END {
            inside = false;
        } else if inside {
            if let Some(rest) = t.strip_prefix("denyinterfaces") {
                out.extend(rest.split_whitespace().map(str::to_string));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLER: &str = "# written by live-installer\nduid\npersistent\ndenyinterfaces wlan* wlp*\n\ninterface enp0s2\nstatic ip_address=10.77.0.1/24\n";

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_block_goes_into_the_global_part_before_the_first_interface_scope() {
        let m = merge(INSTALLER, &v(&["enp0s2", "enp0s1", "enp0s2"]));
        let block = format!("{BEGIN}\ndenyinterfaces enp0s1 enp0s2\n{END}\n");
        let (b, i) = (m.find(&block).unwrap(), m.find("interface enp0s2").unwrap());
        assert!(
            b < i,
            "denyinterfaces must precede `interface enp0s2`, else dhcpcd ignores it:\n{m}"
        );
        assert!(m.contains("denyinterfaces wlan* wlp*"), "{m}");
        assert_eq!(merge(&m, &v(&["enp0s1", "enp0s2"])), m, "idempotent");
        assert_eq!(denied(&m), v(&["enp0s1", "enp0s2"]));
        // the installer's static block is untouched and still last
        assert!(m.ends_with("interface enp0s2\nstatic ip_address=10.77.0.1/24\n"));
    }

    #[test]
    fn the_block_follows_the_owned_set_and_disappears_with_it() {
        let m = merge(INSTALLER, &v(&["enp0s1", "enp0s2"]));
        let m2 = merge(&m, &v(&["enp0s1"]));
        assert_eq!(denied(&m2), v(&["enp0s1"]));
        assert_eq!(
            merge(&m2, &[]),
            INSTALLER,
            "removing the block restores the file byte for byte"
        );
        // a block left at the END by an older build moves into the global part
        let old = format!("{INSTALLER}{BEGIN}\ndenyinterfaces enp0s1\n{END}\n");
        let fixed = merge(&old, &v(&["enp0s1"]));
        assert!(
            fixed.find(BEGIN).unwrap() < fixed.find("interface enp0s2").unwrap(),
            "{fixed}"
        );
        assert_eq!(fixed.matches(BEGIN).count(), 1);
    }

    #[test]
    fn a_file_without_scopes_or_a_final_newline_and_hostile_names() {
        let m = merge("duid", &v(&["eth0", "a b", "wlan*", "", "x\ny"]));
        assert_eq!(m, format!("duid\n{BEGIN}\ndenyinterfaces eth0\n{END}\n"));
        assert_eq!(
            merge("", &v(&["eth0"])),
            format!("{BEGIN}\ndenyinterfaces eth0\n{END}\n")
        );
        // comments that merely mention interface do not open a scope
        let c = merge("# interface eth9 is special\nduid\n", &v(&["eth0"]));
        assert!(
            c.ends_with(&format!("{BEGIN}\ndenyinterfaces eth0\n{END}\n")),
            "{c}"
        );
    }

    #[test]
    fn a_dangling_begin_marker_never_eats_the_rest_of_the_file() {
        let m = merge(&format!("a\n{BEGIN}\nb\n"), &[]);
        assert_eq!(m, "a\nb\n");
    }

    #[test]
    fn settings_validate() {
        assert_eq!(
            Settings::from_values(None, None, None).unwrap(),
            Settings::default()
        );
        assert_eq!(
            Settings::from_values(Some("leave"), Some("/etc/x.conf"), Some("/run/x")).unwrap(),
            Settings {
                mode: Mode::Leave,
                conf: "/etc/x.conf".into(),
                run_dir: "/run/x".into()
            }
        );
        assert!(Settings::from_values(Some("bogus"), None, None).is_err());
        assert!(Settings::from_values(None, Some("rel/x"), None).is_err());
        assert!(Settings::from_values(None, None, Some("/etc/../x")).is_err());
        let d = std::env::temp_dir().join(format!("pdhcpcd-run-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(!manager_running(&d));
        std::fs::write(d.join("sock"), "").unwrap();
        assert!(manager_running(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_block_is_atomic_idempotent_and_skips_a_missing_file() {
        let d = std::env::temp_dir().join(format!("pdhcpcd-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("dhcpcd.conf");
        assert!(!write_block(&f, &v(&["eth0"])).unwrap(), "missing file");
        std::fs::write(&f, INSTALLER).unwrap();
        assert!(write_block(&f, &v(&["eth0"])).unwrap());
        assert!(!write_block(&f, &v(&["eth0"])).unwrap());
        assert_eq!(denied(&std::fs::read_to_string(&f).unwrap()), v(&["eth0"]));
        assert!(write_block(&f, &[]).unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), INSTALLER);
        let _ = std::fs::remove_dir_all(&d);
    }
}
