//! The init-managed services the web UI may show and control (lane H):
//! which ones, whether they are installed, and start/stop/restart through
//! systemd or OpenRC. `patronus applyd` runs [`control`] as root for the
//! unprivileged web UI (op `service`), so service control works in the
//! normal setup, not only when patronus-web itself runs as root.

use patronus_core::service::{InitSystem, ServiceManager};
use patronus_core::{Error, Result};
use std::path::Path;

/// Daemons Patronus starts or relies on. Only those actually installed on
/// the box (unit file / init script present) are listed or controllable.
pub const KNOWN_SERVICES: &[(&str, &str)] = &[
    ("patronus-firewall", "Boot-time `patronus apply`"),
    ("patronus-web", "Web interface"),
    ("patronus-applyd", "Root apply broker for the web interface"),
    ("patronus-dashboard", "SD-WAN dashboard"),
    ("kea-dhcp4", "DHCPv4 server"),
    ("kea-dhcp6", "DHCPv6 server"),
    ("dnsmasq", "DHCP / DNS forwarder / RA / relay"),
    ("unbound", "DNS resolver"),
    ("radvd", "IPv6 router advertisements"),
    ("chronyd", "NTP"),
    ("keepalived", "VRRP high availability"),
    ("conntrackd", "Connection-state sync"),
    ("ipsec", "IPsec (strongSwan, Gentoo OpenRC)"),
    ("strongswan", "IPsec (strongSwan charon)"),
    (
        "strongswan-swanctl",
        "IPsec (strongSwan charon, swanctl unit)",
    ),
    ("sshd", "SSH"),
];

/// Services the web UI may only restart: stopping them would cut the UI
/// off from the box (web, its broker) or is not what "stop" means for a
/// one-shot boot apply (patronus-firewall: restart = re-apply everything).
pub const RESTART_ONLY: &[&str] = &["patronus-web", "patronus-applyd", "patronus-firewall"];

const SYSTEMD_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// The [`KNOWN_SERVICES`] installed under `init`.
pub fn installed(init: InitSystem) -> Vec<(&'static str, &'static str)> {
    installed_under(init, Path::new("/"))
}

/// [`installed`] with the filesystem rooted at `root` (tests).
pub fn installed_under(init: InitSystem, root: &Path) -> Vec<(&'static str, &'static str)> {
    let p = |abs: String| root.join(abs.trim_start_matches('/'));
    KNOWN_SERVICES
        .iter()
        .copied()
        .filter(|(name, _)| match init {
            InitSystem::Systemd => SYSTEMD_UNIT_DIRS
                .iter()
                .any(|d| p(format!("{d}/{name}.service")).exists()),
            InitSystem::OpenRC | InitSystem::SysVInit => p(format!("/etc/init.d/{name}")).exists(),
            InitSystem::Unknown => false,
        })
        .collect()
}

/// Why a control request is refused before the init system is asked.
pub fn check(name: &str, action: &str, installed: &[(&str, &str)]) -> Result<()> {
    if !installed.iter().any(|(n, _)| *n == name) {
        return Err(Error::Service(format!(
            "{name} is not a Patronus-managed service installed on this system"
        )));
    }
    match action {
        "restart" => Ok(()),
        "start" | "stop" if RESTART_ONLY.contains(&name) => Err(Error::Service(format!(
            "{name} can only be restarted from the web interface (stopping it would cut the \
             interface off)"
        ))),
        "start" | "stop" => Ok(()),
        other => Err(Error::Service(format!("unknown action {other:?}"))),
    }
}

/// start / stop / restart `name` through systemd or OpenRC (as the caller:
/// root in `patronus applyd`).
pub fn control(name: &str, action: &str) -> Result<()> {
    let mgr = ServiceManager::new();
    check(name, action, &installed(mgr.init_system()))?;
    match action {
        "start" => mgr.start(name),
        "stop" => mgr.stop(name),
        _ => mgr.restart(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_installed_known_services_and_safe_actions_pass() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/init.d")).unwrap();
        for s in ["unbound", "patronus-web", "random-daemon"] {
            std::fs::write(d.path().join("etc/init.d").join(s), "").unwrap();
        }
        let inst = installed_under(InitSystem::OpenRC, d.path());
        let names: Vec<&str> = inst.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["patronus-web", "unbound"]);
        assert!(installed_under(InitSystem::Systemd, d.path()).is_empty());
        assert!(installed_under(InitSystem::Unknown, d.path()).is_empty());

        assert!(check("unbound", "stop", &inst).is_ok());
        assert!(check("unbound", "start", &inst).is_ok());
        assert!(check("unbound", "restart", &inst).is_ok());
        let e = check("random-daemon", "stop", &inst)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a Patronus-managed service"), "{e}");
        let e = check("chronyd", "start", &inst).unwrap_err().to_string();
        assert!(e.contains("not a Patronus-managed"), "not installed: {e}");
        let e = check("patronus-web", "stop", &inst)
            .unwrap_err()
            .to_string();
        assert!(e.contains("only be restarted"), "{e}");
        assert!(check("patronus-web", "restart", &inst).is_ok());
        assert!(check("unbound", "reload; rm -rf /", &inst).is_err());
    }
}
