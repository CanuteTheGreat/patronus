//! DHCP client for interfaces in `dhcp` (IPv4) / `dhcp6` (IPv6) mode.
//!
//! Two backends, chosen at build time by the Gentoo `dhcpcd` USE flag
//! (cargo feature `dhcpcd`: prefer net-misc/dhcpcd; without it prefer
//! busybox `udhcpc`), overridable at runtime with the `dhcp_client`
//! system_config key (`dhcpcd` / `udhcpc`). If the preferred client is not
//! installed the other one is used with a warning. DHCPv6 needs dhcpcd.
//!
//! The daemon runs per interface through [`crate::supervise`]; its config
//! (dhcpcd.conf / the udhcpc event script) is generated under the net state
//! dir. udhcpc's script installs addresses with the lease lifetime, so the
//! kernel marks them `dynamic` and the interfaces applier never mistakes
//! them for stale static addresses.

use crate::supervise::{which, DaemonSpec, NetPaths};
use patronus_core::{Error, Result};
use std::path::PathBuf;

pub const SERVICE: &str = "patronus-dhcpc";

/// Store key overriding the build-time preference.
pub const CLIENT_KEY: &str = "dhcp_client";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Dhcpcd,
    Udhcpc,
}

impl Client {
    pub fn as_str(&self) -> &'static str {
        match self {
            Client::Dhcpcd => "dhcpcd",
            Client::Udhcpc => "udhcpc",
        }
    }

    /// Build-time default (USE=dhcpcd).
    pub fn preferred() -> Self {
        if cfg!(feature = "dhcpcd") {
            Client::Dhcpcd
        } else {
            Client::Udhcpc
        }
    }

    /// argv prefix to run this client, if installed.
    pub fn locate(&self) -> Option<Vec<String>> {
        match self {
            Client::Dhcpcd => which("dhcpcd").map(|p| vec![p.to_string_lossy().into()]),
            Client::Udhcpc => which("udhcpc")
                .map(|p| vec![p.to_string_lossy().into()])
                .or_else(|| {
                    which("busybox").map(|p| vec![p.to_string_lossy().into(), "udhcpc".into()])
                }),
        }
    }
}

/// Pick the client: override > build preference > whatever is installed.
pub fn choose(
    override_: Option<&str>,
    need_v6: bool,
) -> Result<(Client, Vec<String>, Option<String>)> {
    let first = match override_.map(str::trim) {
        Some("dhcpcd") => Client::Dhcpcd,
        Some("udhcpc") => Client::Udhcpc,
        Some("") | None => Client::preferred(),
        Some(o) => {
            return Err(Error::Config(format!(
                "Invalid dhcp_client {o:?} (dhcpcd or udhcpc)"
            )))
        }
    };
    let second = if first == Client::Dhcpcd {
        Client::Udhcpc
    } else {
        Client::Dhcpcd
    };
    let order: Vec<Client> = if need_v6 {
        vec![Client::Dhcpcd]
    } else {
        vec![first, second]
    };
    for (i, c) in order.iter().enumerate() {
        if let Some(argv) = c.locate() {
            let warn = (i > 0).then(|| {
                format!(
                    "{} is not installed; using {} as the DHCP client",
                    first.as_str(),
                    c.as_str()
                )
            });
            return Ok((*c, argv, warn));
        }
    }
    Err(Error::Network(if need_v6 {
        "DHCPv6 needs dhcpcd (net-misc/dhcpcd, USE=dhcpcd), which is not installed".into()
    } else {
        "no DHCP client installed (net-misc/dhcpcd or busybox udhcpc)".into()
    }))
}

/// Route metric for the default route a DHCP lease installs.
pub fn metric_for_role(role: Option<&str>) -> u32 {
    match role {
        Some("wan") => 100,
        Some(r) if r.starts_with("opt") => 200 + r[3..].parse::<u32>().unwrap_or(0).min(99),
        Some("lan") => 300,
        _ => 400,
    }
}

/// The metric of `dev`'s DHCP default route: the interface's own `metric` when
/// set, else the role's default.
pub fn metric_for(role: Option<&str>, own: Option<u32>) -> u32 {
    own.unwrap_or_else(|| metric_for_role(role))
}

/// busybox udhcpc event script for one interface.
///
/// `system_resolv` (the WAN lease): the lease's DNS servers also become the
/// router's own resolver config, through `resolvconf` when installed, else
/// written to `/etc/resolv.conf` (what dhcpcd's stock resolv.conf hook does
/// for the dhcpcd backend). Without it the embedded tier (udhcpc) never had a
/// working resolver, and the dnsmasq forwarder, which reads resolv.conf, had
/// no upstreams.
///
/// The default route is installed with `proto dhcp`; a busybox `ip` applet
/// (no rt_protos names) rejects that, so the script retries without the
/// protocol instead of silently leaving the router without a default route
/// (seen on a GL-AR750S, 2026-11-13).
pub fn udhcpc_script(dev: &str, metric: u32, dns_file: &str, system_resolv: bool) -> String {
    let resolv = if system_resolv {
        format!(
            r#"    if [ -s "{dns_file}" ]; then
      if command -v resolvconf >/dev/null 2>&1; then
        resolvconf -a "$dev.udhcpc" < "{dns_file}"
      else
        cat "{dns_file}" > /etc/resolv.conf
      fi
    fi
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"#!/bin/sh
# Generated by Patronus for {dev}: udhcpc event script. Do not edit;
# configure the interface in the web UI (Interfaces) instead.
# Addresses are added with the lease lifetime so they show up as dynamic.
dev="$interface"
case "$1" in
  deconfig)
    ip -4 addr flush dev "$dev" scope global
    ip link set dev "$dev" up
    ;;
  bound|renew)
    want="$ip/${{mask:-32}}"
    for a in $(ip -4 -o addr show dev "$dev" scope global | awk '{{print $4}}'); do
      [ "$a" = "$want" ] || ip addr del "$a" dev "$dev"
    done
    life="${{lease:-forever}}"
    ip addr replace "$want" dev "$dev" valid_lft "$life" preferred_lft "$life" ${{broadcast:+broadcast $broadcast}}
    if [ -n "$router" ]; then
      set -- $router
      ip route replace default via "$1" dev "$dev" metric {metric} proto dhcp 2>/dev/null \
        || ip route replace default via "$1" dev "$dev" metric {metric}
    fi
    : > "{dns_file}.tmp"
    for s in $dns; do echo "nameserver $s" >> "{dns_file}.tmp"; done
    [ -n "$domain" ] && echo "search $domain" >> "{dns_file}.tmp"
    mv "{dns_file}.tmp" "{dns_file}"
{resolv}    ;;
  leasefail|nak)
    ;;
esac
exit 0
"#
    )
}

/// Where dhcpcd keeps the DUID it presents (its `duid` file in the database
/// directory); the first existing directory wins, Gentoo/Debian default last.
pub const DHCPCD_DBDIRS: &[&str] = &["/var/lib/dhcpcd", "/var/db/dhcpcd", "/var/lib/dhcpcd5"];

/// Path of dhcpcd's `duid` file on this box.
pub fn duid_file() -> PathBuf {
    let dir = DHCPCD_DBDIRS
        .iter()
        .find(|d| std::path::Path::new(d).is_dir())
        .unwrap_or(&DHCPCD_DBDIRS[0]);
    PathBuf::from(dir).join("duid")
}

/// dhcpcd.conf for one interface.
/// `iaid`: the DHCPv6 IAID of IA_NA and IA_PD (`None` = IA_NA from the MAC
/// address, IA_PD [`crate::netconf::DEFAULT_PD_IAID`]).
pub fn dhcpcd_conf(
    dev: &str,
    v4: bool,
    v6: bool,
    metric: u32,
    pd: &[String],
    iaid: Option<u32>,
) -> String {
    let mut c = format!(
        "# Generated by Patronus for {dev}; do not edit (Interfaces page).\n\
         hostname\nclientid\npersistent\noption rapid_commit\n\
         option domain_name_servers, domain_name, domain_search, host_name\n\
         option interface_mtu\nrequire dhcp_server_identifier\nnoipv4ll\n\
         metric {metric}\n"
    );
    match (v4, v6) {
        (true, false) => c.push_str("ipv4only\n"),
        (false, true) => c.push_str("ipv6only\n"),
        _ => {}
    }
    if v6 {
        // the ISP keys its binding on DUID + IAID: a pinned IAID (the replaced
        // router's) gets the same address and delegated prefix back at once
        match iaid {
            Some(n) => c.push_str(&format!("ipv6rs\nia_na {n}\n")),
            None => c.push_str("ipv6rs\nia_na\n"),
        }
        if !pd.is_empty() {
            // delegated prefix: one /64 slice per downstream interface
            // (dhcpcd assigns it there; radvd advertises it)
            let n = iaid.unwrap_or(crate::netconf::DEFAULT_PD_IAID);
            c.push_str(&format!("ia_pd {n}"));
            for (n, d) in pd.iter().enumerate() {
                c.push_str(&format!(" {d}/{n}/64"));
            }
            c.push('\n');
        }
    }
    c
}

/// dhcpcd `script`: run dhcpcd's stock hooks, then tell radvd that the
/// delegated prefix changed (it advertises `::/64` = whatever /64 the
/// downstream interface carries).
pub fn pd_hook_script() -> String {
    "#!/bin/sh\n# Generated by Patronus (DHCPv6 prefix delegation).\n\
     for h in /usr/lib/dhcpcd/dhcpcd-run-hooks /usr/lib/dhcpcd5/dhcpcd-run-hooks /usr/libexec/dhcpcd-run-hooks /lib/dhcpcd/dhcpcd-run-hooks; do\n\
     \x20 [ -x \"$h\" ] && { \"$h\"; break; }\n\
     done\n\
     case \"$reason\" in\n\
     \x20 BOUND6|RENEW6|REBIND6|DELEGATED6) pkill -HUP -x radvd 2>/dev/null ;;\n\
     esac\n\
     exit 0\n"
        .to_string()
}

/// Ask the DHCP client that serves `dev` for a renew, so it runs its bound/renew handling again and puts the
/// lease's default route back. Needed when the device went administratively down and up while the lease stayed
/// (the kernel drops every route of a device that goes down; wpa_supplicant takes its device down when it
/// restarts): busybox udhcpc never notices that by itself. udhcpc gets SIGUSR1 (renew), dhcpcd `-n` (rebind).
pub async fn renew(dev: &str) -> Result<String> {
    // `dhcpcd -n DEV` STARTS a new dhcpcd (a manager) when no dhcpcd serves DEV yet: only ask a running one
    let dhcpcd = which("dhcpcd").filter(|_| dhcpcd_serves(&DHCPCD_RUN_DIRS, dev));
    renew_in(std::path::Path::new("/proc"), dev, dhcpcd).await
}

/// Where dhcpcd keeps its pid files (`<dev>.pid` per-interface instance, `pid` for a manager); build-time choice.
const DHCPCD_RUN_DIRS: [&str; 2] = ["/run/dhcpcd", "/var/run/dhcpcd"];

/// Does a running dhcpcd (a per-interface instance for `dev`, or a manager) answer `dhcpcd -n dev`?
pub fn dhcpcd_serves(run_dirs: &[&str], dev: &str) -> bool {
    run_dirs.iter().any(|d| {
        [format!("{dev}.pid"), "pid".to_string()].iter().any(|f| {
            std::fs::read_to_string(std::path::Path::new(d).join(f))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .is_some_and(|pid| {
                    pid > 0 && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
                })
        })
    })
}

/// [`renew`] against another /proc (tests).
pub async fn renew_in(
    proc_dir: &std::path::Path,
    dev: &str,
    dhcpcd: Option<PathBuf>,
) -> Result<String> {
    let mut hit = Vec::new();
    if let Ok(rd) = std::fs::read_dir(proc_dir) {
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let d = e.path();
            if std::fs::read_to_string(d.join("comm"))
                .unwrap_or_default()
                .trim()
                != "udhcpc"
            {
                continue;
            }
            let cmd = std::fs::read(d.join("cmdline")).unwrap_or_default();
            let args: Vec<&[u8]> = cmd.split(|b| *b == 0).collect();
            if args
                .windows(2)
                .any(|w| w[0] == b"-i" && w[1] == dev.as_bytes())
            {
                hit.push(pid);
            }
        }
    }
    if !hit.is_empty() {
        for pid in &hit {
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(*pid),
                nix::sys::signal::Signal::SIGUSR1,
            )
            .map_err(|e| Error::Network(format!("udhcpc {pid}: {e}")))?;
        }
        return Ok(format!("asked udhcpc (pid {hit:?}) to renew its lease"));
    }
    if let Some(bin) = dhcpcd {
        let out = tokio::process::Command::new(&bin)
            .args(["-n", dev])
            .output()
            .await
            .map_err(|e| Error::Network(format!("dhcpcd -n {dev}: {e}")))?;
        return if out.status.success() {
            Ok("asked dhcpcd to rebind".to_string())
        } else {
            Err(Error::Network(format!(
                "dhcpcd -n {dev}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        };
    }
    Err(Error::Network(format!("no DHCP client runs for {dev}")))
}

/// The daemon spec for `dev`.
#[allow(clippy::too_many_arguments)]
pub fn spec(
    dev: &str,
    v4: bool,
    v6: bool,
    role: Option<&str>,
    own_metric: Option<u32>,
    client: Client,
    argv_prefix: &[String],
    paths: &NetPaths,
    pd: &[String],
    duid: Option<&str>,
    iaid: Option<u32>,
) -> Result<DaemonSpec> {
    let metric = metric_for(role, own_metric);
    let dir = paths.state_dir.join("dhcp");
    let mut argv: Vec<String> = argv_prefix.to_vec();
    let mut files = Vec::new();
    match client {
        Client::Udhcpc => {
            if v6 {
                return Err(Error::Network("DHCPv6 needs dhcpcd".into()));
            }
            let script = dir.join(format!("udhcpc-{dev}.sh"));
            let dns = dir.join(format!("{dev}.resolv"));
            files.push((
                script.clone(),
                udhcpc_script(dev, metric, &dns.to_string_lossy(), role == Some("wan")),
                0o755,
            ));
            argv.extend(
                [
                    "-f",
                    "-i",
                    dev,
                    "-s",
                    &script.to_string_lossy(),
                    "-R",
                    "-t",
                    "5",
                    "-T",
                    "3",
                    "-A",
                    "10",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
        Client::Dhcpcd => {
            let conf: PathBuf = dir.join(format!("dhcpcd-{dev}.conf"));
            let mut text = dhcpcd_conf(dev, v4, v6, metric, pd, iaid);
            let mut hook_file = None;
            if v6 && !pd.is_empty() {
                // after dhcpcd's own hooks, make radvd re-read the prefix
                let hook = dir.join(format!("pd-hook-{dev}.sh"));
                text.push_str(&format!("script {}\n", hook.display()));
                hook_file = Some((hook, pd_hook_script(), 0o755));
            }
            files.push((conf.clone(), text, 0o644));
            files.extend(hook_file);
            // a pinned DUID: dhcpcd reads its duid file at start, so the file
            // is in place before the daemon is (re)started
            if let (true, Some(d)) = (v6, duid) {
                files.push((duid_file(), format!("{d}\n"), 0o644));
            }
            argv.extend(
                ["-B", "-f", &conf.to_string_lossy(), dev]
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
    }
    Ok(DaemonSpec {
        service: SERVICE,
        instance: dev.to_string(),
        argv,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn renew_finds_the_udhcpc_of_the_device_only() {
        let d = tempfile::tempdir().unwrap();
        // our own pid stands in for "a udhcpc of another device" (it must not be signalled), a missing pid for
        // the one of the device: the signal then fails, which proves it was picked
        let mk = |pid: &str, comm: &str, args: &[&str]| {
            let p = d.path().join(pid);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("comm"), format!("{comm}\n")).unwrap();
            std::fs::write(p.join("cmdline"), args.join("\0")).unwrap();
        };
        mk(
            &std::process::id().to_string(),
            "udhcpc",
            &["udhcpc", "-f", "-i", "eth1"],
        );
        mk(
            "2147483000",
            "udhcpc",
            &["udhcpc", "-f", "-i", "wlan0", "-s", "x"],
        );
        mk("12", "bash", &["bash", "-i", "wlan0"]);
        let e = renew_in(d.path(), "wlan0", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("udhcpc 2147483000"), "{e}");
        // nobody serves wlan5 and there is no dhcpcd: said so
        let e = renew_in(d.path(), "wlan5", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no DHCP client runs for wlan5"), "{e}");
    }

    #[test]
    fn dhcpcd_is_asked_only_when_one_serves_the_device() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_str().unwrap().to_string();
        let dirs = [dir.as_str()];
        assert!(!dhcpcd_serves(&dirs, "wan0"), "no pid file");
        std::fs::write(d.path().join("wan0.pid"), "2147483000\n").unwrap();
        assert!(!dhcpcd_serves(&dirs, "wan0"), "stale pid");
        std::fs::write(
            d.path().join("wan0.pid"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        assert!(dhcpcd_serves(&dirs, "wan0"), "per-interface instance");
        assert!(!dhcpcd_serves(&dirs, "wan1"));
        std::fs::write(d.path().join("pid"), format!("{}\n", std::process::id())).unwrap();
        assert!(dhcpcd_serves(&dirs, "wan1"), "a manager serves every port");
    }

    #[test]
    fn specs_and_scripts() {
        let p = NetPaths::under(std::path::Path::new("/x"));
        let s = spec(
            "eth0",
            true,
            false,
            Some("wan"),
            None,
            Client::Udhcpc,
            &["udhcpc".into()],
            &p,
            &[],
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.argv[..5], ["udhcpc", "-f", "-i", "eth0", "-s"]);
        assert!(s.files[0].1.contains("metric 100 proto dhcp"));
        assert!(s.files[0].1.contains("valid_lft"));
        // the WAN lease feeds the router's own resolver, and a busybox ip that
        // rejects `proto dhcp` still gets the default route
        let w = &s.files[0].1;
        assert!(
            w.contains("cat \"/x/net/dhcp/eth0.resolv\" > /etc/resolv.conf"),
            "{w}"
        );
        assert!(w.contains("resolvconf -a \"$dev.udhcpc\""));
        assert!(w.contains(
            "proto dhcp 2>/dev/null \\\n        || ip route replace default via \"$1\" dev \"$dev\" metric 100\n"
        ));
        let lan = spec(
            "eth1",
            true,
            false,
            Some("lan"),
            None,
            Client::Udhcpc,
            &["udhcpc".into()],
            &p,
            &[],
            None,
            None,
        )
        .unwrap();
        assert!(!lan.files[0].1.contains("resolv.conf"));
        assert!(lan.files[0].1.contains("metric 300"));
        assert!(spec(
            "eth0",
            true,
            true,
            None,
            None,
            Client::Udhcpc,
            &["udhcpc".into()],
            &p,
            &[],
            None,
            None
        )
        .is_err());
        let d = spec(
            "eth0",
            false,
            true,
            Some("opt2"),
            None,
            Client::Dhcpcd,
            &["dhcpcd".into()],
            &p,
            &["lan0".into(), "opt1".into()],
            Some("00:04:aa:bb"),
            None,
        )
        .unwrap();
        assert!(d.files[0].1.contains("ia_pd 1 lan0/0/64 opt1/1/64\n"));
        // the pinned DUID lands in dhcpcd's duid file, newline terminated
        let duid = d.files.iter().find(|f| f.0.ends_with("duid")).unwrap();
        assert_eq!(duid.1, "00:04:aa:bb\n");
        assert_eq!(d.argv.last().unwrap(), "eth0");
        assert!(d.files[0].1.contains("ipv6only\nipv6rs\nia_na"));
        assert!(d.files[0].1.contains("metric 202"));
        // a pinned IAID (the replaced router's) is used for IA_NA and IA_PD
        let c = dhcpcd_conf("eth0", true, true, 100, &["lan0".into()], Some(305419896));
        assert!(
            c.contains("ia_na 305419896\nia_pd 305419896 lan0/0/64\n"),
            "{c}"
        );
        let c = dhcpcd_conf("eth0", true, true, 100, &[], Some(7));
        assert!(c.contains("ia_na 7\n") && !c.contains("ia_pd"), "{c}");
        // an interface's own metric beats the role's default (5 GHz uplink ahead of the 2.4 GHz one)
        let own = spec(
            "wl24-sta",
            true,
            false,
            Some("wan"),
            Some(150),
            Client::Udhcpc,
            &["udhcpc".into()],
            &p,
            &[],
            None,
            None,
        )
        .unwrap();
        assert!(own.files[0].1.contains("metric 150 proto dhcp"));
        assert!(!own.files[0].1.contains("metric 100"));
        assert_eq!(metric_for(Some("wan"), None), 100);
        assert_eq!(metric_for(Some("wan"), Some(7)), 7);
        assert!(choose(Some("bogus"), false)
            .unwrap_err()
            .to_string()
            .contains("Invalid"));
    }
}
