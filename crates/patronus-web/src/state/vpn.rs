//! VPN state, read live from the kernel / daemons. Nothing here is stored
//! or invented: WireGuard peers come from `wg show all dump`, IPsec SAs
//! from `swanctl --list-sas`. Managing tunnels (store + applier, keys,
//! client configs) is lane F; until it lands the write endpoints answer
//! 501 instead of pretending.
//!
//! This file used to hold fixtures (three "Active" WireGuard peers with
//! made-up keys, an "Established" IPsec tunnel to 203.0.113.100, client
//! configs with placeholder private keys and a made-up server endpoint),
//! which also made the dashboard report 4 VPN connections on every box.

use patronus_config::{Applier, ConfigStore};
use std::process::Command;
use std::sync::Arc;

/// A peer counts as connected when its last handshake is this recent:
/// WireGuard re-handshakes every 2 minutes while traffic flows
/// (REKEY_AFTER_TIME 120 s) and gives a session up after 180 s.
pub const WG_CONNECTED_SECS: u64 = 180;

/// Live VPN state. Each `*_error` says why that part could not be read
/// (tool missing, permission denied); the lists are then empty.
#[derive(Debug, Clone, Default)]
pub struct VpnSnapshot {
    pub wg_peers: Vec<crate::templates::WireGuardPeer>,
    pub wg_error: Option<String>,
    pub ipsec_tunnels: Vec<crate::templates::IpsecTunnel>,
    pub ipsec_error: Option<String>,
    /// strongSwan is installed but charon is not running: IPsec is not in
    /// use, so there are no SAs. A normal state, not an error.
    pub ipsec_not_running: bool,
}

impl VpnSnapshot {
    /// WireGuard peers with a recent handshake + established IKE SAs.
    pub fn active_connections(&self) -> usize {
        self.wg_peers.iter().filter(|p| p.connected).count()
            + self
                .ipsec_tunnels
                .iter()
                .filter(|t| t.status.eq_ignore_ascii_case("ESTABLISHED"))
                .count()
    }

    /// Real read failures, in display order (WireGuard, IPsec). "Tool not
    /// installed" is not one: then there is no tunnel of that kind to
    /// count. When this is non-empty `active_connections()` is only a
    /// floor -- the dashboard and /api/status must say so.
    pub fn read_errors(&self) -> Vec<String> {
        [&self.wg_error, &self.ipsec_error]
            .into_iter()
            .flatten()
            .filter(|e| !e.contains(NOT_INSTALLED))
            .cloned()
            .collect()
    }
}

/// Reads VPN state from the system. With the IPsec applier (lane F) the
/// SAs are read through it -- i.e. by `patronus applyd` as root when it
/// runs, since charon's VICI socket is root-only.
#[derive(Default)]
pub struct VpnManager {
    ipsec: Option<(Arc<ConfigStore>, Arc<dyn Applier>)>,
}

/// IPsec state from the IPsec applier's status (`installed`, `running`,
/// `sas`, `error`) into the snapshot fields.
pub fn ipsec_from_status(st: &serde_json::Value, s: &mut VpnSnapshot) {
    if st.get("installed").and_then(|v| v.as_bool()) == Some(false) {
        s.ipsec_error = Some("strongSwan (`swanctl`) is not installed".into());
        return;
    }
    if st.get("running").and_then(|v| v.as_bool()) == Some(true) {
        s.ipsec_tunnels =
            parse_swanctl_list_sas(st.get("sas").and_then(|v| v.as_str()).unwrap_or(""));
        return;
    }
    let err = st.get("error").and_then(|v| v.as_str()).unwrap_or("");
    match classify_swanctl_failure(err) {
        SwanctlFailure::NotRunning => s.ipsec_not_running = true,
        SwanctlFailure::NotInstalled => {
            s.ipsec_error = Some("strongSwan (`swanctl`) is not installed".into())
        }
        SwanctlFailure::Error(e) => s.ipsec_error = Some(e),
    }
}

/// What `run` returns when the tool is not installed.
const NOT_INSTALLED: &str = "not installed";

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(format!(
            "`{cmd} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(NOT_INSTALLED.to_string()),
        Err(e) => Err(format!("`{cmd}`: {e}")),
    }
}

/// Why `swanctl --list-sas` produced no SA list.
#[derive(Debug, PartialEq, Eq)]
pub enum SwanctlFailure {
    /// strongSwan is not installed.
    NotInstalled,
    /// strongSwan is installed but charon is not running (no VICI socket,
    /// or a stale one): IPsec is simply not in use. Not an error.
    NotRunning,
    /// A real failure (e.g. permission denied on the VICI socket), with
    /// swanctl's plugin noise and usage text stripped.
    Error(String),
}

fn run_swanctl_list_sas() -> Result<String, SwanctlFailure> {
    match Command::new("swanctl").arg("--list-sas").output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(classify_swanctl_failure(&format!(
            "{}\n{}",
            String::from_utf8_lossy(&o.stderr),
            String::from_utf8_lossy(&o.stdout)
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SwanctlFailure::NotInstalled),
        Err(e) => Err(SwanctlFailure::Error(format!("`swanctl`: {e}"))),
    }
}

/// Classify the output of a failed `swanctl --list-sas`. With charon
/// stopped swanctl prints plugin-load warnings, `connecting to
/// 'unix:///var/run/charon.vici' failed: No such file or directory`
/// (or `Connection refused` for a stale socket), then its whole usage
/// text, and exits 2 -- that is "IPsec not running", not a failure.
pub fn classify_swanctl_failure(output: &str) -> SwanctlFailure {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim)
        .take_while(|l| *l != "usage:" && !(l.starts_with("strongSwan ") && l.contains(" swanctl")))
        .filter(|l| !l.is_empty() && !(l.starts_with("plugin '") && l.contains("failed to load")))
        .collect();
    let not_running = lines.iter().any(|l| {
        l.contains("connecting to")
            && (l.contains("No such file or directory") || l.contains("Connection refused"))
    });
    if not_running {
        SwanctlFailure::NotRunning
    } else if lines.is_empty() {
        SwanctlFailure::Error("`swanctl --list-sas` failed".into())
    } else {
        SwanctlFailure::Error(format!("`swanctl --list-sas` failed: {}", lines.join("; ")))
    }
}

impl VpnManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read IPsec SAs through the IPsec applier (`patronus applyd`).
    pub fn with_ipsec(store: Arc<ConfigStore>, ipsec: Option<Arc<dyn Applier>>) -> Self {
        Self {
            ipsec: ipsec.map(|a| (store, a)),
        }
    }

    /// Read WireGuard and IPsec state now.
    pub async fn snapshot(&self) -> VpnSnapshot {
        let via_applier = self.ipsec.is_some();
        let mut snap = tokio::task::spawn_blocking(move || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut s = VpnSnapshot::default();
            match run("wg", &["show", "all", "dump"]) {
                Ok(out) => s.wg_peers = parse_wg_dump(&out, now),
                Err(e) if e == NOT_INSTALLED => {
                    s.wg_error = Some("wireguard-tools (`wg`) is not installed".into())
                }
                Err(e) => s.wg_error = Some(e),
            }
            if via_applier {
                return s;
            }
            match run_swanctl_list_sas() {
                Ok(out) => s.ipsec_tunnels = parse_swanctl_list_sas(&out),
                Err(SwanctlFailure::NotInstalled) => {
                    s.ipsec_error = Some("strongSwan (`swanctl`) is not installed".into())
                }
                // Installed but unused: a normal state, no SAs to list.
                Err(SwanctlFailure::NotRunning) => s.ipsec_not_running = true,
                Err(SwanctlFailure::Error(e)) => s.ipsec_error = Some(e),
            }
            s
        })
        .await
        .unwrap_or_default();
        if let Some((store, a)) = &self.ipsec {
            match a.status(store).await {
                Ok(st) => ipsec_from_status(&st, &mut snap),
                Err(e) => snap.ipsec_error = Some(format!("cannot read IPsec state: {e}")),
            }
        }
        snap
    }

    pub async fn list_wireguard_peers(
        &self,
    ) -> anyhow::Result<Vec<crate::templates::WireGuardPeer>> {
        let s = self.snapshot().await;
        match s.wg_error {
            Some(e) => Err(anyhow::anyhow!(e)),
            None => Ok(s.wg_peers),
        }
    }

    pub async fn list_ipsec_tunnels(&self) -> anyhow::Result<Vec<crate::templates::IpsecTunnel>> {
        let s = self.snapshot().await;
        match s.ipsec_error {
            Some(e) => Err(anyhow::anyhow!(e)),
            None => Ok(s.ipsec_tunnels),
        }
    }

    /// Connected WireGuard peers + established IPsec SAs (0 when neither
    /// tool is installed: then there is nothing we could have counted).
    pub async fn count_active_connections(&self) -> anyhow::Result<usize> {
        Ok(self.snapshot().await.active_connections())
    }
}

/// "3 min 4 s ago" style age.
pub fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min {} s ago", secs / 60, secs % 60),
        3600..=86_399 => format!("{} h {} min ago", secs / 3600, (secs % 3600) / 60),
        _ => format!("{} d {} h ago", secs / 86_400, (secs % 86_400) / 3600),
    }
}

/// Human-readable byte count (binary units).
pub fn format_bytes(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.2} GiB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.2} MiB", f / (K * K))
    } else if f >= K {
        format!("{:.1} KiB", f / K)
    } else {
        format!("{b} B")
    }
}

/// Parse `wg show all dump`. Interface lines have 5 tab-separated fields
/// (`if privkey pubkey port fwmark`), peer lines 9
/// (`if pubkey psk endpoint allowed-ips handshake rx tx keepalive`).
pub fn parse_wg_dump(out: &str, now_unix: u64) -> Vec<crate::templates::WireGuardPeer> {
    let mut peers: Vec<crate::templates::WireGuardPeer> = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 9 {
            continue;
        }
        let (iface, pubkey, endpoint, allowed, hs, rx, tx) =
            (f[0], f[1], f[3], f[4], f[5], f[6], f[7]);
        let handshake: u64 = hs.parse().unwrap_or(0);
        let age = (handshake > 0).then(|| now_unix.saturating_sub(handshake));
        let connected = matches!(age, Some(a) if a <= WG_CONNECTED_SECS);
        let status = match age {
            None => "No handshake yet".to_string(),
            Some(_) if connected => "Connected".to_string(),
            Some(_) => "Idle".to_string(),
        };
        let n = peers.iter().filter(|p| p.interface == iface).count() + 1;
        peers.push(crate::templates::WireGuardPeer {
            id: peers.len() as u32 + 1,
            name: format!("{iface} peer {n}"),
            interface: iface.to_string(),
            public_key: pubkey.to_string(),
            allowed_ips: if allowed == "(none)" {
                String::new()
            } else {
                allowed.replace(',', ", ")
            },
            endpoint: (endpoint != "(none)").then(|| endpoint.to_string()),
            status,
            connected,
            last_handshake: age.map(format_age),
            handshake_age_secs: age,
            transfer: format!(
                "{} in / {} out",
                format_bytes(rx.parse().unwrap_or(0)),
                format_bytes(tx.parse().unwrap_or(0))
            ),
        });
    }
    peers
}

/// Parse `swanctl --list-sas` (text output). An IKE SA starts at column 0
/// (`name: #1, ESTABLISHED, IKEv2, ...`); its `remote ... @ ADDR[port]` line
/// gives the gateway; CHILD SA traffic selectors are the 4-space-indented
/// `local`/`remote` lines.
pub fn parse_swanctl_list_sas(out: &str) -> Vec<crate::templates::IpsecTunnel> {
    let mut tunnels: Vec<crate::templates::IpsecTunnel> = Vec::new();
    for line in out.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if indent == 0 {
            let Some((name, rest)) = t.split_once(':') else {
                continue;
            };
            let status = rest
                .split(',')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            tunnels.push(crate::templates::IpsecTunnel {
                id: tunnels.len() as u32 + 1,
                name: name.trim().to_string(),
                status,
                local_subnet: String::new(),
                remote_subnet: String::new(),
                remote_gateway: String::new(),
            });
            continue;
        }
        let Some(cur) = tunnels.last_mut() else {
            continue;
        };
        let mut words = t.split_whitespace();
        let key = words.next().unwrap_or("");
        let rest: Vec<&str> = words.collect();
        match (indent, key) {
            (2, "remote") => {
                if let Some(pos) = rest.iter().position(|w| *w == "@") {
                    if let Some(addr) = rest.get(pos + 1) {
                        cur.remote_gateway = addr.split('[').next().unwrap_or(addr).to_string();
                    }
                }
            }
            (i, "local") if i >= 4 => append(&mut cur.local_subnet, &rest.join(" ")),
            (i, "remote") if i >= 4 => append(&mut cur.remote_subnet, &rest.join(" ")),
            _ => {}
        }
    }
    tunnels
}

fn append(dst: &mut String, v: &str) {
    if v.is_empty() {
        return;
    }
    if !dst.is_empty() {
        dst.push_str(", ");
    }
    dst.push_str(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    #[test]
    fn wg_dump_peers_come_from_the_kernel_dump() {
        let dump = format!(
            "wg0\tPRIVKEY=\tSERVERPUB=\t51820\toff\n\
             wg0\tPEERA=\t(none)\t192.0.2.7:51820\t10.99.0.2/32,fd00:99::2/128\t{}\t1024\t2048\t25\n\
             wg0\tPEERB=\t(none)\t(none)\t10.99.0.3/32\t0\t0\t0\toff\n\
             wg1\tPRIVKEY2=\tPUB2=\t51821\toff\n\
             wg1\tPEERC=\tPSK=\t198.51.100.9:4500\t(none)\t{}\t0\t0\toff\n",
            NOW - 30,
            NOW - 600
        );
        let p = parse_wg_dump(&dump, NOW);
        assert_eq!(p.len(), 3, "interface lines are not peers");
        assert_eq!(p[0].public_key, "PEERA=");
        assert_eq!(p[0].interface, "wg0");
        assert_eq!(p[0].name, "wg0 peer 1");
        assert_eq!(p[0].allowed_ips, "10.99.0.2/32, fd00:99::2/128");
        assert_eq!(p[0].endpoint.as_deref(), Some("192.0.2.7:51820"));
        assert!(p[0].connected);
        assert_eq!(p[0].status, "Connected");
        assert_eq!(p[0].last_handshake.as_deref(), Some("30 s ago"));
        assert_eq!(p[0].transfer, "1.0 KiB in / 2.0 KiB out");
        assert_eq!(p[1].name, "wg0 peer 2");
        assert!(!p[1].connected);
        assert_eq!(p[1].status, "No handshake yet");
        assert_eq!(p[1].endpoint, None);
        assert_eq!(p[1].last_handshake, None);
        assert_eq!(p[2].name, "wg1 peer 1");
        assert_eq!(p[2].status, "Idle");
        assert_eq!(p[2].allowed_ips, "");
        let snap = VpnSnapshot {
            wg_peers: p,
            ..Default::default()
        };
        assert_eq!(snap.active_connections(), 1, "only the recent handshake");
    }

    #[test]
    fn no_wireguard_interfaces_means_no_peers() {
        assert!(parse_wg_dump("", NOW).is_empty());
        assert_eq!(VpnSnapshot::default().active_connections(), 0);
    }

    #[test]
    fn read_errors_skip_missing_tools_but_keep_real_failures() {
        let snap = VpnSnapshot {
            wg_error: Some("`wg show all dump` failed: Operation not permitted".into()),
            ipsec_error: Some("strongSwan (`swanctl`) is not installed".into()),
            ..Default::default()
        };
        assert_eq!(
            snap.read_errors(),
            vec!["`wg show all dump` failed: Operation not permitted".to_string()]
        );
        let none = VpnSnapshot {
            wg_error: Some("wireguard-tools (`wg`) is not installed".into()),
            ..Default::default()
        };
        assert!(none.read_errors().is_empty());
    }

    #[test]
    fn swanctl_with_charon_stopped_is_not_running_not_an_error() {
        // Real output of `swanctl --list-sas` (strongSwan 5.9.8) with charon
        // stopped: exit 2, VICI connect error, then the usage text.
        let out = "\
plugin 'ldap': failed to load - ldap_plugin_create not found and no plugin file available
plugin 'curl': failed to load - curl_plugin_create not found and no plugin file available
connecting to 'unix:///var/run/charon.vici' failed: No such file or directory
Error: connecting to 'default' URI failed: No such file or directory
strongSwan 5.9.8 swanctl
usage:
  swanctl --list-sas [--ike <name>|--ike-id <id>] [--child <name>|--child-id <id>]
           --help            (-h)  show usage information
";
        assert_eq!(classify_swanctl_failure(out), SwanctlFailure::NotRunning);
        // strongSwan 6.0.7 (Gentoo): different socket path and usage header.
        let v6 = "\
connecting to 'unix:///run/charon.vici' failed: No such file or directory
strongSwan 6.0.7 swanctl (--list-sas/-l)
list currently active IKE_SAs
usage:
  swanctl --list-sas [--ike <name>|--ike-id <id>] [--child <name>|--child-id <id>]
";
        assert_eq!(classify_swanctl_failure(v6), SwanctlFailure::NotRunning);
        let stale = "connecting to 'unix:///var/run/charon.vici' failed: Connection refused\n\
                     Error: connecting to 'default' URI failed: Connection refused\n";
        assert_eq!(classify_swanctl_failure(stale), SwanctlFailure::NotRunning);

        // A real failure stays an error, without the usage text.
        let denied = "connecting to 'unix:///var/run/charon.vici' failed: Permission denied\n\
                      Error: connecting to 'default' URI failed: Permission denied\n\
                      strongSwan 5.9.8 swanctl\nusage:\n  swanctl --list-sas\n";
        match classify_swanctl_failure(denied) {
            SwanctlFailure::Error(e) => {
                assert!(e.contains("Permission denied"), "{e}");
                assert!(!e.contains("usage"), "{e}");
                assert!(!e.contains("--help"), "{e}");
            }
            other => panic!("{other:?}"),
        }

        // Not running: no error anywhere (VPN page, /api/status, dashboard).
        let snap = VpnSnapshot {
            ipsec_not_running: true,
            ..Default::default()
        };
        assert!(snap.read_errors().is_empty());
        assert_eq!(snap.active_connections(), 0);
    }

    #[test]
    fn ages_are_rendered_from_real_seconds() {
        assert_eq!(format_age(0), "0 s ago");
        assert_eq!(format_age(61), "1 min 1 s ago");
        assert_eq!(format_age(3600 * 2 + 60 * 5), "2 h 5 min ago");
        assert_eq!(format_age(86_400 * 3 + 3600), "3 d 1 h ago");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.00 MiB");
    }

    #[test]
    fn swanctl_sas_are_parsed_with_gateway_and_selectors() {
        let out = "\
gw-gw: #1, ESTABLISHED, IKEv2, 5f1b9a46b2e9c0f8_i* 4a3e2a1b5b0b2a4d_r
  local  'moon.strongswan.org' @ 192.168.0.1[4500]
  remote 'sun.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
  established 2s ago, rekeying in 14130s
  net-net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128
    installed 2s ago, rekeying in 3368s, expires in 3958s
    in  c4a3e1b5,      0 bytes,     0 packets
    out c8f0e1f3,      0 bytes,     0 packets
    local  10.1.0.0/16
    remote 10.2.0.0/16
road: #2, CONNECTING, IKEv2, 1111_i 0000_r
  local  '%any' @ 192.168.0.1[500]
  remote '%any' @ 203.0.113.9[500]
";
        let t = parse_swanctl_list_sas(out);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].name, "gw-gw");
        assert_eq!(t[0].status, "ESTABLISHED");
        assert_eq!(t[0].remote_gateway, "192.168.0.2");
        assert_eq!(t[0].local_subnet, "10.1.0.0/16");
        assert_eq!(t[0].remote_subnet, "10.2.0.0/16");
        assert_eq!(t[1].status, "CONNECTING");
        assert_eq!(t[1].remote_gateway, "203.0.113.9");
        let snap = VpnSnapshot {
            ipsec_tunnels: t,
            ..Default::default()
        };
        assert_eq!(snap.active_connections(), 1);
        assert!(parse_swanctl_list_sas("").is_empty());
    }
}
