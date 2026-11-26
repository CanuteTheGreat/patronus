//! Live facts for the security overview (`patronus-web` `security.rs`,
//! docs/SECURITY-OVERVIEW.md), read as root: `patronus applyd` op `system`,
//! action `posture_facts` (in-process when the caller is root).
//!
//! Everything here is what the running system does, not what the store says:
//! the sockets that are listening and which process owns them, the effective
//! sshd configuration of the RUNNING sshd (`sshd -T` with that process's own
//! arguments), Dropbear's flags, the kernel's WireGuard peers (preshared key
//! set? last handshake), the proposals strongSwan loaded and the algorithms of
//! the SAs that are up, the tls-crypt state of every running OpenVPN, whether
//! Suricata and a validating Unbound run, the main nftables table (terse: no
//! set contents) and the memory size. Parsers are pure functions with tests;
//! `facts` only collects.

use patronus_core::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// One listening socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listener {
    /// `tcp` or `udp`.
    pub proto: String,
    /// Local address (`0.0.0.0`, `::`, `192.168.1.1`, ...).
    pub addr: String,
    pub port: u16,
    pub inode: u64,
    /// Process name (`/proc/<pid>/comm`), empty when unknown.
    pub process: String,
    pub pid: Option<u32>,
}

fn hex_ip(h: &str) -> Option<String> {
    let b = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    match b.len() {
        4 => Some(std::net::Ipv4Addr::new(b[3], b[2], b[1], b[0]).to_string()),
        16 => {
            // four little-endian 32-bit words
            let mut o = [0u8; 16];
            for w in 0..4 {
                for i in 0..4 {
                    o[w * 4 + i] = b[w * 4 + 3 - i];
                }
            }
            let a = std::net::Ipv6Addr::from(o);
            Some(match a.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => a.to_string(),
            })
        }
        _ => None,
    }
}

/// Parse `/proc/net/{tcp,tcp6,udp,udp6}`: TCP sockets in LISTEN (0A), UDP
/// sockets that are bound and not connected (07).
pub fn parse_proc_net(text: &str, proto: &str) -> Vec<Listener> {
    let want = if proto == "tcp" { "0A" } else { "07" };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || f[3] != want {
                return None;
            }
            let (a, p) = f[1].split_once(':')?;
            // a connected UDP socket has a remote port
            if proto == "udp" && !f[2].ends_with(":0000") {
                return None;
            }
            Some(Listener {
                proto: proto.into(),
                addr: hex_ip(a)?,
                port: u16::from_str_radix(p, 16).ok()?,
                inode: f[9].parse().ok()?,
                process: String::new(),
                pid: None,
            })
        })
        .collect()
}

/// Effective `sshd -T` output: lower-case key -> values (repeated keys such as
/// `port` and `listenaddress` collect every value).
pub fn parse_sshd_t(text: &str) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for l in text.lines() {
        if let Some((k, v)) = l.trim().split_once(' ') {
            m.entry(k.to_ascii_lowercase())
                .or_default()
                .push(v.trim().to_string());
        }
    }
    m
}

/// The arguments of a running sshd that change its effective configuration
/// (`-f FILE`, `-o OPT`, `-p PORT`, `-h KEY`), for `sshd -T`.
pub fn sshd_config_args(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        let takes = matches!(a.as_str(), "-f" | "-o" | "-p" | "-h" | "-c");
        if takes && i + 1 < argv.len() {
            out.push(a.clone());
            out.push(argv[i + 1].clone());
            i += 2;
            continue;
        }
        for flag in ["-f", "-o", "-p", "-h", "-c"] {
            if let Some(rest) = a.strip_prefix(flag) {
                if !rest.is_empty() && a.len() > 2 {
                    out.push(flag.to_string());
                    out.push(rest.to_string());
                }
            }
        }
        i += 1;
    }
    out
}

/// What a running Dropbear allows, from its flags.
pub fn dropbear_flags(argv: &[String]) -> Value {
    let has = |f: &str| argv.iter().skip(1).any(|a| a == f);
    let mut ports: Vec<String> = Vec::new();
    for w in argv.windows(2) {
        if w[0] == "-p" {
            ports.push(w[1].clone());
        }
    }
    json!({
        "password_auth": !has("-s"),
        "root_password": !(has("-s") || has("-g") || has("-w")),
        "root_login": !has("-w"),
        "ports": ports,
    })
}

/// One WireGuard peer as the kernel has it (`wg show all dump`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WgPeer {
    pub interface: String,
    pub public_key: String,
    pub preshared_key: bool,
    pub endpoint: String,
    /// Unix time of the last handshake, 0 = none since the interface came up.
    pub latest_handshake: i64,
}

pub fn parse_wg_dump(text: &str) -> Vec<WgPeer> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 9 {
                return None;
            }
            Some(WgPeer {
                interface: f[0].into(),
                public_key: f[1].into(),
                preshared_key: f[2] != "(none)" && !f[2].is_empty(),
                endpoint: f[3].into(),
                latest_handshake: f[5].parse().unwrap_or(0),
            })
        })
        .collect()
}

/// `proposals` / `esp_proposals` / `ah_proposals` lines of swanctl files,
/// with the block path they sit in (`connections.site-a`,
/// `connections.site-a.children.net`).
pub fn parse_swanctl_proposals(text: &str) -> Vec<Value> {
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for raw in text.lines() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if let Some(name) = l.strip_suffix('{') {
            stack.push(name.trim().to_string());
            continue;
        }
        if l == "}" {
            stack.pop();
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let k = k.trim();
            if matches!(k, "proposals" | "esp_proposals" | "ah_proposals") {
                out.push(json!({
                    "block": stack.join("."),
                    "kind": if k == "proposals" { "ike" } else { "esp" },
                    "proposals": v.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect::<Vec<_>>(),
                }));
            }
        }
    }
    out
}

/// Algorithm tokens of the SAs that are up (`swanctl --list-sas`), e.g.
/// `AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384`.
pub fn parse_list_sas_algorithms(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .split_whitespace()
        .map(|t| t.trim_end_matches(','))
        .filter(|t| {
            t.contains('/') && t.chars().next().is_some_and(|c| c.is_ascii_uppercase()) && {
                let u = t.to_ascii_uppercase();
                [
                    "AES", "3DES", "DES", "CHACHA", "CAMELLIA", "BLOWFISH", "HMAC", "PRF", "MODP",
                    "ECP", "CURVE",
                ]
                .iter()
                .any(|a| u.contains(a))
            }
        })
        .map(str::to_string)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// tls-crypt / tls-auth / weak data ciphers of one OpenVPN config text.
pub fn openvpn_config_facts(text: &str) -> Value {
    let mut crypt = false;
    let mut auth = false;
    let mut weak_cipher = false;
    for raw in text.lines() {
        let l = raw.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let key = l.split_whitespace().next().unwrap_or("");
        match key {
            "tls-crypt" | "tls-crypt-v2" | "<tls-crypt>" | "<tls-crypt-v2>" => crypt = true,
            "tls-auth" | "<tls-auth>" => auth = true,
            "cipher" | "data-ciphers" | "ncp-ciphers" | "data-ciphers-fallback" => {
                let u = l.to_ascii_uppercase();
                if ["BF-", "DES", "RC2", "CAST", "SEED"]
                    .iter()
                    .any(|w| u.contains(w))
                {
                    weak_cipher = true;
                }
            }
            _ => {}
        }
    }
    json!({ "tls_crypt": crypt, "tls_auth": auth, "weak_cipher": weak_cipher })
}

/// `val-permissive-mode`, the validator module and trust anchors of an
/// unbound.conf text.
pub fn unbound_config_facts(text: &str) -> Value {
    let mut validator = None::<bool>;
    let mut anchor = false;
    let mut permissive = false;
    for raw in text.lines() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = l.split_once(':') {
            let v = v.trim().trim_matches('"');
            match k.trim() {
                "module-config" => validator = Some(v.split_whitespace().any(|m| m == "validator")),
                "auto-trust-anchor-file" | "trust-anchor-file" | "trust-anchor" => anchor = true,
                "val-permissive-mode" => permissive = v == "yes",
                _ => {}
            }
        }
    }
    // unbound's built-in module-config is "validator iterator"
    json!({ "validator": validator.unwrap_or(true), "trust_anchor": anchor, "permissive": permissive })
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

struct Proc {
    pid: u32,
    comm: String,
    argv: Vec<String>,
}

fn processes() -> (Vec<Proc>, HashMap<u64, u32>) {
    let mut procs = Vec::new();
    let mut sockets: HashMap<u64, u32> = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return (procs, sockets);
    };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let base = e.path();
        let comm = read(base.join("comm")).trim().to_string();
        let argv: Vec<String> = std::fs::read(base.join("cmdline"))
            .unwrap_or_default()
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        // zombies keep a comm but no sockets: skip them
        if read(base.join("stat")).split_whitespace().nth(2) == Some("Z") {
            continue;
        }
        if let Ok(fds) = std::fs::read_dir(base.join("fd")) {
            for fd in fds.flatten() {
                if let Ok(t) = std::fs::read_link(fd.path()) {
                    let t = t.to_string_lossy();
                    if let Some(i) = t
                        .strip_prefix("socket:[")
                        .and_then(|r| r.strip_suffix(']'))
                        .and_then(|i| i.parse().ok())
                    {
                        sockets.entry(i).or_insert(pid);
                    }
                }
            }
        }
        procs.push(Proc { pid, comm, argv });
    }
    (procs, sockets)
}

/// Collect the facts (`params.parts`: list of `listeners`, `ssh`, `wg`,
/// `ipsec`, `openvpn`, `dns`, `ids`, `nft`, `system`; absent = all).
pub fn facts(params: &Value) -> Result<Value> {
    let parts: Vec<String> = params["parts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let want = |p: &str| parts.is_empty() || parts.iter().any(|x| x == p);
    let mut out = serde_json::Map::new();
    let (procs, sockets) = processes();
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();

    let mut listeners: Vec<Listener> = Vec::new();
    for (f, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ] {
        listeners.extend(parse_proc_net(&read(f), proto));
    }
    for l in &mut listeners {
        if let Some(pid) = sockets.get(&l.inode) {
            l.pid = Some(*pid);
            l.process = by_pid.get(pid).map(|p| p.comm.clone()).unwrap_or_default();
        }
    }
    listeners.sort_by(|a, b| {
        (a.proto.as_str(), a.port, a.addr.as_str()).cmp(&(
            b.proto.as_str(),
            b.port,
            b.addr.as_str(),
        ))
    });
    listeners.dedup_by(|a, b| a.proto == b.proto && a.port == b.port && a.addr == b.addr);
    if want("listeners") {
        out.insert("listeners".into(), json!(listeners));
    }

    if want("system") {
        let mem_kb = read("/proc/meminfo")
            .lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .unwrap_or(0);
        let uptime = read("/proc/uptime")
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;
        out.insert(
            "system".into(),
            json!({
                "mem_total_mb": mem_kb / 1024,
                "uptime_secs": uptime,
                "tcp_syncookies": read("/proc/sys/net/ipv4/tcp_syncookies").trim(),
                "processes": procs.iter().map(|p| p.comm.clone()).collect::<std::collections::BTreeSet<_>>(),
            }),
        );
    }

    if want("ssh") {
        let mut ssh = serde_json::Map::new();
        // the listening sshd master (the parent of every session)
        let master = listeners
            .iter()
            .filter(|l| l.proto == "tcp" && matches!(l.process.as_str(), "sshd" | "dropbear"))
            .filter_map(|l| l.pid)
            .filter_map(|p| by_pid.get(&p))
            .collect::<Vec<_>>();
        if let Some(p) = master.iter().find(|p| p.comm == "sshd") {
            let mut args: Vec<String> = vec!["-T".into()];
            args.extend(sshd_config_args(&p.argv));
            let bin = p
                .argv
                .first()
                .filter(|b| b.starts_with('/'))
                .cloned()
                .unwrap_or_else(|| crate::ssh::SSHD_BIN.to_string());
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            match Command::new(&bin).args(&refs).output() {
                Ok(o) if o.status.success() => {
                    let m = parse_sshd_t(&String::from_utf8_lossy(&o.stdout));
                    ssh.insert("sshd".into(), json!(m));
                }
                Ok(o) => {
                    ssh.insert(
                        "sshd_error".into(),
                        json!(String::from_utf8_lossy(&o.stderr).trim().to_string()),
                    );
                }
                Err(e) => {
                    ssh.insert("sshd_error".into(), json!(e.to_string()));
                }
            }
        }
        if let Some(p) = master.iter().find(|p| p.comm == "dropbear") {
            ssh.insert("dropbear".into(), dropbear_flags(&p.argv));
        }
        // authorized keys of root and the login users (counted, never read out)
        let mut keys = 0usize;
        let mut files = vec![std::path::PathBuf::from("/root/.ssh/authorized_keys")];
        if let Ok(rd) = std::fs::read_dir("/home") {
            files.extend(rd.flatten().map(|e| e.path().join(".ssh/authorized_keys")));
        }
        files.push("/etc/dropbear/authorized_keys".into());
        for f in files {
            keys += read(f)
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .count();
        }
        ssh.insert("authorized_keys".into(), json!(keys));
        out.insert("ssh".into(), Value::Object(ssh));
    }

    if want("wg") {
        let peers = run("wg", &["show", "all", "dump"])
            .map(|t| parse_wg_dump(&t))
            .unwrap_or_default();
        out.insert("wg".into(), json!({ "peers": peers }));
    }

    if want("ipsec") {
        let mut props = Vec::new();
        let mut files: Vec<std::path::PathBuf> = vec!["/etc/swanctl/swanctl.conf".into()];
        if let Ok(rd) = std::fs::read_dir("/etc/swanctl/conf.d") {
            files.extend(rd.flatten().map(|e| e.path()));
        }
        for f in files {
            for mut p in parse_swanctl_proposals(&read(&f)) {
                p["file"] = json!(f.display().to_string());
                props.push(p);
            }
        }
        let charon = procs
            .iter()
            .any(|p| p.comm == "charon" || p.comm == "charon-systemd");
        let sas = if charon {
            run("swanctl", &["--list-sas"])
                .map(|t| parse_list_sas_algorithms(&t))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        out.insert(
            "ipsec".into(),
            json!({ "running": charon, "proposals": props, "sa_algorithms": sas }),
        );
    }

    if want("openvpn") {
        let mut v = Vec::new();
        for p in procs.iter().filter(|p| p.comm == "openvpn") {
            let mut cfg = None;
            for w in p.argv.windows(2) {
                if w[0] == "--config" {
                    cfg = Some(w[1].clone());
                }
            }
            if cfg.is_none() && p.argv.len() == 2 && !p.argv[1].starts_with('-') {
                cfg = Some(p.argv[1].clone());
            }
            let mut f = cfg
                .as_ref()
                .map(|c| {
                    let path = if c.starts_with('/') {
                        std::path::PathBuf::from(c)
                    } else {
                        std::fs::read_link(format!("/proc/{}/cwd", p.pid))
                            .unwrap_or_default()
                            .join(c)
                    };
                    openvpn_config_facts(&read(path))
                })
                .unwrap_or_else(|| json!({}));
            // options given on the command line count too
            let line = p.argv.join("\n").replace("--", "");
            let cl = openvpn_config_facts(&line);
            for k in ["tls_crypt", "tls_auth", "weak_cipher"] {
                if cl[k] == true {
                    f[k] = json!(true);
                }
            }
            f["pid"] = json!(p.pid);
            f["config"] = json!(cfg);
            v.push(f);
        }
        out.insert("openvpn".into(), json!(v));
    }

    if want("dns") {
        let ub = procs.iter().find(|p| p.comm == "unbound");
        let cfg = ub.and_then(|p| {
            p.argv
                .windows(2)
                .find(|w| w[0] == "-c")
                .map(|w| w[1].clone())
        });
        let path = cfg
            .clone()
            .unwrap_or_else(|| "/etc/unbound/unbound.conf".into());
        let mut f = if ub.is_some() {
            unbound_config_facts(&read(&path))
        } else {
            json!({})
        };
        f["unbound_running"] = json!(ub.is_some());
        f["dnsmasq_running"] = json!(procs.iter().any(|p| p.comm == "dnsmasq"));
        f["config"] = json!(path);
        out.insert("dns".into(), f);
    }

    if want("ids") {
        let running = procs
            .iter()
            .any(|p| p.comm.starts_with("Suricata") || p.comm == "suricata");
        out.insert("ids".into(), json!({ "suricata_running": running }));
    }

    if want("nft") {
        let main = run("nft", &["-j", "-t", "list", "table", "inet", "patronus"])
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .unwrap_or(Value::Null);
        let guard = run(
            "nft",
            &["-j", "-t", "list", "table", "inet", "patronus_guard"],
        )
        .is_some();
        out.insert("nft".into(), json!({ "main": main, "guard_table": guard }));
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_listeners_v4_v6_and_udp() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0\n\
   1: 0132A8C0:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1235 1 0\n\
   2: 0132A8C0:01BB 0A32A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 1236 1 0\n";
        let l = parse_proc_net(tcp, "tcp");
        assert_eq!(l.len(), 2, "established socket skipped");
        assert_eq!(
            (l[0].addr.as_str(), l[0].port, l[0].inode),
            ("0.0.0.0", 22, 1234)
        );
        assert_eq!((l[1].addr.as_str(), l[1].port), ("192.168.50.1", 443));
        let tcp6 = "h\n   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 0\n";
        let l6 = parse_proc_net(tcp6, "tcp");
        assert_eq!((l6[0].addr.as_str(), l6[0].port), ("::", 80));
        let udp = "h\n   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2 0\n\
   1: 00000000:A000 0100007F:0035 07 00000000:00000000 00:00000000 00000000     0        0 10 2 0\n";
        let u = parse_proc_net(udp, "udp");
        assert_eq!(u.len(), 1, "connected udp socket skipped");
        assert_eq!(u[0].port, 53);
    }

    #[test]
    fn sshd_t_and_args() {
        let m = parse_sshd_t("port 22\nport 2222\npasswordauthentication no\nPermitRootLogin prohibit-password\nlistenaddress 0.0.0.0:22\n");
        assert_eq!(m["port"], vec!["22", "2222"]);
        assert_eq!(m["passwordauthentication"], vec!["no"]);
        assert_eq!(m["permitrootlogin"], vec!["prohibit-password"]);
        let a: Vec<String> = [
            "/usr/sbin/sshd",
            "-D",
            "-E",
            "/log",
            "-o",
            "PasswordAuthentication=yes",
            "-p22",
            "-f",
            "/x.conf",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            sshd_config_args(&a),
            vec![
                "-o",
                "PasswordAuthentication=yes",
                "-p",
                "22",
                "-f",
                "/x.conf"
            ]
        );
        let d: Vec<String> = ["dropbear", "-F", "-s", "-p", "22"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let f = dropbear_flags(&d);
        assert_eq!(f["password_auth"], false);
        assert_eq!(f["ports"], json!(["22"]));
    }

    #[test]
    fn wg_dump_peers() {
        let t = "wg0\tPRIV\tPUB\t51820\toff\n\
wg0\tpeerA=\t(none)\t198.51.100.7:51820\t10.9.0.2/32\t1700000000\t10\t20\t25\n\
wg0\tpeerB=\tPSK=\t(none)\t10.9.0.3/32\t0\t0\t0\toff\n";
        let p = parse_wg_dump(t);
        assert_eq!(p.len(), 2);
        assert!(!p[0].preshared_key && p[0].latest_handshake == 1_700_000_000);
        assert!(p[1].preshared_key && p[1].latest_handshake == 0);
    }

    #[test]
    fn swanctl_proposals_and_sas() {
        let t = "connections {\n  site-a {\n    proposals = aes256-sha256-modp2048, aes128-sha1-modp1024\n    children {\n      net {\n        esp_proposals = aes256gcm16-ecp384 # good\n      }\n    }\n  }\n}\n";
        let p = parse_swanctl_proposals(t);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0]["block"], "connections.site-a");
        assert_eq!(p[0]["kind"], "ike");
        assert_eq!(p[0]["proposals"][1], "aes128-sha1-modp1024");
        assert_eq!(p[1]["block"], "connections.site-a.children.net");
        assert_eq!(p[1]["kind"], "esp");
        let s = parse_list_sas_algorithms("site-a: #1, ESTABLISHED, IKEv2\n  AES_CBC-128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024\n  net: #2, INSTALLED, TUNNEL, ESP:AES_GCM_16-256/ECP_384\n");
        assert!(s.iter().any(|a| a.contains("MODP_1024")), "{s:?}");
        assert!(
            s.iter().any(|a| a.contains("AES_GCM_16-256/ECP_384")),
            "{s:?}"
        );
    }

    #[test]
    fn openvpn_and_unbound_config() {
        let o = openvpn_config_facts("dev tun\ntls-crypt /etc/x.key\ncipher AES-256-GCM\n");
        assert_eq!(
            (o["tls_crypt"].clone(), o["weak_cipher"].clone()),
            (json!(true), json!(false))
        );
        let o = openvpn_config_facts("# tls-crypt x\ntls-auth ta.key 0\ncipher BF-CBC\n");
        assert_eq!(o["tls_crypt"], false);
        assert_eq!(o["tls_auth"], true);
        assert_eq!(o["weak_cipher"], true);
        let u = unbound_config_facts("server:\n  module-config: \"validator iterator\"\n  auto-trust-anchor-file: \"/var/lib/unbound/root.key\"\n");
        assert_eq!(
            u,
            json!({"validator": true, "trust_anchor": true, "permissive": false})
        );
        let u = unbound_config_facts(
            "server:\n  module-config: \"iterator\"\n  val-permissive-mode: yes\n",
        );
        assert_eq!(u["validator"], false);
        assert_eq!(u["permissive"], true);
    }
}
