//! Optional components through Portage (USE=plugins): the daemons behind
//! Patronus' USE flags (miniupnpd for `upnp`, squid for `web-proxy`, ...)
//! can be installed, updated and removed from the Packages page instead of
//! by hand. Every action is one `emerge` run as a background job whose output
//! is kept; binary packages from the Gentoo binhost are preferred
//! (`--getbinpkg --usepkg`), and what the build then lacks is compiled. Only
//! the catalog below can be touched: a request names a component id, never an
//! atom or an argument. On a system without Portage the page says so and every
//! action answers 501.

use crate::supervise::{which, NetPaths};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use sqlx::Row;
use std::path::PathBuf;

pub struct Component {
    pub id: &'static str,
    /// the Patronus USE flag / cargo feature this daemon serves
    pub feature: &'static str,
    pub title: &'static str,
    pub atom: &'static str,
    /// a program that exists once the package is installed
    pub binary: &'static str,
}

pub const CATALOG: &[Component] = &[
    Component {
        id: "igmpproxy",
        feature: "igmp",
        title: "IGMP proxy",
        atom: "net-misc/igmpproxy",
        binary: "igmpproxy",
    },
    Component {
        id: "miniupnpd",
        feature: "upnp",
        title: "UPnP / NAT-PMP daemon",
        atom: "net-misc/miniupnpd[nftables]",
        binary: "miniupnpd",
    },
    Component {
        id: "squid",
        feature: "web-proxy",
        title: "Squid web proxy",
        atom: "net-proxy/squid",
        binary: "squid",
    },
    Component {
        id: "frr",
        feature: "dynamic-routing",
        title: "FRRouting (BGP/OSPF)",
        atom: "net-misc/frr",
        binary: "vtysh",
    },
    Component {
        id: "softflowd",
        feature: "netflow",
        title: "NetFlow exporter",
        atom: "net-analyzer/softflowd",
        binary: "softflowd",
    },
    Component {
        id: "tayga",
        feature: "nat64",
        title: "NAT64 (tayga)",
        atom: "net-proxy/tayga",
        binary: "tayga",
    },
    Component {
        id: "xl2tpd",
        feature: "l2tp",
        title: "L2TP daemon",
        atom: "net-dialup/xl2tpd",
        binary: "xl2tpd",
    },
    Component {
        id: "rsyslog",
        feature: "syslog",
        title: "Remote syslog",
        atom: "app-admin/rsyslog",
        binary: "rsyslogd",
    },
    Component {
        id: "keepalived",
        feature: "ha",
        title: "VRRP (keepalived)",
        atom: "sys-cluster/keepalived",
        binary: "keepalived",
    },
    Component {
        id: "suricata",
        feature: "intrusion-detection",
        title: "Suricata IDS/IPS",
        atom: "net-analyzer/suricata",
        binary: "suricata",
    },
    Component {
        id: "openvpn",
        feature: "vpn-openvpn",
        title: "OpenVPN",
        atom: "net-vpn/openvpn",
        binary: "openvpn",
    },
    Component {
        id: "strongswan",
        feature: "vpn-ipsec",
        title: "strongSwan (IPsec)",
        atom: "net-vpn/strongswan",
        binary: "swanctl",
    },
];

pub fn find(id: &str) -> Option<&'static Component> {
    CATALOG.iter().find(|c| c.id == id)
}

/// The command line for an action on a component (nothing user-supplied).
pub fn emerge_args(c: &Component, action: &str) -> Option<Vec<String>> {
    let atom = c.atom.to_string();
    Some(match action {
        "install" => ["--noreplace", "--getbinpkg", "--usepkg", "--quiet-build"]
            .iter()
            .map(|s| s.to_string())
            .chain([atom])
            .collect(),
        "update" => ["--update", "--getbinpkg", "--usepkg", "--quiet-build"]
            .iter()
            .map(|s| s.to_string())
            .chain([atom])
            .collect(),
        "remove" => vec!["--depclean".into(), "--quiet-build".into(), atom],
        _ => return None,
    })
}

pub fn emerge_path() -> Option<PathBuf> {
    which("emerge")
}

fn jobs_dir(paths: &NetPaths) -> PathBuf {
    paths.state_dir.join("packages")
}

/// What the page shows: every component, whether its program is installed,
/// and the latest job per component.
pub async fn overview(store: &ConfigStore) -> Result<Value> {
    settle_jobs(store, &NetPaths::default()).await;
    let rows = sqlx::query(
        "SELECT id, component, action, status, started_at, finished_at, exit_code FROM package_jobs ORDER BY id DESC LIMIT 30",
    )
    .fetch_all(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("read package_jobs: {e}")))?;
    let jobs: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"id": r.get::<i64,_>(0), "component": r.get::<String,_>(1), "action": r.get::<String,_>(2),
                   "status": r.get::<String,_>(3), "started_at": r.get::<i64,_>(4),
                   "finished_at": r.get::<Option<i64>,_>(5), "exit_code": r.get::<Option<i64>,_>(6)})
        })
        .collect();
    let comps: Vec<Value> = CATALOG
        .iter()
        .map(|c| {
            json!({"id": c.id, "feature": c.feature, "title": c.title, "atom": c.atom,
                   "installed": which(c.binary).is_some(),
                   "last_job": jobs.iter().find(|j| j["component"] == c.id)})
        })
        .collect();
    Ok(json!({"portage": emerge_path().is_some(), "components": comps, "jobs": jobs}))
}

/// Serializes `start` (the check for a running job and the insert).
static START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn exit_file(paths: &NetPaths, id: i64) -> PathBuf {
    jobs_dir(paths).join(format!("job-{id}.exit"))
}

/// Finish rows whose exit file exists; give up on rows with none after 6 h.
/// Returns the id of a job that is still running.
async fn settle_jobs(store: &ConfigStore, paths: &NetPaths) -> Option<i64> {
    let pool = store.pool().ok()?;
    let rows = sqlx::query("SELECT id, started_at FROM package_jobs WHERE status = 'running'")
        .fetch_all(pool)
        .await
        .ok()?;
    let now = chrono::Utc::now().timestamp();
    let mut live = None;
    for r in rows {
        let (id, started): (i64, i64) = (r.get(0), r.get(1));
        let code = std::fs::read_to_string(exit_file(paths, id))
            .ok()
            .and_then(|t| t.trim().parse::<i64>().ok());
        let (status, code) = match code {
            Some(c) => (if c == 0 { "ok" } else { "failed" }, Some(c)),
            None if now - started > 6 * 3600 => ("failed", Some(-1)),
            None => {
                live = Some(id);
                continue;
            }
        };
        let _ = sqlx::query(
            "UPDATE package_jobs SET status = ?, finished_at = ?, exit_code = ? WHERE id = ?",
        )
        .bind(status)
        .bind(now)
        .bind(code)
        .bind(id)
        .execute(pool)
        .await;
    }
    live
}

/// Start `action` on component `id` in the background (as root: directly when
/// we are root, else through the applyd broker); returns the job id.
pub async fn start(
    store: &std::sync::Arc<ConfigStore>,
    paths: &NetPaths,
    id: &str,
    action: &str,
) -> Result<i64> {
    let c = find(id).ok_or_else(|| Error::Config(format!("no component {id:?}")))?;
    emerge_args(c, action).ok_or_else(|| {
        crate::lan::invalid(format!("action {action:?}: install, update or remove"))
    })?;
    let root = nix::unistd::geteuid().is_root();
    if emerge_path().is_none() {
        return Err(Error::Service(
            "not a Portage system: emerge is not installed (501)".into(),
        ));
    }
    let _g = START.lock().await;
    if settle_jobs(store, paths).await.is_some() {
        return Err(crate::lan::invalid(
            "another package job is running (Portage allows one at a time)",
        ));
    }
    let jid = sqlx::query(
        "INSERT INTO package_jobs (component, action, status, started_at, log_path) VALUES (?, ?, 'running', ?, '')",
    )
    .bind(c.id)
    .bind(action)
    .bind(chrono::Utc::now().timestamp())
    .execute(store.pool()?)
    .await
    .map_err(|e| Error::Config(format!("save job: {e}")))?
    .last_insert_rowid();
    let log = jobs_dir(paths).join(format!("job-{jid}.log"));
    let _ = sqlx::query("UPDATE package_jobs SET log_path = ? WHERE id = ?")
        .bind(log.to_string_lossy().as_ref())
        .bind(jid)
        .execute(store.pool()?)
        .await;
    let res = if root {
        spawn_emerge(&paths.state_dir, jid, c.id, action)
    } else {
        crate::applyd::request_system(
            &crate::applyd::socket_path(),
            "package_job",
            json!({"job": jid, "component": c.id, "action": action}),
        )
        .await
        .map(|_| ())
    };
    if let Err(e) = res {
        let _ = sqlx::query("UPDATE package_jobs SET status = 'failed', finished_at = ?, exit_code = -1 WHERE id = ?")
            .bind(chrono::Utc::now().timestamp())
            .bind(jid)
            .execute(store.pool()?)
            .await;
        return Err(e);
    }
    Ok(jid)
}

/// The detached `emerge` run for a job (called by the root broker): output
/// to job-<id>.log, exit code to job-<id>.exit when it is done.
pub fn spawn_emerge(state_dir: &std::path::Path, job: i64, id: &str, action: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let c = find(id).ok_or_else(|| Error::Config(format!("no component {id:?}")))?;
    let args = emerge_args(c, action).ok_or_else(|| {
        crate::lan::invalid(format!("action {action:?}: install, update or remove"))
    })?;
    let emerge = emerge_path().ok_or_else(|| {
        Error::Service("not a Portage system: emerge is not installed (501)".into())
    })?;
    let dir = state_dir.join("packages");
    std::fs::create_dir_all(&dir).map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
    let log = dir.join(format!("job-{job}.log"));
    let exit = dir.join(format!("job-{job}.exit"));
    let _ = std::fs::remove_file(&exit);
    let script = r#"log=$1; exit=$2; shift 2; chmod 644 "$log" 2>/dev/null; "$@" >"$log" 2>&1 </dev/null; echo $? > "$exit.tmp"; chmod 644 "$exit.tmp"; mv "$exit.tmp" "$exit""#;
    std::fs::File::create(&log).map_err(|e| Error::Config(format!("{}: {e}", log.display())))?;
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .arg(&log)
        .arg(&exit)
        .arg(&emerge)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // its own session: the job outlives the broker's connection and a restart of it
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()
                .map(|_| ())
                .map_err(std::io::Error::from)
        });
    }
    cmd.spawn()
        .map_err(|e| Error::Service(format!("starting emerge: {e}")))?;
    Ok(())
}

/// The last 64 KiB of a job's log.
pub async fn job_log(store: &ConfigStore, id: i64) -> Result<Option<String>> {
    let Some(r) = sqlx::query("SELECT log_path FROM package_jobs WHERE id = ?")
        .bind(id)
        .fetch_optional(store.pool()?)
        .await
        .map_err(|e| Error::Config(format!("read job: {e}")))?
    else {
        return Ok(None);
    };
    let path: String = r.get(0);
    let text = std::fs::read(&path).unwrap_or_default();
    let tail = &text[text.len().saturating_sub(65536)..];
    Ok(Some(String::from_utf8_lossy(tail).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_catalog_atoms_and_known_actions_reach_emerge() {
        let c = find("openvpn").unwrap();
        let i = emerge_args(c, "install").unwrap();
        assert_eq!(i.last().unwrap(), "net-vpn/openvpn");
        assert!(i.contains(&"--getbinpkg".to_string()) && i.contains(&"--noreplace".to_string()));
        assert!(emerge_args(c, "update")
            .unwrap()
            .contains(&"--update".to_string()));
        assert_eq!(emerge_args(c, "remove").unwrap()[0], "--depclean");
        assert!(emerge_args(c, "--sync").is_none() && emerge_args(c, "install; rm").is_none());
        assert!(find("net-vpn/openvpn").is_none() && find("../x").is_none());
        // catalog ids and binaries are unique and atoms are category/package
        let mut ids: Vec<_> = CATALOG.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG.len());
        assert!(CATALOG
            .iter()
            .all(|c| c.atom.matches('/').count() == 1 && !c.atom.contains(' ')));
    }

    #[tokio::test]
    async fn overview_lists_every_component_and_start_needs_portage() {
        let store = std::sync::Arc::new(ConfigStore::open_in_memory().await.unwrap());
        let o = overview(&store).await.unwrap();
        assert_eq!(o["components"].as_array().unwrap().len(), CATALOG.len());
        let d = tempfile::tempdir().unwrap();
        let p = NetPaths::under(d.path());
        assert!(start(&store, &p, "nope", "install").await.is_err());
        assert!(start(&store, &p, "squid", "explode").await.is_err());
        if emerge_path().is_none() {
            let e = start(&store, &p, "squid", "install").await.unwrap_err();
            assert!(e.to_string().contains("not a Portage system"));
        }
    }
}
