//! `patronus applyd`: a small root-owned apply broker for patronus-web.
//!
//! patronus-web runs as the unprivileged `patronus` user (with only
//! CAP_NET_ADMIN/CAP_NET_RAW). That is enough for netlink and nftables, but
//! not for starting init-managed daemons (DHCP clients, pppd) or writing
//! their unit state. So the web UI writes the store and then asks this
//! broker, over a unix socket (`/run/patronus/applyd.sock`, mode 0660,
//! group `patronus`), to run ONE named applier against the same store, as
//! root. The request carries only an applier name; the broker reads the
//! configuration from the store itself, so the socket grants nothing beyond
//! "re-apply what is already stored".
//!
//! Protocol: one JSON line each way.
//!   -> {"applier":"interfaces"}
//!   <- {"ok":true,"applied":[...],"warnings":[...]} | {"ok":false,"error":"..."}

use async_trait::async_trait;
use patronus_config::applier::{Applier, ApplierRegistry, ApplyReport, Phase};
use patronus_config::declarative::{DeclarativeConfig, ResourceKind};
use patronus_config::store::ConfigStore;
use patronus_core::{Error, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub const DEFAULT_SOCKET: &str = "/run/patronus/applyd.sock";

/// `$PATRONUS_APPLYD_SOCKET` or the default.
pub fn socket_path() -> PathBuf {
    std::env::var_os("PATRONUS_APPLYD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

fn reply(r: &std::result::Result<ApplyReport, String>) -> Value {
    match r {
        Ok(rep) => json!({"ok": true, "applied": rep.applied, "warnings": rep.warnings}),
        Err(e) => json!({"ok": false, "error": e}),
    }
}

/// Serve apply requests until the process is stopped.
pub async fn serve(
    registry: ApplierRegistry,
    store: ConfigStore,
    socket: &Path,
    group: Option<&str>,
) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::Network(format!("{}: {e}", dir.display())))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)
        .map_err(|e| Error::Network(format!("bind {}: {e}", socket.display())))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))
            .map_err(|e| Error::Network(format!("chmod {}: {e}", socket.display())))?;
        if let Some(g) = group {
            match nix::unistd::Group::from_name(g) {
                Ok(Some(gr)) => {
                    nix::unistd::chown(socket, None, Some(gr.gid))
                        .map_err(|e| Error::Network(format!("chown {}: {e}", socket.display())))?;
                }
                _ => tracing::warn!("group {g} not found; {} stays root-only", socket.display()),
            }
        }
    }
    tracing::info!("applyd listening on {}", socket.display());
    let store = Arc::new(store);
    let registry = Arc::new(registry);
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    loop {
        let (conn, _) = listener
            .accept()
            .await
            .map_err(|e| Error::Network(format!("accept: {e}")))?;
        let (store, registry, lock) = (store.clone(), registry.clone(), lock.clone());
        tokio::spawn(async move {
            let (rd, mut wr) = conn.into_split();
            let mut line = String::new();
            let mut rd = BufReader::new(rd);
            if rd.read_line(&mut line).await.is_err() {
                return;
            }
            let name = serde_json::from_str::<Value>(&line).ok().and_then(|v| {
                v.get("applier")
                    .and_then(|a| a.as_str())
                    .map(str::to_string)
            });
            let res = match name.as_deref().and_then(|n| registry.by_name(n)) {
                Some(a) => {
                    let _g = lock.lock().await;
                    tracing::info!("applyd: applying {}", a.name());
                    a.apply(&store).await.map_err(|e| e.to_string())
                }
                None => Err(format!("unknown applier {name:?}")),
            };
            let mut out = reply(&res).to_string();
            out.push('\n');
            let _ = wr.write_all(out.as_bytes()).await;
        });
    }
}

/// Ask the broker to run applier `name`.
pub async fn request(socket: &Path, name: &str) -> Result<ApplyReport> {
    let conn = UnixStream::connect(socket)
        .await
        .map_err(|e| Error::Network(format!("apply broker {}: {e}", socket.display())))?;
    let (rd, mut wr) = conn.into_split();
    wr.write_all(format!("{}\n", json!({ "applier": name })).as_bytes())
        .await
        .map_err(|e| Error::Network(format!("apply broker: {e}")))?;
    let mut line = String::new();
    BufReader::new(rd)
        .read_line(&mut line)
        .await
        .map_err(|e| Error::Network(format!("apply broker: {e}")))?;
    let v: Value = serde_json::from_str(&line)
        .map_err(|e| Error::Network(format!("apply broker answered {line:?}: {e}")))?;
    let strs = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
        Ok(ApplyReport {
            applied: strs("applied"),
            warnings: strs("warnings"),
        })
    } else {
        Err(Error::Network(
            v.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("apply broker failed")
                .to_string(),
        ))
    }
}

/// An applier that applies through the broker and renders locally.
pub struct RemoteApplier {
    local: Arc<dyn Applier>,
    socket: PathBuf,
}

impl RemoteApplier {
    pub fn new(local: Arc<dyn Applier>, socket: PathBuf) -> Self {
        Self { local, socket }
    }

    /// The broker when its socket exists and we are not root; otherwise
    /// the local applier itself (root, containers, tests).
    pub fn wrap(local: Arc<dyn Applier>) -> Arc<dyn Applier> {
        let socket = socket_path();
        if !nix::unistd::geteuid().is_root() && socket.exists() {
            tracing::info!(
                "{} changes are applied through the root broker at {}",
                local.name(),
                socket.display()
            );
            Arc::new(Self::new(local, socket))
        } else {
            local
        }
    }
}

#[async_trait]
impl Applier for RemoteApplier {
    fn name(&self) -> &'static str {
        self.local.name()
    }
    fn phase(&self) -> Phase {
        self.local.phase()
    }
    async fn apply(&self, _store: &ConfigStore) -> Result<ApplyReport> {
        request(&self.socket, self.local.name()).await
    }
    async fn render(&self, store: &ConfigStore) -> Result<String> {
        self.local.render(store).await
    }
    fn resource_kinds(&self) -> &'static [ResourceKind] {
        self.local.resource_kinds()
    }
    async fn upsert_resource(&self, store: &ConfigStore, c: &DeclarativeConfig) -> Result<()> {
        self.local.upsert_resource(store, c).await
    }
    async fn delete_resource(&self, store: &ConfigStore, k: &ResourceKind, n: &str) -> Result<()> {
        self.local.delete_resource(store, k, n).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    #[async_trait]
    impl Applier for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn phase(&self) -> Phase {
            Phase::Interfaces
        }
        async fn apply(&self, s: &ConfigStore) -> Result<ApplyReport> {
            let mut r = ApplyReport::default();
            match s.load_system_config("fail").await? {
                Some(e) => Err(Error::Config(e)),
                None => {
                    r.applied("did it");
                    r.warnings.push("careful".into());
                    Ok(r)
                }
            }
        }
        async fn render(&self, _s: &ConfigStore) -> Result<String> {
            Ok("local render".into())
        }
    }

    #[tokio::test]
    async fn broker_runs_the_named_applier_against_its_store() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("c.db");
        let store = ConfigStore::open(&db).await.unwrap();
        let sock = d.path().join("run/applyd.sock");
        let reg = ApplierRegistry::new().with(Echo);
        let s2 = sock.clone();
        tokio::spawn(async move { serve(reg, store, &s2, None).await });
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let remote = RemoteApplier::new(Arc::new(Echo), sock.clone());
        let web_store = ConfigStore::open(&db).await.unwrap();
        let r = remote.apply(&web_store).await.unwrap();
        assert_eq!(
            (r.applied, r.warnings),
            (vec!["did it".to_string()], vec!["careful".to_string()])
        );
        // the broker reads what the web process stored
        web_store
            .save_system_config("fail", "Invalid thing")
            .await
            .unwrap();
        let e = remote.apply(&web_store).await.unwrap_err().to_string();
        assert!(e.contains("Invalid thing"), "{e}");
        assert!(request(&sock, "nope")
            .await
            .unwrap_err()
            .to_string()
            .contains("unknown applier"));
        assert_eq!(remote.render(&web_store).await.unwrap(), "local render");
    }
}
