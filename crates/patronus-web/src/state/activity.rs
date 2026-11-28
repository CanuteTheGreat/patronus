//! The cached system-activity sampler behind `/api/v1/system/activity`.
//!
//! A request only reads the latest [`Snapshot`]; it never waits for the
//! sampling interval. The first request starts a background task that takes
//! two `/proc` samples a moment apart (the CPU percentages need both), then
//! keeps sampling every `dashboard.activity_sample_secs`. The task stops by
//! itself when nobody has asked for [`IDLE_STOP_SECS`], so an idle router
//! (and a small access point) does not read `/proc` all day.

use patronus_config::ConfigStore;
use patronus_network::activity::{self, Host, RawSample, Snapshot};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

/// The task stops after this long without a request.
pub const IDLE_STOP_SECS: i64 = 120;
/// Pause between the first two samples (fast first answer).
const WARMUP_MS: u64 = 700;

pub struct Sampler {
    snap: RwLock<Option<Arc<Snapshot>>>,
    running: AtomicBool,
    // Mutex, not AtomicI64: 32-bit MIPS (the NOR tier) has no 64-bit atomics
    last_request: Mutex<i64>,
    store: Mutex<Option<Arc<ConfigStore>>>,
    proc_root: PathBuf,
    passwd: PathBuf,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Sampler {
    pub fn new(proc_root: PathBuf, passwd: PathBuf) -> Self {
        Sampler {
            snap: RwLock::new(None),
            running: AtomicBool::new(false),
            last_request: Mutex::new(0),
            store: Mutex::new(None),
            proc_root,
            passwd,
        }
    }

    /// The process-wide sampler over the real `/proc`.
    pub fn global() -> &'static Arc<Sampler> {
        static S: OnceLock<Arc<Sampler>> = OnceLock::new();
        S.get_or_init(|| Arc::new(Sampler::new("/proc".into(), "/etc/passwd".into())))
    }

    /// The newest snapshot (`None` while the first two samples are being
    /// taken), and make sure the background task is running.
    pub fn latest(self: &Arc<Self>, store: &Arc<ConfigStore>) -> Option<Arc<Snapshot>> {
        *self.last_request.lock().unwrap_or_else(|p| p.into_inner()) = now();
        *self.store.lock().unwrap_or_else(|e| e.into_inner()) = Some(store.clone());
        if !self.running.swap(true, Ordering::AcqRel) {
            let me = self.clone();
            tokio::spawn(async move { me.run().await });
        }
        self.snap.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn interval(&self) -> Duration {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let secs = match store {
            Some(s) => {
                patronus_config::dashboard::load(&s)
                    .await
                    .activity_sample_secs
            }
            None => patronus_config::dashboard::Settings::default().activity_sample_secs,
        };
        Duration::from_secs(secs as u64)
    }

    async fn read(&self) -> Option<RawSample> {
        let (root, passwd) = (self.proc_root.clone(), self.passwd.clone());
        tokio::task::spawn_blocking(move || activity::take(&root, &passwd, Host::detect()))
            .await
            .ok()?
            .map_err(|e| tracing::warn!("system activity: cannot read /proc: {e}"))
            .ok()
    }

    /// Sample until nobody has asked for [`IDLE_STOP_SECS`].
    async fn sample_until_idle(&self) {
        let host = Host::detect();
        let mut prev = self.read().await;
        let mut pause = Duration::from_millis(WARMUP_MS);
        loop {
            tokio::time::sleep(pause).await;
            if now() - *self.last_request.lock().unwrap_or_else(|p| p.into_inner()) > IDLE_STOP_SECS
            {
                return;
            }
            if let Some(cur) = self.read().await {
                if let Some(p) = &prev {
                    if let Some(s) = activity::compute(
                        p,
                        &cur,
                        host,
                        patronus_network::services::KNOWN_SERVICES,
                        now(),
                    ) {
                        *self.snap.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(s));
                    }
                }
                prev = Some(cur);
            }
            pause = self.interval().await;
        }
    }

    async fn run(self: Arc<Self>) {
        loop {
            self.sample_until_idle().await;
            self.running.store(false, Ordering::Release);
            // a request that arrived between the last idle check and the flag reset
            let asked = now() - *self.last_request.lock().unwrap_or_else(|p| p.into_inner())
                <= IDLE_STOP_SECS;
            if !asked || self.running.swap(true, Ordering::AcqRel) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_answer_comes_without_waiting_and_a_snapshot_follows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ConfigStore::open(dir.path().join("c.db")).await.unwrap());
        let s = Arc::new(Sampler::new("/proc".into(), "/etc/passwd".into()));
        let t = std::time::Instant::now();
        assert!(s.latest(&store).is_none(), "nothing sampled yet");
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "the request did not wait"
        );
        let mut got = None;
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            got = s.latest(&store);
            if got.is_some() {
                break;
            }
        }
        let snap = got.expect("a snapshot within 8 s");
        assert!(snap.process_count > 0 && snap.memory.total > 0);
        assert!(
            snap.processes.iter().any(|p| p.pid == std::process::id()),
            "this process is listed"
        );
    }
}
