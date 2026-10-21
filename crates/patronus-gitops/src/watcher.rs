//! GitOps watcher: keeps a local clone of a config repository in step with
//! its remote branch and applies the declarative resources found there
//! (`apiVersion: patronus.firewall/v1` YAML/TOML) through the
//! [`ApplyEngine`], i.e. into the config store and onto the system via the
//! same appliers `patronus apply` uses.
//!
//! Shipped as `patronus gitops sync` (one pass) and `patronus gitops watch`
//! (the `patronus-gitops` service), configured by the `[gitops]` section of
//! /etc/patronus/patronus.toml.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use git2::{FetchOptions, RemoteCallbacks, Repository};
use patronus_config::{ApplyEngine, ConfigParser, DeclarativeConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// GitOps repository configuration (`[gitops]` in patronus.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GitOpsConfig {
    /// Git repository URL (https://, ssh://, git@host:path or a local path)
    pub repo_url: String,

    /// Branch to watch
    pub branch: String,

    /// Local directory to clone into
    pub local_path: PathBuf,

    /// Directory within the repo holding the configs (e.g. "configs/")
    pub config_path: Option<String>,

    /// Poll interval in seconds
    pub poll_interval_secs: u64,

    /// Apply changes automatically; when false a sync only validates and
    /// reports what would change (`patronus gitops sync --apply` applies)
    pub auto_apply: bool,

    /// SSH key path for private repos
    pub ssh_key_path: Option<PathBuf>,

    /// Username for Git authentication
    pub username: Option<String>,

    /// Password/token for Git authentication
    pub password: Option<String>,

    /// File patterns to load (e.g. ["*.yaml", "*.yml", "*.toml"])
    pub file_patterns: Vec<String>,

    /// Validate every config before applying any of them
    pub validate_before_apply: bool,
}

impl Default for GitOpsConfig {
    fn default() -> Self {
        Self {
            repo_url: String::new(),
            branch: "main".to_string(),
            local_path: PathBuf::from("/var/lib/patronus/gitops/repo"),
            config_path: None,
            poll_interval_secs: 60,
            auto_apply: false,
            ssh_key_path: None,
            username: None,
            password: None,
            file_patterns: vec!["*.yaml".to_string(), "*.yml".to_string()],
            validate_before_apply: true,
        }
    }
}

/// Represents a Git sync event
#[derive(Debug, Clone, Serialize)]
pub struct GitSyncEvent {
    pub timestamp: DateTime<Utc>,
    pub commit_hash: String,
    pub commit_message: String,
    pub author: String,
    pub files_changed: Vec<String>,
    pub configs_found: usize,
    pub applied: bool,
    /// Resources created/updated/deleted by the apply
    pub changes_applied: usize,
    pub error: Option<String>,
}

/// Result of a Git sync operation
#[derive(Debug)]
pub struct SyncResult {
    /// The checkout moved to a commit that had not been processed yet
    pub updated: bool,
    pub event: Option<GitSyncEvent>,
}

/// GitOps repository watcher
pub struct GitOpsWatcher {
    config: GitOpsConfig,
    apply_engine: Arc<RwLock<ApplyEngine>>,
    repo: Option<Repository>,
    /// Last commit whose configs were applied (or, without auto-apply,
    /// validated and reported); a failed apply is retried on the next sync.
    processed_commit: Option<String>,
    sync_history: Arc<RwLock<Vec<GitSyncEvent>>>,
}

impl GitOpsWatcher {
    /// Create a new GitOps watcher
    pub fn new(config: GitOpsConfig, apply_engine: Arc<RwLock<ApplyEngine>>) -> Self {
        Self {
            config,
            apply_engine,
            repo: None,
            processed_commit: None,
            sync_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn config(&self) -> &GitOpsConfig {
        &self.config
    }

    /// Clone the repository, or open the existing clone (its `origin` must
    /// be the configured URL).
    pub async fn init(&mut self) -> Result<()> {
        if self.config.repo_url.trim().is_empty() {
            bail!("gitops: repo_url is not set ([gitops] repo_url in patronus.toml)");
        }
        let path = self.config.local_path.clone();
        if path.join(".git").exists() {
            info!("GitOps: opening existing clone at {}", path.display());
            let repo = Repository::open(&path).context("open existing clone")?;
            let url = repo
                .find_remote("origin")
                .ok()
                .and_then(|r| r.url().map(str::to_string));
            if url.as_deref() != Some(self.config.repo_url.as_str()) {
                bail!(
                    "gitops: {} is a clone of {:?}, not {} (remove it or change local_path)",
                    path.display(),
                    url,
                    self.config.repo_url
                );
            }
            self.repo = Some(repo);
        } else {
            if path.exists()
                && std::fs::read_dir(&path)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            {
                bail!(
                    "gitops: {} exists and is not a git clone; refusing to clone over it",
                    path.display()
                );
            }
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            info!(
                "GitOps: cloning {} ({})",
                self.config.repo_url, self.config.branch
            );
            let mut fo = FetchOptions::new();
            fo.remote_callbacks(self.callbacks());
            let repo = git2::build::RepoBuilder::new()
                .fetch_options(fo)
                .branch(&self.config.branch)
                .clone(&self.config.repo_url, &path)
                .context("git clone failed")?;
            self.repo = Some(repo);
        }
        Ok(())
    }

    fn callbacks(&self) -> RemoteCallbacks<'static> {
        let mut callbacks = RemoteCallbacks::new();
        if let Some(ssh_key) = self.config.ssh_key_path.clone() {
            callbacks.credentials(move |_url, user, _allowed| {
                git2::Cred::ssh_key(user.unwrap_or("git"), None, &ssh_key, None)
            });
        } else if let (Some(u), Some(p)) =
            (self.config.username.clone(), self.config.password.clone())
        {
            callbacks
                .credentials(move |_url, _user, _allowed| git2::Cred::userpass_plaintext(&u, &p));
        }
        callbacks
    }

    /// Fetch the branch and move the checkout to the remote tip. The remote
    /// is the source of truth: a rewritten branch (force push) is followed
    /// with a hard reset, never left behind. Returns the new HEAD hash.
    fn fetch_to_remote_tip(&self) -> Result<String> {
        let repo = self.repo.as_ref().context("repository not initialized")?;
        let mut remote = repo.find_remote("origin").context("no origin remote")?;
        let mut fo = FetchOptions::new();
        fo.remote_callbacks(self.callbacks());
        let refspec = format!(
            "+refs/heads/{0}:refs/remotes/origin/{0}",
            self.config.branch
        );
        remote
            .fetch(&[refspec.as_str()], Some(&mut fo), None)
            .context("git fetch failed")?;
        let tip = repo
            .find_reference(&format!("refs/remotes/origin/{}", self.config.branch))
            .context("remote branch not found after fetch")?
            .peel_to_commit()?;
        let head = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        if head.as_ref().map(|c| c.id()) != Some(tip.id()) {
            let ff = match &head {
                Some(h) => repo.graph_descendant_of(tip.id(), h.id()).unwrap_or(false),
                None => true,
            };
            if !ff {
                warn!(
                    "GitOps: {} was rewritten upstream; resetting the clone to {}",
                    self.config.branch,
                    tip.id()
                );
            }
            let local = format!("refs/heads/{}", self.config.branch);
            repo.reference(&local, tip.id(), true, "gitops: follow remote")?;
            repo.set_head(&local)?;
            repo.reset(
                tip.as_object(),
                git2::ResetType::Hard,
                Some(git2::build::CheckoutBuilder::new().force()),
            )
            .context("checkout of the remote tip failed")?;
        }
        Ok(tip.id().to_string())
    }

    fn commit_details(&self) -> Result<(String, String, String)> {
        let repo = self.repo.as_ref().context("repository not initialized")?;
        let commit = repo.head()?.peel_to_commit()?;
        let author = commit.author();
        Ok((
            commit.id().to_string(),
            commit.summary().unwrap_or("").to_string(),
            format!(
                "{} <{}>",
                author.name().unwrap_or("unknown"),
                author.email().unwrap_or("")
            ),
        ))
    }

    fn config_dir(&self) -> PathBuf {
        match &self.config.config_path {
            Some(p) => self.config.local_path.join(p.trim_start_matches('/')),
            None => self.config.local_path.clone(),
        }
    }

    /// Config files (matching `file_patterns`) in the config directory and
    /// its subdirectories, in a stable order. `.git` is skipped.
    fn find_config_files(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let base = self.config_dir();
        if base.exists() {
            self.walk(&base, &mut out)?;
        }
        out.sort();
        Ok(out)
    }

    fn walk(&self, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name != ".git" {
                    self.walk(&path, out)?;
                }
            } else if self
                .config
                .file_patterns
                .iter()
                .any(|p| self.matches_pattern(name, p))
            {
                out.push(path);
            }
        }
        Ok(())
    }

    /// Simple pattern matching (supports one * wildcard)
    fn matches_pattern(&self, file_name: &str, pattern: &str) -> bool {
        match pattern.split_once('*') {
            Some((pre, post)) if !post.contains('*') => {
                file_name.len() >= pre.len() + post.len()
                    && file_name.starts_with(pre)
                    && file_name.ends_with(post)
            }
            Some(_) => false,
            None => file_name == pattern,
        }
    }

    /// Load and parse all config files (YAML lists or single TOML docs).
    fn load_configs(&self, files: &[PathBuf]) -> Result<Vec<DeclarativeConfig>> {
        let mut all = Vec::new();
        for file in files {
            let content = std::fs::read_to_string(file)
                .with_context(|| format!("read {}", file.display()))?;
            let rel = file.strip_prefix(&self.config.local_path).unwrap_or(file);
            match file.extension().and_then(|e| e.to_str()) {
                Some("yaml") | Some("yml") => all.extend(
                    ConfigParser::parse_yaml(&content)
                        .with_context(|| format!("{}", rel.display()))?,
                ),
                Some("toml") => all.push(
                    ConfigParser::parse_toml(&content)
                        .with_context(|| format!("{}", rel.display()))?,
                ),
                _ => continue,
            }
        }
        let mut seen = std::collections::HashSet::new();
        for c in &all {
            if !seen.insert(c.metadata.name.as_str()) {
                bail!(
                    "resource name {:?} is defined more than once in the repository",
                    c.metadata.name
                );
            }
        }
        Ok(all)
    }

    /// One pass: fetch, and if the remote tip has not been processed yet,
    /// load + validate its configs and (with auto_apply) apply them.
    pub async fn sync(&mut self) -> Result<SyncResult> {
        let apply = self.config.auto_apply;
        self.sync_with(apply).await
    }

    /// [`sync`](Self::sync) with an explicit apply decision (the CLI's
    /// `--apply` / `--dry-run`).
    pub async fn sync_with(&mut self, apply: bool) -> Result<SyncResult> {
        let head = self.fetch_to_remote_tip()?;
        if self.processed_commit.as_deref() == Some(head.as_str()) {
            debug!("GitOps: {head} already processed");
            return Ok(SyncResult {
                updated: false,
                event: None,
            });
        }
        let (commit_hash, commit_message, author) = self.commit_details()?;
        let files = self.find_config_files()?;
        let mut event = GitSyncEvent {
            timestamp: Utc::now(),
            commit_hash,
            commit_message,
            author,
            files_changed: files
                .iter()
                .map(|p| {
                    p.strip_prefix(&self.config.local_path)
                        .unwrap_or(p)
                        .display()
                        .to_string()
                })
                .collect(),
            configs_found: 0,
            applied: false,
            changes_applied: 0,
            error: None,
        };

        let configs = match self.load_configs(&files) {
            Ok(c) => c,
            Err(e) => {
                // a broken commit is reported once and not retried until
                // the branch moves again
                event.error = Some(format!("{e:#}"));
                error!("GitOps: commit {head}: {e:#}");
                self.processed_commit = Some(head);
                self.add_to_history(event.clone()).await;
                return Ok(SyncResult {
                    updated: true,
                    event: Some(event),
                });
            }
        };
        event.configs_found = configs.len();
        info!(
            "GitOps: commit {} has {} resource(s) in {} file(s)",
            head,
            configs.len(),
            files.len()
        );

        if self.config.validate_before_apply {
            if let Some(e) = configs
                .iter()
                .find_map(|c| ConfigParser::validate_config(c).err())
            {
                event.error = Some(format!("validation failed: {e}"));
                error!("GitOps: commit {head}: validation failed: {e}");
                self.processed_commit = Some(head);
                self.add_to_history(event.clone()).await;
                return Ok(SyncResult {
                    updated: true,
                    event: Some(event),
                });
            }
        }

        let mut engine = self.apply_engine.write().await;
        if !apply {
            let diff = engine.diff(&configs)?;
            info!(
                "GitOps: auto_apply is off; {} change(s) waiting:\n{}",
                diff.total_changes(),
                patronus_config::apply::format_diff(&diff)
            );
            drop(engine);
            self.processed_commit = Some(head);
            self.add_to_history(event.clone()).await;
            return Ok(SyncResult {
                updated: true,
                event: Some(event),
            });
        }
        match engine.apply(configs).await {
            Ok(r) if r.success => {
                info!(
                    "GitOps: applied commit {head}: {} change(s)",
                    r.changes_applied
                );
                event.applied = true;
                event.changes_applied = r.changes_applied;
                self.processed_commit = Some(head);
            }
            Ok(r) => {
                // store rolled back; retried on the next sync
                let msg = format!(
                    "apply failed{}: {}",
                    if r.rollback_performed {
                        " (rolled back)"
                    } else {
                        ""
                    },
                    r.errors.join("; ")
                );
                error!("GitOps: commit {head}: {msg}");
                event.error = Some(msg);
            }
            Err(e) => {
                error!("GitOps: commit {head}: apply failed: {e}");
                event.error = Some(format!("apply failed: {e}"));
            }
        }
        drop(engine);
        self.add_to_history(event.clone()).await;
        Ok(SyncResult {
            updated: true,
            event: Some(event),
        })
    }

    /// Add event to sync history
    async fn add_to_history(&self, event: GitSyncEvent) {
        let mut history = self.sync_history.write().await;
        history.push(event);
        if history.len() > 100 {
            history.remove(0);
        }
    }

    /// Get sync history
    pub async fn get_history(&self) -> Vec<GitSyncEvent> {
        self.sync_history.read().await.clone()
    }

    /// Poll forever: one [`sync`](Self::sync) every `poll_interval_secs`
    /// (the first one right away). Errors (remote unreachable, ...) are
    /// logged and retried on the next tick.
    pub async fn run(&mut self) -> Result<()> {
        let secs = self.config.poll_interval_secs.max(5);
        info!(
            "GitOps: watching {} ({}) every {secs}s, auto_apply={}",
            self.config.repo_url, self.config.branch, self.config.auto_apply
        );
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = self.sync().await {
                error!("GitOps sync failed: {e:#}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use patronus_config::applier::{Applier, ApplierRegistry, ApplyReport, Phase};
    use patronus_config::declarative::ResourceKind;
    use patronus_config::store::ConfigStore;
    use std::sync::Mutex;

    /// Records what the engine dispatched to it.
    #[derive(Default)]
    struct Recorder {
        log: Mutex<Vec<String>>,
    }

    struct Rec(Arc<Recorder>);

    #[async_trait]
    impl Applier for Rec {
        fn name(&self) -> &'static str {
            "recorder"
        }
        fn phase(&self) -> Phase {
            Phase::Firewall
        }
        async fn apply(&self, _s: &ConfigStore) -> patronus_core::Result<ApplyReport> {
            self.0.log.lock().unwrap().push("apply".into());
            Ok(ApplyReport::default())
        }
        async fn render(&self, _s: &ConfigStore) -> patronus_core::Result<String> {
            Ok(String::new())
        }
        fn resource_kinds(&self) -> &'static [ResourceKind] {
            &[ResourceKind::FirewallRule]
        }
        async fn upsert_resource(
            &self,
            _s: &ConfigStore,
            c: &DeclarativeConfig,
        ) -> patronus_core::Result<()> {
            self.0
                .log
                .lock()
                .unwrap()
                .push(format!("upsert {}", c.metadata.name));
            Ok(())
        }
        async fn delete_resource(
            &self,
            _s: &ConfigStore,
            _k: &ResourceKind,
            n: &str,
        ) -> patronus_core::Result<()> {
            self.0.log.lock().unwrap().push(format!("delete {n}"));
            Ok(())
        }
    }

    fn rule(name: &str, port: u16) -> String {
        format!(
            "- apiVersion: patronus.firewall/v1\n  kind: FirewallRule\n  metadata:\n    name: {name}\n  spec:\n    action: allow\n    interface: \"@wan\"\n    source: {{ address: \"0.0.0.0/0\" }}\n    destination: {{ address: \"192.168.1.10\", ports: [{port}] }}\n    protocol: tcp\n    enabled: true\n"
        )
    }

    /// Replace the work tree with `files` and commit them.
    fn commit(repo: &Repository, files: &[(&str, &str)], msg: &str) -> git2::Oid {
        let root = repo.workdir().unwrap().to_path_buf();
        for e in std::fs::read_dir(&root).unwrap() {
            let p = e.unwrap().path();
            if p.file_name().unwrap() != ".git" {
                if p.is_dir() {
                    std::fs::remove_dir_all(&p).unwrap();
                } else {
                    std::fs::remove_file(&p).unwrap();
                }
            }
        }
        let mut idx = repo.index().unwrap();
        idx.clear().unwrap();
        for (f, c) in files {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, c).unwrap();
            idx.add_path(Path::new(f)).unwrap();
        }
        idx.write().unwrap();
        let tree = repo.find_tree(idx.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("QA", "qa@errant.solutions").unwrap();
        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parents)
            .unwrap()
    }

    async fn watcher(
        upstream: &Path,
        clone: &Path,
        state: &Path,
        auto_apply: bool,
    ) -> (GitOpsWatcher, Arc<Recorder>) {
        let rec = Arc::new(Recorder::default());
        let store = Arc::new(ConfigStore::open_in_memory().await.unwrap());
        let mut engine = ApplyEngine::new(state.to_path_buf())
            .with_target(store, ApplierRegistry::new().with(Rec(rec.clone())));
        engine.init().await.unwrap();
        let cfg = GitOpsConfig {
            repo_url: upstream.display().to_string(),
            branch: "main".into(),
            local_path: clone.to_path_buf(),
            config_path: Some("firewall".into()),
            auto_apply,
            ..Default::default()
        };
        let mut w = GitOpsWatcher::new(cfg, Arc::new(RwLock::new(engine)));
        w.init().await.unwrap();
        (w, rec)
    }

    fn upstream_repo(dir: &Path) -> Repository {
        git2::Repository::init_opts(dir, git2::RepositoryInitOptions::new().initial_head("main"))
            .unwrap()
    }

    fn log(rec: &Recorder) -> Vec<String> {
        rec.log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn the_initial_clone_is_applied_and_later_commits_add_change_and_delete() {
        let t = tempfile::tempdir().unwrap();
        let up = upstream_repo(&t.path().join("up"));
        commit(
            &up,
            &[
                ("firewall/web.yaml", &rule("allow-web", 443)),
                ("README.md", "not a config"),
            ],
            "first",
        );
        let (mut w, rec) = watcher(
            &t.path().join("up"),
            &t.path().join("clone"),
            &t.path().join("st"),
            true,
        )
        .await;

        // the commit that was there at clone time is applied (it used to be
        // skipped: only commits arriving after init were ever processed)
        let r = w.sync().await.unwrap();
        let ev = r.event.unwrap();
        assert!(r.updated && ev.applied, "{ev:?}");
        assert_eq!(ev.files_changed, vec!["firewall/web.yaml".to_string()]);
        assert_eq!(log(&rec), vec!["upsert allow-web", "apply"]);

        // nothing new upstream: nothing happens
        assert!(!w.sync().await.unwrap().updated);
        assert_eq!(log(&rec).len(), 2);

        // a new rule in a subdirectory + the old one removed
        commit(
            &up,
            &[("firewall/lan/ssh.yaml", &rule("allow-ssh", 22))],
            "swap",
        );
        let ev = w.sync().await.unwrap().event.unwrap();
        assert!(ev.applied, "{ev:?}");
        let l = log(&rec);
        assert!(l.contains(&"upsert allow-ssh".to_string()), "{l:?}");
        assert!(l.contains(&"delete allow-web".to_string()), "{l:?}");

        // a force-pushed (rewritten) branch is followed, not ignored
        let first = up
            .head()
            .unwrap()
            .peel_to_commit()
            .unwrap()
            .parent(0)
            .unwrap();
        up.reset(first.as_object(), git2::ResetType::Hard, None)
            .unwrap();
        commit(
            &up,
            &[("firewall/web.yaml", &rule("allow-web", 8443))],
            "rewrite",
        );
        let ev = w.sync().await.unwrap().event.unwrap();
        assert!(ev.applied, "{ev:?}");
        assert_eq!(ev.commit_message, "rewrite");
        let web = std::fs::read_to_string(t.path().join("clone/firewall/web.yaml")).unwrap();
        assert!(web.contains("8443"), "{web}");
        assert!(!t.path().join("clone/firewall/lan/ssh.yaml").exists());
    }

    #[tokio::test]
    async fn without_auto_apply_or_with_a_broken_commit_nothing_is_applied() {
        let t = tempfile::tempdir().unwrap();
        let up = upstream_repo(&t.path().join("up"));
        commit(
            &up,
            &[("firewall/web.yaml", &rule("allow-web", 443))],
            "first",
        );
        let (mut w, rec) = watcher(
            &t.path().join("up"),
            &t.path().join("clone"),
            &t.path().join("st"),
            false,
        )
        .await;
        let ev = w.sync().await.unwrap().event.unwrap();
        assert!(!ev.applied && ev.error.is_none(), "{ev:?}");
        assert_eq!(ev.configs_found, 1);
        assert!(log(&rec).is_empty());

        // a duplicate name / unparsable file is reported, not half-applied
        commit(
            &up,
            &[
                ("firewall/a.yaml", &rule("dup", 1)),
                ("firewall/b.yaml", &rule("dup", 2)),
            ],
            "dup",
        );
        let ev = w.sync_with(true).await.unwrap().event.unwrap();
        assert!(!ev.applied, "{ev:?}");
        assert!(ev.error.unwrap().contains("more than once"));
        commit(&up, &[("firewall/a.yaml", "- kind: [")], "garbage");
        let ev = w.sync_with(true).await.unwrap().event.unwrap();
        assert!(ev.error.is_some(), "{ev:?}");
        assert!(log(&rec).is_empty());
        assert_eq!(w.get_history().await.len(), 3);
    }

    #[tokio::test]
    async fn init_refuses_a_foreign_clone_or_a_non_git_directory() {
        let t = tempfile::tempdir().unwrap();
        let up = upstream_repo(&t.path().join("up"));
        commit(&up, &[("x.yaml", &rule("x", 1))], "first");
        let other = t.path().join("other");
        upstream_repo(&other);
        let engine = || Arc::new(RwLock::new(ApplyEngine::new(t.path().join("st"))));
        let cfg = |p: &Path| GitOpsConfig {
            repo_url: t.path().join("up").display().to_string(),
            local_path: p.to_path_buf(),
            ..Default::default()
        };
        assert!(GitOpsWatcher::new(cfg(&other), engine())
            .init()
            .await
            .is_err());
        let junk = t.path().join("junk");
        std::fs::create_dir_all(&junk).unwrap();
        std::fs::write(junk.join("f"), "x").unwrap();
        assert!(GitOpsWatcher::new(cfg(&junk), engine())
            .init()
            .await
            .is_err());
        let mut no_url = GitOpsWatcher::new(GitOpsConfig::default(), engine());
        assert!(no_url.init().await.is_err());
    }

    #[test]
    fn test_pattern_matching() {
        let watcher = GitOpsWatcher::new(
            GitOpsConfig::default(),
            Arc::new(RwLock::new(ApplyEngine::new(PathBuf::from(
                "/tmp/patronus-test",
            )))),
        );
        assert!(watcher.matches_pattern("config.yaml", "*.yaml"));
        assert!(watcher.matches_pattern("test.yml", "*.yml"));
        assert!(!watcher.matches_pattern("config.toml", "*.yaml"));
        assert!(!watcher.matches_pattern(".yaml", "a*.yaml"));
        assert!(watcher.matches_pattern("exact.txt", "exact.txt"));
    }
}
