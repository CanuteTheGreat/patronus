use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use git2::{Repository, RemoteCallbacks, FetchOptions};
use notify::{Watcher, RecursiveMode, Event};
use patronus_config::{ConfigParser, ApplyEngine, DeclarativeConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn, error, debug};

/// GitOps repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitOpsConfig {
    /// Git repository URL
    pub repo_url: String,

    /// Branch to watch
    pub branch: String,

    /// Local directory to clone/pull to
    pub local_path: PathBuf,

    /// Path within repo containing configs (e.g., "configs/")
    pub config_path: Option<String>,

    /// Poll interval in seconds (if not using webhooks)
    pub poll_interval_secs: u64,

    /// Auto-apply changes or require manual approval
    pub auto_apply: bool,

    /// SSH key path for private repos
    pub ssh_key_path: Option<PathBuf>,

    /// Username for Git authentication
    pub username: Option<String>,

    /// Password/token for Git authentication
    pub password: Option<String>,

    /// File patterns to watch (e.g., ["*.yaml", "*.yml"])
    pub file_patterns: Vec<String>,

    /// Validate configs before applying
    pub validate_before_apply: bool,
}

impl Default for GitOpsConfig {
    fn default() -> Self {
        Self {
            repo_url: String::new(),
            branch: "main".to_string(),
            local_path: PathBuf::from("/var/patronus/gitops"),
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
    pub error: Option<String>,
}

/// Result of a Git sync operation
#[derive(Debug)]
pub struct SyncResult {
    pub updated: bool,
    pub event: Option<GitSyncEvent>,
}

/// GitOps repository watcher
pub struct GitOpsWatcher {
    config: GitOpsConfig,
    apply_engine: Arc<RwLock<ApplyEngine>>,
    repo: Option<Repository>,
    last_commit: Option<String>,
    sync_history: Arc<RwLock<Vec<GitSyncEvent>>>,
}

impl GitOpsWatcher {
    /// Create a new GitOps watcher
    pub fn new(config: GitOpsConfig, apply_engine: Arc<RwLock<ApplyEngine>>) -> Self {
        Self {
            config,
            apply_engine,
            repo: None,
            last_commit: None,
            sync_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize the watcher - clone or open repository
    pub async fn init(&mut self) -> Result<()> {
        info!("Initializing GitOps watcher for {}", self.config.repo_url);

        // Create local directory if it doesn't exist
        if !self.config.local_path.exists() {
            tokio::fs::create_dir_all(&self.config.local_path).await
                .context("Failed to create local repo directory")?;
        }

        // Check if repo already exists
        if self.config.local_path.join(".git").exists() {
            info!("Opening existing repository at {:?}", self.config.local_path);
            self.repo = Some(Repository::open(&self.config.local_path)
                .context("Failed to open existing repository")?);
        } else {
            info!("Cloning repository from {}", self.config.repo_url);
            self.clone_repository()
                .context("Failed to clone repository")?;
        }

        // Get initial commit hash
        if let Some(repo) = &self.repo {
            self.last_commit = Some(self.get_current_commit_hash(repo)?);
            info!("Initial commit: {}", self.last_commit.as_ref().unwrap());
        }

        Ok(())
    }

    /// Clone the repository
    fn clone_repository(&mut self) -> Result<()> {
        let mut callbacks = RemoteCallbacks::new();

        // Setup authentication if provided
        if let Some(ssh_key) = &self.config.ssh_key_path {
            let ssh_key = ssh_key.clone();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                git2::Cred::ssh_key(
                    username_from_url.unwrap_or("git"),
                    None,
                    &ssh_key,
                    None,
                )
            });
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let username = username.clone();
            let password = password.clone();
            callbacks.credentials(move |_url, _username_from_url, _allowed_types| {
                git2::Cred::userpass_plaintext(&username, &password)
            });
        }

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);

        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fetch_options);
        builder.branch(&self.config.branch);

        self.repo = Some(builder.clone(&self.config.repo_url, &self.config.local_path)
            .context("Git clone failed")?);

        Ok(())
    }

    /// Pull latest changes from remote
    fn pull_changes(&mut self) -> Result<bool> {
        let repo = self.repo.as_ref()
            .context("Repository not initialized")?;

        // Get current commit before pull
        let old_commit = self.get_current_commit_hash(repo)?;

        // Fetch from remote
        let mut remote = repo.find_remote("origin")
            .context("Failed to find origin remote")?;

        let mut callbacks = RemoteCallbacks::new();

        // Setup authentication
        if let Some(ssh_key) = &self.config.ssh_key_path {
            let ssh_key = ssh_key.clone();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                git2::Cred::ssh_key(
                    username_from_url.unwrap_or("git"),
                    None,
                    &ssh_key,
                    None,
                )
            });
        } else if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            let username = username.clone();
            let password = password.clone();
            callbacks.credentials(move |_url, _username_from_url, _allowed_types| {
                git2::Cred::userpass_plaintext(&username, &password)
            });
        }

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);

        remote.fetch(&[&self.config.branch], Some(&mut fetch_options), None)
            .context("Git fetch failed")?;

        // Get reference to remote branch
        let fetch_head = repo.find_reference("FETCH_HEAD")
            .context("Failed to find FETCH_HEAD")?;
        let fetch_commit = repo.reference_to_annotated_commit(&fetch_head)
            .context("Failed to get fetch commit")?;

        // Perform merge analysis
        let (analysis, _) = repo.merge_analysis(&[&fetch_commit])
            .context("Merge analysis failed")?;

        if analysis.is_up_to_date() {
            debug!("Repository is up to date");
            return Ok(false);
        }

        if analysis.is_fast_forward() {
            // Fast-forward merge
            let refname = format!("refs/heads/{}", self.config.branch);
            let mut reference = repo.find_reference(&refname)
                .context("Failed to find branch reference")?;

            reference.set_target(fetch_commit.id(), "Fast-forward merge")
                .context("Failed to set reference target")?;

            repo.set_head(&refname)
                .context("Failed to set HEAD")?;

            repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                .context("Checkout failed")?;

            let new_commit = self.get_current_commit_hash(repo)?;
            debug!("Fast-forwarded from {} to {}", old_commit, new_commit);

            self.last_commit = Some(new_commit);
            return Ok(true);
        }

        warn!("Repository requires merge (not fast-forward) - this is not supported in auto-mode");
        Ok(false)
    }

    /// Get current commit hash
    fn get_current_commit_hash(&self, repo: &Repository) -> Result<String> {
        let head = repo.head()
            .context("Failed to get HEAD")?;
        let commit = head.peel_to_commit()
            .context("Failed to get commit")?;
        Ok(commit.id().to_string())
    }

    /// Get commit details
    fn get_commit_details(&self, repo: &Repository) -> Result<(String, String, String)> {
        let head = repo.head()?;
        let commit = head.peel_to_commit()?;

        let message = commit.message().unwrap_or("").to_string();
        let author = commit.author();
        let author_name = format!("{} <{}>",
            author.name().unwrap_or("Unknown"),
            author.email().unwrap_or("unknown@example.com")
        );
        let hash = commit.id().to_string();

        Ok((hash, message, author_name))
    }

    /// Find all config files in the repository
    async fn find_config_files(&self) -> Result<Vec<PathBuf>> {
        let base_path = if let Some(config_path) = &self.config.config_path {
            self.config.local_path.join(config_path)
        } else {
            self.config.local_path.clone()
        };

        let mut config_files = Vec::new();

        if !base_path.exists() {
            return Ok(config_files);
        }

        let mut entries = tokio::fs::read_dir(&base_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    // Check if file matches any of the patterns
                    for pattern in &self.config.file_patterns {
                        if self.matches_pattern(file_name, pattern) {
                            config_files.push(path.clone());
                            break;
                        }
                    }
                }
            }
        }

        Ok(config_files)
    }

    /// Simple pattern matching (supports * wildcard)
    fn matches_pattern(&self, file_name: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                file_name.starts_with(parts[0]) && file_name.ends_with(parts[1])
            } else {
                false
            }
        } else {
            file_name == pattern
        }
    }

    /// Load and parse all config files
    async fn load_configs(&self, files: &[PathBuf]) -> Result<Vec<DeclarativeConfig>> {
        let mut all_configs = Vec::new();

        for file in files {
            let content = tokio::fs::read_to_string(file).await
                .with_context(|| format!("Failed to read {:?}", file))?;

            // Determine format from extension
            let configs = if file.extension().and_then(|e| e.to_str()) == Some("yaml")
                || file.extension().and_then(|e| e.to_str()) == Some("yml") {
                ConfigParser::parse_yaml(&content)
                    .with_context(|| format!("Failed to parse YAML from {:?}", file))?
            } else if file.extension().and_then(|e| e.to_str()) == Some("toml") {
                vec![ConfigParser::parse_toml(&content)
                    .with_context(|| format!("Failed to parse TOML from {:?}", file))?]
            } else {
                continue; // Skip unknown formats
            };

            all_configs.extend(configs);
        }

        Ok(all_configs)
    }

    /// Perform a sync operation
    pub async fn sync(&mut self) -> Result<SyncResult> {
        debug!("Starting sync operation");

        // Pull latest changes
        let updated = self.pull_changes()
            .context("Failed to pull changes")?;

        if !updated {
            return Ok(SyncResult {
                updated: false,
                event: None,
            });
        }

        info!("Repository updated, processing configurations");

        // Get commit details
        let repo = self.repo.as_ref().unwrap();
        let (commit_hash, commit_message, author) = self.get_commit_details(repo)?;

        // Find config files
        let config_files = self.find_config_files().await
            .context("Failed to find config files")?;

        info!("Found {} config files", config_files.len());

        // Load configs
        let configs = self.load_configs(&config_files).await
            .context("Failed to load configurations")?;

        info!("Loaded {} configurations", configs.len());

        let mut event = GitSyncEvent {
            timestamp: Utc::now(),
            commit_hash,
            commit_message,
            author,
            files_changed: config_files.iter()
                .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(|s| s.to_string()))
                .collect(),
            configs_found: configs.len(),
            applied: false,
            error: None,
        };

        // Validate if required
        if self.config.validate_before_apply {
            for config in &configs {
                if let Err(e) = ConfigParser::validate_config(config) {
                    let error_msg = format!("Validation failed: {}", e);
                    error!("{}", error_msg);
                    event.error = Some(error_msg);
                    self.add_to_history(event.clone()).await;
                    return Ok(SyncResult {
                        updated: true,
                        event: Some(event),
                    });
                }
            }
        }

        // Apply if auto_apply is enabled
        if self.config.auto_apply {
            info!("Auto-applying {} configurations", configs.len());

            let mut engine = self.apply_engine.write().await;
            match engine.apply(configs).await {
                Ok(result) => {
                    info!("Successfully applied configurations: {} creates, {} updates, {} deletes",
                        result.creates, result.updates, result.deletes);
                    event.applied = true;
                }
                Err(e) => {
                    let error_msg = format!("Apply failed: {}", e);
                    error!("{}", error_msg);
                    event.error = Some(error_msg);
                }
            }
        } else {
            info!("Auto-apply disabled, configurations ready for manual review");
        }

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

        // Keep only last 100 events
        if history.len() > 100 {
            history.remove(0);
        }
    }

    /// Get sync history
    pub async fn get_history(&self) -> Vec<GitSyncEvent> {
        self.sync_history.read().await.clone()
    }

    /// Start polling for changes
    pub async fn start_polling(mut self: Arc<Self>) -> Result<()> {
        info!("Starting GitOps polling with interval {} seconds", self.config.poll_interval_secs);

        let interval = Duration::from_secs(self.config.poll_interval_secs);
        let mut ticker = time::interval(interval);

        loop {
            ticker.tick().await;

            // Clone Arc to get mutable access
            let watcher_clone = Arc::clone(&self);

            // Need to use interior mutability pattern here
            // In production, would use RwLock<GitOpsWatcher> or refactor
            match Arc::get_mut(&mut self) {
                Some(watcher) => {
                    if let Err(e) = watcher.sync().await {
                        error!("Sync failed: {}", e);
                    }
                }
                None => {
                    // Multiple references exist, can't get mutable access
                    warn!("Cannot sync: multiple references to watcher exist");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let watcher = GitOpsWatcher::new(
            GitOpsConfig::default(),
            Arc::new(RwLock::new(ApplyEngine::new(false))),
        );

        assert!(watcher.matches_pattern("config.yaml", "*.yaml"));
        assert!(watcher.matches_pattern("test.yml", "*.yml"));
        assert!(watcher.matches_pattern("firewall.yaml", "*.yaml"));
        assert!(!watcher.matches_pattern("config.toml", "*.yaml"));
        assert!(watcher.matches_pattern("exact.txt", "exact.txt"));
    }
}
