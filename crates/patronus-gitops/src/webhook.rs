use anyhow::{Context, Result};
use patronus_config::ApplyEngine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use crate::watcher::GitOpsWatcher;

/// GitHub webhook payload
#[derive(Debug, Deserialize)]
pub struct GitHubWebhook {
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub repository: GitHubRepository,
    pub pusher: GitHubUser,
    pub commits: Vec<GitHubCommit>,
}

#[derive(Debug, Deserialize)]
pub struct GitHubRepository {
    pub name: String,
    pub full_name: String,
    pub clone_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubUser {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct GitHubCommit {
    pub id: String,
    pub message: String,
    pub author: GitHubUser,
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// GitLab webhook payload
#[derive(Debug, Deserialize)]
pub struct GitLabWebhook {
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub project: GitLabProject,
    pub user_name: String,
    pub user_email: String,
    pub commits: Vec<GitLabCommit>,
}

#[derive(Debug, Deserialize)]
pub struct GitLabProject {
    pub name: String,
    pub git_http_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GitLabCommit {
    pub id: String,
    pub message: String,
    pub author: GitLabAuthor,
    pub modified: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GitLabAuthor {
    pub name: String,
    pub email: String,
}

/// Generic webhook event
#[derive(Debug, Serialize)]
pub struct WebhookEvent {
    pub provider: WebhookProvider,
    pub repository: String,
    pub branch: String,
    pub commit_id: String,
    pub commit_message: String,
    pub author: String,
    pub files_changed: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum WebhookProvider {
    GitHub,
    GitLab,
    Gitea,
    Generic,
}

/// Webhook server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Listen address
    pub listen_addr: String,

    /// Listen port
    pub port: u16,

    /// Webhook secret for validation
    pub secret: Option<String>,

    /// Expected provider
    pub provider: WebhookProvider,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            port: 9999,
            secret: None,
            provider: WebhookProvider::Generic,
        }
    }
}

/// Webhook handler
pub struct WebhookHandler {
    config: WebhookConfig,
    watcher: Arc<RwLock<GitOpsWatcher>>,
}

impl WebhookHandler {
    pub fn new(config: WebhookConfig, watcher: Arc<RwLock<GitOpsWatcher>>) -> Self {
        Self { config, watcher }
    }

    /// Parse GitHub webhook payload
    pub fn parse_github(&self, payload: &str) -> Result<WebhookEvent> {
        let webhook: GitHubWebhook = serde_json::from_str(payload)
            .context("Failed to parse GitHub webhook")?;

        // Extract branch from ref (refs/heads/main -> main)
        let branch = webhook.git_ref
            .strip_prefix("refs/heads/")
            .unwrap_or(&webhook.git_ref)
            .to_string();

        let latest_commit = webhook.commits.last()
            .context("No commits in webhook")?;

        let mut files_changed = Vec::new();
        files_changed.extend(latest_commit.modified.clone());
        files_changed.extend(latest_commit.added.clone());
        files_changed.extend(latest_commit.removed.clone());

        Ok(WebhookEvent {
            provider: WebhookProvider::GitHub,
            repository: webhook.repository.full_name,
            branch,
            commit_id: latest_commit.id.clone(),
            commit_message: latest_commit.message.clone(),
            author: format!("{} <{}>", latest_commit.author.name, latest_commit.author.email),
            files_changed,
        })
    }

    /// Parse GitLab webhook payload
    pub fn parse_gitlab(&self, payload: &str) -> Result<WebhookEvent> {
        let webhook: GitLabWebhook = serde_json::from_str(payload)
            .context("Failed to parse GitLab webhook")?;

        let branch = webhook.git_ref
            .strip_prefix("refs/heads/")
            .unwrap_or(&webhook.git_ref)
            .to_string();

        let latest_commit = webhook.commits.last()
            .context("No commits in webhook")?;

        let mut files_changed = Vec::new();
        files_changed.extend(latest_commit.modified.clone());
        files_changed.extend(latest_commit.added.clone());
        files_changed.extend(latest_commit.removed.clone());

        Ok(WebhookEvent {
            provider: WebhookProvider::GitLab,
            repository: webhook.project.name,
            branch,
            commit_id: latest_commit.id.clone(),
            commit_message: latest_commit.message.clone(),
            author: format!("{} <{}>", latest_commit.author.name, latest_commit.author.email),
            files_changed,
        })
    }

    /// Handle webhook event
    pub async fn handle_event(&self, event: WebhookEvent) -> Result<()> {
        info!("Received webhook from {}: {} - {}",
            event.repository, event.commit_id, event.commit_message);

        // Trigger sync in watcher
        let mut watcher = self.watcher.write().await;
        match watcher.sync().await {
            Ok(result) => {
                if result.updated {
                    info!("Webhook triggered successful sync");
                } else {
                    info!("Webhook received but no updates needed");
                }
                Ok(())
            }
            Err(e) => {
                error!("Webhook sync failed: {}", e);
                Err(e)
            }
        }
    }

    /// Verify webhook signature (for GitHub)
    pub fn verify_github_signature(&self, payload: &[u8], signature: &str) -> bool {
        if let Some(secret) = &self.config.secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            type HmacSha256 = Hmac<Sha256>;

            if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                mac.update(payload);

                // GitHub sends "sha256=<hash>"
                if let Some(hash) = signature.strip_prefix("sha256=") {
                    if let Ok(expected) = hex::decode(hash) {
                        return mac.verify_slice(&expected).is_ok();
                    }
                }
            }
            false
        } else {
            // No secret configured, accept all
            warn!("No webhook secret configured, accepting all webhooks");
            true
        }
    }

    /// Verify webhook signature (for GitLab)
    pub fn verify_gitlab_token(&self, token: &str) -> bool {
        if let Some(secret) = &self.config.secret {
            token == secret
        } else {
            warn!("No webhook secret configured, accepting all webhooks");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_webhook() {
        let payload = r#"{
            "ref": "refs/heads/main",
            "repository": {
                "name": "patronus-config",
                "full_name": "myorg/patronus-config",
                "clone_url": "https://github.com/myorg/patronus-config.git"
            },
            "pusher": {
                "name": "john",
                "email": "john@example.com"
            },
            "commits": [{
                "id": "abc123",
                "message": "Update firewall rules",
                "author": {
                    "name": "John Doe",
                    "email": "john@example.com"
                },
                "modified": ["firewall.yaml"],
                "added": [],
                "removed": []
            }]
        }"#;

        let handler = WebhookHandler::new(
            WebhookConfig::default(),
            Arc::new(RwLock::new(GitOpsWatcher::new(
                Default::default(),
                Arc::new(RwLock::new(ApplyEngine::new(false))),
            ))),
        );

        let event = handler.parse_github(payload).unwrap();
        assert_eq!(event.branch, "main");
        assert_eq!(event.commit_id, "abc123");
        assert_eq!(event.files_changed, vec!["firewall.yaml"]);
    }
}
