//! Application Steering by User/Group
//!
//! Routes traffic based on application type, user identity, and group membership

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Application identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppId {
    Http,
    Https,
    Ssh,
    Rdp,
    Zoom,
    Teams,
    Slack,
    Custom(String),
}

/// User/group identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId {
    pub username: String,
    pub groups: Vec<String>,
}

/// Steering policy
#[derive(Debug, Clone)]
pub struct SteeringPolicy {
    pub name: String,
    pub app: AppId,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub tunnel_id: u32,
    pub priority: u16,
}

/// Application steering engine
pub struct AppSteering {
    policies: Arc<RwLock<Vec<SteeringPolicy>>>,
    user_cache: Arc<RwLock<HashMap<Ipv4Addr, UserId>>>,
}

impl AppSteering {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(Vec::new())),
            user_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add steering policy
    pub async fn add_policy(&self, policy: SteeringPolicy) {
        let mut policies = self.policies.write().await;
        policies.push(policy);
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Find tunnel for traffic
    pub async fn select_tunnel(&self, src_ip: Ipv4Addr, app: AppId) -> Option<u32> {
        let policies = self.policies.read().await;
        let user_cache = self.user_cache.read().await;

        let user = user_cache.get(&src_ip)?;

        for policy in policies.iter() {
            if policy.app != app {
                continue;
            }

            if !policy.users.is_empty() && !policy.users.contains(&user.username) {
                continue;
            }

            if !policy.groups.is_empty() {
                let has_group = policy.groups.iter()
                    .any(|g| user.groups.contains(g));
                if !has_group {
                    continue;
                }
            }

            return Some(policy.tunnel_id);
        }

        None
    }

    /// Register user session
    pub async fn register_user(&self, ip: Ipv4Addr, user: UserId) {
        let mut cache = self.user_cache.write().await;
        cache.insert(ip, user);
    }
}

impl Default for AppSteering {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_steering() {
        let steering = AppSteering::new();

        let policy = SteeringPolicy {
            name: "Executive SSH".to_string(),
            app: AppId::Ssh,
            users: vec!["alice".to_string()],
            groups: vec!["executives".to_string()],
            tunnel_id: 1,
            priority: 100,
        };

        steering.add_policy(policy).await;

        let user = UserId {
            username: "alice".to_string(),
            groups: vec!["executives".to_string()],
        };

        let ip = "192.168.1.100".parse().unwrap();
        steering.register_user(ip, user).await;

        let tunnel = steering.select_tunnel(ip, AppId::Ssh).await;
        assert_eq!(tunnel, Some(1));
    }
}
