//! Audit logging for security events

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::IpAddr;
use tracing::{error, info};

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    /// User login attempt
    LoginAttempt { success: bool, reason: Option<String> },
    /// User logout
    Logout,
    /// Password change
    PasswordChange { success: bool },
    /// MFA enrollment
    MfaEnroll { method: String },
    /// MFA verification
    MfaVerify { success: bool, method: String },
    /// Token refresh
    TokenRefresh,
    /// Token revocation
    TokenRevoke { token_id: String },
    /// API key creation
    ApiKeyCreate { key_id: String },
    /// API key revocation
    ApiKeyRevoke { key_id: String },
    /// Permission grant
    PermissionGrant { target_user: String, permission: String },
    /// Permission revoke
    PermissionRevoke { target_user: String, permission: String },
    /// Resource access
    ResourceAccess { resource_type: String, resource_id: String, action: String },
    /// Security policy change
    PolicyChange { policy: String, change: String },
    /// Failed authorization
    AuthorizationFailed { resource: String, required_role: String },
    /// Suspicious activity detected
    SuspiciousActivity { description: String },

    // GraphQL Mutation Events (Sprint 25)
    /// Site created
    SiteCreate { site_id: String, site_name: String },
    /// Site updated
    SiteUpdate { site_id: String, fields_changed: Vec<String> },
    /// Site delete attempted
    SiteDelete { site_id: String, blocked: bool },
    /// Policy created
    PolicyCreate { policy_id: u64, policy_name: String, priority: u32 },
    /// Policy updated
    PolicyUpdate { policy_id: u64, fields_changed: Vec<String> },
    /// Policy deleted
    PolicyDelete { policy_id: u64, policy_name: String },
    /// Policy toggled
    PolicyToggle { policy_id: u64, enabled: bool },
    /// User created
    UserCreate { user_id: String, email: String, role: String },
    /// User role updated
    UserRoleUpdate { user_id: String, old_role: String, new_role: String },
    /// User deactivated
    UserDeactivate { user_id: String, email: String },
    /// User password reset
    PasswordReset { user_id: String, by_admin: bool },
    /// Path health check
    PathHealthCheck { path_id: u64 },
    /// Path failover
    PathFailover { path_id: u64, reason: String },
    /// Cache cleared
    CacheClear,
    /// System health check
    SystemHealthCheck,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub event_type: String,
    pub event_data: String,
    pub success: bool,
    pub severity: String,
}

/// Audit severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    pool: SqlitePool,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Initialize audit log table
    pub async fn init(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                user_email TEXT,
                ip_address TEXT,
                user_agent TEXT,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                success INTEGER NOT NULL,
                severity TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes for common queries
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, timestamp DESC)"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type, timestamp DESC)"
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs(severity, timestamp DESC)"
        )
        .execute(&self.pool)
        .await?;

        info!("Audit log table initialized");
        Ok(())
    }

    /// Log an audit event
    pub async fn log(
        &self,
        event: AuditEvent,
        user_id: Option<String>,
        user_email: Option<String>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> anyhow::Result<()> {
        let (event_type, event_data, success, severity) = self.serialize_event(&event);

        let ip_str = ip_address.map(|ip| ip.to_string());

        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                timestamp, user_id, user_email, ip_address, user_agent,
                event_type, event_data, success, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(Utc::now().to_rfc3339())
        .bind(&user_id)
        .bind(&user_email)
        .bind(&ip_str)
        .bind(&user_agent)
        .bind(&event_type)
        .bind(&event_data)
        .bind(success as i32)
        .bind(severity.as_str())
        .execute(&self.pool)
        .await?;

        // Log to tracing as well
        match severity {
            AuditSeverity::Critical => {
                error!(
                    user_id = ?user_id,
                    event = event_type,
                    "Critical security event"
                );
            }
            AuditSeverity::Warning => {
                tracing::warn!(
                    user_id = ?user_id,
                    event = event_type,
                    "Security warning"
                );
            }
            AuditSeverity::Info => {
                info!(
                    user_id = ?user_id,
                    event = event_type,
                    "Security event"
                );
            }
        }

        Ok(())
    }

    /// Serialize event to string and determine severity
    fn serialize_event(&self, event: &AuditEvent) -> (String, String, bool, AuditSeverity) {
        let event_type = match event {
            AuditEvent::LoginAttempt { .. } => "login_attempt",
            AuditEvent::Logout => "logout",
            AuditEvent::PasswordChange { .. } => "password_change",
            AuditEvent::MfaEnroll { .. } => "mfa_enroll",
            AuditEvent::MfaVerify { .. } => "mfa_verify",
            AuditEvent::TokenRefresh => "token_refresh",
            AuditEvent::TokenRevoke { .. } => "token_revoke",
            AuditEvent::ApiKeyCreate { .. } => "api_key_create",
            AuditEvent::ApiKeyRevoke { .. } => "api_key_revoke",
            AuditEvent::PermissionGrant { .. } => "permission_grant",
            AuditEvent::PermissionRevoke { .. } => "permission_revoke",
            AuditEvent::ResourceAccess { .. } => "resource_access",
            AuditEvent::PolicyChange { .. } => "policy_change",
            AuditEvent::AuthorizationFailed { .. } => "authorization_failed",
            AuditEvent::SuspiciousActivity { .. } => "suspicious_activity",
            // GraphQL mutation events
            AuditEvent::SiteCreate { .. } => "site_create",
            AuditEvent::SiteUpdate { .. } => "site_update",
            AuditEvent::SiteDelete { .. } => "site_delete",
            AuditEvent::PolicyCreate { .. } => "policy_create",
            AuditEvent::PolicyUpdate { .. } => "policy_update",
            AuditEvent::PolicyDelete { .. } => "policy_delete",
            AuditEvent::PolicyToggle { .. } => "policy_toggle",
            AuditEvent::UserCreate { .. } => "user_create",
            AuditEvent::UserRoleUpdate { .. } => "user_role_update",
            AuditEvent::UserDeactivate { .. } => "user_deactivate",
            AuditEvent::PasswordReset { .. } => "password_reset",
            AuditEvent::PathHealthCheck { .. } => "path_health_check",
            AuditEvent::PathFailover { .. } => "path_failover",
            AuditEvent::CacheClear => "cache_clear",
            AuditEvent::SystemHealthCheck => "system_health_check",
        };

        let event_data = serde_json::to_string(event).unwrap_or_default();

        let success = match event {
            AuditEvent::LoginAttempt { success, .. } => *success,
            AuditEvent::PasswordChange { success } => *success,
            AuditEvent::MfaVerify { success, .. } => *success,
            AuditEvent::AuthorizationFailed { .. } => false,
            AuditEvent::SuspiciousActivity { .. } => false,
            AuditEvent::SiteDelete { blocked, .. } => !*blocked,  // Success if not blocked
            _ => true,
        };

        let severity = match event {
            AuditEvent::SuspiciousActivity { .. } => AuditSeverity::Critical,
            AuditEvent::AuthorizationFailed { .. } => AuditSeverity::Warning,
            AuditEvent::LoginAttempt { success: false, .. } => AuditSeverity::Warning,
            AuditEvent::PolicyChange { .. } => AuditSeverity::Warning,
            AuditEvent::PermissionGrant { .. } | AuditEvent::PermissionRevoke { .. } => {
                AuditSeverity::Warning
            }
            // Mutation events with elevated severity
            AuditEvent::SiteDelete { .. } => AuditSeverity::Warning,
            AuditEvent::PolicyDelete { .. } => AuditSeverity::Warning,
            AuditEvent::UserCreate { .. } => AuditSeverity::Warning,
            AuditEvent::UserRoleUpdate { .. } => AuditSeverity::Warning,
            AuditEvent::UserDeactivate { .. } => AuditSeverity::Warning,
            AuditEvent::PasswordReset { .. } => AuditSeverity::Warning,
            AuditEvent::PathFailover { .. } => AuditSeverity::Warning,
            _ => AuditSeverity::Info,
        };

        (event_type.to_string(), event_data, success, severity)
    }

    /// Get audit logs for a user
    pub async fn get_user_logs(
        &self,
        user_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>, Option<String>, String, String, i32, String)>(
            "SELECT id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity
             FROM audit_logs
             WHERE user_id = ?
             ORDER BY timestamp DESC
             LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity)| {
            AuditLog {
                id,
                timestamp: DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&Utc),
                user_id,
                user_email,
                ip_address,
                user_agent,
                event_type,
                event_data,
                success: success != 0,
                severity,
            }
        })
        .collect();

        Ok(logs)
    }

    /// Get recent critical events
    pub async fn get_critical_events(&self, limit: i64) -> anyhow::Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>, Option<String>, String, String, i32, String)>(
            "SELECT id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity
             FROM audit_logs
             WHERE severity = 'critical'
             ORDER BY timestamp DESC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity)| {
            AuditLog {
                id,
                timestamp: DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&Utc),
                user_id,
                user_email,
                ip_address,
                user_agent,
                event_type,
                event_data,
                success: success != 0,
                severity,
            }
        })
        .collect();

        Ok(logs)
    }

    /// Get failed login attempts for an IP
    pub async fn get_failed_logins(
        &self,
        ip_address: IpAddr,
        since: DateTime<Utc>,
    ) -> anyhow::Result<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_logs
             WHERE event_type = 'login_attempt'
             AND success = 0
             AND ip_address = ?
             AND timestamp >= ?",
        )
        .bind(ip_address.to_string())
        .bind(since.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }

    /// Get all audit logs with optional filters
    pub async fn get_logs(
        &self,
        event_type: Option<String>,
        severity: Option<String>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: i64,
    ) -> anyhow::Result<Vec<AuditLog>> {
        let mut query = String::from(
            "SELECT id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity
             FROM audit_logs WHERE 1=1"
        );

        let mut params: Vec<String> = Vec::new();

        if let Some(et) = event_type {
            query.push_str(" AND event_type = ?");
            params.push(et);
        }

        if let Some(sev) = severity {
            query.push_str(" AND severity = ?");
            params.push(sev);
        }

        if let Some(start) = since {
            query.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }

        if let Some(end) = until {
            query.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ?");

        let mut sqlx_query = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>, Option<String>, String, String, i32, String)>(&query);

        for param in &params {
            sqlx_query = sqlx_query.bind(param);
        }
        sqlx_query = sqlx_query.bind(limit);

        let logs = sqlx_query
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|(id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity)| {
                AuditLog {
                    id,
                    timestamp: DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&Utc),
                    user_id,
                    user_email,
                    ip_address,
                    user_agent,
                    event_type,
                    event_data,
                    success: success != 0,
                    severity,
                }
            })
            .collect();

        Ok(logs)
    }

    /// Get mutation audit logs (Sprint 25)
    pub async fn get_mutation_logs(
        &self,
        limit: i64,
    ) -> anyhow::Result<Vec<AuditLog>> {
        let mutation_events = vec![
            "site_create", "site_update", "site_delete",
            "policy_create", "policy_update", "policy_delete", "policy_toggle",
            "user_create", "user_role_update", "user_deactivate", "password_reset",
            "path_health_check", "path_failover", "cache_clear", "system_health_check"
        ];

        let placeholders = mutation_events.iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            "SELECT id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity
             FROM audit_logs
             WHERE event_type IN ({})
             ORDER BY timestamp DESC
             LIMIT ?",
            placeholders
        );

        let mut sqlx_query = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>, Option<String>, String, String, i32, String)>(&query);

        for event in &mutation_events {
            sqlx_query = sqlx_query.bind(event);
        }
        sqlx_query = sqlx_query.bind(limit);

        let logs = sqlx_query
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|(id, timestamp, user_id, user_email, ip_address, user_agent, event_type, event_data, success, severity)| {
                AuditLog {
                    id,
                    timestamp: DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&Utc),
                    user_id,
                    user_email,
                    ip_address,
                    user_agent,
                    event_type,
                    event_data,
                    success: success != 0,
                    severity,
                }
            })
            .collect();

        Ok(logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_db() -> SqlitePool {
        SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_audit_logger_init() {
        let pool = setup_test_db().await;
        let logger = AuditLogger::new(pool);

        assert!(logger.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_log_event() {
        let pool = setup_test_db().await;
        let logger = AuditLogger::new(pool);
        logger.init().await.unwrap();

        let event = AuditEvent::LoginAttempt {
            success: true,
            reason: None,
        };

        assert!(logger
            .log(
                event,
                Some("user123".to_string()),
                Some("user@example.com".to_string()),
                Some("192.168.1.1".parse().unwrap()),
                Some("Mozilla/5.0".to_string())
            )
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_get_user_logs() {
        let pool = setup_test_db().await;
        let logger = AuditLogger::new(pool);
        logger.init().await.unwrap();

        // Log some events
        for i in 0..5 {
            let event = AuditEvent::LoginAttempt {
                success: i % 2 == 0,
                reason: None,
            };

            logger
                .log(event, Some("user123".to_string()), None, None, None)
                .await
                .unwrap();
        }

        let logs = logger.get_user_logs("user123", 10).await.unwrap();
        assert_eq!(logs.len(), 5);
    }

    #[tokio::test]
    async fn test_failed_login_count() {
        let pool = setup_test_db().await;
        let logger = AuditLogger::new(pool);
        logger.init().await.unwrap();

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Log failed attempts
        for _ in 0..3 {
            let event = AuditEvent::LoginAttempt {
                success: false,
                reason: Some("Invalid credentials".to_string()),
            };

            logger
                .log(event, None, None, Some(ip), None)
                .await
                .unwrap();
        }

        let since = Utc::now() - chrono::Duration::minutes(5);
        let count = logger.get_failed_logins(ip, since).await.unwrap();

        assert_eq!(count, 3);
    }
}
