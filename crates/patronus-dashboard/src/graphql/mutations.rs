// GraphQL Mutations - Write operations
//
// This module implements all GraphQL mutation resolvers for creating,
// updating, and deleting data.
//
// Sprint 25: All mutations include audit logging for compliance tracking

use async_graphql::{Context, Object, Result};
use chrono::Utc;
use crate::graphql::{
    types::*,
    get_state,
};
use crate::security::audit::AuditEvent;

/// Helper function to get user info from auth context for audit logging
fn get_audit_user_info(ctx: &Context<'_>) -> (Option<String>, Option<String>) {
    if let Ok(auth_ctx) = ctx.data::<crate::graphql::AuthContext>() {
        if let Some(claims) = &auth_ctx.claims {
            return (Some(claims.sub.clone()), Some(claims.email.clone()));
        }
    }
    (None, None)
}

/// Root mutation object
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    // ========== Site Mutations ==========

    /// Create a new site
    async fn create_site(
        &self,
        ctx: &Context<'_>,
        input: CreateSiteInput,
    ) -> Result<GqlSite> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Validate input
        if input.name.trim().is_empty() {
            return Err(async_graphql::Error::new("Site name cannot be empty"));
        }

        // Create site object
        use patronus_sdwan::types::{Site, SiteId, SiteStatus as SdwanSiteStatus};
        let site_id = SiteId::generate();

        let site = Site {
            id: site_id,
            name: input.name.clone(),
            public_key: vec![0; 32], // Generate proper key in production
            endpoints: Vec::new(),
            created_at: std::time::SystemTime::now(),
            last_seen: std::time::SystemTime::now(),
            status: SdwanSiteStatus::Active,
        };

        // Insert into database
        state.db.upsert_site(&site).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create site: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::SiteCreate {
                site_id: site_id.to_string(),
                site_name: input.name.clone(),
            },
            user_id,
            user_email,
            None, // IP address
            None, // User agent
        ).await;

        let result = GqlSite {
            id: site_id.to_string(),
            name: input.name.clone(),
            location: input.location.clone(),
            endpoint_count: 0,
            status: SiteStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "SITE_CREATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "site_id": site_id.to_string(),
                "site_name": input.name,
                "location": input.location,
                "created_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Update an existing site
    async fn update_site(
        &self,
        ctx: &Context<'_>,
        input: UpdateSiteInput,
    ) -> Result<GqlSite> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse site ID
        use patronus_sdwan::types::SiteId;
        let site_id: SiteId = input.id.parse()
            .map_err(|_| async_graphql::Error::new("Invalid site ID"))?;

        // Get existing site from database
        let mut site = state.db.get_site(&site_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("Site not found"))?;

        // Track changed fields for audit log
        let mut fields_changed = Vec::new();

        // Update fields
        if let Some(name) = &input.name {
            if name.trim().is_empty() {
                return Err(async_graphql::Error::new("Site name cannot be empty"));
            }
            site.name = name.clone();
            fields_changed.push("name".to_string());
        }

        if let Some(status) = input.status {
            use patronus_sdwan::types::SiteStatus as SdwanSiteStatus;
            site.status = match status {
                SiteStatus::Active => SdwanSiteStatus::Active,
                SiteStatus::Degraded => SdwanSiteStatus::Degraded,
                SiteStatus::Offline => SdwanSiteStatus::Inactive,
                SiteStatus::Maintenance => SdwanSiteStatus::Inactive, // Map maintenance to inactive
            };
            fields_changed.push("status".to_string());
        }

        if input.location.is_some() {
            fields_changed.push("location".to_string());
        }

        site.last_seen = std::time::SystemTime::now();

        // Update in database
        state.db.upsert_site(&site).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update site: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::SiteUpdate {
                site_id: site.id.to_string(),
                fields_changed: fields_changed.clone(),
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        let result = GqlSite {
            id: site.id.to_string(),
            name: site.name.clone(),
            location: input.location.clone(),
            endpoint_count: site.endpoints.len() as i32,
            status: match site.status {
                patronus_sdwan::types::SiteStatus::Active => SiteStatus::Active,
                patronus_sdwan::types::SiteStatus::Degraded => SiteStatus::Degraded,
                patronus_sdwan::types::SiteStatus::Inactive => SiteStatus::Offline,
            },
            created_at: chrono::DateTime::from_timestamp(
                site.created_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                0
            ).unwrap_or_else(|| Utc::now()),
            updated_at: Utc::now(),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "SITE_UPDATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "site_id": site.id.to_string(),
                "site_name": site.name,
                "fields_changed": fields_changed,
                "updated_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Delete a site
    async fn delete_site(
        &self,
        ctx: &Context<'_>,
        id: String,
    ) -> Result<bool> {
        // Require admin role for deletion
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Parse site ID
        use patronus_sdwan::types::SiteId;
        let site_id: SiteId = id.parse()
            .map_err(|_| async_graphql::Error::new("Invalid site ID"))?;

        // Check if site exists
        let site = state.db.get_site(&site_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("Site not found"))?;

        // Check for active paths (Sprint 30)
        let path_count = state.db.count_site_paths(&site_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)

        // Delete site and cascade to paths and endpoints (Sprint 30)
        let rows_affected = state.db.delete_site(&site_id).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete site: {}", e)))?;

        let _ = state.audit_logger.log(
            AuditEvent::SiteDelete {
                site_id: site_id.to_string(),
                blocked: false,
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "SITE_DELETED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "site_id": site_id.to_string(),
                "site_name": site.name,
                "paths_deleted": path_count,
                "rows_affected": rows_affected,
                "deleted_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(true)
    }

    // ========== Policy Mutations ==========

    /// Create a new traffic policy
    async fn create_policy(
        &self,
        ctx: &Context<'_>,
        input: CreatePolicyInput,
    ) -> Result<GqlPolicy> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Validate input
        if input.name.trim().is_empty() {
            return Err(async_graphql::Error::new("Policy name cannot be empty"));
        }

        if input.priority < 0 || input.priority > 1000 {
            return Err(async_graphql::Error::new("Priority must be between 0 and 1000"));
        }

        // Parse match_rules JSON
        use patronus_sdwan::policy::{MatchRules, PathPreference, RoutingPolicy};
        let match_rules: MatchRules = serde_json::from_str(&input.match_rules)
            .map_err(|e| async_graphql::Error::new(format!("Invalid match_rules JSON: {}", e)))?;

        // Map GraphQL action to PathPreference
        let path_preference = match input.action {
            PolicyAction::Route => PathPreference::LowestLatency, // Default for routing
            PolicyAction::Qos => PathPreference::LowestLatency,
            PolicyAction::Allow => PathPreference::LowestLatency,
            PolicyAction::Deny => PathPreference::LowestLatency,
        };

        // Generate policy ID
        let policy_id = uuid::Uuid::new_v4().as_u128() as u64;

        let policy = RoutingPolicy {
            id: policy_id,
            name: input.name.clone(),
            priority: input.priority as u32,
            match_rules,
            path_preference,
            enabled: true,
        };

        // Insert into database
        state.db.upsert_policy(&policy).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create policy: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PolicyCreate {
                policy_id,
                policy_name: input.name.clone(),
                priority: input.priority as u32,
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // New policies start with zero stats (Sprint 30)
        let result = GqlPolicy {
            id: policy_id.to_string(),
            name: input.name.clone(),
            description: input.description.clone(),
            priority: input.priority,
            match_rules: input.match_rules,
            action: input.action,
            enabled: true,
            packets_matched: 0,
            bytes_matched: 0,
            created_at: Utc::now(),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "POLICY_CREATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "policy_id": policy_id.to_string(),
                "policy_name": input.name,
                "priority": input.priority,
                "action": format!("{:?}", input.action),
                "created_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Update an existing policy
    async fn update_policy(
        &self,
        ctx: &Context<'_>,
        input: UpdatePolicyInput,
    ) -> Result<GqlPolicy> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse policy ID
        let policy_id = input.id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid policy ID"))?;

        // Get existing policy from database
        let mut policy = state.db.get_policy(policy_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("Policy not found"))?;

        // Track changed fields for audit log
        let mut fields_changed = Vec::new();

        // Update fields
        if let Some(name) = input.name {
            if name.trim().is_empty() {
                return Err(async_graphql::Error::new("Policy name cannot be empty"));
            }
            policy.name = name;
            fields_changed.push("name".to_string());
        }

        if let Some(priority) = input.priority {
            if priority < 0 || priority > 1000 {
                return Err(async_graphql::Error::new("Priority must be between 0 and 1000"));
            }
            policy.priority = priority as u32;
            fields_changed.push("priority".to_string());
        }

        if let Some(match_rules_json) = input.match_rules {
            use patronus_sdwan::policy::MatchRules;
            policy.match_rules = serde_json::from_str(&match_rules_json)
                .map_err(|e| async_graphql::Error::new(format!("Invalid match_rules JSON: {}", e)))?;
            fields_changed.push("match_rules".to_string());
        }

        if let Some(enabled) = input.enabled {
            policy.enabled = enabled;
            fields_changed.push("enabled".to_string());
        }

        // Update in database
        state.db.upsert_policy(&policy).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update policy: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PolicyUpdate {
                policy_id,
                fields_changed: fields_changed.clone(),
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Get traffic stats (Sprint 30)
        let stats = state.traffic_stats.get_policy_stats(policy_id).await.unwrap_or_default();

        let result = GqlPolicy {
            id: policy.id.to_string(),
            name: policy.name.clone(),
            description: input.description,
            priority: policy.priority as i32,
            match_rules: serde_json::to_string(&policy.match_rules).unwrap_or_default(),
            action: PolicyAction::Route, // TODO: Map from PathPreference
            enabled: policy.enabled,
            packets_matched: stats.packets_matched as i64,
            bytes_matched: stats.bytes_matched as i64,
            created_at: Utc::now(),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "POLICY_UPDATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "policy_id": policy_id.to_string(),
                "policy_name": policy.name,
                "fields_changed": fields_changed,
                "updated_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Delete a policy
    async fn delete_policy(
        &self,
        ctx: &Context<'_>,
        id: String,
    ) -> Result<bool> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse policy ID
        let policy_id = id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid policy ID"))?;

        // Check if policy exists
        let policy = state.db.get_policy(policy_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("Policy not found"))?;

        // Delete from database
        state.db.delete_policy(policy_id).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to delete policy: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PolicyDelete {
                policy_id,
                policy_name: policy.name.clone(),
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "POLICY_DELETED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "policy_id": policy_id.to_string(),
                "policy_name": policy.name,
                "deleted_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(true)
    }

    /// Enable or disable a policy
    async fn toggle_policy(
        &self,
        ctx: &Context<'_>,
        id: String,
        enabled: bool,
    ) -> Result<GqlPolicy> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse policy ID
        let policy_id = id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid policy ID"))?;

        // Get existing policy
        let mut policy = state.db.get_policy(policy_id).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("Policy not found"))?;

        // Toggle enabled state
        policy.enabled = enabled;

        // Update in database
        state.db.upsert_policy(&policy).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to toggle policy: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PolicyToggle {
                policy_id,
                enabled,
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Get traffic stats (Sprint 30)
        let stats = state.traffic_stats.get_policy_stats(policy_id).await.unwrap_or_default();

        let result = GqlPolicy {
            id: policy.id.to_string(),
            name: policy.name.clone(),
            description: None,
            priority: policy.priority as i32,
            match_rules: serde_json::to_string(&policy.match_rules).unwrap_or_default(),
            action: PolicyAction::Route, // TODO: Map from PathPreference
            enabled: policy.enabled,
            packets_matched: stats.packets_matched as i64,
            bytes_matched: stats.bytes_matched as i64,
            created_at: Utc::now(),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "POLICY_TOGGLED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "policy_id": policy_id.to_string(),
                "policy_name": policy.name,
                "enabled": enabled,
                "toggled_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    // ========== User Mutations ==========

    /// Create a new user (admin only)
    async fn create_user(
        &self,
        ctx: &Context<'_>,
        input: CreateUserInput,
    ) -> Result<GqlUser> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Validate email format
        if !input.email.contains('@') {
            return Err(async_graphql::Error::new("Invalid email format"));
        }

        // Validate password strength
        use crate::auth::password::validate_password_strength;
        if let Err(e) = validate_password_strength(&input.password) {
            return Err(async_graphql::Error::new(format!("Password validation failed: {}", e)));
        }

        // Hash password
        use crate::auth::password::hash_password;
        let password_hash = hash_password(&input.password)
            .map_err(|e| async_graphql::Error::new(format!("Failed to hash password: {}", e)))?;

        // Map GraphQL UserRole to auth UserRole
        let user_role = match input.role {
            UserRole::Admin => crate::auth::users::UserRole::Admin,
            UserRole::Operator => crate::auth::users::UserRole::Operator,
            UserRole::Viewer => crate::auth::users::UserRole::Viewer,
        };

        // Create user using repository method
        state.user_repository.create_user(
            &input.email,
            "User", // Default name, can be updated later
            &password_hash,
            user_role,
        ).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to create user: {}", e)))?;

        // Fetch the created user to get the full object
        let user = state.user_repository.get_user_by_email(&input.email).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to fetch created user: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("User was created but could not be retrieved"))?;

        // Audit log (Sprint 25)
        let (admin_id, admin_email) = get_audit_user_info(ctx);
        let admin_email_for_event = admin_email.clone(); // Clone for event broadcasting (Sprint 28)
        let role_str = match user.role {
            crate::auth::users::UserRole::Admin => "admin".to_string(),
            crate::auth::users::UserRole::Operator => "operator".to_string(),
            crate::auth::users::UserRole::Viewer => "viewer".to_string(),
        };
        let _ = state.audit_logger.log(
            AuditEvent::UserCreate {
                user_id: user.id.clone(),
                email: user.email.clone(),
                role: role_str.clone(),
            },
            admin_id,
            admin_email,
            None,
            None,
        ).await;

        let result = GqlUser {
            id: user.id.clone(),
            email: user.email.clone(),
            role: match user.role {
                crate::auth::users::UserRole::Admin => UserRole::Admin,
                crate::auth::users::UserRole::Operator => UserRole::Operator,
                crate::auth::users::UserRole::Viewer => UserRole::Viewer,
            },
            active: user.is_active,
            created_at: user.created_at,
            last_login: user.last_login,
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "USER_CREATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "user_id": user.id,
                "email": user.email,
                "role": role_str,
                "created_by": admin_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Update user role (admin only)
    async fn update_user_role(
        &self,
        ctx: &Context<'_>,
        user_id: String,
        role: UserRole,
    ) -> Result<GqlUser> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Get current user for audit log
        let old_user = state.user_repository.get_user(&user_id).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get user: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("User not found"))?;

        let old_role_str = match old_user.role {
            crate::auth::users::UserRole::Admin => "admin".to_string(),
            crate::auth::users::UserRole::Operator => "operator".to_string(),
            crate::auth::users::UserRole::Viewer => "viewer".to_string(),
        };

        // Map GraphQL UserRole to auth UserRole string
        let role_str = match role {
            UserRole::Admin => "admin",
            UserRole::Operator => "operator",
            UserRole::Viewer => "viewer",
        };

        // Update user with new role
        use crate::auth::users::UpdateUserRequest;
        let update_req = UpdateUserRequest {
            email: None,
            name: None,
            role: Some(role_str.to_string()),
            is_active: None,
        };

        let user = state.user_repository.update_user(&user_id, update_req).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update user role: {}", e)))?;

        // Audit log (Sprint 25)
        let (admin_id, admin_email) = get_audit_user_info(ctx);
        let admin_email_for_event = admin_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::UserRoleUpdate {
                user_id: user_id.clone(),
                old_role: old_role_str.clone(),
                new_role: role_str.to_string(),
            },
            admin_id,
            admin_email,
            None,
            None,
        ).await;

        // Revoke all user's active tokens (Sprint 29)
        let _ = state.token_revocation.revoke_all_user_tokens(
            &user_id,
            format!("Role changed from {} to {}", old_role_str, role_str),
        ).await;

        let result = GqlUser {
            id: user.id.clone(),
            email: user.email.clone(),
            role: match user.role {
                crate::auth::users::UserRole::Admin => UserRole::Admin,
                crate::auth::users::UserRole::Operator => UserRole::Operator,
                crate::auth::users::UserRole::Viewer => UserRole::Viewer,
            },
            active: user.is_active,
            created_at: user.created_at,
            last_login: user.last_login,
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "USER_ROLE_UPDATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "user_id": user_id,
                "email": user.email,
                "old_role": old_role_str,
                "new_role": role_str,
                "updated_by": admin_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Deactivate a user (admin only)
    async fn deactivate_user(
        &self,
        ctx: &Context<'_>,
        user_id: String,
    ) -> Result<bool> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Get user info for audit log
        let user = state.user_repository.get_user(&user_id).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get user: {}", e)))?
            .ok_or_else(|| async_graphql::Error::new("User not found"))?;

        // Deactivate user using update
        use crate::auth::users::UpdateUserRequest;
        let update_req = UpdateUserRequest {
            email: None,
            name: None,
            role: None,
            is_active: Some(false),
        };

        state.user_repository.update_user(&user_id, update_req).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to deactivate user: {}", e)))?;

        // Audit log (Sprint 25)
        let (admin_id, admin_email) = get_audit_user_info(ctx);
        let admin_email_for_event = admin_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::UserDeactivate {
                user_id: user_id.clone(),
                email: user.email.clone(),
            },
            admin_id,
            admin_email,
            None,
            None,
        ).await;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "USER_DEACTIVATED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "user_id": user_id,
                "email": user.email,
                "deactivated_by": admin_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        // Revoke all user's active tokens (Sprint 29)
        let _ = state.token_revocation.revoke_all_user_tokens(
            &user_id,
            "User deactivated".to_string(),
        ).await;

        Ok(true)
    }

    /// Reset user password (admin only)
    async fn reset_user_password(
        &self,
        ctx: &Context<'_>,
        user_id: String,
        new_password: String,
    ) -> Result<bool> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Validate password strength
        use crate::auth::password::validate_password_strength;
        if let Err(e) = validate_password_strength(&new_password) {
            return Err(async_graphql::Error::new(format!("Password validation failed: {}", e)));
        }

        // Hash new password
        use crate::auth::password::hash_password;
        let password_hash = hash_password(&new_password)
            .map_err(|e| async_graphql::Error::new(format!("Failed to hash password: {}", e)))?;

        // Update password in database
        state.user_repository.update_password(&user_id, &password_hash).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update password: {}", e)))?;

        // Audit log (Sprint 25)
        let (admin_id, admin_email) = get_audit_user_info(ctx);
        let admin_email_for_event = admin_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PasswordReset {
                user_id: user_id.clone(),
                by_admin: true,
            },
            admin_id,
            admin_email,
            None,
            None,
        ).await;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "USER_PASSWORD_RESET".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "user_id": user_id,
                "by_admin": true,
                "reset_by": admin_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        // Revoke all user's active tokens (Sprint 29)
        let _ = state.token_revocation.revoke_all_user_tokens(
            &user_id,
            "Password reset by admin".to_string(),
        ).await;

        Ok(true)
    }

    // ========== Path Management ==========

    /// Manually trigger path health check
    async fn check_path_health(
        &self,
        ctx: &Context<'_>,
        path_id: String,
    ) -> Result<GqlPath> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse path ID
        use patronus_sdwan::types::PathId;
        let pid = path_id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid path ID"))?;
        let pid = PathId::new(pid);

        // Get path from database
        let path = state.db.get_path(pid).await
            .map_err(|e| async_graphql::Error::new(format!("Database error: {}", e)))?;

        // Get latest metrics
        let metrics = state.db.get_latest_metrics(pid).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to get metrics: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PathHealthCheck {
                path_id: pid.as_u64(),
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // TODO: Trigger immediate probe via path monitor
        // For now, we just return the current metrics

        let result = GqlPath {
            id: path.id.as_u64().to_string(),
            source_site_id: path.src_site.to_string(),
            destination_site_id: path.dst_site.to_string(),
            latency_ms: metrics.latency_ms,
            packet_loss: metrics.packet_loss_pct,
            bandwidth_mbps: metrics.bandwidth_mbps,
            quality_score: metrics.score as f64,
            status: match path.status {
                patronus_sdwan::types::PathStatus::Up => PathStatus::Optimal,
                patronus_sdwan::types::PathStatus::Degraded => PathStatus::Degraded,
                patronus_sdwan::types::PathStatus::Down => PathStatus::Failed,
            },
            last_updated: chrono::DateTime::from_timestamp(
                metrics.measured_at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                0
            ).unwrap_or_else(|| Utc::now()),
        };

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "PATH_HEALTH_CHECKED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "path_id": pid.as_u64().to_string(),
                "source_site_id": path.src_site.to_string(),
                "destination_site_id": path.dst_site.to_string(),
                "latency_ms": metrics.latency_ms,
                "packet_loss": metrics.packet_loss_pct,
                "quality_score": metrics.score,
                "checked_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(result)
    }

    /// Force path failover
    async fn failover_path(
        &self,
        ctx: &Context<'_>,
        path_id: String,
    ) -> Result<bool> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Parse path ID
        use patronus_sdwan::types::{PathId, PathStatus as SdwanPathStatus};
        let pid = path_id.parse::<u64>()
            .map_err(|_| async_graphql::Error::new("Invalid path ID"))?;
        let pid = PathId::new(pid);

        // Mark path as down
        state.db.update_path_status(pid, SdwanPathStatus::Down).await
            .map_err(|e| async_graphql::Error::new(format!("Failed to update path status: {}", e)))?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::PathFailover {
                path_id: pid.as_u64(),
                reason: "Manual failover triggered".to_string(),
            },
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "PATH_FAILOVER".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "path_id": pid.as_u64().to_string(),
                "reason": "Manual failover triggered",
                "triggered_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        // TODO: Trigger routing engine to reroute traffic

        Ok(true)
    }

    // ========== System Operations ==========

    /// Clear system cache
    async fn clear_cache(
        &self,
        ctx: &Context<'_>,
    ) -> Result<bool> {
        // Require admin role
        let _auth = crate::graphql::require_role(ctx, crate::auth::users::UserRole::Admin)?;

        let state = get_state(ctx)?;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::CacheClear,
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Clear caches (Sprint 30)
        let metrics_cleared = state.metrics_cache.clear().await;
        let routing_cleared = state.routing_cache.clear().await;
        let total_cleared = metrics_cleared + routing_cleared;

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "CACHE_CLEARED".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "metrics_entries_cleared": metrics_cleared,
                "routing_entries_cleared": routing_cleared,
                "total_cleared": total_cleared,
                "cleared_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(true)
    }

    /// Trigger full system health check
    async fn system_health_check(
        &self,
        ctx: &Context<'_>,
    ) -> Result<String> {
        // Require operator or admin role
        let _auth = crate::graphql::require_min_role(ctx, crate::auth::users::UserRole::Operator)?;

        let state = get_state(ctx)?;

        // Check database connectivity
        let site_count = state.db.count_sites().await
            .map_err(|e| async_graphql::Error::new(format!("Database check failed: {}", e)))?;

        // Check metrics collector
        let metrics = state.metrics_collector.get_current_metrics().await;

        // Audit log (Sprint 25)
        let (user_id, user_email) = get_audit_user_info(ctx);
        let user_email_for_event = user_email.clone(); // Clone for event broadcasting (Sprint 28)
        let _ = state.audit_logger.log(
            AuditEvent::SystemHealthCheck,
            user_id,
            user_email,
            None,
            None,
        ).await;

        // Compile health status
        let status = format!(
            "System Health OK\n\
             - Database: Connected ({} sites)\n\
             - Metrics Collector: Active (CPU: {:.1}%, Memory: {:.1}%)\n\
             - Throughput: {:.2} Mbps\n\
             - Active Flows: {}",
            site_count,
            metrics.cpu_usage,
            metrics.memory_usage,
            metrics.throughput_mbps,
            metrics.active_flows
        );

        // Broadcast event to WebSocket clients (Sprint 28)
        let _ = state.events_tx.send(crate::state::Event {
            event_type: "SYSTEM_HEALTH_CHECK".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "site_count": site_count,
                "cpu_usage": metrics.cpu_usage,
                "memory_usage": metrics.memory_usage,
                "throughput_mbps": metrics.throughput_mbps,
                "active_flows": metrics.active_flows,
                "checked_by": user_email_for_event.unwrap_or_else(|| "system".to_string()),
            }),
        });

        Ok(status)
    }
}
