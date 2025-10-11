// GraphQL Authentication & Authorization
//
// This module provides authentication guards and role-based access control
// for GraphQL resolvers.

use async_graphql::{Context, Result, Error};
use crate::auth::jwt::Claims;
use crate::auth::users::UserRole;

/// Authentication context for GraphQL operations
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// JWT claims if user is authenticated
    pub claims: Option<Claims>,
}

impl AuthContext {
    /// Create new auth context with claims
    pub fn new(claims: Option<Claims>) -> Self {
        Self { claims }
    }

    /// Check if user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.claims.is_some()
    }

    /// Get user ID if authenticated
    pub fn user_id(&self) -> Option<&str> {
        self.claims.as_ref().map(|c| c.sub.as_str())
    }

    /// Get user role if authenticated
    pub fn role(&self) -> Option<UserRole> {
        self.claims.as_ref().and_then(|c| match c.role.as_str() {
            "admin" => Some(UserRole::Admin),
            "operator" => Some(UserRole::Operator),
            "viewer" => Some(UserRole::Viewer),
            _ => None,
        })
    }

    /// Check if user has specific role
    pub fn has_role(&self, role: UserRole) -> bool {
        match self.role() {
            Some(user_role) => user_role == role,
            None => false,
        }
    }

    /// Check if user has minimum role level
    pub fn has_min_role(&self, min_role: UserRole) -> bool {
        match self.role() {
            Some(user_role) => {
                // Admin > Operator > Viewer
                match min_role {
                    UserRole::Viewer => true, // All roles satisfy viewer
                    UserRole::Operator => matches!(user_role, UserRole::Operator | UserRole::Admin),
                    UserRole::Admin => user_role == UserRole::Admin,
                }
            }
            None => false,
        }
    }
}

/// Get authentication context from GraphQL context
pub fn get_auth<'a>(ctx: &'a Context<'_>) -> Result<&'a AuthContext> {
    ctx.data::<AuthContext>()
        .map_err(|_| Error::new("Authentication context not found"))
}

/// Require authentication - returns error if not authenticated
pub fn require_auth<'a>(ctx: &'a Context<'_>) -> Result<&'a AuthContext> {
    let auth = get_auth(ctx)?;
    if !auth.is_authenticated() {
        return Err(Error::new("Authentication required"));
    }
    Ok(auth)
}

/// Require specific role - returns error if user doesn't have role
pub fn require_role<'a>(ctx: &'a Context<'_>, role: UserRole) -> Result<&'a AuthContext> {
    let auth = require_auth(ctx)?;
    let role_name = format!("{role:?}");
    if !auth.has_role(role) {
        return Err(Error::new(format!("Role {role_name} required")));
    }
    Ok(auth)
}

/// Require minimum role level - returns error if user doesn't have sufficient permissions
pub fn require_min_role<'a>(ctx: &'a Context<'_>, min_role: UserRole) -> Result<&'a AuthContext> {
    let auth = require_auth(ctx)?;
    let role_name = format!("{min_role:?}");
    if !auth.has_min_role(min_role) {
        return Err(Error::new(format!("Minimum role {role_name} required")));
    }
    Ok(auth)
}

/// Guard macro for authenticated operations
#[macro_export]
macro_rules! require_auth {
    ($ctx:expr) => {
        $crate::graphql::auth::require_auth($ctx)?
    };
}

/// Guard macro for role-based operations
#[macro_export]
macro_rules! require_role {
    ($ctx:expr, $role:expr) => {
        $crate::graphql::auth::require_role($ctx, $role)?
    };
}

/// Guard macro for minimum role level operations
#[macro_export]
macro_rules! require_min_role {
    ($ctx:expr, $min_role:expr) => {
        $crate::graphql::auth::require_min_role($ctx, $min_role)?
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_authenticated() {
        let claims = Claims {
            sub: "user123".to_string(),
            email: "test@example.com".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "jti123".to_string(),
        };

        let auth = AuthContext::new(Some(claims));

        assert!(auth.is_authenticated());
        assert_eq!(auth.user_id(), Some("user123"));
        assert_eq!(auth.role(), Some(UserRole::Admin));
    }

    #[test]
    fn test_auth_context_unauthenticated() {
        let auth = AuthContext::new(None);

        assert!(!auth.is_authenticated());
        assert_eq!(auth.user_id(), None);
        assert_eq!(auth.role(), None);
    }

    #[test]
    fn test_role_hierarchy() {
        let admin_claims = Claims {
            sub: "admin".to_string(),
            email: "admin@example.com".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "jti1".to_string(),
        };

        let operator_claims = Claims {
            sub: "operator".to_string(),
            email: "operator@example.com".to_string(),
            role: "operator".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "jti2".to_string(),
        };

        let viewer_claims = Claims {
            sub: "viewer".to_string(),
            email: "viewer@example.com".to_string(),
            role: "viewer".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "jti3".to_string(),
        };

        let admin_auth = AuthContext::new(Some(admin_claims));
        let operator_auth = AuthContext::new(Some(operator_claims));
        let viewer_auth = AuthContext::new(Some(viewer_claims));

        // Admin has all roles
        assert!(admin_auth.has_min_role(UserRole::Admin));
        assert!(admin_auth.has_min_role(UserRole::Operator));
        assert!(admin_auth.has_min_role(UserRole::Viewer));

        // Operator has operator and viewer
        assert!(!operator_auth.has_min_role(UserRole::Admin));
        assert!(operator_auth.has_min_role(UserRole::Operator));
        assert!(operator_auth.has_min_role(UserRole::Viewer));

        // Viewer only has viewer
        assert!(!viewer_auth.has_min_role(UserRole::Admin));
        assert!(!viewer_auth.has_min_role(UserRole::Operator));
        assert!(viewer_auth.has_min_role(UserRole::Viewer));
    }

    #[test]
    fn test_specific_role_check() {
        let admin_claims = Claims {
            sub: "admin".to_string(),
            email: "admin@example.com".to_string(),
            role: "admin".to_string(),
            iat: 0,
            exp: 9999999999,
            token_type: crate::auth::jwt::TokenType::Access,
            jti: "jti1".to_string(),
        };

        let auth = AuthContext::new(Some(admin_claims));

        assert!(auth.has_role(UserRole::Admin));
        assert!(!auth.has_role(UserRole::Operator));
        assert!(!auth.has_role(UserRole::Viewer));
    }
}
