//! Role-Based Access Control (RBAC)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    // Site permissions
    SiteRead,
    SiteWrite,
    SiteDelete,

    // Tunnel permissions
    TunnelRead,
    TunnelWrite,
    TunnelDelete,

    // Policy permissions
    PolicyRead,
    PolicyWrite,
    PolicyDelete,

    // User permissions
    UserRead,
    UserWrite,
    UserDelete,

    // Organization permissions
    OrgRead,
    OrgWrite,
    OrgDelete,

    // Admin permissions
    AdminAll,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    pub org_id: Uuid,
}

impl Role {
    pub fn new(name: impl Into<String>, description: impl Into<String>, org_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: description.into(),
            permissions: HashSet::new(),
            org_id,
        }
    }

    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.insert(permission);
        self
    }

    pub fn with_permissions(mut self, permissions: Vec<Permission>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission) || self.permissions.contains(&Permission::AdminAll)
    }
}

// Pre-defined roles
impl Role {
    pub fn viewer(org_id: Uuid) -> Self {
        Self::new("viewer", "Read-only access", org_id)
            .with_permissions(vec![
                Permission::SiteRead,
                Permission::TunnelRead,
                Permission::PolicyRead,
                Permission::OrgRead,
            ])
    }

    pub fn operator(org_id: Uuid) -> Self {
        Self::new("operator", "Operational access", org_id)
            .with_permissions(vec![
                Permission::SiteRead,
                Permission::SiteWrite,
                Permission::TunnelRead,
                Permission::TunnelWrite,
                Permission::PolicyRead,
                Permission::PolicyWrite,
                Permission::OrgRead,
            ])
    }

    pub fn admin(org_id: Uuid) -> Self {
        Self::new("admin", "Full administrative access", org_id)
            .with_permission(Permission::AdminAll)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub org_id: Uuid,
    pub role_ids: Vec<Uuid>,
}

impl User {
    pub fn new(username: impl Into<String>, email: impl Into<String>, org_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            username: username.into(),
            email: email.into(),
            org_id,
            role_ids: vec![],
        }
    }

    pub fn with_role(mut self, role_id: Uuid) -> Self {
        self.role_ids.push(role_id);
        self
    }
}

pub struct RbacManager {
    roles: HashMap<Uuid, Role>,
    users: HashMap<Uuid, User>,
    org_roles: HashMap<Uuid, Vec<Uuid>>, // org_id -> [role_ids]
    org_users: HashMap<Uuid, Vec<Uuid>>, // org_id -> [user_ids]
}

impl RbacManager {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            users: HashMap::new(),
            org_roles: HashMap::new(),
            org_users: HashMap::new(),
        }
    }

    pub fn create_role(&mut self, role: Role) -> Result<Uuid> {
        let role_id = role.id;
        let org_id = role.org_id;

        self.roles.insert(role_id, role);
        self.org_roles
            .entry(org_id)
            .or_insert_with(Vec::new)
            .push(role_id);

        tracing::info!("Created role: {}", role_id);
        Ok(role_id)
    }

    pub fn create_user(&mut self, user: User) -> Result<Uuid> {
        let user_id = user.id;
        let org_id = user.org_id;

        // Verify all roles exist and belong to same org
        for role_id in &user.role_ids {
            let role = self.roles.get(role_id)
                .ok_or_else(|| anyhow::anyhow!("Role not found: {}", role_id))?;

            if role.org_id != org_id {
                anyhow::bail!("Role {} does not belong to organization {}", role_id, org_id);
            }
        }

        self.users.insert(user_id, user);
        self.org_users
            .entry(org_id)
            .or_insert_with(Vec::new)
            .push(user_id);

        tracing::info!("Created user: {}", user_id);
        Ok(user_id)
    }

    pub fn assign_role(&mut self, user_id: &Uuid, role_id: &Uuid) -> Result<()> {
        let user = self.users.get_mut(user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let role = self.roles.get(role_id)
            .ok_or_else(|| anyhow::anyhow!("Role not found"))?;

        if user.org_id != role.org_id {
            anyhow::bail!("Role does not belong to user's organization");
        }

        if !user.role_ids.contains(role_id) {
            user.role_ids.push(*role_id);
        }

        Ok(())
    }

    pub fn check_permission(&self, user_id: &Uuid, permission: &Permission) -> bool {
        if let Some(user) = self.users.get(user_id) {
            for role_id in &user.role_ids {
                if let Some(role) = self.roles.get(role_id) {
                    if role.has_permission(permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn get_user_permissions(&self, user_id: &Uuid) -> HashSet<Permission> {
        let mut permissions = HashSet::new();

        if let Some(user) = self.users.get(user_id) {
            for role_id in &user.role_ids {
                if let Some(role) = self.roles.get(role_id) {
                    if role.permissions.contains(&Permission::AdminAll) {
                        // Admin has all permissions
                        return HashSet::from([Permission::AdminAll]);
                    }
                    permissions.extend(role.permissions.clone());
                }
            }
        }

        permissions
    }

    pub fn get_org_users(&self, org_id: &Uuid) -> Vec<&User> {
        self.org_users
            .get(org_id)
            .map(|user_ids| {
                user_ids
                    .iter()
                    .filter_map(|id| self.users.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_org_roles(&self, org_id: &Uuid) -> Vec<&Role> {
        self.org_roles
            .get(org_id)
            .map(|role_ids| {
                role_ids
                    .iter()
                    .filter_map(|id| self.roles.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for RbacManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_creation() {
        let org_id = Uuid::new_v4();
        let role = Role::viewer(org_id);

        assert_eq!(role.name, "viewer");
        assert!(role.has_permission(&Permission::SiteRead));
        assert!(!role.has_permission(&Permission::SiteWrite));
    }

    #[test]
    fn test_admin_has_all_permissions() {
        let org_id = Uuid::new_v4();
        let admin = Role::admin(org_id);

        assert!(admin.has_permission(&Permission::SiteRead));
        assert!(admin.has_permission(&Permission::SiteWrite));
        assert!(admin.has_permission(&Permission::UserDelete));
        assert!(admin.has_permission(&Permission::AdminAll));
    }

    #[test]
    fn test_user_role_assignment() {
        let mut manager = RbacManager::new();
        let org_id = Uuid::new_v4();

        let viewer = Role::viewer(org_id);
        let viewer_id = viewer.id;
        manager.create_role(viewer).unwrap();

        let user = User::new("alice", "alice@example.com", org_id)
            .with_role(viewer_id);
        let user_id = user.id;
        manager.create_user(user).unwrap();

        assert!(manager.check_permission(&user_id, &Permission::SiteRead));
        assert!(!manager.check_permission(&user_id, &Permission::SiteWrite));
    }

    #[test]
    fn test_multiple_roles() {
        let mut manager = RbacManager::new();
        let org_id = Uuid::new_v4();

        let viewer = Role::viewer(org_id);
        let viewer_id = viewer.id;
        manager.create_role(viewer).unwrap();

        let operator = Role::operator(org_id);
        let operator_id = operator.id;
        manager.create_role(operator).unwrap();

        let user = User::new("bob", "bob@example.com", org_id)
            .with_role(viewer_id)
            .with_role(operator_id);
        let user_id = user.id;
        manager.create_user(user).unwrap();

        // Has permissions from both roles
        assert!(manager.check_permission(&user_id, &Permission::SiteRead));
        assert!(manager.check_permission(&user_id, &Permission::SiteWrite));
        assert!(!manager.check_permission(&user_id, &Permission::SiteDelete));
    }

    #[test]
    fn test_cross_org_role_assignment_fails() {
        let mut manager = RbacManager::new();
        let org1 = Uuid::new_v4();
        let org2 = Uuid::new_v4();

        let role = Role::viewer(org1);
        let role_id = role.id;
        manager.create_role(role).unwrap();

        let user = User::new("charlie", "charlie@example.com", org2)
            .with_role(role_id);

        let result = manager.create_user(user);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_user_permissions() {
        let mut manager = RbacManager::new();
        let org_id = Uuid::new_v4();

        let operator = Role::operator(org_id);
        let operator_id = operator.id;
        manager.create_role(operator).unwrap();

        let user = User::new("dave", "dave@example.com", org_id)
            .with_role(operator_id);
        let user_id = user.id;
        manager.create_user(user).unwrap();

        let permissions = manager.get_user_permissions(&user_id);
        assert!(permissions.contains(&Permission::SiteRead));
        assert!(permissions.contains(&Permission::SiteWrite));
        assert!(permissions.contains(&Permission::PolicyWrite));
        assert!(!permissions.contains(&Permission::UserDelete));
    }
}
