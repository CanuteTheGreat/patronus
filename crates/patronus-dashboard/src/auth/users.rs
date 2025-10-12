//! User management and repository

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::{ApiError, Result};

/// Helper to convert sqlx errors to ApiError
fn db_error(e: sqlx::Error) -> ApiError {
    ApiError::Internal(format!("Database error: {}", e))
}

/// User role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Operator => "operator",
            UserRole::Viewer => "viewer",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(UserRole::Admin),
            "operator" => Ok(UserRole::Operator),
            "viewer" => Ok(UserRole::Viewer),
            _ => Err(ApiError::InvalidRequest(format!("Invalid role: {}", s))),
        }
    }
}

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Create user request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: String,
    pub password: String,
    pub role: String,
}

/// Update user request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

/// Change password request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// User repository for database operations
pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Initialize users table
    pub async fn init(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_login INTEGER,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(())
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        email: &str,
        name: &str,
        password_hash: &str,
        role: UserRole,
    ) -> Result<User> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO users (id, email, name, role, password_hash, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            "#,
        )
        .bind(&id)
        .bind(email)
        .bind(name)
        .bind(role.as_str())
        .bind(password_hash)
        .bind(now.timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                ApiError::InvalidRequest("Email already exists".to_string())
            } else {
                db_error(e)
            }
        })?;

        Ok(User {
            id,
            email: email.to_string(),
            name: name.to_string(),
            role,
            password_hash: password_hash.to_string(),
            created_at: now,
            last_login: None,
            is_active: true,
        })
    }

    /// Get user by ID
    pub async fn get_user(&self, id: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, email, name, role, password_hash, created_at, last_login, is_active
            FROM users
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        match row {
            Some(row) => Ok(Some(User {
                id: row.get(0),
                email: row.get(1),
                name: row.get(2),
                role: UserRole::from_str(row.get(3))?,
                password_hash: row.get(4),
                created_at: DateTime::from_timestamp(row.get(5), 0).unwrap_or_default(),
                last_login: row
                    .get::<Option<i64>, _>(6)
                    .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                is_active: row.get::<i64, _>(7) != 0,
            })),
            None => Ok(None),
        }
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT id, email, name, role, password_hash, created_at, last_login, is_active
            FROM users
            WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        match row {
            Some(row) => Ok(Some(User {
                id: row.get(0),
                email: row.get(1),
                name: row.get(2),
                role: UserRole::from_str(row.get(3))?,
                password_hash: row.get(4),
                created_at: DateTime::from_timestamp(row.get(5), 0).unwrap_or_default(),
                last_login: row
                    .get::<Option<i64>, _>(6)
                    .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                is_active: row.get::<i64, _>(7) != 0,
            })),
            None => Ok(None),
        }
    }

    /// List all users
    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows = sqlx::query(
            r#"
            SELECT id, email, name, role, password_hash, created_at, last_login, is_active
            FROM users
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        let mut users = Vec::new();
        for row in rows {
            users.push(User {
                id: row.get(0),
                email: row.get(1),
                name: row.get(2),
                role: UserRole::from_str(row.get(3))?,
                password_hash: row.get(4),
                created_at: DateTime::from_timestamp(row.get(5), 0).unwrap_or_default(),
                last_login: row
                    .get::<Option<i64>, _>(6)
                    .and_then(|ts| DateTime::from_timestamp(ts, 0)),
                is_active: row.get::<i64, _>(7) != 0,
            });
        }

        Ok(users)
    }

    /// Update user
    pub async fn update_user(&self, id: &str, req: UpdateUserRequest) -> Result<User> {
        // Get current user
        let user = self
            .get_user(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

        // Update fields
        let email = req.email.as_deref().unwrap_or(&user.email);
        let name = req.name.as_deref().unwrap_or(&user.name);
        let role = if let Some(role_str) = req.role {
            UserRole::from_str(&role_str)?
        } else {
            user.role.clone()
        };
        let is_active = req.is_active.unwrap_or(user.is_active);

        sqlx::query(
            r#"
            UPDATE users
            SET email = ?, name = ?, role = ?, is_active = ?
            WHERE id = ?
            "#,
        )
        .bind(email)
        .bind(name)
        .bind(role.as_str())
        .bind(if is_active { 1 } else { 0 })
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        // Return updated user
        self.get_user(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))
    }

    /// Update password
    pub async fn update_password(&self, id: &str, new_password_hash: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            "#,
        )
        .bind(new_password_hash)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(())
    }

    /// Update last login time
    pub async fn update_last_login(&self, id: &str) -> Result<()> {
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE users
            SET last_login = ?
            WHERE id = ?
            "#,
        )
        .bind(now.timestamp())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(())
    }

    /// Delete user
    pub async fn delete_user(&self, id: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM users
            WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(())
    }

    /// Check if any users exist (for initial setup)
    pub async fn has_users(&self) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?;

        let count: i64 = row.get(0);
        Ok(count > 0)
    }
}
