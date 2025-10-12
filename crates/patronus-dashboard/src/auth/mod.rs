//! Authentication and authorization module

pub mod jwt;
pub mod middleware;
pub mod password;
pub mod users;

pub use jwt::{Claims, TokenPair, generate_tokens, validate_token, refresh_access_token};
pub use middleware::auth_middleware;
pub use password::{hash_password, verify_password};
pub use users::{User, UserRole, UserRepository, CreateUserRequest, ChangePasswordRequest};
