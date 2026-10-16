//! JWT token generation and validation
//!
//! # Signing secret
//!
//! Tokens are signed with HS256 using a secret that is loaded at startup by
//! [`init_from_env`] (called from `main`), never a compile-time constant:
//!
//! 1. `PATRONUS_JWT_SECRET` env var, if set. Must be at least
//!    [`MIN_SECRET_LEN`] bytes or startup fails. In an HA deployment every
//!    dashboard node MUST be given the same value, otherwise a token issued
//!    by one node is rejected by the others.
//! 2. Otherwise a persisted secret file (`PATRONUS_JWT_SECRET_FILE`, default
//!    `jwt_secret` next to `PATRONUS_DB_PATH`). On first start it is created
//!    with 64 bytes from the OS RNG (hex-encoded) and mode 0600; later starts
//!    reuse it, so issued tokens survive restarts.
//!
//! There is deliberately no fixed fallback string: a previous build signed
//! with a hardcoded secret, which let anyone forge admin tokens.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use uuid::Uuid;

use crate::error::{ApiError, Result};

/// Env var holding the shared signing secret (must be identical on all HA nodes).
pub const JWT_SECRET_ENV: &str = "PATRONUS_JWT_SECRET";

/// Env var overriding where the generated secret file is persisted.
pub const JWT_SECRET_FILE_ENV: &str = "PATRONUS_JWT_SECRET_FILE";

/// File name of the generated secret when no explicit path is configured.
pub const DEFAULT_SECRET_FILE_NAME: &str = "jwt_secret";

/// Minimum accepted secret length in bytes (HS256 key should be >= 256 bits).
pub const MIN_SECRET_LEN: usize = 32;

/// Number of random bytes generated for a new secret.
const GENERATED_SECRET_BYTES: usize = 64;

/// Access token expiration (15 minutes)
const ACCESS_TOKEN_EXPIRY: i64 = 15 * 60;

/// Refresh token expiration (7 days)
const REFRESH_TOKEN_EXPIRY: i64 = 7 * 24 * 60 * 60;

/// HMAC keys derived from the signing secret.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

/// Signing secrets that have shipped in this codebase or its docs, or are
/// obvious placeholders. Anyone can read these, so a token signed with one
/// is forgeable: refuse to start rather than run with a public key.
pub const KNOWN_DEFAULT_SECRETS: &[&str] = &[
    "your-secret-key-change-in-production",
    "change-me-in-production-please-32bytes",
    "patronus-dashboard-jwt-secret-change-me",
];

/// Substrings that mark a secret as a copy-pasted placeholder.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "change-in-production",
    "changeme",
    "change-me",
    "change_me",
    "your-secret",
    "your_secret",
    "replace-me",
    "replaceme",
    "example",
    "placeholder",
];

/// Reject secrets that are publicly known or trivially guessable.
pub fn check_secret_strength(secret: &[u8]) -> std::result::Result<(), String> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(format!(
            "JWT secret is {} bytes; at least {} bytes are required",
            secret.len(),
            MIN_SECRET_LEN
        ));
    }
    let text = String::from_utf8_lossy(secret).to_ascii_lowercase();
    if KNOWN_DEFAULT_SECRETS.iter().any(|d| text == *d) {
        return Err(
            "JWT secret is a publicly known default value; generate one with `openssl rand -hex 32`"
                .to_string(),
        );
    }
    if let Some(m) = PLACEHOLDER_MARKERS.iter().find(|m| text.contains(**m)) {
        return Err(format!(
            "JWT secret looks like a placeholder (contains {:?}); generate one with `openssl rand -hex 32`",
            m
        ));
    }
    let distinct: std::collections::HashSet<u8> = secret.iter().copied().collect();
    if distinct.len() < 8 {
        return Err(format!(
            "JWT secret uses only {} distinct bytes; generate one with `openssl rand -hex 32`",
            distinct.len()
        ));
    }
    Ok(())
}

impl JwtKeys {
    /// Build keys from a secret, rejecting short, known-default or
    /// placeholder secrets (see [`check_secret_strength`]).
    pub fn new(secret: &[u8]) -> std::result::Result<Self, String> {
        check_secret_strength(secret)?;
        Ok(Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        })
    }
}

#[cfg(test)]
impl JwtKeys {
    /// Test-only: build keys from any secret (to simulate an attacker using
    /// a weak/known key) without the strength check.
    pub(crate) fn unchecked(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

impl std::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JwtKeys(<redacted>)")
    }
}

/// Process-wide signing keys, set once at startup.
static KEYS: OnceLock<JwtKeys> = OnceLock::new();

/// Where the signing secret came from (for startup logging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    Env,
    ExistingFile(PathBuf),
    GeneratedFile(PathBuf),
}

/// Resolve the signing secret: the env value if present, else the persisted
/// file (generated on first use). Takes the env value as a parameter so it is
/// unit-testable without mutating process env.
pub fn resolve_secret(
    env_value: Option<String>,
    file_path: &Path,
) -> std::result::Result<(Vec<u8>, SecretSource), String> {
    if let Some(value) = env_value {
        let bytes = value.into_bytes();
        if bytes.len() < MIN_SECRET_LEN {
            return Err(format!(
                "{} is {} bytes; it must be at least {} bytes (e.g. `openssl rand -hex 32`)",
                JWT_SECRET_ENV,
                bytes.len(),
                MIN_SECRET_LEN
            ));
        }
        check_secret_strength(&bytes).map_err(|e| format!("{}: {}", JWT_SECRET_ENV, e))?;
        return Ok((bytes, SecretSource::Env));
    }
    load_or_create_secret_file(file_path)
}

/// Read the secret file, or create it with fresh OS-RNG bytes (mode 0600).
pub fn load_or_create_secret_file(
    path: &Path,
) -> std::result::Result<(Vec<u8>, SecretSource), String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let secret = contents.trim().as_bytes().to_vec();
            if secret.len() < MIN_SECRET_LEN {
                return Err(format!(
                    "JWT secret file {} holds {} bytes; at least {} are required \
                     (delete it to regenerate, or set {})",
                    path.display(),
                    secret.len(),
                    MIN_SECRET_LEN,
                    JWT_SECRET_ENV
                ));
            }
            check_secret_strength(&secret)
                .map_err(|e| format!("JWT secret file {}: {}", path.display(), e))?;
            warn_if_permissive(path);
            Ok((secret, SecretSource::ExistingFile(path.to_path_buf())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut raw = [0u8; GENERATED_SECRET_BYTES];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let encoded: String = raw.iter().map(|b| format!("{:02x}", b)).collect();

            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
                }
            }

            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(path) {
                Ok(mut f) => {
                    f.write_all(encoded.as_bytes())
                        .and_then(|_| f.sync_all())
                        .map_err(|e| format!("cannot write {}: {}", path.display(), e))?;
                    Ok((
                        encoded.into_bytes(),
                        SecretSource::GeneratedFile(path.to_path_buf()),
                    ))
                }
                // Another process created it between our read and create: use theirs.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    load_or_create_secret_file(path)
                }
                Err(e) => Err(format!("cannot create {}: {}", path.display(), e)),
            }
        }
        Err(e) => Err(format!(
            "cannot read JWT secret file {}: {}",
            path.display(),
            e
        )),
    }
}

#[cfg(unix)]
fn warn_if_permissive(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            tracing::warn!(
                "JWT secret file {} is readable by group/others; chmod 600 it",
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_permissive(_path: &Path) {}

/// Default secret-file path: `PATRONUS_JWT_SECRET_FILE`, else `jwt_secret`
/// in the directory holding the dashboard database.
pub fn default_secret_file(db_path: &str) -> PathBuf {
    if let Ok(p) = std::env::var(JWT_SECRET_FILE_ENV) {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    secret_file_next_to_db(db_path)
}

fn secret_file_next_to_db(db_path: &str) -> PathBuf {
    Path::new(db_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join(DEFAULT_SECRET_FILE_NAME)
}

/// Install the process-wide signing keys. Fails if already initialised.
pub fn init(secret: &[u8]) -> std::result::Result<(), String> {
    let keys = JwtKeys::new(secret)?;
    KEYS.set(keys)
        .map_err(|_| "JWT signing keys already initialised".to_string())?;
    let _ = CLUSTER_TOKEN.set(derive_cluster_token(secret));
    Ok(())
}

/// Node-to-node HA RPC credential (sent as `x-patronus-cluster-token`).
static CLUSTER_TOKEN: OnceLock<String> = OnceLock::new();

/// Header carrying the cluster RPC credential.
pub const CLUSTER_TOKEN_HEADER: &str = "x-patronus-cluster-token";

fn derive_cluster_token(secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"patronus-ha-cluster-rpc-v1");
    hex::encode(mac.finalize().into_bytes())
}

/// Token HA peers must present on `/ha/vote`, `/ha/heartbeat` and
/// `/ha/submit`. Derived from the shared signing secret, so every node
/// configured with the same `PATRONUS_JWT_SECRET` agrees on it while
/// outsiders (who could otherwise inject replicated writes such as a new
/// admin user) cannot produce it.
pub fn cluster_rpc_token() -> &'static str {
    CLUSTER_TOKEN.get_or_init(|| {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        hex::encode(raw)
    })
}

/// Load the secret from env / secret file and install it. Called once from `main`.
pub fn init_from_env(db_path: &str) -> std::result::Result<SecretSource, String> {
    let env_value = match std::env::var_os(JWT_SECRET_ENV) {
        Some(v) => Some(
            v.into_string()
                .map_err(|_| format!("{} is not valid UTF-8", JWT_SECRET_ENV))?,
        ),
        None => None,
    };
    let (secret, source) = resolve_secret(env_value, &default_secret_file(db_path))?;
    init(&secret)?;
    Ok(source)
}

/// Process-wide keys. If `main` never initialised them (library/test use),
/// fall back to an ephemeral OS-RNG key -- never a fixed string -- so tokens
/// stay unforgeable (they just won't survive a restart).
fn keys() -> &'static JwtKeys {
    KEYS.get_or_init(|| {
        tracing::warn!("JWT keys not initialised; using an ephemeral random signing key");
        let mut raw = [0u8; GENERATED_SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        JwtKeys::new(&raw).expect("generated secret meets minimum length")
    })
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// User email
    pub email: String,

    /// User role
    pub role: String,

    /// Issued at (timestamp)
    pub iat: i64,

    /// Expiration time (timestamp)
    pub exp: i64,

    /// Token type (access or refresh)
    pub token_type: TokenType,

    /// JWT ID (for token revocation)
    pub jti: String,
}

/// Token type
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

/// Token pair (access + refresh)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Generate JWT token pair (access + refresh)
pub fn generate_tokens(user_id: &str, email: &str, role: &str) -> Result<TokenPair> {
    generate_tokens_with_keys(keys(), user_id, email, role)
}

/// Generate a token pair signed with explicit keys.
pub fn generate_tokens_with_keys(
    keys: &JwtKeys,
    user_id: &str,
    email: &str,
    role: &str,
) -> Result<TokenPair> {
    let now = Utc::now();

    // Generate access token
    let access_claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ACCESS_TOKEN_EXPIRY)).timestamp(),
        token_type: TokenType::Access,
        jti: Uuid::new_v4().to_string(),
    };

    let access_token = encode(&Header::default(), &access_claims, &keys.encoding)
        .map_err(|e| ApiError::Internal(format!("Failed to generate access token: {}", e)))?;

    // Generate refresh token
    let refresh_claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::seconds(REFRESH_TOKEN_EXPIRY)).timestamp(),
        token_type: TokenType::Refresh,
        jti: Uuid::new_v4().to_string(),
    };

    let refresh_token = encode(&Header::default(), &refresh_claims, &keys.encoding)
        .map_err(|e| ApiError::Internal(format!("Failed to generate refresh token: {}", e)))?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_EXPIRY,
    })
}

/// Validate JWT token and extract claims
pub fn validate_token(token: &str) -> Result<Claims> {
    validate_token_with_keys(keys(), token)
}

/// Validate a token against explicit keys.
pub fn validate_token_with_keys(keys: &JwtKeys, token: &str) -> Result<Claims> {
    let token_data =
        decode::<Claims>(token, &keys.decoding, &Validation::default()).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ApiError::Unauthorized("Token expired".to_string())
                }
                _ => ApiError::Unauthorized(format!("Invalid token: {}", e)),
            }
        })?;

    Ok(token_data.claims)
}

/// Refresh access token using refresh token
pub fn refresh_access_token(refresh_token: &str) -> Result<TokenPair> {
    let claims = validate_token(refresh_token)?;

    // Verify this is a refresh token
    if claims.token_type != TokenType::Refresh {
        return Err(ApiError::Unauthorized("Invalid token type".to_string()));
    }

    // Generate new token pair
    generate_tokens(&claims.sub, &claims.email, &claims.role)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRONG_A: &str = "3f9c1a7e5b2d48c6a0e1f7b39d2c5e8a61b4d0f7c3a9e2b5";
    const STRONG_B: &str = "a81e4c7f09b25d36e7c1f4a8b0d93e62c5f17a4b8e0d2c9f";

    #[test]
    fn test_known_default_and_placeholder_secrets_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt_secret");
        for bad in KNOWN_DEFAULT_SECRETS.iter().map(|s| s.to_string()).chain([
            "please-changeme-this-is-my-jwt-secret-value".to_string(),
            "your-secret-here-0123456789abcdefghijklmnop".to_string(),
            "x".repeat(64),
            "abababababababababababababababababababab".to_string(),
        ]) {
            // Env path: refuse, and never fall back to a generated file.
            assert!(
                resolve_secret(Some(bad.clone()), &path).is_err(),
                "env secret {:?} must be refused",
                bad
            );
            assert!(!path.exists());
            assert!(JwtKeys::new(bad.as_bytes()).is_err());
            // Secret-file path: refuse a planted weak/default value too.
            std::fs::write(&path, &bad).unwrap();
            assert!(resolve_secret(None, &path).is_err());
            std::fs::remove_file(&path).unwrap();
        }
        assert!(JwtKeys::new(STRONG_A.as_bytes()).is_ok());
    }

    #[test]
    fn test_admin_token_forged_with_old_default_is_rejected() {
        // The QA finding: anyone could mint an admin token with the old
        // compile-time secret. The running process must not accept it.
        let old = JwtKeys::unchecked(b"your-secret-key-change-in-production");
        let forged = generate_tokens_with_keys(&old, "admin-id", "a@b.c", "admin").unwrap();
        assert!(validate_token(&forged.access_token).is_err());
        assert!(refresh_access_token(&forged.refresh_token).is_err());
    }

    #[test]
    fn test_generate_and_validate_tokens() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");

        // Validate access token
        let claims = validate_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_refresh_token() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        // Refresh using refresh token
        let new_tokens = refresh_access_token(&tokens.refresh_token).unwrap();

        assert!(!new_tokens.access_token.is_empty());
        assert_ne!(new_tokens.access_token, tokens.access_token);
    }

    #[test]
    fn test_invalid_token() {
        let result = validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_token_type_for_refresh() {
        let tokens = generate_tokens("user-123", "test@example.com", "admin").unwrap();

        // Try to refresh using access token (should fail)
        let result = refresh_access_token(&tokens.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_from_other_key_rejected() {
        let key_a = JwtKeys::new(STRONG_A.as_bytes()).unwrap();
        let key_b = JwtKeys::new(STRONG_B.as_bytes()).unwrap();
        let tokens = generate_tokens_with_keys(&key_a, "user-1", "a@example.com", "admin").unwrap();

        assert!(validate_token_with_keys(&key_a, &tokens.access_token).is_ok());
        assert!(validate_token_with_keys(&key_b, &tokens.access_token).is_err());
        assert!(validate_token_with_keys(&key_b, &tokens.refresh_token).is_err());
    }

    #[test]
    fn test_old_hardcoded_secret_token_rejected() {
        // A token forged with the former compile-time secret must not validate.
        let old = JwtKeys::unchecked(b"your-secret-key-change-in-production");
        let forged = generate_tokens_with_keys(&old, "attacker", "x@example.com", "admin").unwrap();
        assert!(validate_token(&forged.access_token).is_err());
    }

    #[test]
    fn test_short_secret_rejected() {
        assert!(JwtKeys::new(&STRONG_A.as_bytes()[..MIN_SECRET_LEN - 1]).is_err());
        assert!(JwtKeys::new(&STRONG_A.as_bytes()[..MIN_SECRET_LEN]).is_ok());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt_secret");
        let err = resolve_secret(Some("too-short".to_string()), &path).unwrap_err();
        assert!(err.contains(JWT_SECRET_ENV));
        let err = resolve_secret(Some(String::new()), &path).unwrap_err();
        assert!(err.contains(JWT_SECRET_ENV));
        // A rejected env secret must not silently fall back to a generated file.
        assert!(!path.exists());
    }

    #[test]
    fn test_env_secret_used_when_long_enough() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt_secret");
        let value = STRONG_A.to_string();
        let (secret, source) = resolve_secret(Some(value.clone()), &path).unwrap();
        assert_eq!(secret, value.into_bytes());
        assert_eq!(source, SecretSource::Env);
        assert!(!path.exists());
    }

    #[test]
    fn test_generated_secret_file_persisted_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("jwt_secret");

        let (first, src1) = resolve_secret(None, &path).unwrap();
        assert_eq!(src1, SecretSource::GeneratedFile(path.clone()));
        assert!(first.len() >= MIN_SECRET_LEN);
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let (second, src2) = resolve_secret(None, &path).unwrap();
        assert_eq!(src2, SecretSource::ExistingFile(path.clone()));
        assert_eq!(first, second);

        // Tokens issued before a "restart" still validate after it.
        let k1 = JwtKeys::new(&first).unwrap();
        let k2 = JwtKeys::new(&second).unwrap();
        let t = generate_tokens_with_keys(&k1, "u", "u@example.com", "admin").unwrap();
        assert!(validate_token_with_keys(&k2, &t.access_token).is_ok());

        // A different file gets a different random secret.
        let other = dir.path().join("other_secret");
        let (third, _) = resolve_secret(None, &other).unwrap();
        assert_ne!(first, third);
    }

    #[test]
    fn test_short_secret_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt_secret");
        std::fs::write(&path, "short\n").unwrap();
        assert!(resolve_secret(None, &path).is_err());
    }

    #[test]
    fn test_secret_file_defaults_next_to_db() {
        assert_eq!(
            secret_file_next_to_db("/data/dashboard.db"),
            PathBuf::from("/data/jwt_secret")
        );
        assert_eq!(
            secret_file_next_to_db("dashboard.db"),
            PathBuf::from("./jwt_secret")
        );
    }
}
