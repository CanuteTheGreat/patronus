-- Lane H (system/admin): external authentication servers for the web UI
-- login. RADIUS (PAP over UDP, RFC 2865): a person who is not a local
-- account logs in with their RADIUS credentials; the first successful login
-- creates a password-less `web_users` row (password_hash '!external:radius')
-- with the server's default role, which an admin can change or disable like
-- any account. Local accounts never fall back to RADIUS. Read by
-- patronus-web/src/radius.rs and auth.rs.
CREATE TABLE IF NOT EXISTS auth_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- 'radius'
    kind TEXT NOT NULL DEFAULT 'radius',
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 1812,
    -- shared secret; never returned by the API
    secret TEXT NOT NULL,
    -- role of an account created at its first login: operator | readonly
    default_role TEXT NOT NULL DEFAULT 'readonly',
    timeout_secs INTEGER NOT NULL DEFAULT 5,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
