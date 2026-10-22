-- Lane H (system/admin): API keys for automation (Rustinion collectors,
-- Terraform, scripts). Only a SHA-256 digest of the token is stored: the
-- token itself is shown once, when it is created. Read by
-- patronus-web/src/apikeys.rs.
--
-- scope: 'readonly' (GET only) or 'operator' (may change configuration).
-- Keys never carry admin rights: accounts, backups/restores and key
-- management stay with logged-in admins.
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- first characters of the token, to recognise it in the list
    prefix TEXT NOT NULL,
    -- SHA-256 (hex) of the whole token
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'readonly',
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    -- unix seconds; NULL = never expires
    expires_at INTEGER,
    last_used_at INTEGER
);
