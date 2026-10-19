-- Lane H (system/admin): web UI accounts, persisted in the config store
-- (they used to live in memory: every account but the generated admin
-- vanished on restart). Read and written by patronus-web/src/auth.rs.
--
-- Accounts are configuration like everything else: they are part of
-- backups, exports and config revisions (password hashes and TOTP secrets
-- included, which is why backup files are 0600 and admin-only). An import
-- of a document that predates this table keeps the current accounts.
CREATE TABLE IF NOT EXISTS web_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    -- argon2 PHC string (patronus_secrets::crypto::hash_password)
    password_hash TEXT NOT NULL,
    -- 'admin' | 'operator' | 'readonly'
    role TEXT NOT NULL DEFAULT 'readonly',
    enabled INTEGER NOT NULL DEFAULT 1,
    -- TOTP (RFC 6238, USE=totp): base32 secret once enrolment is confirmed
    totp_secret TEXT,
    -- secret of an enrolment that was started but not confirmed yet
    totp_pending TEXT,
    -- last accepted 30-second step: a code is accepted once
    totp_last_step INTEGER,
    -- JSON array of SHA-256 hex digests of the unused recovery codes
    recovery_codes TEXT,
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    updated_at INTEGER NOT NULL
);
