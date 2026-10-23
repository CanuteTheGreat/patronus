-- Remote / encrypted automatic configuration backups. Each target is a URL
-- the configuration export is uploaded to (http(s) PUT = WebDAV/Nextcloud/
-- an object-store gateway, sftp://, ftps://) by curl, optionally encrypted
-- first with AES-256-GCM under a key derived (Argon2id) from a passphrase.
-- Read by patronus-web/src/backup_remote.rs.
--
-- password / passphrase are stored in this store like the web password
-- hashes and API credentials: backups of the store and the store itself
-- are 0600, admin-only; the API never returns them.
CREATE TABLE IF NOT EXISTS backup_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    passphrase TEXT NOT NULL DEFAULT '',
    -- 0 = only when asked ("run now")
    interval_hours INTEGER NOT NULL DEFAULT 24,
    insecure_tls INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run INTEGER,
    last_status TEXT,
    last_file TEXT
);
