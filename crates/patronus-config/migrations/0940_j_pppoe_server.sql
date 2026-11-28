-- PPPoE access concentrator accounts. Global settings live in lan_settings.
-- Passwords are shared secrets required by CHAP; the service UI must mask them
-- and generated pppd files must be root-owned with mode 0600.
CREATE TABLE IF NOT EXISTS pppoe_server_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    address TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);
