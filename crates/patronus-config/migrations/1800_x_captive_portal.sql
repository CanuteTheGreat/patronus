-- Lane x: captive portal (USE=captive-portal, patronus_network::captive + patronus-captiveportal).
-- Configuration: zones bound to an interface/VLAN/bridge, portal users, voucher rolls and their
-- codes, passthrough entries. Global settings are `captive.*` keys of lan_settings.
CREATE TABLE IF NOT EXISTS cp_zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    interface TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'none',
    radius_server TEXT,
    radius_port INTEGER,
    radius_acct_port INTEGER,
    radius_secret TEXT,
    radius_accounting INTEGER,
    radius_nas_id TEXT,
    radius_timeout_secs INTEGER,
    idle_minutes INTEGER,
    hard_minutes INTEGER,
    download_kbit INTEGER,
    upload_kbit INTEGER,
    terms_required INTEGER,
    https_login INTEGER,
    redirect_url TEXT,
    page_title TEXT,
    welcome_text TEXT,
    terms_text TEXT,
    button_text TEXT,
    success_text TEXT,
    logout_text TEXT,
    user_label TEXT,
    password_label TEXT,
    voucher_label TEXT,
    error_text TEXT,
    accent_color TEXT,
    description TEXT,
    max_sessions INTEGER,
    updated_at INTEGER NOT NULL
);

-- Local portal accounts (password = argon2 hash). zone empty = every zone with local login.
CREATE TABLE IF NOT EXISTS cp_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    zone TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Voucher rolls: `count` codes valid for `minutes` from their first use.
CREATE TABLE IF NOT EXISTS cp_voucher_rolls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 20,
    minutes INTEGER NOT NULL DEFAULT 60,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- The codes of a roll (generated when the roll is created).
CREATE TABLE IF NOT EXISTS cp_vouchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    roll_id INTEGER NOT NULL,
    code TEXT NOT NULL UNIQUE,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cp_vouchers_roll ON cp_vouchers(roll_id);

-- Passthrough: client MACs / client IPs (CIDR) that never see the portal, and destination host
-- names (resolved at apply time) reachable before login.
CREATE TABLE IF NOT EXISTS cp_passthrough (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zone TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Runtime state (NON_CONFIG_TABLES: never exported, never rolled back, pruned after
-- captive.session_retention_days).
CREATE TABLE IF NOT EXISTS cp_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sid TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    dev TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL,
    voucher TEXT,
    started INTEGER NOT NULL,
    expires INTEGER NOT NULL DEFAULT 0,
    idle_secs INTEGER NOT NULL DEFAULT 0,
    download_kbit INTEGER NOT NULL DEFAULT 0,
    upload_kbit INTEGER NOT NULL DEFAULT 0,
    last_interim INTEGER NOT NULL DEFAULT 0,
    disconnect_req INTEGER NOT NULL DEFAULT 0,
    ended INTEGER,
    end_reason TEXT
);
CREATE INDEX IF NOT EXISTS cp_sessions_active ON cp_sessions(ended);

CREATE TABLE IF NOT EXISTS cp_voucher_use (
    code TEXT PRIMARY KEY,
    first_used INTEGER NOT NULL,
    expires INTEGER NOT NULL
);
