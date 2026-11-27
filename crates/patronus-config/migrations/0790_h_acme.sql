-- Certificate manager (USE=certs, patronus-network/src/certs.rs): ACME
-- certificates the router obtains and renews itself.  Secrets (DNS provider
-- tokens, TSIG secret) are stored like other service secrets and are never
-- returned by the API.  Settings (`certs.*`) live in lan_settings.
CREATE TABLE IF NOT EXISTS acme_certs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    domains TEXT NOT NULL,
    email TEXT,
    tos INTEGER NOT NULL DEFAULT 0,
    directory TEXT NOT NULL DEFAULT 'staging',
    directory_url TEXT,
    ca_bundle TEXT,
    challenge TEXT NOT NULL DEFAULT 'http-01',
    dns_provider TEXT NOT NULL DEFAULT 'none',
    cf_token TEXT,
    cf_api_base TEXT,
    dns_server TEXT,
    dns_zone TEXT,
    tsig_key_name TEXT,
    tsig_algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
    tsig_secret TEXT,
    propagation_secs INTEGER NOT NULL DEFAULT 5,
    renew_days INTEGER NOT NULL DEFAULT 30,
    use_for_web INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- What the last attempt did (bookkeeping, not configuration: one row per
-- certificate, rewritten in place, so it never grows).
CREATE TABLE IF NOT EXISTS acme_status (
    name TEXT PRIMARY KEY,
    last_attempt INTEGER NOT NULL DEFAULT 0,
    last_ok INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    not_after INTEGER NOT NULL DEFAULT 0,
    attempts_failed INTEGER NOT NULL DEFAULT 0
);
