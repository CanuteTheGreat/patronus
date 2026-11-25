-- Request history is operational data, not configuration. Timestamps are UTC
-- Unix milliseconds; the monotonically increasing id is the live cursor.
CREATE TABLE IF NOT EXISTS web_access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL,
    client TEXT NOT NULL,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('anonymous', 'user', 'api_key')),
    principal_name TEXT,
    api_key_id INTEGER,
    attempted_user TEXT,
    method TEXT NOT NULL,
    path_group TEXT NOT NULL,
    status INTEGER NOT NULL CHECK (status BETWEEN 100 AND 599),
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    bytes INTEGER CHECK (bytes IS NULL OR bytes >= 0)
);
CREATE INDEX IF NOT EXISTS web_access_log_timestamp ON web_access_log(timestamp_ms, id);
CREATE INDEX IF NOT EXISTS web_access_log_principal ON web_access_log(principal_name, timestamp_ms);
CREATE INDEX IF NOT EXISTS web_access_log_api_key ON web_access_log(api_key_id, timestamp_ms);
