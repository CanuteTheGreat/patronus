-- Groups and privileges (RBAC) for web accounts. A group maps areas of the
-- UI/API to 'read' or 'write'; an account that is a member gets exactly
-- those privileges instead of the coarse role (admins always keep
-- everything). Read by patronus-web/src/rbac.rs, enforced in the request gate.
CREATE TABLE IF NOT EXISTS rbac_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- JSON object: {"firewall": "write", "vpn": "read", ...}
    privileges TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rbac_members (
    user_id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL
);
