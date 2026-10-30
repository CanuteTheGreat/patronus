-- Lane S (device segmentation, docs/design/device-segmentation.md): device
-- groups and enrolled devices, group links, one-way service rules, and the
-- per-segment opt-in switch. Nothing here changes behaviour by itself:
-- `seg_segments.enabled` is 0 until the operator turns default-deny
-- isolation on for a segment, and enabling adopts the devices already on it
-- into the built-in `home` group (intra=1, internet=allow).
--
-- Rendered by patronus-firewall/src/seg_rules.rs (own nft table
-- `inet patronus_seg`, hook priority -10, loaded in the same atomic nft -f as
-- the main table); the L2 side (proxy ARP, isolated bridge ports) by
-- patronus-network/src/seg.rs. Accessors: patronus-config/src/seg.rs.

CREATE TABLE IF NOT EXISTS seg_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,                 -- [a-z0-9_-]{1,32}
    description TEXT,
    intra INTEGER NOT NULL DEFAULT 1,          -- members may talk to each other
    internet TEXT NOT NULL DEFAULT 'allow',    -- allow | deny
    quarantine INTEGER NOT NULL DEFAULT 0,     -- members reach DHCP/DNS/ICMP only
    builtin INTEGER NOT NULL DEFAULT 0,
    dns_policy_id INTEGER,                     -- reserved for the DNS-policy lane
    time_policy_id INTEGER                     -- reserved for the time-limit lane
);

-- kind: wifi | wired | vpn. `segment` is a role token ('@lan', '@opt1') or an
-- interface name. A Wi-Fi device is `pending` (mac NULL) until its first join.
CREATE TABLE IF NOT EXISTS seg_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    mac TEXT UNIQUE,
    group_id INTEGER NOT NULL REFERENCES seg_groups(id),
    kind TEXT NOT NULL DEFAULT 'wired',
    segment TEXT NOT NULL,
    ip4 TEXT UNIQUE,
    wg_peer_id INTEGER,
    state TEXT NOT NULL DEFAULT 'active',      -- pending | active | revoked
    dhcp_mapping_id INTEGER REFERENCES dhcp_static_mappings(id) ON DELETE SET NULL,
    dns_policy_id INTEGER,
    time_policy_id INTEGER,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    revoked_at INTEGER,
    last_seen INTEGER,
    last_ip TEXT,
    note TEXT
);

-- bidirectional link between two groups (stored with group_a < group_b)
CREATE TABLE IF NOT EXISTS seg_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_a INTEGER NOT NULL REFERENCES seg_groups(id) ON DELETE CASCADE,
    group_b INTEGER NOT NULL REFERENCES seg_groups(id) ON DELETE CASCADE,
    UNIQUE(group_a, group_b)
);

-- one-way: src may open NEW connections to dst:ports (replies ride conntrack)
CREATE TABLE IF NOT EXISTS seg_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    src_kind TEXT NOT NULL,                    -- device | group
    src_id INTEGER NOT NULL,
    dst_kind TEXT NOT NULL,
    dst_id INTEGER NOT NULL,
    proto TEXT NOT NULL,                       -- tcp | udp
    ports TEXT NOT NULL,                       -- "80,443,8000-8010"
    schedule TEXT,                             -- reserved: not enforced yet
    enabled INTEGER NOT NULL DEFAULT 1
);

-- per-segment opt-in. A segment is a role token or interface name.
CREATE TABLE IF NOT EXISTS seg_segments (
    segment TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    adopted_at INTEGER,
    updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO seg_groups (name, description, intra, internet, quarantine, builtin)
    VALUES ('home', 'Devices that were on the network when segmentation was enabled', 1, 'allow', 0, 1);
INSERT OR IGNORE INTO seg_groups (name, description, intra, internet, quarantine, builtin)
    VALUES ('quarantine', 'Unknown devices: DHCP, DNS and ping only', 0, 'deny', 1, 1);
