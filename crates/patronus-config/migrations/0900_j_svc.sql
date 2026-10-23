-- Feature pages (patronus-network/src/svc.rs): tables of the daemon-backed
-- features that need a list of rows. Their settings live in lan_settings
-- (`<slug>.<key>`). Applied by the feature's applier; undone with the LAN
-- tables snapshot when the applier refuses a change.

-- syslog (USE=syslog): remote collectors, written to /etc/rsyslog.d
CREATE TABLE IF NOT EXISTS syslog_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER,
    proto TEXT,
    severity TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- IGMP proxy (USE=igmp): downstream interfaces
CREATE TABLE IF NOT EXISTS igmp_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- L2TP server (USE=l2tp): PPP users (passwords are secrets, never returned)
CREATE TABLE IF NOT EXISTS l2tp_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- IDS (USE=intrusion-detection): custom Suricata rules
CREATE TABLE IF NOT EXISTS ids_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    proto TEXT,
    src TEXT,
    dst TEXT,
    dport TEXT,
    content TEXT,
    msg TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- Dynamic routing (USE=dynamic-routing): FRR BGP neighbours/networks, OSPF interfaces
CREATE TABLE IF NOT EXISTS frr_bgp_neighbors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    remote_as INTEGER NOT NULL,
    password TEXT,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS frr_bgp_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS frr_ospf_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iface TEXT NOT NULL,
    area TEXT,
    passive INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL
);

-- Wake-on-LAN: saved hosts
CREATE TABLE IF NOT EXISTS wol_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mac TEXT NOT NULL,
    interface TEXT,
    updated_at INTEGER NOT NULL
);

-- SD-WAN edge (USE=sdwan): announced endpoints and subnets; the agent's own
-- credentials live in edge_state (outside the web UI's undo snapshot)
CREATE TABLE IF NOT EXISTS edge_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    interface_type TEXT,
    cost_per_gb INTEGER,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edge_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edge_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
