-- Lane E (WAN & routing): gateways, gateway monitoring, gateway groups
-- (multi-WAN failover / load balancing) and static routes, applied by
-- patronus-network/src/routes.rs (boot phase "routes").
--
-- Static routes use the foundation `routes` table (lane E owns it):
--   destination/prefix_len  the network (NULL destination = default route)
--   gateway                 an IP address OR the name of a row in
--                           route_gateways (resolved at apply time, so a
--                           DHCP/PPPoE gateway that changes address keeps
--                           its routes)
--   interface               a device or @role (optional with an IP gateway)
-- Patronus tags the kernel routes it installs with its own route protocol
-- numbers and only ever removes routes carrying them.

-- A gateway = an upstream router reached through one interface.
CREATE TABLE IF NOT EXISTS route_gateways (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- device name or @role (@wan, @opt1, ...)
    interface TEXT NOT NULL,
    -- 'inet' | 'inet6'
    family TEXT NOT NULL DEFAULT 'inet',
    -- NULL = dynamic: learned from the interface's own default route (DHCP
    -- lease, PPPoE peer, static interface gateway, IPv6 router advertisement)
    address TEXT,
    -- address probed by the monitor; NULL = the gateway address itself
    monitor_ip TEXT,
    monitor_enabled INTEGER NOT NULL DEFAULT 1,
    -- thresholds: a gateway whose packet loss over the last probes reaches
    -- loss_threshold (%) or whose average round trip exceeds
    -- latency_threshold (ms) counts as degraded
    loss_threshold INTEGER NOT NULL DEFAULT 20,
    latency_threshold INTEGER NOT NULL DEFAULT 500,
    description TEXT,
    updated_at INTEGER NOT NULL
);

-- Multi-WAN (USE=multiwan): members in the lowest tier with at least one
-- usable gateway carry the traffic (several in that tier = load balanced by
-- weight); higher tiers take over when a whole tier fails.
CREATE TABLE IF NOT EXISTS route_gateway_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- when a member stops being usable: 'down' (no replies at all),
    -- 'loss', 'latency' or 'loss_latency'
    trigger TEXT NOT NULL DEFAULT 'down',
    description TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS route_gateway_group_members (
    group_name TEXT NOT NULL REFERENCES route_gateway_groups(name)
        ON DELETE CASCADE ON UPDATE CASCADE,
    gateway TEXT NOT NULL REFERENCES route_gateways(name)
        ON DELETE CASCADE ON UPDATE CASCADE,
    tier INTEGER NOT NULL DEFAULT 1,
    weight INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (group_name, gateway)
);

-- The default route Patronus installs (system_config keys, set by the UI):
--   routing.default_gateway4 / routing.default_gateway6 = a gateway or group
--   name; absent or '' = automatic (the per-interface default routes the
--   interfaces phase installs, preferred by role: WAN, then OPT1, ...).
