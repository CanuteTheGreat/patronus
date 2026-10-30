-- Lane s, part d: uplink (gateway) health history, extra probes, SLA rollups.
-- Written by patronus-web's uplink recorder (state/uplink.rs) from the
-- gateway monitor's published results.
CREATE TABLE IF NOT EXISTS ins_uplink_samples (
    ts       INTEGER NOT NULL,             -- unix time, one row per gateway per minute
    gateway  TEXT    NOT NULL,
    state    TEXT    NOT NULL,             -- online | loss | latency | down | pending | unmonitored
    rtt_ms   REAL,
    loss_pct REAL,
    icmp_ok  INTEGER,                      -- NULL = not probed
    tcp_ok   INTEGER,
    dns_ok   INTEGER,
    http_ok  INTEGER,
    degraded INTEGER NOT NULL DEFAULT 0,   -- an extra probe failed while ICMP answered
    probes   TEXT    NOT NULL DEFAULT '[]',-- JSON: every probe result of the sample
    PRIMARY KEY (ts, gateway)
);
CREATE INDEX IF NOT EXISTS idx_ins_uplink_gw ON ins_uplink_samples(gateway, ts);

-- One row per sample hour so SLA graphs outlive the raw minutes.
CREATE TABLE IF NOT EXISTS ins_uplink_hourly (
    hour     INTEGER NOT NULL,
    gateway  TEXT    NOT NULL,
    samples  INTEGER NOT NULL DEFAULT 0,
    up       INTEGER NOT NULL DEFAULT 0,   -- samples not down
    good     INTEGER NOT NULL DEFAULT 0,   -- online and no failing probe
    degraded INTEGER NOT NULL DEFAULT 0,
    down     INTEGER NOT NULL DEFAULT 0,
    rtt_sum  REAL    NOT NULL DEFAULT 0,
    rtt_n    INTEGER NOT NULL DEFAULT 0,
    rtt_max  REAL,
    loss_sum REAL    NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, gateway)
);

-- Probes besides ICMP, run through each gateway's own interface.
CREATE TABLE IF NOT EXISTS ins_uplink_probes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    gateway  TEXT    NOT NULL REFERENCES route_gateways(name) ON DELETE CASCADE ON UPDATE CASCADE,
    kind     TEXT    NOT NULL,             -- tcp | http | dns
    target   TEXT    NOT NULL,             -- tcp: IP; dns: resolver IP; http: URL
    port     INTEGER,                      -- tcp (required)
    name     TEXT    NOT NULL DEFAULT '',  -- dns: the name to resolve
    critical INTEGER NOT NULL DEFAULT 0,   -- a failure counts as a lost sample (feeds failover)
    enabled  INTEGER NOT NULL DEFAULT 1,
    UNIQUE (gateway, kind, target, port, name)
);
