-- Lane s (device segmentation), part d: traffic insight history.
-- Hourly buckets of conntrack byte deltas by (internal address, direction,
-- country, ASN), written by patronus-web's insight collector
-- (state/insight.rs). Rows are keyed by the internal IP so the history works
-- before and without the device model; the per-device views join
-- seg_devices (ip4 / last_ip) at query time when that table exists.
CREATE TABLE IF NOT EXISTS ins_usage (
    bucket  INTEGER NOT NULL,              -- unix time of the hour start
    ip      TEXT    NOT NULL,              -- the internal (LAN side) address
    dir     TEXT    NOT NULL,              -- up (device -> remote) | down
    country TEXT    NOT NULL DEFAULT '--', -- ISO 3166 code, '--' unknown/folded, 'LAN' not used
    asn     INTEGER NOT NULL DEFAULT 0,    -- 0 unknown/folded
    asn_org TEXT    NOT NULL DEFAULT '',
    bytes   INTEGER NOT NULL DEFAULT 0,
    packets INTEGER NOT NULL DEFAULT 0,
    flows   INTEGER NOT NULL DEFAULT 0,    -- flows opened in the bucket
    PRIMARY KEY (bucket, ip, dir, country, asn)
);
CREATE INDEX IF NOT EXISTS idx_ins_usage_ip ON ins_usage(ip, bucket);

-- Privacy: addresses, CIDRs, device names or group names whose traffic is
-- never recorded. kind = ip | group | device.
CREATE TABLE IF NOT EXISTS ins_exclude (
    kind TEXT NOT NULL,
    ref  TEXT NOT NULL,
    PRIMARY KEY (kind, ref)
);
