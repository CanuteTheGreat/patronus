-- Lane u, part b: UPS readings (USE=ups), one row per UPS per sample.
-- Written by patronus-web's UPS recorder (state/ups.rs) from `upsc`; measured
-- history, so it is in NON_CONFIG_TABLES and pruned by `ups.retention_days`.
CREATE TABLE IF NOT EXISTS ups_samples (
    ts          INTEGER NOT NULL,           -- unix time
    ups         TEXT    NOT NULL,           -- UPS name (ups.ups_name)
    state       TEXT    NOT NULL,           -- online | on_battery | low_battery | unknown
    flags       TEXT    NOT NULL DEFAULT '',-- raw ups.status words (OL CHRG, OB DISCHRG LB, RB ...)
    charge_pct  REAL,                       -- NULL = the UPS did not report it
    runtime_s   INTEGER,
    load_pct    REAL,
    input_v     REAL,
    output_v    REAL,
    battery_v   REAL,
    PRIMARY KEY (ts, ups)
);
CREATE INDEX IF NOT EXISTS idx_ups_samples_ups ON ups_samples(ups, ts);
