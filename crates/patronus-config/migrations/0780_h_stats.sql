-- Historical statistics (lane H, patronus-web/src/state/stats.rs):
-- 5-minute averages of cpu / mem (percent) and rx:<if> / tx:<if> (bit/s),
-- kept stats.retention_days (default 30); per-interface daily byte totals
-- for monthly data accounting, kept two years.
CREATE TABLE IF NOT EXISTS stat_points (
    ts INTEGER NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS stat_points_metric_ts ON stat_points(metric, ts);
CREATE INDEX IF NOT EXISTS stat_points_ts ON stat_points(ts);
CREATE TABLE IF NOT EXISTS traffic_daily (
    day TEXT NOT NULL,
    iface TEXT NOT NULL,
    rx INTEGER NOT NULL DEFAULT 0,
    tx INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, iface)
);
