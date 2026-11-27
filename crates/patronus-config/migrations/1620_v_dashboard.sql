-- Customizable dashboard (lane u, patronus-config/src/dashboard.rs): one layout
-- document per web user (widget ids and on/off, in display order). Ids are
-- validated against the widget registry of patronus-web on save and unknown ids
-- are dropped on read, so a layout survives upgrades and downgrades. Settings
-- (`dashboard.*`, `diag.*`) are keys of system_config.
CREATE TABLE IF NOT EXISTS dashboard_layouts (
    user TEXT PRIMARY KEY,
    layout_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
