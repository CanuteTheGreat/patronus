-- Lane N: settings of signed plugins (USE=plugins). The schema (types, limits,
-- hints) travels in the signed bundle's manifest; this table holds the values
-- an operator saved, one row per plugin setting, as JSON text of the typed value.
-- `secret` copies the schema flag at save time so a config diff can hide the
-- value without reading the bundle. Plain configuration: it is in the export,
-- in revisions and in GitOps (kind PluginSettings), unlike measured history.
CREATE TABLE IF NOT EXISTS plugin_settings (
    plugin TEXT NOT NULL,
    setting TEXT NOT NULL,
    value TEXT NOT NULL,
    secret INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (plugin, setting)
);
