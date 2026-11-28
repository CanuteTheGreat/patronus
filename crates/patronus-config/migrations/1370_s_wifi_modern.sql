-- Lane S: Wi-Fi 6/6E/7 on the standard tier (docs/WIFI-MODERN.md). Every value is a typed column with the
-- documented default (patronus_config::seg_wifi_gen, a test compares them). Existing networks get
-- standard 'auto': the newest generation the radio AND the installed hostapd support, probed at apply time.
-- band may now also be '6g' (WPA3-SAE only, checked by the store) and width 160 / 320 (6 GHz).
ALTER TABLE seg_wifi_networks ADD COLUMN standard TEXT NOT NULL DEFAULT 'auto';     -- auto | n | ac | ax | be
ALTER TABLE seg_wifi_networks ADD COLUMN bss_color INTEGER NOT NULL DEFAULT 0;      -- 1-63, 0 = derived from the name
ALTER TABLE seg_wifi_networks ADD COLUMN discovery TEXT NOT NULL DEFAULT 'auto';    -- 6 GHz: auto | probe | fils | off
ALTER TABLE seg_wifi_networks ADD COLUMN discovery_interval INTEGER NOT NULL DEFAULT 20; -- TU between discovery frames, 1-20
ALTER TABLE seg_wifi_networks ADD COLUMN mlo_links TEXT NOT NULL DEFAULT '';        -- Wi-Fi 7 extra links: band/channel/width,...
ALTER TABLE seg_wifi_networks ADD COLUMN mlo_wait INTEGER NOT NULL DEFAULT 20;       -- s every multi-link link gets to come up, 5-120
