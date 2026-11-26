-- Lane H: the language an account sees the web UI and the API's messages in.
-- '' = no choice of its own: the system default (system_config `ui.language`, then the
-- browser's Accept-Language) applies. Read and written by patronus-web (i18n).
ALTER TABLE web_users ADD COLUMN language TEXT NOT NULL DEFAULT '';
