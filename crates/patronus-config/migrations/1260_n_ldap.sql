-- Lane N: LDAP / Active Directory login for the web UI (auth_servers rows of
-- kind 'ldap'). `host`/`port` is the directory server, `secret` the password
-- of the optional search account `bind_dn` (never returned by the API).
-- The login searches `base_dn` with `user_filter` ({u} = the escaped user
-- name) using that account (anonymous when empty), then binds as the entry
-- found with the password the person typed. Members of `operator_group` (a
-- group entry DN holding `member: <user dn>`) get the operator role at their
-- first login, everybody else the server's default role.
ALTER TABLE auth_servers ADD COLUMN base_dn TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_servers ADD COLUMN bind_dn TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_servers ADD COLUMN user_filter TEXT NOT NULL DEFAULT '(uid={u})';
-- none | starttls | ldaps
ALTER TABLE auth_servers ADD COLUMN tls TEXT NOT NULL DEFAULT 'none';
ALTER TABLE auth_servers ADD COLUMN operator_group TEXT NOT NULL DEFAULT '';
