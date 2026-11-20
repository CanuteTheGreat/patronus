# Web UI port and the anti-lockout rule

The web interface listens on HTTPS port 8443 by default. The port is a typed
setting, not a constant.

| Where | How |
|---|---|
| Store | `system_config` key `web.https_port` (empty/absent = default 8443). It is part of every export, backup, revision and import, so declarative export / plan / apply and config history carry it like any other row. |
| API | `GET /api/system/web` shows the stored port (`configured`), the environment override (`env_override`), the `effective_port`, the port this process listens on (`running_port`) and `restart_required`. `PUT /api/system/web {"https_port": 9443}` stores it (admin only, `0` = back to the default); a port outside 1-65535 or the SSH port is a 400. |
| UI | System page, "Web interface" card. |
| Environment | `PATRONUS_HTTPS_PORT` wins over the stored key (the router image sets it to 443). The `patronus-web` process reads it. The firewall applier reads it too, so a process that applies the firewall without that variable (applyd) sees only the stored key: on a unit that needs the variable, also store the same port. |

Precedence: `PATRONUS_HTTPS_PORT`, then `web.https_port`, then 8443.

The listener moves to a new port at the next restart of `patronus-web` (the
System page says so). Saving first re-applies the firewall, so the new port is
already open when you restart.

## Anti-lockout follows the real ports

The system rule "Anti-lockout" (management access from `@mgmt`) is stored with
the seeded ports tcp 22 and 8443. When the ruleset is rendered, normally and in
lockdown, it is rewritten from the configured settings
(`patronus_config::defaults::follow_ports`):

* the SSH port (`ssh.port`, for example 2222 after an OpenWrt import) replaces 22;
* the web port, when one is configured (environment or `web.https_port`), replaces
  the seeded 8443, or is added when the stored list does not name it (the router
  image seeds `22,80,443`).

Nothing is written back to the stored rule, so a port change can never leave a
stale value behind. `PATRONUS_ANTI_LOCKOUT_PORTS` still sets the seeded list at
first boot.

Proof: unit tests in `patronus-config` (`defaults.rs`) and `patronus-firewall`
(`anti_lockout_follows_web_port`), and netlab step 1b of `lane-h-system.sh`
(nft ruleset after `PUT /api/system/web`).
