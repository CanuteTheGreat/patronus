# Signed plugins and their settings

A plugin is one signed bundle (`patronus plugin keygen | pack | verify`, installed from the Packages page or
`POST /api/packages/plugins`, USE=plugins, standard tier only). The manifest (`plugin.json` in the plugin
directory, signed as a whole) lists the files, an optional supervised `service` and an optional `settings`
schema. Nothing is installed unless the signature verifies against a trusted key.

## Settings schema

Each entry of `settings` is one typed setting. Patronus draws the form on the Packages page from it, checks
every saved value on the server against the same schema, stores the values as configuration and hands them to
the service in a private file.

| field | meaning |
| --- | --- |
| `key` | lowercase letters, digits, `_`, starting with a letter, at most 40 characters |
| `type` | `string`, `int`, `bool`, `enum`, `address` (IPv4 or IPv6), `port`, `list` |
| `label`, `hint` | form label (80 characters) and hint (400). The hint shows on hover and on keyboard focus and is the field's `aria-describedby` |
| `default` | used when no value is saved; must itself pass the schema |
| `min`, `max` | `int`/`port`: bounds of the value; `string`: length; `list`: number of items (at most 256) |
| `pattern` | `string` (and `list` of strings): the whole value must match this regular expression (linear-time engine) |
| `values` | `enum`: the allowed values |
| `item`, `item_min`, `item_max` | `list`: the item type (`string` by default, `int`, `address`, `port`) and its bounds |
| `secret` | `string` only: never sent back to a browser or API client (only whether one is saved), no default allowed |
| `required` | no default and no saved value: the service is not started and the apply says why |

At most 64 settings. An invalid schema (min above max, a default that fails its own rule, a pattern that does not
compile, `values` on an int, ...) is refused by `patronus plugin pack` and again when a bundle is installed.

## How the values reach the service

- Values live in the store table `plugin_settings` (migration 1290), so they ride in the config export/import,
  in revisions and rollback. A config diff hides rows flagged `secret`.
- The plugins applier writes the effective values (saved value, else default) to two files next to the plugin
  directory, mode 0600, owned by root:
  `<state>/net/plugins/<name>.settings.json` (one JSON object) and `<state>/net/plugins/<name>.settings.env`
  (`PLUGIN_<KEY>='value'` lines, lists as compact JSON, for shell services).
- The service finds them through the placeholders `{settings}` (the JSON file) and `{settings_env}` (the env
  file) in its `service.exec` arguments. A change restarts the service; an unchanged apply leaves it running.
- Installing an update keeps the saved values the new schema still accepts and drops the rest (the default
  applies again). Removing the plugin deletes its values and both files.
- The signed bundle is public: a secret has no default, and error messages never repeat a refused value.

## API

- `GET  /api/packages/plugins/<name>/settings`: schema plus current values; a secret has `value: null` and `is_set`.
- `PUT  /api/packages/plugins/<name>/settings` (admin): `{"values": {key: value}, "clear": [key]}`. All or
  nothing; an unknown key or an invalid value is `400` with the reason; a secret sent as an empty string keeps
  its saved value; `clear` returns a key to its default.
- GitOps: `kind: PluginSettings`, `metadata.name` = the plugin, `spec` = `{key: value}`. The declared keys
  replace the saved ones; a plain key left out returns to its default, a secret left out is kept. Deleting the
  resource clears every saved value of the plugin.

## Proof

Unit tests in `crates/patronus-network/src/plugin_settings.rs` (schema checks, out-of-range refusal, secret
masking, export/import round trip, update reconcile, GitOps replace), `ci/netlab/lane-n-plugin-settings.sh`
(real binaries: fail closed on a required value, API refusals, 0600 file, service restart, update, reboot,
removal) and `ci/plugin-settings-e2e.py` (Playwright Firefox at 1280 and 390 px, light and dark: form, hints,
refusals, saved values in the file and the service, the secret never in the page or any response, contrast).
