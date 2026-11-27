#!/usr/bin/env bash
# Lane N: default text editor (System page > Default text editor). The key is `[system] editor` in
# patronus.toml, PUT /api/system/editor and the GitOps resource `kind: DefaultEditor`; the applier runs the
# image's `default-editor set <choice>` and the result is checked on the system itself
# (/etc/default-editor.conf, /etc/env.d/99editor). A refused value (unknown name, a binary that is not
# installed) is a 400 with the reason and changes nothing; a reboot (`patronus apply`) puts the editor back.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

DB=/t/lane-n-default-editor.db
DIR=/t/default-editor
rm -rf "$DB" "$NL_T/nl-jar" "$DIR"; mkdir -p "$DIR"
command -v git >/dev/null || { apt-get install -y -qq git >/dev/null; }

# the tool of the image (run.sh copies it next to the lanes) and two stand-in editors
install -m 0755 "$NL_T/default-editor" /usr/sbin/default-editor
for b in /usr/bin/vim /usr/bin/nvim /usr/bin/nano; do [ -x "$b" ] || { printf '#!/bin/sh\nexit 0\n' >"$b"; chmod 755 "$b"; MADE+=("$b"); }; done
cp -a /etc/env.d/99editor "$DIR/99editor.orig" 2>/dev/null || true
cleanup() { for b in "${MADE[@]:-}"; do [ -n "$b" ] && rm -f "$b"; done; rm -f /etc/default-editor.conf; }
trap cleanup EXIT
rm -f /etc/default-editor.conf /etc/env.d/99editor
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$NL_OUT" "$1"; }
effective() { sed -n 's/^EDITOR="\(.*\)"/\1/p' /etc/env.d/99editor; }

nl_write_installer_toml
printf '\n[system]\neditor = "nano"\n' >>"$NL_TOML"
nl_boot "$DB"
[ "$(effective)" = /usr/bin/nano ] || nl_fail "patronus.toml [system] editor = nano was not applied at the first boot: $(cat /etc/env.d/99editor 2>&1)"
grep -q '^EDITOR_CHOICE=nano$' /etc/default-editor.conf || nl_fail "/etc/default-editor.conf: $(cat /etc/default-editor.conf)"
nl_ok "patronus.toml [system] editor is applied at the first boot"

nl_web_start "$DB"; nl_login
nl_api GET /system/editor; [ "$NL_CODE" = 200 ] || nl_fail "GET editor: $NL_CODE"
[ "$(jget 'd["settings"]["editor"]')" = nano ] || nl_fail "stored: $(cat "$NL_OUT")"
[ "$(jget 'd["embedded"]')" = False ] || nl_fail "embedded flag: $(cat "$NL_OUT")"
nl_web GET /system; [ "$NL_CODE" = 200 ] && grep -q 'id="editor-card"' "$NL_OUT" || nl_fail "System page has no editor card: $NL_CODE"
nl_ok "the API reports the stored choice; the System page has the control"

nl_api PUT /system/editor '{"editor":"neovim"}'
[ "$NL_CODE" = 200 ] || nl_fail "PUT neovim: $NL_CODE $(cat "$NL_OUT")"
[ "$(effective)" = /usr/bin/nvim ] || nl_fail "neovim not in effect: $(cat /etc/env.d/99editor)"
grep -q '^VISUAL="/usr/bin/nvim"$' /etc/env.d/99editor || nl_fail "VISUAL: $(cat /etc/env.d/99editor)"
nl_ok "PUT neovim: EDITOR and VISUAL are /usr/bin/nvim"

for bad in '{"editor":"emacs"}' '{"editor":""}' '{"editor":"vim -u NONE"}' '{"editor":"/usr/bin/../bin/vim"}' '{"editor":"relative/vim"}'; do
  nl_api PUT /system/editor "$bad"
  [ "$NL_CODE" = 400 ] || nl_fail "$bad must be refused (400), got $NL_CODE $(cat "$NL_OUT")"
  grep -q 'Invalid editor' "$NL_OUT" || nl_fail "the refusal does not say what is wrong: $(cat "$NL_OUT")"
done
[ "$(effective)" = /usr/bin/nvim ] || nl_fail "a refused value changed the editor"
nl_ok "invalid editors are refused with the reason, nothing changed"

rm -f /usr/bin/nvim
nl_api PUT /system/editor '{"editor":"neovim"}'
nl_api PUT /system/editor '{"editor":"/opt/none/bin/ed"}'
[ "$NL_CODE" = 400 ] && grep -q 'not installed' "$NL_OUT" || nl_fail "a missing binary must be refused: $NL_CODE $(cat "$NL_OUT")"
nl_api GET /system/editor
[ "$(jget 'd["settings"]["editor"]')" = neovim ] || nl_fail "rollback failed: $(cat "$NL_OUT")"
nl_ok "an editor that is not installed is refused and rolled back (neovim needs app-editors/neovim)"
printf '#!/bin/sh\nexit 0\n' >/usr/bin/nvim; chmod 755 /usr/bin/nvim

echo "=== reboot: something resets the box, patronus apply restores it"
nl_web_stop
rm -f /etc/default-editor.conf /etc/env.d/99editor
nl_boot "$DB"
[ "$(effective)" = /usr/bin/nvim ] || nl_fail "editor not restored at boot: $(cat /etc/env.d/99editor 2>&1)"
nl_ok "the setting survives a reboot"

echo "=== GitOps: kind DefaultEditor"
UP=$DIR/upstream
cat >>"$NL_TOML" <<EOF

[gitops]
repo_url = "$UP"
branch = "main"
local_path = "$DIR/clone"
config_path = "config"
poll_interval_secs = 5
auto_apply = true
EOF
g() { git -C "$UP" -c user.name=QA -c user.email=qa@example.invalid "$@"; }
git init -q -b main "$UP"; mkdir -p "$UP/config"
cat >"$UP/config/resources.yaml" <<'EOF'
- apiVersion: patronus.firewall/v1
  kind: DefaultEditor
  metadata: { name: default-editor }
  spec: { editor: vim }
EOF
g add -A && g commit -qm editor
R "$P" --db "$DB" gitops sync --apply --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1 || { cat "$NL_OUT"; nl_fail "gitops sync failed"; }
[ "$(effective)" = /usr/bin/vim ] || { cat "$NL_OUT"; nl_fail "GitOps editor not applied: $(cat /etc/env.d/99editor)"; }
nl_ok "GitOps DefaultEditor applied: vim"

cat >"$UP/config/resources.yaml" <<'EOF'
- apiVersion: patronus.firewall/v1
  kind: DefaultEditor
  metadata: { name: default-editor }
  spec: { editor: emacs }
EOF
g add -A && g commit -qm bad
if R "$P" --db "$DB" gitops sync --apply --bootstrap "$NL_TOML" --state-dir "$DIR/state" >"$NL_OUT" 2>&1; then cat "$NL_OUT"; nl_fail "an invalid editor was accepted from git"; fi
grep -q 'Invalid editor' "$NL_OUT" || { cat "$NL_OUT"; nl_fail "no reason for the refused editor"; }
[ "$(effective)" = /usr/bin/vim ] || nl_fail "refused git change altered the editor"
nl_ok "an invalid editor in git is refused with the reason"
echo "PASS lane-n-default-editor"
