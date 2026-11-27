#!/bin/sh
# Host test of the embedded tier's /etc/profile.d/10-editor.sh (busybox/dash-style sh): the default is busybox vi, never nano, whatever
# /etc/default-editor.conf says; vim/nvim/an absolute path are honoured only when that binary exists. Both embedded overlays ship the same file.
H=$(cd "$(dirname "$0")/../.." && pwd)
F1=$H/embedded-aarch64/ax1800/overlay/etc/profile.d/10-editor.sh
F2=$H/embedded-mips/overlay/etc/profile.d/10-editor.sh
W=$(mktemp -d "${TMPDIR:-/tmp}/edprof.XXXX"); trap 'rm -rf "$W"' EXIT
fail=0
no() { echo "FAIL: editor-profile: $1"; fail=1; }
ok() { echo "PASS: editor-profile: $1"; }
cmp -s "$F1" "$F2" && ok "both overlays ship the same file" || no "ax1800 and slate editor profiles differ"
run() { # conf-content -> prints "EDITOR VISUAL"
  conf=$W/conf; if [ -n "$1" ]; then printf '%s\n' "$1" > "$conf"; else rm -f "$conf"; fi
  sed "s#/etc/default-editor.conf#$conf#g" "$F1" > "$W/p.sh"
  sh -c ". $W/p.sh; echo \"\$EDITOR \$VISUAL\""
}
[ "$(run '')" = "vi vi" ] && ok "default (no conf) is vi" || no "default is '$(run '')'"
[ "$(run 'EDITOR_CHOICE=vim')" != "nano nano" ] && ok "vim choice never yields nano" || no "vim choice gave nano"
[ "$(run 'EDITOR_CHOICE=nano')" = "vi vi" ] && ok "nano in the conf is ignored (vi)" || no "nano conf gave '$(run 'EDITOR_CHOICE=nano')'"
[ "$(run 'EDITOR_CHOICE=/nonexistent/ed')" = "vi vi" ] && ok "missing absolute path falls back to vi" || no "missing path not ignored"
cp /bin/sh "$W/myed"; [ "$(run "EDITOR_CHOICE=$W/myed")" = "$W/myed $W/myed" ] && ok "existing absolute path honoured" || no "absolute path not honoured"
grep -qw nano "$F1" && grep -v '^#' "$F1" | grep -qw nano && no "profile mentions nano outside comments"
[ $fail = 0 ] && echo "editor-profile: all ok"
exit $fail
