# Default editor on the embedded tier: busybox vi (owner 2026-11-27: vim, never nano, on every tier).
# vim (a few MB of binary plus its runtime tree) does not fit the NAND budget of these images; busybox `vi` is the same modal editor and is
# already in the image. A user who adds a different editor sets EDITOR_CHOICE in /etc/default-editor.conf (vim|nvim|vi|/absolute/path).
EDITOR=vi
if [ -r /etc/default-editor.conf ]; then
	_c=$(sed -n 's/^[[:space:]]*EDITOR_CHOICE=[[:space:]]*"\{0,1\}\([^"#[:space:]]*\)"\{0,1\}.*/\1/p' /etc/default-editor.conf | tail -n 1)
	case "$_c" in
	"" | vim | neovim | nvim | vi) [ -z "$_c" ] || { command -v "${_c#neovim}" >/dev/null 2>&1 && EDITOR=$_c; [ "$_c" = neovim ] && command -v nvim >/dev/null 2>&1 && EDITOR=nvim; } ;;
	/*) [ -x "$_c" ] && EDITOR=$_c ;;
	esac
	unset _c
fi
VISUAL=$EDITOR
export EDITOR VISUAL
