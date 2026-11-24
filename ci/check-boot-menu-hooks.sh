#!/usr/bin/env bash
# Regression test: the kernel hook + the unattended-menu script that net-firewall/patronus ships for installs WITHOUT boot environments.
# Found 2026-11-24 (azkaban patronus-lab): kernel updates landed in /boot but grub.cfg was never rewritten (sys-kernel/installkernel is built
# without USE=grub), so the machine booted its install-day kernel forever; and a menu that waits for a key after one failed boot never recovers.
#   91-patronus-boot-entry : every kernel install/removal rewrites grub.cfg atomically, never fails the kernel install, leaves a ZFS
#                            boot-environment install alone (the installer's own hook owns that menu)
#   11_patronus_unattended : fallback chain over the kernel entries + a retry entry that finally restarts the machine
# Real GRUB boots of the generated menu: tools/vmtest/scenarios/installed_firstrun.py + gentoo/live-iso/common/grub-autoboot-test.py (CI, x86_64).
set -eu
cd "$(dirname "$0")/.."
F=gentoo/net-firewall/patronus/files
fail() { echo "FAIL: $*" >&2; exit 1; }
for f in patronus-boot-entry patronus-grub-unattended; do sh -n "$F/$f" || fail "$f: syntax"; done
for e in gentoo/net-firewall/patronus/patronus-0.2.0.ebuild gentoo/net-firewall/patronus/patronus-9999.ebuild; do
  grep -q 'newexe "${FILESDIR}/patronus-boot-entry" 91-patronus-boot-entry' "$e" || fail "$e: kernel hook not installed"
  [ "$(grep -c 'newexe "${FILESDIR}/patronus-boot-entry" 91-patronus-boot-entry' "$e")" = 2 ] || fail "$e: hook must be in postinst.d AND postrm.d"
  grep -q 'newexe "${FILESDIR}/patronus-grub-unattended" 11_patronus_unattended' "$e" || fail "$e: unattended menu script not installed"
done
echo "ok files installed by both ebuilds"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export PATRONUS_BOOT_ENTRY_CONF=$T/none            # no conf.d: defaults
mkdir -p "$T/boot/grub"
cat > "$T/mkconfig" <<'EOS'
#!/bin/sh
# fake grub-mkconfig -o FILE: writes the kernels it is told about
[ -e "$MK_FAIL" ] && exit 1
[ "$1" = -o ] && printf 'menuentry "kernel %s"\n' "$(cat "$MK_VER")" > "$2"
EOS
chmod +x "$T/mkconfig"
export MK_VER=$T/ver MK_FAIL=$T/fail
conf() { printf 'GRUB_CFG=%s/boot/grub/grub.cfg\nGRUB_MKCONFIG=%s/mkconfig\n%s\n' "$T" "$T" "${1:-}" > "$T/conf"; export PATRONUS_BOOT_ENTRY_CONF=$T/conf; }
conf
echo old > "$T/boot/grub/grub.cfg"; echo 6.99.1 > "$MK_VER"
sh "$F/patronus-boot-entry" 6.99.1 2>/dev/null || fail "hook failed a kernel install"
grep -q 'kernel 6.99.1' "$T/boot/grub/grub.cfg" || fail "kernel install did not rewrite grub.cfg: $(cat "$T/boot/grub/grub.cfg")"
[ ! -e "$T/boot/grub/grub.cfg.new" ] || fail "temporary grub.cfg.new left behind"
echo 6.99.2 > "$MK_VER"; sh "$F/patronus-boot-entry" 6.99.2 2>/dev/null; grep -q 'kernel 6.99.2' "$T/boot/grub/grub.cfg" || fail "second kernel not in grub.cfg"
echo "ok kernel install rewrites grub.cfg"
touch "$T/fail"; echo 6.99.3 > "$MK_VER"
sh "$F/patronus-boot-entry" 6.99.3 2>/dev/null || fail "a failing grub-mkconfig must never fail the kernel install"
grep -q 'kernel 6.99.2' "$T/boot/grub/grub.cfg" || fail "failed mkconfig must leave grub.cfg unchanged"
[ ! -e "$T/boot/grub/grub.cfg.new" ] || fail "failed mkconfig left grub.cfg.new"
rm -f "$T/fail"
echo "ok failing grub-mkconfig leaves the menu alone and does not fail the install"
# a ZFS boot-environment install (the installer's static menu, hook 90-horcrux-be / /etc/horcrux/be.conf) is not touched
touch "$T/be.conf"; conf "BE_CONF=$T/be.conf"
echo 6.99.4 > "$MK_VER"; sh "$F/patronus-boot-entry" 6.99.4 2>/dev/null || true
grep -q 'kernel 6.99.4' "$T/boot/grub/grub.cfg" && fail "boot-environment install: the static menu must be left alone"
conf "BOOT_ENTRY=off"; sh "$F/patronus-boot-entry" 6.99.4 2>/dev/null || true
grep -q 'kernel 6.99.4' "$T/boot/grub/grub.cfg" && fail "BOOT_ENTRY=off must not touch the menu"
echo "ok boot-environment installs and BOOT_ENTRY=off are left alone"

# unattended menu: two kernels as grub-mkconfig's 10_linux prints them, then the generated fallback chain
G=$T/grub.d; mkdir "$G"
cat > "$G/10_linux" <<'EOS'
#!/bin/sh
cat <<'EOM'
menuentry 'Patronus GNU/Linux' --class gnu-linux $menuentry_id_option 'gnulinux-6.99.2-advanced-uuid' {
	linux /vmlinuz-6.99.2 root=UUID=x
}
menuentry 'Patronus GNU/Linux, with Linux 6.99.1' --class gnu-linux $menuentry_id_option 'gnulinux-6.99.1-advanced-uuid' {
	linux /vmlinuz-6.99.1 root=UUID=x
}
EOM
EOS
cp "$F/patronus-grub-unattended" "$G/11_patronus_unattended"; chmod +x "$G"/*
conf
out=$("$G/11_patronus_unattended") || fail "unattended script failed"
grep -q 'px_fallback_add 0 ' <<<"$out" || fail "newest kernel (entry 0) not in the fallback chain"
grep -q 'px_fallback_add 1 ' <<<"$out" || fail "previous kernel (entry 1) not in the fallback chain"
grep -q 'set fallback="${px_fallback}2"' <<<"$out" || fail "fallback chain must end in the retry entry (number 2): $out"
grep -q "menuentry 'Start the boot menu again (automatic retry)' .*'patronus-retry'" <<<"$out" || fail "no retry entry"
grep -q '^[[:space:]]*reboot$' <<<"$out" || fail "retry entry never restarts the machine"
echo "ok unattended menu: fallback chain over both kernels, retry, restart"
conf "UNATTENDED=off"; [ -z "$("$G/11_patronus_unattended")" ] || fail "UNATTENDED=off must print nothing"
echo "boot menu hooks: pass"
