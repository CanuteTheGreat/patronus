#!/bin/bash
# Inside the builder: native musl build of systemd (the Slate's cut-down configuration: no udev/networkd/resolved/logind,
# libmount on, multicall binary) into /out/systemd-root; then the size trim list assemble.sh applies. Marker /out/stage-systemd.ok
set -uo pipefail
V=${SD_VERSION:-262.2}
mkdir -p /tmp/sd /out && cd /tmp/sd
[ -d systemd-$V ] || { curl -sfL https://github.com/systemd/systemd/archive/refs/tags/v$V.tar.gz -o sd.tgz && tar xzf sd.tgz; } || exit 1
cd systemd-$V
OFF="resolve networkd timesyncd logind hostnamed localed machined portabled sysext mountfsd userdb timedated nsresourced coredump pstore oomd efi tpm environment-d binfmt hibernate backlight vconsole quotacheck storagetm hwdb rfkill xdg-autostart firstboot randomseed repart homed importd remote kmod seccomp apparmor selinux audit pam acl blkid openssl libcryptsetup libfido2 qrencode gnutls microhttpd libcurl idn pcre2 p11kit tpm2 elfutils zlib bzip2 xz lz4 zstd bpf-framework bootloader ukify analyze utmp"
ARGS="-Dlibc=musl -Dmode=release -Dauto_features=disabled -Dlibmount=enabled -Dtests=false -Dman=disabled -Dhtml=disabled -Dsystemd-multicall-binary=true -Dsplit-bin=true -Drootprefix=/usr -Dsysvinit-path= -Dsysvrcnd-path= -Ddefault-network=false"
for o in $OFF; do ARGS="$ARGS -D$o=false"; done
# musl 1.2.6 (Alpine 3.24) has what systemd 262 needs (renameat2, statx mount ids): no shims. 3.22/3.23 do not.
export CFLAGS="-Os -ffunction-sections -fdata-sections" LDFLAGS="-Wl,--gc-sections"
rc=1
for i in $(seq 0 14); do   # the option set moves between releases: drop options meson says do not exist
  rm -rf build; meson setup build --prefix=/usr $ARGS > /out/systemd-meson.log 2>&1 && { rc=0; break; }
  bad=$(grep -oE 'Unknown option[s]?: "?[a-z0-9_-]+|option "?[a-z0-9_-]+"? (is not|value)' /out/systemd-meson.log | grep -oE '[a-z0-9_-]+$|"[a-z0-9_-]+"' | tr -d '"' | head -1)
  [ -z "$bad" ] && break; echo "dropping option $bad"; ARGS=$(echo "$ARGS" | sed -E "s/ -D$bad=[^ ]*//")
done
[ $rc -eq 0 ] || { tail -40 /out/systemd-meson.log; echo "MESON FAILED"; exit 1; }
ninja -C build -k 0 -j${JOBS:-4} > /out/systemd-ninja.log 2>&1 || { tail -40 /out/systemd-ninja.log; echo "NINJA FAILED"; grep -E "error:" /out/systemd-ninja.log | sort -u | head -30; exit 1; }
rm -rf /out/systemd-root; DESTDIR=/out/systemd-root meson install -C build --no-rebuild > /out/systemd-install.log 2>&1 || exit 1
find /out/systemd-root -type f -perm -u+x -exec sh -c 'head -c4 "$1" | grep ELF >/dev/null && strip --strip-unneeded "$1"' _ {} \; 2>/dev/null
du -sh /out/systemd-root; ls -l /out/systemd-root/usr/lib/systemd/systemd && touch /out/stage-systemd.ok
