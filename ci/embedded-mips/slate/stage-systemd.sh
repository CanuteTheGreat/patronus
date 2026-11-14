#!/bin/bash
# Runs INSIDE pembed-slate-g after stage-all.sh: cross-build systemd (latest stable) for mips-unknown-linux-musl,
# install into /out/systemd-root, report sizes. Log /out/systemd.log. Marker /out/stage-systemd.ok
set -uo pipefail
exec > >(tee -a /out/systemd.log) 2>&1
T=mips-unknown-linux-musl; SYS=/usr/$T; V=${SD_VERSION:-262.2}
step() { echo "== $(date -u +%T) $*"; }
step "musl in the sysroot: $(ls $SYS/usr/lib/libc.so && strings $SYS/usr/lib/libc.so | grep -m1 -E '^1\.[0-9]+\.[0-9]+$')"
qlist -IRv 2>/dev/null | grep -E "cross-$T/(musl|gcc)" || ls /var/db/pkg/cross-$T/
step "sysroot deps: libcap util-linux libucontext"
echo 'sys-apps/util-linux -cramfs -ncurses -readline -python -su -suid -logger -tty-helpers -udev -systemd -cryptsetup -audit -nls -pam -selinux -magic -rtas -uuidd -kill -hardlink -caps static-libs' >> $SYS/etc/portage/package.use/embedded
echo 'sys-libs/libcap -pam -tools' >> $SYS/etc/portage/package.use/embedded
echo 'sys-libs/libucontext *' >> $SYS/etc/portage/package.accept_keywords/e
ROOT=$SYS $T-emerge -q --keep-going --nodeps sys-libs/libcap sys-apps/util-linux sys-libs/libucontext 2>&1 | tail -20
ls -l $SYS/usr/lib/libmount.so* $SYS/usr/lib/libcap.so* $SYS/usr/lib/libucontext* 2>&1 | head
step "host tools"; emerge -q --noreplace dev-build/meson dev-util/gperf dev-python/jinja2 dev-python/pyelftools 2>&1 | tail -3
step "systemd v$V source"
mkdir -p /tmp/sd && cd /tmp/sd && { [ -d systemd-$V ] || { curl -sfL https://github.com/systemd/systemd/archive/refs/tags/v$V.tar.gz -o sd.tgz && tar xzf sd.tgz; }; }
cd /tmp/sd/systemd-$V || exit 1
cat > /tmp/sd/cross.ini <<EOF
[binaries]
c = '$T-gcc'
cpp = '$T-g++'
ar = '$T-ar'
strip = '$T-strip'
pkg-config = 'pkg-config'
[properties]
sys_root = '$SYS'
pkg_config_libdir = '$SYS/usr/lib/pkgconfig:$SYS/usr/share/pkgconfig'
[built-in options]
c_args = ['-Os', '-march=mips32r2', '-msoft-float', '-ffunction-sections', '-fdata-sections']
c_link_args = ['-Wl,--gc-sections', '-Wl,-O1']
[host_machine]
system = 'linux'
cpu_family = 'mips'
cpu = 'mips32r2'
endian = 'big'
EOF
export PKG_CONFIG_SYSROOT_DIR=$SYS PKG_CONFIG_LIBDIR=$SYS/usr/lib/pkgconfig:$SYS/usr/share/pkgconfig
OFF="resolve networkd timesyncd logind hostnamed localed machined portabled sysext mountfsd userdb timedated nsresourced coredump pstore oomd efi tpm environment-d binfmt sysinstall hibernate backlight vconsole quotacheck storagetm hwdb rfkill xdg-autostart firstboot kernel-install analyze translations ldconfig utmp gshadow nss-myhostname nss-systemd fuzz-tests urlify vcs-tag compat-sysv-interfaces"
ARGS="-Dlibc=musl -Dmode=release -Dauto_features=disabled -Dtests=false -Dman=disabled -Dhtml=disabled -Dsystemd-multicall-binary=true -Dsplit-bin=true -Drootprefix=/usr -Dsysvinit-path= -Dsysvrcnd-path= -Ddefault-network=false"
for o in $OFF; do ARGS="$ARGS -D$o=false"; done
step "meson setup"
rm -rf build; meson setup build --cross-file /tmp/sd/cross.ini --prefix=/usr $ARGS > /out/systemd-meson.log 2>&1; rc=$?
if [ $rc -ne 0 ]; then
  # unknown/ill-typed options: drop them one by one and retry (the option set moves between releases)
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    bad=$(grep -oE 'Unknown option[s]?: "?[a-z0-9_-]+|option "?[a-z0-9_-]+"? (is not|value)' /out/systemd-meson.log | grep -oE '[a-z0-9_-]+$|"[a-z0-9_-]+"' | tr -d '"' | head -1)
    [ -z "$bad" ] && break; echo "dropping option $bad"; ARGS=$(echo "$ARGS" | sed -E "s/ -D$bad=[^ ]*//")
    rm -rf build; meson setup build --cross-file /tmp/sd/cross.ini --prefix=/usr $ARGS > /out/systemd-meson.log 2>&1 && { rc=0; break; }
  done
fi
tail -40 /out/systemd-meson.log
[ $rc -eq 0 ] || { echo "MESON FAILED"; exit 1; }
step "ninja"; ninja -C build -j4 > /out/systemd-ninja.log 2>&1; rc=$?; tail -30 /out/systemd-ninja.log; echo "ninja rc=$rc"
[ $rc -eq 0 ] || exit 1
step install; rm -rf /out/systemd-root; DESTDIR=/out/systemd-root meson install -C build --no-rebuild > /out/systemd-install.log 2>&1; echo "install rc=$?"
find /out/systemd-root -type f -perm -u+x -exec file {} + | grep -c ELF
du -sh /out/systemd-root; ls -l /out/systemd-root/usr/lib/systemd/systemd /out/systemd-root/usr/bin/systemctl 2>&1
touch /out/stage-systemd.ok
step done
