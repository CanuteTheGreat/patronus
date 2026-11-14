T=mips-unknown-linux-musl; O=/out/pack; rm -rf $O; mkdir -p $O
cp ${CARGO_TARGET_DIR:-/out/target-s}/$T/release/patronus-cli $O/   # multi-call: patronus-web is a link (assemble.sh)
[ -n "${WEB_SEPARATE:-}" ] && cp ${CARGO_TARGET_DIR:-/out/target-s}/$T/release/patronus-web $O/
LA=$($T-gcc -print-file-name=libatomic.so.1); cp -L $LA $O/libatomic.so.1; $T-strip --strip-unneeded $O/libatomic.so.1
# missing-library check for every ELF in the rootfs
cd /rootfs; for f in $(find . -type f -perm -u+x); do $T-readelf -d $f 2>/dev/null | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p'; done | sort -u > $O/needed.txt
for l in $(cat $O/needed.txt); do [ -e usr/lib/$l ] || [ -e lib/$l ] || echo "MISSING $l"; done
# dhcpcd/OpenRC from the sysroot emerge keep their symbol tables
for f in /rootfs/sbin/dhcpcd /rootfs-openrc/sbin/* /rootfs-openrc/bin/* /rootfs-openrc/usr/libexec/rc/bin/* /rootfs-openrc/usr/libexec/rc/sbin/* /rootfs-openrc/lib/*.so* /rootfs-openrc/usr/lib/*.so*; do
  [ -f "$f" ] && [ ! -L "$f" ] && head -c4 "$f" | grep -q ELF && $T-strip --strip-unneeded "$f" 2>/dev/null; done
tar cf $O/rootfs.tar -C /rootfs --exclude=./usr/include --exclude=./usr/share/man --exclude=./usr/share/doc --exclude=./var/db/pkg .
ls -l $O
# the OpenRC variant's init system (stage-openrc.sh): assemble.sh OPENRC_TREE=
[ -x /rootfs-openrc/sbin/openrc-init ] && tar cf $O/openrc.tar -C /rootfs-openrc --exclude=./usr/include --exclude=./usr/share/man --exclude=./usr/share/doc --exclude=./var/db/pkg --exclude=./usr/lib/pkgconfig .
ls -l $O
