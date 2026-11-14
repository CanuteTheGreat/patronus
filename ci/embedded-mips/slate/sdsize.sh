T=mips-unknown-linux-musl; R=/out/systemd-root; S=/tmp/sdstrip; rm -rf $S; cp -a $R $S
find $S -type f -exec sh -c 'file "$1" | grep -q ELF && '$T'-strip --strip-unneeded "$1"' _ {} \; 2>/dev/null
du -sh $S; for f in usr/lib/systemd/systemd usr/lib/systemd/systemd-journald usr/lib/systemd/systemd-executor usr/bin/systemctl usr/lib/systemd/libsystemd-shared-262.so usr/lib/systemd/libsystemd-core-262.so usr/lib/libsystemd.so.0.45.0 usr/lib/systemd/systemd-udevd usr/bin/journalctl usr/bin/systemd-tmpfiles usr/bin/systemd-sysusers; do ls -l $S/$f 2>/dev/null | awk '{print $5, $9}'; done
$T-readelf -d $S/usr/lib/systemd/systemd | grep NEEDED
mksquashfs $S /tmp/sd.sq -comp xz -b 256K -noappend -no-xattrs -quiet 2>/dev/null && ls -l /tmp/sd.sq
