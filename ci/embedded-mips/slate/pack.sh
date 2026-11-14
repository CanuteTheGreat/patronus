T=mips-unknown-linux-musl; O=/out/pack; rm -rf $O; mkdir -p $O
cp /out/target-g/$T/release/patronus-cli /out/target-g/$T/release/patronus-web $O/
LA=$($T-gcc -print-file-name=libatomic.so.1); cp -L $LA $O/libatomic.so.1; $T-strip --strip-unneeded $O/libatomic.so.1
# missing-library check for every ELF in the rootfs
cd /rootfs; for f in $(find . -type f -perm -u+x); do $T-readelf -d $f 2>/dev/null | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p'; done | sort -u > $O/needed.txt
for l in $(cat $O/needed.txt); do [ -e usr/lib/$l ] || [ -e lib/$l ] || echo "MISSING $l"; done
tar cf $O/rootfs.tar -C /rootfs --exclude=./usr/include --exclude=./usr/share/man --exclude=./usr/share/doc --exclude=./var/db/pkg .
ls -l $O
