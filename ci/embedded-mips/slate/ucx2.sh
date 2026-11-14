T=mips-unknown-linux-musl; SYS=/usr/$T; cd /tmp/ucx/libucontext-1.5.1
cp -a libucontext.so* libucontext.a $SYS/usr/lib/ 2>/dev/null; ls libucontext.so*; 
[ -e $SYS/usr/lib/libucontext.so.1 ] || cp libucontext.so $SYS/usr/lib/libucontext.so.1
ln -sf libucontext.so.1 $SYS/usr/lib/libucontext.so
mkdir -p $SYS/usr/include/libucontext; cp -a include/libucontext/*.h $SYS/usr/include/libucontext/ 2>/dev/null; cp -a arch/mips/include/libucontext/* $SYS/usr/include/libucontext/ 2>/dev/null; cp -a include/*.h $SYS/usr/include/ 2>/dev/null
cat > $SYS/usr/lib/pkgconfig/libucontext.pc <<P
prefix=/usr
libdir=/usr/lib
includedir=/usr/include
Name: libucontext
Description: ucontext library
Version: 1.5.1
Cflags: -I\${includedir}
Libs: -L\${libdir} -lucontext
P
ls -l $SYS/usr/lib/libucontext* ; ls $SYS/usr/include/libucontext; $T-readelf -h $SYS/usr/lib/libucontext.so.1 | grep -E 'Machine|Class'
