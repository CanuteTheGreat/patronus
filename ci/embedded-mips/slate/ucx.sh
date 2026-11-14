T=mips-unknown-linux-musl; SYS=/usr/$T
cd /tmp && rm -rf ucx && mkdir ucx && cd ucx && tar xf /var/cache/distfiles/libucontext-1.5.1.tar.* && cd libucontext-1.5.1 && \
make ARCH=mips CC=$T-gcc AR=$T-ar CFLAGS="-Os -march=mips32r2 -msoft-float -fPIC" libucontext.so libucontext.a libucontext.pc > /out/ucx.log 2>&1; echo "make rc=$?"
make ARCH=mips DESTDIR=$SYS prefix=/usr libdir=/usr/lib pkgconfigdir=/usr/lib/pkgconfig install >> /out/ucx.log 2>&1; echo "install rc=$?"
ls $SYS/usr/lib/libucontext* $SYS/usr/lib/pkgconfig/libucontext.pc; tail -5 /out/ucx.log
