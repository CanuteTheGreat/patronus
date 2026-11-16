# Builder for the GL-AX1800 (IPQ6018, aarch64 musl) router image. Alpine is musl on aarch64 natively, so there is no
# cross toolchain: the userland comes from Alpine 3.24 packages (build.sh), Patronus and systemd are built here.
# Built on an arm64 runner (the CI job does `docker build`; the layer cache keeps it a one-time cost per host).
FROM alpine:3.24
RUN apk add --no-cache bash build-base git curl pkgconf perl cmake clang-dev linux-headers rustup \
      openssl-dev openssl-libs-static libmnl-dev libnftnl-dev \
      squashfs-tools xz tar coreutils findutils binutils file python3 mtd-utils-ubi \
      meson samurai gperf py3-jinja2 py3-elftools libcap-dev util-linux-dev libucontext-dev \
      qemu-system-aarch64 qemu-img cpio e2fsprogs kmod dropbear openssh-client
# the stable Rust toolchain with the tier-2 musl target (no build-std, no nightly)
RUN rustup-init -y --profile minimal --default-toolchain stable -t aarch64-unknown-linux-musl >/dev/null 2>&1 && /root/.cargo/bin/rustc -V
ENV PATH=/root/.cargo/bin:$PATH
