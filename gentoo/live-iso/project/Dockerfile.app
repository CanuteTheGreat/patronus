# syntax=docker/dockerfile:1.4
# Builds the Patronus binaries (patronus CLI/applyd, patronus-web, patronus-install)
# on Debian bookworm (glibc older than Gentoo's -> runs on the live system).
FROM rust:1-bookworm AS app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential clang libmnl-dev libnftnl-dev libssl-dev pkg-config libelf-dev zlib1g-dev protobuf-compiler libdbus-1-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ENV CARGO_TARGET_DIR=/cache/target CARGO_PROFILE_RELEASE_DEBUG=0
ARG JOBS=4
RUN --mount=type=cache,target=/cache/target --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    set -e; export CARGO_BUILD_JOBS=${JOBS}; \
    cargo build --release -p patronus-cli -p patronus-web -p patronus-installer; \
    mkdir -p /out/usr/bin /out/etc/init.d /out/etc/conf.d /out/etc/patronus; \
    cp /cache/target/release/patronus-cli /cache/target/release/patronus-web /cache/target/release/patronus-install /out/usr/bin/; \
    ln -s patronus-cli /out/usr/bin/patronus; \
    cp gentoo/net-firewall/patronus/files/patronus.toml /out/etc/patronus/patronus.toml
COPY gentoo/net-firewall/patronus/files/patronus-web.initd /out/etc/init.d/patronus-web
COPY gentoo/net-firewall/patronus/files/patronus-applyd.initd /out/etc/init.d/patronus-applyd
COPY gentoo/net-firewall/patronus/files/patronus-firewall.initd /out/etc/init.d/patronus-firewall
COPY gentoo/net-firewall/patronus/files/patronus.confd /out/etc/conf.d/patronus
FROM scratch
COPY --from=app /out/ /out/
