#!/bin/bash
# on the build host: cross-build patronus-cli + patronus-web for the router tier in container pembed-g4
CLI_FEAT=${CLI_FEATURES:-nftables,cli,dhcp-server,dns-server,uci-import}
WEB_FEAT=${WEB_FEATURES:-dhcp,dns,tls-openssl}
for spec in "patronus-cli:$CLI_FEAT" "patronus-web:$WEB_FEAT"; do
  pkg=${spec%%:*}; feat=${spec#*:}
  docker exec -e OPENSSL_DIR=/usr/mips-unknown-linux-musl/usr -e OPENSSL_STATIC=1 pembed-g4 sh -c \
    "bash /w/rust-g.sh build --release --target mips-unknown-linux-musl -Z build-std=std,panic_abort -p $pkg --no-default-features --features $feat > /out/build-$pkg.log 2>&1"
done
