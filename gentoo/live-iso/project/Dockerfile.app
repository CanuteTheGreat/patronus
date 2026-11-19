# syntax=docker/dockerfile:1.4
# Builds the Patronus binaries (patronus CLI/applyd, patronus-web, patronus-install)
# on Debian bookworm (glibc older than Gentoo's -> runs on the live system).
FROM rust:1-bookworm AS app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential clang libmnl-dev libnftnl-dev libssl-dev pkg-config libelf-dev zlib1g-dev protobuf-compiler libdbus-1-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ENV CARGO_TARGET_DIR=/cache/target CARGO_PROFILE_RELEASE_DEBUG=0
ARG JOBS=4
ARG IMAGE_BUILD=
RUN --mount=type=cache,target=/cache/target --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/usr/local/cargo/git \
    set -e; export CARGO_BUILD_JOBS=${JOBS}; \
    case "$(uname -m)" in x86_64) cpu=x86-64-v2; trip=X86_64_UNKNOWN_LINUX_GNU;; aarch64) cpu=generic; trip=AARCH64_UNKNOWN_LINUX_GNU;; riscv64) cpu=generic-rv64; trip=RISCV64GC_UNKNOWN_LINUX_GNU;; *) echo "unsupported arch"; exit 1;; esac; \
    export CARGO_TARGET_${trip}_RUSTFLAGS="-C target-cpu=$cpu"; \
    cargo build --release -p patronus-cli -p patronus-web -p patronus-installer; \
    P=/out/usr/share/patronus-image; mkdir -p $P/payload/bin $P/payload/files $P/repo/net-firewall/patronus; \
    cp /cache/target/release/patronus-cli /cache/target/release/patronus-web /cache/target/release/patronus-install $P/payload/bin/; \
    python3 gentoo/live-iso/common/check-cpu-baseline.py $P/payload/bin/patronus-cli $P/payload/bin/patronus-web $P/payload/bin/patronus-install; \
    ver=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1); [ -n "$ver" ]; \
    cp -a gentoo/net-firewall/patronus/files/. $P/payload/files/; \
    cp -a gentoo/acct-group gentoo/acct-user gentoo/sec-keys $P/repo/; \
    cp gentoo/live-iso/project/image/patronus-image.ebuild $P/repo/net-firewall/patronus/patronus-${ver}_p${IMAGE_BUILD:-$(date -u +%Y%m%d)}.ebuild
# The application stage only STAGES the product (binaries + the real ebuild's files/ directory + an image-local Portage repository).
# common/setup-rootfs.sh runs /usr/libexec/project-image-packages (project/overlay) while the Portage tree is still present, and that
# emerges net-firewall/patronus from the staged payload: every file of the product ends up owned by a package on the installed system.
# Nothing here is copied to / by hand any more (the old hand-copy lost every init script nobody listed, e.g. patronus-dhcpc).
FROM scratch
COPY --from=app /out/ /out/
