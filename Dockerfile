# Patronus — Gentoo-native container build
#
# Builds Patronus the way it's meant to be installed: through Portage
# against the project's own overlay in gentoo/net-firewall/patronus, with
# real USE flags controlling what actually gets compiled in (nftables vs
# iptables, wireguard vs openvpn vs ipsec, monitoring backends, etc.) —
# not a fixed cargo build with everything baked in.
#
# Override USE flags at build time, e.g.:
#   docker build --build-arg PATRONUS_USE="web cli api nftables wireguard" .

ARG CI_BASE_IMAGE=gentoo/stage3:amd64-systemd
FROM ${CI_BASE_IMAGE} AS builder

ARG PATRONUS_USE="web cli api nftables wireguard multiwan monitoring prometheus backup systemd"

# Portage's default FEATURES include ipc-sandbox/network-sandbox/pid-sandbox,
# which call unshare(2) to create new namespaces per sandboxed action. Inside
# a `docker build` layer there's no CAP_SYS_ADMIN, so every one of those calls
# fails with EPERM -- and instead of failing fast, Portage just retries the
# unshare repeatedly (visible in CI logs as a flood of "Unable to unshare:
# EPERM" every few seconds), burning the whole job timeout without making
# real progress. Disable the namespace-based sandbox features here.
#
# Also disable the base ptrace-based sandbox (FEATURES=sandbox/usersandbox):
# it misreads process personality bits under binfmt_misc/QEMU (ARM64 Linux
# hosts) and under Rosetta 2 (Apple Silicon Docker Desktop), aborting any
# package with a Rust/Go build-script subprocess (e.g. dev-lang/go) with
# "unknown x86_64 (CS) personality" / SIGABRT -- confirmed live in run #141
# (dev-lang/go-1.26.7 compile phase). Known sandbox-vs-emulation
# incompatibility, not a package bug. Already fixed this exact way in
# gentoo/docker/Dockerfile.iso-builder; this just ports the same fix here.
RUN echo 'FEATURES="${FEATURES} -sandbox -usersandbox -ipc-sandbox -network-sandbox -pid-sandbox"' \
    >> /etc/portage/make.conf

RUN emerge-webrsync

# Register this project's own overlay as a local Portage repo (already a
# fully self-contained repo: has its own metadata/layout.conf + profiles/repo_name)
COPY gentoo /var/db/repos/patronus-overlay
RUN mkdir -p /etc/portage/repos.conf && \
    printf '[patronus]\nlocation = /var/db/repos/patronus-overlay\npriority = 50\n' \
    > /etc/portage/repos.conf/patronus-overlay.conf

RUN echo "net-firewall/patronus ${PATRONUS_USE} -openrc" > /etc/portage/package.use/patronus-docker-build
RUN echo "net-firewall/patronus ~amd64" > /etc/portage/package.accept_keywords/patronus && \
    echo "=net-firewall/patronus-9999 **" >> /etc/portage/package.accept_keywords/patronus

# Install patronus's DEPENDENCIES only (Go/Rust toolchains, libs, etc.)
# before copying any application source. Ebuild DEPEND/RDEPEND metadata
# comes from the overlay .ebuild file (already present above), not from the
# source tree, so this layer is cache-stable across ordinary commits and
# only re-runs when the ebuild/overlay/USE flags actually change. This is
# what actually fixes the "every commit re-emerges the whole toolchain from
# scratch" problem -- a .dockerignore .git/ exclusion alone was NOT enough,
# because the expensive dependency build was previously gated behind the
# full-source COPY below, not behind the (rarely-changing) ebuild metadata.
RUN emerge --verbose --autounmask-write --onlydeps net-firewall/patronus && \
    etc-update --automode -5 || true

# The live ebuild (patronus-9999) fetches via git-r3 from this project's own
# repo (git.canutethegreat.com); for a from-source container build we vendor
# the working tree directly instead, so the image always reflects what's
# actually in this checkout, not whatever HEAD happens to be upstream. A
# versioned release ebuild (patronus-0.1.0, tag v0.1.0) also exists in this
# overlay for users who want a pinned, non-live install outside Docker.
COPY . /usr/src/patronus
RUN cd /usr/src/patronus && cargo vendor /var/cache/distfiles/patronus-vendor 2>&1 | tail -5 || true

# git-r3 would otherwise re-clone from the remote (EGIT_REPO_URI) even though
# we just vendored the local checkout above, silently ignoring uncommitted
# local changes. EGIT_OVERRIDE_REPO_<PN> is git-r3's documented mechanism to
# point it at a local path instead.
ENV EGIT_OVERRIDE_REPO_PATRONUS=/usr/src/patronus

# Dependencies are already merged above, so this now only builds and links
# patronus itself -- the part that's actually supposed to run on every commit.
RUN emerge --verbose net-firewall/patronus

# --- Runtime --------------------------------------------------------------
# NOTE: this intentionally does NOT copy just the patronus-web binary into
# a fresh, bare gentoo/stage3 stage. net-firewall/patronus's RDEPEND
# includes net-firewall/nftables (see gentoo/net-firewall/patronus/
# patronus-9999.ebuild, USE=nftables is on by default) because every
# nft-invoking code path (patronus-web, patronus-firewall, patronus-network,
# patronus-captiveportal -- all shell out to `nft` by PATH lookup, e.g.
# patronus-firewall/src/nftables.rs) needs the real `nft` binary and its
# shared-library dependencies (libnftnl, libmnl, ...) present at runtime.
#
# A prior version of this Dockerfile copied only
# /usr/bin/patronus-web + /etc/patronus + /var/lib/patronus into a bare
# `FROM gentoo/stage3:amd64-systemd` stage, silently dropping every other
# RDEPEND nftables actually needs. The container booted and served HTTP
# fine until the first firewall-initializing request, which failed with
# "Failed to execute nft script: Broken pipe (os error 32)" -- `nft` was
# never on PATH in that stage at all, so a request to invoke it ended up
# spawning (and immediately losing) a shell that couldn't exec it. This
# wasn't CI flakiness, it reproduced on every single build (see run #311,
# task 7990's Smoke-test-the-built-image step) and would have broken any
# real deployment of this image identically.
#
# Fix: ship the actual builder stage's root filesystem instead of a
# fresh/bare one. The builder already ran a real `emerge` of
# net-firewall/patronus, which pulled in net-firewall/nftables (and
# everything *it* depends on) as a genuine Portage-resolved RDEPEND --
# there is no path-guessing involved in "which .so files does nft need"
# because the builder environment is the one that actually linked it.
# This trades image size (full Portage tree / build toolchain still
# present) for correctness; revisit with a real multi-stage COPY (binary
# + `qlist -e net-firewall/nftables`-derived file list) if image size
# ever becomes a concrete problem.
RUN useradd -r -u 1000 -m -s /bin/bash patronus 2>/dev/null || true && \
    chown -R patronus:patronus /etc/patronus /var/lib/patronus /var/log/patronus 2>/dev/null || true

USER patronus
WORKDIR /home/patronus
EXPOSE 8443 51820/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/ || exit 1

CMD ["patronus-web"]
