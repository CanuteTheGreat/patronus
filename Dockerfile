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

FROM gentoo/stage3:amd64-systemd AS builder

ARG PATRONUS_USE="web cli api nftables wireguard multiwan monitoring prometheus backup systemd"

RUN emerge-webrsync

# Register this project's own overlay as a local Portage repo (already a
# fully self-contained repo: has its own metadata/layout.conf + profiles/repo_name)
COPY gentoo /var/db/repos/patronus-overlay
RUN mkdir -p /etc/portage/repos.conf && \
    printf '[patronus-overlay]\nlocation = /var/db/repos/patronus-overlay\npriority = 50\n' \
    > /etc/portage/repos.conf/patronus-overlay.conf

RUN echo "net-firewall/patronus ${PATRONUS_USE}" > /etc/portage/package.use/patronus-docker-build
RUN echo "net-firewall/patronus ~amd64" > /etc/portage/package.accept_keywords/patronus

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

RUN emerge --verbose --autounmask-write net-firewall/patronus && \
    etc-update --automode -5 || true
RUN emerge --verbose net-firewall/patronus

# --- Runtime stage --------------------------------------------------------
FROM gentoo/stage3:amd64-systemd

COPY --from=builder /usr/bin/patronus-web /usr/bin/patronus-web
COPY --from=builder /etc/patronus /etc/patronus
COPY --from=builder /var/lib/patronus /var/lib/patronus

RUN useradd -r -u 1000 -m -s /bin/bash patronus 2>/dev/null || true && \
    chown -R patronus:patronus /etc/patronus /var/lib/patronus /var/log/patronus 2>/dev/null || true

USER patronus
WORKDIR /home/patronus
EXPOSE 8443 51820/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/ || exit 1

CMD ["patronus-web"]
