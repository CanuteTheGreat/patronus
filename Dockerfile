# Multi-stage Dockerfile for Patronus SD-WAN

# Builder stage - use latest stable Rust for edition2024 support
FROM rust:latest AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libsqlite3-dev \
    libssl-dev \
    libmnl-dev \
    libnftnl-dev \
    libelf-dev \
    zlib1g-dev \
    build-essential \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates/
COPY operator ./operator/

# Build release binaries (only essential packages for web interface)
RUN cargo build --release -p patronus-web

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libsqlite3-0 \
    libssl3 \
    wireguard-tools \
    iproute2 \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create patronus user
RUN useradd -r -u 1000 -m -s /bin/bash patronus

# Copy binaries from builder
COPY --from=builder /build/target/release/patronus-web /usr/bin/

# Create directories
RUN mkdir -p /etc/patronus /var/lib/patronus /var/log/patronus && \
    chown -R patronus:patronus /etc/patronus /var/lib/patronus /var/log/patronus

# Note: Configuration should be mounted at runtime via docker-compose or kubectl

# Switch to patronus user
USER patronus
WORKDIR /home/patronus

# Expose ports
EXPOSE 8443 51820/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/ || exit 1

# Default command - run the web interface
CMD ["patronus-web"]
