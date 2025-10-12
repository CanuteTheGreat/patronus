# Multi-stage Dockerfile for Patronus SD-WAN

# Builder stage
FROM rust:1.75-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libsqlite3-dev \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates/

# Build release binaries
RUN cargo build --release --workspace

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
COPY --from=builder /build/target/release/patronus-sdwan /usr/bin/
COPY --from=builder /build/target/release/patronus-dashboard /usr/bin/

# Create directories
RUN mkdir -p /etc/patronus /var/lib/patronus /var/log/patronus && \
    chown -R patronus:patronus /etc/patronus /var/lib/patronus /var/log/patronus

# Copy default configuration (if exists)
COPY --chown=patronus:patronus config.example.yaml /etc/patronus/config.yaml || true

# Switch to patronus user
USER patronus
WORKDIR /home/patronus

# Expose ports
EXPOSE 8080 8081 51820/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Default command
CMD ["patronus-sdwan", "--config", "/etc/patronus/config.yaml"]
