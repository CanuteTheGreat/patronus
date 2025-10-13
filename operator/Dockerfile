# Build stage
FROM rust:1.75 AS builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY operator ./operator

# Build the operator
RUN cd operator && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install CA certificates and other runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 operator

# Copy binary from builder
COPY --from=builder /build/target/release/patronus-operator /usr/local/bin/patronus-operator

# Set user
USER operator

# Run the operator
ENTRYPOINT ["/usr/local/bin/patronus-operator"]
