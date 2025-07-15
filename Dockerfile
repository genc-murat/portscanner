# Dockerfile
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release with optimizations
RUN cargo build --release --target x86_64-unknown-linux-gnu

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Create non-root user
RUN useradd -r -s /bin/false scanner

# Copy the binary from builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-gnu/release/portscanner /usr/local/bin/portscanner

# Set permissions
RUN chmod +x /usr/local/bin/portscanner

# Switch to non-root user for security (except for SYN scan which requires root)
USER scanner

# Set working directory
WORKDIR /home/scanner

# Expose no ports (this is a client tool)
EXPOSE 

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD portscanner --help > /dev/null || exit 1

# Default entrypoint
ENTRYPOINT ["portscanner"]

# Default command (show help)
CMD ["--help"]

# Labels for metadata
LABEL maintainer="muttafi@gmail.com"
LABEL description="Fast, modern port scanner with advanced service detection and OS fingerprinting"
LABEL version="0.4.0"
LABEL org.opencontainers.image.source="https://github.com/genc-murat/portscanner"
LABEL org.opencontainers.image.documentation="https://github.com/genc-murat/portscanner/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"