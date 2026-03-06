# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM rustlang/rust:nightly-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release

# ==============================================================================
# Stage 2: Runtime
# ==============================================================================
FROM ubuntu:22.04

ARG COMMIT_SHA
ARG BUILD_DATE
ARG GIT_BRANCH

LABEL org.opencontainers.image.title="grandine"
LABEL org.opencontainers.image.description="High performance Ethereum lean client"
LABEL org.opencontainers.image.authors="Grandine <info@grandine.io>"
LABEL org.opencontainers.image.source=https://github.com/grandinetech/lean
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.revision=$COMMIT_SHA
LABEL org.opencontainers.image.ref.name=$GIT_BRANCH
LABEL org.opencontainers.image.created=$BUILD_DATE

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder stage
COPY --from=builder /app/target/release/lean_client /usr/local/bin/lean_client

ENTRYPOINT ["lean_client"]
