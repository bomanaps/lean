FROM rustlang/rust:nightly-bookworm AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN cargo build --release

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/lean_client /usr/local/bin/lean_client

ENTRYPOINT ["lean_client"]