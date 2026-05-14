# syntax=docker/dockerfile:1.7

FROM rust:1.91-bookworm AS ebpf-builder

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo +nightly install --locked bpf-linker

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY agent/Cargo.toml agent/Cargo.toml
COPY common/Cargo.toml common/Cargo.toml
COPY lavender-ebpf/Cargo.toml lavender-ebpf/Cargo.toml
COPY lavender-ebpf/rust-toolchain.toml lavender-ebpf/rust-toolchain.toml
COPY lavender-ebpf/.cargo/config.toml lavender-ebpf/.cargo/config.toml

COPY agent/src agent/src
COPY common/src common/src
COPY lavender-ebpf/src lavender-ebpf/src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo +nightly build -p lavender-ebpf --target bpfel-unknown-none -Z build-std=core --release && \
    mkdir -p /out && \
    artifact="$(find /app/target/bpfel-unknown-none/release/deps -maxdepth 1 -type f -name 'lavender_ebpf-*' ! -name '*.d' ! -name '*.rlib' ! -name '*.rmeta' ! -name '*.so' | head -n 1)" && \
    test -n "$artifact" && \
    cp "$artifact" /out/lavender-ebpf

FROM rust:1.91-bookworm AS agent-builder

ENV CARGO_HOME=/usr/local/cargo

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY agent/Cargo.toml agent/Cargo.toml
COPY common/Cargo.toml common/Cargo.toml
COPY lavender-ebpf/Cargo.toml lavender-ebpf/Cargo.toml

COPY agent/src agent/src
COPY agent/build.rs agent/build.rs
COPY common/src common/src
COPY lavender.toml lavender.toml

COPY --from=ebpf-builder /out/lavender-ebpf /app/prebuilt-ebpf/lavender-ebpf

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    LAVENDER_PREBUILT_EBPF_PATH=/app/prebuilt-ebpf/lavender-ebpf \
    cargo build -p agent --release && \
    mkdir -p /out && \
    cp /app/target/release/agent /out/agent

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=agent-builder /out/agent /app/agent
COPY docker/agent/lavender.docker.toml /app/lavender.toml

CMD ["/app/agent"]
