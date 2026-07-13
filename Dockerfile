FROM rust:trixie AS chef

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef

COPY .cargo ./.cargo

FROM chef AS planner
# Follow cargo-chef workspace guidance so new crates are picked up automatically.
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    CARGO_TARGET_DIR=/app/target cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    CARGO_TARGET_DIR=/app/target cargo build --release --package redactor-app --bin redactor --features http \
    && install -D /app/target/release/redactor /artifacts/redactor

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Keep the runtime stage independent from distro-specific user-management tools.
RUN mkdir -p /etc/redactor /var/lib/redactor \
    && chown -R 65532:65532 /etc/redactor /var/lib/redactor

WORKDIR /var/lib/redactor
ENV HOME=/var/lib/redactor

COPY --from=builder /artifacts/redactor /usr/local/bin/redactor
COPY docker/redactor.toml /etc/redactor/redactor.toml

USER 65532:65532

EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/redactor"]
CMD ["serve", "--config", "/etc/redactor/redactor.toml"]
