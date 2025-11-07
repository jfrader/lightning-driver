# === Builder Stage ===
FROM rust:latest AS builder
RUN apk add --no-cache musl-dev openssl-dev protobuf-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release binary
RUN cargo build --release --locked

# === Runtime Stage ===
FROM alpine:3.20
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/rust-lightning-driver /usr/local/bin/

# Default config (can be overridden)
ENV STRATEGY=Lnd
ENV HOST=https://host.docker.internal:10009
ENV CERT_PATH=/config/tls.cert
ENV MACAROON_PATH=/config/admin.macaroon

VOLUME ["/config"]

CMD ["rust-lightning-driver"]
