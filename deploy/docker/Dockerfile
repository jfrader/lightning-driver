# syntax=docker/dockerfile:1
FROM rust:1.93.1-bookworm AS api-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY lightning-client lightning-client
COPY api-server api-server
COPY synthetic-node-harness synthetic-node-harness
RUN CARGO_BUILD_JOBS=2 cargo build --locked --release -p lightning-driver-api

FROM node:24-bookworm-slim AS ui-build
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG UI_COMMIT=2940f568256a4eb04abd08ce4ed5c0863c585b9c
RUN git clone https://github.com/jfrader/lightning-driver-ui /ui \
    && cd /ui && git checkout --detach "$UI_COMMIT"
WORKDIR /ui
RUN npm ci && npm run build

FROM node:24-bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates libssl3 tini && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/lightning-driver
COPY --from=api-build /build/target/release/api-server ./api-server
RUN ldd ./api-server > /tmp/api-ldd && cat /tmp/api-ldd \
    && ! grep -q 'not found' /tmp/api-ldd && rm /tmp/api-ldd
COPY --from=ui-build /ui/dist ./dist
COPY deploy/server.mjs deploy/run.sh ./
COPY deploy/docker/config.localhost.toml deploy/docker/healthcheck.mjs ./
ENV HOST=0.0.0.0 STATE_DIR=/state
USER 1000:1000
EXPOSE 4400
ENTRYPOINT ["/usr/bin/tini", "--", "/bin/bash", "/opt/lightning-driver/run.sh"]
