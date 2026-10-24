# Lightning Driver backend

Backend for [lightning-driver-ui](https://github.com/jfrader/lightning-driver-ui).

It manages LND (gRPC or REST), Core Lightning (REST) and Bitcoin Core (RPC) nodes from one
`config.toml`. The server holds the node credentials, enforces each node's policy and journals every
mutation before it reaches a daemon. The browser only calls `/api/v1` on the same origin.

The API contract is [`api-server/openapi.json`](api-server/openapi.json); the UI pins a copy.

## What it does

- Sign in with a passkey (WebAuthn). You can link a Nostr key (NIP-07). Enrollment tokens are printed
  on the host and work once.
- Read balances, invoices, payments, peers, channels, transactions and fee estimates, plus node
  info, Bitcoin Core chain/mempool/peers and LND watchtower state.
- Create and pay invoices, connect or disconnect a peer, open or close a channel, generate an
  address, or send on-chain. Each one is checked against the policy and authorized before it runs.
- Operations are journaled in SQLite: a restart does not send anything twice, and unresolved
  operations are checked against the node later.
- Decode BOLT11 invoices locally.

## Layout

- `api-server`: HTTP API, auth, operation engine, CLN/LND/Bitcoin adapters, SQLite journal.
- `lightning-client`: shared model, money, settings and validation types.
- `synthetic-node-harness`: disposable loopback nodes for development and tests.
- `deploy`: systemd units, the installer and the UI static server.

## Requirements

- Rust 1.93.1 and Cargo, a C build toolchain, `pkg-config`, OpenSSL headers and `protoc` for the LND
  gRPC bindings. SQLite is bundled.
- A state directory owned by the service user with mode `0700`, on local disk.
- One `serve` process per database. It holds an exclusive lock, so bind it privately behind a TLS
  reverse proxy that preserves the `Host` header.

## Setup

Copy `config.example.toml` into the state directory, set `public_origin` and `rp_id` to the exact
public hostname, and replace `nodes = []` with your node entries. Relative paths resolve against
that directory, not the working directory.

A Lightning node entry:

```toml
[[nodes]]
id = "lnd"
label = "LND"
backend = "lnd_grpc"                    # lnd_grpc | lnd_rest | cln_rest | bitcoin_rpc
endpoint = "https://127.0.0.1:10009/"   # HTTPS origin, no path
certificate_file = "lnd/tls.cert"
credential_file = "lnd/admin.macaroon"  # LND macaroon, CLN rune, Bitcoin Core cookie
expected_pubkey = "<compressed hex pubkey>"
network = "mainnet"                     # mainnet | testnet | testnet4 | signet | regtest
read_only = false

[nodes.policy]                          # example limits; set your own
create_invoice_msat = { min = "1000", max = "1000000000" }
pay_invoice_msat = { min = "1000", max = "1000000000" }
open_channel_sat = { min = "20000", max = "5000000" }
send_onchain_sat = { min = "10000", max = "1000000" }
fee_rate_sat_vbyte = { min = "1", max = "200" }
max_routing_fee_msat = "5000000"
default_max_routing_fee_msat = "1000000"
invoice_expiry_seconds = { min = 600, max = 86400, default = 3600 }

[nodes.peer_policy]
allowed_hosts = ["peer.example.invalid"]
allowed_ports = [9735]
```

A `bitcoin_rpc` node takes `expected_genesis` and the RPC cookie instead of the Lightning fields;
`certificate_file` is required only for an HTTPS endpoint. For stock LND's self-signed certificate,
set `tls_verification = "pinned"` and point `certificate_file` at that exact `tls.cert`; a rotated
certificate needs the new file and a restart. CLN is CA-verified.

## Running it

`deploy/install.sh` installs the release API and a static-plus-proxy server for the built UI as
user-level systemd services. The state directory defaults to `~/.local/state/lightning-driver` and
needs `config.toml` before the first install.

```sh
deploy/install.sh --ui-dist /path/to/lightning-driver-ui/dist
```

`--port` must match the port in `api.public_origin` (4400 by default). Re-running the script after a
rebuild upgrades both artifacts and restarts the services; it never rewrites the state directory.

For API-only work, run the server directly:

```sh
CARGO_BUILD_JOBS=2 cargo run -p api-server -- serve --config /path/to/state/config.toml
```

The first `serve` creates `invoice_key_file` with mode `0600`. Logs are JSON Lines on stderr;
[`docs/runbook.md`](docs/runbook.md) documents the events and the startup, lock, enrollment and node
authentication procedures.

## Node permissions

LND reads need `info:read`, `invoices:read`, `peers:read`, `offchain:read` and `onchain:read`. Every
mutation is preflighted with `CheckMacaroonPermissions`, so the macaroon also needs `macaroon:read`,
plus `invoices:write`, `offchain:write`, `peers:write` or `onchain:write` for the operations in use.
CLN runes are checked with `checkrune` before dispatch.

## Enrollment and recovery

Register an authenticator with a token printed once on the host:

```sh
cargo run --quiet -p api-server -- auth enrollment --config /path/to/state/config.toml
```

Submit the token in the UI and complete the passkey or NIP-07 ceremony. Tokens last
`api.limits.preauth_seconds` (300 by default). Issue another token to add a backup authenticator; it
does not create a second operator or revoke the first.

If every authenticator is lost, reset authentication from the host:

```sh
cargo run --quiet -p api-server -- auth recovery \
  --config /path/to/state/config.toml \
  --confirm-reset-authentication
```

That revokes passkeys, Nostr identities, sessions, tokens and outstanding challenges, then prints a
new enrollment token. Operation history and pending records are kept.

## Development

The synthetic harness starts three throwaway loopback TLS nodes (CLN REST, LND REST, LND gRPC) and
prints the commands for a disposable configuration. It needs `openssl` on PATH.

```sh
cargo run -p synthetic-node-harness --features synthetic-dev -- --acknowledge-synthetic-dev --public-port 5173
```

Run the printed commands in separate terminals, then `npm run dev` in the UI repo. Its proxy sends
`/api` to `http://127.0.0.1:8080` and keeps the browser's `Host` and `Origin`. Omit `--public-port`
for API-only work on port 8080. Stop the API before Ctrl-C on the harness; it deletes its keys,
journal and configuration.

## Checks

These are the CI steps:

```sh
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --workspace
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --no-default-features
CARGO_BUILD_JOBS=2 cargo check --workspace --all-features
```

Set `HTTP_EVIDENCE_DIR` while running `cargo test -p api-server --lib journeys` to capture actual
response JSON, then validate it with `python3 tools/validate-journey-responses.py <dir>`. The
validator needs the `jsonschema` Python package.

Tests drive the real routes, adapters and passkey ceremonies against the synthetic harness. They are
not a compatibility certification for a real daemon.

## Limitations

- The API serves no frontend assets. `deploy/install.sh` installs the UI build behind a separate
  static-plus-proxy service on the same origin, routing `/api/v1/*` here.
- There is no password or other login fallback.
