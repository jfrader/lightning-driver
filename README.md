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

## Installation

### Docker (recommended simple path)

Requires Docker with Compose and Git. From this checkout:

```sh
cd deploy/docker
install -d -m 0700 state
export APP_UID=$(id -u) APP_GID=$(id -g)
docker compose up -d --build
```

Open **http://localhost:4400**. No node is required to open the UI. The first
start creates `deploy/docker/state/config.toml`; all persistent state stays in
that directory. See [Docker setup](deploy/docker/README.md) for enrollment,
node credentials, backups and optional domain HTTPS with Caddy.

For hosts without Docker, [the simple systemd unit](deploy/standalone/README.md)
uses one dedicated account and the same process supervisor.

### Hardened host installation

`deploy/install.sh` keeps API and UI in separate accounts and verifies artifact
manifests. The requirements, configuration and install commands below apply to
this hardened path.

## Host requirements

- Rust 1.93.1 and Cargo, a C build toolchain, `pkg-config`, OpenSSL headers and `protoc` for the LND
  gRPC bindings. SQLite is bundled.
- A state directory owned by the service user with mode `0700`, on local disk.
- One `serve` process per database. It holds an exclusive lock, so bind it privately behind a TLS
  reverse proxy that preserves the `Host` header.

The plaintext API listener only accepts loopback bind addresses, including when `public_origin`
uses HTTPS. Terminate TLS on the same host. Remote proxy transport is not supported; do not expose
the listener on a LAN or wildcard address.

Credential files must be owned by the service user, have one hard link and mode `0600` (or stricter).
Public certificates may also be root-owned. Ancestors must be real directories owned by root or the
service user and not group/world-writable; root-owned sticky directories such as `/tmp` are allowed.
Symlinks in any path component and hard-linked material are rejected.

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

## Running it (hardened host path)

`deploy/install.sh` installs the release API and a static-plus-proxy server as system services with
distinct `lightning-driver-api` and `lightning-driver-ui` accounts. Create these unprivileged system
accounts before installation. The state directory defaults to `/var/lib/lightning-driver`; provision
it with mode `0700`, owned by `lightning-driver-api`, and put the protected config and credentials
there. The UI account must not own or read that state. Install binaries/assets outside home directories
(default `/usr/local`); `ProtectHome=yes` hides home directories from both services.

```sh
sudo useradd --system --home-dir /var/lib/lightning-driver --shell /usr/sbin/nologin lightning-driver-api
sudo useradd --system --no-create-home --shell /usr/sbin/nologin lightning-driver-ui
sudo install -d -m 0700 -o lightning-driver-api -g lightning-driver-api /var/lib/lightning-driver
```

Build as your own user first: the installer requires root, and building as root is refused. Then
install with the manifest and digest produced by `deploy/manifest.mjs` (see below):

```sh
cargo build --locked --release -p lightning-driver-api
sudo deploy/install.sh --ui-dist /path/to/lightning-driver-ui/dist \
  --binary target/release/api-server \
  --artifact-manifest /path/to/manifest.json --manifest-sha256 <trusted-manifest-sha256>
```

`--port` must match the port in `api.public_origin` (4400 by default). Re-running the script after a
rebuild upgrades both artifacts and restarts the services; it never rewrites the state directory.

The static server sends `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src
'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; …` with
`frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
NIP-46 remote signing connects to a relay the operator picks, so those origins are blocked by
default. Add the approved ones in a drop-in, space-separated and `wss://` only, then restart the
unit; the installer re-renders the main unit and would drop values written there:

```sh
sudo systemctl edit lightning-driver-ui
# [Service]
# Environment="RELAY_ORIGINS=wss://relay.example wss://relay2.example"
sudo systemctl restart lightning-driver-ui.service
```

Any other scheme, a path, a query or the absence of an explicit origin fails the server at startup.

When a TLS reverse proxy fronts this server, set `TRUSTED_PROXY` in the same drop-in to the proxy's
address (comma-separated for several). Only then does the server believe the `X-Real-IP` that proxy
sets, and the API's admission sees one identity per browser instead of the proxy's address for
everyone. The proxy must overwrite (not append) `X-Real-IP` with the client it accepted; from any
other peer the header is ignored and the TCP peer is used.

When migrating an existing user installation, stop and disable its two `systemctl --user` units first.
Move the complete state (including the original invoice key), transfer ownership to the API account,
and update any absolute paths in config before installing system units. Do not run both installations.
Host enrollment/recovery commands must run as `lightning-driver-api` for this installation.
The API sandbox permits writes only in the configured state directory; database, key and credentials
must live there. The UI has no writable persistent paths and cannot access the state directory.

Supplied artifacts require a version-1 JSON manifest and its SHA-256 from an independent trusted
release/build channel (a checksum shipped only beside an untrusted artifact is not provenance).
`deploy/manifest.mjs` writes that manifest from a built UI and, optionally, a built binary, and prints
its digest:

```sh
node deploy/manifest.mjs --ui-dist /path/to/lightning-driver-ui/dist \
  --ui-revision <full-ui-commit> --binary target/release/api-server \
  --api-revision <full-backend-commit> --out manifest.json
```

The manifest contains `ui.repository` (`https://github.com/jfrader/lightning-driver-ui`),
`ui.revision` (full source commit) and `ui.files` (every relative asset path mapped to its SHA-256).
With `--binary`, it also requires `api.repository` (`https://github.com/jfrader/lightning-driver`),
`api.revision` and `api.sha256`. Extra files, symlinks, missing provenance and mismatches are rejected.
The installer verifies a private staged snapshot before installing it. It never builds: pass the
`--binary` you built with `--locked`.

For API-only work, run the server directly:

```sh
CARGO_BUILD_JOBS=2 cargo run -p lightning-driver-api -- serve --config /path/to/state/config.toml
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
cargo run --quiet -p lightning-driver-api -- auth enrollment --config /path/to/state/config.toml
```

Submit the token in the UI and complete the passkey or NIP-07 ceremony. Tokens last
`api.limits.preauth_seconds` (300 by default). Issue another token to add a backup authenticator; it
does not create a second operator or revoke the first.

If every authenticator is lost, reset authentication from the host:

```sh
cargo run --quiet -p lightning-driver-api -- auth recovery \
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
node --test deploy/*.test.mjs
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --workspace
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --no-default-features
CARGO_BUILD_JOBS=2 cargo check --workspace --all-features
```

Deployment tests require Node, Docker Compose (configuration parsing only; no
image build or daemon needed) and Python 3.11+ for the standard TOML parser.

Set `HTTP_EVIDENCE_DIR` while running `cargo test -p lightning-driver-api --lib journeys` to capture actual
response JSON, then validate it with `python3 tools/validate-journey-responses.py <dir>`. The
validator needs the `jsonschema` Python package.

Tests drive the real routes, adapters and passkey ceremonies against the synthetic harness. They are
not a compatibility certification for a real daemon.

## Limitations

- The API serves no frontend assets. `deploy/install.sh` installs the UI build behind a separate
  static-plus-proxy service on the same origin, routing `/api/v1/*` here.
- There is no password or other login fallback.

## Releasing

For the first publish, from the release checkout run `cargo login` with a crates.io API token,
then `cargo publish -p lightning-client`, then `cargo publish -p lightning-driver-api`.
Trusted publishing requires each crate to exist first. In each crate's crates.io
Settings → Trusted Publishing, add GitHub owner `jfrader`, repository `lightning-driver`,
workflow `release.yml`, and leave the environment empty. Revoke the bootstrap API token.

For subsequent versions, update the manifests and lockfile, then push the matching `v*` tag.
The release workflow requires the tag to match both crate versions, checks the workspace,
and publishes `lightning-client` then `lightning-driver-api` using trusted publishing.
Already-published versions are skipped; registry errors fail the run. It creates a GitHub
release with generated notes unless that release already exists.
Manual workflow dispatch must select a `v*` tag; branch dispatches are skipped.
