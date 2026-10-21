# Lightning node-manager backend

This workspace runs the **passkey API, configured-node registry, durable operation journal, the operation engine with its create/authorize/confirm routes, local invoice decoding, and typed CLN REST, LND REST and LND gRPC adapters**. Live collection read routes (`balances`, `invoices`, `payments`, `peers`, `channels`, `transactions`, `fee-estimates`, `info`) and frontend asset serving are still pending, so those paths return JSON 404. Adapters are proven against the loopback synthetic harness only; no real daemon has been contacted, and nothing here is a real-node or production readiness claim.

The versioned wire contract is [`api-server/openapi.json`](api-server/openapi.json). The frozen contract includes later-stage endpoints; their presence in that file is not an implementation claim.

`lightning-client` owns the shared `model`, `money`, `settings` and `validation` modules. The legacy single-node `LightningClient` interface, configuration factory and transport wrappers are removed; CLN and LND adapters live in `api-server` without client-crate feature flags.

## Requirements and configuration

- Rust/Cargo 1.93.1; workspace edition remains 2021.
- A C build toolchain, `pkg-config`, OpenSSL development headers and `protoc` for the existing gRPC binding. SQLite is bundled by rusqlite.
- One API process per database, persistent local storage, and a public HTTPS origin behind a TLS reverse proxy. Bind the backend privately and preserve the original `Host` header. Forwarded identity/host/scheme headers are not trusted.
- Use a state directory owned by the service operator with mode `0700`. The database and instance-lock file are created with mode `0600`; existing unsafe file modes or symlinks are rejected. Do not share a SQLite database over a network filesystem.

Copy `config.example.toml` into that directory and replace the example public hostname and RP ID with the exact intended hostname **before enrolling authenticators**. Relative database/key/certificate references resolve against the configuration file's directory, not the command's working directory.

The example has `nodes = []`. No node credentials, certificates or real nodes are required to start the API. `invoice_key_file` is required: on first start it is created with mode `0600` when absent and no pending ciphertext exists; a missing, wrong, truncated or unsafe key with pending ciphertext fails startup closed. No money limits are inferred from this example.

Run the API:

```sh
CARGO_BUILD_JOBS=2 cargo run -p api-server -- serve --config /absolute/state-directory/config.toml
```

`serve` holds an exclusive instance lock. Host authentication commands can use the same configuration/database while it runs. Starting a second API instance against that database fails without resetting authentication or journal state. The listener uses two HTTP workers. The startup line on stderr reports the bound API address, not any Lightning endpoint.

### Explicit loopback-only development

For local browser work, use a **separate synthetic state directory**, for example `/tmp/lightning-driver/lightning-auth-stage1`, with this configuration:

```toml
nodes = []

[api]
bind = "127.0.0.1:8080"
public_origin = "http://localhost:8080"
rp_id = "localhost"
database = "manager.sqlite"
invoice_key_file = "pending-invoice.key"
allow_insecure_loopback = true
```

Create the directory with `install -d -m 700 /tmp/lightning-driver/lightning-auth-stage1`, save the configuration as `config.toml`, then run:

```sh
CARGO_BUILD_JOBS=2 cargo run -p api-server -- serve --config /tmp/lightning-driver/lightning-auth-stage1/config.toml
```

Both the bind address and public origin must be loopback when the development exception is enabled. Use `localhost` consistently in the browser, Origin and Host. A same-origin development proxy must preserve that Host; if its public port differs, configure that exact origin port. Development uses `ld_dev_session`/`ld_dev_preauth` HttpOnly, SameSite=Strict cookies without Secure; production always uses Secure `__Host-ld_session`/`__Host-ld_preauth` cookies. The development flag never weakens public HTTPS configuration or passkey verification.

The Rust checkpoint does not serve frontend assets or a registration page. The frontend must use the same origin and the frozen JSON API; WebAuthn registration needs an authenticator, not a password or a curl-only login.

## Host enrollment and recovery

Issue an enrollment token from a trusted host terminal:

```sh
CARGO_BUILD_JOBS=2 cargo run --quiet -p api-server -- auth enrollment --config /tmp/lightning-driver/lightning-auth-stage1/config.toml
```

The command prints one random token once on stdout. It expires after `api.limits.preauth_seconds` (default 300 seconds), is hash-only at rest and is consumed when enrollment starts. Do not place it in a URL, command argument, log or persisted browser storage. Issue a new token if enrollment fails or is abandoned.

Browser enrollment sequence:

1. GET `/api/v1/auth/bootstrap` for the preauthentication cookie, CSRF token and expiry.
2. POST `/api/v1/auth/enrollment/start` with `{ "enrollment_token": "..." }`, that cookie and `X-CSRF-Token`. Exact Origin/Host checks apply.
3. Pass the returned `options.publicKey` JSON to a compatible WebAuthn browser helper; POST its registration response with `challenge_id` to `/api/v1/auth/enrollment/finish`.
4. Keep only the returned authenticated CSRF/expiry view in memory. The app session is an opaque HttpOnly cookie.

Issue another host enrollment token to register an independent backup authenticator for the same operator. Enrollment does not create a second account or revoke existing authenticators. Login uses `/api/v1/auth/passkey/start` and `/finish` with a fresh anonymous bootstrap context. All ceremony state is held server-side, bounded, expiring and single-use, including failed verification attempts.

Lost-all-authenticator recovery is host-only and requires explicit confirmation:

```sh
CARGO_BUILD_JOBS=2 cargo run --quiet -p api-server -- auth recovery \
  --config /tmp/lightning-driver/lightning-auth-stage1/config.toml \
  --confirm-reset-authentication
```

Without the confirmation flag, the command refuses without modifying storage. Confirmed recovery atomically revokes all registered passkeys and previous enrollment tokens, advances the durable authentication generation, and prints one new enrollment token. Running sessions/ceremonies cannot authenticate after that generation changes. Re-enroll using the normal sequence. The operator ID, operation history, unresolved claims and encrypted pending-invoice records are not deleted by authentication recovery.

Stopping/restarting the API preserves passkeys and SQLite operation history but loses ephemeral sessions/grants. Startup marks potentially dispatched unfinished operations unknown and expires undispatched reviews; it never submits or retries a node action. There is no password fallback, legacy `/login`, `/logout`, money-moving `/api` route or supported `set-password` utility.

## Session and policy endpoints

- GET `/api/v1/session` returns the current CSRF token, idle/absolute expiries, last authentication time and server reauthentication policy; unauthenticated access returns 401.
- DELETE `/api/v1/session` requires exact Origin and the session's `X-CSRF-Token`, revokes that session and returns an empty 204 response.
- GET `/api/v1/config` requires authentication and returns safe runtime policy only. It contains no database paths, node endpoints, certificates, macaroons, runes or other credential material.
- JSON requests use `Content-Type: application/json`; responses/errors use `Cache-Control: no-store`. Bootstrap is reachable without an authenticated CSRF token. All POSTs use the preauth/session-bound token as appropriate; login is not a CSRF exemption.

The default reauthentication policy is `every_operation`. For a server-controlled recent-auth window, configure:

```toml
[api.reauth]
mode = "recent"
recent_auth_seconds = 120
```

This policy is exposed now and enforced by the operation routes. A sensitive confirm without a bound, unexpired authorization is rejected; the browser cannot weaken the server policy.

## Registry, history and decode reads

Authenticated GET `/api/v1/nodes` returns the sorted configured registry, including a genuine fresh empty list when no nodes are configured. GET `/nodes/{node_id}`, `/status` and `/policy` under the same API prefix return sanitized registry/status/effective policy. These reads still present the registry projection, not a live observation: until the collection routes are wired, status reports `unsupported` with `node_unverified`, freshness is stale with no observation, observed identity/revision/sync are null and network is `unknown`. The fleet snapshot itself is a fresh local observation. Mutation capabilities follow the configured policy and adapter availability (`read_only` takes precedence, otherwise `unverified`). Configured expected identity/network are not advertised as verified observations.

GET `/nodes/{node_id}/operations` and `/operations/{operation_id}` read the durable journal even for removed or retargeted node IDs. Lists support `state` (including `nonterminal`) and `kind`, ordered by exact creation time descending then ID ascending. Filters apply in SQLite before the snapshot bound. Unresolved counts use all nonterminal records, not a capped page. Historical review identities are never rewritten to the current configured binding. Mixed historical bindings produce page network `unknown`; a single historical binding retains its original network. These reads perform no node reconciliation or mutation.

POST `/nodes/{node_id}/decode` requires the normal session/Origin/CSRF boundary and JSON `{ "bolt11": "..." }`. It uses the maintained local BOLT11 parser even for read-only/unverified nodes; an unobserved node network yields `network_matches_node: null`. Malformed invoices fail; valid expired invoices decode with `expired: true`. This call never pays or acquires a journal claim.

Collection cursors are random opaque server-held snapshot tokens. They bind authenticated session, resource, node/config/history identity scope, filters and limit. Immutable rows and observation time do not shift between pages. TTL/restart returns `410 cursor_expired`; malformed cursors or changed selectors/session return `400 invalid_cursor`. A truncated snapshot remains truncated on its final page even with no next cursor. Query keys are explicit; duplicate/unknown keys and noncanonical/invalid explicit limits fail rather than falling back to defaults.

Central `[api.limits]` cache defaults are `snapshot_max_entries=64`, `snapshot_per_session=8`, `snapshot_cache_bytes=16777216`. `[api.limits.pagination]` defaults are `default_limit=50`, `max_limit=200`, `snapshot_ttl_seconds=120`, `snapshot_max_items=10000`. Cache entry counts, serialized row bytes and per-snapshot row/token counts are bounded; expired allocations are reclaimed on requests without background workers. Repeated abandoned reads can hit `429 rate_limited` until expiry. Restart discards cursors, not history.

Fingerprints are centralized SHA-256 digests of deterministic typed JSON tuples. The public policy/binding fingerprint still uses `binding-v1`, node ID, backend, expected pubkey/network, endpoint and certificate/credential file references (not file contents). The internal operation binding revision additionally hashes the certificate and credential bytes read at startup, so rotating either invalidates old bindings without exposing them. Policy input is `policy-v1`, that binding digest, money policy, peer egress policy, read-only flag, public origin, RP ID, explicit development exception, global reauth policy and runtime limits. File-reference rotation changes the digest; credential bytes are deliberately not read in this checkpoint. Actual transport observations must extend verified identity binding in the adapter stage; no verified identity revision is exposed yet. History scope hashes sorted distinct immutable review bindings; fleet scope hashes sorted IDs/binding/policy digests. Neither raw endpoint nor credential references are returned in DTOs.

## Verification

### Synthetic full-stack development

Requires `openssl` on PATH. From the workspace root, start the disposable,
loopback-only TLS node harness explicitly:

```sh
cargo run -p synthetic-node-harness --features synthetic-dev -- --acknowledge-synthetic-dev --public-port 5173
```

It prints exact `api-server serve` and `auth enrollment` commands using its
generated private configuration directory under `/tmp/lightning-driver/`. Run those in
separate terminals. Serve the UI on `http://localhost:5173`; its development proxy
must forward `/api/v1` to `http://127.0.0.1:8080` with `changeOrigin: false`, keeping
the browser's `Host: localhost:5173` and Origin. Enroll a passkey normally. Omit
`--public-port` for API-only work directly on `http://localhost:8080`. There is no
authentication bypass, injected adapter or production configuration change.
Stop the API first, then Ctrl-C the harness: its synthetic journal, credentials
and freshly generated TLS CA/keys are deleted. Do not use this directory for
real state. The harness is not an API-server dependency, is excluded from the
workspace default members, and its binary requires both the non-default feature
and the acknowledgement flag. Every listener and peer must be loopback.

The three independent nodes implement the adapter subset of CLN v25.02 REST and
LND v0.18.5-beta REST/gRPC (Lightning, Router and WalletKit). These are tagged
synthetic shapes, not daemon compatibility certification. Each node runs one
seeded scenario: one retained invoice/payment and fixed transaction/channel
references. Restart the harness for a new independent scenario. Payments settle
on tracking, channels activate after observation, and closes are cooperative.
The library can script rejection, permission loss, timeout before/after effect,
malformed/oversized responses and late LND stream errors, without retrying.
Existing API read-route coverage is unchanged; this harness does not add missing
HTTP collection endpoints or serve frontend assets.

Run wire-level journeys and validate their actual HTTP responses against the
unchanged frozen schema (the Python environment must provide `jsonschema`):

```sh
EVIDENCE=$(mktemp -d /tmp/lightning-driver/lightning-journeys.XXXXXX)
HTTP_EVIDENCE_DIR="$EVIDENCE" CARGO_BUILD_JOBS=2 cargo test -p api-server --lib journeys
python3 tools/validate-journey-responses.py "$EVIDENCE"
CARGO_BUILD_JOBS=2 cargo test -p synthetic-node-harness --features synthetic-dev
```

From the workspace root:

```sh
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --workspace
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --no-default-features
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --all-features
```

Integration tests use the production application factory, real software-authenticator ceremonies, the loopback synthetic harness, temporary synthetic configuration and finite CLI subprocesses. Registry/history/decode tests cover safe projection, strict boundaries, stable filtered snapshots, session/selector/TTL/restart binding, cache limits, exact unresolved counts, removed/retargeted identities, nanosecond ordering and signed synthetic invoices. The nine journey tests exercise all eight mutations across the three transports through the real adapters and HTTP routes. Set `STAGE2A_EVIDENCE_DIR` to a scratch directory while running `cargo test -p api-server --test stage2a` to capture representative actual response JSON tagged with frozen schema names for independent validation. No real Lightning node or funds are involved; synthetic shapes are not daemon compatibility certification.

For an intentional local reset, stop the API and remove **only the synthetic state directory you created** under `/tmp/lightning-driver/`, then recreate it and enroll again. Authentication recovery is the alternative when operation history must be retained. Do not delete a real journal, rotate its key or copy a live SQLite main file alone as a substitute for a reviewed backup/recovery procedure.
