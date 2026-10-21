# Lightning node-manager backend

This branch currently runs the **stage-1 passkey/session/configuration API**, not the complete node manager. Node resources, all three operational adapters, operation orchestration and the synthetic Lightning harness are still pending. Missing endpoints return JSON 404 errors; they do not report invented nodes, balances or successful actions.

The versioned wire contract is [`api-server/openapi.json`](api-server/openapi.json). The frozen contract includes later-stage endpoints; their presence in that file is not an implementation claim.

## Requirements and configuration

- Rust/Cargo 1.93.1; workspace edition remains 2021.
- A C build toolchain, `pkg-config`, OpenSSL development headers and `protoc` for the existing gRPC binding. SQLite is bundled by rusqlite.
- One API process per database, persistent local storage, and a public HTTPS origin behind a TLS reverse proxy. Bind the backend privately and preserve the original `Host` header. Forwarded identity/host/scheme headers are not trusted.
- Use a state directory owned by the service operator with mode `0700`. The database and instance-lock file are created with mode `0600`; existing unsafe file modes or symlinks are rejected. Do not share a SQLite database over a network filesystem.

Copy `config.example.toml` into that directory and replace the example public hostname and RP ID with the exact intended hostname **before enrolling authenticators**. Relative database/key/certificate references resolve against the configuration file's directory, not the command's working directory.

The example has `nodes = []`. No node credentials, certificates or real nodes are required for this checkpoint. `invoice_key_file` is a required typed configuration field reserved for the later operation engine; stage 1 does not open or create it. No money limits are inferred from this example.

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

This policy is exposed now and exercised in the core tests. Sensitive operation HTTP endpoints are deferred; this checkpoint must not be used to move funds.

## Verification

From the workspace root:

```sh
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --workspace
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --no-default-features
CARGO_BUILD_JOBS=2 cargo check -p lightning-client --all-features
```

The stage-1 integration tests use the production application factory, real software-authenticator ceremonies, temporary synthetic configuration and finite CLI subprocesses. They cover token hashing/one-use, recovery refusal/revocation, restart persistence, instance locking, legacy-route rejection, safe config/error responses and a finite loopback serve smoke test. Spawned children are awaited/terminated; no real Lightning node or funds are involved. Feature compilation is not proof that the deferred adapters satisfy the complete MVP.

For an intentional local reset, stop the API and remove **only the synthetic state directory you created** under `/tmp/lightning-driver/`, then recreate it and enroll again. Authentication recovery is the alternative when operation history must be retained. Do not delete a real journal, rotate its key or copy a live SQLite main file alone as a substitute for a reviewed backup/recovery procedure.
