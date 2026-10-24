# API operations runbook

Commands below use the default user-service install. For a custom install, substitute its binary, configuration and service names.

```sh
API="$HOME/.local/lib/lightning-driver/api-server"
CONFIG="$HOME/.local/state/lightning-driver/config.toml"
journalctl --user -u lightning-driver-api.service -n 100 --no-pager -o cat
```

## Log contract

The API writes JSON Lines to stderr: one object and newline per event. Every object has `level` (`info`, `warn`, `error`) and `event`. Additional fields are fixed below; nullable fields remain present. Systemd supplies timestamps. Logging errors are discarded; they never become request errors. There are no success logs on ordinary cached reads.

| event | fields beyond level/event |
| --- | --- |
| `startup` | `version`, `bind` (actual listening address), `node_count` (configured nodes, not healthy nodes), `database` |
| `startup_failure` | `error_code`: `configuration`, `storage_unavailable`, `instance_lock_unavailable`, `confirmation_required`, `listener_unavailable`, `output_unavailable` |
| `node_registration` | `node_id`, `backend`, `kind`, `outcome` (`success`/`failure`), `error_code` (null on success) |
| `read_failure` | `node_id`, `surface`, `error_code`, `stale` |
| `operation_transition` | `operation_id`, `kind`, `from` (null for creation), `to`, `stage`, `outcome` |
| `reconciliation` | `operation_id`, `attempt`, `next_delay_seconds` (null on exhaustion), `exhausted` |
| `auth` | `method` (`passkey`/`nostr`), `action` (`sign_in`, `enroll`, `link`, `unlink`, `sign_out`, `challenge`), `outcome` (`success`/`failure`) |
| `rate_limited` | `scope` (`api`), `retry_after_seconds` (same delay as the HTTP response) |
| `instance_lock` | `outcome` (`acquired`/`failure`) |

`read_failure.stale=true` means a stale observation can be served: for `info`, the summary is marked stale; for collection surfaces, a cached value is returned. False means this read did not serve a stale fallback. Surface names are the API resource names, never resource IDs or request parameters. A failure in the preliminary `info` refresh is logged as `surface=info`, not as a failure of every collection.

Transitions are logged only after commit, including review expiry and restart recovery. Stage-only changes also log. `outcome` uses the existing error-outcome vocabulary: `not_dispatched`, `unknown`, `definite_failure`, `not_applicable`; a successful operation without an error uses `not_applicable`, and `to=succeeded` identifies success. Unchanged evidence/replayed requests do not create transition events. Reconciliation logs when an attempt is durably allocated, before its read; `exhausted=true` appears once, on the final allowed allocation, not on subsequent status polls. This is not a daemon-result log.

Auth logs completed ceremonies and failed starts. Nostr failures without a valid bound challenge use `action=challenge`; Nostr operation authorization also uses `challenge`. Internal session rotation is not `sign_out`. Logs do not identify the operator, authenticator or session. Host token issuance prints its token only to stdout, not to this log.

Only the allowlisted projection is serialized. No node endpoints, credentials, certificates, runes, macaroons, cookies, auth identities, tokens, operation requests/results, invoices or preimages are logged. Node IDs must be nonsecret settings slugs; malformed, invoice-shaped and 64-hex token-shaped IDs are replaced with `[redacted]`. The configured database path is intentionally public metadata: do not put credentials in filenames. Startup version and bind address are build/listener metadata, not node transport data.

For example:

```sh
journalctl --user -u lightning-driver-api.service -o cat --no-pager |
  grep '"event":"node_registration"'
journalctl --user -u lightning-driver-api.service -o cat --no-pager |
  jq -R 'fromjson? | select(.event == "read_failure" and .node_id == "node-a")'
```

## Startup failure

1. Find the latest `startup_failure.error_code`. A `startup` event means the listener was bound; it does not mean all nodes registered successfully.
2. `configuration`: check TOML syntax, exact `api.public_origin` and `api.rp_id`, bind address, node IDs and runtime limits. Relative paths resolve from the config directory. Keep the existing origin/RP ID for enrolled passkeys.
3. `storage_unavailable`: check the service user's ownership, free space and permissions. The state directory must be `0700`; the database, key and lock files must be `0600`, regular files, owned by the service user and not symlinks. Check the pending invoice key is the original 32-byte file. Restore the original key if missing; do not generate a replacement when pending ciphertext exists.
4. `listener_unavailable`: check `ss -ltnp` for an occupied bind address and check the service's configured bind. Do not expose the listener publicly to work around a proxy error.
5. Correct the cause and run `systemctl --user restart lightning-driver-api.service`. Confirm `instance_lock.outcome=acquired`, then `startup`, and inspect every `node_registration`.

## Instance lock or database lock

1. For `instance_lock.outcome=failure` / `startup_failure.error_code=instance_lock_unavailable`, inspect `systemctl --user status lightning-driver-api.service` and `pgrep -af api-server`. Stop a duplicate service/process gracefully. Run only one serving process per database.
2. Do not remove `<database>.serve.lock` while a process may hold it: deleting it can permit two writers. The OS releases the lock when its owner exits; the empty file can remain.
3. If no process owns it, check the lock file's ownership, mode, file type and link count. Fix ownership/permissions only after stopping the service. Do not replace it with a symlink.
4. SQLite contention can surface as `storage_unavailable` (startup or API response); the API does not distinguish a busy DB from other protected-storage failures in logs. Let an in-progress host enrollment/recovery command finish. Find other processes using the database. Keep it on local persistent storage, not NFS. Never delete the database, WAL or SHM files to clear a lock.

## Enrollment and recovery

```sh
"$API" auth enrollment --config "$CONFIG"
```

Use the printed one-use token in the same-origin UI enrollment flow within `api.limits.preauth_seconds` (default 300 seconds). Keep stdout private; do not paste the token into a URL, command argument, issue or log. Successful registration logs `auth` with `action=enroll`, the chosen `method`, and `outcome=success`. For `outcome=failure`, verify the browser origin/Host, token expiry and authenticator; restart the ceremony. Passkey enrollment consumes the token at start, so issue another after an abandoned/failed start. Nostr enrollment consumes it after signature verification. Respect `rate_limited.retry_after_seconds` before retrying.

If all sign-in methods are lost, run from a trusted host terminal:

```sh
"$API" auth recovery --config "$CONFIG" --confirm-reset-authentication
```

This revokes existing passkeys, Nostr identities and sessions, preserves operations, and prints a new enrollment token. Without confirmation, expect `startup_failure.error_code=confirmation_required`. Enroll again and sign in; inspect `auth.action=enroll` and `auth.action=sign_in`. Do not reset the database to recover authentication. Host auth commands may run while the serving process holds its instance lock.

## A node reports `node_auth_error`

1. Filter `node_registration` and `read_failure` by `node_id` and `error_code=node_auth_error`. Note `backend`, `kind` and the failing `surface`.
2. Check that node's protected `credential_file` is readable by the service user. Inspect credentials locally, never by printing them into logs or support tickets.
3. LND: provision the required read/write permissions and `macaroon:read` for mutation preflight. CLN: check the rune's allowed methods/restrictions. Bitcoin Core: check the configured RPC credential/cookie and daemon access. See README's permissions section.
4. Replace credential material through the protected file, restart the API, and check registration and a fresh node read. Do not retry an unresolved payment or send merely because authentication is fixed; check its operation first.

## A pinned certificate rotated (`not_configured`)

1. Find `node_registration` with `outcome=failure,error_code=not_configured` after restart. For a runtime failure, inspect `read_failure` for the same node. This code also covers other construction/configuration failures; confirm the rotation with the node administrator.
2. Verify the replacement certificate through a trusted channel. For pinned LND, `certificate_file` must contain exactly one PEM certificate matching the daemon's DER certificate, currently valid and with a SAN matching the endpoint host.
3. Replace the protected certificate file and restart the API. Confirm registration succeeds and reads are fresh. Never disable TLS verification or silently trust a certificate received over the failing connection.

## An operation is stuck in reconciliation

1. Filter `operation_transition` and `reconciliation` by `operation_id`. Check `to`, `stage`, `attempt`, `next_delay_seconds`, `exhausted`.
2. Open that operation's status in the UI (or authenticated `GET /api/v1/nodes/{node_id}/operations/{operation_id}`); check the node's connectivity/auth and stable identity/configuration. Reconciliation is triggered by status/list reads, not a background retry timer. A delay is a minimum wait before another read can allocate an attempt.
3. Attempts use 5-second exponential backoff capped at 1,800 seconds and a durable lifetime budget of 96. Restarting does not reset it. At `exhausted=true`, automatic observations stop; check the daemon's history independently. Absence of another log does not mean success or failure.
4. Do not resubmit the mutation, delete resource claims, edit the journal or invent a retry endpoint. Unknown/dispatched operations may already have taken effect. Preserve their operation IDs and reconcile with daemon records before any separate action. No manual exhaustion-reset endpoint is provided.

## Stale reads

1. Filter `read_failure` by `node_id` and `surface`. Check `error_code` and `stale`; compare the response's observation time with the current time. `stale=true` is not current node state.
2. Restore connectivity/permissions or correct the verified identity/network mismatch. Identity/network mismatches invalidate Bitcoin/watchtower caches; tower-detail reads cannot return a stale fallback.
3. Wait at least `api.limits.rpc_seconds`, then refresh the surface. A successful read has no log; confirm freshness from the API/UI. For `rate_limited`, wait the advertised delay and reduce polling/concurrency; do not raise limits without checking capacity.

## Restart / redeploy

1. Record unresolved operation IDs. Stop the API gracefully: `systemctl --user stop lightning-driver-api.service`.
2. With writers stopped, back up the state directory, database (including any remaining WAL/SHM), original invoice key and protected configuration/material together. Keep backups private. Never replace the key independently of the database.
3. Install the built binary/UI using the documented `deploy/install.sh` options. Preserve the state directory, origin/RP ID and verified node identity/material. Start/restart the service and inspect `startup`, `instance_lock` and each `node_registration`.
4. Authenticated sessions survive restarts until expiry, sign-out or credential recovery. Grants and challenges are process-local; restart any unfinished sign-in or authorization ceremony. Undispatched reviews expire on restart; create a new review. Dispatched unresolved operations transition to `unknown` / `reconciling` and retain their lifetime reconciliation budget. Check their status before creating another mutation.

This log/runbook contract is verified against the workspace's synthetic adapters/tests, not a production-node operational certification. Log retention, aggregation, alerts, metrics and manual journal repair are outside this change.
