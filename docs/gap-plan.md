# Gap plan — Lightning Driver production readiness

Working plan for GURI-3003 (Finish Lightning Driver: close the production-readiness gaps).
Source inventory: `finish-all-spec.md`; acceptance for each item below cites the code and
test that decides it. Status is what is true on this branch, not what is intended.

## Baseline

Backend `25c14d6`, UI `8478be6` on `jfrader/guri-2973-…`: backend 198 tests, UI 424 unit /
221 browser, first-load budget 265,027 B. Real e2e exists and is opt-in. No CI, no deployable
artifact, no public edge.

## P0 — correctness and production blockers

| Item | Status | Evidence |
| --- | --- | --- |
| P0.1 Stock LND TLS rejected | Done | `tls_verification = "ca" \| "pinned"` per node. Pinned mode requires the exact DER of the configured certificate, checks its validity window, and still verifies the DNS or IP subject. REST uses a preconfigured rustls client; gRPC uses a custom connector over `connect_with_connector_lazy`. `pinned_tls_accepts_stock_lnd_on_both_transports`, `pinned_tls_accepts_ip_san_on_both_transports`, `pinned_tls_rejects_rotated_certificate_on_both_transports`, `pinned_tls_rejects_wrong_san_on_both_transports`, `ca_tls_still_rejects_stock_lnd_ca_as_leaf_on_both_transports`. |
| P0.2 Real CLN open unproven | Done, one CLN limit documented | The Polar `clightning:25.12` image reproduces `mandatory-script-verify-flag-failed (OP_EQUALVERIFY)` on `fundchannel` against bitcoind 29; `25.09.3` funds and pays, now pinned. The adapter passed a funding outpoint to `close`, which CLN rejects with -32602; it now passes the channel id. It also sent `unilateraltimeout: 0`, which CLN treats as "force close now"; a cooperative close omits it, and the suite connects both peers first. The real e2e proves `fundchannel`, `invoice` and `xpay`; CLN 25.09 keeps a cooperatively closed channel in `listpeerchannels` as ONCHAIN with no close cause and never lists it in `listclosedchannels`, so the close operation is accepted and broadcast but stays `pending` (asserted). |
| P0.3 Uncertain operations stay unknown | Done | Read-only reconciliation reserved before contact, persisted in `operation_intents.evidence.reconciliation`, exponential backoff `min(5 × 2^(n−1), 1800)` s, 96 lifetime attempts (43 h 41 min 55 s). Status reads observe one operation; list snapshots observe at most two, sequentially, inside a two-second deadline. No mutation RPC and no automatic redispatch. Exact CLN channel abandonment requires a closed channel with withheld funding; absence and elapsed time never prove failure. `reconciliation_*` tests in `operations/tests.rs`, `operations/cln/tests.rs`, `operations/http_tests.rs`. |
| P0.4 Stale unresolved count | Done, one follow-up found | One `QueryCache` subscription in `create-app.ts` detects operation state changes and invalidates the node summary, fleet, operations lists and the kind's affected reads. Browser regression at phone and desktop. The audit also found the same class on the server: `Live::observed` served a cached node read for up to `limits.rpc_seconds` (30 s), so a list requested right after a successful mutation could still answer from before it. The engine now drops that node's cached reads when a claim reaches the node and when an observation changes state, stage, result or error; `Registry` owns the cache budget and releases the dropped bytes. `a_claim_that_reaches_the_node_drops_its_cached_reads` covers it. |
| P0.5 LND REST partly proven | Done | Every LND REST mutation succeeded through the real adapter on the regtest stack in one run: `new_address`, `send_onchain`, `connect_peer`, `disconnect_peer`, `open_channel`, `pay_invoice`, `close_channel`, alongside the collection reads. The shared REST/gRPC normalization is unchanged. |
| P0.6 Stale contract examples | Done | `api-examples.json` carries `passkey_login_available`, `nostr_login_available` and `auth_method`; openapi and examples hashes re-frozen; UI copy regenerated; `EXAMPLE_GAPS` deleted. |
| P0.7 Desktop sign-in methods | Done | `/more` is a real route at every width with a sidebar and palette entry; the same `MorePage`/`SignInMethods` components serve desktop and phone. Browser coverage at both widths. |
| P0.8 CI and release gates | Done (workflows), unrun | Backend gate job and UI gate job on `[self-hosted, mifulbo-ci]`; opt-in `workflow_dispatch` e2e job that checks out the backend repository with `LIGHTNING_DRIVER_CHECKOUT_TOKEN` and needs Docker. Image digests pinned in the e2e compose file. Nothing has run: the repos are not pushed and there is no release path yet. |

## P1 — completeness and hardening

| Item | Status | Note |
| --- | --- | --- |
| P1.1 Real-passkey e2e | Open | Injected Nostr signer today; virtual-authenticator passkey not covered. |
| P1.2 NIP-46 | Deferred by decision | Fran: for later. NIP-07 only; no copy claims mobile remote signing. |
| P1.3 Link/Nostr step-up | Done | Adding an authenticator requires a session authenticated within `api.limits.authorization_seconds`; a stale session gets `reauth_required`, and the UI signs in again with the method that owns it before retrying once. Unlink keeps its own rule (a fresh signature from the identity being removed) and host recovery stays documented. `linking_a_key_requires_a_session_authenticated_moments_ago` and the sign-in-methods UI test cover both sides. |
| P1.4 Least-privilege credentials | Done | The real e2e adds an LND node with a read-only macaroon and a CLN node with a restricted rune. Reads answer; every mutation is refused before dispatch with `node_auth_error` and creates no operation. The LND adapter's `CheckMacaroonPermissions` preflight requires `macaroon:read` and now treats LND's `InvalidArgument: permission denied` as a refusal instead of an upstream failure; CLN's `checkrune` denial maps to the same code. The README lists the exact per-operation permissions. `a_denied_macaroon_permission_refuses_the_review_before_dispatch` and `a_rune_denial_reads_as_an_auth_error` cover the mapping. |
| P1.5 Read-only and policy on real nodes | Done | The e2e also runs an admin credential on a `read_only = true` node (refused before any RPC), a create-invoice amount above the node's policy bound and a peer host outside the allowlist (both `policy_violation`, no operation created) against real LND. |
| P1.6 Restart/reconnect/recovery drills | Open | Pieces tested; full scripted drill missing. |
| P1.7 Observability and ops runbook | Open | No log contract or runbook yet. |
| P1.8 UI and accessibility gaps | Partly done | Count invalidation and desktop sign-in methods fixed; mobile tab-bar overlap, long-value wrapping, 390/768/1280 and forced-colors audit still open. |
| P1.9 Bundle performance | Accepted debt | Entry route grew 1,272 B across this pass (P0.4, P0.7, the reconciliation copy); budget re-recorded twice, latest `266,299 B` gzip, chart chunk `86,845 B`. No structural headroom yet: the generated validators are the largest initial module (520 kB minified) and need a split that preserves first use. |
| P1.10 GURI-2924 Drawer scrim token | Separate | Library repository, own issue and version bump. |

## P2 — product and delivery

Public hostname/TLS/RP-ID shape, release artifact (container or systemd), versioning, changelog,
rollback, real-node compatibility matrix and repo docs are untouched: nothing is deployed and no
URL, tunnel or DNS record is created.

## Order of slices used here

1. P0.1 TLS (isolated transport seam).
2. P0.6 examples + hash re-freeze (touches both repositories).
3. P0.4 stale counts, then P0.7 desktop sign-in methods (UI shell).
4. P0.3 reconciliation, then the contract field it exposes.
5. P0.8 CI.
6. P0.2/P0.5 when a Docker daemon is available.

## Risks

- Pinned TLS trusts one exact certificate: an unintended rotation breaks the node connection until
  the protected file is replaced. That is deliberate; the error is sanitized as `not_configured`.
- Reconciliation only runs when authenticated reads happen. An operator who closes the browser stops
  the schedule; the ceiling is a count of attempts, not wall-clock time.
- The e2e image digests are resolved for the current tags; a new upstream tag needs a new digest.
