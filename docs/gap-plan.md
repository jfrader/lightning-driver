# Gap plan

## P1.7 — Observability: log contract and ops runbook — Done

GURI-3140 (Observability: log contract and ops runbook), part of GURI-3003 P1.7.

- `api-server/src/observability.rs`: allowlisted JSON Lines events on stderr, typed error codes, no payload/debug serialization, best-effort output.
- Startup/listener, per-node registration, failed read surfaces/stale fallback, committed operation/stage transitions (including expiry/recovery), durable reconciliation allocation/exhaustion, auth, API rate limits and instance-lock events are wired at their owning boundaries.
- Redaction and exact event-field/line-shape tests cover the log projection and secret-bearing configuration, operation, purpose and malformed ID inputs. Failed output is tested without panic.
- `docs/runbook.md` documents the event/field contract and startup, locks, enrollment/recovery, node authentication, pinned-certificate rotation, reconciliation, stale reads and restart/redeploy procedures.
- Verification: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` passed. The workspace has 266 passing tests (257 existing plus 9 new observability tests). The existing binary startup/recovery tests now assert JSON stderr events; the expiry test checks metadata-only projection and transaction rollback. The reconciliation budget test emitted exactly one `exhausted=true` event for its exhausted operation across restart/status reads.

The supplied base commit did not contain `docs/gap-plan.md`; this file records only the requested P1.7 item and does not reconstruct unrelated plan sections.
