# PARITY.md — contract scope for the Rust → Go enforcer port

This file declares what IS and IS NOT parity contract. The port reproduces
current Rust behavior exactly within this scope; anything declared out of
scope here may diverge without failing the port. Sources of truth: the
immutable conformance vector (`tests/conformance/breach_event_v1.json`), the
unchanged Python phase-1 gate suite, and `PARITY_LEDGER.md`.

## Error responses

- **Status codes ARE contract. Error body text is NOT.**
  Axum/serde-generated 400 (malformed JSON) and 415 (bad Content-Type) body
  text is unreproducible by construction. Go returns `{"error": msg}` with
  Go-native text, and maps axum's 400 and 415 cases to **422** — accepted,
  gate-invisible, documented here.

## POST /sessions

- **Check order IS contract:** `409 duplicate → 422 bad CIDR → 500 backend`
  (mirrors `api.rs:73 → :79 → failure path`). A request that is both a
  duplicate session_id and has an invalid CIDR returns **409**.
- **422 rule:** all 7 `Credential` fields are required — nil-pointer check
  after unmarshal; any `json.Unmarshal` error ⇒ 422. Do **not** use
  `DisallowUnknownFields` (axum ignores extra fields; so do we).

## Out of parity scope (revisit at E3)

- Timestamp fractional-second formatting (`chrono` `AutoSi` emits variable
  precision; only the fixed fixture string `2026-06-30T00:00:00+00:00` is
  ever signed or compared in the parity window — events are always `[]`).
  **Resolved at E3 planning (3 July 2026):** live events emit second-precision
  timestamps via the fixed layout; the divergence from chrono is accepted and
  the conformance vector is not re-frozen.
- The `load()` `created_at=now` quirk: field kept verbatim for ledger
  integrity, never serialized.
- Trailing-slash 301 behavior of Go's ServeMux (the gate never sends
  trailing slashes).

## Post-parity divergence — E3.1 (3 July 2026)

The ruleset renderer deliberately diverges from the final Rust output:

- `10.200.0.0/16` (uplink veth pool) added to the unconditional IPv4 denies —
  a targets claim must not reach another session's uplink.
- Every explicit deny logs to NFLOG group 1 (`log prefix "warden:<sid>:"`).
- A trailing catch-all log+counter rule precedes each family's policy drop
  (off-scope packets otherwise fall through unlogged — E3's breach signal
  source).

The 3 `testdata/*.nft` goldens are Go-owned from this point (third
re-capture). Everything else in this file remains contract.

## Linter suppressions are parity-preserving by design

`//nolint:gosec` sites (G204 subprocess interpolation in the Linux backend,
G302/G306 socket mode bits) mirror the Rust implementation exactly. Do NOT
"fix" them — adding input validation or tightening modes the Rust code does
not have is a parity break, not an improvement. See the port plan M9.

## JWK wire format

Response keys serialize **alphabetically** (`crv, key_id, kty, x`;
`retired_at` sorts between `kty` and `x` when present) — matching
`serde_json` without `preserve_order`. Marshal from `map[string]any` (Go
sorts map keys) and pin with a byte-golden test.
