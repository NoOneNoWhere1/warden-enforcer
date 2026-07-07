# Breach Event Canonicalization

**Status:** Normative for v1. Applies to every Warden attester.

Warden's accountability guarantee is that a breach event signed by one runtime
can be verified by any other runtime, indefinitely — including after key
rotation, across language boundaries, and by an external auditor. That only
holds if every implementation agrees, **byte for byte**, on the message that was
signed.

## The contract

The signed message is the breach event serialized with **RFC 8785, JSON
Canonicalization Scheme (JCS)**, with the `signature` field removed.

- Object keys sorted by UTF-16 code unit.
- Minimal string escaping (RFC 8259 rules).
- ECMAScript (`Number.prototype.toString`) number formatting.
- No insignificant whitespace.

The signature is **Ed25519** over the canonical UTF-8 bytes, encoded
**base64url without padding**.

Each attester pins a conformant JCS library in its own stack rather than
re-deriving an ordering:

| Runtime | Attester | Library |
|---|---|---|
| Go | `warden-enforcer` (network) | `github.com/gowebpki/jcs` (`enforcer/internal/canonical/canonical.go`) |
| Python | `warden-mcp` (tool / intent) | a published RFC 8785 implementation (Phase 4) |
| .NET | `warden-api` (resource) | a published RFC 8785 implementation (Phase 2/M5) |

> Do **not** rely on a language's default JSON serializer "happening" to sort
> keys. That is the fragility this document exists to remove: an incidental
> ordering is not a contract, and it silently breaks the first time a non-string
> field or non-ASCII key is added.

## Conformance vector

`enforcer/tests/conformance/breach_event_v1.json` is the frozen, cross-language
test vector. It contains a fixed private-key seed, the derived public key, a
fixed breach event, the expected canonical JSON, and the expected signature.

Every attester's test suite MUST:

1. Reproduce `canonical_json` from `event` (minus `signature`) via its JCS lib.
2. Reproduce `signature_b64url` by Ed25519-signing those bytes with the key
   derived from `private_key_seed_hex`.
3. Verify `signature_b64url` against `public_key_b64url`.

The enforcer side is enforced by `enforcer/internal/breachevent/conformance_test.go`.

**The values in the vector are immutable.** Changing the canonicalization or the
schema means minting `breach_event_v2.json` and bumping a scheme version — never
editing v1, because events already signed under v1 must stay verifiable forever.
