# Security Policy

Warden is enforcement software. Bypass reports are first-class contributions.

## Reporting a vulnerability

Report privately via **GitHub Security Advisories**: Security tab → "Report a vulnerability". Do not open a public issue for security bugs — give us time to patch before disclosure.

## In scope

- Escaping or bypassing the session nftables rules from inside a session namespace
- Forging or tampering with breach events or their Ed25519 signatures
- Spool or Rekor attestation integrity (replay, deletion, substitution)
- Any path that lets a session reach a host outside its `targets` credential claim without generating a breach event

## Out of scope

- The documented not-yet-enforced layers: tool (`tools` claim), resource (`resources` claim), and intent (`intent` claim) — these are not implemented and make no enforcement claim
- Prompt-level attacks on the agent itself (Warden does not control the model)
- Vulnerabilities in upstream dependencies (Rekor, nftables, Go stdlib) — report those upstream
