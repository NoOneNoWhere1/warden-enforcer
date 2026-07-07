# Contributing to Warden

## Dev setup

**Linux (recommended):**

```bash
./scripts/setup.sh          # installs Go, Python deps, kernel tools (prompts before each group)
```

**Enforcer (Go):**

```bash
cd enforcer && go test ./...
```

**Gate tests** (enforcement assertions — require Linux + root + nftables):

```bash
sudo -E python3 -m pytest tests/phase1/
```

The authoritative gate is the `linux-gate` job in `.github/workflows/ci.yml`; that is what CI runs and what PRs must pass.

## PR expectations

- CI green before merge. The `linux-gate` job is the hard gate.
- Do not remove `// PARITY:` markers in the enforcer source — CI guards them via `scripts/verify-parity.sh`. If you touch a parity-marked function, update `enforcer/PARITY_LEDGER.md` accordingly.

## Where help is wanted

The three unimplemented enforcement layers are the main open surface:

- **Tool layer** (Phase 3) — MCP server enforcement of the `tools` credential claim
- **Resource layer** (Phase 2) — retrieval API enforcement of the `resources` claim
- **Intent layer** (Phase 4) — orchestrator enforcement of the `intent` claim

See `README.md §Future vision` and `docs/enforcer-wiki.md §1` for the layer table and the shared breach-event contract each layer must satisfy. The network layer (`enforcer/`) is the reference implementation.
