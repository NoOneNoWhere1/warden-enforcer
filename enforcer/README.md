# warden-enforcer

Host-side daemon that provides network-layer containment for Warden agent sessions. Runs as a systemd service (not a Docker container). Installed via `scripts/install-enforcer.sh`.

---

## API Transport and Authentication

**Decision: Unix domain socket (E2 gate requirement)**

The enforcer API is bound to a Unix domain socket at:

```
/run/warden-enforcer/api.sock
```

File permissions (`0660`, owned by `warden:warden`) enforce caller identity at the OS level. Only processes running as the `warden` user or group can reach the socket. Compose application services that need to call the enforcer must mount the socket path via a bind mount in `infra/compose.yml`.

This means an unauthenticated TCP connection cannot exist — there is no TCP listener. An unauthorized caller receives a connection refusal at the filesystem level, not an HTTP 401. This is the E2 gate requirement.

**Why Unix socket over mTLS:**
- No TLS setup, no certificate lifecycle
- OS enforces identity — no application-layer auth code required
- A single `chmod`/`chown` on the socket file sets the policy
- Simpler to test: an unauthorized caller gets `EACCES` or `ENOENT`, not a TLS handshake failure to implement and verify

**mTLS upgrade trigger:** when the enforcer needs to be called from a host where shared filesystem access is not available (e.g., a separate physical machine). At that point, add a mTLS listener in parallel; do not remove the Unix socket.

---

## API Endpoints

Internal-only. Not exposed outside the host.

```
POST   /sessions               # create session, program nftables rules
DELETE /sessions/{id}          # tear down session and rules
GET    /sessions/{id}/events   # signed breach events for this session
GET    /enforcer/keys/active   # active public key (JWK)
GET    /enforcer/keys/{key_id} # key lookup — active or retired
```

All endpoints are tested via `net/http/httptest` at the handler layer without a real socket or network. The router is Go's standard `net/http` ServeMux (Go 1.22+ method patterns) — no web framework.

The E2 gate test (unauthorized caller rejected) is a `linux_only` pytest in `tests/phase1/test_api_auth.py` and runs in CI only.

---

## Key Lifecycle

The enforcer's Ed25519 signing key is managed explicitly:

- **First start:** generate a keypair, insert a row in `signing_key` table, persist the 32-byte private key scalar to the operator secret store (`ENFORCER_SIGNING_KEY` env var or mounted secret file).
- **Restart:** load the key from the secret store by `key_id`. Do not generate a new key.
- **Rotation:** operator-triggered. New keypair generated, old key retired (`retired_at` set in DB). Old key is never deleted — breach events signed under it remain verifiable indefinitely via `GET /enforcer/keys/{key_id}`.

---

## Running Locally (Linux only)

```bash
# Build
go build -o bin/warden-enforcer ./cmd/warden-enforcer

# Install as systemd service (requires root)
sudo bash scripts/install-enforcer.sh

# Verify socket exists after start
ls -la /run/warden-enforcer/api.sock
```

## Running Tests

```bash
# Unit tests (any platform)
go test -race ./...

# Gate tests (Linux, requires root and nftables)
sudo -E python -m pytest tests/phase1/ -v -m linux_only
```
