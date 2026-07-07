#!/usr/bin/env bash
# Smoke test for the Go enforcer binary (port plan Amendment 9) — the one DoD
# gate runnable on a dev Mac. Non-Linux builds select the Noop sandbox
# backend, so no root, netns, or nftables is needed. Exercises every API
# status path and the JWK wire order over the real unix socket.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Short base dir: unix socket paths are capped at 104 bytes on macOS.
TMP="$(mktemp -d /tmp/wrdn-smoke.XXXXXX)"
BIN="$TMP/warden-enforcer"
SOCK="$TMP/sock/api.sock"
PID=""

cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

(cd "$REPO_ROOT/enforcer" && go build -o "$BIN" ./cmd/warden-enforcer)

export ENFORCER_KEY_ID="smoke-key"
ENFORCER_SIGNING_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
export ENFORCER_SIGNING_KEY
export ENFORCER_SOCKET="$SOCK"
# E3.3: the attestation spool is always on; default path needs root.
export ENFORCER_OUTBOX="$TMP/outbox.jsonl"

"$BIN" 2>/dev/null &
PID=$!

for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
[ -S "$SOCK" ] || { echo "FAIL: socket never appeared at $SOCK"; exit 1; }

fail=0
check() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "ok:   $1"
    else
        echo "FAIL: $1 — expected $2, got $3"
        fail=1
    fi
}

status() { # method path [body] -> http status code
    if [ $# -eq 3 ]; then
        curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" \
            -X "$1" -H 'Content-Type: application/json' -d "$3" "http://localhost$2"
    else
        curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" \
            -X "$1" "http://localhost$2"
    fi
}

body() { # path -> response body (GET)
    curl -s --unix-socket "$SOCK" "http://localhost$1"
}

VALID='{"session_id":"smoke-1","agent_id":"smoke-agent","targets":["10.99.0.0/24"],"tools":[],"resources":[],"intent":"smoke","ttl_secs":60}'
DUP_BAD_CIDR='{"session_id":"smoke-1","agent_id":"smoke-agent","targets":["not-a-cidr"],"tools":[],"resources":[],"intent":"smoke","ttl_secs":60}'
MISSING_FIELD='{"agent_id":"smoke-agent","targets":[],"intent":"smoke","ttl_secs":60}'
BAD_CIDR='{"session_id":"smoke-2","agent_id":"smoke-agent","targets":["not-a-cidr"],"tools":[],"resources":[],"intent":"smoke","ttl_secs":60}'

check "201 create session"            201 "$(status POST /sessions "$VALID")"
check "409 duplicate session_id"      409 "$(status POST /sessions "$VALID")"
check "409 duplicate + bad CIDR"      409 "$(status POST /sessions "$DUP_BAD_CIDR")"
check "422 missing required field"    422 "$(status POST /sessions "$MISSING_FIELD")"
check "422 bad CIDR"                  422 "$(status POST /sessions "$BAD_CIDR")"

check "200 events for session"        200 "$(status GET /sessions/smoke-1/events)"
check "events body is []"             "[]" "$(body /sessions/smoke-1/events)"
check "404 events unknown session"    404 "$(status GET /sessions/nope/events)"

check "200 active key"                200 "$(status GET /enforcer/keys/active)"
jwk="$(body /enforcer/keys/active)"
if printf '%s' "$jwk" | grep -qE '^\{"crv":"Ed25519","key_id":"[^"]+","kty":"OKP","x":"[^"]+"\}$'; then
    echo "ok:   active JWK wire order (crv, key_id, kty, x)"
else
    echo "FAIL: active JWK wire order — got: $jwk"
    fail=1
fi
check "404 unknown key"               404 "$(status GET /enforcer/keys/unknown-key-id)"

check "204 delete session"            204 "$(status DELETE /sessions/smoke-1)"
check "404 delete unknown session"    404 "$(status DELETE /sessions/smoke-1)"

if [ "$fail" -ne 0 ]; then
    echo "smoke: FAILED"
    exit 1
fi
echo "smoke: all checks passed"
