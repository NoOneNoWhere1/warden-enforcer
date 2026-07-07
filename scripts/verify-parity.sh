#!/usr/bin/env bash
# Verify test IDENTITY between the Rust enforcer and the Go port.
#
# Reads enforcer/PARITY_LEDGER.md: every Rust test row must map to a Go
# test function that actually exists in enforcer/. Fails on any unmapped
# row or any mapped Go test that cannot be found. This replaces ">=N tests
# pass" as the binding parity check — counts are gameable, identity is not.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LEDGER="$REPO_ROOT/enforcer/PARITY_LEDGER.md"
GO_DIR="$REPO_ROOT/enforcer"

[ -f "$LEDGER" ] || { echo "FAIL: ledger not found at $LEDGER"; exit 1; }

unmapped=0
missing=0
mapped=0

while IFS='|' read -r _ rust go _rest; do
    rust="$(echo "$rust" | xargs)"
    go="$(echo "$go" | xargs)"
    case "$rust" in
        *::*) ;;      # data rows only
        *) continue ;;
    esac
    if [ -z "$go" ]; then
        echo "PENDING: $rust (no Go test mapped)"
        unmapped=$((unmapped + 1))
    elif grep -rq "func $go(" "$GO_DIR" --include="*_test.go"; then
        mapped=$((mapped + 1))
    else
        echo "MISSING: $rust -> $go (mapped Go test not found in enforcer/)"
        missing=$((missing + 1))
    fi
done < "$LEDGER"

total=$((unmapped + missing + mapped))
echo ""
echo "parity: $mapped/$total mapped and present, $unmapped pending, $missing missing"

if [ "$unmapped" -gt 0 ] || [ "$missing" -gt 0 ]; then
    exit 1
fi
echo "OK: full parity — every Rust test has an existing Go counterpart"
