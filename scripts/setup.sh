#!/usr/bin/env bash
# Warden prerequisite bootstrap for apt-based Linux.
# Prompts before each install group; use --yes to skip all prompts.
#
# Usage:
#   ./scripts/setup.sh          # interactive
#   ./scripts/setup.sh --yes    # non-interactive (CI / Docker)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── OS guard ──────────────────────────────────────────────────────────────────

if [[ "$(uname -s)" != "Linux" ]] || ! command -v apt-get &>/dev/null; then
    echo "setup.sh targets apt-based Linux. On macOS use the Docker one-liner in demo/README.md."
    exit 0
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

YES=0
for arg in "$@"; do
    [[ "$arg" == "--yes" ]] && YES=1
done

# $1 = group label  $2 = command string shown to user
# Returns 0 if user says yes (or --yes), 1 if declined.
_confirm() {
    local label="$1" cmd="$2"
    if [[ $YES -eq 1 ]]; then return 0; fi
    echo ""
    echo "  Group: $label"
    echo "  Command: $cmd"
    printf "  Install? [y/N] "
    read -r _ans
    [[ "$_ans" =~ ^[Yy]$ ]]
}

_apt() {
    $SUDO apt-get install -y "$@"
}

# Version compare: returns 0 if $1 <= $2 (semver / go-version strings).
_ver_lte() {
    printf '%s\n%s\n' "$1" "$2" | sort -V | head -1 | grep -qx "$1"
}

# ── Status tracking ───────────────────────────────────────────────────────────

G1_STATUS="skipped"
G2_STATUS="skipped"
G3_STATUS="skipped"
G4_STATUS="skipped"

# ── Group 1: kernel tools ─────────────────────────────────────────────────────

if command -v nft &>/dev/null && command -v ip &>/dev/null && command -v ping &>/dev/null; then
    echo "Group 1 (kernel tools): already installed."
    G1_STATUS="already installed"
else
    CMD="${SUDO:+sudo }apt-get install -y nftables iproute2 iputils-ping"
    if _confirm "kernel tools (nftables iproute2 iputils-ping)" "$CMD"; then
        $SUDO apt-get update -q
        _apt nftables iproute2 iputils-ping
        G1_STATUS="installed"
    else
        echo "  Skipped."
        G1_STATUS="declined"
    fi
fi

# ── Group 2: Python ───────────────────────────────────────────────────────────

_py_ok() {
    python3 -c "import sys; exit(0 if sys.version_info >= (3, 12) else 1)" 2>/dev/null
}

_need_python=0
_py_ok || _need_python=1
command -v pip3 &>/dev/null || _need_python=1

_deps_ok() {
    python3 -c "import cryptography, psycopg2, pytest, requests" 2>/dev/null
}

if [[ $_need_python -eq 0 ]] && _deps_ok; then
    echo "Group 2 (Python): already installed."
    G2_STATUS="already installed"
else
    PIP_CMD="pip3 install --break-system-packages -r requirements-test.txt"
    CMD="$PIP_CMD"
    [[ $_need_python -eq 1 ]] && CMD="${SUDO:+sudo }apt-get install -y python3 python3-pip && $CMD"
    if _confirm "Python 3.12+ + test deps" "$CMD"; then
        if [[ $_need_python -eq 1 ]]; then
            $SUDO apt-get update -q
            _apt python3 python3-pip
        fi
        # ponytail: --break-system-packages matches the demo Docker one-liner; switch to a venv if conflicts arise
        pip3 install --break-system-packages -r "$REPO_ROOT/requirements-test.txt"
        G2_STATUS="installed"
    else
        echo "  Skipped."
        G2_STATUS="declined"
    fi
fi

# ── Group 3: Go ───────────────────────────────────────────────────────────────

GO_WANT="1.26.4"
GOARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
GO_TAR="go${GO_WANT}.linux-${GOARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

_go_bin() {
    if command -v go &>/dev/null; then echo "go"; return; fi
    if [[ -x /usr/local/go/bin/go ]]; then echo "/usr/local/go/bin/go"; return; fi
    echo ""
}

_go_version() {
    local bin="$1"
    "$bin" version 2>/dev/null | awk '{print $3}' | sed 's/go//'
}

_GO_BIN="$(_go_bin)"

if [[ -n "$_GO_BIN" ]]; then
    _GOT="$(_go_version "$_GO_BIN")"
    if _ver_lte "$GO_WANT" "$_GOT"; then
        echo "Group 3 (Go): already installed ($_GOT)."
        G3_STATUS="already installed ($_GOT)"
    else
        echo "Group 3 (Go): found $_GOT, need >= $GO_WANT."
        _GO_UPGRADE=1
    fi
else
    _GO_UPGRADE=1
fi

if [[ "${_GO_UPGRADE:-0}" -eq 1 ]]; then
    CMD="rm -rf /usr/local/go && curl -fsSL \"$GO_URL\" | ${SUDO:+sudo }tar -C /usr/local -xz"
    if _confirm "Go $GO_WANT" "$CMD"; then
        # Ensure curl + ca-certificates are present
        if ! command -v curl &>/dev/null; then
            $SUDO apt-get update -q
            _apt curl ca-certificates
        fi
        $SUDO rm -rf /usr/local/go
        curl -fsSL "$GO_URL" | $SUDO tar -C /usr/local -xz
        G3_STATUS="installed $GO_WANT"
        if [[ ":$PATH:" != *":/usr/local/go/bin:"* ]]; then
            echo ""
            echo "  Go installed. Add to PATH for this shell:"
            echo "    export PATH=/usr/local/go/bin:\$PATH"
        fi
    else
        echo "  Skipped."
        G3_STATUS="declined"
    fi
fi

# ── Group 4: Docker (check only) ─────────────────────────────────────────────

if command -v docker &>/dev/null; then
    _DOCKER_VER="$(docker version --format '{{.Client.Version}}' 2>/dev/null || echo unknown)"
    echo "Group 4 (Docker): found version $_DOCKER_VER."
    G4_STATUS="found $_DOCKER_VER"
else
    echo "Group 4 (Docker): not found — needed only for the Rekor stage and stage-4 postgres."
    echo "  Install: https://get.docker.com"
    G4_STATUS="not found (optional)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "========================================"
echo "  Setup summary"
echo "========================================"
echo "  Group 1 (kernel tools) : $G1_STATUS"
echo "  Group 2 (Python)       : $G2_STATUS"
echo "  Group 3 (Go)           : $G3_STATUS"
echo "  Group 4 (Docker)       : $G4_STATUS"
echo ""
echo "  Next: follow demo/README.md"
