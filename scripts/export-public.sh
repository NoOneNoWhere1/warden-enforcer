#!/usr/bin/env bash
# Export a curated public tree from the private warden repo.
# Usage: export-public.sh <target-dir>
#
# The public repo starts from `git init` in the exported tree — never a
# filtered clone. The private git history contains confidential documents.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() { echo "ERROR: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "Usage: $0 <target-dir>"
TARGET="$1"

# Refuse a target that exists and is non-empty.
if [ -e "$TARGET" ] && [ -n "$(ls -A "$TARGET" 2>/dev/null)" ]; then
    die "target '$TARGET' exists and is non-empty; remove it first"
fi

mkdir -p "$TARGET"

echo "Exporting to $TARGET ..."

# ── Copy include-list ────────────────────────────────────────────────────────

# Dirs (full subtree)
cp -rp "$REPO_ROOT/enforcer"    "$TARGET/enforcer"
cp -rp "$REPO_ROOT/demo"        "$TARGET/demo"
mkdir -p "$TARGET/tests"
cp -rp "$REPO_ROOT/tests/phase1" "$TARGET/tests/phase1"
cp -rp "$REPO_ROOT/tests/phase5" "$TARGET/tests/phase5"

# clearing/ — two files only
mkdir -p "$TARGET/clearing"
cp -p "$REPO_ROOT/clearing/__init__.py" "$TARGET/clearing/__init__.py"
cp -p "$REPO_ROOT/clearing/service.py"  "$TARGET/clearing/service.py"

# Root files
cp -p "$REPO_ROOT/tests/conftest.py"       "$TARGET/tests/conftest.py"
cp -p "$REPO_ROOT/pytest.ini"              "$TARGET/pytest.ini"
cp -p "$REPO_ROOT/requirements-test.txt"  "$TARGET/requirements-test.txt"
cp -p "$REPO_ROOT/.gitignore"             "$TARGET/.gitignore"
cp -p "$REPO_ROOT/.dockerignore"          "$TARGET/.dockerignore"
cp -p "$REPO_ROOT/LICENSE"               "$TARGET/LICENSE"
cp -p "$REPO_ROOT/README.md"             "$TARGET/README.md"
cp -p "$REPO_ROOT/CONTRIBUTING.md"       "$TARGET/CONTRIBUTING.md"
cp -p "$REPO_ROOT/SECURITY.md"           "$TARGET/SECURITY.md"

# infra/migrations
mkdir -p "$TARGET/infra/migrations"
cp -p "$REPO_ROOT/infra/migrations/001_initial_schema.sql" "$TARGET/infra/migrations/001_initial_schema.sql"
cp -p "$REPO_ROOT/infra/migrations/002_clearing.sql"       "$TARGET/infra/migrations/002_clearing.sql"

# scripts (preserve execute bits via cp -p)
mkdir -p "$TARGET/scripts"
cp -p "$REPO_ROOT/scripts/install-enforcer.sh"  "$TARGET/scripts/install-enforcer.sh"
cp -p "$REPO_ROOT/scripts/smoke.sh"             "$TARGET/scripts/smoke.sh"
cp -p "$REPO_ROOT/scripts/verify-parity.sh"     "$TARGET/scripts/verify-parity.sh"
cp -p "$REPO_ROOT/scripts/setup.sh"             "$TARGET/scripts/setup.sh"

# docs
mkdir -p "$TARGET/docs"
cp -p "$REPO_ROOT/docs/enforcer-wiki.md"                              "$TARGET/docs/enforcer-wiki.md"
cp -p "$REPO_ROOT/docs/breach-event-canonicalization.md"              "$TARGET/docs/breach-event-canonicalization.md"
cp -p "$REPO_ROOT/docs/slashing-policy.md"                            "$TARGET/docs/slashing-policy.md"
cp -p "$REPO_ROOT/docs/enforcement_first_accountability_architecture.svg" "$TARGET/docs/enforcement_first_accountability_architecture.svg"
cp -p "$REPO_ROOT/docs/kernel_egress_enforcement_packet_path.svg"     "$TARGET/docs/kernel_egress_enforcement_packet_path.svg"
cp -p "$REPO_ROOT/docs/demo.gif"                                     "$TARGET/docs/demo.gif"

# Templates → installed paths
mkdir -p "$TARGET/.github/workflows"
cp -p "$SCRIPT_DIR/export/compose.public.yml"  "$TARGET/infra/compose.yml"
cp -p "$SCRIPT_DIR/export/ci-public.yml"       "$TARGET/.github/workflows/ci.yml"
cp -p "$SCRIPT_DIR/export/env.example.public"  "$TARGET/.env.example"

# ── Clean ────────────────────────────────────────────────────────────────────

rm -rf "$TARGET/enforcer/bin"

# ── Module path rewrite ───────────────────────────────────────────────────────
# perl -pi -e is POSIX-compatible across macOS (BSD) and Linux; sed -i is not.

perl -pi -e 's|github\.com/NoOneNoWhere1/warden/enforcer|github.com/NoOneNoWhere1/warden-enforcer/enforcer|g' \
    "$TARGET/enforcer/go.mod"

# Rewrite all .go files
find "$TARGET/enforcer" -name '*.go' -exec \
    perl -pi -e 's|github\.com/NoOneNoWhere1/warden/enforcer|github.com/NoOneNoWhere1/warden-enforcer/enforcer|g' {} +

# go.sum needs no change: it contains only external deps.

# ── Verification ─────────────────────────────────────────────────────────────

echo "Verifying Go build ..."
(cd "$TARGET/enforcer" && go build ./... && go vet ./...)

echo "Verifying Python syntax ..."
python3 -m py_compile \
    "$TARGET/demo/run_demo.py" \
    "$TARGET/demo/rogue_recon_agent.py" \
    "$TARGET/clearing/service.py" \
    "$TARGET/clearing/__init__.py" \
    "$TARGET/tests/conftest.py"

# Phase test files (glob via find; xargs feeds py_compile)
find "$TARGET/tests/phase1" "$TARGET/tests/phase5" -name '*.py' \
    | xargs python3 -m py_compile

echo "Verifying compose config ..."
if command -v docker >/dev/null 2>&1; then
    POSTGRES_PASSWORD=x docker compose -f "$TARGET/infra/compose.yml" config --quiet
else
    echo "WARN: docker not available — skipping compose config check"
fi

echo "Checking old module path is gone ..."
if grep -r "NoOneNoWhere1/warden/enforcer" "$TARGET" 2>/dev/null; then
    die "old module path still present in target"
fi

echo "Checking private doc references are gone ..."
if grep -rn "Warden_Build_Plan" "$TARGET" 2>/dev/null; then
    die "private doc reference (Warden_Build_Plan) found in target"
fi

# ── Clean bytecode ────────────────────────────────────────────────────────────
# Must run AFTER verification: py_compile above regenerates __pycache__.

# ponytail: -prune stops find from descending into matched dirs; + batches rm calls
find "$TARGET" -name __pycache__ -type d -prune -exec rm -rf {} +
find "$TARGET" \( -name '*.pyc' -o -name '*.pyo' \) -delete

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "DONE: $TARGET"
echo ""
echo "Next steps (publish session):"
echo "  cd $TARGET"
echo "  git init -b main && git add . && git commit -m \"Initial public release\""
echo "  gh repo create NoOneNoWhere1/warden-enforcer --public --source=. --remote=origin --push"
echo ""
echo "IMPORTANT: fresh history only — never filter-branch or clone the private repo;"
echo "its history contains private documents."
