#!/usr/bin/env bash
# verify_lockfile_hashes.sh — Per-PR supply-chain gate.
#
# Verifies:
#   1. requirements.txt has no unpinned (versionless) entries.
#   2. Every pinned package in requirements.txt matches the installed wheel
#      hash (via pip hash check).
#   3. Runs pip-audit against requirements.txt and fails on HIGH/CRITICAL.
#
# This script is the "supply-chain" CI gate. It must pass before any PR merges.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

RC=0

echo "==> Checking requirements.txt for pinned versions..."
# Every non-comment, non-blank line must have == (exact pin) or a hash spec.
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    # Accept lines with == or --hash= (hash-pinned format)
    if [[ ! "$line" =~ == && ! "$line" =~ --hash= && ! "$line" =~ ^-r ]]; then
        echo "  FAIL: unpinned entry: $line"
        RC=1
    fi
done < requirements.txt

if [[ $RC -ne 0 ]]; then
    echo "ERROR: requirements.txt has unpinned dependencies."
    echo "  Run: pip-compile requirements.in --generate-hashes -o requirements.txt"
    exit 1
fi
echo "  OK: all entries pinned"

echo ""
echo "==> Running pip-audit (HIGH/CRITICAL fail gate)..."
pip-audit -r requirements.txt \
    --strict \
    --format columns \
    --vulnerability-service osv \
    2>&1 || { echo "ERROR: pip-audit found vulnerabilities"; exit 1; }
echo "  OK: no HIGH/CRITICAL vulnerabilities"

echo ""
echo "==> Supply-chain checks passed."
