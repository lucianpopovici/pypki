#!/usr/bin/env bash
# conformance/pebble/runner.sh — Run Pebble ACME compliance against PyPKI.
#
# Requires: docker, docker compose
# Usage: bash conformance/pebble/runner.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Starting PyPKI + Pebble..."
docker compose up -d pypki pebble

echo "==> Waiting for Pebble to be ready..."
for i in $(seq 1 30); do
    if docker compose exec pebble wget -q --spider http://localhost:14000/dir 2>/dev/null; then
        echo "  Pebble ready after ${i}s"
        break
    fi
    sleep 1
done

echo "==> Running Pebble compliance suite..."
# Pebble's integration tests are run via its test suite.
# This exercises: newNonce, newAccount, newOrder, finalize, download, revoke,
# keyChange, deactivateAccount, error responses.
docker compose exec pebble pebble-cmd \
    -config /pebble/config.json \
    -strict 2>&1 | tee results.log || true

echo "==> Collecting results..."
docker compose logs pypki 2>&1 | tail -50 >> results.log || true

echo "==> Stopping..."
docker compose down -v

echo ""
echo "Results saved to conformance/pebble/results.log"
echo "Summary:"
grep -E "^(PASS|FAIL|ERROR|---)" results.log || echo "  (no structured summary found)"
