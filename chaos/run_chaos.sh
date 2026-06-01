#!/usr/bin/env bash
# chaos/run_chaos.sh — Chaos suite orchestrator
# Invoked by: ./run_tests.sh --chaos
#
# Each scenario exits 0 on PASS (or SKIP) and 1 on FAIL.
# The suite fails if any scenario fails (not just skips).

set -euo pipefail

_CHAOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(dirname "$_CHAOS_DIR")"
PYTHON="${PYTHON:-python3}"

PASS=0
FAIL=0
SKIP=0

run_scenario() {
    local script="$1"
    local name
    name="$(basename "$script" .py)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if "$PYTHON" "$script"; then
        PASS=$((PASS + 1))
    else
        local rc=$?
        if [[ $rc -eq 2 ]]; then
            SKIP=$((SKIP + 1))
        else
            FAIL=$((FAIL + 1))
            echo "  [FAIL] $name"
        fi
    fi
}

echo "╔══════════════════════════════════════════════╗"
echo "║        Tier 6.5 — Chaos Suite                ║"
echo "╚══════════════════════════════════════════════╝"
echo "PYPKI_CHAOS_ITERATIONS=${PYPKI_CHAOS_ITERATIONS:-100}"
echo ""

# Run scenarios in order. Infrastructure-dependent ones skip cleanly when
# their required env vars are absent.
run_scenario "$_CHAOS_DIR/F01_kill_mid_sign.py"
run_scenario "$_CHAOS_DIR/F02_kill_pre_response.py"
run_scenario "$_CHAOS_DIR/F03_db_kill_mid_tx.py"
run_scenario "$_CHAOS_DIR/F04_hsm_disconnect.py"
run_scenario "$_CHAOS_DIR/F05_crl_disk_full.py"
run_scenario "$_CHAOS_DIR/F06_audit_disk_full.py"
run_scenario "$_CHAOS_DIR/F07_webhook_hang.py"
run_scenario "$_CHAOS_DIR/F08_webhook_500.py"
run_scenario "$_CHAOS_DIR/F09_pg_failover.py"
run_scenario "$_CHAOS_DIR/F10_replica_lag.py"
run_scenario "$_CHAOS_DIR/F11_ocsp_partition.py"
run_scenario "$_CHAOS_DIR/F12_clock_forward.py"
run_scenario "$_CHAOS_DIR/F13_clock_backward.py"
run_scenario "$_CHAOS_DIR/F14_concurrent_issue.py"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Chaos suite: $PASS passed, $FAIL failed, $SKIP skipped"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
    echo "CHAOS SUITE FAILED"
    exit 1
fi
echo "CHAOS SUITE PASSED"
exit 0
