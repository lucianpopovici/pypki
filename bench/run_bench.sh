#!/usr/bin/env bash
# bench/run_bench.sh — Performance bench orchestrator
# Invoked by: ./run_tests.sh --bench
#
# Each bench writes a result file to bench/results/.
# The suite is informational — exits 0 always unless a bench script crashes.

set -euo pipefail

_BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
N="${PYPKI_BENCH_N:-200}"
OCSP_N="${PYPKI_BENCH_OCSP_N:-500}"
CERTS="${PYPKI_BENCH_CERTS:-100}"
MAX_REVOKED="${PYPKI_BENCH_MAX_REVOKED:-100000}"
STORAGE_N="${PYPKI_BENCH_STORAGE_N:-1000}"

echo "╔══════════════════════════════════════════════╗"
echo "║        Tier 6.7 — Performance Bench          ║"
echo "╚══════════════════════════════════════════════╝"
echo "N=${N}, OCSP_N=${OCSP_N}, MAX_REVOKED=${MAX_REVOKED}"
echo ""

echo "--- Issuance throughput ---"
"$PYTHON" "$_BENCH_DIR/issuance.py" --n "$N" || echo "[warn] issuance bench failed"

echo ""
echo "--- OCSP throughput ---"
"$PYTHON" "$_BENCH_DIR/ocsp.py" --n "$OCSP_N" --certs "$CERTS" || echo "[warn] ocsp bench failed"

echo ""
echo "--- CRL generation time ---"
"$PYTHON" "$_BENCH_DIR/crl_gen.py" --max-revoked "$MAX_REVOKED" || echo "[warn] crl_gen bench failed"

echo ""
echo "--- Storage growth ---"
"$PYTHON" "$_BENCH_DIR/storage.py" --n "$STORAGE_N" || echo "[warn] storage bench failed"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Bench complete. Results in bench/results/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exit 0
