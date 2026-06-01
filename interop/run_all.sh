#!/usr/bin/env bash
# interop/run_all.sh — Run the full interop matrix.
#
# Usage:
#   ./interop/run_all.sh                        # required protocols only
#   ./interop/run_all.sh --include-best-effort  # + best-effort protocols
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BEST_EFFORT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --include-best-effort) BEST_EFFORT=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

REQUIRED=(scep acme/certbot acme/acme-sh acme/lego est cmp ocsp tsa crl smime mldsa pkcs12)
BEST_EFFORT_PROTOS=()

PASS=()
FAIL=()
SKIP=()

run_proto() {
    local proto="$1"
    local run_sh="$SCRIPT_DIR/$proto/run.sh"

    if [[ ! -f "$run_sh" ]]; then
        echo "  SKIP: $proto (no run.sh)"
        SKIP+=("$proto")
        return
    fi

    echo ""
    echo "========================================================"
    echo "  Interop: $proto"
    echo "========================================================"
    set +e
    bash "$run_sh" 2>&1
    RC=$?
    set -e

    if [[ $RC -eq 0 ]]; then
        PASS+=("$proto")
        echo "  OK: $proto"
    else
        FAIL+=("$proto")
        echo "  FAIL: $proto (exit $RC)"
    fi
}

for proto in "${REQUIRED[@]}"; do
    run_proto "$proto"
done

if [[ $BEST_EFFORT -eq 1 ]]; then
    for proto in "${BEST_EFFORT_PROTOS[@]}"; do
        run_proto "$proto"
    done
fi

echo ""
echo "========================================================"
echo "  Interop summary"
echo "========================================================"
echo "  PASS (${#PASS[@]}): ${PASS[*]:-none}"
echo "  FAIL (${#FAIL[@]}): ${FAIL[*]:-none}"
echo "  SKIP (${#SKIP[@]}): ${SKIP[*]:-none}"

if [[ ${#FAIL[@]} -gt 0 ]]; then
    exit 1
fi
