#!/usr/bin/env bash
# run_fuzz.sh — Entry point for the PyPKI fuzz suite.
#
# Uses Atheris (libFuzzer-backed) when available; falls back to the
# stdlib random-walk runner (_stdlib_runner.py) with zero new deps.
#
# Usage:
#   ./fuzz/run_fuzz.sh                          # all targets, 300s each
#   ./fuzz/run_fuzz.sh --target tlv             # single target
#   ./fuzz/run_fuzz.sh --budget 3600            # 1-hour nightly budget
#   ./fuzz/run_fuzz.sh --target cmp_pkimessage --budget 3600
#
# Environment:
#   PYPKI_FUZZ_BUDGET   override default budget per target (seconds)
#   PYPKI_FUZZ_SEED     RNG seed for reproducibility (stdlib runner only)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

cd "$REPO_DIR"

BUDGET="${PYPKI_FUZZ_BUDGET:-300}"
SEED="${PYPKI_FUZZ_SEED:-}"
TARGET=""
VERBOSE=0

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)  TARGET="$2";   shift 2 ;;
        --budget)  BUDGET="$2";   shift 2 ;;
        --seed)    SEED="$2";     shift 2 ;;
        --verbose) VERBOSE=1;     shift   ;;
        *)         echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Seed corpus (idempotent — skips existing files)
# ---------------------------------------------------------------------------
echo "==> Ensuring seed corpus is populated..."
python3 fuzz/setup_corpus.py

# ---------------------------------------------------------------------------
# Detect Atheris
# ---------------------------------------------------------------------------
HAS_ATHERIS=0
if python3 -c "import atheris" 2>/dev/null; then
    HAS_ATHERIS=1
    echo "==> Atheris detected — using libFuzzer backend"
else
    echo "==> Atheris not found — using stdlib random-walk backend"
    echo "    (Install atheris for coverage-guided fuzzing: pip install atheris)"
fi

# ---------------------------------------------------------------------------
# Target list
# ---------------------------------------------------------------------------
ALL_TARGETS=(
    tlv
    scep_envelope
    cmp_pkimessage
    crmf_popo
    est_csr
    mldsa_roundtrip
    ocsp_request
    tsa_request
)

if [[ -n "$TARGET" ]]; then
    TARGETS=("$TARGET")
else
    TARGETS=("${ALL_TARGETS[@]}")
fi

# ---------------------------------------------------------------------------
# Run each target
# ---------------------------------------------------------------------------
FAILURES=()

for t in "${TARGETS[@]}"; do
    echo ""
    echo "========================================================"
    echo "  Fuzzing: $t  (budget=${BUDGET}s)"
    echo "========================================================"

    HARNESS="fuzz/harness_${t}.py"
    CORPUS="fuzz/corpus/${t}"

    if [[ ! -f "$HARNESS" ]]; then
        echo "ERROR: harness not found: $HARNESS"
        FAILURES+=("$t: harness missing")
        continue
    fi

    if [[ $HAS_ATHERIS -eq 1 ]]; then
        # Atheris invocation: harness runs its own main when __name__ == "__main__"
        # We pass -max_total_time to libFuzzer.
        set +e
        python3 "$HARNESS" \
            "$CORPUS" \
            -max_total_time="$BUDGET" \
            -print_final_stats=1 \
            -artifact_prefix="fuzz/corpus/regressions/${t}_" 2>&1
        RC=$?
        set -e
    else
        # Stdlib runner
        SEED_ARG=""
        [[ -n "$SEED" ]] && SEED_ARG="--seed $SEED"
        VERBOSE_ARG=""
        [[ $VERBOSE -eq 1 ]] && VERBOSE_ARG="--verbose"
        set +e
        python3 fuzz/_stdlib_runner.py "harness_${t}" \
            --budget "$BUDGET" \
            $SEED_ARG \
            $VERBOSE_ARG 2>&1
        RC=$?
        set -e
    fi

    if [[ $RC -ne 0 ]]; then
        FAILURES+=("$t (exit $RC)")
        echo "  FAIL: $t exited with $RC"
    else
        echo "  OK: $t clean"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "  All fuzz targets CLEAN"
    exit 0
else
    echo "  FAILURES:"
    for f in "${FAILURES[@]}"; do
        echo "    - $f"
    done
    echo ""
    echo "  Crash inputs saved to fuzz/corpus/regressions/"
    exit 1
fi
