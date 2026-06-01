#!/usr/bin/env bash
set -euo pipefail

WEB_URL="${WEB_UI_URL:-http://localhost:8090}"
PAM_USER="${WEB_UI_PAM_USER:-}"
PAM_PASS="${WEB_UI_PAM_PASS:-}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
RUN_UNIT=1
RUN_WEBUI=1
RUN_FUZZ=0
RUN_INTEROP=0
RUN_CHAOS=0
RUN_CONFORMANCE=0
RUN_BENCH=0
FUZZ_TARGET=""
FUZZ_BUDGET="${PYPKI_FUZZ_BUDGET:-300}"
CONFORMANCE_PKITS=0
CONFORMANCE_RFC5280=0
CONFORMANCE_ALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fuzz)           RUN_FUZZ=1; shift ;;
        --target)         FUZZ_TARGET="$2"; shift 2 ;;
        --budget)         FUZZ_BUDGET="$2"; shift 2 ;;
        --interop)        RUN_INTEROP=1; shift ;;
        --chaos)          RUN_CHAOS=1; shift ;;
        --conformance)    RUN_CONFORMANCE=1; shift ;;
        --pkits)          CONFORMANCE_PKITS=1; shift ;;
        --rfc5280-corners)CONFORMANCE_RFC5280=1; shift ;;
        --all)            CONFORMANCE_ALL=1; shift ;;
        --bench)          RUN_BENCH=1; shift ;;
        --no-unit)        RUN_UNIT=0; shift ;;
        --no-webui)       RUN_WEBUI=0; shift ;;
        *)                echo "Unknown option: $1"; exit 1 ;;
    esac
done

# If any specific phase flags are given, disable the default phases unless
# --no-unit / --no-webui explicitly requested.
if [[ $RUN_FUZZ -eq 1 || $RUN_INTEROP -eq 1 || $RUN_CHAOS -eq 1 || \
      $RUN_CONFORMANCE -eq 1 || $RUN_BENCH -eq 1 ]]; then
    # Only explicit phases run unless unit/webui are explicitly kept.
    # Default: if ANY Tier 6 flag is set, skip the normal phases unless
    # the caller explicitly combined them.
    :  # phases run based on their own flags
fi

# ---------------------------------------------------------------------------
# Helper: wait for the web UI to accept connections
# ---------------------------------------------------------------------------
wait_for_server() {
    python3 - <<'PYEOF'
import sys, time, urllib.request, os
url = os.environ.get("WEB_UI_URL", "http://localhost:8090") + "/"
for i in range(40):
    try:
        urllib.request.urlopen(url, timeout=2)
        print(f"  ready after {i+1}s")
        sys.exit(0)
    except Exception:
        time.sleep(1)
print("ERROR: server did not start within 40s", file=sys.stderr)
sys.exit(1)
PYEOF
}

# ---------------------------------------------------------------------------
# Phase 1 — Unit tests (no server needed)
# ---------------------------------------------------------------------------
if [[ $RUN_UNIT -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Phase 1 — Unit tests (no server needed)"
    echo "========================================================"
    python3 -m pytest test_pki_server.py -v --tb=short
fi

# ---------------------------------------------------------------------------
# Phase 2 — Web UI tests without auth
# ---------------------------------------------------------------------------
if [[ $RUN_WEBUI -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Phase 2 — Web UI tests, no auth (Playwright)"
    echo "========================================================"
    echo "==> Starting PyPKI server (no-auth config)..."
    python3 pypki.py pypki.test.json &
    SERVER_PID=$!

    cleanup() {
        echo "==> Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    }
    trap cleanup EXIT

    echo "==> Waiting for web UI at $WEB_URL ..."
    wait_for_server

    python3 -m pytest test_webui.py -v --tb=short \
        -k "not TestPamLogin"

    trap - EXIT
    cleanup

    # --- Phase 3 — PAM login tests ---
    if [ -n "$PAM_USER" ] && [ -n "$PAM_PASS" ]; then
        echo ""
        echo "========================================================"
        echo "  Phase 3 — PAM authentication tests (Playwright)"
        echo "========================================================"
        rm -f ./ca/config.json
        python3 pypki.py pypki.auth.json &
        SERVER_PID=$!
        trap cleanup EXIT
        echo "==> Waiting for web UI at $WEB_URL ..."
        wait_for_server
        python3 -m pytest test_webui.py -v --tb=short \
            -k "TestPamLogin" \
            --pam-user "$PAM_USER" \
            --pam-pass "$PAM_PASS"
        trap - EXIT
        cleanup
    else
        echo ""
        echo "  Phase 3 — PAM tests SKIPPED (WEB_UI_PAM_USER/WEB_UI_PAM_PASS not set)"
    fi
fi

# ---------------------------------------------------------------------------
# Tier 6.1 — Fuzz
# ---------------------------------------------------------------------------
if [[ $RUN_FUZZ -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Tier 6.1 — Fuzz (budget=${FUZZ_BUDGET}s)"
    echo "========================================================"
    FUZZ_ARGS="--budget $FUZZ_BUDGET"
    [[ -n "$FUZZ_TARGET" ]] && FUZZ_ARGS="$FUZZ_ARGS --target $FUZZ_TARGET"
    PYPKI_FUZZ_BUDGET="$FUZZ_BUDGET" bash fuzz/run_fuzz.sh $FUZZ_ARGS
fi

# ---------------------------------------------------------------------------
# Tier 6.2 — Interop
# ---------------------------------------------------------------------------
if [[ $RUN_INTEROP -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Tier 6.2 — Interop matrix"
    echo "========================================================"
    bash interop/run_all.sh
fi

# ---------------------------------------------------------------------------
# Tier 6.5 — Chaos
# ---------------------------------------------------------------------------
if [[ $RUN_CHAOS -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Tier 6.5 — Chaos & failure injection"
    echo "========================================================"
    if [[ -f chaos/run_chaos.sh ]]; then
        bash chaos/run_chaos.sh
    else
        echo "  Chaos suite not yet implemented (Tier 6.5 pending)."
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Tier 6.6 — Conformance
# ---------------------------------------------------------------------------
if [[ $RUN_CONFORMANCE -eq 1 || $CONFORMANCE_PKITS -eq 1 || \
      $CONFORMANCE_RFC5280 -eq 1 || $CONFORMANCE_ALL -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Tier 6.6 — Conformance batteries"
    echo "========================================================"
    CONF_RC=0

    if [[ $CONFORMANCE_PKITS -eq 1 || $CONFORMANCE_ALL -eq 1 || $RUN_CONFORMANCE -eq 1 ]]; then
        echo "--- NIST PKITS ---"
        python3 conformance/pkits/runner.py || CONF_RC=1
    fi

    if [[ $CONFORMANCE_RFC5280 -eq 1 || $CONFORMANCE_ALL -eq 1 || $RUN_CONFORMANCE -eq 1 ]]; then
        echo "--- RFC 5280 corner cases ---"
        python3 conformance/rfc5280_corners/runner.py || CONF_RC=1
    fi

    if [[ $CONFORMANCE_ALL -eq 1 ]]; then
        echo "--- Pebble ACME compliance ---"
        if [[ -f conformance/pebble/runner.sh ]] && command -v docker &>/dev/null; then
            bash conformance/pebble/runner.sh || CONF_RC=1
        else
            echo "  SKIP: Pebble requires docker"
        fi
    fi

    [[ $CONF_RC -ne 0 ]] && exit 1
fi

# ---------------------------------------------------------------------------
# Tier 6.7 — Performance bench
# ---------------------------------------------------------------------------
if [[ $RUN_BENCH -eq 1 ]]; then
    echo ""
    echo "========================================================"
    echo "  Tier 6.7 — Performance baseline"
    echo "========================================================"
    if [[ -f bench/run_bench.sh ]]; then
        bash bench/run_bench.sh
    else
        echo "  Bench suite not yet implemented (Tier 6.7 pending)."
        exit 0
    fi
fi

echo ""
echo "All requested phases passed."
