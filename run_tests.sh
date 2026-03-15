#!/usr/bin/env bash
set -euo pipefail

WEB_URL="${WEB_UI_URL:-http://localhost:8090}"
PAM_USER="${WEB_UI_PAM_USER:-}"
PAM_PASS="${WEB_UI_PAM_PASS:-}"

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
echo ""
echo "========================================================"
echo "  Phase 1 — Unit tests (no server needed)"
echo "========================================================"
python3 -m pytest test_pki_server.py -v --tb=short

# ---------------------------------------------------------------------------
# Phase 2 — Web UI tests without auth  (uses pypki.test.json: no_auth=true)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Phase 3 — PAM login tests  (only when credentials are provided)
# ---------------------------------------------------------------------------
if [ -n "$PAM_USER" ] && [ -n "$PAM_PASS" ]; then
    echo ""
    echo "========================================================"
    echo "  Phase 3 — PAM authentication tests (Playwright)"
    echo "========================================================"
    echo "==> Starting PyPKI server (PAM auth enabled)..."

    # Remove any config.json written by Phase 2 PATCH tests so it doesn't
    # contaminate the Phase 3 server with invalid values.
    rm -f ./ca/config.json

    # pypki.auth.json is the same as pypki.test.json but with no_auth=false
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

echo ""
echo "All tests passed."
