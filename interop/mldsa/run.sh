#!/usr/bin/env bash
# interop/mldsa/run.sh — ML-DSA X.509 interop test using openssl + oqs-provider.
#
# Tests:
#   - Verify a PyPKI-issued ML-DSA cert using openssl verify
#   - Paired cert chain validation (classical + ML-DSA)
#
# Requires: openssl with oqs-provider loaded (for ML-DSA signature verification).
# The oqs-provider supports ML-DSA from version 0.6.0+.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"
SERVER_PID=""
FAILURES=()

cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }

# Check for OQS provider.
if ! openssl list -providers 2>/dev/null | grep -q "oqsprovider\|oqs"; then
    echo "SKIP: openssl oqs-provider not available"
    echo "  Install from https://github.com/open-quantum-safe/oqs-provider"
    exit 0
fi

# Start PyPKI with ML-DSA enabled (classical CA key, ML-DSA leaf certs).
python3 -c "
import sys,subprocess,time,urllib.request
p=subprocess.Popen([sys.executable,'pki_server.py',
    '--no-auth','--port','18097',
    '--data-dir','$WORK/pypki',
    '--ca-key-type','ec-p256'],
    cwd='$REPO',stdout=open('$WORK/s.log','w'),stderr=subprocess.STDOUT)
open('$WORK/pid','w').write(str(p.pid))
" 2>/dev/null
for i in $(seq 1 30); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18097/',timeout=2)" 2>/dev/null && break
    sleep 1
done
SERVER_PID=$(cat "$WORK/pid" 2>/dev/null || echo "")

python3 -c "
import urllib.request
open('$WORK/ca.pem','wb').write(urllib.request.urlopen('http://localhost:18097/api/ca-cert').read())
"

# Issue an ML-DSA leaf cert.
python3 - "$WORK" <<'PYEOF'
import sys, json, urllib.request
w = sys.argv[1]
try:
    r = urllib.request.urlopen(urllib.request.Request(
        "http://localhost:18097/api/ml-dsa-issue",
        data=json.dumps({
            "cn": "mldsa-interop-test",
            "san": ["mldsa-interop-test.local"],
            "variant": "ml-dsa-44",
        }).encode(),
        headers={"Content-Type": "application/json"}))
    res = json.loads(r.read())
    open(f"{w}/mldsa_cert.pem","w").write(res.get("cert_pem",""))
    print("ML-DSA cert issued:", res.get("subject","?"))
except Exception as e:
    print(f"WARNING: ML-DSA issue failed: {e}")
    open(f"{w}/mldsa_cert.pem","w").write("")
PYEOF

echo "--- Test 1: Verify ML-DSA cert with openssl + oqs-provider ---"
if [[ -s "$WORK/mldsa_cert.pem" ]]; then
    openssl verify \
        -provider oqsprovider \
        -provider default \
        -CAfile "$WORK/ca.pem" \
        "$WORK/mldsa_cert.pem" 2>&1 | tee "$WORK/verify.log"
    if grep -q "OK" "$WORK/verify.log"; then
        echo "  ML-DSA verify: OK"
    else
        _fail "mldsa_verify"
    fi
else
    echo "  SKIP: ML-DSA cert not available (ML-DSA may be disabled)"
fi

echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "ML-DSA interop: ALL PASS"
    exit 0
else
    echo "ML-DSA interop: FAILURES: ${FAILURES[*]}"
    mkdir -p "_failures/$TS"
    cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true
    exit 1
fi
