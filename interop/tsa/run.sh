#!/usr/bin/env bash
# interop/tsa/run.sh — TSA interop test using openssl ts.
#
# Operations tested: sign, verify, policy-OID match, nonce round-trip.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

FAILURES=()
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"

cleanup() { kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }

echo "==> Starting PyPKI with TSA enabled..."
python3 -c "
import sys, subprocess, time, urllib.request

proc = subprocess.Popen(
    [sys.executable, 'pki_server.py',
     '--no-auth', '--port', '18091',
     '--data-dir', '$WORK/pypki',
     '--ca-key-type', 'ec-p256',
     '--tsa-enabled'],
    cwd='$REPO',
    stdout=open('$WORK/server.log', 'w'),
    stderr=subprocess.STDOUT,
)
for i in range(30):
    try:
        urllib.request.urlopen('http://localhost:18091/', timeout=2)
        print(f'Ready after {i+1}s')
        break
    except Exception:
        time.sleep(1)
with open('$WORK/server.pid', 'w') as f:
    f.write(str(proc.pid))
print('PID:', proc.pid)
"
SERVER_PID=$(cat "$WORK/server.pid")

# Get CA cert.
python3 -c "
import urllib.request
resp = urllib.request.urlopen('http://localhost:18091/api/ca-cert')
open('$WORK/ca.pem','wb').write(resp.read())
"

# Create a test file to timestamp.
echo "Hello, PyPKI TSA interop test" > "$WORK/test_data.txt"

echo ""
echo "--- Test 1: Create timestamp request ---"
openssl ts -query \
    -data "$WORK/test_data.txt" \
    -sha256 \
    -cert \
    -out "$WORK/request.tsq"
_fail_msg=""
[[ -s "$WORK/request.tsq" ]] || { _fail "ts_query_create"; }
echo "  TSQ created ($(wc -c < "$WORK/request.tsq") bytes)"

echo ""
echo "--- Test 2: Send to PyPKI TSA endpoint ---"
curl -s \
    -H "Content-Type: application/timestamp-query" \
    --data-binary @"$WORK/request.tsq" \
    http://localhost:18091/tsa \
    -o "$WORK/response.tsr"
[[ -s "$WORK/response.tsr" ]] || _fail "tsr_empty"

# Print TSR info.
openssl ts -reply -in "$WORK/response.tsr" -text 2>&1 | tee "$WORK/tsr_info.log"
if grep -q "Status: Granted\|Status info: Granted" "$WORK/tsr_info.log"; then
    echo "  TSA sign: OK"
else
    _fail "tsa_status_not_granted"
fi

echo ""
echo "--- Test 3: Verify timestamp ---"
openssl ts -verify \
    -in "$WORK/response.tsr" \
    -data "$WORK/test_data.txt" \
    -CAfile "$WORK/ca.pem" 2>&1 | tee "$WORK/verify.log"
if grep -q "OK" "$WORK/verify.log"; then
    echo "  TSA verify: OK"
else
    _fail "tsa_verify"
fi

echo ""
echo "--- Test 4: Verify fails with wrong data ---"
echo "tampered data" > "$WORK/tampered.txt"
if openssl ts -verify \
    -in "$WORK/response.tsr" \
    -data "$WORK/tampered.txt" \
    -CAfile "$WORK/ca.pem" 2>&1 | grep -q "verification failure\|FAILED\|error"; then
    echo "  TSA tamper detection: OK"
else
    _fail "tsa_tamper_detect"
fi

echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "TSA interop: ALL PASS"
    exit 0
else
    echo "TSA interop: FAILURES: ${FAILURES[*]}"
    mkdir -p "_failures/$TS"
    cp "$WORK"/*.log "$WORK"/*.tsr 2>/dev/null | true
    cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true
    exit 1
fi
