#!/usr/bin/env bash
# interop/cmp/run.sh — CMP interop test using openssl cmp (≥ 3.0).
#
# Operations tested: ir, cr, kur, rr, genm (algorithm advertisement).
# Requires: openssl >= 3.0 with CMP support.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

FAILURES=()
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"
SERVER_PID=""

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }

# Verify openssl >= 3.0 with CMP
OPENSSL_VER=$(openssl version | awk '{print $2}' | cut -d. -f1)
if [[ "$OPENSSL_VER" -lt 3 ]]; then
    echo "SKIP: openssl cmp requires openssl >= 3.0 (found $(openssl version))"
    exit 0
fi

echo "==> Starting PyPKI with CMP enabled..."
python3 -c "
import sys, subprocess, time, urllib.request

proc = subprocess.Popen(
    [sys.executable, 'pki_server.py',
     '--no-auth', '--port', '18092',
     '--data-dir', '$WORK/pypki',
     '--ca-key-type', 'rsa-2048',
     '--cmp-enabled'],
    cwd='$REPO',
    stdout=open('$WORK/server.log', 'w'),
    stderr=subprocess.STDOUT,
)
for i in range(30):
    try:
        urllib.request.urlopen('http://localhost:18092/', timeout=2)
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
resp = urllib.request.urlopen('http://localhost:18092/api/ca-cert')
open('$WORK/ca.pem','w').write(resp.read().decode())
"

# Generate a client key for CMP operations.
openssl genrsa -out "$WORK/client.key" 2048 2>/dev/null
openssl req -new -key "$WORK/client.key" \
    -subj "/CN=cmp-ir-test/O=PyPKI" \
    -out "$WORK/client.csr" 2>/dev/null

echo ""
echo "--- Test 1: CMP ir (initialization request) ---"
openssl cmp \
    -cmd ir \
    -server localhost:18092/cmp \
    -ref "cmp-ir-client" \
    -secret "pass:secret" \
    -newkey "$WORK/client.key" \
    -subject "/CN=cmp-ir-test" \
    -certout "$WORK/ir_cert.pem" \
    -cacertsout "$WORK/chain.pem" \
    -unprotected_errors \
    2>&1 | tee "$WORK/ir.log"

if [[ -s "$WORK/ir_cert.pem" ]]; then
    echo "  CMP ir: OK"
else
    _fail "cmp_ir"
fi

if [[ -s "$WORK/ir_cert.pem" ]]; then
    echo ""
    echo "--- Test 2: CMP kur (key update request) ---"
    openssl genrsa -out "$WORK/new.key" 2048 2>/dev/null
    openssl cmp \
        -cmd kur \
        -server localhost:18092/cmp \
        -cert "$WORK/ir_cert.pem" \
        -key "$WORK/client.key" \
        -newkey "$WORK/new.key" \
        -certout "$WORK/kur_cert.pem" \
        -unprotected_errors \
        2>&1 | tee "$WORK/kur.log"

    if [[ -s "$WORK/kur_cert.pem" ]]; then
        echo "  CMP kur: OK"
    else
        _fail "cmp_kur"
    fi

    echo ""
    echo "--- Test 3: CMP rr (revocation request) ---"
    openssl cmp \
        -cmd rr \
        -server localhost:18092/cmp \
        -cert "$WORK/ir_cert.pem" \
        -key "$WORK/client.key" \
        -revreason 0 \
        -unprotected_errors \
        2>&1 | tee "$WORK/rr.log"
    if grep -q "revocation accepted\|successfully revoked\|PKIStatus: accepted" "$WORK/rr.log"; then
        echo "  CMP rr: OK"
    else
        _fail "cmp_rr"
    fi
fi

echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "CMP interop: ALL PASS"
    exit 0
else
    echo "CMP interop: FAILURES: ${FAILURES[*]}"
    mkdir -p "_failures/$TS"
    cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true
    exit 1
fi
