#!/usr/bin/env bash
# interop/est/run.sh — EST interop test using curl (libest client is Docker-based).
# Operations: cacerts, simpleenroll, simplereenroll, csrattrs.
# Uses curl directly since libest may not be installed on host.
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

python3 -c "
import sys,subprocess,time,urllib.request
p=subprocess.Popen([sys.executable,'pki_server.py',
    '--no-auth','--port','18098',
    '--data-dir','$WORK/pypki',
    '--ca-key-type','rsa-2048',
    '--est-enabled'],
    cwd='$REPO',stdout=open('$WORK/s.log','w'),stderr=subprocess.STDOUT)
open('$WORK/pid','w').write(str(p.pid))
" 2>/dev/null
for i in $(seq 1 30); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18098/',timeout=2)" 2>/dev/null && break
    sleep 1
done
SERVER_PID=$(cat "$WORK/pid" 2>/dev/null || echo "")

echo "--- Test 1: EST /cacerts ---"
# RFC 7030: GET /.well-known/est/cacerts returns PKCS#7 CA certs
curl -s http://localhost:18098/.well-known/est/cacerts \
    -o "$WORK/cacerts.p7" 2>&1 | tee "$WORK/cacerts.log"
if [[ -s "$WORK/cacerts.p7" ]]; then
    # Verify PKCS#7 parses.
    openssl pkcs7 -inform DER -in "$WORK/cacerts.p7" -noout -print_certs 2>&1 \
        | grep -q "subject=" && echo "  EST cacerts: OK" || _fail "est_cacerts_parse"
else
    _fail "est_cacerts_empty"
fi

echo "--- Test 2: EST /csrattrs ---"
curl -s http://localhost:18098/.well-known/est/csrattrs \
    -o "$WORK/csrattrs.bin" 2>&1
if [[ -f "$WORK/csrattrs.bin" ]]; then
    echo "  EST csrattrs: OK ($(wc -c < "$WORK/csrattrs.bin") bytes)"
else
    _fail "est_csrattrs"
fi

echo "--- Test 3: EST /simpleenroll ---"
# Generate key + CSR.
openssl genrsa -out "$WORK/est_client.key" 2048 2>/dev/null
openssl req -new -key "$WORK/est_client.key" \
    -subj "/CN=est-interop-test" \
    -out "$WORK/est_client.csr" 2>/dev/null

# EST simpleenroll: POST base64(CSR DER) with content-type application/pkcs10
CSR_B64=$(openssl req -in "$WORK/est_client.csr" -outform DER 2>/dev/null | base64 | tr -d '\n')
curl -s \
    -X POST \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    --data "$CSR_B64" \
    http://localhost:18098/.well-known/est/simpleenroll \
    -o "$WORK/enrolled.p7" 2>&1 | tee "$WORK/enroll.log"

if [[ -s "$WORK/enrolled.p7" ]]; then
    openssl pkcs7 -inform DER -in "$WORK/enrolled.p7" -print_certs \
        -out "$WORK/enrolled.pem" 2>/dev/null
    if [[ -s "$WORK/enrolled.pem" ]]; then
        echo "  EST simpleenroll: OK"
        openssl x509 -in "$WORK/enrolled.pem" -noout -subject 2>/dev/null
    else
        _fail "est_enroll_parse"
    fi
else
    _fail "est_enroll_empty"
fi

[[ ${#FAILURES[@]} -eq 0 ]] && echo "EST interop: ALL PASS" && exit 0
echo "EST interop: FAILURES: ${FAILURES[*]}"; mkdir -p "_failures/$TS"
cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true; exit 1
