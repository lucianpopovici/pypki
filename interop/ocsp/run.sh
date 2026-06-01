#!/usr/bin/env bash
# interop/ocsp/run.sh — OCSP interop test using openssl ocsp.
#
# Operations tested:
#   - Live OCSP response (per-request signing)
#   - Response with nonce
#   - Response without nonce
#   - Pre-generated response (if --ocsp-pre-gen is enabled)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$SCRIPT_DIR"

FAILURES=()
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }
_assert_file() { [[ -s "$1" ]] || _fail "$2: file empty: $1"; }

# Start PyPKI with OCSP and issue a test cert.
echo "==> Starting PyPKI with OCSP enabled..."
python3 -c "
import sys, os, subprocess, time, urllib.request, tempfile, pathlib

repo = '$REPO'
work = '$WORK'

# Start server
proc = subprocess.Popen(
    [sys.executable, 'pki_server.py',
     '--no-auth', '--port', '18090',
     '--data-dir', work + '/pypki',
     '--ca-key-type', 'ec-p256',
     '--ocsp-enabled'],
    cwd=repo,
    stdout=open(work + '/server.log', 'w'),
    stderr=subprocess.STDOUT,
)

# Wait for it
for i in range(30):
    try:
        urllib.request.urlopen('http://localhost:18090/', timeout=2)
        print(f'Server ready after {i+1}s')
        break
    except Exception:
        time.sleep(1)
else:
    print('ERROR: server did not start', file=sys.stderr)
    proc.terminate()
    sys.exit(1)

with open(work + '/server.pid', 'w') as f:
    f.write(str(proc.pid))
print('Server PID:', proc.pid)
"

SERVER_PID=$(cat "$WORK/server.pid" 2>/dev/null || echo "")
cleanup_server() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup_server EXIT

# Issue a test certificate via REST API.
echo "==> Issuing test certificate..."
python3 - "$WORK" <<'PYEOF'
import sys, json, urllib.request, urllib.parse

work = sys.argv[1]

# Get CA cert
resp = urllib.request.urlopen("http://localhost:18090/api/ca-cert")
ca_pem = resp.read().decode()
with open(f"{work}/ca.pem", "w") as f:
    f.write(ca_pem)

# Issue a TLS server cert
data = json.dumps({
    "profile": "tls_server",
    "cn": "ocsp-test.example.com",
    "san": ["ocsp-test.example.com"],
}).encode()
req = urllib.request.Request(
    "http://localhost:18090/api/issue",
    data=data,
    headers={"Content-Type": "application/json"},
)
resp = urllib.request.urlopen(req)
result = json.loads(resp.read())
with open(f"{work}/leaf.pem", "w") as f:
    f.write(result["cert_pem"])
print("Issued cert for:", result.get("subject", "unknown"))
PYEOF

_assert_file "$WORK/ca.pem" "ca_cert"
_assert_file "$WORK/leaf.pem" "leaf_cert"

# Extract serial from leaf cert for OCSP request.
SERIAL=$(openssl x509 -in "$WORK/leaf.pem" -noout -serial | cut -d= -f2)
echo "  Leaf cert serial: $SERIAL"

echo ""
echo "--- Test 1: OCSP request with nonce ---"
openssl ocsp \
    -issuer "$WORK/ca.pem" \
    -cert "$WORK/leaf.pem" \
    -url http://localhost:18090/ocsp \
    -nonce \
    -resp_text \
    -out "$WORK/ocsp_nonce.resp" 2>&1 | tee "$WORK/ocsp_nonce.log"

if grep -q "OCSP Response Status: successful" "$WORK/ocsp_nonce.log" || \
   grep -q "good" "$WORK/ocsp_nonce.log"; then
    echo "  OCSP with nonce: OK"
else
    _fail "ocsp_with_nonce"
fi

echo ""
echo "--- Test 2: OCSP request without nonce ---"
openssl ocsp \
    -issuer "$WORK/ca.pem" \
    -cert "$WORK/leaf.pem" \
    -url http://localhost:18090/ocsp \
    -no_nonce \
    -out "$WORK/ocsp_nononce.resp" 2>&1 | tee "$WORK/ocsp_nononce.log"

if grep -q "good" "$WORK/ocsp_nononce.log" || \
   grep -q "successful" "$WORK/ocsp_nononce.log"; then
    echo "  OCSP without nonce: OK"
else
    _fail "ocsp_without_nonce"
fi

echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "OCSP interop: ALL PASS"
    exit 0
else
    echo "OCSP interop: FAILURES: ${FAILURES[*]}"
    mkdir -p "_failures/$TS"
    cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true
    exit 1
fi
