#!/usr/bin/env bash
# interop/pkcs12/run.sh — PKCS#12 import/export round-trip via openssl pkcs12.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"
SERVER_PID=""
FAILURES=()

cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }

python3 -c "
import sys,subprocess,time,urllib.request
p=subprocess.Popen([sys.executable,'pki_server.py','--no-auth','--port','18095','--data-dir','$WORK/pypki','--ca-key-type','rsa-2048'],cwd='$REPO',stdout=open('$WORK/s.log','w'),stderr=subprocess.STDOUT)
open('$WORK/pid','w').write(str(p.pid))
" 2>/dev/null
for i in $(seq 1 30); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18095/',timeout=2)" 2>/dev/null && break
    sleep 1
done
SERVER_PID=$(cat "$WORK/pid" 2>/dev/null || echo "")

# Issue a cert and export as PKCS#12.
python3 - "$WORK" <<'PYEOF'
import sys, json, urllib.request
w = sys.argv[1]
open(f"{w}/ca.pem","wb").write(urllib.request.urlopen("http://localhost:18095/api/ca-cert").read())
r = urllib.request.urlopen(urllib.request.Request(
    "http://localhost:18095/api/issue",
    data=json.dumps({"profile":"tls_client","cn":"pkcs12-test","san":["pkcs12-test.local"]}).encode(),
    headers={"Content-Type":"application/json"}))
res = json.loads(r.read())
open(f"{w}/leaf.pem","w").write(res["cert_pem"])
# Export via API if available, else generate key locally
print("Cert issued:", res.get("subject","?"))
PYEOF

# Generate a local key for PKCS#12 bundle.
openssl genrsa -out "$WORK/client.key" 2048 2>/dev/null

echo "--- Test 1: Export to PKCS#12 ---"
openssl pkcs12 -export \
    -in "$WORK/leaf.pem" \
    -inkey "$WORK/client.key" \
    -certfile "$WORK/ca.pem" \
    -passout pass:test1234 \
    -out "$WORK/bundle.p12" 2>&1 | tee "$WORK/export.log"
[[ -s "$WORK/bundle.p12" ]] && echo "  PKCS#12 export: OK" || _fail "pkcs12_export"

echo "--- Test 2: Import / verify PKCS#12 ---"
openssl pkcs12 -info \
    -in "$WORK/bundle.p12" \
    -passin pass:test1234 \
    -noout 2>&1 | tee "$WORK/import.log"
if grep -q "Certificate bag\|MAC verified\|PKCS7" "$WORK/import.log" 2>/dev/null; then
    echo "  PKCS#12 import: OK"
else
    # Different openssl versions have different output; check exit code.
    openssl pkcs12 -in "$WORK/bundle.p12" -passin pass:test1234 -noout 2>/dev/null \
        && echo "  PKCS#12 import: OK" \
        || _fail "pkcs12_import"
fi

echo "--- Test 3: Round-trip cert extraction ---"
openssl pkcs12 -in "$WORK/bundle.p12" \
    -passin pass:test1234 \
    -nokeys \
    -out "$WORK/extracted.pem" 2>/dev/null
if openssl x509 -in "$WORK/extracted.pem" -noout 2>/dev/null; then
    echo "  PKCS#12 round-trip: OK"
else
    _fail "pkcs12_roundtrip"
fi

[[ ${#FAILURES[@]} -eq 0 ]] && echo "PKCS#12 interop: ALL PASS" && exit 0
echo "PKCS#12 interop: FAILURES: ${FAILURES[*]}"; mkdir -p "_failures/$TS"
cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true; exit 1
