#!/usr/bin/env bash
# interop/smime/run.sh — S/MIME interop test using openssl cms.
# Operations: sign, verify, encrypt, sign-then-encrypt.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"
SERVER_PID=""
FAILURES=()

cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }

# Start PyPKI with S/MIME enabled.
python3 -c "
import sys,subprocess,time,urllib.request
p=subprocess.Popen([sys.executable,'pki_server.py','--no-auth','--port','18094','--data-dir','$WORK/pypki','--ca-key-type','rsa-2048'],cwd='$REPO',stdout=open('$WORK/s.log','w'),stderr=subprocess.STDOUT)
open('$WORK/pid','w').write(str(p.pid))
" 2>/dev/null
for i in $(seq 1 30); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18094/',timeout=2)" 2>/dev/null && break
    sleep 1
done
SERVER_PID=$(cat "$WORK/pid" 2>/dev/null || echo "")

# Issue an email_signing cert.
python3 - "$WORK" <<'PYEOF'
import sys, json, urllib.request, subprocess
w = sys.argv[1]
ca_pem = urllib.request.urlopen("http://localhost:18094/api/ca-cert").read()
open(f"{w}/ca.pem","wb").write(ca_pem)

r = urllib.request.urlopen(urllib.request.Request(
    "http://localhost:18094/api/issue",
    data=json.dumps({
        "profile": "email_signing",
        "cn": "Alice Test",
        "email": "alice@example.com",
        "san_email": "alice@example.com",
    }).encode(),
    headers={"Content-Type":"application/json"}))
res = json.loads(r.read())
open(f"{w}/alice.pem","w").write(res["cert_pem"])
open(f"{w}/alice.key","w").write(res.get("key_pem",""))  # server-keygen if supported
print("Issued:", res.get("subject","?"))
PYEOF

# Generate a local key if server-keygen not available.
if [[ ! -s "$WORK/alice.key" ]]; then
    openssl genrsa -out "$WORK/alice.key" 2048 2>/dev/null
fi

echo "Alice cert CN:"
openssl x509 -in "$WORK/alice.pem" -noout -subject 2>/dev/null || echo "  (cert not available)"

# Test data to sign/encrypt.
echo "S/MIME interop test message from PyPKI" > "$WORK/plaintext.txt"

echo ""
echo "--- Test 1: CMS sign ---"
openssl cms -sign \
    -in "$WORK/plaintext.txt" \
    -signer "$WORK/alice.pem" \
    -inkey "$WORK/alice.key" \
    -certfile "$WORK/ca.pem" \
    -out "$WORK/signed.cms" \
    -outform DER 2>&1 | tee "$WORK/sign.log"
[[ -s "$WORK/signed.cms" ]] && echo "  CMS sign: OK" || _fail "cms_sign"

echo ""
echo "--- Test 2: CMS verify ---"
openssl cms -verify \
    -in "$WORK/signed.cms" \
    -inform DER \
    -CAfile "$WORK/ca.pem" \
    -out "$WORK/verified.txt" 2>&1 | tee "$WORK/verify.log"
if grep -q "Verification successful" "$WORK/verify.log" 2>/dev/null || \
   diff -q "$WORK/plaintext.txt" "$WORK/verified.txt" &>/dev/null; then
    echo "  CMS verify: OK"
else
    _fail "cms_verify"
fi

echo ""
echo "--- Test 3: CMS encrypt ---"
openssl cms -encrypt \
    -aes256 \
    -in "$WORK/plaintext.txt" \
    -out "$WORK/encrypted.cms" \
    -outform DER \
    "$WORK/alice.pem" 2>&1 | tee "$WORK/encrypt.log"
[[ -s "$WORK/encrypted.cms" ]] && echo "  CMS encrypt: OK" || _fail "cms_encrypt"

echo ""
echo "--- Test 4: CMS decrypt ---"
openssl cms -decrypt \
    -in "$WORK/encrypted.cms" \
    -inform DER \
    -inkey "$WORK/alice.key" \
    -recip "$WORK/alice.pem" \
    -out "$WORK/decrypted.txt" 2>&1 | tee "$WORK/decrypt.log"
if diff -q "$WORK/plaintext.txt" "$WORK/decrypted.txt" &>/dev/null; then
    echo "  CMS decrypt: OK"
else
    _fail "cms_decrypt"
fi

[[ ${#FAILURES[@]} -eq 0 ]] && echo "S/MIME interop: ALL PASS" && exit 0
echo "S/MIME interop: FAILURES: ${FAILURES[*]}"; mkdir -p "_failures/$TS"
cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true; exit 1
