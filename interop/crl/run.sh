#!/usr/bin/env bash
# interop/crl/run.sh — CRL interop test using openssl crl.
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
p=subprocess.Popen([sys.executable,'pki_server.py','--no-auth','--port','18093','--data-dir','$WORK/pypki','--ca-key-type','rsa-2048','--crl-enabled'],cwd='$REPO',stdout=open('$WORK/s.log','w'),stderr=subprocess.STDOUT)
[time.sleep(1) for _ in range(30) if not [urllib.request.urlopen('http://localhost:18093/',timeout=2) for _ in [0] if not True]]
open('$WORK/pid','w').write(str(p.pid))
" 2>/dev/null || true

# Retry waiting
for i in $(seq 1 30); do
    python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:18093/',timeout=2)" 2>/dev/null && break
    sleep 1
done

SERVER_PID=$(cat "$WORK/pid" 2>/dev/null || echo "")

python3 - "$WORK" <<'PYEOF'
import sys, json, urllib.request
w = sys.argv[1]
urllib.request.urlopen(f"http://localhost:18093/api/ca-cert").read()
open(f"{w}/ca.pem","wb").write(urllib.request.urlopen("http://localhost:18093/api/ca-cert").read())
# Issue + revoke a cert
r = urllib.request.urlopen(urllib.request.Request(
    "http://localhost:18093/api/issue",
    data=json.dumps({"profile":"tls_server","cn":"crl-test.local","san":["crl-test.local"]}).encode(),
    headers={"Content-Type":"application/json"}))
res = json.loads(r.read())
open(f"{w}/leaf.pem","w").write(res["cert_pem"])
serial = res.get("serial_hex") or res.get("serial")
# Revoke it
urllib.request.urlopen(urllib.request.Request(
    "http://localhost:18093/api/revoke",
    data=json.dumps({"serial":str(serial),"reason":"unspecified"}).encode(),
    headers={"Content-Type":"application/json"}))
# Download CRL
open(f"{w}/ca.crl","wb").write(urllib.request.urlopen("http://localhost:18093/crl").read())
print("Setup done, serial:", serial)
PYEOF

echo "--- Test 1: Parse CRL ---"
openssl crl -in "$WORK/ca.crl" -inform DER -noout -text 2>&1 | tee "$WORK/crl_text.log"
if grep -q "Certificate Revocation List" "$WORK/crl_text.log"; then
    echo "  CRL parse: OK"
else
    _fail "crl_parse"
fi

echo "--- Test 2: Validate CRL signature ---"
openssl crl -in "$WORK/ca.crl" -inform DER -CAfile "$WORK/ca.pem" -noout 2>&1 | tee "$WORK/crl_verify.log"
if grep -qi "ok\|verified" "$WORK/crl_verify.log"; then
    echo "  CRL signature: OK"
else
    _fail "crl_signature"
fi

echo "--- Test 3: Verify revoked cert shows in CRL ---"
openssl crl -in "$WORK/ca.crl" -inform DER -text -noout 2>&1 | grep -c "Serial Number" | tee "$WORK/crl_count.log"
if [[ $(cat "$WORK/crl_count.log") -ge 1 ]]; then
    echo "  CRL has revoked entries: OK"
else
    _fail "crl_revoked_entries"
fi

[[ ${#FAILURES[@]} -eq 0 ]] && echo "CRL interop: ALL PASS" && exit 0
echo "CRL interop: FAILURES: ${FAILURES[*]}"; mkdir -p "_failures/$TS"
cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true; exit 1
