#!/usr/bin/env bash
# issue_cert.sh — Shared prerequisite for all phases.
#
# Generates an EC P-256 keypair locally (key stays on endpoint — the IMA/EVM
# best practice), submits a CSR to PyPKI's code_signing profile, verifies
# the returned cert has the required fields, converts to DER, and creates
# control certs used by the negative gates.
#
# Environment:
#   PYPKI_URL      PyPKI server (default: https://localhost:8443)
#   PYPKI_TOKEN    Bearer token for auth (optional)
#   PYPKI_CA       Path to PyPKI root PEM for TLS verification (optional;
#                  defaults to -k / skip verification in test VMs)
#   HARNESS_OUT    Output directory (default: /tmp/ima-evm-harness)
#
# Run once before any phase script.

set -euo pipefail

PYPKI_URL="${PYPKI_URL:-https://localhost:8443}"
PYPKI_TOKEN="${PYPKI_TOKEN:-}"
PYPKI_CA="${PYPKI_CA:-}"
OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"

CURL_OPTS=(-s)
if [ -n "$PYPKI_CA" ]; then
    CURL_OPTS+=(--cacert "$PYPKI_CA")
else
    CURL_OPTS+=(-k)
fi
[ -n "$PYPKI_TOKEN" ] && CURL_OPTS+=(-H "Authorization: Bearer $PYPKI_TOKEN")

mkdir -p "$OUT"

log() { echo "[issue_cert] $*"; }
die() { echo "[issue_cert] ERROR: $*" >&2; exit 1; }

log "Output dir : $OUT"
log "PyPKI URL  : $PYPKI_URL"
echo ""

# ── 1. Generate EC P-256 signing keypair ──────────────────────────────────────
log "Step 1/6: Generating EC P-256 signing keypair (key stays in VM)"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/signing_key.pem"
log "  -> $OUT/signing_key.pem"

# ── 2. Build CSR ──────────────────────────────────────────────────────────────
log "Step 2/6: Building CSR"
openssl req -new -key "$OUT/signing_key.pem" \
    -subj "/CN=PyPKI IMA-EVM Test Signing Key/O=ima-evm-harness" \
    -out "$OUT/signing.csr"
log "  -> $OUT/signing.csr"

# ── 3. Submit to PyPKI ────────────────────────────────────────────────────────
log "Step 3/6: Submitting CSR to PyPKI (profile=code_signing)"
JSON_BODY=$(python3 -c "
import json, sys
csr = open('$OUT/signing.csr').read()
print(json.dumps({'profile': 'code_signing', 'csr_pem': csr}))
")
HTTP_CODE=$(curl "${CURL_OPTS[@]}" -o "$OUT/issue_response.json" -w "%{http_code}" \
    -X POST "$PYPKI_URL/api/issue" \
    -H "Content-Type: application/json" \
    -d "$JSON_BODY")

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
    log "  HTTP $HTTP_CODE from PyPKI"
    cat "$OUT/issue_response.json" >&2
    die "Issuance failed. Check PYPKI_URL, PYPKI_TOKEN, and that PyPKI is running."
fi

python3 -c "
import json, sys
d = json.load(open('$OUT/issue_response.json'))
if 'cert_pem' not in d:
    print('No cert_pem in response:', d, file=sys.stderr)
    sys.exit(1)
open('$OUT/leaf.pem', 'w').write(d['cert_pem'])
open('$OUT/chain.pem', 'w').write(d.get('chain_pem', ''))
open('$OUT/fullchain.pem', 'w').write(d.get('fullchain_pem', ''))
" || die "Failed to parse PyPKI response"

SERIAL=$(openssl x509 -in "$OUT/leaf.pem" -noout -serial | cut -d= -f2)
echo "$SERIAL" > "$OUT/leaf_serial.txt"
log "  -> Issued. Serial: $SERIAL"

# ── 4. Verify cert fields ─────────────────────────────────────────────────────
log "Step 4/6: Verifying cert fields (must have KU + EKU + SKID)"
echo ""
openssl x509 -in "$OUT/leaf.pem" -noout -text \
    | grep -E "Key Usage|Extended Key Usage|Subject Key Identifier|Signature Algorithm|Not Before|Not After"
echo ""

# Hard-check the three required fields
HARNESS_OUT="$OUT" python3 - <<'PYCHECK'
import subprocess, sys, os
out_dir = os.environ.get('HARNESS_OUT', '/tmp/ima-evm-harness')
out_text = subprocess.check_output(
    ['openssl', 'x509', '-in', f'{out_dir}/leaf.pem', '-noout', '-text']
).decode()
ok = True
for required in ['Digital Signature', 'Code Signing', 'Subject Key Identifier']:
    if required in out_text:
        print(f'  [OK] {required} present')
    else:
        print(f'  [FAIL] {required} MISSING — cert shape is wrong', file=sys.stderr)
        ok = False
sys.exit(0 if ok else 1)
PYCHECK

# ── 5. Convert to DER ─────────────────────────────────────────────────────────
log "Step 5/6: Converting leaf (and chain if present) to DER"
openssl x509 -in "$OUT/leaf.pem" -outform DER -out "$OUT/signing_cert.der"
log "  -> $OUT/signing_cert.der"
if [ -s "$OUT/chain.pem" ]; then
    openssl x509 -in "$OUT/chain.pem" -outform DER -out "$OUT/chain.der"
    log "  -> $OUT/chain.der"
fi

# ── 6. Control certs ──────────────────────────────────────────────────────────
log "Step 6/6: Creating control certs for negative gates"

# Wrong-key control: EC P-256 self-signed, does NOT chain to PyPKI root
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/wrong_key.pem"
openssl req -new -x509 -key "$OUT/wrong_key.pem" \
    -subj "/CN=Wrong Key Control (not trusted by PyPKI)" \
    -days 30 -out "$OUT/wrong_cert.pem"
openssl x509 -in "$OUT/wrong_cert.pem" -outform DER -out "$OUT/wrong_cert.der"
log "  -> $OUT/wrong_key.pem / wrong_cert.{pem,der}"

echo ""
log "=== issue_cert.sh complete ==="
echo ""
echo "  Signing key (keep on VM):  $OUT/signing_key.pem"
echo "  Leaf cert PEM:             $OUT/leaf.pem"
echo "  Leaf cert DER:             $OUT/signing_cert.der"
echo "  Chain PEM:                 $OUT/chain.pem"
echo "  Wrong-key control:         $OUT/wrong_key.pem + wrong_cert.{pem,der}"
echo "  Leaf serial:               $(cat "$OUT/leaf_serial.txt")"
echo ""
echo "Next: run enroll_anchor.sh to add the trust anchor to the kernel keyring."
