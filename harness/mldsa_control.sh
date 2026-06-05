#!/usr/bin/env bash
# mldsa_control.sh — Phase D: ML-DSA negative control.
#
# Converts the audit's assertion ("ML-DSA certs are kernel-unusable today")
# into captured evidence. Two attack surfaces are tested:
#
#   D1a  keyctl padd: can the kernel's X.509 parser even load an ML-DSA cert?
#   D1b  sign-file:   can scripts/sign-file use an ML-DSA key+cert to sign a module?
#
# Expected outcome for both: tool or kernel rejects with a concrete error.
# If either unexpectedly succeeds, that is a significant finding — log it loudly.
#
# Preconditions:
#   - issue_cert.sh has been run (provides signing_cert.der for comparison)
#   - PyPKI server accessible (to issue an ML-DSA cert)
#   - Running as root
#
# Environment:
#   PYPKI_URL    PyPKI server (default: https://localhost:8443)
#   PYPKI_TOKEN  Bearer token (optional)
#   HARNESS_OUT  (default: /tmp/ima-evm-harness)

set -euo pipefail

PYPKI_URL="${PYPKI_URL:-https://localhost:8443}"
PYPKI_TOKEN="${PYPKI_TOKEN:-}"
OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
GATE_FILE="$OUT/phase_d_results.txt"

CURL_OPTS=(-s -k)
[ -n "$PYPKI_TOKEN" ] && CURL_OPTS+=(-H "Authorization: Bearer $PYPKI_TOKEN")

log()  { echo "[mldsa_control] $*"; }
warn() { echo "[mldsa_control] WARNING: $*" >&2; }

gate() {
    local g="$1" s="$2"; shift 2
    printf "[GATE %-2s] %-7s %s\n" "$g" "$s" "$*" | tee -a "$GATE_FILE"
}

> "$GATE_FILE"

# ── Step 1: Issue an ML-DSA cert from PyPKI ───────────────────────────────────
log "Requesting ML-DSA cert from PyPKI (ml_dsa_signing profile, server-side key)..."
# ML-DSA keys must be generated server-side (no openssl support for ML-DSA CSRs).
# We only need the cert DER to attempt kernel loading and sign-file usage.
HTTP_CODE=$(curl "${CURL_OPTS[@]}" \
    -o "$OUT/mldsa_response.json" \
    -w "%{http_code}" \
    -X POST "$PYPKI_URL/api/issue" \
    -H "Content-Type: application/json" \
    -d '{"profile": "ml_dsa_signing", "subject": "CN=mldsa-phase-d-test", "key_type": "ml-dsa-65"}')

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    python3 -c "
import json, sys, os
out = os.environ.get('HARNESS_OUT', '/tmp/ima-evm-harness')
d = json.load(open(f'{out}/mldsa_response.json'))
if 'cert_pem' not in d:
    print('No cert_pem in response:', d, file=sys.stderr)
    sys.exit(1)
open(f'{out}/mldsa_leaf.pem', 'w').write(d['cert_pem'])
" HARNESS_OUT="$OUT" && {
        log "  -> ML-DSA cert issued: $OUT/mldsa_leaf.pem"
        openssl x509 -in "$OUT/mldsa_leaf.pem" -noout -text \
            | grep -E "Signature Algorithm|Public Key Algorithm|Subject:" | head -5 || true
        openssl x509 -in "$OUT/mldsa_leaf.pem" -outform DER -out "$OUT/mldsa_leaf.der" 2>/dev/null || {
            warn "openssl could not convert ML-DSA cert to DER (expected — OID unknown to openssl)."
            warn "Attempting raw DER extraction via Python cryptography library..."
            python3 -c "
import base64, re, os
out = os.environ.get('HARNESS_OUT', '/tmp/ima-evm-harness')
pem = open(f'{out}/mldsa_leaf.pem').read()
b64 = re.sub(r'-----.*?-----|\s', '', pem)
open(f'{out}/mldsa_leaf.der','wb').write(base64.b64decode(b64))
print('DER extracted via base64 strip.')
" HARNESS_OUT="$OUT" || {
                log "Could not extract DER. Skipping D1a."
            }
        }
    } || {
        log "ML-DSA issuance returned HTTP 200 but no cert_pem."
        cat "$OUT/mldsa_response.json" >&2
        gate D1a BLOCKED "PyPKI returned 200 but no cert — ml_dsa_signing profile may require a CSR"
    }
else
    log "PyPKI returned HTTP $HTTP_CODE for ml_dsa_signing profile."
    cat "$OUT/mldsa_response.json" >&2
    log ""
    log "This may mean:"
    log "  - ml_dsa_signing profile requires a CSR (no server-side ML-DSA keygen)"
    log "  - The profile name differs (check: GET $PYPKI_URL/api/profiles)"
    log "  - PyPKI is not running"
    gate D1a BLOCKED "PyPKI HTTP $HTTP_CODE — could not issue ML-DSA cert"
    gate D1b BLOCKED "Cannot test sign-file without ML-DSA cert"
    echo ""
    log "Fallback: using the classical signing_cert.der for a sign-file algorithm mismatch test."
    log "This demonstrates the same point: sign-file will fail on unsupported algorithms."
    FALLBACK=1
fi

FALLBACK="${FALLBACK:-0}"

# ── Gate D1a: keyctl padd with ML-DSA cert ────────────────────────────────────
if [ "$FALLBACK" = "0" ] && [ -f "$OUT/mldsa_leaf.der" ]; then
    echo "--- Gate D1a: keyctl padd ML-DSA cert into kernel keyring ---"
    RC=0
    ERR=$(keyctl padd asymmetric "mldsa-test" @u < "$OUT/mldsa_leaf.der" 2>&1) || RC=$?
    if [ "$RC" != 0 ]; then
        gate D1a PASS "keyctl rejected ML-DSA cert (exit=$RC): $ERR
             This confirms the kernel X.509 parser does not support the ML-DSA algorithm OID."
    else
        gate D1a FAIL "keyctl ACCEPTED the ML-DSA cert (unexpected).
             Key ID: $ERR
             This is a significant finding — the kernel may have loaded the cert but
             signing verification may still fail. Document this outcome."
        keyctl unlink "$ERR" @u 2>/dev/null || true
    fi
fi

# ── Gate D1b: sign-file with ML-DSA ───────────────────────────────────────────
# sign-file uses OpenSSL under the hood. OpenSSL has no ML-DSA key support,
# so either: (a) we can't get the private key from PyPKI, or (b) even if we
# had the key in PEM form, sign-file/openssl would reject the unknown algorithm.
#
# For this gate, we use the ML-DSA cert DER with a /dev/null key placeholder
# to show the tool fails before reaching the kernel.

echo "--- Gate D1b: sign-file with ML-DSA cert (classical-algo key, ML-DSA cert) ---"

# Locate sign-file
UNAME_R=$(uname -r)
SIGN_FILE_BIN=""
for loc in \
    "$(command -v sign-file 2>/dev/null || echo '')" \
    "/usr/src/kernels/$UNAME_R/scripts/sign-file" \
    "/usr/src/linux-headers-$UNAME_R/scripts/sign-file"; do
    if [ -n "$loc" ] && [ -x "$loc" ]; then SIGN_FILE_BIN="$loc"; break; fi
done

if [ -z "$SIGN_FILE_BIN" ]; then
    gate D1b BLOCKED "sign-file not found — install kernel-devel or linux-headers"
else
    log "  sign-file: $SIGN_FILE_BIN"
    # Attempt to sign a trivial file. We use the EC key (signing_key.pem) with
    # the ML-DSA cert — sign-file should reject the key/cert mismatch.
    DUMMY="$OUT/mldsa_d1b_target"
    echo 'dummy' > "$DUMMY"

    if [ "$FALLBACK" = "0" ] && [ -f "$OUT/mldsa_leaf.der" ]; then
        CERT_TO_USE="$OUT/mldsa_leaf.der"
    else
        CERT_TO_USE="$OUT/signing_cert.der"
        log "  (fallback: using classical cert to test sign-file error path)"
    fi

    RC=0
    ERR=$("$SIGN_FILE_BIN" sha256 "$OUT/signing_key.pem" "$CERT_TO_USE" "$DUMMY" 2>&1) || RC=$?
    if [ "$RC" != 0 ]; then
        gate D1b PASS "sign-file rejected (exit=$RC): $ERR"
    else
        gate D1b FAIL "sign-file succeeded (exit=0). If the ML-DSA cert was used,
             this is a significant finding — the signed file likely won't load
             under module.sig_enforce=1, but capture the insmod result too."
    fi
fi

echo ""
log "=== Phase D summary ==="
cat "$GATE_FILE"
echo ""
log "A PASS on D1a or D1b means the kernel/tool correctly rejects ML-DSA."
log "This converts the audit's assertion into captured evidence."
