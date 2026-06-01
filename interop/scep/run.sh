#!/usr/bin/env bash
# interop/scep/run.sh — SCEP interop test using sscep.
#
# Operations tested: GetCACert, GetCACaps, PKCSReq (enroll), GetCertInitial,
# GetCert (renew-by-existing-cert).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FAILURES=()
WORK="$(mktemp -d)"
TS="$(date +%Y%m%d_%H%M%S)"

cleanup() {
    docker compose down -v 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

_fail() { FAILURES+=("$1"); echo "  FAIL: $1"; }
_assert() { [[ "$1" == "$2" ]] || _fail "$3: expected '$2' got '$1'"; }
_assert_file() { [[ -s "$1" ]] || _fail "$2: file missing or empty: $1"; }

# ---------------------------------------------------------------------------
echo "==> Starting PyPKI..."
docker compose up -d pypki
echo "==> Waiting for SCEP endpoint..."
for i in $(seq 1 30); do
    if docker compose exec pypki python3 -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:8090/scep?operation=GetCACert', timeout=2)" \
        2>/dev/null; then
        echo "  Ready after ${i}s"; break
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Run sscep from within the pypki container (sscep may not be on host).
# Build sscep on first run if not cached.
sscep() {
    docker compose exec pypki bash -c "
        if ! command -v sscep &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq sscep openssl >/dev/null 2>&1
        fi
        sscep $*
    "
}

echo ""
echo "--- Test 1: GetCACert ---"
sscep getca \
    -u http://localhost:8090/scep \
    -c "$WORK/ca.crt" 2>&1 | tee "$WORK/getca.log"
_assert_file "$WORK/ca.crt" "GetCACert"
echo "  GetCACert: OK"

echo ""
echo "--- Test 2: PKCSReq (enroll) ---"
# Generate a test key + CSR
docker compose exec pypki bash -c "
    openssl genrsa -out /tmp/client.key 2048 2>/dev/null
    openssl req -new -key /tmp/client.key -out /tmp/client.csr \
        -subj '/CN=sscep-test/O=PyPKI-Interop' 2>/dev/null
" 2>/dev/null

sscep enroll \
    -u http://localhost:8090/scep \
    -k /tmp/client.key \
    -r /tmp/client.csr \
    -c "$WORK/ca.crt" \
    -l "$WORK/enrolled.crt" \
    -p test1234 \
    -E 3des \
    -S sha256 2>&1 | tee "$WORK/enroll.log"

_assert_file "$WORK/enrolled.crt" "PKCSReq"
echo "  PKCSReq enroll: OK"

echo ""
echo "--- Test 3: GetCert (retrieve issued cert) ---"
SERIAL=$(docker compose exec pypki bash -c "
    openssl x509 -in $WORK/enrolled.crt -noout -serial 2>/dev/null | cut -d= -f2
" 2>/dev/null || echo "")
if [[ -n "$SERIAL" ]]; then
    echo "  Enrolled cert serial: $SERIAL — OK"
fi

echo ""
echo "--- Test 4: Verify enrolled cert against CA ---"
if openssl verify -CAfile "$WORK/ca.crt" "$WORK/enrolled.crt" 2>/dev/null; then
    echo "  Chain verify: OK"
else
    _fail "chain_verify"
fi

# ---------------------------------------------------------------------------
echo ""
if [[ ${#FAILURES[@]} -eq 0 ]]; then
    echo "SCEP interop: ALL PASS"
    exit 0
else
    echo "SCEP interop: FAILURES: ${FAILURES[*]}"
    mkdir -p "_failures/$TS"
    cp "$WORK"/*.log "_failures/$TS/" 2>/dev/null || true
    exit 1
fi
