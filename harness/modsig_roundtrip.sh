#!/usr/bin/env bash
# modsig_roundtrip.sh — Phase B: kernel module signing round-trip.
#
# This is the canonical validation gate. The kernel's X.509 parser enforces
# keyUsage and EKU most strictly on module signatures, making this the
# definitive test that the code_signing profile is actually accepted.
#
# Two trust modes (--trust-mode):
#
#   leaf (default) — B1–B4 gates only:
#       Stock PKCS#7 (CMS_NOCERTS); leaf cert enrolled in .secondary_trusted_keys.
#       Precondition: run enroll_modsig.sh TRUST_MODE=leaf first.
#
#   ca             — B1–B4 + gate B5:
#       Cert embedded in PKCS#7 (openssl cms, no -nocerts).
#       Only the PyPKI root is trusted (no leaf enrollment required).
#       B5 gate: insmod with embedded-cert module and leaf NOT in any keyring.
#       Precondition: PyPKI root in .builtin_trusted_keys (F2-BUILTIN kernel).
#
# Preconditions:
#   - issue_cert.sh has been run (provides signing_key.pem + signing_cert.der)
#   - F2-BUILTIN anchor enrolled: kernel built with
#       CONFIG_SYSTEM_TRUSTED_KEYS="pypki_root.pem"
#       CONFIG_MODULE_SIG=y
#     OR (for leaf mode) enroll_modsig.sh TRUST_MODE=leaf has been run
#   - module-signing kernel headers available (linux-headers-$(uname -r))
#   - Running as root
#
# Environment:
#   HARNESS_OUT     (default: /tmp/ima-evm-harness)
#   KERNEL_SRC      kernel source/headers base (default: auto-detect)
#   SIGN_FILE       path to scripts/sign-file binary (default: auto-detect)
#   TRUST_MODE      leaf | ca  (default: leaf)

set -euo pipefail

OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
GATE_FILE="$OUT/phase_b_results.txt"
HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUST_MODE="${TRUST_MODE:-leaf}"

# Parse --trust-mode flag
for arg in "$@"; do
    case "$arg" in
        --trust-mode=*) TRUST_MODE="${arg#*=}" ;;
        --trust-mode)   shift; TRUST_MODE="$1" ;;
    esac
done

case "$TRUST_MODE" in
    leaf|ca) ;;
    *) echo "ERROR: --trust-mode must be 'leaf' or 'ca'" >&2; exit 1 ;;
esac

log()  { echo "[modsig_roundtrip] $*"; }
warn() { echo "[modsig_roundtrip] WARNING: $*" >&2; }

gate() {
    local g="$1" s="$2"; shift 2
    printf "[GATE %-2s] %-7s %s\n" "$g" "$s" "$*" | tee -a "$GATE_FILE"
}

dmesg_tail() {
    local mark="$1"
    dmesg | tail -n "+$((mark + 1))" | head -30
}

# ── Preflight ─────────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || { echo "ERROR: must be root" >&2; exit 1; }
[ -f "$OUT/signing_key.pem" ]  || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/signing_cert.der" ] || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/wrong_key.pem" ]    || { log "ERROR: Run issue_cert.sh first."; exit 1; }

# Locate sign-file
if [ -n "${SIGN_FILE:-}" ]; then
    SIGN_FILE_BIN="$SIGN_FILE"
elif command -v sign-file &>/dev/null; then
    SIGN_FILE_BIN=$(command -v sign-file)
else
    # Common locations
    UNAME_R=$(uname -r)
    SIGN_FILE_BIN=""
    for loc in \
        "/usr/src/kernels/$UNAME_R/scripts/sign-file" \
        "/usr/lib/linux-kbuild-$(echo "$UNAME_R" | cut -d- -f1)/scripts/sign-file" \
        "/usr/src/linux-headers-$UNAME_R/scripts/sign-file"; do
        if [ -x "$loc" ]; then SIGN_FILE_BIN="$loc"; break; fi
    done
fi

if [ -z "$SIGN_FILE_BIN" ] || [ ! -x "$SIGN_FILE_BIN" ]; then
    log "ERROR: scripts/sign-file not found."
    log "On Fedora: dnf install kernel-devel  (check /usr/src/kernels/\$(uname -r)/scripts/sign-file)"
    log "On Ubuntu: apt install linux-headers-\$(uname -r)"
    log "Or set: SIGN_FILE=/path/to/sign-file ./modsig_roundtrip.sh"
    exit 1
fi
log "sign-file: $SIGN_FILE_BIN"

# Locate kernel headers for module build
UNAME_R=$(uname -r)
if [ -n "${KERNEL_SRC:-}" ]; then
    KDIR="$KERNEL_SRC"
elif [ -d "/lib/modules/$UNAME_R/build" ]; then
    KDIR="/lib/modules/$UNAME_R/build"
else
    log "ERROR: Kernel headers not found at /lib/modules/$UNAME_R/build"
    log "Install: dnf install kernel-devel  or  apt install linux-headers-$(uname -r)"
    exit 1
fi
log "Kernel build dir: $KDIR"

# Check module signing enforcement
SIG_ENFORCE=""
if [ -f /sys/module/module/parameters/sig_enforce ]; then
    SIG_ENFORCE=$(cat /sys/module/module/parameters/sig_enforce)
fi
CMDLINE_ENFORCE=$(cat /proc/cmdline | grep -o 'module\.sig_enforce=[^ ]*' | cut -d= -f2 || echo "")
log "module.sig_enforce: kernel_param=${CMDLINE_ENFORCE:-unset} sysfs=${SIG_ENFORCE:-unavail}"

if [ "$SIG_ENFORCE" != "1" ] && [ "$CMDLINE_ENFORCE" != "1" ]; then
    warn "Module signature enforcement does not appear to be active."
    warn "Gates B2/B3/B4 (rejection gates) will likely FAIL (modules will load)."
    warn "Boot with: module.sig_enforce=1"
    warn "Continuing — capturing actual kernel behavior."
    echo ""
fi

> "$GATE_FILE"

# ── Build hello.ko ────────────────────────────────────────────────────────────
log "Building hello.ko from $HARNESS_DIR/hello.c ..."
BUILD_DIR="$OUT/module_build"
mkdir -p "$BUILD_DIR"
cp "$HARNESS_DIR/hello.c"   "$BUILD_DIR/"
cp "$HARNESS_DIR/Makefile"  "$BUILD_DIR/"

make -C "$KDIR" M="$BUILD_DIR" modules 2>&1 | sed 's/^/  /'

[ -f "$BUILD_DIR/hello.ko" ] || { log "ERROR: hello.ko build failed."; exit 1; }
log "  -> $BUILD_DIR/hello.ko"

# Preserve a clean unsigned copy for gate B2
cp "$BUILD_DIR/hello.ko" "$OUT/hello_unsigned.ko"

# ── Sign hello.ko with the PyPKI leaf ─────────────────────────────────────────
log "Signing hello.ko with PyPKI leaf cert..."
cp "$BUILD_DIR/hello.ko" "$OUT/hello_signed.ko"
"$SIGN_FILE_BIN" sha512 "$OUT/signing_key.pem" "$OUT/signing_cert.der" "$OUT/hello_signed.ko"

# Verify the sig block was appended
SIG_INFO=$(modinfo "$OUT/hello_signed.ko" 2>/dev/null | grep -i 'sig\|signature' || echo "(no sig info)")
log "  modinfo sig: $SIG_INFO"

# Wrong-key signed copy for gate B3
cp "$BUILD_DIR/hello.ko" "$OUT/hello_wrongkey.ko"
"$SIGN_FILE_BIN" sha512 "$OUT/wrong_key.pem" "$OUT/wrong_cert.der" "$OUT/hello_wrongkey.ko"
log "  Wrong-key signed: $OUT/hello_wrongkey.ko"

# Tampered copy for gate B4 (sign, then corrupt a byte)
cp "$OUT/hello_signed.ko" "$OUT/hello_tampered.ko"
python3 -c "
data = bytearray(open('$OUT/hello_tampered.ko','rb').read())
# Flip a byte in the module body (not the appended sig block)
pos = len(data) // 2
data[pos] ^= 0xFF
open('$OUT/hello_tampered.ko','wb').write(data)
"
log "  Tampered copy: $OUT/hello_tampered.ko"
echo ""

# ── Gate B1: load the PyPKI-signed module ─────────────────────────────────────
echo "--- Gate B1: insmod signed hello.ko ---"
# Remove any previous load of the module
rmmod hello 2>/dev/null || true
MARK=$(dmesg | wc -l)
RC=0; insmod "$OUT/hello_signed.ko" 2>&1 || RC=$?
SNAP=$(dmesg_tail "$MARK" | head -5)
if [ "$RC" = 0 ]; then
    DMESG_HELLO=$(dmesg_tail "$MARK" | grep -i 'hello\|loaded' | head -3 || echo "(see dmesg)")
    gate B1 PASS "insmod exit=0; module loaded. dmesg: $DMESG_HELLO"
    rmmod hello 2>/dev/null || true
else
    gate B1 FAIL "insmod exit=$RC — PyPKI-signed module REJECTED. This is the primary gate.
             dmesg: $SNAP
             This likely means keyUsage/EKU or the trust anchor is wrong. Diagnose before proceeding."
fi

# Gate B2: unsigned module — must be rejected
echo "--- Gate B2: insmod unsigned hello.ko ---"
rmmod hello 2>/dev/null || true
MARK=$(dmesg | wc -l)
RC=0; insmod "$OUT/hello_unsigned.ko" 2>&1 || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'unsigned|rejected|sig|key' | head -3 || echo "(no matching dmesg)")
if [ "$RC" != 0 ]; then
    gate B2 PASS "insmod exit=$RC (rejected); dmesg: $SNAP"
else
    gate B2 FAIL "insmod exit=0 — unsigned module loaded. Is module.sig_enforce=1 active? dmesg: $SNAP"
    rmmod hello 2>/dev/null || true
fi

# Gate B3: wrong-key signed — must be rejected
echo "--- Gate B3: insmod wrong-key signed hello.ko ---"
rmmod hello 2>/dev/null || true
MARK=$(dmesg | wc -l)
RC=0; insmod "$OUT/hello_wrongkey.ko" 2>&1 || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'reject|key|sig|trust' | head -3 || echo "(no matching dmesg)")
if [ "$RC" != 0 ]; then
    gate B3 PASS "insmod exit=$RC (rejected — wrong key not trusted); dmesg: $SNAP"
else
    gate B3 FAIL "insmod exit=0 — wrong-key module loaded. Unexpected. dmesg: $SNAP"
    rmmod hello 2>/dev/null || true
fi

# Gate B4: tampered signed module — must be rejected
echo "--- Gate B4: insmod tampered signed hello.ko ---"
rmmod hello 2>/dev/null || true
MARK=$(dmesg | wc -l)
RC=0; insmod "$OUT/hello_tampered.ko" 2>&1 || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'tamper|corrupt|sig|verify|mismatch' | head -3 || echo "(no matching dmesg)")
if [ "$RC" != 0 ]; then
    gate B4 PASS "insmod exit=$RC (rejected — signature mismatch); dmesg: $SNAP"
else
    gate B4 FAIL "insmod exit=0 — tampered module loaded. dmesg: $SNAP"
    rmmod hello 2>/dev/null || true
fi

# Gate B5 (ca mode only): insmod with embedded cert, leaf NOT in keyring
if [ "$TRUST_MODE" = "ca" ]; then
    echo "--- Gate B5 (ca mode): per-CA trust — insmod with cert embedded, leaf absent ---"

    # Sign a fresh copy with openssl cms (cert embedded, no -nocerts)
    cp "$BUILD_DIR/hello.ko" "$OUT/hello_ca.ko"
    openssl cms -sign \
        -binary -nosmimecap \
        -md sha512 \
        -signer "$OUT/signing_cert.pem" \
        -inkey  "$OUT/signing_key.pem" \
        -in     "$OUT/hello_ca.ko"     \
        -outform DER                   \
        -out    "$OUT/hello_ca_sig.der"

    # Verify cert was embedded
    CERT_COUNT=$(openssl pkcs7 -inform DER -in "$OUT/hello_ca_sig.der" -print_certs -noout 2>/dev/null \
                 | grep -c "subject=" || echo 0)
    log "  Embedded certs in PKCS#7: $CERT_COUNT (expected 1)"

    # Assemble the signed module: [module_body][pkcs7][struct module_signature][marker]
    MODULE_BODY=$(python3 -c "
import struct, sys
data = open('$OUT/hello_ca.ko', 'rb').read()
marker = b'~Module signature appended~\n'
if data.endswith(marker):
    body = data[:-len(marker)]
    sig_len = struct.unpack('>I', body[-12:][8:12])[0]
    sl = body[-12:][3]; kl = body[-12:][4]
    data = body[:-(sl + kl + sig_len + 12)]
sys.stdout.buffer.write(data)
")
    PKCS7_BYTES=$(cat "$OUT/hello_ca_sig.der" | wc -c)
    python3 -c "
import struct, sys
module_body = open('$OUT/hello_ca.ko', 'rb').read()
# strip any existing sig
marker = b'~Module signature appended~\n'
if module_body.endswith(marker):
    body = module_body[:-len(marker)]
    sig_len = struct.unpack('>I', body[-12:][8:12])[0]
    sl = body[-12:][3]; kl = body[-12:][4]
    module_body = body[:-(sl + kl + sig_len + 12)]
pkcs7 = open('$OUT/hello_ca_sig.der', 'rb').read()
sig_struct = bytes([0, 0, 2, 0, 0, 0, 0, 0]) + struct.pack('>I', len(pkcs7))
out = module_body + pkcs7 + sig_struct + b'~Module signature appended~\n'
open('$OUT/hello_ca.ko', 'wb').write(out)
print(f'assembled: module_body={len(module_body)}B pkcs7={len(pkcs7)}B total={len(out)}B')
"
    log "  Signed with embedded cert: $OUT/hello_ca.ko"

    # Verify the leaf is NOT in any keyring before testing
    LEAF_SERIAL=$(openssl x509 -inform DER -in "$OUT/signing_cert.der" -noout -serial 2>/dev/null \
                  | cut -d= -f2 | tr 'A-F' 'a-f' || echo "")
    LEAF_IN_BUILTIN=$(keyctl list %:.builtin_trusted_keys 2>/dev/null \
                       | grep -c "${LEAF_SERIAL}" || echo 0)
    LEAF_IN_SECONDARY=$(keyctl list %:.secondary_trusted_keys 2>/dev/null \
                         | grep -c "${LEAF_SERIAL}" || echo 0)
    if [ "$LEAF_IN_BUILTIN" -gt 0 ] || [ "$LEAF_IN_SECONDARY" -gt 0 ]; then
        gate B5 BLOCKED "leaf cert is enrolled in a trusted keyring — honesty gate failed. Remove it first: keyctl unlink <id> %:.secondary_trusted_keys"
    else
        log "  Leaf absent from all keyrings (builtin=$LEAF_IN_BUILTIN secondary=$LEAF_IN_SECONDARY) ✓"
        rmmod hello 2>/dev/null || true
        MARK=$(dmesg | wc -l)
        RC=0; insmod "$OUT/hello_ca.ko" 2>&1 || RC=$?
        SNAP=$(dmesg_tail "$MARK" | grep -iE 'hello|loaded|key|reject|sig|trust' | head -3 \
               || echo "(no matching dmesg)")
        if [ "$RC" = "0" ]; then
            gate B5 PASS "insmod exit=0 — per-CA trust confirmed (chain leaf→root); dmesg: $SNAP"
            rmmod hello 2>/dev/null || true
        else
            gate B5 FAIL "insmod exit=$RC — per-CA trust NOT working; dmesg: $SNAP"
        fi
    fi
fi

echo ""
log "=== Phase B gate summary (trust-mode=$TRUST_MODE) ==="
cat "$GATE_FILE"
echo ""
log "Full results: $GATE_FILE"

# Determine overall verdict
PASS_COUNT=$(grep -c "PASS" "$GATE_FILE" || true)
FAIL_COUNT=$(grep -c "FAIL" "$GATE_FILE" || true)
EXPECTED=$( [ "$TRUST_MODE" = "ca" ] && echo 5 || echo 4 )

echo ""
if [ "$FAIL_COUNT" = 0 ] && [ "$PASS_COUNT" = "$EXPECTED" ]; then
    log "VERDICT: PASS — all $EXPECTED Phase B gates passed (trust-mode=$TRUST_MODE)."
else
    log "VERDICT: FAIL — $FAIL_COUNT gate(s) failed, $PASS_COUNT/$EXPECTED passed (trust-mode=$TRUST_MODE)."
    log "B1 failure is the most critical: it means the PyPKI-issued cert is"
    log "not accepted by the kernel module verifier. Diagnose trust chain first."
fi
