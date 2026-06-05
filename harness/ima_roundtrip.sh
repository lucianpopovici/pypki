#!/usr/bin/env bash
# ima_roundtrip.sh — Phase A: IMA appraisal round-trip.
#
# Validates that the kernel accepts files signed with the PyPKI leaf and
# rejects unsigned, tampered, and wrong-key-signed files. Proves the
# SKID→keyid linkage (audit Q3) empirically.
#
# Two-pass design (IMA enforcement requires a reboot between passes):
#
#   Pass 1 — labelling (run under ima_appraise=fix):
#       ./ima_roundtrip.sh --label
#     Signs the test binary with evmctl, creates control copies, then
#     instructs you to reboot with ima_appraise=enforce.
#
#   Pass 2 — gating (run under ima_appraise=enforce):
#       ./ima_roundtrip.sh
#     Executes gates A1–A4 and records results to phase_a_results.txt.
#
# Preconditions for both passes:
#   - issue_cert.sh has been run
#   - enroll_anchor.sh has been run (F1 or F2)
#   - Running as root
#
# Environment:
#   HARNESS_OUT   (default: /tmp/ima-evm-harness)

set -euo pipefail

OUT="${HARNESS_OUT:-/tmp/ima-evm-harness}"
LABEL_MODE=0
TARGET="$OUT/test_target"
TARGET_WRONG="$OUT/test_target_wrong"
GATE_FILE="$OUT/phase_a_results.txt"

for arg in "$@"; do
    case "$arg" in
        --label) LABEL_MODE=1 ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

log()  { echo "[ima_roundtrip] $*"; }
warn() { echo "[ima_roundtrip] WARNING: $*" >&2; }

gate() {
    # gate <id> <PASS|FAIL|BLOCKED> <detail>
    local g="$1" s="$2"; shift 2
    printf "[GATE %-2s] %-7s %s\n" "$g" "$s" "$*" | tee -a "$GATE_FILE"
}

dmesg_tail() {
    # dmesg_tail <mark> — lines added to dmesg since line <mark>
    local mark="$1"
    dmesg | tail -n "+$((mark + 1))" | head -30
}

# ── Common preflight ──────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || { echo "ERROR: must be root" >&2; exit 1; }

[ -f "$OUT/signing_key.pem" ]   || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/signing_cert.der" ]  || { log "ERROR: Run issue_cert.sh first."; exit 1; }
[ -f "$OUT/wrong_key.pem" ]     || { log "ERROR: Run issue_cert.sh first."; exit 1; }

if ! command -v evmctl &>/dev/null; then
    log "ERROR: evmctl not found."
    log "Install: dnf install ima-evm-utils  (Fedora)"
    log "         apt install ima-evm-utils  (Debian/Ubuntu)"
    exit 1
fi

if [ ! -d /sys/kernel/security/ima ]; then
    log "ERROR: /sys/kernel/security/ima not present."
    log "IMA is not enabled in this kernel (need CONFIG_IMA=y)."
    exit 2
fi

APPRAISE_MODE=$(cat /proc/cmdline | grep -o 'ima_appraise=[^ ]*' | cut -d= -f2 || echo "off")
log "Detected ima_appraise=$APPRAISE_MODE (from /proc/cmdline)"

# ── LABEL MODE (pass 1) ───────────────────────────────────────────────────────
if [ "$LABEL_MODE" = 1 ]; then
    log "=== Label pass (ima_appraise=fix recommended) ==="
    if [ "$APPRAISE_MODE" != "fix" ]; then
        warn "ima_appraise is '$APPRAISE_MODE', not 'fix'."
        warn "If ima_appraise=enforce is already active, labelling may be blocked."
        warn "Recommended: boot with ima_appraise=fix, then run --label."
        warn "Continuing anyway..."
        echo ""
    fi

    # Prepare the canonical test target (copy of /bin/true)
    cp /bin/true "$TARGET"
    chmod 755 "$TARGET"

    # Sign with the PyPKI leaf key
    log "Signing $TARGET with evmctl (sha256, key=$OUT/signing_key.pem)"
    evmctl ima_sign --key "$OUT/signing_key.pem" -a sha256 "$TARGET"

    # Verify the xattr was set
    XATTR=$(getfattr -m 'security\.ima' -d "$TARGET" 2>/dev/null || echo "")
    if [ -z "$XATTR" ]; then
        log "ERROR: security.ima xattr not set after evmctl."
        log "evmctl may require the filesystem to be mounted with user_xattr."
        exit 1
    fi
    log "  security.ima xattr: $(echo "$XATTR" | grep 'security.ima')"

    # Unsigned copy (no xattr) — for gate A2
    cp /bin/true "$OUT/test_target_unsigned"
    chmod 755 "$OUT/test_target_unsigned"
    log "  Unsigned copy: $OUT/test_target_unsigned"

    # Wrong-key signed copy — for gate A4
    cp /bin/true "$TARGET_WRONG"
    chmod 755 "$TARGET_WRONG"
    evmctl ima_sign --key "$OUT/wrong_key.pem" -a sha256 "$TARGET_WRONG"
    log "  Wrong-key signed: $TARGET_WRONG"

    # Tampered copy with the original sig (for gate A3 — hash mismatch)
    # Built at gate time, not here, to ensure freshness.

    echo ""
    log "Label pass complete."
    echo ""
    echo "  [SNAP] Snapshot the VM now."
    echo ""
    echo "  To enable enforcement, edit the grub boot entry:"
    echo "    1. Reboot, press 'e' at grub, append:  ima_appraise=enforce"
    echo "    2. Or permanently: add to GRUB_CMDLINE_LINUX in /etc/default/grub,"
    echo "       then: grub2-mkconfig -o /boot/grub2/grub.cfg"
    echo ""
    echo "  After rebooting into enforce mode, run: ./ima_roundtrip.sh"
    exit 0
fi

# ── GATE MODE (pass 2) ────────────────────────────────────────────────────────
log "=== Gate pass (ima_appraise=enforce required) ==="
echo ""

if [ "$APPRAISE_MODE" != "enforce" ]; then
    warn "ima_appraise is '$APPRAISE_MODE', not 'enforce'."
    warn "Gates A1–A4 may not produce enforcement behavior."
    warn "Boot with ima_appraise=enforce and re-run."
    warn "Continuing anyway (results will reflect actual kernel behavior)..."
    echo ""
fi

[ -f "$TARGET" ] || { log "ERROR: $TARGET not found. Run --label first."; exit 1; }
[ -f "$OUT/test_target_unsigned" ] || { log "ERROR: Unsigned control missing. Run --label first."; exit 1; }
[ -f "$TARGET_WRONG" ] || { log "ERROR: Wrong-key control missing. Run --label first."; exit 1; }

> "$GATE_FILE"

# Gate A1: execute the signed binary — should succeed
echo "--- Gate A1: exec signed binary ---"
MARK=$(dmesg | wc -l)
RC=0; "$TARGET" 2>/dev/null || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'ima|appraise|denied|eacces' | head -3 || echo "(no ima dmesg)")
if [ "$RC" = 0 ]; then
    gate A1 PASS "exit=0 (ran); IMA dmesg: $SNAP"
else
    gate A1 FAIL "exit=$RC (expected 0 — signed binary rejected); dmesg: $SNAP"
fi

# Gate A2: execute unsigned copy — should be EACCES / denied
echo "--- Gate A2: exec unsigned binary ---"
MARK=$(dmesg | wc -l)
RC=0; "$OUT/test_target_unsigned" 2>/dev/null || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'ima|appraise|denied|eacces' | head -3 || echo "(no ima dmesg)")
if [ "$RC" != 0 ]; then
    gate A2 PASS "exit=$RC (denied); dmesg: $SNAP"
else
    gate A2 FAIL "exit=0 — unsigned binary was NOT rejected. Is enforce mode active? dmesg: $SNAP"
fi

# Gate A3: tamper the signed binary (copy sig, change content) — should be denied
echo "--- Gate A3: exec tampered signed binary ---"
TAMPERED="$OUT/test_target_tampered"
cp "$TARGET" "$TAMPERED"
chmod 755 "$TAMPERED"
# Copy the original IMA sig xattr (so a sig IS present, but hash won't match)
if command -v getfattr &>/dev/null && command -v setfattr &>/dev/null; then
    getfattr -n security.ima --absolute-names "$TARGET" 2>/dev/null \
        | setfattr --restore=- 2>/dev/null || true
fi
# Corrupt one byte in the ELF body (past the header) so the sig's hash mismatches
python3 -c "
import sys
data = bytearray(open('$TAMPERED','rb').read())
data[64] ^= 0xFF  # flip a byte past the ELF magic
open('$TAMPERED','wb').write(data)
"
MARK=$(dmesg | wc -l)
RC=0; "$TAMPERED" 2>/dev/null || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'ima|appraise|hash|mismatch|denied' | head -3 || echo "(no ima dmesg)")
if [ "$RC" != 0 ]; then
    gate A3 PASS "exit=$RC (denied after tampering); dmesg: $SNAP"
else
    gate A3 FAIL "exit=0 — tampered binary ran. dmesg: $SNAP"
fi

# Gate A4: execute wrong-key signed binary — should be denied
echo "--- Gate A4: exec wrong-key signed binary ---"
MARK=$(dmesg | wc -l)
RC=0; "$TARGET_WRONG" 2>/dev/null || RC=$?
SNAP=$(dmesg_tail "$MARK" | grep -iE 'ima|key|trust|denied|eacces' | head -3 || echo "(no ima dmesg)")
if [ "$RC" != 0 ]; then
    gate A4 PASS "exit=$RC (denied — wrong key not trusted); dmesg: $SNAP"
else
    gate A4 FAIL "exit=0 — wrong-key binary executed. Wrong cert may be enrolled. dmesg: $SNAP"
fi

echo ""
log "=== Phase A gate summary ==="
cat "$GATE_FILE"
echo ""
log "Full results: $GATE_FILE"
log "Append to RESULTS.md once reviewed."
