#!/usr/bin/env bash
# verify_reproducibility.sh — Verify that two builds of the same commit
# produce bit-identical pypki-main.zip artifacts.
#
# This script runs build_release.sh twice in /tmp and compares the SHA-256.
# A difference means some non-determinism (timestamp, ordering, etc.) crept
# in. diffoscope is invoked on failure for human-readable diagnostics.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

BUILD1="$(mktemp -d)"
BUILD2="$(mktemp -d)"

cleanup() {
    rm -rf "$BUILD1" "$BUILD2"
}
trap cleanup EXIT

echo "==> Build 1 (epoch=$SOURCE_DATE_EPOCH)..."
cp -r "$REPO/." "$BUILD1/"
(cd "$BUILD1" && bash scripts/build_release.sh 2>&1 | sed 's/^/  /')
SHA1=$(sha256sum "$BUILD1/pypki-main.zip" | cut -d' ' -f1)
echo "  SHA-256: $SHA1"

echo ""
echo "==> Build 2..."
cp -r "$REPO/." "$BUILD2/"
(cd "$BUILD2" && bash scripts/build_release.sh 2>&1 | sed 's/^/  /')
SHA2=$(sha256sum "$BUILD2/pypki-main.zip" | cut -d' ' -f1)
echo "  SHA-256: $SHA2"

echo ""
if [[ "$SHA1" == "$SHA2" ]]; then
    echo "==> REPRODUCIBLE: both builds produced identical artifacts."
    exit 0
else
    echo "==> FAIL: builds differ!"
    echo "  Build 1: $SHA1"
    echo "  Build 2: $SHA2"
    if command -v diffoscope &>/dev/null; then
        echo ""
        echo "==> diffoscope output:"
        diffoscope "$BUILD1/pypki-main.zip" "$BUILD2/pypki-main.zip" || true
    else
        echo "  (Install diffoscope for detailed diff: apt install diffoscope)"
    fi
    exit 1
fi
