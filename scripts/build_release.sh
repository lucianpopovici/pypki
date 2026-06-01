#!/usr/bin/env bash
# build_release.sh — Produce a reproducible pypki-main.zip release artifact.
#
# Reproducibility requirements:
#   - SOURCE_DATE_EPOCH must be set (set to the git tag's commit timestamp).
#   - File ordering is deterministic (sorted).
#   - No .pyc files included.
#   - Permissions normalized to 0644 (files) / 0755 (scripts).
#
# Usage:
#   export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
#   ./scripts/build_release.sh
#
# Output: pypki-main.zip (in the repo root)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    echo "ERROR: SOURCE_DATE_EPOCH is not set."
    echo "  Run: export SOURCE_DATE_EPOCH=\$(git log -1 --format=%ct)"
    exit 1
fi

VERSION="$(git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)"
OUTFILE="$REPO/pypki-main.zip"

echo "==> Building pypki-main.zip (version=$VERSION epoch=$SOURCE_DATE_EPOCH)"

# Collect files to include (sorted for determinism).
# Exclude: .pyc, __pycache__, test files, fuzz/chaos/bench/docs, .git
INCLUDE_PATTERNS=(
    "*.py"
    "der_codec.py"
    "requirements.txt"
)

# Gather source files, excluding dev/test artifacts.
mapfile -t FILES < <(
    find . -name "*.py" \
        ! -name "test_*.py" \
        ! -name "get_cert.py" \
        ! -path "./.git/*" \
        ! -path "./fuzz/*" \
        ! -path "./chaos/*" \
        ! -path "./bench/*" \
        ! -path "./interop/*" \
        ! -path "./conformance/*" \
        ! -path "./__pycache__/*" \
        -type f \
    | sort
)
FILES+=(requirements.txt)

# Write the zip with deterministic mtime and permissions.
python3 - <<PYEOF
import zipfile, os, stat, time

source_date = int(os.environ["SOURCE_DATE_EPOCH"])
mtime = time.gmtime(source_date)[:6]

files = """$(printf '%s\n' "${FILES[@]}")""".strip().split('\n')

with zipfile.ZipFile("$OUTFILE", "w", compression=zipfile.ZIP_DEFLATED,
                     strict_timestamps=False) as zf:
    for f in sorted(set(files)):
        if not os.path.exists(f):
            continue
        info = zipfile.ZipInfo(f.lstrip('./'), date_time=mtime)
        # Normalize permissions
        if f.endswith('.sh') or os.access(f, os.X_OK):
            info.external_attr = (0o755 << 16) | 0o20
        else:
            info.external_attr = (0o644 << 16) | 0o20
        with open(f, 'rb') as fh:
            zf.writestr(info, fh.read())

print(f"Created {len(files)} files in pypki-main.zip")
PYEOF

SHA=$(sha256sum "$OUTFILE" | cut -d' ' -f1)
echo "==> pypki-main.zip SHA-256: $SHA"
echo "$SHA  pypki-main.zip" > pypki-main.zip.sha256
echo "==> Done: $OUTFILE"
