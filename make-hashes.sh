#!/usr/bin/env bash
# Regenerate hash-pinned requirements files from .in sources.
# Run after any change to requirements.in or requirements-dev.in.
#
# Requires: pip install pip-tools
#
# Usage:
#   ./make-hashes.sh           # regenerate both files
#   ./make-hashes.sh runtime   # regenerate requirements.txt only
#   ./make-hashes.sh dev       # regenerate requirements-dev.txt only

set -euo pipefail

if ! command -v pip-compile &>/dev/null; then
    echo "pip-compile not found. Install with: pip install pip-tools"
    exit 1
fi

TARGET="${1:-all}"

if [[ "$TARGET" == "all" || "$TARGET" == "runtime" ]]; then
    echo "Compiling requirements.txt ..."
    pip-compile requirements.in \
        --generate-hashes \
        --no-header \
        --annotation-style line \
        -o requirements.txt
    echo "  -> requirements.txt updated"
fi

if [[ "$TARGET" == "all" || "$TARGET" == "dev" ]]; then
    echo "Compiling requirements-dev.txt ..."
    pip-compile requirements-dev.in \
        --generate-hashes \
        --no-header \
        --annotation-style line \
        -o requirements-dev.txt
    echo "  -> requirements-dev.txt updated"
fi

echo "Done. Verify with: pip install --require-hashes -r requirements.txt"
