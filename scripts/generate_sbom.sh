#!/usr/bin/env bash
# generate_sbom.sh — Generate a CycloneDX SBOM for a release.
#
# Requires cyclonedx-bom (dev dep: pip install cyclonedx-bom).
# Output is written to stdout (suitable for redirect to pypki-sbom.cdx.json).
#
# Usage:
#   ./scripts/generate_sbom.sh > pypki-sbom.cdx.json
#   ./scripts/generate_sbom.sh --out pypki-sbom.cdx.json
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        *)     echo "Unknown option: $1"; exit 1 ;;
    esac
done

VERSION="$(git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)"

if ! python3 -c "import cyclonedx" 2>/dev/null; then
    echo "ERROR: cyclonedx-bom not installed. Run: pip install cyclonedx-bom" >&2
    exit 1
fi

CMD=(
    python3 -m cyclonedx_py
    environment
    --short-PURLs
    --output-format json
)

if [[ -n "$OUT" ]]; then
    "${CMD[@]}" --output-file "$OUT"
    echo "==> SBOM written to $OUT" >&2

    # Embed project metadata (component name + version).
    python3 - "$OUT" "$VERSION" <<'PYEOF'
import json, sys
path, version = sys.argv[1], sys.argv[2]
with open(path) as f:
    sbom = json.load(f)
sbom.setdefault("metadata", {}).setdefault("component", {}).update({
    "type": "application",
    "name": "pypki",
    "version": version,
})
with open(path, "w") as f:
    json.dump(sbom, f, indent=2)
PYEOF
else
    "${CMD[@]}"
fi
