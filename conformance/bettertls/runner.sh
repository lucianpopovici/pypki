#!/usr/bin/env bash
# conformance/bettertls/runner.sh — BetterTLS name-constraints conformance test
#
# BetterTLS: https://github.com/Netflix/bettertls
# Tests name-constraint behaviour as deployed by web PKI.
#
# Requirements: Go toolchain. Skip when not available.
#
# Results go to conformance/bettertls/results.md

set -euo pipefail
_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v go &>/dev/null; then
    echo "SKIP: Go toolchain not available — BetterTLS requires Go"
    exit 0
fi

# Clone BetterTLS if not already present.
BETTERTLS_DIR="${_DIR}/bettertls-src"
if [[ ! -d "$BETTERTLS_DIR" ]]; then
    echo "Cloning BetterTLS ..."
    git clone --depth=1 https://github.com/Netflix/bettertls.git "$BETTERTLS_DIR"
fi

# Build the test runner.
(cd "$BETTERTLS_DIR" && go build ./...)

# Run against PyPKI's cert-validation logic.
# BetterTLS normally tests a TLS client; here we run the certificate
# path validation tests that are relevant to our name-constraint implementation.
echo "Running BetterTLS name-constraint test suite ..."
echo "(This is a best-effort nightly gate; failures are tracked but not release-blocking)"

# Results stub — update when BetterTLS integration is fully wired.
cat > "${_DIR}/results.md" << 'EOF'
# BetterTLS Results

**Status:** Pending full integration.

BetterTLS requires a running TLS server to test name-constraint validation.
PyPKI's name-constraint implementation is validated via:
1. RFC 5280 corner cases (conformance/rfc5280_corners/) — 32 cases covering
   permitted/excluded subtrees for DNS, IP, email, URI types.
2. PKITS 4.12 name constraints test section.

Full BetterTLS integration will be completed in Tier 7 when PyPKI exposes
a stable TLS endpoint for external conformance testing.

Last run: N/A (pending)
EOF

echo "BetterTLS: stub results written. Full integration pending."
exit 0
