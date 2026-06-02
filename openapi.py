#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
OpenAPI 3.0 spec loader and drift validator for PyPKI.

Serves docs/openapi.json at GET /api/openapi.json.
At startup (when validate=True), warns about spec paths that have no
corresponding handler and vice versa — keeps spec honest without
requiring a full router registry.

No pip dependencies; stdlib only.
"""

import json
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("pypki.openapi")

_SPEC_FILE = Path(__file__).parent / "docs" / "openapi.json"
_spec_cache: Optional[dict] = None


def load_spec() -> dict:
    """Load and cache the OpenAPI spec from docs/openapi.json."""
    global _spec_cache
    if _spec_cache is None:
        if not _SPEC_FILE.exists():
            raise FileNotFoundError(f"OpenAPI spec not found: {_SPEC_FILE}")
        _spec_cache = json.loads(_SPEC_FILE.read_text())
    return _spec_cache


def spec_json() -> str:
    """Return the spec as a compact JSON string."""
    return json.dumps(load_spec(), separators=(",", ":"))


def spec_json_pretty() -> str:
    """Return the spec as a pretty-printed JSON string."""
    return json.dumps(load_spec(), indent=2)


def get_spec_paths() -> set:
    """Return the set of path keys in the spec (e.g. '/api/certs/{serial}')."""
    return set(load_spec().get("paths", {}).keys())


# Known handler paths for drift checking (human-maintained, not auto-derived)
_KNOWN_HANDLER_PATHS = {
    "/api/health",
    "/api/version",
    "/api/openapi.json",
    "/api/certs",
    "/api/certs/{serial}",
    "/api/certs/{serial}/pem",
    "/api/certs/{serial}/p12",
    "/api/issue",
    "/api/revoke",
    "/api/renew",
    "/api/config",
    "/api/audit",
    "/api/metrics",
    "/api/issue-sub-ca",
    "/api/cross-sign",
    "/api/paired-issue",
    "/api/composite-issue",
    "/api/slh-dsa-issue",
    "/api/agility/summary",
    "/api/agility/breakdown",
    "/api/agility/migration-forecast",
    "/api/agility/csr-demand",
    "/api/ssh/sign",
    "/api/ssh/host-cert",
    "/api/ssh/certs",
    "/api/ssh/known-hosts",
    "/api/ssh/krl/{fingerprint}",
    "/api/wg/peers",
    "/api/wg/peers/{peer_id}/revoke",
    "/api/wg/servers",
    "/api/wg/server-config/{server_id}",
    "/api/matter/dac",
    "/api/matter/dac/bulk",
    "/api/matter/pai",
    "/api/matter/authorities",
    "/api/matter/dacs",
    "/api/acme/eab/mint",
    "/api/acme/eab/revoke/{kid}",
    "/api/acme/eab/keys",
    "/api/scep/otp",
    "/api/services",
    "/api/services/{name}/start",
    "/api/services/{name}/stop",
    "/api/ra/approve/{id}",
    "/api/ra/deny/{id}",
    "/ca/cert.pem",
    "/ca/crl",
}


def check_drift() -> tuple[set, set]:
    """
    Return (undocumented, unimplemented) path sets.

    undocumented: paths with handlers but no spec entry (spec is incomplete)
    unimplemented: spec paths with no known handler (spec has phantom entries)
    """
    spec_paths  = get_spec_paths()
    handler_paths = _KNOWN_HANDLER_PATHS
    undocumented   = handler_paths - spec_paths
    unimplemented  = spec_paths - handler_paths
    return undocumented, unimplemented


def validate_and_warn() -> None:
    """Log warnings for any spec/handler drift."""
    try:
        undocumented, unimplemented = check_drift()
        if undocumented:
            log.warning(
                "OpenAPI drift: %d handler path(s) not in spec: %s",
                len(undocumented), sorted(undocumented),
            )
        if unimplemented:
            log.warning(
                "OpenAPI drift: %d spec path(s) with no known handler: %s",
                len(unimplemented), sorted(unimplemented),
            )
        if not undocumented and not unimplemented:
            log.debug("OpenAPI spec: no drift detected")
    except Exception as exc:
        log.warning("OpenAPI drift check failed: %s", exc)
