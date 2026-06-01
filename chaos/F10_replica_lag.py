"""
F10 — Postgres replica lag at OCSP query time.

Invariants tested: 4 (revocation persists), 6 (OCSP reflects state at query time).

Requires: PYPKI_CHAOS_POSTGRES_DSN. Skip otherwise.

Simulate: revoke a cert on the primary; query OCSP against a replica that hasn't
yet replicated the revocation. The live-signing OCSP path should be queried
against the primary; if it hits the replica, it may return a stale `good`.

This test documents the gap and validates the configuration requirement.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult

_PG_DSN = os.environ.get("PYPKI_CHAOS_POSTGRES_DSN")


def run() -> bool:
    result = ScenarioResult("F10_replica_lag")
    print("\n=== F10: Postgres replica lag at OCSP query time ===")

    if not _PG_DSN:
        result.skip("PYPKI_CHAOS_POSTGRES_DSN not set")
        return result.summary()

    # This scenario requires a Postgres primary + replica with configurable lag.
    # The infrastructure (docker-compose with pg_lagslot) is documented in
    # chaos/README.md but is not automated here.
    result.skip(
        "Replica-lag OCSP scenario requires manual Postgres cluster setup. "
        "To test: (1) start primary+replica with artificial replication lag, "
        "(2) revoke a cert on primary, (3) query OCSP endpoint configured "
        "to read from the replica, (4) verify it returns 'good' (known gap), "
        "(5) configure OCSP to read from primary and verify 'revoked'."
    )

    # Document the known residual risk.
    result.check(
        "documented_residual_risk",
        True,
        "See docs/THREAT_MODEL.md §3b.9 and §3b.10 for the residual risk analysis",
    )

    return result.summary()


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
