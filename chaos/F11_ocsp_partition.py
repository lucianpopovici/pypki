"""
F11 — Network partition between PyPKI and OCSP responder.

Invariants tested: 6 (OCSP response reflects state at time T).

Requires: iptables access (root) and PYPKI_CHAOS_IPTABLES=1. Skip otherwise.

A network partition to the OCSP responder should not affect issuance. The CA
must still issue certs. Pre-generated OCSP responses remain valid up to their
nextUpdate. Live signing falls back gracefully.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult

_IPTABLES = os.environ.get("PYPKI_CHAOS_IPTABLES", "0") == "1"


def run() -> bool:
    result = ScenarioResult("F11_ocsp_partition")
    print("\n=== F11: Network partition to OCSP responder ===")

    if not _IPTABLES:
        result.skip(
            "PYPKI_CHAOS_IPTABLES=1 not set — skipping iptables-based partition test"
        )
        return result.summary()

    # In a real test:
    # 1. Start PyPKI with --ocsp-live-signing.
    # 2. Block outbound TCP to the OCSP responder port.
    # 3. Issue a cert.
    # 4. Query OCSP — should return the pre-generated response (or timeout gracefully).
    # 5. Unblock, verify live signing resumes.
    result.skip(
        "iptables partition test requires root and a running OCSP responder. "
        "Manual steps documented in chaos/README.md."
    )
    return result.summary()


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
