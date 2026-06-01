"""
harness_crmf_popo.py — Fuzz the CRMF parse + POPO verify chain.

Targets:
  CMPv2ASN1.parse_crmf    — extract certreq_der, spki_der, popo_raw
  CMPv2ASN1.verify_popo   — signature verification on attacker-supplied key

parse_crmf is best-effort (partial dicts on failure). verify_popo is
load-bearing for security: bad POPO must be rejected, never accepted.
The fuzz goal is to confirm neither function hangs or panics; correctness
(false accept/reject) is tested by unit tests.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import types as _types
_ps_stub = _types.ModuleType("pki_server")
for _attr in ("CertificateAuthority", "AuditLog", "RateLimiter", "CertProfile",
              "ServerConfig", "DEFAULT_CONFIG"):
    setattr(_ps_stub, _attr, None)
sys.modules.setdefault("pki_server", _ps_stub)

from cmp_server import CMPv2ASN1


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    # --- parse_crmf ---
    result = CMPv2ASN1.parse_crmf(data)
    assert isinstance(result, dict)

    certreq_der = result.get("certreq_der")
    spki_der = result.get("spki")
    popo_raw = result.get("popo_raw")

    # --- verify_popo (only when parse yielded something to verify) ---
    if certreq_der and spki_der and popo_raw:
        try:
            ok, reason = CMPv2ASN1.verify_popo(certreq_der, spki_der, popo_raw)
            assert isinstance(ok, bool)
            assert isinstance(reason, str)
        except Exception:
            # Crypto failures, malformed SPKIs etc. are all acceptable.
            pass

    # Also call verify_popo with fully synthetic fuzz-controlled inputs to
    # exercise all three bytes independently.
    try:
        CMPv2ASN1.verify_popo(data, data, data)
    except Exception:
        pass


def _atheris_main() -> None:
    import atheris  # type: ignore
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    try:
        import atheris  # type: ignore
        _atheris_main()
    except ImportError:
        from _stdlib_runner import run
        corpus_dir = Path(__file__).parent / "corpus" / "crmf_popo"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
