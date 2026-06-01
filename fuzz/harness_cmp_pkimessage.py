"""
harness_cmp_pkimessage.py — Fuzz the CMP PKIMessage parser.

Targets:
  CMPv2ASN1.parse_pki_message   — anonymous public POST surface
  CMPv2ASN1._parse_pki_header   — called internally by parse_pki_message

The CMP endpoint is publicly reachable (RFC 4210). Adversarial PKIMessage
blobs with malformed context tags, oversized lengths, or deeply nested
optional fields are the expected attack surface.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# cmp_server imports pki_server at module level (circular). Stub it out so
# we can load CMPv2ASN1 without starting a full CA instance.
import unittest.mock as _mock
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

    # parse_pki_message swallows exceptions via try/except; should always
    # return a dict (possibly with "parse_error" key).
    result = CMPv2ASN1.parse_pki_message(data)
    assert isinstance(result, dict), f"expected dict, got {type(result)}"

    # Verify structural invariants on the returned dict.
    assert "header" in result
    assert isinstance(result["header"], dict)
    body_raw = result.get("body_raw")
    assert body_raw is None or isinstance(body_raw, (bytes, bytearray))


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
        corpus_dir = Path(__file__).parent / "corpus" / "cmp_pkimessage"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
