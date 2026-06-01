"""
harness_ocsp_request.py — Fuzz the OCSP request parser.

Target: OCSPRequestParser.parse (anonymous public GET/POST)

The OCSP endpoint is fully public and high-frequency on deployed CAs.
The parser returns None on failure, but adversarial length fields,
malformed CertID structures, and oversized nonce extensions all need
to be handled without hanging or crashing.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ocsp_server import OCSPRequestParser


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    result = OCSPRequestParser.parse(data)
    # Must return None or a dict — never an unhandled exception.
    assert result is None or isinstance(result, dict)

    if isinstance(result, dict):
        # Structural invariants on a successful parse.
        serial = result.get("serial")
        assert serial is None or isinstance(serial, int)
        nonce = result.get("nonce")
        assert nonce is None or isinstance(nonce, (bytes, bytearray))
        # Nonce length must be within RFC 8954 bounds if present and valid.
        if nonce is not None and not result.get("nonce_length_violation"):
            assert 1 <= len(nonce) <= 32, f"nonce length {len(nonce)} out of bounds"


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
        corpus_dir = Path(__file__).parent / "corpus" / "ocsp_request"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
