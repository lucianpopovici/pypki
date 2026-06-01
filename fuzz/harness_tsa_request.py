"""
harness_tsa_request.py — Fuzz the TSA TimeStampReq parser.

Target: TSARequestParser.parse (anonymous public POST to /tsa)

TimeStampReq is a publicly accessible endpoint. The parser returns None on
failure, but adversarial inputs can trigger edge cases in the optional-field
walk loop (policy OID, nonce, certReq), malformed messageImprint hashes, and
deeply nested AlgorithmIdentifier sequences.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tsa_server import TSARequestParser


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    result = TSARequestParser.parse(data)
    # Must return None or a dict — never an unhandled exception.
    assert result is None or isinstance(result, dict)

    if isinstance(result, dict):
        version = result.get("version")
        assert version is None or isinstance(version, int)
        nonce = result.get("nonce")
        assert nonce is None or isinstance(nonce, int)
        cert_req = result.get("cert_req")
        assert cert_req is None or isinstance(cert_req, bool)
        imprint = result.get("imprint")
        assert imprint is None or isinstance(imprint, (bytes, bytearray))


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
        corpus_dir = Path(__file__).parent / "corpus" / "tsa_request"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
