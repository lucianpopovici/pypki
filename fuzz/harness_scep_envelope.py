"""
harness_scep_envelope.py — Fuzz the SCEP CMS envelope parser.

Targets:
  CMSParser.parse_signed_data   — anonymous public POST surface
  CMSParser.parse_enveloped_data — called on decrypted inner content

Both are called with attacker-controlled bytes on every SCEP enrollment
request. The parsers use try/except internally but must not infinite-loop
or recurse unboundedly on adversarial length fields.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scep_server import CMSParser


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    # --- parse_signed_data ---
    # Returns a dict (possibly with "parse_error" key). Should never crash.
    result = CMSParser.parse_signed_data(data)
    assert isinstance(result, dict)

    # If we got certificates out, they should be bytes objects.
    certs = result.get("certificates", [])
    assert isinstance(certs, list)
    for c in certs:
        assert isinstance(c, (bytes, bytearray))

    # --- parse_enveloped_data ---
    # Needs a private key; pass a dummy so the decryption attempt fails
    # gracefully without hanging on crypto.  The target here is the
    # ASN.1 parsing layer before the crypto call.
    try:
        CMSParser.parse_enveloped_data(data, _DUMMY_KEY)
    except Exception:
        # Any exception from crypto or ASN.1 parsing is acceptable.
        pass


# Minimal RSA key for the decrypt-path parsing (crypto will fail, that's fine).
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    _DUMMY_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
except Exception:
    _DUMMY_KEY = None  # type: ignore[assignment]


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
        corpus_dir = Path(__file__).parent / "corpus" / "scep_envelope"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
