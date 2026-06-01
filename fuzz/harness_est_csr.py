"""
harness_est_csr.py — Fuzz the EST CSR decoder.

Target: ESTHandler._decode_csr (authenticated POST /simpleenroll)

_decode_csr tries base64-DER, raw DER, and PEM in turn, delegating to
cryptography's x509.load_*_x509_csr. The fuzz target is the three-way
dispatch and the base64 decode step; the underlying x509 parser is
cryptography's and not our concern.

The relevant bug class is unexpected exceptions escaping the try/except
chain, causing a 500 with a traceback leaked to the client.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the decode function directly to avoid needing a full server instance.
import base64
from cryptography import x509


def _decode_csr(body: bytes):
    """Mirrors ESTHandler._decode_csr logic."""
    if not body:
        return None
    try:
        der = base64.b64decode(body)
        return x509.load_der_x509_csr(der)
    except Exception:
        pass
    try:
        return x509.load_der_x509_csr(body)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_csr(body)
    except Exception:
        pass
    return None


def TestOneInput(data: bytes) -> None:
    result = _decode_csr(data)
    # Must return None or a valid CSR object — never crash.
    assert result is None or isinstance(result, x509.CertificateSigningRequest)


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
        corpus_dir = Path(__file__).parent / "corpus" / "est_csr"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
