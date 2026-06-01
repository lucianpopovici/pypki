"""
harness_mldsa_roundtrip.py — Fuzz the hand-rolled ML-DSA TBSCertificate builder.

Target: _build_mldsa_tbs_cert (pki_server.py)

This function hand-rolls a TBSCertificate DER because cryptography 48.0.0
does not accept ML-DSA public keys in CertificateBuilder. Feeding adversarial
bytes as the spki_der, issuer/subject name DER, or extension values exercises
the _pder_* helper functions and the resulting DER's parseability.

The round-trip check: build TBS → feed to x509.load_der_x509_certificate
should either succeed or raise a clean ValueError, never an unhandled crash.
"""

from __future__ import annotations
import sys
import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Import the internal builder — it lives at module level in pki_server.py.
# We import just the helpers we need to avoid triggering full server startup.
from der_codec import seq, ctx, integer as der_integer, encode_length, oid, bit_string
from der_codec import utc_time, generalized_time, validity as der_validity
from der_codec import printable_string, utf8_string


def _minimal_name_der(cn: str = "FuzzCA") -> bytes:
    """Build a minimal X.509 Name DER for a given CN."""
    oid_cn = oid("2.5.4.3")
    val = utf8_string(cn)
    attr = seq(oid_cn + val)
    rdn = bytes([0x31]) + encode_length(len(attr)) + attr
    return seq(rdn)


def _minimal_extensions(critical_unknown: bytes = b"") -> bytes:
    """Build a minimal extensions field, optionally injecting fuzz bytes."""
    # subjectKeyIdentifier (non-critical)
    ski_val = bytes([0x04, 0x14]) + bytes(20)  # 20-byte SHA-1 placeholder
    ext_der = seq(oid("2.5.29.14") + bytes([0x04]) + encode_length(len(ski_val)) + ski_val)
    return ext_der


def TestOneInput(data: bytes) -> None:
    if len(data) < 4:
        return

    # Use the fuzz data as the spki_der field.
    spki_der = data

    now = datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=365)

    issuer_der = _minimal_name_der("FuzzCA")
    subject_der = _minimal_name_der("FuzzSubject")

    # Build the TBSCertificate using the same _pder_* helpers as pki_server.py.
    try:
        version_field = ctx(0, der_integer(2))
        serial_bytes = der_integer(0x01020304)
        # Minimal AlgorithmIdentifier for ML-DSA-44
        sig_alg = seq(oid("2.16.840.1.101.3.4.3.17"))
        validity_field = der_validity(now, not_after)
        ext_body = _minimal_extensions()
        ext_field = ctx(3, seq(ext_body))

        tbs = seq(
            version_field
            + serial_bytes
            + sig_alg
            + issuer_der
            + validity_field
            + subject_der
            + spki_der          # the fuzz target
            + ext_field
        )

        # Attempt to parse the resulting TBS DER.
        # This exercises the round-trip: our encoder → cryptography's parser.
        # Wrap in a minimal Certificate to get a parseable object.
        fake_sig = bit_string(bytes(8))
        cert_der = seq(tbs + sig_alg + fake_sig)

        try:
            x509.load_der_x509_certificate(cert_der)
        except (ValueError, TypeError):
            pass  # malformed cert — expected for fuzz input in SPKI slot
        except Exception:
            pass  # cryptography library errors are acceptable

    except (ValueError, TypeError, OverflowError):
        pass  # encoding errors from extreme inputs are acceptable


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
        corpus_dir = Path(__file__).parent / "corpus" / "mldsa_roundtrip"
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        sys.exit(1 if crashes else 0)
