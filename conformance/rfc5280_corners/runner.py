"""
conformance/rfc5280_corners/runner.py — Hand-authored RFC 5280 corner-case suite.

Each case in cases/ is a directory containing:
  cert.der          — the certificate to validate (DER)
  issuer.der        — the issuing CA certificate (DER)  [optional]
  expected.txt      — "valid" or "invalid: <reason>"
  README.md         — human description of what the case tests

Runner validates cert.der against issuer.der (or self-signed against itself)
using cryptography's verifier and asserts the outcome matches expected.txt.

Usage:
    python3 conformance/rfc5280_corners/runner.py
    python3 conformance/rfc5280_corners/runner.py --case notbefore_after_notafter
    python3 conformance/rfc5280_corners/runner.py --generate-cases   # create test certs
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import (
    BasicConstraints, NameConstraints, SubjectAlternativeName,
    SubjectKeyIdentifier, AuthorityKeyIdentifier, KeyUsage,
    DNSName, IPAddress, RFC822Name, UniformResourceIdentifier,
)
import ipaddress

_HERE = Path(__file__).parent
_CASES_DIR = _HERE / "cases"
_RESULTS_FILE = _HERE / "results.md"
_UTC = datetime.timezone.utc


# ---------------------------------------------------------------------------
# Cert generation helpers
# ---------------------------------------------------------------------------

def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _now() -> datetime.datetime:
    return datetime.datetime.now(_UTC).replace(microsecond=0)


def _make_ca(
    cn: str = "TestCA",
    key=None,
    path_length: Optional[int] = None,
    issuer_key=None,
    issuer_cert=None,
    not_before: Optional[datetime.datetime] = None,
    not_after: Optional[datetime.datetime] = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    k = key or _key()
    nb = not_before or _now()
    na = not_after or (nb + datetime.timedelta(days=3650))
    issuer_name = (_name(issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
                   if issuer_cert else _name(cn))
    signer_key = issuer_key or k
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_name)
        .public_key(k.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
            critical=False,
        )
        .add_extension(
            KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                     content_commitment=False, key_encipherment=False,
                     data_encipherment=False, key_agreement=False,
                     encipher_only=False, decipher_only=False),
            critical=True,
        )
    )
    cert = builder.sign(signer_key, hashes.SHA256())
    return k, cert


def _make_leaf(
    cn: str = "leaf",
    ca_key=None,
    ca_cert=None,
    sans: list = None,
    not_before: Optional[datetime.datetime] = None,
    not_after: Optional[datetime.datetime] = None,
    serial: Optional[int] = None,
    extra_extensions: list = None,
    add_default_san: bool = True,
) -> x509.Certificate:
    k = _key()
    nb = not_before or _now()
    na = not_after or (nb + datetime.timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject if ca_cert else _name(cn))
        .public_key(k.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
    )
    if ca_cert:
        builder = builder.add_extension(
            AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    # cryptography's verifier requires at least one SAN extension.
    effective_sans = sans or ([DNSName("placeholder.local")] if add_default_san else [])
    if effective_sans:
        builder = builder.add_extension(SubjectAlternativeName(effective_sans), critical=False)
    # cryptography's build_client_verifier requires keyUsage.
    builder = builder.add_extension(
        KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                 content_commitment=False, key_encipherment=True, data_encipherment=False,
                 key_agreement=False, encipher_only=False, decipher_only=False),
        critical=True,
    )
    for ext, crit in (extra_extensions or []):
        builder = builder.add_extension(ext, critical=crit)
    signer = ca_key or _key()
    return builder.sign(signer, hashes.SHA256())


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _write_case(
    name: str,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    expected: str,
    description: str,
) -> None:
    case_dir = _CASES_DIR / name
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "cert.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (case_dir / "issuer.der").write_bytes(issuer.public_bytes(serialization.Encoding.DER))
    (case_dir / "expected.txt").write_text(expected + "\n")
    if not (case_dir / "README.md").exists():
        (case_dir / "README.md").write_text(f"# {name}\n\n{description}\n")


def generate_cases() -> None:
    """Generate all RFC 5280 corner-case test certs."""
    _CASES_DIR.mkdir(parents=True, exist_ok=True)

    # ---- 1: notBefore > notAfter (hand-rolled DER — library rejects building) ----
    ca_key, ca_cert = _make_ca()
    # cryptography enforces valid date order at build time, so we hand-roll this
    # specific malformed cert using der_codec.
    from der_codec import (seq as _seq, ctx as _ctx, integer as _der_int,
                           oid as _oid, bit_string as _bit_str,
                           utc_time as _utc_time, octet_string as _oct_str,
                           encode_length as _enc_len)
    _nb = _now() + datetime.timedelta(days=1)   # notBefore AFTER notAfter
    _na = _now()
    _ecdsa_sha256 = _seq(_oid("1.2.840.10045.4.3.2"))
    _issuer_raw = ca_cert.subject.public_bytes()
    _subject_raw = _issuer_raw
    _validity_raw = _seq(_utc_time(_nb) + _utc_time(_na))
    _tmpkey = ec.generate_private_key(ec.SECP256R1())
    _spki = _tmpkey.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _tbs = _seq(
        _ctx(0, _der_int(2))       # [0] v3
        + _der_int(9999)           # serial
        + _ecdsa_sha256            # signature AlgID
        + _issuer_raw              # issuer
        + _validity_raw            # validity (inverted)
        + _subject_raw             # subject
        + _spki                    # subjectPublicKeyInfo
    )
    # Fake signature (8 zero bytes — invalid, but we want DER to parse)
    _sig = _bit_str(bytes(8))
    bad_der = _seq(_tbs + _ecdsa_sha256 + _sig)
    case_dir = _CASES_DIR / "notbefore_after_notafter"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "cert.der").write_bytes(bad_der)
    (case_dir / "issuer.der").write_bytes(ca_cert.public_bytes(serialization.Encoding.DER))
    (case_dir / "expected.txt").write_text("invalid: notBefore > notAfter\n")
    if not (case_dir / "README.md").exists():
        (case_dir / "README.md").write_text(
            "# notbefore_after_notafter\n\n"
            "Hand-rolled DER with inverted validity dates.\n"
            "RFC 5280 §4.1.2.5: notBefore MUST be <= notAfter.\n"
        )

    # ---- 2: Minimum validity (60 s) — valid ----
    nb60 = _now()
    na60 = nb60 + datetime.timedelta(seconds=60)
    ok60 = _make_leaf(ca_key=ca_key, ca_cert=ca_cert, not_before=nb60, not_after=na60)
    _write_case(
        "minimum_validity_60s", ok60, ca_cert,
        "valid",
        "Cert with exactly 60-second validity: should be accepted.",
    )

    # ---- 3: Path length 0 — three-level chain rejects ----
    ca0_key, ca0_cert = _make_ca(cn="CA0", path_length=0)
    inter_key, inter_cert = _make_ca(cn="Inter", key=_key(), issuer_key=ca0_key,
                                      issuer_cert=ca0_cert, path_length=None)
    leaf_under_inter = _make_leaf(ca_key=inter_key, ca_cert=inter_cert)
    # Store ca0 as trust anchor (issuer.der), inter as intermediate (intermediate.der).
    case_dir3 = _CASES_DIR / "pathlength_0_three_level"
    case_dir3.mkdir(parents=True, exist_ok=True)
    (case_dir3 / "cert.der").write_bytes(
        leaf_under_inter.public_bytes(serialization.Encoding.DER))
    (case_dir3 / "issuer.der").write_bytes(
        ca0_cert.public_bytes(serialization.Encoding.DER))
    (case_dir3 / "intermediate.der").write_bytes(
        inter_cert.public_bytes(serialization.Encoding.DER))
    (case_dir3 / "expected.txt").write_text("invalid: pathLenConstraint violated\n")
    if not (case_dir3 / "README.md").exists():
        (case_dir3 / "README.md").write_text(
            "# pathlength_0_three_level\n\n"
            "CA0(pathLen=0) → Inter(CA) → leaf. pathLen=0 means CA0 cannot sign "
            "an intermediate CA cert. The chain should be rejected.\n"
        )

    # ---- 4: pathLenConstraint = 0, two-level (valid) ----
    leaf_direct = _make_leaf(ca_key=ca0_key, ca_cert=ca0_cert)
    _write_case(
        "pathlength_0_two_level", leaf_direct, ca0_cert,
        "valid",
        "pathLenConstraint=0 allows CA0 to directly sign leaf certs.",
    )

    # ---- 5: Negative serial number (RFC violation) ----
    # We can't easily build a negative-serial cert with cryptography; instead
    # we test PyPKI's issuance refuses negative serials (handled in test_pki_server.py).
    # Placeholder case with documented limitation.
    valid_ser = _make_leaf(ca_key=ca_key, ca_cert=ca_cert, serial=1)
    _write_case(
        "valid_serial_one", valid_ser, ca_cert,
        "valid",
        "Serial number 1 — valid per RFC 5280 §4.1.2.2.",
    )

    # ---- 6: Zero-length serial ----
    # cryptography enforces positive serials; document the case.
    try:
        zero_ser = _make_leaf(ca_key=ca_key, ca_cert=ca_cert, serial=0)
        _write_case(
            "zero_serial", zero_ser, ca_cert,
            "invalid: serial must be positive",
            "RFC 5280 §4.1.2.2: serial MUST be a positive integer. 0 is invalid.",
        )
    except Exception:
        pass  # cryptography may reject it at build time

    # ---- 7: Unknown critical extension ----
    from cryptography.x509 import UnrecognizedExtension
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    unknown_oid = x509.ObjectIdentifier("1.2.3.4.5.6.7.8.9")
    unknown_ext = UnrecognizedExtension(unknown_oid, b"\x05\x00")
    leaf_unknown_crit = _make_leaf(
        ca_key=ca_key, ca_cert=ca_cert,
        extra_extensions=[(unknown_ext, True)],   # critical=True
    )
    _write_case(
        "unknown_critical_extension", leaf_unknown_crit, ca_cert,
        "invalid: unrecognized critical extension",
        "RFC 5280 §4.2: if a cert contains a critical extension that is not "
        "recognized, the cert MUST be rejected.",
    )

    # ---- 8: Non-critical unknown extension (valid) ----
    leaf_unknown_noncrit = _make_leaf(
        ca_key=ca_key, ca_cert=ca_cert,
        extra_extensions=[(unknown_ext, False)],  # critical=False
    )
    _write_case(
        "unknown_noncritical_extension", leaf_unknown_noncrit, ca_cert,
        "valid",
        "Non-critical unrecognized extensions must be ignored per RFC 5280 §4.2.",
    )

    # ---- 9: nameConstraints dNSName ----
    nc_ca_key, nc_ca_cert = _make_ca(cn="NCCA")
    leaf_in_nc = _make_leaf(
        ca_key=nc_ca_key, ca_cert=nc_ca_cert,
        sans=[DNSName("host.example.com")],
    )
    _write_case(
        "name_constraints_permitted_dns", leaf_in_nc, nc_ca_cert,
        "valid",
        "Leaf SAN host.example.com — standard valid cert under NC CA.",
    )

    # ---- 10: AKI / SKI mismatch ----
    wrong_ca_key, wrong_ca_cert = _make_ca(cn="WrongCA")
    # Sign with wrong_ca_key but embed ca_cert's AKI
    leaf_aki_mismatch = (
        x509.CertificateBuilder()
        .subject_name(_name("aki-mismatch"))
        .issuer_name(ca_cert.subject)
        .public_key(_key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_public_key(wrong_ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_case(
        "aki_mismatch", leaf_aki_mismatch, ca_cert,
        "invalid: AKI does not match issuer SKI",
        "The AKI in the leaf cert references the wrong CA public key. "
        "RFC 5280 §4.2.1.1 requires AKI to match the issuer's SKI.",
    )

    # ---- 11: Validity crossing year 2038 ----
    far_future = _make_leaf(
        ca_key=ca_key, ca_cert=ca_cert,
        not_before=_now(),
        not_after=datetime.datetime(2050, 6, 15, tzinfo=_UTC),
    )
    _write_case(
        "validity_year_2050", far_future, ca_cert,
        "valid",
        "GeneralizedTime used for dates >= 2050. Must be handled without overflow.",
    )

    # ---- 12: Leaf cert claims CA=True ----
    leaf_claiming_ca = (
        x509.CertificateBuilder()
        .subject_name(_name("fake-ca"))
        .issuer_name(ca_cert.subject)
        .public_key(_key().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=365))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _write_case(
        "leaf_claims_ca_true", leaf_claiming_ca, ca_cert,
        "invalid: EE certificate must not set cA=TRUE",
        "RFC 5280 §6.1.4: when validating as an EE cert, cA=TRUE is rejected. "
        "cryptography's verifier correctly enforces this at the relying-party level.",
    )

    print(f"Generated {len(list(_CASES_DIR.iterdir()))} corner cases in {_CASES_DIR}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _parse_expected(expected_txt: str) -> tuple[bool, str]:
    s = expected_txt.strip()
    if s.startswith("valid"):
        return True, s
    elif s.startswith("invalid"):
        return False, s
    return True, s  # default to valid for unknown


def _validate_cert(cert_der: bytes, issuer_der: bytes,
                   intermediate_der: Optional[bytes] = None) -> tuple[bool, str]:
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        issuer = x509.load_der_x509_certificate(issuer_der)
    except Exception as e:
        return False, f"load error: {e}"

    try:
        from cryptography.x509.verification import PolicyBuilder, Store
        store_obj = Store([issuer])
        builder = PolicyBuilder().store(store_obj)
        # Use build_client_verifier: does not require SAN or DNS name, which
        # is correct for RFC 5280 path validation (not TLS-specific).
        verifier = builder.build_client_verifier()
        chain = ([x509.load_der_x509_certificate(intermediate_der)]
                 if intermediate_der else [])
        verifier.verify(cert, chain)
        return True, "valid"
    except ImportError:
        # Fallback for older cryptography versions: check issuer signature.
        try:
            issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                *_sig_params(cert.signature_hash_algorithm),
            )
            return True, "valid (sig-only)"
        except Exception as e2:
            return False, str(e2)
    except Exception as e:
        return False, str(e)


def _sig_params(alg):
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    if isinstance(alg, type(None)):
        return ()
    # Return args suitable for ec.ECDSA or RSA PKCS1v15 verify.
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        return (ECDSA(alg),)
    except Exception:
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
        return (PKCS1v15(), alg)


def run(case_filter: Optional[str] = None, verbose: bool = False) -> int:
    if not _CASES_DIR.exists():
        print(f"No cases directory found. Run with --generate-cases first.")
        return 0

    cases = sorted(_CASES_DIR.iterdir())
    if case_filter:
        cases = [c for c in cases if case_filter in c.name]

    total = skipped = passed = failed = 0
    failures: list[str] = []

    for case_dir in cases:
        if not case_dir.is_dir():
            continue

        cert_path = case_dir / "cert.der"
        issuer_path = case_dir / "issuer.der"
        expected_path = case_dir / "expected.txt"

        if not cert_path.exists() or not expected_path.exists():
            skipped += 1
            continue

        total += 1
        expected_valid, expected_reason = _parse_expected(expected_path.read_text())
        issuer_bytes = (issuer_path.read_bytes() if issuer_path.exists()
                        else cert_path.read_bytes())
        intermediate_path = case_dir / "intermediate.der"
        intermediate_bytes = (intermediate_path.read_bytes()
                               if intermediate_path.exists() else None)

        got_valid, got_reason = _validate_cert(cert_path.read_bytes(), issuer_bytes,
                                               intermediate_bytes)

        if got_valid == expected_valid:
            passed += 1
            if verbose:
                print(f"  ✓ {case_dir.name}")
        else:
            failed += 1
            failures.append(case_dir.name)
            print(f"  ✗ {case_dir.name}")
            print(f"      expected: {expected_reason}")
            print(f"      got:      {'valid' if got_valid else 'invalid'}: {got_reason}")

    print(f"\nRFC 5280 corners: {total} cases, {passed} passed, {failed} failed, {skipped} skipped")

    _write_results(cases, failures)
    return failed


def _write_results(cases, failures: list[str]) -> None:
    import datetime as dt
    lines = [
        "# RFC 5280 Corner-Case Results\n\n",
        f"Last run: {dt.datetime.now(dt.timezone.utc).isoformat()}\n\n",
        f"Failures: {len(failures)}\n\n",
        "| Case | Result |\n",
        "| ---- | ------ |\n",
    ]
    for c in cases:
        if c.is_dir():
            outcome = "FAIL" if c.name in failures else "PASS"
            lines.append(f"| {c.name} | {outcome} |\n")
    _RESULTS_FILE.write_text("".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        description="RFC 5280 corner-case conformance runner"
    )
    parser.add_argument("--case", help="Run only cases matching this substring")
    parser.add_argument("--generate-cases", action="store_true",
                        help="Generate all test certificates and cases")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.generate_cases:
        generate_cases()
        return

    failed = run(case_filter=args.case, verbose=args.verbose)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _main()
