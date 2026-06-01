"""
setup_corpus.py — Generate minimal seed corpus for each fuzz harness.

Run once before the first fuzzing session:
    python3 fuzz/setup_corpus.py

Seeds are small, well-formed DER inputs that give the fuzzer a valid
starting point. Each corpus/ subdirectory gets 5–10 seeds.

Sources used here:
  1. Hand-crafted minimal DER from der_codec primitives
  2. Constants from the existing test suite (protocol-specific)

Existing files in corpus/ are NOT overwritten; add --overwrite to force.
"""

from __future__ import annotations
import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from der_codec import (
    seq, set_, ctx, integer as der_int, octet_string, bit_string, null,
    oid, encode_length, utf8_string, printable_string, utc_time,
    generalized_time, validity as der_validity,
)
import datetime

_FUZZ = Path(__file__).parent
_UTC = datetime.timezone.utc


def _write(corpus_dir: Path, name: str, data: bytes, overwrite: bool) -> None:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    dest = corpus_dir / name
    if dest.exists() and not overwrite:
        return
    dest.write_bytes(data)
    print(f"  wrote {dest.relative_to(_FUZZ.parent)} ({len(data)} bytes)")


# ---------------------------------------------------------------------------
# TLV primitive seeds
# ---------------------------------------------------------------------------

def _seed_tlv(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "tlv_primitive"
    _write(d, "integer_zero.der", b"\x02\x01\x00", overwrite)
    _write(d, "integer_ff.der",   b"\x02\x02\x00\xff", overwrite)
    _write(d, "empty_seq.der",    b"\x30\x00", overwrite)
    _write(d, "empty_set.der",    b"\x31\x00", overwrite)
    _write(d, "empty_octet.der",  b"\x04\x00", overwrite)
    _write(d, "oid_cn.der",       b"\x06\x03\x55\x04\x03", overwrite)
    # Long-form length (128 bytes payload)
    payload = bytes(128)
    _write(d, "long_form_len.der", b"\x04\x81\x80" + payload, overwrite)
    # Two-byte long form
    payload2 = bytes(256)
    _write(d, "two_byte_len.der", b"\x04\x82\x01\x00" + payload2, overwrite)
    # Nested sequence
    inner = der_int(42)
    _write(d, "nested_seq.der", seq(seq(inner)), overwrite)
    # Truncated (triggers IndexError — valid corpus entry)
    _write(d, "truncated.der", b"\x30\x10\x02", overwrite)


# ---------------------------------------------------------------------------
# SCEP envelope seeds
# ---------------------------------------------------------------------------

def _seed_scep(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "scep_envelope"
    # Minimal ContentInfo shell (wrong content type — will parse_error gracefully)
    oid_data = oid("1.2.840.113549.1.7.2")          # id-signedData
    inner_placeholder = octet_string(b"\x30\x00")
    content_info = seq(oid_data + ctx(0, inner_placeholder))
    _write(d, "minimal_content_info.der", content_info, overwrite)

    # Empty ContentInfo
    _write(d, "empty_seq.der", b"\x30\x00", overwrite)

    # Random bytes that look like a length prefix
    _write(d, "length_bomb.der", b"\x30\x84\x00\x00\x01\x00" + bytes(8), overwrite)

    # Minimal SignedData skeleton (version + empty fields)
    signed_data_body = (
        der_int(1)                          # version 1
        + set_(b"")                          # digestAlgorithms
        + seq(oid("1.2.840.113549.1.7.1"))   # encapContentInfo
        + set_(b"")                          # signerInfos
    )
    content_info2 = seq(
        oid("1.2.840.113549.1.7.2")
        + ctx(0, seq(signed_data_body))
    )
    _write(d, "minimal_signed_data.der", content_info2, overwrite)


# ---------------------------------------------------------------------------
# CMP PKIMessage seeds
# ---------------------------------------------------------------------------

def _seed_cmp(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "cmp_pkimessage"
    # Minimal PKIMessage shell
    sender = seq(ctx(4, b"\x00", constructed=False))   # [4] NULL sender
    recipient = seq(ctx(4, b"\x00", constructed=False))
    header = seq(der_int(2) + sender + recipient)     # pvno=2, sender, recipient
    body = ctx(0, b"", constructed=False)              # [0] ir (empty)
    pki_msg = seq(header + body)
    _write(d, "minimal_pkimessage.der", pki_msg, overwrite)
    _write(d, "empty_seq.der", b"\x30\x00", overwrite)
    _write(d, "single_byte.der", b"\x30", overwrite)
    # Header with context tags
    msg_time = ctx(0, utc_time(datetime.datetime(2024, 1, 1, tzinfo=_UTC)), constructed=False)
    header2 = seq(der_int(2) + sender + recipient + msg_time)
    _write(d, "header_with_time.der", seq(header2 + body), overwrite)


# ---------------------------------------------------------------------------
# CRMF POPO seeds
# ---------------------------------------------------------------------------

def _seed_crmf(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "crmf_popo"
    # Minimal CertReqMessages shell
    cert_req_id = der_int(0)
    cert_template = seq(b"")   # empty CertTemplate
    cert_req = seq(cert_req_id + cert_template)
    cert_req_msg = seq(cert_req)
    cert_req_msgs = seq(cert_req_msg)
    _write(d, "minimal_certreqmsgs.der", cert_req_msgs, overwrite)
    _write(d, "empty_seq.der", b"\x30\x00", overwrite)
    # With POPO raVerified [0]
    popo_ra = ctx(0, b"", constructed=False)
    cert_req_msg_popo = seq(cert_req + popo_ra)
    _write(d, "popo_ra_verified.der", seq(cert_req_msg_popo), overwrite)


# ---------------------------------------------------------------------------
# EST CSR seeds
# ---------------------------------------------------------------------------

def _seed_est(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "est_csr"
    # PEM-style input
    pem_like = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkq\n-----END CERTIFICATE REQUEST-----\n"
    _write(d, "pem_stub.pem", pem_like, overwrite)
    # Minimal SEQUENCE (will fail CSR parse but not crash)
    _write(d, "minimal_seq.der", b"\x30\x00", overwrite)
    # Base64 of minimal sequence
    import base64
    _write(d, "b64_minimal.b64", base64.b64encode(b"\x30\x00"), overwrite)
    # Just a single byte
    _write(d, "single_byte.bin", b"\x00", overwrite)
    # Empty
    _write(d, "empty.bin", b"", overwrite)


# ---------------------------------------------------------------------------
# OCSP request seeds
# ---------------------------------------------------------------------------

def _seed_ocsp(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "ocsp_request"
    sha1_alg = seq(oid("1.3.14.3.2.26") + null())
    issuer_name_hash = octet_string(bytes(20))   # SHA-1 placeholder
    issuer_key_hash  = octet_string(bytes(20))
    serial_num = der_int(1)
    cert_id = seq(sha1_alg + issuer_name_hash + issuer_key_hash + serial_num)
    request = seq(cert_id)
    req_list = seq(request)
    tbs_request = seq(req_list)
    ocsp_request = seq(tbs_request)
    _write(d, "minimal_ocsp_request.der", ocsp_request, overwrite)

    # With nonce extension
    nonce_val = octet_string(bytes(16))
    nonce_ext = seq(
        oid("1.3.6.1.5.5.7.48.1.2")
        + octet_string(nonce_val)
    )
    exts = seq(nonce_ext)
    req_exts = ctx(2, exts)
    tbs_with_nonce = seq(req_list + req_exts)
    _write(d, "ocsp_with_nonce.der", seq(tbs_with_nonce), overwrite)

    _write(d, "empty_seq.der", b"\x30\x00", overwrite)


# ---------------------------------------------------------------------------
# TSA request seeds
# ---------------------------------------------------------------------------

def _seed_tsa(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "tsa_request"
    sha256_alg = seq(oid("2.16.840.1.101.3.4.2.1") + null())
    imprint = octet_string(bytes(32))   # SHA-256 placeholder
    msg_imprint = seq(sha256_alg + imprint)
    ts_req = seq(der_int(1) + msg_imprint)
    _write(d, "minimal_tsreq.der", ts_req, overwrite)

    # With nonce + certReq
    nonce = der_int(0xDEADBEEF)
    cert_req_bool = b"\x01\x01\xff"   # BOOLEAN TRUE
    ts_req_full = seq(der_int(1) + msg_imprint + nonce + cert_req_bool)
    _write(d, "tsreq_with_nonce.der", ts_req_full, overwrite)

    _write(d, "empty_seq.der", b"\x30\x00", overwrite)


# ---------------------------------------------------------------------------
# ML-DSA roundtrip seeds
# ---------------------------------------------------------------------------

def _seed_mldsa(overwrite: bool) -> None:
    d = _FUZZ / "corpus" / "mldsa_roundtrip"
    # Minimal SubjectPublicKeyInfo (empty key bytes)
    ml_dsa_44_oid = oid("2.16.840.1.101.3.4.3.17")
    spki = seq(seq(ml_dsa_44_oid) + bit_string(bytes(32)))
    _write(d, "minimal_spki.der", spki, overwrite)

    # SPKI with large key (exercise length encoding)
    large_spki = seq(seq(ml_dsa_44_oid) + bit_string(bytes(1312)))  # ML-DSA-44 pub size
    _write(d, "mldsa44_spki.der", large_spki, overwrite)

    _write(d, "empty_spki.der", b"\x30\x00", overwrite)
    _write(d, "single_byte.der", b"\x00", overwrite)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Populate fuzz seed corpus")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing corpus files")
    args = parser.parse_args()

    print("Generating seed corpus...")
    _seed_tlv(args.overwrite)
    _seed_scep(args.overwrite)
    _seed_cmp(args.overwrite)
    _seed_crmf(args.overwrite)
    _seed_est(args.overwrite)
    _seed_ocsp(args.overwrite)
    _seed_tsa(args.overwrite)
    _seed_mldsa(args.overwrite)
    print("Done. Corpus ready in fuzz/corpus/")


if __name__ == "__main__":
    main()
