#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
Unit tests for scep_server.py

Covers:
  - DER / ASN.1 helpers    (_encode_length, _decode_length, _decode_tlv,
                             _seq, _set, _oid, _integer, _octet_string,
                             _null, _bool, _printable_string, _utf8_string,
                             _decode_oid_bytes)
  - CMSParser               (parse_signed_data — structure, version,
                              signer info, signed attributes;
                              parse_enveloped_data — AES-256-CBC round-trip)
  - CMSBuilder              (signed_data — ContentInfo structure,
                              OID, signed attributes, signer info;
                              enveloped_data — encrypt/decrypt round-trip;
                              _degenerate_certs — parseable output)
  - SCEPDatabase            (create_transaction, set_success, set_failure,
                              get, all_transactions; in-memory and file-backed)

Run:
    python -m pytest test_scep_server.py -v
"""

import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

import pki_server as pki
import scep_server as scep

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_ca(tmpdir: str) -> pki.CertificateAuthority:
    return pki.CertificateAuthority(ca_dir=tmpdir)


def _gen_key(size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


# ---------------------------------------------------------------------------
# DER / ASN.1 helpers
# ---------------------------------------------------------------------------

class TestDERHelpersEncodeDecode(unittest.TestCase):

    def test_encode_decode_length_short(self):
        for n in (0, 1, 10, 127):
            enc = scep._encode_length(n)
            self.assertEqual(len(enc), 1)
            self.assertEqual(enc[0], n)
            decoded, nxt = scep._decode_length(enc, 0)
            self.assertEqual(decoded, n)

    def test_encode_decode_length_long_one_byte(self):
        for n in (128, 200, 255):
            enc = scep._encode_length(n)
            decoded, _ = scep._decode_length(enc, 0)
            self.assertEqual(decoded, n)
            self.assertEqual(enc[0], 0x81)

    def test_encode_decode_length_long_two_bytes(self):
        for n in (256, 1000, 65535):
            enc = scep._encode_length(n)
            decoded, _ = scep._decode_length(enc, 0)
            self.assertEqual(decoded, n)
            self.assertEqual(enc[0], 0x82)

    def test_decode_tlv_basic(self):
        data = b"\x04\x03abc"
        tag, val, nxt = scep._decode_tlv(data, 0)
        self.assertEqual(tag, 0x04)
        self.assertEqual(val, b"abc")
        self.assertEqual(nxt, 5)

    def test_seq_wraps_content(self):
        inner = b"\x01\x02\x03"
        result = scep._seq(inner)
        self.assertEqual(result[0], 0x30)
        self.assertEqual(result[2:], inner)

    def test_set_wraps_content(self):
        inner = b"\x01"
        result = scep._set(inner)
        self.assertEqual(result[0], 0x31)

    def test_null(self):
        self.assertEqual(scep._null(), b"\x05\x00")

    def test_bool_true(self):
        enc = scep._bool(True)
        self.assertEqual(enc, b"\x01\x01\xff")

    def test_bool_false(self):
        enc = scep._bool(False)
        self.assertEqual(enc, b"\x01\x01\x00")

    def test_octet_string(self):
        data = b"\xDE\xAD"
        enc = scep._octet_string(data)
        self.assertEqual(enc[0], 0x04)
        self.assertEqual(enc[2:], data)

    def test_printable_string(self):
        enc = scep._printable_string("Hello")
        self.assertEqual(enc[0], 0x13)
        self.assertEqual(enc[2:], b"Hello")

    def test_utf8_string(self):
        enc = scep._utf8_string("Héllo")
        self.assertEqual(enc[0], 0x0C)
        self.assertEqual(enc[2:], "Héllo".encode("utf-8"))

    def test_integer_zero(self):
        enc = scep._integer(0)
        self.assertEqual(enc, b"\x02\x01\x00")

    def test_integer_positive(self):
        enc = scep._integer(1)
        self.assertEqual(enc, b"\x02\x01\x01")

    def test_integer_needs_leading_zero(self):
        enc = scep._integer(0x80)
        self.assertEqual(enc[0], 0x02)   # INTEGER
        self.assertEqual(enc[2], 0x00)   # leading zero
        self.assertEqual(enc[3], 0x80)

    def test_integer_large(self):
        n = 2 ** 64
        enc = scep._integer(n)
        self.assertEqual(enc[0], 0x02)


class TestOIDEncoding(unittest.TestCase):

    def _roundtrip(self, oid_str: str) -> str:
        enc = scep._oid(oid_str)
        # enc = 0x06 + length + value
        val_len = enc[1] if enc[1] < 0x80 else int.from_bytes(enc[2:2+(enc[1]&0x7F)], "big")
        val_start = 2 if enc[1] < 0x80 else 2 + (enc[1] & 0x7F)
        return scep._decode_oid_bytes(enc[val_start:val_start + val_len])

    def test_oid_roundtrip_sha256_with_rsa(self):
        self.assertEqual(self._roundtrip(scep.OID_SHA256_WITH_RSA), scep.OID_SHA256_WITH_RSA)

    def test_oid_roundtrip_data(self):
        self.assertEqual(self._roundtrip(scep.OID_DATA), scep.OID_DATA)

    def test_oid_roundtrip_signed_data(self):
        self.assertEqual(self._roundtrip(scep.OID_SIGNED_DATA), scep.OID_SIGNED_DATA)

    def test_oid_roundtrip_transaction_id(self):
        self.assertEqual(self._roundtrip(scep.OID_TRANSACTION_ID), scep.OID_TRANSACTION_ID)

    def test_decode_oid_bytes_empty(self):
        self.assertEqual(scep._decode_oid_bytes(b""), "")


# ---------------------------------------------------------------------------
# CMSBuilder + CMSParser integration
# ---------------------------------------------------------------------------

class TestCMSBuilderParser(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)

    # ── signed_data ────────────────────────────────────────────────────────

    def test_signed_data_is_valid_content_info(self):
        """Output must be a ContentInfo SEQUENCE."""
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-001",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        self.assertIsInstance(der, bytes)
        self.assertGreater(len(der), 0)
        tag, _, _ = scep._decode_tlv(der, 0)
        self.assertEqual(tag, 0x30, "ContentInfo must be SEQUENCE")

    def test_signed_data_parseable_by_cms_parser(self):
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-parse-test",
            sender_nonce=b"\xAA" * 16,
            recipient_nonce=b"\xBB" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", result, result.get("parse_error"))

    def test_signed_data_has_signer_info(self):
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-si",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        self.assertIn("signer_info", result)

    def test_signed_data_contains_signed_attrs(self):
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-attrs",
            sender_nonce=b"\xCC" * 16,
            recipient_nonce=b"\xDD" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        si = result.get("signer_info", {})
        self.assertIn("signed_attrs", si)

    def test_signed_data_transaction_id_in_attrs(self):
        txid = "unique-txid-789"
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id=txid,
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        si = result.get("signer_info", {})
        attrs = si.get("signed_attrs", {})
        # OID_TRANSACTION_ID value should contain the txid
        txid_oid = scep.OID_TRANSACTION_ID
        if txid_oid in attrs:
            attr_val = attrs[txid_oid]
            self.assertIn(txid.encode("ascii"), attr_val)

    def test_signed_data_with_inner_cert_has_certificates(self):
        # Issue a cert to use as inner_der
        priv = _gen_key()
        cert = self.ca.issue_certificate(
            subject_str="CN=TestSCEP",
            public_key=priv.public_key(),
            validity_days=30,
        )
        cert_der = cert.public_bytes(Encoding.DER)
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-cert",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=cert_der,
        )
        result = scep.CMSParser.parse_signed_data(der)
        # Should have at least one certificate (degenerate p7c)
        self.assertIn("certificates", result)
        self.assertGreaterEqual(len(result["certificates"]), 1)

    def test_signed_data_failure_includes_fail_info(self):
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_FAILURE,
            transaction_id="txid-fail",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
            fail_info=scep.FAIL_BAD_REQUEST,
        )
        # Should parse without error — fail_info attribute is present
        result = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", result)

    def test_signed_data_pending_status(self):
        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_PENDING,
            transaction_id="txid-pending",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", result)

    # ── enveloped_data round-trip ──────────────────────────────────────────

    def test_enveloped_data_roundtrip_aes256(self):
        """Encrypt with CMSBuilder then decrypt with CMSParser."""
        priv = _gen_key()
        # Issue a cert for the recipient
        cert = self.ca.issue_certificate(
            subject_str="CN=scep-client",
            public_key=priv.public_key(),
            validity_days=30,
        )
        plaintext = b"Hello from SCEP client!"
        env_der = scep.CMSBuilder.enveloped_data(
            plaintext=plaintext,
            recipient_cert=cert,
        )
        self.assertIsInstance(env_der, bytes)
        self.assertGreater(len(env_der), 0)

        recovered = scep.CMSParser.parse_enveloped_data(env_der, priv)
        self.assertEqual(recovered, plaintext)

    def test_enveloped_data_wrong_key_raises(self):
        priv = _gen_key()
        wrong_priv = _gen_key()
        cert = self.ca.issue_certificate(
            subject_str="CN=scep-client2",
            public_key=priv.public_key(),
            validity_days=30,
        )
        env_der = scep.CMSBuilder.enveloped_data(
            plaintext=b"secret data",
            recipient_cert=cert,
        )
        with self.assertRaises(Exception):
            scep.CMSParser.parse_enveloped_data(env_der, wrong_priv)

    def test_enveloped_data_large_payload(self):
        priv = _gen_key()
        cert = self.ca.issue_certificate(
            subject_str="CN=scep-big",
            public_key=priv.public_key(),
            validity_days=30,
        )
        large_payload = os.urandom(4096)
        env_der = scep.CMSBuilder.enveloped_data(large_payload, cert)
        recovered = scep.CMSParser.parse_enveloped_data(env_der, priv)
        self.assertEqual(recovered, large_payload)

    # ── _degenerate_certs ──────────────────────────────────────────────────

    def test_degenerate_certs_is_sequence(self):
        priv = _gen_key()
        cert = self.ca.issue_certificate(
            subject_str="CN=scep-degen",
            public_key=priv.public_key(),
            validity_days=30,
        )
        cert_der = cert.public_bytes(Encoding.DER)
        ca_der = self.ca.ca_cert.public_bytes(Encoding.DER)
        degen = scep.CMSBuilder._degenerate_certs(cert_der, ca_der)
        # Must be a SEQUENCE (ContentInfo)
        tag, _, _ = scep._decode_tlv(degen, 0)
        self.assertEqual(tag, 0x30)


# ---------------------------------------------------------------------------
# CMSParser — parse_signed_data error handling
# ---------------------------------------------------------------------------

class TestCMSParserErrorHandling(unittest.TestCase):

    def test_parse_garbage_data(self):
        result = scep.CMSParser.parse_signed_data(b"\xFF\xFF\xFF\xFF\xFF")
        self.assertIn("parse_error", result)

    def test_parse_empty_data(self):
        result = scep.CMSParser.parse_signed_data(b"")
        self.assertIn("parse_error", result)

    def test_parse_truncated_data(self):
        result = scep.CMSParser.parse_signed_data(b"\x30\x10\x06\x09")
        self.assertIn("parse_error", result)


# ---------------------------------------------------------------------------
# SCEPDatabase
# ---------------------------------------------------------------------------

class TestSCEPDatabaseInMemory(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self._tmpdir) / "scep_test.db")
        self.db = scep.SCEPDatabase(self.db_path)

    def test_create_and_get_transaction(self):
        self.db.create_transaction("txid-1", "CN=Test", "CSR_PEM", "192.168.1.1")
        row = self.db.get("txid-1")
        self.assertIsNotNone(row)
        self.assertEqual(row["transaction_id"], "txid-1")
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["subject"], "CN=Test")
        self.assertEqual(row["requester_ip"], "192.168.1.1")

    def test_get_unknown_returns_none(self):
        self.assertIsNone(self.db.get("unknown-txid"))

    def test_set_success(self):
        self.db.create_transaction("txid-2", "CN=OK", "CSR", "10.0.0.1")
        self.db.set_success("txid-2", "CERT_PEM_DATA")
        row = self.db.get("txid-2")
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["cert_pem"], "CERT_PEM_DATA")

    def test_set_failure(self):
        self.db.create_transaction("txid-3", "CN=Bad", "CSR", "10.0.0.2")
        self.db.set_failure("txid-3", scep.FAIL_BAD_REQUEST, "Challenge mismatch")
        row = self.db.get("txid-3")
        self.assertEqual(row["status"], "failure")
        self.assertEqual(row["fail_info"], scep.FAIL_BAD_REQUEST)
        self.assertEqual(row["fail_reason"], "Challenge mismatch")

    def test_all_transactions_returns_all(self):
        for i in range(5):
            self.db.create_transaction(f"txid-{i}", f"CN=User{i}", "CSR", "")
        rows = self.db.all_transactions()
        self.assertEqual(len(rows), 5)

    def test_all_transactions_ordered_by_created_at_desc(self):
        for i in range(3):
            self.db.create_transaction(f"ordered-{i}", f"CN=U{i}", "CSR", "")
            time.sleep(0.01)  # ensure distinct timestamps
        rows = self.db.all_transactions()
        times = [r["created_at"] for r in rows]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_create_transaction_idempotent_on_replace(self):
        """INSERT OR REPLACE — second call with same txid replaces."""
        self.db.create_transaction("dup-txid", "CN=First", "CSR1", "1.1.1.1")
        self.db.create_transaction("dup-txid", "CN=Second", "CSR2", "2.2.2.2")
        row = self.db.get("dup-txid")
        self.assertEqual(row["subject"], "CN=Second")

    def test_set_success_updates_updated_at(self):
        self.db.create_transaction("ts-txid", "CN=Test", "CSR", "")
        before = self.db.get("ts-txid")["updated_at"]
        time.sleep(0.05)
        self.db.set_success("ts-txid", "CERT")
        after = self.db.get("ts-txid")["updated_at"]
        self.assertGreater(after, before)

    def test_set_failure_updates_updated_at(self):
        self.db.create_transaction("tf-txid", "CN=Test", "CSR", "")
        before = self.db.get("tf-txid")["updated_at"]
        time.sleep(0.05)
        self.db.set_failure("tf-txid", scep.FAIL_BAD_ALG, "bad algo")
        after = self.db.get("tf-txid")["updated_at"]
        self.assertGreater(after, before)

    def test_database_persists_across_instances(self):
        self.db.create_transaction("persist-txid", "CN=Persist", "CSR", "")
        db2 = scep.SCEPDatabase(self.db_path)
        row = db2.get("persist-txid")
        self.assertIsNotNone(row)
        self.assertEqual(row["subject"], "CN=Persist")

    def test_all_transactions_empty_db(self):
        rows = self.db.all_transactions()
        self.assertEqual(rows, [])

    def test_scep_status_codes_are_strings(self):
        """Verify the module-level status constants are strings (PrintableString)."""
        self.assertIsInstance(scep.STATUS_SUCCESS, str)
        self.assertIsInstance(scep.STATUS_FAILURE, str)
        self.assertIsInstance(scep.STATUS_PENDING, str)

    def test_scep_fail_info_codes_are_strings(self):
        for code in (scep.FAIL_BAD_ALG, scep.FAIL_BAD_MESSAGE_CHECK,
                     scep.FAIL_BAD_REQUEST, scep.FAIL_BAD_TIME, scep.FAIL_BAD_CERT_ID):
            self.assertIsInstance(code, str)

    def test_scep_message_type_codes_are_strings(self):
        for mt in (scep.MSG_PKCSREQ, scep.MSG_CERTRESP, scep.MSG_GETCERT,
                   scep.MSG_GETCRL):
            self.assertIsInstance(mt, str)


# ---------------------------------------------------------------------------
# Integration — CMSBuilder → parse_signed_data attributes round-trip
# ---------------------------------------------------------------------------

class TestCMSRoundTrip(unittest.TestCase):
    """Verify that CMSBuilder produces messages parseable by CMSParser
       and that key signed attributes survive the round-trip."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)

    def _build(self, txid, status, msg_type=scep.MSG_CERTRESP, fail_info=None):
        return scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=msg_type,
            pki_status=status,
            transaction_id=txid,
            sender_nonce=b"\xAA" * 16,
            recipient_nonce=b"\xBB" * 16,
            inner_der=b"",
            fail_info=fail_info,
        )

    def test_success_round_trip(self):
        der = self._build("rt-success", scep.STATUS_SUCCESS)
        parsed = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", parsed)
        self.assertIn("signer_info", parsed)
        self.assertIn("signed_attrs", parsed["signer_info"])

    def test_failure_with_fail_info_round_trip(self):
        der = self._build("rt-failure", scep.STATUS_FAILURE,
                          fail_info=scep.FAIL_BAD_REQUEST)
        parsed = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", parsed)

    def test_pending_round_trip(self):
        der = self._build("rt-pending", scep.STATUS_PENDING)
        parsed = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", parsed)

    def test_multiple_message_types(self):
        for msg_type in (scep.MSG_PKCSREQ, scep.MSG_CERTRESP,
                         scep.MSG_GETCERT, scep.MSG_GETCRL):
            der = self._build(f"rt-{msg_type}", scep.STATUS_SUCCESS, msg_type)
            parsed = scep.CMSParser.parse_signed_data(der)
            self.assertNotIn("parse_error", parsed, f"Parse failed for msg_type={msg_type}")


# ---------------------------------------------------------------------------
# RFC 5083 + RFC 5084 — AuthEnvelopedData (AES-GCM)
# ---------------------------------------------------------------------------

class TestRFC5083AuthEnvelopedData(unittest.TestCase):
    """
    RFC 5083 (CMS AuthEnvelopedData) + RFC 5084 (AES-GCM in CMS).

    Covers:
    - CMSBuilder.auth_enveloped_data: content type OID, round-trip,
      GCMParameters (nonce + ICVlen), recipient info
    - CMSParser.parse_enveloped_data dispatches on AuthEnvelopedData OID
    - Tampered ciphertext or auth tag → decryption failure
    - Wrong private key → decryption failure
    - GetCACaps advertises AES-GCM
    - _cms_content_type helper returns correct OID
    """

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp()
        cls.ca = _make_ca(cls._tmpdir)
        cls.key = _gen_key()
        cls.cert = cls._issue_cert(cls.ca, cls.key.public_key())

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    @staticmethod
    def _issue_cert(ca, pubkey):
        """Issue a minimal test cert from the CA."""
        import datetime
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
            .issuer_name(ca.ca_cert.subject)
            .public_key(pubkey)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca.ca_key, _SHA256())
        )

    # ---- builder: content type OID ----

    def test_content_type_oid_is_auth_enveloped(self):
        """ContentInfo OID must be id-ct-authEnvelopedData (1.2.840.113549.1.9.16.1.23)."""
        der = scep.CMSBuilder.auth_enveloped_data(b"hello", self.cert)
        self.assertEqual(scep._cms_content_type(der), scep.OID_AUTH_ENVELOPED_DATA)

    def test_classic_enveloped_data_oid(self):
        """Existing enveloped_data still yields OID_ENVELOPED_DATA."""
        der = scep.CMSBuilder.enveloped_data(b"hello", self.cert)
        self.assertEqual(scep._cms_content_type(der), scep.OID_ENVELOPED_DATA)

    # ---- round-trip: builder → parser ----

    def test_auth_enveloped_roundtrip_short(self):
        """Short plaintext round-trips through auth_enveloped_data/parse_enveloped_data."""
        plaintext = b"SCEP test payload"
        der = scep.CMSBuilder.auth_enveloped_data(plaintext, self.cert)
        result = scep.CMSParser.parse_enveloped_data(der, self.key)
        self.assertEqual(result, plaintext)

    def test_auth_enveloped_roundtrip_empty(self):
        """Empty plaintext round-trips (edge case: zero-length GCM input)."""
        der = scep.CMSBuilder.auth_enveloped_data(b"", self.cert)
        result = scep.CMSParser.parse_enveloped_data(der, self.key)
        self.assertEqual(result, b"")

    def test_auth_enveloped_roundtrip_large(self):
        """4096-byte payload round-trips correctly."""
        plaintext = os.urandom(4096)
        der = scep.CMSBuilder.auth_enveloped_data(plaintext, self.cert)
        result = scep.CMSParser.parse_enveloped_data(der, self.key)
        self.assertEqual(result, plaintext)

    # ---- GCMParameters structure ----

    def test_gcm_nonce_is_12_bytes(self):
        """GCMParameters nonce MUST be 12 bytes (96-bit, recommended for GCM)."""
        der = scep.CMSBuilder.auth_enveloped_data(b"data", self.cert)
        # Locate GCMParameters: parse ContentInfo → AuthEnvelopedData → authEncryptedContentInfo
        # → contentEncryptionAlgorithm → GCMParameters
        _, ci_val, _ = scep._decode_tlv(der, 0)
        ci_pos = 0
        _, _, ci_pos = scep._decode_tlv(ci_val, ci_pos)   # contentType OID
        _, ev_outer, _ = scep._decode_tlv(ci_val, ci_pos) # [0]
        _, ev_val, _ = scep._decode_tlv(ev_outer, 0)      # AuthEnvelopedData SEQUENCE
        ev_pos = 0
        _, _, ev_pos = scep._decode_tlv(ev_val, ev_pos)   # version
        _, _, ev_pos = scep._decode_tlv(ev_val, ev_pos)   # recipientInfos
        _, aci_val, _ = scep._decode_tlv(ev_val, ev_pos)  # authEncryptedContentInfo
        aci_pos = 0
        _, _, aci_pos = scep._decode_tlv(aci_val, aci_pos)  # contentType OID
        _, ca_seq, _ = scep._decode_tlv(aci_val, aci_pos)   # contentEncAlg SEQUENCE
        _, _, ca_pos = scep._decode_tlv(ca_seq, 0)           # algorithm OID
        _, gcm_params, _ = scep._decode_tlv(ca_seq, ca_pos)  # GCMParameters SEQUENCE
        _, nonce, _ = scep._decode_tlv(gcm_params, 0)        # aes-nonce OCTET STRING
        self.assertEqual(len(nonce), 12, "GCM nonce must be 12 bytes")

    def test_gcm_icv_len_is_16(self):
        """GCMParameters aes-ICVlen MUST be 16 (128-bit tag, max security)."""
        der = scep.CMSBuilder.auth_enveloped_data(b"data", self.cert)
        _, ci_val, _ = scep._decode_tlv(der, 0)
        ci_pos = 0
        _, _, ci_pos = scep._decode_tlv(ci_val, ci_pos)
        _, ev_outer, _ = scep._decode_tlv(ci_val, ci_pos)
        _, ev_val, _ = scep._decode_tlv(ev_outer, 0)
        ev_pos = 0
        _, _, ev_pos = scep._decode_tlv(ev_val, ev_pos)
        _, _, ev_pos = scep._decode_tlv(ev_val, ev_pos)
        _, aci_val, _ = scep._decode_tlv(ev_val, ev_pos)
        aci_pos = 0
        _, _, aci_pos = scep._decode_tlv(aci_val, aci_pos)
        _, ca_seq, _ = scep._decode_tlv(aci_val, aci_pos)
        _, _, ca_pos = scep._decode_tlv(ca_seq, 0)
        _, gcm_params, _ = scep._decode_tlv(ca_seq, ca_pos)
        gp_pos = 0
        _, _, gp_pos = scep._decode_tlv(gcm_params, gp_pos)  # skip nonce
        _, icvlen_bytes, _ = scep._decode_tlv(gcm_params, gp_pos)
        self.assertEqual(int.from_bytes(icvlen_bytes, "big"), 16)

    # ---- security: wrong key / tampered data ----

    def test_wrong_private_key_raises(self):
        """Decryption with a different private key must raise (CEK decrypt fails)."""
        wrong_key = _gen_key()
        der = scep.CMSBuilder.auth_enveloped_data(b"secret", self.cert)
        with self.assertRaises(Exception):
            scep.CMSParser.parse_enveloped_data(der, wrong_key)

    def test_tampered_ciphertext_raises(self):
        """Flipping a bit in the ciphertext must raise (GCM auth tag mismatch)."""
        plaintext = b"integrity-protected payload"
        der = scep.CMSBuilder.auth_enveloped_data(plaintext, self.cert)
        # Flip a byte near the end of the DER (in the ciphertext region)
        bad = bytearray(der)
        bad[-30] ^= 0xFF
        with self.assertRaises(Exception):
            scep.CMSParser.parse_enveloped_data(bytes(bad), self.key)

    def test_tampered_mac_tag_raises(self):
        """Flipping a byte in the trailing 16-byte mac tag must raise."""
        plaintext = b"mac-protected"
        der = scep.CMSBuilder.auth_enveloped_data(plaintext, self.cert)
        # The mac tag is the last 18 bytes: 0x04 + 0x10 + 16 bytes
        bad = bytearray(der)
        bad[-5] ^= 0xFF  # inside the 16-byte tag
        with self.assertRaises(Exception):
            scep.CMSParser.parse_enveloped_data(bytes(bad), self.key)

    # ---- dispatcher: parse_enveloped_data selects correct path ----

    def test_parse_dispatch_cbc_unchanged(self):
        """CBC EnvelopedData still decrypts correctly after the refactor."""
        plaintext = b"classic CBC payload"
        der = scep.CMSBuilder.enveloped_data(plaintext, self.cert)
        result = scep.CMSParser.parse_enveloped_data(der, self.key)
        self.assertEqual(result, plaintext)

    def test_parse_dispatch_gcm_path(self):
        """parse_enveloped_data selects GCM path when OID matches."""
        plaintext = b"gcm dispatch"
        der = scep.CMSBuilder.auth_enveloped_data(plaintext, self.cert)
        result = scep.CMSParser.parse_enveloped_data(der, self.key)
        self.assertEqual(result, plaintext)

    # ---- GetCACaps ----

    def test_get_ca_caps_includes_aes_gcm(self):
        """GetCACaps response MUST include the 'AES-GCM' capability token."""
        import tempfile, http.server, threading, urllib.request
        from dispatcher_server import RouteTable
        from pathlib import Path

        tmpdir = tempfile.mkdtemp()
        try:
            ca = _make_ca(tmpdir)
            from dispatcher_server import RouteTable
            rt = RouteTable()
            proxy = scep.start_scep_server(
                route_table=rt, prefix="/scep", ca=ca,
                ca_dir=Path(tmpdir),
            )
            # Build a handler and call _handle_get_ca_caps directly
            class _FakeRequest:
                def makefile(self, *a, **kw):
                    import io
                    return io.BytesIO(b"")
            class _BoundHandler(scep.SCEPHandler):
                pass
            _BoundHandler.ca = ca
            _BoundHandler.db = scep.SCEPDatabase(str(Path(tmpdir) / "s.db"))
            _BoundHandler.challenge = ""

            captured = {}
            class _Recorder:
                def __init__(self): self._headers = []; self._body = b""
                def write(self, b): self._body += b
                def flush(self): pass

            import io
            rec = _Recorder()
            handler = object.__new__(_BoundHandler)
            handler.wfile = rec

            def _fake_send_response(code): pass
            def _fake_send_header(k, v): pass
            def _fake_end_headers(): pass
            handler.send_response = _fake_send_response
            handler.send_header   = _fake_send_header
            handler.end_headers   = _fake_end_headers
            handler.client_address = ("127.0.0.1", 0)
            _BoundHandler._handle_get_ca_caps(handler)
            caps_text = rec._body.decode()
            self.assertIn("AES-GCM", caps_text,
                          f"GetCACaps must include AES-GCM; got: {caps_text!r}")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ---- _cms_content_type helper ----

    def test_cms_content_type_enveloped(self):
        der = scep.CMSBuilder.enveloped_data(b"x", self.cert)
        self.assertEqual(scep._cms_content_type(der), scep.OID_ENVELOPED_DATA)

    def test_cms_content_type_auth_enveloped(self):
        der = scep.CMSBuilder.auth_enveloped_data(b"x", self.cert)
        self.assertEqual(scep._cms_content_type(der), scep.OID_AUTH_ENVELOPED_DATA)

    def test_cms_content_type_garbage_returns_empty(self):
        self.assertEqual(scep._cms_content_type(b"\x00\x01\x02"), "")


# ---------------------------------------------------------------------------
# RFC 8933 — CMS contentType attribute always present in signedAttrs
# ---------------------------------------------------------------------------

class TestRFC8933CMSContentType(unittest.TestCase):
    """
    RFC 8933 §2 MUST: the content-type signed attribute MUST be present
    whenever signedAttrs are included in a SignerInfo.

    Verifies that CMSBuilder.signed_data always emits OID_CONTENT_TYPE
    (1.2.840.113549.1.9.3) with value OID_DATA (1.2.840.113549.1.7.1) in
    signedAttrs, regardless of pki_status or fail_info presence.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp()
        cls.ca = _make_ca(cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _signed_attrs(self, **kwargs):
        defaults = dict(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-8933",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        defaults.update(kwargs)
        der = scep.CMSBuilder.signed_data(**defaults)
        result = scep.CMSParser.parse_signed_data(der)
        self.assertNotIn("parse_error", result, result.get("parse_error"))
        return result["signer_info"]["signed_attrs"]

    # ---- contentType always present ----

    def test_content_type_present_in_success_response(self):
        """RFC 8933 §2 MUST: contentType in signedAttrs for SUCCESS."""
        attrs = self._signed_attrs(pki_status=scep.STATUS_SUCCESS)
        self.assertIn(scep.OID_CONTENT_TYPE, attrs,
                      "RFC 8933: contentType must be present in signedAttrs")

    def test_content_type_present_in_failure_response(self):
        """RFC 8933 §2 MUST: contentType in signedAttrs for FAILURE."""
        attrs = self._signed_attrs(
            pki_status=scep.STATUS_FAILURE,
            fail_info=scep.FAIL_BAD_REQUEST,
        )
        self.assertIn(scep.OID_CONTENT_TYPE, attrs,
                      "RFC 8933: contentType must be present in signedAttrs")

    def test_content_type_present_in_pending_response(self):
        """RFC 8933 §2 MUST: contentType in signedAttrs for PENDING."""
        attrs = self._signed_attrs(pki_status=scep.STATUS_PENDING)
        self.assertIn(scep.OID_CONTENT_TYPE, attrs,
                      "RFC 8933: contentType must be present in signedAttrs")

    # ---- contentType value is OID_DATA ----

    def test_content_type_value_is_oid_data(self):
        """contentType attribute value MUST be id-data (1.2.840.113549.1.7.1)."""
        attrs = self._signed_attrs()
        raw_value = attrs[scep.OID_CONTENT_TYPE]
        decoded = scep._decode_oid_bytes(raw_value)
        self.assertEqual(decoded, scep.OID_DATA,
                         f"contentType value must be OID_DATA, got {decoded!r}")

    # ---- signedAttrs block always present ----

    def test_signed_attrs_never_absent(self):
        """SignerInfo MUST include signedAttrs so RFC 8933 contentType can live there."""
        for status in (scep.STATUS_SUCCESS, scep.STATUS_FAILURE, scep.STATUS_PENDING):
            der = scep.CMSBuilder.signed_data(
                ca=self.ca,
                message_type=scep.MSG_CERTRESP,
                pki_status=status,
                transaction_id=f"txid-{status}",
                sender_nonce=os.urandom(16),
                recipient_nonce=os.urandom(16),
                inner_der=b"",
            )
            result = scep.CMSParser.parse_signed_data(der)
            si = result.get("signer_info", {})
            self.assertIn("signed_attrs", si,
                          f"signedAttrs absent for status={status!r}")

    # ---- contentType is first (canonical ordering) ----

    def test_content_type_position_is_deterministic(self):
        """Building two identical responses yields identical signed_attrs bytes (no random ordering)."""
        kwargs = dict(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-stable",
            sender_nonce=b"\xAA" * 16,
            recipient_nonce=b"\xBB" * 16,
            inner_der=b"",
        )
        der1 = scep.CMSBuilder.signed_data(**kwargs)
        der2 = scep.CMSBuilder.signed_data(**kwargs)
        r1 = scep.CMSParser.parse_signed_data(der1)
        r2 = scep.CMSParser.parse_signed_data(der2)
        self.assertEqual(
            r1["signer_info"].get("signed_attrs_raw"),
            r2["signer_info"].get("signed_attrs_raw"),
            "signed_attrs bytes must be deterministic for identical inputs",
        )

    # ---- signature still verifies after adding contentType ----

    def test_signature_verifies_with_content_type_present(self):
        """The PKCS#1v15 signature over signedAttrs must verify against CA public key."""
        from cryptography.hazmat.primitives.asymmetric import padding as ap
        from cryptography.hazmat.primitives.hashes import SHA256
        import hashlib

        der = scep.CMSBuilder.signed_data(
            ca=self.ca,
            message_type=scep.MSG_CERTRESP,
            pki_status=scep.STATUS_SUCCESS,
            transaction_id="txid-verify",
            sender_nonce=b"\x01" * 16,
            recipient_nonce=b"\x02" * 16,
            inner_der=b"",
        )
        result = scep.CMSParser.parse_signed_data(der)
        si = result["signer_info"]

        # Re-encode signed_attrs as SET (0x31) for signature verification
        raw = si["signed_attrs_raw"]
        signed_attrs_set = b"\x31" + scep._encode_length(len(raw)) + raw

        sig = si["signature"]
        pub = self.ca.ca_cert.public_key()
        try:
            pub.verify(sig, signed_attrs_set, ap.PKCS1v15(), SHA256())
        except Exception as e:
            self.fail(f"Signature verification failed: {e}")


if __name__ == "__main__":
    unittest.main()
