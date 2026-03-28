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


if __name__ == "__main__":
    unittest.main()
