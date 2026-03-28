#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
Unit tests for ipsec_server.py

Covers:
  - RFC4945Validator.validate_request   (SAN enforcement, wildcard prohibition,
                                         CIDR prohibition, email validation,
                                         empty subject check)
  - RFC4945Validator.check_cn_san_consistency  (advisory CN/SAN mismatch)
  - RFC4945Validator.check_name_constraints    (permitted / excluded subtrees)
  - IPsecCertIssuer.issue              (profile EKU, server-side key gen,
                                        client-supplied public key, RFC 4945 KU)
  - IPsecCertIssuer.batch_issue        (RFC 4809 §3.1.2)
  - IPsecCertIssuer.pkc_update         (RFC 4809 §3.3 — same DN, new key)
  - IPsecCertIssuer.pkc_renew          (RFC 4809 §3.5 — same DN, same key)
  - ApprovalQueue                      (enqueue / approve / reject /
                                        confirm_receipt / list_pending /
                                        record_direct_confirmation)
  - DER helpers                        (_enc_len / _dec_len round-trips,
                                         _oid_enc, _int_enc, _oct_enc,
                                         _generalized_time, _decode_oid_bytes)

Run:
    python -m pytest test_ipsec_server.py -v
"""

import datetime
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List, Optional

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

import pki_server as pki
import ipsec_server as ipsec

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_ca(tmpdir: str) -> pki.CertificateAuthority:
    return pki.CertificateAuthority(
        ca_dir=tmpdir,
        ocsp_url="http://ocsp.example.com",
        crl_url="http://crl.example.com/ca.crl",
    )


def _gen_key(size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


# ---------------------------------------------------------------------------
# DER helper tests
# ---------------------------------------------------------------------------

class TestDERHelpers(unittest.TestCase):

    def test_enc_dec_len_short(self):
        """Lengths < 0x80 use single-byte encoding."""
        for n in (0, 1, 10, 127):
            enc = ipsec._enc_len(n)
            decoded, next_pos = ipsec._dec_len(enc, 0)
            self.assertEqual(decoded, n)
            self.assertEqual(next_pos, 1)

    def test_enc_dec_len_long_form(self):
        """Lengths >= 0x80 use multi-byte encoding."""
        for n in (128, 255, 256, 65535, 65536):
            enc = ipsec._enc_len(n)
            decoded, _ = ipsec._dec_len(enc, 0)
            self.assertEqual(decoded, n)

    def test_oid_enc_roundtrip(self):
        """OID encoding should decode back to the same dotted string."""
        oids = [
            "1.2.840.113549.1.1.11",   # sha256WithRSAEncryption
            "1.3.6.1.5.5.7.3.5",       # id-kp-ipsecEndSystem
            "1.3.6.1.5.5.7.3.6",       # id-kp-ipsecTunnel
            "1.3.6.1.5.5.7.3.7",       # id-kp-ipsecUser
            "2.16.840.1.101.3.4.2.1",  # sha-256
        ]
        for oid_str in oids:
            enc = ipsec._oid_enc(oid_str)
            # enc starts with 0x06 tag + length; skip them to get value
            val_start = 2 if enc[1] < 0x80 else 2 + (enc[1] & 0x7F)
            decoded = ipsec._decode_oid_bytes(enc[2:enc[1] + 2])
            self.assertEqual(decoded, oid_str, f"OID roundtrip failed for {oid_str}")

    def test_int_enc_zero(self):
        enc = ipsec._int_enc(0)
        self.assertEqual(enc, b"\x02\x01\x00")

    def test_int_enc_positive(self):
        enc = ipsec._int_enc(1)
        # tag=0x02, len=1, value=0x01
        self.assertEqual(enc, b"\x02\x01\x01")

    def test_int_enc_needs_padding(self):
        """Values with high bit set need a leading zero byte."""
        enc = ipsec._int_enc(0x80)
        self.assertEqual(enc[0], 0x02)  # INTEGER tag
        val = enc[2:]
        self.assertEqual(val[0], 0x00)  # leading zero
        self.assertEqual(val[1], 0x80)

    def test_oct_enc(self):
        data = b"\xDE\xAD\xBE\xEF"
        enc = ipsec._oct_enc(data)
        self.assertEqual(enc[0], 0x04)  # OCTET STRING tag
        self.assertEqual(enc[2:], data)

    def test_generalized_time_format(self):
        dt = datetime.datetime(2026, 3, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)
        enc = ipsec._generalized_time(dt)
        self.assertEqual(enc[0], 0x18)  # GeneralizedTime tag
        time_str = enc[2:].decode()
        self.assertEqual(time_str, "20260328120000Z")


# ---------------------------------------------------------------------------
# RFC4945Validator — validate_request
# ---------------------------------------------------------------------------

class TestRFC4945ValidatorRequest(unittest.TestCase):

    # ── ipsec_tunnel ────────────────────────────────────────────────────────

    def test_tunnel_valid_with_dns(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=vpn.example.com", "ipsec_tunnel",
            san_dns=["vpn.example.com"]
        )
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_tunnel_valid_with_ip(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=10.0.0.1", "ipsec_tunnel",
            san_ips=["10.0.0.1"]
        )
        self.assertTrue(ok)

    def test_tunnel_missing_san_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=vpn.example.com", "ipsec_tunnel"
        )
        self.assertFalse(ok)
        self.assertIn("RFC 4945", err)
        self.assertIn("dNSName", err)

    # ── ipsec_end ───────────────────────────────────────────────────────────

    def test_end_valid_with_fqdn(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=host.example.com", "ipsec_end",
            san_dns=["host.example.com"]
        )
        self.assertTrue(ok)

    def test_end_missing_san_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=device", "ipsec_end"
        )
        self.assertFalse(ok)
        self.assertIn("ipsec_end", err)

    # ── ipsec_user ──────────────────────────────────────────────────────────

    def test_user_valid_with_email(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=Alice", "ipsec_user",
            san_emails=["alice@example.com"]
        )
        self.assertTrue(ok)

    def test_user_missing_email_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=Alice", "ipsec_user",
            san_dns=["alice.example.com"]
        )
        self.assertFalse(ok)
        self.assertIn("rfc822Name", err)

    # ── Wildcard prohibition ─────────────────────────────────────────────────

    def test_wildcard_dns_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=vpn.example.com", "ipsec_tunnel",
            san_dns=["*.example.com"]
        )
        self.assertFalse(ok)
        self.assertIn("wildcard", err.lower())

    def test_wildcard_in_subdomain_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=vpn.example.com", "ipsec_end",
            san_dns=["*.sub.example.com"]
        )
        self.assertFalse(ok)
        self.assertIn("wildcard", err.lower())

    def test_non_wildcard_accepted(self):
        ok, _ = ipsec.RFC4945Validator.validate_request(
            "CN=vpn.example.com", "ipsec_tunnel",
            san_dns=["sub.example.com", "vpn.example.com"]
        )
        self.assertTrue(ok)

    # ── CIDR prohibition ─────────────────────────────────────────────────────

    def test_cidr_in_san_ip_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=gw", "ipsec_tunnel",
            san_ips=["10.0.0.0/8"]
        )
        self.assertFalse(ok)
        self.assertIn("CIDR", err)

    def test_invalid_ip_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=gw", "ipsec_tunnel",
            san_ips=["not-an-ip"]
        )
        self.assertFalse(ok)
        self.assertIn("Invalid IP", err)

    def test_valid_ipv6_accepted(self):
        ok, _ = ipsec.RFC4945Validator.validate_request(
            "CN=gw6", "ipsec_end",
            san_ips=["2001:db8::1"]
        )
        self.assertTrue(ok)

    # ── Email format ─────────────────────────────────────────────────────────

    def test_email_missing_at_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=Alice", "ipsec_user",
            san_emails=["alice-no-at-sign"]
        )
        self.assertFalse(ok)
        self.assertIn("@", err)

    # ── Subject MUST be non-empty ─────────────────────────────────────────────

    def test_empty_subject_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "", "ipsec_end", san_dns=["host.example.com"]
        )
        self.assertFalse(ok)
        self.assertIn("empty", err.lower())

    def test_whitespace_only_subject_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "   ", "ipsec_end", san_dns=["host.example.com"]
        )
        self.assertFalse(ok)

    def test_blank_value_subject_rejected(self):
        ok, err = ipsec.RFC4945Validator.validate_request(
            "CN=  ", "ipsec_end", san_dns=["host.example.com"]
        )
        self.assertFalse(ok)
        self.assertIn("blank", err.lower())


# ---------------------------------------------------------------------------
# RFC4945Validator — check_cn_san_consistency
# ---------------------------------------------------------------------------

class TestRFC4945CNSANConsistency(unittest.TestCase):

    def test_cn_fqdn_in_san_no_warning(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "CN=vpn.example.com",
            san_dns=["vpn.example.com"],
            san_ips=[],
            san_emails=[],
        )
        self.assertIsNone(w)

    def test_cn_fqdn_not_in_san_warns(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "CN=vpn.example.com",
            san_dns=["other.example.com"],
            san_ips=[],
            san_emails=[],
        )
        self.assertIsNotNone(w)
        self.assertIn("vpn.example.com", w)

    def test_cn_ip_in_san_no_warning(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "CN=10.0.0.1",
            san_dns=[],
            san_ips=["10.0.0.1"],
            san_emails=[],
        )
        self.assertIsNone(w)

    def test_cn_ip_not_in_san_warns(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "CN=10.0.0.1",
            san_dns=[],
            san_ips=["10.0.0.2"],
            san_emails=[],
        )
        self.assertIsNotNone(w)
        self.assertIn("10.0.0.1", w)

    def test_non_fqdn_cn_no_warning(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "CN=Alice VPN User",
            san_dns=[],
            san_ips=[],
            san_emails=["alice@example.com"],
        )
        self.assertIsNone(w)

    def test_no_cn_no_warning(self):
        w = ipsec.RFC4945Validator.check_cn_san_consistency(
            "O=Example Corp",
            san_dns=["host.example.com"],
            san_ips=[],
            san_emails=[],
        )
        self.assertIsNone(w)


# ---------------------------------------------------------------------------
# RFC4945Validator — check_name_constraints
# ---------------------------------------------------------------------------

class TestRFC4945NameConstraints(unittest.TestCase):

    def _make_constrained_ca(self, tmpdir, permitted_dns=None, excluded_dns=None):
        ca = _make_ca(tmpdir)
        # Issue a sub-CA with name constraints
        permitted = []
        if permitted_dns:
            for d in permitted_dns:
                permitted.append(x509.DNSName(d))
        excluded = []
        if excluded_dns:
            for d in excluded_dns:
                excluded.append(x509.DNSName(d))

        if not permitted and not excluded:
            return ca

        nc = x509.NameConstraints(
            permitted_subtrees=permitted if permitted else None,
            excluded_subtrees=excluded if excluded else None,
        )
        # Patch the CA cert with name constraints for testing
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding as pad
        import datetime as dt

        _nvb = getattr(ca.ca_cert, "not_valid_before_utc", ca.ca_cert.not_valid_before)
        _nva = getattr(ca.ca_cert, "not_valid_after_utc",  ca.ca_cert.not_valid_after)
        builder = (
            x509.CertificateBuilder()
            .subject_name(ca.ca_cert.subject)
            .issuer_name(ca.ca_cert.issuer)
            .public_key(ca.ca_cert.public_key())
            .serial_number(ca.ca_cert.serial_number)
            .not_valid_before(_nvb)
            .not_valid_after(_nva)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(nc, critical=True)
        )
        patched_cert = builder.sign(ca.ca_key, hashes.SHA256())
        ca.ca_cert = patched_cert
        return ca

    def test_no_constraints_always_ok(self):
        with tempfile.TemporaryDirectory() as d:
            ca = _make_ca(d)
            ok, err = ipsec.RFC4945Validator.check_name_constraints(
                ca.ca_cert, ["anything.example.com"], [], []
            )
            self.assertTrue(ok)

    def test_permitted_subtree_match_ok(self):
        with tempfile.TemporaryDirectory() as d:
            ca = self._make_constrained_ca(d, permitted_dns=["example.com"])
            ok, err = ipsec.RFC4945Validator.check_name_constraints(
                ca.ca_cert, ["sub.example.com"], [], []
            )
            self.assertTrue(ok, err)

    def test_permitted_subtree_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as d:
            ca = self._make_constrained_ca(d, permitted_dns=["example.com"])
            ok, err = ipsec.RFC4945Validator.check_name_constraints(
                ca.ca_cert, ["other.org"], [], []
            )
            self.assertFalse(ok)
            self.assertIn("outside all NameConstraints", err)

    def test_excluded_subtree_match_fails(self):
        with tempfile.TemporaryDirectory() as d:
            ca = self._make_constrained_ca(d, excluded_dns=["bad.example.com"])
            ok, err = ipsec.RFC4945Validator.check_name_constraints(
                ca.ca_cert, ["sub.bad.example.com"], [], []
            )
            self.assertFalse(ok)
            self.assertIn("excluded subtree", err)

    def test_excluded_subtree_non_match_ok(self):
        with tempfile.TemporaryDirectory() as d:
            ca = self._make_constrained_ca(d, excluded_dns=["bad.example.com"])
            ok, err = ipsec.RFC4945Validator.check_name_constraints(
                ca.ca_cert, ["good.example.com"], [], []
            )
            self.assertTrue(ok, err)


# ---------------------------------------------------------------------------
# IPsecCertIssuer — issue
# ---------------------------------------------------------------------------

class TestIPsecCertIssuerIssue(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)
        self.issuer = ipsec.IPsecCertIssuer(self.ca)

    def _issue_tunnel(self, **kwargs):
        defaults = dict(
            subject_str="CN=vpn.example.com,O=TestOrg",
            profile="ipsec_tunnel",
            san_dns=["vpn.example.com"],
            validity_days=90,
        )
        defaults.update(kwargs)
        return self.issuer.issue(**defaults)

    # ── Basic issuance ────────────────────────────────────────────────────

    def test_issue_returns_certificate(self):
        cert, priv_key_pem, warning = self._issue_tunnel()
        self.assertIsInstance(cert, x509.Certificate)

    def test_issue_server_side_key_returns_pem(self):
        cert, priv_key_pem, warning = self._issue_tunnel()
        self.assertIsNotNone(priv_key_pem)
        self.assertIn("PRIVATE KEY", priv_key_pem)

    def test_issue_client_supplied_key_no_pem_returned(self):
        priv = _gen_key()
        pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        cert, priv_key_pem, warning = self._issue_tunnel(public_key_pem=pub_pem)
        self.assertIsNone(priv_key_pem)

    def test_issue_with_key_password_returns_encrypted_pem(self):
        cert, priv_key_pem, warning = self._issue_tunnel(key_password="s3cr3t")
        self.assertIsNotNone(priv_key_pem)
        self.assertIn("ENCRYPTED", priv_key_pem)

    # ── RFC 4945 EKU ──────────────────────────────────────────────────────

    def test_tunnel_profile_has_ipsec_tunnel_eku(self):
        cert, _, _ = self._issue_tunnel()
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [str(o) for o in eku.value]
        self.assertIn(str(ipsec.OID_KP_IPSEC_TUNNEL), oids)

    def test_end_profile_has_ipsec_end_system_eku(self):
        cert, _, _ = self.issuer.issue(
            subject_str="CN=device.example.com",
            profile="ipsec_end",
            san_dns=["device.example.com"],
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [str(o) for o in eku.value]
        self.assertIn(str(ipsec.OID_KP_IPSEC_END_SYSTEM), oids)

    def test_user_profile_has_ipsec_user_eku(self):
        cert, _, _ = self.issuer.issue(
            subject_str="CN=Alice",
            profile="ipsec_user",
            san_emails=["alice@example.com"],
        )
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = [str(o) for o in eku.value]
        self.assertIn(str(ipsec.OID_KP_IPSEC_USER), oids)

    # ── RFC 4945 Key Usage ────────────────────────────────────────────────

    def test_key_usage_digital_signature_only(self):
        cert, _, _ = self._issue_tunnel()
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertFalse(ku.key_encipherment)
        self.assertFalse(ku.key_cert_sign)
        self.assertFalse(ku.crl_sign)

    def test_key_usage_is_critical(self):
        cert, _, _ = self._issue_tunnel()
        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ext.critical)

    # ── Basic constraints ─────────────────────────────────────────────────

    def test_basic_constraints_not_ca(self):
        cert, _, _ = self._issue_tunnel()
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(bc.ca)

    # ── SAN present ───────────────────────────────────────────────────────

    def test_san_dns_present_in_cert(self):
        cert, _, _ = self._issue_tunnel(san_dns=["vpn.example.com", "backup.example.com"])
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = [n.value for n in san if isinstance(n, x509.DNSName)]
        self.assertIn("vpn.example.com", dns_names)
        self.assertIn("backup.example.com", dns_names)

    def test_san_ip_present_in_cert(self):
        import ipaddress
        cert, _, _ = self.issuer.issue(
            subject_str="CN=10.0.0.1",
            profile="ipsec_end",
            san_ips=["10.0.0.1"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ip_addrs = [str(n.value) for n in san if isinstance(n, x509.IPAddress)]
        self.assertIn("10.0.0.1", ip_addrs)

    # ── Validation failures ────────────────────────────────────────────────

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.issuer.issue(
                subject_str="CN=test",
                profile="unknown_profile",
                san_dns=["test.example.com"],
            )
        self.assertIn("Unknown IPsec profile", str(ctx.exception))

    def test_missing_required_san_raises(self):
        with self.assertRaises(ValueError):
            self.issuer.issue(
                subject_str="CN=vpn",
                profile="ipsec_tunnel",
                # no san_dns, no san_ips
            )

    def test_wildcard_san_raises(self):
        with self.assertRaises(ValueError):
            self.issuer.issue(
                subject_str="CN=vpn",
                profile="ipsec_tunnel",
                san_dns=["*.example.com"],
            )

    def test_cidr_san_raises(self):
        with self.assertRaises(ValueError):
            self.issuer.issue(
                subject_str="CN=gw",
                profile="ipsec_tunnel",
                san_ips=["10.0.0.0/8"],
            )


# ---------------------------------------------------------------------------
# IPsecCertIssuer — batch_issue  (RFC 4809 §3.1.2)
# ---------------------------------------------------------------------------

class TestIPsecCertIssuerBatch(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)
        self.issuer = ipsec.IPsecCertIssuer(self.ca)

    def test_batch_issue_returns_list(self):
        requests = [
            {"subject": "CN=gw1.example.com", "profile": "ipsec_tunnel",
             "san_dns": ["gw1.example.com"]},
            {"subject": "CN=gw2.example.com", "profile": "ipsec_tunnel",
             "san_dns": ["gw2.example.com"]},
        ]
        results = self.issuer.batch_issue(requests)
        self.assertEqual(len(results), 2)

    def test_batch_issue_success_entries(self):
        requests = [
            {"subject": "CN=h1.example.com", "profile": "ipsec_end",
             "san_dns": ["h1.example.com"]},
        ]
        results = self.issuer.batch_issue(requests)
        self.assertTrue(results[0]["ok"])
        self.assertIn("cert_pem", results[0])

    def test_batch_issue_partial_failure(self):
        requests = [
            {"subject": "CN=ok.example.com", "profile": "ipsec_end",
             "san_dns": ["ok.example.com"]},
            {"subject": "CN=bad", "profile": "ipsec_tunnel",
             # missing san for ipsec_tunnel — should produce an error result
            },
        ]
        results = self.issuer.batch_issue(requests)
        self.assertEqual(len(results), 2)
        # First should succeed
        self.assertTrue(results[0]["ok"])
        # Second should carry an error
        self.assertFalse(results[1]["ok"])
        self.assertIn("error", results[1])

    def test_batch_empty_returns_empty(self):
        results = self.issuer.batch_issue([])
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# IPsecCertIssuer — pkc_update  (RFC 4809 §3.3)
# ---------------------------------------------------------------------------

class TestIPsecPKCUpdate(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)
        self.issuer = ipsec.IPsecCertIssuer(self.ca)

    def _issue_tunnel(self):
        return self.issuer.issue(
            subject_str="CN=vpn.example.com,O=TestOrg",
            profile="ipsec_tunnel",
            san_dns=["vpn.example.com"],
            validity_days=90,
        )

    def test_pkc_update_issues_new_cert_with_same_subject(self):
        old_cert, _, _ = self._issue_tunnel()
        new_priv = _gen_key()
        new_pub_pem = new_priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

        new_cert, _ = self.issuer.pkc_update(
            old_serial=old_cert.serial_number,
            new_public_key_pem=new_pub_pem,
        )
        self.assertIsInstance(new_cert, x509.Certificate)
        self.assertEqual(new_cert.subject, old_cert.subject)

    def test_pkc_update_new_cert_has_different_serial(self):
        old_cert, _, _ = self._issue_tunnel()
        new_cert, _ = self.issuer.pkc_update(old_serial=old_cert.serial_number)
        self.assertNotEqual(new_cert.serial_number, old_cert.serial_number)

    def test_pkc_update_new_cert_different_public_key(self):
        old_cert, _, _ = self._issue_tunnel()
        new_priv = _gen_key()
        new_pub_pem = new_priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        new_cert, _ = self.issuer.pkc_update(
            old_serial=old_cert.serial_number,
            new_public_key_pem=new_pub_pem,
        )
        old_pub = old_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        new_pub = new_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertNotEqual(old_pub, new_pub)

    def test_pkc_update_nonexistent_serial_raises(self):
        with self.assertRaises((ValueError, RuntimeError)):
            self.issuer.pkc_update(old_serial=999999999)


# ---------------------------------------------------------------------------
# IPsecCertIssuer — pkc_renew  (RFC 4809 §3.5)
# ---------------------------------------------------------------------------

class TestIPsecPKCRenew(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmpdir)
        self.issuer = ipsec.IPsecCertIssuer(self.ca)

    def _issue_end(self):
        return self.issuer.issue(
            subject_str="CN=device.example.com",
            profile="ipsec_end",
            san_dns=["device.example.com"],
            validity_days=30,
        )

    def test_pkc_renew_returns_certificate(self):
        old_cert, _, _ = self._issue_end()
        new_cert = self.issuer.pkc_renew(old_serial=old_cert.serial_number, validity_days=90)
        self.assertIsInstance(new_cert, x509.Certificate)

    def test_pkc_renew_same_public_key(self):
        old_cert, _, _ = self._issue_end()
        new_cert = self.issuer.pkc_renew(old_serial=old_cert.serial_number)
        old_pub = old_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        new_pub = new_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(old_pub, new_pub)

    def test_pkc_renew_same_subject(self):
        old_cert, _, _ = self._issue_end()
        new_cert = self.issuer.pkc_renew(old_serial=old_cert.serial_number)
        self.assertEqual(new_cert.subject, old_cert.subject)

    def test_pkc_renew_new_serial(self):
        old_cert, _, _ = self._issue_end()
        new_cert = self.issuer.pkc_renew(old_serial=old_cert.serial_number)
        self.assertNotEqual(new_cert.serial_number, old_cert.serial_number)

    def test_pkc_renew_nonexistent_serial_raises(self):
        with self.assertRaises((ValueError, RuntimeError)):
            self.issuer.pkc_renew(old_serial=999999999)


# ---------------------------------------------------------------------------
# ApprovalQueue
# ---------------------------------------------------------------------------

class TestApprovalQueue(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self._tmpdir) / "ipsec.db")
        self.queue = ipsec.ApprovalQueue(self.db_path)

    def test_enqueue_returns_request_id(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"}, requester_ip="1.2.3.4")
        self.assertIsInstance(rid, str)
        self.assertTrue(len(rid) > 0)

    def test_get_returns_request(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        row = self.queue.get(rid)
        self.assertIsNotNone(row)
        self.assertEqual(row["request_id"], rid)
        self.assertEqual(row["state"], ipsec.ApprovalQueue.STATE_PENDING)

    def test_get_unknown_returns_none(self):
        self.assertIsNone(self.queue.get("nonexistent-uuid"))

    def test_list_pending(self):
        rid1 = self.queue.enqueue({"subject_str": "CN=a"})
        rid2 = self.queue.enqueue({"subject_str": "CN=b"})
        pending = self.queue.list_pending()
        ids = [r["request_id"] for r in pending]
        self.assertIn(rid1, ids)
        self.assertIn(rid2, ids)

    def test_approve_changes_state(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.approve(rid, serial=12345, cert_pem="-----BEGIN CERTIFICATE-----")
        row = self.queue.get(rid)
        self.assertEqual(row["state"], ipsec.ApprovalQueue.STATE_APPROVED)
        self.assertEqual(row["result_serial"], 12345)

    def test_approve_removes_from_pending(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.approve(rid, serial=99, cert_pem="CERT")
        pending = self.queue.list_pending()
        ids = [r["request_id"] for r in pending]
        self.assertNotIn(rid, ids)

    def test_reject_changes_state(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.reject(rid, reason="Policy violation")
        row = self.queue.get(rid)
        self.assertEqual(row["state"], ipsec.ApprovalQueue.STATE_REJECTED)
        self.assertEqual(row["reject_reason"], "Policy violation")

    def test_reject_removes_from_pending(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.reject(rid)
        pending = self.queue.list_pending()
        ids = [r["request_id"] for r in pending]
        self.assertNotIn(rid, ids)

    def test_confirm_receipt_after_approve(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.approve(rid, serial=42, cert_pem="CERT")
        result = self.queue.confirm_receipt(rid, serial=42)
        self.assertTrue(result)

    def test_confirm_receipt_wrong_serial(self):
        rid = self.queue.enqueue({"subject_str": "CN=test"})
        self.queue.approve(rid, serial=42, cert_pem="CERT")
        result = self.queue.confirm_receipt(rid, serial=999)
        self.assertFalse(result)

    def test_record_direct_confirmation(self):
        result = self.queue.record_direct_confirmation(serial=100, requester_ip="1.2.3.4")
        self.assertTrue(result)

    def test_record_direct_confirmation_duplicate_returns_false(self):
        self.queue.record_direct_confirmation(serial=200)
        result = self.queue.record_direct_confirmation(serial=200)
        self.assertFalse(result)

    def test_multiple_enqueue_separate_ids(self):
        ids = {self.queue.enqueue({}) for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_queue_persists_across_instances(self):
        rid = self.queue.enqueue({"subject_str": "CN=persistent"})
        # Create a new ApprovalQueue instance pointing at same DB
        queue2 = ipsec.ApprovalQueue(self.db_path)
        row = queue2.get(rid)
        self.assertIsNotNone(row)
        self.assertEqual(row["request_id"], rid)


if __name__ == "__main__":
    unittest.main()
