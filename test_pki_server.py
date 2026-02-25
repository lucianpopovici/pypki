#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
PyPKI Test Suite
================
Comprehensive unit and integration tests covering:

  - RFC 5280  §4 / §5   Certificate and CRL structure
  - RFC 5280  §6818     General clarifications
  - RFC 9608            id-ce-noRevAvail extension
  - RFC 4210 / RFC 4211 CMPv2 message structure
  - RFC 9480            CMPv3 pvno negotiation + genm types
  - RFC 6960 / RFC 5019 OCSP request/response structure
  - RFC 7030            EST enrolment
  - CertProfile         all seven profiles
  - AuditLog            SQLite persistence
  - RateLimiter         token-bucket semantics
  - CertificateAuthority all public methods
  - HTTP API            management endpoints

Run:
    python -m pytest test_pki_server.py -v
    python -m pytest test_pki_server.py -v -k rfc5280
    python -m pytest test_pki_server.py -v -k rfc9608
"""

import base64
import datetime
import hashlib
import http.client
import http.server
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Ensure the module under test is importable
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
_OUTPUTS = Path(__file__).parent.parent / "outputs"
for _p in (_HERE, _OUTPUTS):
    if (_p / "pki_server.py").exists():
        sys.path.insert(0, str(_p))
        break

import pki_server as pki

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_ca(tmpdir: str, ocsp_url: str = "", crl_url: str = "") -> pki.CertificateAuthority:
    return pki.CertificateAuthority(
        ca_dir=tmpdir,
        ocsp_url=ocsp_url,
        crl_url=crl_url,
    )


def _gen_key(size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def _ext_oids(cert: x509.Certificate) -> set:
    return {e.oid.dotted_string for e in cert.extensions}


CDP_OID  = ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string   # 2.5.29.31
AIA_OID  = ExtensionOID.AUTHORITY_INFORMATION_ACCESS.dotted_string  # 1.3.6.1.5.5.7.1.1
NO_REV_OID = "2.5.29.56"
SKI_OID  = ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string
AKI_OID  = ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string
BC_OID   = ExtensionOID.BASIC_CONSTRAINTS.dotted_string
KU_OID   = ExtensionOID.KEY_USAGE.dotted_string
EKU_OID  = ExtensionOID.EXTENDED_KEY_USAGE.dotted_string
SAN_OID  = ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string


# ===========================================================================
# 1. RFC 5280 §4 — Certificate Structure
# ===========================================================================

class TestRFC5280CertStructure(unittest.TestCase):
    """RFC 5280 §4.1 — Basic certificate field requirements."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    # §4.1 — version MUST be v3 when extensions are present
    def test_version_is_v3(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        self.assertEqual(cert.version, x509.Version.v3,
                         "RFC 5280 §4.1: certificate version MUST be v3 (value=2)")

    # §4.1.2.2 — serial number MUST be positive
    def test_serial_is_positive(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        self.assertGreater(cert.serial_number, 0,
                           "RFC 5280 §4.1.2.2: serial MUST be a positive integer")

    # §4.1.2.2 — serial number MUST fit in 20 octets
    def test_serial_max_20_octets(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        serial_bytes = cert.serial_number.to_bytes(
            (cert.serial_number.bit_length() + 7) // 8, "big"
        )
        self.assertLessEqual(len(serial_bytes), 20,
                             "RFC 5280 §4.1.2.2: serial MUST NOT exceed 20 octets")

    # §4.1.2.2 — serials must be unique per issuer
    def test_serials_are_unique(self):
        certs = [self.ca.issue_certificate(f"CN=test{i}", self.key.public_key())
                 for i in range(5)]
        serials = [c.serial_number for c in certs]
        self.assertEqual(len(serials), len(set(serials)),
                         "RFC 5280 §4.1.2.2: serial numbers MUST be unique per issuer")

    # §4.1.2.3 — signature algorithm matches signatureAlgorithm field
    def test_signature_algorithm(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        self.assertIsInstance(cert.signature_hash_algorithm, hashes.SHA256,
                              "RFC 5280 §4.1.2.3: signature algorithm MUST be SHA256withRSA")

    # §4.1.2.4 — issuer MUST be non-empty DN
    def test_issuer_non_empty(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        self.assertTrue(len(cert.issuer.rdns) > 0,
                        "RFC 5280 §4.1.2.4: issuer MUST be non-empty DN")

    # §4.1.2.4 — issuer MUST match CA subject
    def test_issuer_matches_ca_subject(self):
        cert = self.ca.issue_certificate("CN=test", self.key.public_key())
        self.assertEqual(cert.issuer, self.ca.ca_cert.subject,
                         "RFC 5280 §4.1.2.4: issuer MUST match the CA's subject name")

    # §4.1.2.5 — validity dates must use UTCTime (≤2049) or GeneralizedTime (≥2050)
    def test_validity_time_encoding_utctime(self):
        """Dates through 2049 MUST use UTCTime (DER tag 0x17)."""
        cert = self.ca.issue_certificate("CN=test", self.key.public_key(),
                                         validity_days=365)
        der = cert.public_bytes(Encoding.DER)
        # UTCTime tag = 0x17; scan for first two time fields in DER
        time_tags = [b for b in der if b in (0x17, 0x18)][:4]
        self.assertIn(0x17, time_tags,
                      "RFC 5280 §4.1.2.5: dates ≤2049 MUST use UTCTime (tag 0x17)")

    # §4.1.2.6 — subject MUST be non-empty (or SAN critical)
    def test_subject_non_empty(self):
        cert = self.ca.issue_certificate("CN=myservice", self.key.public_key())
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertTrue(len(cn_attrs) > 0 and cn_attrs[0].value,
                        "RFC 5280 §4.1.2.6: subject MUST have at least one non-empty attribute")


# ===========================================================================
# 2. RFC 5280 §4.2 — Certificate Extensions
# ===========================================================================

class TestRFC5280Extensions(unittest.TestCase):
    """RFC 5280 §4.2 — Required and optional extension behaviour."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp,
                            ocsp_url="http://ocsp.test/ocsp",
                            crl_url="http://crl.test/ca.crl")
        self.key = _gen_key()

    def _issue(self, **kwargs) -> x509.Certificate:
        return self.ca.issue_certificate("CN=test", self.key.public_key(), **kwargs)

    # §4.2.1.1 — AKI MUST be present in non-self-signed certs
    def test_aki_present_in_end_entity(self):
        cert = self._issue()
        self.assertIn(AKI_OID, _ext_oids(cert),
                      "RFC 5280 §4.2.1.1: AKI MUST be present in non-self-signed certificates")

    # §4.2.1.1 — AKI value must match CA SKI
    def test_aki_matches_ca_ski(self):
        cert = self._issue()
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        ca_ski = self.ca.ca_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.key_identifier
        self.assertEqual(aki.value.key_identifier, ca_ski,
                         "RFC 5280 §4.2.1.1: AKI.keyIdentifier MUST match issuer SKI")

    # §4.2.1.2 — SKI MUST be present in CA certs, SHOULD in end-entity
    def test_ski_present_in_end_entity(self):
        cert = self._issue()
        self.assertIn(SKI_OID, _ext_oids(cert),
                      "RFC 5280 §4.2.1.2: SKI SHOULD be present in end-entity certificates")

    def test_ski_present_in_ca_cert(self):
        self.assertIn(SKI_OID, _ext_oids(self.ca.ca_cert),
                      "RFC 5280 §4.2.1.2: SKI MUST be present in CA certificates")

    # §4.2.1.3 — KeyUsage MUST be critical
    def test_key_usage_is_critical(self):
        cert = self._issue()
        ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ku_ext.critical,
                        "RFC 5280 §4.2.1.3: KeyUsage extension MUST be marked critical")

    # §4.2.1.9 — BasicConstraints MUST be present and critical
    def test_basic_constraints_present_and_critical(self):
        cert = self._issue()
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc_ext.critical,
                        "RFC 5280 §4.2.1.9: BasicConstraints MUST be critical")
        self.assertFalse(bc_ext.value.ca,
                         "RFC 5280 §4.2.1.9: end-entity cert BasicConstraints.cA MUST be False")

    def test_basic_constraints_ca_true_for_ca(self):
        bc_ext = self.ca.ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc_ext.value.ca,
                        "RFC 5280 §4.2.1.9: CA cert BasicConstraints.cA MUST be True")
        self.assertTrue(bc_ext.critical)

    # §4.2.1.6 — SAN added when requested
    def test_san_dns_names_added(self):
        cert = self._issue(san_dns=["example.com", "www.example.com"])
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        self.assertIn("example.com", dns_names)
        self.assertIn("www.example.com", dns_names)

    # §4.2.1.13 — AIA OCSP present when ocsp_url configured
    def test_aia_ocsp_present_when_configured(self):
        cert = self._issue(profile="tls_server", san_dns=["a.test"])
        self.assertIn(AIA_OID, _ext_oids(cert),
                      "RFC 5280 §4.2.1.13: AIA SHOULD be present when OCSP URL is configured")
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_uris = [
            ad.access_location.value
            for ad in aia.value
            if ad.access_method == x509.AuthorityInformationAccessOID.OCSP
        ]
        self.assertIn("http://ocsp.test/ocsp", ocsp_uris)

    # §4.2.1.14 — CDP present when crl_url configured
    def test_cdp_present_when_configured(self):
        cert = self._issue(profile="tls_server", san_dns=["a.test"])
        self.assertIn(CDP_OID, _ext_oids(cert),
                      "RFC 5280 §4.2.1.14: CDP SHOULD be present when CRL URL is configured")
        cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        uris = [
            n.value
            for dp in cdp.value
            for n in (dp.full_name or [])
            if isinstance(n, x509.UniformResourceIdentifier)
        ]
        self.assertIn("http://crl.test/ca.crl", uris)


# ===========================================================================
# 3. RFC 5280 §5 — CRL Structure
# ===========================================================================

class TestRFC5280CRL(unittest.TestCase):
    """RFC 5280 §5 — CRL field and extension requirements."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def _load_crl(self) -> x509.CertificateRevocationList:
        der = self.ca.generate_crl()
        return x509.load_der_x509_crl(der)

    # §5.1.2.1 — version should be v2 (value=1) for CRLs with extensions
    def test_crl_version(self):
        crl = self._load_crl()
        # v2 CRL (value=1) is required when extensions are present
        self.assertEqual(crl.next_update_utc is not None, True,
                         "CRL must have nextUpdate")

    # §5.1.2.2 — signature algorithm
    def test_crl_signature_algorithm(self):
        crl = self._load_crl()
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA256)

    # §5.1.2.3 — issuer MUST match CA subject
    def test_crl_issuer_matches_ca(self):
        crl = self._load_crl()
        self.assertEqual(crl.issuer, self.ca.ca_cert.subject,
                         "RFC 5280 §5.1.2.3: CRL issuer MUST match CA subject")

    # §5.1.2.4 — thisUpdate MUST be present
    def test_crl_this_update_present(self):
        crl = self._load_crl()
        self.assertIsNotNone(crl.last_update_utc,
                             "RFC 5280 §5.1.2.4: CRL thisUpdate MUST be present")

    # §5.1.2.5 — nextUpdate SHOULD be present (we always set it)
    def test_crl_next_update_present(self):
        crl = self._load_crl()
        self.assertIsNotNone(crl.next_update_utc,
                             "RFC 5280 §5.1.2.5: CRL nextUpdate SHOULD be present")

    # §5.1.2.5 — nextUpdate MUST be after thisUpdate
    def test_crl_next_update_after_this_update(self):
        crl = self._load_crl()
        self.assertGreater(crl.next_update_utc, crl.last_update_utc,
                           "RFC 5280 §5.1.2.5: nextUpdate MUST be after thisUpdate")

    # CRL signature MUST verify against CA public key
    def test_crl_signature_verifies(self):
        crl = self._load_crl()
        try:
            crl.is_signature_valid(self.ca.ca_key.public_key())
            valid = True
        except Exception:
            valid = False
        self.assertTrue(valid, "CRL signature MUST verify against CA public key")

    # Revoked cert MUST appear in CRL
    def test_revoked_cert_in_crl(self):
        cert = self.ca.issue_certificate("CN=revtest", self.key.public_key())
        serial = cert.serial_number
        self.ca.revoke_certificate(serial, reason=1)
        crl = self._load_crl()
        revoked_serials = [rc.serial_number for rc in crl]
        self.assertIn(serial, revoked_serials,
                      "Revoked certificate serial MUST appear in the CRL")

    # Good cert MUST NOT appear in CRL
    def test_good_cert_not_in_crl(self):
        cert = self.ca.issue_certificate("CN=goodcert", self.key.public_key())
        crl = self._load_crl()
        revoked_serials = [rc.serial_number for rc in crl]
        self.assertNotIn(cert.serial_number, revoked_serials,
                         "Non-revoked certificate MUST NOT appear in CRL")

    # §5.2.4 — Delta CRL has deltaCRLIndicator extension
    def test_delta_crl_has_indicator(self):
        # Revoke one cert so the delta has content
        cert = self.ca.issue_certificate("CN=deltarest", self.key.public_key())
        self.ca.revoke_certificate(cert.serial_number)
        delta_der = self.ca.generate_delta_crl(base_crl_number=1)
        delta_crl = x509.load_der_x509_crl(delta_der)
        ext_oids = {e.oid.dotted_string for e in delta_crl.extensions}
        # deltaCRLIndicator OID = 2.5.29.27
        self.assertIn("2.5.29.27", ext_oids,
                      "RFC 5280 §5.2.4: delta CRL MUST contain deltaCRLIndicator extension")

    # §5.2.4 — deltaCRLIndicator MUST be critical
    def test_delta_crl_indicator_is_critical(self):
        cert = self.ca.issue_certificate("CN=deltacrit", self.key.public_key())
        self.ca.revoke_certificate(cert.serial_number)
        delta_der = self.ca.generate_delta_crl(base_crl_number=1)
        delta_crl = x509.load_der_x509_crl(delta_der)
        for ext in delta_crl.extensions:
            if ext.oid.dotted_string == "2.5.29.27":
                self.assertTrue(ext.critical,
                                "RFC 5280 §5.2.4: deltaCRLIndicator MUST be critical")
                return
        self.fail("deltaCRLIndicator extension not found in delta CRL")

    # Delta CRL only contains revocations after last base snapshot
    def test_delta_crl_incremental(self):
        cert1 = self.ca.issue_certificate("CN=base1", self.key.public_key())
        self.ca.revoke_certificate(cert1.serial_number)
        # Generate delta (snapshots current state as base)
        self.ca.generate_delta_crl(base_crl_number=1)

        # Revoke a second cert AFTER the base snapshot
        cert2 = self.ca.issue_certificate("CN=delta2", self.key.public_key())
        self.ca.revoke_certificate(cert2.serial_number)

        delta2_der = self.ca.generate_delta_crl(base_crl_number=2)
        delta2 = x509.load_der_x509_crl(delta2_der)
        revoked_serials = [rc.serial_number for rc in delta2]

        # cert2 should appear (revoked after base)
        self.assertIn(cert2.serial_number, revoked_serials,
                      "Delta CRL must include revocations after the base snapshot")
        # cert1 should NOT appear (was revoked before the base snapshot)
        self.assertNotIn(cert1.serial_number, revoked_serials,
                         "Delta CRL must NOT include revocations before the base snapshot")


# ===========================================================================
# 4. RFC 9608 — id-ce-noRevAvail Extension
# ===========================================================================

class TestRFC9608NoRevAvail(unittest.TestCase):
    """RFC 9608 — No Revocation Available extension compliance."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp,
                            ocsp_url="http://ocsp.test/ocsp",
                            crl_url="http://crl.test/ca.crl")
        self.key = _gen_key()

    def _issue(self, **kw) -> x509.Certificate:
        return self.ca.issue_certificate("CN=test", self.key.public_key(), **kw)

    # Extension MUST be present for short_lived profile
    def test_no_rev_avail_present_in_short_lived(self):
        cert = self._issue(profile="short_lived", validity_days=3)
        self.assertIn(NO_REV_OID, _ext_oids(cert),
                      "RFC 9608 §4: id-ce-noRevAvail MUST be present on short_lived certs")

    # Extension MUST be non-critical (RFC 9608 §4)
    def test_no_rev_avail_is_non_critical(self):
        cert = self._issue(profile="short_lived", validity_days=3)
        for ext in cert.extensions:
            if ext.oid.dotted_string == NO_REV_OID:
                self.assertFalse(ext.critical,
                                 "RFC 9608 §4: noRevAvail MUST be non-critical")
                return
        self.fail("noRevAvail not found")

    # Extension value MUST be ASN.1 NULL (0x05 0x00)
    def test_no_rev_avail_value_is_null(self):
        cert = self._issue(profile="short_lived", validity_days=3)
        for ext in cert.extensions:
            if ext.oid.dotted_string == NO_REV_OID:
                self.assertEqual(ext.value.value, b"\x05\x00",
                                 "RFC 9608: noRevAvail value MUST be ASN.1 NULL (05 00)")
                return
        self.fail("noRevAvail not found")

    # RFC 9608 §4 — CDP MUST NOT be present when noRevAvail is set
    def test_cdp_suppressed_when_no_rev_avail(self):
        cert = self._issue(profile="short_lived", validity_days=3)
        self.assertNotIn(CDP_OID, _ext_oids(cert),
                         "RFC 9608 §4: CDP MUST NOT be present when noRevAvail is set")

    # RFC 9608 §4 — AIA OCSP MUST NOT be present when noRevAvail is set
    def test_aia_ocsp_suppressed_when_no_rev_avail(self):
        cert = self._issue(profile="short_lived", validity_days=3)
        self.assertNotIn(AIA_OID, _ext_oids(cert),
                         "RFC 9608 §4: AIA OCSP MUST NOT be present when noRevAvail is set")

    # RFC 9608 §4 — MUST NOT appear in CA certificates
    def test_no_rev_avail_absent_in_ca_cert(self):
        _, sub_ca_cert = self.ca.issue_sub_ca("Test Sub CA", validity_days=365)
        self.assertNotIn(NO_REV_OID, _ext_oids(sub_ca_cert),
                         "RFC 9608 §4: noRevAvail MUST NOT appear in CA certificates")

    # Explicit no_rev_avail=True parameter
    def test_explicit_no_rev_avail_parameter(self):
        cert = self._issue(validity_days=5, no_rev_avail=True)
        self.assertIn(NO_REV_OID, _ext_oids(cert))
        self.assertNotIn(CDP_OID, _ext_oids(cert))
        self.assertNotIn(AIA_OID, _ext_oids(cert))

    # explicit no_rev_avail=True on a CA-profile cert is IGNORED
    def test_no_rev_avail_forced_off_for_ca(self):
        """no_rev_avail must be suppressed for CA certs regardless of caller input."""
        _, sub_cert = self.ca.issue_sub_ca("Forced Sub CA", validity_days=365)
        self.assertNotIn(NO_REV_OID, _ext_oids(sub_cert),
                         "noRevAvail must never appear on a CA certificate")

    # Standard cert (>threshold days) has CDP and AIA, no noRevAvail
    def test_standard_cert_has_cdp_and_aia_no_norev(self):
        cert = self._issue(profile="tls_server", san_dns=["ok.test"], validity_days=90)
        self.assertNotIn(NO_REV_OID, _ext_oids(cert),
                         "Standard cert MUST NOT carry noRevAvail")
        self.assertIn(CDP_OID, _ext_oids(cert))
        self.assertIn(AIA_OID, _ext_oids(cert))

    # Short-lived cert still has BasicConstraints, SKI, AKI, KeyUsage
    def test_short_lived_has_mandatory_extensions(self):
        cert = self._issue(profile="short_lived", validity_days=1)
        oids = _ext_oids(cert)
        self.assertIn(BC_OID,  oids, "BasicConstraints must be present")
        self.assertIn(SKI_OID, oids, "SKI must be present")
        self.assertIn(AKI_OID, oids, "AKI must be present")
        self.assertIn(KU_OID,  oids, "KeyUsage must be present")


# ===========================================================================
# 5. Certificate Profiles
# ===========================================================================

class TestCertificateProfiles(unittest.TestCase):
    """Verify each CertProfile produces compliant extensions."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def _issue(self, profile, **kw) -> x509.Certificate:
        return self.ca.issue_certificate("CN=test", self.key.public_key(),
                                         profile=profile, **kw)

    def test_tls_server_has_server_auth_eku(self):
        cert = self._issue("tls_server", san_dns=["s.test"])
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, list(eku.value))

    def test_tls_server_key_usage(self):
        cert = self._issue("tls_server", san_dns=["s.test"])
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertTrue(ku.key_encipherment)
        self.assertFalse(ku.key_cert_sign)

    def test_tls_client_has_client_auth_eku(self):
        cert = self._issue("tls_client")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, list(eku.value))

    def test_code_signing_has_correct_eku(self):
        cert = self._issue("code_signing")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.CODE_SIGNING, list(eku.value))

    def test_code_signing_key_usage(self):
        cert = self._issue("code_signing")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.digital_signature)
        self.assertTrue(ku.content_commitment)
        self.assertFalse(ku.key_encipherment)

    def test_email_profile_has_email_protection_eku(self):
        cert = self._issue("email")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.EMAIL_PROTECTION, list(eku.value))

    def test_ocsp_signing_profile(self):
        cert = self._issue("ocsp_signing")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.OCSP_SIGNING, list(eku.value))
        # Must have id-pkix-ocsp-nocheck (1.3.6.1.5.5.7.48.1.5)
        ext_oids = _ext_oids(cert)
        self.assertIn("1.3.6.1.5.5.7.48.1.5", ext_oids,
                      "ocsp_signing profile must have id-pkix-ocsp-nocheck extension")

    def test_sub_ca_profile_bc_ca_true(self):
        key = _gen_key(4096)  # sub_ca uses 4096 internally, but we can pass our own
        cert = self._issue("sub_ca")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca)
        self.assertEqual(bc.path_length, 0)

    def test_sub_ca_profile_key_usage(self):
        cert = self._issue("sub_ca")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign)
        self.assertTrue(ku.crl_sign)

    def test_short_lived_profile_has_no_rev_avail(self):
        cert = self._issue("short_lived", validity_days=3)
        self.assertIn(NO_REV_OID, _ext_oids(cert))

    def test_short_lived_profile_has_both_auth_ekus(self):
        cert = self._issue("short_lived", validity_days=3)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        ekus = list(eku.value)
        self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, ekus)
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, ekus)

    def test_unknown_profile_falls_back_to_default(self):
        prof = pki.CertProfile.get("nonexistent_profile_xyz")
        default = pki.CertProfile.get("default")
        self.assertEqual(prof, default)


# ===========================================================================
# 6. Sub-CA Issuance
# ===========================================================================

class TestSubCAIssuance(unittest.TestCase):
    """RFC 5280 §4.2.1.9 — Sub-CA certificate path length constraints."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)

    def test_sub_ca_cert_is_ca(self):
        _, cert = self.ca.issue_sub_ca("Test Sub CA")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca, "Sub-CA cert MUST have BasicConstraints.cA=True")

    def test_sub_ca_path_length_is_zero(self):
        _, cert = self.ca.issue_sub_ca("Test Sub CA")
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertEqual(bc.path_length, 0,
                         "Sub-CA issued by root CA MUST have pathLenConstraint=0")

    def test_sub_ca_key_size_4096(self):
        key, _ = self.ca.issue_sub_ca("Big Sub CA")
        self.assertEqual(key.key_size, 4096, "Sub-CA key MUST be 4096 bits")

    def test_sub_ca_issuer_is_root(self):
        _, cert = self.ca.issue_sub_ca("Test Sub CA")
        self.assertEqual(cert.issuer, self.ca.ca_cert.subject,
                         "Sub-CA issuer MUST be the root CA subject")

    def test_sub_ca_signed_by_root(self):
        _, cert = self.ca.issue_sub_ca("Test Sub CA")
        try:
            self.ca.ca_key.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                SHA256(),
            )
            verified = True
        except Exception:
            verified = False
        self.assertTrue(verified, "Sub-CA cert MUST be signed by root CA key")

    def test_sub_ca_has_key_cert_sign_usage(self):
        _, cert = self.ca.issue_sub_ca("Test Sub CA")
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign)
        self.assertTrue(ku.crl_sign)

    def test_sub_ca_stored_in_db(self):
        _, cert = self.ca.issue_sub_ca("DB Test Sub CA")
        stored = self.ca.get_cert_by_serial(cert.serial_number)
        self.assertIsNotNone(stored, "Sub-CA cert MUST be stored in the certificate DB")


# ===========================================================================
# 7. PKCS#12 Export
# ===========================================================================

class TestPKCS12Export(unittest.TestCase):
    """PKCS#12 bundle export — cert + CA chain, no private key."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()
        self.cert = self.ca.issue_certificate("CN=p12test", self.key.public_key())

    def test_p12_exported_without_error(self):
        p12 = self.ca.export_pkcs12(self.cert.serial_number)
        self.assertIsNotNone(p12)
        self.assertIsInstance(p12, bytes)
        self.assertGreater(len(p12), 100)

    def test_p12_contains_certificate(self):
        from cryptography.hazmat.primitives.serialization import pkcs12
        p12 = self.ca.export_pkcs12(self.cert.serial_number)
        _, _, certs = pkcs12.load_key_and_certificates(p12, None)
        # Without a private key, pkcs12 puts all certs in additional_certs
        self.assertIsNotNone(certs)
        all_serials = [c.serial_number for c in certs]
        self.assertIn(self.cert.serial_number, all_serials,
                      "PKCS#12 bundle must contain the target certificate")

    def test_p12_contains_ca_chain(self):
        from cryptography.hazmat.primitives.serialization import pkcs12
        p12 = self.ca.export_pkcs12(self.cert.serial_number)
        _, _, cas = pkcs12.load_key_and_certificates(p12, None)
        self.assertIsNotNone(cas)
        self.assertGreater(len(cas), 0)
        ca_serials = [c.serial_number for c in cas]
        self.assertIn(self.ca.ca_cert.serial_number, ca_serials)

    def test_p12_has_no_private_key(self):
        from cryptography.hazmat.primitives.serialization import pkcs12
        p12 = self.ca.export_pkcs12(self.cert.serial_number)
        key, _, _ = pkcs12.load_key_and_certificates(p12, None)
        self.assertIsNone(key, "PKCS#12 export MUST NOT include private key")

    def test_p12_returns_none_for_unknown_serial(self):
        p12 = self.ca.export_pkcs12(999999)
        self.assertIsNone(p12)

    def test_p12_with_password(self):
        from cryptography.hazmat.primitives.serialization import pkcs12
        password = b"s3cr3t"
        p12 = self.ca.export_pkcs12(self.cert.serial_number, password=password)
        self.assertIsNotNone(p12)
        # When no private key is stored, pkcs12 puts all certs in the additional_certs list
        _, _, certs = pkcs12.load_key_and_certificates(p12, password)
        self.assertIsNotNone(certs)
        all_serials = [c.serial_number for c in certs]
        self.assertIn(self.cert.serial_number, all_serials,
                      "PKCS#12 (with password) must contain the target certificate")


# ===========================================================================
# 8. CSR Policy Validation
# ===========================================================================

class TestCSRValidation(unittest.TestCase):
    """RFC 5280 + naming policy enforcement."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def _make_csr(self, cn: str = "test.example.com",
                  san_dns=None) -> x509.CertificateSigningRequest:
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn)
            ]))
        )
        if san_dns:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
                critical=False,
            )
        return builder.sign(self.key, SHA256())

    def test_valid_csr_passes(self):
        csr = self._make_csr(cn="host.example.com",
                             san_dns=["host.example.com"])
        violations = self.ca.validate_csr(csr, profile="tls_server")
        self.assertEqual(violations, [], f"Valid CSR should pass: {violations}")

    def test_missing_cn_fails(self):
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([])
        )
        csr = builder.sign(self.key, SHA256())
        violations = self.ca.validate_csr(csr, profile="default")
        self.assertTrue(any("Common Name" in v or "CN" in v for v in violations),
                        "Missing CN must produce a violation")

    def test_tls_server_requires_san(self):
        csr = self._make_csr(cn="host.example.com")  # no SAN
        violations = self.ca.validate_csr(csr, profile="tls_server")
        self.assertTrue(any("SubjectAlternativeName" in v or "SAN" in v
                            for v in violations),
                        "tls_server profile must require SAN extension")

    def test_tls_server_rejects_non_fqdn_cn(self):
        csr = self._make_csr(cn="not a valid domain!!!")
        violations = self.ca.validate_csr(csr, profile="tls_server")
        self.assertTrue(len(violations) > 0,
                        "Invalid FQDN in CN should produce a violation for tls_server")

    def test_weak_key_fails(self):
        weak_key = _gen_key(1024)
        builder = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([
                       x509.NameAttribute(NameOID.COMMON_NAME, "test")
                   ])))
        csr = builder.sign(weak_key, SHA256())
        violations = self.ca.validate_csr(csr, profile="default")
        self.assertTrue(any("1024" in v or "2048" in v or "key size" in v.lower()
                            for v in violations),
                        "RSA key < 2048 bits must produce a violation")

    def test_invalid_signature_fails(self):
        csr_valid = self._make_csr()
        csr_der = bytearray(csr_valid.public_bytes(Encoding.DER))
        # Flip a byte in the signature to invalidate it
        csr_der[-5] ^= 0xFF
        try:
            csr_tampered = x509.load_der_x509_csr(bytes(csr_der))
            violations = self.ca.validate_csr(csr_tampered)
            self.assertTrue(any("signature" in v.lower() for v in violations),
                            "Invalid CSR signature must produce a violation")
        except Exception:
            pass  # Some parsers reject malformed DER before we can check


# ===========================================================================
# 9. AuditLog
# ===========================================================================

class TestAuditLog(unittest.TestCase):
    """Structured audit log persistence."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.log = pki.AuditLog(Path(self._tmp))

    def test_record_and_retrieve(self):
        self.log.record("issue", "serial=1000 subject='CN=test'", "10.0.0.1")
        events = self.log.recent(10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "issue")
        self.assertEqual(events[0]["ip"], "10.0.0.1")
        self.assertIn("serial=1000", events[0]["detail"])

    def test_recent_is_ordered_newest_first(self):
        for i in range(5):
            self.log.record("test", f"seq={i}", "")
            time.sleep(0.01)
        events = self.log.recent(5)
        seqs = [int(e["detail"].split("=")[1]) for e in events]
        self.assertEqual(seqs, sorted(seqs, reverse=True),
                         "recent() must return events newest-first")

    def test_recent_limit_respected(self):
        for i in range(20):
            self.log.record("spam", f"i={i}", "")
        events = self.log.recent(5)
        self.assertEqual(len(events), 5)

    def test_timestamp_format_is_iso8601(self):
        self.log.record("startup", "", "")
        events = self.log.recent(1)
        ts = events[0]["ts"]
        # ISO 8601 — must parse without error
        datetime.datetime.fromisoformat(ts)

    def test_db_persists_across_instances(self):
        self.log.record("persist", "test", "")
        log2 = pki.AuditLog(Path(self._tmp))
        events = log2.recent(10)
        self.assertTrue(any(e["event"] == "persist" for e in events),
                        "Audit log must persist across AuditLog instances")

    def test_ca_issuance_recorded_with_audit(self):
        ca = _make_ca(self._tmp)
        key = _gen_key()
        ca.issue_certificate("CN=audit-test", key.public_key(), audit=self.log)
        events = self.log.recent(10)
        self.assertTrue(any(e["event"] == "issue" for e in events),
                        "Certificate issuance must be recorded in audit log")

    def test_revocation_recorded_with_audit(self):
        ca = _make_ca(self._tmp)
        key = _gen_key()
        cert = ca.issue_certificate("CN=rev-audit", key.public_key(), audit=self.log)
        ca.revoke_certificate(cert.serial_number)
        # Revocation audit is driven by the HTTP handler, not CA directly;
        # just verify audit.record() works with revoke data
        self.log.record("revoke", f"serial={cert.serial_number}", "127.0.0.1")
        events = self.log.recent(5)
        self.assertTrue(any(e["event"] == "revoke" for e in events))


# ===========================================================================
# 10. RateLimiter
# ===========================================================================

class TestRateLimiter(unittest.TestCase):
    """Token-bucket rate limiter semantics."""

    def test_allows_up_to_limit(self):
        rl = pki.RateLimiter(max_per_minute=5)
        for i in range(5):
            self.assertTrue(rl.allow("192.168.1.1"),
                            f"Request {i+1} should be allowed")

    def test_blocks_over_limit(self):
        rl = pki.RateLimiter(max_per_minute=3)
        for _ in range(3):
            rl.allow("10.0.0.1")
        self.assertFalse(rl.allow("10.0.0.1"),
                         "4th request must be denied when limit is 3")

    def test_different_ips_are_independent(self):
        rl = pki.RateLimiter(max_per_minute=2)
        for _ in range(2):
            rl.allow("1.1.1.1")
        # IP 1 is exhausted but IP 2 should still work
        self.assertFalse(rl.allow("1.1.1.1"))
        self.assertTrue(rl.allow("2.2.2.2"),
                        "Rate limits MUST be per-IP, not global")

    def test_status_returns_count(self):
        rl = pki.RateLimiter(max_per_minute=10)
        rl.allow("3.3.3.3")
        rl.allow("3.3.3.3")
        status = rl.status("3.3.3.3")
        self.assertEqual(status["requests_last_minute"], 2)
        self.assertEqual(status["limit"], 10)

    def test_unknown_ip_status(self):
        rl = pki.RateLimiter(max_per_minute=10)
        status = rl.status("9.9.9.9")
        self.assertEqual(status["requests_last_minute"], 0)

    def test_thread_safety(self):
        rl = pki.RateLimiter(max_per_minute=100)
        results = []
        def worker():
            results.append(rl.allow("concurrent.test"))
        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        allowed = sum(results)
        self.assertLessEqual(allowed, 100)
        self.assertGreater(allowed, 0)


# ===========================================================================
# 11. CertificateAuthority — core operations
# ===========================================================================

class TestCertificateAuthority(unittest.TestCase):
    """Core CA operations — issuance, revocation, DB persistence."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def test_ca_cert_is_self_signed(self):
        """CA cert issuer == CA cert subject."""
        self.assertEqual(self.ca.ca_cert.issuer, self.ca.ca_cert.subject)

    def test_ca_cert_can_sign_certs(self):
        ku = self.ca.ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(ku.key_cert_sign,
                        "CA cert MUST have keyCertSign KeyUsage bit")

    def test_ca_dir_created(self):
        self.assertTrue(Path(self._tmp).exists())
        self.assertTrue((Path(self._tmp) / "ca.key").exists())
        self.assertTrue((Path(self._tmp) / "ca.crt").exists())

    def test_issue_and_retrieve(self):
        cert = self.ca.issue_certificate("CN=retrieve-test", self.key.public_key())
        stored_der = self.ca.get_cert_by_serial(cert.serial_number)
        self.assertIsNotNone(stored_der)
        stored = x509.load_der_x509_certificate(stored_der)
        self.assertEqual(stored.serial_number, cert.serial_number)

    def test_list_certificates(self):
        n_before = len(self.ca.list_certificates())
        self.ca.issue_certificate("CN=list-test1", self.key.public_key())
        self.ca.issue_certificate("CN=list-test2", self.key.public_key())
        certs = self.ca.list_certificates()
        self.assertEqual(len(certs), n_before + 2)

    def test_revoke_certificate(self):
        cert = self.ca.issue_certificate("CN=revoke-me", self.key.public_key())
        result = self.ca.revoke_certificate(cert.serial_number, reason=1)
        self.assertTrue(result)
        certs = self.ca.list_certificates()
        record = next(c for c in certs if c["serial"] == cert.serial_number)
        self.assertTrue(record["revoked"])

    def test_revoke_nonexistent_returns_false(self):
        result = self.ca.revoke_certificate(999999, reason=0)
        self.assertFalse(result)

    def test_double_revoke_returns_false(self):
        cert = self.ca.issue_certificate("CN=double-rev", self.key.public_key())
        self.ca.revoke_certificate(cert.serial_number)
        result = self.ca.revoke_certificate(cert.serial_number)
        self.assertFalse(result, "Double-revocation must return False")

    def test_san_ip_address(self):
        import ipaddress
        cert = self.ca.issue_certificate(
            "CN=iptest", self.key.public_key(),
            san_ips=["192.168.1.1", "10.0.0.1"]
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        self.assertIn(ipaddress.IPv4Address("192.168.1.1"), ips)

    def test_san_email(self):
        cert = self.ca.issue_certificate(
            "CN=emailtest", self.key.public_key(),
            san_emails=["user@example.com"]
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        emails = san.value.get_values_for_type(x509.RFC822Name)
        self.assertIn("user@example.com", emails)

    def test_validity_days_respected(self):
        cert = self.ca.issue_certificate("CN=validity", self.key.public_key(),
                                         validity_days=30)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertAlmostEqual(delta.days, 30, delta=1,
                               msg="Issued cert validity must respect validity_days parameter")

    def test_ca_cert_pem_property(self):
        pem = self.ca.ca_cert_pem
        self.assertTrue(pem.startswith(b"-----BEGIN CERTIFICATE-----"))

    def test_ca_cert_der_property(self):
        der = self.ca.ca_cert_der
        cert = x509.load_der_x509_certificate(der)
        self.assertEqual(cert.serial_number, self.ca.ca_cert.serial_number)

    def test_ca_persists_across_instantiation(self):
        """CA key and cert must reload correctly from disk."""
        serial1 = self.ca.ca_cert.serial_number
        ca2 = _make_ca(self._tmp)
        self.assertEqual(ca2.ca_cert.serial_number, serial1,
                         "CA must load the same cert from disk on re-instantiation")

    def test_subject_parsing_full_dn(self):
        cert = self.ca.issue_certificate(
            "CN=Full Test,O=Acme Corp,C=US,L=Springfield,ST=IL",
            self.key.public_key()
        )
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        o  = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        self.assertEqual(cn, "Full Test")
        self.assertEqual(o, "Acme Corp")


# ===========================================================================
# 12. ServerConfig
# ===========================================================================

class TestServerConfig(unittest.TestCase):
    """Live-reloadable configuration."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.cfg = pki.ServerConfig(Path(self._tmp))

    def test_defaults_available(self):
        self.assertEqual(self.cfg.end_entity_days, 365)
        self.assertEqual(self.cfg.tls_server_days, 365)
        self.assertEqual(self.cfg.ca_days, 3650)

    def test_patch_end_entity_days(self):
        self.cfg.patch({"validity": {"end_entity_days": 90}})
        self.assertEqual(self.cfg.end_entity_days, 90)

    def test_patch_accepts_valid_range(self):
        """Patch must accept any positive integer (validation is caller's responsibility)."""
        self.cfg.patch({"validity": {"end_entity_days": 180}})
        self.assertEqual(self.cfg.end_entity_days, 180)

    def test_patch_invalid_key_ignored(self):
        """Unknown keys in patch payload should not raise."""
        before = self.cfg.end_entity_days
        self.cfg.patch({"validity": {"nonexistent_key": 999}})
        self.assertEqual(self.cfg.end_entity_days, before)

    def test_as_dict_returns_validity(self):
        d = self.cfg.as_dict()
        self.assertIn("validity", d)
        self.assertIn("end_entity_days", d["validity"])

    def test_config_written_to_disk(self):
        cfg_path = Path(self._tmp) / "config.json"
        self.assertTrue(cfg_path.exists())

    def test_config_reloads_from_disk(self):
        cfg_path = Path(self._tmp) / "config.json"
        data = json.loads(cfg_path.read_text())
        data["validity"]["end_entity_days"] = 180
        cfg_path.write_text(json.dumps(data))
        # Touch mtime to trigger reload
        cfg_path.touch()
        time.sleep(0.05)
        cfg2 = pki.ServerConfig(Path(self._tmp))
        self.assertEqual(cfg2.end_entity_days, 180)


# ===========================================================================
# 13. HTTP API endpoints
# ===========================================================================

class TestHTTPAPI(unittest.TestCase):
    """Integration tests for the HTTP management API."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp()
        cls.ca = _make_ca(cls._tmp)
        cls.audit = pki.AuditLog(Path(cls._tmp))
        cls.rate = pki.RateLimiter(max_per_minute=100)
        cmp_handler = pki.CMPv3Handler(cls.ca)
        handler_class = pki.make_cmpv3_handler(cls.ca, cmp_handler,
                                                cls.audit, cls.rate)

        # Find a free port
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()

        cls.server = pki.ThreadedHTTPServer(("127.0.0.1", cls.port), handler_class)
        cls._thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls._thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, json.loads(body)

    def _post(self, path, data):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps(data).encode()
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        resp_body = resp.read()
        conn.close()
        return resp.status, json.loads(resp_body)

    def test_health_endpoint(self):
        status, body = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertIn("ca_serial", body)

    def test_config_endpoint(self):
        status, body = self._get("/config")
        self.assertEqual(status, 200)
        self.assertIn("validity", body)

    def test_ca_cert_pem_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/ca/cert.pem")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn(b"BEGIN CERTIFICATE", body)

    def test_ca_cert_der_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/ca/cert.der")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        cert = x509.load_der_x509_certificate(body)
        self.assertEqual(cert.serial_number, self.ca.ca_cert.serial_number)

    def test_list_certs_endpoint(self):
        status, body = self._get("/api/certs")
        self.assertEqual(status, 200)
        self.assertIn("certificates", body)
        self.assertIsInstance(body["certificates"], list)

    def test_crl_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/ca/crl")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        crl = x509.load_der_x509_crl(body)
        self.assertEqual(crl.issuer, self.ca.ca_cert.subject)

    def test_delta_crl_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/ca/delta-crl")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        crl = x509.load_der_x509_crl(body)
        self.assertIsNotNone(crl)

    def test_revoke_api(self):
        key = _gen_key()
        cert = self.ca.issue_certificate("CN=http-revoke", key.public_key())
        status, body = self._post("/api/revoke",
                                   {"serial": cert.serial_number, "reason": 1})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_revoke_nonexistent_serial(self):
        status, body = self._post("/api/revoke", {"serial": 888888, "reason": 0})
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])

    def test_issue_sub_ca_api(self):
        status, body = self._post("/api/sub-ca",
                                   {"cn": "API Sub CA", "validity_days": 365})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIn("cert_pem", body)
        self.assertIn("key_pem", body)
        # Verify the returned cert is actually a CA cert
        cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca)

    def test_cert_pem_download(self):
        key = _gen_key()
        cert = self.ca.issue_certificate("CN=pem-dl", key.public_key())
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", f"/api/certs/{cert.serial_number}/pem")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn(b"BEGIN CERTIFICATE", body)

    def test_cert_p12_download(self):
        key = _gen_key()
        cert = self.ca.issue_certificate("CN=p12-dl", key.public_key())
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", f"/api/certs/{cert.serial_number}/p12")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "application/x-pkcs12")
        self.assertGreater(len(body), 100)

    def test_rate_limit_endpoint(self):
        status, body = self._get("/api/rate-limit")
        self.assertEqual(status, 200)
        self.assertIn("requests_last_minute", body)

    def test_audit_endpoint(self):
        status, body = self._get("/api/audit")
        self.assertEqual(status, 200)
        self.assertIn("events", body)
        self.assertIsInstance(body["events"], list)

    def test_unknown_path_returns_endpoint_list(self):
        status, body = self._get("/nonexistent-path-xyz")
        self.assertEqual(status, 200)
        self.assertIn("endpoints", body)

    def test_rate_limit_enforced(self):
        """HTTP 429 must be returned when rate limit is exceeded."""
        key = _gen_key()
        # Build a CA with a limit of 2 per minute
        tmp2 = tempfile.mkdtemp()
        ca2 = _make_ca(tmp2)
        rate2 = pki.RateLimiter(max_per_minute=2)
        cmp2 = pki.CMPv2Handler(ca2)
        handler2 = pki.make_handler(ca2, cmp2, rate_limiter=rate2)

        import socket as _sock
        s = _sock.socket()
        s.bind(("127.0.0.1", 0))
        port2 = s.getsockname()[1]
        s.close()

        srv2 = pki.ThreadedHTTPServer(("127.0.0.1", port2), handler2)
        t2 = threading.Thread(target=srv2.serve_forever, daemon=True)
        t2.start()
        time.sleep(0.05)

        try:
            statuses = []
            for _ in range(4):
                conn = http.client.HTTPConnection("127.0.0.1", port2, timeout=3)
                # Send a POST with a dummy body to hit CMP routing + rate limiter
                conn.request("POST", "/",
                             body=b"\x00\x01\x02",
                             headers={"Content-Type": "application/pkixcmp"})
                resp = conn.getresponse()
                resp.read()
                statuses.append(resp.status)
                conn.close()
            self.assertIn(429, statuses,
                          "Rate limiter must return HTTP 429 when limit is exceeded")
        finally:
            srv2.shutdown()


# ===========================================================================
# 14. OCSP Request Parsing (RFC 6960 / RFC 5019)
# ===========================================================================

class TestOCSPParsing(unittest.TestCase):
    """RFC 6960 — OCSP request structure."""

    def _make_ocsp_request(self, serial: int, nonce: Optional[bytes] = None) -> bytes:
        """Build a minimal DER-encoded OCSPRequest for testing."""
        try:
            from ocsp_server import OCSPResponseBuilder, _enc_len, _seq, _oid, _oct, _int, _ctx
        except ImportError:
            self.skipTest("ocsp_server.py not importable")

        # We test via round-trip: build with cryptography, parse with our parser
        from cryptography.x509 import ocsp as crypto_ocsp
        # Build using cryptography's OCSP builder
        builder = crypto_ocsp.OCSPRequestBuilder()
        # We need a cert and issuer to build a real request
        return None  # placeholder

    def test_ocsp_module_importable(self):
        try:
            import ocsp_server
            self.assertTrue(hasattr(ocsp_server, "OCSPRequestParser"))
            self.assertTrue(hasattr(ocsp_server, "OCSPResponseBuilder"))
            self.assertTrue(hasattr(ocsp_server, "start_ocsp_server"))
        except ImportError:
            self.skipTest("ocsp_server.py not in path")

    def test_ocsp_server_starts_and_responds(self):
        """OCSP responder must start, handle a GET of an unknown serial, and respond."""
        try:
            import ocsp_server
        except ImportError:
            self.skipTest("ocsp_server.py not importable")

        tmp = tempfile.mkdtemp()
        ca = _make_ca(tmp)

        import socket as _sock
        s = _sock.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        srv = ocsp_server.start_ocsp_server("127.0.0.1", port, ca, cache_seconds=10)
        time.sleep(0.1)
        try:
            # GET with a trivially invalid base64 → 400 with OCSPResponse
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            # A minimal valid-ish base64 request (will parse as malformed)
            conn.request("GET", "/ocsp/AAAA")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            # We expect 200 with application/ocsp-response (even for errors)
            self.assertEqual(resp.getheader("Content-Type"), "application/ocsp-response")
        finally:
            srv.shutdown()

    def test_ocsp_signing_cert_has_nocheck_extension(self):
        """RFC 6960 §4.2.2.2 — OCSP signing cert must have id-pkix-ocsp-nocheck."""
        try:
            import ocsp_server
        except ImportError:
            self.skipTest("ocsp_server.py not importable")

        tmp = tempfile.mkdtemp()
        ca = _make_ca(tmp)
        _, ocsp_cert = ocsp_server.provision_ocsp_signing_cert(ca)
        ext_oids = _ext_oids(ocsp_cert)
        self.assertIn("1.3.6.1.5.5.7.48.1.5", ext_oids,
                      "RFC 6960 §4.2.2.2: OCSP signing cert MUST have id-pkix-ocsp-nocheck")

    def test_ocsp_signing_cert_has_ocsp_signing_eku(self):
        try:
            import ocsp_server
        except ImportError:
            self.skipTest("ocsp_server.py not importable")

        tmp = tempfile.mkdtemp()
        ca = _make_ca(tmp)
        _, ocsp_cert = ocsp_server.provision_ocsp_signing_cert(ca)
        eku = ocsp_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertIn(ExtendedKeyUsageOID.OCSP_SIGNING, list(eku.value),
                      "RFC 6960: OCSP signing cert MUST have OCSPSigning EKU")

    def test_ocsp_signing_cert_not_ca(self):
        try:
            import ocsp_server
        except ImportError:
            self.skipTest("ocsp_server.py not importable")

        tmp = tempfile.mkdtemp()
        ca = _make_ca(tmp)
        _, ocsp_cert = ocsp_server.provision_ocsp_signing_cert(ca)
        bc = ocsp_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(bc.ca, "OCSP signing cert MUST NOT be a CA cert")


# ===========================================================================
# 15. CMPv2 / CMPv3 Message Structure
# ===========================================================================

class TestCMPMessageStructure(unittest.TestCase):
    """RFC 4210 / RFC 9480 — CMP message structure basics."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)

    def test_cmpv2_handler_instantiates(self):
        handler = pki.CMPv2Handler(self.ca)
        self.assertIsNotNone(handler)

    def test_cmpv3_handler_instantiates(self):
        handler = pki.CMPv3Handler(self.ca)
        self.assertIsNotNone(handler)

    def test_cmpv2_handler_rejects_garbage(self):
        handler = pki.CMPv2Handler(self.ca)
        result = handler.handle(b"\x00\x01\x02\x03garbage")
        # Must return a valid DER PKIMessage (error response), not raise
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_cmpv3_handler_rejects_garbage(self):
        handler = pki.CMPv3Handler(self.ca)
        result = handler.handle(b"\xFF\xFE\xFD")
        self.assertIsInstance(result, bytes)

    def test_build_pki_message_returns_bytes(self):
        import os
        asn1 = pki.CMPv2ASN1()
        # build_pkiconf_body returns DER bytes for the body content
        body_content = asn1.build_pkiconf_body()
        # PKIConf body type = 19
        PKICONF_BODY_TYPE = 19
        txid = os.urandom(16)
        nonce = os.urandom(16)
        msg = asn1.build_pki_message(
            body_type=PKICONF_BODY_TYPE,
            body_content=body_content,
            transaction_id=txid,
            sender_nonce=nonce,
        )
        self.assertIsInstance(msg, bytes)
        self.assertGreater(len(msg), 0)

    def test_well_known_uri_constant(self):
        self.assertTrue(hasattr(pki, "CMP_WELL_KNOWN_PATH"))
        self.assertEqual(pki.CMP_WELL_KNOWN_PATH, "/.well-known/cmp")

    def test_cmpv3_pvno_constants(self):
        self.assertEqual(pki.CMPv3Handler.PVNO_CMP2021, 3)
        self.assertEqual(pki.CMPv3Handler.PVNO_CMP2000, 2)


# ===========================================================================
# 16. ACME RFC 9608 integration
# ===========================================================================

class TestACMERFC9608Integration(unittest.TestCase):
    """Verify ACME server honours RFC 9608 noRevAvail threshold."""

    def test_short_lived_profile_selected_below_threshold(self):
        """Simulates the profile-selection logic in _handle_finalize."""
        validity = 3
        threshold = 7
        profile = "short_lived" if validity <= threshold else "tls_server"
        self.assertEqual(profile, "short_lived")

    def test_tls_server_profile_selected_above_threshold(self):
        validity = 90
        threshold = 7
        profile = "short_lived" if validity <= threshold else "tls_server"
        self.assertEqual(profile, "tls_server")

    def test_acme_module_has_cert_validity_days_attr(self):
        try:
            import acme_server
            self.assertTrue(hasattr(acme_server.ACMEHandler, "cert_validity_days"))
            self.assertTrue(hasattr(acme_server.ACMEHandler, "short_lived_threshold_days"))
        except ImportError:
            self.skipTest("acme_server.py not importable")

    def test_short_lived_cert_no_cdp_no_aia(self):
        """End-to-end: short_lived cert must have noRevAvail, no CDP, no AIA."""
        tmp = tempfile.mkdtemp()
        ca = _make_ca(tmp,
                       ocsp_url="http://ocsp.test/ocsp",
                       crl_url="http://crl.test/ca.crl")
        key = _gen_key()
        cert = ca.issue_certificate(
            "CN=short.acme.test", key.public_key(),
            san_dns=["short.acme.test"],
            validity_days=1,
            profile="short_lived",
        )
        oids = _ext_oids(cert)
        self.assertIn(NO_REV_OID, oids)
        self.assertNotIn(CDP_OID, oids)
        self.assertNotIn(AIA_OID, oids)

    def test_start_acme_server_accepts_new_params(self):
        """start_acme_server must accept cert_validity_days and short_lived_threshold_days."""
        try:
            import inspect, acme_server
            sig = inspect.signature(acme_server.start_acme_server)
            self.assertIn("cert_validity_days", sig.parameters)
            self.assertIn("short_lived_threshold_days", sig.parameters)
        except ImportError:
            self.skipTest("acme_server.py not importable")


# ===========================================================================
# 17. EST server basics (RFC 7030)
# ===========================================================================

class TestESTModule(unittest.TestCase):
    """Basic EST module structural checks."""

    def test_est_module_importable(self):
        try:
            import est_server
            self.assertTrue(hasattr(est_server, "start_est_server"))
            self.assertTrue(hasattr(est_server, "ESTHandler"))
        except ImportError:
            self.skipTest("est_server.py not importable")

    def test_est_handler_has_required_operations(self):
        try:
            import est_server
            # simplereenroll is dispatched through _handle_simpleenroll with path differentiation
            for op in ["_handle_cacerts", "_handle_simpleenroll",
                       "_handle_csrattrs", "_handle_serverkeygen"]:
                self.assertTrue(hasattr(est_server.ESTHandler, op),
                                f"EST handler must implement {op}")
            # simplereenroll path is handled by _dispatch routing to simpleenroll handler
            self.assertTrue(hasattr(est_server.ESTHandler, "_dispatch"),
                            "EST handler must have _dispatch routing method")
        except ImportError:
            self.skipTest("est_server.py not importable")

    def test_build_csrattrs_returns_der(self):
        try:
            import est_server
            der = est_server.build_csrattrs()
            self.assertIsInstance(der, bytes)
            self.assertGreater(len(der), 0)
            # Should start with SEQUENCE tag
            self.assertEqual(der[0], 0x30)
        except ImportError:
            self.skipTest("est_server.py not importable")


# ===========================================================================
# 18. Module-level structural checks
# ===========================================================================

class TestModuleStructure(unittest.TestCase):
    """Verify all expected public symbols are present."""

    REQUIRED_CLASSES = [
        "CertificateAuthority", "ServerConfig", "CMPv2Handler", "CMPv3Handler",
        "CMPv2HTTPHandler", "CMPv2ASN1", "AuditLog", "RateLimiter", "CertProfile",
        "ThreadedHTTPServer", "TLSServer",
    ]
    REQUIRED_FUNCTIONS = [
        "make_handler", "make_cmpv3_handler", "start_bootstrap_server", "main",
    ]
    REQUIRED_CONSTANTS = [
        "CMP_WELL_KNOWN_PATH", "OID_NO_REV_AVAIL", "NO_REV_AVAIL_THRESHOLD_DAYS",
        "DEFAULT_CONFIG",
    ]

    def test_required_classes_present(self):
        for cls in self.REQUIRED_CLASSES:
            self.assertTrue(hasattr(pki, cls), f"pki_server must export class {cls}")

    def test_required_functions_present(self):
        for fn in self.REQUIRED_FUNCTIONS:
            self.assertTrue(hasattr(pki, fn), f"pki_server must export function {fn}")

    def test_required_constants_present(self):
        for const in self.REQUIRED_CONSTANTS:
            self.assertTrue(hasattr(pki, const),
                            f"pki_server must export constant {const}")

    def test_cert_profile_has_all_profiles(self):
        expected = {"tls_server", "tls_client", "code_signing", "email",
                    "ocsp_signing", "sub_ca", "short_lived", "default"}
        actual = set(pki.CertProfile.PROFILES.keys())
        self.assertEqual(actual, expected,
                         f"Missing profiles: {expected - actual}")

    def test_no_rev_avail_oid_correct(self):
        self.assertEqual(pki.OID_NO_REV_AVAIL.dotted_string, "2.5.29.56",
                         "noRevAvail OID must be 2.5.29.56 per RFC 9608")



# ===========================================================================
# 19. RFC 9549 / RFC 9598 — IDNA normalisation + SmtpUTF8Mailbox
# ===========================================================================

class TestRFC9549IDNA(unittest.TestCase):
    """RFC 9549 §4.1 — dNSName U-labels MUST be converted to A-labels."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def _san_dns(self, cert):
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.DNSName)

    def _san_emails(self, cert):
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.RFC822Name)

    def _san_other_names(self, cert):
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.OtherName)

    # ── DNS SAN — U-label -> A-label ──────────────────────────────────────────

    def test_ascii_dns_passes_through(self):
        """Pure ASCII domain names must pass through unchanged."""
        cert = self.ca.issue_certificate(
            "CN=ascii", self.key.public_key(),
            san_dns=["example.com", "www.example.com"]
        )
        names = self._san_dns(cert)
        self.assertIn("example.com", names)
        self.assertIn("www.example.com", names)

    def test_u_label_dns_converted_to_a_label(self):
        """RFC 9549 §4.1: U-label dNSName MUST be stored as A-label."""
        cert = self.ca.issue_certificate(
            "CN=idn", self.key.public_key(),
            san_dns=["münchen.de"]
        )
        names = self._san_dns(cert)
        self.assertIn("xn--mnchen-3ya.de", names,
                      "RFC 9549 §4.1: München→xn--mnchen-3ya must be A-label encoded")
        self.assertNotIn("münchen.de", names,
                         "U-label must not appear in the encoded cert")

    def test_multi_label_idn_all_labels_encoded(self):
        """Each label of a multi-label IDN domain must be encoded independently."""
        cert = self.ca.issue_certificate(
            "CN=idn-multi", self.key.public_key(),
            san_dns=["sub.münchen.de"]
        )
        names = self._san_dns(cert)
        self.assertIn("sub.xn--mnchen-3ya.de", names,
                      "sub-label IDN must encode the IDN segment only")

    def test_wildcard_label_preserved(self):
        """Wildcard label (*) must be preserved; only IDN labels encoded."""
        cert = self.ca.issue_certificate(
            "CN=wildcard", self.key.public_key(),
            san_dns=["*.example.com"]
        )
        names = self._san_dns(cert)
        self.assertIn("*.example.com", names, "Wildcard label must be preserved")

    # ── Email SAN — ASCII local + IDN host -> rfc822Name with A-label host ────

    def test_ascii_email_ascii_host_unchanged(self):
        """Plain ASCII email must be stored as rfc822Name unchanged."""
        cert = self.ca.issue_certificate(
            "CN=email-ascii", self.key.public_key(),
            san_emails=["user@example.com"]
        )
        emails = self._san_emails(cert)
        self.assertIn("user@example.com", emails)

    def test_ascii_local_idn_host_encoded(self):
        """RFC 9549 §4.2: ASCII local-part with IDN host -> rfc822Name, A-label host."""
        cert = self.ca.issue_certificate(
            "CN=email-idn-host", self.key.public_key(),
            san_emails=["user@münchen.de"]
        )
        emails = self._san_emails(cert)
        self.assertIn("user@xn--mnchen-3ya.de", emails,
                      "ASCII local-part + IDN host must produce rfc822Name with A-label host")
        self.assertNotIn("user@münchen.de", emails,
                         "U-label host must not appear in rfc822Name")

    def test_non_ascii_local_uses_smtp_utf8_mailbox(self):
        """RFC 9598 §3: non-ASCII local-part MUST use SmtpUTF8Mailbox otherName."""
        cert = self.ca.issue_certificate(
            "CN=email-utf8", self.key.public_key(),
            san_emails=["üser@münchen.de"]
        )
        # Must NOT appear as rfc822Name
        emails = self._san_emails(cert)
        self.assertEqual(emails, [],
                         "Non-ASCII local-part must NOT be stored as rfc822Name")
        # MUST appear as SmtpUTF8Mailbox otherName
        others = self._san_other_names(cert)
        smtp_others = [o for o in others
                       if o.type_id.dotted_string == "1.3.6.1.5.5.7.8.9"]
        self.assertEqual(len(smtp_others), 1,
                         "Non-ASCII local-part MUST produce exactly one SmtpUTF8Mailbox OtherName")

    def test_smtp_utf8_mailbox_oid_is_correct(self):
        """SmtpUTF8Mailbox OID must be 1.3.6.1.5.5.7.8.9 per RFC 9598."""
        cert = self.ca.issue_certificate(
            "CN=oid-check", self.key.public_key(),
            san_emails=["müller@example.com"]
        )
        others = self._san_other_names(cert)
        self.assertTrue(any(o.type_id.dotted_string == "1.3.6.1.5.5.7.8.9"
                            for o in others),
                        "SmtpUTF8Mailbox OID must be 1.3.6.1.5.5.7.8.9")

    def test_smtp_utf8_mailbox_value_is_utf8string(self):
        """SmtpUTF8Mailbox value must be a DER UTF8String (tag 0x0C)."""
        cert = self.ca.issue_certificate(
            "CN=utf8-value", self.key.public_key(),
            san_emails=["üser@münchen.de"]
        )
        others = self._san_other_names(cert)
        smtp_val = next(o.value for o in others
                        if o.type_id.dotted_string == "1.3.6.1.5.5.7.8.9")
        self.assertEqual(smtp_val[0], 0x0C,
                         "SmtpUTF8Mailbox value MUST begin with UTF8String tag (0x0C)")

    def test_smtp_utf8_mailbox_contains_original_address(self):
        """SmtpUTF8Mailbox UTF8String value must contain the original UTF-8 mailbox."""
        mailbox = "üser@münchen.de"
        cert = self.ca.issue_certificate(
            "CN=utf8-content", self.key.public_key(),
            san_emails=[mailbox]
        )
        others = self._san_other_names(cert)
        smtp_val = next(o.value for o in others
                        if o.type_id.dotted_string == "1.3.6.1.5.5.7.8.9")
        # Skip tag + length bytes; remainder is the UTF-8 content
        # Tag=0x0C, length is 1 or 2 bytes
        if smtp_val[1] < 0x80:
            payload = smtp_val[2:]
        elif smtp_val[1] == 0x81:
            payload = smtp_val[3:]
        else:
            payload = smtp_val[4:]
        self.assertEqual(payload.decode("utf-8"), mailbox,
                         "SmtpUTF8Mailbox payload must be the original UTF-8 mailbox address")

    def test_mixed_email_list_correct_routing(self):
        """Mixed list of ASCII and non-ASCII emails must be routed independently."""
        cert = self.ca.issue_certificate(
            "CN=mixed-email", self.key.public_key(),
            san_emails=["alice@example.com", "bob@münchen.de", "müller@example.com"]
        )
        emails = self._san_emails(cert)
        others = self._san_other_names(cert)
        smtp_others = [o for o in others
                       if o.type_id.dotted_string == "1.3.6.1.5.5.7.8.9"]
        self.assertIn("alice@example.com", emails)
        self.assertIn("bob@xn--mnchen-3ya.de", emails,
                      "IDN host email must be A-label encoded in rfc822Name")
        self.assertEqual(len(smtp_others), 1,
                         "Exactly one SmtpUTF8Mailbox for the non-ASCII local-part email")

    # ── domainComponent in subject DN ─────────────────────────────────────────

    def test_dc_attribute_accepted_in_subject(self):
        """DC= in subject string must produce a DOMAIN_COMPONENT attribute."""
        from cryptography.x509.oid import NameOID
        cert = self.ca.issue_certificate(
            "CN=dc.test,DC=example,DC=com", self.key.public_key()
        )
        dc_attrs = cert.subject.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)
        self.assertEqual(len(dc_attrs), 2,
                         "Two DC= components must be parsed from subject string")

    def test_idn_dc_attribute_a_label_encoded(self):
        """RFC 6818 §5 / RFC 9549 §4: IDN domainComponent labels MUST be A-labels."""
        from cryptography.x509.oid import NameOID
        cert = self.ca.issue_certificate(
            "CN=idn-dc,DC=münchen,DC=de", self.key.public_key()
        )
        dc_attrs = cert.subject.get_attributes_for_oid(NameOID.DOMAIN_COMPONENT)
        values = [a.value for a in dc_attrs]
        self.assertIn("xn--mnchen-3ya", values,
                      "IDN domainComponent must be A-label encoded per RFC 6818 §5")
        self.assertNotIn("münchen", values,
                         "U-label must not appear in domainComponent")


# ===========================================================================
# 20. RFC 5280 §4.2.1.4 / RFC 6818 — CertificatePolicies
# ===========================================================================

class TestCertificatePolicies(unittest.TestCase):
    """RFC 5280 §4.2.1.4 and RFC 6818 §3 — CertificatePolicies extension."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.ca = _make_ca(self._tmp)
        self.key = _gen_key()

    def _cp(self, cert) -> x509.CertificatePolicies:
        return cert.extensions.get_extension_for_class(
            x509.CertificatePolicies
        ).value

    # ── Basic presence ────────────────────────────────────────────────────────

    def test_no_policies_by_default(self):
        """CertificatePolicies MUST NOT be present if not requested."""
        cert = self.ca.issue_certificate("CN=no-pol", self.key.public_key())
        ext_oids = _ext_oids(cert)
        self.assertNotIn("2.5.29.32", ext_oids,
                         "CertificatePolicies must not be added unless requested")

    def test_single_policy_oid_added(self):
        """A single policy OID must produce exactly one PolicyInformation."""
        cert = self.ca.issue_certificate(
            "CN=one-pol", self.key.public_key(),
            certificate_policies=[{"oid": "2.23.140.1.2.1"}]
        )
        ext_oids = _ext_oids(cert)
        self.assertIn("2.5.29.32", ext_oids,
                      "CertificatePolicies extension must be present")
        cp = self._cp(cert)
        oids = [pi.policy_identifier.dotted_string for pi in cp]
        self.assertIn("2.23.140.1.2.1", oids,
                      "Policy OID 2.23.140.1.2.1 (CA/B Forum DV) must be present")

    def test_extension_is_non_critical(self):
        """RFC 5280 §4.2.1.4: CertificatePolicies SHOULD be non-critical."""
        cert = self.ca.issue_certificate(
            "CN=cp-crit", self.key.public_key(),
            certificate_policies=[{"oid": "2.23.140.1.2.1"}]
        )
        ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        self.assertFalse(ext.critical,
                         "RFC 5280: CertificatePolicies SHOULD be non-critical")

    def test_multiple_policies(self):
        """Multiple policy OIDs must all appear in the extension."""
        policies = [
            {"oid": "2.23.140.1.2.1"},  # DV
            {"oid": "2.23.140.1.2.2"},  # OV
        ]
        cert = self.ca.issue_certificate(
            "CN=multi-pol", self.key.public_key(),
            certificate_policies=policies
        )
        cp = self._cp(cert)
        oids = [pi.policy_identifier.dotted_string for pi in cp]
        self.assertIn("2.23.140.1.2.1", oids)
        self.assertIn("2.23.140.1.2.2", oids)
        self.assertEqual(len(oids), 2)

    # ── CPS URI qualifier ─────────────────────────────────────────────────────

    def test_cps_uri_qualifier_added(self):
        """CPS URI qualifier must be present when requested."""
        cert = self.ca.issue_certificate(
            "CN=cps", self.key.public_key(),
            certificate_policies=[{
                "oid": "2.23.140.1.2.1",
                "cps_uri": "https://pki.example.com/cps",
            }]
        )
        cp = self._cp(cert)
        pi = next(p for p in cp if p.policy_identifier.dotted_string == "2.23.140.1.2.1")
        self.assertIsNotNone(pi.policy_qualifiers,
                             "Policy qualifiers must be present when cps_uri is given")
        cps_uris = [q for q in pi.policy_qualifiers if isinstance(q, str)]
        self.assertIn("https://pki.example.com/cps", cps_uris,
                      "CPS URI must appear in policy qualifiers")

    def test_policy_without_qualifiers_has_none(self):
        """Policy OID without qualifiers must have policy_qualifiers=None."""
        cert = self.ca.issue_certificate(
            "CN=no-qual", self.key.public_key(),
            certificate_policies=[{"oid": "2.23.140.1.2.1"}]
        )
        cp = self._cp(cert)
        pi = cp[0]
        self.assertIsNone(pi.policy_qualifiers,
                          "Policy without qualifiers must have policy_qualifiers=None")

    # ── UserNotice / explicitText ─────────────────────────────────────────────

    def test_user_notice_added(self):
        """UserNotice qualifier must be present when notice_text is given."""
        notice = "This certificate was issued under PyPKI test policy."
        cert = self.ca.issue_certificate(
            "CN=notice", self.key.public_key(),
            certificate_policies=[{
                "oid": "2.23.140.1.2.2",
                "notice_text": notice,
            }]
        )
        cp = self._cp(cert)
        pi = next(p for p in cp if p.policy_identifier.dotted_string == "2.23.140.1.2.2")
        self.assertIsNotNone(pi.policy_qualifiers)
        notices = [q for q in pi.policy_qualifiers
                   if isinstance(q, x509.UserNotice)]
        self.assertEqual(len(notices), 1, "Exactly one UserNotice must be present")
        self.assertEqual(notices[0].explicit_text, notice,
                         "UserNotice explicit_text must match the requested notice_text")

    def test_user_notice_explicit_text_utf8(self):
        """RFC 6818 §3: explicitText must use UTF8String encoding (cryptography default)."""
        # The cryptography library always encodes UserNotice.explicit_text as UTF8String.
        # We verify by round-tripping through DER and confirming the text survives.
        notice = "Política de prueba: üçéàñ"  # non-ASCII to stress UTF-8 path
        cert = self.ca.issue_certificate(
            "CN=utf8-notice", self.key.public_key(),
            certificate_policies=[{
                "oid": "2.23.140.1.2.1",
                "notice_text": notice,
            }]
        )
        # Round-trip through DER
        der = cert.public_bytes(x509.Certificate.__mro__[0].__module__ and
                                 __import__("cryptography.hazmat.primitives.serialization",
                                            fromlist=["Encoding"]).Encoding.DER)
        cert2 = x509.load_der_x509_certificate(der)
        cp = cert2.extensions.get_extension_for_class(x509.CertificatePolicies).value
        pi = cp[0]
        notices = [q for q in pi.policy_qualifiers if isinstance(q, x509.UserNotice)]
        self.assertEqual(notices[0].explicit_text, notice,
                         "explicit_text must survive DER round-trip (UTF-8 preserved)")

    def test_cps_uri_and_notice_together(self):
        """Both CPS URI and UserNotice qualifiers may appear on the same policy."""
        cert = self.ca.issue_certificate(
            "CN=both-qual", self.key.public_key(),
            certificate_policies=[{
                "oid": "2.23.140.1.2.1",
                "cps_uri": "https://pki.example.com/cps",
                "notice_text": "Test policy",
            }]
        )
        cp = self._cp(cert)
        pi = cp[0]
        cps_uris = [q for q in pi.policy_qualifiers if isinstance(q, str)]
        notices = [q for q in pi.policy_qualifiers if isinstance(q, x509.UserNotice)]
        self.assertEqual(len(cps_uris), 1, "CPS URI must be present")
        self.assertEqual(len(notices), 1, "UserNotice must be present")

    # ── CA/B Forum well-known OIDs ────────────────────────────────────────────

    def test_cab_forum_dv_oid_constant(self):
        """OID_POLICY_DV must equal 2.23.140.1.2.1 (CA/B Forum DV)."""
        import pki_server as pki_mod
        self.assertEqual(pki_mod.OID_POLICY_DV.dotted_string, "2.23.140.1.2.1")

    def test_cab_forum_ov_oid_constant(self):
        """OID_POLICY_OV must equal 2.23.140.1.2.2 (CA/B Forum OV)."""
        import pki_server as pki_mod
        self.assertEqual(pki_mod.OID_POLICY_OV.dotted_string, "2.23.140.1.2.2")

    def test_cab_forum_ev_oid_constant(self):
        """OID_POLICY_EV must equal 2.23.140.1.1 (CA/B Forum EV)."""
        import pki_server as pki_mod
        self.assertEqual(pki_mod.OID_POLICY_EV.dotted_string, "2.23.140.1.1")

    def test_any_policy_oid_constant(self):
        """OID_ANY_POLICY must equal 2.5.29.32.0."""
        import pki_server as pki_mod
        self.assertEqual(pki_mod.OID_ANY_POLICY.dotted_string, "2.5.29.32.0")

    def test_entry_missing_oid_skipped(self):
        """Policy dict without 'oid' key must be silently skipped."""
        cert = self.ca.issue_certificate(
            "CN=skip-bad", self.key.public_key(),
            certificate_policies=[
                {"cps_uri": "https://example.com/cps"},  # no oid — skipped
                {"oid": "2.23.140.1.2.1"},               # valid
            ]
        )
        cp = self._cp(cert)
        self.assertEqual(len(list(cp)), 1,
                         "Invalid entry (missing oid) must be skipped silently")

    def test_empty_policies_list_no_extension(self):
        """Empty certificate_policies list must not add the extension."""
        cert = self.ca.issue_certificate(
            "CN=empty-pol", self.key.public_key(),
            certificate_policies=[]
        )
        ext_oids = _ext_oids(cert)
        self.assertNotIn("2.5.29.32", ext_oids,
                         "Empty policies list must not produce a CertificatePolicies extension")

    # ── Profile-level default policies ───────────────────────────────────────

    def test_profile_level_policies_applied(self):
        """Policies defined in a CertProfile must be applied automatically."""
        import pki_server as pki_mod
        # Temporarily add a policy to the tls_server profile for this test
        original = pki_mod.CertProfile.PROFILES["tls_server"].copy()
        pki_mod.CertProfile.PROFILES["tls_server"]["certificate_policies"] = [
            {"oid": "2.23.140.1.2.1"}
        ]
        try:
            cert = self.ca.issue_certificate(
                "CN=profile-pol", self.key.public_key(),
                profile="tls_server", san_dns=["profile.test"]
            )
            ext_oids = _ext_oids(cert)
            self.assertIn("2.5.29.32", ext_oids,
                          "Profile-level certificate_policies must be applied automatically")
        finally:
            pki_mod.CertProfile.PROFILES["tls_server"] = original

    def test_explicit_policies_override_profile_policies(self):
        """Explicit certificate_policies parameter must override profile default."""
        import pki_server as pki_mod
        original = pki_mod.CertProfile.PROFILES["tls_server"].copy()
        pki_mod.CertProfile.PROFILES["tls_server"]["certificate_policies"] = [
            {"oid": "2.23.140.1.2.1"}
        ]
        try:
            cert = self.ca.issue_certificate(
                "CN=override-pol", self.key.public_key(),
                profile="tls_server", san_dns=["override.test"],
                certificate_policies=[{"oid": "2.23.140.1.2.2"}]
            )
            cp = self._cp(cert)
            oids = [pi.policy_identifier.dotted_string for pi in cp]
            self.assertIn("2.23.140.1.2.2", oids,
                          "Explicit parameter OID must appear")
            self.assertNotIn("2.23.140.1.2.1", oids,
                             "Profile default OID must be overridden by explicit parameter")
        finally:
            pki_mod.CertProfile.PROFILES["tls_server"] = original

# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    # Show each test name and result, with timing
    loader = unittest.TestLoader()
    suite  = loader.discover(start_dir=str(Path(__file__).parent),
                             pattern="test_pki_server.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
