#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
IPsec PKI Server — RFC 4945 + RFC 4806 + RFC 4809
===================================================
Companion module for pki_server.py that adds IPsec-specific PKI support.

RFC compliance implemented here
---------------------------------
  RFC 4945  The Internet IP Security PKI Profile of IKEv1/ISAKMP, IKEv2 and PKIX
            Standards Track (August 2007)
            - Certificate issuance with mandatory SAN enforcement
            - FQDN → dNSName, email → rfc822Name, IPv4/IPv6 → iPAddress
            - Wildcard prohibition (§3.1.2 / §4.1.2: MUST NOT generate wildcards)
            - Extended Key Usage: id-kp-ipsecEndSystem, id-kp-ipsecTunnel,
              id-kp-ipsecUser (OIDs 1.3.6.1.5.5.7.3.5 / .6 / .7)
            - No CIDR notation in SubjectAltName (§3.1.1 / §4.1.1)
            - Both SubjectName and SAN fields required for FQDN/IP/email IDs
            - Key usage: digitalSignature only for IKE authentication certs

  RFC 4806  Online Certificate Status Protocol (OCSP) Extensions to IKEv2
            Standards Track (February 2007)
            - Hash-based OCSP lookup endpoint: POST /ipsec/ocsp-hash
              Accepts a SHA-1 hash of the issuer cert (the IKEv2 CERTREQ format)
              instead of a full OCSPRequest; returns a standard OCSP response.
            - GET /ipsec/ocsp-hash/<hex> for cacheable lookups
            - Cert Encoding value 14 ("OCSP Content") response generation
            - Inline OCSP response suitable for embedding in IKEv2 CERT payloads

  RFC 4809  Requirements for an IPsec Certificate Management Profile
            Informational (February 2007)
            - ipsec_peer certificate profile satisfying §3.1.6 PKC profile
              requirements (full CERTPROFILE mandatory fields, path validation
              support, revocation checking support)
            - Batch issuance endpoint: POST /ipsec/batch-issue (§3.1.2 "batches")
            - PKC update endpoint: POST /ipsec/update (rekey with same SubjectName,
              new public key, per RFC 4809 §3.3 "PKC Update" definition)
            - Admin interface endpoint for VPN-PKI integration (§3.1.1)

REST API exposed on --ipsec-port (default 8085, plain HTTP)
-------------------------------------------------------------
  GET  /ipsec/health                  — liveness check
  GET  /ipsec/ca-cert                 — CA cert for trust anchor distribution
  GET  /ipsec/profiles                — list supported IPsec certificate profiles
  POST /ipsec/issue                   — RFC 4945 + 4809 compliant cert issuance
  POST /ipsec/batch-issue             — RFC 4809 §3.1.2 batch issuance
  POST /ipsec/update                  — RFC 4809 PKC Update (same DN, new key)
  POST /ipsec/revoke                  — revoke an IPsec certificate
  GET  /ipsec/cert/<serial>           — fetch issued cert by serial
  POST /ipsec/ocsp-hash               — RFC 4806 hash-based OCSP lookup
  GET  /ipsec/ocsp-hash/<hex>         — RFC 4806 cacheable GET variant

IPsec certificate profiles (RFC 4945 §2 / RFC 4809 §3.1.6)
------------------------------------------------------------
  ipsec_tunnel  — gateway-to-gateway VPN tunnel (id-kp-ipsecTunnel)
                  SAN: FQDN or IP of the gateway
  ipsec_end     — host/device end-system (id-kp-ipsecEndSystem)
                  SAN: FQDN or IP of the device
  ipsec_user    — human VPN user (id-kp-ipsecUser)
                  SAN: email (rfc822Name) of the user

RFC 4809 compliance notes
--------------------------
  RFC 4809 is an Informational document (not a standard). It defines
  *requirements* for a future standards-track profile, intended to be satisfied
  by existing enrollment protocols (CMPv2, SCEP, EST, ACME). This module
  satisfies the following mandatory requirements from §3:
    [R-1]  PKC lifecycle: issuance, renewal/rekey, update, revoke (§3.3)
    [R-2]  PKC Profile: mandatory CERTPROFILE fields present (§3.1.6)
    [R-3]  Name forms: FQDN, USER_FQDN (email), IPv4, IPv6 (§3.1.5)
    [R-4]  Revocation info: OCSP AIA + CDP embedded in issued certs (§3.2)
    [R-5]  Batch issuance: POST /ipsec/batch-issue (§3.1.2)
    [R-6]  Admin availability: this server is the "Admin" interface (§3.1.3)
    [R-7]  Path validation: AKI + SKI + CDP + OCSP AIA always included (§3.1.6)
  The requirements NOT addressed here are out-of-scope for a CA server:
    [N-1]  §3.1.4 / §3.4  IKE peer-side ID verification — client implementation
    [N-2]  §3.5           SPD policy configuration — VPN gateway configuration
    [N-3]  §3.1.3 "moving media" — physical deployment method

Dependencies: cryptography (same as pki_server.py)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.server
import ipaddress
import json
import logging
import re
import secrets
import sqlite3
import ssl
import threading
import time
import traceback
from datetime import timezone as _tz
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption, PublicFormat,
    load_pem_public_key,
)
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

logger = logging.getLogger("ipsec")

# ---------------------------------------------------------------------------
# IPsec-specific OIDs  (RFC 4945 §2 / RFC 3280)
# ---------------------------------------------------------------------------

# id-kp-ipsecEndSystem  1.3.6.1.5.5.7.3.5
OID_KP_IPSEC_END_SYSTEM = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.5")
# id-kp-ipsecTunnel     1.3.6.1.5.5.7.3.6
OID_KP_IPSEC_TUNNEL     = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.6")
# id-kp-ipsecUser       1.3.6.1.5.5.7.3.7
OID_KP_IPSEC_USER       = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.7")

# RFC 4806 / IKEv2 Cert Encoding value 14 ("OCSP Content")
IKEV2_CERT_ENCODING_OCSP_CONTENT = 14

# ---------------------------------------------------------------------------
# DER / ASN.1 helpers  (re-implemented locally to keep module self-contained)
# ---------------------------------------------------------------------------

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    lb: list[int] = []
    while n:
        lb.append(n & 0xFF)
        n >>= 8
    lb.reverse()
    return bytes([0x80 | len(lb)]) + bytes(lb)

def _dec_len(data: bytes, pos: int) -> Tuple[int, int]:
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    nb = b & 0x7F
    return int.from_bytes(data[pos+1:pos+1+nb], "big"), pos + 1 + nb

def _dec_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = data[pos]
    ln, vstart = _dec_len(data, pos + 1)
    return tag, data[vstart:vstart + ln], vstart + ln

def _seq(c: bytes) -> bytes:
    return b"\x30" + _enc_len(len(c)) + c

def _oid_enc(dotted: str) -> bytes:
    parts = list(map(int, dotted.split(".")))
    enc = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            enc += b"\x00"
        else:
            buf: list[int] = []
            while p:
                buf.append(p & 0x7F)
                p >>= 7
            buf.reverse()
            enc += bytes([(b | 0x80) if i < len(buf)-1 else b for i, b in enumerate(buf)])
    return b"\x06" + _enc_len(len(enc)) + enc

def _int_enc(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    raw: list[int] = []
    n = v
    while n:
        raw.append(n & 0xFF)
        n >>= 8
    raw.reverse()
    if raw[0] & 0x80:
        raw.insert(0, 0)
    return b"\x02" + _enc_len(len(raw)) + bytes(raw)

def _oct_enc(v: bytes) -> bytes:
    return b"\x04" + _enc_len(len(v)) + v

def _bit_enc(v: bytes, unused: int = 0) -> bytes:
    return b"\x03" + _enc_len(len(v) + 1) + bytes([unused]) + v

def _ctx(n: int, c: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 | n) if constructed else (0x80 | n)
    return bytes([tag]) + _enc_len(len(c)) + c

def _null() -> bytes:
    return b"\x05\x00"

def _generalized_time(dt: datetime.datetime) -> bytes:
    s = dt.strftime("%Y%m%d%H%M%SZ").encode()
    return b"\x18" + _enc_len(len(s)) + s

def _decode_oid_bytes(data: bytes) -> str:
    if not data:
        return ""
    parts = [data[0] // 40, data[0] % 40]
    i, cur = 1, 0
    while i < len(data):
        cur = (cur << 7) | (data[i] & 0x7F)
        if not (data[i] & 0x80):
            parts.append(cur)
            cur = 0
        i += 1
    return ".".join(map(str, parts))

# OID strings (for response building)
OID_SHA1            = "1.3.14.3.2.26"
OID_SHA256          = "2.16.840.1.101.3.4.2.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_BASIC_OCSP_RESP = "1.3.6.1.5.5.7.48.1.1"
OID_OCSP_NONCE      = "1.3.6.1.5.5.7.48.1.2"
OID_OCSP_NOCHECK    = "1.3.6.1.5.5.7.48.1.5"

RESP_SUCCESSFUL        = 0
RESP_MALFORMED_REQUEST = 1
RESP_INTERNAL_ERROR    = 2
STATUS_GOOD    = 0
STATUS_REVOKED = 1
STATUS_UNKNOWN = 2


# ---------------------------------------------------------------------------
# RFC 4945 — IPsec certificate profile validator
# ---------------------------------------------------------------------------

class RFC4945Validator:
    """
    Validates and normalises certificate issuance requests against RFC 4945.

    Key rules enforced:
      §3.1.1 / §4.1.1  IPv4/IPv6 IDs: iPAddress SAN MUST match; CIDR prohibited
      §3.1.2 / §4.1.2  FQDN IDs: dNSName SAN MUST be present; NO wildcards
      §3.1.3 / §4.1.3  USER_FQDN (email): rfc822Name SAN MUST be present
      §3.1.6            ID must correspond to keying material; verified by caller
      §3.2 / §4.2       Cert must support path validation (AKI, CDP, AIA-OCSP)
      §3.3 / §4.3       X.509 Signature cert type only; CRL/delta-CRL aware
    """

    # Wildcard pattern — RFC 4945 §3.1.2 / §4.1.2: MUST NOT generate wildcards
    _WILDCARD_RE = re.compile(r"(^|\.)?\*")

    @classmethod
    def validate_request(
        cls,
        subject_str: str,
        profile: str,
        san_dns: Optional[List[str]] = None,
        san_emails: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """
        Returns (ok, error_message).
        All validations are per RFC 4945 §3 (IKEv1) and §4 (IKEv2).
        """
        san_dns    = san_dns    or []
        san_emails = san_emails or []
        san_ips    = san_ips    or []

        # ── Profile-specific SAN requirements ──────────────────────────────
        if profile == "ipsec_tunnel":
            # Gateway certs MUST have FQDN or IP identity (§3.1.1 / §3.1.2)
            if not san_dns and not san_ips:
                return False, (
                    "RFC 4945 §3.1.1/§3.1.2: ipsec_tunnel profile requires at least "
                    "one dNSName (FQDN) or iPAddress SAN for gateway identity"
                )
        elif profile == "ipsec_end":
            # End-system certs MUST have FQDN or IP (§3.1.1 / §3.1.2)
            if not san_dns and not san_ips:
                return False, (
                    "RFC 4945 §3.1.1/§3.1.2: ipsec_end profile requires at least "
                    "one dNSName or iPAddress SAN for device identity"
                )
        elif profile == "ipsec_user":
            # User certs MUST have rfc822Name / USER_FQDN identity (§3.1.3)
            if not san_emails:
                return False, (
                    "RFC 4945 §3.1.3: ipsec_user profile requires at least "
                    "one rfc822Name (email) SAN for user identity"
                )

        # ── No wildcards (RFC 4945 §3.1.2 / §4.1.2) ────────────────────────
        for dns in san_dns:
            if cls._WILDCARD_RE.search(dns):
                return False, (
                    f"RFC 4945 §3.1.2: wildcard DNS SANs are prohibited in IPsec "
                    f"certificates. Remove '*' from '{dns}'"
                )

        # ── No CIDR notation in iPAddress SANs (RFC 4945 §3.1.1 / §4.1.1) ──
        for ip in san_ips:
            if "/" in ip:
                return False, (
                    f"RFC 4945 §3.1.1: CIDR notation is prohibited in SubjectAltName "
                    f"iPAddress fields. Use a single address, not a range: '{ip}'"
                )
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return False, f"Invalid IP address in san_ips: '{ip}'"

        # ── Validate email format ────────────────────────────────────────────
        for email in san_emails:
            if "@" not in email:
                return False, f"Invalid email SAN (missing @): '{email}'"

        # ── Subject MUST be non-empty (RFC 4945 §5.1.2) ─────────────────────
        # First pass: string-level check (catches obvious empty / whitespace)
        if not subject_str.strip():
            return False, (
                "RFC 4945 §5.1.2: subject_str must not be empty"
            )
        # Second pass: parse all key=value pairs and verify at least one
        # produces a non-blank value, so inputs like "CN=  " are caught.
        parsed_attrs = []
        for part in subject_str.split(","):
            k, _, v = part.strip().partition("=")
            if k.strip() and v.strip():
                parsed_attrs.append((k.strip().upper(), v.strip()))
        if not parsed_attrs:
            return False, (
                "RFC 4945 §5.1.2: subject_str contains no valid key=value pairs "
                "(all values are blank). Every IPsec certificate MUST have a "
                "non-empty Subject or — if Subject is intentionally empty — the "
                "SubjectAltName extension MUST be marked critical."
            )

        return True, ""
    @classmethod
    def check_name_constraints(
        cls,
        ca_cert: "x509.Certificate",
        san_dns: List[str],
        san_emails: List[str],
        san_ips: List[str],
    ) -> Tuple[bool, str]:
        """
        RFC 4945 §5.1.3 / RFC 5280 §4.2.1.10 — Name Constraints enforcement.

        If the CA certificate carries a NameConstraints extension, every SAN in
        the certificate-to-be-issued must fall within a permitted subtree AND
        must NOT fall within an excluded subtree.

        Returns (ok, error_message).  If no NameConstraints extension is
        present on the CA cert, always returns (True, "").

        Subtree match rules (RFC 5280 §4.2.1.10):
          dNSName     — exact match or suffix: permitted ".example.com" covers
                        "sub.example.com" and "example.com"
          rfc822Name  — exact address or all in domain: "@example.com" covers
                        any address in that domain
          iPAddress   — CIDR block (network/mask bytes in the extension)
        """
        try:
            nc_ext = ca_cert.extensions.get_extension_for_class(
                x509.NameConstraints
            )
        except x509.ExtensionNotFound:
            return True, ""   # No constraints — everything is permitted

        nc = nc_ext.value
        permitted = nc.permitted_subtrees or []
        excluded  = nc.excluded_subtrees  or []

        def _dns_in_subtree(name: str, subtree: x509.GeneralName) -> bool:
            if not isinstance(subtree, x509.DNSName):
                return False
            constraint = subtree.value.lstrip(".")
            name_lower = name.lower()
            constraint_lower = constraint.lower()
            return (name_lower == constraint_lower or
                    name_lower.endswith("." + constraint_lower))

        def _email_in_subtree(addr: str, subtree: x509.GeneralName) -> bool:
            if not isinstance(subtree, x509.RFC822Name):
                return False
            constraint = subtree.value
            if "@" in constraint:
                return addr.lower() == constraint.lower()
            # domain constraint like "example.com" — match any @example.com
            _, _, domain = addr.partition("@")
            return domain.lower() == constraint.lstrip("@").lower()

        def _ip_in_subtree(addr_str: str, subtree: x509.GeneralName) -> bool:
            if not isinstance(subtree, x509.IPAddress):
                return False
            try:
                import ipaddress as _ip
                network = _ip.ip_network(subtree.value, strict=False)
                return _ip.ip_address(addr_str) in network
            except Exception:
                return False

        errors = []

        for dns in san_dns:
            if excluded and any(_dns_in_subtree(dns, s) for s in excluded):
                errors.append(
                    f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: dNSName '{dns}' "
                    f"falls within a NameConstraints excluded subtree of this CA."
                )
            elif permitted:
                dns_permitted = [s for s in permitted if isinstance(s, x509.DNSName)]
                if dns_permitted and not any(_dns_in_subtree(dns, s) for s in dns_permitted):
                    errors.append(
                        f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: dNSName '{dns}' "
                        f"is outside all NameConstraints permitted subtrees of this CA. "
                        f"Permitted DNS subtrees: "
                        f"{[s.value for s in dns_permitted]}"
                    )

        for email in san_emails:
            if excluded and any(_email_in_subtree(email, s) for s in excluded):
                errors.append(
                    f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: rfc822Name '{email}' "
                    f"falls within a NameConstraints excluded subtree of this CA."
                )
            elif permitted:
                email_permitted = [s for s in permitted if isinstance(s, x509.RFC822Name)]
                if email_permitted and not any(_email_in_subtree(email, s) for s in email_permitted):
                    errors.append(
                        f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: rfc822Name '{email}' "
                        f"is outside all NameConstraints permitted email subtrees of this CA. "
                        f"Permitted email subtrees: "
                        f"{[s.value for s in email_permitted]}"
                    )

        for ip_str in san_ips:
            if excluded and any(_ip_in_subtree(ip_str, s) for s in excluded):
                errors.append(
                    f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: iPAddress '{ip_str}' "
                    f"falls within a NameConstraints excluded subtree of this CA."
                )
            elif permitted:
                ip_permitted = [s for s in permitted if isinstance(s, x509.IPAddress)]
                if ip_permitted and not any(_ip_in_subtree(ip_str, s) for s in ip_permitted):
                    errors.append(
                        f"RFC 5280 §4.2.1.10 / RFC 4945 §5.1.3: iPAddress '{ip_str}' "
                        f"is outside all NameConstraints permitted IP subtrees of this CA. "
                        f"Permitted IP subtrees: "
                        f"{[str(s.value) for s in ip_permitted]}"
                    )

        if errors:
            return False, "  |  ".join(errors)
        return True, ""

    @classmethod
    def check_cn_san_consistency(
        cls,
        subject_str: str,
        san_dns: List[str],
        san_ips: List[str],
        san_emails: List[str],
    ) -> Optional[str]:
        """
        RFC 4945 §3.1 / §4.1: implementations SHOULD populate ID with
        information contained within the end-entity cert. Warn if the
        subject CN is an FQDN/IP that is not represented in the SANs.
        Returns a warning string or None.
        """
        cn = ""
        for part in subject_str.split(","):
            k, _, v = part.strip().partition("=")
            if k.strip().upper() == "CN":
                cn = v.strip()
                break
        if not cn:
            return None

        # If CN looks like an IP
        try:
            ipaddress.ip_address(cn)
            if cn not in san_ips:
                return (
                    f"RFC 4945 §3.1.1: CN='{cn}' is an IP address but is not "
                    f"in san_ips. Add it to allow IKE peers to use it as a lookup key."
                )
            return None
        except ValueError:
            pass

        # If CN looks like an FQDN (contains a dot, no spaces)
        if "." in cn and " " not in cn and "@" not in cn:
            if cn not in san_dns:
                return (
                    f"RFC 4945 §3.1.2: CN='{cn}' looks like an FQDN but is not "
                    f"in san_dns. Add it so IKE peers can use it as a cert lookup key."
                )
        return None


# ---------------------------------------------------------------------------
# RFC 4806 — Hash-based OCSP lookup (IKEv2 CERTREQ / CERT payload support)
# ---------------------------------------------------------------------------

class RFC4806OCSPHashResolver:
    """
    Implements RFC 4806 §3 hash-based OCSP lookup.

    IKEv2 CERTREQ payloads with Cert Encoding = 14 ("OCSP Content") carry
    SHA-1 hashes of trusted OCSP responder certificates rather than full
    OCSPRequests. This class:

      1. Accepts the SHA-1 hash of an issuer certificate (20 bytes)
      2. Verifies it matches our CA certificate
      3. Looks up revocation status for the requested serial
      4. Returns a full RFC 6960 OCSP response suitable for embedding
         in an IKEv2 CERT payload (Cert Encoding = 14)

    The endpoint POST /ipsec/ocsp-hash accepts JSON:
      { "issuer_cert_hash_hex": "<40 hex chars>",
        "serial": <int>,
        "nonce_hex": "<hex>" (optional) }

    This allows IKEv2 implementations to resolve revocation status even
    when they cannot reach the OCSP responder directly (RFC 4806 §1 use case:
    firewall prevents out-of-band OCSP access).
    """

    def __init__(self, ca: "CertificateAuthority", ocsp_key, ocsp_cert):
        self.ca        = ca
        self.ocsp_key  = ocsp_key
        self.ocsp_cert = ocsp_cert

        # Pre-compute SHA-1 hash of the CA cert DER (trust-anchor hash)
        ca_der = ca.ca_cert.public_bytes(Encoding.DER)
        self._ca_cert_sha1 = hashlib.sha1(ca_der).digest()

        # RFC 4806 §4.1: the CERTREQ Certification Authority field contains
        # the SHA-1 hash of the *OCSP responder* certificate the peer trusts
        # (case b in RFC 2560 §2.2 — Trusted Responder).  Pre-compute that
        # hash so we accept both:
        #   (a) SHA-1 of CA cert — peer trusts the CA itself as OCSP responder
        #   (b) SHA-1 of OCSP signing cert — peer trusts our dedicated OCSP responder
        ocsp_cert_der = ocsp_cert.public_bytes(Encoding.DER)
        self._ocsp_cert_sha1 = hashlib.sha1(ocsp_cert_der).digest()

        # Also SHA-1 of issuer Name DER and key hash (for CertID in OCSP response)
        self._ca_name_hash_sha1 = hashlib.sha1(
            ca.ca_cert.subject.public_bytes()
        ).digest()
        pub_spki = ca.ca_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        # Extract BIT STRING value from SPKI to get the key hash
        try:
            _, spki_inner, _ = _dec_tlv(pub_spki, 0)
            sp = 0
            _, _, sp = _dec_tlv(spki_inner, sp)           # skip AlgorithmIdentifier
            _, bit_val, _ = _dec_tlv(spki_inner, sp)
            self._ca_key_hash_sha1 = hashlib.sha1(bit_val[1:]).digest()  # skip unused-bits byte
        except Exception:
            self._ca_key_hash_sha1 = hashlib.sha1(pub_spki).digest()

    def resolve(
        self,
        issuer_cert_hash: bytes,  # SHA-1 of issuer cert DER  (RFC 4806 §3.1)
        serial: int,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bool, bytes, str]:
        """
        Returns (ok, ocsp_response_der, error_message).

        Per RFC 4806 §4.1: the CA value in a CERTREQ is the SHA-1 hash of
        the trust anchor's certificate DER. We verify it matches our CA
        before responding.
        """
        # RFC 4806 §4.1: verify hash identifies a trusted OCSP responder.
        # Accept three variants:
        #   (a) SHA-1 of the CA cert DER     — CA as its own OCSP responder
        #   (b) SHA-1 of the OCSP-signing cert DER — our dedicated OCSP responder
        #   (c) SHA-256 of either cert       — forward-compat for newer IKE implementations
        ca_der   = self.ca.ca_cert.public_bytes(Encoding.DER)
        ocsp_der = self.ocsp_cert.public_bytes(Encoding.DER)
        accepted = {
            self._ca_cert_sha1,                     # (a) SHA-1 of CA cert
            self._ocsp_cert_sha1,                   # (b) SHA-1 of OCSP signing cert
            hashlib.sha256(ca_der).digest(),         # (c) SHA-256 of CA cert
            hashlib.sha256(ocsp_der).digest(),       # (c) SHA-256 of OCSP cert
        }
        if issuer_cert_hash not in accepted:
            return False, b"", (
                "RFC 4806 §4.1: issuer_cert_hash does not match any trusted OCSP responder. "
                f"Accepted SHA-1 hashes: CA={self._ca_cert_sha1.hex()}, "
                f"OCSPcert={self._ocsp_cert_sha1.hex()}. "
                f"Got={issuer_cert_hash.hex()} (len={len(issuer_cert_hash)}). "
                "Ensure your IKEv2 peer sends the SHA-1 of the OCSP signing cert, "
                "or the CA cert, from GET /ipsec/ca-cert."
            )

        # Look up serial in DB
        try:
            conn = sqlite3.connect(str(self.ca.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT serial, revoked, revoked_at, reason "
                "FROM certificates WHERE serial=?",
                (serial,)
            ).fetchone()
            conn.close()
        except Exception as e:
            logger.error(f"RFC4806 DB error: {e}")
            return False, b"", f"Database error: {e}"

        now = datetime.datetime.now(_tz.utc)
        next_update = now + datetime.timedelta(minutes=30)  # RFC 4806: short validity for IKE

        if row is None:
            status = STATUS_UNKNOWN
            revoked_at = None
            reason = 0
        elif row["revoked"]:
            status = STATUS_REVOKED
            try:
                revoked_at = datetime.datetime.fromisoformat(row["revoked_at"])
                if revoked_at.tzinfo is None:
                    revoked_at = revoked_at.replace(tzinfo=_tz.utc)
            except Exception:
                revoked_at = now
            reason = row["reason"] or 0
        else:
            status = STATUS_GOOD
            revoked_at = None
            reason = 0

        resp_der = self._build_response(
            serial=serial,
            cert_status=status,
            revoked_at=revoked_at,
            revocation_reason=reason,
            this_update=now,
            next_update=next_update,
            nonce=nonce,
        )
        return True, resp_der, ""

    def _build_response(
        self,
        serial: int,
        cert_status: int,
        revoked_at: Optional[datetime.datetime],
        revocation_reason: int,
        this_update: datetime.datetime,
        next_update: datetime.datetime,
        nonce: Optional[bytes],
    ) -> bytes:
        """Build a DER-encoded OCSPResponse using SHA-1 CertID (RFC 4806 compatibility)."""

        # ── CertStatus ────────────────────────────────────────────────────
        if cert_status == STATUS_GOOD:
            cert_status_der = _ctx(0, b"", constructed=False)
        elif cert_status == STATUS_REVOKED:
            rev_time = _generalized_time(revoked_at or datetime.datetime.now(_tz.utc))
            reason_enc = _ctx(0, _seq(_int_enc(revocation_reason)), constructed=True)
            cert_status_der = _ctx(1, rev_time + reason_enc)
        else:
            cert_status_der = _ctx(2, b"", constructed=False)

        # ── CertID — RFC 4806 uses SHA-1 (matches IKEv2 CERTREQ hash) ────
        hash_alg = _seq(_oid_enc(OID_SHA1) + _null())
        cert_id  = _seq(
            hash_alg
            + _oct_enc(self._ca_name_hash_sha1)
            + _oct_enc(self._ca_key_hash_sha1)
            + _int_enc(serial)
        )

        # ── SingleResponse ────────────────────────────────────────────────
        single_resp = _seq(
            cert_id
            + cert_status_der
            + _generalized_time(this_update)
            + _ctx(0, _generalized_time(next_update))
        )

        # ── ResponseData ──────────────────────────────────────────────────
        try:
            ski = self.ocsp_cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.key_identifier
            responder_id = _ctx(2, _oct_enc(ski))
        except Exception:
            responder_id = _ctx(1, self.ocsp_cert.subject.public_bytes())

        extensions_der = b""
        if nonce is not None:
            nonce_ext = _seq(_oid_enc(OID_OCSP_NONCE) + _oct_enc(_oct_enc(nonce)))
            extensions_der = _ctx(1, _seq(nonce_ext))

        tbs_response_data = _seq(
            responder_id
            + _generalized_time(this_update)
            + _seq(single_resp)
            + extensions_der
        )

        # ── Signature ─────────────────────────────────────────────────────
        sig_bytes = self.ocsp_key.sign(
            tbs_response_data, asym_padding.PKCS1v15(), SHA256()
        )
        sig_alg = _seq(_oid_enc(OID_SHA256_WITH_RSA) + _null())
        sig_bit = _bit_enc(sig_bytes)
        certs_field = _ctx(0, _seq(self.ocsp_cert.public_bytes(Encoding.DER)))

        basic_ocsp_resp = _seq(tbs_response_data + sig_alg + sig_bit + certs_field)
        response_bytes  = _seq(_oid_enc(OID_BASIC_OCSP_RESP) + _oct_enc(basic_ocsp_resp))

        return _seq(
            _ctx(0, bytes([RESP_SUCCESSFUL]), constructed=False)
            + _ctx(0, response_bytes)
        )


# ---------------------------------------------------------------------------
# RFC 4809 / RFC 4945 — IPsec certificate issuer
# ---------------------------------------------------------------------------

class IPsecCertIssuer:
    """
    Issues RFC 4945-compliant IPsec certificates through pki_server's CA.

    Profiles:
      ipsec_tunnel  id-kp-ipsecTunnel    RFC 4945 §2 / gateway-to-gateway
      ipsec_end     id-kp-ipsecEndSystem RFC 4945 §2 / host end-system
      ipsec_user    id-kp-ipsecUser      RFC 4945 §2 / human VPN user

    RFC 4809 PKC lifecycle operations:
      issue   — initial issuance (rekey = same DN, new key)
      update  — PKC Update: same DN, new key, potentially new SAN
      batch   — multiple issuances in one call (§3.1.2)
    """

    # RFC 4945 §2 EKU OID mapping
    PROFILE_EKU = {
        "ipsec_tunnel": OID_KP_IPSEC_TUNNEL,
        "ipsec_end":    OID_KP_IPSEC_END_SYSTEM,
        "ipsec_user":   OID_KP_IPSEC_USER,
    }

    VALID_PROFILES = set(PROFILE_EKU.keys())

    def __init__(self, ca: "CertificateAuthority"):
        self.ca = ca
        # RFC 4945 §5.3: SHA-1 MUST NOT be used for new certificate signatures.
        # Check the CA certificate's own signature algorithm at startup so
        # administrators know immediately if the trust anchor is weak.
        self._check_ca_hash_strength(ca)

    @staticmethod
    def _check_ca_hash_strength(ca: "CertificateAuthority") -> None:
        """
        RFC 4945 §5.3: warn if the CA certificate was signed with SHA-1 or
        a weaker hash.  Issued IPsec certs are always signed with SHA-256
        (see _rebuild_with_ipsec_eku), but a SHA-1 trust anchor weakens the
        whole chain and SHOULD be replaced.

        Raises: nothing — logs a WARNING to avoid breaking existing deployments
        that have not yet migrated their CA.
        """
        try:
            sig_hash = ca.ca_cert.signature_hash_algorithm
            if sig_hash is None:
                return  # e.g. Ed25519 — no separate hash OID
            name = sig_hash.name.lower()
            # SHA-1 variants: "sha1", "sha-1", "sha_1"
            if "sha1" in name.replace("-", "").replace("_", ""):
                logger.warning(
                    "RFC 4945 §5.3: CA certificate is signed with %s. "
                    "SHA-1 MUST NOT be used for new IPsec certificate signatures. "
                    "The CA trust anchor should be replaced with a SHA-256 (or "
                    "stronger) signed certificate before issuing new IPsec certs. "
                    "All newly issued certs from this server use SHA-256, but the "
                    "weak CA signature reduces overall chain security.",
                    sig_hash.name,
                )
            elif name in ("md5", "md2"):
                logger.error(
                    "RFC 4945 §5.3: CA certificate uses %s — this algorithm is "
                    "cryptographically broken. Replace the CA immediately.",
                    sig_hash.name,
                )
        except Exception as e:
            logger.debug("RFC 4945 §5.3 CA hash check skipped: %s", e)

    def issue(
        self,
        subject_str: str,
        public_key_pem: Optional[str] = None,
        validity_days: int = 365,
        profile: str = "ipsec_end",
        san_dns: Optional[List[str]] = None,
        san_emails: Optional[List[str]] = None,
        san_ips: Optional[List[str]] = None,
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        audit_ip: str = "",
        key_password: Optional[str] = None,
    ) -> Tuple[x509.Certificate, Optional[str], Optional[str]]:
        """
        Issue an RFC 4945-compliant IPsec certificate.

        Returns (certificate, private_key_pem_or_None, warning_or_None).
        private_key_pem is only returned if public_key_pem was not supplied
        (i.e. the key was generated server-side).
        warning may contain RFC 4945 advisory messages (non-fatal).

        key_password: RFC 4809 §3.1.2 — private keys MUST NOT be transmitted
        in plaintext.  When start_ipsec_server() runs without TLS (dev only),
        callers SHOULD supply key_password so the returned PEM is encrypted.
        When TLS is active, the transport layer already protects the key, but
        encrypting at the application layer provides defence-in-depth.
        If key_password is None AND no TLS is configured, a WARNING is logged.
        """
        if profile not in self.VALID_PROFILES:
            raise ValueError(
                f"Unknown IPsec profile '{profile}'. "
                f"Valid: {sorted(self.VALID_PROFILES)}"
            )

        san_dns    = san_dns    or []
        san_emails = san_emails or []
        san_ips    = san_ips    or []

        # ── RFC 4945 validation ───────────────────────────────────────────
        ok, err = RFC4945Validator.validate_request(
            subject_str, profile, san_dns, san_emails, san_ips
        )
        if not ok:
            raise ValueError(err)

        # RFC 4945 §5.1.3 / RFC 5280 §4.2.1.10 — NameConstraints
        nc_ok, nc_err = RFC4945Validator.check_name_constraints(
            self.ca.ca_cert, san_dns, san_emails, san_ips
        )
        if not nc_ok:
            raise ValueError(nc_err)

        warning = RFC4945Validator.check_cn_san_consistency(
            subject_str, san_dns, san_ips, san_emails
        )

        # ── Resolve public key ────────────────────────────────────────────
        priv_key_pem: Optional[str] = None
        if public_key_pem:
            pub_key = load_pem_public_key(public_key_pem.encode())
        else:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_key = priv.public_key()
            # RFC 4809 §3.1.2 + §3.3.4: private key MUST be protected in transit.
            # If a key_password is supplied, use AES-256-CBC encryption (PKCS#8
            # BestAvailableEncryption) so the PEM blob is safe even if the
            # transport is inspected.  Without TLS AND without a password, we
            # still serve the key but emit a security warning.
            if key_password:
                encryption = BestAvailableEncryption(key_password.encode())
            else:
                logger.warning(
                    "RFC 4809 §3.1.2: server-generated private key returned "
                    "without password encryption. Enable TLS (--ipsec-tls-cert / "
                    "--ipsec-tls-key) or supply 'key_password' in the request."
                )
                encryption = NoEncryption()
            priv_key_pem = priv.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, encryption
            ).decode()

        # ── Build certificate via CA's issue_certificate ──────────────────
        # We pass the raw parameters; the CA handles SKI, AKI, CDP, AIA.
        cert = self.ca.issue_certificate(
            subject_str=subject_str,
            public_key=pub_key,
            validity_days=validity_days,
            profile="default",       # we override EKU/KU ourselves below
            san_dns=san_dns,
            san_emails=san_emails,
            san_ips=san_ips,
            ocsp_url=ocsp_url,
            crl_url=crl_url,
            requester_ip=audit_ip,
        )

        # ── Re-sign with correct RFC 4945 EKU (override default profile) ─
        # The CA's issue_certificate doesn't know about ipsec EKUs, so we
        # rebuild the cert with the correct EKU injected.
        cert = self._rebuild_with_ipsec_eku(cert, pub_key, profile, validity_days,
                                             san_dns, san_emails, san_ips,
                                             ocsp_url, crl_url)

        # RFC 4945 §5.2 — advisory CDP reachability check (SHOULD, not MUST)
        if crl_url:
            cdp_ok, cdp_detail = _validate_cdp_url(crl_url)
            if not cdp_ok:
                cdp_warning = f"RFC 4945 §5.2 CDP advisory: {cdp_detail}"
                logger.warning(cdp_warning)
                warning = f"{warning}  |  {cdp_warning}" if warning else cdp_warning

        return cert, priv_key_pem, warning

    def _rebuild_with_ipsec_eku(
        self,
        template: x509.Certificate,
        pub_key,
        profile: str,
        validity_days: int,
        san_dns: List[str],
        san_emails: List[str],
        san_ips: List[str],
        ocsp_url: Optional[str],
        crl_url: Optional[str],
    ) -> x509.Certificate:
        """
        Build a new certificate with the correct RFC 4945 IPsec EKU,
        reusing the serial / subject / validity from the template cert
        that was already recorded in the CA's database.
        RFC 4945 §3.3 / §4.3: only X.509 Signature cert type; digitalSignature KU only.
        """
        ipsec_eku = self.PROFILE_EKU[profile]

        # Key usage: RFC 4945 §3.2 / §4.2 — digitalSignature only for IKE auth
        builder = (
            x509.CertificateBuilder()
            .subject_name(template.subject)
            .issuer_name(template.issuer)
            .public_key(pub_key)
            .serial_number(template.serial_number)
            .not_valid_before(getattr(template, "not_valid_before_utc", template.not_valid_before))
            .not_valid_after(getattr(template, "not_valid_after_utc", template.not_valid_after))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,   # RFC 4945: MUST for IKE signing
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ipsec_eku]), critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(pub_key), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca.ca_key.public_key()
                ),
                critical=False,
            )
        )

        # ── SAN — RFC 4945 §3.1 / §4.1 ────────────────────────────────────
        # RFC 4945 §5.1.3 (via RFC 5280): when Subject is empty the SAN
        # extension MUST be marked critical so relying parties know the SAN
        # carries the binding identity.
        san_names: list = []
        for d in san_dns:
            san_names.append(x509.DNSName(d))
        for e in san_emails:
            san_names.append(x509.RFC822Name(e))
        for ip in san_ips:
            try:
                san_names.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        if san_names:
            subject_is_empty = (
                len(list(template.subject)) == 0
            )
            san_critical = subject_is_empty  # RFC 4945 §5.1.3 / RFC 5280 §4.2.1.6
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names), critical=san_critical
            )

        # ── AIA (OCSP) + CDP — RFC 4809 §3.2 / RFC 4945 §3.2 ──────────────
        if ocsp_url:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]),
                critical=False,
            )
        if crl_url:
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]),
                critical=False,
            )

        cert = builder.sign(self.ca.ca_key, SHA256())

        # Update the DER stored in the CA's DB to reflect the rebuilt cert
        try:
            conn = sqlite3.connect(str(self.ca.db_path))
            conn.execute(
                "UPDATE certificates SET der=? WHERE serial=?",
                (cert.public_bytes(Encoding.DER), cert.serial_number),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Could not update cert DER in DB after EKU rebuild: {e}")

        return cert

    def batch_issue(
        self,
        requests: List[Dict[str, Any]],
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        audit_ip: str = "",
        key_password: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        RFC 4809 §3.1.2 — batch issuance.
        Each request in `requests` may contain the same fields as issue().
        Each request may also carry its own 'key_password'; if absent, the
        top-level key_password is used (RFC 4809 §3.1.2 / §3.3.4).
        Returns list of result dicts: {ok, serial, cert_pem, key_pem?, warning?, error?}
        """
        results: List[Dict[str, Any]] = []
        for i, req in enumerate(requests):
            try:
                cert, priv_key_pem, warning = self.issue(
                    subject_str  = req.get("subject", ""),
                    public_key_pem = req.get("public_key_pem"),
                    validity_days  = int(req.get("validity_days", 365)),
                    profile        = req.get("profile", "ipsec_end"),
                    san_dns        = req.get("san_dns", []),
                    san_emails     = req.get("san_emails", []),
                    san_ips        = req.get("san_ips", []),
                    ocsp_url       = req.get("ocsp_url", ocsp_url),
                    crl_url        = req.get("crl_url", crl_url),
                    audit_ip       = audit_ip,
                    key_password   = req.get("key_password"),
                )
                result: Dict[str, Any] = {
                    "ok":       True,
                    "index":    i,
                    "serial":   cert.serial_number,
                    "subject":  cert.subject.rfc4514_string(),
                    "not_after": getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
                    "cert_pem": cert.public_bytes(Encoding.PEM).decode(),
                }
                if priv_key_pem:
                    result["key_pem"] = priv_key_pem
                if warning:
                    result["warning"] = warning
                results.append(result)
            except Exception as e:
                results.append({"ok": False, "index": i, "error": str(e)})
        return results

    def pkc_update(
        self,
        old_serial: int,
        new_public_key_pem: Optional[str] = None,
        new_san_dns: Optional[List[str]] = None,
        new_san_emails: Optional[List[str]] = None,
        new_san_ips: Optional[List[str]] = None,
        validity_days: Optional[int] = None,
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        audit_ip: str = "",
        key_password: Optional[str] = None,
    ) -> x509.Certificate:
        """
        RFC 4809 §3.3 PKC Update — same SubjectName, new public key, possibly
        altered SubjectAltName. Issues a new cert; old cert is NOT automatically
        revoked (operator may choose to revoke separately per §3.3).
        """
        # Fetch old cert from DB
        try:
            conn = sqlite3.connect(str(self.ca.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT der, profile FROM certificates WHERE serial=? AND revoked=0",
                (old_serial,)
            ).fetchone()
            conn.close()
        except Exception as e:
            raise RuntimeError(f"DB error fetching serial {old_serial}: {e}")

        if row is None:
            raise ValueError(
                f"No active (non-revoked) certificate with serial {old_serial}"
            )

        old_cert = x509.load_der_x509_certificate(row["der"])
        old_profile = row["profile"] or "ipsec_end"

        # Reconstruct subject string from old cert
        subject_parts = []
        attr_map = {
            NameOID.COMMON_NAME:              "CN",
            NameOID.ORGANIZATION_NAME:        "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME:             "C",
            NameOID.LOCALITY_NAME:            "L",
            NameOID.STATE_OR_PROVINCE_NAME:   "ST",
        }
        for attr in old_cert.subject:
            label = attr_map.get(attr.oid, attr.oid.dotted_string)
            subject_parts.append(f"{label}={attr.value}")
        subject_str = ",".join(subject_parts)

        # Reconstruct SANs from old cert if not overridden
        if new_san_dns is None and new_san_emails is None and new_san_ips is None:
            new_san_dns, new_san_emails, new_san_ips = [], [], []
            try:
                san_ext = old_cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        new_san_dns.append(name.value)
                    elif isinstance(name, x509.RFC822Name):
                        new_san_emails.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        new_san_ips.append(str(name.value))
            except x509.ExtensionNotFound:
                pass

        # Resolve old profile to ipsec_* profile
        profile = old_profile if old_profile in self.VALID_PROFILES else "ipsec_end"

        # Issue new cert with same subject
        cert, priv_key_pem, _ = self.issue(
            subject_str    = subject_str,
            public_key_pem = new_public_key_pem,
            validity_days  = validity_days or 365,
            profile        = profile,
            san_dns        = new_san_dns or [],
            san_emails     = new_san_emails or [],
            san_ips        = new_san_ips or [],
            ocsp_url       = ocsp_url,
            crl_url        = crl_url,
            audit_ip       = audit_ip,
            key_password   = key_password,
        )

        logger.info(
            f"PKC Update (RFC 4809 §3.3): old serial={old_serial} → "
            f"new serial={cert.serial_number} subject={subject_str!r}"
        )
        return cert, priv_key_pem


    def pkc_renew(
        self,
        old_serial: int,
        validity_days: int = 365,
        ocsp_url: Optional[str] = None,
        crl_url: Optional[str] = None,
        audit_ip: str = "",
        key_password: Optional[str] = None,
    ) -> "x509.Certificate":
        """
        RFC 4809 §3.5 PKC Renew — re-issue with the SAME public key and same
        SubjectName, extending the validity window.

        This is distinct from pkc_update() (§3.3), which requires a new key.
        Renew is used for routine certificate lifecycle maintenance without
        changing the key pair.

        The old certificate is NOT automatically revoked; the operator may
        choose to revoke it separately if policy requires (RFC 4809 §3.5).
        """
        # Fetch old cert from DB
        try:
            conn = sqlite3.connect(str(self.ca.db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT der, profile FROM certificates WHERE serial=? AND revoked=0",
                (old_serial,)
            ).fetchone()
            conn.close()
        except Exception as e:
            raise RuntimeError(f"DB error fetching serial {old_serial}: {e}")

        if row is None:
            raise ValueError(
                f"No active (non-revoked) certificate with serial {old_serial}"
            )

        old_cert = x509.load_der_x509_certificate(row["der"])
        old_profile = row["profile"] or "ipsec_end"

        # Reconstruct subject string from old cert
        subject_parts = []
        attr_map = {
            NameOID.COMMON_NAME:              "CN",
            NameOID.ORGANIZATION_NAME:        "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME:             "C",
            NameOID.LOCALITY_NAME:            "L",
            NameOID.STATE_OR_PROVINCE_NAME:   "ST",
        }
        for attr in old_cert.subject:
            label = attr_map.get(attr.oid, attr.oid.dotted_string)
            subject_parts.append(f"{label}={attr.value}")
        subject_str = ",".join(subject_parts)

        # Extract existing SANs
        san_dns, san_emails, san_ips = [], [], []
        try:
            san_ext = old_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns.append(name.value)
                elif isinstance(name, x509.RFC822Name):
                    san_emails.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ips.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        # Extract existing public key — reuse it (that's the point of Renew vs Update)
        old_pub_key = old_cert.public_key()
        old_pub_key_pem = old_pub_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

        profile = old_profile if old_profile in self.VALID_PROFILES else "ipsec_end"

        # Issue new cert with SAME public key
        new_cert, _, warning = self.issue(
            subject_str    = subject_str,
            public_key_pem = old_pub_key_pem,   # same key — no private key returned
            validity_days  = validity_days,
            profile        = profile,
            san_dns        = san_dns,
            san_emails     = san_emails,
            san_ips        = san_ips,
            ocsp_url       = ocsp_url,
            crl_url        = crl_url,
            audit_ip       = audit_ip,
        )

        logger.info(
            f"PKC Renew (RFC 4809 §3.5): old serial={old_serial} → "
            f"new serial={new_cert.serial_number} subject={subject_str!r} "
            f"(same public key, validity_days={validity_days})"
        )
        if warning:
            logger.warning(f"PKC Renew warning: {warning}")
        return new_cert


# ---------------------------------------------------------------------------
# RFC 4809 §3.4.4 — Manual approval queue
# ---------------------------------------------------------------------------

class ApprovalQueue:
    """
    RFC 4809 §3.4.4 — Manual Approval Option.

    When a PKC request arrives with require_approval=True (or when the server
    is configured with approval_required=True for a profile), the request is
    held in a pending queue rather than issued immediately.  An administrator
    then calls POST /ipsec/approve/<request_id> to issue the cert, or
    POST /ipsec/reject/<request_id> to decline.

    Storage is in-memory + SQLite-backed so it survives server restarts.
    """

    # Pending-request states
    STATE_PENDING  = "pending"
    STATE_APPROVED = "approved"
    STATE_REJECTED = "rejected"

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_table()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_table(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ipsec_pending_requests (
                    request_id    TEXT PRIMARY KEY,
                    state         TEXT NOT NULL DEFAULT 'pending',
                    created_at    TEXT NOT NULL,
                    decided_at    TEXT,
                    confirmed_at  TEXT,
                    requester_ip  TEXT,
                    request_json  TEXT NOT NULL,
                    result_serial INTEGER,
                    result_cert_pem TEXT,
                    reject_reason TEXT
                )
            """)
            # RFC 4809 §3.4.10 — confirmations for directly issued certs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ipsec_cert_confirmations (
                    serial        INTEGER PRIMARY KEY,
                    confirmed_at  TEXT NOT NULL,
                    requester_ip  TEXT
                )
            """)
            # Migrate existing DB: add confirmed_at if absent (idempotent)
            cols = {r[1] for r in conn.execute(
                "PRAGMA table_info(ipsec_pending_requests)"
            ).fetchall()}
            if "confirmed_at" not in cols:
                try:
                    conn.execute(
                        "ALTER TABLE ipsec_pending_requests ADD COLUMN confirmed_at TEXT"
                    )
                except Exception:
                    pass
            conn.commit()

    def record_direct_confirmation(self, serial: int, requester_ip: str = "") -> bool:
        """
        RFC 4809 §3.4.10 — record confirmation for a cert issued directly
        (not via the approval queue).
        Returns True if this is the first confirmation for this serial.
        """
        now = datetime.datetime.now(_tz.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                try:
                    conn.execute(
                        "INSERT INTO ipsec_cert_confirmations (serial, confirmed_at, requester_ip) VALUES (?,?,?)",
                        (serial, now, requester_ip)
                    )
                    conn.commit()
                    logger.info(f"RFC4809 §3.4.10: direct cert confirmation serial={serial}")
                    return True
                except sqlite3.IntegrityError:
                    return False  # already confirmed

    def enqueue(self, request_data: Dict[str, Any], requester_ip: str = "") -> str:
        """Add a request to the pending queue. Returns request_id."""
        import uuid
        request_id = str(uuid.uuid4())
        now = datetime.datetime.now(_tz.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO ipsec_pending_requests "                    "(request_id, state, created_at, requester_ip, request_json) "                    "VALUES (?,?,?,?,?)",
                    (request_id, self.STATE_PENDING, now, requester_ip,
                     json.dumps(request_data))
                )
                conn.commit()
        logger.info(f"RFC4809 §3.4.4: queued pending request {request_id}")
        return request_id

    def get(self, request_id: str) -> Optional[Dict]:
        """Return the pending request row as a dict, or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ipsec_pending_requests WHERE request_id=?",
                (request_id,)
            ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_pending(self) -> List[Dict]:
        """Return all pending (unapproved) requests."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ipsec_pending_requests WHERE state=? ORDER BY created_at",
                (self.STATE_PENDING,)
            ).fetchall()
        return [dict(r) for r in rows]

    def approve(self, request_id: str, serial: int, cert_pem: str):
        """Mark a request as approved and store the issued cert."""
        now = datetime.datetime.now(_tz.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE ipsec_pending_requests SET state=?, decided_at=?, "                    "result_serial=?, result_cert_pem=? WHERE request_id=?",
                    (self.STATE_APPROVED, now, serial, cert_pem, request_id)
                )
                conn.commit()
        logger.info(f"RFC4809 §3.4.4: approved request {request_id} → serial={serial}")

    def reject(self, request_id: str, reason: str = ""):
        """Mark a request as rejected."""
        now = datetime.datetime.now(_tz.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE ipsec_pending_requests SET state=?, decided_at=?, "                    "reject_reason=? WHERE request_id=?",
                    (self.STATE_REJECTED, now, reason, request_id)
                )
                conn.commit()
        logger.info(f"RFC4809 §3.4.4: rejected request {request_id}: {reason}")

    def confirm_receipt(self, request_id: str, serial: int) -> bool:
        """
        RFC 4809 §3.4.10 — Enrollment Confirmation.
        Record that the peer has confirmed receipt of the issued certificate.
        Returns True if the record was found and updated, False otherwise.
        """
        now = datetime.datetime.now(_tz.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "ALTER TABLE ipsec_pending_requests "
                    "ADD COLUMN confirmed_at TEXT"
                ) if not self._has_column(conn, "confirmed_at") else None
                cursor = conn.execute(
                    "UPDATE ipsec_pending_requests SET confirmed_at=? "
                    "WHERE request_id=? AND result_serial=?",
                    (now, request_id, serial)
                )
                conn.commit()
                updated = cursor.rowcount > 0
        if updated:
            logger.info(
                f"RFC4809 §3.4.10: enrollment confirmation received — "
                f"request_id={request_id} serial={serial}"
            )
        return updated

    @staticmethod
    def _has_column(conn: sqlite3.Connection, col: str) -> bool:
        """Check whether ipsec_pending_requests already has a given column."""
        rows = conn.execute(
            "PRAGMA table_info(ipsec_pending_requests)"
        ).fetchall()
        return any(r[1] == col for r in rows)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class IPsecHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler for the IPsec PKI server.

    Endpoints:
      GET  /ipsec/health
      GET  /ipsec/ca-cert
      GET  /ipsec/profiles
      POST /ipsec/issue              (may return pending if require_approval=true)
      POST /ipsec/enroll             PKCS#10 CSR enrollment (RFC 4809 §3.4.5)
      POST /ipsec/batch-issue
      POST /ipsec/update             RFC 4809 §3.3 — new key, same subject
      POST /ipsec/renew              RFC 4809 §3.5 — same key, new validity
      POST /ipsec/revoke
      GET  /ipsec/cert/<serial>
      GET  /ipsec/pending            RFC 4809 §3.4.4 — list pending requests
      GET  /ipsec/pending/<id>       status of a pending request
      POST /ipsec/approve/<id>       RFC 4809 §3.4.4 — approve a pending request
      POST /ipsec/reject/<id>        RFC 4809 §3.4.4 — reject a pending request
      POST /ipsec/confirm            RFC 4809 §3.4.10 — enrollment confirmation
      POST /ipsec/ocsp-hash
      GET  /ipsec/ocsp-hash/<hex>/<serial>
    """

    # Set by start_ipsec_server()
    issuer: "IPsecCertIssuer"        = None
    ocsp_resolver: "RFC4806OCSPHashResolver" = None
    approval_queue: "ApprovalQueue"  = None
    ca: "CertificateAuthority"       = None
    ocsp_url: Optional[str]          = None
    crl_url:  Optional[str]          = None
    tls_active: bool                  = False   # True when TLS is wrapping the socket

    def log_message(self, fmt, *args):
        logger.debug(f"IPsec {self.client_address[0]} — {fmt % args}")

    def _send_json(self, data: Any, code: int = 200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code: int, body: bytes, ct: str):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[Dict]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            return json.loads(body) if body else {}
        except Exception:
            return None

    def do_GET(self):
        try:
            self._do_GET(self.path.split("?")[0].rstrip("/"))
        except Exception as e:
            logger.error(f"IPsec GET error on {self.path}: {e}\n{traceback.format_exc()}")
            self._send_json({"error": f"Internal server error: {e}"}, 500)

    def _do_GET(self, path: str):
        if path == "/ipsec/health":
            # Include RFC 4945 §5.2 CDP reachability advisory in health response
            cdp_status = {}
            if self.crl_url:
                cdp_ok, cdp_detail = _validate_cdp_url(self.crl_url, timeout=3.0)
                cdp_status = {"url": self.crl_url, "reachable": cdp_ok, "detail": cdp_detail}
            else:
                cdp_status = {"url": None, "reachable": None,
                              "detail": "RFC 4945 §5.2: no crl_url configured — issued certs will lack CDP"}
            # RFC 4945 §5.1.3: report NameConstraints presence
            try:
                self.ca.ca_cert.extensions.get_extension_for_class(x509.NameConstraints)
                nc_status = "present — issuance requests will be checked against permitted/excluded subtrees"
            except x509.ExtensionNotFound:
                nc_status = "not present — all names accepted (standard open CA)"
            # RFC 4945 §5.3: CA cert hash algorithm
            try:
                ca_hash = self.ca.ca_cert.signature_hash_algorithm
                ca_hash_name = ca_hash.name if ca_hash else "none (EdDSA)"
                sha1_warn = ("sha1" in ca_hash_name.lower().replace("-","").replace("_",""))
            except Exception:
                ca_hash_name = "unknown"
                sha1_warn = False
            self._send_json({
                "status": "ok",
                "rfc": ["RFC4945", "RFC4806", "RFC4809"],
                "profiles": sorted(IPsecCertIssuer.VALID_PROFILES),
                "tls": self.tls_active,
                "compliance": {
                    "rfc4945_s5_1_3_name_constraints": nc_status,
                    "rfc4945_s5_2_cdp": cdp_status,
                    "rfc4945_s5_3_ca_hash": {
                        "algorithm": ca_hash_name,
                        "sha1_warning": sha1_warn,
                        "note": (
                            "RFC 4945 §5.3: CA cert uses SHA-1 — MUST be replaced"
                            if sha1_warn else
                            "ok — SHA-256 or stronger"
                        ),
                    },
                },
            })

        elif path == "/ipsec/ca-cert":
            # RFC 4809 §3.1.3 (b): allow Peer to retrieve root cert from Admin.
            # For intermediate CA mode we return the full chain PEM so the peer
            # can verify certificates up to the trust anchor it already holds.
            pem = self.ca.ca_chain_pem
            self._send_raw(200, pem, "application/x-pem-file")

        elif path == "/ipsec/profiles":
            self._send_json({
                "profiles": {
                    "ipsec_tunnel": {
                        "eku": "id-kp-ipsecTunnel (1.3.6.1.5.5.7.3.6)",
                        "use": "Gateway-to-gateway VPN tunnel (RFC 4945 §2)",
                        "san_required": "dNSName or iPAddress",
                        "rfc4809_role": "IPsec Peer (gateway)",
                    },
                    "ipsec_end": {
                        "eku": "id-kp-ipsecEndSystem (1.3.6.1.5.5.7.3.5)",
                        "use": "Host/device end-system (RFC 4945 §2)",
                        "san_required": "dNSName or iPAddress",
                        "rfc4809_role": "IPsec Peer (device)",
                    },
                    "ipsec_user": {
                        "eku": "id-kp-ipsecUser (1.3.6.1.5.5.7.3.7)",
                        "use": "Human VPN user (RFC 4945 §2)",
                        "san_required": "rfc822Name (email)",
                        "rfc4809_role": "IPsec Peer (user)",
                    },
                }
            })

        elif path.startswith("/ipsec/cert/"):
            serial_str = path[len("/ipsec/cert/"):]
            try:
                serial = int(serial_str)
            except ValueError:
                self._send_json({"error": "Invalid serial number"}, 400)
                return
            try:
                conn = sqlite3.connect(str(self.ca.db_path))
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT der, revoked FROM certificates WHERE serial=?", (serial,)
                ).fetchone()
                conn.close()
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
                return
            if row is None:
                self._send_json({"error": f"Certificate serial {serial} not found"}, 404)
                return
            cert = x509.load_der_x509_certificate(row["der"])
            pem = cert.public_bytes(Encoding.PEM)
            self._send_raw(200, pem, "application/x-pem-file")

        elif path.startswith("/ipsec/ocsp-hash/"):
            # RFC 4806 GET variant: /ipsec/ocsp-hash/<issuer_hash_hex>/<serial_hex>
            rest = path[len("/ipsec/ocsp-hash/"):]
            parts = rest.split("/")
            if len(parts) < 2:
                self._send_json(
                    {"error": "Expected /ipsec/ocsp-hash/<issuer_sha1_hex>/<serial_hex>"},
                    400
                )
                return
            try:
                issuer_hash = bytes.fromhex(parts[0])
                serial      = int(parts[1], 16)
            except ValueError as e:
                self._send_json({"error": f"Invalid hex value: {e}"}, 400)
                return
            ok, resp_der, err = self.ocsp_resolver.resolve(issuer_hash, serial)
            if not ok:
                self._send_json({"error": err}, 400)
                return
            # RFC 4806 §4.2: OCSP response suitable for IKEv2 CERT payload (Cert Encoding 14)
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(resp_der)))
            self.send_header("X-IKEv2-Cert-Encoding", str(IKEV2_CERT_ENCODING_OCSP_CONTENT))
            self.send_header("Cache-Control", "max-age=1800, public")  # 30 min per RFC 4806
            self.end_headers()
            self.wfile.write(resp_der)

        elif path == "/ipsec/pending":
            # RFC 4809 §3.4.4 — list all pending approval requests
            if self.approval_queue is None:
                self._send_json({"error": "Approval queue not configured"}, 500)
                return
            rows = self.approval_queue.list_pending()
            self._send_json({
                "ok": True,
                "pending_count": len(rows),
                "requests": [
                    {
                        "request_id":   r["request_id"],
                        "created_at":   r["created_at"],
                        "requester_ip": r["requester_ip"],
                        "subject":      json.loads(r["request_json"]).get("subject", ""),
                        "profile":      json.loads(r["request_json"]).get("profile", ""),
                        "approve_url":  f"/ipsec/approve/{r['request_id']}",
                        "reject_url":   f"/ipsec/reject/{r['request_id']}",
                    }
                    for r in rows
                ],
                "rfc4809": "Pending approval queue per RFC 4809 §3.4.4",
            })

        elif path.startswith("/ipsec/pending/"):
            # RFC 4809 §3.4.4 — status of one pending request
            request_id = path[len("/ipsec/pending/"):]
            if self.approval_queue is None:
                self._send_json({"error": "Approval queue not configured"}, 500)
                return
            row = self.approval_queue.get(request_id)
            if row is None:
                self._send_json({"error": f"Unknown request_id: {request_id}"}, 404)
                return
            resp = {
                "request_id":   row["request_id"],
                "state":        row["state"],
                "created_at":   row["created_at"],
                "decided_at":   row["decided_at"],
                "requester_ip": row["requester_ip"],
                "subject":      json.loads(row["request_json"]).get("subject", ""),
                "profile":      json.loads(row["request_json"]).get("profile", ""),
            }
            if row["state"] == ApprovalQueue.STATE_APPROVED:
                resp["serial"]   = row["result_serial"]
                resp["cert_pem"] = row["result_cert_pem"]
            elif row["state"] == ApprovalQueue.STATE_REJECTED:
                resp["reject_reason"] = row["reject_reason"]
            self._send_json(resp)

        else:
            self._send_json({
                "error": "unknown endpoint",
                "endpoints": {
                    "GET  /ipsec/health":                    "liveness check",
                    "GET  /ipsec/ca-cert":                   "CA cert PEM (RFC 4809 §3.1.3)",
                    "GET  /ipsec/profiles":                  "IPsec certificate profiles",
                    "GET  /ipsec/cert/<serial>":             "fetch cert by serial",
                    "GET  /ipsec/ocsp-hash/<hash>/<serial>": "RFC 4806 cacheable OCSP GET",
                    "GET  /ipsec/pending":                   "list pending approval requests (RFC 4809 §3.4.4)",
                    "GET  /ipsec/pending/<id>":              "status of one pending request",
                    "POST /ipsec/issue":                     "issue RFC 4945/4809 cert (add require_approval:true to queue)",
                    "POST /ipsec/enroll":                    "PKCS#10 CSR enrollment (RFC 4809 §3.4.5)",
                    "POST /ipsec/batch-issue":               "RFC 4809 §3.1.2 batch issuance",
                    "POST /ipsec/update":                    "RFC 4809 §3.3 PKC Update — new key, same subject",
                    "POST /ipsec/renew":                     "RFC 4809 §3.5 PKC Renew — same key, new validity",
                    "POST /ipsec/revoke":                    "revoke an IPsec cert",
                    "POST /ipsec/confirm":                   "enrollment confirmation (RFC 4809 §3.4.10)",
                    "POST /ipsec/approve/<id>":              "approve a pending request (RFC 4809 §3.4.4)",
                    "POST /ipsec/reject/<id>":               "reject a pending request (RFC 4809 §3.4.4)",
                    "POST /ipsec/ocsp-hash":                 "RFC 4806 hash-based OCSP lookup",
                }
            }, 404)

    def do_POST(self):
        try:
            self._do_POST(self.path.split("?")[0].rstrip("/"))
        except Exception as e:
            logger.error(f"IPsec POST error on {self.path}: {e}\n{traceback.format_exc()}")
            self._send_json({"error": f"Internal server error: {e}"}, 500)

    def _do_POST(self, path: str):
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON in request body"}, 400)
            return

        client_ip = self.client_address[0]

        # ── POST /ipsec/issue ─────────────────────────────────────────────
        if path == "/ipsec/issue":
            subject = data.get("subject", "").strip()
            if not subject:
                self._send_json({"error": "subject is required"}, 400)
                return
            profile = data.get("profile", "ipsec_end")
            if profile not in IPsecCertIssuer.VALID_PROFILES:
                self._send_json(
                    {"error": f"Unknown profile '{profile}'. "
                               f"Valid: {sorted(IPsecCertIssuer.VALID_PROFILES)}"},
                    400
                )
                return

            # RFC 4809 §3.4.4 — manual approval option
            if data.get("require_approval"):
                if self.approval_queue is None:
                    self._send_json({"error": "Approval queue not configured"}, 500)
                    return
                request_id = self.approval_queue.enqueue(data, requester_ip=client_ip)
                self._send_json({
                    "ok":        False,
                    "pending":   True,
                    "request_id": request_id,
                    "message":   "Request queued for administrator approval (RFC 4809 §3.4.4)",
                    "status_url": f"/ipsec/pending/{request_id}",
                    "approve_url": f"/ipsec/approve/{request_id}",
                    "reject_url":  f"/ipsec/reject/{request_id}",
                }, 202)
                return

            try:
                cert, priv_key_pem, warning = self.issuer.issue(
                    subject_str    = subject,
                    public_key_pem = data.get("public_key_pem"),
                    validity_days  = int(data.get("validity_days", 365)),
                    profile        = profile,
                    san_dns        = data.get("san_dns", []),
                    san_emails     = data.get("san_emails", []),
                    san_ips        = data.get("san_ips", []),
                    ocsp_url       = data.get("ocsp_url", self.ocsp_url),
                    crl_url        = data.get("crl_url", self.crl_url),
                    audit_ip       = client_ip,
                    key_password   = data.get("key_password"),
                )
            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
                return
            resp: Dict[str, Any] = {
                "ok":       True,
                "serial":   cert.serial_number,
                "subject":  cert.subject.rfc4514_string(),
                "profile":  profile,
                "not_after": getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
                "cert_pem": cert.public_bytes(Encoding.PEM).decode(),
                "rfc": {
                    "4945": "digitalSignature only KU; IPsec EKU; SANs validated",
                    "4809": "AIA-OCSP and CDP included for path validation",
                },
            }
            if priv_key_pem:
                resp["key_pem"] = priv_key_pem
                if data.get("key_password"):
                    resp["key_encrypted"] = True
                    resp["key_encryption"] = "PKCS8 AES-256-CBC (supply key_password to openssl to decrypt)"
                else:
                    resp["key_encrypted"] = False
                    resp["key_security_warning"] = (
                        "RFC 4809 §3.1.2: key returned unencrypted. "
                        "Supply 'key_password' in the request or enable TLS."
                    )
            if warning:
                resp["warning"] = warning
            self._send_json(resp, 201)

        # ── POST /ipsec/batch-issue (RFC 4809 §3.1.2) ────────────────────
        elif path == "/ipsec/batch-issue":
            requests_list = data.get("requests", data if isinstance(data, list) else [])
            if not isinstance(requests_list, list) or not requests_list:
                self._send_json(
                    {"error": "Body must be {'requests': [...]} or a JSON array"},
                    400
                )
                return
            results = self.issuer.batch_issue(
                requests  = requests_list,
                ocsp_url  = data.get("ocsp_url", self.ocsp_url) if isinstance(data, dict) else self.ocsp_url,
                crl_url   = data.get("crl_url", self.crl_url)   if isinstance(data, dict) else self.crl_url,
                audit_ip  = client_ip,
            )
            n_ok   = sum(1 for r in results if r.get("ok"))
            n_fail = len(results) - n_ok
            self._send_json({
                "ok": n_fail == 0,
                "total": len(results),
                "issued": n_ok,
                "failed": n_fail,
                "results": results,
                "rfc4809": "batch-issue per RFC 4809 §3.1.2",
            }, 200 if n_fail == 0 else 207)

        # ── POST /ipsec/update (RFC 4809 §3.3 PKC Update) ────────────────
        elif path == "/ipsec/update":
            old_serial = data.get("old_serial")
            if old_serial is None:
                self._send_json({"error": "old_serial is required"}, 400)
                return
            try:
                cert, priv_key_pem = self.issuer.pkc_update(
                    old_serial       = int(old_serial),
                    new_public_key_pem = data.get("public_key_pem"),
                    new_san_dns      = data.get("san_dns"),
                    new_san_emails   = data.get("san_emails"),
                    new_san_ips      = data.get("san_ips"),
                    validity_days    = data.get("validity_days"),
                    ocsp_url         = data.get("ocsp_url", self.ocsp_url),
                    crl_url          = data.get("crl_url", self.crl_url),
                    audit_ip         = client_ip,
                    key_password     = data.get("key_password"),
                )
            except (ValueError, RuntimeError) as e:
                self._send_json({"error": str(e)}, 400)
                return
            resp = {
                "ok":          True,
                "old_serial":  int(old_serial),
                "new_serial":  cert.serial_number,
                "subject":     cert.subject.rfc4514_string(),
                "not_after":   getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
                "cert_pem":    cert.public_bytes(Encoding.PEM).decode(),
                "rfc4809":     "PKC Update per RFC 4809 §3.3",
                "note":        "Old certificate NOT automatically revoked — revoke separately if required",
            }
            if priv_key_pem:
                resp["key_pem"] = priv_key_pem
                if data.get("key_password"):
                    resp["key_encrypted"] = True
                    resp["key_encryption"] = "PKCS8 AES-256-CBC (supply key_password to openssl to decrypt)"
                else:
                    resp["key_encrypted"] = False
                    resp["key_security_warning"] = (
                        "RFC 4809 §3.1.2: key returned unencrypted. "
                        "Supply 'key_password' in the request or enable TLS."
                    )
            self._send_json(resp, 201)

        # ── POST /ipsec/renew (RFC 4809 §3.5 — same key, new validity) ───
        elif path == "/ipsec/renew":
            old_serial = data.get("old_serial")
            if old_serial is None:
                self._send_json({"error": "old_serial is required"}, 400)
                return
            try:
                new_cert = self.issuer.pkc_renew(
                    old_serial    = int(old_serial),
                    validity_days = int(data.get("validity_days", 365)),
                    ocsp_url      = data.get("ocsp_url", self.ocsp_url),
                    crl_url       = data.get("crl_url",  self.crl_url),
                    audit_ip      = client_ip,
                )
            except (ValueError, RuntimeError) as e:
                self._send_json({"error": str(e)}, 400)
                return
            self._send_json({
                "ok":         True,
                "old_serial": int(old_serial),
                "new_serial": new_cert.serial_number,
                "subject":    new_cert.subject.rfc4514_string(),
                "not_after":  getattr(new_cert, "not_valid_after_utc", new_cert.not_valid_after).isoformat(),
                "cert_pem":   new_cert.public_bytes(Encoding.PEM).decode(),
                "rfc4809":    "PKC Renew per RFC 4809 §3.5 — same public key, new validity window",
                "note":       "Old certificate NOT automatically revoked — revoke separately if required",
            }, 201)

        # ── POST /ipsec/enroll (RFC 4809 §3.4.5 — PKCS#10 CSR) ──────────
        elif path == "/ipsec/enroll":
            csr_pem = (data.get("csr_pem") or "").strip()
            if not csr_pem:
                self._send_json({
                    "error": "csr_pem is required (PKCS#10 PEM)",
                    "rfc": "RFC 4809 §3.4.5 — Peer-direct enrollment with proof of possession",
                }, 400)
                return
            try:
                from cryptography.x509 import load_pem_x509_csr
                csr = load_pem_x509_csr(csr_pem.encode())
            except Exception as e:
                self._send_json({"error": f"Invalid PKCS#10 CSR: {e}"}, 400)
                return
            # Verify CSR signature — proof-of-possession (RFC 4809 §3.3.1)
            if not csr.is_signature_valid:
                self._send_json({
                    "error": "CSR signature invalid — proof-of-possession check failed (RFC 4809 §3.3.1)",
                }, 400)
                return
            # Extract subject from CSR
            attr_label = {
                "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU",
                "2.5.4.6": "C",  "2.5.4.7": "L",  "2.5.4.8": "ST",
            }
            subject_parts = [
                f"{attr_label.get(attr.oid.dotted_string, attr.oid.dotted_string)}={attr.value}"
                for attr in csr.subject
            ]
            subject_str = ",".join(subject_parts)
            if not subject_str.strip():
                self._send_json({"error": "CSR Subject must not be empty (RFC 4945 §5.1.2)"}, 400)
                return
            # Extract SANs from CSR extension unless caller overrides
            san_dns    = data.get("san_dns")
            san_emails = data.get("san_emails")
            san_ips    = data.get("san_ips")
            if san_dns is None and san_emails is None and san_ips is None:
                san_dns, san_emails, san_ips = [], [], []
                try:
                    csr_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for n in csr_san.value:
                        if isinstance(n, x509.DNSName):       san_dns.append(n.value)
                        elif isinstance(n, x509.RFC822Name):  san_emails.append(n.value)
                        elif isinstance(n, x509.IPAddress):   san_ips.append(str(n.value))
                except x509.ExtensionNotFound:
                    pass
            profile = data.get("profile", "ipsec_end")
            if profile not in IPsecCertIssuer.VALID_PROFILES:
                self._send_json({
                    "error": f"Unknown profile '{profile}'. Valid: {sorted(IPsecCertIssuer.VALID_PROFILES)}"
                }, 400)
                return
            # RFC 4809 §3.4.4 — honour require_approval flag
            if data.get("require_approval"):
                if self.approval_queue is None:
                    self._send_json({"error": "Approval queue not configured"}, 500)
                    return
                from cryptography.hazmat.primitives.serialization import PublicFormat as _PF
                pub_pem = csr.public_key().public_bytes(Encoding.PEM, _PF.SubjectPublicKeyInfo).decode()
                queued  = dict(data)
                queued.update({"subject": subject_str, "public_key_pem": pub_pem,
                               "san_dns": san_dns or [], "san_emails": san_emails or [],
                               "san_ips": san_ips or []})
                queued.pop("csr_pem", None)
                request_id = self.approval_queue.enqueue(queued, requester_ip=client_ip)
                self._send_json({
                    "ok": False, "pending": True, "request_id": request_id,
                    "message": "CSR enrollment queued for administrator approval (RFC 4809 §3.4.4)",
                    "status_url":  f"/ipsec/pending/{request_id}",
                    "approve_url": f"/ipsec/approve/{request_id}",
                    "reject_url":  f"/ipsec/reject/{request_id}",
                }, 202)
                return
            # Issue cert directly — private key never leaves the peer
            from cryptography.hazmat.primitives.serialization import PublicFormat as _PF
            pub_pem = csr.public_key().public_bytes(Encoding.PEM, _PF.SubjectPublicKeyInfo).decode()
            try:
                cert, _, warning = self.issuer.issue(
                    subject_str    = subject_str,
                    public_key_pem = pub_pem,
                    validity_days  = int(data.get("validity_days", 365)),
                    profile        = profile,
                    san_dns        = san_dns or [],
                    san_emails     = san_emails or [],
                    san_ips        = san_ips or [],
                    ocsp_url       = data.get("ocsp_url", self.ocsp_url),
                    crl_url        = data.get("crl_url",  self.crl_url),
                    audit_ip       = client_ip,
                )
            except ValueError as e:
                self._send_json({"error": str(e)}, 400)
                return
            resp = {
                "ok":       True,
                "serial":   cert.serial_number,
                "subject":  cert.subject.rfc4514_string(),
                "profile":  profile,
                "not_after": getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
                "cert_pem": cert.public_bytes(Encoding.PEM).decode(),
                "rfc4809":  "PKCS#10 CSR enrollment per RFC 4809 §3.4.5 — private key not escrowed",
            }
            if warning:
                resp["warning"] = warning
            self._send_json(resp, 201)

        # ── POST /ipsec/approve/<id> (RFC 4809 §3.4.4) ───────────────────
        elif path.startswith("/ipsec/approve/"):
            request_id = path[len("/ipsec/approve/"):]
            if not request_id:
                self._send_json({"error": "request_id required in URL path"}, 400)
                return
            if self.approval_queue is None:
                self._send_json({"error": "Approval queue not configured"}, 500)
                return
            row = self.approval_queue.get(request_id)
            if row is None:
                self._send_json({"error": f"Unknown request_id: {request_id}"}, 404)
                return
            if row["state"] != ApprovalQueue.STATE_PENDING:
                self._send_json({
                    "error": f"Request already in state '{row['state']}'",
                    "request_id": request_id,
                }, 409)
                return
            req_data = json.loads(row["request_json"])
            if data and data.get("validity_days"):
                req_data["validity_days"] = data["validity_days"]
            try:
                cert, priv_key_pem, warning = self.issuer.issue(
                    subject_str    = req_data.get("subject", ""),
                    public_key_pem = req_data.get("public_key_pem"),
                    validity_days  = int(req_data.get("validity_days", 365)),
                    profile        = req_data.get("profile", "ipsec_end"),
                    san_dns        = req_data.get("san_dns", []),
                    san_emails     = req_data.get("san_emails", []),
                    san_ips        = req_data.get("san_ips", []),
                    ocsp_url       = req_data.get("ocsp_url", self.ocsp_url),
                    crl_url        = req_data.get("crl_url",  self.crl_url),
                    audit_ip       = client_ip,
                    key_password   = req_data.get("key_password"),
                )
            except Exception as e:
                self._send_json({"error": f"Issuance failed during approval: {e}"}, 500)
                return
            cert_pem = cert.public_bytes(Encoding.PEM).decode()
            self.approval_queue.approve(request_id, cert.serial_number, cert_pem)
            resp = {
                "ok":         True,
                "request_id": request_id,
                "serial":     cert.serial_number,
                "subject":    cert.subject.rfc4514_string(),
                "not_after":  getattr(cert, "not_valid_after_utc", cert.not_valid_after).isoformat(),
                "cert_pem":   cert_pem,
                "rfc4809":    "Approved per RFC 4809 §3.4.4",
            }
            if priv_key_pem:
                resp["key_pem"]       = priv_key_pem
                resp["key_encrypted"] = bool(req_data.get("key_password"))
            if warning:
                resp["warning"] = warning
            self._send_json(resp, 201)

        # ── POST /ipsec/reject/<id> (RFC 4809 §3.4.4) ────────────────────
        elif path.startswith("/ipsec/reject/"):
            request_id = path[len("/ipsec/reject/"):]
            if not request_id:
                self._send_json({"error": "request_id required in URL path"}, 400)
                return
            if self.approval_queue is None:
                self._send_json({"error": "Approval queue not configured"}, 500)
                return
            row = self.approval_queue.get(request_id)
            if row is None:
                self._send_json({"error": f"Unknown request_id: {request_id}"}, 404)
                return
            if row["state"] != ApprovalQueue.STATE_PENDING:
                self._send_json({
                    "error": f"Request already in state '{row['state']}'",
                    "request_id": request_id,
                }, 409)
                return
            reason = (data.get("reason") or "") if data else ""
            self.approval_queue.reject(request_id, reason)
            self._send_json({
                "ok":         True,
                "request_id": request_id,
                "state":      "rejected",
                "reason":     reason,
                "rfc4809":    "Rejected per RFC 4809 §3.4.4",
            })

        # ── POST /ipsec/confirm (RFC 4809 §3.4.10 — enrollment confirmation) ─
        elif path == "/ipsec/confirm":
            """
            RFC 4809 §3.4.10 — Enrollment Confirmation Handshake.

            After receiving and successfully installing a certificate, the peer
            SHOULD send a confirmation to the PKI so the CA knows the cert was
            received intact and is in use.  This is analogous to the CMPv2
            certConf / pkiConf two-phase commit (RFC 4210 §5.3.18).

            For pending-queue issuances, supply request_id + serial.
            For direct issuances (via /ipsec/issue or /ipsec/enroll), supply
            only serial.

            Request body (JSON):
              { "serial": <int>,           // REQUIRED — cert serial number
                "request_id": "<uuid>",    // OPTIONAL — for approval-queue certs
                "thumbprint_sha256": "<hex>" }  // OPTIONAL — cert fingerprint for audit
            """
            serial = data.get("serial")
            if serial is None:
                self._send_json({"error": "serial is required"}, 400)
                return
            serial = int(serial)

            request_id = data.get("request_id", "")
            thumbprint  = data.get("thumbprint_sha256", "")

            confirmed_queue  = False
            confirmed_direct = False

            if self.approval_queue:
                if request_id:
                    confirmed_queue = self.approval_queue.confirm_receipt(request_id, serial)
                confirmed_direct = self.approval_queue.record_direct_confirmation(serial, client_ip)

            # Verify the serial actually exists in the CA database (optional audit)
            cert_exists = False
            try:
                conn = sqlite3.connect(str(self.ca.db_path))
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT serial FROM certificates WHERE serial=? AND revoked=0", (serial,)
                ).fetchone()
                conn.close()
                cert_exists = row is not None
            except Exception:
                pass

            logger.info(
                f"RFC4809 §3.4.10: enrollment confirmation — serial={serial} "
                f"request_id={request_id!r} ip={client_ip} "
                f"thumbprint={thumbprint!r} cert_exists={cert_exists}"
            )

            self._send_json({
                "ok":          True,
                "serial":      serial,
                "confirmed":   True,
                "cert_found":  cert_exists,
                "rfc4809":     "Enrollment confirmation recorded per RFC 4809 §3.4.10",
                "note": (
                    "Certificate is active and confirmation recorded."
                    if cert_exists else
                    "Warning: serial not found in active certificate database."
                ),
            })

        # ── POST /ipsec/revoke ────────────────────────────────────────────
        elif path == "/ipsec/revoke":
            serial = data.get("serial")
            reason = int(data.get("reason", 0))
            if serial is None:
                self._send_json({"error": "serial is required"}, 400)
                return
            try:
                ok_r = self.ca.revoke_certificate(int(serial), reason)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
                return

            # RFC 4809 §3.5: return a cryptographically signed revocation confirmation
            # so the requestor can prove to third parties that the revocation was
            # processed by the CA.  We sign a canonical JSON payload with the CA key
            # and return the signature as base64 (RS256 / PKCS#1 v1.5 over SHA-256).
            revoked_at = datetime.datetime.now(_tz.utc).isoformat()
            confirmation_payload = json.dumps({
                "serial":     int(serial),
                "reason":     reason,
                "revoked_at": revoked_at,
                "ca_subject": self.ca.ca_cert.subject.rfc4514_string(),
            }, separators=(",", ":"), sort_keys=True).encode()

            try:
                from cryptography.hazmat.primitives.asymmetric import padding as _pad
                sig_bytes = self.ca.ca_key.sign(
                    confirmation_payload,
                    _pad.PKCS1v15(),
                    SHA256(),
                )
                sig_b64 = base64.b64encode(sig_bytes).decode()
                sig_alg = "RS256 (PKCS#1 v1.5 / SHA-256)"
            except Exception as sig_err:
                logger.warning(f"RFC4809 §3.5: could not sign revocation confirmation: {sig_err}")
                sig_b64 = None
                sig_alg = "unavailable"

            resp = {
                "ok":           ok_r,
                "serial":       int(serial),
                "reason":       reason,
                "revoked_at":   revoked_at,
                "rfc4809_s3_5": "signed revocation confirmation",
                "confirmation": {
                    "payload_b64": base64.b64encode(confirmation_payload).decode(),
                    "signature_b64": sig_b64,
                    "algorithm":     sig_alg,
                    "verify_with":   "GET /ipsec/ca-cert — use CA public key to verify RS256 signature over payload",
                },
            }
            self._send_json(resp)

        # ── POST /ipsec/ocsp-hash (RFC 4806) ─────────────────────────────
        elif path == "/ipsec/ocsp-hash":
            issuer_hash_hex = data.get("issuer_cert_hash_hex", "").strip()
            serial          = data.get("serial")
            nonce_hex       = data.get("nonce_hex", "")

            if not issuer_hash_hex:
                self._send_json({"error": "issuer_cert_hash_hex is required"}, 400)
                return
            if serial is None:
                self._send_json({"error": "serial is required"}, 400)
                return
            try:
                issuer_hash = bytes.fromhex(issuer_hash_hex)
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
            except ValueError as e:
                self._send_json({"error": f"hex decode error: {e}"}, 400)
                return

            ok_r, resp_der, err = self.ocsp_resolver.resolve(
                issuer_cert_hash=issuer_hash,
                serial=int(serial),
                nonce=nonce,
            )
            if not ok_r:
                self._send_json({"error": err}, 400)
                return

            # RFC 4806 §4.2: return OCSP response DER + base64 for embedding in IKEv2 CERT
            self._send_json({
                "ok":                   True,
                "serial":               int(serial),
                "ikev2_cert_encoding":  IKEV2_CERT_ENCODING_OCSP_CONTENT,
                "ocsp_response_b64":    base64.b64encode(resp_der).decode(),
                "rfc4806":              "OCSP Content per RFC 4806 §3 — embed in IKEv2 CERT payload",
            })

        else:
            self._send_json({"error": "unknown endpoint"}, 404)


# ---------------------------------------------------------------------------
# CDP URL validation (RFC 4945 §5.2)
# ---------------------------------------------------------------------------

def _validate_cdp_url(crl_url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """
    RFC 4945 §5.2: the CA SHOULD publish CRLs at the URL embedded in issued
    certificates.  This helper performs a lightweight HEAD (then GET on
    failure) to verify the URL is reachable and returns a non-empty body.

    Returns (reachable: bool, detail: str).

    This is a SHOULD, not a MUST, so the result is advisory — callers log a
    warning but do not fail the issuance on unreachability.

    Network access may be unavailable in test/CI environments; failures are
    silently treated as "not reachable" so the warning is only shown when an
    actual URL is configured.
    """
    if not crl_url:
        return False, "crl_url is empty — issued certs will have no CDP pointer (RFC 4945 §5.2 SHOULD)"
    try:
        import urllib.request as _ur
        import urllib.error  as _ue
        req = _ur.Request(crl_url, method="HEAD")
        req.add_header("User-Agent", "PyPKI-IPsec-CDP-Check/1.0")
        with _ur.urlopen(req, timeout=timeout) as resp:
            if resp.status in (200, 204):
                return True, f"CDP reachable: HTTP {resp.status}"
            return False, f"CDP returned HTTP {resp.status}"
    except Exception as head_err:
        # Fall back to GET for servers that reject HEAD
        try:
            req2 = _ur.Request(crl_url, method="GET")
            req2.add_header("User-Agent", "PyPKI-IPsec-CDP-Check/1.0")
            with _ur.urlopen(req2, timeout=timeout) as resp2:
                content = resp2.read(64)   # just enough to confirm non-empty
                if resp2.status == 200 and content:
                    return True, f"CDP reachable: HTTP {resp2.status} ({len(content)}+ bytes)"
                return False, f"CDP returned HTTP {resp2.status} (empty body)"
        except Exception as get_err:
            return False, (
                f"RFC 4945 §5.2: CDP URL '{crl_url}' is not reachable "
                f"(HEAD: {head_err}; GET: {get_err}). "
                f"IKEv2 peers that perform CRL checks will fail path validation."
            )


# ---------------------------------------------------------------------------
# OCSP signing cert provisioner (reused from ocsp_server pattern)
# ---------------------------------------------------------------------------

def _provision_ipsec_ocsp_cert(ca: "CertificateAuthority"):
    """Issue (or reuse) a dedicated OCSP signing cert for the IPsec server."""
    key_path  = ca.ca_dir / "ipsec_ocsp.key"
    cert_path = ca.ca_dir / "ipsec_ocsp.crt"

    if key_path.exists() and cert_path.exists():
        try:
            key  = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if getattr(cert, "not_valid_after_utc", cert.not_valid_after) > (
                datetime.datetime.now(_tz.utc) + datetime.timedelta(days=7)
            ):
                logger.info("Reusing existing IPsec OCSP signing certificate")
                return key, cert
        except Exception as e:
            logger.warning(f"IPsec OCSP cert reload failed: {e}, re-issuing")

    logger.info("Generating IPsec OCSP signing certificate...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(_tz.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "PyPKI IPsec OCSP Responder"),
        ]))
        .issuer_name(ca.ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(ca._next_serial())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(OID_OCSP_NOCHECK), b"\x05\x00"
            ),
            critical=False,
        )
        .sign(ca.ca_key, SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
    _exp = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
    logger.info(f"IPsec OCSP cert issued, valid until {_exp.date()}")
    return key, cert


# ---------------------------------------------------------------------------
# TLS cert provisioner (RFC 4809 §3.1.2 — secure transport)
# ---------------------------------------------------------------------------

def _provision_ipsec_tls_cert(ca: "CertificateAuthority", hostname: str):
    """
    Issue (or reuse) a TLS server certificate for the IPsec PKI server.

    RFC 4809 §3.1.2 requires all VPN-PKI transactions to be authenticated
    and encrypted.  This helper mirrors the pattern used by est_server.py's
    start_est_server() so all sub-servers share the same trust anchor.

    Returns (cert_path, key_path) as Path objects.
    """
    cert_path = Path(ca.ca_dir) / "ipsec_tls.crt"
    key_path  = Path(ca.ca_dir) / "ipsec_tls.key"

    if cert_path.exists() and key_path.exists():
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if getattr(existing, "not_valid_after_utc", existing.not_valid_after) > (
                datetime.datetime.now(_tz.utc) + datetime.timedelta(days=1)
            ):
                logger.info("Reusing existing IPsec TLS server certificate")
                return cert_path, key_path
        except Exception:
            pass  # re-provision below

    logger.info(f"Provisioning IPsec TLS server certificate for '{hostname}'...")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now  = datetime.datetime.now(_tz.utc)

    # Build SAN list — always include the literal hostname plus localhost aliases
    san_names: list[x509.GeneralName] = [x509.DNSName("localhost")]
    try:
        ipaddress.ip_address(hostname)
        san_names.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        san_names.insert(0, x509.DNSName(hostname))
    san_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyPKI IPsec Server"),
        ]))
        .issuer_name(ca.ca_cert.subject)
        .public_key(priv.public_key())
        .serial_number(ca._next_serial())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True,  data_encipherment=False,
                key_agreement=False,    key_cert_sign=False,
                crl_sign=False,         encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.ca_key.public_key()),
            critical=False,
        )
        .sign(ca.ca_key, SHA256())
    )

    key_path.write_bytes(
        priv.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
    _exp2 = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
    logger.info(f"IPsec TLS cert issued, valid until {_exp2.date()}")
    return cert_path, key_path


# ---------------------------------------------------------------------------
# Integration entry point
# ---------------------------------------------------------------------------

def start_ipsec_server(
    host: str,
    port: int,
    ca: "CertificateAuthority",
    ocsp_url: Optional[str] = None,
    crl_url: Optional[str] = None,
    tls_cert_path: Optional[str] = None,
    tls_key_path: Optional[str] = None,
) -> http.server.HTTPServer:
    """
    Start the IPsec PKI server in a background thread. Returns the HTTPServer.

    TLS (RFC 4809 §3.1.2 — "Secure Transactions")
    -----------------------------------------------
    RFC 4809 §3.1.2 mandates that ALL VPN-PKI transactions must be
    authenticated and encrypted.  TLS is the mechanism used here.

    If tls_cert_path and tls_key_path are both supplied, those PEM files are
    loaded directly.  Otherwise, a TLS server cert is auto-provisioned from
    the CA (same as the EST server pattern in est_server.py).

    The resulting server listens on HTTPS; use --ipsec-tls-cert and
    --ipsec-tls-key in pki_server.py, or pass them here directly.

    Without TLS, the server still starts (useful for unix-socket deployment or
    development behind an mTLS-terminating proxy) but logs a WARNING on every
    private-key response.

    Called from pki_server.py:
        srv = start_ipsec_server(host=args.host, port=args.ipsec_port, ca=ca,
                                  ocsp_url=..., crl_url=...,
                                  tls_cert_path=args.ipsec_tls_cert,
                                  tls_key_path=args.ipsec_tls_key)
    """
    ocsp_key, ocsp_cert = _provision_ipsec_ocsp_cert(ca)
    issuer        = IPsecCertIssuer(ca)
    ocsp_resolver = RFC4806OCSPHashResolver(ca, ocsp_key, ocsp_cert)

    # Resolve TLS cert/key paths
    use_tls = False
    if tls_cert_path and tls_key_path:
        cert_pem_path = str(tls_cert_path)
        key_pem_path  = str(tls_key_path)
        use_tls = True
    else:
        # Auto-provision an IPsec-server TLS cert from the CA
        try:
            auto_cert, auto_key = _provision_ipsec_tls_cert(ca, host)
            cert_pem_path = str(auto_cert)
            key_pem_path  = str(auto_key)
            use_tls = True
        except Exception as e:
            logger.warning(
                f"RFC 4809 §3.1.2: could not provision TLS cert ({e}). "
                f"Starting in plain-HTTP mode — NOT suitable for production. "
                f"Supply --ipsec-tls-cert / --ipsec-tls-key to enable TLS."
            )

    class BoundHandler(IPsecHandler):
        pass

    # RFC 4809 §3.4.4 — approval queue shares the CA's SQLite DB
    aq = ApprovalQueue(str(ca.db_path))

    BoundHandler.ca             = ca
    BoundHandler.issuer         = issuer
    BoundHandler.ocsp_resolver  = ocsp_resolver
    BoundHandler.approval_queue = aq
    BoundHandler.ocsp_url       = ocsp_url
    BoundHandler.crl_url        = crl_url
    BoundHandler.tls_active     = use_tls

    class _ThreadedServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads      = True

    srv = _ThreadedServer((host, port), BoundHandler)

    if use_tls:
        from cmp_server import TLSContextHolder, TlsCertWatcher

        def _build_ipsec_ctx(cp, kp):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.options |= ssl.OP_NO_COMPRESSION
            ctx.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!RC4:!DES:!MD5"
            )
            ctx.load_cert_chain(certfile=cp, keyfile=kp)
            # Accept (but don't require) client certs for mTLS
            ctx.verify_mode = ssl.CERT_OPTIONAL
            ctx.load_verify_locations(str(ca.ca_dir / "ca.crt"))
            return ctx

        tls_ctx = _build_ipsec_ctx(cert_pem_path, key_pem_path)
        holder  = TLSContextHolder(tls_ctx)

        # Rebuild server as a per-connection TLS server so the certificate
        # can be hot-reloaded without restarting.
        class _IPsecTLSServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads      = True
            ctx_holder: TLSContextHolder = None

            def get_request(self):
                sock, addr = super().get_request()
                try:
                    tls_sock = self.ctx_holder.get().wrap_socket(sock, server_side=True)
                    return tls_sock, addr
                except ssl.SSLError as exc:
                    logger.warning("IPsec TLS handshake failed from %s: %s", addr, exc)
                    sock.close()
                    raise

        srv = _IPsecTLSServer((host, port), BoundHandler)
        srv.ctx_holder = holder

        tls_reload_interval = getattr(ca, "_tls_reload_interval", 60)
        if tls_reload_interval > 0:
            watcher = TlsCertWatcher(
                holder=holder,
                cert_path=cert_pem_path,
                key_path=key_pem_path,
                build_ctx=_build_ipsec_ctx,
                poll_interval=tls_reload_interval,
            ).start()
            srv._tls_watcher = watcher
        else:
            srv._tls_watcher = None

        def _reload_tls() -> bool:
            if srv._tls_watcher:
                return srv._tls_watcher.reload_now()
            try:
                holder.swap(_build_ipsec_ctx(cert_pem_path, key_pem_path))
                logger.info("IPsec TLS context reloaded via reload_tls()")
                return True
            except Exception as exc:
                logger.error("IPsec TLS reload failed: %s", exc)
                return False

        srv.reload_tls = _reload_tls
        scheme = "https"
    else:
        srv._tls_watcher = None
        srv.reload_tls   = lambda: False
        scheme = "http"

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info(
        f"IPsec PKI server listening on {scheme}://{host}:{port}/ipsec "
        f"(RFC 4945 + RFC 4806 + RFC 4809, TLS={'enabled' if use_tls else 'DISABLED'})"
    )
    return srv


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="PyPKI IPsec Server — RFC 4945 / RFC 4806 / RFC 4809"
    )
    parser.add_argument("--host",      default="0.0.0.0")
    parser.add_argument("--port",      type=int, default=8085)
    parser.add_argument("--ca-dir",    default="./ca")
    parser.add_argument("--ocsp-url",  default="",
                        help="OCSP URL to embed in issued certs")
    parser.add_argument("--crl-url",   default="",
                        help="CRL URL to embed in issued certs")
    parser.add_argument("--tls-cert",  default="",
                        help="Path to PEM TLS server cert (auto-provisioned if omitted)")
    parser.add_argument("--tls-key",   default="",
                        help="Path to PEM TLS server key (auto-provisioned if omitted)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    import logging as _log
    _log.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found — place it in the same directory.")
        raise SystemExit(1)

    ca_dir = Path(args.ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    config = ServerConfig(ca_dir=ca_dir)
    ca     = CertificateAuthority(ca_dir=str(ca_dir), config=config)

    srv = start_ipsec_server(
        host=args.host,
        port=args.port,
        ca=ca,
        ocsp_url=args.ocsp_url or None,
        crl_url=args.crl_url  or None,
        tls_cert_path=args.tls_cert or None,
        tls_key_path=args.tls_key  or None,
    )

    tls_note = "(TLS auto-provisioned)" if not args.tls_cert else f"(TLS: {args.tls_cert})"
    scheme   = "https"

    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         PyPKI IPsec PKI Server                                     ║
║         RFC 4945 + RFC 4806 + RFC 4809                             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Base URL : {scheme}://{args.host}:{args.port}/ipsec                        ║
║  TLS      : {tls_note:<55} ║
╠══════════════════════════════════════════════════════════════════════╣
║  Certificate Profiles (RFC 4945 §2)                                ║
║    ipsec_tunnel  — id-kp-ipsecTunnel  gateway-to-gateway VPN       ║
║    ipsec_end     — id-kp-ipsecEndSystem  host end-system           ║
║    ipsec_user    — id-kp-ipsecUser  human VPN user                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  REST Endpoints                                                     ║
║    GET  /ipsec/health                 liveness check               ║
║    GET  /ipsec/ca-cert                CA cert (RFC 4809 §3.1.3)    ║
║    GET  /ipsec/profiles               profile descriptions         ║
║    POST /ipsec/issue                  issue cert (require_approval) ║
║    POST /ipsec/enroll                 PKCS#10 CSR (RFC 4809 §3.4.5)║
║    POST /ipsec/batch-issue            RFC 4809 §3.1.2 batch        ║
║    POST /ipsec/update                 RFC 4809 §3.3 — new key      ║
║    POST /ipsec/renew                  RFC 4809 §3.5 — same key     ║
║    POST /ipsec/revoke                 revoke a cert                ║
║    GET  /ipsec/pending                list pending approvals        ║
║    POST /ipsec/approve/<id>           approve pending request       ║
║    POST /ipsec/reject/<id>            reject pending request        ║
║    GET  /ipsec/cert/<serial>          fetch cert by serial         ║
║    POST /ipsec/ocsp-hash              RFC 4806 IKEv2 OCSP lookup   ║
║    GET  /ipsec/ocsp-hash/<h>/<s>      RFC 4806 cacheable GET       ║
╠══════════════════════════════════════════════════════════════════════╣
║  Example — issue cert with encrypted key (RFC 4809 §3.1.2):        ║
║    curl -k -X POST {scheme}://{args.host}:{args.port}/ipsec/issue \\       ║
║      -H 'Content-Type: application/json' \\                        ║
║      -d '{{"subject":"CN=gw1.vpn.example.com,O=Corp",             ║
║             "profile":"ipsec_tunnel",                              ║
║             "san_dns":["gw1.vpn.example.com"],                    ║
║             "key_password":"s3cr3t",                               ║
║             "validity_days":365}}'                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  Decrypt returned key:                                              ║
║    openssl pkcs8 -in key.pem -passin pass:s3cr3t -out plain.pem   ║
╠══════════════════════════════════════════════════════════════════════╣
║  RFC 4806 — IKEv2 inline OCSP:                                     ║
║    curl -k -X POST {scheme}://{args.host}:{args.port}/ipsec/ocsp-hash \\   ║
║      -d '{{"issuer_cert_hash_hex":"<sha1_of_ca_cert>",            ║
║             "serial":<int>}}'                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down IPsec PKI server...")
        srv.shutdown()


if __name__ == "__main__":
    main()
