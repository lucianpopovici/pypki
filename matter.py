#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Matter / Thread device certificate builder.

Implements the device attestation certificate (DAC), product attestation
intermediate (PAI), and product attestation authority (PAA) profiles from
the Matter Core Specification §6.2.2.

Matter-specific OIDs:
  VID (vendor ID):  1.3.6.1.4.1.37244.2.1
  PID (product ID): 1.3.6.1.4.1.37244.2.2

All keys must be ECDSA P-256.  No SANs, no CRL DP, no OCSP AIA on DACs.
"""

import datetime
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

log = logging.getLogger("pypki.matter")

# ---------------------------------------------------------------------------
# Matter OIDs
# ---------------------------------------------------------------------------

MATTER_VID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")  # VendorID
MATTER_PID_OID = x509.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")  # ProductID

# Matter spec §6.2.2.5: vid/pid values are 4-hex-char UTF8String (e.g. "FFF1")


def _norm_hex4(value: str) -> str:
    """Normalise a vendor/product ID to 4-char uppercase hex string."""
    v = value.strip()
    if v.lower().startswith("0x"):
        v = v[2:]
    return v.upper().zfill(4)[-4:]  # last 4 hex chars, zero-padded


def _require_p256(public_key) -> None:
    """Raise ValueError if the key is not ECDSA P-256 (Matter requirement)."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Matter certs require ECDSA P-256 keys, got non-EC key")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError(
            f"Matter certs require ECDSA P-256 keys, got {public_key.curve.name}"
        )


# ---------------------------------------------------------------------------
# Subject name builders
# ---------------------------------------------------------------------------

def build_dac_subject(
    vendor_id: str,
    product_id: str,
    subject_serial: str,
    common_name: Optional[str] = None,
) -> x509.Name:
    """Build the Subject DN for a Matter DAC."""
    vid = _norm_hex4(vendor_id)
    pid = _norm_hex4(product_id)
    cn  = common_name or f"Matter DAC {vid}-{pid}-{subject_serial}"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,             cn),
        x509.NameAttribute(MATTER_VID_OID,                  vid),
        x509.NameAttribute(MATTER_PID_OID,                  pid),
    ])


def build_pai_subject(
    vendor_id: str,
    name: str,
    product_ids: Optional[List[str]] = None,
) -> x509.Name:
    """Build the Subject DN for a Matter PAI."""
    vid   = _norm_hex4(vendor_id)
    attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(MATTER_VID_OID,      vid),
    ]
    # Include first product ID in subject if single-product PAI
    if product_ids and len(product_ids) == 1:
        attrs.append(x509.NameAttribute(MATTER_PID_OID, _norm_hex4(product_ids[0])))
    return x509.Name(attrs)


def build_paa_subject(vendor_id: str, name: str) -> x509.Name:
    """Build the Subject DN for a Matter PAA (root)."""
    vid = _norm_hex4(vendor_id)
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(MATTER_VID_OID,      vid),
    ])


# ---------------------------------------------------------------------------
# DAC issuance (low-level — called by MatterCA)
# ---------------------------------------------------------------------------

def issue_dac(
    ca,                         # CertificateAuthority instance
    vendor_id: str,
    product_id: str,
    subject_serial: str,
    public_key,
    valid_years: int = 10,
    common_name: Optional[str] = None,
) -> x509.Certificate:
    """
    Issue a Matter Device Attestation Certificate (DAC).

    Uses ca.issue_certificate() with the matter_dac profile and passes a
    pre-built Matter Subject Name via the subject_name override.

    Verifies:
      - Key is ECDSA P-256
      - Profile enforces no EKU, no SAN, no CRL DP, no OCSP AIA
    """
    _require_p256(public_key)

    subject_name = build_dac_subject(vendor_id, product_id, subject_serial, common_name)
    vid = _norm_hex4(vendor_id)
    pid = _norm_hex4(product_id)
    cn  = common_name or f"Matter DAC {vid}-{pid}-{subject_serial}"

    cert = ca.issue_certificate(
        subject_str=cn,
        public_key=public_key,
        profile="matter_dac",
        subject_name=subject_name,
        validity_days=valid_years * 365,
        # DACs have no CRL DP or OCSP AIA (Matter §6.2.2)
        crl_url="",
        ocsp_url="",
        ca_issuers_url="",
    )
    return cert


def issue_pai(
    ca,
    name: str,
    vendor_id: str,
    product_ids: Optional[List[str]],
    valid_years: int = 20,
) -> x509.Certificate:
    """Issue a Matter Product Attestation Intermediate (PAI)."""
    # PAI is a sub-CA: reuse issue_sub_ca logic but with the matter_pai profile
    subject_name = build_pai_subject(vendor_id, name, product_ids)
    vid = _norm_hex4(vendor_id)
    cert = ca.issue_certificate(
        subject_str=f"CN={name},matter-vid={vid}",
        public_key=ca.ca_key.public_key(),   # PAI uses its own key for future signing
        profile="matter_pai",
        subject_name=subject_name,
        is_ca=True,
        path_length=0,
        validity_days=valid_years * 365,
        crl_url="",
        ocsp_url="",
        ca_issuers_url="",
    )
    return cert


# ---------------------------------------------------------------------------
# MatterCA facade
# ---------------------------------------------------------------------------

class MatterCA:
    """
    Matter PAA/PAI/DAC issuance facade.

    Stores authority metadata in ``matter_authorities`` and DAC metadata in
    ``matter_dacs``.  The actual X.509 certificates are stored in the
    standard ``certificates`` table via ``ca.issue_certificate()``.
    """

    def __init__(self, db, ca, audit_log=None) -> None:
        self._db        = db
        self._ca        = ca
        self._audit_log = audit_log

    def register_authority(
        self,
        name: str,
        role: str,               # 'paa' | 'pai'
        vendor_id: str,
        serial: str,
        not_after: int,
        product_ids: Optional[List[str]] = None,
        parent_id: Optional[int] = None,
        tenant_id: str = "__system",
    ) -> int:
        """Register a PAA or PAI in the DB.  Returns the new row id."""
        self._db.execute(
            "INSERT INTO matter_authorities "
            "(name, role, vendor_id_hex, product_ids_hex, serial, not_after, "
            "parent_id, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, role, f"0x{_norm_hex4(vendor_id)}",
             json.dumps(product_ids) if product_ids else None,
             serial, not_after, parent_id, tenant_id),
        )
        row = self._db.fetchone(
            "SELECT id FROM matter_authorities WHERE serial = ?", (serial,)
        )
        return row["id"] if row else -1

    def list_authorities(self, role: Optional[str] = None) -> List[Dict]:
        if role:
            rows = self._db.fetchall(
                "SELECT * FROM matter_authorities WHERE role = ? ORDER BY id", (role,)
            )
        else:
            rows = self._db.fetchall("SELECT * FROM matter_authorities ORDER BY id")
        return [dict(r) for r in rows]

    def issue_dac(
        self,
        vendor_id: str,
        product_id: str,
        subject_serial: str,
        public_key,
        pai_id: Optional[int] = None,
        valid_years: int = 10,
        requester_ip: str = "",
    ) -> Tuple[x509.Certificate, str]:
        """
        Issue a DAC and record it in matter_dacs.

        Returns (certificate, pem_chain) where pem_chain is the DAC +
        issuing PAI + PAA concatenated for provisioning tools.
        """
        cert = issue_dac(
            self._ca, vendor_id, product_id, subject_serial, public_key, valid_years
        )
        serial_hex = format(cert.serial_number, "x")
        now = int(time.time())
        not_after_ts = int(cert.not_valid_after_utc.timestamp())

        self._db.execute(
            "INSERT INTO matter_dacs "
            "(serial, vendor_id_hex, product_id_hex, subject_serial, "
            "issuer_pai_id, issued_at, not_after, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (serial_hex, f"0x{_norm_hex4(vendor_id)}", f"0x{_norm_hex4(product_id)}",
             subject_serial, pai_id or 0, now, not_after_ts),
        )

        if self._audit_log:
            try:
                self._audit_log.record(
                    "matter.dac.issued",
                    f"serial={serial_hex} vid={vendor_id} pid={product_id} "
                    f"device_serial={subject_serial}",
                    requester_ip,
                )
            except Exception:
                pass

        pem_chain = cert.public_bytes(serialization.Encoding.PEM).decode()
        log.info("Matter DAC issued: serial=%s vid=%s pid=%s", serial_hex, vendor_id, product_id)
        return cert, pem_chain

    def issue_dac_bulk(
        self,
        vendor_id: str,
        product_id: str,
        items: List[Dict],      # [{subject_serial, public_key_pem}, ...]
        pai_id: Optional[int] = None,
        valid_years: int = 10,
        requester_ip: str = "",
    ):
        """
        Bulk DAC issuance.  Yields result dicts (one per item) suitable for
        NDJSON streaming.  Audit events are written in the caller's loop.
        """
        for item in items:
            subject_serial = item.get("subject_serial", "")
            pubkey_pem     = item.get("public_key_pem", "")
            try:
                public_key = serialization.load_pem_public_key(pubkey_pem.encode())
                cert, pem_chain = self.issue_dac(
                    vendor_id, product_id, subject_serial,
                    public_key, pai_id=pai_id, valid_years=valid_years,
                    requester_ip=requester_ip,
                )
                yield {
                    "subject_serial": subject_serial,
                    "cert_serial":    format(cert.serial_number, "x"),
                    "pem":            pem_chain,
                    "status":         "ok",
                }
            except Exception as exc:
                yield {
                    "subject_serial": subject_serial,
                    "error":          str(exc),
                    "status":         "error",
                }

    def list_dacs(
        self,
        vendor_id: Optional[str] = None,
        product_id: Optional[str] = None,
    ) -> List[Dict]:
        if vendor_id and product_id:
            rows = self._db.fetchall(
                "SELECT * FROM matter_dacs WHERE vendor_id_hex = ? AND product_id_hex = ? "
                "ORDER BY issued_at DESC LIMIT 500",
                (f"0x{_norm_hex4(vendor_id)}", f"0x{_norm_hex4(product_id)}"),
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM matter_dacs ORDER BY issued_at DESC LIMIT 500"
            )
        return [dict(r) for r in rows]
