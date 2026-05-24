#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
ACME Server — RFC 8555 (Automatic Certificate Management Environment)
======================================================================
Implements the ACME protocol for automated certificate issuance and renewal.
Designed to share the CertificateAuthority from pki_server.py.

Supported challenge types:
  - http-01  : Client places a token at /.well-known/acme-challenge/<token>
  - dns-01   : Client creates a TXT record at _acme-challenge.<domain>
               (validation is simulated/manual in this implementation)

RFC 9608 — No Revocation Available:
  Certificates with validity <= short_lived_threshold_days (default 7) automatically
  receive the id-ce-noRevAvail extension (OID 2.5.29.56, non-critical, NULL value) and
  have CDP and AIA-OCSP extensions suppressed, per RFC 9608 §4.
  Standard 90-day certs use the tls_server profile (with CDP/AIA if configured).

ACME flow (RFC 8555 §7):
  1. GET  /acme/directory          → directory URLs
  2. HEAD /acme/new-nonce          → fresh nonce (Replay-Nonce header)
  3. POST /acme/new-account        → create/find account (JWK + JWS)
  4. POST /acme/new-order          → request cert for identifier(s)
  5. POST /acme/order/<id>/auth    → fetch authorization details
  6. POST /acme/challenge/<id>     → trigger challenge validation
  7. POST /acme/order/<id>/finalize → submit CSR, get cert URL
  8. POST /acme/cert/<id>          → download issued certificate (PEM chain)

All POST bodies are JWS (JSON Web Signature) with JWK or KID headers.
Nonces are single-use and tracked server-side.

Dependencies (already required by pki_server.py):
    pip install cryptography

Usage:
    Standalone:
        python acme_server.py [--host 0.0.0.0] [--port 8888] [--ca-dir ./ca]

    Integrated (imported by pki_server.py via --acme-port):
        python pki_server.py --acme-port 8888
"""

import base64
import datetime
import hashlib
import http.server
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
from db import make_db, Database
import time
import traceback
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# §5.11 — histogram import (lazy to avoid circular import at module load)
def _get_hist_acme():
    from pki_server import _hist_acme_order  # noqa: PLC0415
    return _hist_acme_order

logger = logging.getLogger("acme")

# ---------------------------------------------------------------------------
# Helpers — Base64url (RFC 4648 §5, no padding)
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# RFC 8738 — IP identifier validation
# ---------------------------------------------------------------------------

def _validate_acme_identifier(
    ident: dict,
    *,
    allow_private_ip: bool = False,
) -> Tuple[bool, Optional[str]]:
    """
    Validate one element of a `new-order` ``identifiers`` array.

    Supports two identifier types:

      * ``dns`` — accepted as-is; downstream IDN handling lives in the CA.
      * ``ip``  — must parse via :func:`ipaddress.ip_address`. RFC 8738 §3
                  defines this identifier; clients submit the literal
                  textual form. Reserved, loopback, link-local, multicast,
                  unspecified, and private IPs are rejected by default
                  (RFC 8738 §6 — public CAs SHOULD refuse them); enable
                  ``allow_private_ip`` for homelab / internal use.

    Returns ``(ok, error_detail)``. ``error_detail`` is the ACME problem
    detail string when ``ok`` is False; ``None`` when ``ok`` is True.
    """
    itype = ident.get("type")
    value = ident.get("value", "")

    if itype == "dns":
        if not isinstance(value, str) or not value:
            return False, "dns identifier requires a non-empty 'value'"
        return True, None

    if itype == "ip":
        if not isinstance(value, str) or not value:
            return False, "ip identifier requires a non-empty 'value'"
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            return False, f"ip identifier {value!r} is not a valid IP: {exc}"
        if not allow_private_ip and (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False, (
                f"ip identifier {value!r} is private/reserved; enable "
                "--acme-allow-private-ip to permit it on this server"
            )
        return True, None

    return False, f"Unsupported identifier type: {itype!r}"


# RFC 8738 §4: only http-01 and tls-alpn-01 are valid for ip identifiers.
# dns-01 is explicitly excluded — there is no reverse-DNS challenge in this
# profile.
_ACME_CHALLENGE_TYPES_BY_IDENTIFIER = {
    "dns": ("http-01", "dns-01", "tls-alpn-01"),
    "ip":  ("http-01", "tls-alpn-01"),
}


# ---------------------------------------------------------------------------
# JWS / JWK utilities
# ---------------------------------------------------------------------------

class JWSError(Exception):
    pass


def jwk_thumbprint(jwk: dict) -> str:
    """
    Compute the RFC 7638 JWK thumbprint (SHA-256, base64url).
    Only includes required members in lexicographic order.
    """
    kty = jwk.get("kty", "")
    if kty == "RSA":
        required = {k: jwk[k] for k in ("e", "kty", "n")}
    elif kty == "EC":
        required = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    else:
        raise JWSError(f"Unsupported key type: {kty}")
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    return b64url_encode(hashlib.sha256(canonical).digest())


def jwk_to_public_key(jwk: dict):
    """Convert a JWK dict to a cryptography public key object."""
    kty = jwk.get("kty")
    if kty == "RSA":
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e, n).public_key()
    elif kty == "EC":
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers, SECP256R1, SECP384R1, SECP521R1
        )
        curves = {"P-256": SECP256R1(), "P-384": SECP384R1(), "P-521": SECP521R1()}
        crv = curves.get(jwk.get("crv", ""))
        if not crv:
            raise JWSError(f"Unsupported EC curve: {jwk.get('crv')}")
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return EllipticCurvePublicNumbers(x, y, crv).public_key()
    raise JWSError(f"Unsupported JWK kty: {kty}")


def verify_jws(body: bytes, stored_jwk: Optional[dict] = None) -> Tuple[dict, dict, dict]:
    """
    Parse and verify a JWS (Flattened JSON Serialization).
    Returns (header, payload_dict, jwk).

    If stored_jwk is provided, verifies against it (KID flow).
    Otherwise uses the embedded JWK (new-account flow).

    Raises JWSError on any verification failure.
    """
    try:
        jws = json.loads(body)
    except json.JSONDecodeError as e:
        raise JWSError(f"Invalid JSON: {e}")

    protected_b64 = jws.get("protected", "")
    payload_b64   = jws.get("payload", "")
    signature_b64 = jws.get("signature", "")

    if not all([protected_b64, signature_b64]):
        raise JWSError("Missing JWS fields")

    try:
        header = json.loads(b64url_decode(protected_b64))
    except Exception as e:
        raise JWSError(f"Bad protected header: {e}")

    # payload may be empty string for POST-as-GET
    if payload_b64:
        try:
            payload = json.loads(b64url_decode(payload_b64))
        except Exception as e:
            raise JWSError(f"Bad payload: {e}")
    else:
        payload = {}

    # Determine public key
    if stored_jwk:
        jwk = stored_jwk
    elif "jwk" in header:
        jwk = header["jwk"]
    else:
        raise JWSError("No JWK in header and no stored key")

    try:
        pub_key = jwk_to_public_key(jwk)
    except Exception as e:
        raise JWSError(f"Cannot load JWK: {e}")

    signing_input = f"{protected_b64}.{payload_b64}".encode()
    sig = b64url_decode(signature_b64)

    alg = header.get("alg", "")
    try:
        if alg.startswith("RS"):
            hash_map = {"RS256": SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
            h = hash_map.get(alg)
            if not h:
                raise JWSError(f"Unsupported RSA alg: {alg}")
            pub_key.verify(sig, signing_input, padding.PKCS1v15(), h)
        elif alg.startswith("ES"):
            from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
            hash_map = {"ES256": SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
            h = hash_map.get(alg)
            if not h:
                raise JWSError(f"Unsupported EC alg: {alg}")
            pub_key.verify(sig, signing_input, ECDSA(h))
        else:
            raise JWSError(f"Unsupported alg: {alg}")
    except Exception as e:
        raise JWSError(f"Signature verification failed: {e}")

    return header, payload, jwk


# ---------------------------------------------------------------------------
# ACME Database
# ---------------------------------------------------------------------------

class ACMEDatabase:
    """DAL-backed store for ACME accounts, orders, authorizations, challenges.

    Accepts a ``Database`` object so the backend is configurable — SQLite for
    single-node deployments, PostgreSQL for HA (§5.2).
    """

    def __init__(self, db):
        if isinstance(db, str):
            from db import make_db
            if not db.startswith(("sqlite:///", "postgresql://", "postgres://")):
                db = f"sqlite:///{db}"
            db = make_db(db)
        self._db = db
        self._init()

    def _init(self):
        for stmt in [
            """CREATE TABLE IF NOT EXISTS nonces (
                value TEXT PRIMARY KEY,
                created_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS accounts (
                kid         TEXT PRIMARY KEY,
                jwk_json    TEXT NOT NULL,
                thumbprint  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'valid',
                contact     TEXT,
                eab_kid     TEXT,
                created_at  REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS eab_keys (
                kid          TEXT PRIMARY KEY,
                mac_key_b64  TEXT NOT NULL,
                created_at   REAL NOT NULL,
                revoked_at   REAL
            )""",
            """CREATE TABLE IF NOT EXISTS orders (
                id          TEXT PRIMARY KEY,
                account_kid TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                identifiers TEXT NOT NULL,
                not_before  TEXT,
                not_after   TEXT,
                cert_id     TEXT,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS authorizations (
                id          TEXT PRIMARY KEY,
                order_id    TEXT NOT NULL,
                identifier  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS challenges (
                id          TEXT PRIMARY KEY,
                auth_id     TEXT NOT NULL,
                type        TEXT NOT NULL,
                token       TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                validated_at REAL,
                error       TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS certificates (
                id          TEXT PRIMARY KEY,
                order_id    TEXT NOT NULL,
                pem_chain   TEXT NOT NULL,
                serial      INTEGER,
                created_at  REAL NOT NULL
            )""",
        ]:
            self._db.execute(stmt)
        # §5.4 — add ra_request_id column to orders if absent (idempotent)
        try:
            self._db.execute("ALTER TABLE orders ADD COLUMN ra_request_id TEXT")
        except Exception:
            pass
        # RFC 8739 — STAR columns (idempotent)
        for _col, _dflt in [
            ("star_end_date",       "NULL"),
            ("star_lifetime",       "NULL"),
            ("star_allow_cert_get", "0"),
            ("star_active",         "0"),
        ]:
            try:
                self._db.execute(
                    f"ALTER TABLE orders ADD COLUMN {_col} INTEGER DEFAULT {_dflt}"
                )
            except Exception:
                pass

    # -- Nonces --

    def create_nonce(self) -> str:
        nonce = b64url_encode(os.urandom(16))
        self._db.execute("INSERT INTO nonces VALUES (?, ?)", (nonce, time.time()))
        return nonce

    def consume_nonce(self, nonce: str) -> bool:
        """Returns True if nonce was valid and is now consumed."""
        with self._db.advisory_lock("acme-nonce"):
            row = self._db.fetchone("SELECT value FROM nonces WHERE value=?", (nonce,))
            if not row:
                return False
            self._db.execute("DELETE FROM nonces WHERE value=?", (nonce,))
        return True

    def purge_old_nonces(self, max_age_secs: int = 3600):
        cutoff = time.time() - max_age_secs
        self._db.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))

    # -- Accounts --

    def create_or_find_account(self, jwk: dict, contact: Optional[list], eab_kid: Optional[str] = None) -> tuple:
        """Returns (is_new: bool, account: dict)."""
        thumb = jwk_thumbprint(jwk)
        kid = f"acct-{thumb[:16]}"
        with self._db.transaction():
            row = self._db.fetchone("SELECT * FROM accounts WHERE kid=?", (kid,))
            if row:
                return False, dict(row)
            self._db.execute(
                "INSERT INTO accounts VALUES (?,?,?,?,?,?,?)",
                (kid, json.dumps(jwk), thumb, "valid",
                 json.dumps(contact) if contact else None, eab_kid, time.time())
            )
            account = dict(self._db.fetchone("SELECT * FROM accounts WHERE kid=?", (kid,)))
        return True, account

    def get_account(self, kid: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM accounts WHERE kid=?", (kid,))
        return dict(row) if row else None

    def get_account_by_thumbprint(self, thumb: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM accounts WHERE thumbprint=?", (thumb,))
        return dict(row) if row else None

    def update_account_key(self, kid: str, new_jwk: dict, new_thumbprint: str):
        """Replace the JWK and thumbprint for an existing account (key rollover)."""
        self._db.execute(
            "UPDATE accounts SET jwk_json=?, thumbprint=? WHERE kid=?",
            (json.dumps(new_jwk), new_thumbprint, kid)
        )

    # -- EAB Keys --

    def add_eab_key(self, kid: str, mac_key_b64: str):
        self._db.execute(
            "INSERT OR REPLACE INTO eab_keys (kid, mac_key_b64, created_at) VALUES (?, ?, ?)",
            (kid, mac_key_b64, time.time())
        )

    def get_eab_key(self, kid: str) -> Optional[str]:
        row = self._db.fetchone(
            "SELECT mac_key_b64 FROM eab_keys WHERE kid=? AND revoked_at IS NULL", (kid,)
        )
        return row["mac_key_b64"] if row else None

    def mint_eab_key(self) -> tuple:
        """Generate a new EAB kid + 32-byte mac_key, store in DB, return (kid, mac_key_b64)."""
        import secrets
        kid = base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode()
        mac_key_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        self.add_eab_key(kid, mac_key_b64)
        return kid, mac_key_b64

    def list_eab_keys(self) -> list:
        """Return all EAB key records (newest first). mac_key_b64 is included for active keys only."""
        rows = self._db.fetchall(
            "SELECT kid, created_at, revoked_at FROM eab_keys ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows] if rows else []

    def revoke_eab_key(self, kid: str) -> bool:
        """Mark an EAB key as revoked. Returns True if the key existed."""
        row = self._db.fetchone("SELECT kid FROM eab_keys WHERE kid=?", (kid,))
        if not row:
            return False
        self._db.execute(
            "UPDATE eab_keys SET revoked_at=? WHERE kid=?", (time.time(), kid)
        )
        return True

    # -- Orders --

    def create_order(
        self,
        account_kid: str,
        identifiers: list,
        star_params: Optional[dict] = None,
    ) -> dict:
        order_id = b64url_encode(os.urandom(12))
        now = time.time()
        expires = now + 86400  # 24 hours

        star_end_date       = int(star_params["end_date"])       if star_params else None
        star_lifetime       = int(star_params["lifetime"])       if star_params else None
        star_allow_cert_get = 1 if star_params and star_params.get("allow_certificate_get") else 0

        # Create authorizations for each identifier. Challenge set varies
        # by identifier type per RFC 8738 §4: ip identifiers MUST NOT offer
        # dns-01 (there is no reverse-DNS variant of that challenge).
        with self._db.transaction():
            self._db.execute(
                "INSERT INTO orders (id,account_kid,status,identifiers,not_before,"
                "not_after,cert_id,created_at,expires_at,ra_request_id,"
                "star_end_date,star_lifetime,star_allow_cert_get,star_active)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (order_id, account_kid, "pending",
                 json.dumps(identifiers), None, None, None, now, expires, None,
                 star_end_date, star_lifetime, star_allow_cert_get, 0)
            )
            auth_ids = []
            for ident in identifiers:
                auth_id = b64url_encode(os.urandom(12))
                self._db.execute(
                    "INSERT INTO authorizations VALUES (?,?,?,?,?,?)",
                    (auth_id, order_id, json.dumps(ident), "pending", now, expires)
                )
                challenge_types = _ACME_CHALLENGE_TYPES_BY_IDENTIFIER.get(
                    ident.get("type"),
                    ("http-01", "dns-01", "tls-alpn-01"),
                )
                for ctype in challenge_types:
                    chall_id = b64url_encode(os.urandom(12))
                    token = b64url_encode(os.urandom(32))
                    self._db.execute(
                        "INSERT INTO challenges VALUES (?,?,?,?,?,?,?)",
                        (chall_id, auth_id, ctype, token, "pending", None, None)
                    )
                auth_ids.append(auth_id)
            order = dict(self._db.fetchone("SELECT * FROM orders WHERE id=?", (order_id,)))
        order["auth_ids"] = auth_ids
        return order

    def get_order(self, order_id: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM orders WHERE id=?", (order_id,))
        return dict(row) if row else None

    def update_order(self, order_id: str, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [order_id]
        self._db.execute(f"UPDATE orders SET {sets} WHERE id=?", vals)

    def get_order_authorizations(self, order_id: str) -> list:
        rows = self._db.fetchall(
            "SELECT * FROM authorizations WHERE order_id=?", (order_id,)
        )
        return [dict(r) for r in rows]

    # -- Authorizations --

    def get_authorization(self, auth_id: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM authorizations WHERE id=?", (auth_id,))
        return dict(row) if row else None

    def update_authorization(self, auth_id: str, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [auth_id]
        self._db.execute(f"UPDATE authorizations SET {sets} WHERE id=?", vals)

    # -- Challenges --

    def get_challenge(self, chall_id: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM challenges WHERE id=?", (chall_id,))
        return dict(row) if row else None

    def get_auth_challenges(self, auth_id: str) -> list:
        rows = self._db.fetchall("SELECT * FROM challenges WHERE auth_id=?", (auth_id,))
        return [dict(r) for r in rows]

    def update_challenge(self, chall_id: str, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [chall_id]
        self._db.execute(f"UPDATE challenges SET {sets} WHERE id=?", vals)

    # -- Certificates --

    def store_certificate(self, order_id: str, pem_chain: str, serial: int) -> str:
        cert_id = b64url_encode(os.urandom(12))
        self._db.execute(
            "INSERT INTO certificates VALUES (?,?,?,?,?)",
            (cert_id, order_id, pem_chain, serial, time.time())
        )
        return cert_id

    def get_certificate(self, cert_id: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM certificates WHERE id=?", (cert_id,))
        return dict(row) if row else None

    def update_certificate(self, cert_id: str, pem_chain: str, serial: int) -> None:
        """Replace the PEM chain and serial for an existing cert record (STAR renewal)."""
        self._db.execute(
            "UPDATE certificates SET pem_chain=?, serial=?, created_at=? WHERE id=?",
            (pem_chain, serial, time.time(), cert_id),
        )

    def list_active_star_orders(self) -> list:
        """Return orders with star_active=1 joined to their current certificate."""
        rows = self._db.fetchall(
            "SELECT o.*, c.id AS cert_rec_id, c.pem_chain AS cert_pem_chain, "
            "       c.created_at AS cert_issued_at "
            "FROM orders o JOIN certificates c ON c.order_id = o.id "
            "WHERE o.star_active = 1",
        )
        return [dict(r) for r in rows]

    def count_account_certs_since(self, account_kid: str, since_unix: float) -> int:
        """Return number of certificates issued for *account_kid* after *since_unix*."""
        row = self._db.fetchone(
            "SELECT COUNT(*) FROM certificates c "
            "JOIN orders o ON c.order_id = o.id "
            "WHERE o.account_kid = ? AND c.created_at > ?",
            (account_kid, since_unix),
        )
        return row[0] if row else 0


# ---------------------------------------------------------------------------
# Challenge Validator
# ---------------------------------------------------------------------------

class ChallengeValidator:
    """
    Validates ACME challenges.

    http-01: Performs a real HTTP fetch to /.well-known/acme-challenge/<token>
             and checks the key authorization response.

    dns-01:  In a real deployment this would query DNS TXT records. Here we
             provide a manual-approval mode (auto_approve=True skips DNS check,
             useful for testing/internal CAs).
    """

    def __init__(
        self,
        auto_approve_dns: bool = False,
        http_timeout: int = 10,
        tls_alpn01_enabled: bool = False,
        dns01_hook=None,
    ):
        self.auto_approve_dns = auto_approve_dns
        self.http_timeout = http_timeout
        self.tls_alpn01_enabled = tls_alpn01_enabled
        self.dns01_hook = dns01_hook  # callable(domain, token, key_auth) -> (bool, str)

    def key_authorization(self, token: str, jwk_thumbprint_str: str) -> str:
        return f"{token}.{jwk_thumbprint_str}"

    def validate_http01(self, domain: str, token: str, key_auth: str) -> Tuple[bool, str]:
        """Fetch /.well-known/acme-challenge/<token> and verify key authorization.

        RFC 8738 §4 — for ip identifiers the literal is used as the URL host.
        IPv6 literals must be bracketed per RFC 3986 §3.2.2; bare IPv6 in a URL
        would parse the colons as a port separator.
        """
        host = domain
        try:
            if isinstance(ipaddress.ip_address(domain), ipaddress.IPv6Address):
                host = f"[{domain}]"
        except ValueError:
            pass  # not an IP literal — keep the hostname as-is
        url = f"http://{host}/.well-known/acme-challenge/{token}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PyPKI-ACME/1.0"})
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                body = resp.read().decode().strip()
                if body == key_auth:
                    return True, "ok"
                return False, f"Expected '{key_auth}', got '{body}'"
        except urllib.error.URLError as e:
            return False, f"HTTP fetch failed: {e}"
        except Exception as e:
            return False, f"Validation error: {e}"

    def validate_tls_alpn01(self, domain: str, port: int, key_auth: str) -> Tuple[bool, str]:
        """
        Validate tls-alpn-01 challenge (RFC 8737).

        Opens a TLS connection to domain:443 (or port), requests ALPN "acme-tls/1",
        and checks that the server certificate contains the correct
        id-pe-acmeIdentifier extension with SHA-256(key_auth).
        """
        import socket, ssl as _ssl, hashlib

        expected_digest = hashlib.sha256(key_auth.encode()).digest()
        ACME_ID_OID = "1.3.6.1.5.5.7.1.31"

        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        ctx.set_alpn_protocols(["acme-tls/1"])

        try:
            raw_sock = socket.create_connection((domain, port), timeout=self.http_timeout)
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=domain)

            # Check ALPN negotiated
            negotiated = tls_sock.selected_alpn_protocol()
            if negotiated != "acme-tls/1":
                tls_sock.close()
                return False, f"Server did not negotiate acme-tls/1 (got {negotiated!r})"

            # Get the DER certificate
            cert_der = tls_sock.getpeercert(binary_form=True)
            tls_sock.close()

            if not cert_der:
                return False, "Server presented no certificate"

            # Parse and check the acmeIdentifier extension
            from cryptography import x509 as _x509
            cert = _x509.load_der_x509_certificate(cert_der)

            found = False
            for ext in cert.extensions:
                if ext.oid.dotted_string == ACME_ID_OID:
                    found = True
                    # Extension value is DER OCTET STRING wrapping the 32-byte digest
                    raw = ext.value.value  # raw DER bytes of the extension value
                    # Strip OCTET STRING tag+length (04 20) if present
                    digest_bytes = raw[2:] if raw[:2] == b" " else raw
                    if digest_bytes == expected_digest:
                        return True, "ok"
                    return False, (
                        f"acmeIdentifier digest mismatch: "
                        f"expected {expected_digest.hex()}, got {digest_bytes.hex()}"
                    )

            if not found:
                return False, "Certificate missing id-pe-acmeIdentifier extension"

            return False, "Validation failed"

        except Exception as e:
            return False, f"tls-alpn-01 connection error: {e}"

    def validate_dns01(self, domain: str, token: str, key_auth: str) -> Tuple[bool, str]:
        """
        Validate DNS-01 challenge.
        Expected TXT record: _acme-challenge.<domain> = base64url(sha256(key_auth))

        If a dns01_hook callable was provided at construction time it is called first
        and its result is used directly (production webhook / RFC 2136 mode).
        """
        if self.dns01_hook is not None:
            try:
                return self.dns01_hook(domain, token, key_auth)
            except Exception as e:
                return False, f"dns01_hook raised: {e}"

        if self.auto_approve_dns:
            logger.info(f"dns-01 auto-approved for {domain} (test mode)")
            return True, "auto-approved"

        expected_digest = b64url_encode(hashlib.sha256(key_auth.encode()).digest())
        txt_name = f"_acme-challenge.{domain}"

        try:
            import socket
            # Try to resolve TXT via a basic UDP DNS query
            # For production, use dnspython; here we do a best-effort lookup
            answers = self._lookup_txt(txt_name)
            if expected_digest in answers:
                return True, "ok"
            return False, f"TXT record not found. Expected {expected_digest} at {txt_name}"
        except Exception as e:
            return False, f"DNS lookup error: {e}"

    def _lookup_txt(self, name: str) -> list:
        """Very basic DNS TXT lookup using socket/UDP. Returns list of TXT strings."""
        import socket, struct

        def encode_name(n):
            parts = n.rstrip(".").split(".")
            out = b""
            for p in parts:
                encoded = p.encode()
                out += bytes([len(encoded)]) + encoded
            return out + b"\x00"

        query_id = os.urandom(2)
        flags = b"\x01\x00"  # standard query, recursion desired
        qdcount = b"\x00\x01"
        ancount = b"\x00\x00"
        nscount = b"\x00\x00"
        arcount = b"\x00\x00"
        qname = encode_name(name)
        qtype = b"\x00\x10"   # TXT
        qclass = b"\x00\x01"  # IN

        packet = query_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(packet, ("8.8.8.8", 53))
        resp, _ = sock.recvfrom(4096)
        sock.close()

        # Parse answer section (very simplified)
        results = []
        # Skip header (12 bytes) + question section
        pos = 12
        # Skip question
        while pos < len(resp) and resp[pos] != 0:
            pos += resp[pos] + 1
        pos += 5  # null + qtype + qclass

        an_count = struct.unpack(">H", resp[6:8])[0]
        for _ in range(an_count):
            # Skip name (may be compressed pointer)
            if resp[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(resp) and resp[pos] != 0:
                    pos += resp[pos] + 1
                pos += 1
            if pos + 10 > len(resp):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[pos:pos+10])
            pos += 10
            rdata = resp[pos:pos+rdlen]
            pos += rdlen
            if rtype == 16:  # TXT
                # TXT RDATA: length-prefixed strings
                txt_pos = 0
                txt_val = b""
                while txt_pos < len(rdata):
                    seg_len = rdata[txt_pos]
                    txt_val += rdata[txt_pos+1:txt_pos+1+seg_len]
                    txt_pos += 1 + seg_len
                results.append(txt_val.decode(errors="replace"))

        return results


# ---------------------------------------------------------------------------
# RFC 8739 — STAR background renewal worker
# ---------------------------------------------------------------------------

class STARRenewalWorker:
    """
    Background thread that re-issues STAR certificates before they expire.

    Wakes every *interval* seconds.  For each active STAR order it checks
    whether the current cert has passed the half-lifetime mark; if so it
    re-uses the same public key (extracted from the stored PEM chain) and
    issues a fresh short-lived cert, updating the certificate record in-place
    so that GET /acme/cert/<id> always returns the current cert.

    Orders whose ``star_end_date`` has passed are deactivated (status →
    invalid, star_active → 0).
    """

    def __init__(self, db: "ACMEDatabase", ca, interval: int = 60):
        self._db = db
        self._ca = ca
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="acme-star-renewer"
        )

    def start(self):
        self._thread.start()
        logger.info("ACME STAR renewal worker started (interval=%ds)", self._interval)

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self._interval):
            try:
                self._tick()
            except Exception as exc:
                logger.error("STAR renewal tick error: %s", exc)

    def _tick(self):
        now = time.time()
        for order in self._db.list_active_star_orders():
            end_date = order.get("star_end_date") or 0
            if end_date and end_date <= now:
                self._db.update_order(order["id"], star_active=0, status="invalid")
                logger.info("STAR order %s: past end-date, deactivated", order["id"])
                continue
            lifetime = order.get("star_lifetime") or 0
            if not lifetime:
                continue
            cert_issued_at = order.get("cert_issued_at") or 0
            renew_at = cert_issued_at + lifetime / 2
            if now < renew_at:
                continue
            try:
                self._renew(order)
            except Exception as exc:
                logger.error("STAR renewal failed for order %s: %s", order["id"], exc)

    def _renew(self, order: dict):
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives.serialization import Encoding as _Enc

        identifiers = json.loads(order["identifiers"])
        domains = [i["value"] for i in identifiers if i["type"] == "dns"]
        ips    = [i["value"] for i in identifiers if i["type"] == "ip"]
        primary = domains[0] if domains else (ips[0] if ips else "star-client")

        # Extract public key from the first PEM block in the stored chain
        current_pem = order.get("cert_pem_chain", "")
        end_marker = "-----END CERTIFICATE-----"
        first_block = current_pem[: current_pem.index(end_marker) + len(end_marker)]
        pub_key = _x509.load_pem_x509_certificate(first_block.encode()).public_key()

        validity_days = max(1, order["star_lifetime"] // 86400)
        new_cert = self._ca.issue_certificate(
            subject_str=f"CN={primary}",
            public_key=pub_key,
            san_dns=domains if domains else None,
            san_ips=ips if ips else None,
            validity_days=validity_days,
            profile="short_lived",
            protocol="acme",
        )
        pem_chain = (
            new_cert.public_bytes(_Enc.PEM).decode()
            + self._ca.ca_cert.public_bytes(_Enc.PEM).decode()
        )
        self._db.update_certificate(order["cert_rec_id"], pem_chain, new_cert.serial_number)
        logger.info(
            "STAR order %s: renewed cert serial=%s validity=%dd",
            order["id"], new_cert.serial_number, validity_days,
        )


# ---------------------------------------------------------------------------
# ACME HTTP Request Handler
# ---------------------------------------------------------------------------

class ACMEHandler(http.server.BaseHTTPRequestHandler):
    """
    RFC 8555 ACME HTTP handler.

    All ACME endpoints use application/jose+json bodies (JWS).
    GET /directory and HEAD /acme/new-nonce are unauthenticated.
    Everything else requires a valid JWS with a consumed nonce.
    """

    # Injected by the server factory
    db: ACMEDatabase = None
    ca = None             # CertificateAuthority instance
    ra = None             # RAWorkflow instance (§5.4); None = auto-issue without RA
    validator: ChallengeValidator = None
    base_url: str = ""    # e.g. "http://localhost:8888"
    cert_validity_days: int = 90        # validity for ACME-issued certs
    short_lived_threshold_days: int = 7 # certs valid <= this get noRevAvail (RFC 9608)
    allow_private_ip: bool = False      # RFC 8738: permit private/reserved IPs in ip identifiers
    require_eab: bool = False           # RFC 8555 §7.3.4: gate account creation behind EAB
    per_account_cert_limit: int = 0     # max certs per account per window (0 = unlimited)
    per_account_window_days: int = 7    # rolling window for per-account limit
    # RFC 8739 — STAR
    star_enabled: bool = False
    star_min_lifetime: int = 86400      # minimum cert lifetime in seconds (default 1 day)
    star_max_duration: int = 7776000    # maximum auto-renewal window in seconds (default 90 days)

    def log_message(self, format, *args):
        logger.info(f"ACME {self.address_string()} - {format % args}")

    def _verify_external_account_binding(self, eab: dict, account_jwk: dict) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify the RFC 8555 §7.3.4 External Account Binding JWS.
        Returns (ok, error_detail, kid).
        """
        try:
            # 1. Parse outer JWS (already done by verify_jws, but eab is the inner JWS)
            # The 'eab' field in new-account is itself a JWS in Flattened JSON Serialization.
            # It MUST use HS256 and be signed with the EAB MAC key.
            # Its payload MUST be the account's public key (JWK).
            protected_b64 = eab.get("protected", "")
            payload_b64   = eab.get("payload", "")
            signature_b64 = eab.get("signature", "")
            
            if not all([protected_b64, payload_b64, signature_b64]):
                return False, "Missing EAB JWS fields", None
            
            header = json.loads(b64url_decode(protected_b64))
            kid = header.get("kid")
            if not kid:
                return False, "EAB JWS missing 'kid' in protected header", None
            
            # 2. Lookup MAC key
            # Support class-level testing pattern where self may be None
            _db = self.db if self is not None else ACMEHandler.db
            mac_key_b64 = _db.get_eab_key(kid)
            if not mac_key_b64:
                return False, f"EAB kid '{kid}' not found or revoked", None
            
            mac_key = b64url_decode(mac_key_b64)
            
            # 3. Verify HS256 signature
            import hmac
            alg = header.get("alg")
            if alg != "HS256":
                return False, f"EAB JWS must use HS256 algorithm (got {alg})", None
                
            signing_input = f"{protected_b64}.{payload_b64}".encode()
            actual_sig = b64url_decode(signature_b64)
            
            expected_sig = hmac.new(mac_key, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(actual_sig, expected_sig):
                return False, "EAB JWS signature verification failed", None
                
            # 4. Verify payload matches account JWK
            payload = json.loads(b64url_decode(payload_b64))
            # RFC 8555 §7.3.4: "The payload of the JWS is the account's public key... in JWK format"
            if payload != account_jwk:
                return False, "EAB payload does not match account public key", None
                
            return True, None, kid
        except Exception as e:
            return False, f"EAB verification error: {e}", None

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_HEAD(self):
        if self.path == "/new-nonce":
            self._new_nonce_response(method="HEAD")
        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        try:
            self._do_GET_inner(path)
        except Exception as e:
            logger.error(f"ACME GET error on {path}: {e}\n{traceback.format_exc()}")
            try:
                self._send_error(500, "urn:ietf:params:acme:error:serverInternal", str(e))
            except Exception:
                pass

    def _do_GET_inner(self, path: str):
        if path in ("/directory", ""):
            self._handle_directory()
        elif path == "/new-nonce":
            self._new_nonce_response(method="GET")
        elif path == "/terms":
            # Serve a minimal Terms of Service page so certbot can fetch it
            body = b"Terms of Service: This is an internal CA. Use at your own risk."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/renewal-info" or path.startswith("/renewal-info/"):
            # draft-ietf-acme-ari — return 404 with proper JSON to signal not supported
            # certbot treats a 404 here as "no renewal info available" and continues
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Renewal information not available")

        # ------------------------------------------------------------------
        # Unauthenticated GET for order/authz/cert resources.
        # RFC 8555 §7.5 allows plain GET for resource polling. certbot uses
        # these after the initial POST-as-GET to check for status changes.
        # We return the resource without verifying account ownership, which
        # is acceptable for read-only status polling on non-sensitive data.
        # ------------------------------------------------------------------
        elif re.match(r"^/order/[^/]+$", path):
            order_id = path.split("/")[-1]
            order = self.db.get_order(order_id)
            if not order:
                self._send_error(404, "urn:ietf:params:acme:error:malformed", "Order not found")
                return
            self._refresh_order_status(order_id)
            order = self.db.get_order(order_id)
            order_url = f"{self.base_url}/order/{order_id}"
            self._send_json(self._order_response(order), 200,
                            headers={"Location": order_url}, add_nonce=True)

        elif re.match(r"^/authz/[^/]+$", path):
            auth_id = path.split("/")[-1]
            authz = self.db.get_authorization(auth_id)
            if not authz:
                self._send_error(404, "urn:ietf:params:acme:error:malformed",
                                 "Authorization not found")
                return
            # Build a lightweight account stub for _authz_response (only needs thumbprint)
            account_kid = self.db.get_order(authz["order_id"])
            if account_kid:
                account_rec = self.db.get_account(account_kid["account_kid"])
            else:
                account_rec = None
            if not account_rec:
                self._send_error(404, "urn:ietf:params:acme:error:malformed",
                                 "Authorization account not found")
                return
            self._send_json(self._authz_response(authz, account_rec), 200, add_nonce=True)

        elif re.match(r"^/cert/[^/]+$", path):
            cert_id = path.split("/")[-1]
            cert_rec = self.db.get_certificate(cert_id)
            if not cert_rec:
                self._send_error(404, "urn:ietf:params:acme:error:malformed",
                                 "Certificate not found")
                return
            pem_chain = cert_rec["pem_chain"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/pem-certificate-chain")
            self.send_header("Content-Length", str(len(pem_chain)))
            self.send_header("Replay-Nonce", self.db.create_nonce())
            self.end_headers()
            self.wfile.write(pem_chain)

        else:
            self._send_error(404, "urn:ietf:params:acme:error:malformed", "Not found")

    def do_POST(self):
        path = self.path.rstrip("/")
        try:
            if path == "/new-account":
                self._handle_new_account()
            elif path == "/new-order":
                self._handle_new_order()
            elif re.match(r"^/order/[^/]+$", path):
                self._handle_get_order(path.split("/")[-1])
            elif re.match(r"^/order/[^/]+/finalize$", path):
                order_id = path.split("/")[-2]
                self._handle_finalize(order_id)
            elif re.match(r"^/authz/[^/]+$", path):
                self._handle_get_authz(path.split("/")[-1])
            elif re.match(r"^/challenge/[^/]+/[^/]+$", path):
                parts = path.split("/")
                self._handle_challenge(parts[-2], parts[-1])
            elif re.match(r"^/cert/[^/]+$", path):
                self._handle_get_cert(path.split("/")[-1])
            elif path == "/revoke-cert":
                self._handle_revoke()
            elif path == "/key-change":
                self._handle_key_change()
            else:
                self._send_error(404, "urn:ietf:params:acme:error:malformed", "Unknown endpoint")
        except JWSError as e:
            logger.warning(f"JWS error on {path}: {e}")
            self._send_error(400, "urn:ietf:params:acme:error:malformed", str(e))
        except Exception as e:
            logger.error(f"ACME error on {path}: {e}\n{traceback.format_exc()}")
            self._send_error(500, "urn:ietf:params:acme:error:serverInternal", str(e))

    # ------------------------------------------------------------------
    # Directory
    # ------------------------------------------------------------------

    def _handle_directory(self):
        directory = {
            "newNonce":   f"{self.base_url}/new-nonce",
            "newAccount": f"{self.base_url}/new-account",
            "newOrder":   f"{self.base_url}/new-order",
            "revokeCert": f"{self.base_url}/revoke-cert",
            "keyChange":  f"{self.base_url}/key-change",
            # renewalInfo stub (draft-ietf-acme-ari) — certbot ≥2.8 checks for this
            # field and gracefully ignores it when not a full URL; include it so
            # certbot does not log a warning about a missing field.
            "renewalInfo": f"{self.base_url}/renewal-info",
            "meta": {
                "termsOfService": f"{self.base_url}/terms",
                "website":        f"{self.base_url}",
                "caaIdentities":  [],
                "externalAccountRequired": self.require_eab,
            },
        }
        # RFC 8739 §3.4.1 — advertise STAR capability in meta.autoRenewal
        if self.star_enabled:
            directory["meta"]["autoRenewal"] = {
                "minLifetime":          self.star_min_lifetime,
                "maxDuration":          self.star_max_duration,
                "allow-certificate-get": True,
            }
        # RFC 8555 §7.1.1 — directory response SHOULD include Replay-Nonce
        self._send_json(directory, 200, add_nonce=True)

    # ------------------------------------------------------------------
    # Nonce
    # ------------------------------------------------------------------

    def _new_nonce_response(self, method: str = "HEAD"):
        nonce = self.db.create_nonce()
        self.send_response(200)
        self.send_header("Replay-Nonce", nonce)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # ------------------------------------------------------------------
    # Account
    # ------------------------------------------------------------------

    def _handle_new_account(self):
        body = self._read_body()
        header, payload, jwk = verify_jws(body)

        # Validate nonce
        nonce = header.get("nonce", "")
        if not self.db.consume_nonce(nonce):
            self._send_error(400, "urn:ietf:params:acme:error:badNonce",
                             "Invalid or already-used nonce")
            return

        contact = payload.get("contact")
        tos_agreed = payload.get("termsOfServiceAgreed", False)
        eab_payload = payload.get("externalAccountBinding")
        eab_kid = None

        if self.require_eab:
            if not eab_payload:
                self._send_error(400, "urn:ietf:params:acme:error:externalAccountRequired",
                                 "External Account Binding is required")
                return
            
            ok, err, eab_kid = self._verify_external_account_binding(eab_payload, jwk)
            if not ok:
                self._send_error(400, "urn:ietf:params:acme:error:unauthorized",
                                 f"External Account Binding failed: {err}")
                return
        elif eab_payload:
            # Optional EAB verification if provided even if not strictly required
            ok, err, eab_kid = self._verify_external_account_binding(eab_payload, jwk)
            if not ok:
                self._send_error(400, "urn:ietf:params:acme:error:unauthorized",
                                 f"External Account Binding failed: {err}")
                return

        is_new, account = self.db.create_or_find_account(jwk, contact, eab_kid=eab_kid)
        kid_url = f"{self.base_url}/account/{account['kid']}"

        # RFC 8555 §7.3: onlyReturnExisting — return 400 if account doesn't exist
        if payload.get("onlyReturnExisting") and is_new:
            # We created a new account but caller said not to — roll it back
            # (In practice we shouldn't reach here since create_or_find returns
            #  existing; keep as a guard.)
            self._send_error(400, "urn:ietf:params:acme:error:accountDoesNotExist",
                             "Account does not exist and onlyReturnExisting is set")
            return

        resp = {
            "status": account["status"],
            "contact": json.loads(account["contact"]) if account.get("contact") else [],
            "orders": f"{self.base_url}/account/{account['kid']}/orders",
        }

        # RFC 8555 §7.3: 201 Created for new accounts, 200 OK for existing
        status_code = 201 if is_new else 200
        self._send_json(resp, status_code,
                        headers={"Location": kid_url},
                        add_nonce=True)

    # ------------------------------------------------------------------
    # Order
    # ------------------------------------------------------------------

    def _handle_new_order(self):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        identifiers = payload.get("identifiers", [])
        if not identifiers:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             "No identifiers provided")
            return

        # Validate identifier types. RFC 8555 §7.4 + RFC 8738 §3 — accept
        # `dns` and `ip`; everything else is unsupportedIdentifier. Private
        # / reserved IPs are gated by --acme-allow-private-ip.
        for ident in identifiers:
            ok, detail = _validate_acme_identifier(
                ident, allow_private_ip=self.allow_private_ip,
            )
            if not ok:
                err_type = (
                    "urn:ietf:params:acme:error:unsupportedIdentifier"
                    if ident.get("type") not in ("dns", "ip")
                    else "urn:ietf:params:acme:error:rejectedIdentifier"
                )
                self._send_error(400, err_type, detail)
                return

        # RFC 8739 — STAR auto-renewal
        star_params = None
        auto_renewal = payload.get("auto-renewal")
        if auto_renewal is not None:
            if not self.star_enabled:
                self._send_error(400, "urn:ietf:params:acme:error:unsupportedIdentifier",
                                 "STAR auto-renewal is not supported on this server")
                return
            # Validate end-date
            end_date_str = auto_renewal.get("end-date")
            if not end_date_str:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 "auto-renewal.end-date is required")
                return
            try:
                from datetime import datetime, timezone as _tz
                end_dt = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
                end_ts = end_dt.timestamp()
            except Exception:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 "auto-renewal.end-date must be ISO 8601")
                return
            now_ts = time.time()
            if end_ts <= now_ts:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 "auto-renewal.end-date must be in the future")
                return
            if end_ts - now_ts > self.star_max_duration:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 f"auto-renewal.end-date exceeds maxDuration of "
                                 f"{self.star_max_duration}s")
                return
            # Validate lifetime
            lifetime = auto_renewal.get("lifetime")
            if lifetime is None:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 "auto-renewal.lifetime is required")
                return
            try:
                lifetime = int(lifetime)
            except Exception:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 "auto-renewal.lifetime must be an integer (seconds)")
                return
            if lifetime < self.star_min_lifetime:
                self._send_error(400, "urn:ietf:params:acme:error:malformed",
                                 f"auto-renewal.lifetime must be >= minLifetime "
                                 f"({self.star_min_lifetime}s)")
                return
            star_params = {
                "end_date":              int(end_ts),
                "lifetime":              lifetime,
                "allow_certificate_get": bool(auto_renewal.get("allow-certificate-get", False)),
            }

        order = self.db.create_order(account["kid"], identifiers, star_params=star_params)
        order_url = f"{self.base_url}/order/{order['id']}"

        resp = self._order_response(order)
        self._send_json(resp, 201,
                        headers={"Location": order_url},
                        add_nonce=True)

    def _handle_get_order(self, order_id: str):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        order = self.db.get_order(order_id)
        if not order:
            self._send_error(404, "urn:ietf:params:acme:error:malformed", "Order not found")
            return

        # §5.4 — if order is in 'processing' state, check RA for approval
        if order.get("status") == "processing" and order.get("ra_request_id") and self.ra:
            ra_req = self.ra.get(order["ra_request_id"])
            if ra_req and ra_req["status"] == "issued":
                # Approved — issue certificate and move order to 'valid'
                cert_der = self.ra._db.fetchone(
                    "SELECT cert_der FROM pending_requests WHERE request_id=?",
                    (order["ra_request_id"],),
                )["cert_der"]
                from cryptography import x509 as _x509
                from cryptography.hazmat.primitives.serialization import Encoding as _Enc
                cert = _x509.load_der_x509_certificate(bytes(cert_der))
                cert_pem = cert.public_bytes(_Enc.PEM).decode()
                ca_pem = self.ca.ca_cert.public_bytes(_Enc.PEM).decode()
                pem_chain = cert_pem + ca_pem
                cert_id = self.db.store_certificate(order_id, pem_chain, cert.serial_number)
                self.db.update_order(order_id, status="valid", cert_id=cert_id)
                order = self.db.get_order(order_id)
            elif ra_req and ra_req["status"] == "denied":
                self.db.update_order(order_id, status="invalid")
                order = self.db.get_order(order_id)

        self._refresh_order_status(order_id)
        order = self.db.get_order(order_id)
        order_url = f"{self.base_url}/order/{order_id}"
        # RFC 8555 §7.4 — finalize response MUST include Location: <order-url>
        # certbot polls this URL to detect when status transitions to "valid"
        self._send_json(self._order_response(order), 200, add_nonce=True,
                        headers={"Location": order_url})

    def _order_response(self, order: dict) -> dict:
        auths = self.db.get_order_authorizations(order["id"])
        auth_urls = [f"{self.base_url}/authz/{a['id']}" for a in auths]
        resp = {
            "status": order["status"],
            "expires": self._ts(order["expires_at"]),
            "identifiers": json.loads(order["identifiers"]),
            "authorizations": auth_urls,
            "finalize": f"{self.base_url}/order/{order['id']}/finalize",
        }
        if order.get("cert_id"):
            resp["certificate"] = f"{self.base_url}/cert/{order['cert_id']}"
        # RFC 8739 — echo auto-renewal fields when this is a STAR order
        if order.get("star_lifetime"):
            from datetime import datetime, timezone as _tz
            resp["auto-renewal"] = {
                "end-date":               datetime.fromtimestamp(
                    order["star_end_date"], tz=_tz.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lifetime":               order["star_lifetime"],
                "allow-certificate-get":  bool(order.get("star_allow_cert_get")),
            }
        return resp

    def _refresh_order_status(self, order_id: str):
        """Recompute order status from its authorizations."""
        auths = self.db.get_order_authorizations(order_id)
        statuses = [a["status"] for a in auths]
        if any(s == "invalid" for s in statuses):
            self.db.update_order(order_id, status="invalid")
        elif all(s == "valid" for s in statuses):
            order = self.db.get_order(order_id)
            if order["status"] == "pending":
                self.db.update_order(order_id, status="ready")

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def _handle_get_authz(self, auth_id: str):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        authz = self.db.get_authorization(auth_id)
        if not authz:
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Authorization not found")
            return

        self._send_json(self._authz_response(authz, account), 200, add_nonce=True)

    def _authz_response(self, authz: dict, account: dict) -> dict:
        challenges = self.db.get_auth_challenges(authz["id"])
        thumb = account["thumbprint"]

        chall_list = []
        for c in challenges:
            key_auth = self.validator.key_authorization(c["token"], thumb)
            entry = {
                "type":   c["type"],
                "url":    f"{self.base_url}/challenge/{authz['id']}/{c['id']}",
                "token":  c["token"],
                "status": c["status"],
            }
            if c["type"] == "dns-01":
                entry["dns-digest"] = b64url_encode(
                    hashlib.sha256(key_auth.encode()).digest()
                )
            if c.get("validated_at"):
                entry["validated"] = self._ts(c["validated_at"])
            if c.get("error"):
                entry["error"] = json.loads(c["error"])
            chall_list.append(entry)

        return {
            "identifier": json.loads(authz["identifier"]),
            "status":     authz["status"],
            "expires":    self._ts(authz["expires_at"]),
            "challenges": chall_list,
        }

    # ------------------------------------------------------------------
    # Challenge
    # ------------------------------------------------------------------

    def _handle_challenge(self, auth_id: str, chall_id: str):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        authz = self.db.get_authorization(auth_id)
        if not authz:
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Authorization not found")
            return

        chall = self.db.get_challenge(chall_id)
        if not chall or chall["auth_id"] != auth_id:
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Challenge not found")
            return

        if chall["status"] != "pending":
            # Already processing or done — return current state
            authz_url = f"{self.base_url}/authz/{auth_id}"
            self._send_json(
                self._challenge_response(chall, auth_id, account), 200,
                add_nonce=True,
                headers={"Link": f'<{authz_url}>;rel="up"'},
            )
            return

        # Mark as processing and kick off async validation
        self.db.update_challenge(chall_id, status="processing")

        identifier = json.loads(authz["identifier"])
        domain = identifier.get("value", "")
        thumb = account["thumbprint"]
        key_auth = self.validator.key_authorization(chall["token"], thumb)

        # Respond immediately, validate asynchronously
        resp = self._challenge_response(
            {**chall, "status": "processing"}, auth_id, account
        )
        # RFC 8555 §7.5.1 — Link: <authz-url>;rel="up" is REQUIRED on challenge responses
        # certbot uses this header to know which authorization to poll.
        authz_url = f"{self.base_url}/acme/authz/{auth_id}"
        self._send_json(resp, 200, add_nonce=True,
                        headers={"Link": f'<{authz_url}>;rel="up"'})

        # Async validation thread
        threading.Thread(
            target=self._do_validate,
            args=(chall_id, auth_id, authz["order_id"], chall["type"], domain, chall["token"], key_auth),
            daemon=True,
        ).start()

    def _do_validate(self, chall_id, auth_id, order_id, chall_type, domain, token, key_auth):
        """Runs in background thread. Validates challenge and updates DB."""
        try:
            if chall_type == "http-01":
                ok, msg = self.validator.validate_http01(domain, token, key_auth)
            elif chall_type == "dns-01":
                ok, msg = self.validator.validate_dns01(domain, token, key_auth)
            elif chall_type == "tls-alpn-01":
                if not self.validator.tls_alpn01_enabled:
                    ok, msg = False, "tls-alpn-01 not enabled on this server (--alpn-acme)"
                else:
                    import hashlib
                    digest = hashlib.sha256(key_auth.encode()).digest()
                    ok, msg = self.validator.validate_tls_alpn01(domain, 443, key_auth)
            else:
                ok, msg = False, f"Unknown challenge type: {chall_type}"

            if ok:
                self.db.update_challenge(chall_id, status="valid",
                                         validated_at=time.time())
                self.db.update_authorization(auth_id, status="valid")
                logger.info(f"Challenge {chall_id} validated for {domain} via {chall_type}")
            else:
                error = json.dumps({
                    "type": "urn:ietf:params:acme:error:incorrectResponse",
                    "detail": msg,
                })
                self.db.update_challenge(chall_id, status="invalid", error=error)
                self.db.update_authorization(auth_id, status="invalid")
                logger.warning(f"Challenge {chall_id} failed for {domain}: {msg}")

            self._refresh_order_status(order_id)
        except Exception as e:
            logger.error(f"Validation thread error: {e}")

    def _challenge_response(self, chall: dict, auth_id: str, account: dict) -> dict:
        resp = {
            "type":   chall["type"],
            "url":    f"{self.base_url}/challenge/{auth_id}/{chall['id']}",
            "token":  chall["token"],
            "status": chall["status"],
        }
        if chall.get("validated_at"):
            resp["validated"] = self._ts(chall["validated_at"])
        if chall.get("error"):
            resp["error"] = json.loads(chall["error"])
        return resp

    # ------------------------------------------------------------------
    # Finalize (submit CSR)
    # ------------------------------------------------------------------

    def _handle_finalize(self, order_id: str):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        order = self.db.get_order(order_id)
        if not order:
            self._send_error(404, "urn:ietf:params:acme:error:malformed", "Order not found")
            return

        self._refresh_order_status(order_id)
        order = self.db.get_order(order_id)

        if order["status"] not in ("ready",):
            self._send_error(403, "urn:ietf:params:acme:error:orderNotReady",
                             f"Order is {order['status']}, not ready")
            return

        # Decode and validate the CSR
        csr_b64 = payload.get("csr", "")
        if not csr_b64:
            self._send_error(400, "urn:ietf:params:acme:error:malformed", "Missing CSR")
            return

        try:
            csr_der = b64url_decode(csr_b64)
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:badCSR", f"Invalid CSR: {e}")
            return

        if not csr.is_signature_valid:
            self._send_error(400, "urn:ietf:params:acme:error:badCSR",
                             "CSR signature is invalid")
            return

        # Check CSR identifiers match order identifiers. RFC 8738 §5 — for
        # ip identifiers the CSR MUST encode an iPAddress SAN (not dNSName).
        identifiers = json.loads(order["identifiers"])
        order_domains = {i["value"] for i in identifiers if i["type"] == "dns"}
        order_ips_text = {i["value"] for i in identifiers if i["type"] == "ip"}
        # Normalize order IPs to ipaddress objects for comparison; clients may
        # round-trip an IPv6 in non-canonical case (e.g. 2001:DB8::1).
        order_ips = {ipaddress.ip_address(v) for v in order_ips_text}

        csr_domains = set()
        csr_ips = set()
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            csr_domains = {n.value for n in san_ext.value.get_values_for_type(x509.DNSName)}
            csr_ips = set(san_ext.value.get_values_for_type(x509.IPAddress))
        except x509.ExtensionNotFound:
            # Fall back to CN
            try:
                csr_domains = {csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}
            except Exception:
                pass

        if not csr_domains >= order_domains:
            self._send_error(400, "urn:ietf:params:acme:error:badCSR",
                             f"CSR domains {csr_domains} don't cover order domains {order_domains}")
            return

        if not csr_ips >= order_ips:
            csr_ip_strs = sorted(str(i) for i in csr_ips)
            order_ip_strs = sorted(str(i) for i in order_ips)
            self._send_error(400, "urn:ietf:params:acme:error:badCSR",
                             f"CSR IP SANs {csr_ip_strs} don't cover order "
                             f"IP identifiers {order_ip_strs}")
            return

        # Per-account rate limit check
        if self.per_account_cert_limit > 0:
            account_kid = order["account_kid"]
            window_secs = self.per_account_window_days * 86400
            since = time.time() - window_secs
            count = self.db.count_account_certs_since(account_kid, since)
            if count >= self.per_account_cert_limit:
                logger.warning(
                    f"ACME per-account rate limit hit: account={account_kid} "
                    f"count={count}/{self.per_account_cert_limit} "
                    f"window={self.per_account_window_days}d"
                )
                self._send_error(
                    429,
                    "urn:ietf:params:acme:error:rateLimited",
                    f"Account certificate limit reached: {count}/{self.per_account_cert_limit} "
                    f"in the last {self.per_account_window_days} day(s). "
                    "Retry after the window expires.",
                )
                return

        # Issue the certificate (or submit to RA if manual approval is required)
        # RFC 9608: if validity <= short_lived_threshold_days, use short_lived profile
        # which adds id-ce-noRevAvail and suppresses CDP + AIA-OCSP
        try:
            domains = sorted(csr_domains)
            csr_ip_strs = sorted(str(i) for i in csr_ips)
            # Primary subject CN: prefer the first DNS name; fall back to the
            # first IP literal for ip-only orders (RFC 8738 §6).
            primary = domains[0] if domains else (csr_ip_strs[0] if csr_ip_strs else "acme-client")
            subject_str = f"CN={primary}"

            # RFC 8739 — STAR orders always use star_lifetime for validity
            star_lifetime = order.get("star_lifetime")
            if star_lifetime:
                validity = max(1, star_lifetime // 86400)
                profile = "short_lived"
            else:
                validity = self.cert_validity_days
                if validity <= self.short_lived_threshold_days:
                    profile = "short_lived"
                    logger.info(
                        f"ACME cert validity={validity}d <= threshold={self.short_lived_threshold_days}d: "
                        "applying RFC 9608 noRevAvail (profile=short_lived)"
                    )
                else:
                    profile = "tls_server"

            # §5.11: label by dominant identifier type for the histogram
            _challenge_type = "ip" if order_ips and not order_domains else "dns"

            # §5.4 — route through RA if configured
            if self.ra is not None:
                pub_key_der = csr.public_key().public_bytes(
                    Encoding.DER,
                    __import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                _t0 = time.perf_counter()
                ra_req_id, auto_approved, cert = self.ra.submit(
                    protocol="acme",
                    profile=profile,
                    subject_dn=subject_str,
                    public_key_der=pub_key_der,
                    san_dns=list(csr_domains) if csr_domains else None,
                    san_ips=csr_ip_strs if csr_ip_strs else None,
                    validity_days=validity,
                    csr_der=csr.public_bytes(Encoding.DER),
                    requester_ip=self.client_address[0] if hasattr(self, "client_address") else "",
                    protocol_ref=order_id,
                )
                if not auto_approved:
                    # Manual review required — set order to 'processing' (RFC 8555 §7.4)
                    self.db.update_order(order_id, status="processing", ra_request_id=ra_req_id)
                    order = self.db.get_order(order_id)
                    logger.info(
                        f"ACME order {order_id} pending RA approval: request_id={ra_req_id} "
                        f"profile={profile} domains={domains}"
                    )
                    self._send_json(self._order_response(order), 200, add_nonce=True)
                    return
                _get_hist_acme().observe(time.perf_counter() - _t0, (_challenge_type,))
            else:
                _t0 = time.perf_counter()
                cert = self.ca.issue_certificate(
                    subject_str=subject_str,
                    public_key=csr.public_key(),
                    san_dns=list(csr_domains) if csr_domains else None,
                    san_ips=csr_ip_strs if csr_ip_strs else None,
                    validity_days=validity,
                    profile=profile,
                    protocol="acme",
                )
                _get_hist_acme().observe(time.perf_counter() - _t0, (_challenge_type,))

            cert_pem = cert.public_bytes(Encoding.PEM).decode()
            ca_pem = self.ca.ca_cert.public_bytes(Encoding.PEM).decode()
            pem_chain = cert_pem + ca_pem

            cert_id = self.db.store_certificate(order_id, pem_chain, cert.serial_number)
            # RFC 8739 — activate STAR auto-renewal after first issuance
            if star_lifetime:
                self.db.update_order(order_id, status="valid", cert_id=cert_id, star_active=1)
            else:
                self.db.update_order(order_id, status="valid", cert_id=cert_id)

            logger.info(
                f"ACME cert issued: serial={cert.serial_number} "
                f"domains={domains} ips={csr_ip_strs} "
                f"profile={profile} validity={validity}d"
                + (f" star_lifetime={star_lifetime}s" if star_lifetime else "")
            )
        except Exception as e:
            logger.error(f"Certificate issuance failed: {e}")
            self._send_error(500, "urn:ietf:params:acme:error:serverInternal",
                             f"Certificate issuance failed: {e}")
            return

        order = self.db.get_order(order_id)
        self._send_json(self._order_response(order), 200, add_nonce=True)

    # ------------------------------------------------------------------
    # Certificate download
    # ------------------------------------------------------------------

    def _handle_get_cert(self, cert_id: str):
        body = self._read_body()
        account, header, payload = self._verify_with_account(body)

        cert_rec = self.db.get_certificate(cert_id)
        if not cert_rec:
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Certificate not found")
            return

        pem_chain = cert_rec["pem_chain"].encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/pem-certificate-chain")
        self.send_header("Content-Length", str(len(pem_chain)))
        self.send_header("Replay-Nonce", self.db.create_nonce())
        self.end_headers()
        self.wfile.write(pem_chain)

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def _handle_key_change(self):
        """
        RFC 8555 §7.3.5 — Account Key Rollover.

        The outer JWS is signed by the *current* account key (KID flow).
        The inner JWS (payload of the outer) is signed by the *new* key (JWK flow)
        and contains:
          {
            "account": "<account URL>",
            "oldKey":  <current JWK>
          }

        Validation steps (per RFC 8555 §7.3.5):
          1. Verify outer JWS with current account key.
          2. Verify inner JWS with the new key embedded in its header.
          3. Confirm inner payload "account" matches the outer KID URL.
          4. Confirm inner payload "oldKey" matches the current account JWK.
          5. Reject if new key is already used by another account.
          6. Atomically replace the account's JWK + thumbprint.
        """
        body = self._read_body()

        # --- Step 1: verify outer JWS with current account key ---
        try:
            raw = json.loads(body)
            outer_protected_b64 = raw.get("protected", "")
            outer_header = json.loads(b64url_decode(outer_protected_b64))
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Cannot parse outer JWS: {e}")
            return

        nonce = outer_header.get("nonce", "")
        if not self.db.consume_nonce(nonce):
            self._send_error(400, "urn:ietf:params:acme:error:badNonce",
                             "Invalid or already-used nonce")
            return

        kid_url = outer_header.get("kid", "")
        if not kid_url:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             "Outer JWS must use KID (existing account key)")
            return

        kid = kid_url.split("/")[-1]
        account = self.db.get_account(kid)
        if not account:
            self._send_error(400, "urn:ietf:params:acme:error:accountDoesNotExist",
                             f"Account not found: {kid}")
            return

        current_jwk = json.loads(account["jwk_json"])

        try:
            outer_header, outer_payload_raw, _ = verify_jws(body, stored_jwk=current_jwk)
        except JWSError as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Outer JWS verification failed: {e}")
            return

        # outer_payload is the inner JWS (a JSON object string)
        # verify_jws decoded the payload as a dict — but the inner JWS is itself
        # a JWS object, so re-read it from the raw base64 field
        try:
            raw_outer = json.loads(body)
            inner_jws_bytes = b64url_decode(raw_outer.get("payload", ""))
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Cannot read inner JWS: {e}")
            return

        # --- Step 2: verify inner JWS with the new key (embedded JWK) ---
        try:
            inner_header, inner_payload, new_jwk = verify_jws(inner_jws_bytes)
        except JWSError as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Inner JWS verification failed: {e}")
            return

        if "jwk" not in inner_header:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             "Inner JWS must contain the new key as JWK")
            return

        # --- Step 3: inner payload "account" must match outer KID URL ---
        inner_account_url = inner_payload.get("account", "")
        if inner_account_url.split("/")[-1] != kid:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             "Inner payload 'account' does not match outer KID")
            return

        # --- Step 4: inner payload "oldKey" must match current account JWK ---
        inner_old_key = inner_payload.get("oldKey", {})
        # Compare by thumbprint (normalised)
        try:
            inner_old_thumb = jwk_thumbprint(inner_old_key)
            current_thumb   = jwk_thumbprint(current_jwk)
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Cannot compute JWK thumbprint: {e}")
            return

        if inner_old_thumb != current_thumb:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             "Inner payload 'oldKey' does not match current account key")
            return

        # --- Step 5: new key must not already belong to another account ---
        try:
            new_thumb = jwk_thumbprint(new_jwk)
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Invalid new JWK: {e}")
            return

        existing = self.db.get_account_by_thumbprint(new_thumb)
        if existing and existing["kid"] != kid:
            self._send_error(409, "urn:ietf:params:acme:error:malformed",
                             "New key is already in use by a different account")
            return

        # --- Step 6: atomically update the account key ---
        self.db.update_account_key(kid, new_jwk, new_thumb)
        logger.info(f"Key rollover completed for account {kid}: "
                    f"{current_thumb[:8]}… → {new_thumb[:8]}…")

        # Return updated account object (RFC 8555 §7.3.5 — respond with account)
        account = self.db.get_account(kid)
        resp = {
            "status":  account["status"],
            "contact": json.loads(account["contact"]) if account.get("contact") else [],
            "orders":  f"{self.base_url}/account/{kid}/orders",
        }
        self._send_json(resp, 200, add_nonce=True)

    def _handle_revoke(self):
        body = self._read_body()
        # Revocation can be authenticated by account key or cert key
        try:
            header, payload, jwk = verify_jws(body)
        except JWSError as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed", str(e))
            return

        nonce = header.get("nonce", "")
        if not self.db.consume_nonce(nonce):
            self._send_error(400, "urn:ietf:params:acme:error:badNonce",
                             "Invalid or already-used nonce")
            return

        cert_b64 = payload.get("certificate", "")
        reason = payload.get("reason", 0)

        try:
            cert_der = b64url_decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der)
            serial = cert.serial_number
        except Exception as e:
            self._send_error(400, "urn:ietf:params:acme:error:malformed",
                             f"Invalid certificate: {e}")
            return

        ok = self.ca.revoke_certificate(serial, reason)
        if not ok:
            self._send_error(404, "urn:ietf:params:acme:error:malformed",
                             "Certificate not found or already revoked")
            return

        # RFC 8555 §7.6 — successful revocation: 200 OK, empty body
        self.send_response(200)
        self.send_header("Replay-Nonce", self.db.create_nonce())
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------------
    # JWS helpers
    # ------------------------------------------------------------------

    def _verify_with_account(self, body: bytes) -> Tuple[dict, dict, dict]:
        """
        Verify JWS using either embedded JWK (for new-account) or KID lookup.
        Returns (account_dict, header_dict, payload_dict).
        Raises JWSError on failure. Also validates and consumes the nonce.
        """
        try:
            raw = json.loads(body)
            protected_b64 = raw.get("protected", "")
            header = json.loads(b64url_decode(protected_b64))
        except Exception as e:
            raise JWSError(f"Cannot parse JWS header: {e}")

        nonce = header.get("nonce", "")
        if not self.db.consume_nonce(nonce):
            raise JWSError("Invalid or already-used nonce")

        kid_url = header.get("kid", "")
        if kid_url:
            # KID flow: look up account
            kid = kid_url.split("/")[-1]
            account = self.db.get_account(kid)
            if not account:
                raise JWSError(f"Account not found: {kid}")
            stored_jwk = json.loads(account["jwk_json"])
            header, payload, jwk = verify_jws(body, stored_jwk=stored_jwk)
        elif "jwk" in header:
            # JWK flow: verify and look up/create account
            header, payload, jwk = verify_jws(body)
            thumb = jwk_thumbprint(jwk)
            account = self.db.get_account_by_thumbprint(thumb)
            if not account:
                raise JWSError("Account not found for this key")
        else:
            raise JWSError("JWS header has neither kid nor jwk")

        return account, header, payload

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def _send_json(self, data: dict, code: int = 200,
                   headers: Optional[dict] = None,
                   add_nonce: bool = False,
                   content_type: str = "application/json"):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        # RFC 8555 §6.1 — ACME responses use application/json
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if add_nonce:
            self.send_header("Replay-Nonce", self.db.create_nonce())
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, etype: str, detail: str):
        err = {"type": etype, "detail": detail, "status": code}
        body = json.dumps(err, indent=2).encode()
        self.send_response(code)
        # RFC 7807 / RFC 8555 §6.7 — error responses use application/problem+json
        self.send_header("Content-Type", "application/problem+json")
        self.send_header("Content-Length", str(len(body)))
        # Always include a fresh nonce on errors so clients can retry immediately
        self.send_header("Replay-Nonce", self.db.create_nonce())
        # RFC 8555 §6.7 — Link: <directory>;rel="index" on all error responses
        self.send_header("Link", f'<{self.base_url}/directory>;rel="index"')
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _ts(t: float) -> str:
        return datetime.datetime.utcfromtimestamp(t).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# ACME Server factory
# ---------------------------------------------------------------------------

class ThreadedACMEServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_acme_handler(
    db: ACMEDatabase,
    ca,
    validator: ChallengeValidator,
    base_url: str,
    cert_validity_days: int = 90,
    short_lived_threshold_days: int = 7,
    allow_private_ip: bool = False,
    require_eab: bool = False,
    per_account_cert_limit: int = 0,
    per_account_window_days: int = 7,
    ra=None,
    star_enabled: bool = False,
    star_min_lifetime: int = 86400,
    star_max_duration: int = 7776000,
):
    class BoundACMEHandler(ACMEHandler):
        pass
    BoundACMEHandler.db                          = db
    BoundACMEHandler.ca                          = ca
    BoundACMEHandler.ra                          = ra
    BoundACMEHandler.validator                   = validator
    BoundACMEHandler.base_url                    = base_url
    BoundACMEHandler.cert_validity_days          = cert_validity_days
    BoundACMEHandler.short_lived_threshold_days  = short_lived_threshold_days
    BoundACMEHandler.allow_private_ip            = allow_private_ip
    BoundACMEHandler.require_eab                 = require_eab
    BoundACMEHandler.per_account_cert_limit      = per_account_cert_limit
    BoundACMEHandler.per_account_window_days     = per_account_window_days
    BoundACMEHandler.star_enabled                = star_enabled
    BoundACMEHandler.star_min_lifetime           = star_min_lifetime
    BoundACMEHandler.star_max_duration           = star_max_duration
    return BoundACMEHandler


def start_acme_server(
    route_table,
    prefix: str,
    ca,
    ca_dir: Path,
    auto_approve_dns: bool = False,
    base_url: Optional[str] = None,
    enable_tls_alpn01: bool = False,
    cert_validity_days: int = 90,
    short_lived_threshold_days: int = 7,
    dns01_hook=None,
    allow_private_ip: bool = False,
    require_eab: bool = False,
    eab_file: Optional[str] = None,
    per_account_cert_limit: int = 0,
    per_account_window_days: int = 7,
    db_url: str = "",
    star_enabled: bool = False,
    star_min_lifetime: int = 86400,
    star_max_duration: int = 7776000,
):
    """
    Register the ACME handler with *route_table* under *prefix*.

    Returns a _RouteProxy whose .shutdown() unregisters the ACME routes.

    Args:
        route_table: dispatcher_server.RouteTable shared by all services.
        prefix: URL path prefix (e.g. "/acme").  The base_url passed to
                ACME clients should include this prefix so that generated
                URLs resolve correctly (e.g. "http://host:8080/acme").
        enable_tls_alpn01: If True, the tls-alpn-01 challenge type is offered
                           and validated. Requires the main server to advertise
                           "acme-tls/1" via ALPN (--alpn-acme flag).
        cert_validity_days: Validity period for ACME-issued certificates (default: 90).
        short_lived_threshold_days: Certs with validity <= this value automatically
                           receive the RFC 9608 id-ce-noRevAvail extension and have
                           CDP / AIA-OCSP suppressed (default: 7 days).
        dns01_hook: Optional callable for dns-01 challenge validation.
                    Signature: (domain: str, token: str, key_auth: str) -> (bool, str)
                    When provided, this hook is called instead of the built-in DNS
                    TXT lookup. Use make_dns01_webhook_hook() or
                    make_dns01_rfc2136_hook() from pki_server.py to build one.
        allow_private_ip: If True, permit private/reserved IPs in orders.
        require_eab: If True, enforce External Account Binding.
        eab_file: Path to JSON file with EAB credentials.
        db_url: DAL connection URL (default: sqlite:///<ca_dir>/acme.db).
    """
    from dispatcher_server import _RouteProxy

    _acme_url = db_url or f"sqlite:///{ca_dir / 'acme.db'}"
    db = ACMEDatabase(make_db(_acme_url))

    # Load EAB keys if provided
    if eab_file:
        try:
            with open(eab_file, "r") as f:
                eab_keys = json.load(f)
            for kid, key_b64 in eab_keys.items():
                db.add_eab_key(kid, key_b64)
            logger.info(f"Loaded {len(eab_keys)} EAB key(s) from {eab_file}")
        except Exception as e:
            logger.error(f"Failed to load EAB keys from {eab_file}: {e}")

    validator = ChallengeValidator(
        auto_approve_dns=auto_approve_dns,
        tls_alpn01_enabled=enable_tls_alpn01,
        dns01_hook=dns01_hook,
    )
    handler_cls = make_acme_handler(
        db, ca, validator, base_url or "",
        cert_validity_days=cert_validity_days,
        short_lived_threshold_days=short_lived_threshold_days,
        allow_private_ip=allow_private_ip,
        require_eab=require_eab,
        per_account_cert_limit=per_account_cert_limit,
        per_account_window_days=per_account_window_days,
        ra=getattr(ca, "ra", None),
        star_enabled=star_enabled,
        star_min_lifetime=star_min_lifetime,
        star_max_duration=star_max_duration,
    )

    route_table.register(prefix, handler_cls)
    logger.info(f"ACME handler registered at prefix {prefix!r} (base_url={base_url!r})")

    # RFC 8739 — start background STAR renewal worker
    if star_enabled:
        STARRenewalWorker(db, ca).start()

    proxy = _RouteProxy(route_table, prefix, label="acme")
    proxy.acme_db = db   # expose for web UI EAB management
    return proxy


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys
    import importlib.util

    parser = argparse.ArgumentParser(description="ACME Server (RFC 8555)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--ca-dir", default="./ca")
    parser.add_argument("--base-url", default=None,
                        help="Public base URL e.g. https://ca.example.com:8888")
    parser.add_argument("--auto-approve-dns", action="store_true",
                        help="Auto-approve dns-01 challenges (testing only)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Import CertificateAuthority from pki_server if available
    spec = importlib.util.spec_from_file_location(
        "pki_server", Path(__file__).parent / "pki_server.py"
    )
    if spec and spec.loader:
        pki_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pki_mod)
        ca = pki_mod.CertificateAuthority(ca_dir=args.ca_dir)
    else:
        print("ERROR: pki_server.py not found. Run from the same directory.")
        sys.exit(1)

    base_url = args.base_url or f"http://{args.host}:{args.port}"
    ca_dir = Path(args.ca_dir)

    db = ACMEDatabase(make_db(f"sqlite:///{ca_dir / 'acme.db'}"))
    validator = ChallengeValidator(auto_approve_dns=args.auto_approve_dns)
    handler = make_acme_handler(db, ca, validator, base_url)

    server = ThreadedACMEServer((args.host, args.port), handler)

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                  ACME Server (RFC 8555)                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Listening  : {base_url:<51}║
║  CA Dir     : {args.ca_dir:<51}║
║  DNS auto   : {"✓ (testing mode)" if args.auto_approve_dns else "✗ (real DNS validation)":<51}║
╠══════════════════════════════════════════════════════════════════╣
║  Directory  : GET  {base_url}/directory              ║
║  New Nonce  : HEAD {base_url}/new-nonce              ║
║  New Acct   : POST {base_url}/new-account            ║
║  New Order  : POST {base_url}/new-order              ║
║  Revoke     : POST {base_url}/revoke-cert            ║
╠══════════════════════════════════════════════════════════════════╣
║  Challenge types: http-01, dns-01, tls-alpn-01 (RFC 8737)      ║
╚══════════════════════════════════════════════════════════════════╝

  Quick test with curl:
    curl {base_url}/directory | python3 -m json.tool
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ACME server...")
        server.shutdown()
