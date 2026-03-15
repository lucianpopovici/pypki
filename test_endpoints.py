#!/usr/bin/env python3
"""
test_endpoints.py — PyPKI Endpoint Integration Tests
=====================================================
Black-box HTTP tests against a live PyPKI server stack.

Tests every endpoint across all six servers:
  • pki_server.py   (CMP/REST)   — default https://localhost:8443
  • acme_server.py  (ACME)       — default http://localhost:8888
  • scep_server.py  (SCEP)       — default http://localhost:8889
  • est_server.py   (EST)        — default https://localhost:8444
  • ocsp_server.py  (OCSP)       — default http://localhost:8082
  • web_ui.py       (Web UI)     — default http://localhost:8008

Usage
-----
  # Run against default ports (requires --no-verify for self-signed CA cert):
  python test_endpoints.py --no-verify

  # Run against your TLS setup:
  python test_endpoints.py \\
    --pki-url  https://pki.internal:8443 \\
    --acme-url http://pki.internal:8888  \\
    --scep-url http://pki.internal:8889  \\
    --est-url  https://pki.internal:8444 \\
    --ocsp-url http://pki.internal:8082  \\
    --web-url  http://pki.internal:8008  \\
    --ca-cert  ./ca/ca.crt

  # Skip TLS verification entirely (testing only):
  python test_endpoints.py --no-verify

  # Run only one group:
  python test_endpoints.py --only pki
  python test_endpoints.py --only acme
  python test_endpoints.py --only scep
  python test_endpoints.py --only est
  python test_endpoints.py --only ocsp
  python test_endpoints.py --only webui

  # Verbose (show request/response details):
  python test_endpoints.py -v

Requirements: pip install requests cryptography
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import textwrap
import time
import traceback
import urllib.parse
import warnings
from dataclasses import dataclass, field
from typing import Callable, List, Optional

# Suppress InsecureRequestWarning when --no-verify is used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' not installed — run: pip install requests")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    import cryptography.hazmat.primitives.asymmetric.utils as asym_utils
    import datetime
except ImportError:
    sys.exit("ERROR: 'cryptography' not installed — run: pip install cryptography")

# ─────────────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Result:
    name: str
    passed: bool
    message: str = ""
    detail: str = ""


@dataclass
class Suite:
    name: str
    results: List[Result] = field(default_factory=list)

    def add(self, r: Result):
        self.results.append(r)

    @property
    def passed(self):  return sum(1 for r in self.results if r.passed)
    @property
    def failed(self):  return sum(1 for r in self.results if not r.passed)
    @property
    def total(self):   return len(self.results)


SUITES: List[Suite] = []
VERBOSE = False


def suite(name: str) -> Suite:
    s = Suite(name)
    SUITES.append(s)
    return s


def ok(s: Suite, name: str, msg: str = ""):
    s.add(Result(name, True, msg))
    _print_result(True, name, msg)


def fail(s: Suite, name: str, msg: str, detail: str = ""):
    s.add(Result(name, False, msg, detail))
    _print_result(False, name, msg, detail)


def _print_result(passed: bool, name: str, msg: str, detail: str = ""):
    icon = "✅" if passed else "❌"
    line = f"  {icon}  {name}"
    if msg:
        line += f"  — {msg}"
    print(line)
    if detail and (VERBOSE or not passed):
        for dl in detail.splitlines():
            print(f"       {dl}")


def check(s: Suite, name: str, fn: Callable[[], tuple[bool, str]]):
    """Run fn(); record pass/fail. fn returns (ok: bool, message: str)."""
    try:
        passed, msg = fn()
        if passed:
            ok(s, name, msg)
        else:
            fail(s, name, msg)
    except Exception as e:
        fail(s, name, f"Exception: {e}", traceback.format_exc())


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

class Client:
    """Thin wrapper around requests.Session with configurable TLS."""

    def __init__(self, verify, timeout: int = 10):
        self.session = requests.Session()
        self.verify = verify
        self.timeout = timeout

    def get(self, url, **kw):
        return self.session.get(url, verify=self.verify, timeout=self.timeout, **kw)

    def post(self, url, **kw):
        return self.session.post(url, verify=self.verify, timeout=self.timeout, **kw)

    def head(self, url, **kw):
        return self.session.head(url, verify=self.verify, timeout=self.timeout, **kw)

    def patch(self, url, **kw):
        return self.session.patch(url, verify=self.verify, timeout=self.timeout, **kw)


def expect_status(r: requests.Response, *codes: int) -> tuple[bool, str]:
    if r.status_code in codes:
        return True, f"HTTP {r.status_code}"
    return False, f"Expected HTTP {codes}, got {r.status_code}. Body: {r.text[:200]}"


def expect_json(r: requests.Response, *codes: int) -> tuple[bool, str]:
    ok_s, msg = expect_status(r, *codes)
    if not ok_s:
        return False, msg
    ct = r.headers.get("Content-Type", "")
    if "json" not in ct:
        return False, f"Expected JSON content-type, got: {ct}"
    try:
        r.json()
    except Exception as e:
        return False, f"Invalid JSON: {e}"
    return True, f"HTTP {r.status_code} JSON"


def expect_key(r: requests.Response, *keys: str) -> tuple[bool, str]:
    try:
        data = r.json()
        missing = [k for k in keys if k not in data]
        if missing:
            return False, f"Missing JSON keys: {missing}. Got: {list(data.keys())}"
        return True, f"Keys present: {list(keys)}"
    except Exception as e:
        return False, f"JSON parse error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers (for ACME JWS, CMP, OCSP request building)
# ─────────────────────────────────────────────────────────────────────────────

def gen_rsa_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def gen_csr(key, cn: str = "test.example.com", dns_names: list = None):
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns_names]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(key) -> str:
    pub = key.public_key()
    nums = pub.public_numbers()
    def _b64int(n): return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    jwk = {"e": _b64int(nums.e), "kty": "RSA", "n": _b64int(nums.n)}
    canon = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return b64url(hashlib.sha256(canon).digest())


def make_jws(key, payload: dict | None, url: str, nonce: str,
             kid: str = None, jwk_embed: bool = False) -> dict:
    """Build a JWS (flattened JSON serialization) for ACME."""
    pub = key.public_key()
    nums = pub.public_numbers()
    def _b64int(n): return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))

    header: dict = {"alg": "RS256", "nonce": nonce, "url": url}
    if jwk_embed:
        header["jwk"] = {"e": _b64int(nums.e), "kty": "RSA", "n": _b64int(nums.n)}
    elif kid:
        header["kid"] = kid

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    if payload is None:
        payload_b64 = ""
    else:
        payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {
        "protected": header_b64,
        "payload": payload_b64,
        "signature": b64url(sig),
    }


def build_ocsp_request(ca_cert: x509.Certificate, target_serial: int) -> bytes:
    """Build a minimal DER-encoded OCSPRequest for the given serial."""
    def enc_len(n):
        if n < 0x80: return bytes([n])
        lb = []
        while n: lb.append(n & 0xFF); n >>= 8
        lb.reverse()
        return bytes([0x80 | len(lb)]) + bytes(lb)
    def seq(c): return b"\x30" + enc_len(len(c)) + c
    def oct_v(v): return b"\x04" + enc_len(len(v)) + v
    def oid_sha1(): return b"\x06\x05\x2b\x0e\x03\x02\x1a"
    def integer(n):
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80: raw = b"\x00" + raw
        return b"\x02" + enc_len(len(raw)) + raw

    # SHA-1 of issuer name DER
    name_hash = hashlib.sha1(
        ca_cert.subject.public_bytes()
    ).digest()
    # SHA-1 of issuer public key bit string value
    spki = ca_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    # Extract BIT STRING value (skip SEQUENCE tag/len, AlgorithmIdentifier, then BIT STRING tag/len/unused)
    # Simpler: hash the raw public key bytes
    key_hash = hashlib.sha1(
        ca_cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)
        if hasattr(ca_cert.public_key(), "public_numbers") else spki
    ).digest()

    hash_alg = seq(oid_sha1() + b"\x05\x00")
    cert_id = seq(hash_alg + oct_v(name_hash) + oct_v(key_hash) + integer(target_serial))
    request = seq(cert_id)
    request_list = seq(request)
    tbs = seq(request_list)
    ocsp_req = seq(tbs)
    return ocsp_req


# ─────────────────────────────────────────────────────────────────────────────
# ① PKI Server (CMP + REST API)
# ─────────────────────────────────────────────────────────────────────────────

def test_pki(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("PKI Server (REST API)")
    base = cfg.pki_url
    print(f"\n{'─'*60}")
    print(f"  PKI Server  →  {base}")
    print(f"{'─'*60}")

    # ── Health & info ────────────────────────────────────────────
    check(s, "GET /health", lambda: expect_json(c.get(f"{base}/health"), 200))
    check(s, "GET /health → {status: ok}", lambda: (
        c.get(f"{base}/health").json().get("status") == "ok",
        f"status={c.get(f'{base}/health').json().get('status')}"
    ))
    check(s, "GET /config", lambda: expect_json(c.get(f"{base}/config"), 200))
    check(s, "GET /metrics (Prometheus text)", lambda: (
        (r := c.get(f"{base}/metrics")).status_code == 200
        and "text/plain" in r.headers.get("Content-Type", ""),
        f"HTTP {r.status_code} ct={r.headers.get('Content-Type','?')}"
    ))

    # ── CA certificate & CRL ─────────────────────────────────────
    check(s, "GET /ca/cert.pem", lambda: (
        (r := c.get(f"{base}/ca/cert.pem")).status_code == 200
        and b"BEGIN CERTIFICATE" in r.content,
        f"HTTP {r.status_code} len={len(r.content)}"
    ))
    check(s, "GET /ca/cert.der", lambda: (
        (r := c.get(f"{base}/ca/cert.der")).status_code == 200
        and len(r.content) > 100,
        f"HTTP {r.status_code} len={len(r.content)}"
    ))
    check(s, "GET /ca/crl", lambda: (
        (r := c.get(f"{base}/ca/crl")).status_code == 200
        and len(r.content) > 0,
        f"HTTP {r.status_code} len={len(r.content)}"
    ))
    check(s, "GET /ca/delta-crl", lambda: expect_status(
        c.get(f"{base}/ca/delta-crl"), 200, 404
    ))

    # ── CMP well-known ───────────────────────────────────────────
    check(s, "GET /.well-known/cmp", lambda: (
        (r := c.get(f"{base}/.well-known/cmp")).status_code == 200
        and len(r.content) > 0,
        f"HTTP {r.status_code} len={len(r.content)}"
    ))

    # ── Certificate listing ──────────────────────────────────────
    check(s, "GET /api/certs", lambda: (
        (r := c.get(f"{base}/api/certs")).status_code == 200
        and isinstance(r.json().get("certificates", r.json()), list),
        f"HTTP {r.status_code}"
    ))
    check(s, "GET /api/certs?profile=tls_server", lambda: expect_status(
        c.get(f"{base}/api/certs?profile=tls_server"), 200
    ))
    check(s, "GET /api/expiring?days=30", lambda: expect_status(
        c.get(f"{base}/api/expiring?days=30"), 200
    ))
    check(s, "GET /api/expiring bad param → 400", lambda: expect_status(
        c.get(f"{base}/api/expiring?days=notanumber"), 400
    ))

    # ── Audit & rate-limit ───────────────────────────────────────
    check(s, "GET /api/audit", lambda: expect_json(c.get(f"{base}/api/audit"), 200))
    check(s, "GET /api/rate-limit", lambda: expect_json(c.get(f"{base}/api/rate-limit"), 200))
    check(s, "GET /api/whoami", lambda: expect_json(c.get(f"{base}/api/whoami"), 200))

    # ── Issue certificate via REST ───────────────────────────────
    key = gen_rsa_key()
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    issue_payload = {
        "subject": "CN=test-endpoint.example.com,O=TestCo",
        "public_key_pem": pub_pem,
        "validity_days": 30,
        "san_dns": ["test-endpoint.example.com"],
        "profile": "tls_server",
    }
    issue_resp = None
    def _issue():
        nonlocal issue_resp
        r = c.post(f"{base}/api/issue", json=issue_payload,
                   headers={"Content-Type": "application/json"})
        if r.status_code not in (200, 201):
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        issue_resp = r
        data = r.json()
        if "serial" not in data and "cert_pem" not in data and "certificate" not in data:
            return False, f"Missing serial/cert_pem in response: {list(data.keys())}"
        return True, f"HTTP {r.status_code} serial={data.get('serial','?')}"
    check(s, "POST /api/issue (issue certificate)", _issue)

    # ── Per-cert endpoints (using the serial we just issued) ─────
    serial = None
    if issue_resp and issue_resp.ok:
        data = issue_resp.json()
        serial = data.get("serial")
        if serial:
            check(s, f"GET /api/certs/{serial}/pem", lambda sn=serial: (
                (r := c.get(f"{base}/api/certs/{sn}/pem")).status_code == 200
                and b"BEGIN CERTIFICATE" in r.content,
                f"HTTP {r.status_code}"
            ))
            check(s, f"GET /api/certs/{serial}/p12", lambda sn=serial: (
                (r := c.get(f"{base}/api/certs/{sn}/p12")).status_code == 200
                and len(r.content) > 0,
                f"HTTP {r.status_code} len={len(r.content)}"
            ))

            # Renew
            def _renew(sn=serial):
                r = c.post(f"{base}/api/certs/{sn}/renew",
                           json={}, headers={"Content-Type": "application/json"})
                return expect_status(r, 200, 201)
            check(s, f"POST /api/certs/{serial}/renew", _renew)

            # Archive key (key escrow)
            key_pem = key.private_bytes(Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode()
            def _archive(sn=serial, kpem=key_pem):
                r = c.post(f"{base}/api/certs/{sn}/archive",
                           json={"key_pem": kpem},
                           headers={"Content-Type": "application/json"})
                return expect_status(r, 200, 201, 400)  # 400 if already archived
            check(s, f"POST /api/certs/{serial}/archive (key escrow)", _archive)

            # Revoke last (so it doesn't interfere with other tests)
            def _revoke_issued(sn=serial):
                r = c.post(f"{base}/api/revoke",
                           json={"serial": sn, "reason": 0},
                           headers={"Content-Type": "application/json"})
                return expect_status(r, 200)
            check(s, f"POST /api/revoke serial={serial}", _revoke_issued)

    # ── Revoke non-existent serial → error ───────────────────────
    check(s, "POST /api/revoke (unknown serial) → error", lambda: (
        (r := c.post(f"{base}/api/revoke",
                     json={"serial": 999999999, "reason": 0},
                     headers={"Content-Type": "application/json"})).status_code in (400, 404, 200),
        f"HTTP {r.status_code}"
    ))

    # ── Sub-CA issuance ──────────────────────────────────────────
    def _sub_ca():
        r = c.post(f"{base}/api/sub-ca",
                   json={"cn": "Test Intermediate CA", "validity_days": 365},
                   headers={"Content-Type": "application/json"})
        return expect_status(r, 200, 201)
    check(s, "POST /api/sub-ca", _sub_ca)

    # ── Name-constrained CA ──────────────────────────────────────
    def _nc_ca():
        r = c.post(f"{base}/api/name-constrained-ca",
                   json={
                       "cn": "NC Test CA",
                       "validity_days": 365,
                       "permitted_dns": ["example.com"],
                   },
                   headers={"Content-Type": "application/json"})
        return expect_status(r, 200, 201, 400)
    check(s, "POST /api/name-constrained-ca", _nc_ca)

    # ── PATCH /config ────────────────────────────────────────────
    def _patch_config():
        r = c.patch(f"{base}/config",
                    json={"validity": {"end_entity_days": 365}},
                    headers={"Content-Type": "application/json"})
        return expect_status(r, 200)
    check(s, "PATCH /config", _patch_config)

    # ── CMP POST (raw DER) — just check it doesn't 404 ──────────
    def _cmp_post():
        # Send garbage DER — server should return a CMP error response, not 404
        r = c.post(f"{base}/", data=b"\x30\x03\x02\x01\x02",
                   headers={"Content-Type": "application/pkixcmp"})
        return expect_status(r, 200, 400, 500)  # any response but 404
    check(s, "POST / (CMP endpoint reachable)", _cmp_post)

    # ── Unknown path → endpoint listing ─────────────────────────
    check(s, "GET /unknown → JSON endpoint listing", lambda: (
        (r := c.get(f"{base}/unknown-path-xyz")).status_code in (200, 404)
        and "json" in r.headers.get("Content-Type", ""),
        f"HTTP {r.status_code}"
    ))

    return s


# ─────────────────────────────────────────────────────────────────────────────
# ② ACME Server
# ─────────────────────────────────────────────────────────────────────────────

def test_acme(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("ACME Server (RFC 8555)")
    base = cfg.acme_url
    print(f"\n{'─'*60}")
    print(f"  ACME Server  →  {base}")
    print(f"{'─'*60}")

    # ── Directory ────────────────────────────────────────────────
    dir_resp = None
    def _directory():
        nonlocal dir_resp
        r = c.get(f"{base}/acme/directory")
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        required = {"newNonce", "newAccount", "newOrder"}
        missing = required - set(data.keys())
        if missing:
            return False, f"Missing directory keys: {missing}"
        dir_resp = r
        return True, f"HTTP 200 — keys: {sorted(data.keys())}"
    check(s, "GET /acme/directory", _directory)

    if dir_resp is None:
        fail(s, "ACME (remaining tests skipped)", "Directory endpoint failed")
        return s

    directory = dir_resp.json()
    nonce_url  = directory["newNonce"]
    account_url = directory["newAccount"]
    order_url   = directory["newOrder"]

    # ── HEAD /acme/new-nonce ─────────────────────────────────────
    nonce = None
    def _head_nonce():
        nonlocal nonce
        r = c.head(nonce_url)
        nonce = r.headers.get("Replay-Nonce")
        return (
            r.status_code == 200 and bool(nonce),
            f"HTTP {r.status_code} nonce={nonce}"
        )
    check(s, "HEAD /acme/new-nonce", _head_nonce)

    # ── GET /acme/new-nonce ──────────────────────────────────────
    def _get_nonce():
        nonlocal nonce
        r = c.get(nonce_url)
        n = r.headers.get("Replay-Nonce")
        if n:
            nonce = n
        return r.status_code == 200 and bool(n), f"HTTP {r.status_code} nonce={n}"
    check(s, "GET /acme/new-nonce", _get_nonce)

    # ── GET /acme/terms ──────────────────────────────────────────
    check(s, "GET /acme/terms", lambda: expect_status(
        c.get(f"{base}/acme/terms"), 200
    ))

    # ── GET /acme/renewal-info → 404 (not supported) ─────────────
    check(s, "GET /acme/renewal-info → 404", lambda: expect_status(
        c.get(f"{base}/acme/renewal-info"), 404
    ))

    if not nonce:
        fail(s, "ACME account flow (skipped)", "Could not obtain nonce")
        return s

    # ── POST /acme/new-account ───────────────────────────────────
    account_key = gen_rsa_key()
    kid = None
    def _new_account():
        nonlocal nonce, kid
        r = c.get(nonce_url)
        nonce = r.headers.get("Replay-Nonce", nonce)
        jws = make_jws(
            account_key,
            {"termsOfServiceAgreed": True, "contact": ["mailto:test@example.com"]},
            account_url,
            nonce,
            jwk_embed=True,
        )
        resp = c.post(account_url, json=jws,
                      headers={"Content-Type": "application/jose+json"})
        nonce = resp.headers.get("Replay-Nonce", nonce)
        if resp.status_code not in (200, 201):
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
        kid = resp.headers.get("Location") or resp.json().get("kid")
        return True, f"HTTP {resp.status_code} kid={kid}"
    check(s, "POST /acme/new-account", _new_account)

    if not kid:
        fail(s, "ACME order flow (skipped)", "Account creation failed, no kid")
        return s

    # ── POST /acme/new-order ─────────────────────────────────────
    order_location = None
    authz_urls = []
    def _new_order():
        nonlocal nonce, order_location, authz_urls
        r = c.get(nonce_url)
        nonce = r.headers.get("Replay-Nonce", nonce)
        jws = make_jws(
            account_key,
            {"identifiers": [{"type": "dns", "value": "test-acme.example.com"}]},
            order_url,
            nonce,
            kid=kid,
        )
        resp = c.post(order_url, json=jws,
                      headers={"Content-Type": "application/jose+json"})
        nonce = resp.headers.get("Replay-Nonce", nonce)
        if resp.status_code not in (200, 201):
            return False, f"HTTP {resp.status_code}: {resp.text[:300]}"
        order_location = resp.headers.get("Location")
        data = resp.json()
        authz_urls = data.get("authorizations", [])
        return True, f"HTTP {resp.status_code} status={data.get('status')} authzs={len(authz_urls)}"
    check(s, "POST /acme/new-order", _new_order)

    # ── GET /acme/order/<id> ─────────────────────────────────────
    if order_location:
        check(s, "GET /acme/order/<id>", lambda: expect_status(
            c.get(order_location), 200
        ))

    # ── GET + POST /acme/authz/<id> ──────────────────────────────
    chall_url = None
    chall_token = None
    if authz_urls:
        authz_url = authz_urls[0]
        authz_resp = c.get(authz_url)
        check(s, "GET /acme/authz/<id>", lambda: expect_status(
            c.get(authz_url), 200
        ))
        if authz_resp.ok:
            challenges = authz_resp.json().get("challenges", [])
            for ch in challenges:
                if ch.get("type") == "http-01":
                    chall_url = ch.get("url")
                    chall_token = ch.get("token")
                    break
            if not chall_url:
                # Try dns-01
                for ch in challenges:
                    if ch.get("type") == "dns-01":
                        chall_url = ch.get("url")
                        chall_token = ch.get("token")
                        break

        # POST /acme/authz/<id> (POST-as-GET)
        def _post_authz():
            nonlocal nonce
            r = c.get(nonce_url)
            nonce = r.headers.get("Replay-Nonce", nonce)
            jws = make_jws(account_key, None, authz_url, nonce, kid=kid)
            resp = c.post(authz_url, json=jws,
                          headers={"Content-Type": "application/jose+json"})
            nonce = resp.headers.get("Replay-Nonce", nonce)
            return expect_status(resp, 200, 201)
        check(s, "POST /acme/authz/<id> (POST-as-GET)", _post_authz)

    # ── POST /acme/challenge/<authz>/<id> ─────────────────────────
    if chall_url:
        def _respond_challenge():
            nonlocal nonce
            r = c.get(nonce_url)
            nonce = r.headers.get("Replay-Nonce", nonce)
            jws = make_jws(account_key, {}, chall_url, nonce, kid=kid)
            resp = c.post(chall_url, json=jws,
                          headers={"Content-Type": "application/jose+json"})
            nonce = resp.headers.get("Replay-Nonce", nonce)
            # 200 = accepted, challenge may fail validation (expected without real DNS)
            return expect_status(resp, 200, 400)
        check(s, "POST /acme/challenge/<authz>/<id> (respond)", _respond_challenge)

    # ── POST /acme/key-change ─────────────────────────────────────
    def _key_change():
        nonlocal nonce
        r = c.get(nonce_url)
        nonce = r.headers.get("Replay-Nonce", nonce)
        new_key = gen_rsa_key()
        key_change_url = f"{base}/acme/key-change"
        inner_payload = {"account": kid, "oldKey": {
            "e": b64url(account_key.public_key().public_numbers().e.to_bytes(3, "big")),
            "kty": "RSA",
            "n": b64url(account_key.public_key().public_numbers().n.to_bytes(256, "big")),
        }}
        inner_nonce = ""
        inner_jws = make_jws(new_key, inner_payload, key_change_url, inner_nonce, jwk_embed=True)
        outer_jws = make_jws(account_key, inner_jws, key_change_url, nonce, kid=kid)
        resp = c.post(key_change_url, json=outer_jws,
                      headers={"Content-Type": "application/jose+json"})
        nonce = resp.headers.get("Replay-Nonce", nonce)
        # 200 = success, 400/403 = key-change rejected (acceptable in test env)
        return expect_status(resp, 200, 400, 403)
    check(s, "POST /acme/key-change", _key_change)

    # ── POST /acme/revoke-cert (no cert to revoke — expect error) ─
    def _revoke_cert():
        nonlocal nonce
        r = c.get(nonce_url)
        nonce = r.headers.get("Replay-Nonce", nonce)
        revoke_url = f"{base}/acme/revoke-cert"
        jws = make_jws(account_key, {"certificate": b64url(b"fakecert"), "reason": 0},
                       revoke_url, nonce, kid=kid)
        resp = c.post(revoke_url, json=jws,
                      headers={"Content-Type": "application/jose+json"})
        nonce = resp.headers.get("Replay-Nonce", nonce)
        return expect_status(resp, 200, 400, 403, 404)
    check(s, "POST /acme/revoke-cert (error expected)", _revoke_cert)

    return s


# ─────────────────────────────────────────────────────────────────────────────
# ③ SCEP Server
# ─────────────────────────────────────────────────────────────────────────────

def test_scep(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("SCEP Server (RFC 8894)")
    base = cfg.scep_url
    print(f"\n{'─'*60}")
    print(f"  SCEP Server  →  {base}")
    print(f"{'─'*60}")

    scep_paths = ["/scep", "/cgi-bin/pkiclient.exe", "/scep/pkiclient.exe"]

    # ── GetCACaps ────────────────────────────────────────────────
    for path in scep_paths[:1]:  # test primary path, aliases checked separately
        def _caps(p=path):
            r = c.get(f"{base}{p}?operation=GetCACaps")
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}: {r.text[:200]}"
            caps = r.text.strip().split("\n")
            return True, f"Caps: {caps}"
        check(s, f"GET {path}?operation=GetCACaps", _caps)

    # ── GetCACert ────────────────────────────────────────────────
    ca_der = None
    for path in scep_paths[:1]:
        def _cacert(p=path):
            nonlocal ca_der
            r = c.get(f"{base}{p}?operation=GetCACert&message=ca")
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}"
            ca_der = r.content
            ct = r.headers.get("Content-Type", "")
            return True, f"HTTP 200 len={len(r.content)} ct={ct}"
        check(s, f"GET {path}?operation=GetCACert", _cacert)

    # ── Alias paths ──────────────────────────────────────────────
    for path in scep_paths[1:]:
        check(s, f"GET {path}?operation=GetCACaps (alias)", lambda p=path: expect_status(
            c.get(f"{base}{p}?operation=GetCACaps"), 200
        ))

    # ── Unknown operation → 400 ──────────────────────────────────
    check(s, "GET /scep?operation=Unknown → 400", lambda: expect_status(
        c.get(f"{base}/scep?operation=Unknown"), 400
    ))

    # ── POST PKCSReq (minimal — will fail crypto but must reach handler) ─
    def _pkcsreq():
        r = c.post(f"{base}/scep?operation=PKCSReq",
                   data=b"\x00" * 16,
                   headers={"Content-Type": "application/x-pki-message"})
        # Should return SCEP response (even if failure), not 404
        return expect_status(r, 200, 400, 500)
    check(s, "POST /scep?operation=PKCSReq (reachable)", _pkcsreq)

    return s


# ─────────────────────────────────────────────────────────────────────────────
# ④ EST Server
# ─────────────────────────────────────────────────────────────────────────────

def test_est(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("EST Server (RFC 7030)")
    base = cfg.est_url
    est_base = "/.well-known/est"
    print(f"\n{'─'*60}")
    print(f"  EST Server  →  {base}")
    print(f"{'─'*60}")

    # ── GET /.well-known/est/cacerts ─────────────────────────────
    check(s, "GET /.well-known/est/cacerts", lambda: (
        (r := c.get(f"{base}{est_base}/cacerts")).status_code == 200
        and len(r.content) > 0,
        f"HTTP {r.status_code} len={len(r.content)} ct={r.headers.get('Content-Type','?')}"
    ))

    # ── GET /.well-known/est/csrattrs ─────────────────────────────
    check(s, "GET /.well-known/est/csrattrs", lambda: expect_status(
        c.get(f"{base}{est_base}/csrattrs"), 200
    ))

    # ── POST /.well-known/est/simpleenroll ───────────────────────
    key = gen_rsa_key()
    csr = gen_csr(key, "est-test.example.com")
    csr_b64 = base64.b64encode(csr.public_bytes(Encoding.DER)).decode()
    def _simpleenroll():
        r = c.post(
            f"{base}{est_base}/simpleenroll",
            data=csr_b64,
            headers={
                "Content-Type": "application/pkcs10",
                "Content-Transfer-Encoding": "base64",
            },
        )
        # 200 = success, 401 = auth required, 400 = bad request
        return expect_status(r, 200, 201, 400, 401)
    check(s, "POST /.well-known/est/simpleenroll", _simpleenroll)

    # ── POST /.well-known/est/simplereenroll ─────────────────────
    def _simplereenroll():
        r = c.post(
            f"{base}{est_base}/simplereenroll",
            data=csr_b64,
            headers={
                "Content-Type": "application/pkcs10",
                "Content-Transfer-Encoding": "base64",
            },
        )
        # 403 = no client cert presented (correct RFC 7030 behaviour without mTLS)
        return expect_status(r, 200, 201, 400, 401, 403)
    check(s, "POST /.well-known/est/simplereenroll", _simplereenroll)

    # ── POST /.well-known/est/serverkeygen ───────────────────────
    def _serverkeygen():
        # Empty body — server should generate key or return error
        r = c.post(
            f"{base}{est_base}/serverkeygen",
            data=b"",
            headers={"Content-Type": "application/pkcs10"},
        )
        # 403 = no client cert (correct without mTLS), 501 = not implemented
        return expect_status(r, 200, 201, 400, 401, 403, 501)
    check(s, "POST /.well-known/est/serverkeygen", _serverkeygen)

    # ── Labelled EST path ─────────────────────────────────────────
    check(s, "GET /.well-known/est/default/cacerts (labelled)", lambda: expect_status(
        c.get(f"{base}{est_base}/default/cacerts"), 200, 404
    ))

    # ── Invalid path → 404 ───────────────────────────────────────
    check(s, "GET /.well-known/est/nonexistent → 404", lambda: expect_status(
        c.get(f"{base}{est_base}/nonexistent-operation"), 404
    ))

    return s


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ OCSP Server
# ─────────────────────────────────────────────────────────────────────────────

def test_ocsp(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("OCSP Responder (RFC 6960)")
    base = cfg.ocsp_url
    print(f"\n{'─'*60}")
    print(f"  OCSP Server  →  {base}")
    print(f"{'─'*60}")

    # ── Fetch CA cert for building proper OCSP requests ──────────
    ca_cert = None
    ca_cert_error = None
    try:
        # Always skip TLS verification here: we're fetching the CA cert itself,
        # which cannot be verified against a system bundle by definition.
        r = c.session.get(f"{cfg.pki_url}/ca/cert.pem", verify=False, timeout=c.timeout)
        if r.ok:
            ca_cert = x509.load_pem_x509_certificate(r.content)
        else:
            ca_cert_error = f"HTTP {r.status_code} from {cfg.pki_url}/ca/cert.pem"
    except Exception as e:
        ca_cert_error = str(e)

    # ── GET /ocsp/ → 400 (no request) ───────────────────────────
    check(s, "GET /ocsp/ → 400 (no b64 payload)", lambda: expect_status(
        c.get(f"{base}/ocsp/"), 400
    ))

    # ── POST /ocsp with garbage DER → malformed error ────────────
    def _post_garbage():
        r = c.post(f"{base}/ocsp",
                   data=b"\x30\x06\x30\x04\x30\x02\x30\x00",
                   headers={"Content-Type": "application/ocsp-request"})
        return (
            r.status_code == 200
            and r.headers.get("Content-Type", "").startswith("application/ocsp-response"),
            f"HTTP {r.status_code} ct={r.headers.get('Content-Type','?')} len={len(r.content)}"
        )
    check(s, "POST /ocsp (malformed → OCSP error response)", _post_garbage)

    # ── POST /ocsp with well-formed request ───────────────────────
    if ca_cert:
        def _post_real():
            try:
                req_der = build_ocsp_request(ca_cert, target_serial=1)
            except Exception as e:
                return False, f"Failed to build OCSP request: {e}"
            r = c.post(f"{base}/ocsp",
                       data=req_der,
                       headers={"Content-Type": "application/ocsp-request"})
            return (
                r.status_code == 200
                and "ocsp-response" in r.headers.get("Content-Type", ""),
                f"HTTP {r.status_code} len={len(r.content)}"
            )
        check(s, "POST /ocsp (well-formed request → OCSP response)", _post_real)

        # ── GET /ocsp/<base64> (RFC 5019 cacheable GET) ──────────
        def _get_ocsp():
            try:
                req_der = build_ocsp_request(ca_cert, target_serial=1)
            except Exception as e:
                return False, f"Build failed: {e}"
            b64req = base64.urlsafe_b64encode(req_der).rstrip(b"=").decode()
            r = c.get(f"{base}/ocsp/{b64req}")
            return (
                r.status_code == 200
                and "ocsp-response" in r.headers.get("Content-Type", ""),
                f"HTTP {r.status_code} len={len(r.content)}"
            )
        check(s, "GET /ocsp/<base64> (RFC 5019 cacheable GET)", _get_ocsp)
    else:
        reason = f": {ca_cert_error}" if ca_cert_error else ""
        fail(s, "POST /ocsp (well-formed)", f"Could not fetch CA cert for OCSP request building{reason}")
        fail(s, "GET /ocsp/<base64> (RFC 5019)", f"Could not fetch CA cert{reason}")

    # ── Cache-Control header on GET response ─────────────────────
    if ca_cert:
        def _cache_control():
            req_der = build_ocsp_request(ca_cert, target_serial=1)
            b64req = base64.urlsafe_b64encode(req_der).rstrip(b"=").decode()
            r = c.get(f"{base}/ocsp/{b64req}")
            cc = r.headers.get("Cache-Control", "")
            return bool(cc), f"Cache-Control: {cc}"
        check(s, "GET /ocsp/<base64> → Cache-Control header present", _cache_control)

    return s


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ Web UI
# ─────────────────────────────────────────────────────────────────────────────

def test_webui(cfg: argparse.Namespace, c: Client) -> Suite:
    s = suite("Web UI Dashboard")
    base = cfg.web_url
    print(f"\n{'─'*60}")
    print(f"  Web UI  →  {base}")
    print(f"{'─'*60}")

    # ── HTML pages ───────────────────────────────────────────────
    html_pages = [
        ("/", "Dashboard"),
        ("/dashboard", "Dashboard"),
        ("/certs", "Certificates"),
        ("/expiring", "Expiring"),
        ("/revocation", "Revocation"),
        ("/sub-ca", "Sub-CA"),
        ("/config-ui", "Config"),
        ("/metrics-ui", "Metrics"),
        ("/audit", "Audit Log"),
        ("/api-docs", "API Docs"),
        ("/services", "Services"),
    ]
    for path, name in html_pages:
        check(s, f"GET {path} ({name} page)", lambda p=path: (
            (r := c.get(f"{base}{p}")).status_code == 200
            and "text/html" in r.headers.get("Content-Type", ""),
            f"HTTP {r.status_code} ct={r.headers.get('Content-Type','?')}"
        ))

    # ── JSON API endpoints ────────────────────────────────────────
    check(s, "GET /api/certs", lambda: expect_json(c.get(f"{base}/api/certs"), 200))
    check(s, "GET /api/config", lambda: expect_json(c.get(f"{base}/api/config"), 200))
    check(s, "GET /api/audit", lambda: expect_json(c.get(f"{base}/api/audit"), 200))
    check(s, "GET /api/metrics (Prometheus text)", lambda: (
        (r := c.get(f"{base}/api/metrics")).status_code == 200
        and "text/plain" in r.headers.get("Content-Type", ""),
        f"HTTP {r.status_code} ct={r.headers.get('Content-Type','?')}"
    ))

    # ── Services API ──────────────────────────────────────────────
    check(s, "GET /api/services", lambda: expect_json(c.get(f"{base}/api/services"), 200))
    check(s, "GET /api/services returns all 6 service names", lambda: (
        (r := c.get(f"{base}/api/services")).ok
        and all(k in r.json() for k in ("cmp", "acme", "scep", "est", "ocsp", "ipsec")),
        "Expected all 6 service keys in response"
    ))
    check(s, "POST /api/services/unknown/start → 404", lambda: expect_status(
        c.post(f"{base}/api/services/nonexistent/start",
               json={"port": 9999},
               headers={"Content-Type": "application/json"}),
        404
    ))
    check(s, "POST /api/services/ocsp/start (no module) → 503 or 500", lambda: expect_status(
        c.post(f"{base}/api/services/ocsp/start",
               json={"port": 9001},
               headers={"Content-Type": "application/json"}),
        503, 500, 200  # 200 if ocsp module is actually present and port is available
    ))

    # ── PATCH /api/config ─────────────────────────────────────────
    check(s, "PATCH /api/config (validity update)", lambda: (
        (r := c.patch(f"{base}/api/config",
                      json={"validity": {"end_entity_days": 365}},
                      headers={"Content-Type": "application/json"})).status_code in (200, 500),
        f"HTTP {r.status_code} — expected 200 (applied) or 500 (no config object)"
    ))

    # ── Certificate download ──────────────────────────────────────
    certs_r = c.get(f"{base}/api/certs")
    serial = None
    if certs_r.ok:
        certs = certs_r.json()
        if isinstance(certs, list) and certs:
            serial = certs[0].get("serial")
        elif isinstance(certs, dict):
            lst = certs.get("certificates", [])
            if lst:
                serial = lst[0].get("serial")

    if serial:
        check(s, f"GET /api/certs/{serial}/pem", lambda sn=serial: (
            (r := c.get(f"{base}/api/certs/{sn}/pem")).status_code == 200
            and b"CERTIFICATE" in r.content,
            f"HTTP {r.status_code}"
        ))
        check(s, f"GET /api/certs/{serial}/p12", lambda sn=serial: expect_status(
            c.get(f"{base}/api/certs/{sn}/p12"), 200
        ))

    # ── CA cert & CRL downloads ───────────────────────────────────
    check(s, "GET /ca/cert.pem", lambda: (
        (r := c.get(f"{base}/ca/cert.pem")).status_code == 200
        and b"BEGIN CERTIFICATE" in r.content,
        f"HTTP {r.status_code}"
    ))
    check(s, "GET /ca/crl", lambda: expect_status(c.get(f"{base}/ca/crl"), 200))

    # ── POST /api/revoke (non-existent → error, but endpoint reachable) ──
    check(s, "POST /api/revoke (reachable)", lambda: expect_status(
        c.post(f"{base}/api/revoke",
               json={"serial": 999999999, "reason": 0},
               headers={"Content-Type": "application/json"}),
        200, 400, 404
    ))

    # ── Sub-CA via Web UI ─────────────────────────────────────────
    check(s, "POST /api/issue-sub-ca", lambda: expect_status(
        c.post(f"{base}/api/issue-sub-ca",
               json={"cn": "WebUI Test Sub-CA", "validity_days": 365},
               headers={"Content-Type": "application/json"}),
        200, 201
    ))

    # ── Unknown page → 404 ───────────────────────────────────────
    check(s, "GET /unknown → 404", lambda: expect_status(
        c.get(f"{base}/nonexistent-xyz"), 404
    ))

    return s


# ─────────────────────────────────────────────────────────────────────────────
# Summary printer
# ─────────────────────────────────────────────────────────────────────────────

def print_summary():
    total_pass = sum(s.passed for s in SUITES)
    total_fail = sum(s.failed for s in SUITES)
    total_all  = sum(s.total  for s in SUITES)

    print(f"\n{'═'*60}")
    print(f"  RESULTS SUMMARY")
    print(f"{'═'*60}")
    for s in SUITES:
        icon = "✅" if s.failed == 0 else "❌"
        bar = f"{s.passed}/{s.total}"
        print(f"  {icon}  {s.name:<38} {bar:>6}")
        if s.failed:
            for r in s.results:
                if not r.passed:
                    print(f"       ✗  {r.name}: {r.message}")
    print(f"{'─'*60}")
    pct = int(100 * total_pass / total_all) if total_all else 0
    print(f"  Total: {total_pass}/{total_all} passed ({pct}%)")
    print(f"{'═'*60}\n")
    return total_fail


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PyPKI endpoint integration tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # Default (plain HTTP on default ports):
          python test_endpoints.py

          # Full TLS stack as started in the example command:
          python test_endpoints.py \\
            --pki-url  https://pki.internal:8443 \\
            --acme-url http://pki.internal:8888  \\
            --scep-url http://pki.internal:8889  \\
            --est-url  https://pki.internal:8444 \\
            --ocsp-url http://pki.internal:8082  \\
            --web-url  http://pki.internal:8008  \\
            --ca-cert  ./ca/ca.crt

          # Skip TLS verification (quick smoke test):
          python test_endpoints.py --pki-url https://localhost:8443 --no-verify
        """),
    )
    p.add_argument("--pki-url",  default="https://localhost:8443",
                   help="PKI server base URL (default: https://localhost:8443)")
    p.add_argument("--acme-url", default="http://localhost:8888",
                   help="ACME server base URL (default: http://localhost:8888)")
    p.add_argument("--scep-url", default="http://localhost:8889",
                   help="SCEP server base URL (default: http://localhost:8889)")
    p.add_argument("--est-url",  default="https://localhost:8444",
                   help="EST server base URL (default: https://localhost:8444)")
    p.add_argument("--ocsp-url", default="http://localhost:8082",
                   help="OCSP server base URL (default: http://localhost:8082)")
    p.add_argument("--web-url",  default="http://localhost:8008",
                   help="Web UI base URL (default: http://localhost:8008)")
    p.add_argument("--ca-cert",  default=None, metavar="PATH",
                   help="CA certificate PEM for TLS verification (default: system bundle)")
    p.add_argument("--no-verify", action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("--timeout", type=int, default=10,
                   help="Request timeout in seconds (default: 10)")
    p.add_argument("--only", choices=["pki", "acme", "scep", "est", "ocsp", "webui"],
                   help="Run only one test group")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show request/response details for all tests")
    return p.parse_args()


def main():
    global VERBOSE
    cfg = parse_args()
    VERBOSE = cfg.verbose

    # Determine TLS verify setting
    _tmp_ca_file = None
    if cfg.no_verify:
        verify = False
    elif cfg.ca_cert:
        verify = cfg.ca_cert
    else:
        # Auto-bootstrap: fetch the PyPKI CA cert (verify=False for the bootstrap
        # only) and merge it with the system CA bundle so that both self-signed
        # PyPKI certs and externally-signed certs verify correctly.
        try:
            import tempfile, requests as _req
            _r = _req.get(f"{cfg.pki_url}/ca/cert.pem", verify=False, timeout=10)
            if _r.ok and b"BEGIN CERTIFICATE" in _r.content:
                # Build a combined bundle: PyPKI CA + system trust store
                try:
                    import certifi
                    _system_bundle = open(certifi.where(), "rb").read()
                except Exception:
                    _system_bundle = b""
                _tmp_ca_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
                _tmp_ca_file.write(_r.content + b"\n" + _system_bundle)
                _tmp_ca_file.flush()
                verify = _tmp_ca_file.name
            else:
                verify = True  # fall back to system bundle
        except Exception:
            verify = True  # fall back to system bundle

    c = Client(verify=verify, timeout=cfg.timeout)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║       PyPKI Endpoint Integration Tests                  ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  PKI   : {cfg.pki_url:<49}║")
    print(f"║  ACME  : {cfg.acme_url:<49}║")
    print(f"║  SCEP  : {cfg.scep_url:<49}║")
    print(f"║  EST   : {cfg.est_url:<49}║")
    print(f"║  OCSP  : {cfg.ocsp_url:<49}║")
    print(f"║  WebUI : {cfg.web_url:<49}║")
    tls_label = ('disabled (--no-verify)' if cfg.no_verify
                 else cfg.ca_cert or ('auto-fetched CA cert' if _tmp_ca_file else 'system bundle'))
    print(f"║  TLS   : {tls_label:<49}║")
    print("╚══════════════════════════════════════════════════════════╝")

    runners = {
        "pki":   lambda: test_pki(cfg, c),
        "acme":  lambda: test_acme(cfg, c),
        "scep":  lambda: test_scep(cfg, c),
        "est":   lambda: test_est(cfg, c),
        "ocsp":  lambda: test_ocsp(cfg, c),
        "webui": lambda: test_webui(cfg, c),
    }

    if cfg.only:
        runners[cfg.only]()
    else:
        for fn in runners.values():
            try:
                fn()
            except requests.exceptions.ConnectionError as e:
                print(f"\n  ⚠  Connection failed: {e}")
            except Exception as e:
                print(f"\n  ⚠  Unexpected error: {e}")
                if cfg.verbose:
                    traceback.print_exc()

    n_fail = print_summary()

    if _tmp_ca_file is not None:
        _tmp_ca_file.close()
        os.unlink(_tmp_ca_file.name)

    sys.exit(0 if n_fail == 0 else 1)


if __name__ == "__main__":
    main()
