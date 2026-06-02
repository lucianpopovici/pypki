#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
OIDC/JWS primitives for PyPKI SSO.

Stdlib + cryptography only; no new pip dependencies.
Implements Authorization Code Flow with PKCE (RFC 7636).
JWS verification: RS256, ES256, EdDSA (RFC 7515/7517/8037).
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request
from typing import Any, Optional


class AuthError(Exception):
    """Raised on any OIDC/JWS validation failure."""


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int_from_b64url(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def _aud_list(aud: Any) -> list:
    if isinstance(aud, list):
        return aud
    if aud is None:
        return []
    return [aud]


# ---------------------------------------------------------------------------
# JWKS key builders
# ---------------------------------------------------------------------------

def _find_jwk(jwks: list, kid: str) -> dict:
    for key in jwks:
        if key.get("kid") == kid:
            return key
    raise AuthError(f"kid not found in JWKS: {kid!r}")


def _build_rsa_public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import rsa
    n = _int_from_b64url(jwk["n"])
    e = _int_from_b64url(jwk["e"])
    return rsa.RSAPublicNumbers(e, n).public_key()


def _build_ec_public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ec
    crv = jwk.get("crv", "P-256")
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(crv)
    if curve is None:
        raise AuthError(f"unsupported EC curve: {crv!r}")
    x = _int_from_b64url(jwk["x"])
    y = _int_from_b64url(jwk["y"])
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()


def _build_eddsa_public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    crv = jwk.get("crv", "Ed25519")
    if crv != "Ed25519":
        raise AuthError(f"unsupported EdDSA curve: {crv!r}")
    raw = _b64url_decode(jwk["x"])
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# JWS signature verification
# ---------------------------------------------------------------------------

def _verify_jws_sig(jwk: dict, alg: str, message: bytes, sig: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    kty = jwk.get("kty", "")
    try:
        if alg == "RS256" and kty == "RSA":
            pub = _build_rsa_public_key(jwk)
            pub.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())

        elif alg == "ES256" and kty == "EC":
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            pub = _build_ec_public_key(jwk)
            half = len(sig) // 2
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))

        elif alg == "EdDSA" and kty == "OKP":
            pub = _build_eddsa_public_key(jwk)
            pub.verify(sig, message)

        else:
            raise AuthError(f"unsupported alg/kty: {alg}/{kty}")

    except InvalidSignature:
        raise AuthError("signature verification failed")


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

def verify_id_token(
    token: str,
    jwks: list,
    issuer: str,
    audience: str,
    leeway: int = 30,
) -> dict:
    """
    Verify a JWS-signed OIDC ID token.

    Parameters
    ----------
    token    : Raw JWT string (header.payload.sig)
    jwks     : List of JWK dicts from the IdP's jwks_uri
    issuer   : Expected ``iss`` claim value
    audience : Expected value in the ``aud`` claim
    leeway   : Clock-skew tolerance in seconds (default 30)

    Returns the verified claims dict. Raises AuthError on any failure.
    ``alg: none`` and unknown algorithms are rejected before sig check.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed token")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header  = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise AuthError(f"token decode failed: {exc}") from exc

    alg = header.get("alg", "")
    if alg not in {"RS256", "ES256", "EdDSA"}:
        raise AuthError(f"unsupported alg: {alg!r}")

    kid  = header.get("kid", "")
    jwk  = _find_jwk(jwks, kid)
    sig  = _b64url_decode(sig_b64)
    _verify_jws_sig(jwk, alg, f"{header_b64}.{payload_b64}".encode(), sig)

    now = int(time.time())
    if payload.get("iss") != issuer:
        raise AuthError("iss mismatch")
    if audience not in _aud_list(payload.get("aud")):
        raise AuthError("aud mismatch")
    if payload.get("exp", 0) < now - leeway:
        raise AuthError("token expired")
    if payload.get("nbf", 0) > now + leeway:
        raise AuthError("token not yet valid")
    if payload.get("iat", 0) > now + 300:
        raise AuthError("iat in future")

    return payload


# ---------------------------------------------------------------------------
# Network helpers (discovery, JWKS, token exchange)
# ---------------------------------------------------------------------------

def fetch_discovery(issuer: str, timeout: int = 10) -> dict:
    """Fetch the OIDC discovery document from ``{issuer}/.well-known/openid-configuration``."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read())


def fetch_jwks(uri: str, timeout: int = 10) -> list:
    """Fetch the JWKS from *uri* and return the ``keys`` list."""
    with urllib.request.urlopen(uri, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read())
    return data.get("keys", [])


def exchange_code(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    timeout: int = 10,
) -> dict:
    """Exchange an authorization code for tokens (RFC 6749 §4.1.3 + RFC 7636 §4.5)."""
    body = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     client_id,
        "client_secret": client_secret,
        "code_verifier": code_verifier,
    }).encode()
    req = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# PKCE (RFC 7636) and state generation
# ---------------------------------------------------------------------------

def generate_pkce() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256)."""
    verifier   = _b64url_encode(secrets.token_bytes(32))
    challenge  = _b64url_encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def generate_state() -> str:
    """Return a random CSRF state value."""
    return _b64url_encode(secrets.token_bytes(16))


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str = "openid email profile",
) -> str:
    """Build the IdP authorization URL for the Authorization Code + PKCE flow."""
    params = urllib.parse.urlencode({
        "response_type":         "code",
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "state":                 state,
        "scope":                 scope,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    })
    return f"{authorization_endpoint}?{params}"
