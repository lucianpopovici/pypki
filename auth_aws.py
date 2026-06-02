#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
AWS authentication helpers — SigV4 request signing and IMDSv2 credential retrieval.

Stdlib only; no boto3 dependency.
"""

import hashlib
import hmac
import http.client
import json
import logging
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

log = logging.getLogger("pypki.auth_aws")

_IMDS_TTL     = 21600   # 6h token TTL for IMDSv2
_CRED_REFRESH = 300     # refresh credentials 5 min before expiry


# ---------------------------------------------------------------------------
# IMDSv2 credential retrieval
# ---------------------------------------------------------------------------

class IMDSv2Credentials:
    """Thread-safe IMDSv2 credential cache with automatic refresh."""

    def __init__(self) -> None:
        self._lock    = threading.Lock()
        self._creds:  Dict[str, str] = {}
        self._expiry: float = 0.0

    def get(self) -> Dict[str, str]:
        with self._lock:
            if time.time() < self._expiry - _CRED_REFRESH and self._creds:
                return self._creds
            self._creds  = _fetch_imdsv2_creds()
            exp_str      = self._creds.get("Expiration", "")
            self._expiry = _parse_aws_iso(exp_str) if exp_str else time.time() + 3600
            return self._creds


def _fetch_imdsv2_creds() -> Dict[str, str]:
    """Fetch temporary credentials from the EC2 IMDSv2 endpoint."""
    base = "http://169.254.169.254"

    # Step 1: get session token
    req = urllib.request.Request(
        f"{base}/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(_IMDS_TTL)},
    )
    with urllib.request.urlopen(req, timeout=2) as r:
        token = r.read().decode().strip()

    headers = {"X-aws-ec2-metadata-token": token}

    # Step 2: get IAM role name
    req2 = urllib.request.Request(
        f"{base}/latest/meta-data/iam/security-credentials/",
        headers=headers,
    )
    with urllib.request.urlopen(req2, timeout=2) as r:
        role = r.read().decode().strip().splitlines()[0]

    # Step 3: get credentials
    req3 = urllib.request.Request(
        f"{base}/latest/meta-data/iam/security-credentials/{role}",
        headers=headers,
    )
    with urllib.request.urlopen(req3, timeout=2) as r:
        return json.loads(r.read())


def _parse_aws_iso(s: str) -> float:
    """Parse an AWS ISO-8601 expiry string like '2026-06-02T14:00:00Z' to epoch."""
    import datetime
    try:
        dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return time.time() + 3600


def load_static_credentials(path: str) -> Dict[str, str]:
    """
    Load static AWS credentials from a JSON file.

    Expected format::

        {
          "AccessKeyId": "AKIA...",
          "SecretAccessKey": "...",
          "SessionToken": ""
        }
    """
    return json.loads(open(path).read())


# ---------------------------------------------------------------------------
# SigV4 request signing
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _sigv4_signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _hmac_sha256(("AWS4" + secret).encode(), date.encode())
    k = _hmac_sha256(k, region.encode())
    k = _hmac_sha256(k, service.encode())
    k = _hmac_sha256(k, b"aws4_request")
    return k


def sigv4_headers(
    method: str,
    url: str,
    body: bytes,
    service: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str = "",
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Return a dict of headers (including Authorization) for a SigV4-signed request.

    Parameters
    ----------
    method          : HTTP method, e.g. "POST"
    url             : Full URL, e.g. "https://kms.us-east-1.amazonaws.com/"
    body            : Request body bytes
    service         : AWS service name, e.g. "kms"
    region          : AWS region, e.g. "us-east-1"
    access_key      : AWS_ACCESS_KEY_ID
    secret_key      : AWS_SECRET_ACCESS_KEY
    session_token   : AWS_SESSION_TOKEN (empty for static long-term creds)
    extra_headers   : Additional headers to include in canonical request
    """
    parsed     = urllib.parse.urlsplit(url)
    host       = parsed.netloc
    uri        = parsed.path or "/"
    query      = parsed.query or ""

    import datetime
    now    = datetime.datetime.now(datetime.timezone.utc)
    t_date = now.strftime("%Y%m%d")
    t_full = now.strftime("%Y%m%dT%H%M%SZ")

    headers: Dict[str, str] = {
        "host":         host,
        "x-amz-date":  t_full,
        "content-type": "application/x-amz-json-1.1",
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    if extra_headers:
        headers.update({k.lower(): v for k, v in extra_headers.items()})

    # Canonical headers — must be sorted
    signed_keys = sorted(headers)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_keys)
    signed_headers_str = ";".join(signed_keys)

    payload_hash = _sha256_hex(body)
    canonical_request = "\n".join([
        method,
        uri,
        query,
        canonical_headers,
        signed_headers_str,
        payload_hash,
    ])

    credential_scope = f"{t_date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        t_full,
        credential_scope,
        _sha256_hex(canonical_request.encode()),
    ])

    signing_key = _sigv4_signing_key(secret_key, t_date, region, service)
    signature   = _hmac_sha256(signing_key, string_to_sign.encode()).hex()

    auth = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, "
        f"Signature={signature}"
    )

    result = {
        "Authorization":    auth,
        "Content-Type":     "application/x-amz-json-1.1",
        "X-Amz-Date":       t_full,
        "Host":             host,
    }
    if session_token:
        result["X-Amz-Security-Token"] = session_token
    if extra_headers:
        result.update(extra_headers)
    return result


def resolve_credentials(
    auth_mode: str = "imdsv2",
    static_file: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Return (access_key, secret_key, session_token).

    auth_mode:
      'imdsv2'  — EC2/ECS IMDSv2 (preferred in cloud; fails fast outside cloud)
      'static'  — static_file JSON
      'env'     — AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN env vars
    """
    if auth_mode == "static" and static_file:
        creds = load_static_credentials(static_file)
        return creds["AccessKeyId"], creds["SecretAccessKey"], creds.get("SessionToken", "")
    if auth_mode == "env":
        return (
            os.environ["AWS_ACCESS_KEY_ID"],
            os.environ["AWS_SECRET_ACCESS_KEY"],
            os.environ.get("AWS_SESSION_TOKEN", ""),
        )
    # Default: IMDSv2
    creds = _fetch_imdsv2_creds()
    return creds["AccessKeyId"], creds["SecretAccessKey"], creds.get("Token", "")
