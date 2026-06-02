#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Authentication backends and DB-backed session store for PyPKI SSO.

Provides:
  - OIDCConfig   — OIDC client parameters
  - JWKSCache    — thread-safe JWKS cache with TTL + kid-miss refresh
  - DbSessionStore — DB-backed replacement for the in-memory SessionStore
  - map_roles()  — IdP group → PyPKI role mapping
  - encode/decode_flow_cookie() — HMAC-signed short-lived state/PKCE cookie

No new pip dependencies: uses stdlib + cryptography + db.py.
"""

import dataclasses
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from typing import Optional, List

log = logging.getLogger("pypki.auth")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Authentication / authorization failure."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class OIDCConfig:
    """OIDC client configuration (loaded from CLI flags)."""
    issuer:                str
    client_id:             str
    client_secret:         str
    redirect_uri:          str
    identity_claim:        str  = "email"
    roles_claim:           str  = "groups"
    role_map:              dict = dataclasses.field(default_factory=dict)
    default_role:          str  = "pki:viewer"
    session_ttl:           int  = 8 * 3600    # seconds
    jwks_refresh_interval: int  = 86400       # seconds


# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------

class JWKSCache:
    """
    Thread-safe JWKS cache with TTL-based refresh and kid-miss refresh.

    Loads OIDC discovery + JWKS at startup. Caches in the ``sso_jwks_cache``
    table so a restart doesn't hammer the IdP. Falls back to cached keys if
    the IdP is unreachable, backing off 5 minutes between retries.
    """

    BACKOFF_SECONDS = 300

    def __init__(self, db, config: OIDCConfig) -> None:
        import oidc as _oidc
        self._db     = db
        self._config = config
        self._oidc   = _oidc
        self._lock   = threading.Lock()
        self._discovery: Optional[dict] = None
        self._jwks:      Optional[list] = None
        self._last_fetch = 0
        self._last_fail  = 0
        self._failed     = False

    def startup_load(self) -> bool:
        """Fetch discovery + JWKS at startup. Returns True on success."""
        try:
            self._discovery = self._oidc.fetch_discovery(self._config.issuer)
            self._jwks      = self._oidc.fetch_jwks(self._discovery["jwks_uri"])
            self._last_fetch = int(time.time())
            self._db.execute(
                "INSERT OR REPLACE INTO sso_jwks_cache (issuer, jwks_json, fetched_at) "
                "VALUES (?, ?, ?)",
                (self._config.issuer, json.dumps(self._jwks), self._last_fetch),
            )
            log.info("OIDC discovery loaded: issuer=%s", self._config.issuer)
            return True
        except Exception as exc:
            log.error("OIDC discovery failed (%s) — falling back to PAM", exc)
            self._failed = True
            # Try loading from DB cache
            row = self._db.fetchone(
                "SELECT jwks_json FROM sso_jwks_cache WHERE issuer = ?",
                (self._config.issuer,),
            )
            if row:
                self._jwks = json.loads(row["jwks_json"])
                log.warning("Using stale JWKS from DB cache for issuer=%s", self._config.issuer)
            return False

    def get_jwks(self) -> list:
        """Return current JWKS, refreshing if the TTL has expired."""
        with self._lock:
            return self._get_jwks_locked()

    def _get_jwks_locked(self) -> list:
        now = int(time.time())
        if self._jwks and (now - self._last_fetch) < self._config.jwks_refresh_interval:
            return self._jwks
        if self._failed and (now - self._last_fail) < self.BACKOFF_SECONDS:
            return self._jwks or []
        self._refresh_locked()
        return self._jwks or []

    def _refresh_locked(self) -> None:
        try:
            if self._discovery is None:
                self._discovery = self._oidc.fetch_discovery(self._config.issuer)
            self._jwks       = self._oidc.fetch_jwks(self._discovery["jwks_uri"])
            self._last_fetch = int(time.time())
            self._failed     = False
            self._db.execute(
                "INSERT OR REPLACE INTO sso_jwks_cache (issuer, jwks_json, fetched_at) "
                "VALUES (?, ?, ?)",
                (self._config.issuer, json.dumps(self._jwks), self._last_fetch),
            )
        except Exception as exc:
            log.warning("JWKS refresh failed: %s", exc)
            self._failed    = True
            self._last_fail = int(time.time())

    def get_jwks_for_kid(self, kid: str) -> list:
        """Return JWKS, forcing a refresh if *kid* is not present."""
        with self._lock:
            jwks = self._get_jwks_locked()
            if any(k.get("kid") == kid for k in jwks):
                return jwks
            # kid-miss: force one refresh (unless in backoff)
            now = int(time.time())
            if self._failed and (now - self._last_fail) < self.BACKOFF_SECONDS:
                return jwks
            self._last_fetch = 0  # force refresh
            self._refresh_locked()
            return self._jwks or []

    @property
    def authorization_endpoint(self) -> str:
        return (self._discovery or {}).get("authorization_endpoint", "")

    @property
    def token_endpoint(self) -> str:
        return (self._discovery or {}).get("token_endpoint", "")

    @property
    def available(self) -> bool:
        return self._discovery is not None


# ---------------------------------------------------------------------------
# DB-backed session store
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class SessionRecord:
    session_id:   str
    auth_backend: str
    identity:     str
    idp_subject:  Optional[str]
    idp_issuer:   Optional[str]
    roles:        List[str]
    created_at:   int
    expires_at:   int
    last_seen_at: int
    revoked:      bool


class DbSessionStore:
    """
    DB-backed session store.  Replaces the in-memory SessionStore in web_ui.py.

    Provides the same interface (``create``, ``validate``, ``invalidate``,
    ``record_failure``, ``is_locked_out``, ``clear_failures``, ``purge_expired``)
    so existing PAM login code needs minimal changes. PAM sessions are stored
    with ``auth_backend='pam'``; OIDC sessions with ``auth_backend='oidc'``;
    long-lived API tokens with ``auth_backend='token'``.

    Thread-safety: all DB writes go through the DAL (thread-local connections
    for SQLite, connection pool for Postgres). The brute-force failure map is
    in-memory (resets on restart; intentional — it's a DoS defence, not state).
    """

    COOKIE_NAME             = "pypki_session"
    SESSION_LIFETIME_SECONDS = 8 * 3600
    MAX_FAILURES            = 10
    LOCKOUT_SECONDS         = 300

    def __init__(self, db) -> None:
        self._db    = db
        self._lock  = threading.Lock()
        self._failures: dict = {}  # ip → (count, since)

    # ---- Session lifecycle ----

    def create(
        self,
        identity: str,
        auth_backend: str = "pam",
        roles: Optional[List[str]] = None,
        ttl_seconds: Optional[int] = None,
        idp_subject: Optional[str] = None,
        idp_issuer: Optional[str] = None,
    ) -> str:
        """Create a new session and return the opaque session token."""
        now = int(time.time())
        ttl = ttl_seconds if ttl_seconds is not None else self.SESSION_LIFETIME_SECONDS
        session_id = secrets.token_urlsafe(32)
        self._db.execute(
            "INSERT INTO sso_sessions "
            "(session_id, auth_backend, identity, idp_subject, idp_issuer, "
            "roles, created_at, expires_at, last_seen_at, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (session_id, auth_backend, identity,
             idp_subject, idp_issuer,
             json.dumps(roles or []),
             now, now + ttl, now),
        )
        return session_id

    def validate(self, session_id: str) -> Optional[str]:
        """Return the identity (username/email) if the session is valid, else None."""
        rec = self.validate_record(session_id)
        return rec.identity if rec else None

    def validate_record(self, session_id: str) -> Optional[SessionRecord]:
        """Return the full SessionRecord if valid, else None."""
        if not session_id:
            return None
        now = int(time.time())
        row = self._db.fetchone(
            "SELECT session_id, auth_backend, identity, idp_subject, idp_issuer, "
            "roles, created_at, expires_at, last_seen_at, revoked "
            "FROM sso_sessions WHERE session_id = ?",
            (session_id,),
        )
        if row is None:
            return None
        if row["revoked"] or row["expires_at"] < now:
            return None
        self._db.execute(
            "UPDATE sso_sessions SET last_seen_at = ? WHERE session_id = ?",
            (now, session_id),
        )
        return SessionRecord(
            session_id   = row["session_id"],
            auth_backend = row["auth_backend"],
            identity     = row["identity"],
            idp_subject  = row["idp_subject"],
            idp_issuer   = row["idp_issuer"],
            roles        = json.loads(row["roles"] or "[]"),
            created_at   = row["created_at"],
            expires_at   = row["expires_at"],
            last_seen_at = now,
            revoked      = bool(row["revoked"]),
        )

    def invalidate(self, session_id: str) -> None:
        """Revoke a session (logout)."""
        self._db.execute(
            "UPDATE sso_sessions SET revoked = 1 WHERE session_id = ?",
            (session_id,),
        )

    def revoke_by_id(self, session_id: str) -> bool:
        """Admin revocation by session_id. Returns True."""
        self._db.execute(
            "UPDATE sso_sessions SET revoked = 1 WHERE session_id = ?",
            (session_id,),
        )
        return True

    def list_sessions(self, include_expired: bool = False) -> List[dict]:
        """Return sessions; excludes expired+revoked unless *include_expired*."""
        now = int(time.time())
        rows = self._db.fetchall(
            "SELECT session_id, auth_backend, identity, idp_subject, idp_issuer, "
            "roles, created_at, expires_at, last_seen_at, revoked "
            "FROM sso_sessions ORDER BY created_at DESC LIMIT 500",
        )
        out = []
        for row in rows:
            expired = row["expires_at"] < now
            if not include_expired and (expired or row["revoked"]):
                continue
            out.append({
                "session_id":   row["session_id"],
                "auth_backend": row["auth_backend"],
                "identity":     row["identity"],
                "idp_subject":  row["idp_subject"],
                "idp_issuer":   row["idp_issuer"],
                "roles":        json.loads(row["roles"] or "[]"),
                "created_at":   row["created_at"],
                "expires_at":   row["expires_at"],
                "last_seen_at": row["last_seen_at"],
                "revoked":      bool(row["revoked"]),
                "expired":      expired,
            })
        return out

    def purge_expired(self) -> None:
        """Hard-delete sessions that expired more than 1 hour ago."""
        self._db.execute(
            "DELETE FROM sso_sessions WHERE expires_at < ? AND revoked = 1",
            (int(time.time()) - 3600,),
        )

    # ---- Brute-force rate limiting (in-memory) ----

    def record_failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            count, since = self._failures.get(ip, (0, now))
            if now - since > self.LOCKOUT_SECONDS:
                count, since = 0, now
            self._failures[ip] = (count + 1, since)

    def is_locked_out(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            count, since = self._failures.get(ip, (0, 0))
        return (now - since <= self.LOCKOUT_SECONDS) and count >= self.MAX_FAILURES

    def clear_failures(self, ip: str) -> None:
        with self._lock:
            self._failures.pop(ip, None)


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------

def map_roles(claims: dict, config: OIDCConfig) -> List[str]:
    """
    Extract the groups claim and map to PyPKI roles via *config.role_map*.

    Supports dotted claim paths (e.g. ``"resource_access.pypki.roles"``).
    Unknown groups receive *config.default_role* unless it is ``pki:none``.
    """
    raw: Any = claims
    for part in config.roles_claim.split("."):
        if not isinstance(raw, dict):
            raw = []
            break
        raw = raw.get(part, [])

    groups: list = raw if isinstance(raw, list) else ([raw] if raw else [])

    roles: List[str] = []
    for group in groups:
        mapped = config.role_map.get(str(group), "")
        for r in mapped.split(","):
            r = r.strip()
            if r:
                roles.append(r)

    if not roles and config.default_role != "pki:none":
        roles = [config.default_role]

    return roles


# ---------------------------------------------------------------------------
# Flow cookie (short-lived HMAC-signed state+PKCE carrier)
# ---------------------------------------------------------------------------

_FLOW_COOKIE_NAME = "pypki_flow"
_FLOW_COOKIE_TTL  = 600   # 10 minutes


def _derive_flow_key(secret_bytes: bytes) -> bytes:
    """Derive a 32-byte HMAC key from the provided secret material."""
    return hashlib.sha256(b"pypki-oidc-flow-cookie\x00" + secret_bytes).digest()


def encode_flow_cookie(state: str, code_verifier: str, key: bytes) -> str:
    """Return a signed, base64url-encoded cookie value."""
    payload = json.dumps({
        "s":   state,
        "v":   code_verifier,
        "exp": int(time.time()) + _FLOW_COOKIE_TTL,
    }).encode()
    import oidc as _oidc
    sig  = hmac.new(key, payload, hashlib.sha256).digest()
    return _oidc._b64url_encode(payload) + "." + _oidc._b64url_encode(sig)


def decode_flow_cookie(value: str, key: bytes) -> dict:
    """Decode and verify a flow cookie. Raises AuthError on failure."""
    import oidc as _oidc
    try:
        payload_b64, sig_b64 = value.rsplit(".", 1)
    except ValueError:
        raise AuthError("malformed flow cookie")
    try:
        payload  = _oidc._b64url_decode(payload_b64)
        sig      = _oidc._b64url_decode(sig_b64)
    except Exception:
        raise AuthError("flow cookie decode error")
    expected = hmac.new(key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise AuthError("flow cookie signature invalid")
    data = json.loads(payload)
    if data.get("exp", 0) < int(time.time()):
        raise AuthError("flow cookie expired")
    return data
