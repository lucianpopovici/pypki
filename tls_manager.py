"""
TLS context manager with hot-rotation support (CLAUDE-tls-bootstrap.md).

Supports three deployment patterns:
  A: self-bootstrap — PyPKI issues its own admin cert from its own CA.
  B: external-frontend — nginx terminates TLS; PyPKI serves plaintext on loopback.
  C: external-cert — operator provides cert+key; PyPKI reloads on SIGHUP or
     pypki_admin.py tls-replace.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import ssl
import threading
from pathlib import Path
from typing import Callable, Optional, Tuple

log = logging.getLogger(__name__)

# TLS 1.2+ only; forward-secret cipher suites (TLS 1.3 has its own list).
SECURE_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
])


def _serial_of(cert_path: Path) -> str:
    """Return the hex serial of the cert at *cert_path*, or '?' on error."""
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return hex(cert.serial_number)
    except Exception:
        return "?"


def _cert_not_valid_after(cert_path: Path) -> Optional[datetime.datetime]:
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return cert.not_valid_after_utc
    except Exception:
        return None


class TLSManager:
    """Thread-safe TLS context holder with hot-rotation.

    Every call to :meth:`context` returns the *currently active*
    ``ssl.SSLContext``.  Callers hold a reference to it for the duration
    of a single connection; next connection picks up whatever is current.

    Rotation is atomic: ``_context`` is replaced under ``_lock`` so
    no caller sees a partial state.
    """

    def __init__(self, cert_path: Path, key_path: Path) -> None:
        self._lock = threading.Lock()
        self._active_paths: Tuple[Path, Path] = (cert_path, key_path)
        self._context = self._build_context(cert_path, key_path)
        self._rotation_history: list[dict] = []
        self._audit_fn: Optional[Callable[[str, dict], None]] = None

    def set_audit_fn(self, fn: Callable[[str, dict], None]) -> None:
        """Wire in an audit-log callback: fn(event_name, details_dict)."""
        self._audit_fn = fn

    @staticmethod
    def _build_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(SECURE_CIPHERS)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        # Disable session tickets: long-lived tickets weaken FS in single-server deployments.
        ctx.options |= getattr(ssl, "OP_NO_TICKET", 0)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx

    def context(self) -> ssl.SSLContext:
        """Return the active SSLContext (thread-safe)."""
        with self._lock:
            return self._context

    def active_paths(self) -> Tuple[Path, Path]:
        """Return (cert_path, key_path) for the currently active material."""
        with self._lock:
            return self._active_paths

    def rotate(self, cert_path: Path, key_path: Path) -> None:
        """Hot-rotate to new TLS material.

        Builds a fresh SSLContext, validates it loads correctly, then
        atomically replaces the active context.  In-flight connections
        keep the old context; new connections get the new one.

        Raises on invalid cert/key (old context stays active).
        """
        new_ctx = self._build_context(cert_path, key_path)
        new_serial = _serial_of(cert_path)
        with self._lock:
            old_serial = _serial_of(self._active_paths[0])
            self._context = new_ctx
            self._active_paths = (cert_path, key_path)

        record = {
            "old_serial": old_serial,
            "new_serial": new_serial,
            "new_cert": str(cert_path),
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._rotation_history = (self._rotation_history + [record])[-10:]
        if self._audit_fn:
            self._audit_fn("tls_rotated", record)
        log.info("TLS cert rotated: serial %s → %s", old_serial, new_serial)

    def rotation_history(self) -> list[dict]:
        """Return the last 10 rotation records."""
        with self._lock:
            return list(self._rotation_history)

    def check_and_rotate_if_needed(
        self,
        issue_fn: Callable[[], Tuple[Path, Path]],
        renewal_fraction: float = 1.0 / 3,
    ) -> bool:
        """Check remaining lifetime; call *issue_fn* and rotate if < fraction.

        Returns True if rotation happened.
        """
        cert_path, _ = self.active_paths()
        nva = _cert_not_valid_after(cert_path)
        if nva is None:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        # Derive total lifetime from the cert itself
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            total = (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds()
        except Exception:
            total = 90 * 86400
        remaining = (nva - now).total_seconds()
        if remaining < total * renewal_fraction:
            new_cert, new_key = issue_fn()
            self.rotate(new_cert, new_key)
            return True
        return False

    def status(self) -> dict:
        """Return a human-readable status dict for pypki_admin.py tls-status."""
        cert_path, key_path = self.active_paths()
        nva = _cert_not_valid_after(cert_path)
        days_left: Optional[int] = None
        serial = "?"
        algo = "?"
        subject = "?"
        if nva:
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (nva - now).days
            try:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                serial = hex(cert.serial_number)
                subject = cert.subject.rfc4514_string()
                pub = cert.public_key()
                algo = type(pub).__name__
            except Exception:
                pass
        return {
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "serial": serial,
            "subject": subject,
            "algorithm": algo,
            "not_valid_after": nva.isoformat() if nva else None,
            "days_remaining": days_left,
            "rotation_history": self.rotation_history(),
        }


def generate_self_signed_bootstrap(
    hostname: str,
    cert_path: Path,
    key_path: Path,
    validity_hours: int = 24,
) -> None:
    """Generate a 24h self-signed ECDSA P-256 bootstrap cert for *hostname*.

    Writes cert_path (PEM) and key_path (PEM, mode 0600).  Used by
    ``pypki init`` before the CA has been bootstrapped — resolves the
    chicken-and-egg problem.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import os

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    # Determine subject alternative names
    san_list: list[x509.GeneralName] = []
    try:
        san_list.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        san_list.append(x509.DNSName(hostname))
    # Always add localhost / loopback for local access
    if hostname not in ("localhost", "127.0.0.1"):
        san_list.append(x509.DNSName("localhost"))
        san_list.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=validity_hours))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    log.info(
        "Generated bootstrap TLS cert for %s (valid %dh) at %s",
        hostname, validity_hours, cert_path,
    )
