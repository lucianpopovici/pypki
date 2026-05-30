"""TLS bootstrap setup — generate the 24h self-signed bootstrap cert."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def setup_bootstrap_tls(
    *,
    hostname: str,
    tls_dir: Path,
    validity_hours: int = 24,
    dry_run: bool = False,
) -> tuple[Path, Path]:
    """Generate the bootstrap TLS cert+key for *hostname*.

    Returns (cert_path, key_path).  The key is mode 0600.
    Idempotent if both files exist and the cert is still valid.
    """
    cert_path = tls_dir / "admin-bootstrap.crt"
    key_path = tls_dir / "admin-bootstrap.key"

    if cert_path.exists() and key_path.exists():
        # Verify the cert is still valid
        try:
            import datetime
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            now = datetime.datetime.now(datetime.timezone.utc)
            if cert.not_valid_after_utc > now:
                log.info("Bootstrap TLS cert still valid; skipping regeneration.")
                return cert_path, key_path
        except Exception:
            pass  # Fall through to regenerate

    if dry_run:
        log.info("[dry-run] Would generate 24h bootstrap TLS cert for %s at %s", hostname, tls_dir)
        return cert_path, key_path

    from tls_manager import generate_self_signed_bootstrap
    tls_dir.mkdir(parents=True, exist_ok=True)
    generate_self_signed_bootstrap(
        hostname=hostname,
        cert_path=cert_path,
        key_path=key_path,
        validity_hours=validity_hours,
    )
    log.info("Bootstrap TLS cert written to %s", cert_path)
    return cert_path, key_path
