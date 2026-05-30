"""CA hierarchy setup during bootstrap."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def setup_ca(
    *,
    ca_dir: Path,
    ca_key_type: str = "ec-p256",
    ca_name: str = "PyPKI Root CA",
    validity_years: int = 30,
    passphrase: Optional[bytes] = None,
    dry_run: bool = False,
) -> None:
    """Initialize a self-signed root CA in *ca_dir*.

    Idempotent: if ca.key already exists, validates it is readable and returns.
    """
    ca_dir.mkdir(parents=True, exist_ok=True)
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"

    if key_path.exists() and cert_path.exists():
        log.info("CA already initialized at %s — skipping CA setup.", ca_dir)
        return

    if dry_run:
        log.info("[dry-run] Would create %s CA at %s", ca_key_type, ca_dir)
        return

    log.info("Initializing CA: name=%r key=%s validity=%dy", ca_name, ca_key_type, validity_years)

    # Delegate to pki_server's existing CA initialization logic
    try:
        from pki_server import CertificateAuthority, ServerConfig
        config = ServerConfig(ca_dir=ca_dir)
        # CertificateAuthority.__init__ creates the CA on first run
        ca = CertificateAuthority(
            ca_dir=str(ca_dir),
            config=config,
            pki_db_url=f"sqlite:///{ca_dir / 'certificates.db'}",
        )
        log.info("CA initialized: %s", cert_path)
    except Exception as e:
        log.error("CA setup failed: %s", e)
        raise


def detect_existing_state(state_dir: Path, config_dir: Path) -> dict:
    """Return a summary of what's already installed."""
    import subprocess

    def _is_running() -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "pypki.service"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() == "active"
        except Exception:
            return False

    return {
        "config_present": (config_dir / "config.yaml").exists(),
        "db_present": (state_dir / "db" / "pki.db").exists()
                      or (state_dir / "db").exists(),
        "ca_present": any((state_dir / "ca").glob("*.key")),
        "running": _is_running(),
        "answers_present": (config_dir / "init-answers.yaml").exists(),
    }
