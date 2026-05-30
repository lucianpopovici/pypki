"""Install the systemd unit file during bootstrap."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_UNIT_SRC = Path(__file__).parent.parent / "packaging" / "systemd" / "pypki.service"
_UNIT_DST = Path("/etc/systemd/system/pypki.service")


def _is_systemd() -> bool:
    try:
        with open("/proc/1/comm") as f:
            return "systemd" in f.read()
    except OSError:
        return False


def install_systemd_unit(*, dry_run: bool = False) -> bool:
    """Copy packaging/systemd/pypki.service to /etc/systemd/system/.

    Returns True if systemd is available and the unit was installed.
    """
    if not _is_systemd():
        log.info("PID 1 is not systemd; skipping unit installation.")
        return False

    if not _UNIT_SRC.exists():
        log.warning("Unit file not found at %s; skipping.", _UNIT_SRC)
        return False

    if dry_run:
        log.info("[dry-run] Would install %s → %s", _UNIT_SRC, _UNIT_DST)
        log.info("[dry-run] Would: systemctl daemon-reload && systemctl enable pypki.service")
        return True

    try:
        shutil.copy2(_UNIT_SRC, _UNIT_DST)
        os.chmod(_UNIT_DST, 0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(["systemctl", "enable", "pypki.service"], check=True, capture_output=True)
        log.info("systemd unit installed and enabled.")
        return True
    except Exception as e:
        log.warning("Could not install systemd unit (need root?): %s", e)
        return False


def start_service(dry_run: bool = False) -> bool:
    if dry_run:
        log.info("[dry-run] Would: systemctl start pypki.service")
        return True
    try:
        subprocess.run(["systemctl", "start", "pypki.service"], check=True, capture_output=True)
        log.info("pypki.service started.")
        return True
    except Exception as e:
        log.warning("Could not start pypki.service: %s", e)
        return False
