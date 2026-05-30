"""Firewall stack detection and template application."""
from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent / "packaging" / "firewall"


def _service_active(name: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def detect_firewall_stack() -> str:
    """Return the active firewall stack name or 'none'."""
    if shutil.which("nft") and _service_active("nftables"):
        return "nftables"
    if shutil.which("ufw") and _service_active("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd") and _service_active("firewalld"):
        return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "none"


def detect_mac() -> str:
    """Return 'apparmor', 'selinux', or 'none'."""
    if Path("/sys/kernel/security/apparmor").exists():
        return "apparmor"
    if Path("/sys/fs/selinux").exists():
        return "selinux"
    return "none"


def apply_firewall_template(stack: Optional[str] = None, *, dry_run: bool = False) -> bool:
    """Apply the appropriate firewall template for the detected (or given) stack.

    Returns True if something was applied.
    """
    if stack is None:
        stack = detect_firewall_stack()

    if stack == "none":
        log.warning("No active firewall stack detected. Install nftables or ufw.")
        return False

    if stack == "nftables":
        src = _TEMPLATES_DIR / "nftables" / "pypki.nft"
        if dry_run:
            log.info("[dry-run] Would nft -f %s", src)
            return True
        try:
            subprocess.run(["nft", "-f", str(src)], check=True, capture_output=True)
            log.info("nftables rules applied from %s", src)
            return True
        except Exception as e:
            log.error("nft apply failed: %s", e)
            return False

    if stack == "ufw":
        src = _TEMPLATES_DIR / "ufw" / "setup-ufw.sh"
        if dry_run:
            log.info("[dry-run] Would run %s", src)
            return True
        try:
            subprocess.run(["bash", str(src)], check=True, capture_output=True)
            log.info("ufw rules applied from %s", src)
            return True
        except Exception as e:
            log.error("ufw setup failed: %s", e)
            return False

    log.info("Firewall stack %r detected; apply template manually: packaging/firewall/%s/", stack, stack)
    return False
