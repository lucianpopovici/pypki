"""
Stdlib sd_notify shim — sends systemd readiness/watchdog notifications
without requiring python-systemd.  Uses a plain SOCK_DGRAM sendto(2)
to $NOTIFY_SOCKET (POSIX or abstract-namespace socket).
"""
import os
import socket
import threading
import time
from typing import Callable, Optional


def sd_notify(state: str) -> bool:
    """Send an arbitrary sd_notify state string. Returns False if not running
    under systemd (NOTIFY_SOCKET not set), True on success."""
    sock_path = os.environ.get("NOTIFY_SOCKET")
    if not sock_path:
        return False
    if sock_path.startswith("@"):
        # Abstract namespace socket
        sock_path = "\0" + sock_path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(state.encode(), sock_path)
        return True
    except OSError:
        return False


def ready() -> bool:
    """Notify systemd that the service is ready to accept connections."""
    return sd_notify("READY=1")


def reloading() -> bool:
    """Notify systemd that the service is reloading configuration."""
    return sd_notify("RELOADING=1")


def stopping() -> bool:
    """Notify systemd that the service is stopping."""
    return sd_notify("STOPPING=1")


def watchdog() -> bool:
    """Send a watchdog keepalive to prevent systemd from restarting the service."""
    return sd_notify("WATCHDOG=1")


def status(msg: str) -> bool:
    """Set a human-readable status string visible in 'systemctl status'."""
    return sd_notify(f"STATUS={msg}")


def watchdog_interval() -> Optional[float]:
    """Return the WatchdogSec interval in seconds, or None if not set.
    Returns half the configured interval (send at 2× the required rate)."""
    val = os.environ.get("WATCHDOG_USEC")
    if not val:
        return None
    try:
        return int(val) / 2_000_000  # usec → sec, half the interval
    except ValueError:
        return None


class WatchdogThread:
    """Background thread that sends sd_notify(WATCHDOG=1) periodically.

    Stops automatically when *liveness_fn* returns False, allowing the
    service to signal systemd that it is unhealthy and should be restarted.

    Usage::

        wdt = WatchdogThread(interval=30)
        wdt.start()
        # ... on shutdown:
        wdt.stop()
    """

    def __init__(
        self,
        interval: float = 30.0,
        liveness_fn: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._interval = interval
        self._liveness_fn = liveness_fn or (lambda: True)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="sd-watchdog", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        while not self._stop_event.wait(timeout=self._interval):
            if not self._liveness_fn():
                # Do NOT send watchdog — systemd will restart us.
                return
            watchdog()
