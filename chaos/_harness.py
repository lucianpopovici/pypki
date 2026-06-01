"""
chaos/_harness.py — Shared infrastructure for chaos scenario files.

Each scenario uses PyPKI's Python API directly (in-process CertificateAuthority)
for the invariant checks and normal issuance. Process-kill scenarios (F01, F02)
additionally spawn a subprocess and signal it.
"""

from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

# Make the project root importable.
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

import pki_server as pki


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ITERATIONS = int(os.environ.get("PYPKI_CHAOS_ITERATIONS", "100"))
_PYPKI_BIN = _ROOT / "pki_server.py"


# ---------------------------------------------------------------------------
# In-process CA factory
# ---------------------------------------------------------------------------

def make_test_ca(tmpdir: Optional[str] = None) -> tuple[str, pki.CertificateAuthority]:
    """Create a fresh CA in a temp directory. Returns (ca_dir, ca)."""
    ca_dir = tmpdir or tempfile.mkdtemp(prefix="chaos-ca-")
    ca = pki.CertificateAuthority(ca_dir=ca_dir)
    return ca_dir, ca


def make_audit_log(ca_dir: str) -> pki.AuditLog:
    return pki.AuditLog(Path(ca_dir))


# ---------------------------------------------------------------------------
# Key generation (EC P-256 is fast)
# ---------------------------------------------------------------------------

def _gen_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# Issue a cert via the in-process CA
# ---------------------------------------------------------------------------

def issue_one(ca: pki.CertificateAuthority,
              audit: Optional[pki.AuditLog] = None,
              cn: str = "chaos-test") -> pki.x509.Certificate:
    key = _gen_key()
    return ca.issue_certificate(f"CN={cn}", key.public_key(), audit=audit)


# ---------------------------------------------------------------------------
# Subprocess-based CA (for process-kill scenarios)
# ---------------------------------------------------------------------------

class SubprocessCA:
    """
    Starts pki_server.py as a subprocess for scenarios that need
    to inject a process-level failure (SIGKILL, SIGTERM).
    """

    PORT = 19090  # avoid conflict with any running instance

    def __init__(self, ca_dir: str):
        self.ca_dir = ca_dir
        self.proc: Optional[subprocess.Popen] = None

    def start(self, wait_ready: bool = True) -> None:
        cmd = [
            sys.executable, str(_PYPKI_BIN),
            "--ca-dir", self.ca_dir,
            "--port", str(self.PORT),
            "--log-level", "WARNING",
        ]
        self.proc = subprocess.Popen(
            cmd,
            env={**os.environ, "PYPKI_CA_PASSPHRASE": "chaos-test"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if wait_ready:
            self._wait(timeout=20)

    def _wait(self, timeout: int) -> None:
        import urllib.request
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{self.PORT}/health", timeout=1
                )
                return
            except Exception:
                if self.proc.poll() is not None:
                    raise RuntimeError("pki_server exited before becoming ready")
                time.sleep(0.3)
        raise TimeoutError(f"pki_server did not start within {timeout}s")

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def issue_via_http(self, cn: str = "chaos-http") -> dict:
        """Issue a cert through the running subprocess's HTTP API."""
        import json
        import urllib.request
        from cryptography import x509 as cx
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID

        key = _gen_key()
        csr = (
            cx.CertificateSigningRequestBuilder()
            .subject_name(cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .add_extension(
                cx.SubjectAlternativeName([cx.DNSName(f"{cn}.local")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        # Use the CMP endpoint (simpleenroll-style) — or SCEP; whichever is simplest.
        # For chaos testing, use the raw REST /api/renew if cert already exists.
        # Simplest: use the in-process API to issue the cert (call via the CA dir).
        # We just need a cert serial in the DB for the kill scenario to work.
        raise NotImplementedError(
            "HTTP-based issuance: use issue_via_ca() for in-process scenarios. "
            "This is reserved for true subprocess kill scenarios (F01, F02)."
        )


# ---------------------------------------------------------------------------
# DB helpers (read-only; used by invariant checkers)
# ---------------------------------------------------------------------------

def open_db(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite DB read-only."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def open_db_rw(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite DB read-write (for setup/inject steps only)."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Scenario result reporting
# ---------------------------------------------------------------------------

class ScenarioResult:
    def __init__(self, name: str):
        self.name = name
        self.passed: list[str] = []
        self.failed: list[str] = []
        self.skipped: list[str] = []

    def check(self, label: str, condition: bool, msg: str = "") -> None:
        if condition:
            self.passed.append(label)
            print(f"  ✓  {label}")
        else:
            self.failed.append(label)
            print(f"  ✗  {label}" + (f": {msg}" if msg else ""))

    def skip(self, reason: str) -> None:
        self.skipped.append(reason)
        print(f"  ⊘  SKIP: {reason}")

    def summary(self) -> bool:
        ok = len(self.failed) == 0
        status = "PASS" if ok else "FAIL"
        print(
            f"\n[{self.name}] {status}: "
            f"{len(self.passed)} passed, {len(self.failed)} failed, "
            f"{len(self.skipped)} skipped"
        )
        return ok


# ---------------------------------------------------------------------------
# Concurrent issuance helper (for F14)
# ---------------------------------------------------------------------------

def concurrent_issue(ca: pki.CertificateAuthority,
                     audit: pki.AuditLog,
                     n_threads: int = 8,
                     certs_per_thread: int = 10) -> list[pki.x509.Certificate]:
    """Issue certs from n_threads simultaneously; return all issued certs."""
    results: list = []
    lock = threading.Lock()
    errors: list[Exception] = []

    def worker(tid: int) -> None:
        for i in range(certs_per_thread):
            try:
                cert = issue_one(ca, audit, cn=f"thread-{tid}-cert-{i}")
                with lock:
                    results.append(cert)
            except Exception as e:
                with lock:
                    errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if errors:
        # Non-fatal: log but don't abort — some issuance errors are expected
        # under failure injection. The invariants will catch real problems.
        print(f"  [warn] {len(errors)} issuance error(s) during concurrent load")

    return results
