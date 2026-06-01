"""
F07 — Webhook receiver hangs indefinitely.

Invariants tested: 1 (audit completeness — issuance must not be blocked).

Key property: issue_certificate() must return before the webhook is delivered.
The WebhookDispatcher fires webhooks on a background daemon thread; a hanging
receiver blocks that thread but must never propagate back to the issuing caller.

The timing check is the invariant: n certs must be issued in under
(n × webhook_timeout) seconds, which proves issuance returned before the
webhook could have completed.

Note: dispatcher.stop() is called with a short timeout and the background
thread is abandoned — it is a daemon thread and will be reaped when the
test process exits.  DB invariants are checked after issuance, before the
dispatcher has a chance to time out, which is the correct ordering.
"""

from __future__ import annotations

import http.server
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from chaos._harness import ScenarioResult, make_audit_log, issue_one, ITERATIONS
from chaos.invariants import audit_log_complete, no_duplicate_serials


class _HangingHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that hangs for much longer than the webhook timeout."""

    # Set by the test to allow graceful shutdown of in-progress handlers.
    _stop = threading.Event()

    def do_POST(self):
        # Simulate a hung receiver: wait 60s or until the test is done.
        _HangingHandler._stop.wait(timeout=60)

    def log_message(self, *args):
        pass


def run() -> bool:
    result = ScenarioResult("F07_webhook_hang")
    print("\n=== F07: Webhook receiver hangs indefinitely ===")
    print("Testing: issuance is non-blocking even with a hung webhook receiver\n")

    server = http.server.HTTPServer(("127.0.0.1", 0), _HangingHandler)
    webhook_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    ca_dir = tempfile.mkdtemp(prefix="chaos-F07-")
    try:
        import pki_server as pki
        import hooks as hooks_mod

        ca = pki.CertificateAuthority(ca_dir=ca_dir)
        audit = make_audit_log(ca_dir)

        # Short HTTP timeout so the dispatcher isn't stuck indefinitely.
        webhook_timeout = 1  # seconds
        dispatcher = hooks_mod.WebhookDispatcher(
            urls=[f"http://127.0.0.1:{webhook_port}/hook"],
            timeout=webhook_timeout,
        )
        dispatcher.start()
        ca._webhook = dispatcher

        n_certs = min(ITERATIONS, 10)
        t0 = time.monotonic()

        issued = []
        for i in range(n_certs):
            try:
                cert = issue_one(ca, audit, cn=f"f07-cert-{i}")
                issued.append(cert)
            except Exception as e:
                result.check(f"issue_{i}", False, str(e))

        issuance_elapsed = time.monotonic() - t0

        result.check(
            "all_certs_issued",
            len(issued) == n_certs,
            f"only {len(issued)}/{n_certs} issued",
        )

        # Issuance must complete in under webhook_timeout seconds.
        # If issuance were synchronously waiting for webhooks it would take
        # ≥ n_certs × webhook_timeout seconds.  The daemon dispatcher makes
        # issuance return immediately.
        result.check(
            "issuance_not_blocked_by_webhook",
            issuance_elapsed < webhook_timeout,
            f"issuance took {issuance_elapsed:.2f}s — expected < {webhook_timeout}s "
            f"(would be ≥{n_certs * webhook_timeout}s if blocking on webhook)",
        )

        # Signal the dispatcher to stop; don't wait for in-flight retries
        # (the background thread is a daemon and will be reaped by the OS).
        ca._webhook = None
        dispatcher.stop(timeout=0.1)
        del ca, audit

        # DB invariants must hold — they are committed before the webhook fires.
        pki_db = Path(ca_dir) / "certificates.db"
        ok1, msg1 = audit_log_complete.check(pki_db, Path(ca_dir) / "audit.db")
        result.check("audit_log_complete", ok1, msg1)

        ok2, msg2 = no_duplicate_serials.check(pki_db)
        result.check("no_duplicate_serials", ok2, msg2)

        # Signal any in-progress handlers to exit, then shut down.
        _HangingHandler._stop.set()
        server.shutdown()
        return result.summary()
    finally:
        _HangingHandler._stop.set()
        server.shutdown()
        shutil.rmtree(ca_dir, ignore_errors=True)


if __name__ == "__main__":
    ok = run()
    sys.exit(0 if ok else 1)
