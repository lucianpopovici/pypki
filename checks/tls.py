"""TLS certificate expiry checks."""
import datetime
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="admin-tls-expiry",
    severity=Severity.HIGH,
    category="tls",
    description="Admin endpoint cert > 7 days from expiry",
)
def check_admin_tls_expiry(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    cert_path = Path(env.tls_cert_path) if env.tls_cert_path else None

    if not cert_path or not cert_path.exists():
        return CheckResult(
            id="admin-tls-expiry", severity=Severity.HIGH, category="tls",
            status=Status.SKIP,
            description="Admin endpoint cert > 7 days from expiry",
            finding="TLS cert path not configured or not found",
            remediation="Set --tls-cert-path or configure tls.cert_path",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )

    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        nva = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (nva - now).days
    except Exception as e:
        return CheckResult(
            id="admin-tls-expiry", severity=Severity.HIGH, category="tls",
            status=Status.ERROR,
            description="Admin endpoint cert > 7 days from expiry",
            finding=f"Failed to read cert: {e}",
            remediation="pypki_admin.py tls-rotate",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )

    if days_left < 0:
        return CheckResult(
            id="admin-tls-expiry", severity=Severity.HIGH, category="tls",
            status=Status.FAIL,
            description="Admin endpoint cert > 7 days from expiry",
            finding=f"Cert EXPIRED {-days_left} days ago",
            remediation="pypki_admin.py tls-rotate",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"days_remaining": days_left},
        )
    if days_left <= 7:
        return CheckResult(
            id="admin-tls-expiry", severity=Severity.HIGH, category="tls",
            status=Status.WARN,
            description="Admin endpoint cert > 7 days from expiry",
            finding=f"Cert expires in {days_left} days (threshold: 7)",
            remediation="pypki_admin.py tls-rotate",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"days_remaining": days_left},
        )
    return CheckResult(
        id="admin-tls-expiry", severity=Severity.HIGH, category="tls",
        status=Status.PASS,
        description="Admin endpoint cert > 7 days from expiry",
        finding=f"Cert expires in {days_left} days",
        remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"days_remaining": days_left},
    )
