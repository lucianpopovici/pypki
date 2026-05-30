"""Issuance-related checks: CA cert expiry, CRL freshness."""
import datetime
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="cert-expiry-soon",
    severity=Severity.MEDIUM,
    category="issuance",
    description="Active CA certs are > 90 days from expiry",
)
def check_cert_expiry_soon(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    ca_dir = Path(env.ca_dir) if env.ca_dir else None
    if not ca_dir or not ca_dir.exists():
        return CheckResult(
            id="cert-expiry-soon", severity=Severity.MEDIUM, category="issuance",
            status=Status.SKIP,
            description="Active CA certs are > 90 days from expiry",
            finding="CA directory not configured",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )

    expiring = []
    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = 90

    for cert_path in ca_dir.glob("**/*.crt"):
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            days_left = (cert.not_valid_after_utc - now).days
            if days_left < threshold:
                expiring.append((str(cert_path), days_left))
        except Exception:
            pass

    if not expiring:
        return CheckResult(
            id="cert-expiry-soon", severity=Severity.MEDIUM, category="issuance",
            status=Status.PASS,
            description="Active CA certs are > 90 days from expiry",
            finding=f"No CA certs expiring within {threshold} days",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    details = ", ".join(f"{p} ({d}d)" for p, d in expiring)
    return CheckResult(
        id="cert-expiry-soon", severity=Severity.MEDIUM, category="issuance",
        status=Status.WARN,
        description="Active CA certs are > 90 days from expiry",
        finding=f"{len(expiring)} cert(s) expiring soon: {details}",
        remediation="Renew or replace the affected CA certificates",
        timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"expiring": expiring},
    )
