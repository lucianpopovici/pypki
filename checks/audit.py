"""Audit chain integrity checks."""
import time

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="audit-chain-intact",
    severity=Severity.CRITICAL,
    category="audit",
    description="Last 1000 audit entries verify against their hash chain",
    timeout_seconds=30,
)
def check_audit_chain_intact(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()

    if not env.audit_chain_enabled:
        return CheckResult(
            id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
            status=Status.SKIP,
            description="Last 1000 audit entries verify against their hash chain",
            finding="Audit chain not enabled (--audit-chain-enabled not set)",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )

    if env.db is None:
        return CheckResult(
            id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
            status=Status.SKIP,
            description="Last 1000 audit entries verify against their hash chain",
            finding="No database connection available for audit check",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )

    try:
        from audit_chain import AuditChain
        chain = AuditChain(env.db)
        ok, broken_at = chain.verify_last(1000)
        if ok:
            return CheckResult(
                id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
                status=Status.PASS,
                description="Last 1000 audit entries verify against their hash chain",
                finding="Last 1000 entries verified",
                remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
            )
        return CheckResult(
            id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
            status=Status.FAIL,
            description="Last 1000 audit entries verify against their hash chain",
            finding=f"Chain broken at entry {broken_at}",
            remediation="pypki_admin.py audit-verify --verbose for details",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"broken_at": broken_at},
        )
    except ImportError:
        return CheckResult(
            id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
            status=Status.SKIP,
            description="Last 1000 audit entries verify against their hash chain",
            finding="audit_chain module not available",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    except Exception as e:
        return CheckResult(
            id="audit-chain-intact", severity=Severity.CRITICAL, category="audit",
            status=Status.ERROR,
            description="Last 1000 audit entries verify against their hash chain",
            finding=f"Verification error: {e}",
            remediation="pypki_admin.py audit-verify for details",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )
