"""Backup recency and target reachability checks."""
import datetime
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="backup-recent",
    severity=Severity.HIGH,
    category="backup",
    description="Most recent backup is within 1.5× the configured interval",
)
def check_backup_recent(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    # Look for the most recent backup file in the state dir
    backup_dir = Path(env.state_dir) / "backups"
    if not backup_dir.exists():
        return CheckResult(
            id="backup-recent", severity=Severity.HIGH, category="backup",
            status=Status.SKIP,
            description="Most recent backup is within 1.5× the configured interval",
            finding=f"Backup directory {backup_dir} does not exist",
            remediation="pypki_admin.py backup-now",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )

    backups = sorted(backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return CheckResult(
            id="backup-recent", severity=Severity.HIGH, category="backup",
            status=Status.WARN,
            description="Most recent backup is within 1.5× the configured interval",
            finding="No backup files found",
            remediation="pypki_admin.py backup-now",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )

    newest = backups[0]
    age_hours = (time.time() - newest.stat().st_mtime) / 3600
    threshold_hours = env.backup_interval_hours * 1.5

    if age_hours > threshold_hours:
        return CheckResult(
            id="backup-recent", severity=Severity.HIGH, category="backup",
            status=Status.WARN,
            description="Most recent backup is within 1.5× the configured interval",
            finding=f"Most recent backup is {age_hours:.1f}h old (threshold: {threshold_hours:.1f}h)",
            remediation="pypki_admin.py backup-now",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"age_hours": round(age_hours, 1), "backup": str(newest)},
        )
    return CheckResult(
        id="backup-recent", severity=Severity.HIGH, category="backup",
        status=Status.PASS,
        description="Most recent backup is within 1.5× the configured interval",
        finding=f"Most recent backup is {age_hours:.1f}h old",
        remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"age_hours": round(age_hours, 1), "backup": str(newest)},
    )
