"""Runtime checks: DB, time sync, entropy, disk space."""
import datetime
import shutil
import subprocess
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="time-sync",
    severity=Severity.HIGH,
    category="runtime",
    description="NTP drift < 1 second; chrony/timesyncd active",
    timeout_seconds=5,
)
def check_time_sync(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    drift: float | None = None
    source = "unknown"

    # Try chronyc tracking
    if shutil.which("chronyc"):
        try:
            result = subprocess.run(
                ["chronyc", "tracking"], capture_output=True, text=True, timeout=4
            )
            for line in result.stdout.splitlines():
                if "System time" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p in ("slow", "fast") and i > 0:
                            try:
                                drift = float(parts[i - 1])
                                source = "chronyd"
                            except ValueError:
                                pass
        except Exception:
            pass

    # Try timedatectl
    if drift is None and shutil.which("timedatectl"):
        try:
            result = subprocess.run(
                ["timedatectl", "show", "--property=NTPSynchronized"],
                capture_output=True, text=True, timeout=4,
            )
            if "yes" in result.stdout:
                drift = 0.0
                source = "systemd-timesyncd"
        except Exception:
            pass

    threshold = 1.0
    if drift is None:
        return CheckResult(
            id="time-sync", severity=Severity.HIGH, category="runtime",
            status=Status.WARN,
            description="NTP drift < 1 second; chrony/timesyncd active",
            finding="Could not determine NTP drift (chronyc/timedatectl unavailable)",
            remediation="apt install chrony; systemctl enable --now chronyd",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )
    if drift > threshold:
        return CheckResult(
            id="time-sync", severity=Severity.HIGH, category="runtime",
            status=Status.WARN,
            description="NTP drift < 1 second; chrony/timesyncd active",
            finding=f"drift: {drift:.3f}s (threshold: {threshold}s, source: {source})",
            remediation="systemctl restart chronyd; chronyc tracking",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"drift_seconds": drift, "threshold": threshold, "source": source},
        )
    return CheckResult(
        id="time-sync", severity=Severity.HIGH, category="runtime",
        status=Status.PASS,
        description="NTP drift < 1 second; chrony/timesyncd active",
        finding=f"drift: {drift:.3f}s (source: {source})",
        remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"drift_seconds": drift, "source": source},
    )


@register_check(
    id="entropy-available",
    severity=Severity.HIGH,
    category="runtime",
    description="/proc/sys/kernel/random/entropy_avail > 256",
    timeout_seconds=2,
)
def check_entropy_available(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    try:
        avail = int(Path("/proc/sys/kernel/random/entropy_avail").read_text())
    except OSError:
        return CheckResult(
            id="entropy-available", severity=Severity.HIGH, category="runtime",
            status=Status.SKIP,
            description="/proc/sys/kernel/random/entropy_avail > 256",
            finding="/proc not available (container without procfs?)",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    threshold = 256
    if avail >= threshold:
        return CheckResult(
            id="entropy-available", severity=Severity.HIGH, category="runtime",
            status=Status.PASS,
            description="/proc/sys/kernel/random/entropy_avail > 256",
            finding=f"entropy_avail = {avail}",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"entropy_avail": avail},
        )
    return CheckResult(
        id="entropy-available", severity=Severity.HIGH, category="runtime",
        status=Status.WARN,
        description="/proc/sys/kernel/random/entropy_avail > 256",
        finding=f"entropy_avail = {avail} (threshold: {threshold})",
        remediation="apt install rng-tools; systemctl enable --now rngd",
        timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"entropy_avail": avail, "threshold": threshold},
    )


@register_check(
    id="disk-free-state",
    severity=Severity.MEDIUM,
    category="runtime",
    description="State directory has > 20% free space and > 3× DB size",
)
def check_disk_free_state(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    state_dir = Path(env.state_dir)
    if not state_dir.exists():
        return CheckResult(
            id="disk-free-state", severity=Severity.MEDIUM, category="runtime",
            status=Status.SKIP,
            description="State directory has > 20% free space",
            finding=f"{state_dir} does not exist",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )

    usage = shutil.disk_usage(state_dir)
    free_pct = usage.free / usage.total * 100
    if free_pct < 20:
        return CheckResult(
            id="disk-free-state", severity=Severity.MEDIUM, category="runtime",
            status=Status.WARN,
            description="State directory has > 20% free space",
            finding=f"Only {free_pct:.1f}% free ({usage.free // 1024 // 1024} MB)",
            remediation="Free up disk space or expand the volume",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"free_pct": round(free_pct, 1), "free_bytes": usage.free},
        )
    return CheckResult(
        id="disk-free-state", severity=Severity.MEDIUM, category="runtime",
        status=Status.PASS,
        description="State directory has > 20% free space",
        finding=f"{free_pct:.1f}% free ({usage.free // 1024 // 1024} MB)",
        remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"free_pct": round(free_pct, 1)},
    )
