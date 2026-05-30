"""Host hardening checks: firewall, sysctl, MAC policy."""
import subprocess
import shutil
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


@register_check(
    id="systemd-hardening-score",
    severity=Severity.MEDIUM,
    category="hardening",
    description="systemd-analyze security pypki.service score <= 1.0",
    timeout_seconds=15,
)
def check_systemd_hardening_score(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    if not shutil.which("systemd-analyze"):
        return CheckResult(
            id="systemd-hardening-score", severity=Severity.MEDIUM, category="hardening",
            status=Status.SKIP,
            description="systemd-analyze security pypki.service score <= 1.0",
            finding="systemd-analyze not available",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    try:
        result = subprocess.run(
            ["systemd-analyze", "security", "pypki.service", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        score_str = None
        for line in result.stdout.splitlines():
            if "→" in line and "SAFE" in line.upper() or "EXPOSED" in line.upper() or "MEDIUM" in line.upper():
                parts = line.strip().split()
                if parts:
                    try:
                        float(parts[-1])
                        score_str = parts[-1]
                    except ValueError:
                        pass
        # Fallback: last numeric token in last line
        if not score_str:
            last = result.stdout.strip().splitlines()
            if last:
                parts = last[-1].strip().split()
                for tok in reversed(parts):
                    try:
                        float(tok)
                        score_str = tok
                        break
                    except ValueError:
                        pass

        if score_str is None:
            return CheckResult(
                id="systemd-hardening-score", severity=Severity.MEDIUM, category="hardening",
                status=Status.ERROR,
                description="systemd-analyze security pypki.service score <= 1.0",
                finding="Could not parse score from systemd-analyze output",
                remediation="Check packaging/systemd/pypki.service is installed",
                timing_ms=int((time.monotonic() - t0) * 1000),
            )

        score = float(score_str)
        threshold = 1.0
        if score <= threshold:
            return CheckResult(
                id="systemd-hardening-score", severity=Severity.MEDIUM, category="hardening",
                status=Status.PASS,
                description="systemd-analyze security pypki.service score <= 1.0",
                finding=f"Score: {score} (threshold: {threshold})",
                remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
                metadata={"score": score},
            )
        return CheckResult(
            id="systemd-hardening-score", severity=Severity.MEDIUM, category="hardening",
            status=Status.WARN,
            description="systemd-analyze security pypki.service score <= 1.0",
            finding=f"Score: {score} (threshold: {threshold})",
            remediation="Review packaging/systemd/pypki.service hardening directives",
            timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"score": score},
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            id="systemd-hardening-score", severity=Severity.MEDIUM, category="hardening",
            status=Status.ERROR,
            description="systemd-analyze security pypki.service score <= 1.0",
            finding="systemd-analyze timed out",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )


@register_check(
    id="sysctl-applied",
    severity=Severity.MEDIUM,
    category="hardening",
    description="Key sysctl values from pypki.conf match runtime values",
)
def check_sysctl_applied(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()

    # Key security parameters we care most about
    expected = {
        "kernel.randomize_va_space": "2",
        "kernel.yama.ptrace_scope": "1",
        "net.ipv4.ip_forward": "0",
        "kernel.kptr_restrict": "2",
    }

    if not shutil.which("sysctl"):
        return CheckResult(
            id="sysctl-applied", severity=Severity.MEDIUM, category="hardening",
            status=Status.SKIP,
            description="Key sysctl values from pypki.conf match runtime values",
            finding="sysctl command not available",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )

    mismatches = []
    for key, expected_val in expected.items():
        try:
            result = subprocess.run(
                ["sysctl", "-n", key], capture_output=True, text=True, timeout=2
            )
            actual = result.stdout.strip()
            if actual != expected_val:
                mismatches.append(f"{key}: got {actual!r}, want {expected_val!r}")
        except Exception as e:
            mismatches.append(f"{key}: error reading ({e})")

    if not mismatches:
        return CheckResult(
            id="sysctl-applied", severity=Severity.MEDIUM, category="hardening",
            status=Status.PASS,
            description="Key sysctl values from pypki.conf match runtime values",
            finding=f"{len(expected)} key sysctl values verified",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    return CheckResult(
        id="sysctl-applied", severity=Severity.MEDIUM, category="hardening",
        status=Status.WARN,
        description="Key sysctl values from pypki.conf match runtime values",
        finding=f"{len(mismatches)} mismatch(es): " + "; ".join(mismatches),
        remediation="sysctl --system  (or: cp packaging/sysctl/pypki.conf /etc/sysctl.d/ && sysctl --system)",
        timing_ms=int((time.monotonic() - t0) * 1000),
    )
