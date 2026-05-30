"""Secret-file permission checks."""
import os
import stat
import time
from pathlib import Path

from preflight import CheckEnv, CheckResult, Severity, Status, register_check


def _pass(id, severity, category, description, finding, metadata=None, t0=None):
    return CheckResult(
        id=id, severity=severity, category=category,
        status=Status.PASS, description=description, finding=finding,
        remediation=None, timing_ms=int((time.monotonic() - (t0 or time.monotonic())) * 1000),
        metadata=metadata or {},
    )


def _fail(id, severity, category, description, finding, remediation=None, metadata=None, t0=None):
    return CheckResult(
        id=id, severity=severity, category=category,
        status=Status.FAIL, description=description, finding=finding,
        remediation=remediation, timing_ms=int((time.monotonic() - (t0 or time.monotonic())) * 1000),
        metadata=metadata or {},
    )


@register_check(
    id="ca-key-permissions",
    severity=Severity.CRITICAL,
    category="secrets",
    description="All CA key files are mode 0600, owned by the service user",
)
def check_ca_key_permissions(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    bad = []
    checked = 0
    for key_path in env.ca_key_paths:
        try:
            st = Path(key_path).stat()
            checked += 1
            mode = stat.S_IMODE(st.st_mode)
            if mode != 0o600:
                bad.append((str(key_path), oct(mode)))
        except OSError:
            pass

    if not bad:
        return CheckResult(
            id="ca-key-permissions", severity=Severity.CRITICAL, category="secrets",
            status=Status.PASS, description="All CA key files are mode 0600",
            finding=f"{checked} key(s) checked, all 0600",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
            metadata={"checked": checked},
        )
    paths_str = " ".join(p for p, _ in bad)
    return CheckResult(
        id="ca-key-permissions", severity=Severity.CRITICAL, category="secrets",
        status=Status.FAIL, description="All CA key files must be mode 0600",
        finding=f"{len(bad)} key(s) with wrong permissions: {bad}",
        remediation=f"chmod 0600 {paths_str}",
        timing_ms=int((time.monotonic() - t0) * 1000),
        metadata={"violations": bad, "checked": checked},
    )


@register_check(
    id="secrets-dir-permissions",
    severity=Severity.CRITICAL,
    category="secrets",
    description="Secrets directory is mode 0700 with no world-readable files",
)
def check_secrets_dir_permissions(env: CheckEnv) -> CheckResult:
    t0 = time.monotonic()
    secrets_dir = Path(env.config_dir) / "secrets"

    if not secrets_dir.exists():
        return CheckResult(
            id="secrets-dir-permissions", severity=Severity.CRITICAL, category="secrets",
            status=Status.SKIP,
            description="Secrets directory is mode 0700 with no world-readable files",
            finding=f"{secrets_dir} does not exist — skipping",
            remediation=f"mkdir -p -m 0700 {secrets_dir}",
            timing_ms=int((time.monotonic() - t0) * 1000),
        )

    mode = stat.S_IMODE(secrets_dir.stat().st_mode)
    world_readable = [
        str(p) for p in secrets_dir.iterdir()
        if stat.S_IMODE(p.stat().st_mode) & 0o004
    ]

    problems = []
    if mode != 0o700:
        problems.append(f"dir is {oct(mode)}, expected 0700")
    if world_readable:
        problems.append(f"{len(world_readable)} world-readable file(s): {world_readable}")

    if not problems:
        return CheckResult(
            id="secrets-dir-permissions", severity=Severity.CRITICAL, category="secrets",
            status=Status.PASS,
            description="Secrets directory is mode 0700 with no world-readable files",
            finding=f"{secrets_dir} is 0700, no world-readable files",
            remediation=None, timing_ms=int((time.monotonic() - t0) * 1000),
        )
    return CheckResult(
        id="secrets-dir-permissions", severity=Severity.CRITICAL, category="secrets",
        status=Status.FAIL,
        description="Secrets directory must be mode 0700 with no world-readable files",
        finding="; ".join(problems),
        remediation=f"chmod 0700 {secrets_dir}; chmod go-r {secrets_dir}/*",
        timing_ms=int((time.monotonic() - t0) * 1000),
    )
