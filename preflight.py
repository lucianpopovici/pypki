"""
Preflight check runner (CLAUDE-preflight-check.md).

Runs all registered checks concurrently (bounded thread pool), collects
results, formats them for human / JSON / Prometheus output, and exits
with the appropriate code.

Usage:
    results = run(env=CheckEnv.from_config(config, db))
    print(format_human(results))
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime
import enum
import json
import os
import sys
import time
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]

    def exit_code(self) -> int:
        """Exit code when --exit-on-warning fires at this level."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Status(enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclasses.dataclass(frozen=True)
class CheckResult:
    id: str
    severity: Severity
    category: str
    status: Status
    description: str
    finding: str
    remediation: Optional[str]
    timing_ms: int
    metadata: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class CheckEnv:
    """Runtime environment passed to every check function."""
    ca_key_paths: list  = dataclasses.field(default_factory=list)
    ca_dir: Optional[str] = None
    config: Optional[Any] = None
    db: Optional[Any] = None
    state_dir: str = "/var/lib/pypki"
    config_dir: str = "/etc/pypki"
    tls_cert_path: Optional[str] = None
    backup_interval_hours: int = 24
    audit_chain_enabled: bool = False
    webhook_urls: list = dataclasses.field(default_factory=list)

    @classmethod
    def from_config(cls, config: Any = None, db: Any = None) -> "CheckEnv":
        env = cls(config=config, db=db)
        if config:
            # Discover key paths from config if available
            ca_dir = getattr(config, "ca_dir", None)
            if ca_dir:
                from pathlib import Path
                env.ca_dir = str(ca_dir)
                env.ca_key_paths = list(Path(ca_dir).glob("**/*.key"))
        return env


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

CHECK_CATALOG: list[dict] = []


def register_check(
    *,
    id: str,
    severity: Severity,
    category: str,
    description: str,
    timeout_seconds: float = 10,
) -> Callable:
    """Decorator that registers a check function in CHECK_CATALOG."""
    def decorator(fn: Callable) -> Callable:
        CHECK_CATALOG.append({
            "id": id,
            "severity": severity,
            "category": category,
            "description": description,
            "timeout_seconds": timeout_seconds,
            "fn": fn,
        })
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_one(entry: dict, env: CheckEnv, timeout: float) -> CheckResult:
    fn = entry["fn"]
    t0 = time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(fn, env)
            result = future.result(timeout=timeout)
        return result
    except concurrent.futures.TimeoutError:
        return CheckResult(
            id=entry["id"],
            severity=entry["severity"],
            category=entry["category"],
            status=Status.ERROR,
            description=entry["description"],
            finding=f"Check timed out after {timeout}s",
            remediation=None,
            timing_ms=int((time.monotonic() - t0) * 1000),
        )
    except Exception as e:
        return CheckResult(
            id=entry["id"],
            severity=entry["severity"],
            category=entry["category"],
            status=Status.ERROR,
            description=entry["description"],
            finding=f"Check raised an exception: {e}",
            remediation=None,
            timing_ms=int((time.monotonic() - t0) * 1000),
        )


def run(
    env: Optional[CheckEnv] = None,
    *,
    include_categories: Optional[list[str]] = None,
    exclude_categories: Optional[list[str]] = None,
    include_ids: Optional[list[str]] = None,
    exclude_ids: Optional[list[str]] = None,
    skip_slow: bool = False,
    parallelism: int = 8,
    per_check_timeout: float = 10.0,
) -> list[CheckResult]:
    """Run all registered checks concurrently.  Returns list of CheckResult."""
    if env is None:
        env = CheckEnv()

    # Import all check modules to trigger @register_check decorators
    _ensure_checks_loaded()

    entries = list(CHECK_CATALOG)
    if include_categories:
        entries = [e for e in entries if e["category"] in include_categories]
    if exclude_categories:
        entries = [e for e in entries if e["category"] not in exclude_categories]
    if include_ids:
        entries = [e for e in entries if e["id"] in include_ids]
    if exclude_ids:
        entries = [e for e in entries if e["id"] not in exclude_ids]
    if skip_slow:
        entries = [e for e in entries if e["timeout_seconds"] <= 1]

    results: list[CheckResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = {
            pool.submit(_run_one, entry, env, per_check_timeout): entry
            for entry in entries
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results


def _ensure_checks_loaded() -> None:
    """Import all checks sub-modules so decorators register checks."""
    import importlib
    for mod in ("checks.secrets", "checks.runtime", "checks.tls",
                "checks.backup", "checks.hardening", "checks.issuance",
                "checks.audit", "checks.backends"):
        try:
            importlib.import_module(mod)
        except ImportError:
            pass


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

_STATUS_ICON = {
    Status.PASS: "✓",
    Status.WARN: "⚠",
    Status.FAIL: "✗",
    Status.SKIP: "→",
    Status.ERROR: "!",
}

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_STATUS_COLOR = {
    Status.PASS: "\033[32m",
    Status.WARN: "\033[33m",
    Status.FAIL: "\033[31m",
    Status.SKIP: "\033[90m",
    Status.ERROR: "\033[31m",
}
_RESET = "\033[0m"


def _colorize(s: str, color: str) -> str:
    if _USE_COLOR:
        return f"{color}{s}{_RESET}"
    return s


def format_human(results: list[CheckResult], *, use_color: Optional[bool] = None) -> str:
    use_c = _USE_COLOR if use_color is None else use_color
    lines = []
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"\nPyPKI preflight — {now}\n")

    for r in sorted(results, key=lambda x: (-x.severity.value, x.category, x.id)):
        icon = _STATUS_ICON[r.status]
        if use_c:
            icon = _colorize(icon, _STATUS_COLOR[r.status])
        line = f"  {icon} {r.id:<30} {r.severity.name.lower():<10} {r.category:<15} ({r.timing_ms}ms)"
        lines.append(line)
        if r.status not in (Status.PASS, Status.SKIP):
            lines.append(f"      finding:     {r.finding}")
            if r.remediation:
                lines.append(f"      fix:         {r.remediation}")

    counts = {s: sum(1 for r in results if r.status == s) for s in Status}
    total_ms = sum(r.timing_ms for r in results)
    worst = _highest_unpassed(results)

    lines.append(
        f"\nSummary: "
        f"{counts[Status.PASS]} PASS · "
        f"{counts[Status.WARN]} WARN · "
        f"{counts[Status.FAIL]} FAIL · "
        f"{counts[Status.ERROR]} ERROR · "
        f"{counts[Status.SKIP]} SKIP"
    )
    lines.append(f"Total time: {total_ms / 1000:.1f}s")
    if worst:
        lines.append(f"Highest severity not passing: {worst.name.lower()}")

    remediation_items = [(r.id, r.remediation) for r in results
                         if r.status not in (Status.PASS, Status.SKIP) and r.remediation]
    if remediation_items:
        lines.append("\nTo remediate:")
        for cid, rem in remediation_items:
            lines.append(f"  - {cid:<30}  {rem}")

    return "\n".join(lines)


def format_json(results: list[CheckResult]) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    worst = _highest_unpassed(results)
    counts = {s.value: sum(1 for r in results if r.status == s) for s in Status}
    payload = {
        "schema_version": 1,
        "generated_at": now,
        "total_time_ms": sum(r.timing_ms for r in results),
        "summary": {
            "pass": counts["PASS"],
            "warn": counts["WARN"],
            "fail": counts["FAIL"],
            "error": counts["ERROR"],
            "skip": counts["SKIP"],
            "highest_unpassed": worst.name.lower() if worst else "none",
        },
        "checks": [
            {
                "id": r.id,
                "severity": r.severity.name.lower(),
                "category": r.category,
                "status": r.status.value,
                "description": r.description,
                "finding": r.finding,
                "remediation": r.remediation,
                "timing_ms": r.timing_ms,
                "metadata": r.metadata,
            }
            for r in sorted(results, key=lambda x: x.id)
        ],
    }
    return json.dumps(payload, indent=2)


def format_prometheus(results: list[CheckResult]) -> str:
    lines = [
        "# HELP pypki_preflight_check_status Status of each preflight check (0=pass 1=warn 2=fail 3=error 4=skip)",
        "# TYPE pypki_preflight_check_status gauge",
    ]
    status_val = {Status.PASS: 0, Status.WARN: 1, Status.FAIL: 2, Status.ERROR: 3, Status.SKIP: 4}
    for r in sorted(results, key=lambda x: x.id):
        labels = f'check="{r.id}",severity="{r.severity.name.lower()}",category="{r.category}"'
        lines.append(f"pypki_preflight_check_status{{{labels}}} {status_val[r.status]}")

    lines += [
        "",
        "# HELP pypki_preflight_check_timing_ms Per-check execution time in milliseconds",
        "# TYPE pypki_preflight_check_timing_ms gauge",
    ]
    for r in sorted(results, key=lambda x: x.id):
        labels = f'check="{r.id}"'
        lines.append(f"pypki_preflight_check_timing_ms{{{labels}}} {r.timing_ms}")

    counts = {s.value: sum(1 for r in results if r.status == s) for s in Status}
    lines += [
        "",
        "# HELP pypki_preflight_summary Count of checks by status",
        "# TYPE pypki_preflight_summary gauge",
    ]
    for status_name, count in counts.items():
        lines.append(f'pypki_preflight_summary{{status="{status_name.lower()}"}} {count}')

    return "\n".join(lines) + "\n"


def _highest_unpassed(results: list[CheckResult]) -> Optional[Severity]:
    worst: Optional[Severity] = None
    for r in results:
        if r.status not in (Status.PASS, Status.SKIP):
            if worst is None or r.severity > worst:
                worst = r.severity
    return worst


def determine_exit_code(results: list[CheckResult], threshold: Severity) -> int:
    """Return non-zero if any check at or above *threshold* is not passing."""
    worst = _highest_unpassed(results)
    if worst is None:
        return 0
    if worst >= threshold:
        return worst.exit_code()
    return 0
