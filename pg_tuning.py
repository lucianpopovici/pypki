"""
PostgreSQL tuning recommendations for a PKI workload (CLAUDE-db-bootstrap.md).

Write-heavy at issuance peaks, predictably sized, durability-critical.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)


def _ram_mb() -> int:
    """Return total system RAM in megabytes."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024  # KiB → MiB
    except OSError:
        pass
    return 4096  # safe fallback


def recommended_params() -> dict[str, str]:
    """Return recommended ALTER SYSTEM values for the current host."""
    ram_mb = _ram_mb()
    shared_buffers_mb = max(128, ram_mb // 4)
    effective_cache_mb = max(256, ram_mb // 2)

    return {
        "wal_level": "'replica'",
        "synchronous_commit": "'on'",
        "full_page_writes": "on",
        "checkpoint_timeout": "'15min'",
        "checkpoint_completion_target": "0.9",
        "max_wal_size": "'2GB'",
        "min_wal_size": "'256MB'",
        "shared_buffers": f"'{shared_buffers_mb}MB'",
        "effective_cache_size": f"'{effective_cache_mb}MB'",
        "work_mem": "'16MB'",
        "maintenance_work_mem": "'256MB'",
        "random_page_cost": "1.1",
        "log_min_duration_statement": "1000",
        "log_lock_waits": "on",
    }


def apply(
    *,
    admin_dsn: str,
    mode: str = "recommended",
    dry_run: bool = False,
) -> None:
    """Apply (or print) Postgres tuning parameters.

    *mode* is one of: ``recommended``, ``print-only``, ``none``.
    ``print-only`` works without elevated DB permissions.
    ``none`` is a no-op.
    """
    if mode == "none":
        return

    params = recommended_params()

    if mode in ("recommended", "print-only"):
        for param, value in params.items():
            log.info("  ALTER SYSTEM SET %s = %s;", param, value)

    if mode == "print-only" or dry_run:
        log.info("[print-only] No changes applied.")
        return

    try:
        import psycopg  # type: ignore[import]
    except ImportError:
        raise RuntimeError("psycopg required for Postgres tuning")

    conn = psycopg.connect(admin_dsn, autocommit=True)
    try:
        managed_postgres = False
        for param, value in params.items():
            try:
                conn.execute(f"ALTER SYSTEM SET {param} = {value}")
            except Exception as e:
                if "permission denied" in str(e).lower() or "not supported" in str(e).lower():
                    if not managed_postgres:
                        log.warning(
                            "ALTER SYSTEM not permitted (cloud-managed Postgres?). "
                            "Apply the following settings via your provider's UI:"
                        )
                        managed_postgres = True
                    log.warning("  %s = %s", param, value)
                else:
                    raise
        if not managed_postgres:
            conn.execute("SELECT pg_reload_conf()")
            log.info("Postgres tuning applied and config reloaded.")
    finally:
        conn.close()
