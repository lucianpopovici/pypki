"""DB setup during bootstrap — calls into db_bootstrap."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def setup_db(
    *,
    backend: str = "sqlite",
    state_dir: Path,
    postgres_dsn: Optional[str] = None,
    dry_run: bool = False,
) -> str:
    """Initialize the database and return the runtime DSN."""
    if backend == "sqlite":
        db_path = state_dir / "db" / "pki.db"
        from db_bootstrap import init_sqlite
        init_sqlite(db_path, dry_run=dry_run)
        return f"sqlite:///{db_path}"

    if backend == "postgres":
        if not postgres_dsn:
            raise ValueError("--postgres-dsn is required for postgres backend")
        # For postgres, db-init is the full command; here we just return the DSN
        log.info("Postgres backend selected; run pypki_admin.py db-init for full setup.")
        return postgres_dsn

    raise ValueError(f"Unknown backend: {backend!r}")
