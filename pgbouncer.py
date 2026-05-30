"""
PgBouncer configuration helpers (CLAUDE-db-bootstrap.md).

Transaction-mode pooling is the right choice for PyPKI's workload but
constrains the DAL: no LISTEN/NOTIFY, no cross-transaction advisory locks
(the DAL already satisfies this — advisory_lock() in db.py acquires and
releases within a single transaction).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

SAMPLE_TEMPLATE = """\
; PgBouncer configuration for PyPKI (transaction-mode pooling).
; Install at /etc/pgbouncer/pgbouncer.ini and adjust the values below.
; See docs/POSTGRES.md for full setup guide.

[databases]
{target_db} = host={db_host} port={db_port} dbname={target_db}

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {listen_port}
pool_mode = transaction          ; CRITICAL: session mode breaks advisory locks held across txs
max_client_conn = 1000
default_pool_size = {pool_size}
reserve_pool_size = 8
server_tls_sslmode = require
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
logfile = /var/log/pgbouncer/pgbouncer.log
pidfile = /run/pgbouncer/pgbouncer.pid
admin_users = pgbouncer
"""

USERLIST_TEMPLATE = """\
; /etc/pgbouncer/userlist.txt
; Format: "username" "password-hash"
; Generate hash: psql -c "SELECT passwd FROM pg_shadow WHERE usename='pypki';"
"{role}" "SCRAM-SHA-256$..."
"""


def emit_sample(
    target_db: str,
    role: str,
    db_host: str = "127.0.0.1",
    db_port: int = 5432,
    listen_port: int = 6432,
    pool_size: int = 32,
    output_dir: Optional[Path] = None,
) -> str:
    """Return a sample PgBouncer config string and optionally write it to disk."""
    config = SAMPLE_TEMPLATE.format(
        target_db=target_db,
        role=role,
        db_host=db_host,
        db_port=db_port,
        listen_port=listen_port,
        pool_size=pool_size,
    )
    userlist = USERLIST_TEMPLATE.format(role=role)

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "pgbouncer.ini.sample").write_text(config)
        (output_dir / "userlist.txt.sample").write_text(userlist)
        log.info("PgBouncer sample config written to %s/", output_dir)

    return config


def verify_connectivity(
    *,
    host: str = "127.0.0.1",
    port: int = 6432,
    dbname: str,
    role: str,
    password: str,
) -> bool:
    """Probe PgBouncer by opening and immediately closing a connection.

    Returns True on success, False on failure (never raises).
    """
    try:
        import psycopg  # type: ignore[import]
        dsn = f"host={host} port={port} dbname={dbname} user={role} password={password} connect_timeout=5"
        conn = psycopg.connect(dsn, autocommit=True)
        conn.execute("SELECT 1")
        conn.close()
        log.info("PgBouncer connectivity verified at %s:%d", host, port)
        return True
    except Exception as e:
        log.warning("PgBouncer connectivity check failed: %s", e)
        return False
