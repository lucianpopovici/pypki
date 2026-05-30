#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
restore.py — Scripted, idempotent restore for PyPKI backups.

This module decrypts, verifies, and stages backup content produced by
backup.py. It never writes to the live CA directory — operators point
the restored content at a staging directory and promote it manually.

Public API
----------
    RestoreResult    -- frozen dataclass with restore outcome details
    RestoreEngine    -- restore()

Selective restore
-----------------
Pass ``tables=["certificates", "revocations", ...]`` to restore only
specific SQL tables from the DB dump. The SQL dump is parsed line-by-line;
only CREATE TABLE and INSERT statements for the listed tables are written.
This is used in the leaf-compromise runbook to replace cert/revocation
data without touching the audit chain.

Safe-to-replace table allowlist
---------------------------------
    certificates
    revocations
    certificate_requests
    pending_requests

Other tables (audit, audit_chain, policy_decisions, etc.) must NOT be
selectively replaced — it would break chain integrity.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import re
import sqlite3
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from backup import _decrypt_tarball, _verify_tarball

if TYPE_CHECKING:
    from db import Database

logger = logging.getLogger("pypki.restore")

# Tables that may be selectively restored without breaking audit chain integrity.
SAFE_RESTORE_TABLES = frozenset([
    "certificates",
    "revocations",
    "certificate_requests",
    "pending_requests",
])


# ---------------------------------------------------------------------------
# RestoreResult
# ---------------------------------------------------------------------------

@dataclass
class RestoreResult:
    """Outcome of a restore operation."""
    manifest: Dict
    verified: bool
    files_restored: List[str]
    dry_run: bool
    outcome: str   # 'ok' | 'failed'
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# SQL filtering for selective restore
# ---------------------------------------------------------------------------

def _filter_sql_for_tables(sql: str, tables: List[str]) -> str:
    """
    Return only the CREATE TABLE and INSERT statements for *tables*
    from a SQLite .dump() SQL string.

    Also includes the leading PRAGMA and transaction boilerplate so the
    filtered SQL is re-importable as-is.
    """
    table_set = set(tables)
    out_lines: List[str] = []

    # Always include the header lines (BEGIN TRANSACTION, PRAGMA, etc.)
    in_target_create = False
    skip_until_semicolon = False

    lines = sql.split("\n")
    for line in lines:
        stripped = line.strip()

        # Always keep boilerplate
        if stripped.startswith("BEGIN TRANSACTION"):
            out_lines.append(line)
            continue
        if stripped.startswith("COMMIT"):
            out_lines.append(line)
            continue
        if stripped.upper().startswith("PRAGMA"):
            out_lines.append(line)
            continue

        # Detect CREATE TABLE
        m = re.match(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?"?(\w+)"?', stripped, re.IGNORECASE)
        if m:
            table_name = m.group(1)
            if table_name in table_set:
                in_target_create = True
                out_lines.append(line)
            else:
                in_target_create = False
                skip_until_semicolon = True
            continue

        # Detect INSERT INTO
        m2 = re.match(r'INSERT INTO\s+"?(\w+)"?', stripped, re.IGNORECASE)
        if m2:
            table_name = m2.group(1)
            if table_name in table_set:
                out_lines.append(line)
                skip_until_semicolon = False
                in_target_create = False
            else:
                skip_until_semicolon = True
                in_target_create = False
            continue

        # We're inside a CREATE TABLE block or skipping
        if in_target_create:
            out_lines.append(line)
            if ";" in stripped:
                in_target_create = False
            continue

        if skip_until_semicolon:
            if ";" in stripped:
                skip_until_semicolon = False
            continue

        # Blank lines and comments pass through
        if not stripped or stripped.startswith("--"):
            out_lines.append(line)

    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# RestoreEngine
# ---------------------------------------------------------------------------

class RestoreEngine:
    """
    Verifies and stages PyPKI backups to a destination directory.

    Parameters
    ----------
    db : DAL Database for recording restore_events rows.
         Pass None to skip DB recording (e.g. in tests without a DB).
    """

    def __init__(self, db: Optional["Database"]) -> None:
        self._db = db

    def restore(
        self,
        backup_path: Path,
        dest_dir: Path,
        passphrase: Optional[bytes] = None,
        dry_run: bool = False,
        db_only: bool = False,
        keys_only: bool = False,
        tables: Optional[List[str]] = None,
    ) -> RestoreResult:
        """
        Restore a backup to *dest_dir*.

        Parameters
        ----------
        backup_path : path to the backup file (.tar.gz or .tar.gz.enc)
        dest_dir    : staging directory to write files into
        passphrase  : decryption passphrase (required for .enc files)
        dry_run     : if True, verify but do not write any files
        db_only     : only restore db/ content (skip keys/)
        keys_only   : only restore keys/ content (skip db/)
        tables      : selective table restore from db/ (implies db_only logic
                      for DB content; other content still restored unless
                      combined with db_only)

        Returns
        -------
        RestoreResult
        """
        started_at = datetime.now(timezone.utc).isoformat()
        files_restored: List[str] = []
        manifest: Dict = {}

        try:
            # Step 1: read and optionally decrypt
            raw = backup_path.read_bytes()
            encrypted = str(backup_path).endswith(".enc")
            if encrypted:
                if passphrase is None:
                    raise ValueError("Backup is encrypted but no passphrase provided")
                tarball_bytes = _decrypt_tarball(raw, passphrase)
            else:
                tarball_bytes = raw

            # Step 2: open tarball and extract all members
            tar_contents: Dict[str, bytes] = {}
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    f = tf.extractfile(member)
                    if f is not None:
                        parts = member.name.split("/", 1)
                        rel = parts[1] if len(parts) > 1 else member.name
                        tar_contents[rel] = f.read()

            # Step 3+4: verify via _verify_tarball (re-reads tarball but consistent)
            manifest = _verify_tarball(tarball_bytes, passphrase=None)

            # Step 5: dry_run → stop here
            if dry_run:
                result = RestoreResult(
                    manifest=manifest,
                    verified=True,
                    files_restored=[],
                    dry_run=True,
                    outcome="ok",
                )
                self._record_event(
                    started_at=started_at,
                    manifest_hash=self._manifest_hash(manifest),
                    dry_run=True,
                    tables=tables,
                    outcome="ok",
                )
                return result

            # Step 6: write files to dest_dir
            dest_dir.mkdir(parents=True, exist_ok=True)

            for rel_path, data in tar_contents.items():
                # Skip internal control files
                if rel_path in ("manifest.json", "signature"):
                    continue

                # Apply db_only / keys_only filters
                if db_only and not rel_path.startswith("db/"):
                    continue
                if keys_only and not rel_path.startswith("keys/"):
                    continue

                # Step 7: selective table restore for DB files
                if rel_path.startswith("db/") and tables is not None:
                    if not _restore_db_file(rel_path, data, tables, dest_dir):
                        continue
                    files_restored.append(rel_path)
                    continue

                # Normal file write
                dest_file = dest_dir / rel_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                dest_file.write_bytes(data)
                files_restored.append(rel_path)
                logger.debug(f"Restored {rel_path} ({len(data)} bytes)")

            completed_at = datetime.now(timezone.utc).isoformat()
            result = RestoreResult(
                manifest=manifest,
                verified=True,
                files_restored=files_restored,
                dry_run=False,
                outcome="ok",
            )
            self._record_event(
                started_at=started_at,
                manifest_hash=self._manifest_hash(manifest),
                dry_run=False,
                tables=tables,
                outcome="ok",
                completed_at=completed_at,
            )
            return result

        except Exception as exc:
            logger.error(f"Restore failed: {exc}")
            completed_at = datetime.now(timezone.utc).isoformat()
            self._record_event(
                started_at=started_at,
                manifest_hash=self._manifest_hash(manifest),
                dry_run=dry_run,
                tables=tables,
                outcome="failed",
                completed_at=completed_at,
            )
            return RestoreResult(
                manifest=manifest,
                verified=False,
                files_restored=files_restored,
                dry_run=dry_run,
                outcome="failed",
                error=str(exc),
            )

    def _manifest_hash(self, manifest: Dict) -> str:
        import hashlib
        return hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode()
        ).hexdigest()

    def _record_event(
        self,
        started_at: str,
        manifest_hash: str,
        dry_run: bool,
        tables: Optional[List[str]],
        outcome: str,
        completed_at: Optional[str] = None,
    ) -> None:
        if self._db is None:
            return
        try:
            self._db.execute(
                "INSERT INTO restore_events "
                "(started_at, completed_at, manifest_hash, dry_run, "
                " initiator, selective_tables, outcome) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    started_at,
                    completed_at,
                    manifest_hash,
                    1 if dry_run else 0,
                    "cli",
                    json.dumps(tables) if tables else None,
                    outcome,
                ),
            )
        except Exception as exc:
            logger.warning(f"Could not record restore event: {exc}")


# ---------------------------------------------------------------------------
# DB file restore with selective table filtering
# ---------------------------------------------------------------------------

def _restore_db_file(
    rel_path: str,
    gz_data: bytes,
    tables: List[str],
    dest_dir: Path,
) -> bool:
    """
    Decompress and optionally filter a DB SQL dump, then write it.

    Returns True if something was written, False if nothing to write.
    """
    # Validate requested tables against the allowlist
    bad = [t for t in tables if t not in SAFE_RESTORE_TABLES]
    if bad:
        raise ValueError(
            f"Tables not in safe-restore allowlist: {bad}. "
            f"Allowed: {sorted(SAFE_RESTORE_TABLES)}"
        )

    # Decompress
    sql = gzip.decompress(gz_data).decode()

    # Filter
    filtered_sql = _filter_sql_for_tables(sql, tables)

    if not filtered_sql.strip():
        logger.debug(f"No matching tables in {rel_path}; skipping")
        return False

    dest_file = dest_dir / rel_path
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    dest_file.write_text(filtered_sql)
    logger.debug(f"Wrote filtered SQL for {tables} to {dest_file}")
    return True
