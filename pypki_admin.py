#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
pypki_admin.py — operator CLI for offline PyPKI tasks.

This is separate from ``pki_server.py`` (the running server) on purpose —
admin tasks are offline, run by humans, and shouldn't share argparse with
the 100+ server-runtime flags. Today it covers only data migration; future
admin tasks (rotate-ca-passphrase, monitor-expiry, etc.) belong here too.

Subcommands
-----------

  migrate-data       Copy all canonical state from one DAL backend to another.
  verify-migration   Confirm a destination matches its source after migration.

Both subcommands operate on ALL FOUR PyPKI logical databases (pki, audit,
acme, scep) by default. Supply ``--namespace`` to limit scope.

Examples
--------

  # SQLite ./ca/ → Postgres (one DB per namespace; the destination
  # databases must already exist and have schema migrations applied).
  python pypki_admin.py migrate-data \\
      --from-ca-dir ./ca \\
      --to-db-url-tmpl 'postgresql://pypki@localhost/pypki_{namespace}'

  python pypki_admin.py verify-migration \\
      --from-ca-dir ./ca \\
      --to-db-url-tmpl 'postgresql://pypki@localhost/pypki_{namespace}'

  # Per-namespace explicit URLs:
  python pypki_admin.py migrate-data \\
      --from-url-pki   sqlite:///ca/certificates.db \\
      --from-url-audit sqlite:///ca/audit.db \\
      --to-url-pki     postgresql://localhost/pypki_pki \\
      --to-url-audit   postgresql://localhost/pypki_audit \\
      --namespace pki --namespace audit

The runbook in ``docs/MIGRATION.md`` and ``docs/STORAGE.md`` walks through
the full operator procedure (stop service, run migrate-data, run
verify-migration, restart with new URL).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

import db
import migration
import migrations as migration_runner_mod


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# URL resolution
# ---------------------------------------------------------------------------

def _resolve_urls(args: argparse.Namespace, side: str) -> Dict[str, str]:
    """Return ``{namespace: db_url}`` for ``side`` ('from' or 'to').

    Argument precedence (most to least specific):
      1. ``--{side}-url-<namespace>`` per-namespace explicit URL
      2. ``--{side}-db-url-tmpl`` template like ``postgresql://.../{namespace}``
      3. ``--{side}-ca-dir`` directory containing the four .db files (sqlite only)
    """
    out: Dict[str, str] = {}
    for ns, default_file, _ in migration_runner_mod.PYPKI_NAMESPACES:
        explicit = getattr(args, f"{side}_url_{ns}", None)
        if explicit:
            out[ns] = explicit
            continue
        tmpl = getattr(args, f"{side}_db_url_tmpl", None)
        if tmpl:
            out[ns] = tmpl.format(namespace=ns)
            continue
        ca_dir = getattr(args, f"{side}_ca_dir", None)
        if ca_dir:
            out[ns] = f"sqlite:///{Path(ca_dir).resolve() / default_file}"
            continue
    return out


def _make_factory(urls: Dict[str, str]) -> Callable[[str], db.Database]:
    """Return a function that opens the right DB for a given namespace."""
    def factory(ns: str) -> db.Database:
        if ns not in urls:
            raise SystemExit(
                f"no database URL configured for namespace {ns!r} — "
                f"pass --from-ca-dir/--to-ca-dir, "
                f"--from-db-url-tmpl/--to-db-url-tmpl, "
                f"or --from-url-{ns}/--to-url-{ns}"
            )
        return db.make_db(urls[ns])
    return factory


def _selected_namespaces(args: argparse.Namespace) -> List[str]:
    if not args.namespace:
        return list(migration.TABLE_CATALOG.keys())
    bad = [ns for ns in args.namespace if ns not in migration.TABLE_CATALOG]
    if bad:
        raise SystemExit(f"unknown namespace(s): {', '.join(bad)}. "
                         f"Valid: {', '.join(migration.TABLE_CATALOG)}")
    return list(args.namespace)


# ---------------------------------------------------------------------------
# Subcommand: migrate-data
# ---------------------------------------------------------------------------

def cmd_migrate_data(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.migrate-data")

    src_urls = _resolve_urls(args, "from")
    dst_urls = _resolve_urls(args, "to")
    namespaces = _selected_namespaces(args)

    missing = [ns for ns in namespaces if ns not in src_urls or ns not in dst_urls]
    if missing:
        raise SystemExit(
            f"missing source or destination URL for: {', '.join(missing)}"
        )

    log.info(f"migrating namespaces: {', '.join(namespaces)}")
    for ns in namespaces:
        log.info(f"  {ns}: {src_urls[ns]!r} → {dst_urls[ns]!r}")

    if not args.yes:
        log.warning(
            "PyPKI MUST be stopped before running migrate-data. "
            "Continuing without --yes prompts for confirmation."
        )
        try:
            ans = input("Type 'yes' to proceed: ").strip().lower()
        except EOFError:
            ans = ""
        if ans != "yes":
            log.error("aborted by user")
            return 1

    src_factory = _make_factory(src_urls)
    dst_factory = _make_factory(dst_urls)

    try:
        results = migration.migrate_all(
            src_factory, dst_factory,
            batch=args.batch,
            namespaces=namespaces,
        )
    except migration.MigrationError as e:
        log.error(f"migration failed: {e}")
        return 2

    total_rows = 0
    for ns, table_counts in results.items():
        for table, n in table_counts.items():
            total_rows += n
    log.info(f"✅ migration complete: {total_rows} rows copied across "
             f"{len(results)} namespace(s)")
    log.info("Next: run `pypki-admin verify-migration` with the same URLs.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: verify-migration
# ---------------------------------------------------------------------------

def cmd_verify_migration(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.verify-migration")

    src_urls = _resolve_urls(args, "from")
    dst_urls = _resolve_urls(args, "to")
    namespaces = _selected_namespaces(args)

    missing = [ns for ns in namespaces if ns not in src_urls or ns not in dst_urls]
    if missing:
        raise SystemExit(
            f"missing source or destination URL for: {', '.join(missing)}"
        )

    src_factory = _make_factory(src_urls)
    dst_factory = _make_factory(dst_urls)

    errors = migration.verify_all(
        src_factory, dst_factory,
        sample=args.sample,
        namespaces=namespaces,
    )

    total_errors = sum(len(v) for v in errors.values())
    if total_errors == 0:
        log.info(f"✅ verification PASSED for namespaces: {', '.join(namespaces)}")
        return 0

    log.error(f"❌ verification FAILED with {total_errors} error(s)")
    for ns in namespaces:
        for err in errors.get(ns, []):
            log.error(f"  {err}")
    log.error("Migration is NOT safe to commit. Investigate and re-run.")
    return 3


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_url_args(p: argparse.ArgumentParser, side: str) -> None:
    """Add the {side}-url group: ca-dir / db-url-tmpl / per-namespace URLs."""
    side_label = "source" if side == "from" else "destination"
    g = p.add_argument_group(
        f"{side_label} URL ({side}-side)",
        f"How to reach the {side_label} databases. "
        f"Use --{side}-ca-dir for the SQLite-only common case, "
        f"--{side}-db-url-tmpl for a Postgres-deployment-per-namespace, "
        f"or per-namespace --{side}-url-NS for full control.",
    )
    g.add_argument(
        f"--{side}-ca-dir", default=None, metavar="DIR",
        help=f"Directory holding the four logical SQLite files "
             f"({', '.join(f for _, f, _ in migration_runner_mod.PYPKI_NAMESPACES)}). "
             f"Resolves to sqlite:///<dir>/<file> per namespace.",
    )
    g.add_argument(
        f"--{side}-db-url-tmpl", default=None, metavar="URL_TMPL",
        help="DAL URL template with literal '{namespace}' placeholder, e.g. "
             "'postgresql://pypki@localhost/pypki_{namespace}'.",
    )
    for ns, _, _ in migration_runner_mod.PYPKI_NAMESPACES:
        g.add_argument(
            f"--{side}-url-{ns}", default=None, metavar="URL",
            help=f"Explicit DAL URL for the '{ns}' namespace. "
                 f"Wins over both --{side}-ca-dir and --{side}-db-url-tmpl.",
        )


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--namespace", action="append", default=None,
        choices=list(migration.TABLE_CATALOG.keys()),
        help="Limit operation to one or more namespaces (repeat the flag to "
             "select several). Default: all four namespaces.",
    )
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="pypki-admin",
        description="Offline admin tools for PyPKI deployments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = root.add_subparsers(dest="command", required=True)

    md = sub.add_parser(
        "migrate-data",
        help="Copy canonical state from one DAL backend to another.",
        description=(
            "Copy all canonical (non-ephemeral) state from a source backend "
            "to a destination. The destination MUST already have its schema "
            "applied at the same version as the source — run "
            "`pypki migrate --db-url <dst>` against each destination DB first."
        ),
    )
    _add_url_args(md, "from")
    _add_url_args(md, "to")
    _add_common_args(md)
    md.add_argument(
        "--batch", type=int, default=10_000,
        help="Rows per batch when copying large tables (default 10000).",
    )
    md.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the 'PyPKI must be stopped' confirmation prompt.",
    )
    md.set_defaults(func=cmd_migrate_data)

    vm = sub.add_parser(
        "verify-migration",
        help="Confirm a destination matches its source after migration.",
        description=(
            "Compare row counts, randomly-sampled row contents, and sequence "
            "state between the source and destination backends. Exit code 0 "
            "means safe to cut over; non-zero means there's drift."
        ),
    )
    _add_url_args(vm, "from")
    _add_url_args(vm, "to")
    _add_common_args(vm)
    vm.add_argument(
        "--sample", type=int, default=100,
        help="Per-table random sample size for content comparison "
             "(default 100). Larger = slower but stronger evidence.",
    )
    vm.set_defaults(func=cmd_verify_migration)

    return root


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
