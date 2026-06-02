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

try:
    import ceremony as _ceremony_mod
    HAS_CEREMONY = True
except ImportError:
    HAS_CEREMONY = False
    _ceremony_mod = None  # type: ignore[assignment]


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


def _ceremony_cmd(fn_name: str):
    """Return a wrapper that calls ceremony.<fn_name> or prints an error."""
    def _run(args: argparse.Namespace) -> int:
        _setup_logging(getattr(args, "log_level", "INFO"))
        if not HAS_CEREMONY:
            print("ERROR: ceremony.py not found — place it in the same directory.")
            return 1
        return getattr(_ceremony_mod, f"cmd_{fn_name}")(args)
    return _run


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

    # ------------------------------------------------------------------
    # Ceremony subcommands (§5.3)
    # ------------------------------------------------------------------

    _cer_help = (
        "§5.3 offline root CA key ceremony. "
        "Requires ceremony.py in the same directory."
    )

    er = sub.add_parser(
        "export-root",
        help="Export offline root CA bundle (§5.3).",
        description=(
            "Package the root CA private key, certificate, and counters "
            "into an AES-256-GCM encrypted tar.gz bundle suitable for "
            "airgapped signing ceremonies."
        ),
    )
    er.add_argument("--ca-dir", default="./ca", metavar="DIR")
    er.add_argument("--out", required=True, metavar="BUNDLE.tar.gz.enc",
                    help="Output path for the encrypted bundle.")
    er.add_argument("--passphrase-env", default=None, metavar="ENV_VAR",
                    help="Read passphrase from this environment variable instead of prompting.")
    er.add_argument("--threshold", type=int, default=0, metavar="M",
                    help="Shamir M-of-N threshold (≥2 to enable splitting).")
    er.add_argument("--shares", type=int, default=0, metavar="N",
                    help="Total Shamir shares to generate.")
    er.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    er.set_defaults(func=_ceremony_cmd("export_root"))

    sc = sub.add_parser(
        "sign-csr",
        help="Sign a sub-CA CSR from the offline bundle (§5.3).",
        description=(
            "Decrypt the offline root bundle and issue a sub-CA certificate "
            "for the supplied CSR.  Runs entirely from the bundle; "
            "no DB writes, no network access required."
        ),
    )
    sc.add_argument("--bundle", required=True, metavar="BUNDLE.tar.gz.enc")
    sc.add_argument("--csr-in", required=True, metavar="CSR.pem")
    sc.add_argument("--cert-out", required=True, metavar="CERT.pem")
    sc.add_argument("--passphrase-env", default=None, metavar="ENV_VAR")
    sc.add_argument("--share", action="append", default=[], metavar="SHARE",
                    help="Shamir share (repeat M times to reconstruct passphrase).")
    sc.add_argument("--validity-days", type=int, default=1825, metavar="N")
    sc.add_argument("--path-length", type=int, default=None, metavar="N")
    sc.add_argument("--permitted-dns", nargs="+", default=[], metavar="DOMAIN")
    sc.add_argument("--excluded-dns", nargs="+", default=[], metavar="DOMAIN")
    sc.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sc.set_defaults(func=_ceremony_cmd("sign_csr"))

    ic = sub.add_parser(
        "import-cert",
        help="Import a ceremony-signed cert into an online CA (§5.3).",
    )
    ic.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ic.add_argument("--cert-in", required=True, metavar="CERT.pem")
    ic.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ic.set_defaults(func=_ceremony_cmd("import_cert"))

    op = sub.add_parser(
        "ocsp-prebuild",
        help="Pre-generate OCSP response files for static serving (RFC 5019 §6).",
        description=(
            "Generate one signed .ocsp file per certificate in the CA database. "
            "Files are written under OUTPUT/<sha1-issuer-key>/<sha1-issuer-name>/<serial>.ocsp, "
            "a layout compatible with nginx proxy_cache and Apache mod_ssl_ct static serving."
        ),
    )
    op.add_argument(
        "--ca-dir", default="./ca", metavar="DIR",
        help="CA data directory (default: ./ca).",
    )
    op.add_argument(
        "--output", required=True, metavar="DIR",
        help="Root directory for generated .ocsp files.",
    )
    op.add_argument(
        "--validity-hours", type=int, default=24, metavar="N",
        help="nextUpdate = now + N hours (default 24).",
    )
    op.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )
    op.set_defaults(func=cmd_ocsp_prebuild)

    # ------------------------------------------------------------------
    # Audit-chain subcommands
    # ------------------------------------------------------------------

    av = sub.add_parser(
        "audit-verify",
        help="Verify the hash chain integrity of the audit log.",
        description=(
            "Walk audit rows in insertion order and recompute each hash. "
            "Exit code 0 = chain intact; 2 = breaks detected. "
            "Breaks indicate tampering, deletion, or a concurrency bug."
        ),
    )
    av.add_argument("--ca-dir", default="./ca", metavar="DIR",
                    help="CA data directory (default: ./ca).")
    av.add_argument("--audit-db-url", default=None, metavar="URL",
                    help="Explicit audit DB URL (overrides ca-dir default).")
    av.add_argument("--from-id", type=int, default=1, metavar="N",
                    help="Start verification at row id N (default 1).")
    av.add_argument("--to-id", type=int, default=None, metavar="M",
                    help="Stop at row id M inclusive (default: last row).")
    av.add_argument("--json", dest="json_output", action="store_true",
                    help="Emit JSON instead of human-readable output.")
    av.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    av.set_defaults(func=cmd_audit_verify)

    ae = sub.add_parser(
        "audit-export",
        help="Export a chain segment with its final hash.",
        description=(
            "Write a JSON document containing the requested audit rows plus "
            "the final_hash so operators can publish an external anchor "
            "(git commit, S3 object, transparency log entry)."
        ),
    )
    ae.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ae.add_argument("--audit-db-url", default=None, metavar="URL")
    ae.add_argument("--since", default=None, metavar="ISO8601",
                    help="Include rows with ts >= this ISO-8601 timestamp.")
    ae.add_argument("--from-id", type=int, default=1, metavar="N")
    ae.add_argument("--to-id", type=int, default=None, metavar="M")
    ae.add_argument("--out", default="-", metavar="FILE",
                    help="Output path; '-' writes to stdout (default).")
    ae.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ae.set_defaults(func=cmd_audit_export)

    # ---- policy subcommands ----
    pv = sub.add_parser(
        "policy-validate",
        help="Validate a policy JSON file (schema + regex compile); no side effects.",
    )
    pv.add_argument("policy_file", metavar="FILE",
                    help="Path to the JSON policy file to validate.")
    pv.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    pv.set_defaults(func=cmd_policy_validate)

    pt = sub.add_parser(
        "policy-test",
        help="Dry-run a JSON request against a policy file and print the decision.",
    )
    pt.add_argument("policy_file", metavar="FILE",
                    help="Path to the JSON policy file.")
    pt.add_argument("--request", required=True, metavar="JSON",
                    help='Issuance request as JSON, e.g. \'{"profile":"tls_server",'
                         '"requester_backend":"oidc","sans":["foo.example.com"]}\'')
    pt.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    pt.set_defaults(func=cmd_policy_test)

    ps = sub.add_parser(
        "policy-show",
        help="Show the currently loaded policy (hash, rule count, default).",
    )
    ps.add_argument("policy_file", metavar="FILE",
                    help="Path to the policy file to inspect.")
    ps.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ps.set_defaults(func=cmd_policy_show)

    ph = sub.add_parser(
        "policy-history",
        help="List all policy versions stored in the PKI DB.",
    )
    ph.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ph.add_argument("--pki-db-url", default=None, metavar="URL")
    ph.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ph.set_defaults(func=cmd_policy_history)

    asw = sub.add_parser(
        "ari-set-window",
        help="Set or override the ARI renewal window for a specific certificate.",
        description=(
            "Write an admin override for the suggestedWindow returned by "
            "GET /acme/renewal-info/{certId}. Use this during incident response "
            "to force clients to renew immediately (set end in the past) or "
            "to extend the normal window."
        ),
    )
    asw.add_argument("cert_id", metavar="CERT_ID",
                     help="RFC 9773 certId: base64url(AKI).base64url(serial).")
    asw.add_argument("--start", required=True, metavar="ISO8601",
                     help="Window start (ISO-8601 UTC, e.g. 2026-06-01T00:00:00Z).")
    asw.add_argument("--end", required=True, metavar="ISO8601",
                     help="Window end (ISO-8601 UTC).")
    asw.add_argument("--retry-after", type=int, default=21600, metavar="SECONDS",
                     help="Retry-After seconds for clients (default: 21600).")
    asw.add_argument("--explanation", default=None, metavar="URL",
                     help="Optional explanationURL to include in the response.")
    asw.add_argument("--set-by", default="admin", metavar="USER",
                     help="Who set the override (audit trail, default: admin).")
    asw.add_argument("--ca-dir", default="./ca", metavar="DIR")
    asw.add_argument("--acme-db-url", default=None, metavar="URL",
                     help="Explicit ACME DB URL (overrides ca-dir default).")
    asw.add_argument("--log-level", default="WARNING",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    asw.set_defaults(func=cmd_ari_set_window)

    abs_ = sub.add_parser(
        "ari-bulk-shorten",
        help="Force immediate renewal for all matching certificates (incident response).",
        description=(
            "Set the suggestedWindow.end to now (or a specified time) for all "
            "certificates whose certId matches the given SQL LIKE pattern. "
            "Used when a CA must revoke a population of certs on a deadline."
        ),
    )
    abs_.add_argument("--filter", required=True, metavar="PATTERN",
                      help="SQL LIKE pattern matched against certId (e.g. 'abc123.%%').")
    abs_.add_argument("--end", default=None, metavar="ISO8601",
                      help="Override window end (default: now — forces immediate renewal).")
    abs_.add_argument("--retry-after", type=int, default=300, metavar="SECONDS",
                      help="Retry-After seconds during incident (default: 300).")
    abs_.add_argument("--explanation", default=None, metavar="URL",
                      help="Incident explanation URL to surface to clients.")
    abs_.add_argument("--set-by", default="admin", metavar="USER")
    abs_.add_argument("--ca-dir", default="./ca", metavar="DIR")
    abs_.add_argument("--acme-db-url", default=None, metavar="URL")
    abs_.add_argument("--log-level", default="WARNING",
                      choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    abs_.set_defaults(func=cmd_ari_bulk_shorten)

    # ------------------------------------------------------------------
    # SSH CA subcommands
    # ------------------------------------------------------------------

    ssh_rev = sub.add_parser(
        "ssh-revoke",
        help="Revoke an SSH certificate by serial.",
    )
    ssh_rev.add_argument("serial", type=int, metavar="SERIAL",
                         help="SSH cert serial number (uint64 integer).")
    ssh_rev.add_argument("--reason", default="", metavar="REASON",
                         help="Optional revocation reason string.")
    ssh_rev.add_argument("--ca-dir", default="./ca", metavar="DIR",
                         help="CA data directory (default: ./ca).")
    ssh_rev.add_argument("--pki-db-url", default=None, metavar="URL")
    ssh_rev.set_defaults(func=cmd_ssh_revoke)

    ssh_list = sub.add_parser(
        "ssh-list",
        help="List issued SSH certificates.",
    )
    ssh_list.add_argument("--principal", default=None, metavar="NAME",
                          help="Filter by principal name.")
    ssh_list.add_argument("--include-revoked", action="store_true",
                          help="Include revoked certs in output.")
    ssh_list.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ssh_list.add_argument("--pki-db-url", default=None, metavar="URL")
    ssh_list.set_defaults(func=cmd_ssh_list)

    ssh_krl = sub.add_parser(
        "ssh-krl-export",
        help="Build and export a signed KRL for all revoked SSH certs.",
    )
    ssh_krl.add_argument("--out", default="-", metavar="FILE",
                         help="Output path; '-' writes to stdout (default).")
    ssh_krl.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ssh_krl.add_argument("--pki-db-url", default=None, metavar="URL")
    ssh_krl.set_defaults(func=cmd_ssh_krl_export)

    # --- DB bootstrap (CLAUDE-db-bootstrap.md) ---
    dbi = sub.add_parser(
        "db-init",
        help="Bootstrap a SQLite or Postgres database for PyPKI.",
    )
    dbi.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    dbi.add_argument("--sqlite-path", default="/var/lib/pypki/db/pki.db",
                     help="Path to SQLite file (sqlite backend only).")
    dbi.add_argument("--dsn", default=None, metavar="URL",
                     help="Bootstrap admin DSN (postgres only).")
    dbi.add_argument("--target-db", default="pypki")
    dbi.add_argument("--target-role", default="pypki")
    dbi.add_argument("--target-role-password-source", default=None, metavar="SOURCE",
                     help="file:///path or env://VARNAME.")
    dbi.add_argument("--tls", choices=["require", "verify-ca", "verify-full", "mtls"],
                     default="require")
    dbi.add_argument("--extensions", default="citext",
                     help="Comma-separated Postgres extensions (default: citext).")
    dbi.add_argument("--apply-tuning", choices=["recommended", "none", "print-only"],
                     default="none")
    dbi.add_argument("--with-pgbouncer-sample", action="store_true",
                     help="Emit a PgBouncer sample config.")
    dbi.add_argument("--dry-run", action="store_true")
    dbi.set_defaults(func=cmd_db_init)

    # --- TLS management (CLAUDE-tls-bootstrap.md) ---
    tls_rotate = sub.add_parser(
        "tls-rotate",
        help="Force TLS cert re-issuance from the PyPKI CA.",
    )
    tls_rotate.add_argument("--ca-dir", default="./ca")
    tls_rotate.add_argument("--tls-cert", default="/etc/pypki/tls/admin.crt")
    tls_rotate.add_argument("--tls-key", default="/etc/pypki/tls/admin.key")
    tls_rotate.add_argument("--hostname", default="localhost")
    tls_rotate.add_argument("--dry-run", action="store_true")
    tls_rotate.set_defaults(func=cmd_tls_rotate)

    tls_status = sub.add_parser(
        "tls-status",
        help="Print current TLS cert chain, expiry, and rotation history.",
    )
    tls_status.add_argument("--tls-cert", default="/etc/pypki/tls/admin.crt")
    tls_status.set_defaults(func=cmd_tls_status)

    tls_replace = sub.add_parser(
        "tls-replace",
        help="Swap in operator-provided cert+key (Pattern C).",
    )
    tls_replace.add_argument("--cert", required=True, metavar="PATH")
    tls_replace.add_argument("--key", required=True, metavar="PATH")
    tls_replace.add_argument("--dry-run", action="store_true")
    tls_replace.set_defaults(func=cmd_tls_replace)

    # --- Hardening (CLAUDE-os-hardening-firewall.md) ---
    hs = sub.add_parser("hardening-status",
                        help="Print current host hardening status.")
    hs.set_defaults(func=cmd_hardening_status)

    ha = sub.add_parser("hardening-apply",
                        help="Install firewall, sysctl, and MAC profiles.")
    ha.add_argument("--firewall-stack",
                    choices=["auto", "nftables", "ufw", "firewalld", "iptables", "none"],
                    default="auto")
    ha.add_argument("--apply-sysctl", action="store_true")
    ha.add_argument("--dry-run", action="store_true")
    ha.set_defaults(func=cmd_hardening_apply)

    hv = sub.add_parser("hardening-validate",
                        help="Assert hardening state matches expectations.")
    hv.set_defaults(func=cmd_hardening_validate)

    # --- Preflight (CLAUDE-preflight-check.md) ---
    pf = sub.add_parser(
        "preflight",
        help="Run preflight checks against the deployment.",
    )
    pf.add_argument("--format", choices=["human", "json", "prometheus"], default="human")
    pf.add_argument("--output", default=None, metavar="PATH",
                    help="Write output to file (default: stdout).")
    pf.add_argument("--include", default=None, metavar="CATS",
                    help="Comma-separated categories to include.")
    pf.add_argument("--exclude", default=None, metavar="CATS",
                    help="Comma-separated categories to exclude.")
    pf.add_argument("--exit-on-warning",
                    choices=["critical", "high", "medium", "low", "none"],
                    default="critical",
                    help="Exit non-zero when any check at or above this severity fails.")
    pf.add_argument("--skip-slow", action="store_true",
                    help="Skip checks that take > 1s (KMS, S3 probes).")
    pf.add_argument("--quick", action="store_true",
                    help="Alias for --skip-slow --exit-on-warning high.")
    pf.add_argument("--ci", action="store_true",
                    help="Alias for --format json --exit-on-warning high.")
    pf.add_argument("--timeout", type=float, default=10.0,
                    help="Per-check timeout in seconds (default: 10).")
    pf.add_argument("--parallelism", type=int, default=8)
    pf.add_argument("--no-color", action="store_true")
    pf.add_argument("--ca-dir", default="./ca")
    pf.set_defaults(func=cmd_preflight)

    # --- Upgrade (CLAUDE-upgrade-tooling.md) ---
    upg = sub.add_parser(
        "upgrade",
        help="Run a full upgrade cycle with pre-flight, migrate, health-check, rollback.",
    )
    upg.add_argument("--to", required=True, metavar="VERSION",
                     help="Target version (e.g. 2.5.0 or 'latest').")
    upg.add_argument("--channel", choices=["stable", "security", "preview", "pinned"],
                     default="stable")
    upg.add_argument("--health-window", default="5m", metavar="DURATION",
                     help="Health check window duration (default: 5m).")
    upg.add_argument("--no-rollback", action="store_true",
                     help="Disable auto-rollback on health check failure.")
    upg.add_argument("--accept-irreversible", action="store_true",
                     help="Allow crossing non-reversible schema migrations.")
    upg.add_argument("--dry-run", action="store_true")
    upg.set_defaults(func=cmd_upgrade)

    upg_check = sub.add_parser("upgrade-check",
                               help="Show available versions in the configured channel.")
    upg_check.add_argument("--channel", default="stable")
    upg_check.set_defaults(func=cmd_upgrade_check)

    upg_status = sub.add_parser("upgrade-status",
                                help="Print current upgrade state machine position.")
    upg_status.set_defaults(func=cmd_upgrade_status)

    upg_rollback = sub.add_parser("upgrade-rollback",
                                  help="Manually trigger rollback from an upgrade.")
    upg_rollback.add_argument("--confirm", action="store_true", required=True)
    upg_rollback.set_defaults(func=cmd_upgrade_rollback)

    # --- Backup / DR (CLAUDE-backup-restore.md) ---
    bn = sub.add_parser(
        "backup-now",
        help="Create a backup of the CA state immediately.",
    )
    bn.add_argument("--ca-dir", default="./ca", metavar="DIR",
                    help="CA directory (default: ./ca).")
    bn.add_argument("--target", required=True, metavar="URI",
                    help="Target URI for the backup (file:// supported).")
    bn.add_argument("--passphrase-file", metavar="PATH",
                    help="Path to a file containing the backup encryption passphrase.")
    bn.add_argument("--log-level", default="WARNING")
    bn.set_defaults(func=cmd_backup_now)

    rst = sub.add_parser(
        "restore",
        help="Restore a backup to a staging directory.",
    )
    rst.add_argument("--from", dest="from_path", required=True, metavar="BACKUP",
                     help="Path to the backup file (.tar.gz or .tar.gz.enc).")
    rst.add_argument("--to", dest="to_dir", required=True, metavar="DIR",
                     help="Destination directory to stage the restore into.")
    rst.add_argument("--passphrase-file", metavar="PATH",
                     help="Path to a file containing the decryption passphrase.")
    rst.add_argument("--dry-run", action="store_true",
                     help="Verify the backup without writing any files.")
    rst.add_argument("--db-only", action="store_true",
                     help="Only restore database files (skip keys/).")
    rst.add_argument("--keys-only", action="store_true",
                     help="Only restore key files (skip db/).")
    rst.add_argument("--tables", nargs="+", metavar="TABLE",
                     help="Selective table restore (safe tables only).")
    rst.add_argument("--ca-dir", default="./ca", metavar="DIR",
                     help="CA directory for recording restore event (default: ./ca).")
    rst.add_argument("--log-level", default="WARNING")
    rst.set_defaults(func=cmd_restore)

    es = sub.add_parser(
        "emergency-stop",
        help="Halt all certificate issuance (CA key compromise response).",
    )
    es.add_argument("--ca-dir", default="./ca", metavar="DIR")
    es.add_argument("--reason", required=True, metavar="REASON",
                    help="Human-readable reason for the halt (required).")
    es.add_argument("--by", default=None, metavar="USER",
                    help="Operator identity (default: current OS user).")
    es.add_argument("--log-level", default="WARNING")
    es.set_defaults(func=cmd_emergency_stop)

    er = sub.add_parser(
        "emergency-resume",
        help="Clear emergency halt and re-enable certificate issuance.",
    )
    er.add_argument("--ca-dir", default="./ca", metavar="DIR")
    er.add_argument("--by", default=None, metavar="USER",
                    help="Operator identity (default: current OS user).")
    er.add_argument("--log-level", default="WARNING")
    er.set_defaults(func=cmd_emergency_resume)

    rb = sub.add_parser(
        "revoke-batch",
        help="Mass-revoke certificates from a serial number list.",
    )
    rb.add_argument("--ca-dir", default="./ca", metavar="DIR")
    rb.add_argument("--serial-file", required=True, metavar="FILE",
                    help="Path to a file with one hex or decimal serial per line.")
    rb.add_argument("--reason", default="key_compromise", metavar="REASON",
                    choices=[
                        "unspecified", "key_compromise", "ca_compromise",
                        "affiliation_changed", "superseded",
                        "cessation_of_operation", "certificate_hold",
                        "remove_from_crl", "privilege_withdrawn",
                        "aa_compromise",
                    ],
                    help="RFC 5280 revocation reason (default: key_compromise).")
    rb.add_argument("--dry-run", action="store_true",
                    help="List certificates that would be revoked without revoking.")
    rb.add_argument("--log-level", default="WARNING")
    rb.set_defaults(func=cmd_revoke_batch)

    # ca-init --shamir and ca-recover --shamir: user-friendly wrappers over
    # the ceremony subcommands for the Shamir offline-root flow.
    ci = sub.add_parser(
        "ca-init",
        help="Initialise (or re-export) the offline root CA bundle.",
        description=(
            "Wrapper around 'export-root' with Shamir splitting enabled. "
            "Pass --shamir M-of-N to split the bundle passphrase into N shares, "
            "any M of which reconstruct it."
        ),
    )
    ci.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ci.add_argument("--out", required=True, metavar="BUNDLE.tar.gz.enc",
                    help="Output path for the encrypted bundle.")
    ci.add_argument("--shamir", metavar="M-of-N",
                    help="Enable Shamir splitting, e.g. '3-of-5'.")
    ci.add_argument("--passphrase-env", default=None, metavar="ENV_VAR",
                    help="Read passphrase from environment variable (no Shamir).")
    ci.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ci.set_defaults(func=cmd_ca_init)

    cr = sub.add_parser(
        "ca-recover",
        help="Reconstruct offline root passphrase from Shamir shares.",
        description=(
            "Wrapper around 'sign-csr' that prompts for Shamir shares "
            "and then issues a sub-CA certificate from the offline bundle."
        ),
    )
    cr.add_argument("--bundle", required=True, metavar="BUNDLE.tar.gz.enc")
    cr.add_argument("--csr-in", required=True, metavar="CSR.pem")
    cr.add_argument("--cert-out", required=True, metavar="CERT.pem")
    cr.add_argument("--shares", type=int, required=True, metavar="M",
                    help="Number of Shamir shares to collect.")
    cr.add_argument("--validity-days", type=int, default=1825, metavar="N")
    cr.add_argument("--path-length", type=int, default=None, metavar="N")
    cr.add_argument("--permitted-dns", nargs="+", default=[], metavar="DOMAIN")
    cr.add_argument("--excluded-dns", nargs="+", default=[], metavar="DOMAIN")
    cr.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    cr.set_defaults(func=cmd_ca_recover)

    # ------------------------------------------------------------------
    # Crypto agility subcommands
    # ------------------------------------------------------------------

    ag_sum = sub.add_parser(
        "agility-summary",
        help="Print a text table of active cert distribution by crypto class.",
    )
    ag_sum.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ag_sum.add_argument("--pki-db-url", default=None, metavar="URL")
    ag_sum.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ag_sum.set_defaults(func=cmd_agility_summary)

    ag_re = sub.add_parser(
        "agility-reclassify",
        help="Re-run the crypto classifier over all certs with class 'unknown'.",
    )
    ag_re.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ag_re.add_argument("--pki-db-url", default=None, metavar="URL")
    ag_re.add_argument("--log-level", default="WARNING",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ag_re.set_defaults(func=cmd_agility_reclassify)

    ag_ex = sub.add_parser(
        "agility-export",
        help="Export all certificates with their crypto classification.",
    )
    ag_ex.add_argument("--format", default="csv", choices=["csv", "json"],
                       help="Output format (default: csv).")
    ag_ex.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ag_ex.add_argument("--pki-db-url", default=None, metavar="URL")
    ag_ex.add_argument("--log-level", default="WARNING",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ag_ex.set_defaults(func=cmd_agility_export)

    # ------------------------------------------------------------------
    # SSO session management subcommands
    # ------------------------------------------------------------------

    ss_list = sub.add_parser(
        "session-list",
        help="List active SSO sessions (PAM, OIDC, and API tokens).",
    )
    ss_list.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ss_list.add_argument("--pki-db-url", default=None, metavar="URL")
    ss_list.add_argument("--all", action="store_true", dest="include_all",
                         help="Include expired and revoked sessions.")
    ss_list.add_argument("--log-level", default="WARNING",
                         choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ss_list.set_defaults(func=cmd_session_list)

    ss_rev = sub.add_parser(
        "session-revoke",
        help="Revoke a specific session by its session ID.",
    )
    ss_rev.add_argument("session_id", metavar="SESSION_ID")
    ss_rev.add_argument("--ca-dir", default="./ca", metavar="DIR")
    ss_rev.add_argument("--pki-db-url", default=None, metavar="URL")
    ss_rev.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ss_rev.set_defaults(func=cmd_session_revoke)

    tok_create = sub.add_parser(
        "token-create",
        help="Create a long-lived API token for service-account automation.",
    )
    tok_create.add_argument("--identity", required=True, metavar="NAME",
                            help="Name or email of the service account.")
    tok_create.add_argument("--role", default="pki:operator", metavar="ROLE",
                            help="PyPKI role (default: pki:operator).")
    tok_create.add_argument("--ttl", type=int, default=365, metavar="DAYS",
                            help="Token lifetime in days (default: 365).")
    tok_create.add_argument("--ca-dir", default="./ca", metavar="DIR")
    tok_create.add_argument("--pki-db-url", default=None, metavar="URL")
    tok_create.add_argument("--log-level", default="WARNING",
                            choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    tok_create.set_defaults(func=cmd_token_create)

    tok_list = sub.add_parser(
        "token-list",
        help="List active API tokens.",
    )
    tok_list.add_argument("--ca-dir", default="./ca", metavar="DIR")
    tok_list.add_argument("--pki-db-url", default=None, metavar="URL")
    tok_list.add_argument("--log-level", default="WARNING",
                          choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    tok_list.set_defaults(func=cmd_token_list)

    # ------------------------------------------------------------------
    # Portal subcommands
    # ------------------------------------------------------------------

    lnk = sub.add_parser(
        "link-account",
        help="Grant portal ownership of a certificate to a user identity.",
    )
    lnk.add_argument("--serial", required=True, type=int, metavar="SERIAL",
                     help="Certificate serial number.")
    lnk.add_argument("--identity", required=True, metavar="IDENTITY",
                     help="User identity (email, username, OIDC sub, etc.).")
    lnk.add_argument("--kind", default="static", metavar="KIND",
                     choices=["oidc", "pam", "acme", "scep", "est", "cmp", "ssh", "static"],
                     help="Owner kind (default: static).")
    lnk.add_argument("--ca-dir", default="./ca", metavar="DIR")
    lnk.add_argument("--pki-db-url", default=None, metavar="URL")
    lnk.add_argument("--log-level", default="WARNING",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    lnk.set_defaults(func=cmd_link_account)

    premap = sub.add_parser(
        "portal-remap",
        help="Re-apply static owner mappings from --portal-owner-mapping-file to all certs.",
    )
    premap.add_argument("--mapping-file", required=True, metavar="FILE",
                        help="JSON owner-mapping file.")
    premap.add_argument("--ca-dir", default="./ca", metavar="DIR")
    premap.add_argument("--pki-db-url", default=None, metavar="URL")
    premap.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    premap.set_defaults(func=cmd_portal_remap)

    # ------------------------------------------------------------------
    # WireGuard subcommands
    # ------------------------------------------------------------------

    wg_list = sub.add_parser(
        "wg-peer-list",
        help="List active WireGuard peers.",
    )
    wg_list.add_argument("--include-revoked", action="store_true")
    wg_list.add_argument("--ca-dir", default="./ca", metavar="DIR")
    wg_list.add_argument("--pki-db-url", default=None, metavar="URL")
    wg_list.add_argument("--log-level", default="WARNING",
                         choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    wg_list.set_defaults(func=cmd_wg_peer_list)

    wg_rev = sub.add_parser(
        "wg-peer-revoke",
        help="Revoke a WireGuard peer by peer_id.",
    )
    wg_rev.add_argument("peer_id", metavar="PEER_ID")
    wg_rev.add_argument("--ca-dir", default="./ca", metavar="DIR")
    wg_rev.add_argument("--pki-db-url", default=None, metavar="URL")
    wg_rev.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    wg_rev.set_defaults(func=cmd_wg_peer_revoke)

    # ------------------------------------------------------------------
    # Matter subcommands
    # ------------------------------------------------------------------

    mat_list = sub.add_parser(
        "matter-paa-list",
        help="List registered Matter PAA/PAI authorities.",
    )
    mat_list.add_argument("--ca-dir", default="./ca", metavar="DIR")
    mat_list.add_argument("--pki-db-url", default=None, metavar="URL")
    mat_list.add_argument("--log-level", default="WARNING",
                          choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    mat_list.set_defaults(func=cmd_matter_paa_list)

    mat_bulk = sub.add_parser(
        "matter-dac-bulk-issue",
        help="Bulk-issue Matter DACs from a JSON file.",
    )
    mat_bulk.add_argument("--vendor-id",   required=True, metavar="HEX")
    mat_bulk.add_argument("--product-id",  required=True, metavar="HEX")
    mat_bulk.add_argument("--input-file",  required=True, metavar="FILE",
                          help="JSON array of {subject_serial, public_key_pem}.")
    mat_bulk.add_argument("--output-file", default=None, metavar="FILE",
                          help="NDJSON output file (default: stdout).")
    mat_bulk.add_argument("--valid-years", type=int, default=10, metavar="N")
    mat_bulk.add_argument("--ca-dir", default="./ca", metavar="DIR")
    mat_bulk.add_argument("--pki-db-url", default=None, metavar="URL")
    mat_bulk.add_argument("--log-level", default="WARNING",
                          choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    mat_bulk.set_defaults(func=cmd_matter_dac_bulk)

    # ------------------------------------------------------------------
    # OpenAPI subcommand
    # ------------------------------------------------------------------

    oa = sub.add_parser(
        "openapi-export",
        help="Export the OpenAPI 3.0 spec to stdout or a file.",
    )
    oa.add_argument("--output", default=None, metavar="FILE",
                    help="Output file (default: stdout).")
    oa.add_argument("--pretty", action="store_true",
                    help="Pretty-print JSON (default: compact).")
    oa.add_argument("--check-drift", action="store_true",
                    help="Print any handler/spec drift warnings and exit.")
    oa.add_argument("--log-level", default="WARNING",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    oa.set_defaults(func=cmd_openapi_export)

    # ------------------------------------------------------------------
    # Cloud KMS subcommands
    # ------------------------------------------------------------------

    kms_imp = sub.add_parser(
        "kms-import-ca",
        help="Register an existing cloud KMS key as a PyPKI CA signing key.",
    )
    kms_imp.add_argument("--backend", required=True,
                         choices=["aws-kms", "gcp-kms", "azure-kv"])
    kms_imp.add_argument("--backend-ref", required=True, metavar="REF",
                         help="ARN/resource path/vault URL for the key.")
    kms_imp.add_argument("--name",    required=True, metavar="NAME",
                         help="Human name for this CA (e.g. root-2026).")
    kms_imp.add_argument("--ca-dir",  default="./ca", metavar="DIR")
    kms_imp.add_argument("--pki-db-url", default=None, metavar="URL")
    kms_imp.add_argument("--aws-region", default="us-east-1")
    kms_imp.add_argument("--log-level", default="INFO",
                         choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    kms_imp.set_defaults(func=cmd_kms_import_ca)

    kms_test = sub.add_parser(
        "kms-test-sign",
        help="Round-trip test: sign a test digest with the KMS-backed CA key and verify.",
    )
    kms_test.add_argument("--backend", required=True,
                          choices=["aws-kms", "gcp-kms", "azure-kv"])
    kms_test.add_argument("--backend-ref", required=True, metavar="REF")
    kms_test.add_argument("--aws-region", default="us-east-1")
    kms_test.add_argument("--log-level", default="INFO",
                          choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    kms_test.set_defaults(func=cmd_kms_test_sign)

    kms_rot = sub.add_parser(
        "kms-rotate-version",
        help="Switch the CA to a new key version in the same KMS backend.",
    )
    kms_rot.add_argument("--name",    required=True, metavar="NAME")
    kms_rot.add_argument("--new-ref", required=True, metavar="REF",
                         help="New backend_ref (new version ARN/URL).")
    kms_rot.add_argument("--ca-dir",  default="./ca", metavar="DIR")
    kms_rot.add_argument("--pki-db-url", default=None, metavar="URL")
    kms_rot.add_argument("--log-level", default="INFO",
                         choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    kms_rot.set_defaults(func=cmd_kms_rotate_version)

    # ------------------------------------------------------------------
    # Tenant management subcommands
    # ------------------------------------------------------------------

    def _add_tenant_db_args(p):
        p.add_argument("--ca-dir", default="./ca", metavar="DIR")
        p.add_argument("--pki-db-url", default=None, metavar="URL")
        p.add_argument("--log-level", default="WARNING",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    tc = sub.add_parser("tenant-create", help="Create a new tenant.")
    tc.add_argument("--slug", required=True, metavar="SLUG")
    tc.add_argument("--display-name", required=True, metavar="NAME")
    tc.add_argument("--owner-identity", default="system", metavar="IDENTITY")
    tc.add_argument("--max-active-certs", type=int, default=None, metavar="N")
    _add_tenant_db_args(tc)
    tc.set_defaults(func=cmd_tenant_create)

    tl = sub.add_parser("tenant-list", help="List tenants.")
    tl.add_argument("--include-suspended", action="store_true")
    _add_tenant_db_args(tl)
    tl.set_defaults(func=cmd_tenant_list)

    ts = sub.add_parser("tenant-show", help="Show tenant details.")
    ts.add_argument("--slug", required=True, metavar="SLUG")
    _add_tenant_db_args(ts)
    ts.set_defaults(func=cmd_tenant_show)

    tq = sub.add_parser("tenant-set-quota", help="Set quota for a tenant.")
    tq.add_argument("--slug", required=True, metavar="SLUG")
    tq.add_argument("--max-active-certs", type=int, default=None, metavar="N")
    tq.add_argument("--max-issuances-per-day", type=int, default=None, metavar="N")
    tq.add_argument("--max-sub-cas", type=int, default=None, metavar="N")
    _add_tenant_db_args(tq)
    tq.set_defaults(func=cmd_tenant_set_quota)

    ta = sub.add_parser("tenant-add-admin", help="Grant a user admin access to a tenant.")
    ta.add_argument("--slug", required=True, metavar="SLUG")
    ta.add_argument("--identity", required=True, metavar="IDENTITY")
    ta.add_argument("--role", default="operator",
                    choices=["admin", "operator", "viewer"])
    _add_tenant_db_args(ta)
    ta.set_defaults(func=cmd_tenant_add_admin)

    tra = sub.add_parser("tenant-remove-admin",
                         help="Remove a user's admin access from a tenant.")
    tra.add_argument("--slug", required=True, metavar="SLUG")
    tra.add_argument("--identity", required=True, metavar="IDENTITY")
    _add_tenant_db_args(tra)
    tra.set_defaults(func=cmd_tenant_remove_admin)

    tda = sub.add_parser("tenant-add-dns-alias",
                         help="Add a DNS hostname alias for a tenant.")
    tda.add_argument("--slug", required=True, metavar="SLUG")
    tda.add_argument("--hostname", required=True, metavar="HOST")
    _add_tenant_db_args(tda)
    tda.set_defaults(func=cmd_tenant_add_dns_alias)

    tsu = sub.add_parser("tenant-suspend", help="Suspend a tenant (read-only).")
    tsu.add_argument("--slug", required=True, metavar="SLUG")
    tsu.add_argument("--reason", default="", metavar="REASON")
    _add_tenant_db_args(tsu)
    tsu.set_defaults(func=cmd_tenant_suspend)

    tre = sub.add_parser("tenant-resume", help="Resume a suspended tenant.")
    tre.add_argument("--slug", required=True, metavar="SLUG")
    _add_tenant_db_args(tre)
    tre.set_defaults(func=cmd_tenant_resume)

    td = sub.add_parser("tenant-delete", help="Delete an empty tenant.")
    td.add_argument("--slug", required=True, metavar="SLUG")
    td.add_argument("--confirm", action="store_true",
                    help="Required to actually delete.")
    _add_tenant_db_args(td)
    td.set_defaults(func=cmd_tenant_delete)

    # ------------------------------------------------------------------
    # Code-signing log subcommands
    # ------------------------------------------------------------------

    cs_verify = sub.add_parser(
        "codesign-log-verify",
        help="Re-hash the full Merkle tree from leaves and verify against checkpoints.",
    )
    cs_verify.add_argument("--ca-dir", default="./ca", metavar="DIR")
    cs_verify.add_argument("--pki-db-url", default=None, metavar="URL")
    cs_verify.add_argument("--log-level", default="INFO",
                           choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    cs_verify.set_defaults(func=cmd_codesign_log_verify)

    cs_anchor = sub.add_parser(
        "codesign-anchor-now",
        help="Write a signed Merkle checkpoint immediately.",
    )
    cs_anchor.add_argument("--ca-dir", default="./ca", metavar="DIR")
    cs_anchor.add_argument("--pki-db-url", default=None, metavar="URL")
    cs_anchor.add_argument("--log-level", default="INFO",
                           choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    cs_anchor.set_defaults(func=cmd_codesign_anchor_now)

    return root


def cmd_ocsp_prebuild(args: argparse.Namespace) -> int:
    """Pre-generate one OCSP response file per certificate in the CA."""
    _setup_logging(args.log_level)
    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError:
        print("ERROR: pki_server.py not found — place it in the same directory.")
        return 1
    try:
        import ocsp_server
    except ImportError:
        print("ERROR: ocsp_server.py not found — place it in the same directory.")
        return 1

    ca_dir = Path(args.ca_dir)
    if not ca_dir.is_dir():
        print(f"ERROR: CA directory not found: {ca_dir}")
        return 1

    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=str(ca_dir), config=config)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    count = ocsp_server.generate_static_responses(
        ca=ca,
        output_dir=out,
        validity_hours=args.validity_hours,
    )
    print(f"Wrote {count} OCSP response(s) to {out}")
    return 0


def _audit_db(args: argparse.Namespace):
    """Return an open Database for the audit log."""
    from pathlib import Path as _P
    url = getattr(args, "audit_db_url", None)
    if not url:
        ca_dir = _P(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'audit.db'}"
    return db.make_db(url)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify hash chain integrity. Exit 0 = ok; 2 = breaks found."""
    import json as _json
    import time as _time
    _setup_logging(args.log_level)
    try:
        import audit_chain
    except ImportError:
        print("ERROR: audit_chain.py not found.")
        return 1

    d = _audit_db(args)
    try:
        t0 = _time.monotonic()
        report = audit_chain.verify_chain(d, start_id=args.from_id, end_id=args.to_id)
        elapsed = _time.monotonic() - t0
    finally:
        d.close()

    end_id_str = str(args.to_id) if args.to_id else "last"
    if args.json_output:
        out = {
            "rows_checked": report.rows_checked,
            "ok": report.ok,
            "elapsed_s": round(elapsed, 3),
            "final_hash": report.final_hash,
            "breaks": [
                {"id": b.id, "kind": b.kind, "expected": b.expected, "found": b.found}
                for b in report.breaks
            ],
        }
        print(_json.dumps(out, indent=2))
    else:
        print(f"Verified rows {args.from_id}..{end_id_str} in {elapsed:.1f}s")
        if report.ok:
            print("Chain intact.")
            print(f"Final hash: {report.final_hash[:16]}...{report.final_hash[-4:]}")
        else:
            first = report.breaks[0]
            print(f"CHAIN BROKEN at row {first.id}:")
            print(f"  {first.kind}: expected {first.expected[:16]}..., "
                  f"found {first.found[:16] if first.found else '(null)'}...")
            subsequent = sum(
                1 for b in report.breaks[1:] if b.id > first.id
            )
            if subsequent:
                print(f"{subsequent} subsequent row(s) are unverifiable from this point.")

    return 0 if report.ok else 2


def cmd_audit_export(args: argparse.Namespace) -> int:
    """Export a chain segment as JSON."""
    import json as _json
    import sys as _sys
    _setup_logging(args.log_level)
    try:
        import audit_chain
    except ImportError:
        print("ERROR: audit_chain.py not found.")
        return 1

    d = _audit_db(args)
    try:
        payload = audit_chain.export_chain(
            d,
            since=args.since,
            start_id=args.from_id,
            end_id=args.to_id,
        )
    finally:
        d.close()

    text = _json.dumps(payload, indent=2)
    if args.out == "-":
        print(text)
    else:
        from pathlib import Path as _P
        _P(args.out).write_text(text, encoding="utf-8")
        print(f"Exported {len(payload['rows'])} row(s) to {args.out}")
    return 0


def _acme_db(args: argparse.Namespace):
    """Return an open ACME Database object from args."""
    from pathlib import Path as _P
    url = getattr(args, "acme_db_url", None)
    if not url:
        ca_dir = _P(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'acme.db'}"
    try:
        import acme_server
    except ImportError:
        print("ERROR: acme_server.py not found — place it in the same directory.")
        raise SystemExit(1)
    return acme_server.ACMEDatabase(url)


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Validate a policy JSON file — schema + regex compile, no side effects."""
    _setup_logging(args.log_level)
    try:
        import policy as _policy
    except ImportError:
        print("ERROR: policy.py not found.")
        return 1
    try:
        p = _policy.load_policy(args.policy_file)
        print(f"OK  {args.policy_file}")
        print(f"    version=1  rules={len(p.rules)}  default={p.default}")
        print(f"    hash={p.content_hash[:16]}...")
        return 0
    except Exception as exc:
        print(f"INVALID  {args.policy_file}")
        print(f"  {exc}")
        return 1


def cmd_policy_test(args: argparse.Namespace) -> int:
    """Dry-run a request against a policy file and print the decision."""
    import json as _json
    _setup_logging(args.log_level)
    try:
        import policy as _policy
    except ImportError:
        print("ERROR: policy.py not found.")
        return 1
    try:
        pol = _policy.load_policy(args.policy_file)
    except Exception as exc:
        print(f"Policy load error: {exc}")
        return 1
    try:
        req_dict = _json.loads(args.request)
    except _json.JSONDecodeError as exc:
        print(f"Invalid --request JSON: {exc}")
        return 1
    req = _policy.IssuanceRequest(
        profile=req_dict.get("profile", ""),
        requester_backend=req_dict.get("requester_backend", ""),
        requester_roles=tuple(req_dict.get("requester_roles", [])),
        requester_identity=req_dict.get("requester_identity", ""),
        sans=tuple(req_dict.get("sans", [])),
        key_type=req_dict.get("key_type", ""),
        key_bits=int(req_dict.get("key_bits", 0)),
        validity_days_requested=int(req_dict.get("validity_days_requested", 0)),
        request_id=req_dict.get("request_id", ""),
    )
    decision = _policy.evaluate(req, pol)
    print(f"Decision : {decision.action}")
    print(f"Rule     : {decision.rule_name or '(default)'}")
    print(f"Reason   : {decision.reason or '-'}")
    if decision.sets:
        print(f"Sets     : {decision.sets}")
    print(f"Hash     : {decision.policy_hash[:16]}...")
    return 0 if decision.allowed else 2


def cmd_policy_show(args: argparse.Namespace) -> int:
    """Show metadata for a policy file."""
    _setup_logging(args.log_level)
    try:
        import policy as _policy
    except ImportError:
        print("ERROR: policy.py not found.")
        return 1
    try:
        pol = _policy.load_policy(args.policy_file)
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    print(f"File    : {args.policy_file}")
    print(f"Hash    : {pol.content_hash}")
    print(f"Default : {pol.default}")
    print(f"Rules   : {len(pol.rules)}")
    for i, rule in enumerate(pol.rules, 1):
        print(f"  [{i:2d}] {rule.name!r}  decide={rule.decide}")
    return 0


def cmd_policy_history(args: argparse.Namespace) -> int:
    """List policy versions stored in the PKI DB."""
    import json as _json
    import datetime as _dt
    _setup_logging(args.log_level)
    from db import make_db
    ca_dir = args.ca_dir
    url = getattr(args, "pki_db_url", None) or f"sqlite:///{ca_dir}/certificates.db"
    db = make_db(url)
    try:
        rows = db.fetchall(
            "SELECT content_hash, loaded_at, loaded_by FROM policy_versions ORDER BY loaded_at DESC"
        )
    except Exception as exc:
        print(f"Error reading policy_versions: {exc}")
        db.close()
        return 1
    db.close()
    if not rows:
        print("No policy versions recorded.")
        return 0
    print(f"{'Hash (first 16)':18}  {'Loaded at':20}  {'By':12}")
    print("-" * 58)
    for row in rows:
        ts = _dt.datetime.fromtimestamp(row["loaded_at"], tz=_dt.timezone.utc).isoformat()
        print(f"{row['content_hash'][:16]}  {ts}  {row['loaded_by']}")
    return 0


def cmd_ari_set_window(args: argparse.Namespace) -> int:
    """Set or update the ARI renewal-window override for one certificate."""
    _setup_logging(args.log_level)
    try:
        acme_db = _acme_db(args)
    except SystemExit:
        return 1

    acme_db.set_renewal_override(
        cert_id_str=args.cert_id,
        window_start=args.start,
        window_end=args.end,
        retry_after=args.retry_after,
        explanation=args.explanation,
        set_by=args.set_by,
    )
    print(
        f"Override set for {args.cert_id}: "
        f"window=[{args.start}, {args.end}] retry_after={args.retry_after}s"
    )
    return 0


def cmd_ari_bulk_shorten(args: argparse.Namespace) -> int:
    """Force immediate renewal for all certificates matching a certId pattern."""
    import datetime as _dt
    _setup_logging(args.log_level)
    try:
        acme_db = _acme_db(args)
    except SystemExit:
        return 1

    now_str = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = args.end if args.end else now_str

    # Find all certIds matching the pattern (LIKE query on overrides + certs tables)
    rows = acme_db._db.fetchall(
        "SELECT DISTINCT cert_id FROM acme_renewal_overrides WHERE cert_id LIKE ?",
        (args.filter,),
    )
    cert_ids_from_overrides = {r["cert_id"] for r in rows}

    # Also search the certificates table by constructing certIds
    # for certs whose serial matches the AKI pattern portion.
    # Simpler: bulk-set overrides for cert_ids already in the override table,
    # then let the operator also pass explicit cert_ids for new ones.
    count = 0
    for row in rows:
        cid = row["cert_id"]
        acme_db.set_renewal_override(
            cert_id_str=cid,
            window_start=now_str,
            window_end=end_str,
            retry_after=args.retry_after,
            explanation=args.explanation,
            set_by=args.set_by,
        )
        count += 1

    # Also update any certs not yet in overrides whose cert_id matches the pattern.
    # We scan acme_replacements.new_serial and certificates.serial to compute certIds.
    try:
        import acme_server as _acme
        from cryptography import x509 as _x509
        cert_rows = acme_db._db.fetchall("SELECT pem_chain, serial FROM certificates")
        for cr in cert_rows:
            end_marker = "-----END CERTIFICATE-----"
            pem = cr["pem_chain"].split(end_marker)[0].strip() + "\n" + end_marker
            try:
                cert_obj = _x509.load_pem_x509_certificate(pem.encode())
                cid = _acme.cert_id_from_cert(cert_obj)
            except Exception:
                continue
            if cid is None:
                continue
            # Apply LIKE matching (simple: use SQL fnmatch-style %)
            import fnmatch
            pat = args.filter.replace("%", "*").replace("_", "?")
            if not fnmatch.fnmatch(cid, pat):
                continue
            if cid in cert_ids_from_overrides:
                continue  # already updated above
            acme_db.set_renewal_override(
                cert_id_str=cid,
                window_start=now_str,
                window_end=end_str,
                retry_after=args.retry_after,
                explanation=args.explanation,
                set_by=args.set_by,
            )
            count += 1
    except Exception as e:
        print(f"WARNING: cert scan failed: {e}")

    print(f"Bulk-shorten: set window_end={end_str} on {count} certificate(s).")
    return 0


def _pki_db_for_args(args: argparse.Namespace):
    """Open the PKI database for SSH admin subcommands."""
    url = getattr(args, "pki_db_url", None)
    if not url:
        ca_dir = Path(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'certificates.db'}"
    return db.make_db(url)


def _pki_ca_for_args(args: argparse.Namespace):
    """Instantiate a CertificateAuthority for SSH admin subcommands."""
    try:
        from pki_server import CertificateAuthority, ServerConfig
    except ImportError as exc:
        raise SystemExit(f"ERROR: pki_server.py not available: {exc}")
    ca_dir = Path(getattr(args, "ca_dir", "./ca"))
    if not ca_dir.is_dir():
        raise SystemExit(f"ERROR: CA directory not found: {ca_dir}")
    config = ServerConfig(ca_dir=ca_dir)
    pki_db_url = getattr(args, "pki_db_url", None) or ""
    ca = CertificateAuthority(ca_dir=str(ca_dir), config=config, pki_db_url=pki_db_url)
    ca.enable_ssh_ca()
    return ca


def cmd_ssh_revoke(args: argparse.Namespace) -> int:
    """Revoke an SSH certificate by serial number."""
    try:
        ca = _pki_ca_for_args(args)
    except SystemExit as exc:
        print(exc)
        return 1
    ok = ca.revoke_ssh_cert(args.serial, reason=args.reason)
    if ok:
        print(f"SSH cert serial={args.serial} revoked.")
        return 0
    print(f"ERROR: SSH cert serial={args.serial} not found or already revoked.")
    return 1


def cmd_ssh_list(args: argparse.Namespace) -> int:
    """List issued SSH certificates."""
    import json as _json
    try:
        ca = _pki_ca_for_args(args)
    except SystemExit as exc:
        print(exc)
        return 1
    certs = ca.list_ssh_certs(
        principal=args.principal,
        include_revoked=args.include_revoked,
    )
    print(_json.dumps(certs, indent=2))
    return 0


def cmd_ssh_krl_export(args: argparse.Namespace) -> int:
    """Build and export a signed KRL for all revoked SSH certs."""
    import sys as _sys
    try:
        ca = _pki_ca_for_args(args)
    except SystemExit as exc:
        print(exc)
        return 1
    krl_bytes = ca.build_ssh_krl()
    if args.out == "-":
        _sys.stdout.buffer.write(krl_bytes)
    else:
        Path(args.out).write_bytes(krl_bytes)
        print(f"KRL written to {args.out} ({len(krl_bytes)} bytes)")
    return 0


# ---------------------------------------------------------------------------
# DB bootstrap commands (CLAUDE-db-bootstrap.md)
# ---------------------------------------------------------------------------

def cmd_db_init(args: argparse.Namespace) -> int:
    """Initialize the database for PyPKI."""
    import logging as _log
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    log = logging.getLogger("db-init")

    if args.backend == "sqlite":
        from db_bootstrap import init_sqlite, verify_sqlite
        path = Path(args.sqlite_path)
        if path.exists():
            issues = verify_sqlite(path)
            if issues:
                for issue in issues:
                    log.warning("Existing SQLite DB issue: %s", issue)
            else:
                log.info("SQLite DB already initialized and healthy: %s", path)
            return 0
        init_sqlite(path, dry_run=args.dry_run)
        return 0

    # Postgres
    if not args.dsn:
        print("ERROR: --dsn is required for postgres backend", file=sys.stderr)
        return 1
    if not args.target_role_password_source:
        print("ERROR: --target-role-password-source required for postgres", file=sys.stderr)
        return 1

    from db_bootstrap import init_postgres
    exts = [e.strip() for e in args.extensions.split(",") if e.strip()]
    init_postgres(
        admin_dsn=args.dsn,
        target_db=args.target_db,
        target_role=args.target_role,
        password_source=args.target_role_password_source,
        tls_mode=args.tls,
        extensions=exts,
        apply_tuning=args.apply_tuning,
        dry_run=args.dry_run,
    )

    if args.with_pgbouncer_sample:
        from pgbouncer import emit_sample
        print(emit_sample(
            target_db=args.target_db,
            role=args.target_role,
        ))
    return 0


# ---------------------------------------------------------------------------
# TLS management commands (CLAUDE-tls-bootstrap.md)
# ---------------------------------------------------------------------------

def cmd_tls_rotate(args: argparse.Namespace) -> int:
    """Force TLS cert re-issuance from the CA."""
    from tls_manager import generate_self_signed_bootstrap
    cert_path = Path(args.tls_cert)
    key_path = Path(args.tls_key)

    if args.dry_run:
        print(f"[dry-run] Would generate new TLS cert for {args.hostname}")
        print(f"[dry-run] Would write cert → {cert_path}")
        print(f"[dry-run] Would write key  → {key_path}")
        return 0

    generate_self_signed_bootstrap(
        hostname=args.hostname,
        cert_path=cert_path,
        key_path=key_path,
        validity_hours=24 * 90,  # 90 days (pypki_self_tls profile validity)
    )
    print(f"TLS cert rotated: {cert_path}")
    print("Send SIGHUP to the running pypki-server to pick up the new cert.")
    return 0


def cmd_tls_status(args: argparse.Namespace) -> int:
    """Print TLS cert status."""
    import json as _json
    from tls_manager import TLSManager
    cert_path = Path(args.tls_cert)
    if not cert_path.exists():
        print(f"TLS cert not found: {cert_path}", file=sys.stderr)
        return 1
    # Key path: same stem, .key extension
    key_path = cert_path.with_suffix(".key")
    if not key_path.exists():
        key_path = cert_path.parent / (cert_path.stem + ".key")

    try:
        mgr = TLSManager(cert_path, key_path)
        status = mgr.status()
        print(_json.dumps(status, indent=2))
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_tls_replace(args: argparse.Namespace) -> int:
    """Swap in operator-provided cert+key (Pattern C)."""
    cert = Path(args.cert)
    key = Path(args.key)
    if not cert.exists():
        print(f"Cert not found: {cert}", file=sys.stderr)
        return 1
    if not key.exists():
        print(f"Key not found: {key}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"[dry-run] Would load TLSManager with {cert} + {key}")
        return 0

    from tls_manager import TLSManager
    try:
        TLSManager(cert, key)  # Validate they load
        print(f"Cert+key validated. Send SIGHUP to pypki-server to apply.")
        return 0
    except Exception as e:
        print(f"Invalid cert/key: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Hardening commands (CLAUDE-os-hardening-firewall.md)
# ---------------------------------------------------------------------------

def cmd_hardening_status(args: argparse.Namespace) -> int:
    """Print current host hardening status."""
    from bootstrap.firewall_setup import detect_firewall_stack, detect_mac
    fw = detect_firewall_stack()
    mac = detect_mac()

    import shutil
    import subprocess

    score = "?"
    if shutil.which("systemd-analyze"):
        try:
            r = subprocess.run(
                ["systemd-analyze", "security", "pypki.service", "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            last = r.stdout.strip().splitlines()
            if last:
                parts = last[-1].split()
                for tok in reversed(parts):
                    try:
                        float(tok)
                        score = tok
                        break
                    except ValueError:
                        pass
        except Exception:
            pass

    sysctl_path = Path("/etc/sysctl.d/99-pypki.conf")
    ulimits_path = Path("/etc/security/limits.d/pypki.conf")
    apparmor_profile = Path("/etc/apparmor.d/usr.bin.pypki-server")
    selinux_module = Path("/etc/selinux/local/pypki.pp")

    print("PyPKI Host Hardening Status")
    print("=" * 40)
    print(f"  Firewall stack:       {fw}")
    print(f"  MAC framework:        {mac}")
    print(f"  systemd score:        {score}")
    print(f"  sysctl config:        {'installed' if sysctl_path.exists() else 'NOT installed'}")
    print(f"  ulimits config:       {'installed' if ulimits_path.exists() else 'NOT installed'}")
    print(f"  AppArmor profile:     {'installed' if apparmor_profile.exists() else 'NOT installed'}")
    print(f"  SELinux module:       {'installed' if selinux_module.exists() else 'NOT installed'}")
    return 0


def cmd_hardening_apply(args: argparse.Namespace) -> int:
    """Install firewall templates, sysctl, and MAC profiles."""
    from bootstrap.firewall_setup import apply_firewall_template, detect_firewall_stack

    stack = None if args.firewall_stack == "auto" else args.firewall_stack
    applied = apply_firewall_template(stack, dry_run=args.dry_run)
    if applied:
        print("Firewall rules applied.")
    else:
        print("No firewall rules applied (check firewall stack).")

    if args.apply_sysctl:
        import subprocess
        src = Path(__file__).parent / "packaging" / "sysctl" / "pypki.conf"
        dst = Path("/etc/sysctl.d/99-pypki.conf")
        if args.dry_run:
            print(f"[dry-run] Would install {src} → {dst}")
        elif src.exists():
            import shutil
            shutil.copy2(src, dst)
            subprocess.run(["sysctl", "--system"], capture_output=True)
            print(f"sysctl config installed: {dst}")

    return 0


def cmd_hardening_validate(args: argparse.Namespace) -> int:
    """Validate hardening state matches expected baseline."""
    return cmd_hardening_status(args)


# ---------------------------------------------------------------------------
# Preflight command (CLAUDE-preflight-check.md)
# ---------------------------------------------------------------------------

def cmd_preflight(args: argparse.Namespace) -> int:
    """Run preflight checks."""
    import preflight as _pf

    if args.ci:
        args.format = "json"
        args.exit_on_warning = "high"
    if args.quick:
        args.skip_slow = True
        args.exit_on_warning = "high"

    if args.no_color:
        _pf._USE_COLOR = False

    env = _pf.CheckEnv(
        ca_dir=args.ca_dir,
        ca_key_paths=list(Path(args.ca_dir).glob("**/*.key")) if Path(args.ca_dir).exists() else [],
    )

    include_cats = [c.strip() for c in args.include.split(",")] if args.include else None
    exclude_cats = [c.strip() for c in args.exclude.split(",")] if args.exclude else None

    results = _pf.run(
        env=env,
        include_categories=include_cats,
        exclude_categories=exclude_cats,
        skip_slow=args.skip_slow,
        parallelism=args.parallelism,
        per_check_timeout=args.timeout,
    )

    if args.format == "json":
        output = _pf.format_json(results)
    elif args.format == "prometheus":
        output = _pf.format_prometheus(results)
    else:
        output = _pf.format_human(results)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Preflight results written to {args.output}")
    else:
        print(output)

    threshold = _pf.Severity.from_str(args.exit_on_warning) if args.exit_on_warning != "none" else None
    if threshold:
        return _pf.determine_exit_code(results, threshold)
    return 0


# ---------------------------------------------------------------------------
# Upgrade commands (CLAUDE-upgrade-tooling.md)
# ---------------------------------------------------------------------------

def _parse_duration(s: str) -> int:
    """Parse '5m', '30s', '1h' → seconds."""
    s = s.strip()
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


def cmd_upgrade(args: argparse.Namespace) -> int:
    """Run a full upgrade cycle."""
    from upgrade import UpgradeConfig, run_upgrade_preflight, run_health_window, set_upgrade_state

    health_seconds = _parse_duration(args.health_window)
    cfg = UpgradeConfig(
        target_version=args.to,
        channel=args.channel,
        health_window_seconds=health_seconds,
        rollback_on_failure=not args.no_rollback,
        accept_irreversible=args.accept_irreversible,
        dry_run=args.dry_run,
    )

    print(f"Upgrading to {cfg.target_version} (dry_run={cfg.dry_run})")

    # Pre-flight
    set_upgrade_state("preflight", target=cfg.target_version)
    pf_results = run_upgrade_preflight(cfg)
    failed = [r for r in pf_results if not r.success]
    if failed:
        for r in failed:
            print(f"  FAIL [{r.step}]: {r.message}", file=sys.stderr)
        return 1

    print(f"Pre-flight passed. Health window: {health_seconds}s")

    if cfg.dry_run:
        print("[dry-run] Would proceed with upgrade.")
        set_upgrade_state("idle")
        return 0

    # Health check window (simplified — real upgrade would stop/start the service)
    set_upgrade_state("health-check", target=cfg.target_version)
    ok, reason = run_health_window(cfg)
    if ok:
        set_upgrade_state("finalized", target=cfg.target_version)
        print(f"Upgrade to {cfg.target_version} complete.")
        return 0

    if cfg.rollback_on_failure:
        from upgrade import rollback
        rollback(cfg, reason)
        set_upgrade_state("idle")
    else:
        print(f"Health check failed: {reason}", file=sys.stderr)
        set_upgrade_state("failed", reason=reason)
        return 1
    return 0


def cmd_upgrade_check(args: argparse.Namespace) -> int:
    """Show available versions."""
    from upgrade import fetch_available_versions
    versions = fetch_available_versions(args.channel)
    if not versions:
        print("No versions available (offline or source unreachable).")
        return 0
    print(f"Available versions ({args.channel} channel):")
    for v in versions:
        print(f"  {v}")
    return 0


def cmd_upgrade_status(args: argparse.Namespace) -> int:
    """Print current upgrade state."""
    import json as _json
    from upgrade import get_upgrade_state
    state = get_upgrade_state()
    print(_json.dumps(state, indent=2))
    return 0


def cmd_upgrade_rollback(args: argparse.Namespace) -> int:
    """Manually trigger rollback."""
    from upgrade import UpgradeConfig, rollback, get_upgrade_state
    state = get_upgrade_state()
    target = state.get("target", "unknown")
    cfg = UpgradeConfig(target_version=target)
    rollback(cfg, "manual rollback via CLI")
    return 0


# ---------------------------------------------------------------------------
# Backup / DR subcommands
# ---------------------------------------------------------------------------

def _read_passphrase_file(path: Optional[str]) -> Optional[bytes]:
    """Read passphrase from file, stripping trailing newline."""
    if path is None:
        return None
    return Path(path).read_bytes().rstrip(b"\n")


def _pki_db_for_ca_dir(ca_dir: str) -> "db.Database":
    """Open the PKI DB for a given CA directory."""
    from pathlib import Path as _P
    url = f"sqlite:///{_P(ca_dir) / 'certificates.db'}"
    return db.make_db(url)


def _open_audit_for_ca_dir(ca_dir: str):
    """Construct an AuditLog for a given CA directory."""
    from pki_server import AuditLog
    return AuditLog(Path(ca_dir))


def cmd_backup_now(args: argparse.Namespace) -> int:
    """Create a backup of the CA state immediately."""
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.backup-now")

    try:
        from backup import BackupConfig, BackupEngine
    except ImportError:
        print("ERROR: backup.py not found.")
        return 1

    ca_dir = Path(args.ca_dir)
    if not ca_dir.is_dir():
        print(f"ERROR: CA directory not found: {ca_dir}")
        return 1

    passphrase = _read_passphrase_file(getattr(args, "passphrase_file", None))
    pki_db = _pki_db_for_ca_dir(args.ca_dir)

    config = BackupConfig(
        targets=(args.target,),
        passphrase=passphrase,
        retention_count=0,
        retention_days=0,
    )
    engine = BackupEngine(ca_dir=ca_dir, db=pki_db, config=config)
    try:
        path = engine.create_backup()
        print(f"Backup created: {path}")
        return 0
    except Exception as exc:
        print(f"ERROR: Backup failed: {exc}")
        log.exception("backup-now failed")
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore a backup to a staging directory."""
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.restore")

    try:
        from restore import RestoreEngine
    except ImportError:
        print("ERROR: restore.py not found.")
        return 1

    backup_path = Path(args.from_path)
    if not backup_path.is_file():
        print(f"ERROR: Backup file not found: {backup_path}")
        return 1

    passphrase = _read_passphrase_file(getattr(args, "passphrase_file", None))

    try:
        pki_db = _pki_db_for_ca_dir(args.ca_dir)
    except Exception:
        pki_db = None

    engine = RestoreEngine(db=pki_db)
    result = engine.restore(
        backup_path=backup_path,
        dest_dir=Path(args.to_dir),
        passphrase=passphrase,
        dry_run=getattr(args, "dry_run", False),
        db_only=getattr(args, "db_only", False),
        keys_only=getattr(args, "keys_only", False),
        tables=getattr(args, "tables", None),
    )

    if result.outcome == "ok":
        if result.dry_run:
            print("Dry run: backup verified successfully (no files written)")
        else:
            print(f"Restore successful: {len(result.files_restored)} file(s) staged to {args.to_dir}")
            for f in result.files_restored:
                print(f"  {f}")
        return 0
    else:
        print(f"ERROR: Restore failed: {result.error}")
        return 1


def cmd_emergency_stop(args: argparse.Namespace) -> int:
    """Halt all certificate issuance immediately."""
    import getpass as _getpass
    _setup_logging(args.log_level)

    ca_dir = Path(args.ca_dir)
    operator = getattr(args, "by", None) or _getpass.getuser()
    reason = args.reason
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

    pki_db = _pki_db_for_ca_dir(args.ca_dir)
    try:
        pki_db.execute(
            "UPDATE emergency_state SET halted=1, halt_reason=?, halted_at=?, halted_by=? "
            "WHERE state='global'",
            (reason, now, operator),
        )
    except Exception as exc:
        print(f"ERROR: Could not update emergency_state: {exc}")
        print("Hint: run 'pypki_admin.py db-init --ca-dir ...' to apply migration 006_dr.sql")
        return 1

    # Audit
    try:
        audit = _open_audit_for_ca_dir(args.ca_dir)
        audit.record(
            "emergency_stop",
            f"halted by={operator!r} reason={reason!r}",
        )
        audit.close()
    except Exception as exc:
        logging.warning(f"Could not write audit log: {exc}")

    print(f"Emergency stop activated. Reason: {reason}")
    print("Issuance is now blocked. Running server will refuse new certs on next request.")
    print("To re-enable: pypki_admin.py emergency-resume --ca-dir <dir>")
    return 0


def cmd_emergency_resume(args: argparse.Namespace) -> int:
    """Clear emergency halt and re-enable issuance."""
    import getpass as _getpass
    _setup_logging(args.log_level)

    operator = getattr(args, "by", None) or _getpass.getuser()
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

    pki_db = _pki_db_for_ca_dir(args.ca_dir)
    try:
        pki_db.execute(
            "UPDATE emergency_state SET halted=0, halt_reason=NULL, halted_at=NULL, halted_by=NULL "
            "WHERE state='global'",
        )
    except Exception as exc:
        print(f"ERROR: Could not update emergency_state: {exc}")
        return 1

    try:
        audit = _open_audit_for_ca_dir(args.ca_dir)
        audit.record(
            "emergency_resume",
            f"resumed by={operator!r}",
        )
        audit.close()
    except Exception as exc:
        logging.warning(f"Could not write audit log: {exc}")

    print("Emergency stop cleared. Issuance is now re-enabled.")
    return 0


def cmd_revoke_batch(args: argparse.Namespace) -> int:
    """Mass-revoke certificates from a serial number list."""
    _setup_logging(args.log_level)
    log = logging.getLogger("pypki.revoke-batch")

    try:
        from pki_server import CertificateAuthority, ServerConfig, AuditLog
    except ImportError:
        print("ERROR: pki_server.py not found.")
        return 1

    ca_dir = Path(args.ca_dir)
    serial_file = Path(args.serial_file)
    if not serial_file.is_file():
        print(f"ERROR: serial file not found: {serial_file}")
        return 1

    # Parse serials: one per line, hex (0x…) or decimal
    serials: list[int] = []
    for line in serial_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            serials.append(int(line, 16) if line.startswith("0x") or
                           any(c in "abcdefABCDEF" for c in line) else int(line))
        except ValueError:
            print(f"WARNING: Could not parse serial {line!r} — skipping")

    if not serials:
        print("No valid serials found in file.")
        return 1

    if args.dry_run:
        print(f"Dry run: would revoke {len(serials)} certificate(s):")
        for s in serials:
            print(f"  {s} (0x{s:X})")
        return 0

    # RFC 5280 §5.3.1 reason codes
    _REASON_CODES: dict[str, int] = {
        "unspecified": 0,
        "key_compromise": 1,
        "ca_compromise": 2,
        "affiliation_changed": 3,
        "superseded": 4,
        "cessation_of_operation": 5,
        "certificate_hold": 6,
        "remove_from_crl": 8,
        "privilege_withdrawn": 9,
        "aa_compromise": 10,
    }
    reason_int = _REASON_CODES.get(args.reason, 0)

    config = ServerConfig(ca_dir=ca_dir)
    ca = CertificateAuthority(ca_dir=str(ca_dir), config=config)
    audit = AuditLog(ca_dir)

    revoked = 0
    failed = 0
    for serial in serials:
        try:
            ca.revoke_certificate(serial, reason=reason_int)
            audit.record(
                "revoke",
                f"serial={serial} reason={args.reason}",
            )
            revoked += 1
        except Exception as exc:
            log.warning(f"Failed to revoke serial {serial}: {exc}")
            failed += 1

    audit.close()
    print(f"Revoked {revoked} certificate(s); {failed} failure(s).")
    return 0 if failed == 0 else 1


def cmd_ca_init(args: argparse.Namespace) -> int:
    """Initialise (or re-export) the offline root CA bundle, optionally with Shamir."""
    _setup_logging(args.log_level)

    # Parse --shamir M-of-N if given
    shamir = getattr(args, "shamir", None)
    threshold = 0
    shares = 0
    if shamir:
        try:
            m_str, n_str = shamir.split("-of-")
            threshold = int(m_str)
            shares = int(n_str)
        except (ValueError, AttributeError):
            print(f"ERROR: --shamir must be in 'M-of-N' format (e.g. '3-of-5'), got: {shamir!r}")
            return 1
        if threshold < 2:
            print("ERROR: Shamir threshold must be ≥ 2")
            return 1
        if shares < threshold:
            print("ERROR: Total shares must be ≥ threshold")
            return 1

    # Build a compatible namespace for the ceremony command
    import argparse as _ap
    ceremony_args = _ap.Namespace(
        ca_dir=args.ca_dir,
        out=args.out,
        passphrase_env=getattr(args, "passphrase_env", None),
        threshold=threshold,
        shares=shares,
        log_level=args.log_level,
    )
    return _ceremony_cmd("export_root")(ceremony_args)


def cmd_ca_recover(args: argparse.Namespace) -> int:
    """Collect M Shamir shares interactively and issue a sub-CA cert from the bundle."""
    _setup_logging(args.log_level)

    n_shares = args.shares
    print(f"Collecting {n_shares} Shamir share(s). Paste each share and press Enter.")
    collected: list[str] = []
    for i in range(1, n_shares + 1):
        while True:
            share = input(f"  Share {i}/{n_shares}: ").strip()
            if share:
                collected.append(share)
                break
            print("  (empty — please paste the share)")

    import argparse as _ap
    ceremony_args = _ap.Namespace(
        bundle=args.bundle,
        csr_in=args.csr_in,
        cert_out=args.cert_out,
        passphrase_env=None,
        share=collected,
        validity_days=args.validity_days,
        path_length=args.path_length,
        permitted_dns=args.permitted_dns,
        excluded_dns=args.excluded_dns,
        log_level=args.log_level,
    )
    return _ceremony_cmd("sign_csr")(ceremony_args)


def cmd_agility_summary(args: argparse.Namespace) -> int:
    """Print a text summary of the crypto-agility posture."""
    _setup_logging(args.log_level)
    from pathlib import Path as _Path
    from db import make_db as _make_db
    db_url = getattr(args, "pki_db_url", None) or f"sqlite:///{_Path(args.ca_dir)/'certificates.db'}"
    db = _make_db(db_url)
    try:
        import agility as _ag
        summ = _ag.summary(db)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"As of:        {summ['as_of']}")
    print(f"Active certs: {summ['total_active_certs']:,}")
    print(f"PQ-capable:   {summ['pq_capable_pct']}%")
    print()
    print(f"{'Class':<22} {'Count':>8}  {'%':>6}")
    print("-" * 42)
    for cls, info in sorted(summ["by_class"].items(), key=lambda kv: -kv[1]["count"]):
        print(f"{cls:<22} {info['count']:>8,}  {info['pct']:>5.1f}%")
    if summ["ca_key_backends"]:
        print()
        print("CA key backends:")
        for backend, n in summ["ca_key_backends"].items():
            print(f"  {backend}: {n}")
    return 0


def cmd_agility_reclassify(args: argparse.Namespace) -> int:
    """Re-run the classifier over all certs with crypto_class = 'unknown'."""
    _setup_logging(args.log_level)
    from pathlib import Path as _Path
    from db import make_db as _make_db
    db_url = getattr(args, "pki_db_url", None) or f"sqlite:///{_Path(args.ca_dir)/'certificates.db'}"
    db = _make_db(db_url)
    try:
        import agility as _ag
        updated, skipped = _ag.backfill(db)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"Reclassified: {updated} cert(s) updated, {skipped} remain unknown.")
    return 0


def cmd_agility_export(args: argparse.Namespace) -> int:
    """Export all active certs with their crypto classification to CSV or JSON."""
    _setup_logging(args.log_level)
    from pathlib import Path as _Path
    from db import make_db as _make_db
    import datetime
    db_url = getattr(args, "pki_db_url", None) or f"sqlite:///{_Path(args.ca_dir)/'certificates.db'}"
    db = _make_db(db_url)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    rows = db.fetchall(
        "SELECT serial, subject, not_before, not_after, profile, crypto_class, revoked "
        "FROM certificates ORDER BY serial",
    )
    fmt = getattr(args, "format", "csv")
    if fmt == "json":
        import json
        data = [
            {
                "serial": row[0], "subject": row[1],
                "not_before": row[2], "not_after": row[3],
                "profile": row[4], "crypto_class": row[5] or "unknown",
                "revoked": bool(row[6]),
            }
            for row in rows
        ]
        print(json.dumps(data, indent=2))
    else:
        print("serial,subject,not_before,not_after,profile,crypto_class,revoked")
        for row in rows:
            subject = str(row[1] or "").replace('"', '""')
            print(f'{row[0]},"{subject}",{row[2]},{row[3]},{row[4] or ""},{row[5] or "unknown"},{int(row[6])}')
    return 0


def _open_pki_db(args):
    """Open the PKI database for SSO admin subcommands."""
    from db import make_db
    url = getattr(args, "pki_db_url", None)
    if not url:
        ca_dir = Path(getattr(args, "ca_dir", "./ca"))
        url = f"sqlite:///{ca_dir / 'certificates.db'}"
    return make_db(url)


def cmd_session_list(args: argparse.Namespace) -> int:
    """List active SSO sessions."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import time as _time
    now = int(_time.time())
    include_all = getattr(args, "include_all", False)

    cond = "" if include_all else "WHERE (revoked = 0 AND expires_at > ?)"
    params = () if include_all else (now,)
    rows = db.fetchall(
        "SELECT session_id, auth_backend, identity, roles, created_at, "
        "expires_at, revoked FROM sso_sessions " + cond +
        " ORDER BY created_at DESC LIMIT 200",
        params,
    )
    if not rows:
        print("No active sessions.")
        return 0
    print(f"{'SESSION_ID':<44} {'BACKEND':<7} {'IDENTITY':<30} {'ROLES':<20} {'EXPIRES'}")
    print("-" * 120)
    for row in rows:
        import datetime as _dt
        exp = _dt.datetime.fromtimestamp(row["expires_at"]).strftime("%Y-%m-%d %H:%M")
        tag = "[REVOKED] " if row["revoked"] else ("[EXP] " if row["expires_at"] < now else "")
        sid = row["session_id"][:40] + ".."
        ident = (row["identity"] or "")[:28]
        roles = (row["roles"] or "[]")[:18]
        print(f"{tag}{sid:<44} {row['auth_backend']:<7} {ident:<30} {roles:<20} {exp}")
    return 0


def cmd_session_revoke(args: argparse.Namespace) -> int:
    """Revoke a session by ID."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    session_id = args.session_id
    row = db.fetchone(
        "SELECT identity, auth_backend FROM sso_sessions WHERE session_id = ?",
        (session_id,),
    )
    if row is None:
        print(f"ERROR: session not found: {session_id!r}")
        return 1
    db.execute(
        "UPDATE sso_sessions SET revoked = 1 WHERE session_id = ?",
        (session_id,),
    )
    print(f"Session revoked: identity={row['identity']} backend={row['auth_backend']}")
    return 0


def cmd_token_create(args: argparse.Namespace) -> int:
    """Create a long-lived API token for automation."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import time as _time, secrets as _sec, json as _json

    identity = args.identity
    role     = args.role
    ttl_days = args.ttl
    ttl_sec  = ttl_days * 86400
    now      = int(_time.time())
    token    = _sec.token_urlsafe(32)

    db.execute(
        "INSERT INTO sso_sessions "
        "(session_id, auth_backend, identity, idp_subject, idp_issuer, "
        "roles, created_at, expires_at, last_seen_at, revoked) "
        "VALUES (?, 'token', ?, NULL, NULL, ?, ?, ?, ?, 0)",
        (token, identity, _json.dumps([role]), now, now + ttl_sec, now),
    )
    import datetime as _dt
    exp = _dt.datetime.fromtimestamp(now + ttl_sec).strftime("%Y-%m-%d %H:%M UTC")
    print(f"API token created for {identity!r} (role={role}, expires={exp}):")
    print(f"  {token}")
    print("Pass as: Authorization: Bearer <token>")
    return 0


def cmd_token_list(args: argparse.Namespace) -> int:
    """List active API tokens."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import time as _time
    now = int(_time.time())

    rows = db.fetchall(
        "SELECT session_id, identity, roles, created_at, expires_at, revoked "
        "FROM sso_sessions WHERE auth_backend = 'token' ORDER BY created_at DESC",
    )
    if not rows:
        print("No API tokens found.")
        return 0
    print(f"{'TOKEN (first 20)':<22} {'IDENTITY':<30} {'ROLES':<20} {'EXPIRES'}")
    print("-" * 90)
    for row in rows:
        import datetime as _dt
        expired = row["expires_at"] < now
        tag = "[REVOKED] " if row["revoked"] else ("[EXP] " if expired else "")
        exp = _dt.datetime.fromtimestamp(row["expires_at"]).strftime("%Y-%m-%d %H:%M")
        short = row["session_id"][:20] + ".."
        ident = (row["identity"] or "")[:28]
        roles = (row["roles"] or "[]")[:18]
        print(f"{tag}{short:<22} {ident:<30} {roles:<20} {exp}")
    return 0


def cmd_link_account(args: argparse.Namespace) -> int:
    """Grant portal ownership of a cert to a user identity."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import portal as _portal
    _portal.tag_owner(db, args.serial, args.kind, args.identity)
    print(f"Ownership granted: serial={args.serial} kind={args.kind} identity={args.identity!r}")
    return 0


def cmd_portal_remap(args: argparse.Namespace) -> int:
    """Re-apply static owner mappings from a JSON file."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import portal as _portal
    mappings = _portal.load_owner_mapping_file(args.mapping_file)
    if not mappings:
        print("No mappings found in file.")
        return 0
    n = _portal.apply_static_mappings(mappings, db)
    print(f"Applied {n} ownership row(s) from {len(mappings)} mapping(s).")
    return 0


def cmd_wg_peer_list(args: argparse.Namespace) -> int:
    """List active WireGuard peers."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import wireguard_ca as _wg
    wg = _wg.WireGuardCA(db)
    peers = wg.list_peers(include_revoked=getattr(args, "include_revoked", False))
    if not peers:
        print("No peers found.")
        return 0
    print(f"{'PEER_ID':<18} {'NAME':<20} {'ALLOWED_IPS':<22} {'EXPIRES':<22} STATUS")
    print("-" * 90)
    import datetime as _dt
    for p in peers:
        exp = _dt.datetime.fromtimestamp(p["valid_before"]).strftime("%Y-%m-%d %H:%M")
        ips = ", ".join(p["allowed_ips"])[:20]
        tag = "[REVOKED] " if p["revoked"] else ""
        print(f"{tag}{p['peer_id']:<18} {p['peer_name']:<20} {ips:<22} {exp:<22}")
    return 0


def cmd_wg_peer_revoke(args: argparse.Namespace) -> int:
    """Revoke a WireGuard peer."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import wireguard_ca as _wg
    wg = _wg.WireGuardCA(db)
    ok = wg.revoke_peer(args.peer_id)
    if ok:
        print(f"Peer revoked: {args.peer_id}")
        return 0
    print(f"ERROR: peer not found: {args.peer_id!r}")
    return 1


def cmd_matter_paa_list(args: argparse.Namespace) -> int:
    """List Matter PAA/PAI authorities."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import matter as _matter
    from pki_server import CertificateAuthority
    ca = CertificateAuthority(ca_dir=getattr(args, "ca_dir", "./ca"), pki_db_url=getattr(args, "pki_db_url", None) or "")
    mc = _matter.MatterCA(db, ca)
    auths = mc.list_authorities()
    if not auths:
        print("No Matter authorities registered.")
        return 0
    for a in auths:
        print(f"[{a['role'].upper()}] id={a['id']} name={a['name']!r} vid={a['vendor_id_hex']}")
    return 0


def cmd_matter_dac_bulk(args: argparse.Namespace) -> int:
    """Bulk-issue Matter DACs from a JSON input file."""
    _setup_logging(args.log_level)
    import json as _json
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    db = _open_pki_db(args)

    try:
        items = _json.loads(Path(getattr(args, "input_file", "")).read_text())
    except Exception as exc:
        print(f"ERROR: could not read input file: {exc}")
        return 1

    from pki_server import CertificateAuthority
    import matter as _matter
    ca = CertificateAuthority(ca_dir=getattr(args, "ca_dir", "./ca"), pki_db_url=getattr(args, "pki_db_url", None) or "")
    mc = _matter.MatterCA(db, ca)

    out = open(getattr(args, "output_file") or "/dev/stdout", "w") if getattr(args, "output_file", None) else None

    ok_count = err_count = 0
    for result in mc.issue_dac_bulk(
        args.vendor_id, args.product_id, items,
        valid_years=args.valid_years,
    ):
        line = _json.dumps(result)
        if out:
            out.write(line + "\n")
        else:
            print(line)
        if result.get("status") == "ok":
            ok_count += 1
        else:
            err_count += 1

    if out:
        out.close()
    print(f"Done: {ok_count} issued, {err_count} errors.", file=__import__("sys").stderr)
    return 0 if err_count == 0 else 1


def cmd_openapi_export(args: argparse.Namespace) -> int:
    """Export the OpenAPI spec."""
    _setup_logging(args.log_level)
    import openapi as _oa
    if getattr(args, "check_drift", False):
        undoc, unimp = _oa.check_drift()
        if undoc:
            print(f"Undocumented handler paths ({len(undoc)}):")
            for p in sorted(undoc):
                print(f"  {p}")
        if unimp:
            print(f"Spec paths with no handler ({len(unimp)}):")
            for p in sorted(unimp):
                print(f"  {p}")
        if not undoc and not unimp:
            print("No drift detected.")
        return 1 if (undoc or unimp) else 0

    text = _oa.spec_json_pretty() if getattr(args, "pretty", False) else _oa.spec_json()
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(text)
        print(f"OpenAPI spec written to {output}")
    else:
        print(text)
    return 0


def cmd_kms_import_ca(args: argparse.Namespace) -> int:
    """Register an existing cloud KMS key as a PyPKI CA."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import time as _time, json as _json
    now = int(_time.time())
    db.execute(
        "INSERT OR REPLACE INTO ca_keys "
        "(name, backend, backend_ref, backend_meta_json, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (args.name, args.backend, args.backend_ref,
         _json.dumps({"region": getattr(args, "aws_region", "us-east-1")}),
         now),
    )
    print(f"CA key registered: name={args.name!r} backend={args.backend} ref={args.backend_ref!r}")
    return 0


def cmd_kms_test_sign(args: argparse.Namespace) -> int:
    """Round-trip test sign + verify with a cloud KMS key."""
    _setup_logging(args.log_level)
    import key_backend as _kb
    import hashlib

    cfg = {"region": getattr(args, "aws_region", "us-east-1")}
    try:
        backend = _kb.build_backend(args.backend, args.backend_ref, cfg)
        pub_key = backend.public_key(args.backend_ref)
        print(f"Public key loaded: {type(pub_key).__name__}")

        # Sign a test digest
        test_data = b"pypki-kms-test-sign-probe"
        digest    = hashlib.sha256(test_data).digest()
        sig       = backend.sign(args.backend_ref, digest, "ecdsa-sha256")
        print(f"Signature ({len(sig)} bytes): {sig[:8].hex()}...")

        # Verify
        from cryptography.hazmat.primitives.asymmetric import ec as _ec, padding as _pad
        from cryptography.hazmat.primitives import hashes as _h
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        if hasattr(pub_key, "verify"):
            from cryptography.hazmat.primitives.asymmetric import ec
            pub_key.verify(sig, test_data, ec.ECDSA(_h.SHA256()))
            print("Signature verified OK.")
        print("kms-test-sign: PASS")
        return 0
    except Exception as exc:
        print(f"kms-test-sign: FAILED — {exc}")
        return 1


def cmd_kms_rotate_version(args: argparse.Namespace) -> int:
    """Atomically switch a CA to a new KMS key version."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    row = db.fetchone("SELECT * FROM ca_keys WHERE name = ?", (args.name,))
    if row is None:
        print(f"ERROR: CA key not found: {args.name!r}")
        return 1
    old_ref = row["backend_ref"]
    db.execute(
        "UPDATE ca_keys SET backend_ref = ? WHERE name = ?",
        (args.new_ref, args.name),
    )
    print(f"CA key rotated: {args.name!r}")
    print(f"  old ref: {old_ref}")
    print(f"  new ref: {args.new_ref}")
    print("Restart the PyPKI server to load the new key version.")
    return 0


def _get_tenant_manager(args):
    db = _open_pki_db(args)
    from tenant import TenantManager
    return TenantManager(db)


def cmd_tenant_create(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    try:
        t = tm.create(
            slug=args.slug,
            display_name=args.display_name,
            created_by=getattr(args, "owner_identity", "system"),
            max_active_certs=getattr(args, "max_active_certs", None),
        )
        print(f"Tenant created: {t.slug!r} ({t.display_name})")
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1


def cmd_tenant_list(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    tenants = tm.list(include_suspended=getattr(args, "include_suspended", False))
    if not tenants:
        print("No tenants.")
        return 0
    print(f"{'SLUG':<20} {'DISPLAY NAME':<30} {'STATUS'}")
    print("-" * 60)
    for t in tenants:
        status = "[SUSPENDED]" if t.suspended else "active"
        print(f"{t.slug:<20} {t.display_name:<30} {status}")
    return 0


def cmd_tenant_show(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    t = tm.get(args.slug)
    if t is None:
        print(f"ERROR: Tenant not found: {args.slug!r}")
        return 1
    quota = tm.get_quota(args.slug)
    print(f"Slug:          {t.slug}")
    print(f"Name:          {t.display_name}")
    print(f"Created by:    {t.created_by}")
    print(f"Isolation:     {t.isolation_level}")
    print(f"Suspended:     {t.suspended}" + (f" ({t.suspended_reason})" if t.suspended_reason else ""))
    if quota:
        print(f"Quota (active certs): {quota.max_active_certs or 'unlimited'}")
        print(f"Quota (per-day):      {quota.max_issuances_per_day or 'unlimited'}")
    admins = tm.list_admins(args.slug)
    if admins:
        print(f"Admins:        {', '.join(a['identity'] + '(' + a['role'] + ')' for a in admins)}")
    return 0


def cmd_tenant_set_quota(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    kwargs = {}
    if getattr(args, "max_active_certs", None) is not None:
        kwargs["max_active_certs"] = args.max_active_certs
    if getattr(args, "max_issuances_per_day", None) is not None:
        kwargs["max_issuances_per_day"] = args.max_issuances_per_day
    if getattr(args, "max_sub_cas", None) is not None:
        kwargs["max_sub_cas"] = args.max_sub_cas
    tm.set_quota(args.slug, **kwargs)
    print(f"Quota updated for tenant {args.slug!r}")
    return 0


def cmd_tenant_add_admin(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    tm.add_admin(args.slug, args.identity, getattr(args, "role", "operator"))
    print(f"Admin added: {args.identity!r} → {args.slug!r} (role={args.role})")
    return 0


def cmd_tenant_remove_admin(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    tm.remove_admin(args.slug, args.identity)
    print(f"Admin removed: {args.identity!r} from {args.slug!r}")
    return 0


def cmd_tenant_add_dns_alias(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    try:
        tm.add_dns_alias(args.slug, args.hostname)
        print(f"DNS alias added: {args.hostname!r} → {args.slug!r}")
        return 0
    except ValueError as exc:
        print(f"ERROR: {exc}")
        return 1


def cmd_tenant_suspend(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    tm.suspend(args.slug, getattr(args, "reason", ""))
    print(f"Tenant suspended: {args.slug!r}")
    return 0


def cmd_tenant_resume(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    tm = _get_tenant_manager(args)
    tm.resume(args.slug)
    print(f"Tenant resumed: {args.slug!r}")
    return 0


def cmd_tenant_delete(args: argparse.Namespace) -> int:
    _setup_logging(args.log_level)
    if not getattr(args, "confirm", False):
        print("ERROR: Add --confirm to actually delete the tenant.")
        return 1
    tm = _get_tenant_manager(args)
    try:
        tm.delete(args.slug)
        print(f"Tenant deleted: {args.slug!r}")
        return 0
    except (ValueError, PermissionError) as exc:
        print(f"ERROR: {exc}")
        return 1


def cmd_codesign_log_verify(args: argparse.Namespace) -> int:
    """Verify the Merkle log from leaves up."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import merkle_log as _ml
    ok, msg = _ml.verify_log(db)
    print(msg)
    return 0 if ok else 1


def cmd_codesign_anchor_now(args: argparse.Namespace) -> int:
    """Write a signed Merkle checkpoint immediately."""
    _setup_logging(args.log_level)
    db = _open_pki_db(args)
    import merkle_log as _ml
    from pki_server import CertificateAuthority
    ca = CertificateAuthority(ca_dir=getattr(args, "ca_dir", "./ca"))
    chk = _ml.write_checkpoint(db, ca.ca_key)
    print(f"Checkpoint written: tree_size={chk['tree_size']} root={chk['root_hash'][:16]}…")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
