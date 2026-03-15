#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
pypki.py — Single entry point for PyPKI.

Reads pypki.json in the current directory (or a path given as the first
argument) and translates it into pki_server CLI arguments before calling
pki_server.main().

Usage:
    python pypki.py                   # uses ./pypki.json
    python pypki.py /etc/pypki.json   # custom config path
"""

import json
import sys
from pathlib import Path


def _load_config(path: Path) -> dict:
    if not path.exists():
        print(f"ERROR: config file not found: {path}")
        print("  Create pypki.json (see pypki.json.example or the docs).")
        sys.exit(1)
    with path.open() as f:
        return json.load(f)


def _build_argv(cfg: dict) -> list:
    """Convert pypki.json structure to pki_server CLI argument list."""
    argv = []

    # ── core ──────────────────────────────────────────────────────────────────
    argv += ["--host",      cfg.get("host", "0.0.0.0")]
    argv += ["--ca-dir",    cfg.get("ca_dir", "./ca")]
    argv += ["--log-level", cfg.get("log_level", "INFO")]

    # ── CMP port ──────────────────────────────────────────────────────────────
    cmp = cfg.get("cmp", {})
    argv += ["--port", str(cmp.get("port", 8080))]

    # ── TLS ───────────────────────────────────────────────────────────────────
    tls = cfg.get("tls", {})
    mode = tls.get("mode", "none")
    if mode == "mtls":
        argv.append("--mtls")
    elif mode == "tls":
        argv.append("--tls")

    if mode in ("tls", "mtls"):
        hostname = tls.get("hostname", "localhost")
        if hostname:
            argv += ["--tls-hostname", hostname]
        if tls.get("cert"):
            argv += ["--tls-cert", tls["cert"]]
        if tls.get("key"):
            argv += ["--tls-key", tls["key"]]
        if tls.get("tls13_only"):
            argv.append("--tls13-only")
        reload_interval = tls.get("reload_interval", 60)
        argv += ["--tls-reload-interval", str(reload_interval)]

    # ── Web UI — always on ────────────────────────────────────────────────────
    web = cfg.get("web_ui", {})
    web_port = web.get("port", 8090)
    argv += ["--web-port", str(web_port)]
    if web.get("no_auth", False):
        argv.append("--web-no-auth")
    pam_service = web.get("pam_service", "login")
    if pam_service:
        argv += ["--web-pam-service", pam_service]

    # ── ACME ──────────────────────────────────────────────────────────────────
    acme = cfg.get("acme", {})
    if acme.get("enabled", False):
        argv += ["--acme-port", str(acme.get("port", 8888))]
        if acme.get("cert_days"):
            argv += ["--acme-cert-days", str(acme["cert_days"])]
        if acme.get("short_lived_threshold_days"):
            argv += ["--acme-short-lived-threshold", str(acme["short_lived_threshold_days"])]
        if acme.get("auto_approve_dns"):
            argv.append("--acme-auto-approve-dns")
        if acme.get("base_url"):
            argv += ["--acme-base-url", acme["base_url"]]

    # ── SCEP ──────────────────────────────────────────────────────────────────
    scep = cfg.get("scep", {})
    if scep.get("enabled", False):
        argv += ["--scep-port", str(scep.get("port", 8889))]
        if scep.get("challenge"):
            argv += ["--scep-challenge", scep["challenge"]]

    # ── EST ───────────────────────────────────────────────────────────────────
    est = cfg.get("est", {})
    if est.get("enabled", False):
        argv += ["--est-port", str(est.get("port", 8443))]
        if not est.get("require_auth", True):
            argv.append("--est-no-auth")
        if est.get("tls_cert"):
            argv += ["--est-tls-cert", est["tls_cert"]]
        if est.get("tls_key"):
            argv += ["--est-tls-key", est["tls_key"]]

    # ── OCSP ──────────────────────────────────────────────────────────────────
    ocsp = cfg.get("ocsp", {})
    if ocsp.get("enabled", False):
        argv += ["--ocsp-port", str(ocsp.get("port", 9001))]
        argv += ["--ocsp-cache-seconds", str(ocsp.get("cache_seconds", 300))]
        if ocsp.get("url"):
            argv += ["--ocsp-url", ocsp["url"]]

    # ── IPsec ─────────────────────────────────────────────────────────────────
    ipsec = cfg.get("ipsec", {})
    if ipsec.get("enabled", False):
        argv += ["--ipsec-port", str(ipsec.get("port", 8444))]
        if ipsec.get("tls_cert"):
            argv += ["--ipsec-tls-cert", ipsec["tls_cert"]]
        if ipsec.get("tls_key"):
            argv += ["--ipsec-tls-key", ipsec["tls_key"]]

    # ── Validity periods ──────────────────────────────────────────────────────
    validity = cfg.get("validity", {})
    if validity.get("end_entity_days"):
        argv += ["--end-entity-days", str(validity["end_entity_days"])]
    if validity.get("client_cert_days"):
        argv += ["--client-cert-days", str(validity["client_cert_days"])]
    if validity.get("tls_server_days"):
        argv += ["--tls-server-days", str(validity["tls_server_days"])]
    if validity.get("ca_days"):
        argv += ["--ca-days", str(validity["ca_days"])]

    return argv


def main():
    # Allow passing a config path as the first argument
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        config_path = Path(sys.argv[1])
    else:
        config_path = Path("pypki.json")

    cfg = _load_config(config_path)

    # Build and inject argv so pki_server.main() sees them
    argv = _build_argv(cfg)
    sys.argv = [sys.argv[0]] + argv

    print(f"[pypki] Starting with config: {config_path}")
    print(f"[pypki] Args: {' '.join(argv)}\n")

    import pki_server
    pki_server.main()


if __name__ == "__main__":
    main()
