#!/usr/bin/env python3
"""
pypki-wg-sync — WireGuard server config sync agent (pull mode).

Polls GET /api/wg/server-config/<server-id> and applies the result with
``wg syncconf`` so connected peers are not dropped.

No pip dependencies; stdlib only.

Usage:
  python3 sync.py \
    --server-id vpn-01 \
    --pypki-url https://pki.example.com \
    --api-token <token> \
    --interface wg0 \
    [--interval 60]

The agent writes the fetched config to a temp file and runs:
  wg syncconf <iface> <(wg-quick strip <iface>)
which applies peer changes without restarting the interface.

Systemd unit:
  [Service]
  ExecStart=/usr/bin/python3 /usr/local/lib/pypki/sync.py --server-id vpn-01 ...
  Restart=on-failure
  RestartSec=30
"""

import argparse
import hashlib
import http.client
import logging
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse

log = logging.getLogger("pypki-wg-sync")

# ---------------------------------------------------------------------------
# Config fetch
# ---------------------------------------------------------------------------

def fetch_server_config(
    pypki_url: str,
    server_id: str,
    api_token: str,
    timeout: int = 10,
) -> str:
    """Fetch wg server config from PyPKI. Returns the raw config text."""
    parsed = urllib.parse.urlsplit(pypki_url)
    path   = f"/api/wg/server-config/{server_id}"

    if parsed.scheme == "https":
        import ssl
        ctx  = ssl.create_default_context()
        conn = http.client.HTTPSConnection(parsed.netloc, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(parsed.netloc, timeout=timeout)

    conn.request("GET", path, headers={"Authorization": f"Bearer {api_token}"})
    resp = conn.getresponse()
    if resp.status != 200:
        raise RuntimeError(f"PyPKI returned HTTP {resp.status}")
    return resp.read().decode()


# ---------------------------------------------------------------------------
# Config application
# ---------------------------------------------------------------------------

def apply_config(config_text: str, interface: str) -> None:
    """
    Write config to a temp file, then apply with ``wg syncconf``.

    ``wg syncconf`` updates peers without dropping existing connections.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, prefix="pypki-wg-"
    ) as f:
        f.write(config_text)
        tmp_path = f.name
    os.chmod(tmp_path, 0o600)

    try:
        # wg syncconf requires the stripped config (no [Interface] section).
        # ``wg-quick strip`` outputs just the [Peer] sections.
        strip_result = subprocess.run(
            ["wg-quick", "strip", interface],
            capture_output=True, text=True,
        )
        # If strip fails (interface not running), fall back to setconf.
        if strip_result.returncode != 0:
            subprocess.run(
                ["wg", "setconf", interface, tmp_path],
                check=True,
            )
        else:
            subprocess.run(
                ["wg", "syncconf", interface, tmp_path],
                check=True,
            )
        log.info("Applied WireGuard config to interface %s", interface)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_loop(args: argparse.Namespace) -> None:
    last_hash: str = ""

    while True:
        try:
            config = fetch_server_config(
                pypki_url=args.pypki_url,
                server_id=args.server_id,
                api_token=args.api_token,
            )
            new_hash = hashlib.sha256(config.encode()).hexdigest()
            if new_hash != last_hash:
                log.info("Config changed — applying to %s", args.interface)
                apply_config(config, args.interface)
                last_hash = new_hash
            else:
                log.debug("Config unchanged")
        except Exception as exc:
            log.warning("Sync error: %s", exc)

        time.sleep(args.interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description="PyPKI WireGuard config sync agent")
    parser.add_argument("--server-id",   required=True)
    parser.add_argument("--pypki-url",   required=True)
    parser.add_argument("--api-token",   required=True)
    parser.add_argument("--interface",   default="wg0")
    parser.add_argument("--interval",    type=int, default=60)
    parser.add_argument("--log-level",   default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log.info("pypki-wg-sync starting: server=%s iface=%s", args.server_id, args.interface)
    run_loop(args)


if __name__ == "__main__":
    sys.exit(main())
