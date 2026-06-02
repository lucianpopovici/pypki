#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
WireGuard PKI — peer identity registry and config distribution.

WireGuard uses Curve25519 keys for its cryptography; there are no X.509
certificates involved.  This module tracks peer identities (public key,
allowed IPs, validity window) in a DB table, emits ready-to-paste wg config
snippets, and supports revocation by removing peers from the server config.

Key format: WireGuard uses 32-byte Curve25519 public/private keys encoded
as base64 (the same format as ``wg genkey`` / ``wg pubkey``).

Dependencies: cryptography (already a runtime dep).
"""

import base64
import dataclasses
import datetime
import json
import logging
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("pypki.wg")


# ---------------------------------------------------------------------------
# WireGuardProfile — policy governing peer enrollments
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class WireGuardProfile:
    """Policy applied when enrolling a new WireGuard peer."""
    max_validity_seconds: int       = 2_592_000   # 30 days
    allowed_ip_pattern:   str       = r"^\d+\.\d+\.\d+\.\d+/\d+$"  # any CIDR
    require_csr:          bool      = False        # if True, refuse server-side keygen
    portal_self_revoke:   bool      = True


WG_PROFILES: Dict[str, WireGuardProfile] = {
    "wg_user_vpn": WireGuardProfile(
        max_validity_seconds=2_592_000,              # 30 days
        allowed_ip_pattern=r"^10\.\d+\.\d+\.\d+/32$",
        require_csr=False,
        portal_self_revoke=True,
    ),
    "wg_site_to_site": WireGuardProfile(
        max_validity_seconds=31_536_000,             # 1 year
        allowed_ip_pattern=r"^10\.\d+\.\d+\.\d+/(8|16|24)$",
        require_csr=True,
        portal_self_revoke=False,
    ),
}


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[str, str]:
    """
    Generate a Curve25519 keypair in WireGuard's base64 format.

    Returns (private_key_b64, public_key_b64).  The private key is returned
    only here — the caller is responsible for delivering it securely.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    priv = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv_b64, pub_b64


def pubkey_from_privkey(priv_b64: str) -> str:
    """Derive the WireGuard public key from a base64 private key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw  = base64.b64decode(priv_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


# ---------------------------------------------------------------------------
# Peer ID generation
# ---------------------------------------------------------------------------

def _next_peer_id(db) -> str:
    """Generate a monotonic peer ID like 'wg-2026-0042'."""
    year = datetime.datetime.now(datetime.timezone.utc).year
    rows = db.fetchall(
        "SELECT peer_id FROM wg_peers WHERE peer_id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"wg-{year}-%",),
    )
    if rows:
        last = rows[0]["peer_id"]
        try:
            n = int(last.split("-")[2]) + 1
        except (IndexError, ValueError):
            n = 1
    else:
        n = 1
    return f"wg-{year}-{n:04d}"


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

def peer_client_config(
    peer: Dict,
    priv_key_b64: str,
    servers: List[Dict],
    dns: Optional[str] = None,
) -> str:
    """
    Build a client wg config snippet for the given peer.

    *priv_key_b64* is the private key (only available at enrollment time).
    *servers* is a list of wg_servers rows this peer is assigned to.
    """
    raw_ips = peer.get("allowed_ips") or "[]"
    allowed_ips = raw_ips if isinstance(raw_ips, list) else json.loads(raw_ips)
    address = ", ".join(allowed_ips) if allowed_ips else ""

    lines = [
        "[Interface]",
        f"PrivateKey = {priv_key_b64 or '<private-key>'}",
        f"Address = {address}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append("")

    for srv in servers:
        lines += [
            "[Peer]",
            f"PublicKey = {srv['public_key']}",
            f"Endpoint = {srv['endpoint']}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
        ]
        if peer.get("persistent_keepalive"):
            lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")
        lines.append("")

    return "\n".join(lines)


def server_config(server: Dict, peers: List[Dict]) -> str:
    """
    Build a server wg config with all active peers.

    This is the output of ``GET /api/wg/server-config/<server_id>``.
    """
    now = int(time.time())
    lines = [
        "[Interface]",
        f"PrivateKey = <server-private-key>",
        f"ListenPort = {server.get('listen_port', 51820)}",
        f"# Network: {server.get('network_cidr', '')}",
        "",
    ]
    for peer in peers:
        if peer.get("revoked"):
            continue
        if peer.get("valid_before", 0) < now:
            continue
        raw_ips2 = peer.get("allowed_ips") or "[]"
        allowed_ips = raw_ips2 if isinstance(raw_ips2, list) else json.loads(raw_ips2)
        allowed_str = ", ".join(allowed_ips)
        lines += [
            "[Peer]",
            f"# {peer.get('peer_name', peer.get('peer_id', ''))}",
            f"PublicKey = {peer['public_key']}",
            f"AllowedIPs = {allowed_str}",
        ]
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {peer['endpoint']}")
        if peer.get("persistent_keepalive"):
            lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WireGuardCA — the main facade
# ---------------------------------------------------------------------------

class WireGuardCA:
    """
    Peer identity registry.  All state lives in the PKI database.

    Thread-safety: each public method operates through the DAL;
    SQLite WAL mode ensures concurrent reads are safe.
    """

    def __init__(self, db, audit_log=None) -> None:
        self._db        = db
        self._audit_log = audit_log

    # ---- Server registration ----

    def register_server(
        self,
        server_id: str,
        public_key: str,
        endpoint: str,
        listen_port: int = 51820,
        network_cidr: str = "10.10.0.0/24",
        tenant_id: str = "__system",
    ) -> Dict:
        self._db.execute(
            "INSERT OR REPLACE INTO wg_servers "
            "(server_id, public_key, endpoint, listen_port, network_cidr, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (server_id, public_key, endpoint, listen_port, network_cidr, tenant_id),
        )
        log.info("WG server registered: %s at %s", server_id, endpoint)
        return {"server_id": server_id, "endpoint": endpoint}

    def list_servers(self) -> List[Dict]:
        rows = self._db.fetchall("SELECT * FROM wg_servers")
        return [dict(r) for r in rows]

    # ---- Peer enrollment ----

    def enroll_peer(
        self,
        peer_name: str,
        allowed_ips: List[str],
        profile_name: str = "wg_user_vpn",
        public_key: Optional[str] = None,   # None → server generates keypair
        endpoint: Optional[str] = None,
        persistent_keepalive: Optional[int] = None,
        valid_seconds: Optional[int] = None,
        server_ids: Optional[List[str]] = None,
        tenant_id: str = "__system",
        requester_ip: str = "",
    ) -> Dict:
        """
        Enroll a new WireGuard peer.

        If *public_key* is None, a Curve25519 keypair is generated server-side
        and the private key is returned **once** in the response (never stored).

        Returns a dict with peer metadata, wg config, and (if server-generated)
        the private key.
        """
        prof = WG_PROFILES.get(profile_name)
        if prof is None:
            raise ValueError(f"Unknown WireGuard profile: {profile_name!r}")

        # Validate allowed_ips against profile pattern
        pat = re.compile(prof.allowed_ip_pattern)
        for ip in allowed_ips:
            if not pat.match(ip):
                raise ValueError(
                    f"Allowed IP {ip!r} does not match profile pattern {prof.allowed_ip_pattern!r}"
                )

        # Key handling
        priv_b64 = None
        if public_key is None:
            if prof.require_csr:
                raise ValueError(
                    f"Profile {profile_name!r} requires CSR mode (supply public_key)"
                )
            priv_b64, public_key = generate_keypair()

        # Validity
        now = int(time.time())
        max_sec = prof.max_validity_seconds
        secs = min(valid_seconds, max_sec) if valid_seconds else max_sec
        valid_before = now + secs

        peer_id = _next_peer_id(self._db)

        self._db.execute(
            "INSERT INTO wg_peers "
            "(peer_id, peer_name, public_key, allowed_ips, endpoint, "
            "persistent_keepalive, profile_name, valid_after, valid_before, "
            "revoked, tenant_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (peer_id, peer_name, public_key, json.dumps(allowed_ips),
             endpoint, persistent_keepalive, profile_name,
             now, valid_before, tenant_id, now),
        )

        # Assign to servers (all servers if none specified)
        if server_ids is None:
            server_ids = [r["server_id"] for r in self._db.fetchall("SELECT server_id FROM wg_servers")]
        for sid in server_ids:
            self._db.execute(
                "INSERT OR IGNORE INTO wg_assignments (peer_id, server_id, assigned_at) VALUES (?, ?, ?)",
                (peer_id, sid, now),
            )

        if self._audit_log:
            try:
                self._audit_log.record(
                    "wg.enroll",
                    f"peer_id={peer_id} name={peer_name!r} allowed_ips={allowed_ips}",
                    requester_ip,
                )
            except Exception:
                pass

        log.info("WG peer enrolled: %s (%s)", peer_id, peer_name)

        # Build response
        peer_row = {"peer_id": peer_id, "peer_name": peer_name, "public_key": public_key,
                    "allowed_ips": allowed_ips, "endpoint": endpoint,
                    "persistent_keepalive": persistent_keepalive, "valid_before": valid_before}
        servers = self._servers_for_peer(peer_id)
        cfg = peer_client_config(peer_row, priv_b64 or "", servers)

        result: Dict[str, Any] = {
            "peer_id":    peer_id,
            "peer_name":  peer_name,
            "public_key": public_key,
            "config":     cfg,
            "valid_before": valid_before,
        }
        if priv_b64 is not None:
            result["private_key"] = priv_b64  # returned once only

        return result

    def _servers_for_peer(self, peer_id: str) -> List[Dict]:
        rows = self._db.fetchall(
            "SELECT s.* FROM wg_servers s "
            "JOIN wg_assignments a ON a.server_id = s.server_id "
            "WHERE a.peer_id = ?",
            (peer_id,),
        )
        return [dict(r) for r in rows]

    # ---- Peer query ----

    def list_peers(
        self,
        include_revoked: bool = False,
        tenant_id: Optional[str] = None,
    ) -> List[Dict]:
        now = int(time.time())
        conds = []
        params: list = []
        if not include_revoked:
            conds.append("revoked = 0 AND valid_before > ?")
            params.append(now)
        if tenant_id:
            conds.append("tenant_id = ?")
            params.append(tenant_id)
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = self._db.fetchall(
            f"SELECT * FROM wg_peers {where} ORDER BY created_at DESC",
            tuple(params),
        )
        result = []
        for r in rows:
            d = dict(r)
            d["allowed_ips"] = json.loads(d.get("allowed_ips") or "[]")
            result.append(d)
        return result

    def get_peer(self, peer_id: str) -> Optional[Dict]:
        row = self._db.fetchone("SELECT * FROM wg_peers WHERE peer_id = ?", (peer_id,))
        if row is None:
            return None
        d = dict(row)
        d["allowed_ips"] = json.loads(d.get("allowed_ips") or "[]")
        return d

    # ---- Server config distribution ----

    def get_server_config(self, server_id: str) -> Optional[str]:
        srv_row = self._db.fetchone("SELECT * FROM wg_servers WHERE server_id = ?", (server_id,))
        if srv_row is None:
            return None
        peer_rows = self._db.fetchall(
            "SELECT p.* FROM wg_peers p "
            "JOIN wg_assignments a ON a.peer_id = p.peer_id "
            "WHERE a.server_id = ?",
            (server_id,),
        )
        peers = []
        for r in peer_rows:
            d = dict(r)
            d["allowed_ips"] = json.loads(d.get("allowed_ips") or "[]")
            peers.append(d)
        return server_config(dict(srv_row), peers)

    # ---- Revocation ----

    def revoke_peer(self, peer_id: str, requester_ip: str = "") -> bool:
        row = self._db.fetchone("SELECT peer_name FROM wg_peers WHERE peer_id = ?", (peer_id,))
        if row is None:
            return False
        now = int(time.time())
        self._db.execute(
            "UPDATE wg_peers SET revoked = 1, revoked_at = ? WHERE peer_id = ?",
            (now, peer_id),
        )
        if self._audit_log:
            try:
                self._audit_log.record(
                    "wg.revoke",
                    f"peer_id={peer_id} name={row['peer_name']!r}",
                    requester_ip,
                )
            except Exception:
                pass
        log.info("WG peer revoked: %s", peer_id)
        return True
