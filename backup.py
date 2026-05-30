#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
backup.py — Encrypted, integrity-verified backup of PyPKI state.

Architecture
------------
A backup is a gzip tarball (optionally AES-256-GCM encrypted) with:

  pypki-backup-<ts>/
    manifest.json       -- file hashes, signing pubkey, created_at
    db/pki.sql.gz       -- sqlite3 .dump() of the PKI DB (gzipped)
    db/acme.sql.gz      -- (if present)
    db/scep.sql.gz      -- (if present)
    db/est.sql.gz       -- (if present)
    keys/ca.key.pem     -- CA key (already passphrase-encrypted)
    config/config.yaml  -- server config (if present)
    audit-seal.json     -- latest audit_log row id+hash (if audit_chain table exists)
    signature           -- Ed25519 sig over manifest.json bytes

Encryption
----------
If BackupConfig.passphrase is set, the whole tarball is wrapped:

  file = salt(16) || nonce(12) || AESGCM(scrypt(passphrase, salt, N=2^17)).encrypt(tarball)

The KDF is scrypt with N=2^17, r=8, p=1 (RFC 7914). This is memory-hard
and intentionally slow — do not call from the hot path.

Signing key
-----------
An Ed25519 signing key is stored at ``ca_dir/backup-signing.key`` (PEM,
unencrypted). It is generated on the first backup if absent. This key
proves the backup came from this CA instance; it is not a secret.

Public API
----------
    BackupConfig            -- frozen dataclass of backup settings
    BackupEngine            -- create_backup, list_backups, prune_backups, verify_backup
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import sqlite3
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature

if TYPE_CHECKING:
    from db import Database

logger = logging.getLogger("pypki.backup")

# ---------------------------------------------------------------------------
# Encryption constants (scrypt: N=2^17, r=8, p=1 — RFC 7914)
# ---------------------------------------------------------------------------
_SALT_LEN = 16
_NONCE_LEN = 12
_SCRYPT_N = 2 ** 17
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32

# DB filename → tarball internal name mapping
_DB_FILES = [
    ("certificates.db", "pki"),
    ("acme.db", "acme"),
    ("scep.db", "scep"),
    ("est.db", "est"),
]

SIGNING_KEY_FILE = "backup-signing.key"
FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# BackupConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackupConfig:
    """Immutable configuration for the backup engine."""
    targets: Tuple[str, ...]          # file:// URIs
    passphrase: Optional[bytes]       # None = no outer encryption
    retention_count: int              # 0 = unlimited
    retention_days: int               # 0 = unlimited


# ---------------------------------------------------------------------------
# Internal encryption helpers
# ---------------------------------------------------------------------------

def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from passphrase + salt using scrypt."""
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase)


def _encrypt_tarball(plaintext: bytes, passphrase: bytes) -> bytes:
    """Encrypt a tarball with AES-256-GCM + scrypt KDF."""
    import secrets as _secrets
    salt = _secrets.token_bytes(_SALT_LEN)
    nonce = _secrets.token_bytes(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def _decrypt_tarball(blob: bytes, passphrase: bytes) -> bytes:
    """Decrypt a blob produced by _encrypt_tarball."""
    if len(blob) < _SALT_LEN + _NONCE_LEN + 16:
        raise ValueError("encrypted blob too short")
    salt = blob[:_SALT_LEN]
    nonce = blob[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ct = blob[_SALT_LEN + _NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# Signing key management
# ---------------------------------------------------------------------------

def _load_or_create_signing_key(ca_dir: Path) -> Ed25519PrivateKey:
    """Load or generate the Ed25519 backup signing key."""
    key_path = ca_dir / SIGNING_KEY_FILE
    if key_path.exists():
        pem = key_path.read_bytes()
        return serialization.load_pem_private_key(pem, password=None)
    # Generate and persist
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    logger.info(f"Generated backup signing key at {key_path}")
    return key


def _pubkey_der_hex(key: Ed25519PrivateKey) -> str:
    """Return the DER-encoded SPKI of the public key as a hex string."""
    pub = key.public_key()
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der.hex()


def _load_pubkey_from_der_hex(hex_str: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from DER hex."""
    der = bytes.fromhex(hex_str)
    return serialization.load_der_public_key(der)


# ---------------------------------------------------------------------------
# Database dump helpers
# ---------------------------------------------------------------------------

def _dump_sqlite_gz(db_path: Path) -> bytes:
    """Dump a SQLite DB via .iterdump() and gzip-compress the SQL."""
    conn = sqlite3.connect(str(db_path))
    try:
        sql = "\n".join(conn.iterdump())
    finally:
        conn.close()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(sql.encode())
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Audit seal helpers
# ---------------------------------------------------------------------------

def _get_audit_seal(db: "Database") -> Optional[Dict]:
    """Retrieve the latest audit_log entry id and hash if the chain exists."""
    try:
        row = db.fetchone(
            "SELECT id, chain_hash FROM audit ORDER BY id DESC LIMIT 1"
        )
        if row is None:
            return None
        return {"final_id": row["id"], "final_hash": row["chain_hash"]}
    except Exception:
        # audit_chain table may not exist in all deployments
        try:
            row = db.fetchone(
                "SELECT id FROM audit ORDER BY id DESC LIMIT 1"
            )
            if row is None:
                return None
            return {"final_id": row["id"], "final_hash": None}
        except Exception:
            return None


# ---------------------------------------------------------------------------
# File: target URI helpers
# ---------------------------------------------------------------------------

def _parse_file_uri(uri: str) -> Path:
    """Parse a file:// URI and return the Path."""
    parsed = urlparse(uri)
    if parsed.scheme not in ("file", ""):
        raise ValueError(f"Unsupported target scheme: {parsed.scheme!r} in {uri!r}")
    return Path(parsed.path)


def _write_to_target(target_uri: str, filename: str, data: bytes) -> str:
    """Write *data* as *filename* to *target_uri*. Returns the full path written."""
    if target_uri.startswith("file://") or not target_uri.startswith(
        ("s3://", "gs://", "https://")
    ):
        dest_dir = _parse_file_uri(target_uri)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / filename
        dest.write_bytes(data)
        return str(dest)
    raise ValueError(
        f"Target URI scheme not supported (only file:// in this release): {target_uri!r}"
    )


def _list_backups_in_dir(directory: Path) -> List[Dict]:
    """Return a sorted list of backup file dicts in *directory*."""
    if not directory.is_dir():
        return []
    files = sorted(
        [
            f for f in directory.iterdir()
            if f.name.startswith("pypki-backup-") and (
                f.name.endswith(".tar.gz") or f.name.endswith(".tar.gz.enc")
            )
        ],
        key=lambda f: f.name,
    )
    result = []
    for f in files:
        stat = f.stat()
        result.append({
            "path": str(f),
            "filename": f.name,
            "size_bytes": stat.st_size,
            "mtime": stat.st_mtime,
        })
    return result


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_manifest(
    prefix: str,
    files: Dict[str, bytes],
    signing_pubkey_der_hex: str,
    audit_seal: Optional[Dict],
    created_at: str,
) -> Dict:
    file_hashes: Dict[str, Dict] = {}
    for name, data in files.items():
        file_hashes[name] = {
            "sha256": _sha256_hex(data),
            "size": len(data),
        }
    manifest: Dict = {
        "format_version": FORMAT_VERSION,
        "created_at": created_at,
        "created_by": "pypki-backup",
        "prefix": prefix,
        "files": file_hashes,
        "signing_pubkey": signing_pubkey_der_hex,
    }
    if audit_seal:
        manifest["audit_seal"] = audit_seal
    return manifest


# ---------------------------------------------------------------------------
# BackupEngine
# ---------------------------------------------------------------------------

class BackupEngine:
    """
    Creates, lists, prunes, and verifies PyPKI backups.

    Parameters
    ----------
    ca_dir : root directory of the CA (holds ca.key, *.db, config.yaml …)
    db     : DAL Database for the PKI DB (used to record backup metadata
             and to read the audit seal)
    config : immutable backup configuration
    """

    def __init__(self, ca_dir: Path, db: "Database", config: BackupConfig) -> None:
        self._ca_dir = ca_dir
        self._db = db
        self._config = config

    # ------------------------------------------------------------------
    # create_backup
    # ------------------------------------------------------------------

    def create_backup(self) -> Path:
        """
        Create a backup of the CA state.

        Steps:
          1. Dump each SQLite DB via iterdump() → gzip
          2. Collect CA key file
          3. Build manifest.json with sha256 of each file
          4. Sign manifest with Ed25519 signing key (generate if absent)
          5. Package into tarball (gzip)
          6. If passphrase: AES-256-GCM encrypt the tarball
          7. Write to each target URI
          8. Record in `backups` table

        Returns the Path written (first file:// target or a temp file).
        """
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        prefix = f"pypki-backup-{ts}"
        created_at = now.isoformat()

        signing_key = _load_or_create_signing_key(self._ca_dir)
        pubkey_hex = _pubkey_der_hex(signing_key)

        # --- Collect files ---
        files: Dict[str, bytes] = {}

        # DB dumps
        for db_filename, db_label in _DB_FILES:
            db_path = self._ca_dir / db_filename
            if db_path.exists():
                sql_gz = _dump_sqlite_gz(db_path)
                files[f"db/{db_label}.sql.gz"] = sql_gz
                logger.debug(f"Dumped {db_path} ({len(sql_gz)} bytes compressed)")

        # CA key file
        ca_key_path = self._ca_dir / "ca.key"
        if ca_key_path.exists():
            files["keys/ca.key.pem"] = ca_key_path.read_bytes()

        # Config
        config_path = self._ca_dir / "config.yaml"
        if config_path.exists():
            files["config/config.yaml"] = config_path.read_bytes()

        # Audit seal
        audit_seal = _get_audit_seal(self._db)

        if audit_seal:
            files["audit-seal.json"] = json.dumps(audit_seal).encode()

        # --- Build manifest ---
        manifest = _build_manifest(prefix, files, pubkey_hex, audit_seal, created_at)
        manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode()

        # --- Sign manifest ---
        signature = signing_key.sign(manifest_bytes)

        # --- Build tarball in memory ---
        tarball_bytes = self._build_tarball(
            prefix, manifest_bytes, signature, files
        )

        # --- Optionally encrypt ---
        encrypted = self._config.passphrase is not None
        if encrypted:
            output_bytes = _encrypt_tarball(tarball_bytes, self._config.passphrase)
            ext = ".tar.gz.enc"
        else:
            output_bytes = tarball_bytes
            ext = ".tar.gz"

        filename = f"{prefix}{ext}"
        manifest_hash = _sha256_hex(manifest_bytes)

        # --- Write to targets ---
        first_path: Optional[Path] = None
        for target_uri in self._config.targets:
            t_start = time.monotonic()
            try:
                written = _write_to_target(target_uri, filename, output_bytes)
                duration_ms = int((time.monotonic() - t_start) * 1000)
                status = "success"
                if first_path is None:
                    first_path = Path(written)
                self._record_backup(
                    created_at=created_at,
                    manifest_hash=manifest_hash,
                    target_uri=target_uri,
                    size_bytes=len(output_bytes),
                    upload_duration_ms=duration_ms,
                    upload_status=status,
                    audit_seal=audit_seal,
                )
                logger.info(f"Backup written to {written} ({len(output_bytes)} bytes)")
            except Exception as exc:
                logger.error(f"Backup to {target_uri!r} failed: {exc}")
                self._record_backup(
                    created_at=created_at,
                    manifest_hash=manifest_hash,
                    target_uri=target_uri,
                    size_bytes=len(output_bytes),
                    upload_duration_ms=int((time.monotonic() - t_start) * 1000),
                    upload_status="failed",
                    audit_seal=audit_seal,
                )

        if first_path is None:
            # No targets succeeded; write to a tempfile so caller gets something
            tmp = tempfile.NamedTemporaryFile(
                delete=False, suffix=ext, prefix="pypki-backup-"
            )
            tmp.write(output_bytes)
            tmp.close()
            first_path = Path(tmp.name)
            logger.warning(f"No targets succeeded; backup at temp path {first_path}")

        # Prune old backups
        for target_uri in self._config.targets:
            try:
                self.prune_backups(target_uri)
            except Exception as exc:
                logger.warning(f"Pruning {target_uri!r} failed: {exc}")

        return first_path

    def _build_tarball(
        self,
        prefix: str,
        manifest_bytes: bytes,
        signature: bytes,
        files: Dict[str, bytes],
    ) -> bytes:
        """Package all content into an in-memory gzip tarball."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            def _add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(name=f"{prefix}/{name}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            _add("manifest.json", manifest_bytes)
            _add("signature", signature)
            for rel_path, data in files.items():
                _add(rel_path, data)

        return buf.getvalue()

    def _record_backup(
        self,
        created_at: str,
        manifest_hash: str,
        target_uri: str,
        size_bytes: int,
        upload_duration_ms: int,
        upload_status: str,
        audit_seal: Optional[Dict],
    ) -> None:
        """Insert a row into the backups table."""
        try:
            self._db.execute(
                "INSERT INTO backups "
                "(created_at, manifest_hash, target_uri, size_bytes, "
                " upload_duration_ms, upload_status, audit_final_id, audit_final_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    created_at,
                    manifest_hash,
                    target_uri,
                    size_bytes,
                    upload_duration_ms,
                    upload_status,
                    audit_seal["final_id"] if audit_seal else None,
                    audit_seal["final_hash"] if audit_seal else None,
                ),
            )
        except Exception as exc:
            logger.warning(f"Could not record backup in DB: {exc}")

    # ------------------------------------------------------------------
    # list_backups
    # ------------------------------------------------------------------

    def list_backups(self, target_uri: str) -> List[Dict]:
        """
        Return a list of backup files at *target_uri*.

        Only file:// URIs are supported in this release. Returns dicts with
        keys: path, filename, size_bytes, mtime.
        """
        if target_uri.startswith("file://") or not target_uri.startswith(
            ("s3://", "gs://", "https://")
        ):
            directory = _parse_file_uri(target_uri)
            return _list_backups_in_dir(directory)
        raise ValueError(f"Unsupported target URI: {target_uri!r}")

    # ------------------------------------------------------------------
    # prune_backups
    # ------------------------------------------------------------------

    def prune_backups(self, target_uri: str) -> int:
        """
        Delete old backups at *target_uri* per retention policy.

        Returns the count of deleted files.
        """
        backups = self.list_backups(target_uri)
        if not backups:
            return 0

        to_delete: List[str] = []

        # Apply retention_count
        if self._config.retention_count > 0:
            if len(backups) > self._config.retention_count:
                excess = backups[: len(backups) - self._config.retention_count]
                to_delete.extend(b["path"] for b in excess)

        # Apply retention_days
        if self._config.retention_days > 0:
            cutoff = time.time() - self._config.retention_days * 86400
            for b in backups:
                if b["mtime"] < cutoff and b["path"] not in to_delete:
                    to_delete.append(b["path"])

        for path in to_delete:
            try:
                os.unlink(path)
                logger.info(f"Pruned old backup: {path}")
            except OSError as exc:
                logger.warning(f"Could not delete {path}: {exc}")

        return len(to_delete)

    # ------------------------------------------------------------------
    # verify_backup
    # ------------------------------------------------------------------

    def verify_backup(self, backup_path: Path) -> Dict:
        """
        Verify a backup file without restoring it.

        Steps:
          1. If .enc extension: decrypt using config.passphrase
          2. Open tarball, extract manifest.json and signature
          3. Verify Ed25519 signature over manifest.json bytes
          4. Verify SHA-256 of every file listed in manifest

        Returns the manifest dict on success. Raises on any failure.
        """
        data = backup_path.read_bytes()

        # Detect encrypted backup
        if str(backup_path).endswith(".enc"):
            if self._config.passphrase is None:
                raise ValueError("Backup is encrypted but no passphrase configured")
            data = _decrypt_tarball(data, self._config.passphrase)

        return _verify_tarball(data, passphrase=None)


# ---------------------------------------------------------------------------
# Standalone tarball verification (also used by RestoreEngine)
# ---------------------------------------------------------------------------

def _verify_tarball(tarball_bytes: bytes, passphrase: Optional[bytes]) -> Dict:
    """
    Verify a (possibly encrypted) tarball and return its manifest.

    If *passphrase* is given, decrypts first. Raises on any integrity failure.
    """
    data = tarball_bytes
    if passphrase is not None:
        data = _decrypt_tarball(data, passphrase)

    # Read all files from the tarball
    tar_contents: Dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf.getmembers():
            f = tf.extractfile(member)
            if f is not None:
                # Strip the prefix directory component
                parts = member.name.split("/", 1)
                rel = parts[1] if len(parts) > 1 else member.name
                tar_contents[rel] = f.read()

    if "manifest.json" not in tar_contents:
        raise ValueError("Backup tarball missing manifest.json")
    if "signature" not in tar_contents:
        raise ValueError("Backup tarball missing signature")

    manifest_bytes = tar_contents["manifest.json"]
    signature = tar_contents["signature"]

    manifest = json.loads(manifest_bytes)

    # Verify signature
    pubkey_hex = manifest.get("signing_pubkey")
    if not pubkey_hex:
        raise ValueError("manifest.json missing signing_pubkey field")
    try:
        pubkey = _load_pubkey_from_der_hex(pubkey_hex)
        pubkey.verify(signature, manifest_bytes)
    except InvalidSignature:
        raise ValueError("Backup signature verification FAILED — backup may be tampered")
    except Exception as exc:
        raise ValueError(f"Signature verification error: {exc}")

    # Verify file hashes
    for rel_path, file_meta in manifest.get("files", {}).items():
        if rel_path not in tar_contents:
            raise ValueError(f"File listed in manifest but missing from tarball: {rel_path}")
        actual_hash = _sha256_hex(tar_contents[rel_path])
        expected_hash = file_meta["sha256"]
        if actual_hash != expected_hash:
            raise ValueError(
                f"Hash mismatch for {rel_path}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

    return manifest
