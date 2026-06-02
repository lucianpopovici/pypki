#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Append-only Merkle transparency log for PyPKI's code-signing portal.

Hash strategy follows RFC 6962 §2.1:
  - Leaf:  SHA256(0x00 || leaf_data)
  - Node:  SHA256(0x01 || left_hash || right_hash)
  - Empty: SHA256(b"")

All appends are serialized via advisory_lock("codesign-merkle").
Tree nodes are persisted in codesign_tree_nodes(level, idx, hash).
"""

import hashlib
import logging
import threading
import time
from typing import List, Optional, Tuple

log = logging.getLogger("pypki.merkle_log")

_EMPTY_HASH = hashlib.sha256(b"").digest()


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


# ---------------------------------------------------------------------------
# Tree size helpers
# ---------------------------------------------------------------------------

def _largest_power_of_2_below(n: int) -> int:
    """Return the largest power of 2 strictly less than n (n > 1)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def _root_from_hashes(hashes: List[bytes]) -> bytes:
    """Compute the root hash from a list of leaf hashes."""
    n = len(hashes)
    if n == 0:
        return _EMPTY_HASH
    if n == 1:
        return hashes[0]
    k = _largest_power_of_2_below(n)
    left  = _root_from_hashes(hashes[:k])
    right = _root_from_hashes(hashes[k:])
    return _node_hash(left, right)


# ---------------------------------------------------------------------------
# Core append and query
# ---------------------------------------------------------------------------

def _next_sequence(db) -> int:
    """Return the next sequence number = count of existing leaves."""
    row = db.fetchone(
        "SELECT COALESCE(COUNT(*), 0) AS n FROM codesign_tree_nodes WHERE level = 0"
    )
    return row["n"] if row else 0


def append(payload_hash: bytes, db) -> Tuple[int, bytes]:
    """
    Append a leaf to the Merkle log.

    Parameters
    ----------
    payload_hash : SHA-256 digest of the log entry content
    db           : Database connection (advisory lock acquired inside)

    Returns
    -------
    (sequence, leaf_hash) where sequence is the zero-based leaf index and
    leaf_hash is H(0x00 || payload_hash).
    """
    with db.advisory_lock("codesign-merkle"):
        seq       = _next_sequence(db)
        leaf      = _leaf_hash(payload_hash)
        # Store the leaf at level 0
        db.execute(
            "INSERT OR REPLACE INTO codesign_tree_nodes (level, idx, hash) VALUES (0, ?, ?)",
            (seq, leaf),
        )
        # Propagate upward: merge siblings into parent nodes
        _propagate(db, seq, leaf)
        return seq, leaf


def _propagate(db, seq: int, h: bytes) -> None:
    """Build/update parent nodes up the tree after inserting leaf at seq."""
    idx   = seq
    level = 0
    while idx % 2 == 1:
        # This node is a right child — merge with its left sibling
        sibling_row = db.fetchone(
            "SELECT hash FROM codesign_tree_nodes WHERE level = ? AND idx = ?",
            (level, idx - 1),
        )
        if sibling_row is None:
            break
        parent_hash = _node_hash(bytes(sibling_row["hash"]), h)
        level += 1
        idx   = idx // 2
        db.execute(
            "INSERT OR REPLACE INTO codesign_tree_nodes (level, idx, hash) VALUES (?, ?, ?)",
            (level, idx, parent_hash),
        )
        h = parent_hash


def _get_leaf_hashes(db, tree_size: int) -> List[bytes]:
    """Return all leaf hashes in order for a tree of tree_size leaves."""
    rows = db.fetchall(
        "SELECT hash FROM codesign_tree_nodes WHERE level = 0 ORDER BY idx LIMIT ?",
        (tree_size,),
    )
    return [bytes(r["hash"]) for r in rows]


def root_hash(db, tree_size: Optional[int] = None) -> bytes:
    """Compute and return the current Merkle root."""
    if tree_size is None:
        row = db.fetchone(
            "SELECT COALESCE(COUNT(*), 0) AS n FROM codesign_tree_nodes WHERE level = 0"
        )
        tree_size = row["n"] if row else 0
    leaves = _get_leaf_hashes(db, tree_size)
    return _root_from_hashes(leaves)


def tree_size(db) -> int:
    """Return the current number of leaves in the log."""
    row = db.fetchone(
        "SELECT COALESCE(COUNT(*), 0) AS n FROM codesign_tree_nodes WHERE level = 0"
    )
    return row["n"] if row else 0


# ---------------------------------------------------------------------------
# Inclusion proof
# ---------------------------------------------------------------------------

def inclusion_proof(seq: int, n: int, db) -> List[bytes]:
    """
    Return the sibling path (inclusion proof) for leaf at index seq in a
    tree of n leaves.

    Follows RFC 6962 §2.1.3. The proof is the list of sibling hashes from
    the leaf to the root. A verifier recomputes the root using these hashes.
    """
    if n == 0 or seq >= n:
        return []
    leaves = _get_leaf_hashes(db, n)
    return _proof_for(seq, leaves)


def _proof_for(idx: int, leaves: List[bytes]) -> List[bytes]:
    """Recursive inclusion proof computation."""
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_2_below(n)
    if idx < k:
        return _proof_for(idx, leaves[:k]) + [_root_from_hashes(leaves[k:])]
    else:
        return _proof_for(idx - k, leaves[k:]) + [_root_from_hashes(leaves[:k])]


def verify_inclusion_proof(
    leaf_hash: bytes,
    seq: int,
    proof: List[bytes],
    expected_root: bytes,
    n: int,
) -> bool:
    """
    Verify an inclusion proof (RFC 6962 §2.1.1).

    Parameters
    ----------
    leaf_hash     : H(0x00 || payload_hash) for the leaf
    seq           : Zero-based leaf index
    proof         : Sibling hashes from leaf to root (output of inclusion_proof)
    expected_root : The root hash to verify against
    n             : Tree size at proof generation time
    """
    h        = leaf_hash
    idx      = seq
    last_idx = n - 1

    for sibling in proof:
        if idx % 2 == 1 or idx == last_idx:
            # This node is a right child (or the lone rightmost node at this level):
            # sibling goes LEFT.
            h = _node_hash(sibling, h)
            # Skip up past consecutive lone-right-child levels.
            while idx % 2 == 0 and last_idx > 0:
                idx      //= 2
                last_idx //= 2
        else:
            # This node is a left child: sibling goes RIGHT.
            h = _node_hash(h, sibling)

        idx      //= 2
        last_idx //= 2

    return h == expected_root


# ---------------------------------------------------------------------------
# Checkpoint (signed tree head)
# ---------------------------------------------------------------------------

def write_checkpoint(db, signing_key, tree_size_val: Optional[int] = None) -> dict:
    """
    Compute and store a signed tree head.

    The checkpoint signs the tree_size and root_hash with the CA's signing key.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    sz   = tree_size_val if tree_size_val is not None else tree_size(db)
    r    = root_hash(db, sz)
    now  = int(time.time())
    msg  = (str(sz) + "\n" + r.hex()).encode()

    if isinstance(signing_key, ec.EllipticCurvePrivateKey):
        sig = signing_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    else:
        sig = signing_key.sign(msg)

    db.execute(
        "INSERT OR REPLACE INTO codesign_checkpoints "
        "(tree_size, root_hash, signed_at, signature) VALUES (?, ?, ?, ?)",
        (sz, r, now, sig),
    )
    return {"tree_size": sz, "root_hash": r.hex(), "signed_at": now}


def verify_log(db) -> Tuple[bool, str]:
    """
    Re-hash the full Merkle tree from leaves and compare against the last checkpoint.

    Returns (ok, message).
    """
    sz     = tree_size(db)
    actual = root_hash(db, sz)
    row    = db.fetchone(
        "SELECT root_hash, tree_size FROM codesign_checkpoints ORDER BY tree_size DESC LIMIT 1"
    )
    if row is None:
        return True, f"No checkpoint; tree has {sz} leaves, root={actual.hex()[:16]}…"
    expected = bytes(row["root_hash"])
    if actual != expected:
        return False, (
            f"Root hash mismatch at tree_size={row['tree_size']}: "
            f"computed={actual.hex()[:16]}… stored={expected.hex()[:16]}…"
        )
    return True, f"Log verified: {sz} leaves, root={actual.hex()[:16]}…"
