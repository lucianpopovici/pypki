#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
ssh_wire.py — SSH binary protocol wire-format primitives (RFC 4251 §5).

Encoding:
    pack_string(s)            length-prefixed bytes/str (4-byte big-endian length)
    pack_uint32(n)            4 bytes big-endian
    pack_uint64(n)            8 bytes big-endian
    pack_mpint(n)             SSH multiple-precision integer (sign-bit padded)
    pack_name_list(names)     comma-delimited list packed as a string

Decoding:
    unpack_string(data, pos)  → (value: bytes, next_pos: int)
    unpack_uint32(data, pos)  → (value: int,   next_pos: int)
    unpack_uint64(data, pos)  → (value: int,   next_pos: int)
    unpack_mpint(data, pos)   → (value: int,   next_pos: int)
"""
from __future__ import annotations

import struct
from typing import Iterable, Tuple


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def pack_string(s: bytes | str) -> bytes:
    """SSH string: 4-byte big-endian length followed by data bytes."""
    if isinstance(s, str):
        s = s.encode()
    return struct.pack(">I", len(s)) + s


def pack_uint32(n: int) -> bytes:
    return struct.pack(">I", n)


def pack_uint64(n: int) -> bytes:
    return struct.pack(">Q", n)


def pack_mpint(n: int) -> bytes:
    """SSH mpint: big-endian byte string of a non-negative integer.

    If the high bit of the first byte is set, a 0x00 prefix is added to
    indicate a positive value (SSH two's-complement convention).
    Zero is encoded as an empty string (length=0).
    """
    if n < 0:
        raise ValueError("pack_mpint: negative integers not supported")
    if n == 0:
        return pack_string(b"")
    # Minimal big-endian encoding
    byte_len = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_len, "big")
    # Prepend 0x00 if high bit would indicate negative
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return pack_string(raw)


def pack_name_list(names: Iterable[str]) -> bytes:
    """SSH name-list: comma-separated names packed as a single SSH string."""
    joined = ",".join(names).encode("ascii")
    return pack_string(joined)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def unpack_string(data: bytes, pos: int) -> Tuple[bytes, int]:
    """Read an SSH string at *pos*, return (value, next_pos)."""
    if len(data) < pos + 4:
        raise ValueError(f"unpack_string: truncated at pos={pos}")
    (length,) = struct.unpack_from(">I", data, pos)
    start = pos + 4
    end   = start + length
    if len(data) < end:
        raise ValueError(f"unpack_string: data too short (need {end}, have {len(data)})")
    return data[start:end], end


def unpack_uint32(data: bytes, pos: int) -> Tuple[int, int]:
    if len(data) < pos + 4:
        raise ValueError(f"unpack_uint32: truncated at pos={pos}")
    (val,) = struct.unpack_from(">I", data, pos)
    return val, pos + 4


def unpack_uint64(data: bytes, pos: int) -> Tuple[int, int]:
    if len(data) < pos + 8:
        raise ValueError(f"unpack_uint64: truncated at pos={pos}")
    (val,) = struct.unpack_from(">Q", data, pos)
    return val, pos + 8


def unpack_mpint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read an SSH mpint and return (integer value, next_pos)."""
    raw, next_pos = unpack_string(data, pos)
    if not raw:
        return 0, next_pos
    # Strip leading sign byte if present
    val = int.from_bytes(raw, "big")
    return val, next_pos
