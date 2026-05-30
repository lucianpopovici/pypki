#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
mnemonic.py — Byte-to-word encoding for paper backup of Shamir shares.

API:
    encode(data: bytes) -> list[str]
        Convert arbitrary bytes to a sequence of English words.
        Output length: len(data) + 2  (two extra words for CRC-16 checksum).

    decode(words: list[str]) -> bytes
        Reverse encode(); raises ValueError on unknown words or bad checksum.

Word list: first 256 words from the BIP-39 English wordlist (one word per
byte value 0x00–0xFF). This gives unambiguous encoding with a publicly
known, auditable wordlist — no proprietary encoding.

Checksum: CRC-16/CCITT (polynomial 0x1021, init 0xFFFF) of the original
data bytes, appended as two extra words (high byte first). This lets
decode() detect transcription errors in the word sequence.
"""

from __future__ import annotations

import struct
from typing import List


# ---------------------------------------------------------------------------
# Word list: first 256 words from BIP-39 English
# ---------------------------------------------------------------------------

WORDLIST: List[str] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "acquire", "across", "act", "action",
    "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "afford",
    "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien",
    "all", "alley", "allow", "almost", "alone", "alpha", "already", "also",
    "alter", "always", "amateur", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
    "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
    "april", "arch", "arctic", "area", "arena", "argue", "arm", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art",
    "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend",
    "attitude", "attract", "auction", "audit", "august", "aunt", "author",
    "auto", "autumn", "average", "avocado", "avoid", "awake", "aware",
    "away", "awesome", "awful", "awkward", "axis", "baby", "balance",
    "bamboo", "banana", "banner", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because",
    "become", "beef", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket",
    "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse",
    "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb",
    "bone", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
    "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy",
]

assert len(WORDLIST) == 256, (
    f"WORDLIST must have exactly 256 entries, got {len(WORDLIST)}"
)

# Build reverse lookup once at import time.
_WORD_TO_BYTE: dict[str, int] = {w: i for i, w in enumerate(WORDLIST)}


# ---------------------------------------------------------------------------
# CRC-16/CCITT (polynomial 0x1021, init 0xFFFF)
# ---------------------------------------------------------------------------

def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encode(data: bytes) -> List[str]:
    """
    Convert *data* to a list of English words.

    Output length is ``len(data) + 2``: one word per data byte, plus two
    checksum words (CRC-16 high byte, CRC-16 low byte).

    Parameters
    ----------
    data : arbitrary bytes to encode (may be empty — produces 2 checksum words)

    Returns
    -------
    list[str] : word sequence suitable for writing on paper
    """
    words = [WORDLIST[b] for b in data]
    crc = _crc16(data)
    words.append(WORDLIST[(crc >> 8) & 0xFF])   # high byte
    words.append(WORDLIST[crc & 0xFF])            # low byte
    return words


def decode(words: List[str]) -> bytes:
    """
    Reverse *encode()*: convert a word sequence back to bytes.

    Validates the two trailing CRC-16 checksum words. Raises ValueError if
    any word is not in WORDLIST or if the checksum does not match.

    Parameters
    ----------
    words : word sequence as produced by encode()

    Returns
    -------
    bytes : original data

    Raises
    ------
    ValueError : unknown word or checksum mismatch
    """
    if len(words) < 2:
        raise ValueError(
            f"word sequence too short: need at least 2 checksum words, got {len(words)}"
        )

    byte_values: List[int] = []
    for i, word in enumerate(words):
        if word not in _WORD_TO_BYTE:
            raise ValueError(f"unknown word at position {i}: {word!r}")
        byte_values.append(_WORD_TO_BYTE[word])

    # Last two bytes are the CRC-16
    data = bytes(byte_values[:-2])
    crc_hi = byte_values[-2]
    crc_lo = byte_values[-1]
    expected_crc = (crc_hi << 8) | crc_lo

    actual_crc = _crc16(data)
    if actual_crc != expected_crc:
        raise ValueError(
            f"checksum mismatch: expected 0x{expected_crc:04X}, "
            f"got 0x{actual_crc:04X} — check for transcription errors"
        )

    return data
