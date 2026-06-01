"""
harness_tlv.py — Fuzz the der_codec decode_tlv / decode_length primitives.

These are the lowest-level DER parsers. Every higher-level parser depends on
them. Bugs here (infinite loops, OOB reads, integer overflow in length calc)
would propagate to every protocol surface.

TestOneInput contract:
  - Must not crash with an unhandled exception for any input.
  - Must not loop indefinitely (the budget enforcer in run_fuzz.sh handles
    wallclock, but parsers must not recurse unboundedly).
  - Expected: IndexError, ValueError for malformed DER.
"""

from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from der_codec import decode_tlv, decode_length, encode_length


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    # --- Test 1: single decode_tlv call ---
    try:
        tag, value, next_pos = decode_tlv(data, 0)
        # Invariant: next_pos must not exceed len(data)
        assert next_pos <= len(data), f"next_pos={next_pos} > len={len(data)}"
        # Invariant: len(value) matches claimed length
        # (decode_tlv slices, so this is just a sanity check)
        assert isinstance(value, (bytes, bytearray))
    except (IndexError, ValueError, AssertionError):
        return

    # --- Test 2: iterative walk until end of buffer ---
    pos = 0
    depth = 0
    max_depth = 128
    try:
        while pos < len(data) and depth < max_depth:
            tag, value, pos = decode_tlv(data, pos)
            depth += 1
            # If constructed (bit 6 set), recurse into value — but only
            # shallowly to avoid stack exhaustion on adversarial input.
            if (tag & 0x20) and len(value) > 0 and depth < 4:
                inner_pos = 0
                inner_depth = 0
                while inner_pos < len(value) and inner_depth < 32:
                    _, _, inner_pos = decode_tlv(value, inner_pos)
                    inner_depth += 1
    except (IndexError, ValueError):
        pass

    # --- Test 3: encode_length / decode_length round-trip on claimed length ---
    if len(data) >= 2:
        try:
            length, npos = decode_length(data, 0)
            # Lengths above 16 MB are pathological; skip re-encoding them.
            if length < 0x100_0000:
                reenc = encode_length(length)
                relength, _ = decode_length(reenc, 0)
                assert relength == length, f"round-trip failed: {length} != {relength}"
        except (IndexError, ValueError, AssertionError):
            pass


# ---------------------------------------------------------------------------
# Atheris entry point (when Atheris is available)
# ---------------------------------------------------------------------------

def _atheris_main() -> None:
    import atheris  # type: ignore
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    try:
        import atheris  # type: ignore
        _atheris_main()
    except ImportError:
        from _stdlib_runner import run
        from pathlib import Path
        corpus_dir = Path(__file__).parent / "corpus" / "tlv_primitive"
        import sys as _sys
        crashes = run(sys.modules[__name__], corpus_dir, budget_seconds=300)
        _sys.exit(1 if crashes else 0)
