"""ULID generator — zero-dependency inline implementation.

powhttp uses ULIDs (Crockford base32, 26 chars: 10 for a 48-bit millisecond
timestamp, 16 for 80 bits of randomness). ULIDs sort lexicographically by
time, which is why powhttp's `entryIds[]` array is ordered. We match the
format so `da-powhttp-mcp` can ingest our IDs unchanged.

Reference: https://github.com/ulid/spec
"""

from __future__ import annotations

import os
import time
from typing import Final

# Crockford's base32 alphabet — no I, L, O, or U (to avoid ambiguity).
_ALPHABET: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
assert len(_ALPHABET) == 32


def _encode(value: int, length: int) -> str:
    """Encode an int as exactly `length` base32 chars, left-padded."""
    out: list[str] = []
    for _ in range(length):
        out.append(_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


def new_ulid(ts_ms: int | None = None) -> str:
    """Generate a fresh ULID.

    Args:
        ts_ms: Millisecond timestamp to embed. Defaults to now.
    """
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    # 48-bit timestamp → 10 Crockford chars
    time_part = _encode(ts_ms & ((1 << 48) - 1), 10)
    # 80 bits of randomness → 16 Crockford chars
    rand = int.from_bytes(os.urandom(10), "big")
    rand_part = _encode(rand, 16)
    return time_part + rand_part


def ulid_timestamp(ulid: str) -> int:
    """Extract the embedded millisecond timestamp from a ULID string."""
    if len(ulid) != 26:
        raise ValueError(f"ULID must be 26 chars, got {len(ulid)}")
    value = 0
    for ch in ulid[:10]:
        i = _ALPHABET.find(ch.upper())
        if i < 0:
            raise ValueError(f"invalid ULID char: {ch!r}")
        value = (value << 5) | i
    return value


if __name__ == "__main__":
    # Smoke test.
    for _ in range(3):
        u = new_ulid()
        print(u, "→ ts_ms =", ulid_timestamp(u))
