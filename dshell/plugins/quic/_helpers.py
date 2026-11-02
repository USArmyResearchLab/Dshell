# SPDX-License-Identifier: BSD-3-Clause
"""
Minimal QUIC long-header helpers (pure-Python, CI-friendly).

We only parse the QUIC *long header* preamble:
- header form (always "long" here)
- version (uint32)
- DCID (Destination Connection ID)
- SCID (Source Connection ID)

RFC 9000 §17.2 layout (prefix):
[first byte][version(4)][dcid_len(1)][dcid][scid_len(1)][scid]...
We intentionally stop after SCID; fields after that vary by packet type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class QuicLongHeaderMeta:
    header_form: str   # "long"
    version: int       # 32-bit version (0 for version negotiation)
    dcid: bytes        # Destination Connection ID
    scid: bytes        # Source Connection ID


def is_quic_long_header(data: bytes) -> bool:
    """
    True if the buffer looks like a QUIC *long header* (MSB set) and is long enough
    for [first byte][version][dcid_len] (>= 6 bytes).
    """
    return len(data) >= 6 and (data[0] & 0x80) == 0x80


def parse_quic_long_header(data: bytes) -> Optional[QuicLongHeaderMeta]:
    """
    Parse the QUIC long header preamble and return QuicLongHeaderMeta, or None if invalid.
    Safe to call on arbitrary UDP payloads.
    """
    try:
        if not is_quic_long_header(data):
            return None

        # version: 4 bytes after first byte
        version = int.from_bytes(data[1:5], "big")

        p = 5
        # DCID length + DCID
        dcid_len = data[p]
        p += 1
        if p + dcid_len > len(data):
            return None
        dcid = data[p : p + dcid_len]
        p += dcid_len

        # SCID length + SCID
        if p >= len(data):
            return None
        scid_len = data[p]
        p += 1
        if p + scid_len > len(data):
            return None
        scid = data[p : p + scid_len]

        return QuicLongHeaderMeta(
            header_form="long",
            version=version,
            dcid=dcid,
            scid=scid,
        )
    except Exception:
        # Be defensive: never raise from helpers
        return None


__all__ = [
    "QuicLongHeaderMeta",
    "is_quic_long_header",
    "parse_quic_long_header",
]
