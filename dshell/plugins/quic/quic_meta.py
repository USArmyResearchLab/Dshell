# SPDX-License-Identifier: BSD-3-Clause
"""
Minimal QUIC metadata helpers (pure-Python, testable without pcap libs).

We only parse the QUIC *long header* preamble:
- header form (long vs short)
- version
- Destination Connection ID (DCID)
- Source Connection ID (SCID)

RFC 9000 §17.2: [first byte][version(4)][dcid_len(1)][dcid][scid_len(1)][scid]...
We intentionally stop after SCID; the rest (token/len/packet-number/etc.) varies by type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class QuicLongHeaderMeta:
    header_form: str            # "long"
    version: int                # 32-bit version (0 for version negotiation)
    dcid: bytes                 # Destination Connection ID
    scid: bytes                 # Source Connection ID


def is_quic_long_header(data: bytes) -> bool:
    """
    Return True if the first byte looks like a QUIC *long header* (most significant bit set).
    Minimal preamble: 1 (first byte) + 4 (version) + 1 (dcid_len) = 6 bytes.
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

        # [0] = first byte (we don't currently break out packet type/reserved here)
        # [1:5] version (network byte order)
        version = int.from_bytes(data[1:5], "big")

        # DCID
        p = 5
        dcid_len = data[p]
        p += 1
        if p + dcid_len > len(data):
            return None
        dcid = data[p:p + dcid_len]
        p += dcid_len

        # SCID
        if p >= len(data):
            return None
        scid_len = data[p]
        p += 1
        if p + scid_len > len(data):
            return None
        scid = data[p:p + scid_len]

        return QuicLongHeaderMeta(
            header_form="long",
            version=version,
            dcid=dcid,
            scid=scid,
        )
    except Exception:
        # Never raise from here; just return None for “not-QUIC” or malformed
        return None


__all__ = [
    "QuicLongHeaderMeta",
    "is_quic_long_header",
    "parse_quic_long_header",
]
