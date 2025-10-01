# SPDX-License-Identifier: BSD-3-Clause
"""
QUIC (RFC 9000) decoder (long-header metadata)

Parses QUIC *long header* preamble from UDP payloads to extract:
- version (uint32)
- DCID (Destination Connection ID)
- SCID (Source Connection ID)

Defaults to UDP/443 but --ports can be used to add/override.
Never throws on malformed inputs; logs at debug and skips.

Example (table):
    decode -r traffic.pcap -p quic --ports 443,8443

Columns:
    ts, src, sport, dst, dport, version, dcid, scid, cid_len
"""

from __future__ import annotations

# Framework import (kept only here so helpers remain importable without Dshell deps)
from dshell.decoder import Decoder  # type: ignore

# Import pure-Python helpers (no Dshell/pcap deps)
from ._helpers import (
    QuicLongHeaderMeta,
    is_quic_long_header as _is_quic_long_header,
    parse_quic_long_header as _parse_quic_long_header,
)


class quic(Decoder):  # Dshell convention: class name == plugin name
    """
    QUIC long-header metadata extractor.
    Uses pure-Python helpers for safe parsing.
    """

    def __init__(self):
        # Human-facing metadata shown by `decode -p quic -h`
        Decoder.__init__(
            self,
            name="quic",
            description="Extract QUIC long-header metadata (version, DCID, SCID)",
            author="Akindotcome",
            filter="udp",  # BPF-level; we'll further filter by port(s)
        )
        # Default port(s); allow override via --ports
        self.ports = {443}

        # Output columns for table/CSV reporters
        self.columns = (
            "ts",
            "src",
            "sport",
            "dst",
            "dport",
            "version",
            "dcid",
            "scid",
            "cid_len",
        )

    def options(self, opts):
        """
        Add CLI options: --ports 443,8443
        """
        opts.add_option(
            "ports",
            "comma-separated UDP ports to consider as QUIC",
            default="443",
        )

    def preparse(self, opts):
        """
        Process CLI options before decoding starts.
        """
        ports = set()
        for tok in str(opts.ports).split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                ports.add(int(tok))
            except ValueError:
                self.warn(f"Invalid port '{tok}', skipping")
        if ports:
            self.ports = ports

    def packet(self, pkt):
        """
        Per-packet hook. `pkt` is Dshell’s packet object with helpers like:
          - pkt.time
          - pkt.ip, pkt.udp
          - pkt.src, pkt.dst, pkt.sport, pkt.dport
          - pkt.data (payload bytes)
        If your Dshell version differs, map these accordingly.
        """
        try:
            # Only targeted UDP ports
            if pkt.dport not in self.ports and pkt.sport not in self.ports:
                return

            data = bytes(pkt.data or b"")
            meta = _parse_quic_long_header(data)
            if not meta:
                return  # not a QUIC long header

            # Render CIDs in hex for readability
            dcid_hex = meta.dcid.hex()
            scid_hex = meta.scid.hex()
            cid_len = f"{len(meta.dcid)}/{len(meta.scid)}"

            # Emit a row (works with table/CSV/JSON reporters)
            self.write(
                ts=pkt.time,
                src=pkt.src,
                sport=pkt.sport,
                dst=pkt.dst,
                dport=pkt.dport,
                version=meta.version,
                dcid=dcid_hex,
                scid=scid_hex,
                cid_len=cid_len,
            )
        except Exception as e:
            # Be defensive; never take down the decode loop
            self.debug(f"quic: decode error: {e!r}")
            return
