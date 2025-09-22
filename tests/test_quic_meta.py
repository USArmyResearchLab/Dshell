# tests/test_quic_meta.py
import pathlib
from importlib.machinery import SourceFileLoader

# Load module directly by path to avoid importing dshell/__init__ (pcapy/geoip2)
MODULE_PATH = pathlib.Path(__file__).parents[1] / "dshell" / "plugins" / "quic" / "quic_meta.py"
quic_meta = SourceFileLoader("quic_meta", str(MODULE_PATH)).load_module()

is_quic_long_header = quic_meta.is_quic_long_header
parse_quic_long_header = quic_meta.parse_quic_long_header
QuicLongHeaderMeta = quic_meta.QuicLongHeaderMeta


def test_quic_long_header_parsing_basic():
    first = bytes([0xC3])           # long-header bit set
    version = (1).to_bytes(4, "big")
    dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    scid = b"\xAA\xBB\xCC\xDD"
    blob = first + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid

    assert is_quic_long_header(blob) is True

    meta = parse_quic_long_header(blob)
    assert isinstance(meta, QuicLongHeaderMeta)
    assert meta.header_form == "long"
    assert meta.version == 1
    assert meta.dcid == dcid
    assert meta.scid == scid


def test_not_quic_or_too_short():
    assert is_quic_long_header(b"\x10\x00") is False
    assert parse_quic_long_header(b"\x10\x00") is None


def test_malformed_lengths():
    bad = bytes([0x80]) + b"\x00\x00\x00\x01" + bytes([50])  # dcid_len=50, exceeds buffer
    assert is_quic_long_header(bad) is True
    assert parse_quic_long_header(bad) is None
