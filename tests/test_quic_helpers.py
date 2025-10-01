import importlib.util
import pathlib
import sys

HELPERS = pathlib.Path(__file__).parents[1] / "dshell" / "plugins" / "quic" / "_helpers.py"
spec = importlib.util.spec_from_file_location("dshell_quic_helpers", str(HELPERS))
mod = importlib.util.module_from_spec(spec)

# IMPORTANT: register the module before executing so dataclasses/typing can resolve it
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

# Pull symbols under test
is_quic_long_header = mod.is_quic_long_header
parse_quic_long_header = mod.parse_quic_long_header
QuicLongHeaderMeta = mod.QuicLongHeaderMeta


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
