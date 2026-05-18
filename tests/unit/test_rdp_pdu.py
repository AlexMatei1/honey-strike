"""RDP PDU parser tests.

We synthesize byte-exact TPKT + X.224 PDUs the same way an mstsc client does,
then assert the parser pulls out the cookie, mstshash, and the requested
security protocol bitfield.
"""

from __future__ import annotations

import struct

from honeystrike.services.rdp.pdu import (
    PROTOCOL_HYBRID,
    PROTOCOL_SSL,
    build_connection_confirm,
    parse_connection_request,
)


def _build_cr_pdu(*, mstshash: str | None = None, protocols: int | None = None) -> bytes:
    """Compose a TPKT-framed X.224 Connection Request matching a real client.

    Layout (from [MS-RDPBCGR] §2.2.1.1):
      TPKT header (4)
        X.224 CR fixed (7)
          [optional] "Cookie: mstshash=<value>\\r\\n"
          [optional] RDP Negotiation Request (8): type=1 flags=0 len=8 protocols
    """
    cookie_bytes = b""
    if mstshash is not None:
        cookie_bytes = f"Cookie: mstshash={mstshash}\r\n".encode("ascii")

    neg_bytes = b""
    if protocols is not None:
        neg_bytes = struct.pack("<BBHI", 0x01, 0x00, 8, protocols)

    payload = cookie_bytes + neg_bytes
    # X.224 CR: LI + type + DST + SRC + class = 7 bytes (LI counts bytes AFTER itself)
    x224 = bytes(
        [
            6 + len(payload),  # LI
            0xE0,              # CR
            0x00, 0x00,        # DST-REF
            0x00, 0x00,        # SRC-REF
            0x00,              # class / options
        ]
    ) + payload

    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(x224)) + x224
    return tpkt


def test_parses_mstshash_cookie_and_protocols() -> None:
    cr = _build_cr_pdu(mstshash="Administrator", protocols=PROTOCOL_SSL | PROTOCOL_HYBRID)
    parsed = parse_connection_request(cr)
    assert parsed is not None
    assert parsed.mstshash == "Administrator"
    assert parsed.cookie_raw == "Cookie: mstshash=Administrator"
    assert parsed.requested_protocols == (PROTOCOL_SSL | PROTOCOL_HYBRID)
    assert parsed.raw_length == len(cr)


def test_parses_without_cookie() -> None:
    cr = _build_cr_pdu(mstshash=None, protocols=PROTOCOL_SSL)
    parsed = parse_connection_request(cr)
    assert parsed is not None
    assert parsed.mstshash is None
    assert parsed.cookie_raw is None
    assert parsed.requested_protocols == PROTOCOL_SSL


def test_parses_without_negotiation_request() -> None:
    cr = _build_cr_pdu(mstshash="guest", protocols=None)
    parsed = parse_connection_request(cr)
    assert parsed is not None
    assert parsed.mstshash == "guest"
    assert parsed.requested_protocols == 0


def test_malformed_returns_none() -> None:
    assert parse_connection_request(b"") is None
    assert parse_connection_request(b"\x03\x00\x00") is None  # too short
    assert parse_connection_request(b"GET / HTTP/1.1\r\n") is None  # not TPKT
    # Wrong X.224 type byte
    cr = bytearray(_build_cr_pdu(mstshash="x"))
    cr[5] = 0xF0  # not 0xE0 (CR)
    assert parse_connection_request(bytes(cr)) is None


def test_build_connection_confirm_is_valid_tpkt() -> None:
    cc = build_connection_confirm(selected_protocol=PROTOCOL_SSL)
    # TPKT header version + reserved + total length
    assert cc[0] == 0x03
    assert cc[1] == 0x00
    total_len = struct.unpack(">H", cc[2:4])[0]
    assert total_len == len(cc)
    # X.224 type byte is CC (0xD0)
    assert cc[5] == 0xD0
    # RDP Negotiation Response starts after the 7-byte X.224 header
    rsp_type = cc[11]
    selected = struct.unpack("<I", cc[15:19])[0]
    assert rsp_type == 0x02         # TYPE_RDP_NEG_RSP
    assert selected == PROTOCOL_SSL
