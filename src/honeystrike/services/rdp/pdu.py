"""RDP wire-format parser — just enough to capture the interesting bits.

The full RDP protocol stack is huge; we only need to:

  1. Parse the X.224 Connection Request PDU wrapped in a TPKT header.
  2. Pull out the optional routing token / `mstshash=` cookie.
  3. Read the optional RDP Negotiation Request (`type=0x01`) to learn which
     security protocols the client supports (`PROTOCOL_RDP`, `PROTOCOL_SSL`,
     `PROTOCOL_HYBRID`, `PROTOCOL_HYBRID_EX`).
  4. Compose a valid X.224 Connection Confirm + RDP Negotiation Response so
     scanners advance to the next step.

References:
  - RFC 1006 (TPKT)
  - ITU-T X.224 §13.3 (CR PDU)
  - [MS-RDPBCGR] §2.2.1.1, §2.2.1.2

We deliberately keep parsing tolerant: malformed PDUs return `None` rather
than raising — every received byte is interesting threat-intel data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


# TPKT header constants
_TPKT_VERSION = 0x03
_TPKT_HEADER_LEN = 4

# X.224 PDU types (high nibble of the type byte)
_X224_TYPE_CR = 0xE0   # Connection Request
_X224_TYPE_CC = 0xD0   # Connection Confirm

# RDP Negotiation Request / Response types
_RDP_NEG_REQ = 0x01
_RDP_NEG_RSP = 0x02

# RDP security protocol bit flags (from [MS-RDPBCGR] §2.2.1.1.1)
PROTOCOL_RDP        = 0x00000000
PROTOCOL_SSL        = 0x00000001
PROTOCOL_HYBRID     = 0x00000002
PROTOCOL_RDSTLS     = 0x00000004
PROTOCOL_HYBRID_EX  = 0x00000008


@dataclass(slots=True, frozen=True)
class ConnectionRequest:
    """Parsed X.224 Connection Request PDU."""

    cookie_raw: str | None       # full routing-token line, e.g. "Cookie: mstshash=Administrator"
    mstshash: str | None         # the `mstshash=` value, if present
    requested_protocols: int     # bitfield from RDP Negotiation Request (0 if absent)
    raw_length: int              # full PDU size on the wire


def parse_connection_request(buf: bytes) -> ConnectionRequest | None:
    """Parse a TPKT-framed X.224 Connection Request.

    Returns None for any structural problem; the listener still logs the raw
    bytes so the operator sees malformed/probing traffic.
    """
    try:
        return _parse(buf)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        return None


def _parse(buf: bytes) -> ConnectionRequest | None:
    if len(buf) < _TPKT_HEADER_LEN:
        return None
    if buf[0] != _TPKT_VERSION:
        return None
    tpkt_len = struct.unpack(">H", buf[2:4])[0]
    if tpkt_len < 7 or tpkt_len > len(buf):
        # Length looks bogus; still try to parse what we have.
        tpkt_len = len(buf)

    # X.224 header starts at offset 4. First byte: LI (length indicator).
    li = buf[4]
    type_byte = buf[5]
    if type_byte & 0xF0 != _X224_TYPE_CR:
        return None

    # Routing token / cookie lives between the X.224 header and the optional
    # RDP Negotiation Request (CR-LF terminated, ASCII).
    cookie_start = 4 + 7  # TPKT(4) + X.224 fixed header (7 bytes for CR PDU)
    cookie_end = cookie_start
    while cookie_end + 1 < tpkt_len:
        if buf[cookie_end] == 0x0D and buf[cookie_end + 1] == 0x0A:
            break
        cookie_end += 1

    cookie_raw: str | None = None
    mstshash: str | None = None
    if cookie_end > cookie_start and cookie_end + 1 < tpkt_len:
        cookie_bytes = buf[cookie_start:cookie_end]
        try:
            cookie_raw = cookie_bytes.decode("ascii", errors="replace").strip()
        except UnicodeDecodeError:
            cookie_raw = None
        if cookie_raw and "mstshash=" in cookie_raw.lower():
            # Find the value after the last `=`, before any trailing whitespace.
            value = cookie_raw.split("=", 1)[1] if "=" in cookie_raw else ""
            mstshash = value.strip()
        neg_start = cookie_end + 2   # skip CRLF
    else:
        neg_start = cookie_start

    requested_protocols = 0
    # Optional RDP Negotiation Request: type(1) flags(1) length(2) protocols(4)
    if neg_start + 8 <= tpkt_len and buf[neg_start] == _RDP_NEG_REQ:
        requested_protocols = struct.unpack("<I", buf[neg_start + 4:neg_start + 8])[0]

    return ConnectionRequest(
        cookie_raw=cookie_raw,
        mstshash=mstshash,
        requested_protocols=requested_protocols,
        raw_length=tpkt_len,
    )


def build_connection_confirm(*, selected_protocol: int = PROTOCOL_SSL) -> bytes:
    """Compose a valid X.224 CC PDU + RDP Negotiation Response.

    Returning `PROTOCOL_SSL` advertises that the server wants TLS next — we
    won't actually serve TLS (the next bytes we receive will get logged as
    raw and the socket dropped), but the response is structurally valid so
    scanners advance to the next stage and reveal their TLS ClientHello.
    """
    # RDP Negotiation Response (8 bytes)
    rdp_neg_rsp = struct.pack("<BBHI", _RDP_NEG_RSP, 0x00, 8, selected_protocol)

    # X.224 Connection Confirm PDU
    # Fixed header: LI(1) type(1) DST-REF(2) SRC-REF(2) class(1) = 7 bytes
    x224 = bytes(
        [
            6 + len(rdp_neg_rsp),  # LI counts bytes after itself
            _X224_TYPE_CC,
            0x00, 0x00,            # DST-REF
            0x12, 0x34,            # SRC-REF (arbitrary)
            0x00,                   # class / options
        ]
    ) + rdp_neg_rsp

    # TPKT envelope
    tpkt = bytes([_TPKT_VERSION, 0x00]) + struct.pack(">H", 4 + len(x224)) + x224
    return tpkt
