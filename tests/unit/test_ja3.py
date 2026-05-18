"""Tests for the JA3 parser using a known-good ClientHello capture.

We don't need to ship a multi-megabyte pcap — we hand-craft a ClientHello
that exercises every parsed field, then assert the resulting JA3 string.
"""

from __future__ import annotations

import hashlib
import struct

from honeystrike.services.http.ja3 import _GREASE, compute_ja3


def _build_client_hello(
    *,
    tls_version: int = 0x0303,                  # TLS 1.2
    ciphers: list[int] = (0x1301, 0x1302, 0x0A0A),   # last one = GREASE
    extensions: list[tuple[int, bytes]] | None = None,
    sni: str | None = "honeypot.example",
) -> bytes:
    """Assemble a TLS 1.2/1.3 ClientHello record. Bytes-exact."""
    if extensions is None:
        # supported_groups (0x000A): secp256r1 (23), x25519 (29), GREASE (0xAAAA)
        sg_ext = struct.pack(">H", 6) + struct.pack(">HHH", 23, 29, 0xAAAA)
        # ec_point_formats (0x000B): uncompressed (0)
        epf_ext = struct.pack(">B", 1) + bytes([0])
        # server_name (0x0000)
        sni_bytes = sni.encode("ascii") if sni else b""
        sni_ext = (
            struct.pack(">H", 3 + len(sni_bytes))   # list len
            + bytes([0])                              # name_type=host_name
            + struct.pack(">H", len(sni_bytes))
            + sni_bytes
        )
        extensions = [
            (0x000A, sg_ext),
            (0x000B, epf_ext),
            (0x0000, sni_ext),
        ]

    # cipher_suites
    ciphers_bytes = b"".join(struct.pack(">H", c) for c in ciphers)

    # extensions block
    ext_bytes = b""
    for ext_type, ext_data in extensions:
        ext_bytes += struct.pack(">HH", ext_type, len(ext_data)) + ext_data
    extensions_block = struct.pack(">H", len(ext_bytes)) + ext_bytes

    hello_body = (
        struct.pack(">H", tls_version)
        + b"\x00" * 32                   # random
        + bytes([0])                     # session_id length
        + struct.pack(">H", len(ciphers_bytes)) + ciphers_bytes
        + bytes([1, 0])                  # compression methods (null only)
        + extensions_block
    )

    handshake = bytes([0x01])             # ClientHello
    # 3-byte handshake length
    handshake += struct.pack(">I", len(hello_body))[1:]
    handshake += hello_body

    record = (
        bytes([0x16, 0x03, 0x03])         # type=handshake, version=TLS 1.2
        + struct.pack(">H", len(handshake))
        + handshake
    )
    return record


def test_compute_ja3_returns_expected_string_and_md5() -> None:
    record = _build_client_hello()
    fp = compute_ja3(record)
    assert fp is not None

    # GREASE values must be stripped from ciphers / extensions / curves.
    assert all(c not in _GREASE for c in fp.ciphers)
    assert all(e not in _GREASE for e in fp.extensions)
    assert all(c not in _GREASE for c in fp.elliptic_curves)

    expected_string = "771,4865-4866,10-11-0,23-29,0"
    assert fp.ja3_string == expected_string
    assert fp.ja3_hash == hashlib.md5(expected_string.encode("ascii")).hexdigest()


def test_sni_is_parsed() -> None:
    fp = compute_ja3(_build_client_hello(sni="evil.example.com"))
    assert fp is not None
    assert fp.sni == "evil.example.com"


def test_no_sni_returns_none() -> None:
    record = _build_client_hello(extensions=[(0x000A, b"\x00\x00")])
    fp = compute_ja3(record)
    assert fp is not None
    assert fp.sni is None


def test_malformed_input_returns_none() -> None:
    assert compute_ja3(b"") is None
    assert compute_ja3(b"\x16\x03\x03\x00\x05garbage") is None
    # Truncated record header.
    assert compute_ja3(b"\x16\x03") is None
    # Not a handshake record.
    assert compute_ja3(b"\x17\x03\x03\x00\x05hello") is None
