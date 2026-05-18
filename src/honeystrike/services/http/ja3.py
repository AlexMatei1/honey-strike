"""JA3 TLS fingerprint computation.

Reference:  https://github.com/salesforce/ja3
Spec:       JA3 = MD5(
              TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            )
            where each list is a `-`-joined string of decimal IANA codepoints.

This module operates on the *raw bytes* of a TLS ClientHello record. It does
**not** perform a TLS handshake — the listener is expected to:

  1. Read the first 5 bytes (TLS record header)
  2. Read the rest of the ClientHello message
  3. Call `compute_ja3(client_hello_bytes)`
  4. Then perform the actual TLS handshake (e.g. with ssl.SSLContext) on a
     forwarded socket so the upstream FastAPI app sees plaintext HTTP

We deliberately keep parsing tolerant: malformed ClientHellos return `None`
rather than raising — the dashboard cares about *what* the attacker sent,
and an unparseable hello is itself data worth recording.

GREASE values (RFC 8701) are filtered out of cipher and extension lists per
the JA3 convention.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


# RFC 8701: GREASE values follow the pattern 0xNANA for N in [0..F].
_GREASE = frozenset(
    {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
     0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
)

_HANDSHAKE_RECORD_TYPE = 0x16
_CLIENT_HELLO_TYPE = 0x01
_EXT_SUPPORTED_GROUPS = 0x000A      # "elliptic_curves" in JA3 nomenclature
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_SERVER_NAME = 0x0000           # SNI


@dataclass(slots=True, frozen=True)
class JA3Fingerprint:
    ja3_string: str
    ja3_hash: str         # MD5 of ja3_string
    tls_version: int
    sni: str | None
    ciphers: list[int]
    extensions: list[int]
    elliptic_curves: list[int]
    ec_point_formats: list[int]


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE]


def compute_ja3(client_hello_record: bytes) -> JA3Fingerprint | None:
    """Parse a TLS record carrying a ClientHello and return its JA3.

    `client_hello_record` is expected to start with the 5-byte TLS record
    header (`0x16 0x03 0xXX <len_hi> <len_lo>`) followed by the handshake
    message.
    """
    try:
        return _compute(client_hello_record)
    except (struct.error, IndexError, ValueError):
        return None


def _compute(buf: bytes) -> JA3Fingerprint | None:
    pos = 0
    if len(buf) < 5 or buf[0] != _HANDSHAKE_RECORD_TYPE:
        return None
    record_len = struct.unpack(">H", buf[3:5])[0]
    pos = 5
    end = min(len(buf), 5 + record_len)

    if pos + 4 > end or buf[pos] != _CLIENT_HELLO_TYPE:
        return None
    # handshake length (3 bytes), skip
    pos += 4

    # client_version: 2 bytes
    if pos + 2 > end:
        return None
    tls_version = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 2

    # random: 32 bytes
    pos += 32

    # session_id
    if pos + 1 > end:
        return None
    sid_len = buf[pos]
    pos += 1 + sid_len

    # cipher_suites
    if pos + 2 > end:
        return None
    ciphers_len = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 2
    if pos + ciphers_len > end or ciphers_len % 2:
        return None
    ciphers_raw = [
        struct.unpack(">H", buf[pos + i:pos + i + 2])[0]
        for i in range(0, ciphers_len, 2)
    ]
    pos += ciphers_len

    # compression_methods
    if pos + 1 > end:
        return None
    comp_len = buf[pos]
    pos += 1 + comp_len

    # extensions
    extensions: list[int] = []
    elliptic_curves: list[int] = []
    ec_point_formats: list[int] = []
    sni: str | None = None

    if pos + 2 <= end:
        ext_total_len = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2
        ext_end = min(end, pos + ext_total_len)

        while pos + 4 <= ext_end:
            ext_type = struct.unpack(">H", buf[pos:pos + 2])[0]
            ext_len = struct.unpack(">H", buf[pos + 2:pos + 4])[0]
            pos += 4
            ext_data = buf[pos:pos + ext_len]
            pos += ext_len
            extensions.append(ext_type)

            if ext_type == _EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                curves_len = struct.unpack(">H", ext_data[:2])[0]
                elliptic_curves = [
                    struct.unpack(">H", ext_data[2 + i:2 + i + 2])[0]
                    for i in range(0, curves_len, 2)
                ]
            elif ext_type == _EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
                fmts_len = ext_data[0]
                ec_point_formats = list(ext_data[1:1 + fmts_len])
            elif ext_type == _EXT_SERVER_NAME and len(ext_data) >= 5:
                # SNI list: 2-byte list len, 1-byte name type, 2-byte name len, name
                try:
                    name_len = struct.unpack(">H", ext_data[3:5])[0]
                    sni_bytes = ext_data[5:5 + name_len]
                    sni = sni_bytes.decode("ascii", errors="replace") or None
                except (struct.error, IndexError):
                    sni = None

    ciphers = _strip_grease(ciphers_raw)
    extensions = _strip_grease(extensions)
    elliptic_curves = _strip_grease(elliptic_curves)

    ja3_string = "{},{},{},{},{}".format(
        tls_version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in elliptic_curves),
        "-".join(str(f) for f in ec_point_formats),
    )
    # MD5 here is REQUIRED by the JA3 spec (https://github.com/salesforce/ja3) —
    # it identifies a TLS-stack fingerprint, not a security boundary.
    # `usedforsecurity=False` keeps FIPS-enabled Python builds happy; # nosec
    # tells bandit, # noqa: S324 tells ruff.
    ja3_hash = hashlib.md5(                                # nosec B324  # noqa: S324
        ja3_string.encode("ascii"), usedforsecurity=False
    ).hexdigest()

    return JA3Fingerprint(
        ja3_string=ja3_string,
        ja3_hash=ja3_hash,
        tls_version=tls_version,
        sni=sni,
        ciphers=ciphers,
        extensions=extensions,
        elliptic_curves=elliptic_curves,
        ec_point_formats=ec_point_formats,
    )
