"""Telnet protocol helpers — pure logic, no sockets (so it unit-tests).

We implement just enough of RFC 854 to look like a real `telnetd`: refuse
the handful of option negotiations a client opens with (so it stops asking),
and strip any inline IAC command sequences from the user's input lines.
"""

from __future__ import annotations

# Telnet control bytes (RFC 854).
IAC = 0xFF          # Interpret As Command
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA           # subnegotiation begin
SE = 0xF0           # subnegotiation end

BANNER = "\r\nUbuntu 22.04.3 LTS\r\n"
LOGIN_PROMPT = "login: "
PASSWORD_PROMPT = "Password: "
FAIL_MESSAGE = "\r\nLogin incorrect\r\n"


def refuse_options(data: bytes) -> bytes:
    """Given raw bytes that may contain IAC option requests, build a reply
    that politely refuses every option (WILL→DONT, DO→WONT) so the client
    stops negotiating and starts sending the login. Returns the reply bytes
    (possibly empty)."""
    reply = bytearray()
    i = 0
    n = len(data)
    while i < n:
        if data[i] == IAC and i + 2 < n:
            verb, opt = data[i + 1], data[i + 2]
            if verb == WILL:
                reply += bytes([IAC, DONT, opt])
            elif verb == DO:
                reply += bytes([IAC, WONT, opt])
            # WONT / DONT need no reply.
            i += 3
        else:
            i += 1
    return bytes(reply)


def strip_iac(data: bytes) -> bytes:
    """Remove IAC command sequences from a line of input, returning just the
    printable user bytes. Handles 3-byte option commands and SB...SE blocks."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == IAC and i + 1 < n:
            nxt = data[i + 1]
            if nxt == SB:
                # Skip to SE.
                j = i + 2
                while j < n and data[j] != SE:
                    j += 1
                i = j + 1
            elif nxt in (DO, DONT, WILL, WONT):
                i += 3
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


def clean_credential(raw: bytes, *, max_len: int = 256) -> str:
    """Turn a raw input line into a sanitised credential string: strip IAC,
    drop CR/LF and control chars, cap the length."""
    text = strip_iac(raw).decode("utf-8", errors="replace")
    text = text.replace("\r", "").replace("\n", "")
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:max_len]
