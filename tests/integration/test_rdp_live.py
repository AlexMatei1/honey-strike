"""Live RDP honeypot integration test.

Forges a valid Connection Request PDU (TPKT + X.224 + mstshash cookie + RDP
Negotiation Request), sends it to the running listener, asserts:
  - we got back a structurally valid Connection Confirm
  - a session row with the mstshash cookie was persisted
"""

from __future__ import annotations

import socket
import struct
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from honeystrike.core.models import Event, Session
from honeystrike.services.rdp.pdu import PROTOCOL_HYBRID, PROTOCOL_SSL


def _build_cr_pdu(mstshash: str, protocols: int) -> bytes:
    cookie = f"Cookie: mstshash={mstshash}\r\n".encode("ascii")
    neg = struct.pack("<BBHI", 0x01, 0x00, 8, protocols)
    payload = cookie + neg
    x224 = bytes([6 + len(payload), 0xE0, 0, 0, 0, 0, 0]) + payload
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(x224)) + x224


def _send_cr(host: str, port: int, mstshash: str, protocols: int) -> tuple[datetime, bytes]:
    before = datetime.now(UTC)
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(_build_cr_pdu(mstshash, protocols))
    try:
        reply = s.recv(4096)
    except socket.timeout:
        reply = b""
    s.close()
    return before, reply


@pytest.mark.asyncio
async def test_rdp_live_captures_mstshash_and_returns_valid_cc(
    rdp_endpoint, db, wait_for
) -> None:
    host, port = rdp_endpoint
    mstshash = "IntegrationTester"
    requested = PROTOCOL_SSL | PROTOCOL_HYBRID

    before, reply = _send_cr(host, port, mstshash, requested)

    # Valid TPKT + X.224 CC reply structurally.
    assert len(reply) >= 19, reply
    assert reply[0] == 0x03           # TPKT version
    assert reply[5] == 0xD0           # X.224 CC type byte

    async def _find_session() -> Session | None:
        rows = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "rdp")
                    .where(Session.started_at >= before)
                    .order_by(Session.started_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .all()
        )
        return rows[0] if rows and rows[0].state == "CLOSED" else None

    session = await wait_for(_find_session, timeout=10.0)
    assert session is not None, f"no CLOSED rdp session since {before}"

    events = (
        (
            await db.execute(
                select(Event)
                .where(Event.session_id == session.id)
                .where(Event.event_type == "RDP_CONNECT")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1, events
    payload = events[0].payload
    assert payload["mstshash"] == mstshash
    assert payload["requested_protocols"] == requested
    assert "PROTOCOL_SSL" in payload["requested_protocols_names"]
    assert "PROTOCOL_HYBRID" in payload["requested_protocols_names"]
