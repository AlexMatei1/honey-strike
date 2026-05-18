"""Live JA3 sniffer integration test.

Opens a TLS handshake against the TLS-fingerprint honeypot, asserts the
session row + TLS_CLIENT_HELLO event land, and that the FingerprintWorker
populates `ja3_hash` on the resulting fingerprints row.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.models import Event, Fingerprint, Session

TLS_HOST = os.getenv("HONEYPOT_TLS_HOST", os.getenv("HONEYSTRIKE_HOST", "127.0.0.1"))
TLS_PORT = int(os.getenv("HONEYPOT_TLS_PORT", "8443"))


def _port_open(host: str, port: int, *, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def tls_endpoint() -> tuple[str, int]:
    if not _port_open(TLS_HOST, TLS_PORT):
        pytest.skip(f"tls-honeypot not reachable at {TLS_HOST}:{TLS_PORT}")
    return TLS_HOST, TLS_PORT


def _handshake_and_drop(host: str, port: int) -> None:
    """Initiate a TLS handshake; tolerate any error since the sniffer aborts."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        wrapped.close()
    except (ssl.SSLError, OSError):
        # Expected — the sniffer never completes the handshake.
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


@pytest.mark.asyncio
async def test_tls_sniffer_captures_ja3(
    tls_endpoint, db: AsyncSession, wait_for
) -> None:
    host, port = tls_endpoint
    before = datetime.now(UTC)
    await asyncio.to_thread(_handshake_and_drop, host, port)

    async def _find_session() -> Session | None:
        rows = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "tls")
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
    assert session is not None, "no CLOSED tls session captured"
    assert session.event_count >= 1

    events = (
        (
            await db.execute(
                select(Event).where(Event.session_id == session.id)
            )
        )
        .scalars()
        .all()
    )
    tls_events = [e for e in events if e.event_type == "TLS_CLIENT_HELLO"]
    assert tls_events, "no TLS_CLIENT_HELLO event for the session"
    payload = tls_events[0].payload
    assert payload["parseable"] is True
    # ja3_hash is a 32-char lowercase MD5 hex string.
    assert isinstance(payload["ja3_hash"], str)
    assert len(payload["ja3_hash"]) == 32


@pytest.mark.asyncio
async def test_fingerprint_worker_populates_ja3_hash(
    tls_endpoint, db: AsyncSession, wait_for
) -> None:
    host, port = tls_endpoint
    before = datetime.now(UTC)
    await asyncio.to_thread(_handshake_and_drop, host, port)

    async def _fp_with_ja3() -> Fingerprint | None:
        await db.commit()
        row = (
            (
                await db.execute(
                    select(Fingerprint)
                    .join(Session, Session.id == Fingerprint.session_id)
                    .where(Session.service == "tls")
                    .where(Session.started_at >= before)
                    .order_by(Session.started_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        return row if row and row.ja3_hash else None

    fp = await wait_for(_fp_with_ja3, timeout=30.0)
    assert fp is not None, "FingerprintWorker did not write ja3_hash within 30s"
    assert len(fp.ja3_hash) == 32
