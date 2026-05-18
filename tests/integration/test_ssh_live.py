"""Live SSH honeypot integration test.

Drives a real `paramiko.Transport` against the running ssh-honeypot container
through host port 2222. Asserts the resulting events (banner grab, 3 auth
attempts, granted shell command, session close) land in PG + Redis.
"""

from __future__ import annotations

import contextlib
import socket
import time
from datetime import UTC, datetime

import paramiko
import pytest
from sqlalchemy import select

from honeystrike.core.models import Event, Session


def _bruteforce_and_shell(host: str, port: int) -> datetime:
    """Hit the honeypot the way Hydra-on-one-TCP-connection would.

    Returns the wall-clock time *before* we connected so the assertion phase
    can find the freshly-created session row without relying on the client-
    side source port (NAT'd through Docker on dev hosts).
    """
    before = datetime.now(UTC)
    sock = socket.create_connection((host, port), timeout=10)

    transport = paramiko.Transport(sock)
    transport.start_client(timeout=10)
    granted = False
    for pw in ("hunter2", "letmein", "qwerty"):
        try:
            transport.auth_password("root", pw)
            granted = True
            break
        except paramiko.AuthenticationException:
            continue

    if granted:
        chan = transport.open_session()
        chan.get_pty()
        chan.invoke_shell()
        chan.settimeout(3)
        time.sleep(0.5)
        with contextlib.suppress(socket.timeout):
            chan.recv(4096)
        chan.send(b"whoami\n")
        time.sleep(0.3)
        with contextlib.suppress(socket.timeout):
            chan.recv(4096)
        chan.send(b"exit\n")
        time.sleep(0.3)

    transport.close()
    return before


@pytest.mark.asyncio
async def test_ssh_live_captures_brute_force_and_shell(
    ssh_endpoint, db, redis_client, wait_for
) -> None:
    host, port = ssh_endpoint
    before = _bruteforce_and_shell(host, port)

    async def _find_session() -> Session | None:
        rows = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "ssh")
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
    assert session is not None, f"no CLOSED ssh session since {before}"
    assert session.event_count > 0
    assert session.duration_ms is not None and session.duration_ms > 0

    events = (
        (
            await db.execute(
                select(Event)
                .where(Event.session_id == session.id)
                .order_by(Event.ts.asc())
            )
        )
        .scalars()
        .all()
    )
    types = [e.event_type for e in events]
    assert types.count("SSH_AUTH_ATTEMPT") >= 1, types
    assert "SSH_BANNER_GRAB" in types
    # Per-IP counter may or may not have granted shell depending on prior runs;
    # but if it did, a SSH_COMMAND must follow.
    granted = any(
        e.event_type == "SSH_AUTH_ATTEMPT" and e.payload.get("success") for e in events
    )
    if granted:
        assert any(e.event_type == "SSH_COMMAND" for e in events), types

    # Redis stream received at least the events we just persisted.
    stream_len = int(await redis_client.xlen("honeystrike:events"))
    assert stream_len >= len(events) + 2  # +SESSION_OPEN +SESSION_CLOSE
