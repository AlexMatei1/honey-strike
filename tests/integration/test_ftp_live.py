"""Live FTP honeypot integration test.

Uses stdlib `ftplib` (the simplest realistic client) to login, run a few
commands, and verify they all land as FTP_COMMAND events.
"""

from __future__ import annotations

import contextlib
import ftplib
import socket
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from honeystrike.core.models import Event, Session


def _drive_ftp_client(host: str, port: int) -> datetime:
    """Returns the wall-clock time before the probe started."""
    before = datetime.now(UTC)
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=10)
    ftp.login("root", "toor")
    with contextlib.suppress(Exception):
        ftp.cwd("/etc")
    ftp.set_pasv(True)
    # Data channels intentionally fail (passive ports not exposed) — only
    # the *commands* are interesting for capture.
    for op in ("LIST", "RETR /etc/passwd"):
        try:
            ftp.sock.settimeout(3)
            if op == "LIST":
                ftp.retrlines("LIST")
            else:
                ftp.retrbinary(op, lambda _b: None)
        except (ConnectionRefusedError, socket.timeout, ftplib.error_perm):
            continue
    with contextlib.suppress(Exception):
        ftp.quit()
    return before


@pytest.mark.asyncio
async def test_ftp_live_captures_login_and_commands(
    ftp_endpoint, db, wait_for
) -> None:
    host, port = ftp_endpoint
    before = _drive_ftp_client(host, port)

    async def _find_session() -> Session | None:
        rows = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "ftp")
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
    assert session is not None, f"no CLOSED ftp session since {before}"
    assert session.event_count >= 4, session.event_count

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
    commands = [e.payload.get("command", "").upper() for e in events]

    assert "USER" in commands
    assert "PASS" in commands
    assert "CWD" in commands

    user_evt = next(e for e in events if e.payload.get("command", "").upper() == "USER")
    pass_evt = next(e for e in events if e.payload.get("command", "").upper() == "PASS")

    assert user_evt.payload["captured_username"] == "root"
    assert pass_evt.payload["captured_password"] == "toor"
    assert pass_evt.payload["paired_username"] == "root"
